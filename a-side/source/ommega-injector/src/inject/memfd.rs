//! 把 payload 镜像塞进目标进程自己名下的一个 memfd 里。
//!
//! 为什么不走跨进程递 fd：那条路要在目标进程里建一个 unix socket 收 fd，SELinux 得放行
//! 「我们的 socket → 目标域」这条跨域规则；换一台机器、换一个域就得多加一条策略，而且
//! A 端这台机器上往 system_app 递的时候内核只送来 SCM_CREDENTIALS、把 SCM_RIGHTS 丢掉了。
//! memfd 这条不经过任何 IPC：在目标进程里 memfd_create 出一个匿名文件，字节分块写进
//! 目标栈上一块固定的暂存区、再用目标自己的 write() 落进 memfd，最后把手里的 fd 交给
//! android_dlopen_ext。目标读的是自己的内存，不需要任何读文件的权限。

use std::ffi::CString;
use std::io::Read;
use std::path::Path;

use anyhow::{bail, Context, Result};
use log::{debug, info, warn};
use nix::unistd::Pid;

use crate::sys;

use super::payload_fd::remote_c_int_result;

/// Linux 的 memfd 标志：exec 时关掉（别漏给以后 exec 出去的东西）。
const MFD_CLOEXEC: usize = 0x0001;
/// Android 内核自己加的位。没这个位，memfd 出来就是不可执行的（mmap PROT_EXEC 被拒），
/// 而 dlopen 必须能 exec 那段代码。老内核不认这个位（EINVAL），所以要退回去重试一次。
const MFD_EXEC: usize = 0x0010;

/// 一次搬多少字节。真正贵的是每块一次远程 write()（每块都得让目标停下来再走），
/// 所以块别太小；30 多 KB 一次 process_vm_writev 搬得动。
const CHUNK: usize = 32 * 1024;

/// 在目标栈上占一块固定大小的暂存区，之后每块都写回这一处。千万不能把每块都当成一次
/// 新分配往下压 —— 2 MB 的镜像那么干会把目标线程的栈拉下去两兆（目标的主线程也就
/// 8 MB 可用），而且我们走的时候也不还回去。
const SCRATCH_LEN: usize = CHUNK;

#[derive(Clone, Copy)]
pub(super) struct RemoteMemfdAddrs {
    pub(super) memfd_create: usize,
    pub(super) write: usize,
    pub(super) lseek: usize,
    pub(super) libc_return: usize,
}

/// memfd_create 的两次尝试用的标志位（先连 MFD_EXEC 一起要，吃 EINVAL 再退回只要 CLOEXEC）。
fn memfd_flag_attempts() -> [usize; 2] {
    [MFD_CLOEXEC | MFD_EXEC, MFD_CLOEXEC]
}

/// 把 reader 的内容按 CHUNK 分块交给 write_chunk —— 真实实现是目标进程里的 write()。
/// 返回总共写进去的字节数。write_chunk 返回实际写下的字节数，短写直接算失败：memfd 的
/// write 要么全写下要么报错，短写说明对面状态不对，别装作写完了往下走。
fn stream_payload(
    reader: &mut dyn Read,
    write_chunk: &mut dyn FnMut(&[u8]) -> Result<usize>,
) -> Result<usize> {
    let mut buf = vec![0u8; CHUNK];
    let mut total = 0usize;
    loop {
        let read = reader
            .read(&mut buf)
            .context("failed to read the payload image")?;
        if read == 0 {
            return Ok(total);
        }
        let written = write_chunk(&buf[..read])?;
        if written != read {
            bail!("short remote write at offset {total}: wrote {written} of {read} bytes");
        }
        total += read;
    }
}

pub(super) fn write_payload_into_remote_memfd<F, G, H>(
    pid: Pid,
    name: &str,
    path: &Path,
    addrs: RemoteMemfdAddrs,
    push_to_remote_stack: &mut F,
    get_remote_errno: &G,
    close_remote: &H,
) -> Result<i32>
where
    F: FnMut(&[u8]) -> Result<usize>,
    G: Fn() -> Result<i32>,
    H: Fn(i32) -> Result<()>,
{
    let name_c = CString::new(name).context("memfd name contains a NUL byte")?;
    let name_ptr = push_to_remote_stack(name_c.as_bytes_with_nul())?;

    let mut fd = -1;
    let mut last_errno = 0;
    for flags in memfd_flag_attempts() {
        let created = remote_c_int_result(sys::remote_call(
            pid,
            addrs.memfd_create,
            addrs.libc_return,
            &[name_ptr, flags],
        )?);
        if created >= 0 {
            fd = created;
            debug!("remote memfd created fd={fd} flags=0x{flags:x}");
            break;
        }
        last_errno = get_remote_errno()?;
    }
    if fd < 0 {
        bail!("remote memfd_create failed: errno={last_errno}");
    }

    let mut file = std::fs::File::open(path)
        .with_context(|| format!("failed to open payload image {}", path.display()))?;

    // 暂存区只占一次，后面每块都写回同一个位置。
    let scratch = push_to_remote_stack(&vec![0u8; SCRATCH_LEN])?;

    let streamed = stream_payload(&mut file, &mut |chunk| {
        sys::write_process_exact(pid, scratch, chunk)
            .context("failed to write a payload chunk into the target scratch buffer")?;
        let wrote = remote_c_int_result(sys::remote_call(
            pid,
            addrs.write,
            addrs.libc_return,
            &[fd as usize, scratch, chunk.len()],
        )?);
        if wrote < 0 {
            bail!("remote write failed: errno={}", get_remote_errno()?);
        }
        Ok(wrote as usize)
    });

    let total = match streamed {
        Ok(total) => total,
        Err(error) => {
            close_after_failure(close_remote, fd, &error);
            return Err(error);
        }
    };

    // 写完文件偏移停在末尾。dlopen 会按 library_fd_offset 去读，先归零更稳（也顺带证明
    // 目标手里那个 fd 确实是个能定位的文件）。
    let seek_res = remote_c_int_result(sys::remote_call(
        pid,
        addrs.lseek,
        addrs.libc_return,
        &[fd as usize, 0, libc::SEEK_SET as usize],
    )?);
    if seek_res != 0 {
        let errno = get_remote_errno()?;
        let error =
            anyhow::anyhow!("remote lseek back to 0 failed: result={seek_res} errno={errno}");
        close_after_failure(close_remote, fd, &error);
        return Err(error);
    }

    info!("payload image written into remote memfd fd={fd} bytes={total}");
    Ok(fd)
}

/// 失败路径上先试着把目标那个 fd 关掉，关不掉也只是记一笔 —— 不能把真正的错盖掉。
fn close_after_failure<H>(close_remote: &H, fd: i32, original: &anyhow::Error)
where
    H: Fn(i32) -> Result<()>,
{
    if let Err(close_error) = close_remote(fd) {
        warn!("failed to close remote memfd {fd} after {original:#}: {close_error:#}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memfd_flags_ask_for_exec_first() {
        let [first, second] = memfd_flag_attempts();
        assert_eq!(
            first & MFD_EXEC,
            MFD_EXEC,
            "dlopen 要的 memfd 必须可执行，第一个尝试就得带上 MFD_EXEC"
        );
        assert_eq!(first & MFD_CLOEXEC, MFD_CLOEXEC);
        assert_eq!(
            second, MFD_CLOEXEC,
            "老内核不认 exec 位，退回去只留 CLOEXEC"
        );
    }

    #[test]
    fn stream_payload_writes_every_chunk_in_order() {
        let data: Vec<u8> = (0..(CHUNK * 2 + 7)).map(|i| (i % 251) as u8).collect();
        let mut reader = std::io::Cursor::new(data.clone());
        let mut sink: Vec<u8> = Vec::new();
        let mut chunks: Vec<usize> = Vec::new();
        let total = stream_payload(&mut reader, &mut |chunk| {
            chunks.push(chunk.len());
            sink.extend_from_slice(chunk);
            Ok(chunk.len())
        })
        .expect("streaming the payload must succeed");

        assert_eq!(total, data.len());
        assert_eq!(sink, data, "字节顺序不能变");
        assert_eq!(chunks, vec![CHUNK, CHUNK, 7]);
    }

    #[test]
    fn stream_payload_writes_every_chunk_to_one_scratch_pointer() {
        let data: Vec<u8> = (0..(CHUNK + 3)).map(|i| (i % 97) as u8).collect();
        let mut reader = std::io::Cursor::new(data.clone());
        let scratch = 0x0000_7f11_2200_0000usize;
        let mut writes: Vec<(usize, Vec<u8>)> = Vec::new();
        let total = stream_payload(&mut reader, &mut |chunk| {
            writes.push((scratch, chunk.to_vec()));
            Ok(chunk.len())
        })
        .expect("streaming the payload must succeed");

        assert_eq!(total, data.len());
        assert_eq!(writes.len(), 2);
        assert!(
            writes.iter().all(|(ptr, _)| *ptr == scratch),
            "每块都得写回同一处暂存区，不能把目标的栈越压越深"
        );
        assert_eq!(writes[0].1.as_slice(), &data[..CHUNK]);
        assert_eq!(writes[1].1.as_slice(), &data[CHUNK..]);
    }

    #[test]
    fn stream_payload_rejects_a_short_write() {
        let mut reader = std::io::Cursor::new(vec![7u8; 4096]);
        let error = stream_payload(&mut reader, &mut |chunk| Ok(chunk.len() - 1))
            .expect_err("短写必须当失败");
        assert!(
            error.to_string().contains("short remote write"),
            "错误里要说清是短写: {error:#}"
        );
    }

    #[test]
    fn stream_payload_allows_an_empty_payload() {
        let mut reader = std::io::Cursor::new(Vec::<u8>::new());
        let total = stream_payload(&mut reader, &mut |_| Ok(0)).expect("空 payload 也算成功");
        assert_eq!(total, 0);
    }
}
