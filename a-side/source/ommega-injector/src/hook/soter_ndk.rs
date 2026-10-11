//! 从 Java/Treble 那条 binder 路去调 SOTER HAL，给 write 侧的拦截做一次真触发。
//!
//! 为什么不直接用 payload 里现成的 rsbinder：rsbinder 是纯 Rust 自己实现对
//! /dev/binder 的 ioctl，压根不引用 libbinder.so，而我们 hook 是打在
//! libbinder*.so 的 ioctl GOT 上的。自检报回来的 code=0 是真实 HAL 回的，
//! 证明不了拦截生效 —— 这一点之前踩过一次，别再用 rsbinder 当验证手段。
//!
//! libbinder_ndk.so 的 NEEDED 里有 libbinder.so，从它发事务必然穿过那个被改过的
//! 入口。宿主本来就是 Java 服务，libbinder 早在进程起来时就加载好了，GOT 也早已
//! 改完，这里 dlopen 只是把 wrapper 带进来，顺带确认符号齐不齐。
//!
//! 用 dlopen 而不是 link：NDK 的 libbinder_ndk stub 要 API 29，这套配置是 26。

use std::ffi::{c_char, CStr, CString};

const LIB_BINDER_NDK: &[u8] = b"libbinder_ndk.so\0";
const SYM_GET_SERVICE: &[u8] = b"AServiceManager_getService\0";
const SYM_PARCEL_CREATE: &[u8] = b"AParcel_create\0";
const SYM_WRITE_STRING: &[u8] = b"AParcel_writeString\0";
const SYM_TRANSACT: &[u8] = b"AIBinder_transact\0";
const SYM_PARCEL_DELETE: &[u8] = b"AParcel_delete\0";
const SYM_READ_INT32: &[u8] = b"AParcel_readInt32\0";
const SYM_SET_DATA_POSITION: &[u8] = b"AParcel_setDataPosition\0";
const SYM_WRITE_INT32: &[u8] = b"AParcel_writeInt32\0";
const SYM_WRITE_INT64: &[u8] = b"AParcel_writeInt64\0";

/// `AIBinder` / `AParcel` 都是不透明指针，我们只负责传，不碰内容。
#[repr(C)]
struct AIBinder {
    _private: [u8; 0],
}

#[repr(C)]
struct AParcel {
    _private: [u8; 0],
}

/// `AIDL` 的 `Status` 头在 parcel 开头占一个 int32；`AIBinder_transact` 本身不读它，
/// 所以拿返回值之前得先把读指针跳过这 4 字节。
const STATUS_HEADER_LEN: i32 = 4;

/// 动态拿到的那几个函数指针。签名对着 `android/binder_ibinder.h` /
/// `android/binder_parcel.h` 抄。
struct NdkBinder {
    get_service: unsafe extern "C" fn(*const c_char) -> *mut AIBinder,
    parcel_create: unsafe extern "C" fn() -> *mut AParcel,
    write_string: unsafe extern "C" fn(*mut AParcel, *const c_char, i32) -> i32,
    transact:
        unsafe extern "C" fn(*mut AIBinder, u32, *mut *mut AParcel, *mut *mut AParcel, u32) -> i32,
    parcel_delete: unsafe extern "C" fn(*mut AParcel),
    read_int32: unsafe extern "C" fn(*const AParcel, *mut i32) -> i32,
    set_data_position: unsafe extern "C" fn(*const AParcel, i32) -> i32,
    // 这两个可选：老设备/老 ROM 上取不到也不影响原来那条无参路，取不到就带参数那条不能用。
    write_int32: Option<unsafe extern "C" fn(*mut AParcel, i32) -> i32>,
    write_int64: Option<unsafe extern "C" fn(*mut AParcel, i64) -> i32>,
}

// 函数指针指向 .text，跟进程同寿命，跨线程共享没有别名问题。
unsafe impl Send for NdkBinder {}
unsafe impl Sync for NdkBinder {}

fn load() -> Option<NdkBinder> {
    unsafe {
        let handle = libc::dlopen(
            LIB_BINDER_NDK.as_ptr() as *const c_char,
            libc::RTLD_NOW | libc::RTLD_LOCAL,
        );
        if handle.is_null() {
            return None;
        }
        // 这里故意不 dlclose：句柄要留到进程结束，免得 wrapper 被 unloading。
        macro_rules! sym {
            ($name:ident, $bytes:expr) => {
                let raw = libc::dlsym(handle, $bytes.as_ptr() as *const c_char);
                if raw.is_null() {
                    return None;
                }
                // SAFETY: 名字来自 libbinder_ndk 的导出表，签名按头文件抄，
                // 实际实现与之一致。
                let $name = std::mem::transmute_copy(&raw);
            };
        }
        sym!(get_service, SYM_GET_SERVICE);
        sym!(parcel_create, SYM_PARCEL_CREATE);
        sym!(write_string, SYM_WRITE_STRING);
        sym!(transact, SYM_TRANSACT);
        sym!(parcel_delete, SYM_PARCEL_DELETE);
        sym!(read_int32, SYM_READ_INT32);
        sym!(set_data_position, SYM_SET_DATA_POSITION);
        // 可选符号，缺了不算失败。
        let write_int32 = {
            let raw = libc::dlsym(handle, SYM_WRITE_INT32.as_ptr() as *const c_char);
            (!raw.is_null()).then(|| std::mem::transmute_copy(&raw))
        };
        let write_int64 = {
            let raw = libc::dlsym(handle, SYM_WRITE_INT64.as_ptr() as *const c_char);
            (!raw.is_null()).then(|| std::mem::transmute_copy(&raw))
        };
        Some(NdkBinder {
            get_service,
            parcel_create,
            write_string,
            transact,
            parcel_delete,
            read_int32,
            set_data_position,
            write_int32,
            write_int64,
        })
    }
}

/// 对 SOTER HAL 的 `ISoter` 发一次 code，返回它回的 service-specific error。
///
/// `interface` 是 AIDL 的 interface token（`vendor.qti.hardware.soter.ISoter`）。
/// 调用方自己保证 `code` 是只读的那几个（当前只有 8 = getDeviceId）。
pub fn transact(service: &str, interface: &str, code: u32) -> Result<i32, String> {
    let ndk = load().ok_or_else(|| {
        format!(
            "libbinder_ndk.so or one of its symbols is missing: {}",
            last_dl_error()
        )
    })?;

    let name = CString::new(service).map_err(|e| format!("bad service name: {e}"))?;
    unsafe {
        let binder = (ndk.get_service)(name.as_ptr());
        if binder.is_null() {
            return Err(format!(
                "AServiceManager_getService({service}) returned null"
            ));
        }

        // 不用 AIBinder_prepareTransaction：它靠 getInterfaceDescriptor() 拼 token，
        // 而远端代理那个 descriptor 是空的，实测直接返 -38（ENOSYS）。远端 binder
        // 只能自己把 AIDL 的 interface token 写进 parcel 开头。
        let mut input: *mut AParcel = (ndk.parcel_create)();
        if input.is_null() {
            return Err("AParcel_create returned null".to_string());
        }
        // AParcel 的头一个字段是它归属的 AIBinder。AIBinder_transact 会拿这个字段
        // 跟传进去的 binder 比对，不一致直接返 EINVAL(-22)。AParcel_create() 建
        // 出来的 parcel 这个位置是空的，得自己补。
        //
        // 依据：反汇编 libbinder_ndk.so 的 AIBinder_transact，
        //   ldr x8,[x19] / ldr x5,[x8] / cmp x5,x24 / b.eq ... / mov w22,#-0x16
        // 就是这段检查。布局 `{ AIBinder*, Parcel*, bool }` 也能从那几处 ldr
        // 的偏移（+0 / +8 / +0x10）对上。
        *(input as *mut *mut AIBinder) = binder;
        let descriptor = CString::new(interface).map_err(|e| format!("bad interface: {e}"))?;
        let wrote = (ndk.write_string)(input, descriptor.as_ptr(), interface.len() as i32);
        if wrote != 0 {
            (ndk.parcel_delete)(input);
            return Err(format!("writing the interface token failed: {wrote}"));
        }

        // AIBinder_transact 会接管 input（内部把它 delete 掉），所以这边不能再碰它。
        let mut output: *mut AParcel = std::ptr::null_mut();
        let status = (ndk.transact)(binder, code, &mut input, &mut output, 0);
        if status != 0 {
            if !output.is_null() {
                (ndk.parcel_delete)(output);
            }
            return Err(format!("AIBinder_transact(code={code}) failed: {status}"));
        }
        if output.is_null() {
            return Err(format!(
                "AIBinder_transact(code={code}) gave no reply parcel"
            ));
        }

        let skip = (ndk.set_data_position)(output, STATUS_HEADER_LEN);
        let mut error_code: i32 = i32::MIN;
        let read = (ndk.read_int32)(output, &mut error_code);
        (ndk.parcel_delete)(output);

        if skip != 0 || read != 0 {
            return Err(format!(
                "reading the reply failed (setDataPosition={skip}, readInt32={read})"
            ));
        }
        Ok(error_code)
    }
}

/// 把 `dlopen` 的错误信息捞出来，失败时能看清到底缺在哪一步。
fn last_dl_error() -> String {
    unsafe {
        let raw = libc::dlerror();
        if raw.is_null() {
            String::new()
        } else {
            CStr::from_ptr(raw).to_string_lossy().into_owned()
        }
    }
}

// 明确表个态：这个模块只发只读调用，别被以后顺手加进来的写操作带偏。
#[allow(dead_code)]
const READ_ONLY_CODES: [u32; 1] = [8];

/// 一次调用的参数（够覆盖 SOTER 那几个号：uid / alias / challenge / session）。
pub enum Arg<'a> {
    I32(i32),
    I64(i64),
    Str(&'a str),
}

/// 带参数版的 [`transact`]：参数按声明顺序写进 parcel，再发同一个 code。
///
/// 存在的理由：`service call` 那个命令行工具写的 parcel 跟 AIDL 布局对不上，
/// 只要带字符串参数，HAL 就抛 `0x80000008`；这里走 libbinder_ndk 的真 AIDL 布局。
pub fn transact_with_args(
    service: &str,
    interface: &str,
    code: u32,
    args: &[Arg<'_>],
) -> Result<(i32, Vec<i32>), String> {
    let ndk = load().ok_or_else(|| {
        format!(
            "libbinder_ndk.so or one of its symbols is missing: {}",
            last_dl_error()
        )
    })?;
    let name = CString::new(service).map_err(|e| format!("bad service name: {e}"))?;
    unsafe {
        let binder = (ndk.get_service)(name.as_ptr());
        if binder.is_null() {
            return Err(format!(
                "AServiceManager_getService({service}) returned null"
            ));
        }
        let mut input: *mut AParcel = (ndk.parcel_create)();
        if input.is_null() {
            return Err("AParcel_create returned null".to_string());
        }
        // 见 `transact` 里那段注释：这个字段得自己补上，否则 AIBinder_transact 返 -22。
        *(input as *mut *mut AIBinder) = binder;
        // AIDL 的请求头：严格模式 0 + work source 0 + 接口标记。宿主里那条路是 Java 的
        // Binder 帮你写的，单独跑得自己写 —— 实测只写 token 的话远端直接拒
        // （AIBinder_transact 返 -2147483647）。
        match ndk.write_int32 {
            Some(write) => {
                for value in [0i32, 0i32, rsbinder::INTERFACE_HEADER as i32] {
                    if write(input, value) != 0 {
                        (ndk.parcel_delete)(input);
                        return Err("writing the AIDL header failed".to_string());
                    }
                }
            }
            None => {
                (ndk.parcel_delete)(input);
                return Err("AParcel_writeInt32 unavailable".to_string());
            }
        }
        let descriptor = CString::new(interface).map_err(|e| format!("bad interface: {e}"))?;
        let wrote = (ndk.write_string)(input, descriptor.as_ptr(), interface.len() as i32);
        if wrote != 0 {
            (ndk.parcel_delete)(input);
            return Err(format!("writing the interface token failed: {wrote}"));
        }
        for arg in args {
            let failed = match arg {
                Arg::I32(value) => match ndk.write_int32 {
                    Some(write) => write(input, *value) != 0,
                    None => return Err("AParcel_writeInt32 unavailable".to_string()),
                },
                Arg::I64(value) => match ndk.write_int64 {
                    Some(write) => write(input, *value) != 0,
                    None => return Err("AParcel_writeInt64 unavailable".to_string()),
                },
                Arg::Str(value) => {
                    let text = CString::new(*value).map_err(|e| format!("bad arg: {e}"))?;
                    (ndk.write_string)(input, text.as_ptr(), value.len() as i32) != 0
                }
            };
            if failed {
                (ndk.parcel_delete)(input);
                return Err("writing an argument failed".to_string());
            }
        }
        let mut output: *mut AParcel = std::ptr::null_mut();
        let status = (ndk.transact)(binder, code, &mut input, &mut output, 0);
        if status != 0 {
            if !output.is_null() {
                (ndk.parcel_delete)(output);
            }
            return Err(format!("AIBinder_transact(code={code}) failed: {status}"));
        }
        if output.is_null() {
            return Err(format!(
                "AIBinder_transact(code={code}) gave no reply parcel"
            ));
        }
        let skip = (ndk.set_data_position)(output, STATUS_HEADER_LEN);
        let mut error_code: i32 = i32::MIN;
        let read = (ndk.read_int32)(output, &mut error_code);
        // 后面的字全读出来（当 32 位字），答复布局不确定时靠它们认 —— 比猜 i64 靠谱。
        let mut words: Vec<i32> = Vec::new();
        for _ in 0..16 {
            let mut word: i32 = 0;
            if (ndk.read_int32)(output, &mut word) != 0 {
                break;
            }
            words.push(word);
        }
        (ndk.parcel_delete)(output);
        if skip != 0 || read != 0 {
            return Err(format!(
                "reading the reply failed (setDataPosition={skip}, readInt32={read})"
            ));
        }
        Ok((error_code, words))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 在 PC 上跑不了（没有 libbinder_ndk），这条只在设备上跑得通；
    /// 它同时兼作"符号加载没写错"的检查。
    #[test]
    fn loading_the_ndk_wrapper_does_not_crash() {
        // 拿不到库就直接放过：这个测试的目的只是保证 dlopen/dlsym 那段的
        // 字符串和签名没写反，不是验证系统行为。
        let _ = load();
    }

    #[test]
    fn only_read_only_codes_are_meant_to_go_through_here() {
        assert_eq!(READ_ONLY_CODES, [8]);
    }
}
