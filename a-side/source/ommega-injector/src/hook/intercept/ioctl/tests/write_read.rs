use super::*;
use std::sync::atomic::AtomicUsize;

static EFAULT_IOCTL_CALLS: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn efault_ioctl(_fd: c_int, _request: c_int, _arg: *mut c_void) -> c_int {
    EFAULT_IOCTL_CALLS.fetch_add(1, Ordering::SeqCst);
    *libc::__errno() = libc::EFAULT;
    -1
}

#[test]
fn invalid_binder_write_read_input_returns_efault_without_crashing() {
    let _guard = SYNTHETIC_REPLY_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    EFAULT_IOCTL_CALLS.store(0, Ordering::SeqCst);
    let previous = OLD_IOCTL.swap(efault_ioctl as *mut c_void, Ordering::SeqCst);

    assert_eq!(
        unsafe {
            new_ioctl(
                91,
                BINDER_WRITE_READ as c_int,
                std::ptr::dangling_mut::<c_void>(),
            )
        },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EFAULT)
    );

    let mut bwr = binder_write_read {
        write_size: size_of::<u32>(),
        write_consumed: 0,
        write_buffer: 1,
        read_size: 0,
        read_consumed: 0,
        read_buffer: 0,
    };
    assert_eq!(
        unsafe {
            new_ioctl(
                91,
                BINDER_WRITE_READ as c_int,
                (&mut bwr as *mut binder_write_read).cast(),
            )
        },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EFAULT)
    );
    assert_eq!(EFAULT_IOCTL_CALLS.load(Ordering::SeqCst), 1);

    bwr.write_size = 0;
    bwr.write_buffer = 0;
    bwr.read_size = size_of::<u32>();
    bwr.read_buffer = 1;
    assert_eq!(
        unsafe {
            new_ioctl(
                91,
                BINDER_WRITE_READ as c_int,
                (&mut bwr as *mut binder_write_read).cast(),
            )
        },
        -1
    );
    assert_eq!(EFAULT_IOCTL_CALLS.load(Ordering::SeqCst), 2);

    OLD_IOCTL.store(previous, Ordering::SeqCst);
    reset_binder_fd_for_test(91);
    unsafe { *libc::__errno() = 0 };
}

#[test]
fn unsafe_reply_parcels_and_partial_commands_are_not_claimed() {
    let _guard = SYNTHETIC_REPLY_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let fd = 93;
    let connection = binder_state_key(fd);
    let previous = OLD_IOCTL.swap(efault_ioctl as *mut c_void, Ordering::SeqCst);
    let mut tr: binder_transaction_data = unsafe { std::mem::zeroed() };
    tr.data_size = 1;
    tr.data.ptr.buffer = 1;
    let mut write = Vec::new();
    push_unaligned(&mut write, &BC_REPLY_CMD);
    push_unaligned(&mut write, &tr);
    let mut bwr = binder_write_read {
        write_size: write.len(),
        write_consumed: 0,
        write_buffer: write.as_mut_ptr() as libc::c_ulong,
        read_size: 0,
        read_consumed: 0,
        read_buffer: 0,
    };

    reset_pending_reply_frames_for_test(connection, 1);
    assert_eq!(
        unsafe {
            new_ioctl(
                fd,
                BINDER_WRITE_READ as c_int,
                (&mut bwr as *mut binder_write_read).cast(),
            )
        },
        -1
    );
    assert_eq!(pending_reply_frame_claims_for_test(connection), vec![false]);

    tr.data_size = 0;
    tr.data.ptr.buffer = 0;
    write.clear();
    push_unaligned(&mut write, &BC_REPLY_CMD);
    push_unaligned(&mut write, &tr);
    bwr.write_size = write.len();
    bwr.write_consumed = size_of::<u32>() + 1;
    bwr.write_buffer = write.as_mut_ptr() as libc::c_ulong;
    assert_eq!(
        unsafe {
            new_ioctl(
                fd,
                BINDER_WRITE_READ as c_int,
                (&mut bwr as *mut binder_write_read).cast(),
            )
        },
        -1
    );
    assert_eq!(pending_reply_frame_claims_for_test(connection), vec![false]);

    OLD_IOCTL.store(previous, Ordering::SeqCst);
    reset_pending_reply_frames_for_test(connection, 0);
    reset_binder_fd_for_test(fd);
    unsafe { *libc::__errno() = 0 };
}

static DRIVER_SEEN_WRITE_SIZE: AtomicUsize = AtomicUsize::new(0);

/// 假驱动：内核就是这么干的 —— 交给它多少它吃多少，并如实报告吃了多少。
unsafe extern "C" fn consume_everything_ioctl(
    _fd: c_int,
    request: c_int,
    arg: *mut c_void,
) -> c_int {
    assert_eq!(request, BINDER_WRITE_READ as c_int);
    let bwr = &mut *(arg as *mut binder_write_read);
    DRIVER_SEEN_WRITE_SIZE.store(bwr.write_size, Ordering::SeqCst);
    bwr.write_consumed = bwr.write_size;
    0
}

/// 宿主释放我们合成回复的那块 parcel 时，那条 BC_FREE_BUFFER 得整条抹掉（内核对那个
/// 指针一无所知），驱动于是少看见 12 字节。可报回宿主的 write_consumed 必须把这 12 字节
/// 替驱动认下来：宿主的 libbinder 只认「我写出去的字节全被收下了」，一旦
/// `write_consumed < write_size` 它当场 abort ——
/// `Driver did not consume write buffer. err: OK consumed: 80 of 92.`
/// 宿主进程直接没（2026-09-27 02:08:36 pid 15616，/data/tombstones/tombstone_15）。
#[test]
fn dropped_free_buffer_bytes_are_acknowledged_to_the_host() {
    let _guard = SYNTHETIC_REPLY_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let fd = 94;
    let connection = binder_state_key(fd);
    let previous = OLD_IOCTL.swap(consume_everything_ioctl as *mut c_void, Ordering::SeqCst);

    // 造一条「已经扣下来的 SOTER 调用」：这块 parcel 就是宿主待会儿要释放的内存。
    let parcel = crate::parcel::build_plain_reply(&0i32).expect("plain reply should be buildable");
    let owned = parcel.data_ptr() as libc::c_ulong;
    remember_intercepted_soter(connection, vec![0u8; 4], parcel);

    // 写缓冲 = [BC_FREE_BUFFER(我们那块)] + 一条占位命令（命令字 0，dir/size 全 0）。
    let mut write = Vec::new();
    push_unaligned(&mut write, &BC_FREE_BUFFER_CMD);
    push_unaligned(&mut write, &owned);
    push_unaligned(&mut write, &0u32);
    let original_write_size = write.len();
    let dropped = size_of::<u32>() + size_of::<libc::c_ulong>();

    DRIVER_SEEN_WRITE_SIZE.store(usize::MAX, Ordering::SeqCst);
    let mut bwr = binder_write_read {
        write_size: original_write_size,
        write_consumed: 0,
        write_buffer: write.as_mut_ptr() as libc::c_ulong,
        read_size: 0,
        read_consumed: 0,
        read_buffer: 0,
    };
    assert_eq!(
        unsafe {
            new_ioctl(
                fd,
                BINDER_WRITE_READ as c_int,
                (&mut bwr as *mut binder_write_read).cast(),
            )
        },
        0
    );
    // 驱动只看见剥掉那 12 字节之后的流……
    assert_eq!(
        DRIVER_SEEN_WRITE_SIZE.load(Ordering::SeqCst),
        original_write_size - dropped
    );
    // ……但宿主得被告知「你写出去的全被收下了」，否则它自己的 libbinder 会把进程 abort 掉。
    assert_eq!(bwr.write_size, original_write_size);
    assert_eq!(bwr.write_consumed, original_write_size);

    OLD_IOCTL.store(previous, Ordering::SeqCst);
    reset_binder_fd_for_test(fd);
    unsafe { *libc::__errno() = 0 };
}
