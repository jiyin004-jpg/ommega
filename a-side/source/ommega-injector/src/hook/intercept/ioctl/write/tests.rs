use super::super::super::SYNTHETIC_REPLY_TEST_LOCK;
use super::super::test_support::push_unaligned;
use super::*;
use crate::hook::rewrite::reset_pending_reply_frames_for_test;
use crate::parcel::build_plain_reply;

#[test]
fn write_parser_tracks_transaction_and_reply_completions() {
    let _guard = SYNTHETIC_REPLY_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let _route_guard = crate::tracker::state_test_guard();
    reset_pending_reply_frames_for_test(0, 0);
    let tr: binder_transaction_data = unsafe { std::mem::zeroed() };
    let mut write = Vec::new();
    let bc_transaction_cmd = BC_REPLY_CMD - BC_REPLY_NR + BC_TRANSACTION_NR;
    push_unaligned(&mut write, &bc_transaction_cmd);
    push_unaligned(&mut write, &tr);
    push_unaligned(&mut write, &BC_REPLY_CMD);
    push_unaligned(&mut write, &tr);
    push_unaligned(&mut write, &BC_ACQUIRE_DONE_CMD);
    let acquire_target = LocalBinderTarget {
        ptr: 0x1234,
        cookie: 0x5678,
    };
    let acquire_retirement = register_operation_publication_for_test(acquire_target);
    let connection = binder_state_key(20);
    bind_operation_publication_connection(acquire_retirement, connection);
    assert_eq!(
        mark_operation_publication_acquire_pending(acquire_target, connection),
        Some(acquire_retirement)
    );
    push_unaligned(
        &mut write,
        &binder_ptr_cookie {
            ptr: acquire_target.ptr,
            cookie: acquire_target.cookie,
        },
    );

    let mut app_replies = Vec::new();
    let completions = unsafe { parse_write_buffer(20, &mut write, &mut app_replies) };
    assert_eq!(completions.len(), 3);
    assert_eq!(completions[0].1, None);
    assert!(completions[0].2);
    assert_eq!(completions[0].3, None);
    assert_eq!(completions[1].1, Some(0));
    assert!(!completions[1].2);
    assert_eq!(completions[1].3, None);
    assert_eq!(completions[2].3, Some(acquire_retirement));
    abort_prepared_bc_replies(20);
    cancel_operation_publication_acquire_pending(acquire_retirement);
    finish_local_operation_publication(acquire_retirement);
}

#[test]
fn inbound_shadow_free_is_translated_and_released_only_after_consumption() {
    let _guard = SYNTHETIC_REPLY_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let connection = binder_state_key(20);
    clear_inbound_transaction_shadows(connection);
    let original = [1u8, 2, 3, 4];
    let mut tr: binder_transaction_data = unsafe { std::mem::zeroed() };
    tr.data_size = original.len();
    tr.data.ptr.buffer = original.as_ptr() as libc::c_ulong;
    let shadow = unsafe { TransactionPayloadShadow::read(&tr) }
        .expect("readable transaction should create a shadow");
    let shadow_buffer = retain_inbound_transaction_shadow(connection, shadow);
    publish_inbound_transaction_shadows(connection, &[shadow_buffer]);

    let mut write = Vec::new();
    push_unaligned(&mut write, &BC_FREE_BUFFER_CMD);
    push_unaligned(&mut write, &shadow_buffer);
    push_unaligned(&mut write, &BC_REPLY_CMD);
    assert!(!unsafe { write_buffer_is_safe_to_intercept(&write) });

    let (rewritten, removed) = unsafe { rewrite_inbound_free_buffers(connection, &mut write) };
    let command_end = size_of::<u32>() + size_of::<libc::c_ulong>();
    assert_eq!(removed, 0);
    assert_eq!(rewritten, vec![(command_end, shadow_buffer)]);
    assert_eq!(
        unsafe {
            std::ptr::read_unaligned(write.as_ptr().add(std::mem::size_of::<u32>()) as *const usize)
        },
        original.as_ptr() as usize
    );

    complete_inbound_free_buffers(connection, &rewritten, command_end - 1);
    assert_eq!(
        inbound_transaction_original_buffer(connection, shadow_buffer),
        Some(original.as_ptr() as libc::c_ulong)
    );
    mark_inbound_free_buffers_consumed(connection, &rewritten, command_end);
    complete_inbound_free_buffers(connection, &rewritten, command_end);
    assert_eq!(
        inbound_transaction_original_buffer(connection, shadow_buffer),
        None
    );
}

#[test]
fn our_own_reply_buffer_gets_its_free_command_dropped_whole() {
    let _guard = SYNTHETIC_REPLY_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // 换一个 connection，别和上面那些用例抢同一个队列。
    let connection = binder_state_key(77);
    // 造一条"已经扣下来的 SOTER 调用"：parcel 就是宿主待会儿要释放的那块内存。
    let parcel = build_plain_reply(&0i32).expect("plain reply should be buildable");
    let owned = parcel.data_ptr() as usize;
    remember_intercepted_soter(connection, vec![0u8; 4], parcel);

    let mut write = Vec::new();
    push_unaligned(&mut write, &BC_FREE_BUFFER_CMD);
    push_unaligned(&mut write, &owned);
    // 后面跟一条无关命令：它应该原地不动、只是往前挪。命令字 0 的 dir/size 都是 0，
    // rewrite 那圈只认 BC_FREE_BUFFER（dir == 1），所以它就是个纯粹的占位。
    push_unaligned(&mut write, &0u32);
    let total = write.len();

    let (rewritten, removed) = unsafe { rewrite_inbound_free_buffers(connection, &mut write) };
    // 不是 inbound shadow，所以不进 rewritten；但命令得整条没了。
    assert!(rewritten.is_empty());
    assert_eq!(removed, size_of::<u32>() + size_of::<libc::c_ulong>());
    assert_eq!(write.len(), total - removed);
    assert_eq!(
        unsafe { std::ptr::read_unaligned(write.as_ptr() as *const u32) },
        0u32
    );
    // 记录也一并清了，不然宿主下次再释放同一个地址会重复命中。
    assert!(!is_soter_owned_buffer(connection, owned));
}

/// 宿主回给 App 的那笔 BC_REPLY 得被换成我们自己的 parcel：指针、长度都指向我们的，
/// TF_STATUS_CODE 也得清掉（不清客户端会把答复当错误码读）。
///
/// 用 12 号（`getVersion`）做样本：它不需要问 daemon，纯本地就能出一份答复，正好把
/// 「待答 → 拼 parcel → 换 copy 源」这一整条串起来。
#[test]
fn the_hosts_app_reply_is_replaced_by_ours() {
    let _guard = SYNTHETIC_REPLY_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    std::env::set_var("OMMEGA_SOTER_APP_SERVE", "1");
    crate::hook::soter::stash_app_call_for_test(
        crate::hook::soter::SoterCall {
            hal: false,
            hidl: false,
            has_return_code: false,
            code: 12,
            wire_code: 12,
            op: "getVersion",
            uid: None,
            alias: None,
            challenge: None,
            session: None,
            key: None,
            caller_uid: None,
            data_size: 0,
        },
        10349,
    );

    // 宿主自己那份答复（壳子回的 -200 那种形状）放一块真内存里，让它可读。
    let host_reply = [0u8, 0, 0, 0, 1, 0, 0, 0, 0x38, 0xff, 0xff, 0xff];
    let mut tr: binder_transaction_data = unsafe { std::mem::zeroed() };
    tr.data_size = host_reply.len();
    tr.data.ptr.buffer = host_reply.as_ptr() as libc::c_ulong;
    // 故意带上「这是一个错误码」的标：换完之后必须被清掉。
    tr.flags = crate::hook::binder::TF_STATUS_CODE;
    let mut write = Vec::new();
    push_unaligned(&mut write, &BC_REPLY_CMD);
    push_unaligned(&mut write, &tr);

    let mut app_replies = Vec::new();
    let _ = unsafe { parse_write_buffer(20, &mut write, &mut app_replies) };

    assert_eq!(app_replies.len(), 1, "着一笔应该归我们答");
    let ours = &app_replies[0];
    let (patched_size, patched_buffer, patched_flags) = unsafe {
        let patched = std::ptr::read_unaligned(
            write.as_ptr().add(std::mem::size_of::<u32>()) as *const binder_transaction_data
        );
        (patched.data_size, patched.data.ptr.buffer, patched.flags)
    };
    assert_eq!(patched_size, ours.data_size(), "长度指向我们的 parcel");
    assert_eq!(
        patched_buffer as usize,
        ours.data_ptr() as usize,
        "copy 源换成我们的了"
    );
    assert_eq!(
        patched_flags & crate::hook::binder::TF_STATUS_CODE,
        0,
        "错误码标得清掉，否则客户端把答复当异常读"
    );
    let bytes = unsafe { std::slice::from_raw_parts(ours.data_ptr(), ours.data_size()) };
    assert_eq!(
        &bytes[..8],
        &[0, 0, 0, 0, 1, 0, 0, 0],
        "Status ok + 版本号 1"
    );

    // 一笔只认一次：再来一笔 BC_REPLY 没有待答的请求，就不该动它。
    let mut write2 = Vec::new();
    push_unaligned(&mut write2, &BC_REPLY_CMD);
    push_unaligned(&mut write2, &tr);
    let mut app_replies2 = Vec::new();
    let _ = unsafe { parse_write_buffer(20, &mut write2, &mut app_replies2) };
    assert!(app_replies2.is_empty(), "没有待答请求时不许动宿主的答复");

    crate::hook::soter::clear_app_call_for_test();
    std::env::remove_var("OMMEGA_SOTER_APP_SERVE");
}
