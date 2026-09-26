use super::super::*;
use crate::hook::soter::SoterCall;

fn prepared_bc_reply(fd: c_int, reply_index: usize) -> Option<PreparedBcReply> {
    let connection = binder_state_key(fd);
    PREPARED_BC_REPLIES.with(|prepared| {
        prepared
            .borrow()
            .get(&connection)
            .and_then(|replies| replies.get(reply_index))
            .copied()
    })
}

fn remember_prepared_bc_reply(fd: c_int, prepared_reply: PreparedBcReply) {
    let connection = binder_state_key(fd);
    PREPARED_BC_REPLIES.with(|prepared| {
        prepared
            .borrow_mut()
            .entry(connection)
            .or_default()
            .push_back(prepared_reply);
    });
}

fn take_prepared_bc_reply(fd: c_int) -> Option<PreparedBcReply> {
    let connection = binder_state_key(fd);
    PREPARED_BC_REPLIES.with(|prepared| {
        let mut prepared = prepared.borrow_mut();
        let replies = prepared.get_mut(&connection)?;
        let reply = replies.pop_front();
        if replies.is_empty() {
            prepared.remove(&connection);
        }
        reply
    })
}

pub(super) fn complete_prepared_bc_reply(
    fd: c_int,
    observed_data_ptr: usize,
) -> Option<NativeBinderRetirement> {
    let connection = binder_state_key(fd);
    let Some(prepared) = take_prepared_bc_reply(fd) else {
        return commit_bc_reply(connection, None, observed_data_ptr);
    };
    let data_ptr = prepared.data_ptr;
    if data_ptr != observed_data_ptr {
        warn!(
            "event=reply consumed prepared BC_REPLY with changed data pointer fd={} prepared=0x{:x} observed=0x{:x}",
            fd, data_ptr, observed_data_ptr
        );
    }
    commit_bc_reply(connection, prepared.frame_id, data_ptr)
}

pub(super) fn abort_prepared_bc_replies(fd: c_int) {
    abort_prepared_bc_replies_for_connection(binder_state_key(fd));
}

pub(in crate::hook::intercept) fn abort_prepared_bc_replies_for_connection(
    connection: BinderStateKey,
) {
    let prepared = PREPARED_BC_REPLIES.with(|prepared| prepared.borrow_mut().remove(&connection));
    if let Some(prepared) = prepared {
        for reply in prepared {
            abort_bc_reply(connection, reply.frame_id, reply.data_ptr);
        }
    }
}

pub(super) unsafe fn write_buffer_is_safe_to_intercept(write: &[u8]) -> bool {
    let mut offset = 0usize;
    while offset < write.len() {
        if write.len() - offset < size_of::<u32>() {
            return false;
        }
        let cmd = std::ptr::read_unaligned(write.as_ptr().add(offset) as *const u32);
        offset += size_of::<u32>();
        let cmd_size = _ioc_size(cmd);
        if cmd_size > write.len() - offset {
            return false;
        }
        let command_end = offset + cmd_size;
        let cmd_nr = _ioc_nr(cmd);
        if _ioc_dir(cmd) == 1 && matches!(cmd_nr, BC_REPLY_NR | BC_REPLY_SG_NR) {
            let expected_size = if cmd_nr == BC_REPLY_SG_NR {
                size_of::<binder_transaction_data_sg>()
            } else {
                size_of::<binder_transaction_data>()
            };
            if cmd_size != expected_size {
                return false;
            }
            let tr = std::ptr::read_unaligned(
                write.as_ptr().add(offset) as *const binder_transaction_data
            );
            if TransactionPayloadShadow::read(&tr).is_none() {
                return false;
            }
        }
        offset = command_end;
    }
    true
}

pub(super) unsafe fn rewrite_inbound_free_buffers(
    connection: BinderStateKey,
    write: &mut Vec<u8>,
) -> (Vec<(usize, usize)>, usize) {
    let mut offset = 0usize;
    let mut rewritten = Vec::new();
    // 宿主把我们合成回复的那块 parcel 释放了：这条命令得整条抹掉 —— 内核对那个
    // 指针一无所知，真发出去就是 binder_user_error + EINVAL，整个 ioctl 批次都废。
    let mut dropped: Vec<(usize, usize)> = Vec::new();
    while write.len().saturating_sub(offset) >= size_of::<u32>() {
        let command_start = offset;
        let cmd = std::ptr::read_unaligned(write.as_ptr().add(offset) as *const u32);
        offset += size_of::<u32>();
        let cmd_size = _ioc_size(cmd);
        if cmd_size > write.len().saturating_sub(offset) {
            break;
        }
        let command_end = offset + cmd_size;
        if _ioc_dir(cmd) == 1
            && _ioc_nr(cmd) == BC_FREE_BUFFER_NR
            && cmd_size == size_of::<libc::c_ulong>()
        {
            let payload = write.as_mut_ptr().add(offset) as *mut libc::c_ulong;
            let shadow_buffer = std::ptr::read_unaligned(payload) as usize;
            if is_soter_owned_buffer(connection, shadow_buffer) {
                dropped.push((command_start, command_end));
                release_intercepted_soter(connection, shadow_buffer);
            } else if let Some(original_buffer) =
                inbound_transaction_original_buffer(connection, shadow_buffer)
            {
                std::ptr::write_unaligned(payload, original_buffer);
                rewritten.push((command_end, shadow_buffer));
            }
        }
        offset = command_end;
    }
    if dropped.is_empty() {
        return (rewritten, 0);
    }
    let removed = dropped.iter().map(|(start, end)| end - start).sum();
    // 从后往前抹，前面的命令坐标就不会被搅动。
    for (start, end) in dropped.iter().rev() {
        write.drain(*start..*end);
    }
    // 那些窗口的结束位置得往前挪，挪多少 = 排在它前面被删掉的命令总长。
    for (end, _) in rewritten.iter_mut() {
        let shifted: usize = dropped
            .iter()
            .filter(|(_, drop_end)| drop_end <= end)
            .map(|(start, drop_end)| drop_end - start)
            .sum();
        *end -= shifted;
    }
    (rewritten, removed)
}

pub(super) fn mark_inbound_free_buffers_consumed(
    connection: BinderStateKey,
    rewritten: &[(usize, usize)],
    write_consumed: usize,
) {
    let mut entries = INBOUND_TRANSACTION_SHADOWS
        .lock()
        .expect("inbound transaction shadow map poisoned");
    for &(_, shadow_buffer) in rewritten
        .iter()
        .take_while(|(end, _)| *end <= write_consumed)
    {
        if let Some(shadow) = entries.get_mut(&(connection, shadow_buffer)) {
            if shadow.state == InboundTransactionShadowState::Live {
                shadow.state = InboundTransactionShadowState::KernelFreedPendingAck;
            }
        }
    }
}

pub(in crate::hook::intercept) fn complete_inbound_free_buffers(
    connection: BinderStateKey,
    rewritten: &[(usize, usize)],
    write_consumed: usize,
) {
    let mut entries = INBOUND_TRANSACTION_SHADOWS
        .lock()
        .expect("inbound transaction shadow map poisoned");
    for &(_, shadow_buffer) in rewritten
        .iter()
        .take_while(|(end, _)| *end <= write_consumed)
    {
        if entries
            .get(&(connection, shadow_buffer))
            .is_some_and(|shadow| {
                shadow.state == InboundTransactionShadowState::KernelFreedPendingAck
            })
        {
            entries.remove(&(connection, shadow_buffer));
        }
    }
}

/// 拿去换掉真 handle 的那个无效值。挑一个远超任何真实 ref 号的数 —— binder 的
/// ref 号是从 1 往上发的，内核在它自己的 rb-tree 里查不到就回 BR_FAILED_REPLY。
/// 代价是内核会打一条 binder_user_error，可接受：SOTER 调用不频繁。
const SOTER_VOID_HANDLE: u32 = 0x7fff_ffff;

/// 扣下一条出站 SOTER 调用：备好真回复、把目标 handle 换坏。
///
/// 备不出回复（本地后端不认识这个号、或者参数不够）就什么也不动，让这条调用照
/// 原样去真 HAL —— 宁可慢一点，也别把宿主坑在一条它永远等不到的回复上。
fn intercept_soter_call(fd: c_int, tr: &mut binder_transaction_data, call: &SoterCall) {
    let Some((framed, parcel)) = crate::hook::soter::build_br_reply(call) else {
        // 本地后端不认识这个号、或者参数不够 —— 放它去真 HAL。宿主等的是真回复，
        // 比让它永远等不到要好。
        log::info!(
            "event=soter intercept skipped side=hal code={} uid={:?} (no local answer)",
            call.code,
            call.uid
        );
        return;
    };
    let connection = binder_state_key(fd);
    let framed_len = framed.len();
    remember_intercepted_soter(connection, framed, parcel);
    // target 是个普通结构体，不是 union，改它不用 unsafe（tr 本身是本地副本，
    // 不会碰到宿主内存）。
    tr.target.handle = SOTER_VOID_HANDLE;
    // 这条就是"拦截真的动手了"的无歧义凭据：出现它说明 handle 已被换坏、合成回复
    // 已备好，read 侧随后会把内核的 BR_FAILED_REPLY 就地改成这条回复。
    log::info!(
        "event=soter intercept armed side=hal code={} uid={:?} framed_len={} handle=0x{:x}",
        call.code,
        call.uid,
        framed_len,
        SOTER_VOID_HANDLE
    );
}

pub(super) unsafe fn parse_write_buffer(
    fd: c_int,
    write: &mut [u8],
) -> Vec<(usize, Option<usize>, bool, Option<NativeBinderRetirement>)> {
    let base = write.as_mut_ptr();
    let total_size = write.len();
    let mut offset = 0usize;
    let mut completion_commands = Vec::new();
    let mut reply_count = 0;
    while offset < total_size {
        let command_start = base.add(offset);
        if total_size.saturating_sub(offset) < size_of::<u32>() {
            warn!(
                "truncated binder write command header: remaining={}",
                total_size.saturating_sub(offset)
            );
            break;
        }

        let cmd = std::ptr::read_unaligned(command_start as *const u32);
        offset += size_of::<u32>();
        let payload = base.add(offset);

        let cmd_size = _ioc_size(cmd);
        if cmd_size > total_size.saturating_sub(offset) {
            warn!(
                "truncated binder write command payload: nr={} size={} remaining={}",
                _ioc_nr(cmd),
                cmd_size,
                total_size.saturating_sub(offset)
            );
            break;
        }

        let cmd_nr = _ioc_nr(cmd);
        let is_write = _ioc_dir(cmd) == 1;

        if is_write {
            match cmd_nr {
                BC_TRANSACTION_NR | BC_REPLY_NR | BC_TRANSACTION_SG_NR | BC_REPLY_SG_NR => {
                    let is_sg = matches!(cmd_nr, BC_TRANSACTION_SG_NR | BC_REPLY_SG_NR);
                    let is_reply = matches!(cmd_nr, BC_REPLY_NR | BC_REPLY_SG_NR);
                    let expected_size = if is_sg {
                        size_of::<binder_transaction_data_sg>()
                    } else {
                        size_of::<binder_transaction_data>()
                    };
                    if cmd_size == expected_size {
                        let tr_ptr = payload as *mut binder_transaction_data;
                        let mut tr = std::ptr::read_unaligned(tr_ptr);
                        let prepared = is_reply
                            .then(|| prepared_bc_reply(fd, reply_count))
                            .flatten();
                        if let Some(prepared) = prepared {
                            tr = prepared.transaction;
                        }
                        let mut shadow = None;
                        let inspectable = if let Some(mut payload) =
                            TransactionPayloadShadow::read(&tr)
                        {
                            payload.install(&mut tr);
                            shadow = Some(payload);
                            true
                        } else {
                            warn!(
                                "event=binder skipped unsafe {} parcel fd={} data_size={} offsets_size={}",
                                if is_reply { "reply" } else { "transaction" },
                                fd,
                                tr.data_size,
                                tr.offsets_size
                            );
                            false
                        };
                        let label = match cmd_nr {
                            BC_TRANSACTION_NR => "BC_TRANSACTION",
                            BC_REPLY_NR => "BC_REPLY",
                            BC_TRANSACTION_SG_NR => "BC_TRANSACTION_SG",
                            BC_REPLY_SG_NR => "BC_REPLY_SG",
                            _ => unreachable!(),
                        };
                        let frame_id = if is_reply && prepared.is_none() && inspectable {
                            Some(handle_bc_reply(binder_state_key(fd), &mut tr))
                        } else {
                            None
                        };
                        if inspectable {
                            log_write_transaction(label, &tr);
                            if !is_reply {
                                // 出站的 transaction 里可能就有 SOTER 的：宿主进程
                                // 把 App 的请求转成对高通 HAL 的调用发出去。认出来了、
                                // 而且我们本地答得了的话，就把目标 handle 换坏 ——
                                // 命令本体原样留着（偏移记账全不用动），内核查不到那个
                                // ref，会照自己的规矩回一个 BR_FAILED_REPLY，我们在读
                                // 阶段把它换成真回复。
                                // SAFETY: 上面 payload shadow 已经把这段换成本进程里的
                                // 副本，tr.data 指向 tr.data_size 个可读字节。
                                if let Some(call) = unsafe { crate::hook::soter::observe(&tr) } {
                                    if crate::hook::soter::interceptable(&call) {
                                        intercept_soter_call(fd, &mut tr, &call);
                                    }
                                }
                            }
                        }
                        if let Some(shadow) = shadow.as_ref() {
                            shadow.restore(&mut tr);
                        }
                        if let Some(frame_id) = frame_id {
                            remember_prepared_bc_reply(
                                fd,
                                PreparedBcReply {
                                    frame_id,
                                    data_ptr: tr.data.ptr.buffer as usize,
                                    transaction: tr,
                                },
                            );
                        }
                        std::ptr::write_unaligned(tr_ptr, tr);
                        completion_commands.push((
                            offset + cmd_size,
                            is_reply.then_some(tr.data.ptr.buffer as usize),
                            !is_reply && (tr.flags & TF_ONE_WAY) == 0,
                            None,
                        ));
                    } else if !is_sg {
                        warn!(
                            "unexpected binder write command payload size {} for nr={}",
                            cmd_size, cmd_nr
                        );
                    } else {
                        warn!(
                            "unexpected binder write SG payload size {} for nr={}",
                            cmd_size, cmd_nr
                        );
                    }
                    if cmd_size != expected_size {
                        completion_commands.push((
                            offset + cmd_size,
                            is_reply.then_some(0),
                            false,
                            None,
                        ));
                    }
                    if is_reply {
                        reply_count += 1;
                    }
                }
                _ => {}
            }
            if cmd == BC_ACQUIRE_DONE_CMD && cmd_size == size_of::<binder_ptr_cookie>() {
                let ptr_cookie = std::ptr::read_unaligned(payload as *const binder_ptr_cookie);
                let target = LocalBinderTarget {
                    ptr: ptr_cookie.ptr,
                    cookie: ptr_cookie.cookie,
                };
                completion_commands.push((
                    offset + cmd_size,
                    None,
                    false,
                    operation_publication_pending_acquire(target, binder_state_key(fd)),
                ));
            }
        }

        offset += cmd_size;
    }

    completion_commands
}

#[cfg(test)]
mod tests;
