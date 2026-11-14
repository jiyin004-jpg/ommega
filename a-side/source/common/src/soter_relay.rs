//! A 端 SOTER 接替转发的线协议：payload 问「这笔 HAL 调用该由谁答」，daemon 回结论。
//!
//! 拦下调用的是注入在 SOTER 宿主里的 payload，宿主是 uid 1000、读不到 A 端配置（0770 的
//! keystore 目录），所以「走远程还是本地」不能由 payload 自己判断，得问跑在别处的 daemon
//! （`top.jiyin004.ommega.IMaintenanceService.forwardSoter`）。
//!
//! blob 布局（小端，两个 crate 共用这一份实现，谁也别另写一套）：
//!
//! ```text
//! [0]      结论：0 = 后面跟着远程答案 / 1 = 用 A 端本地自签那套 / 2 = 透传真 HAL
//! --- 结论不是 0 时到此为止，就 1 个字节 ---
//! [1..5]   答案种类：0 = Code / 1 = Buffer / 2 = Init
//! Code:    [5..9]  code: i32
//! Buffer:  [5..9]  code: i32, [9..13] data_len: u32（0xFFFF_FFFF = 空数据）, [13..] data
//! Init:    [5..9]  status: i32, [9..17] session: i64
//! ```

use std::vec::Vec;

/// 远程给出了答案，后面跟着答案本体。
pub const STATUS_ANSWER: u8 = 0;
/// 远程没答案 → 用 A 端本地自签那套答（等价于接线之前的行为）。
pub const STATUS_LOCAL: u8 = 1;
/// 谁也答不了，而且配置不允许退回本地 → 放这笔调用去真 HAL。
pub const STATUS_PASSTHROUGH: u8 = 2;

/// 只有返回值的答案（generate* / has* / remove*）。
pub const KIND_CODE: u32 = 0;
/// 带 out 参数的答案（export* / getDeviceId / finishSign）。
pub const KIND_BUFFER: u32 = 1;
/// initSign：一个状态码加一个会话号。
pub const KIND_INIT: u32 = 2;

/// `Buffer` 的空数据标记 —— 状态码照给，out 参数为空。
pub const NO_DATA: u32 = u32::MAX;

/// HAL 号码 ↔ op 名。
///
/// **14 槽排布（2 / 6 / 14 是空号）**：soterserver 发 code 5 / 9 时只带 uid，正好对应
/// `generateAskKeyPair(int)` 和 `hasAskAlready(int)`。APK 里那份 `ISoter.java`（1–11 连号）
/// 是没被用到的类，按它读会把该带的 alias/challenge 读丢。
pub const HAL_OPS: [(u32, &str); 11] = [
    (1, "export_ask_public_key"),
    (3, "export_auth_key_public_key"),
    (4, "finish_sign"),
    (5, "generate_ask_key_pair"),
    (7, "generate_auth_key_pair"),
    (8, "get_device_id"),
    (9, "has_ask_already"),
    (10, "has_auth_key"),
    (11, "init_sign"),
    (12, "remove_all_uid_key"),
    (13, "remove_auth_key"),
];

/// HAL 号码对应的 op 名；认不出来返回 `None`（那就别转发）。
pub fn op_for_code(code: u32) -> Option<&'static str> {
    HAL_OPS.iter().find(|(n, _)| *n == code).map(|(_, op)| *op)
}

/// op 名对应的 HAL 号码；不认识的返回 `None`（daemon 侧用这个挡乱来的请求）。
pub fn code_for_op(op: &str) -> Option<u32> {
    HAL_OPS
        .iter()
        .find(|(_, name)| *name == op)
        .map(|(code, _)| *code)
}

/// 远程对这几个 op 会回一段 base64 的 `data`，其余的只回状态码。
pub fn answers_with_data(op: &str) -> bool {
    matches!(
        op,
        "get_device_id" | "export_ask_public_key" | "export_auth_key_public_key" | "finish_sign"
    )
}

/// `initSign` 的答案里除了状态码还有一个会话号。
pub fn answers_with_session(op: &str) -> bool {
    op == "init_sign"
}

// ── 真机 cpu_id 的副本文件 ──────────────────────────────────────────────
//
// SOTER 的身份是 `(cpu_id, uid)` 绑在一起的，而这个号只有真机（B 端 TEE）有。A 端
// daemon 跟服务端要一次 `get_device_id`（服务端只会让真机答这个 op）学到真值并写到
// 下面这份，payload 读它，本地自签那套就报跟真机一模一样的号 —— 两边各答一个号的话
// 检测器两次一对比就报「不一致」。
//
// 位置定在 `/data/misc/ommega/`：SOTER 宿主是 uid 1000，进不去 0770 的 keystore 目录。

/// 副本文件按顺序找，先读到的算（现在只有一个位置）。
pub const CPU_ID_PATHS: [&str; 1] = ["/data/misc/ommega/soter_cpu_id"];

/// daemon 写的那一份（数据根统一在 `/data/misc/ommega`）。
pub const CPU_ID_WRITE_PATH: &str = "/data/misc/ommega/soter_cpu_id";

/// 环境变量覆盖（测试、临时探针用）。
pub const CPU_ID_ENV: &str = "OMMEGA_SOTER_CPU_ID";

/// 真机 cpu_id 的形状：32 个十六进制字符。
///
/// 不卡 `09000000` 前缀：换代次或换 TEE 实现后号头不一样，卡死会把真值当废值丢掉。
pub fn is_cpu_id(text: &str) -> bool {
    text.len() == 32 && text.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// 从副本文件的内容里抠出 cpu_id。
///
/// 认 `soter_cpu_id: <值>` 这种扁平写法（跟 `log_flag` 一个格式），也认整个文件就一行
/// 光秃秃的值；别的键、注释、空行都跳过。抠不出合法值返回 `None`，这里绝不猜。
pub fn parse_cpu_id(text: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let value = match line.split_once(':') {
            Some((key, value)) if key.trim() == "soter_cpu_id" => value.trim(),
            // 有冒号但不是这个键：别把别的配置项的值当成设备号。
            Some(_) => continue,
            None => line,
        };
        if is_cpu_id(value) {
            return Some(value.to_string());
        }
    }
    None
}

/// 一笔调用的去处，以及远程给的答案本体。
///
/// 形状跟 payload 本地那套 `Answer` 一一对应，转换放在 payload 里做：这个模块不认识
/// `Answer`，只负责把字节摆平。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// 只有状态码。
    Code(i32),
    /// 状态码 + 可选的 out 参数。
    Buffer { code: i32, data: Option<Vec<u8>> },
    /// initSign 的状态码 + 会话号。
    Init { status: i32, session: i64 },
    /// 用 A 端本地自签那套答。
    Local,
    /// 别答，放这笔调用去真 HAL。
    Passthrough,
}

impl Outcome {
    /// 摆成 blob。
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Local => vec![STATUS_LOCAL],
            Self::Passthrough => vec![STATUS_PASSTHROUGH],
            Self::Code(code) => {
                let mut out = Vec::with_capacity(9);
                out.push(STATUS_ANSWER);
                out.extend_from_slice(&KIND_CODE.to_le_bytes());
                out.extend_from_slice(&code.to_le_bytes());
                out
            }
            Self::Buffer { code, data } => {
                let mut out = Vec::with_capacity(13 + data.as_ref().map_or(0, Vec::len));
                out.push(STATUS_ANSWER);
                out.extend_from_slice(&KIND_BUFFER.to_le_bytes());
                out.extend_from_slice(&code.to_le_bytes());
                match data {
                    Some(data) => {
                        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
                        out.extend_from_slice(data);
                    }
                    None => out.extend_from_slice(&NO_DATA.to_le_bytes()),
                }
                out
            }
            Self::Init { status, session } => {
                let mut out = Vec::with_capacity(17);
                out.push(STATUS_ANSWER);
                out.extend_from_slice(&KIND_INIT.to_le_bytes());
                out.extend_from_slice(&status.to_le_bytes());
                out.extend_from_slice(&session.to_le_bytes());
                out
            }
        }
    }

    /// 从 blob 读回来。长度不对、种类不认识、数据截断都返回 `None` ——
    /// 调用方拿到 `None` 就当「本地兜底」，宁可走本地也别拿半截数据去拼答复。
    pub fn decode(blob: &[u8]) -> Option<Self> {
        match *blob.first()? {
            STATUS_LOCAL => return Some(Self::Local),
            STATUS_PASSTHROUGH => return Some(Self::Passthrough),
            STATUS_ANSWER => {}
            _ => return None,
        }
        let kind = u32::from_le_bytes(blob.get(1..5)?.try_into().ok()?);
        let first = i32::from_le_bytes(blob.get(5..9)?.try_into().ok()?);
        match kind {
            KIND_CODE => Some(Self::Code(first)),
            KIND_BUFFER => {
                let len = u32::from_le_bytes(blob.get(9..13)?.try_into().ok()?);
                if len == NO_DATA {
                    return Some(Self::Buffer {
                        code: first,
                        data: None,
                    });
                }
                let start = 13usize;
                let end = start.checked_add(len as usize)?;
                Some(Self::Buffer {
                    code: first,
                    data: Some(blob.get(start..end)?.to_vec()),
                })
            }
            KIND_INIT => {
                let session = i64::from_le_bytes(blob.get(9..17)?.try_into().ok()?);
                Some(Self::Init {
                    status: first,
                    session,
                })
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_32_hex_digits_count_as_a_cpu_id() {
        assert!(is_cpu_id("090000005171734c42866bea148b21f5"));
        assert!(is_cpu_id("090000005171734C42866BEA148B21F5"));
        assert!(!is_cpu_id(""));
        assert!(!is_cpu_id("09000000"));
        assert!(!is_cpu_id("090000005171734c42866bea148b21f50"));
        assert!(!is_cpu_id("090000005171734c42866bea148b21fz"));
        assert!(!is_cpu_id("090000005171734c42866bea148b21f \n"));
    }

    #[test]
    fn the_flat_form_and_the_bare_form_both_parse() {
        let expected = Some("090000005171734c42866bea148b21f5".to_string());
        assert_eq!(
            parse_cpu_id("soter_cpu_id: 090000005171734c42866bea148b21f5\n"),
            expected
        );
        assert_eq!(parse_cpu_id("090000005171734c42866bea148b21f5"), expected);
        // 注释、空行、别的键都不该干扰。
        assert_eq!(
            parse_cpu_id("# SOTER\nlog_flag: 0\nsoter_cpu_id: 090000005171734c42866bea148b21f5\n"),
            expected
        );
        // 值形状不对就不认（宁可用兜底，也不能把别的东西当设备号）。
        assert_eq!(parse_cpu_id("soter_cpu_id: 09000000\n"), None);
        assert_eq!(parse_cpu_id("log_flag: 1\n"), None);
        assert_eq!(parse_cpu_id(""), None);
    }

    fn round_trip(outcome: Outcome) {
        let blob = outcome.encode();
        assert_eq!(Outcome::decode(&blob), Some(outcome));
    }

    #[test]
    fn every_shape_survives_a_round_trip() {
        round_trip(Outcome::Local);
        round_trip(Outcome::Passthrough);
        round_trip(Outcome::Code(0));
        round_trip(Outcome::Code(-5));
        round_trip(Outcome::Buffer {
            code: 0,
            data: Some(vec![1, 2, 3, 4]),
        });
        round_trip(Outcome::Buffer {
            code: -5,
            data: None,
        });
        round_trip(Outcome::Buffer {
            code: 0,
            data: Some(Vec::new()),
        });
        round_trip(Outcome::Init {
            status: 0,
            session: 0x0123_4567_89ab_cdef,
        });
    }

    #[test]
    fn a_truncated_buffer_is_not_half_read() {
        let blob = Outcome::Buffer {
            code: 0,
            data: Some(vec![7; 32]),
        }
        .encode();
        for cut in 1..blob.len() {
            assert_eq!(
                Outcome::decode(&blob[..cut]),
                None,
                "a buffer cut at {cut} bytes must not decode"
            );
        }
    }

    #[test]
    fn the_three_tail_statuses_are_one_byte_each() {
        assert_eq!(Outcome::Local.encode().len(), 1);
        assert_eq!(Outcome::Passthrough.encode().len(), 1);
        assert_eq!(Outcome::Code(0).encode().len(), 9);
        assert_eq!(
            Outcome::Buffer {
                code: 0,
                data: Some(vec![0; 826])
            }
            .encode()
            .len(),
            13 + 826
        );
        assert_eq!(
            Outcome::Init {
                status: 0,
                session: 1
            }
            .encode()
            .len(),
            17
        );
    }

    #[test]
    fn an_unknown_status_or_kind_is_rejected() {
        assert_eq!(Outcome::decode(&[]), None);
        assert_eq!(Outcome::decode(&[9]), None);
        assert_eq!(Outcome::decode(&[STATUS_ANSWER]), None);
        let mut blob = Outcome::Code(0).encode();
        blob[1..5].copy_from_slice(&7u32.to_le_bytes());
        assert_eq!(Outcome::decode(&blob), None);
    }

    #[test]
    fn every_hal_code_has_exactly_one_op() {
        assert_eq!(HAL_OPS.len(), 11);
        for (code, op) in HAL_OPS {
            assert_eq!(op_for_code(code), Some(op));
            assert_eq!(code_for_op(op), Some(code));
            assert!(code_for_op(op).is_some(), "{op} must resolve");
        }
        // 空号不认，app 侧那套号码也不认。
        for reserved in [0, 2, 6, 14, 15] {
            assert_eq!(op_for_code(reserved), None, "{reserved} must not map");
        }
        // 没有重号。
        let mut codes: Vec<u32> = HAL_OPS.iter().map(|(code, _)| *code).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), 11);
    }

    #[test]
    fn only_the_out_parameter_ops_report_data() {
        assert!(answers_with_data("export_ask_public_key"));
        assert!(answers_with_data("get_device_id"));
        assert!(!answers_with_data("has_ask_already"));
        assert!(!answers_with_data("remove_auth_key"));
        assert!(answers_with_session("init_sign"));
        assert!(!answers_with_session("finish_sign"));
    }
}
