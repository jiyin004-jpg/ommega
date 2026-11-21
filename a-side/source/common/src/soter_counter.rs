//! SOTER 的 counter 文件格式：每行 `uid=counter`，全 App 共用一个文件。
//!
//! 两边都要读改写它：注入器那份（SOTER 宿主所在进程，能直开文件时）和 daemon 那份
//! （app 域开不了文件时替它加）。格式和递增规则放在这里，免得两处各写一套越走越偏。
//!
//! 规则：只增不减。App 记着上次看到的号，小回去就当重放、直接删钥匙。

/// 一个新 uid 的起始计数。
pub const COUNTER_BASE: u64 = 1;

/// 从 `uid=counter` 文本里取某个 uid 的计数。
pub fn counter_for(text: &str, uid: i32) -> Option<u64> {
    text.lines().find_map(|line| {
        let (key, value) = line.split_once('=')?;
        if key.trim().parse::<i32>().ok()? != uid {
            return None;
        }
        value.trim().parse::<u64>().ok()
    })
}

/// 把某个 uid 的计数写回去（已有就替换、没有就追加），其它行原样保留。
pub fn set_counter(text: &str, uid: i32, value: u64) -> String {
    let mut out = String::with_capacity(text.len() + 16);
    let mut replaced = false;
    for line in text.lines() {
        let Some((key, _)) = line.split_once('=') else {
            continue;
        };
        if key.trim().parse::<i32>().ok() == Some(uid) {
            out.push_str(&format!("{uid}={value}\n"));
            replaced = true;
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    if !replaced {
        out.push_str(&format!("{uid}={value}\n"));
    }
    out
}

/// 下一次该给的号：盘上那份和内存里那份取大的再 +1，都没有就从 1 开始。
pub fn next_counter(stored: Option<u64>, memory: u64) -> u64 {
    match stored {
        Some(value) => value.max(memory).max(COUNTER_BASE) + 1,
        None => COUNTER_BASE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_uid_starts_at_the_base() {
        assert_eq!(next_counter(None, 0), COUNTER_BASE);
        // 内存里有值也只能往上走，不能回退。
        assert_eq!(next_counter(None, 9), COUNTER_BASE);
    }

    #[test]
    fn the_stored_value_wins_when_it_is_ahead() {
        assert_eq!(next_counter(Some(41), 3), 42);
        assert_eq!(next_counter(Some(3), 41), 42);
    }

    #[test]
    fn other_uids_are_kept_verbatim() {
        let text = "1000=7\n10319=4\n";
        let updated = set_counter(text, 10319, 5);
        assert_eq!(updated, "1000=7\n10319=5\n");
        assert_eq!(counter_for(&updated, 1000), Some(7));
    }

    #[test]
    fn an_unknown_uid_is_appended() {
        let updated = set_counter("1000=7\n", 10319, 1);
        assert_eq!(updated, "1000=7\n10319=1\n");
    }

    /// 解析不认识的行不该把别人的计数读成自己的。
    #[test]
    fn junk_lines_are_ignored() {
        assert_eq!(counter_for("nonsense\n\n10319=8\n", 10319), Some(8));
        assert_eq!(counter_for("10319=x\n", 10319), None);
    }
}
