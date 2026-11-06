//! Android 的 uid 拆分（照 AOSP 的 `UserHandle` / `KernelUid` 那套）。
//!
//! 一个完整 uid = `userId * PER_USER_RANGE + appId`，`PER_USER_RANGE` 是 100000。
//! 机主是 user 0，工作资料是 10/11/12，分身（MIUI / ColorOS 的应用双开、平行空间）
//! 在 user 999。也就是说**同一个包在不同用户下 uid 完全不同**：微信在机主上是
//! 10490，在 user 999 上是 99910490。SOTER 的槽位、钉层、会话本来就按完整 uid
//! 分开存，这里只是把两个数字拆出来，给日志、策略匹配和身份选路用。
//!
//! 几档 uid（AOSP `android_filesystem_config.h`）：
//!   - 10000..=19999  普通应用（appId 落在这一段；加不加 userId 前缀都算）
//!   - 90000..=99999  隔离进程（isolated）。这类进程没有自己的身份，keystore / SOTER
//!     在 AOSP 里本来就不给它开，槽位上不该出现；真出现了按「不是应用」记一笔。
//!   - 1000 以内       系统 / root / shell 之类，不是应用。
//!
//! 注意 `appId` 不看 `userId`，所以「多用户下同一个应用」的唯一判据是
//! `(userId, appId)` 或完整 uid，而不是 appId 一个数。

use serde::Serialize;

/// AOSP `PER_USER_RANGE`：每个用户占 10 万个号。
pub const PER_USER_RANGE: i32 = 100_000;
/// 应用 uid 的起点（`AID_APP_START`）。
pub const AID_APP_START: i32 = 10_000;
/// 应用 uid 的终点（`AID_APP_END`）。
pub const AID_APP_END: i32 = 19_999;
/// 隔离进程起点（`AID_ISOLATED_START`）。
pub const AID_ISOLATED_START: i32 = 90_000;
/// 隔离进程终点（`AID_ISOLATED_END`）。
pub const AID_ISOLATED_END: i32 = 99_999;

/// 拆好的 uid。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Uid {
    /// 请求里那个完整 uid。
    pub raw: i32,
    /// 哪个用户（机主 0、工作资料 10/11、分身 999…）。
    pub user: i32,
    /// 用户内的应用号。
    pub app: i32,
}

impl Uid {
    /// 拆一个 uid。`uid <= 0` 不算合法应用号（`-1` 是 `Process.INVALID_UID`）。
    pub fn parse(raw: i32) -> Option<Uid> {
        if raw <= 0 {
            return None;
        }
        Some(Uid {
            raw,
            user: raw / PER_USER_RANGE,
            app: raw % PER_USER_RANGE,
        })
    }

    /// 是不是普通应用（appId 在 10000..=19999）。分身/多用户只是 user 不同，
    /// appId 这一段不变，所以 user 999 的微信一样算应用。
    pub fn is_app(&self) -> bool {
        (AID_APP_START..=AID_APP_END).contains(&self.app)
    }

    /// 是不是隔离进程（90000..=99999）。
    pub fn is_isolated(&self) -> bool {
        (AID_ISOLATED_START..=AID_ISOLATED_END).contains(&self.app)
    }

    /// 非机主用户（工作资料 / 分身 / 空间）。
    pub fn is_secondary_user(&self) -> bool {
        self.user != 0
    }

    /// 日志里那一格：`10490(user0/app10490)`、`99910490(user999/app10490)`。
    pub fn label(&self) -> String {
        format!("{}(user{}/app{})", self.raw, self.user, self.app)
    }
}

/// 只取用户号，`0` 是机主。非法 uid 当成机主（老调用方的行为）。
pub fn user_of(raw: i32) -> i32 {
    Uid::parse(raw).map(|u| u.user).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primary_user_app() {
        let u = Uid::parse(10490).unwrap();
        assert_eq!((u.user, u.app), (0, 10490));
        assert!(u.is_app());
        assert!(!u.is_secondary_user());
        assert!(!u.is_isolated());
    }

    #[test]
    fn work_profile_app() {
        let u = Uid::parse(1_010_490).unwrap();
        assert_eq!((u.user, u.app), (10, 10490));
        assert!(u.is_app());
        assert!(u.is_secondary_user());
    }

    #[test]
    fn dual_app_user_999() {
        let u = Uid::parse(99_910_490).unwrap();
        assert_eq!((u.user, u.app), (999, 10490));
        assert!(u.is_app(), "分身里的应用还是应用");
        assert!(u.is_secondary_user());
    }

    #[test]
    fn isolated_and_system_are_not_apps() {
        let iso = Uid::parse(99_045).unwrap();
        assert!(iso.is_isolated() && !iso.is_app());
        let sys = Uid::parse(1000).unwrap();
        assert!(!sys.is_app() && !sys.is_isolated() && sys.user == 0);
    }

    #[test]
    fn invalid_uid_is_none() {
        assert!(Uid::parse(0).is_none());
        assert!(Uid::parse(-1).is_none());
        assert_eq!(user_of(-1), 0);
    }

    #[test]
    fn label_carries_user_and_app() {
        assert_eq!(
            Uid::parse(1_010_490).unwrap().label(),
            "1010490(user10/app10490)"
        );
    }
}
