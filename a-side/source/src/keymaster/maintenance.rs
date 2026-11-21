use anyhow::{Context, Result};
use rsbinder::{Interface, Strong};

use crate::android::hardware::security::keymint::{
    ErrorCode::ErrorCode, IKeyMintDevice::IKeyMintDevice, SecurityLevel::SecurityLevel,
};
use crate::android::security::maintenance::IKeystoreMaintenance::{
    BnKeystoreMaintenance, IKeystoreMaintenance,
};
use crate::android::system::keystore2::{
    Domain::Domain, KeyDescriptor::KeyDescriptor, ResponseCode::ResponseCode,
};
use crate::err;
use crate::global::{DB, SUPER_KEY};
use crate::keymaster::db::{KeyEntryLoadBits, KeyType};
use crate::keymaster::error::{into_logged_binder, map_km_error, KsError};
use crate::keymaster::keymint_device::{get_keymint_wrapper, KeyMintWrapper};
use crate::keymaster::permission::{
    check_forwarded_context, check_key_permission, check_keystore_permission,
    check_manage_users_permission, require_ommega_ctx, resolve_caller_info, KeyPerm, KeystorePerm,
};
use crate::keymaster::utils::{AndroidUserId, AppUid, SecureUserId};
use crate::top::jiyin004::ommega::{
    CallerInfo::CallerInfo,
    IMaintenanceService::{BnMaintenanceService, IMaintenanceService},
};
use crate::watchdog as wd;
use std::sync::atomic::Ordering;

/// 这个进程里「早期启动已经结束」。
///
/// 不能只靠包装器自己那个标志：包装器是惰性建的，而「早期已结束」这条事实得熬到
/// 它们迟到的创建之后。KEARLY_BOOT_ENDED 就是为此存在的。
static EARLY_BOOT_KNOWN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub struct MaintenanceManager;

impl MaintenanceManager {
    pub fn new_native_binder() -> Result<Strong<dyn IKeystoreMaintenance>> {
        Ok(BnKeystoreMaintenance::new_binder_with_features(
            Self,
            crate::consts::sid_features(),
        ))
    }

    pub fn new_ommega_binder() -> Result<Strong<dyn IMaintenanceService>> {
        Ok(BnMaintenanceService::new_binder_with_features(
            Self,
            crate::consts::sid_features(),
        ))
    }

    fn on_user_added(&self, ctx: Option<&CallerInfo>, user_id: i32) -> Result<()> {
        check_maintenance_permission(KeystorePerm::ChangeUser, ctx, "onUserAdded")
            .context(err!("caller missing change_user permission"))?;
        let user_id = checked_user_id(user_id)?;
        self.remove_user_state(user_id)
    }

    fn init_user_super_keys(
        &self,
        ctx: Option<&CallerInfo>,
        user_id: i32,
        password: &[u8],
        allow_existing: bool,
    ) -> Result<()> {
        check_maintenance_permission(KeystorePerm::ChangeUser, ctx, "initUserSuperKeys")
            .context(err!("caller missing change_user permission"))?;
        let user_id = checked_user_id(user_id)?;
        let password = password.into();
        DB.with(|db| {
            SUPER_KEY.write().unwrap().initialize_user(
                &mut db.borrow_mut(),
                user_id,
                &password,
                allow_existing,
            )
        })
        .context(err!("initializing user {user_id:?} super keys"))
    }

    fn on_user_password_changed(
        &self,
        ctx: Option<&CallerInfo>,
        user_id: i32,
        password: Option<&[u8]>,
    ) -> Result<()> {
        check_maintenance_permission(KeystorePerm::ChangePassword, ctx, "onUserPasswordChanged")
            .context(err!("caller missing change_password permission"))?;
        let user_id = checked_user_id(user_id)?;
        DB.with(|db| {
            let mut db = db.borrow_mut();
            let mut super_key = SUPER_KEY.write().unwrap();
            match password {
                Some(password) => {
                    let password = password.into();
                    super_key.unlock_or_initialize_user(&mut db, user_id, &password)
                }
                None => super_key.reset_lskf_bound_state(&mut db, user_id),
            }
        })
        .context(err!("handling legacy password change for user {user_id:?}"))
    }

    fn on_user_removed(&self, ctx: Option<&CallerInfo>, user_id: i32) -> Result<()> {
        check_maintenance_permission(KeystorePerm::ChangeUser, ctx, "onUserRemoved")
            .context(err!("caller missing change_user permission"))?;
        let user_id = checked_user_id(user_id)?;
        self.remove_user_state(user_id)
    }

    fn on_user_lskf_removed(&self, ctx: Option<&CallerInfo>, user_id: i32) -> Result<()> {
        check_maintenance_permission(KeystorePerm::ChangePassword, ctx, "onUserLskfRemoved")
            .context(err!("caller missing change_password permission"))?;
        let user_id = checked_user_id(user_id)?;
        DB.with(|db| db.borrow_mut().unbind_auth_bound_keys_for_user(user_id))
            .context(err!("unbinding auth-bound keys for user {user_id:?}"))
    }

    fn clear_namespace(&self, ctx: Option<&CallerInfo>, domain: Domain, nspace: i64) -> Result<()> {
        check_maintenance_permission(KeystorePerm::ClearUID, ctx, "clearNamespace")
            .context(err!("caller missing clear_uid permission"))?;
        DB.with(|db| db.borrow_mut().unbind_keys_for_namespace(domain, nspace))
            .context(err!("clearing namespace domain={domain:?} nspace={nspace}"))
    }

    fn early_boot_ended(&self, ctx: Option<&CallerInfo>) -> Result<()> {
        check_maintenance_permission(KeystorePerm::EarlyBootEnded, ctx, "earlyBootEnded")
            .context(err!("caller missing early_boot_ended permission"))?;
        DB.with(|db| {
            crate::keymaster::super_key::SuperKeyManager::set_up_boot_level_cache(
                &SUPER_KEY,
                &mut db.borrow_mut(),
            )
        })
        .context(err!("setting up boot-level key cache"))?;
        replay_early_boot_ended()?;
        Ok(())
    }

    fn migrate_key_namespace(
        &self,
        ctx: Option<&CallerInfo>,
        source: &KeyDescriptor,
        destination: &KeyDescriptor,
    ) -> Result<()> {
        check_forwarded_context(ctx, "migrateKeyNamespace")?;

        match source.domain {
            Domain::SELINUX | Domain::KEY_ID | Domain::APP => (),
            _ => {
                return Err(KsError::Rc(ResponseCode::INVALID_ARGUMENT)).context(err!(
                    "Source domain must be one of APP, SELINUX, or KEY_ID."
                ));
            }
        };

        let caller = resolve_caller_info(ctx);
        let destination = normalize_migration_destination(destination, caller.uid as u32)?;

        let caller_uid = AppUid(caller.uid as u32 as i64);
        let key_id_guard = DB
            .with(|db| {
                db.borrow_mut()
                    .load_key_entry(
                        source,
                        KeyType::Client,
                        KeyEntryLoadBits::NONE,
                        caller_uid,
                        |descriptor, access_vector| {
                            check_key_permission(
                                KeyPerm::Use,
                                descriptor,
                                access_vector.as_ref(),
                                ctx,
                            )
                            .context(err!("caller missing use permission for migration source"))?;
                            check_key_permission(
                                KeyPerm::Delete,
                                descriptor,
                                access_vector.as_ref(),
                                ctx,
                            )
                            .context(err!(
                                "caller missing delete permission for migration source"
                            ))?;
                            check_key_permission(
                                KeyPerm::Grant,
                                descriptor,
                                access_vector.as_ref(),
                                ctx,
                            )
                            .context(err!("caller missing grant permission for migration source"))
                        },
                    )
                    .map(|(key_id_guard, _)| key_id_guard)
            })
            .context(err!("resolving source key permissions for migration"))?;

        DB.with(|db| {
            db.borrow_mut().migrate_key_namespace(
                key_id_guard,
                &destination,
                caller_uid,
                |descriptor| {
                    check_key_permission(KeyPerm::Rebind, descriptor, None, ctx).context(err!(
                        "caller missing rebind permission for migration destination"
                    ))
                },
            )
        })
        .context(err!("migrating key namespace"))
    }

    fn delete_all_keys(&self, ctx: Option<&CallerInfo>) -> Result<()> {
        check_maintenance_permission(KeystorePerm::DeleteAllKeys, ctx, "deleteAllKeys")
            .context(err!("caller missing delete_all_keys permission"))?;
        call_keymint_wrappers("deleteAllKeys", |keymint| keymint.deleteAllKeys())
    }

    fn get_app_uids_affected_by_sid(
        &self,
        ctx: Option<&CallerInfo>,
        user_id: i32,
        sid: i64,
    ) -> Result<Vec<i64>> {
        check_forwarded_context(ctx, "getAppUidsAffectedBySid")?;
        check_manage_users_permission(ctx).context(err!("caller missing MANAGE_USERS"))?;
        let user_id = checked_user_id(user_id)?;
        DB.with(|db| {
            db.borrow_mut()
                .get_app_uids_affected_by_sid(user_id, SecureUserId(sid))
        })
        .map(|uids| uids.into_iter().map(|uid| uid.0).collect())
        .context(err!("querying app UIDs affected by SID"))
    }

    fn remove_user_state(&self, user_id: AndroidUserId) -> Result<()> {
        DB.with(|db| {
            SUPER_KEY
                .write()
                .unwrap()
                .remove_user(&mut db.borrow_mut(), user_id)
        })
        .context(err!("removing user {user_id:?} keys"))
    }
}

fn check_maintenance_permission(
    permission: KeystorePerm,
    ctx: Option<&CallerInfo>,
    label: &str,
) -> Result<()> {
    check_forwarded_context(ctx, label)?;
    check_keystore_permission(permission, ctx)
}

fn checked_user_id(user_id: i32) -> Result<AndroidUserId> {
    if user_id < 0 {
        return Err(KsError::Rc(ResponseCode::INVALID_ARGUMENT))
            .context(err!("user_id must be non-negative"));
    }
    Ok(AndroidUserId(user_id))
}

fn normalize_migration_destination(
    destination: &KeyDescriptor,
    caller_uid: u32,
) -> Result<KeyDescriptor> {
    let Some(alias) = destination.alias.as_ref() else {
        return Err(KsError::Rc(ResponseCode::INVALID_ARGUMENT))
            .context(err!("migration destination must specify an alias"));
    };

    match destination.domain {
        Domain::APP => Ok(KeyDescriptor {
            domain: Domain::APP,
            nspace: caller_uid as i64,
            alias: Some(alias.clone()),
            blob: None,
        }),
        Domain::SELINUX => Ok(KeyDescriptor {
            domain: Domain::SELINUX,
            nspace: destination.nspace,
            alias: Some(alias.clone()),
            blob: None,
        }),
        _ => Err(KsError::Rc(ResponseCode::INVALID_ARGUMENT))
            .context(err!("migration destination must be APP or SELINUX")),
    }
}

pub(crate) fn replay_early_boot_ended() -> Result<()> {
    // 先落下「早期启动已结束」这件事实，再去通知已经建好的包装器。
    //
    // 包装器是惰性建的，而这一步在一批初始化路径里跑在它们之前；事实存在这里，
    // `create_ta` 建完 TA 会自己补发那次 earlyBootEnded。
    EARLY_BOOT_KNOWN.store(true, Ordering::Release);
    call_keymint_wrappers("earlyBootEnded", |keymint| keymint.earlyBootEnded())
}

/// 这个进程里「早期启动已经结束」。跟包装器在不在无关。
pub(crate) fn early_boot_ended_known() -> bool {
    EARLY_BOOT_KNOWN.load(Ordering::Acquire)
}

fn call_keymint_wrappers<F>(label: &'static str, mut call: F) -> Result<()>
where
    F: FnMut(&KeyMintWrapper) -> rsbinder::status::Result<()>,
{
    let tee = get_keymint_wrapper(SecurityLevel::TRUSTED_ENVIRONMENT)
        .context(err!("opening mandatory TEE KeyMint for {label}"))?;
    map_km_error(call(&tee)).context(err!("calling TEE KeyMint {label}"))?;

    match get_keymint_wrapper(SecurityLevel::STRONGBOX) {
        Ok(strongbox) => {
            map_km_error(call(&strongbox))
                .context(err!("calling optional StrongBox KeyMint {label}"))?;
        }
        Err(error)
            if matches!(
                error.root_cause().downcast_ref::<KsError>(),
                Some(KsError::Km(ErrorCode::HARDWARE_TYPE_UNAVAILABLE))
            ) =>
        {
            log::debug!("optional StrongBox KeyMint unavailable for {label}");
        }
        Err(error) => return Err(error).context(err!("opening optional StrongBox KeyMint")),
    }

    Ok(())
}

impl Interface for MaintenanceManager {}

#[allow(non_snake_case)]
impl IKeystoreMaintenance for MaintenanceManager {
    fn onUserAdded(&self, user_id: i32) -> rsbinder::status::Result<()> {
        let _wp = wd::watch("IKeystoreMaintenance::onUserAdded");
        self.on_user_added(None, user_id)
            .map_err(into_logged_binder)
    }

    fn initUserSuperKeys(
        &self,
        user_id: i32,
        password: &[u8],
        allow_existing: bool,
    ) -> rsbinder::status::Result<()> {
        let _wp = wd::watch("IKeystoreMaintenance::initUserSuperKeys");
        self.init_user_super_keys(None, user_id, password, allow_existing)
            .map_err(into_logged_binder)
    }

    fn onUserRemoved(&self, user_id: i32) -> rsbinder::status::Result<()> {
        let _wp = wd::watch("IKeystoreMaintenance::onUserRemoved");
        self.on_user_removed(None, user_id)
            .map_err(into_logged_binder)
    }

    fn onUserLskfRemoved(&self, user_id: i32) -> rsbinder::status::Result<()> {
        let _wp = wd::watch("IKeystoreMaintenance::onUserLskfRemoved");
        self.on_user_lskf_removed(None, user_id)
            .map_err(into_logged_binder)
    }

    fn clearNamespace(&self, domain: Domain, nspace: i64) -> rsbinder::status::Result<()> {
        let _wp = wd::watch("IKeystoreMaintenance::clearNamespace");
        self.clear_namespace(None, domain, nspace)
            .map_err(into_logged_binder)
    }

    fn earlyBootEnded(&self) -> rsbinder::status::Result<()> {
        let _wp = wd::watch("IKeystoreMaintenance::earlyBootEnded");
        self.early_boot_ended(None).map_err(into_logged_binder)
    }

    fn migrateKeyNamespace(
        &self,
        source: &KeyDescriptor,
        destination: &KeyDescriptor,
    ) -> rsbinder::status::Result<()> {
        let _wp = wd::watch("IKeystoreMaintenance::migrateKeyNamespace");
        self.migrate_key_namespace(None, source, destination)
            .map_err(into_logged_binder)
    }

    fn deleteAllKeys(&self) -> rsbinder::status::Result<()> {
        let _wp = wd::watch("IKeystoreMaintenance::deleteAllKeys");
        self.delete_all_keys(None).map_err(into_logged_binder)
    }

    fn getAppUidsAffectedBySid(
        &self,
        user_id: i32,
        sid: i64,
    ) -> rsbinder::status::Result<Vec<i64>> {
        let _wp = wd::watch("IKeystoreMaintenance::getAppUidsAffectedBySid");
        self.get_app_uids_affected_by_sid(None, user_id, sid)
            .map_err(into_logged_binder)
    }
}

#[allow(non_snake_case)]
impl IMaintenanceService for MaintenanceManager {
    fn onUserAdded(&self, ctx: Option<&CallerInfo>, user_id: i32) -> rsbinder::status::Result<()> {
        let _wp = wd::watch("IMaintenanceService::onUserAdded");
        let ctx = Some(require_ommega_ctx(ctx, "IMaintenanceService::onUserAdded")?);
        self.on_user_added(ctx, user_id).map_err(into_logged_binder)
    }

    fn initUserSuperKeys(
        &self,
        ctx: Option<&CallerInfo>,
        user_id: i32,
        password: &[u8],
        allow_existing: bool,
    ) -> rsbinder::status::Result<()> {
        let _wp = wd::watch("IMaintenanceService::initUserSuperKeys");
        let ctx = Some(require_ommega_ctx(
            ctx,
            "IMaintenanceService::initUserSuperKeys",
        )?);
        self.init_user_super_keys(ctx, user_id, password, allow_existing)
            .map_err(into_logged_binder)
    }

    fn onUserRemoved(
        &self,
        ctx: Option<&CallerInfo>,
        user_id: i32,
    ) -> rsbinder::status::Result<()> {
        let _wp = wd::watch("IMaintenanceService::onUserRemoved");
        let ctx = Some(require_ommega_ctx(
            ctx,
            "IMaintenanceService::onUserRemoved",
        )?);
        self.on_user_removed(ctx, user_id)
            .map_err(into_logged_binder)
    }

    fn onUserLskfRemoved(
        &self,
        ctx: Option<&CallerInfo>,
        user_id: i32,
    ) -> rsbinder::status::Result<()> {
        let _wp = wd::watch("IMaintenanceService::onUserLskfRemoved");
        let ctx = Some(require_ommega_ctx(
            ctx,
            "IMaintenanceService::onUserLskfRemoved",
        )?);
        self.on_user_lskf_removed(ctx, user_id)
            .map_err(into_logged_binder)
    }

    fn clearNamespace(
        &self,
        ctx: Option<&CallerInfo>,
        domain: Domain,
        nspace: i64,
    ) -> rsbinder::status::Result<()> {
        let _wp = wd::watch("IMaintenanceService::clearNamespace");
        let ctx = Some(require_ommega_ctx(
            ctx,
            "IMaintenanceService::clearNamespace",
        )?);
        self.clear_namespace(ctx, domain, nspace)
            .map_err(into_logged_binder)
    }

    fn earlyBootEnded(&self, ctx: Option<&CallerInfo>) -> rsbinder::status::Result<()> {
        let _wp = wd::watch("IMaintenanceService::earlyBootEnded");
        let ctx = Some(require_ommega_ctx(
            ctx,
            "IMaintenanceService::earlyBootEnded",
        )?);
        self.early_boot_ended(ctx).map_err(into_logged_binder)
    }

    fn migrateKeyNamespace(
        &self,
        ctx: Option<&CallerInfo>,
        source: &KeyDescriptor,
        destination: &KeyDescriptor,
    ) -> rsbinder::status::Result<()> {
        let _wp = wd::watch("IMaintenanceService::migrateKeyNamespace");
        let ctx = Some(require_ommega_ctx(
            ctx,
            "IMaintenanceService::migrateKeyNamespace",
        )?);
        self.migrate_key_namespace(ctx, source, destination)
            .map_err(into_logged_binder)
    }

    fn deleteAllKeys(&self, ctx: Option<&CallerInfo>) -> rsbinder::status::Result<()> {
        let _wp = wd::watch("IMaintenanceService::deleteAllKeys");
        let ctx = Some(require_ommega_ctx(
            ctx,
            "IMaintenanceService::deleteAllKeys",
        )?);
        self.delete_all_keys(ctx).map_err(into_logged_binder)
    }

    fn getAppUidsAffectedBySid(
        &self,
        ctx: Option<&CallerInfo>,
        user_id: i32,
        sid: i64,
    ) -> rsbinder::status::Result<Vec<i64>> {
        let _wp = wd::watch("IMaintenanceService::getAppUidsAffectedBySid");
        let ctx = Some(require_ommega_ctx(
            ctx,
            "IMaintenanceService::getAppUidsAffectedBySid",
        )?);
        self.get_app_uids_affected_by_sid(ctx, user_id, sid)
            .map_err(into_logged_binder)
    }

    fn onUserPasswordChanged(
        &self,
        ctx: Option<&CallerInfo>,
        user_id: i32,
        password: Option<&[u8]>,
    ) -> rsbinder::status::Result<()> {
        let _wp = wd::watch("IMaintenanceService::onUserPasswordChanged");
        let ctx = Some(require_ommega_ctx(
            ctx,
            "IMaintenanceService::onUserPasswordChanged",
        )?);
        self.on_user_password_changed(ctx, user_id, password)
            .map_err(into_logged_binder)
    }

    /// Record one observation sent by a hook inside an injected process.
    ///
    /// The line is logged as-is; SOTER observations are also handed to
    /// [`crate::soter_host_health`], which is the only place that can tell a host that came up mute
    /// (it receives App-side calls but never forwards one to the HAL) from a working one. There is
    /// no caller context to require here, and the peer that got this far already passed the
    /// socket authorizer.
    fn reportHookEvent(&self, message: &str) -> rsbinder::status::Result<()> {
        let _wp = wd::watch("IMaintenanceService::reportHookEvent");
        crate::soter_host_health::observe(message);
        log::info!("hook event: {message}");
        Ok(())
    }

    /// 宿主拦到一笔 SOTER HAL 调用，问这笔该由谁答：远程、A 端本地自签，还是透传真 HAL。
    ///
    /// 决策在这里做：daemon 盯着配置文件，改完开关立即生效。
    /// 能走到这里的 peer 已经过了 socket 鉴权。
    fn forwardSoter(&self, request: &str) -> rsbinder::status::Result<Vec<u8>> {
        let _wp = wd::watch("IMaintenanceService::forwardSoter");
        Ok(crate::soter_relay::forward(request))
    }

    /// app 域的 payload 写不动 SOTER 料库（MLS 的写约束要求级别相等），整份文本交给
    /// 这里落盘。与 `forwardSoter` 同理：peer 已经过了 socket 鉴权，不查 caller。
    fn writeSoterStore(&self, text: &str) -> rsbinder::status::Result<bool> {
        let _wp = wd::watch("IMaintenanceService::writeSoterStore");
        Ok(crate::soter_store::write(text))
    }

    /// 料库那半边的读。写走 `writeSoterStore`、读走这里，两边必须成对：调用方读不到就会
    /// 把料库当成空的，接着一次读-改-写就把里面已有的 ASK / AuthKey 整段铲掉。
    fn readSoterStore(&self) -> rsbinder::status::Result<Option<String>> {
        let _wp = wd::watch("IMaintenanceService::readSoterStore");
        Ok(crate::soter_store::read())
    }

    /// 数据根里其它小件的按名读。app 域的宿主进不去那个 0770 目录，开关和状态只能这么读。
    fn readState(&self, name: &str) -> rsbinder::status::Result<Option<String>> {
        let _wp = wd::watch("IMaintenanceService::readState");
        if secret(name) {
            log::warn!("readState: refusing {name} for an app-domain caller");
            return Ok(None);
        }
        if name == "config" {
            // 平铺 config 里的开关（global_scope / debug）payload 要读，token 不需要。
            return Ok(crate::soter_store::read_named(name).map(strip_secrets));
        }
        Ok(crate::soter_store::read_named(name))
    }

    /// 按名写数据根里的小件（单层名字，越界的在 `named_path` 那里就拒了）。
    fn writeState(&self, name: &str, data: &str) -> rsbinder::status::Result<bool> {
        let _wp = wd::watch("IMaintenanceService::writeState");
        if secret(name) || read_only(name) {
            log::warn!("writeState: refusing {name} for an app-domain caller");
            return Ok(false);
        }
        Ok(crate::soter_store::write_named(name, data))
    }

    /// 替 app 域加 counter：那边开不了文件，而号必须单调递增。回 -1 表示没落盘。
    fn bumpCounter(&self, uid: i32, memory_floor: i64) -> rsbinder::status::Result<i64> {
        let _wp = wd::watch("IMaintenanceService::bumpCounter");
        let floor = u64::try_from(memory_floor).unwrap_or(0);
        match crate::soter_store::bump_counter(uid, floor) {
            Some(next) => Ok(i64::try_from(next).unwrap_or(i64::MAX)),
            None => Ok(-1),
        }
    }
}

/// 读都不给的那几份：钥匙库、身份簿、连接凭据。放开了，宿主里一笔 RPC 就能拷走。
fn secret(name: &str) -> bool {
    matches!(
        name,
        "remote_identity" | "rpc.peers" | "keymaster.db" | "unlock.state" | "injector.toml"
    ) || name.starts_with("keybox_")
        || name.ends_with(".bak")
}

/// 能给 app 域读、但只能由面板 / root 写的那些：它们决定行为（注入范围、接管开关、
/// 上报的身份号、调用者归属），让宿主能写就能把自己冒充成别人或把接管翻掉。
fn read_only(name: &str) -> bool {
    matches!(
        name,
        "config.toml"
            | "config"
            | "target.txt"
            | "uid_packages"
            | "soter_app_serve"
            | "soter_host_state"
            | "soter_cpu_id.force"
            | "soter_attk.pem"
            | "soter_platform"
            | "patch.state"
            | "foreground"
            | "inproc"
            | "crash_count"
            | "aaid_table"
            | "boot_done"
    )
}

/// 交给 app 域之前把那几行敏感键抹掉（token 就是远程登录凭据，payload 用不着）。
fn strip_secrets(text: String) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.lines() {
        let key = line.split(':').next().unwrap_or("").trim();
        if key.eq_ignore_ascii_case("token") || key.eq_ignore_ascii_case("password") {
            out.push_str(&format!("{key}: ***\n"));
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}
