use std::{
    cell::RefCell,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, LazyLock, Mutex, Once, OnceLock, RwLock,
    },
};

use rsbinder::Strong;

use anyhow::{Context, Result};

use crate::{
    android::hardware::security::secureclock::ISecureClock::ISecureClock,
    err,
    keymaster::{
        apex::ModuleInfoBundle,
        async_task::AsyncTask,
        db::KeymasterDb,
        enforcements::Enforcements,
        gc::Gc,
        keymint_device::{get_keymint_wrapper, KeyMintDevice},
        super_key::SuperKeyManager,
        utils::get_interface_once,
    },
    plat::property_watcher::PropertyWatcher,
    watchdog as wd,
};

static DB_INIT: Once = Once::new();
const OMMEGA_DB_ROOT: &str = "/data/misc/keystore/ommega/data";
const DB_ORPHAN_LIMIT: usize = 100_000;

pub fn db_root_path() -> &'static Path {
    Path::new(OMMEGA_DB_ROOT)
}

/// A single on-demand worker thread that handles deferred tasks with two different
/// priorities.
pub static ASYNC_TASK: LazyLock<Arc<AsyncTask>> = LazyLock::new(Default::default);

static GC: LazyLock<Arc<Gc>> = LazyLock::new(|| {
    Arc::new(Gc::new_init_with(ASYNC_TASK.clone(), || {
        (
            Box::new(|uuid, blob| {
                let security_level = match uuid.to_security_level() {
                    Some(level) => level,
                    // uuid 认不出对应的 HAL：直接跳过，不在这 unwrap。
                    None => return Ok(()),
                };

                let km_dev = match get_keymint_wrapper(security_level) {
                    Ok(dev) => dev,
                    // 这个 level 的 HAL 拿不到：当「不用失效」放行，让 DB 行正常删掉。
                    // 不能 unwrap（panic=abort 会打崩 keymint 进程）。
                    Err(e) if KeyMintDevice::is_hardware_type_unavailable(&e) => return Ok(()),
                    Err(e) => {
                        return Err(e)
                            .context(err!("Getting KeyMint device to invalidate key blob."))
                    }
                };
                let _wp = wd::watch("invalidate key closure: calling IKeyMintDevice::deleteKey");
                km_dev
                    .delete_Key(blob)
                    .map_err(|e| anyhow::anyhow!("Failed to delete key blob: {e}"))
                    .context(err!("Trying to invalidate key blob."))
            }),
            KeymasterDb::new(db_root_path(), None).expect("Failed to open database"),
            SUPER_KEY.clone(),
        )
    }))
});

/// Open a connection to the Keystore 2.0 database. This is called during the initialization of
/// the thread local DB field. It should never be called directly. The first time this is called
/// we also call KeystoreDB::cleanup_leftovers to restore the key lifecycle invariant. See the
/// documentation of cleanup_leftovers for more details. The function also constructs a blob
/// garbage collector. The initializing closure constructs another database connection without
/// a gc. Although one GC is created for each thread local database connection, this closure
/// is run only once, as long as the ASYNC_TASK instance is the same. So only one additional
/// database connection is created for the garbage collector worker.
pub fn create_thread_local_db() -> KeymasterDb {
    let result = KeymasterDb::new(db_root_path(), Some(GC.clone()));
    let mut db = match result {
        Ok(db) => db,
        Err(e) => {
            log::error!(
                "Failed to open Keystore database at {:?}: {e:?}",
                db_root_path()
            );
            log::error!("Has /data been mounted correctly?");
            panic!("Failed to open database for Keystore, cannot continue: {e:?}")
        }
    };

    DB_INIT.call_once(|| {
        log::info!("Touching Keystore 2.0 database for this first time since boot.");
        log::info!("Calling cleanup_leftovers({DB_ORPHAN_LIMIT}).");
        let n = db
            .cleanup_leftovers(DB_ORPHAN_LIMIT)
            .expect("Failed to cleanup database on startup");
        if n != 0 {
            log::info!(
                "Cleaned up {n} failed entries, indicating keystore crash on key generation"
            );
        }
    });
    db
}

thread_local! {
    /// Database connections are not thread safe, but connecting to the
    /// same database multiple times is safe as long as each connection is
    /// used by only one thread. So we store one database connection per
    /// thread in this thread local key.
    pub static DB: RefCell<KeymasterDb> = RefCell::new(create_thread_local_db());
}

pub static ENFORCEMENTS: LazyLock<Enforcements> = LazyLock::new(Default::default);

pub static SUPER_KEY: LazyLock<Arc<RwLock<SuperKeyManager>>> = LazyLock::new(Default::default);

static BOOT_COMPLETED: AtomicBool = AtomicBool::new(false);

pub fn boot_completed() -> bool {
    BOOT_COMPLETED.load(Ordering::Acquire)
}

/// root 侧在开机完成后落下的标记（`post-fs-data` 开机早期会删掉它）。
///
/// 属性 `sys.boot_completed` 在 payload 里不一定读得到（静态链接，读属性会退到 exec
/// resetprop，换域以后可能被拒），而这个标记只要写出来就一直在，所以以它为准。
pub(crate) const BOOT_DONE_PATH: &str = "/data/misc/keystore/ommega/boot_done";

/// 开机是否已经完成：标记在，或者属性已经看到 1。
///
/// 以标记为主：属性在 payload 里不一定读得到（静态链接，读属性要 exec resetprop）。
///
/// 但标记得是本次开机落下的。正常情况下 `post-fs-data` 每次都先删一遍；没删掉就说明
/// 这次开机没有按标准流程加载模块（手动解压、post-fs-data 被跳），那份是上一次的残留。
/// 拿它的 mtime 对一下开机时长：比开机时刻还早就当它不存在，否则会提前重放
/// earlyBootEnded，把整段早期启动的 EARLY_BOOT_ONLY 限制白白放开。
pub(crate) fn boot_done_present() -> bool {
    if boot_completed() {
        return true;
    }
    let Ok(meta) = std::fs::metadata(BOOT_DONE_PATH) else {
        return false;
    };
    let age = meta
        .modified()
        .ok()
        .and_then(|mtime| std::time::SystemTime::now().duration_since(mtime).ok());
    let (Some(age), Some(uptime)) = (age, boot_uptime()) else {
        // 拿不到开机时长就算了（总比不认标记强）。
        return true;
    };
    if age.as_secs() > uptime.as_secs() + BOOT_DONE_SLACK_SECS {
        log::warn!(
            "ignoring a boot_done left by a previous boot (age {}s > uptime {}s)",
            age.as_secs(),
            uptime.as_secs()
        );
        return false;
    }
    true
}

/// `/proc/uptime` 的第一列（秒）。
fn boot_uptime() -> Option<std::time::Duration> {
    let text = std::fs::read_to_string("/proc/uptime").ok()?;
    let secs: f64 = text.split_whitespace().next()?.parse().ok()?;
    Some(std::time::Duration::from_secs(secs as u64))
}

/// 标记比开机时刻早多少秒还算“本次开机”。留一点余量给开机早期的那几秒。
const BOOT_DONE_SLACK_SECS: u64 = 5;

pub fn await_boot_completed() {
    let _wp = wd::watch_millis("await_boot_completed", 300_000);
    log::info!("monitoring for sys.boot_completed=1");
    while let Err(e) = watch_for_boot_completed() {
        log::error!("failed to watch for boot_completed: {e:?}");
        std::thread::sleep(std::time::Duration::from_secs(5));
    }

    mark_boot_completed();
}

/// 开机已完成：放开 GC 闸门。
///
/// 标记文件（`boot_done`）比属性靠谱，看到标记的路径也得能置位，否则 GC 永远在
/// 「boot not completed」上打转（`gc.rs` 里那句 skip）。
pub(crate) fn mark_boot_completed() {
    if BOOT_COMPLETED.swap(true, Ordering::AcqRel) {
        return;
    }
    log::info!("boot completed; triggering GC");
    GC.notify_gc();
}

fn watch_for_boot_completed() -> Result<()> {
    let watcher =
        PropertyWatcher::new("sys.boot_completed").context(err!("PropertyWatcher::new failed"))?;
    loop {
        let value = watcher
            .read()
            .context(err!("Failed to read sys.boot_completed"))?;
        if value == "1" {
            return Ok(());
        }
        watcher
            .wait(Some(&value))
            .context(err!("Failed to wait for sys.boot_completed"))?;
    }
}

/// Boot-scoped APEX module information used by both KeyMint attestation injection and
/// `getSupplementaryAttestationInfo(Tag::MODULE_HASH)`.
pub static MODULE_INFO_BUNDLE: OnceLock<ModuleInfoBundle> = OnceLock::new();

pub fn install_module_info_bundle(bundle: ModuleInfoBundle) -> Result<()> {
    MODULE_INFO_BUNDLE
        .set(bundle)
        .map_err(|_| anyhow::anyhow!("APEX module info bundle was already initialized"))
}

pub fn module_info_bundle() -> Option<&'static ModuleInfoBundle> {
    MODULE_INFO_BUNDLE.get()
}

/// Timestamp service.
static TIME_STAMP_DEVICE: Mutex<Option<Strong<dyn ISecureClock>>> = Mutex::new(None);

/// Get the timestamp service that verifies auth token timeliness towards security levels with
/// different clocks.
pub fn get_timestamp_service() -> Result<Strong<dyn ISecureClock>> {
    let mut ts_device = TIME_STAMP_DEVICE.lock().unwrap();
    if let Some(dev) = &*ts_device {
        Ok(dev.clone())
    } else {
        let dev = connect_secureclock().context(err!())?;
        *ts_device = Some(dev.clone());
        Ok(dev)
    }
}

fn connect_secureclock() -> Result<Strong<dyn ISecureClock>> {
    let descriptors = <crate::android::hardware::security::secureclock::ISecureClock::BpSecureClock as ISecureClock>::descriptor();
    let dev: Strong<dyn ISecureClock> = get_interface_once(descriptors).context(err!())?;

    Ok(dev)
}

/// Per RFC 5280 4.1.2.5, an undefined expiration (not-after) field should be set to GeneralizedTime
/// 999912312359559, which is 253402300799000 ms from Jan 1, 1970.
pub const UNDEFINED_NOT_AFTER: i64 = 253402300799000i64;
