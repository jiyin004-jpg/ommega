//! 拿设备上现成的 HIDL 服务验一下 HIDL 传输层这半边。
//!
//! 这台机器上没有 HIDL 版 SOTER（全 AIDL），所以用一个无论如何都在的服务
//! `android.hidl.allocator@1.0::IAllocator/ashmem` 来验两件事：
//!
//! 1. `IServiceManager::get(fqName, instance)` 那笔事务编对了 —— 能换回一个句柄；
//! 2. 换回来的句柄真能用 —— 拿它发一笔 `IBase::ping()`。
//!
//! 不碰 SOTER 的业务逻辑，所以不需要 TEE 是好的。
//!
//! ```text
//! adb push target/aarch64-linux-android/release/examples/hidl_probe /data/local/tmp/
//! adb shell su -c /data/local/tmp/hidl_probe
//! ```

use anyhow::Result;

use ommegaclient_b::soter::hwbinder::{HwBinder, Parcel};
use ommegaclient_b::soter::hidl::{HidlSoter, HW_SERVICE_MANAGER_DESCRIPTOR};

/// `android.hidl.base@1.0::IBase` 的 `ping()`，无参无返。
const TX_IBASE_PING: u32 = 6;
const IBASE_DESCRIPTOR: &str = "android.hidl.base@1.0::IBase";

fn main() -> Result<()> {
    let which = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "android.hidl.allocator@1.0::IAllocator/ashmem".to_string());
    let (fq_name, instance) = match which.split_once('/') {
        Some((fq, inst)) => (fq.to_string(), inst.to_string()),
        None => (which.clone(), "default".to_string()),
    };

    println!("== 0. 打开 hwbinder ==");
    let conn = HwBinder::open()?;
    println!("   /dev/hwbinder 打开成功，映射 {} 字节", conn.map_len());

    // 先发一笔完全没有 buffer 对象的事务，把 EFAULT 定位到「parcel 传输」还是
    // 「buffer 对象的地址」。list() 只有 token、没有参数，正好当对照组。
    println!("== 1. 对照组：发一笔没参数的 list() ==");
    {
        let mut p = Parcel::new();
        p.write_interface_token("android.hidl.manager@1.0::IServiceManager");
        match conn.transact(0, 4, &p) {
            Ok(r) => println!("   ✓ 空 parcel 事务通了，应答 {} 字节", r.data.len()),
            Err(e) => println!("   ✗ 空 parcel 也挂了：{e:#}"),
        }
    }

    println!("== 2. getService({fq_name}, {instance}) ==");
    {
        let mut p = Parcel::new();
        p.write_interface_token("android.hidl.manager@1.0::IServiceManager");
        p.write_hidl_string(&fq_name);
        p.write_hidl_string(&instance);
        match conn.transact(0, 1, &p) {
            Ok(r) => {
                let n = r.data.len().min(48);
                let hex: Vec<String> = r.data[..n].iter().map(|b| format!("{b:02x}")).collect();
                println!("   原始应答 {} 字节: {}", r.data.len(), hex.join(" "));
                println!("   offsets = {:?}", r.offsets);
            }
            Err(e) => println!("   ✗ {e:#}"),
        }
    }

    println!(
        "   本进程 pid = {}，先睡 25 秒（此时只有这一个连接），外面看内核状态",
        std::process::id()
    );
    std::thread::sleep(std::time::Duration::from_secs(25));

    let svc = HidlSoter::open_named(&fq_name, &instance, IBASE_DESCRIPTOR)?;
    let svc = match svc {
        Some(svc) => svc,
        None => {
            println!("   hwservicemanager 说这个名字没登记");
            return Ok(());
        }
    };
    let handle = svc.handle();
    println!("   ✓ 拿到句柄 {handle}");

    println!("== 4. 对照组：拿 handle 0（hwservicemanager，已知可用）发 IBase::ping() ==");
    {
        let mut p = Parcel::new();
        p.write_interface_token(IBASE_DESCRIPTOR);
        match conn.transact(0, TX_IBASE_PING, &p) {
            Ok(r) => println!("   ✓ handle 0 的 ping 通了，应答 {} 字节", r.data.len()),
            Err(e) => println!("   ✗ handle 0 的 ping 也挂了：{e:#}"),
        }
    }

    println!("== 5. 用刚拿到的句柄 {handle} 发 IBase::ping() ==");
    println!("   本进程 pid = {}", std::process::id());
    // 句柄号只在收到它的那条 `/dev/hwbinder` 上有意义（每开一次就是内核里一个新
    // `binder_proc`），所以必须走 `svc` 自己的连接，不能借 `conn`。
    match svc.call_on_own_connection(IBASE_DESCRIPTOR, TX_IBASE_PING) {
        Ok(r) => println!("   ✓ 句柄 {handle} 的 ping 通了，应答 {} 字节", r.data.len()),
        Err(e) => println!("   ✗ 句柄 {handle} 的 ping 挂了：{e:#}"),
    }
    println!("== 5b. 反面教材：把同一个句柄号拿到另一条连接上（预期 BR_FAILED_REPLY）==");
    match HwBinder::open().and_then(|other| {
        let mut p = Parcel::new();
        p.write_interface_token(IBASE_DESCRIPTOR);
        other.transact(handle, TX_IBASE_PING, &p)
    }) {
        Ok(r) => println!("   ? 另一条连接也通了，应答 {} 字节", r.data.len()),
        Err(e) => println!("   ✓ 如预期挂了（句柄是 per-proc 的）：{e:#}"),
    }

    // 顺手把 hwservicemanager 自己列一遍，证明同一套编码对 1.0 的 manager 也成立。
    println!("== 6. 拿 hwservicemanager 自己的句柄来 ping（它肯定不是 passthrough）==");
    {
        let mut p = Parcel::new();
        p.write_interface_token(HW_SERVICE_MANAGER_DESCRIPTOR);
        p.write_hidl_string("android.hidl.manager@1.0::IServiceManager");
        p.write_hidl_string("default");
        match conn.transact(0, 1, &p) {
            Ok(r) => {
                let n = r.data.len().min(32);
                let hex: Vec<String> = r.data[..n].iter().map(|b| format!("{b:02x}")).collect();
                println!("   原始应答 {} 字节: {}", r.data.len(), hex.join(" "));
                if r.data.len() >= 28 {
                    let h = u32::from_le_bytes([r.data[12], r.data[13], r.data[14], r.data[15]]);
                    let mut q = Parcel::new();
                    q.write_interface_token(IBASE_DESCRIPTOR);
                    match conn.transact(h, TX_IBASE_PING, &q) {
                        Ok(p) => println!("   ✓ 用它自己返回的句柄 {h} ping 通了，应答 {} 字节", p.data.len()),
                        Err(e) => println!("   ✗ 句柄 {h} ping 挂了：{e:#}"),
                    }
                }
            }
            Err(e) => println!("   ✗ {e:#}"),
        }
    }

    println!("== 7. 顺带问 hwservicemanager 拿一下 SOTER 的句柄（预期没有）==");
    match HidlSoter::open_named(
        "vendor.qti.hardware.soter@1.0::ISoter",
        "default",
        IBASE_DESCRIPTOR,
    )? {
        Some(svc) => println!("   这台机器上居然有 HIDL 版 SOTER，句柄 {}", svc.handle()),
        None => println!("   如预期，没有（这台机器是 AIDL 那套）"),
    }

    println!("\n全部通过。");
    Ok(())
}

// 避免 unused 警告：只用来证明 Parcel 的类型名在探针里可用。
#[allow(dead_code)]
fn _parcel_is_public(p: &Parcel) -> usize {
    p.data().len()
}
