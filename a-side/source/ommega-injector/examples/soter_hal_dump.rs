//! 对 SOTER 的 vendor HAL 发一次事务，把回包原样 dump 成十六进制。
//!
//! 和 `soter_hal_probe` 的区别：那个只发请求不读回包（给观察者看请求长什么样），
//! 这个把回包整个吐出来，用来量真机每个码的应答形状（尤其高通 / MTK 打包差异）。
//!
//! 走 `libbinder_ndk.so`，所以 vendor 的 AIDL 服务要用 `--vnd`（`/dev/vndbinder`）
//! 才找得到；跑它的进程需要能打开那个 binder 设备。
//!
//! ```text
//! cargo build --target aarch64-linux-android --example soter_hal_dump
//! adb push target/aarch64-linux-android/release/examples/soter_hal_dump /data/local/tmp/
//! adb shell su -c '/data/local/tmp/soter_hal_dump --vnd --code 8'
//! ```
//!
//! 只发参数用 `--uid` / `--alias` / `--string` 拼出来的请求；要不要写设备，由调用方
//! 挑码决定（8/9/10/14 是只读，1/3 会推进 TEE 的签名计数器，5/6/7/12/13 会改密钥）。

use std::ffi::{c_char, CString};

const LIB_BINDER_NDK: &[u8] = b"libbinder_ndk.so\0";

#[repr(C)]
struct AIBinder {
    _private: [u8; 0],
}

#[repr(C)]
struct AParcel {
    _private: [u8; 0],
}

struct Ndk {
    get_service: unsafe extern "C" fn(*const c_char) -> *mut AIBinder,
    parcel_create: unsafe extern "C" fn() -> *mut AParcel,
    write_string: unsafe extern "C" fn(*mut AParcel, *const c_char, i32) -> i32,
    write_int32: unsafe extern "C" fn(*mut AParcel, i32) -> i32,
    transact:
        unsafe extern "C" fn(*mut AIBinder, u32, *mut *mut AParcel, *mut *mut AParcel, u32) -> i32,
    parcel_delete: unsafe extern "C" fn(*mut AParcel),
    data_size: unsafe extern "C" fn(*const AParcel) -> i32,
    marshal: unsafe extern "C" fn(*const AParcel, *mut u8, usize) -> i32,
}

fn load() -> Option<Ndk> {
    unsafe {
        let handle = libc::dlopen(
            LIB_BINDER_NDK.as_ptr() as *const c_char,
            libc::RTLD_NOW | libc::RTLD_LOCAL,
        );
        if handle.is_null() {
            return None;
        }
        macro_rules! sym {
            ($name:ident, $name_bytes:expr) => {{
                let raw = libc::dlsym(handle, $name_bytes.as_ptr() as *const c_char);
                if raw.is_null() {
                    return None;
                }
                let $name = std::mem::transmute_copy(&raw);
                $name
            }};
        }
        Some(Ndk {
            get_service: sym!(get_service, b"AServiceManager_getService\0"),
            parcel_create: sym!(parcel_create, b"AParcel_create\0"),
            write_string: sym!(write_string, b"AParcel_writeString\0"),
            write_int32: sym!(write_int32, b"AParcel_writeInt32\0"),
            transact: sym!(transact, b"AIBinder_transact\0"),
            parcel_delete: sym!(parcel_delete, b"AParcel_delete\0"),
            data_size: sym!(data_size, b"AParcel_getDataSize\0"),
            marshal: sym!(marshal, b"AParcel_marshal\0"),
        })
    }
}

fn main() {
    let mut service = "vendor.qti.hardware.soter.ISoter/default".to_string();
    let mut interface = "vendor.qti.hardware.soter.ISoter".to_string();
    let mut code: u32 = 8;
    let mut uid: Option<i32> = None;
    let mut alias: Option<String> = None;
    let mut extra: Option<String> = None;
    let mut vnd = false;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut take = || args.next().unwrap_or_default();
        match arg.as_str() {
            "--service" => service = take(),
            "--interface" => interface = take(),
            "--code" => code = take().parse().unwrap_or(8),
            "--uid" => uid = take().parse().ok(),
            "--alias" => alias = Some(take()),
            "--string" => extra = Some(take()),
            "--vnd" => vnd = true,
            other => eprintln!("ignoring unknown argument {other}"),
        }
    }

    // binder 设备：vendor HAL 在 vndbinder 上。
    if vnd {
        if let Err(error) = init_vndbinder() {
            eprintln!("vndbinder init failed: {error}");
            return;
        }
    }

    let Some(ndk) = load() else {
        eprintln!("libbinder_ndk.so or one of its symbols is missing");
        return;
    };
    let Ok(service_c) = CString::new(service.clone()) else {
        eprintln!("bad service name");
        return;
    };

    unsafe {
        let binder = (ndk.get_service)(service_c.as_ptr());
        if binder.is_null() {
            eprintln!("{service} not found on this binder");
            return;
        }
        let mut input: *mut AParcel = (ndk.parcel_create)();
        if input.is_null() {
            eprintln!("AParcel_create failed");
            return;
        }
        // AParcel 头一个字段是归属的 AIBinder，AIBinder_transact 会比对，得补上。
        *(input as *mut *mut AIBinder) = binder;
        let Ok(descriptor) = CString::new(interface.clone()) else {
            eprintln!("bad interface");
            return;
        };
        (ndk.write_string)(input, descriptor.as_ptr(), interface.len() as i32);
        if let Some(uid) = uid {
            (ndk.write_int32)(input, uid);
        }
        if let Some(alias) = &alias {
            if let Ok(text) = CString::new(alias.as_str()) {
                (ndk.write_string)(input, text.as_ptr(), alias.len() as i32);
            }
        }
        if let Some(extra) = &extra {
            if let Ok(text) = CString::new(extra.as_str()) {
                (ndk.write_string)(input, text.as_ptr(), extra.len() as i32);
            }
        }

        let mut output: *mut AParcel = std::ptr::null_mut();
        let status = (ndk.transact)(binder, code, &mut input, &mut output, 0);
        println!("code={code} transact_status={status}");
        if status != 0 || output.is_null() {
            eprintln!("no reply parcel");
            return;
        }
        let size = (ndk.data_size)(output);
        let mut buffer = vec![0u8; size.max(0) as usize];
        let marshalled = (ndk.marshal)(output, buffer.as_mut_ptr(), buffer.len());
        println!("reply_len={size} marshal_status={marshalled}");
        if marshalled == 0 {
            let hex: String = buffer.iter().map(|b| format!("{b:02x}")).collect();
            println!("reply_hex={hex}");
        }
        (ndk.parcel_delete)(output);
    }
}

/// `/dev/vndbinder` 上的服务要先把 binder 线程池挂在那个设备上。
fn init_vndbinder() -> Result<(), String> {
    rsbinder::ProcessState::init("/dev/vndbinder", 0)
        .map(|_| ())
        .map_err(|error| error.to_string())
}
