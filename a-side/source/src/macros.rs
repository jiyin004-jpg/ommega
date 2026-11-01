/// Generates a message containing the current source file name and line number.
///
/// # Examples
///
/// ```
/// source_location_msg!("Key is expired.");
/// Result:
/// "src/lib.rs:7 Key is expired."
/// ```
#[macro_export]
macro_rules! err {
    { $($arg:tt)+ } => {
        format!("{}:{} {}", file!(), line!(), format_args!($($arg)+))
    };
    {} => {
        format!("{}:{}", file!(), line!())
    };
}

#[macro_export]
macro_rules! root_path {
    () => {
        "/data/misc/ommega"
    };
    ($leaf:literal) => {
        concat!("/data/misc/ommega/", $leaf)
    };
}

/// 密钥材料 + IPC 的根：只有 keystore 域用，app 域不该也不能读。
#[macro_export]
macro_rules! secret_path {
    () => {
        "/data/misc/keystore/ommega"
    };
    ($leaf:literal) => {
        concat!("/data/misc/keystore/ommega/", $leaf)
    };
}
