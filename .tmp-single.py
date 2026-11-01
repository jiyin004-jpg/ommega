import io, os, re

def edit(path, pairs):
    t = io.open(path, encoding='utf-8').read()
    for old, new in pairs:
        if old not in t:
            print('  !! %s 未匹配: %s' % (path, old[:50]))
            continue
        t = t.replace(old, new, 1)
    io.open(path, 'w', encoding='utf-8', newline='\n').write(t)

# ---------- service.sh ----------
edit('template/service.sh', [
    # 注入器：唯一 shell 实现，不做 watchdog 优先
    ('''INJECTOR_CMD=$MODDIR/daemon-injector
for cand in "$BIN_DIR/inject-watchdog" "$MODDIR/libs/arm64-v8a/inject-watchdog"; do
  if [ -x "$cand" ]; then
    INJECTOR_CMD=$cand
    break
  fi
done''',
     '''# 注入器的唯一实现：shell 脚本 `daemon-injector`。
#
# 这里**不再有 Rust 版 watchdog**：watchdog 是 ELF，能被执行（ksu 域有 execute 权限），
# 但它内部要 `sh daemon-injector` —— 跑 shell 脚本需要的是 **read** 权限，而模块目录的
# 标签是 magisk_file，ksu 域没有 read（实测 `sh: Permission denied`，退出码 127）。
# 所以那条路天生走不通，只保留 shell 版，由本脚本（magiskd 域，有 read）拉起。
INJECTOR_CMD=$MODDIR/daemon-injector'''),
    # keymint 路径：只认模块目录
    ('''find_keymint_bin() {
  for cand in "$BIN_DIR/keymint" "$MODDIR/keymint" "$MODDIR/libs/arm64-v8a/keymint" \\
              "$MODDIR/libs/armeabi-v7a/keymint" "$MODDIR/libs/x86_64/keymint" "$MODDIR/libs/x86/keymint"; do
    if [ -x "$cand" ]; then
      echo "$cand"
      return 0
    fi
  done
  return 1
}''',
     '''# keymint 的唯一位置：模块内的 `libs/<abi>/keymint`（按本机 ABI 取）。
#
# ELF 只需要 execute 权限，ksu 域有，所以能直接从模块目录跑；`bin/` 那套热更新
# 布局已经废弃 —— 运行位置只有一个，热更新就是重装模块。
find_keymint_bin() {
  abi=$(getprop ro.product.cpu.abi 2>/dev/null)
  case "$abi" in
    arm64*|aarch64*) abi=arm64-v8a ;;
    armeabi*|armv7*) abi=armeabi-v7a ;;
    x86_64*) abi=x86_64 ;;
    *) abi=x86 ;;
  esac
  cand="$MODDIR/libs/$abi/keymint"
  if [ -x "$cand" ]; then
    echo "$cand"
    return 0
  fi
  return 1
}'''),
    # injector 启动：不再回落
    ('''  if ! start_daemon "$INJECTOR_CMD" "$RUN_DIR/injector-daemon.pid"; then
    INJECTOR_CMD=$MODDIR/daemon-injector
    start_daemon "$INJECTOR_CMD" "$RUN_DIR/injector-daemon.pid" || true
  fi''',
     '''  start_daemon "$INJECTOR_CMD" "$RUN_DIR/injector-daemon.pid" || true'''),
    # kill_all 去掉 watchdog
    ('  pkill -9 -f "$BIN_DIR/inject-watchdog" 2>/dev/null\n', ''),
    # case 去掉 watchdog
    ('*daemon-injector|*inject-watchdog) ensure_sepolicy ;;', '*daemon-injector) ensure_sepolicy ;;'),
])

# ---------- post-fs-data.sh ----------
edit('template/post-fs-data.sh', [
    ('''if [ -x "$BIN_DIR/keymint" ] || [ -x "$MODDIR/libs/arm64-v8a/keymint" ]; then
  km_bin=$BIN_DIR/keymint
  [ -x "$km_bin" ] || km_bin=$MODDIR/libs/arm64-v8a/keymint''',
     '''pf_abi=$(getprop ro.product.cpu.abi 2>/dev/null)
case "$pf_abi" in
  arm64*|aarch64*) pf_abi=arm64-v8a ;;
  armeabi*|armv7*) pf_abi=armeabi-v7a ;;
  x86_64*) pf_abi=x86_64 ;;
  *) pf_abi=x86 ;;
esac
km_bin=$MODDIR/libs/$pf_abi/keymint
if [ -x "$km_bin" ]; then'''),
    ('''# 注入器：优先 Rust 的 inject-watchdog（不可执行时回落 shell 版）。
injector_script=$MODDIR/daemon-injector
[ -x "$BIN_DIR/inject-watchdog" ] && injector_script=$BIN_DIR/inject-watchdog
if [ -f "$MODDIR/daemon-injector" ]; then''',
     '''# 注入器：唯一实现是 shell 版 daemon-injector（Rust 的 watchdog 走不通，见 service.sh）。
injector_script=$MODDIR/daemon-injector
if [ -f "$injector_script" ]; then'''),
])

# ---------- daemon.rs ----------
edit('src/daemon.rs', [
    # find_keymint：只认模块 libs
    ('''fn find_keymint() -> Option<PathBuf> {
    for cand in [format!("{BIN_DIR}/keymint"), format!("{MODDIR}/keymint")] {
        let path = PathBuf::from(cand);
        if path.is_file() {
            return Some(path);
        }
    }
    let abi = resetprop::read_string_property("ro.product.cpu.abi").unwrap_or_default();''',
     '''fn find_keymint() -> Option<PathBuf> {
    // 唯一位置：模块内的 `libs/<abi>/keymint`。ELF 只要能 execute（ksu 域有），
    // 不需要 read；`bin/` 那套热更新布局已废弃。
    let abi = resetprop::read_string_property("ro.product.cpu.abi").unwrap_or_default();'''),
])

# ---------- resetprop.rs ----------
edit('src/plat/resetprop.rs', [
    ('const RESETPROP_BUNDLED: &str = "/data/adb/ommega/bin/resetprop";',
     '''/// resetprop 的唯一位置：模块内的 `libs/<abi>/resetprop`（ELF，ksu 域可 execute）。
///
/// 以前这里指 `/data/adb/ommega/bin/resetprop`（热更新布局），已经废弃——
/// 运行文件只在模块目录一处，热更新就是重装模块。
fn resetprop_path() -> String {
    let abi = rsproperties::get::<String>("ro.product.cpu.abi")
        .unwrap_or_default()
        .trim()
        .to_string();
    let dir = if abi.starts_with("arm64") || abi.starts_with("aarch64") {
        "arm64-v8a"
    } else if abi.starts_with("armeabi") || abi.starts_with("armv7") {
        "armeabi-v7a"
    } else if abi.starts_with("x86_64") {
        "x86_64"
    } else {
        "x86"
    };
    format!("/data/adb/modules/ommega/libs/{dir}/resetprop")
}'''),
])

print('改完')
for f in ('template/service.sh', 'template/post-fs-data.sh', 'src/daemon.rs', 'src/plat/resetprop.rs'):
    t = io.open(f, encoding='utf-8').read()
    print('  %-28s watchdog=%d BIN_DIR/keymint=%d' % (f, t.count('inject-watchdog'), t.count('BIN_DIR/keymint')))
