import io, os

def edit(path, pairs):
    t = io.open(path, encoding='utf-8').read()
    miss = []
    for old, new in pairs:
        if old not in t:
            miss.append(old.splitlines()[0][:60])
            continue
        t = t.replace(old, new, 1)
    io.open(path, 'w', encoding='utf-8', newline='\n').write(t)
    for m in miss:
        print('  !! 未匹配 %s: %s' % (os.path.basename(path), m))

# ---------------- layout.sh：砍到只剩 ommegadata 软链 ----------------
io.open('template/layout.sh', 'w', encoding='utf-8', newline='\n').write('''#!/system/bin/sh
# 开机幂等补一件事：`/data/adb/ommega/ommegadata` 软链。
#
# 面板「保存并生效」要把配置写进 /data/misc/keystore/ommega/，写的是这个软链；
# 它只在 customize.sh 里建过，而手动解压 / 热更新 / 直接把新文件盖进老模块目录
# 都不会跑 customize.sh，缺了它面板一保存就 No such file or directory。
#
# 这里**不再**搬二进制、不再往 bin/ 复制 resetprop：运行文件只认模块目录
# `libs/<abi>/`，`bin/` 那套热更新布局已废弃。

STATE_DIR=/data/adb/ommega
KS_DATA=/data/misc/keystore/ommega

if [ ! -e "$STATE_DIR/ommegadata" ] && [ ! -L "$STATE_DIR/ommegadata" ]; then
  mkdir -p "$KS_DATA" 2>/dev/null
  ln -s "$KS_DATA" "$STATE_DIR/ommegadata" 2>/dev/null
fi
''')

# ---------------- customize.sh：不再复制 resetprop 到 bin ----------------
edit('template/customize.sh', [(
    '''if [ -f "$BINDIR/resetprop" ]; then
  cp -f "$BINDIR/resetprop" "$BIN_DIR/resetprop.tmp"
  chmod 0755 "$BIN_DIR/resetprop.tmp"
  mv -f "$BIN_DIR/resetprop.tmp" "$BIN_DIR/resetprop"
  ui_print "- Bundled resetprop installed (no longer depends on the root manager)"
fi''',
    '''if [ -f "$BINDIR/resetprop" ]; then
  ui_print "- Bundled resetprop installed (no longer depends on the root manager)"
fi''')])

# ---------------- service.sh：kill_all 对准模块目录 ----------------
edit('template/service.sh', [(
    '''kill_all() {
  pkill -9 -f "$BIN_DIR/keymint" 2>/dev/null
  pkill -9 -f "$BIN_DIR/ommega-inject" 2>/dev/null
  sleep 1
}''',
    '''kill_all() {
  # 运行文件只在模块目录一处（`bin/` 布局已废弃）。这里按模块路径匹配，
  # 系统的 keymint HAL 永远不会被碰到。
  pkill -9 -f "$MODDIR/libs/.*/keymint" 2>/dev/null
  pkill -9 -f "$MODDIR/libs/.*/ommega-inject" 2>/dev/null
  pkill -9 -f "$MODDIR/daemon-injector" 2>/dev/null
  sleep 1
}''')])

# ---------------- post-fs-data.sh：resetprop 指模块目录 ----------------
edit('template/post-fs-data.sh', [(
    'RESETPROP_BIN=$BIN_DIR/resetprop',
    '''# resetprop 的唯一位置：模块内 `libs/<abi>/resetprop`（ELF，ksu 域可 execute）
pf_abi=$(getprop ro.product.cpu.abi 2>/dev/null)
case "$pf_abi" in
  arm64*|aarch64*) pf_abi=arm64-v8a ;;
  armeabi*|armv7*) pf_abi=armeabi-v7a ;;
  x86_64*) pf_abi=x86_64 ;;
  *) pf_abi=x86 ;;
esac
RESETPROP_BIN=$MODDIR/libs/$pf_abi/resetprop''')])

# ---------------- daemon-injector：ommega-inject 只认模块目录 ----------------
edit('template/daemon-injector', [(
    '''  if [ -f "$BIN_DIR/ommega-inject" ]; then
    echo "$BIN_DIR/ommega-inject"''',
    '''  if [ -f "$MODDIR/libs/$abi/ommega-inject" ]; then
    echo "$MODDIR/libs/$abi/ommega-inject"''')])

print('--- 剩余 bin 引用')
import re
for f in ('template/customize.sh', 'template/service.sh', 'template/post-fs-data.sh',
          'template/daemon-injector', 'template/layout.sh', 'template/uninstall.sh'):
    for i, line in enumerate(io.open(f, encoding='utf-8').read().splitlines(), 1):
        if 'BIN_DIR' in line:
            print('  %-20s %4d| %s' % (os.path.basename(f), i, line.strip()[:100]))
