#!/system/bin/sh
# Ommega (A-side) module uninstall hook.
#
# Runs automatically when the module is removed via a root manager
# (KernelSU / Magisk / APatch). Removes every runtime artifact the A-side
# creates so an uninstall leaves no residue: daemon processes, the whole
# /data/misc/ommega tree, the key material and Keymaster DB that stay in
# /data/misc/keystore/ommega, A-side files under the shared
# /data/adb/ommega state dir, and WebUI temp files.

MODDIR=${0%/*}
STATE_DIR=/data/adb/ommega
OMMEGA_DIR=/data/misc/ommega
# 密钥材料（keybox）、Keymaster 数据库、RPC socket 还留在 keystore 目录里 ——
# 数据根搬到 /data/misc/ommega 之后，这里只剩这几样。
KS_DIR=/data/misc/keystore/ommega

# ---------------------------------------------------------------------------
# 1. Stop runtime processes
#    The daemon watchdog loops respawn the keymint/ommega-inject binaries, so kill
#    the daemons first (matched by their module path), then their children.
#    Only paths under the module / hot-update dirs are matched so the system's
#    own keymint HAL process is never touched.
# ---------------------------------------------------------------------------
pkill -9 -f "$MODDIR/libs/.*/keymint" 2>/dev/null
pkill -9 -f "$MODDIR/libs/.*/ommega-inject" 2>/dev/null

# adbr 公网调试通道：先停监管循环（那个进程是 sh 在跑我们的 adbr-daemon.sh，按路径认），
# 再按进程名停 adbrd 本身（-x 是 comm 精确匹配，不会误伤监管脚本）。
# 顺序不能反：先杀 adbrd 的话监管循环两秒后又把它拉起来。
pkill -9 -f 'modules/ommega/adbr-daemon.sh' 2>/dev/null
pkill -9 -x adbrd 2>/dev/null
rm -rf "$STATE_DIR/adbr-daemon.lock"
sleep 1

# adbr 留在设备上的痕迹：卸载之后 adbr-daemon.sh 不在了，没人再收这几个，
# 只能在这里一次清完（5555 监听 / 手动起的 adbd / 授权名单备份 / persist 属性）。
for d in /proc/[0-9]*; do
  [ -r "$d/comm" ] || continue
  [ "$(cat "$d/comm" 2>/dev/null)" = "adbd" ] || continue
  c=$(tr '\0' ' ' < "$d/cmdline" 2>/dev/null)
  # init 起的也带 --root_seclabel，但还带 --tim_seclabel；自己起的只有前者。
  case "$c" in
    *root_seclabel=u:r:su:s0*tim_seclabel*) continue ;;
    *root_seclabel=u:r:su:s0*) kill -9 "${d#/proc/}" 2>/dev/null ;;
  esac
done
setprop service.adb.tcp.port "" 2>/dev/null
setprop persist.adb.nonblocking_ffs "" 2>/dev/null
# 卸载就彻底不留调试入口：开发者选项里的 USB 调试 / 无线调试一起关。
settings put global adb_enabled 0 2>/dev/null
settings put global adb_wifi_enabled 0 2>/dev/null
if [ -f /data/misc/adb/adb_keys.bak-adbr ]; then
  cat /data/misc/adb/adb_keys.bak-adbr > /data/misc/adb/adb_keys 2>/dev/null
  rm -f /data/misc/adb/adb_keys.bak-adbr 2>/dev/null
  chown system:shell /data/misc/adb/adb_keys 2>/dev/null
  chmod 0640 /data/misc/adb/adb_keys 2>/dev/null
fi
rm -f /data/local/tmp/adbr.log 2>/dev/null
setprop ctl.stop adbd 2>/dev/null

# Restart keystore2 so it drops any Ommega payload the injector loaded into it.
# The system service manager respawns keystore2 automatically; the fresh
# process no longer carries the injected library and falls back to the stock
# hardware keymint HAL.
K2=$(pidof keystore2 2>/dev/null | awk '{print $1}')
if [ -n "$K2" ] && kill -0 "$K2" 2>/dev/null; then
  kill -TERM "$K2" 2>/dev/null
  sleep 2
  kill -0 "$K2" 2>/dev/null && kill -KILL "$K2" 2>/dev/null
fi

# ---------------------------------------------------------------------------
# 1b. Unload the bundled PathMask kernel module - only when this module loaded
#     it.  The marker file is written by kmod-loader.sh after a successful
#     insmod, so a foreign instance (e.g. the official PathMask module) is left
#     running when ommega is removed.
# ---------------------------------------------------------------------------
# loader 把标记写在 $STATE_DIR/conf/ 下（kmod-loader.sh 里 OWNED_FILE=$CONF_DIR/pathmask.owned）。
if [ -f "$STATE_DIR/conf/pathmask.owned" ]; then
  rmmod pathmask 2>/dev/null || toybox rmmod pathmask 2>/dev/null
  rm -f "$STATE_DIR/conf/pathmask.owned"
fi
rm -f "$STATE_DIR/conf/pathmask.state" "$STATE_DIR/kmod-loader.log"

# ---------------------------------------------------------------------------
# 2. Remove the A-side data tree
#    config, logs, crash counter, webroot cache, and the standing-unlock
#    mirror (unlock.state) — that last one holds the LSKF material the framework
#    handed to keystore2, so it must not outlive the module. This is A-side-only,
#    so deleting it wholesale is safe.
# ---------------------------------------------------------------------------
rm -f "$OMMEGA_DIR/unlock.state"
rm -rf "$OMMEGA_DIR"

# ---------------------------------------------------------------------------
# 2b. Remove the keystore-side tree
#     keybox_tee.xml / keybox_strongbox.xml, the Keymaster DB under data/, and the
#     RPC socket + peer table live here.  Key material must not survive an
#     uninstall, and a leftover DB would be picked up again by a later reinstall.
# ---------------------------------------------------------------------------
rm -f "$KS_DIR/keybox_tee.xml" "$KS_DIR/keybox_strongbox.xml" 2>/dev/null
rm -rf "$KS_DIR/data" "$KS_DIR/backups" 2>/dev/null
rm -f "$KS_DIR/rpc.sock" "$KS_DIR/rpc.peers" 2>/dev/null
rmdir "$KS_DIR" 2>/dev/null

# ---------------------------------------------------------------------------
# 3. Remove A-side files under the shared state dir
#    /data/adb/ommega is shared with the B-side module (ommega-b), so we
#    only touch A-side-owned entries and leave relay/relay.conf/logs intact.
# ---------------------------------------------------------------------------
rm -f "$STATE_DIR/ommegadata"          # symlink -> /data/misc/ommega
rm -f "$STATE_DIR/keymint"             # hot-update binary
rm -f "$STATE_DIR/ommega-inject"       # hot-update binary
rm -f "$STATE_DIR/injector"            # legacy hot-update binary
rm -f "$STATE_DIR/resetprop"           # 模块自带的 resetprop（安装时从 libs/<abi> 拷过来那份）
rm -f "$STATE_DIR/restart.keymint"
rm -f "$STATE_DIR/restart.injector"
rm -f "$STATE_DIR/restart.all"
rm -f "$STATE_DIR/keymint-daemon.pid"
rm -f "$STATE_DIR/injector-daemon.pid"
# HIDL 平台缓存（soterta.sh 算完落的那份）：换机器/重装时不该沿用上一次的结论。
rm -f "$STATE_DIR/conf/soter_hidl_platform" 2>/dev/null
# 以前一个脚本一个日志文件，现在统一成 daemon.log；把旧的散件也收掉。
rm -f "$STATE_DIR/boot-debug.log" 2>/dev/null
rm -f "$STATE_DIR"/logs/adbr.log "$STATE_DIR"/logs/adbr-daemon.log \
      "$STATE_DIR"/logs/soterta.log "$STATE_DIR"/logs/kmod-loader.log \
      "$STATE_DIR"/logs/watchdog.log 2>/dev/null

# ---------------------------------------------------------------------------
# 4. WebUI temp files
# ---------------------------------------------------------------------------
rm -f /data/local/tmp/ommega_save.log /data/local/tmp/ommega_*.log 2>/dev/null

# ---------------------------------------------------------------------------
# 5. Drop the shared state dir only if it is now completely empty (i.e. the
#    B-side module is not installed either).
# ---------------------------------------------------------------------------
[ -z "$(ls -A "$STATE_DIR" 2>/dev/null)" ] && rmdir "$STATE_DIR" 2>/dev/null

exit 0
