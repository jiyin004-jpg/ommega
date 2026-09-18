#!/system/bin/sh
# Ommega (A-side) module uninstall hook.
#
# Runs automatically when the module is removed via a root manager
# (KernelSU / Magisk / APatch). Removes every runtime artifact the A-side
# creates so an uninstall leaves no residue: daemon processes, the whole
# /data/misc/keystore/ommega tree, A-side files under the shared
# /data/adb/ommega state dir, and WebUI temp files.

MODDIR=${0%/*}
STATE_DIR=/data/adb/ommega
OMMEGA_DIR=/data/misc/keystore/ommega

# ---------------------------------------------------------------------------
# 1. Stop runtime processes
#    The daemon watchdog loops respawn the keymint/ommega-inject binaries, so kill
#    the daemons first (matched by their module path), then their children.
#    Only paths under the module / hot-update dirs are matched so the system's
#    own keymint HAL process is never touched.
# ---------------------------------------------------------------------------
pkill -9 -f 'modules/ommega/daemon' 2>/dev/null
pkill -9 -f 'modules/ommega/libs' 2>/dev/null
pkill -9 -f "$STATE_DIR/keymint" 2>/dev/null
pkill -9 -f "$STATE_DIR/ommega-inject" 2>/dev/null
sleep 1

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
if [ -f "$STATE_DIR/pathmask.owned" ]; then
  rmmod pathmask 2>/dev/null || toybox rmmod pathmask 2>/dev/null
  rm -f "$STATE_DIR/pathmask.owned"
fi
rm -f "$STATE_DIR/pathmask.state" "$STATE_DIR/kmod-loader.log"

# ---------------------------------------------------------------------------
# 2. Remove the A-side data tree
#    Keymaster DB, config, keybox, logs, RPC socket, crash counter, webroot
#    cache, etc. This is A-side-only, so deleting it wholesale is safe.
# ---------------------------------------------------------------------------
rm -rf "$OMMEGA_DIR"

# ---------------------------------------------------------------------------
# 3. Remove A-side files under the shared state dir
#    /data/adb/ommega is shared with the B-side module (ommegaclient_b), so we
#    only touch A-side-owned entries and leave relay/relay.conf/logs intact.
# ---------------------------------------------------------------------------
rm -f "$STATE_DIR/ommegadata"          # symlink -> /data/misc/keystore/ommega
rm -f "$STATE_DIR/keymint"             # hot-update binary
rm -f "$STATE_DIR/ommega-inject"       # hot-update binary
rm -f "$STATE_DIR/injector"            # legacy hot-update binary
rm -f "$STATE_DIR/restart.keymint"
rm -f "$STATE_DIR/restart.injector"
rm -f "$STATE_DIR/restart.all"
rm -f "$STATE_DIR/keymint-daemon.pid"
rm -f "$STATE_DIR/injector-daemon.pid"

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
