#!/system/bin/sh
# ommega-b module uninstall hook.
#
# Runs automatically when the module is removed via a root manager
# (KernelSU / Magisk / APatch). Kills the relay agent and removes the B-side
# files under the shared /data/adb/ommega state dir. A-side (ommega module)
# files are left untouched so the two modules can be uninstalled independently.

MODDIR=${0%/*}
STATE_DIR=/data/adb/ommega

# ---------------------------------------------------------------------------
# 1. Stop the relay process (same kill pattern as service.sh).
# ---------------------------------------------------------------------------
pkill -9 -x relay 2>/dev/null
pkill -9 -f 'daemon-relay' 2>/dev/null
sleep 1

# ---------------------------------------------------------------------------
# 1b. Drop the relay's wake lock. It is a named lock in /sys/power/wake_lock and
#     is NOT tied to the process, so a killed relay leaves it behind -- and the
#     device would never suspend again. Release it explicitly.
# ---------------------------------------------------------------------------
if [ -w /sys/power/wake_unlock ]; then
  echo ommega_relay > /sys/power/wake_unlock 2>/dev/null
fi

# ---------------------------------------------------------------------------
# 2. Remove B-side files under the shared state dir. A-side files
#    (ommegadata symlink, keymint/inject, pid files, restart.*) are kept.
# ---------------------------------------------------------------------------
rm -f "$STATE_DIR/relay"              # hot-update relay binary
rm -f "$STATE_DIR/relay.conf"         # relay configuration
rm -f "$STATE_DIR/restart.all"
rm -rf "$STATE_DIR/logs"              # relay logs

# ---------------------------------------------------------------------------
# 3. Drop the shared state dir only if it is now completely empty.
# ---------------------------------------------------------------------------
[ -z "$(ls -A "$STATE_DIR" 2>/dev/null)" ] && rmdir "$STATE_DIR" 2>/dev/null

exit 0
