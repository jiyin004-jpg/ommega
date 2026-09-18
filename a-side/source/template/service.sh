MODDIR=${0%/*}
STATE_DIR=/data/adb/ommega
PROP_FILE="$MODDIR/module.prop"

mkdir -p "$STATE_DIR"

# Update the module.prop description so the module card reflects runtime state.
# Mirrors the legacy A-side (client-a) behaviour.
update_status() {
  local status="$1"
  [ -f "$PROP_FILE" ] || return 0
  sed -i 's/^description=.*/description='"$status"'/' "$PROP_FILE" 2>/dev/null || true
}

pid_matches_script() {
  pid=$1
  script=$2
  [ -r "/proc/$pid/cmdline" ] || return 1
  cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)
  echo "$cmdline" | grep -F "$script" >/dev/null 2>&1
}

start_daemon() {
  script=$1
  pidfile=$2

  if [ -f "$pidfile" ]; then
    pid=$(cat "$pidfile" 2>/dev/null)
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && pid_matches_script "$pid" "$script"; then
      return 0
    fi
    rm -f "$pidfile"
  fi

  sh "$script" &
  pid=$!
  echo $pid > "$pidfile"
  sleep 1
  if ! kill -0 "$pid" 2>/dev/null || ! pid_matches_script "$pid" "$script"; then
    rm -f "$pidfile"
    return 1
  fi
  return 0
}

# WebUI is served by the KernelSU/APatch manager, which auto-detects the
# module's webroot/ folder and injects the window.ksu bridge. No separate
# web server is needed.

# Unconditionally clear any leftover module processes so a fresh start never
# coexists with a stale instance (e.g. after a module update or a manual
# restart where the old watchdog died but its children survived). Only
# module-owned paths are matched; the system keymint HAL is never touched.
kill_all() {
  pkill -9 -f 'modules/ommega/daemon' 2>/dev/null
  pkill -9 -f 'modules/ommega/libs' 2>/dev/null
  pkill -9 -f "$STATE_DIR/keymint" 2>/dev/null
  pkill -9 -f "$STATE_DIR/ommega-inject" 2>/dev/null
  sleep 1
}

kill_all

update_status "Ommega ⏳ 启动中"

start_daemon "$MODDIR/daemon" "$STATE_DIR/keymint-daemon.pid"
start_daemon "$MODDIR/daemon-injector" "$STATE_DIR/injector-daemon.pid"

# Bundled PathMask kernel module: pick the .ko matching this kernel and hide
# /system/priv-app/SoterService only when its binder service cannot be reached
# (see kmod-loader.sh).  Detached on purpose: it has to finish well within a few
# seconds and must never delay late_start or the daemons above.
if [ -f "$MODDIR/kmod-loader.sh" ]; then
  ( sh "$MODDIR/kmod-loader.sh" >> "$STATE_DIR/kmod-loader.log" 2>&1 & )
fi
