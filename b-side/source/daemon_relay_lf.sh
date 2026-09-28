#!/system/bin/sh

# ommega-b relay daemon wrapper.
# Loops over the `relay` binary (the relay_server B-side client) so that it is
# restarted if it ever exits.  The relay daemon mints real-TEE attestation
# chains with an A-side-supplied appid (tag 709).

MODDIR=${0%/*}
STATE_DIR=/data/adb/ommega
CONF_FILE=$STATE_DIR/relay.conf

export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:/vendor/lib64/:/system/lib64/:/apex/com.android.runtime/lib64/bionic/"

# Mirror client-a's behaviour: keep the module's status (shown in KernelSU /
# Magisk) in sync with the relay daemon's real state.
update_status() {
  local status="$1"
  local prop_file="$MODDIR/module.prop"
  [ -f "$prop_file" ] || return 0
  sed -i "s/^description=.*/description=$status/" "$prop_file" 2>/dev/null || true
}

# NOTE: this wrapper intentionally has NO kill logic.  It never kills relay
# processes, even stale ones from a previous run or a manual launch — killing
# them caused healthy relays to die mid-TLS-handshake (exit 137).  The relay
# process itself handles config hot-reload; the wrapper only starts and waits.

find_module_relay() {
  if [ -f "$STATE_DIR/relay" ]; then
    echo "$STATE_DIR/relay"
    return 0
  fi
  if [ -f "$MODDIR/relay" ]; then
    echo "$MODDIR/relay"
    return 0
  fi
  if [ -f "$MODDIR/libs/arm64-v8a/relay" ]; then
    echo "$MODDIR/libs/arm64-v8a/relay"
    return 0
  fi
  if [ -f "$MODDIR/libs/x86_64/relay" ]; then
    echo "$MODDIR/libs/x86_64/relay"
    return 0
  fi
  return 1
}

load_relay_env() {
  # relay.conf uses KEY=VALUE lines; values with '#' are treated as comments.
  if [ -r "$CONF_FILE" ]; then
    while IFS='=' read -r key value; do
      case "$key" in
        \#*|"") continue ;;
      esac
      [ -z "$key" ] && continue
      value=$(echo "$value" | tr -d ' \t')
      case "$key" in
        OMMEGA_RELAY_SERVER|OMMEGA_RELAY_DEVICE_ID|OMMEGA_RELAY_MACHINE_ID|OMMEGA_RELAY_TOKEN|OMMEGA_RELAY_LOG_ENABLED|OMMEGA_RELAY_LOG_LEVEL|OMMEGA_RELAY_LOGCAT_ENABLED|OMMEGA_RELAY_LOGCAT_LEVEL)
          export "$key=$value"
          ;;
      esac
    done < "$CONF_FILE"
  fi
}

mkdir -p "$STATE_DIR"

# Single-instance guard: if another daemon-relay wrapper is already running,
# exit immediately instead of racing it.  This prevents two wrappers from
# starting two relays at once.
is_duplicate_daemon() {
  for pid in $(pgrep -f 'daemon-relay' 2>/dev/null); do
    [ "$pid" = "$$" ] && continue
    if [ -r "/proc/$pid/cmdline" ] && \
       tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | grep -F 'daemon-relay' >/dev/null 2>&1; then
      return 0
    fi
  done
  return 1
}
if is_duplicate_daemon; then
  echo "[relay-daemon] another daemon-relay already running; exiting"
  exit 0
fi

while true; do
  TARGET=$(find_module_relay)
  if [ -z "$TARGET" ]; then
    echo "[relay-daemon] relay binary not found"
    update_status "Ommega Attestation Relay Module ❌ relay binary not found"
    sleep 5
    continue
  fi

  chmod 0755 "$TARGET" 2>/dev/null || true

  load_relay_env

  "$TARGET" "$@" &
  child_pid=$!
  # Record the relay binary's own pid so service.sh can verify (after manual
  # execution) that the relay is genuinely running, not just the wrapper loop.
  echo $child_pid > "$STATE_DIR/relay.pid"

  # Confirm the relay really started (survived the first moments), then mark the
  # module as running — mirrors client-a's "启动后更新 module.prop".
  sleep 1
  if kill -0 "$child_pid" 2>/dev/null; then
    update_status "Ommega Attestation Relay Module ✅ 运行中"
  else
    update_status "Ommega Attestation Relay Module ❌ 启动失败"
  fi

  # The relay hot-reloads relay.conf and restart.all itself; the wrapper only
  # waits for it to exit (crash/stop) and restarts it. It never kills the relay
  # on config changes, so the two never fight.
  wait "$child_pid"
  rc=$?
  rm -f "$STATE_DIR/relay.pid"
  update_status "Ommega Attestation Relay Module ❌ 启动失败"
  echo "[relay-daemon] relay exited with code $rc"
  sleep 1
done
