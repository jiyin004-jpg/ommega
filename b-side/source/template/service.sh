#!/system/bin/sh

# ommegaclient-b relay module service.
# Single entry point for relay process management: before starting, it always
# kills any stale relay processes (from a previous run or a manual launch),
# then spawns a fresh relay binary directly.  No daemon wrapper is used.

MODDIR=${0%/*}
STATE_DIR=/data/adb/ommega
CONF_FILE=$STATE_DIR/relay.conf

export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:/vendor/lib64/:/system/lib64/:/apex/com.android.runtime/lib64/bionic/"

mkdir -p "$STATE_DIR" "$STATE_DIR/logs"

# Reflect the module state in module.prop (shown by KernelSU/Magisk).
# service.sh writes ⏳ before starting; the relay binary itself then
# overwrites it with ✅ 运行中 once it is up, or ❌ 启动失败 if its config
# fails — so executing service.sh always produces a visible state change.
update_status() {
  local status="$1"
  local prop_file="$MODDIR/module.prop"
  [ -f "$prop_file" ] || return 0
  sed -i "s/^description=.*/description=$status/" "$prop_file" 2>/dev/null || true
}

# Resolve the device ABI.  A single module zip now carries several ABIs at
# once, so the libs/<abi> directory must be picked by what this device actually
# runs — falling back to directory order would hand an x86_64 tablet the arm64
# binary.
device_abi() {
  local abi
  abi="$(getprop ro.product.cpu.abi 2>/dev/null)"
  [ -n "$abi" ] || abi="$(uname -m 2>/dev/null)"
  case "$abi" in
    arm64*|aarch64*) echo arm64-v8a ;;
    x86_64*) echo x86_64 ;;
    armeabi*|armv7*) echo armeabi-v7a ;;
    i?86|x86) echo x86 ;;
    *) echo "" ;;
  esac
}

# Locate the relay binary: a user-placed override under $STATE_DIR wins,
# then the module dir, then the module libs/<abi>/ dir for this device.
find_module_relay() {
  if [ -f "$STATE_DIR/relay" ]; then
    echo "$STATE_DIR/relay"
    return 0
  fi
  if [ -f "$MODDIR/relay" ]; then
    echo "$MODDIR/relay"
    return 0
  fi

  local abi
  abi=$(device_abi)
  if [ -n "$abi" ] && [ -f "$MODDIR/libs/$abi/relay" ]; then
    echo "$MODDIR/libs/$abi/relay"
    return 0
  fi

  # getprop/uname unavailable; accept any packaged ABI rather than nothing.
  for abi in arm64-v8a x86_64; do
    if [ -f "$MODDIR/libs/$abi/relay" ]; then
      echo "$MODDIR/libs/$abi/relay"
      return 0
    fi
  done
  return 1
}

# Export OMMEGA_RELAY_* settings from relay.conf (KEY=VALUE lines, '#' = comment).
load_relay_env() {
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

# Wait up to ~10s for the relay binary to actually start. We check by process
# name only (no pid files), so a manual `sh service.sh` can be trusted to have
# brought up the full service.
wait_for_relay() {
  local tries=0
  while [ $tries -lt 20 ]; do
    if pgrep -x relay >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.5
    tries=$((tries + 1))
  done
  return 1
}

# Kill every relay-related process by name only. 'daemon-relay' is matched too
# so leftover wrappers from older module versions get cleaned up.
kill_all() {
  pkill -9 -f 'daemon-relay' 2>/dev/null
  pkill -9 -x relay 2>/dev/null
}

kill_all

update_status "Ommega Attestation Relay Module ⏳ 启动中"

TARGET=$(find_module_relay)
if [ -z "$TARGET" ]; then
  echo "[service] relay binary not found"
  exit 1
fi

chmod 0755 "$TARGET" 2>/dev/null || true
load_relay_env

# 守护循环（放在子 shell 里后台跑，service.sh 本身不阻塞启动流程）：
# B 端要 7×24 挂着领任务，而 relay 除了这里没有任何东西会把它拉起来 ——
# 只有重启手机或重装模块才会再进 service.sh。原版是 `"$TARGET" &` 加
# 等 10s 就退出，进程一挂设备就静默地不再领任务了。A 端 daemon 早就有
# 这个 while 循环，B 端现在对齐。
(
  while true; do
    TARGET=$(find_module_relay)
    if [ -z "$TARGET" ]; then
      echo "[service] relay binary vanished; retrying in 5s"
      sleep 5
      continue
    fi
    chmod 0755 "$TARGET" 2>/dev/null || true
    # 每轮都重新导环境：守护进程要能感知 relay.conf 的改动。
    load_relay_env
    "$TARGET" &
    child=$!
    echo "[service] relay started (pid $child)"
    wait "$child"
    rc=$?
    echo "[service] relay exited (code $rc); restarting in 2s"
    sleep 2
  done
) >> "$STATE_DIR/logs/service.log" 2>&1 &

# 先确认第一次是否真的起来了，好在模块日志里给出可见结果。
if wait_for_relay; then
  echo "[service] ommegaclient-b relay is up"
else
  echo "[service] relay did not come up within 10s; watchdog will keep retrying"
fi
