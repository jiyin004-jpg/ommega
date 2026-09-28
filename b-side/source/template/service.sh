#!/system/bin/sh

# ommega-b relay module service.
# Single entry point for relay process management: before starting, it always
# kills any stale relay processes (from a previous run or a manual launch),
# then spawns a fresh relay binary directly.  No daemon wrapper is used.

MODDIR=${0%/*}
STATE_DIR=/data/adb/ommega
CONF_FILE=$STATE_DIR/relay.conf
LOCK_DIR=$STATE_DIR/relay-service.lock
RELAY_PID_FILE=$STATE_DIR/relay.pid
LOG_FILE=$STATE_DIR/logs/service.log

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

# ---------------------------------------------------------------------------
# 单例：一轮启动里 service.sh 会被并发执行好几次
# ---------------------------------------------------------------------------
# 实测（一加 PLC110 / KernelSU 3.3.0，2026-09-28 00:35:48 那次重启）：同一秒里
# service.sh 被拉起 6 份，每份都自己 fork 一个 while 守护循环，而各自的 kill_all
# 几乎同时执行、谁也杀不掉谁 —— 结果一台设备挂着 6 个 relay，全都拿同一个
# device_id 去抢同一台设备的任务，日志也互相打（service.log 被 6 份一起追加，
# 涨到 100MB 以上）。
#
# 锁借 mkdir 的原子性：抢到的负责起守护循环，并且一直持有（锁跟着守护循环那个
# 子 shell 活）；抢不到的只把现役 relay 杀一下就走 —— 旧守护两秒后会把它拉起来，
# 所以手动 `sh service.sh` 依旧是“重启 relay”的意思，只是不会再长出第二个循环。
# 陈锁（持有者早没了：强杀、断电）会被清掉重抢。
acquire_lock() {
  if mkdir "$LOCK_DIR" 2>/dev/null; then
    echo "$$" > "$LOCK_DIR/pid"
    return 0
  fi

  local holder
  holder=$(cat "$LOCK_DIR/pid" 2>/dev/null)
  if [ -n "$holder" ] && kill -0 "$holder" 2>/dev/null; then
    return 1
  fi

  rm -rf "$LOCK_DIR" 2>/dev/null
  mkdir "$LOCK_DIR" 2>/dev/null || return 1
  echo "$$" > "$LOCK_DIR/pid"
  return 0
}

# service.log 是纯追加的，以前没有任何上限。守护循环每次看见 relay 异常退出都会
# 写两行，多份实例并存时更是成倍增长（实测到过 125MB）。启动时超过 8MB 就轮转
# 一次，只留一份 .1。
rotate_log() {
  local size
  size=$(stat -c %s "$LOG_FILE" 2>/dev/null)
  case "$size" in
    ''|*[!0-9]*) return 0 ;;
  esac
  if [ "$size" -gt 8388608 ]; then
    mv -f "$LOG_FILE" "$LOG_FILE.1" 2>/dev/null
  fi
}

# 判断 relay 到底起来没有。原来用 `pgrep -x relay`，但在这台机器上它的退出码
# 一直不对 —— service.log 里 "relay is up" 从来没出现过一次，永远走 else 分支，
# 于是启动结果永远显示不准确（实际 relay 是好的，靠它自己改 module.prop 兜住）。
# 现在认守护循环写下的 pid：进程还在、cmdline 里带 relay，就算起来了。
pid_is_relay() {
  local pid=$1
  [ -n "$pid" ] || return 1
  kill -0 "$pid" 2>/dev/null || return 1
  [ -r "/proc/$pid/cmdline" ] || return 1
  case "$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)" in
    *relay*) return 0 ;;
  esac
  return 1
}

# Wait up to ~10s for the relay binary to actually start, so a manual
# `sh service.sh` can be trusted to have brought up the full service.
wait_for_relay() {
  local tries=0
  while [ $tries -lt 20 ]; do
    if pid_is_relay "$(cat "$RELAY_PID_FILE" 2>/dev/null)"; then
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

if ! acquire_lock; then
  echo "[service] another instance already owns $LOCK_DIR; restarting the running relay"
  kill_all
  exit 0
fi

rotate_log

kill_all

update_status "Ommega Attestation Relay Module ⏳ 启动中"

TARGET=$(find_module_relay)
if [ -z "$TARGET" ]; then
  echo "[service] relay binary not found"
  rm -rf "$LOCK_DIR"
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
  # 锁由这个子 shell 拿着，它活多久算多久；主脚本退出不影响它。
  trap 'rm -rf "$LOCK_DIR"' EXIT INT TERM HUP
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
    echo "$child" > "$RELAY_PID_FILE"
    echo "[service] relay started (pid $child)"
    wait "$child"
    rc=$?
    rm -f "$RELAY_PID_FILE" 2>/dev/null
    echo "[service] relay exited (code $rc); restarting in 2s"
    sleep 2
  done
) >> "$LOG_FILE" 2>&1 &

# 锁里记守护循环（= 子 shell）的 pid：子 shell 里的 $$ 仍是父 shell 的 pid，
# 所以只能由主脚本用 $! 写。
echo "$!" > "$LOCK_DIR/pid"

# 先确认第一次是否真的起来了，好在模块日志里给出可见结果。
if wait_for_relay; then
  echo "[service] ommega-b relay is up"
else
  echo "[service] relay did not come up within 10s; watchdog will keep retrying"
fi
