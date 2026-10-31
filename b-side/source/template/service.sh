#!/system/bin/sh

# ommega-b relay module service.
# Single entry point for relay process management: before starting, it always
# kills any stale relay processes (from a previous run or a manual launch),
# then spawns a fresh relay binary directly.  No daemon wrapper is used.

MODDIR=${0%/*}
STATE_DIR=/data/adb/ommega-b
BIN_DIR=$STATE_DIR/bin
CONF_DIR=$STATE_DIR/conf
RUN_DIR=$STATE_DIR/run
DB_DIR=$STATE_DIR/db
[ -f "$MODDIR/layout.sh" ] && . "$MODDIR/layout.sh" 2>/dev/null
CONF_FILE=$CONF_DIR/relay.conf
LOCK_DIR=$RUN_DIR/relay-service.lock
RELAY_PID_FILE=$RUN_DIR/relay.pid

# Android 17's system liblog.so references __hash_memory from the system
# libc++.so.  Some vendor images still ship an older libc++.so; keeping
# /vendor/lib64 first makes the dynamic linker reject relay before main().
# Put the platform runtime first and retain vendor libraries as a fallback.
export LD_LIBRARY_PATH="/system/lib64:/apex/com.android.runtime/lib64/bionic:/vendor/lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

mkdir -p "$STATE_DIR"

# relay.conf 里 `OMMEGA_RELAY_LOG_ENABLED` 关着时不要建 logs 目录、也不要开任何
# .log：以前这里无条件 mkdir + `>> logs/xxx.log`，关着日志也会留下一堆空文件
# （service.log 还会因为 relay 的 stdout 越写越大）。关着时一概重定向到 /dev/null。
debug_logging_enabled() {
  grep -qE '^[[:space:]]*OMMEGA_RELAY_LOG_ENABLED[[:space:]]*=[[:space:]]*(true|1|yes|on)' "$CONF_FILE" 2>/dev/null
}

if debug_logging_enabled; then
  mkdir -p "$STATE_DIR/logs"
  LOG_DIR="$STATE_DIR/logs"
  LOG_FILE="$LOG_DIR/service.log"
else
  LOG_DIR=/dev/null
  LOG_FILE=/dev/null
fi

# 单个脚本的日志目标：开日志才给真路径，否则全部丢 /dev/null。
log_target() {
  if [ "$LOG_DIR" = /dev/null ]; then
    printf '/dev/null'
  else
    printf '%s/%s' "$LOG_DIR" "$1"
  fi
}

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
  if [ -f "$BIN_DIR/relay" ]; then
    echo "$BIN_DIR/relay"
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
        OMMEGA_RELAY_SERVER|OMMEGA_RELAY_DEVICE_ID|OMMEGA_RELAY_MACHINE_ID|OMMEGA_RELAY_TOKEN|OMMEGA_RELAY_LOG_ENABLED|OMMEGA_RELAY_LOG_LEVEL|OMMEGA_RELAY_LOGCAT_ENABLED|OMMEGA_RELAY_LOGCAT_LEVEL|OMMEGA_RELAY_SOTER_MUTATION|OMMEGA_RELAY_SOTER_CONCURRENCY|OMMEGA_RELAY_ENABLED|OMMEGA_RELAY_ABDR_ENABLED|OMMEGA_RELAY_PATCHLEVEL_FOLLOW_A|OMMEGA_RELAY_PATCHLEVEL_METHOD)
          export "$key=$value"
          ;;
      esac
    done < "$CONF_FILE"
  fi
}

# 从 relay.conf 的某个键上取真/假。取值都在子 shell 里跑（$(...)），不影响本进程环境。
conf_truthy() {
  value=$(sed -n "s/^$1=//p" "$CONF_FILE" 2>/dev/null | tail -n 1 | tr -d ' \t\r' | tr 'A-Z' 'a-z')
  case "$value" in
    1|true|yes|on) return 0 ;;
  esac
  return 1
}

# WebUI 的「允许远控」总开关（OMMEGA_RELAY_ENABLED）。
# 没写这个键 = 开：老配置里压根没有它，不能因为升级模块就把别人的 relay 停了。
relay_enabled() {
  grep -q '^OMMEGA_RELAY_ENABLED=' "$CONF_FILE" 2>/dev/null || return 0
  conf_truthy OMMEGA_RELAY_ENABLED
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
# 锁里的 pid 可能是上一份实例留下的，而那个号早被别的进程复用了 —— 只看 kill -0 会
# 一直认为「已经有实例在跑」，B 端的后果更重：service.sh 会走「另一个实例持锁」那条
# 分支，把 relay 杀掉然后退出，于是 relay 永远没人拉（2026-10-16，与 A 端同源）。
holder_is_us() {
  p=$1
  s=$2
  [ -n "$p" ] || return 1
  kill -0 "$p" 2>/dev/null || return 1
  [ -r "/proc/$p/cmdline" ] || return 1
  # cmdline 里 NUL 转成空格，所以路径后面一定跟着空格，能把前缀相同的脚本名区分开。
  tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | grep -F "sh $s " >/dev/null 2>&1
}

# 只认自己持有的锁：抢锁有竞态（两份同时判定陈锁时会把对方刚建的锁删掉），
# 所以拿到之后要再核一次归属；退出时也只删自己的锁。
lock_owned() { [ "$(cat "$LOCK_DIR/pid" 2>/dev/null)" = "$$" ]; }
release_lock() { lock_owned && rm -rf "$LOCK_DIR" 2>/dev/null; return 0; }

acquire_lock() {
  if mkdir "$LOCK_DIR" 2>/dev/null; then
    echo "$$" > "$LOCK_DIR/pid"
    sleep 1
    lock_owned || return 1
    return 0
  fi

  local holder
  holder=$(cat "$LOCK_DIR/pid" 2>/dev/null)
  if holder_is_us "$holder" "$0"; then
    return 1
  fi

  rm -rf "$LOCK_DIR" 2>/dev/null
  mkdir "$LOCK_DIR" 2>/dev/null || return 1
  echo "$$" > "$LOCK_DIR/pid"
  sleep 1
  lock_owned || return 1
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
# adbr 监管循环（adbr-daemon.sh）要是被系统清掉（低内存 / 清理类 App），adbrd 就没
# 人拉了 —— 它自己有锁、自己看住 adbrd，所以这里只做「死了就补」：锁在且持有者
# 活着就是零开销。
keep_adbr_watchdog_alive() {
  [ -f "$MODDIR/adbr-daemon.sh" ] || return 0
  abr_holder=$(cat "$RUN_DIR/adbr-daemon.lock/pid" 2>/dev/null)
  if [ -z "$abr_holder" ] || ! holder_is_us "$abr_holder" "$MODDIR/adbr-daemon.sh"; then
    rm -rf "$RUN_DIR/adbr-daemon.lock" 2>/dev/null
    ( sh "$MODDIR/adbr-daemon.sh" --b >> "$(log_target adbr-daemon.log)" 2>&1 & )
  fi
}

# ---------------------------------------------------------------------------
# spl daemon：补丁日期第二种改法（OMMEGA_RELAY_PATCHLEVEL_METHOD=live）
# ---------------------------------------------------------------------------
# relay 通过 abstract socket @spl-daemon 让这个进程直接改 KeyMint TA 的
# attestation 配置（不改属性、不弹 keymint HAL）。它得在 uid 1000 的进程里
# 跑：root 域读不到 vendor 下那几个库（2026-10-17 小米 peridot 实测），所以不
# 能直接由 service.sh 拉，得借 su 换身份。
#
# 非高通机器上这个二进制能起来也连不上 TA，会自己退出 —— 所以失败后 15 秒才
# 再试一次，不要每 2 秒刷一遍日志。真正的可用性判断在 relay 那边：APPLY 连不上
# 就当场退回改属性那条路。
spl_method_is_live() {
  value=$(sed -n 's/^OMMEGA_RELAY_PATCHLEVEL_METHOD=//p' "$CONF_FILE" 2>/dev/null | tail -n 1 | tr -d ' \t\r' | tr 'A-Z' 'a-z')
  [ "$value" = "live" ]
}

find_spl_bin() {
  if [ -f "$BIN_DIR/spl_daemon" ]; then
    echo "$BIN_DIR/spl_daemon"
    return 0
  fi
  local abi
  abi=$(device_abi)
  if [ -n "$abi" ] && [ -f "$MODDIR/libs/$abi/spl_daemon" ]; then
    echo "$MODDIR/libs/$abi/spl_daemon"
    return 0
  fi
  return 1
}

spl_daemon_running() {
  # 快路径：pidof 一次就能问到，不必每轮扫 900 个 /proc（service.sh 实测吃 30% CPU）
  pidof spl_daemon >/dev/null 2>&1 && return 0
  # 回退：只看进程名（/proc/<pid>/comm），不看整条 cmdline：我们自己的调试命令
  # （pidof spl_daemon、ls .../spl_daemon）cmdline 里也带这个字，用 cmdline 判会把
  # 命 令行当成 daemon 在跑，结果永远不拉起（2026-10-22 踩到）。
  for d in /proc/[0-9]*; do
    [ -r "$d/comm" ] || continue
    [ "$(cat "$d/comm" 2>/dev/null)" = "spl_daemon" ] && return 0
  done
  return 1
}

# 找一个能换 uid 的 su：KernelSU / APatch 都自带，路径各家不同。
spl_su() {
  for cand in su /data/adb/ksu/bin/su /data/adb/ap/bin/su /system/bin/su; do
    if command -v "$cand" >/dev/null 2>&1; then
      echo "$cand"
      return 0
    fi
  done
  return 1
}

keep_spl_alive() {
  spl_method_is_live || return 0
  spl_daemon_running && return 0

  local now last
  now=$(date +%s 2>/dev/null || echo 0)
  last=$(cat "$RUN_DIR/spl_daemon.retry" 2>/dev/null || echo 0)
  case "$last" in ''|*[!0-9]*) last=0 ;; esac
  # 退避 15 秒：非高通机器上每次尝试都会失败，不能每 2 秒刷一遍日志；
  # 但也不能太长 —— 自己 TERM 停掉后要尽快回来（60 秒时面板会显示未运行一分钟）。
  if [ "$now" -gt 100000 ] && [ "$last" -gt 0 ] && [ "$now" -ge "$last" ] &&
     [ $((now - last)) -lt 15 ]; then
    return 0
  fi
  [ "$now" -gt 100000 ] && echo "$now" > "$RUN_DIR/spl_daemon.retry" 2>/dev/null

  local bin su_bin staged
  if ! bin=$(find_spl_bin); then
    echo "[service] spl_daemon 不在包里，live 方法会退回 prop"
    return 0
  fi
  if ! su_bin=$(spl_su); then
    echo "[service] 找不到 su，起不了 spl_daemon（live 方法会退回 prop）"
    return 0
  fi
  # /data/adb 下的文件是 adb_data_file，uid 1000 执行报 "inaccessible or not found"
  # （2026-10-22 实测）；shell_data_file 的 /data/local/tmp 才行。所以每次拉起的
  # 时候先拷一份过去 —— 重启会清空 /data/local/tmp，这份不能当唯一的家。
  staged=/data/local/tmp/spl_daemon
  if ! cp -f "$bin" "$staged" 2>/dev/null; then
    echo "[service] 拷 spl_daemon 到 /data/local/tmp 失败"
    return 0
  fi
  chmod 0755 "$staged" 2>/dev/null || true
  # 失败原因得看得到：su 拒绝、SELinux、bin 不起来都写进 spl.log。
  setsid "$su_bin" 1000 -c "LD_LIBRARY_PATH=/vendor/lib64:/system/lib64 $staged" \
    </dev/null >> "$(log_target spl.log)" 2>&1 &
  echo "[service] spl_daemon launched ($staged <- $bin)"
}

# 把 live 关掉（改成 prop、或者整个跟随关掉）时，不能让 daemon 一直挂着不管 ——
# 它停的时候要自己回基线，所以先 TERM 等它退，等不到再 KILL。
stop_spl_if_unused() {
  spl_method_is_live && return 0
  spl_daemon_running || return 0
  pkill -TERM -x spl_daemon 2>/dev/null
  sleep 1
  pkill -9 -x spl_daemon 2>/dev/null
  rm -f /data/local/tmp/spl_daemon 2>/dev/null
  echo "[service] live 已关闭，spl_daemon 已停并回基线"
}

(
  # 锁由这个子 shell 拿着，它活多久算多久；主脚本退出不影响它。
  trap 'release_lock' EXIT INT TERM HUP
  while true; do
    # 每轮都重新导环境：守护进程要能感知 relay.conf 的改动。
    load_relay_env
    # WebUI 的「允许远控」总开关：关着就把 relay 停着不拉（最多 2 秒生效）。
    if ! relay_enabled; then
      sleep 2
      continue
    fi
    TARGET=$(find_module_relay)
    if [ -z "$TARGET" ]; then
      echo "[service] relay binary vanished; retrying in 5s"
      sleep 5
      continue
    fi
    chmod 0755 "$TARGET" 2>/dev/null || true
    "$TARGET" &
    child=$!
    echo "$child" > "$RELAY_PID_FILE"
    echo "[service] relay started (pid $child)"
    # 用轮询代替 wait：relay 一跑就是好几天，卡在 wait 上就没机会做别的了。
    # 每 2 秒顺手看一下 adbr 那一层还在不在。
    while kill -0 "$child" 2>/dev/null; do
      keep_adbr_watchdog_alive
      keep_spl_alive
      stop_spl_if_unused
      # 10 秒：这三个检查都会读文件甚至扫 /proc，没必要 2 秒一次
      sleep 10
    done
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
# 「允许远控」关着时压根不会起 relay，这句就别报「没起来」了（那是预期行为）。
if relay_enabled; then
  if wait_for_relay; then
    echo "[service] ommega-b relay is up"
  else
    echo "[service] relay did not come up within 10s; watchdog will keep retrying"
  fi
else
  echo "[service] remote control is off (OMMEGA_RELAY_ENABLED); relay left stopped"
fi

# adbr 公网调试通道（默认关，WebUI 里点头才跑）：单独一个监管循环，
# 跟 relay 互不影响；它自己拿锁，service.sh 被拉多次也不会长出第二份。
if [ -f "$MODDIR/adbr-daemon.sh" ]; then
  ( sh "$MODDIR/adbr-daemon.sh" --b >> "$(log_target adbr-daemon.log)" 2>&1 & )
fi

# 补丁日期走 live 方法时，先把这个小进程拉起来（之后由上面的守护循环看住）。
keep_spl_alive
