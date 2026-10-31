#!/system/bin/sh

# adbrd 监管脚本 —— A / B 两端共用同一份，用参数选读哪份配置：
#
#   sh adbr-daemon.sh --a   A 端：/data/misc/keystore/ommega/config 里的 `adbr:`
#   sh adbr-daemon.sh --b   B 端：/data/adb/ommega-b/conf/relay.conf 里的 OMMEGA_RELAY_ABDR_ENABLED
#
# 设备被公网远控这件事必须由用户显式点头，所以这里只认配置里的开关，不开就不跑：
#   开关开着 → 保证有一个 adbr 在跑（掉了 2 秒后重拉）
#   开关关着 → 把在跑的那个停掉
# 开关是每 2 秒重读一次，所以 WebUI 里一改，最多 2 秒就生效，不用重启设备。
#
# 认进程认就一个名字 `adbrd` —— 设备侧那份就叫这个（`adbr` 是电脑上的命令行客户端，
# 不是设备上的东西）。认错了名字开关就管不住：名字对不上时，关掉停不掉、打开又会
# 在旁边再起一条，同一台设备在服务端就成了两条通道。
#
# 二进制只有 arm64 一份（见仓库 vendor/adbrd/README.md），别的架构直接退出。

MODE=""
case "$1" in
  --a|a) MODE=a ;;
  --b|b) MODE=b ;;
  *) echo "[adbr] 用法: sh adbr-daemon.sh --a|--b" >&2; exit 2 ;;
esac

MODDIR=${0%/*}
# B 端有自己的一套目录（/data/adb/ommega-b），A/B 装在同一台机器上也不会打架
case "$MODE" in
  a) STATE_DIR=/data/adb/ommega ;;
  b) STATE_DIR=/data/adb/ommega-b ;;
esac
BIN_DIR=$STATE_DIR/bin
CONF_DIR=$STATE_DIR/conf
RUN_DIR=$STATE_DIR/run
DB_DIR=$STATE_DIR/db
[ -f "$MODDIR/layout.sh" ] && . "$MODDIR/layout.sh" 2>/dev/null
LOG="$STATE_DIR/logs/adbr.log"
LOCK_DIR="$RUN_DIR/adbr-daemon.lock"

if [ "$MODE" = "a" ]; then
  CONF=/data/misc/keystore/ommega/config
else
  CONF="$CONF_DIR/relay.conf"
fi

mkdir -p "$STATE_DIR/logs"

# 只认 arm64：上游只给了这一份构建。
# getprop 在某些执行上下文里会拿不到（WebUI 的 exec 桥环境不一定是完整 PATH），
# 那时退回 uname；两个都拿不到才当不支持，别因为读不到属性就白白把功能关了。
abi=$(getprop ro.product.cpu.abi 2>/dev/null)
[ -n "$abi" ] || abi=$(uname -m 2>/dev/null)
case "$abi" in
  arm64*|aarch64*) : ;;
  x86_64|i?86|x86|armv7*|armeabi*) echo "[adbr] 本机不是 arm64（$abi），adbr 不启用" >&2; exit 0 ;;
  *) echo "[adbr] 架构未知（$abi），按 arm64 继续" >&2 ;;
esac

# 单例：service.sh 每次跑都会把我们拉一遍，只有一份能持有这个锁。
# 陈锁（持有者没了：强杀、断电）清掉重抢。
# 同 daemon / daemon-injector：光看 pid 活着不够，得确认那个 pid 跑的是本脚本，
# 否则 pid 被复用时会以为「已经有一份在跑」，adbr 通道就再也起不来。
holder_is_us() {
  p=$1
  s=$2
  [ -n "$p" ] || return 1
  kill -0 "$p" 2>/dev/null || return 1
  [ -r "/proc/$p/cmdline" ] || return 1
  tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | grep -F "sh $s " >/dev/null 2>&1
}

# 同 daemon 那层：抢锁有竞态，拿到之后要再核一次归属；退出只删自己的锁。
lock_owned() { [ "$(cat "$LOCK_DIR/pid" 2>/dev/null)" = "$$" ]; }
release_lock() { lock_owned && rm -rf "$LOCK_DIR" 2>/dev/null; return 0; }

if mkdir "$LOCK_DIR" 2>/dev/null; then
  echo "$$" > "$LOCK_DIR/pid"
else
  if holder_is_us "$(cat "$LOCK_DIR/pid" 2>/dev/null)" "$0"; then
    exit 0
  fi
  rm -rf "$LOCK_DIR" 2>/dev/null
  mkdir "$LOCK_DIR" 2>/dev/null || exit 0
  echo "$$" > "$LOCK_DIR/pid"
  sleep 1
  lock_owned || exit 0
fi
trap 'release_lock' EXIT INT TERM HUP

truthy() {
  case "$(printf '%s' "$1" | tr -d ' \t\r' | tr 'A-Z' 'a-z')" in
    1|true|yes|on) return 0 ;;
  esac
  return 1
}

# 配置里的开关。没写这个键 = 关（adbr 是额外开的口子，绝不能不写就自己开）。
switch_on() {
  if [ "$MODE" = "a" ]; then
    value=$(sed -n 's/^[[:space:]]*adbr[[:space:]]*:[[:space:]]*//p' "$CONF" 2>/dev/null | head -n 1)
  else
    value=$(sed -n 's/^OMMEGA_RELAY_ABDR_ENABLED=//p' "$CONF" 2>/dev/null | tail -n 1)
  fi
  truthy "$value"
}

# 用 /proc/<pid> 的 comm 前缀认进程，不用 pidof/pgrep —— 那两个在 toybox 上行为不一致，
# 而且 pkill -f 会把带 "adbr" 的脚本（就是本脚本自己）一起杀掉。
# 前缀匹配是因为二进制会改自己的进程名：设备侧实测 comm 是 `adbrd-v0.1.0-an`（15 字符
# 截断），按 `= adbrd` 精确比就一个都认不出来，开关关着也停不掉、面板也显示未运行。
adbr_pids() {
  for d in /proc/[0-9]*; do
    [ -r "$d/comm" ] || continue
    case "$(cat "$d/comm" 2>/dev/null)" in
      adbrd*) printf '%s\n' "${d#/proc/}" ;;
    esac
  done
}

find_bin() {
  if [ -x "$BIN_DIR/adbrd" ]; then
    printf '%s\n' "$BIN_DIR/adbrd"
    return 0
  fi
  for abi in arm64-v8a; do
    if [ -f "$MODDIR/libs/$abi/adbrd" ]; then
      printf '%s\n' "$MODDIR/libs/$abi/adbrd"
      return 0
    fi
  done
  return 1
}

# adbd 的 TCP 口：adbr mirror 要连设备本机 127.0.0.1:5555，而有些 ROM 上 init 起的
# adbd 根本不给这个端口。NX809J（Android 16 / MTK）实测两个毛病：
#   1. 起来就崩：usb_ffs_open_thread → PropertyMonitor::Add 抛 bad_optional_access
#      （`persist.adb.nonblocking_ffs=1` 能压住），init 于是无限重启它；
#   2. 就算不崩也不监听 —— init 那个实例带 `--tim_seclabel=u:r:adbd_tradeinmode:s0`，
#      从头到尾没有一句 "adbd listening on"；手动起
#      `/apex/com.android.adbd/bin/adbd --root_seclabel=u:r:su:s0` 才会打
#      "adbd listening on tcp:5555"。
# 所以先探端口，不通就自己起一个（先停 init 那个带 tradeinmode 的）。
adbd_tcp_alive() {
  # 超时压到 1 秒：没人监听时这里会阻塞，而主循环每轮都要问一次。
  timeout 1 nc 127.0.0.1 5555 </dev/null >/dev/null 2>&1
}

ensure_adbd_tcp() {
  # 只在「有人要 TCP 调试」时才管：`service.adb.tcp.port` 被设了端口（adbrd 自己会设，
  # adbr 客户端要 mirror 时也会设）。没人设就不碰用户的 adbd。
  [ "$(getprop service.adb.tcp.port 2>/dev/null)" = "5555" ] || return 0
  adbd_tcp_alive && return 0
  setprop persist.adb.nonblocking_ffs 1 2>/dev/null
  setprop service.adb.tcp.port 5555 2>/dev/null
  setprop ctl.stop adbd 2>/dev/null
  sleep 1
  # 只杀 init 那个带 --tim_seclabel 的；用户/我们自己起的别碰。
  for d in /proc/[0-9]*; do
    [ -r "$d/comm" ] || continue
    [ "$(cat "$d/comm" 2>/dev/null)" = "adbd" ] || continue
    tr '\0' ' ' < "$d/cmdline" 2>/dev/null | grep -q 'tim_seclabel' || continue
    kill -9 "${d#/proc/}" 2>/dev/null
  done
  adbd_bin=
  for cand in /apex/com.android.adbd/bin/adbd /system/bin/adbd; do
    if [ -x "$cand" ]; then adbd_bin=$cand; break; fi
  done
  if [ -z "$adbd_bin" ]; then
    echo "[adbr] 找不到 adbd，5555 起不来"
    return 1
  fi
  "$adbd_bin" --root_seclabel=u:r:su:s0 >> "$LOG" 2>&1 &
  sleep 2
  if adbd_tcp_alive; then
    echo "[adbr] adbd 已在 5555 上监听（手动起的实例）"
    return 0
  fi
  echo "[adbr] adbd 仍没监听 5555"
  return 1
}

while true; do
  # adbd 只在 adbr 开关开着时才需要管：以前这里是「不管开没开，属性被设了就管」，
  # 结果开关关着、adbrd 被杀之后 service.adb.tcp.port=5555 还留着，每轮又去 nc 探
  # 端口（没人监听要阻塞）再起一次 adbd、再杀一次，白烧 CPU。
  if switch_on; then
    ensure_adbd_tcp
    pids=$(adbr_pids)
    if [ -n "$pids" ]; then
      # 记下来给面板看（面板按名字认不出来，见 adbr_pids 上面的注释）。
      printf '%s\n' "$pids" | head -n 1 > "$RUN_DIR/adbrd.pid" 2>/dev/null
    else
      bin=$(find_bin)
      if [ -n "$bin" ]; then
        chmod 0755 "$bin" 2>/dev/null || true
        # --foreground：别让它自己 detach，输出直接进我们的日志，监管循环也看得见它。
        "$bin" --foreground >> "$LOG" 2>&1 &
        echo $! > "$RUN_DIR/adbrd.pid" 2>/dev/null
        echo "[adbr] 已拉起 $bin (pid $!)"
      else
        echo "[adbr] 开关开着但找不到 adbr 二进制"
        rm -f "$RUN_DIR/adbrd.pid" 2>/dev/null
      fi
    fi
  else
    pids=$(adbr_pids)
    rm -f "$RUN_DIR/adbrd.pid" 2>/dev/null
    if [ -n "$pids" ]; then
      echo "[adbr] 开关关着，停掉: $pids"
      for p in $pids; do
        exe=$(readlink "/proc/$p/exe" 2>/dev/null)
        case "$exe" in
          "$STATE_DIR"/*|"$MODDIR"/*) : ;;
          *) echo "[adbr] 停掉的是 $exe（不是模块目录里的那份，确认一下是不是别处手装的）" ;;
        esac
      done
      # shellcheck disable=SC2086
      kill $pids 2>/dev/null
      sleep 1
    fi
    # 不管刚才杀没杀到，只要属性还挂着就收干净 —— adbrd 自己会把
    # service.adb.tcp.port 设成 5555，被杀后它不会自己清，系统 adbd 就一直挂在 5555。
    # 以前这段放在「pids 非空」里，pids 一空就不清了，于是主循环每轮又把 adbd 拉起来，
    # 空转烧 CPU。
    if [ "$(getprop service.adb.tcp.port 2>/dev/null)" = "5555" ]; then
      setprop service.adb.tcp.port ""
      echo "[adbr] 清掉 service.adb.tcp.port=5555"
      if [ "$(getprop init.svc.adbd 2>/dev/null)" = "running" ]; then
        setprop ctl.stop adbd
        echo "[adbr] 停掉 adbd"
      fi
    fi
  fi
  # 开关开着才需要勤查（adbrd 崩了要拉回来）；关着就慢查，没必要每 2 秒扫一遍 /proc。
  if switch_on; then
    sleep 5
  else
    sleep 30
  fi
done
