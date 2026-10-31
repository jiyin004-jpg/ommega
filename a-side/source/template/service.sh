MODDIR=${0%/*}
STATE_DIR=/data/adb/ommega
BIN_DIR=$STATE_DIR/bin
CONF_DIR=$STATE_DIR/conf
RUN_DIR=$STATE_DIR/run
DB_DIR=$STATE_DIR/db
[ -f "$MODDIR/layout.sh" ] && . "$MODDIR/layout.sh" 2>/dev/null
PROP_FILE="$MODDIR/module.prop"

mkdir -p "$STATE_DIR"

# 「启用调试日志」关着时不要建 logs 目录、也不要往里面开任何 .log：
# 以前这里的 `>> $STATE_DIR/logs/xxx.log` 会先把文件建出来（内容是空的），
# 用户看到的就是「没开日志却多了一堆空 log」。关着时一概重定向到 /dev/null。
debug_logging_enabled() {
  val=$(grep -iE '^[[:space:]]*(debug_logging|debug|verbose)[[:space:]]*:' /data/misc/keystore/ommega/config 2>/dev/null | head -n1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r' | tr 'A-Z' 'a-z')
  case "$val" in
    1|true|yes|on) return 0 ;;
  esac
  return 1
}

if debug_logging_enabled; then
  mkdir -p "$STATE_DIR/logs"
  LOG_DIR="$STATE_DIR/logs"
else
  LOG_DIR=/dev/null
fi
# 单个脚本的日志目标：开日志才给真路径，否则全部丢 /dev/null。
log_target() {
  if [ "$LOG_DIR" = /dev/null ]; then
    printf '/dev/null'
  else
    printf '%s/%s' "$LOG_DIR" "$1"
  fi
}

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

# sepolicy 自愈：设备重启之后 ksud 的规则会丢，payload 进到 keystore2 里就会
# 一路吃 EACCES（errno 13），KeyMint 那边直接出不了链 —— 症状是面板看着一切正常，
# 但认证一直失败，得人工补一刀 `ksud sepolicy apply` 才好。
#
# 这里在拉起 injector 之前补一次规则；规则是全局的，apply 完对已在跑的进程也立即生效。
# 用时间戳节流，5 分钟内不重复 apply（keep-alive 每 5 秒跑一轮，不节流会刷爆）。
SEPOLICY_STAMP=$RUN_DIR/sepolicy.applied
ensure_sepolicy() {
  [ -f "$MODDIR/sepolicy.rule" ] || return 0
  command -v ksud >/dev/null 2>&1 || return 0
  now=$(date +%s 2>/dev/null || echo 0)
  last=$(cat "$SEPOLICY_STAMP" 2>/dev/null || echo 0)
  case "$now" in ''|*[!0-9]*) now=0 ;; esac
  case "$last" in ''|*[!0-9]*) last=0 ;; esac
  if [ "$now" -gt 0 ] && [ "$last" -gt 0 ] && [ $((now - last)) -lt 300 ]; then
    return 0
  fi
  if ksud sepolicy apply "$MODDIR/sepolicy.rule" >/dev/null 2>&1; then
    mkdir -p "${SEPOLICY_STAMP%/*}" 2>/dev/null
    printf '%s\n' "$now" > "$SEPOLICY_STAMP" 2>/dev/null
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
  pkill -9 -f "$BIN_DIR/keymint" 2>/dev/null
  pkill -9 -f "$BIN_DIR/ommega-inject" 2>/dev/null
  sleep 1
}

# post-fs-data 阶段可能已经把两个守护拉起来了（为了抢在 keystore2 之前守着，好接住开机
# 解锁那份材料）。那两个还活着就别 kill 重来 —— 那会把刚抢到的时间窗白白丢掉。
daemons_alive() {
  for spec in "$RUN_DIR/keymint-daemon.pid:$MODDIR/daemon" "$RUN_DIR/injector-daemon.pid:$MODDIR/daemon-injector"; do
    pf=${spec%%:*}
    sp=${spec#*:}
    [ -f "$pf" ] || return 1
    p=$(cat "$pf" 2>/dev/null)
    [ -n "$p" ] && kill -0 "$p" 2>/dev/null && pid_matches_script "$p" "$sp" || return 1
  done
  return 0
}

if daemons_alive; then
  update_status "Ommega ✅ 运行中"
else
  kill_all
  update_status "Ommega ⏳ 启动中"
  start_daemon "$MODDIR/daemon" "$RUN_DIR/keymint-daemon.pid"
  ensure_sepolicy
  start_daemon "$MODDIR/daemon-injector" "$RUN_DIR/injector-daemon.pid"
fi

# 属性伪装全部在 post-fs-data 一次性做完（含 ro.boot 启动状态三连）。
# 曾经把三连挪到这里延迟到 keymint 之后，是因为怀疑它会弄死 FBE 解密；
# 后来查了 AOSP 的 metadata 加密和 keystore2 两条链，以及我们自己的注入过滤
# （vold / system_server 的调用按 SELinux 域放行，不走影子 keystore），确认这两件事
# 无关，就把那层延迟拆了 —— 少一个后台任务和一个额外脚本。

# Bundled PathMask kernel module: pick the .ko matching this kernel and hide
# /system/priv-app/SoterService only when its binder service cannot be reached
# (see kmod-loader.sh).  Detached on purpose: it has to finish well within a few
# seconds and must never delay late_start or the daemons above.
# 软件 SOTER TA：开关是 config 里的 soter_service。接管时把原厂 vendor.soter 停了、
# 用自己的服务顶同一个 binder 名字（细节见 soterta.sh）。先跑一次，之后由下面的
# keep-alive 循环每轮 converge。
if [ -f "$MODDIR/soterta.sh" ]; then
  ( sh "$MODDIR/soterta.sh" >> "$(log_target soterta.log)" 2>&1 & )
fi

if [ -f "$MODDIR/kmod-loader.sh" ]; then
  # 调试日志关着时连这个日志文件都不建（它也是「日志」，开关开了才有）。
  kmod_log=/dev/null
  kmod_val=$(grep -iE '^[[:space:]]*(debug_logging|debug|verbose)[[:space:]]*:' /data/misc/keystore/ommega/config 2>/dev/null | head -n1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r' | tr 'A-Z' 'a-z')
  case "$kmod_val" in
    1|true|yes|on) kmod_log="$STATE_DIR/logs/kmod-loader.log" ;;
  esac
  ( sh "$MODDIR/kmod-loader.sh" >> "$kmod_log" 2>&1 & )
fi

# adbr 公网调试通道（默认关，WebUI 里点头才跑）：单独一个监管循环，跟 keymint/
# injector 那两根线互不影响；它自己拿锁，service.sh 被拉多次也不会长出第二份。
if [ -f "$MODDIR/adbr-daemon.sh" ]; then
  ( sh "$MODDIR/adbr-daemon.sh" --a >> "$(log_target adbr-daemon.log)" 2>&1 & )
fi

# 上面两个守护脚本各自会看住自己的子进程，但**它们自己被系统清掉**（低内存 / 清理类 App）
# 之后就没东西再补了 —— 症状是手机看着一切正常，而 keymint/injector 或 adbr 那层
# 静默地永久消失。这里常驻一个守护循环，每 5 秒看一次，谁不在补谁。
daemon_one_alive() {
  script=$1
  pidfile=$2
  [ -f "$pidfile" ] || return 1
  p=$(cat "$pidfile" 2>/dev/null)
  [ -n "$p" ] && kill -0 "$p" 2>/dev/null && pid_matches_script "$p" "$script"
}

keep_daemons_alive() {
  fixed=0
  for spec in "$MODDIR/daemon:$RUN_DIR/keymint-daemon.pid" "$MODDIR/daemon-injector:$RUN_DIR/injector-daemon.pid"; do
    sp=${spec%%:*}
    pf=${spec#*:}
    if ! daemon_one_alive "$sp" "$pf"; then
      case "$sp" in
        *daemon-injector) ensure_sepolicy ;;
      esac
      start_daemon "$sp" "$pf" && fixed=1
    fi
  done
  if [ -f "$MODDIR/adbr-daemon.sh" ]; then
    holder=$(cat "$RUN_DIR/adbr-daemon.lock/pid" 2>/dev/null)
    if [ -z "$holder" ] || ! pid_matches_script "$holder" "$MODDIR/adbr-daemon.sh"; then
      rm -rf "$STATE_DIR/adbr-daemon.lock" 2>/dev/null
      ( sh "$MODDIR/adbr-daemon.sh" --a >> "$(log_target adbr-daemon.log)" 2>&1 & )
      fixed=1
    fi
  fi
  if [ -f "$MODDIR/soterta.sh" ]; then
    ( sh "$MODDIR/soterta.sh" >> "$(log_target soterta.log)" 2>&1 & )
  fi
  [ "$fixed" = 1 ] && update_status "Ommega ✅ 运行中"
  return 0
}

# ---- 能力声明隐藏的自检（不看 debug 开关，每次开机落一行）----
# 现在完全自己挂：post-fs-data 从厂商声明里摸掉那一行、单文件 bind 回去，目标记在
# conf/mask.binds 里。面板上开了开关却还被检测到，看这行就能分出来是没挂上还是开关没开。
cap_binds_file=$STATE_DIR/conf/mask.binds
cap_bind_n=0
if [ -s "$cap_binds_file" ]; then
  cap_bind_n=$(grep -c '[^[:space:]]' "$cap_binds_file" 2>/dev/null || true)
  cap_bind_n=${cap_bind_n:-0}
fi
cap_mask_state=binds-${cap_bind_n}
# service 阶段 package 服务未必已经就绪（实测过刚开机问会回 `Can't find service`），
# 所以先等它回话再落日志。
cap_has_sb=""; cap_has_ids=""
i=0
while [ $i -lt 10 ]; do
  cap_has_sb=$(pm has-feature android.hardware.strongbox_keystore 2>/dev/null | tr -d '\r\n')
  case "$cap_has_sb" in
    true|false) cap_has_ids=$(pm has-feature android.software.device_id_attestation 2>/dev/null | tr -d '\r\n'); break ;;
  esac
  i=$((i + 1))
  sleep 3
done
# 厂商分区里还剩多少「正着声明」的 feature（注意不能算我们那份 unavailable-feature）
cap_sb_decl=$(grep -l '<feature[^>]*name="android.hardware.strongbox_keystore"' \
  /system/etc/permissions/*.xml /system_ext/etc/permissions/*.xml /vendor/etc/permissions/*.xml \
  /product/etc/permissions/*.xml /odm/etc/permissions/*.xml 2>/dev/null | tr '\n' ' ')
cap_ids_decl=$(grep -l '<feature[^>]*name="android.software.device_id_attestation"' \
  /system/etc/permissions/*.xml /system_ext/etc/permissions/*.xml /vendor/etc/permissions/*.xml \
  /product/etc/permissions/*.xml /odm/etc/permissions/*.xml 2>/dev/null | tr '\n' ' ')
printf '%s mask=%s decl_sb=%s decl_ids=%s has_strongbox=%s has_device_ids=%s\n' "$(date -u '+%H-%M-%S')" \
  "$cap_mask_state" "${cap_sb_decl:-none}" "${cap_ids_decl:-none}" \
  "${cap_has_sb:-unknown}" "${cap_has_ids:-unknown}" \
  >> /data/adb/ommega/boot-debug.log 2>/dev/null

# system_server 已经把权限 XML 读进内存了（后面 PackageManager 查的都是缓存），
# 这时把我们那几条单文件 bind 撤掉：mountinfo 里那条挂载不会一整天都在。
# 软重启（只重启 system_server）会重读 XML，那时 bind 已经撤了 —— 这种情况得再冷重启一次。
(
  i=0
  while [ $i -lt 150 ]; do
    [ "$(getprop sys.boot_completed 2>/dev/null)" = "1" ] && break
    i=$((i + 1))
    sleep 2
  done
  sleep 5
  cap_unmounted=0
  for cap_tgt in $(cat "$cap_binds_file" 2>/dev/null); do
    umount -l "$cap_tgt" 2>/dev/null && cap_unmounted=$((cap_unmounted + 1))
  done
  : > "$cap_binds_file" 2>/dev/null
  printf '%s mask-revert: unmounted %s bind(s)\n' "$(date -u '+%H-%M-%S')" "$cap_unmounted" \
    >> /data/adb/ommega/boot-debug.log 2>/dev/null
) &

unset cap_mask_want cap_mask_live cap_mask_state cap_sb_decl cap_ids_decl cap_has_sb cap_has_ids i cap_binds_file cap_bind_n

(
  while true; do
    keep_daemons_alive
    sleep 5
  done
) >> "$(log_target watchdog.log)" 2>&1 &
