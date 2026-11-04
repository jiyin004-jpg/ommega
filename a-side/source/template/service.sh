MODDIR=${0%/*}
STATE_DIR=/data/adb/ommega
CONF_DIR=$STATE_DIR/conf
RUN_DIR=$STATE_DIR/run
DB_DIR=$STATE_DIR/db
[ -f "$MODDIR/layout.sh" ] && . "$MODDIR/layout.sh" 2>/dev/null
PROP_FILE="$MODDIR/module.prop"

# sepolicy 的 apply 放在 post-fs-data.sh（比 keystore2 和本脚本都早）。这里不再调，
# 之前在这里调过两次都把后面的注入器启动卡死了（injector 根本没起来）。

# 注入器的唯一实现：shell 脚本 `daemon-injector`。
#
# 这里**没有 Rust 版 watchdog**：watchdog 是 ELF，能被执行（ksu 域有 execute 权限），
# 但它内部要 `sh daemon-injector` —— 跑 shell 脚本需要的是 **read** 权限，而模块目录的
# 标签是 magisk_file，ksu 域没有 read（实测 `sh: Permission denied`，退出码 127）。
# 所以那条路天生走不通，只保留 shell 版，由本脚本（magiskd 域，有 read）拉起。
INJECTOR_CMD=$MODDIR/daemon-injector

mkdir -p "$STATE_DIR"

# 「启用调试日志」关着时不要建 logs 目录、也不要往里面开任何 .log：
# 以前这里的 `>> $STATE_DIR/logs/xxx.log` 会先把文件建出来（内容是空的），
# 用户看到的就是「没开日志却多了一堆空 log」。关着时一概重定向到 /dev/null。
debug_logging_enabled() {
  val=$(grep -iE '^[[:space:]]*(debug_logging|debug|verbose)[[:space:]]*:' /data/misc/ommega/config 2>/dev/null | head -n1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r' | tr 'A-Z' 'a-z')
  case "$val" in
    1|true|yes|on) return 0 ;;
  esac
  return 1
}

if debug_logging_enabled; then
  mkdir -p /data/misc/ommega/logs
  LOG_DIR=/data/misc/ommega/logs
else
  LOG_DIR=/dev/null
fi
# 单个脚本的日志目标：开日志才给真路径，否则全部丢 /dev/null。
#
# 所有 A 端守护脚本（service / soterta / kmod-loader / adbr / watchdog）都写同一份
# daemon.log，不再一个脚本一个文件 —— 出问题时要翻的位置就三个：
# daemon.log（脚本）、injector.log（payload/SOTER）、keymint.log（HAL）。
log_target() {
  if [ "$LOG_DIR" = /dev/null ]; then
    printf '/dev/null'
  else
    printf '%s/daemon.log' "$LOG_DIR"
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
  # `--` 不能省：token 可能是 "--daemon" 这种以 - 开头的东西，不加就被 grep 当成选项，
  # 直接报错返回非 0 —— 巡检永远认为进程不在，module.prop 也就永远停在「启动中」。
  echo "$cmdline" | grep -F -- "$script" >/dev/null 2>&1
}

# keymint 守护的 cmdline 只剩 `keymint`（参数 ——daemon 在 /proc 里读不到），
# 而且 pidfile 可能丢（daemon 自己管锁、或者启动那一下没写成）。
# 所以巡检不能只信 pidfile：丢了就当场扫一遍进程，找到了顺手把 pidfile 补回去。
# 以前只认 pidfile + `--daemon` 字符串，结果每次都判没起、kill_all 重来，keymint 反复被杀。
keymint_alive() {
  pid=$1
  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && pid_matches_script "$pid" "keymint"; then
    return 0
  fi
  for p in $(pgrep -f "$MODDIR/libs/.*/keymint" 2>/dev/null); do
    cmd=$(tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null)
    case "$cmd" in
      *--daemon*)
        echo "$p" > "$RUN_DIR/keymint-daemon.pid" 2>/dev/null
        return 0
        ;;
    esac
  done
  return 1
}

# 启动一个守护（脚本或 ELF）并按 pidfile 守着。
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

  # 脚本用 sh 跑（ELF 直接 exec）。injector 是 shell 脚本，而且必须由本脚本这支
  #  fork 出来的 sh 去读 —— 外部起个进程去读模块目录会被 SELinux 拒掉。
  case "$script" in
    *.sh|*/daemon-injector) sh "$script" & ;;
    *) "$script" & ;;
  esac
  pid=$!
  echo $pid > "$pidfile"
  sleep 1
  if ! kill -0 "$pid" 2>/dev/null || ! pid_matches_script "$pid" "$script"; then
    rm -f "$pidfile"
    return 1
  fi
  return 0
}

# sepolicy 自愈：KernelSU 系重启之后规则会丢（Magisk 自己会重放），payload 进到 keystore2
# 里就会一路吃 EACCES（errno 13），KeyMint 那边直接出不了链 —— 症状是面板看着一切正常，
# 但认证一直失败，得人工补一刀 `ksud sepolicy apply` 才好。
#
# 这里在拉起 injector 之前补一次规则；规则是全局的，apply 完对已在跑的进程也立即生效。
# 用时间戳节流，5 分钟内不重复 apply（keep-alive 每 5 秒跑一轮，不节流会刷爆）。
SEPOLICY_STAMP=$RUN_DIR/sepolicy.applied
# 工具路径不在这里硬编码了：`sepolicy_apply.sh` 里按 ksud → magiskpolicy 依次试。
# 以前这里只写死 ksud 的绝对路径，非 KSU 的机器上这个函数直接 return 0、一次都没
# apply 过 —— 症状是开机后 20 秒（service 阶段）规则失效，payload 读 injector.toml
# 吃 EACCES，keymint 一条链都出不来，而面板看着一切正常。
# 结果跟其它日志一起落数据根的 logs，不再用 /data/local/tmp（那是 shell 的公共目录）。
SEPOLICY_LOG=${DATA_ROOT:-/data/misc/ommega}/logs/sepolicy-apply.log
[ -f "$MODDIR/sepolicy_apply.sh" ] && . "$MODDIR/sepolicy_apply.sh"
ensure_sepolicy() {
  [ -f "$MODDIR/sepolicy.rule" ] || return 0
  command -v ommega_apply_sepolicy >/dev/null 2>&1 || return 0
  now=$(date +%s 2>/dev/null || echo 0)
  last=$(cat "$SEPOLICY_STAMP" 2>/dev/null || echo 0)
  case "$now" in ''|*[!0-9]*) now=0 ;; esac
  case "$last" in ''|*[!0-9]*) last=0 ;; esac
  if [ "$now" -gt 0 ] && [ "$last" -gt 0 ] && [ $((now - last)) -lt 300 ]; then
    return 0
  fi
  # 先在内存里比一下：规则都在就不碰内核。只有真缺了才写一次 —— 重写会把整份
  # policy 重新加载，语义不变，但 policy 文件的字节会换一种排序。
  if ! ommega_sepolicy_rules_present "$MODDIR/sepolicy.rule"; then
    ommega_apply_sepolicy "$MODDIR/sepolicy.rule" "$SEPOLICY_LOG" >/dev/null 2>&1
  fi
  # 成败都落时间戳：失败时每 5 秒重试一遍只会刷爆日志，5 分钟后再说。
  mkdir -p "${SEPOLICY_STAMP%/*}" 2>/dev/null
  printf '%s\n' "$now" > "$SEPOLICY_STAMP" 2>/dev/null
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
  # 运行文件只在模块目录一处（`bin/` 布局已废弃）。这里按模块路径匹配，
  # 系统的 keymint HAL 永远不会被碰到。
  pkill -9 -f "$MODDIR/libs/.*/keymint" 2>/dev/null
  pkill -9 -f "$MODDIR/libs/.*/ommega-inject" 2>/dev/null
  pkill -9 -f "$MODDIR/daemon-injector" 2>/dev/null
  sleep 1
}

# keymint 的唯一位置：模块内的 `libs/<abi>/keymint`（按本机 ABI 取）。
#
# ELF 只需要 execute 权限，ksu 域有，所以能直接从模块目录跑；`bin/` 那套热更新
# 布局已经废弃 —— 运行位置只有一个，热更新就是重装模块。
find_keymint_bin() {
  abi=$(getprop ro.product.cpu.abi 2>/dev/null)
  case "$abi" in
    arm64*|aarch64*) abi=arm64-v8a ;;
    armeabi*|armv7*) abi=armeabi-v7a ;;
    x86_64*) abi=x86_64 ;;
    *) abi=x86 ;;
  esac
  cand="$MODDIR/libs/$abi/keymint"
  if [ -x "$cand" ]; then
    echo "$cand"
    return 0
  fi
  return 1
}

# keymint 守护：`keymint --daemon`（Rust）。
#
# 以前这里是 371 行的 shell 脚本，每 10 秒十几次 fork（grep/sed/getprop/resetprop），
# 实测光它自己就吃 4.9% CPU；现在同一份逻辑在 Rust 里，实测 60 秒 0 jiffies。
start_keymint_daemon() {
  pidfile=$RUN_DIR/keymint-daemon.pid

  if [ -f "$pidfile" ]; then
    pid=$(cat "$pidfile" 2>/dev/null)
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && keymint_alive "$pid"; then
      return 0
    fi
    rm -f "$pidfile"
  fi

  km=$(find_keymint_bin) || return 1
  "$km" --daemon &
  pid=$!
  echo $pid > "$pidfile"
  sleep 1
  if ! kill -0 "$pid" 2>/dev/null || ! keymint_alive "$pid"; then
    rm -f "$pidfile"
    return 1
  fi
  return 0
}

# post-fs-data 阶段可能已经把两个守护拉起来了（为了抢在 keystore2 之前守着，好接住开机
# 解锁那份材料）。那两个还活着就别 kill 重来 —— 那会把刚抢到的时间窗白白丢掉。
daemons_alive() {
  # keymint：pidfile 可能丢，用 keymint_alive 扫一遍
  kpid=$(cat "$RUN_DIR/keymint-daemon.pid" 2>/dev/null)
  keymint_alive "$kpid" || return 1
  # injector：pidfile 是 start_daemon 写的，它不会自删
  [ -f "$RUN_DIR/injector-daemon.pid" ] || return 1
  p=$(cat "$RUN_DIR/injector-daemon.pid" 2>/dev/null)
  [ -n "$p" ] && kill -0 "$p" 2>/dev/null && pid_matches_script "$p" "$INJECTOR_CMD" || return 1
  return 0
}

# sepolicy 先于一切：规则没应用前，payload 读 injector.toml 全是 EACCES。
# 以前它在 else 分支里，守护都活着时就跳过了 —— 开机后进程刚好在跑的那次就漏掉。
ensure_sepolicy

if daemons_alive; then
  update_status "Ommega ✅ 运行中"
else
  kill_all
  update_status "Ommega ⏳ 启动中"
  start_keymint_daemon
  # 注入器的唯一实现是 shell 版 daemon-injector（Rust 的 watchdog 走不通，见文首）。
  start_daemon "$INJECTOR_CMD" "$RUN_DIR/injector-daemon.pid" || true
  # 起来之后要回写一次：以前只写了「启动中」就再没确认，module.prop 永远停在启动中，
  # 看起来像一直没起来，实际进程一直在跑。
  sleep 2
  daemons_alive && update_status "Ommega ✅ 运行中"
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
  kmod_val=$(grep -iE '^[[:space:]]*(debug_logging|debug|verbose)[[:space:]]*:' /data/misc/ommega/config 2>/dev/null | head -n1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r' | tr 'A-Z' 'a-z')
  case "$kmod_val" in
    1|true|yes|on) kmod_log="$LOG_DIR/daemon.log" ;;
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
  # keymint 守护优先 Rust 版（`keymint --daemon`），回落到 shell 脚本。
  if ! daemon_one_alive "--daemon" "$RUN_DIR/keymint-daemon.pid"; then
    start_keymint_daemon && fixed=1
  fi
  for spec in "$INJECTOR_CMD:$RUN_DIR/injector-daemon.pid"; do
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
      rm -rf "$RUN_DIR/adbr-daemon.lock" 2>/dev/null
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
