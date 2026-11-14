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

# ---- 进程身份：pid + 启动时刻 ----
# 守护自举（memfd 重生）之后，cmdline 里已经没有模块路径了，进程名也换成了系统
# HAL 的名字 —— `grep 路径` / `grep --daemon` 认人的办法全都失效，硬用会在
# 「判定没跑 → 再起一份」上无限循环。改成认「pid + /proc/<pid>/stat 第 22 字段
# （启动时刻）」：pid 会被复用，启动时刻不会。
proc_start_time() {
  [ -r "/proc/$1/stat" ] || return 1
  # 先把换行去掉：comm 里夹换行时（脚本用 echo 写 comm 会带 \n），stat 会变两行，
  # awk 拿到的 $20 就不是 starttime 了。
  tr -d '\n' < "/proc/$1/stat" 2>/dev/null | sed 's/^.*) //' | awk '{print $20}'
}

# pidfile 统一是 `pid starttime` 两列；老格式只有 pid，那就只能看它还在不在。
pidfile_pid() { awk 'NR==1{print $1}' "$1" 2>/dev/null; }
pidfile_stamp() { awk 'NR==1{print $2}' "$1" 2>/dev/null; }

pid_alive_at() {
  [ -n "$1" ] || return 1
  kill -0 "$1" 2>/dev/null || return 1
  if [ -z "$2" ] || [ "$2" = 0 ]; then
    return 0
  fi
  now=$(proc_start_time "$1")
  [ -n "$now" ] && [ "$now" = "$2" ]
}

pidfile_alive() {
  [ -r "$1" ] || return 1
  pid_alive_at "$(pidfile_pid "$1")" "$(pidfile_stamp "$1")"
}

write_pidfile() {
  stamp=$(proc_start_time "$2")
  mkdir -p "${1%/*}" 2>/dev/null
  printf '%s %s\n' "$2" "${stamp:-0}" > "$1" 2>/dev/null
}

# 兼容旧调用点：keymint 守护只看它自己的 pidfile。
keymint_alive() {
  pidfile_alive "$RUN_DIR/keymint-daemon.pid"
}

# 从名字表里取某个角色的伪装路径（daemon 开机时挑好写进去的）。
stealth_name() {
  sed -n "s/^$1=//p" /data/misc/ommega/conf/stealth.names 2>/dev/null | head -n 1
}

# 启动一个守护（脚本或 ELF）并按 pidfile 守着。
start_daemon() {
  script=$1
  pidfile=$2

  pidfile_alive "$pidfile" && return 0
  rm -f "$pidfile"

  # 脚本不再用 `sh /模块路径/脚本` 起：那样 cmdline 里直接写着我们的目录。
  # 模块里的 keymint 能当启动器 —— 脚本读进 memfd，`sh -s` 从标准输入读，
  # 进程名换成名字表里挑好的系统 HAL 名字。启动器不在才退回普通启动。
  case "$script" in
    *.sh|*/daemon-injector)
      cast_fake=$(stealth_name injector)
      cast_km=$(find_module_bin 2>/dev/null)
      if [ -n "$cast_fake" ] && [ -n "$cast_km" ]; then
        OMMEGA_MODDIR="$MODDIR" "$cast_km" --exec-script "$script" "$cast_fake" >/dev/null 2>&1 &
      else
        sh "$script" >/dev/null 2>&1 &
      fi
      ;;
    *) "$script" & ;;
  esac
  pid=$!
  sleep 1
  # pidfile 由脚本/守护自己写（setsid 那条路的 $! 未必是最终进程）。
  pidfile_alive "$pidfile" && return 0
  pid_alive_at "$pid" "" && return 0
  rm -f "$pidfile"
  return 1
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
#
# 自举之后 cmdline 里只剩系统 HAL 的路径（进程 exe 是 memfd），所以认人得看名字表：
# conf/stealth.names 里记的就是我们这几个进程的伪装路径，配上「exe 指向 memfd」
# 这一道就没法误杀真进程 —— 系统里那些同名 HAL 的 exe 是 /vendor 下的真文件。
#
# 先按 exe / comm 快速筛，只对可能属于我们的那几个读 cmdline（加 timeout）：
# 读一个卡在 D 状态的目标的 /proc/pid/cmdline 会把调用方一起卡死（实测过）。
kill_all() {
  all_names=$(awk -F= '{print $2}' /data/misc/ommega/conf/stealth.names 2>/dev/null)
  for p in $(ls /proc | grep -E '^[0-9]+$'); do
    [ "$p" = "$$" ] && continue
    exe=$(readlink "/proc/$p/exe" 2>/dev/null)
    comm=$(cat "/proc/$p/comm" 2>/dev/null)
    hit=0
    # 一、exe 就在模块里的（没自举成功的老进程）
    case "$exe" in
      "$MODDIR"/*|/data/adb/ommega/bin/*) hit=1 ;;
    esac
    # 二、comm 是我们的伪装名（exe 必须是 memfd，否则可能是真系统进程）
    if [ "$hit" = 0 ] && [ -n "$all_names" ]; then
      for n in $all_names; do
        nb=$(echo "$n" | sed 's|.*/||' | cut -c1-15)
        if [ "$comm" = "$nb" ]; then
          case "$exe" in /memfd:*) hit=1 ;; esac
          break
        fi
      done
    fi
    # 三、comm 还是原始名字（旧版本）；四、脚本守护（exe 是系统 sh）
    if [ "$hit" = 0 ]; then
      case "$comm" in keymint|ommega-inject) hit=1 ;; esac
      case "$comm" in
        sh|busybox|toybox)
          cmd=$(timeout 2 cat "/proc/$p/cmdline" 2>/dev/null | tr '\0' ' ')
          case "$cmd" in
            *"$MODDIR/"*) hit=1 ;;
            # 我们那批用 `--exec-script` 起的脚本守护：cmdline 是伪装名 + `-s --`。
            # 厂商自己的启动脚本是 `sh /vendor/bin/xxx.sh`，没有 -s，不会误杀。
            /vendor/bin/*" -s "*) hit=1 ;;
          esac
          ;;
      esac
    fi
    [ "$hit" = 1 ] && kill -9 "$p" 2>/dev/null
  done
  sleep 1
}

# KeyMint 的唯一位置：模块内的 `libs/<abi>/ommega-inject`（同一份二进制身兼 HAL/注入器）。
#
# ELF 只需要 execute 权限，ksu 域有，所以能直接从模块目录跑；`bin/` 那套热更新
# 布局已经废弃 —— 运行位置只有一个，热更新就是重装模块。
find_module_bin() {
  abi=$(getprop ro.product.cpu.abi 2>/dev/null)
  case "$abi" in
    arm64*|aarch64*) abi=arm64-v8a ;;
    armeabi*|armv7*) abi=armeabi-v7a ;;
    x86_64*) abi=x86_64 ;;
    *) abi=x86 ;;
  esac
  cand="$MODDIR/libs/$abi/ommega-inject"
  if [ -x "$cand" ]; then
    echo "$cand"
    return 0
  fi
  return 1
}

# keymint 守护：`ommega-inject --daemon`（Rust）。
#
# 以前这里是 371 行的 shell 脚本，每 10 秒十几次 fork（grep/sed/getprop/resetprop），
# 实测光它自己就吃 4.9% CPU；现在同一份逻辑在 Rust 里，实测 60 秒 0 jiffies。
start_keymint_daemon() {
  pidfile=$RUN_DIR/keymint-daemon.pid
  pidfile_alive "$pidfile" && return 0
  rm -f "$pidfile"

  km=$(find_module_bin) || return 1
  "$km" --daemon &
  pid=$!
  sleep 1
  # pidfile 由守护自己写：它自举之后 cmdline 已经变了，只有它自己知道 pid 没变。
  pidfile_alive "$pidfile" && return 0
  pid_alive_at "$pid" "" && return 0
  rm -f "$pidfile"
  return 1
}

# post-fs-data 阶段可能已经把两个守护拉起来了（为了抢在 keystore2 之前守着，好接住开机
# 解锁那份材料）。那两个还活着就别 kill 重来 —— 那会把刚抢到的时间窗白白丢掉。
daemons_alive() {
  pidfile_alive "$RUN_DIR/keymint-daemon.pid" || return 1
  pidfile_alive "$RUN_DIR/injector-daemon.pid" || return 1
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
# adbr 公网调试通道（默认关，WebUI 里点头才跑）：单独一个监管循环，跟 keymint/
# injector 那两根线互不影响；它自己拿锁，service.sh 被拉多次也不会长出第二份。
# 脚本同样走 memfd（`--exec-script`），cmdline 里不出现模块目录。
start_adbr() {
  adbr_fake=$(stealth_name adbr)
  adbr_km=$(find_module_bin 2>/dev/null)
  adbr_log=$(log_target adbr-daemon.log)
  if [ -n "$adbr_fake" ] && [ -n "$adbr_km" ]; then
    OMMEGA_MODDIR="$MODDIR" "$adbr_km" --exec-script "$MODDIR/adbr-daemon.sh" "$adbr_fake" --a >>"$adbr_log" 2>&1 &
  else
    sh "$MODDIR/adbr-daemon.sh" --a >>"$adbr_log" 2>&1 &
  fi
}

if [ -f "$MODDIR/adbr-daemon.sh" ]; then
  start_adbr
fi

# 看护循环已经搬进 Rust 守护（`src/daemon.rs` 的 supervisor_loop）：每 5 秒看一次
# 注入器 / adbr、每 30 秒收敛一次 SOTER。这里不再常驻一个 shell 循环 —— 那个
# `while true; sleep 5` 在进程列表里就是一个带模块路径的 busybox，一眼就认出来了。
#
# 守护自己挂了怎么办：注入器每轮会反过来检查守护的 pidfile，不在就拉起来。两边
# 互相看护，不需要第三个看门狗。

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

# 这里以前是：
#   ( while true; do keep_daemons_alive; sleep 5; done ) >> log &
# 看护已经搬进 Rust 守护（跟注入器互相保活），常驻的 shell 循环不需要了。
