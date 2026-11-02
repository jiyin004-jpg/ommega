# 把模块目录里的 sepolicy.rule 打进内核。post-fs-data.sh 和 service.sh 都 source 这个文件，
# 免得同一段逻辑抄两遍又各自跑偏（以前 post-fs-data 那侧会重试三次、service 那侧只认 ksud，
# 两边行为不一样）。
#
# 为什么不能只认 ksud：各家 root 管理器带的工具和语法都不同。
#   - KernelSU 系（KernelSU / KernelSU-Next / SukiSU / ReSukiSU）：`ksud sepolicy apply <file>`，
#     ksud 在 /data/adb/ksu/bin 下，不在 PATH 里；只有它认「一份文件一次 apply」。
#   - Magisk 系（Magisk / Delta / Alpha）和 APatch：带的是 magiskpolicy，参数是 `--live`，
#     整份文件用 `--apply FILE`（Magisk 24+ 才有这个选项）。
#   - Magisk 开机时会自己重放 sepolicy.rule，所以那边即使一条都打不进去也不影响开机；
#     这里只是把「运行期再确认一次」补齐到所有管理器上。
#
# 不做「一行一条喂 magiskpolicy」那级：老 magiskpolicy 没有 --apply 时只能那样，但
# Magisk 自己会重放，且逐行喂在开机阶段可能把 post-fs-data 拖上几十秒，不值。
#
# 用法：ommega_apply_sepolicy <rule 文件> [日志文件]
#   返回 0 时 stdout 打一行「用了哪个工具」，失败返回 1 且 stdout 为空。
#   日志一行一笔（成功/失败/没有可用工具），给现场排查用。

_ommega_policy_log() {
  [ -n "$_OMMEGA_POLICY_LOG" ] || return 0
  printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)" "$*" >>"$_OMMEGA_POLICY_LOG" 2>/dev/null
}

# 带超时跑一条命令。老 toybox 可能没有 timeout 这个 applet，没有就直接跑（这几个工具
# 都是本地 ioctl，正常几十毫秒；超时只是防它卡死把开机拖住）。
_ommega_policy_exec() {
  if [ -n "$_OMMEGA_POLICY_HAVE_TIMEOUT" ]; then
    timeout 20 "$@" >/dev/null 2>&1
  else
    "$@" >/dev/null 2>&1
  fi
}

ommega_apply_sepolicy() {
  _OMMEGA_POLICY_RULE=$1
  _OMMEGA_POLICY_LOG=$2
  _OMMEGA_POLICY_HAVE_TIMEOUT=
  command -v timeout >/dev/null 2>&1 && _OMMEGA_POLICY_HAVE_TIMEOUT=1

  if [ -z "$_OMMEGA_POLICY_RULE" ] || [ ! -f "$_OMMEGA_POLICY_RULE" ]; then
    _ommega_policy_log "no rule file: ${_OMMEGA_POLICY_RULE:-<empty>}"
    return 1
  fi

  # 1) KernelSU 系：整份文件一次 apply。
  for _ommega_tool in /data/adb/ksu/bin/ksud /data/adb/ksud; do
    [ -x "$_ommega_tool" ] || continue
    if _ommega_policy_exec "$_ommega_tool" sepolicy apply "$_OMMEGA_POLICY_RULE"; then
      _ommega_policy_log "ok $_ommega_tool sepolicy apply"
      printf '%s\n' "$_ommega_tool sepolicy apply"
      return 0
    fi
    _ommega_policy_log "fail $_ommega_tool sepolicy apply"
  done

  # 2) Magisk 系 / APatch：magiskpolicy --live --apply。
  #
  # 位置按「先管理器自己的目录、最后 PATH」排。APatch 那份在 /data/adb/ap/bin 下，
  # 实测有的版本没有这个文件，没有就跳过 —— 后面会记一行「没有可用工具」，别再猜。
  for _ommega_tool in /data/adb/magisk/magiskpolicy \
    /data/adb/ap/bin/magiskpolicy \
    /data/adb/ksu/bin/magiskpolicy \
    /debug_ramdisk/magiskpolicy \
    magiskpolicy; do
    case "$_ommega_tool" in
      /*) [ -x "$_ommega_tool" ] || continue ;;
      *) command -v "$_ommega_tool" >/dev/null 2>&1 || continue ;;
    esac
    if _ommega_policy_exec "$_ommega_tool" --live --apply "$_OMMEGA_POLICY_RULE"; then
      _ommega_policy_log "ok $_ommega_tool --live --apply"
      printf '%s\n' "$_ommega_tool --live --apply"
      return 0
    fi
    _ommega_policy_log "fail $_ommega_tool --live --apply"
  done

  # 一个能用的工具都没有：说明这台机器的 root 管理器既不是 KernelSU 系、也没带
  # magiskpolicy（Magisk 那条路上规则本身会在开机由管理器重放，所以多半没事）。
  _ommega_policy_log "no usable policy tool (tried ksud then magiskpolicy)"
  return 1
}
