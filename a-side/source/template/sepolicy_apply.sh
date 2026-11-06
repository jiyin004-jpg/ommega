# 把模块目录里的 sepolicy.rule 打进内核。post-fs-data.sh 和 service.sh 都 source 这个文件，
# 免得同一段逻辑抄两遍又各自跑偏（以前 post-fs-data 那侧会重试三次、service 那侧只认 ksud）。
#
# 各家 root 管理器的工具和语法都不一样，这里按能力依次试：
#   - KernelSU 系（KernelSU / KernelSU-Next / SukiSU / ReSukiSU）：`ksud sepolicy apply <file>`。
#     ksud 在 /data/adb/ksu/bin 下，不在 PATH 里（个别 fork 会放进 PATH，也认）。
#   - Magisk 系（Magisk / Delta / Alpha）：`magiskpolicy --live --apply <file>`，
#     `--apply` 是 24.0 之后才有的选项，正好也是本模块要求的最低版本附近。
#   - APatch：`/data/adb/ap/bin/magiskpolicy` 是 `/data/adb/apd` 的软链（apd 的多命令入口），
#     CLI 跟 Magisk 一致，`--live --apply` 同样能用。
#
# 还要说清楚一件事：Magisk 和 APatch 开机时都会自己把模块目录里的 sepolicy.rule 读一遍
# （Magisk 的 sepolicy 模块、APatch 的 `apd/src/module.rs:load_sepolicy_rule`），只有
# KernelSU 系重放这件事从来不做 —— 这正是这段自愈逻辑存在的原因。所以另外两家即使这里
# 一条都打不进去，功能上也过得去；日志会写明白到底找没找到工具。
#
# 用法：ommega_apply_sepolicy <rule 文件> [日志文件]
#   返回 0 时 stdout 打一行「用了哪个工具」，失败返回 1 且 stdout 为空。
#   日志一行一笔，失败时把每个候选路径的存在情况也记下来，方便现场反馈该补哪个位置。

_ommega_policy_log() {
  [ -n "$_OMMEGA_POLICY_LOG" ] || return 0
  printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)" "$*" >>"$_OMMEGA_POLICY_LOG" 2>/dev/null
}

# 候选工具列表：分成两组只是因为调用语法不同，不是按管理器分家。
_ommega_policy_ksud_candidates() {
  printf '%s\n' /data/adb/ksu/bin/ksud /data/adb/ksud ksud
}

_ommega_policy_magiskpolicy_candidates() {
  printf '%s\n' \
    /data/adb/magisk/magiskpolicy \
    /data/adb/ap/bin/magiskpolicy \
    /data/adb/ksu/bin/magiskpolicy \
    /debug_ramdisk/magiskpolicy \
    magiskpolicy
}

# 模块自己带的那份（vendor/policy 编出来的）。上面全找不到时才用它 ——
# 它不依赖任何管理器，但毕竟是我们自己维护的，能用管理器原生的工具就先用原生的。
_ommega_policy_bundled_candidates() {
  [ -n "${MODDIR:-}" ] || return 0
  _ommega_abi=$(getprop ro.product.cpu.abi 2>/dev/null)
  case "$_ommega_abi" in
    arm64* | aarch64*) printf '%s\n' "$MODDIR/libs/arm64-v8a/ommega-policy" ;;
    armeabi* | armv7*) printf '%s\n' "$MODDIR/libs/armeabi-v7a/ommega-policy" ;;
    x86_64*) printf '%s\n' "$MODDIR/libs/x86_64/ommega-policy" ;;
    x86*) printf '%s\n' "$MODDIR/libs/x86/ommega-policy" ;;
    *)
      for _ommega_p in "$MODDIR"/libs/*/ommega-policy; do
        [ -x "$_ommega_p" ] && printf '%s\n' "$_ommega_p"
      done
      ;;
  esac
}

# 候选名 -> 可直接执行的路径。裸名字走 PATH，绝对路径要可执行。
_ommega_policy_resolve() {
  case "$1" in
    /*)
      if [ -x "$1" ]; then printf '%s\n' "$1"; return 0; fi
      ;;
    *)
      _ommega_resolved=$(command -v "$1" 2>/dev/null)
      if [ -n "$_ommega_resolved" ] && [ -x "$_ommega_resolved" ]; then
        printf '%s\n' "$_ommega_resolved"
        return 0
      fi
      ;;
  esac
  return 1
}

# 一个都找不到时，把每个候选的存在情况写进日志：现场照着这行就能知道该给我们补哪个路径。
_ommega_policy_report_candidates() {
  _ommega_line=
  for _ommega_cand in $(_ommega_policy_ksud_candidates) \
    $(_ommega_policy_magiskpolicy_candidates) \
    $(_ommega_policy_bundled_candidates); do
    if _ommega_path=$(_ommega_policy_resolve "$_ommega_cand"); then
      _ommega_line="$_ommega_line $_ommega_cand=found($_ommega_path)"
    else
      _ommega_line="$_ommega_line $_ommega_cand=none"
    fi
  done
  _ommega_policy_log "no usable policy tool; probed:$_ommega_line"
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

# 只给「模块自带那份」用：它会把「规则 N 条、动了 X 处、哪些类型被跳过」打在 stderr 上，
# 这些正是现场排查要看的，所以直接追到日志里而不是咽掉。
_ommega_policy_exec_logged() {
  if [ -z "$_OMMEGA_POLICY_LOG" ]; then
    _ommega_policy_exec "$@"
    return $?
  fi
  if [ -n "$_OMMEGA_POLICY_HAVE_TIMEOUT" ]; then
    timeout 30 "$@" >>"$_OMMEGA_POLICY_LOG" 2>&1
  else
    "$@" >>"$_OMMEGA_POLICY_LOG" 2>&1
  fi
}

# 规则还在不在：用自带那份的 `--check`（只读、不写内核）。
# 返回 0 = 全在，1 = 缺（或者判断不了，宁可按「缺」处理）。
#
# 为什么要这一步：定期重新 apply 一次会把整份 policy 重新加载 —— 语义不变，
# 但 /sys/fs/selinux/policy 的字节会跟着换一种排序（ksud 每 apply 一次就换一次）。
# 对外不可见，但没必要为了「确认」把一台好好的机器每几分钟刷一遍。
ommega_sepolicy_rules_present() {
  _ommega_policy_rule=$1
  for _ommega_cand in $(_ommega_policy_bundled_candidates); do
    _ommega_tool=$(_ommega_policy_resolve "$_ommega_cand") || continue
    if _ommega_policy_exec "$_ommega_tool" --check --apply "$_ommega_policy_rule"; then
      return 0
    fi
    return 1
  done
  return 1
}

# 同一次 --check，但保留三种结果，给「复核别人的成功」用：
#   present / missing / unknown
# unknown 是连自带那份都没找到、根本判断不了 —— 这种时候按成功处理，别把正常的机器判成失败。
ommega_sepolicy_rule_state() {
  _ommega_policy_rule=$1
  for _ommega_cand in $(_ommega_policy_bundled_candidates); do
    _ommega_tool=$(_ommega_policy_resolve "$_ommega_cand") || continue
    _ommega_policy_exec "$_ommega_tool" --check --apply "$_ommega_policy_rule"
    case $? in
      0) printf 'present\n' ;;
      3) printf 'missing\n' ;;
      *) printf 'unknown\n' ;;
    esac
    return 0
  done
  printf 'unknown\n'
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

  # 1) KernelSU 系：整份文件一次 apply（ksud 自己的解析器按行读，列表长度有上限，
  #    sepolicy.rule 里已经按它的上限拆好了）。
  #    ksud 的 rc=0 只说明「解析没报错」，不保证写进内核：PKG110 上 KernelSU 1.4.5
  #    实测 apply 完 avc 照旧、`--check` 仍报缺。所以有自带那份就拿它复核一次，
  #    真缺就继续往下走 —— 下一级是直接写 /sys/fs/selinux/load，那是真的。
  for _ommega_cand in $(_ommega_policy_ksud_candidates); do
    _ommega_tool=$(_ommega_policy_resolve "$_ommega_cand") || continue
    if _ommega_policy_exec "$_ommega_tool" sepolicy apply "$_OMMEGA_POLICY_RULE"; then
      if [ "$(ommega_sepolicy_rule_state "$_OMMEGA_POLICY_RULE")" = "missing" ]; then
        _ommega_policy_log "ksud reported ok but rules still missing; falling through"
        continue
      fi
      _ommega_policy_log "ok $_ommega_tool sepolicy apply"
      printf '%s\n' "$_ommega_tool sepolicy apply"
      return 0
    fi
    _ommega_policy_log "fail $_ommega_tool sepolicy apply"
  done

  # 2) Magisk 系 / APatch：magiskpolicy --live --apply。
  for _ommega_cand in $(_ommega_policy_magiskpolicy_candidates); do
    _ommega_tool=$(_ommega_policy_resolve "$_ommega_cand") || continue
    if _ommega_policy_exec "$_ommega_tool" --live --apply "$_OMMEGA_POLICY_RULE"; then
      _ommega_policy_log "ok $_ommega_tool --live --apply"
      printf '%s\n' "$_ommega_tool --live --apply"
      return 0
    fi
    _ommega_policy_log "fail $_ommega_tool --live --apply"
  done

  # 3) 模块自带的那份：跟 magiskpolicy 一个 CLI（`--live --apply`），但走的是我们
  # 自己那份 libsepol（vendor/policy/ommega_policy.c）。
  for _ommega_cand in $(_ommega_policy_bundled_candidates); do
    _ommega_tool=$(_ommega_policy_resolve "$_ommega_cand") || continue
    if _ommega_policy_exec_logged "$_ommega_tool" --live --apply "$_OMMEGA_POLICY_RULE"; then
      _ommega_policy_log "ok $_ommega_tool --live --apply (bundled)"
      printf '%s\n' "$_ommega_tool --live --apply"
      return 0
    fi
    _ommega_policy_log "fail $_ommega_tool --live --apply (bundled)"
  done

  # 一个能用的工具都没有。这家管理器既不在 KernelSU 那条路上，也没给 magiskpolicy 的
  # 入口（改过二进制名、或者压根不带工具），模块自带的那份也没拷进来。规则这时候
  # 只能靠管理器自己开机重放 —— Magisk / APatch 会，KernelSU 不会。这行日志就是为
  # 这种情况留的。
  _ommega_policy_report_candidates
  return 1
}
