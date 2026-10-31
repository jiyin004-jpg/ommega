#!/system/bin/sh
# 开机属性伪装里「必须晚半拍」的那一组：ro.boot 的启动状态三连。
# （ro.boot.vbmeta.digest / public_key_digest **不在这里**：它们只喂给我们自己的
#  keymint 构造证书，vold 不看，早写在 post-fs-data 里，证书才能带上面板设的伪装值。）
#
# 为什么要等 keymint 起稳再改：
#   - vold 在开机早期读 verifiedbootstate / flash.locked / vbmeta.device_state，
#     拿它们算 FBE key 的派生和元数据加解密策略；
# 早改的后果：vold 按伪装后的状态解密，用户之前（真机状态下加密的）FBE keyblob
# 就解不开 —— 表现是锁屏密码明明输对了，却进不去桌面。
#
# vbmeta.digest 不在这里：它只给我们自己的 keymint 填证书的 verified_boot_hash，
# vold 的判断看 ro.boot.veritymode，与它无关。早写在 post-fs-data 里，证书才能
# 带上面板设的伪装值。
#
# 晚改的代价只有一处：开机到 keymint 起来之间（几百毫秒）读这些属性的检测器会
# 看到真值。app 层的 getprop 是实时的，用户能跑检测器时早就是伪装值了。
#
# 由 service.sh 在 daemon（keymint）启动后调用，别在 post-fs-data 阶段调。

MODDIR=${0%/*}
[ -f "$MODDIR/layout.sh" ] && . "$MODDIR/layout.sh" 2>/dev/null
STATE_DIR=/data/adb/ommega
BIN_DIR=$STATE_DIR/bin
CONF_DIR=$STATE_DIR/conf
TARGET_DIR=/data/misc/keystore/ommega
TARGET_CONF=$TARGET_DIR/config

RESETPROP_BIN=$BIN_DIR/resetprop
if [ ! -x "$RESETPROP_BIN" ]; then
  rp_abi=$(getprop ro.product.cpu.abi 2>/dev/null)
  case "$rp_abi" in
    arm64*) rp_abi=arm64-v8a ;;
    armeabi*|armv7*) rp_abi=armeabi-v7a ;;
    x86_64*) rp_abi=x86_64 ;;
    i?86|x86) rp_abi=x86 ;;
    *) rp_abi= ;;
  esac
  if [ -n "$rp_abi" ] && [ -x "$MODDIR/libs/$rp_abi/resetprop" ]; then
    RESETPROP_BIN="$MODDIR/libs/$rp_abi/resetprop"
  else
    RESETPROP_BIN=resetprop
  fi
fi
rp() { "$RESETPROP_BIN" "$@"; }

# 只在属性本来就存在时改：凭空造一个反而多一处马脚。
set_if_present() {
  [ -n "$1" ] && [ -n "$2" ] || return 0
  [ -n "$(getprop "$1" 2>/dev/null)" ] || return 0
  rp "$1" "$2"
}

# 远程模式下跟 B 真机声明的启动状态；本地模式说本机自己（locked / green）。
RI=$TARGET_DIR/remote_identity
remote=$(grep -iE '^[[:space:]]*remote[[:space:]]*:' "$TARGET_CONF" 2>/dev/null | head -n1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r')
locked=
state=
case "$remote" in
  1|true|yes|on)
    if [ -f "$RI" ]; then
      locked=$(sed -n 's/^device_locked=//p' "$RI" 2>/dev/null | head -n1)
      state=$(sed -n 's/^verified_boot_state=//p' "$RI" 2>/dev/null | head -n1)
    fi
    ;;
esac
case "$state" in
  0) rp ro.boot.verifiedbootstate green ;;
  1) rp ro.boot.verifiedbootstate yellow ;;
  2) rp ro.boot.verifiedbootstate orange ;;
  3) rp ro.boot.verifiedbootstate red ;;
  *) rp ro.boot.verifiedbootstate green ;;
esac
case "$locked" in
  0)
    rp ro.boot.flash.locked 0
    rp ro.boot.vbmeta.device_state unlocked
    ;;
  *)
    rp ro.boot.flash.locked 1
    rp ro.boot.vbmeta.device_state locked
    ;;
esac
unset RI remote locked state

# 面板 props.conf 里显式写的 ro.boot.* 优先级最高。
PROP_OVERRIDES=$CONF_DIR/props.conf
if [ -r "$PROP_OVERRIDES" ]; then
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in ''|'#'*) continue ;; esac
    p_key=${line%%:*}
    p_val=${line#*:}
    p_key=$(printf '%s' "$p_key" | tr -d ' \t\r')
    p_val=$(printf '%s' "$p_val" | tr -d '\r' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
    case "$p_val" in
      \"*\") p_val=${p_val#\"}; p_val=${p_val%\"} ;;
    esac
    case "$p_key" in
      ro.boot.verifiedbootstate|ro.boot.flash.locked|ro.boot.vbmeta.device_state) ;;
      *) continue ;;
    esac
    set_if_present "$p_key" "$p_val"
  done < "$PROP_OVERRIDES"
fi
