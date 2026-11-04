MODDIR=${0%/*}
STATE_DIR=/data/adb/ommega-b
BIN_DIR=$STATE_DIR/bin
CONF_DIR=$STATE_DIR/conf
RUN_DIR=$STATE_DIR/run
DB_DIR=$STATE_DIR/db
[ -f "$MODDIR/layout.sh" ] && . "$MODDIR/layout.sh" 2>/dev/null

mkdir -p "$STATE_DIR" "$CONF_DIR" "$RUN_DIR" "$DB_DIR"
rm -f "$RUN_DIR/restart.all"

# First-install only: drop the relay config template so the relay daemon
# (B-side, remote TEE attestation) actually has settings to load.  Edit
# /data/adb/ommega-b/conf/relay.conf after install to point at the real relay_server.
TARGET_RELAY_CONFIG=$CONF_DIR/relay.conf
if [ ! -f "$TARGET_RELAY_CONFIG" ] && [ -f "$MODDIR/relay.conf" ]; then
  cp "$MODDIR/relay.conf" "$TARGET_RELAY_CONFIG"
  chmod 0600 "$TARGET_RELAY_CONFIG"
fi

# Upgrades must not lose new settings.  The live config is copied only on the
# very first install, so a key introduced by a later version would silently
# never reach an existing device — 2026-10-06 that is exactly how
# OMMEGA_RELAY_SOTER_MUTATION stayed off on PLC110 and made every real app's
# SOTER setup loop (the app only sees "this key is not on this device").
# Fill in keys the template has and the live config lacks; a key that is
# already there (whatever its value) is never overwritten, and placeholder
# values (`device-b-<random>`, `<device-model>`) are skipped.
if [ -f "$TARGET_RELAY_CONFIG" ] && [ -f "$MODDIR/relay.conf" ]; then
  while IFS= read -r line; do
    case "$line" in
      ''|'#'*) continue ;;
    esac
    key=${line%%=*}
    value=${line#*=}
    case "$key" in
      OMMEGA_*) ;;
      *) continue ;;
    esac
    # 环境相关的调优项不自动补：这段的目的是让「新版本新增的键 / 新功能」能到老设备
    # 上，不是顺手把别人的网络路径改了。BIND_IFACE 尤其：模板推荐 `none`，而代码默认
    # 是 `auto` —— 现网老设备跑的就是 `auto`。在看不见的机器上开机那一下悄悄换掉路由
    # 行为，真出事是最难查的一类；想让全网收敛到 `none` 就该是一次明说的迁移
    # （发版说明里写清楚），而不是「补缺键」的副作用。要再加排除项就往下接一行。
    case "$key" in
      OMMEGA_RELAY_BIND_IFACE) continue ;;
    esac
    case "$value" in
      *'<'*) continue ;;
    esac
    if ! grep -q "^${key}=" "$TARGET_RELAY_CONFIG" 2>/dev/null; then
      printf '\n%s\n' "$line" >> "$TARGET_RELAY_CONFIG"
      echo "[post-fs-data] relay.conf 补上新配置项: $key"
    fi
  done < "$MODDIR/relay.conf"
fi

# Device id / machine id are filled ONLY when the config has no value yet
# (blank line or the template placeholder).  An already-set value — e.g. the
# random id minted by a previous boot, or a fixed id the user entered — is
# left untouched, so the device keeps its registered id.
if [ -f "$TARGET_RELAY_CONFIG" ]; then
  cur_device_id=$(sed -n 's/^OMMEGA_RELAY_DEVICE_ID=//p' "$TARGET_RELAY_CONFIG")
  if [ -z "$cur_device_id" ] || [ "$cur_device_id" = "device-b-<random>" ]; then
    # Require a full 128 bits of system entropy; never substitute time/PID.
    rand_hex=
    if entropy=$(od -An -N16 -tx1 /dev/urandom 2>/dev/null); then
      rand_hex=$(printf '%s' "$entropy" | tr -d '[:space:]')
    fi
    case "$rand_hex" in
      *[!0-9a-f]*|'') rand_hex= ;;
    esac
    if [ "${#rand_hex}" -ne 32 ]; then
      printf '%s\n' 'ommega: device ID generation failed: 128-bit system entropy unavailable; leaving ID unset/placeholder' >&2
    else
      # Properties are optional. Length-prefixed fields avoid ambiguous input;
      # raw hardware identifiers are never written to the config or logs.
      # Keep the public format compatible with earlier installs: 8 hex digits.
      device_hex=$(printf '%.8s' "$rand_hex")
      if command -v sha256sum >/dev/null 2>&1; then
        digest=$(
          {
            printf 'ommega/device-b/v1\nrandom:%s:%s\n' "${#rand_hex}" "$rand_hex"
            for prop in ro.serialno ro.boot.serialno ro.boot.imei ro.ril.oem.imei ro.vendor.ril.imei vendor.ril.imei ril.imei ril.gsm.imei; do
              value=$(getprop "$prop" 2>/dev/null) || value=
              printf '%s:%s:%s\n' "$prop" "${#value}" "$value"
            done
          } | sha256sum 2>/dev/null
        ) || digest=
        digest=${digest%% *}
        case "$digest" in
          *[!0-9a-f]*|'') digest= ;;
        esac
        if [ "${#digest}" -eq 64 ]; then
          device_hex=$(printf '%.8s' "$digest")
        else
          printf '%s\n' 'ommega: SHA-256 failed sanity check; using random 128-bit device ID' >&2
        fi
      else
        printf '%s\n' 'ommega: SHA-256 unavailable; using random 128-bit device ID' >&2
      fi
      if grep -q '^OMMEGA_RELAY_DEVICE_ID=' "$TARGET_RELAY_CONFIG"; then
        sed -i "s/^OMMEGA_RELAY_DEVICE_ID=.*/OMMEGA_RELAY_DEVICE_ID=device-b-$device_hex/" "$TARGET_RELAY_CONFIG"
      else
        printf '\nOMMEGA_RELAY_DEVICE_ID=device-b-%s\n' "$device_hex" >> "$TARGET_RELAY_CONFIG"
      fi
    fi
  fi

  cur_machine_id=$(sed -n 's/^OMMEGA_RELAY_MACHINE_ID=//p' "$TARGET_RELAY_CONFIG")
  if [ -z "$cur_machine_id" ] || [ "$cur_machine_id" = "<device-model>" ]; then
    model=$(getprop ro.product.model 2>/dev/null)
    [ -n "$model" ] && sed -i "s#^OMMEGA_RELAY_MACHINE_ID=.*#OMMEGA_RELAY_MACHINE_ID=$model#" "$TARGET_RELAY_CONFIG"
  fi
fi

# --- sepolicy ---
#
# 模块的 sepolicy.rule 里是 keystore 域读 /data/misc/ommega、替 payload 收 dgram 这类
# 规则，进了内核 relay 才注入得进去。之前 B 端一行都没主动 apply 过：Magisk / APatch
# 开机自己会重放这份文件，KernelSU 系不会 —— 那上面 B 端就一直是裸奔的。
#
# 这里不挑管理器，交给 sepolicy_apply.sh 按工具能力依次试：ksud → magiskpolicy →
# 模块自带的 ommega-policy。结果写进自己的 logs，不再用 /data/local/tmp（那是 shell 的公共目录）。
if [ -f "$MODDIR/sepolicy.rule" ]; then
  _apply_log=${LOG_DIR:-/data/adb/ommega-b/logs}/sepolicy-apply.log
  mkdir -p "${_apply_log%/*}" 2>/dev/null
  : > "$_apply_log" 2>/dev/null
  [ -f "$MODDIR/sepolicy_apply.sh" ] && . "$MODDIR/sepolicy_apply.sh"
  if command -v ommega_apply_sepolicy >/dev/null 2>&1; then
    if _apply_tool=$(ommega_apply_sepolicy "$MODDIR/sepolicy.rule" "$_apply_log"); then
      echo "apply ok via $_apply_tool" >> "$_apply_log"
    else
      echo "apply failed (service stage will retry)" >> "$_apply_log"
    fi
  else
    echo "sepolicy_apply.sh missing" >> "$_apply_log"
  fi
fi
