MODDIR=${0%/*}
STATE_DIR=/data/adb/ommega

mkdir -p "$STATE_DIR" "$STATE_DIR/logs"
rm -f "$STATE_DIR/restart.all"

# First-install only: drop the relay config template so the relay daemon
# (B-side, remote TEE attestation) actually has settings to load.  Edit
# /data/adb/ommega/relay.conf after install to point at the real relay_server.
TARGET_RELAY_CONFIG=$STATE_DIR/relay.conf
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
