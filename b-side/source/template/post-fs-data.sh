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

# Device id / machine id are filled ONLY when the config has no value yet
# (blank line or the template placeholder).  An already-set value — e.g. the
# random id minted by a previous boot, or a fixed id the user entered — is
# left untouched, so the device keeps its registered id.
if [ -f "$TARGET_RELAY_CONFIG" ]; then
  cur_device_id=$(sed -n 's/^OMMEGA_RELAY_DEVICE_ID=//p' "$TARGET_RELAY_CONFIG")
  if [ -z "$cur_device_id" ] || [ "$cur_device_id" = "device-b-<random>" ]; then
    rand_hex=$(tr -dc '0-9a-f' < /dev/urandom 2>/dev/null | head -c 8)
    [ -z "$rand_hex" ] && rand_hex=$(date +%s | md5sum 2>/dev/null | cut -c1-8)
    [ -z "$rand_hex" ] && rand_hex="$$"
    sed -i "s/^OMMEGA_RELAY_DEVICE_ID=.*/OMMEGA_RELAY_DEVICE_ID=device-b-$rand_hex/" "$TARGET_RELAY_CONFIG"
  fi

  cur_machine_id=$(sed -n 's/^OMMEGA_RELAY_MACHINE_ID=//p' "$TARGET_RELAY_CONFIG")
  if [ -z "$cur_machine_id" ] || [ "$cur_machine_id" = "<device-model>" ]; then
    model=$(getprop ro.product.model 2>/dev/null)
    [ -n "$model" ] && sed -i "s#^OMMEGA_RELAY_MACHINE_ID=.*#OMMEGA_RELAY_MACHINE_ID=$model#" "$TARGET_RELAY_CONFIG"
  fi
fi
