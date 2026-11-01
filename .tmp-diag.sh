#!/system/bin/sh
logcat -d -t 600 2>/dev/null | grep -iE 'ommega|keymint|keystore2' | tail -30
echo "=== files"
ls -l /data/misc/ommega/ 2>&1 | head -12
echo "=== keystore dir"
ls -l /data/misc/keystore/ommega/ 2>&1 | head -12
