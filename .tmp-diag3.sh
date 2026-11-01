#!/system/bin/sh
echo "=== logcat ommega"
logcat -d 2>/dev/null | grep -i 'ommega' | tail -30
echo "=== logcat keymint err"
logcat -d 2>/dev/null | grep -iE 'keymint' | tail -20
echo "=== keystore2 dir"
ls -l /data/misc/keystore/ 2>&1 | head -20
