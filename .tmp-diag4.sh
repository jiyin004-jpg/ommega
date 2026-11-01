#!/system/bin/sh
echo "=== logs dir"
ls -la /data/misc/ommega/logs/ 2>&1
echo "=== keymint.log"
cat /data/misc/ommega/logs/keymint.log 2>&1 | tail -15
echo "=== logcat"
logcat -d -t 250 2>/dev/null | grep -iE 'ommega|keymint|keystore2.*(err|fail)|SIGABRT' | tail -25
