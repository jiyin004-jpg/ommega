#!/system/bin/sh
echo "=== ps"
ps -A -o PID,ARGS 2>/dev/null | grep -E 'keymint|daemon-injector' | grep -v grep | head -5
echo "=== data root"
ls -l /data/misc/ommega/ 2>&1 | head -14
echo "=== keystore root"
ls -l /data/misc/keystore/ommega/ 2>&1 | head -14
echo "=== config"
cat /data/misc/ommega/config 2>&1 | head -30
echo "=== keymint.log tail"
tail -25 /data/misc/ommega/logs/keymint.log 2>&1
echo "=== injector.log tail"
tail -12 /data/misc/ommega/logs/injector.log 2>&1
