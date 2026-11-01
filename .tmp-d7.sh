#!/system/bin/sh
echo "--- avc tail"
dmesg 2>/dev/null | grep 'avc' | grep -i ommega | tail -5
echo "--- avc count"
dmesg 2>/dev/null | grep 'avc' | grep -ci ommega
echo "--- dirs"
ls -ld /data/misc/ommega /data/misc/ommega/logs /data/misc/ommega/config 2>&1
echo "--- procs"
ps -A -o PID,ARGS 2>/dev/null | grep -E 'keymint --daemon|daemon-injector' | grep -v grep
echo "--- logfiles"
ls -l /data/misc/ommega/logs/ 2>&1 | head -6
