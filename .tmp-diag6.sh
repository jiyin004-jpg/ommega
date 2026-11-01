#!/system/bin/sh
dmesg 2>/dev/null | grep -i 'avc' | grep -i 'ommega' | tail -12
echo "=== count"
dmesg 2>/dev/null | grep -ci 'avc.*ommega'
