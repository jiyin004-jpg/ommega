#!/system/bin/sh
for p in $(pgrep -f 'keystore2' 2>/dev/null); do
  n=$(tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null)
  m=$(grep -c ommega /proc/$p/maps 2>/dev/null)
  echo "pid=$p maps_ommega=$m cmd=$n"
done
echo "=== inject payload in keystore2?"
echo "=== rpc.peers"; cat /data/misc/ommega/rpc.peers 2>&1
echo "=== target.txt"; wc -c /data/misc/ommega/target.txt 2>&1; head -5 /data/misc/ommega/target.txt 2>&1
echo "=== injector config"
grep -E '^(scope|inject|debug|target)' /data/misc/ommega/injector.toml 2>&1 | head -10
