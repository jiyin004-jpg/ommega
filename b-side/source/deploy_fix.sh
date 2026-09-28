#!/system/bin/sh
# 一次性修复:停掉所有 daemon-relay + relay,替换为新版(无kill逻辑),重启单个 daemon
set -x

echo "=== 1. 停掉所有 daemon-relay ==="
for pid in $(pgrep -f daemon-relay); do
  [ "$pid" = "$$" ] && continue
  kill -9 "$pid" 2>/dev/null
done
sleep 1

echo "=== 2. 停掉所有 relay ==="
for pid in $(pgrep -f 'ommega/relay' ; pgrep -f 'libs/arm64-v8a/relay'); do
  kill -9 "$pid" 2>/dev/null
done
sleep 1

echo "=== 3. 清 pid 文件 ==="
rm -f /data/adb/ommega/relay.pid /data/adb/ommega/relay-daemon.pid

echo "=== 4. 替换为新版 daemon-relay ==="
cp /data/local/tmp/daemon-relay /data/adb/modules/ommega-b/daemon-relay
chmod 0755 /data/adb/modules/ommega-b/daemon-relay

echo "=== 5. 验证新版无 kill 逻辑 ==="
grep -c kill_duplicates /data/adb/modules/ommega-b/daemon-relay || true
wc -c /data/adb/modules/ommega-b/daemon-relay

echo "=== 6. 启动单个 daemon ==="
nohup sh /data/adb/modules/ommega-b/daemon-relay >/dev/null 2>&1 &
echo "daemon started, pid=$!"
sleep 3

echo "=== 7. 验证进程 ==="
ps -A | grep -E 'daemon-relay|relay' | grep -v grep
