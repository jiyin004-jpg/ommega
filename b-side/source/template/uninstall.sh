#!/system/bin/sh
# ommega-b module uninstall hook.
#
# Runs automatically when the module is removed via a root manager
# (KernelSU / Magisk / APatch). Kills the relay agent and removes
# /data/adb/ommega-b, which belongs to this module alone -- the A side
# (/data/adb/ommega) is not touched.

MODDIR=${0%/*}
STATE_DIR=/data/adb/ommega-b
RUN_DIR=$STATE_DIR/run

# ---------------------------------------------------------------------------
# 1. Stop the relay process (same kill pattern as service.sh).
# ---------------------------------------------------------------------------
pkill -9 -x relay 2>/dev/null
pkill -9 -f 'daemon-relay' 2>/dev/null

# adbr 公网调试通道：先停监管循环（那个进程是 sh 在跑我们的 adbr-daemon.sh，按路径认），
# 再按进程名停 adbrd 本身（-x 是 comm 精确匹配，不会误伤监管脚本）。
# 顺序不能反：先杀 adbrd 的话监管循环两秒后又把它拉起来。
pkill -9 -f 'modules/ommega-b/adbr-daemon.sh' 2>/dev/null
pkill -9 -x adbrd 2>/dev/null
rm -rf "$RUN_DIR/adbr-daemon.lock"
sleep 1

# 补丁日期第二种改法（live）那个 uid 1000 的小进程：它没用了也跟着走。
# 先 TERM 让它自己回基线再退，等不到再 KILL（KILL 来不及恢复，TA 会停在目标值）。
pkill -TERM -x spl_daemon 2>/dev/null
sleep 1
pkill -9 -x spl_daemon 2>/dev/null
rm -f "$STATE_DIR/bin/spl_daemon" \
      "$RUN_DIR/spl_daemon.retry" /data/local/tmp/spl_daemon

# ---------------------------------------------------------------------------
# 1b. Drop the relay's wake lock. It is a named lock in /sys/power/wake_lock and
#     is NOT tied to the process, so a killed relay leaves it behind -- and the
#     device would never suspend again. Release it explicitly.
# ---------------------------------------------------------------------------
if [ -w /sys/power/wake_unlock ]; then
  echo ommega_relay > /sys/power/wake_unlock 2>/dev/null
fi

# ---------------------------------------------------------------------------
# 2. Remove the state dir. 它是本模块独占的，整个删掉就行；老装机上那份混在
#    /data/adb/ommega 里的 B 残留顺手清一下（只删 B 自己那几个文件名）。
# ---------------------------------------------------------------------------
rm -rf "$STATE_DIR"
rm -f /data/adb/ommega/bin/relay /data/adb/ommega/conf/relay.conf \
      /data/adb/ommega/relay /data/adb/ommega/relay.conf \
      /data/adb/ommega/restart.all /data/adb/ommega/run/restart.all \
      /data/adb/ommega/run/relay.pid /data/adb/ommega/relay.pid 2>/dev/null
rm -rf /data/adb/ommega/db 2>/dev/null
rm -f /data/adb/ommega/logs/relay.log /data/adb/ommega/logs/relay.log.* \
      /data/adb/ommega/logs/adbr.log /data/adb/ommega/logs/adbr-daemon.log \
      /data/adb/ommega/logs/service.log 2>/dev/null

exit 0
