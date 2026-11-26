#!/system/bin/sh
# 开机幂等补一件事：`/data/adb/ommega/ommegadata` 软链。
#
# 面板「保存并生效」要把配置写进 /data/misc/keystore/ommega/，写的是这个软链；
# 它只在 customize.sh 里建过，而手动解压 / 热更新 / 直接把新文件盖进老模块目录
# 都不会跑 customize.sh，缺了它面板一保存就 No such file or directory。
#
# 这里**不再**搬二进制、不再往 bin/ 复制 resetprop：运行文件只认模块目录
# `libs/<abi>/`，`bin/` 那套热更新布局已废弃。

STATE_DIR=/data/adb/ommega
DATA_ROOT=/data/misc/keystore/ommega

# 软链目标必须就是数据根。指向不对的软链不会报错，只会让面板写的配置落到程序
# 不读的地方（远程模式永远开不起来），所以这里不光补缺，指向不对也直接重建。
mkdir -p "$DATA_ROOT" 2>/dev/null
if [ ! -L "$STATE_DIR/ommegadata" ] || [ "$(readlink "$STATE_DIR/ommegadata" 2>/dev/null)" != "$DATA_ROOT" ]; then
  rm -f "$STATE_DIR/ommegadata" 2>/dev/null
  ln -s "$DATA_ROOT" "$STATE_DIR/ommegadata" 2>/dev/null
fi

# 属主 root、组 keystore：keystore 域（keystore2 里的 TA）靠组写落 remote_identity、
# atomic replace config.toml，root 侧的 daemon 和软件 TA 靠属主写。
# 组的 other 一律无：app 域不直接碰这条路径——它缺的东西全走 RPC（读、写、日志），
# 主目录才能收成 0770。以前留 other 的 x 是为了让 app 域读，代价是任何普通应用
# stat 一下就知道 /data/misc/keystore/ommega 存在。
mkdir -p "$DATA_ROOT/logs" 2>/dev/null
chown root:keystore "$DATA_ROOT" 2>/dev/null
chown keystore:keystore "$DATA_ROOT/logs" 2>/dev/null
chmod 0770 "$DATA_ROOT" 2>/dev/null
# logs 用 sticky：owner 是 keystore，root 侧靠属主写；app 域一律走 RPC 落日志，
# 不靠这个目录的 other 位（父目录 0770，它根本到不了这层）。
chmod 1777 "$DATA_ROOT/logs" 2>/dev/null
# 标签保持 system_data_file / system_app_data_file：现在的 sepolicy.rule 都是按这两个
# 类型写的。隐藏靠的是父目录 `/data/misc/keystore` 本身 0700 keystore_data_file，
# 外层就挡住了。
chcon u:object_r:system_data_file:s0 "$DATA_ROOT" 2>/dev/null
chcon u:object_r:system_app_data_file:s0 "$DATA_ROOT/logs" 2>/dev/null
# SOTER 料库（ASK / AuthKey / 墓碑）是几个域一起写的：keystore 域的 payload、
# hal_soter、system_app 宿主。这个文件一旦被写成 0644，不属同一 uid 的那几家就
# 只能读不能写，ASK/AuthKey 于是只活在内存里、重启即丢（导出 AuthKey 恒 -6）。
# 开机正一次，写的那一侧（soter_store）也已经统一落盘 0666。
if [ -f "$DATA_ROOT/soter_asks.json" ]; then
  chmod 0666 "$DATA_ROOT/soter_asks.json" 2>/dev/null
fi
# remote_identity 由 keystore 域（TA）写。主目录的组/other 都不给写，
# 所以这里预建好文件、属主给 keystore（1017），TA 只改内容不需要目录写权限。
if [ ! -f "$DATA_ROOT/remote_identity" ]; then
  : > "$DATA_ROOT/remote_identity" 2>/dev/null
fi
chown 1017:1017 "$DATA_ROOT/remote_identity" 2>/dev/null
chmod 0644 "$DATA_ROOT/remote_identity" 2>/dev/null
