#!/system/bin/sh
# 开机幂等补一件事：`/data/adb/ommega/ommegadata` 软链。
#
# 面板「保存并生效」要把配置写进 /data/misc/ommega/，写的是这个软链；
# 它只在 customize.sh 里建过，而手动解压 / 热更新 / 直接把新文件盖进老模块目录
# 都不会跑 customize.sh，缺了它面板一保存就 No such file or directory。
#
# 这里**不再**搬二进制、不再往 bin/ 复制 resetprop：运行文件只认模块目录
# `libs/<abi>/`，`bin/` 那套热更新布局已废弃。

STATE_DIR=/data/adb/ommega
DATA_ROOT=/data/misc/ommega

# 软链目标必须就是数据根。老版本建过指向 /data/misc/keystore/ommega 的软链，
# 那种不会报错，只会让面板写的配置落到程序不读的地方（远程模式永远开不起来），
# 所以这里不光补缺，指向不对也直接重建。
mkdir -p "$DATA_ROOT" 2>/dev/null
if [ ! -L "$STATE_DIR/ommegadata" ] || [ "$(readlink "$STATE_DIR/ommegadata" 2>/dev/null)" != "$DATA_ROOT" ]; then
  rm -f "$STATE_DIR/ommegadata" 2>/dev/null
  ln -s "$DATA_ROOT" "$STATE_DIR/ommegadata" 2>/dev/null
fi

# 组 system 可写（keystore 域要写 remote_identity / config），other 留 x 让 app 域读。
# 目录可能是别人建的，所以每次开机都正一次。
#
# owner 必须是 keystore：keystore2 里的 TA 要往这里落 remote_identity、keymint 要
# atomic replace config.toml，两者都是「在目录里建临时文件再 rename」，光有文件
# 写权限不够，得目录可写。这个目录是 root 脚本建的，main.rs 降权后那次 chown
# 改不动它，所以只能在 root 这边做。
mkdir -p "$DATA_ROOT/logs" 2>/dev/null
chown keystore:keystore "$DATA_ROOT" 2>/dev/null
chown keystore:keystore "$DATA_ROOT/logs" 2>/dev/null
chmod 0771 "$DATA_ROOT" 2>/dev/null
# logs 用 sticky：app 域（SOTER 宿主不是 keystore uid）的 payload 要往这里写日志，
# 不开 other 写它就落不下档；sticky 位拦住删掉 / 改名别人的文件。
chmod 1777 "$DATA_ROOT/logs" 2>/dev/null
