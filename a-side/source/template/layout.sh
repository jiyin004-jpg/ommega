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

if [ ! -e "$STATE_DIR/ommegadata" ] && [ ! -L "$STATE_DIR/ommegadata" ]; then
  mkdir -p "$DATA_ROOT" 2>/dev/null
  ln -s "$DATA_ROOT" "$STATE_DIR/ommegadata" 2>/dev/null
fi

# 组 system 可写（keystore 域要写 remote_identity / config），other 留 x 让 app 域读。
# 目录可能是别人建的，所以每次开机都正一次。
chmod 0771 "$DATA_ROOT" 2>/dev/null
chmod 0777 "$DATA_ROOT/logs" 2>/dev/null
