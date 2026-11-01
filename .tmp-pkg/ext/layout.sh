#!/system/bin/sh
# 运行时目录整理：把原来平铺在 /data/adb/ommega 根下的东西收进 bin/conf/run/db/logs。
#
# 只在开机（post-fs-data / service）和安装时各跑一次；幂等：目标已存在就不动，
# 旧路径有、新路径没有就搬过去。**只支持新路径**，不再保留老的读取兜底。

STATE_DIR=/data/adb/ommega
BIN_DIR=$STATE_DIR/bin
CONF_DIR=$STATE_DIR/conf
RUN_DIR=$STATE_DIR/run
LOG_DIR_TOP=$STATE_DIR/logs

migrate_ommega_layout() {
  mkdir -p "$BIN_DIR" "$CONF_DIR" "$RUN_DIR" "$LOG_DIR_TOP" 2>/dev/null

  # 二进制（hot update 会往这里换，模块目录里的 libs/ 仍是出厂副本）
  for f in keymint ommega-inject soterta-ta resetprop adbrd; do
    [ -f "$STATE_DIR/$f" ] || continue
    [ -e "$BIN_DIR/$f" ] || mv -f "$STATE_DIR/$f" "$BIN_DIR/$f" 2>/dev/null
  done

  # 配置 / 状态文件
  for f in props.conf injector.payload pathmask.state pathmask.owned \
           remote_identity.applied remote_identity.updated empty_permissions.xml \
           relay.conf log_flag kmod-loader.log; do
    [ -f "$STATE_DIR/$f" ] || continue
    tgt=$CONF_DIR/$f
    case "$f" in
      kmod-loader.log) tgt=$LOG_DIR_TOP/$f ;;
    esac
    [ -e "$tgt" ] || mv -f "$STATE_DIR/$f" "$tgt" 2>/dev/null
  done

  # 运行期：pid、重启标记、锁目录
  for f in keymint-daemon.pid injector-daemon.pid soterta.pid soterta.takeover.pid \
           soterta.host.kicked relay.pid restart.keymint restart.injector restart.all; do
    [ -f "$STATE_DIR/$f" ] || continue
    [ -e "$RUN_DIR/$f" ] || mv -f "$STATE_DIR/$f" "$RUN_DIR/$f" 2>/dev/null
  done
  for d in adbr-daemon.lock injector-daemon.lock keymint-daemon.lock relay-service.lock; do
    [ -d "$STATE_DIR/$d" ] || continue
    [ -e "$RUN_DIR/$d" ] || mv -f "$STATE_DIR/$d" "$RUN_DIR/$d" 2>/dev/null
  done

  # B 端那套会话库在 A 端不存在（A 不跑 relay），所以这里没有 db/

  # keystore 侧：备份类收进 backups/，配置与密钥材料留在原地（TA 里路径是写死的）
  KS_DIR=/data/misc/keystore/ommega
  if [ -d "$KS_DIR" ]; then
    mkdir -p "$KS_DIR/backups" 2>/dev/null
    for f in "$KS_DIR"/config.bak* "$KS_DIR"/config.toml.bak "$KS_DIR"/keybox_tee.xml.bak "$KS_DIR"/keybox_strongbox.xml.bak; do
      [ -f "$f" ] || continue
      mv -f "$f" "$KS_DIR/backups/" 2>/dev/null
    done
  fi
}

migrate_ommega_layout

# 安装期才做的两件事，也在这里幂等补上：ommegadata 软链与 bin/resetprop 都是
# customize.sh 建的，而手动解压、热更新、或直接把新文件盖进老模块目录这几条路
# 都不会跑 customize.sh。缺了软链，面板「保存并生效」写 config 就直接
# No such file or directory（ommegadata 就是写配置的入口）；缺了 resetprop，
# 伪装参数那条会静默失效。开机（post-fs-data / service）与安装各跑一次，有就不动。
KS_DATA=/data/misc/keystore/ommega
MOD_DIR=${0%/*}
[ -d "$MOD_DIR/libs" ] || MOD_DIR=/data/adb/modules/ommega

ensure_state_links() {
  if [ ! -e "$STATE_DIR/ommegadata" ] && [ ! -L "$STATE_DIR/ommegadata" ]; then
    mkdir -p "$KS_DATA" 2>/dev/null
    ln -s "$KS_DATA" "$STATE_DIR/ommegadata" 2>/dev/null
  fi

  if [ ! -x "$BIN_DIR/resetprop" ]; then
    abi=$(getprop ro.product.cpu.abi 2>/dev/null)
    case "$abi" in
      arm64*) abi=arm64-v8a ;;
      armeabi*) abi=armeabi-v7a ;;
      x86_64*) abi=x86_64 ;;
      i?86|x86) abi=x86 ;;
      *) abi= ;;
    esac
    for src in "$STATE_DIR/resetprop" "$MOD_DIR/libs/$abi/resetprop" "$MOD_DIR/resetprop"; do
      [ -f "$src" ] || continue
      cp -f "$src" "$BIN_DIR/resetprop" 2>/dev/null || continue
      chmod 0755 "$BIN_DIR/resetprop" 2>/dev/null
      break
    done
  fi
}

ensure_state_links
