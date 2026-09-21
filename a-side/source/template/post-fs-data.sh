MODDIR=${0%/*}
TARGET_DIR=/data/misc/keystore/ommega
LOG_DIR=$TARGET_DIR/logs
TARGET_KEYBOX=$TARGET_DIR/keybox.xml
TARGET_INJECTOR_CONFIG=$TARGET_DIR/injector.toml
TARGET_CONF=$TARGET_DIR/config
TARGET_TARGET_LIST=$TARGET_DIR/target.txt
STATE_DIR=/data/adb/ommega
# A-side config directory (webroot UI writes here; `ommegadata` is a symlink to
# $TARGET_DIR, so the UI and the keystore process (uid 1017) share one copy).
CLIENTA_DIR=/data/adb/ommega
resetprop persist.logd.size ""
resetprop persist.logd.size.crash ""
resetprop persist.logd.size.system ""
resetprop persist.logd.size.main ""
resetprop ro.boot.flash.locked 1
resetprop ro.boot.verifiedbootstate green
resetprop ro.boot.veritymode enforcing
resetprop ro.boot.vbmeta.device_state locked
resetprop ro.secure 1
resetprop ro.adb.secure 1
resetprop ro.debuggable 0
resetprop sys.oem_unlock_allowed 0
resetprop ro.secureboot.devicelock 1
mkdir -p "$TARGET_DIR"
chmod 0770 "$TARGET_DIR"
chown 1017:1017 "$TARGET_DIR"
mkdir -p "$LOG_DIR"
chmod 0770 "$LOG_DIR"
chown 1017:1017 "$LOG_DIR"
mkdir -p "$STATE_DIR"
rm -f "$STATE_DIR/keymint-daemon.pid" "$STATE_DIR/injector-daemon.pid"
rm -f "$STATE_DIR/restart.keymint" "$STATE_DIR/restart.injector" "$STATE_DIR/restart.all"

# Make the shared A-side config directory traversable and expose the data dir.
mkdir -p "$CLIENTA_DIR"
chmod 0755 "$CLIENTA_DIR"
# The webroot UI and the keystore process (uid 1017) must share ONE data dir:
# the UI only writes "$CLIENTA_DIR/ommegadata/*", the daemons only read
# "$TARGET_DIR/*".  A plain directory (or file) left at that path by an older
# build, a manual step or a file manager puts both sides on separate copies —
# UI saves would then silently never reach the daemon.  Repair it every boot:
# migrate what is there, then replace it with the symlink.
if [ -L "$CLIENTA_DIR/ommegadata" ]; then
  : # already the symlink
elif [ -d "$CLIENTA_DIR/ommegadata" ]; then
  for f in config target.txt system_app keybox.xml; do
    stray="$CLIENTA_DIR/ommegadata/$f"
    real="$TARGET_DIR/$f"
    [ -f "$stray" ] || continue
    # Newest copy wins; copy in place so owner/mode of the real file survive.
    if [ ! -f "$real" ] || [ "$stray" -nt "$real" ]; then
      cat "$stray" > "$real" 2>/dev/null || true
    fi
  done
  rm -rf "$CLIENTA_DIR/ommegadata"
  ln -s "$TARGET_DIR" "$CLIENTA_DIR/ommegadata" 2>/dev/null
elif [ -e "$CLIENTA_DIR/ommegadata" ]; then
  # Stray regular file: keep it aside, then expose the real dir as a symlink.
  mv -f "$CLIENTA_DIR/ommegadata" "$CLIENTA_DIR/ommegadata.stray" 2>/dev/null
  ln -s "$TARGET_DIR" "$CLIENTA_DIR/ommegadata" 2>/dev/null
else
  ln -s "$TARGET_DIR" "$CLIENTA_DIR/ommegadata" 2>/dev/null
fi

# Single data location for the flat A-side config and per-app target list.
# The webroot UI writes these through the `ommegadata` symlink, so no copy is
# needed.  Seed the config on first install with the official online service
# defaults (README "快速使用（官方在线服务）"), so the A-side connects out of
# the box; an already-present config (e.g. from the WebUI or a previous install)
# is left untouched.
if [ ! -f "$TARGET_CONF" ]; then
  cat > "$TARGET_CONF" <<'EOF'
url: http://110.40.170.96:10886
token: aY7kRSDDR6PMmamlKwtgf7mQgr-X5uFd
device_id: device-b-2
tls_insecure: true
remote: on
EOF
fi
if [ ! -f "$TARGET_TARGET_LIST" ]; then
  : > "$TARGET_TARGET_LIST"
fi
chmod 0644 "$TARGET_CONF" "$TARGET_TARGET_LIST" 2>/dev/null || true
chown 1017:1017 "$TARGET_CONF" "$TARGET_TARGET_LIST" 2>/dev/null || true

# Keybox: the webroot UI writes `/data/adb/ommega/ommegadata/keybox.xml` which IS
# $TARGET_KEYBOX (via symlink).  Seed from the module keybox if absent.
if [ ! -f "$TARGET_KEYBOX" ] && [ -f "$MODDIR/keybox.xml" ]; then
  cp "$MODDIR/keybox.xml" "$TARGET_KEYBOX"
fi

if [ ! -f "$TARGET_INJECTOR_CONFIG" ] && [ -f "$MODDIR/injector.toml" ]; then
  cp "$MODDIR/injector.toml" "$TARGET_INJECTOR_CONFIG"
fi

if [ -f "$TARGET_KEYBOX" ]; then
  chmod 0600 "$TARGET_KEYBOX"
  chown 1017:1017 "$TARGET_KEYBOX"
fi

if [ -f "$TARGET_INJECTOR_CONFIG" ]; then
  chmod 0600 "$TARGET_INJECTOR_CONFIG"
  chown 1017:1017 "$TARGET_INJECTOR_CONFIG"
fi

# ---- "声明不支持 StrongBox"（flat config 键 hide_strongbox）----
# 挂载完全交给 root 管理器（Magisk magic mount / KernelSU overlayfs）：
# customize.sh 安装时按设备实际情况在模块 system/<分区>/etc/permissions/ 下
# 放置了 0:0 dummy 设备（whiteout），管理器开机挂载时据此删掉对应的
# strongbox_keystore feature XML，PackageManager 即报不支持；keystore 守护
# 进程（Rust 侧）读同一开关决定是否注册 STRONGBOX security level（config
# watcher 热生效）。这里只按开关增删标记文件，改动下次重启生效。
WL_NAME="android.hardware.security.strongbox_keystore.xml"
# 每项是"模块 system/ 底下的相对路径"：/system 自己不带分区前缀，其余分区要带。
WL_RELS="vendor/etc/permissions product/etc/permissions system_ext/etc/permissions etc/permissions"
hide_strongbox=false
if [ -f "$TARGET_CONF" ]; then
  hide_value=$(grep -iE '^[[:space:]]*(hide_strongbox|no_strongbox|hide_strongbox_keystore)[[:space:]]*:' "$TARGET_CONF" 2>/dev/null | head -n 1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r')
  case "$hide_value" in
    1|true|yes|on) hide_strongbox=true ;;
  esac
  unset hide_value
fi
for rel in $WL_RELS; do
  marker="$MODDIR/system/$rel/$WL_NAME"
  # 换算回系统里的真实路径：vendor 那种自带分区前缀，system 的要补上
  case "$rel" in
    vendor/*|product/*|system_ext/*) src_file="/$rel/$WL_NAME" ;;
    *) src_file="/system/$rel/$WL_NAME" ;;
  esac
  if [ "$hide_strongbox" = true ]; then
    # 系统里真实存在声明、且模块还没有标记时补建（覆盖安装后才出现声明、
    # 或曾被关闭删掉的情形）；设备上不存在的分区路径自然跳过，零副作用
    [ -f "$src_file" ] || continue
    [ -e "$marker" ] && continue
    mkdir -p "$MODDIR/system/$rel"
    if mknod "$marker" c 0 0 2>/dev/null; then
      echo "ommega: hide_strongbox on; whiteout restored at $rel"
    elif printf '<?xml version="1.0" encoding="utf-8"?>\n<permissions/>\n' > "$marker" 2>/dev/null; then
      echo "ommega: hide_strongbox on; overlay restored at $rel"
    fi
  elif [ -e "$marker" ]; then
    rm -f "$marker"
    echo "ommega: hide_strongbox off; whiteout removed from $rel"
  fi
done
unset WL_NAME WL_RELS hide_strongbox
