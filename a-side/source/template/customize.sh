# shellcheck disable=SC2034
SKIPUNZIP=1

SONAME="Ommega"
SUPPORTED_ABIS="arm64 x64"
MIN_SDK=29

if [ "$APATCH" = "true" ]; then
  # APatch：apd 设 APATCH=true/APATCH_VER/APATCH_VER_CODE；它的 installer.sh 会
  # 伪装 MAGISK_VER_CODE=30000（兼容老模块），所以 APATCH 分支必须放在 Magisk
  # 分支之前。挂载行为与 Magisk/KSU 一致（新版同为 metamodule/overlayfs）。
  ui_print "- Installing from APatch app"
  ui_print "- APatch version: $APATCH_VER ($APATCH_VER_CODE)"
  if [ "$(which magisk)" ]; then
    ui_print "*********************************************************"
    ui_print "! Multiple root implementation is NOT supported!"
    ui_print "! Please uninstall Magisk before installing Ommega"
    abort    "*********************************************************"
  fi
elif [ "$BOOTMODE" ] && [ "$KSU" ]; then
  ui_print "- Installing from KernelSU app"
  ui_print "- KernelSU version: $KSU_KERNEL_VER_CODE (kernel) + $KSU_VER_CODE (ksud)"
  if [ "$(which magisk)" ]; then
    ui_print "*********************************************************"
    ui_print "! Multiple root implementation is NOT supported!"
    ui_print "! Please uninstall Magisk before installing Ommega"
    abort    "*********************************************************"
  fi
elif [ "$BOOTMODE" ] && [ "$MAGISK_VER_CODE" ]; then
  ui_print "- Installing from Magisk app"
else
  ui_print "*********************************************************"
  ui_print "! Install from recovery is not supported"
  ui_print "! Please install from APatch, KernelSU or Magisk app"
  abort    "*********************************************************"
fi

VERSION=$(grep_prop version "${TMPDIR}/module.prop")
ui_print "- Installing $SONAME $VERSION"

# check architecture
support=false
for abi in $SUPPORTED_ABIS
do
  if [ "$ARCH" == "$abi" ]; then
    support=true
  fi
done
if [ "$support" == "false" ]; then
  abort "! Unsupported platform: $ARCH"
else
  ui_print "- Device platform: $ARCH"
fi

# check android
if [ "$API" -lt $MIN_SDK ]; then
  ui_print "! Unsupported sdk: $API"
  abort "! Minimal supported sdk is $MIN_SDK"
else
  ui_print "- Device sdk: $API"
fi

ui_print "- Extracting verify.sh"
unzip -o "$ZIPFILE" 'verify.sh' -d "$TMPDIR" >&2
if [ ! -f "$TMPDIR/verify.sh" ]; then
  ui_print "*********************************************************"
  ui_print "! Unable to extract verify.sh!"
  ui_print "! This zip may be corrupted, please try downloading again"
  abort    "*********************************************************"
fi
. "$TMPDIR/verify.sh"
extract "$ZIPFILE" 'customize.sh'  "$TMPDIR/.vunzip"
extract "$ZIPFILE" 'verify.sh'     "$TMPDIR/.vunzip"

ui_print "- Extracting module files"
extract "$ZIPFILE" 'module.prop'     "$MODPATH"
extract "$ZIPFILE" 'post-fs-data.sh' "$MODPATH"
extract "$ZIPFILE" 'service.sh'      "$MODPATH"
extract "$ZIPFILE" 'sepolicy.rule'   "$MODPATH"
extract "$ZIPFILE" 'daemon'          "$MODPATH"
extract "$ZIPFILE" 'daemon-injector' "$MODPATH"
extract "$ZIPFILE" 'injector.toml'   "$MODPATH"
extract "$ZIPFILE" 'keybox.xml'      "$MODPATH"
extract "$ZIPFILE" 'uninstall.sh'    "$MODPATH"
extract "$ZIPFILE" 'kmod-loader.sh'  "$MODPATH"
chmod 755 "$MODPATH/daemon" "$MODPATH/daemon-injector" \
  "$MODPATH/post-fs-data.sh" "$MODPATH/service.sh" "$MODPATH/uninstall.sh" \
  "$MODPATH/kmod-loader.sh"


if [ "$ARCH" = "x64" ] || [ "$ARCH" = "x86_64" ]; then
  ui_print "- Using packaged x64 binaries"
  BINDIR="$MODPATH/libs/x86_64"
  extract "$ZIPFILE" 'libs/x86_64/keymint' "$MODPATH"
  extract "$ZIPFILE" 'libs/x86_64/ommega-inject'  "$MODPATH"
elif [ "$ARCH" = "x86" ]; then
  ui_print "- Using packaged x86 binaries"
  BINDIR="$MODPATH/libs/x86"
  extract "$ZIPFILE" 'libs/x86/keymint' "$MODPATH"
  extract "$ZIPFILE" 'libs/x86/ommega-inject'  "$MODPATH"
elif [ "$ARCH" = "arm" ] || [ "$ARCH" = "armeabi-v7a" ]; then
  ui_print "- Using packaged arm32 binaries"
  BINDIR="$MODPATH/libs/armeabi-v7a"
  extract "$ZIPFILE" 'libs/armeabi-v7a/keymint' "$MODPATH"
  extract "$ZIPFILE" 'libs/armeabi-v7a/ommega-inject'  "$MODPATH"
elif [ "$ARCH" = "arm64" ] || [ "$ARCH" = "arm64-v8a" ]; then
  ui_print "- Using packaged arm64 binaries"
  BINDIR="$MODPATH/libs/arm64-v8a"
  extract "$ZIPFILE" 'libs/arm64-v8a/keymint' "$MODPATH"
  extract "$ZIPFILE" 'libs/arm64-v8a/ommega-inject'  "$MODPATH"
  # pathmask 内核模块只对 arm64 有意义（上游只提供 arm64 构建），逐个 extract
  # 让 verify.sh 对每个 .ko 做 sha256 校验；缺文件或哈希不符会直接中止安装。
  ui_print "- Extracting pathmask kernel modules"
  for kmi in android12-5.10 android13-5.10 android13-5.15 android14-5.15 \
             android14-6.1 android15-6.6 android16-6.12; do
    extract "$ZIPFILE" "pathmask/${kmi}_pathmask.ko" "$MODPATH"
  done
  extract "$ZIPFILE" 'pathmask/UPSTREAM.md' "$MODPATH"
  chmod 0644 "$MODPATH"/pathmask/*.ko
else
  abort "! Unsupported platform: $ARCH"
fi

[ -f "$BINDIR/keymint" ] || abort "! Missing $BINDIR/keymint"
[ -f "$BINDIR/ommega-inject" ] || abort "! Missing $BINDIR/ommega-inject"
chmod 755 "$BINDIR/keymint" "$BINDIR/ommega-inject"

# Extract the WebUI webroot. KernelSU/APatch manager auto-detects this folder,
# serves it in-app and injects the window.ksu bridge; Magisk has no built-in WebUI.
ui_print "- Extracting webroot"
unzip -o "$ZIPFILE" 'webroot/*' -d "$MODPATH" >&2
find "$MODPATH/webroot" -name '*.sha256' -delete 2>/dev/null
[ -f "$MODPATH/webroot/index.html" ] || abort "! Missing webroot/index.html"

# ---- StrongBox 声明隐藏（hide_strongbox 开关的静态载体）----
# 声明 android.hardware.security.strongbox_keystore 的 feature XML 在哪个分区因
# 设备而异，安装时现场检测：对真实存在的声明文件，在模块 system/ 的对应相对路径
# 下放 0:0 dummy 设备（Magisk/KSU 的标准 whiteout 语义，管理器挂载时会删掉目标
# 文件）。挂载完全由 root 管理器完成，本模块不做任何手动 mount；开关关闭时
# post-fs-data.sh 移除标记，管理器下次开机即恢复原状。
# 开关关着就一个标记都不种。这里必须读配置：模块文件是在 magic mount
# 阶段被挂上去的，而模块自己的 post-fs-data.sh 要在那之后才跑，
# 所以安装时无脑创建的话，开关关着的用户装完第一次开机
# 也会被隐藏，PM 说没有 StrongBox 而 daemon 照样提供服务，
# 反而露马脚。开关后面打开时 post-fs-data.sh 会自己补建。
STRONGBOX_HIDDEN=false
CLIENTA_CONF=/data/misc/keystore/ommega/config
if [ -f "$CLIENTA_CONF" ]; then
  hide_val=$(grep -iE '^[[:space:]]*(hide_strongbox|no_strongbox|hide_strongbox_keystore)[[:space:]]*:' "$CLIENTA_CONF" 2>/dev/null | head -n 1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r')
  case "$hide_val" in
    1|true|yes|on) STRONGBOX_HIDDEN=true ;;
  esac
  unset hide_val
fi

STRONGBOX_FEATURE="android.hardware.security.strongbox_keystore.xml"
if [ "$STRONGBOX_HIDDEN" = true ]; then
  for src_dir in \
    /system/etc/permissions \
    /system_ext/etc/permissions \
    /vendor/etc/permissions \
    /product/etc/permissions; do
    [ -f "$src_dir/$STRONGBOX_FEATURE" ] || continue
    # 模块镜像里的路径：Magisk 约定是 system/<分区>/...，而 /system 自己
    # 不再带一层前缀（不然会变成 /system/system/...）。
    rel=${src_dir#/}
    rel=${rel#system/}
    tgt="$MODPATH/system/$rel"
    mkdir -p "$tgt"
    if mknod "$tgt/$STRONGBOX_FEATURE" c 0 0 2>/dev/null; then
      ui_print "- StrongBox whiteout: $rel/$STRONGBOX_FEATURE"
    else
      # mknod 被拒（SELinux/内核限制）时退化为空声明覆盖，效果一致
      printf '<?xml version="1.0" encoding="utf-8"?>\n<permissions/>\n' > "$tgt/$STRONGBOX_FEATURE"
      ui_print "- StrongBox overlay: $rel/$STRONGBOX_FEATURE (whiteout unavailable)"
    fi
  done
fi
unset STRONGBOX_FEATURE STRONGBOX_HIDDEN CLIENTA_CONF

# resetprop 是系统属性伪装（ro.boot.* 等）的依赖：Magisk 自带，APatch/KSU 由
# 其 busybox 提供。缺失时模块仍可安装运行（keymint 接管、StrongBox 隐藏不受
# 影响），只是属性伪装不生效，这里明确提示而不是悄悄失败。
if ! command -v resetprop >/dev/null 2>&1; then
  ui_print "*********************************************************"
  ui_print "! resetprop not found on this manager!"
  ui_print "! System property spoofing will NOT work!"
  ui_print "*********************************************************"
fi

CONFIG_DIR=/data/adb/ommega
mkdir -p "$CONFIG_DIR"
rm -f "$CONFIG_DIR/restart.keymint" "$CONFIG_DIR/restart.injector" "$CONFIG_DIR/restart.all"
rm -f "$CONFIG_DIR/keymint" "$CONFIG_DIR/ommega-inject" "$CONFIG_DIR/injector" # clean up old hot-update binaries

if [ ! -e "$CONFIG_DIR/ommegadata" ] && [ ! -L "$CONFIG_DIR/ommegadata" ]; then
  ln -s /data/misc/keystore/ommega "$CONFIG_DIR/ommegadata"
fi
