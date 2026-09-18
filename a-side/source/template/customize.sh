# shellcheck disable=SC2034
SKIPUNZIP=1

SONAME="Ommega"
SUPPORTED_ABIS="arm64 x64"
MIN_SDK=29

if [ "$BOOTMODE" ] && [ "$KSU" ]; then
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
  ui_print "! Please install from KernelSU or Magisk app"
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

CONFIG_DIR=/data/adb/ommega
mkdir -p "$CONFIG_DIR"
rm -f "$CONFIG_DIR/restart.keymint" "$CONFIG_DIR/restart.injector" "$CONFIG_DIR/restart.all"
rm -f "$CONFIG_DIR/keymint" "$CONFIG_DIR/ommega-inject" "$CONFIG_DIR/injector" # clean up old hot-update binaries

if [ ! -e "$CONFIG_DIR/ommegadata" ] && [ ! -L "$CONFIG_DIR/ommegadata" ]; then
  ln -s /data/misc/keystore/ommega "$CONFIG_DIR/ommegadata"
fi
