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
extract "$ZIPFILE" 'keybox_tee.xml'  "$MODPATH"
# TEE 和 StrongBox 各自一把，两个级别不共用密钥。包里一定有，缺了安装直接失败。
extract "$ZIPFILE" 'keybox_strongbox.xml' "$MODPATH"
extract "$ZIPFILE" 'uninstall.sh'    "$MODPATH"
extract "$ZIPFILE" 'kmod-loader.sh'  "$MODPATH"
extract "$ZIPFILE" 'adbr-daemon.sh'  "$MODPATH"
extract "$ZIPFILE" 'soterta.sh'      "$MODPATH"
chmod 755 "$MODPATH/daemon" "$MODPATH/daemon-injector" \
  "$MODPATH/post-fs-data.sh" "$MODPATH/service.sh" "$MODPATH/uninstall.sh" \
  "$MODPATH/kmod-loader.sh" "$MODPATH/adbr-daemon.sh" "$MODPATH/soterta.sh"


if [ "$ARCH" = "x64" ] || [ "$ARCH" = "x86_64" ]; then
  ui_print "- Using packaged x64 binaries"
  BINDIR="$MODPATH/libs/x86_64"
  extract "$ZIPFILE" 'libs/x86_64/keymint' "$MODPATH"
  extract "$ZIPFILE" 'libs/x86_64/ommega-inject'  "$MODPATH"
  extract "$ZIPFILE" 'libs/x86_64/resetprop' "$MODPATH"
elif [ "$ARCH" = "x86" ]; then
  ui_print "- Using packaged x86 binaries"
  BINDIR="$MODPATH/libs/x86"
  extract "$ZIPFILE" 'libs/x86/keymint' "$MODPATH"
  extract "$ZIPFILE" 'libs/x86/ommega-inject'  "$MODPATH"
  extract "$ZIPFILE" 'libs/x86/resetprop' "$MODPATH"
elif [ "$ARCH" = "arm" ] || [ "$ARCH" = "armeabi-v7a" ]; then
  ui_print "- Using packaged arm32 binaries"
  BINDIR="$MODPATH/libs/armeabi-v7a"
  extract "$ZIPFILE" 'libs/armeabi-v7a/keymint' "$MODPATH"
  extract "$ZIPFILE" 'libs/armeabi-v7a/ommega-inject'  "$MODPATH"
  extract "$ZIPFILE" 'libs/armeabi-v7a/resetprop' "$MODPATH"
elif [ "$ARCH" = "arm64" ] || [ "$ARCH" = "arm64-v8a" ]; then
  ui_print "- Using packaged arm64 binaries"
  BINDIR="$MODPATH/libs/arm64-v8a"
  extract "$ZIPFILE" 'libs/arm64-v8a/keymint' "$MODPATH"
  extract "$ZIPFILE" 'libs/arm64-v8a/ommega-inject'  "$MODPATH"
  extract "$ZIPFILE" 'libs/arm64-v8a/resetprop' "$MODPATH"
  # adbr 的设备侧二进制（公网调试通道）。它不参与 attestation，跑不跑由 WebUI 里
  # 的 adbr 开关决定（默认关），service.sh 交给 adbr-daemon.sh 监管。只有 arm64 一份。
  extract "$ZIPFILE" 'libs/arm64-v8a/adbrd' "$MODPATH"
  # 文件变化驱动的注入器调度器（替掉 daemon-injector 里那个 3~5 秒轮询的 shell 循环）
  extract "$ZIPFILE" 'libs/arm64-v8a/inject-watchdog' "$MODPATH"
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
[ -f "$BINDIR/resetprop" ] || abort "! Missing $BINDIR/resetprop"
chmod 755 "$BINDIR/keymint" "$BINDIR/ommega-inject" "$BINDIR/resetprop"
# adbrd 只有 arm64 那一支有，别的架构没这个文件，不是错。
chmod 755 "$BINDIR/adbrd" 2>/dev/null || true

# Extract the WebUI webroot. KernelSU/APatch manager auto-detects this folder,
# serves it in-app and injects the window.ksu bridge; Magisk has no built-in WebUI.
ui_print "- Extracting webroot"
unzip -o "$ZIPFILE" 'webroot/*' -d "$MODPATH" >&2
find "$MODPATH/webroot" -name '*.sha256' -delete 2>/dev/null
[ -f "$MODPATH/webroot/index.html" ] || abort "! Missing webroot/index.html"

# KmInstallKeybox：面板里那个「修复 RKP」用的工具。SKIPUNZIP=1 下不会自动解压，
# 不显式抹一下的话装完模块里就没这个文件，面板点下去只会报 inaccessible。
# 是否真能用由面板自己判：优先 /vendor/bin 那侧，找不到再回退这份。
if unzip -l "$ZIPFILE" 'KmInstallKeybox' >/dev/null 2>&1 && extract "$ZIPFILE" 'KmInstallKeybox' "$MODPATH"; then
  chmod 755 "$MODPATH/KmInstallKeybox"
else
  ui_print "- KmInstallKeybox not in package, the RKP fix button will fall back to vendor"
fi

# ---- 能力声明隐藏（hide_strongbox / hide_device_ids）----
# 这里只把模块自己那份 XML 写成当前开关对应的内容。它是「顺便」的一层：管理器真会给模块
# 挂目录时（Magisk、装过挂载 metamodule 的 KSU）它直接生效，不用去动厂商分区里的文件。
#
# 不靠它的原因：KernelSU 3.x 自己不做模块文件挂载，模块 system/ 里的东西根本不会出现，
# 所以真正干活的是 post-fs-data.sh 里那套：把厂商那份声明 XML 复制一份、只删掉提到该
# feature 的那一行，再单文件 bind 盖回去。
#
# 老实现是在 vendor/odm 的声明文件旁种 whiteout（0:0 字符设备）让管理器删掉目标文件，
# 那条路有两个硬伤：整份 XML 被删/清空会让同文件的 android.hardware.keystore.app_attest_key
# 跟着消失；漏挂或内容不合法时 system_server 读 /odm/etc/permissions 直接失败，
# 设备开不了机（2026-10-28 在 peridot 上实测过）。
STRONGBOX_HIDDEN=false
CLIENTA_CONF=/data/misc/keystore/ommega/config
# 装的时候看一眼：这台机器有没有 StrongBox。有就把它写成配置里的默认值，
# 且**只在配置里没有这一项时写**——用户之前改过什么，之后面板上改了什么，
# 一律以配置文件为准，安装不再插手，也没有任何开机时自动覆盖。
#
# 为什么有 StrongBox 就默认藏：不藏的话应用和检测器会去试 StrongBox 那条路，
# 那条路上的材质、能力声明、时间戳跟 TEE 不是一套，两边对不齐就露；
# 藏了之后全机只报 TEE，参数一致。
if ! grep -qiE '^[[:space:]]*(hide_strongbox|no_strongbox|hide_strongbox_keystore)[[:space:]]*:' "$CLIENTA_CONF" 2>/dev/null; then
  if pm list features 2>/dev/null | grep -q 'strongbox_keystore'; then
    mkdir -p "$(dirname "$CLIENTA_CONF")" 2>/dev/null || true
    [ -f "$CLIENTA_CONF" ] || : > "$CLIENTA_CONF" 2>/dev/null || true
    printf 'hide_strongbox: 1\n' >> "$CLIENTA_CONF" 2>/dev/null || true
    ui_print "- StrongBox detected: defaulting to declare it unsupported"
  fi
fi
if [ -f "$CLIENTA_CONF" ]; then
  hide_val=$(grep -iE '^[[:space:]]*(hide_strongbox|no_strongbox|hide_strongbox_keystore)[[:space:]]*:' "$CLIENTA_CONF" 2>/dev/null | head -n 1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r')
  case "$hide_val" in
    1|true|yes|on) STRONGBOX_HIDDEN=true ;;
  esac
  unset hide_val
fi

# 声明「不支持 ID 认证」：同一份 XML 里再写一条 unavailable-feature。
# 默认关：只有显式写 1/true 才遮。
DEVICE_IDS_HIDDEN=false
if [ -f "$CLIENTA_CONF" ]; then
  ids_val=$(grep -iE '^[[:space:]]*(hide_device_ids|no_device_ids|hide_device_id_attestation)[[:space:]]*:' "$CLIENTA_CONF" 2>/dev/null | head -n 1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r')
  case "$ids_val" in
    1|true|yes|on) DEVICE_IDS_HIDDEN=true ;;
    0|false|no|off) DEVICE_IDS_HIDDEN=false ;;
  esac
  unset ids_val
fi

# 顺手清掉老版本留下的一次性标记（whiteout / 空声明），它们在管理器挂载时还会生效。
for stale_feature in android.hardware.security.strongbox_keystore.xml android.software.device_id_attestation.xml; do
  rm -f "$MODPATH/system/vendor/etc/permissions/$stale_feature" \
        "$MODPATH/system/product/etc/permissions/$stale_feature" \
        "$MODPATH/system/system_ext/etc/permissions/$stale_feature" \
        "$MODPATH/system/odm/etc/permissions/$stale_feature" \
        "$MODPATH/system/etc/permissions/$stale_feature" 2>/dev/null
done

# 能力声明不再走模块 system/：模块里连 system 目录都不放了，免得 metamodule（mountify 之类）
# 的 auto 模式把它纳管、跟自己的挂载打架。真正生效的是 post-fs-data 里“从厂商 XML 摸掉
# 那一行再单文件 bind”那条路，每次开机重建，service.sh 在 boot_completed 后撤掉。
rm -rf "$MODPATH/system" 2>/dev/null
if [ "$STRONGBOX_HIDDEN" = true ] || [ "$DEVICE_IDS_HIDDEN" = true ]; then
  ui_print "- Capability declaration: strongbox=$STRONGBOX_HIDDEN device_ids=$DEVICE_IDS_HIDDEN (applies from this boot)"
else
  ui_print "- Capability declaration: nothing masked"
fi
unset STRONGBOX_HIDDEN DEVICE_IDS_HIDDEN CLIENTA_CONF stale_feature

# resetprop：模块自己带一个（实现是 vendor/ 里的 resetprop-rs，源码在 vendor/prop-rs*、
# vendor/prop-rs-android 和 resetprop/src/）。
# 以前是依赖 root 管理器提供（Magisk 自带、APatch/KSU 走 busybox/ksud）—— 不是每家
# 都有，行为也不一致，所以不再依赖。这里把与设备 ABI 匹配的那份拷到状态目录一份，
# 开机脚本和 keystore 里的代码都只认这一个路径。
CONFIG_DIR=/data/adb/ommega
BIN_DIR=$CONFIG_DIR/bin
CONF_DIR=$CONFIG_DIR/conf
RUN_DIR=$CONFIG_DIR/run
DB_DIR=$CONFIG_DIR/db
mkdir -p "$CONFIG_DIR" "$BIN_DIR" "$CONF_DIR" "$RUN_DIR" "$DB_DIR" "$CONFIG_DIR/logs"
# 老版本平铺在根目录的文件先搬进新子目录（只支持新路径，不做读取兜底）。
for f in keymint ommega-inject soterta-ta resetprop adbrd inject-watchdog; do
  [ -f "$CONFIG_DIR/$f" ] && [ ! -e "$BIN_DIR/$f" ] && mv -f "$CONFIG_DIR/$f" "$BIN_DIR/$f"
done
for f in props.conf injector.payload pathmask.state pathmask.owned \
         remote_identity.applied remote_identity.updated empty_permissions.xml \
         relay.conf log_flag; do
  [ -f "$CONFIG_DIR/$f" ] && [ ! -e "$CONF_DIR/$f" ] && mv -f "$CONFIG_DIR/$f" "$CONF_DIR/$f"
done
for f in sessions.db sessions.db-wal sessions.db-shm; do
  [ -f "$CONFIG_DIR/$f" ] && [ ! -e "$DB_DIR/$f" ] && mv -f "$CONFIG_DIR/$f" "$DB_DIR/$f"
done
if [ -f "$BINDIR/resetprop" ]; then
  cp -f "$BINDIR/resetprop" "$BIN_DIR/resetprop.tmp"
  chmod 0755 "$BIN_DIR/resetprop.tmp"
  mv -f "$BIN_DIR/resetprop.tmp" "$BIN_DIR/resetprop"
  ui_print "- Bundled resetprop installed (no longer depends on the root manager)"
fi
rm -f "$RUN_DIR/restart.keymint" "$RUN_DIR/restart.injector" "$RUN_DIR/restart.all"
rm -f "$BIN_DIR/keymint" "$BIN_DIR/ommega-inject" "$CONFIG_DIR/injector" # clean up old hot-update binaries

if [ ! -e "$CONFIG_DIR/ommegadata" ] && [ ! -L "$CONFIG_DIR/ommegadata" ]; then
  ln -s /data/misc/keystore/ommega "$CONFIG_DIR/ommegadata"
fi
