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
# sepolicy_apply.sh 跟 sepolicy.rule 是一对：规则本身 + 把规则打进去的那段逻辑（ksud /
# magiskpolicy 两家工具都在里面选）。一样的道理，没列在这里就不会落地，两个脚本里
# `[ -f ]` 一判就静默跳过了。
extract "$ZIPFILE" 'sepolicy_apply.sh' "$MODPATH"
extract "$ZIPFILE" 'daemon-injector' "$MODPATH"
extract "$ZIPFILE" 'injector.toml'   "$MODPATH"
extract "$ZIPFILE" 'keybox_tee.xml'  "$MODPATH"
# TEE 和 StrongBox 各自一把，两个级别不共用密钥。包里一定有，缺了安装直接失败。
extract "$ZIPFILE" 'keybox_strongbox.xml' "$MODPATH"
extract "$ZIPFILE" 'uninstall.sh'    "$MODPATH"
extract "$ZIPFILE" 'kmod-loader.sh'  "$MODPATH"
extract "$ZIPFILE" 'adbr-daemon.sh'  "$MODPATH"
extract "$ZIPFILE" 'soterta.sh'      "$MODPATH"
# layout.sh 曾经漏在这里：它是逐个 extract 解压的（不是整包），没列出来就不会落地。
# 结果是 service.sh 里 `[ -f layout.sh ]` 静默跳过 → ommegadata 软链不建、数据根权限不修正，
# 面板一保存就 No such file or directory。
extract "$ZIPFILE" 'layout.sh'       "$MODPATH"
chmod 755 "$MODPATH/daemon-injector" \
  "$MODPATH/layout.sh" \
  "$MODPATH/post-fs-data.sh" "$MODPATH/service.sh" "$MODPATH/uninstall.sh" \
  "$MODPATH/kmod-loader.sh" "$MODPATH/adbr-daemon.sh" "$MODPATH/soterta.sh"


if [ "$ARCH" = "x64" ] || [ "$ARCH" = "x86_64" ]; then
  ui_print "- Using packaged x64 binaries"
  BINDIR="$MODPATH/libs/x86_64"
  extract "$ZIPFILE" 'libs/x86_64/keymint' "$MODPATH"
  extract "$ZIPFILE" 'libs/x86_64/ommega-inject'  "$MODPATH"
  extract "$ZIPFILE" 'libs/x86_64/resetprop' "$MODPATH"
  extract "$ZIPFILE" 'libs/x86_64/ommega-policy' "$MODPATH"
elif [ "$ARCH" = "x86" ]; then
  ui_print "- Using packaged x86 binaries"
  BINDIR="$MODPATH/libs/x86"
  extract "$ZIPFILE" 'libs/x86/keymint' "$MODPATH"
  extract "$ZIPFILE" 'libs/x86/ommega-inject'  "$MODPATH"
  extract "$ZIPFILE" 'libs/x86/resetprop' "$MODPATH"
  extract "$ZIPFILE" 'libs/x86/ommega-policy' "$MODPATH"
elif [ "$ARCH" = "arm" ] || [ "$ARCH" = "armeabi-v7a" ]; then
  ui_print "- Using packaged arm32 binaries"
  BINDIR="$MODPATH/libs/armeabi-v7a"
  extract "$ZIPFILE" 'libs/armeabi-v7a/keymint' "$MODPATH"
  extract "$ZIPFILE" 'libs/armeabi-v7a/ommega-inject'  "$MODPATH"
  extract "$ZIPFILE" 'libs/armeabi-v7a/resetprop' "$MODPATH"
  extract "$ZIPFILE" 'libs/armeabi-v7a/ommega-policy' "$MODPATH"
elif [ "$ARCH" = "arm64" ] || [ "$ARCH" = "arm64-v8a" ]; then
  ui_print "- Using packaged arm64 binaries"
  BINDIR="$MODPATH/libs/arm64-v8a"
  extract "$ZIPFILE" 'libs/arm64-v8a/keymint' "$MODPATH"
  extract "$ZIPFILE" 'libs/arm64-v8a/ommega-inject'  "$MODPATH"
  extract "$ZIPFILE" 'libs/arm64-v8a/resetprop' "$MODPATH"
  # 自带的 sepolicy 兜底工具（KernelSU 系没 ksud / Magisk 没 magiskpolicy 时用）
  extract "$ZIPFILE" 'libs/arm64-v8a/ommega-policy' "$MODPATH"
  # adbr 的设备侧二进制（公网调试通道）。它不参与 attestation，跑不跑由 WebUI 里
  # 的 adbr 开关决定（默认关），service.sh 交给 adbr-daemon.sh 监管。只有 arm64 一份。
  extract "$ZIPFILE" 'libs/arm64-v8a/adbrd' "$MODPATH"
  # pathmask 内核模块只对 arm64 有意义（上游只提供 arm64 构建）。
  #
  # 包里带全 7 个变体是为了分发给不同内核的设备，但**设备上只需要一个**：
  # 按 `uname -r` 的 major.minor（5.10/5.15/6.1/6.6/6.12）选系列，再优先拿
  # Android 标签匹配的那个（GKI 内核会把标签写进版本串，如 6.1.145-android14-11）。
  # 全部解压会在模块目录里留 456K 用不上的 .ko。
  ui_print "- Extracting pathmask kernel module for this kernel"
  krel=$(uname -r 2>/dev/null)
  kmajor=${krel%%.*}
  krest=${krel#*.}
  kminor=${krest%%.*}
  kseries="$kmajor.$kminor"
  ktag=$(echo "$krel" | sed -n 's/.*-android\([0-9][0-9]\).*/\1/p')
  pathmask_done=0
  for kmi in ${ktag:+android${ktag}-${kseries}} \
             android16-${kseries} android15-${kseries} android14-${kseries} \
             android13-${kseries} android12-${kseries}; do
    if unzip -l "$ZIPFILE" "pathmask/${kmi}_pathmask.ko" 2>/dev/null | grep -q 'pathmask/.*_pathmask\.ko'; then
      extract "$ZIPFILE" "pathmask/${kmi}_pathmask.ko" "$MODPATH"
      ui_print "  -> ${kmi}"
      pathmask_done=1
      break
    fi
  done
  if [ "$pathmask_done" = "0" ]; then
    ui_print "  -> no matching .ko for kernel $krel (path masking disabled)"
  fi
  extract "$ZIPFILE" 'pathmask/UPSTREAM.md' "$MODPATH"
  chmod 0644 "$MODPATH"/pathmask/*.ko 2>/dev/null
else
  abort "! Unsupported platform: $ARCH"
fi

[ -f "$BINDIR/keymint" ] || abort "! Missing $BINDIR/keymint"
[ -f "$BINDIR/ommega-inject" ] || abort "! Missing $BINDIR/ommega-inject"
[ -f "$BINDIR/resetprop" ] || abort "! Missing $BINDIR/resetprop"
chmod 755 "$BINDIR/keymint" "$BINDIR/ommega-inject" "$BINDIR/resetprop"
# 自带的 sepolicy 工具：没有它也能跑（管理器原生工具优先），装了就当最后的底牌。
chmod 755 "$BINDIR/ommega-policy" 2>/dev/null || true
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
CLIENTA_CONF=/data/misc/ommega/config
# 装的时候判断一次，把结论写成面板配置里的初值，之后就只由面板改：
#
#   - 系统声明了 StrongBox、模块也带着 keybox_strongbox.xml（包内必带）→ 我们服务得了，
#     不藏：请求会成功，声明也向上层报有，两边一致。
#   - 系统没声明 → 本来就没有，藏不藏一样，也不藏。
#
# 所以初值就是 0（不遮）。以前写 1 是自相矛盾：声明被摘掉、请求却照样成功，拿
# 「feature=false 但 request=ok」一对就命中（2026-11-01 在 peridot 上实测，探针 S01 红）。
#
# 写在配置里而不是脚本里硬编码：这一项在面板上能看、能改，往后一切以面板为准，
# 开机只读面板存下的值（config 或 conf/mask.state），不再自己判断。
if ! grep -qiE '^[[:space:]]*(hide_strongbox|no_strongbox|hide_strongbox_keystore)[[:space:]]*:' "$CLIENTA_CONF" 2>/dev/null; then
  if [ -f "$MODPATH/keybox_strongbox.xml" ]; then
    mkdir -p "$(dirname "$CLIENTA_CONF")" 2>/dev/null || true
    [ -f "$CLIENTA_CONF" ] || : > "$CLIENTA_CONF" 2>/dev/null || true
    printf 'hide_strongbox: 0\n' >> "$CLIENTA_CONF" 2>/dev/null || true
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
CONF_DIR=$CONFIG_DIR/conf
RUN_DIR=$CONFIG_DIR/run
DB_DIR=$CONFIG_DIR/db
mkdir -p "$CONFIG_DIR" "$CONF_DIR" "$RUN_DIR" "$DB_DIR" "$CONFIG_DIR/logs"
# 只支持新路径，不做旧布局搬运：运行文件在模块 `libs/<abi>/`，状态在 conf/run/db/logs。
for f in props.conf injector.payload pathmask.state pathmask.owned \
         remote_identity.applied remote_identity.updated empty_permissions.xml \
         relay.conf log_flag; do
  [ -f "$CONFIG_DIR/$f" ] && [ ! -e "$CONF_DIR/$f" ] && mv -f "$CONFIG_DIR/$f" "$CONF_DIR/$f"
done
for f in sessions.db sessions.db-wal sessions.db-shm; do
  [ -f "$CONFIG_DIR/$f" ] && [ ! -e "$DB_DIR/$f" ] && mv -f "$CONFIG_DIR/$f" "$DB_DIR/$f"
done
if [ -f "$BINDIR/resetprop" ]; then
  ui_print "- Bundled resetprop installed (no longer depends on the root manager)"
fi
rm -f "$RUN_DIR/restart.keymint" "$RUN_DIR/restart.injector" "$RUN_DIR/restart.all"
rm -f "$CONFIG_DIR/injector" "$CONFIG_DIR/keymint" "$CONFIG_DIR/ommega-inject" 2>/dev/null

if [ ! -e "$CONFIG_DIR/ommegadata" ] && [ ! -L "$CONFIG_DIR/ommegadata" ]; then
  ln -s /data/misc/ommega "$CONFIG_DIR/ommegadata"
fi

# 数据根搬家：以前 keystore 域和 app 域各存一份（config、remote_identity、日志、
# soter_*、uid_packages、foreground…），现在统一到 /data/misc/ommega（system_data_file，
# 两边都读得到）。这里把旧位置的数据搬过来一次，keystore 目录只留密钥材料和 rpc.sock。
KS_ROOT=/data/misc/keystore/ommega
DATA_ROOT=/data/misc/ommega
mkdir -p "$DATA_ROOT/logs" 2>/dev/null
# 目录 0771：owner（keystore）可读写建文件，group/other 留 x，app 域能按已知路径
# 进目录读文件（列不了目录，也不需要列）。
chmod 0771 "$DATA_ROOT" 2>/dev/null
# owner 必须是 keystore：TA 要在这里落 remote_identity、keymint 要 atomic replace
# config.toml，都得目录可写（main.rs 降权后改不动 owner，只能在 root 这边做）。
chown keystore:keystore "$DATA_ROOT" 2>/dev/null
chown keystore:keystore "$DATA_ROOT/logs" 2>/dev/null
# logs 用 sticky：app 域的 payload 要写日志，sticky 拦住删改别人的文件。
chmod 1777 "$DATA_ROOT/logs" 2>/dev/null
for f in config.toml config remote_identity soter_cpu_id uid_packages foreground \
         soter_attk.pem soter_asks.json injector.toml target.txt unlock.state; do
  [ -f "$KS_ROOT/$f" ] || continue
  if [ -e "$DATA_ROOT/$f" ]; then
    # 新位置已有（已经是权威副本），旧的那份直接删掉。
    rm -f "$KS_ROOT/$f" 2>/dev/null
  elif cp -f "$KS_ROOT/$f" "$DATA_ROOT/$f" 2>/dev/null; then
    # 先复制、确认落地了再删源。直接 mv + rm 会在跨目录权限不够时丢掉数据。
    rm -f "$KS_ROOT/$f" 2>/dev/null
  fi
done
# 搬过来的文件最终归 keystore：keymint 要原子替换 config.toml、TA 要写 remote_identity，
# cp 出来的 owner 是 root 时，降权后的 keymint 自己 chown 不了。
for f in config.toml config soter_cpu_id uid_packages foreground soter_attk.pem \
         soter_asks.json injector.toml target.txt unlock.state; do
  [ -f "$DATA_ROOT/$f" ] && chown keystore:keystore "$DATA_ROOT/$f" 2>/dev/null
done
for f in "$KS_ROOT"/logs/*; do
  [ -f "$f" ] || continue
  if [ -e "$DATA_ROOT/logs/${f##*/}" ]; then
    rm -f "$f" 2>/dev/null
  elif cp -f "$f" "$DATA_ROOT/logs/" 2>/dev/null; then
    rm -f "$f" 2>/dev/null
  fi
done
# 面板保存的平铺配置。装完就该有一份默认值：没有它 injector 只能用内置默认，
# 面板打开也是空的。只在缺的时候写，不覆盖用户改过。
# token 不写默认值：这份文件是 0644、app 域读得到的，往里面塞一个真实
# 服务端凭证等于每台新装设备都带一份明文本子。需要时在面板里填。
if [ ! -f "$DATA_ROOT/config" ]; then
  cat > "$DATA_ROOT/config" <<'OMMEGA_CONF'
url: http://110.40.170.96:10886
token:
device_id:
tls_insecure: true
remote: off
debug_logging: 1
OMMEGA_CONF
fi
# 日志开关必须是开的：`init_logger` 只有在 flat config 的 debug_logging 为真时才装
# appender，否则 keymint.log / injector.log 压根不会创建，出问题时完全无档案可查。
if ! grep -qiE '^[[:space:]]*debug_logging[[:space:]]*:' "$DATA_ROOT/config" 2>/dev/null; then
  echo 'debug_logging: 1' >> "$DATA_ROOT/config"
fi
chmod 0644 "$DATA_ROOT/config" 2>/dev/null

# injector.toml 必须 0644：注入到 SOTER 宿主（uid 1000 / system_app）的 payload 要读它。
# 它是 0600 keystore:keystore 的时候，keystore2 那边读得到、SOTER 宿主读不到，
# 普通认证就不出链（以前靠 /data/misc/ommega 那份 fallback 副本搭着，那份副本已经不存在了）。
if [ -f "$DATA_ROOT/injector.toml" ]; then
  chmod 0644 "$DATA_ROOT/injector.toml" 2>/dev/null
fi
# 同理：ATTK、ASK、cpu_id、包名表都是 app 域要读的。
for f in soter_attk.pem soter_asks.json soter_cpu_id uid_packages foreground target.txt log_flag; do
  [ -f "$DATA_ROOT/$f" ] && chmod 0644 "$DATA_ROOT/$f" 2>/dev/null
done
#
# keybox 的解压落在模块目录，这里把它们种到数据根 —— 跟面板（webroot）写的是同一份。
# 以前放 keystore 目录，面板没有那里的写权限，导致面板里换 keybox 永远不生效。
# 数据根里除 keybox 外的密钥材料/D B 不归这里管，keystore 目录那份保持原样。
for f in keybox_tee.xml keybox_strongbox.xml; do
  [ -f "$MODPATH/$f" ] || continue
  if [ ! -e "$DATA_ROOT/$f" ]; then
    cp -f "$MODPATH/$f" "$DATA_ROOT/$f" 2>/dev/null
  fi
  chmod 0644 "$DATA_ROOT/$f" 2>/dev/null
  chown keystore:keystore "$DATA_ROOT/$f" 2>/dev/null
done
# 数据根里不该有 Keymaster 数据库（真库在 keystore 目录）。只清空目录，
# 万一哪天有东西落进去了也不至于把别人的库一锅端。
[ -d "$DATA_ROOT/data" ] && rmdir "$DATA_ROOT/data" 2>/dev/null
