MODDIR=${0%/*}
TARGET_DIR=/data/misc/keystore/ommega
LOG_DIR=$TARGET_DIR/logs
LOG_FILE=$LOG_DIR/post-fs-data.log
# app 域（SOTER 宿主 uid 1000）进不去 keystore 那个 0770 目录，payload 的日志
# 得有个它写得动的位置：权限开到 system 组。
APP_LOG_DIR=/data/misc/ommega/logs
TARGET_KEYBOX=$TARGET_DIR/keybox_tee.xml
TARGET_KEYBOX_SB=$TARGET_DIR/keybox_strongbox.xml
TARGET_INJECTOR_CONFIG=$TARGET_DIR/injector.toml
TARGET_CONF=$TARGET_DIR/config
TARGET_TARGET_LIST=$TARGET_DIR/target.txt
STATE_DIR=/data/adb/ommega
BIN_DIR=$STATE_DIR/bin
CONF_DIR=$STATE_DIR/conf
RUN_DIR=$STATE_DIR/run
DB_DIR=$STATE_DIR/db
[ -f "$MODDIR/layout.sh" ] && . "$MODDIR/layout.sh" 2>/dev/null
# A-side config directory (webroot UI writes here; `ommegadata` is a symlink to
# $TARGET_DIR, so the UI and the keystore process (uid 1017) share one copy).
CLIENTA_DIR=/data/adb/ommega

# 系统属性伪装用模块**自己带**的 resetprop（实现是 vendor/ 里的 resetprop-rs；
# customize.sh 安装时会把与设备 ABI 匹配的那份拷到状态目录）。以前靠管理器提供：
# Magisk 自带、APatch/KSU 走 busybox/ksud，不是每家都有、行为也不一致，所以不再依赖。
# 定成同名函数，下面那一串调用一字不用改；实在找不到自己的才退回 PATH 里那个。
RESETPROP_BIN=$BIN_DIR/resetprop
if [ ! -x "$RESETPROP_BIN" ]; then
  rp_abi=$(getprop ro.product.cpu.abi 2>/dev/null)
  case "$rp_abi" in
    arm64*) rp_abi=arm64-v8a ;;
    armeabi*|armv7*) rp_abi=armeabi-v7a ;;
    x86_64*) rp_abi=x86_64 ;;
    i?86|x86) rp_abi=x86 ;;
    *) rp_abi= ;;
  esac
  if [ -n "$rp_abi" ] && [ -x "$MODDIR/libs/$rp_abi/resetprop" ]; then
    RESETPROP_BIN="$MODDIR/libs/$rp_abi/resetprop"
  else
    RESETPROP_BIN=resetprop
  fi
  unset rp_abi
fi
resetprop() { "$RESETPROP_BIN" "$@"; }

# persist.* 要带 -p：不带的话只改内存属性区，init 落在 /data/property/ 的那份镜像
# 不会跟着变，两边一对就露（检测项 device.property.persistent_suspicious）。
resetprop -p persist.logd.size ""
resetprop -p persist.logd.size.crash ""
resetprop -p persist.logd.size.system ""
resetprop -p persist.logd.size.main ""
resetprop ro.boot.flash.locked 1
resetprop ro.boot.verifiedbootstate green
resetprop ro.boot.veritymode enforcing
resetprop ro.boot.vbmeta.device_state locked
resetprop ro.secure 1
resetprop ro.adb.secure 1
resetprop ro.debuggable 0
resetprop sys.oem_unlock_allowed ""
resetprop ro.secureboot.devicelock 1

# 开机时就把 B 真机声明的身份对齐到本机（文件由 TA 在远程出链时写入）：
# 链是真机出的，本机属性必须说同一台机器，否则检测器报 device_properties /
# VBMeta 摘要不一致。daemon 运行期也会再同步一次（带 zygote 软重启）。
_OMMEGA_IDENTITY=/data/misc/keystore/ommega/remote_identity
if [ -f "$_OMMEGA_IDENTITY" ]; then
  _id_set() {
    [ -n "$1" ] && [ -n "$2" ] && resetprop "$1" "$2"
  }
  _id_get() { sed -n "s/^$1=//p" "$_OMMEGA_IDENTITY" 2>/dev/null | head -n1; }
  _id_set ro.product.brand "$(_id_get brand)"
  _id_set ro.product.device "$(_id_get device)"
  _id_set ro.product.name "$(_id_get product)"
  _id_set ro.product.manufacturer "$(_id_get manufacturer)"
  _id_set ro.product.model "$(_id_get model)"
  _id_set ro.serialno "$(_id_get serial)"
  _id_set ro.boot.vbmeta.digest "$(_id_get vbmeta_digest)"
fi
mkdir -p "$TARGET_DIR"
chmod 0770 "$TARGET_DIR"
chown 1017:1017 "$TARGET_DIR"
# 「启用调试日志」关着时不要建任何日志目录：以前无条件 mkdir，用户关着日志也会
# 多出两个空空的 logs 目录。真正的写日志在 `log_line` 里还要再判一次。
debug_logging_enabled() {
  [ -f "$TARGET_CONF" ] || return 1
  val=$(sed -n 's/^[[:space:]]*\(debug_logging\|debug\|verbose\)[[:space:]]*:[[:space:]]*\(.*\)$/\2/p' "$TARGET_CONF" 2>/dev/null | head -n1 | tr -d ' \r' | tr 'A-Z' 'a-z')
  case "$val" in
    1|true|yes|on) return 0 ;;
  esac
  return 1
}
if debug_logging_enabled; then
  mkdir -p "$LOG_DIR"
  chmod 0770 "$LOG_DIR"
  chown 1017:1017 "$LOG_DIR"
  mkdir -p "$APP_LOG_DIR"
  chmod 0770 "$APP_LOG_DIR"
  chown 0:1000 "$APP_LOG_DIR"
fi
mkdir -p "$STATE_DIR"
rm -f "$RUN_DIR/keymint-daemon.pid" "$RUN_DIR/injector-daemon.pid"

# 只落文件，不再往 stdout 打（那会进管理器的日志，也是系统日志）。
log_line() {
  debug_logging_enabled || return 0
  mkdir -p "$LOG_DIR" 2>/dev/null
  printf '%s [INFO] %s\n' "$(date -u '+%Y-%m-%d %H:%M:%S')" "$*" >> "$LOG_FILE" 2>/dev/null
  return 0
}
rm -f "$RUN_DIR/restart.keymint" "$RUN_DIR/restart.injector" "$RUN_DIR/restart.all"

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
  for f in config target.txt system_app keybox_tee.xml keybox_strongbox.xml; do
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
# device_id 故意留空：留空 = 「让服务端挑一台 B」。服务端用后台配的「默认设备 id」，
# 没配就按负载挑一台在线的（keymint 有效、已锁定、可信启动）。
# 不再像以前那样占位一个 device-b-2：那个名字是服务端公开密钥库的专用槽位，
# 不是一台真 B，填进去只会把请求钉到一个不该去的地方。
# 想固定落到某一台就手动填，或者在 WebUI 的「伪装参数」里点「从服务端同步并保存」。
device_id:
tls_insecure: true
remote: on
EOF
fi
if [ ! -f "$TARGET_TARGET_LIST" ]; then
  : > "$TARGET_TARGET_LIST"
fi
chmod 0644 "$TARGET_CONF" "$TARGET_TARGET_LIST" 2>/dev/null || true
chown 1017:1017 "$TARGET_CONF" "$TARGET_TARGET_LIST" 2>/dev/null || true

# Keybox: the webroot UI writes `/data/adb/ommega/ommegadata/keybox_tee.xml` which IS
# $TARGET_KEYBOX (via symlink).  Seed from the module keybox if absent.
# TEE 和 StrongBox 两份各自独立：各用各的级别，不再共用一份 keybox。
if [ ! -f "$TARGET_KEYBOX" ] && [ -f "$MODDIR/keybox_tee.xml" ]; then
  cp "$MODDIR/keybox_tee.xml" "$TARGET_KEYBOX"
fi
if [ ! -f "$TARGET_KEYBOX_SB" ] && [ -f "$MODDIR/keybox_strongbox.xml" ]; then
  cp "$MODDIR/keybox_strongbox.xml" "$TARGET_KEYBOX_SB"
fi

if [ ! -f "$TARGET_INJECTOR_CONFIG" ] && [ -f "$MODDIR/injector.toml" ]; then
  cp "$MODDIR/injector.toml" "$TARGET_INJECTOR_CONFIG"
fi

if [ -f "$TARGET_KEYBOX" ]; then
  chmod 0600 "$TARGET_KEYBOX"
  chown 1017:1017 "$TARGET_KEYBOX"
fi
if [ -f "$TARGET_KEYBOX_SB" ]; then
  chmod 0600 "$TARGET_KEYBOX_SB"
  chown 1017:1017 "$TARGET_KEYBOX_SB"
fi

if [ -f "$TARGET_INJECTOR_CONFIG" ]; then
  chmod 0600 "$TARGET_INJECTOR_CONFIG"
  chown 1017:1017 "$TARGET_INJECTOR_CONFIG"
fi

# ---- 开机期声明（config.toml 的 [trust]）----
# 检测类 App 比对的是「链里的补丁 tag ↔ 设备属性」，而属性区是 init 开机时加载的：
# 等 zygote/框架起来之后再写运行时属性，已 fork 出去的进程看不到（实测运行期
# resetprop 改不动 App 的 SPL 视图）。所以显式声明必须在这一阶段写进属性区。
# 运行期那条路（daemon 启动时写）保留，管的是我们自己铸链用的 ctx。
# 只有显式写了值才动；auto 一律保持设备原值。
DECLARED_CONF=$TARGET_DIR/config.toml
# 只在设备本来就有这个属性时才改。
#
# 凭空造一个新属性比不改更糟：检测器一看「这型号怎么会有这个键」就露了，
# 而且 resetprop 造出来的值也不会被所有读取方认。所以凡是「改」都先确认真有；
# 没有就跳过，让链上那份自己去算。
setprop_if_present() {
  [ -n "$(getprop "$1" 2>/dev/null)" ] || return 0
  resetprop "$1" "$2"
}

if [ -f "$DECLARED_CONF" ]; then
  # cfg_val <key>：取 config.toml 里 "key = \"value\"" 的 value（[trust] 下的键）
  cfg_val() {
    sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*\"\([^\"]*\)\".*$/\1/p" "$DECLARED_CONF" 2>/dev/null | head -n1 | tr -d '\r'
  }
  d_patch=$(cfg_val security_patch)
  # 没单写就跟着 security_patch 走，跟 Rust 侧 resolve_patch_levels 的继承顺序一致
  d_os=$(cfg_val os_patchlevel); [ "$d_os" = auto ] && d_os=$d_patch
  d_vendor=$(cfg_val vendor_patchlevel); [ "$d_vendor" = auto ] && d_vendor=$d_patch
  # boot 不继承，也不推导：设备原本没这个属性就不造（凭空造一个反而多一处马脚）。
  # 链上的 boot 补丁级别由 keymint 运行时按 boot 镜像日期算，不靠这个属性。
  d_boot=$(cfg_val boot_patchlevel)
  for pair in "$d_os|ro.build.version.security_patch" "$d_vendor|ro.vendor.build.security_patch" "$d_boot|ro.vendor.boot_security_patch"; do
    value=${pair%%|*}
    prop=${pair##*|}
    case "$value" in ""|auto) continue ;; esac
    setprop_if_present "$prop" "$value"
    log_line "ommega: declared $prop=$value (boot stage)"
  done
  # 引导器锁定状态：不少检测器会看。只有真的存在这个键的机型才改。
  setprop_if_present ro.secureboot.lockstate locked
  d_vbkey=$(cfg_val vb_key)
  case "$d_vbkey" in ""|auto|random) ;; *) setprop_if_present ro.boot.vbmeta.public_key_digest "$d_vbkey"; log_line "ommega: declared vbmeta key (boot stage)" ;; esac
  d_vbhash=$(cfg_val vb_hash)
  case "$d_vbhash" in ""|auto|random) ;; *) setprop_if_present ro.boot.vbmeta.digest "$d_vbhash"; log_line "ommega: declared vbmeta hash (boot stage)" ;; esac
  unset d_patch d_os d_vendor d_boot d_vbkey d_vbhash
fi

# ---- 面板里设的属性覆盖 ----
# 单独存一份（$CONF_DIR/props.conf），**不写进这个脚本**：模块一升级，这个脚本
# 就被新版本整个替掉，写在里面的设置会跟着没（以前就是这么丢的）。
#
# 放在最后应用：它是用户在面板上明确点的，优先级高于上面那套默认值和 config.toml
# 里的开机期声明。一行一项 `键: 值`；值可以带引号，不带空格；**空值 = 不覆盖**
# （那一项就由模块自己的默认值决定）。
PROP_OVERRIDES=$CONF_DIR/props.conf
if [ -r "$PROP_OVERRIDES" ]; then
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in ''|'#'*) continue ;; esac
    p_key=${line%%:*}
    p_val=${line#*:}
    p_key=$(printf '%s' "$p_key" | tr -d ' \t\r')
    p_val=$(printf '%s' "$p_val" | tr -d '\r' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
    # 值两边手写的引号去掉（面板不写引号，但手改文件可能会带）
    case "$p_val" in
      \"*\") p_val=${p_val#\"}; p_val=${p_val%\"} ;;
    esac
    case "$p_key" in
      ro.*|persist.*|sys.*) : ;;
      *) continue ;;
    esac
    [ -n "$p_val" ] || continue
    setprop_if_present "$p_key" "$p_val"
    log_line "ommega: override $p_key=$p_val (boot stage)"
  done < "$PROP_OVERRIDES"
fi

# ---- 能力声明隐藏（flat config 键 hide_strongbox / hide_device_ids）----
# 完全自己挂：不往模块 system/ 里放 XML，也不依赖任何 metamodule。
#
# 本机把这条 feature 的声明改成 unavailable 的方式只有两种，我们都走：
#   1. 厂商那份权限 XML 里删掉 <feature name="..."/> 那一行，复制到暂存目录，单文件 bind 盖回原处；
#   2. （已不用）以前还有一条“模块自带一份 <unavailable-feature> XML、靠管理器/metamodule
#      挂到 /system/etc/permissions”的路。那条依赖外部元模块，而且配置改完要重启两次才生效，
#      已经拆掉：现在模块里根本没有 system 目录，mountify 之类的 auto 模式也不会再纳管它。
#
# 挂载痕迹怎么处理（借鉴 mountify 那段）：
#   - 暂存目录优先放在 /mnt/vendor 下、起个像 OEM 权限目录的名字（vendor_permissions），
#     mountinfo 里只露一个看起来属于厂商的 bind 源；
#   - system_server 读完权限 XML 之后（service.sh 等到 sys.boot_completed），把这批 bind
#     用 umount -l 撤掉，mountinfo 里那条挂载一天都在不了，只留开机头几十秒。
#
# 三条保守规则（/odm 的权限 XML 一旦变成非法 XML，system_server 就起不来，代价太大）：
#   - 该 feature 必须是单独一行的 <feature ... />；
#   - 删完必须正好少一条 feature、且剩下 </permissions>，否则跳过这个文件、只记日志；
#   - 挂完回读一次，feature 还在就立刻 umount。
mask_state_file=$STATE_DIR/conf/mask.state

# mask_enabled <配置键> [其它等价键...]
# 判开关：flat config 里有这个键就以它为准；没有就看调用方给的 OMMEGA_MASK_DEFAULT。
# post-fs-data 阶段 /data/misc/keystore/ommega/config 可能还没就绪，那时退回上次开机
# 缓存的结果（/data/adb 这个阶段一定读得到）。
mask_enabled() {
  me_name=$1
  shift
  me_enabled=false
  me_state=0
  [ -f "$mask_state_file" ] && me_state=$(sed -n "s/^$me_name=//p" "$mask_state_file" 2>/dev/null | head -n 1)
  [ "$me_state" = 1 ] && me_enabled=true
  if [ -f "$TARGET_CONF" ]; then
    # 主键本身也要进匹配列表（me_name 不是 me_pat 的一员，以前这里只拼 $@ 漏过自己）
    me_pat=$(printf '%s|' "$me_name" "$@")
    me_pat=${me_pat%|}
    me_value=$(grep -iE "^[[:space:]]*(${me_pat})[[:space:]]*:" "$TARGET_CONF" 2>/dev/null | head -n 1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r')
    case "$me_value" in
      1|true|yes|on) me_enabled=true ;;
      0|false|no|off) me_enabled=false ;;
      *) [ "${OMMEGA_MASK_DEFAULT:-0}" = 1 ] && me_enabled=true ;;
    esac
    # 读到了就以配置为准，顺手落盘给下次开机用
    mkdir -p "$STATE_DIR/conf" 2>/dev/null
    if [ -f "$mask_state_file" ]; then
      grep -v "^$me_name=" "$mask_state_file" > "$mask_state_file.tmp" 2>/dev/null
    else
      : > "$mask_state_file.tmp"
    fi
    printf '%s=%s\n' "$me_name" "$([ "$me_enabled" = true ] && echo 1 || echo 0)" >> "$mask_state_file.tmp" 2>/dev/null
    mv -f "$mask_state_file.tmp" "$mask_state_file" 2>/dev/null
  fi
  [ "$me_enabled" = true ]
}

OMMEGA_MASK_DEFAULT=0 mask_enabled hide_strongbox hide_strongbox_keystore && mask_sb=1 || mask_sb=0
OMMEGA_MASK_DEFAULT=0 mask_enabled hide_device_ids hide_device_id_attestation && mask_ids=1 || mask_ids=0

# 清掉老实现留在模块 system/ 下的 whiteout / 空声明。不清的话管理器挂载时它们还会把
# 厂商那整份 XML 删掉，连带 app_attest_key 这种同一文件里的其它 feature 一起消失。
if [ -d "$MODDIR/system" ]; then
  for mf_stale in android.hardware.security.strongbox_keystore.xml android.software.device_id_attestation.xml; do
    find "$MODDIR/system" -type f -name "$mf_stale" 2>/dev/null | while IFS= read -r mf_old; do rm -f "$mf_old"; done
    find "$MODDIR/system" -type c -name "$mf_stale" 2>/dev/null | while IFS= read -r mf_old; do rm -f "$mf_old"; done
  done
fi

# 开机诊断（不看 debug 开关）：开关状态先落一行，后面 bind 的结果跟着写同一个文件。
printf '%s mask_sb=%s mask_ids=%s\n' "$(date -u '+%H-%M-%S')" "$mask_sb" "$mask_ids" \
  >> /data/adb/ommega/boot-debug.log 2>/dev/null

# ---- 主力：我们自己把那条 feature 从厂商声明里摘掉 ----
# KernelSU 3.x 天生不做模块文件挂载（要装挂载 metamodule 才有），所以模块 system/ 里那份
# XML 在这类机器上根本不会出现，不能指着管理器帮忙。真正干活的是这里：把厂商那份声明 XML
# 复制一份、只删掉提到该 feature 的那一行，再单文件 bind 盖回原处。
#
# 2026-10-28 在 peridot（KernelSU 3.3.1，没装任何 metamodule）实测：开机能过，
# pm has-feature android.hardware.strongbox_keystore 变 false，同一个文件里的
# android.hardware.keystore.app_attest_key 还在。
#
# 三条保守规则（/odm 的权限 XML 一旦变成非法 XML，system_server 就起不来，代价太大）：
#   - 该 feature 必须是单独一行的 <feature ... />；
#   - 删完必须正好少一条 feature、且剩下 </permissions>，否则跳过这个文件、只记日志；
#   - 挂完回读一次，feature 还在就立刻 umount。
mask_stage=$STATE_DIR/perm-stage
mask_binds_file=$STATE_DIR/conf/mask.binds
mask_n=0
mask_binds=""
mask_log() { printf '%s %s\n' "$(date -u '+%H-%M-%S')" "$*" >> /data/adb/ommega/boot-debug.log 2>/dev/null; }

# 暂存目录别长得像 root 模块：/mnt/vendor 已经是独立挂载点时，在里面挂个小 tmpfs，看起来
# 像 OEM 自己挂的权限目录；不是的话退回状态目录（bind 源路径只在 mountinfo 里露一下）。
# /odm* 例外：那些分区在 post-fs-data 阶段未必已经挂稳，以前在 /mnt/vendor 下挂 tmpfs
# 撞上 vendor 自己的挂载、实测直接卡开机，所以 odm 目标一律在状态目录里暂存。
mask_stage_dir() {
  ms_dir=
  if [ -d /mnt/vendor ] && grep -q ' /mnt/vendor ' /proc/mounts 2>/dev/null; then
    ms_dir=/mnt/vendor/vendor_permissions
    if ! grep -q " $ms_dir " /proc/mounts 2>/dev/null; then
      mkdir -p "$ms_dir" 2>/dev/null
      mount -t tmpfs -o mode=0755,seclabel tmpfs "$ms_dir" 2>/dev/null || ms_dir=
    fi
  fi
  [ -n "$ms_dir" ] || ms_dir=$mask_stage
  printf '%s' "$ms_dir"
}

mask_one_xml() {
  mx_src=$1
  mx_feature=$2
  mask_n=$((mask_n + 1))
  # 暂存文件名不带目标路径：mountinfo 里会原样显示，写全了等于自己交代遮了哪个文件
  case "$mx_src" in
    /odm/*|/odm_dlkm/*) mx_stage_dir=$mask_stage ;;
    *) mx_stage_dir=$(mask_stage_dir) ;;
  esac
  mx_stage=$mx_stage_dir/perm.$mask_n
  mx_before=$(grep -c '<feature' "$mx_src" 2>/dev/null || true); mx_before=${mx_before:-0}
  grep -v "<feature[^>]*name=\"$mx_feature\"" "$mx_src" > "$mx_stage" 2>/dev/null || return 0
  mx_after=$(grep -c '<feature' "$mx_stage" 2>/dev/null || true); mx_after=${mx_after:-0}
  if [ "$mx_before" -ne $((mx_after + 1)) ] || ! grep -q '</permissions>' "$mx_stage" 2>/dev/null; then
    mask_log "mask-skip unusual file: $mx_src"
    rm -f "$mx_stage"
    return 0
  fi
  chmod 0644 "$mx_stage" 2>/dev/null
  case "$mx_src" in
    /vendor/*|/odm/*|/odm_dlkm/*) chcon u:object_r:vendor_file:s0 "$mx_stage" 2>/dev/null ;;
    *) chcon u:object_r:system_file:s0 "$mx_stage" 2>/dev/null ;;
  esac
  if mount --bind "$mx_stage" "$mx_src" 2>/dev/null; then
    if grep -q "$mx_feature" "$mx_src" 2>/dev/null; then
      umount "$mx_src" 2>/dev/null
      mask_log "mask-revert bind had no effect: $mx_src"
      rm -f "$mx_stage"
      return 0
    fi
    mask_binds="$mask_binds $mx_src"
    mask_log "mask-bind $mx_feature -> $mx_src"
  else
    mask_log "mask-fail bind failed: $mx_src"
    rm -f "$mx_stage"
  fi
}

mask_declaration_by_bind() {
  md_feature=$1
  for md_dir in /system/etc/permissions /system_ext/etc/permissions /vendor/etc/permissions \
                /product/etc/permissions /odm/etc/permissions; do
    [ -d "$md_dir" ] || continue
    for md_src in "$md_dir"/*.xml; do
      [ -f "$md_src" ] || continue
      grep -q "<feature[^>]*name=\"$md_feature\"" "$md_src" 2>/dev/null || continue
      mask_one_xml "$md_src" "$md_feature"
    done
  done
}

rm -rf "$mask_stage" 2>/dev/null
mkdir -p "$mask_stage" 2>/dev/null
# 不管有没有 metamodule：总是自己从厂商 XML 摘掉那一行再 bind。以前这里会先看模块那份
# XML 在不在（靠元模块挂），挂上了就跳过 —— 现在模块里根本没有 system/，这条分支拆了。
[ "$mask_sb" = 1 ] && mask_declaration_by_bind android.hardware.strongbox_keystore
[ "$mask_ids" = 1 ] && mask_declaration_by_bind android.software.device_id_attestation
# 记一份自己挂过谁：service.sh 等到 boot_completed 后按这份清单 umount -l 撤掉。
mkdir -p "$STATE_DIR/conf" 2>/dev/null
printf '%s\n' ${mask_binds:-} > "$mask_binds_file" 2>/dev/null
mask_log "mask-tier: self bind ->${mask_binds:- none}"
unset mask_stage mask_binds_file mask_n mask_binds ms_dir mx_src mx_feature mx_stage mx_before mx_after mx_stage_dir
unset md_feature md_dir md_src
unset mask_state_file mask_sb mask_ids me_name me_enabled me_state me_pat me_value mf_stale mf_old

# ── 尽早把两个守护拉起来 ─────────────────────────────────────────────────
# 为什么抢在 post-fs-data（最早那个阶段）而不是 service.sh（late_start）：注入 keystore2
# 越早越好 —— 框架的 `onDeviceUnlocked` 只在解锁那一刻发一次、从不补发；那会儿我们还没
# 进 keystore2 的话，这份解锁材料就永久丢了，影子 keystore 会一直 LOCKED 到下一次解锁。
# service.sh 里还有一份同样的启动（这里失败/被杀就靠它兑底），它会先看这两个 pid 文件，
# 活着就不重复启。
pid_matches_script() {
  p=$1
  s=$2
  [ -r "/proc/$p/cmdline" ] || return 1
  tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | grep -F "$s" >/dev/null 2>&1
}

start_daemon_early() {
  script=$1
  pidfile=$2
  if [ -f "$pidfile" ]; then
    pid=$(cat "$pidfile" 2>/dev/null)
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && pid_matches_script "$pid" "$script"; then
      return 0
    fi
    rm -f "$pidfile"
  fi
  # 离开 post-fs-data 阶段后子进程可能被收走，所以用 setsid 脱开（没有就退回普通后台）。
  if command -v setsid >/dev/null 2>&1; then
    setsid sh "$script" >/dev/null 2>&1 &
  else
    sh "$script" >/dev/null 2>&1 &
  fi
  pid=$!
  echo $pid > "$pidfile"
  sleep 1
  if ! kill -0 "$pid" 2>/dev/null || ! pid_matches_script "$pid" "$script"; then
    rm -f "$pidfile"
    return 1
  fi
  return 0
}

if [ -f "$MODDIR/daemon" ]; then
  if start_daemon_early "$MODDIR/daemon" "$RUN_DIR/keymint-daemon.pid"; then
    log_line "ommega: keymint daemon started early in post-fs-data"
  else
    log_line "ommega: keymint daemon early start failed; service.sh will retry"
  fi
fi
if [ -f "$MODDIR/daemon-injector" ]; then
  if start_daemon_early "$MODDIR/daemon-injector" "$RUN_DIR/injector-daemon.pid"; then
    log_line "ommega: injector daemon started early in post-fs-data"
  else
    log_line "ommega: injector daemon early start failed; service.sh will retry"
  fi
fi
