#!/system/bin/sh
# 软件 SOTER TA 的开关与守护。
#
# 原厂 `vendor.qti.hardware.soter.ISoter/default` 只是 TEE 里那个 applet 的薄代理，
# applet 起不来时整族调用一律 -20（一加 PKG110 / 安卓15 实测），微信、以及产线工具
# （工程模式那页的 SOTER key）一起哑。接管的意思是：把 init 的原厂 HAL 停掉，由
# `ommega-inject --soterta-serve` 顶上同一个服务名，用我们自己的 ASK 应答。
#
#   soterta.sh             converge 一次（service.sh 每轮调）
#   soterta.sh status      打一行状态
#
# 开关在 /data/misc/keystore/ommega/config 的 `soter_inject`（1/0），WebUI 写。
# 关掉就是「原厂 HAL 回来」：杀我们的守护、ctl.start vendor.soter。
#
# 为什么不用注入：soterserver 在这个机型上是 platform_app 域 + 它的 libbinder 带共享
# 映射，lsplt 一个 GOT 都认不下来（commit 全失败）。接管服务名跟注入无关，客户端
# 一行都不用改。

MODDIR=${0%/*}
STATE_DIR=/data/adb/ommega
BIN_DIR=$STATE_DIR/bin
CONF_DIR=$STATE_DIR/conf
RUN_DIR=$STATE_DIR/run
DB_DIR=$STATE_DIR/db
[ -f "$MODDIR/layout.sh" ] && . "$MODDIR/layout.sh" 2>/dev/null
CONF=${OMMEGA_CONF_PATH:-/data/misc/keystore/ommega/config}
PIDFILE=$RUN_DIR/soterta.pid
KICKED_FILE=$RUN_DIR/soterta.host.kicked
# 最后一次踢宿主时对应的 TA 实例（pid）。换实例就要重踢，见 kick_host。
TAKEOVER_PID=$RUN_DIR/soterta.takeover.pid
LOG=$STATE_DIR/logs/soterta.log
# 解析结果缓存 + 静默开关。service.sh 的 keep-alive 和 daemon-injector 的
# `soterta.sh hidl` 都是 5 秒一轮、每轮新起一个进程，resolve_hal 无条件 log 会把
# 这个文件刷满「resolved hal=...」（实测每 2~5 秒一条），真正有用的事件全被埋掉。
# 所以：结果没变就不打；hidl/status 这种纯查询连缓存都不碰（QUIET=1）。
RESOLVED_CACHE=$STATE_DIR/conf/soter_hal.cache
QUIET=0
# 单实例：service.sh 的 keep-alive 和 daemon-injector 都会调这个脚本，并发跑两次就会
# 同时起两个 `--soterta-serve`（实测 6212/6213 并存一个多小时）。会话号存在进程内存里，
# initSign 落在 A 进程、finishSign 落到 B 进程就回 -1000 —— 检测器的 T12 每轮必挂，
# App 那边表现为要反复验指纹。抢不到锁的直接退出，让拿到锁的那一轮去 converge。
LOCKFILE=$RUN_DIR/soterta.lock
exec 9>"$LOCKFILE" 2>/dev/null || true
if command -v flock >/dev/null 2>&1; then
  flock -n 9 || exit 0
fi
# 服务名和 init 服务名都不写死：各厂商的 SOTER HAL 叫什么的都有（高通
# `vendor.qti.hardware.soter`、小米 `vendor.xiaomi.hardware.soterservice`、联发科
# `vendor.trustonic.soter`……），写死一个就得每台机器改一次。运行时解析，见 resolve_hal。
SERVICE=
HAL=
BIN=

log() {
  mkdir -p "$STATE_DIR/logs" 2>/dev/null
  printf '%s %s\n' "$(date -u '+%Y-%m-%d %H:%M:%S')" "$*" >> "$LOG" 2>/dev/null
}

conf_get() {
  [ -f "$CONF" ] || return 0
  sed -n "s/^[[:space:]]*$1[[:space:]]*:[[:space:]]*\(.*\)$/\1/p" "$CONF" 2>/dev/null | head -n1
}

enabled() {
  case "$(conf_get soter_inject | tr 'A-Z' 'a-z' | tr -d ' \r')" in
    1|true|yes|on) return 0 ;;
  esac
  return 1
}

device_abi() {
  abi=$(getprop ro.product.cpu.abi 2>/dev/null)
  case "$abi" in
    arm64*|aarch64*) echo arm64-v8a ;;
    armeabi*|armv7*) echo armeabi-v7a ;;
    x86_64*) echo x86_64 ;;
    i?86|x86) echo x86 ;;
    *) echo "" ;;
  esac
}

find_bin() {
  [ -n "$BIN" ] && return 0
  for candidate in "$BIN_DIR/ommega-inject" "$MODDIR/ommega-inject"; do
    if [ -x "$candidate" ]; then BIN=$candidate; return 0; fi
  done
  abi=$(device_abi)
  if [ -n "$abi" ] && [ -x "$MODDIR/libs/$abi/ommega-inject" ]; then
    BIN=$MODDIR/libs/$abi/ommega-inject
    return 0
  fi
  return 1
}

# daemon-injector 每轮注入前会 `pkill -9 -f "$TARGET_INJECTOR"` 清残留，而它的
# TARGET_INJECTOR 跟我们的宿主同名。宿主直接用那个路径就会被连带杀掉（实测每 20 秒
# 一轮），服务名反复重建、宿主握不住，App 一调就是系统错误。
# 拷一份到独立文件名，离开那条 pkill 的匹配。
stage_bin() {
  [ -n "$BIN" ] || return 1
  dst="$BIN_DIR/soterta-ta"
  if [ ! -x "$dst" ] || ! cmp -s "$BIN" "$dst" 2>/dev/null; then
    cp -f "$BIN" "$dst.tmp" 2>/dev/null && chmod 755 "$dst.tmp" && mv -f "$dst.tmp" "$dst"
  fi
  [ -x "$dst" ] && BIN=$dst
  return 0
}

hal_state() {
  resolve_hal
  value=$(getprop "init.svc.$HAL" 2>/dev/null)
  [ -n "$value" ] && echo "$value" || echo unknown
}

# 从 VINTF 清单里取 SOTER 的完整 AIDL 服务名：同一个 `<hal>` 块里的 `<name>` 加
# `<fqname>`。fqname 里已经带接口名和实例（`ITrustonicSoter/default`），拼起来就是
# servicemanager 那个名字。
#
# 以前是拿 `<name>` 后面接一个写死的 `.ISoter/default`，高通机器上碰巧对；联发科 /
# Trustonic 的接口叫 `ITrustonicSoter`（NX809J / 安卓 16 实测），拼出来的是个没人注册
# 的名字 —— 结果每轮「停原厂 → 起我们的 → 查错名 → 判失败 → 拉回原厂」，SOTER 一直
# 时有时无。接口名只能从 fqname 读，不能猜。
vintf_soter_service() {
  for f in /vendor/etc/vintf/manifest*.xml /odm/etc/vintf/manifest*.xml \
           /vendor/etc/vintf/manifest/*.xml /odm/etc/vintf/manifest/*.xml; do
    [ -f "$f" ] || continue
    grep -qi 'soter' "$f" 2>/dev/null || continue
    svc=$(awk '
      /<hal/ { blk = ""; name = ""; fq = "" }
      { blk = blk $0 "\n" }
      name == "" && /<name>/ {
        line = $0
        sub(/.*<name>[[:space:]]*/, "", line)
        sub(/[[:space:]]*<\/name>.*/, "", line)
        name = line
      }
      fq == "" && /<fqname>/ {
        line = $0
        sub(/.*<fqname>[[:space:]]*/, "", line)
        sub(/[[:space:]]*<\/fqname>.*/, "", line)
        # HIDL 的 fqname 带版本前缀（`@1.0::ISoter/default`），直接拼上去就是个非法
        # 服务名（`vendor.qti.hardware.soter.@1.0::ISoter/default`，注册直接拒），要把
        # `@版本::` 那一段去掉 —— 我们要的是 AIDL 名 `包名.ISoter/default`。
        if (line ~ /::/) {
          sub(/^.*::/, "", line)
        }
        fq = line
      }
      /<\/hal>/ {
        if (blk ~ /soter/ && name != "" && fq != "") { print name "." fq; exit }
      }
    ' "$f" 2>/dev/null | head -n1)
    if [ -n "$svc" ]; then echo "$svc"; return 0; fi
  done
  return 1
}

# 解析这台机器的 SOTER 服务名，结果缓存在 SERVICE / HAL 里。
#
# SERVICE（AIDL 服务名）：VINTF 的 `<name>` + `<fqname>`，见 vintf_soter_service。
#   例：`vendor.qti.hardware.soter.ISoter/default`、
#       `vendor.trustonic.hardware.soter.ITrustonicSoter/default`
# HAL（init 服务名）：从 `init.svc.*` 里找唯一带 soter 的那个。
#   例：`init.svc.vendor.soter` → `vendor.soter`（注意它跟 HAL 名不是一个东西：
#   VINTF 写的是包名，init 服务是厂商自己起的名，两者无对应关系，必须分开取）
#
# 两处都解析不出来时才退回高通的旧值 —— 那是目前已知最常见的布局。
resolve_hal() {
  [ -n "$SERVICE" ] && [ -n "$HAL" ] && return 0
  if [ -z "$SERVICE" ]; then
    SERVICE=$(vintf_soter_service) || SERVICE=""
    [ -n "$SERVICE" ] || SERVICE=vendor.qti.hardware.soter.ISoter/default
  fi
  if [ -z "$HAL" ]; then
    cands=$(getprop 2>/dev/null | sed -n 's/^\[init\.svc\.\([^]]*soter[^]]*\)\].*/\1/p')
    # 只有一个候选才直接用；有多个（比如原厂和服务名并存）就取最短那个，
    # 它通常就是原厂 HAL（`vendor.soter` 比 `vendor.qti.hardware.soter-service` 短）。
    if [ -n "$cands" ]; then
      HAL=$(printf '%s\n' "$cands" | awk '{ if (min == "" || length($0) < length(min)) min = $0 } END { print min }')
    fi
    [ -n "$HAL" ] || HAL=vendor.soter
  fi
  resolved="$HAL $SERVICE"
  if [ "$QUIET" != "1" ] && [ "$(cat "$RESOLVED_CACHE" 2>/dev/null)" != "$resolved" ]; then
    mkdir -p "${RESOLVED_CACHE%/*}" 2>/dev/null
    printf '%s\n' "$resolved" > "$RESOLVED_CACHE" 2>/dev/null
    log "resolved hal=$HAL service=$SERVICE"
  fi
  return 0
}

# 这台机器的 SOTER HAL 是 HIDL 还是 AIDL。
#
# 老平台（PGP110 / Android 15 实测）VINTF 里只声明了 HIDL 的
# `vendor.qti.hardware.soter@1.0::ISoter`，客户端走 hwservicemanager；我们顶替的
# `vendor.qti.hardware.soter.ISoter/default` 是 AIDL 那个名字，两边不是一套东西。
# 这种机器上原厂 HAL 必须留着（老客户端只认 HIDL），我们只额外注册 AIDL 名。
soter_hal_is_hidl() {
  # 这里要的是 **包名**（`vendor.trustonic.hardware.soter`），不是完整服务名：
  # manifest 里 `@1.0::ISoter` 那种写法根本不会出现 `.ITrustonicSoter/default`。
  svc=$(vintf_soter_service) || svc=""
  name=${svc%%/*}
  name=${name%.*}
  [ -n "$name" ] || name=vendor.qti.hardware.soter
  for f in /vendor/etc/vintf/manifest*.xml /odm/etc/vintf/manifest*.xml \
           /vendor/etc/vintf/manifest/*.xml /odm/etc/vintf/manifest/*.xml; do
    [ -f "$f" ] || continue
    grep -q "$name" "$f" 2>/dev/null || continue
    # soter 那段是 hidl 才算；同文件里别的 HAL 用什么格式与我们无关。
    if awk -v want="$name" '
         /<hal/ { blk = "" }
         { blk = blk $0 "\n" }
         index(blk, want) { seen = 1 }
         /<\/hal>/ { if (seen) { print blk; exit } }
       ' "$f" 2>/dev/null | grep -q 'format="hidl"'; then
      return 0
    fi
  done
  return 1
}

service_present() {
  resolve_hal
  # servicemanager 偶尔会忙一下（刚开机、服务密集重注册那时），一次不中不要急着判死：
  # 判死会走 take_over → 重启 TA，内存里的 ASK / AuthKey / 签名会话全丢，App 那边
  # 就是一串 -5 / -6 / -204。重试三次再算数。
  sp_i=0
  while [ "$sp_i" -lt 3 ]; do
    if service check "$SERVICE" 2>/dev/null | grep -q ': found$'; then
      return 0
    fi
    sp_i=$((sp_i + 1))
    [ "$sp_i" -lt 3 ] && sleep 0.4
  done
  return 1
}

# 这台机器走 HIDL 还是 AIDL（
# 结果在本次运行里缓存一下：一次 converge 里要问好几遍，每遍都扫 VINTF 太亏）。
# 一次 soterta.sh 调用就是一个进程，缓存只在这一次里有效，够用。
HIDL_PLATFORM=
hidl_platform() {
  if [ -z "$HIDL_PLATFORM" ]; then
    if soter_hal_is_hidl; then HIDL_PLATFORM=1; else HIDL_PLATFORM=0; fi
  fi
  [ "$HIDL_PLATFORM" = "1" ]
}

daemon_pid() {
  [ -f "$PIDFILE" ] || return 1
  pid=$(cat "$PIDFILE" 2>/dev/null)
  case "$pid" in
    ''|*[!0-9]*) return 1 ;;
  esac
  kill -0 "$pid" 2>/dev/null || return 1
  tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | grep -q 'soterta-serve' || return 1
  echo "$pid"
}

stop_daemon() {
  pid=$(daemon_pid)
  if [ -n "$pid" ]; then
    kill -TERM "$pid" 2>/dev/null
    i=0
    while [ "$i" -lt 10 ] && kill -0 "$pid" 2>/dev/null; do
      sleep 0.3
      i=$((i + 1))
    done
    kill -0 "$pid" 2>/dev/null && kill -KILL "$pid" 2>/dev/null
  fi
  rm -f "$PIDFILE" 2>/dev/null
}

# 抢服务名：先把原厂 HAL 停了（不停的话 servicemanager 那边名字还是它的），再起
# 我们的守护。启动失败就退回去把原厂 HAL 拉起来，不能把整台机的 SOTER 留成死的。
take_over() {
  # 先把服务名 / init 服务名解析出来：下面的 start_daemon 要把服务名传给我们自己的 TA，
  # 而下面那个 `$(hal_state)` 是子 shell，里面的 resolve_hal 赋的值传不回来 ——
  # 不先在这里解析一次，TA 会拿到空服务名、默认去注册高通那个名字（NX809J 实测）。
  resolve_hal
  find_bin || { log "injector binary not found"; return 1; }
  stage_bin
  # 服务名只有一个 owner：原厂 HAL 还在跑的时候我们注册不上去（servicemanager 直接拒），
  # 所以**先停原厂、再起守护**。顺序反过来的话每一轮都是「起守护→注册失败→停原厂→
  # 再查服务名→没有→判 takeover failed→拉回原厂」（2026-10-20 PKX110 上实测空转 1507 次）。
  #
  # HIDL 平台的例外：老客户端只认 `@1.0::ISoter`，原厂 HAL 一停它们整条就不通，所以
  # 这种机器上**不停原厂**，我们只额外占住 AIDL 那个名字（工模查的就是它）。
  stop_stock=1
  if hidl_platform; then
    log "SOTER HAL is HIDL; keeping stock HAL and registering the AIDL name alongside"
    stop_stock=0
  fi
  if [ "$stop_stock" -eq 1 ] && [ "$(hal_state)" = "running" ]; then
    log "stopping stock SOTER HAL"
    setprop ctl.stop "$HAL" 2>/dev/null
    sleep 1
  fi
  if [ -z "$(daemon_pid)" ]; then
    start_daemon
  elif ! service_present; then
    # 守护还活着但手上没有服务名：它是在原厂占着名字的时候起来的，重起一个再试。
    log "software SOTER TA is up but holds no service name; restarting it"
    start_daemon restart
  fi
  if [ -z "$(daemon_pid)" ] || ! service_present; then
    log "takeover failed, restoring stock HAL"
    stop_daemon
    # 没停过的东西不用拉；HIDL 设备上拉一下反而会把正在服务的原厂 HAL 重启掉。
    [ "$stop_stock" -eq 1 ] && setprop ctl.start "$HAL" 2>/dev/null
    return 1
  fi
  # 宿主（soterserver）把 HAL 代理缓存在 static 字段里，我们一换服务实例那份代理就死了，
  # 但它不会自己重查 —— App 一调就 DeadObjectException（微信直接「系统错误」，而日志里
  # 一笔 HAL 调用都看不到）。详见 kick_host。
  #
  # HIDL 平台不踢：我们没顶掉 HIDL 那个服务名，宿主手里的代理还是原厂的、没失效；
  # 反过来踢了还添乱 —— 新实例起来时载荷还没注上（daemon-injector 下一轮才注），
  # 那几秒里客户端直接打原厂那个死掉的 TA，检测器一跑就是一片 -20。
  kick_host
  return 0
}

# 起守护并等它把服务名注册上。`restart` 表示先收掉旧的那个。
start_daemon() {
  if [ "$1" = "restart" ]; then
    stop_daemon
  fi
  # 只留一个实例：两份就是两套内存态会话表，init 落在其中一个、finish 落到另一个上
  # 就是 -204（NX721J 实测过两个实例同时在跑）。
  for p in $(pidof soterta-ta 2>/dev/null); do
    kill -9 "$p" 2>/dev/null
  done
  log "starting software SOTER TA: $BIN (service=$SERVICE)"
  # 服务名和描述符只能运行时定（各家接口名不一样），由脚本从 VINTF 读出来传进去。
  OMMEGA_SOTER_SERVICE="$SERVICE" "$BIN" --soterta-serve >>"$LOG" 2>&1 &
  pid=$!
  echo "$pid" > "$PIDFILE.tmp" 2>/dev/null
  mv -f "$PIDFILE.tmp" "$PIDFILE" 2>/dev/null
  sleep 1
}

# 宿主手里缓存的是旧服务实例的代理，**每换一次 TA 实例就得踢一次**。
#
# 所以记的是「踢过哪个 TA 实例」（$TAKEOVER_PID 里存那次的 pid），而不是「踢过一次没有」：
# 旧的那套 `soterta.host.kicked` 只踢一次，之后换 TA 就全瞎了 —— 2026-10-20 实测换完
# 新 TA 所有客户端都报系统错误，得手动删标记再踢一次才恢复。
#
# 幂等：同一个 TA 实例只踢一次。take_over 成功时调一次，hold 每轮也调一次。
kick_host() {
  # HIDL 平台不踢（原因见 take_over 里那段）。这两个字得放在最前面：kick 一次就是一次
  # 载荷丢失 + 客户端打空窗，宁可少踢。
  hidl_platform && return 0
  host_pid=$(pidof com.tencent.soter.soterserver 2>/dev/null | awk '{print $1}')
  ta_pid=$(cat "$PIDFILE" 2>/dev/null)
  kicked_ta=$(cat "$TAKEOVER_PID" 2>/dev/null)
  if [ -n "$host_pid" ] && [ -n "$ta_pid" ] && [ "$kicked_ta" != "$ta_pid" ]; then
    log "restarting soter host pid=$host_pid so it rebinds our service (ta=$ta_pid)"
    kill -9 "$host_pid" 2>/dev/null
    echo "$ta_pid" > "$TAKEOVER_PID" 2>/dev/null
  fi
}

# 原厂 HAL 被谁拉回来了（init 重启、别的模块 ctl.start）就再抢一次：服务名被抢走时
# 检测器会看到 -20，比不接管还难查。
hold() {
  pid=$(daemon_pid)
  if [ -z "$pid" ]; then
    take_over && return 0
  fi
  # HIDL 平台上原厂 HAL 必须一直留着（take_over 里 stop_stock=0），hal_state 恒为
  # running，拿它当「被抢回去」的判据等于每轮都空跑一次 take_over：MEIZU 20 Pro
  # （391QYGDJ2244E）实测 53 分钟写了 236 次，把日志冲得没法看。这种机器只看
  # 我们的 AIDL 名字还在不在。
  if soter_hal_is_hidl; then
    if ! service_present; then
      log "our AIDL name vanished; re-taking over"
      take_over && return 0
    fi
  elif [ "$(hal_state)" = "running" ] || ! service_present; then
    log "stock HAL came back or our service vanished; re-taking over"
    take_over && return 0
  fi
  # 服务名和守护都正常，但 TA 实例可能已经换过了（被重新拉起）：那也得重踢。
  kick_host
}

release() {
  # 同上：$HAL 得先解析出来，否则 `setprop ctl.start ""` 静默失败，
  # 关开关之后原厂 HAL 会把在停着的状态里放着（NX809J 实测）。
  resolve_hal
  stop_daemon
  if [ "$(hal_state)" != "running" ]; then
    log "starting stock SOTER HAL"
    setprop ctl.start "$HAL" 2>/dev/null
  fi
}

case "$1" in
  hidl)
    # 给 daemon-injector 问的：这台机器的 SOTER 是不是 HIDL 平台。
    # 是就打印 1、不是打印 0（它据此决定注不注 SOTER 宿主）。
    # 纯查询：不写日志（这条每 5 秒被问一次）。
    QUIET=1
    resolve_hal
    if hidl_platform; then echo 1; else echo 0; fi
    exit 0
    ;;
  status)
    QUIET=1
    if [ -n "$(daemon_pid)" ]; then
      echo "soterta=us hal=$(hal_state) service=$(service_present && echo yes || echo no)"
    else
      echo "soterta=none hal=$(hal_state) service=$(service_present && echo yes || echo no)"
    fi
    exit 0
    ;;
  enable)
    stop_daemon
    take_over
    exit $?
    ;;
  disable)
    release
    exit 0
    ;;
esac

# 默认：一次 converge（service.sh 的 keep-alive 循环会反复调这个）。
if enabled; then
  hold
else
  release
fi
