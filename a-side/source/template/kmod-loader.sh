#!/system/bin/sh
# Ommega A-side: load the bundled PathMask kernel module and decide whether
# /system/priv-app/SoterService should be masked.
#
# Rules:
#   * pick the bundled official .ko by the kernel's major.minor (`uname -r`),
#     ignoring the patch level; when a kernel series ships several official
#     Android variants, try them in order until one insmods;
#   * probe the Soter binder service for at most PROBE_BUDGET_MS (whole run
#     stays within ~3 s, no 60 s waits):
#       reachable     -> the service is healthy -> keep the path visible
#                        (unload a mask a previous run of ours installed);
#       not reachable -> mask TARGET_PATH with scope_mode=global;
#   * a `pathmask` module that we did not load is left alone unless
#     `pathmask_takeover=1`; when we take it over (or already own it) the
#     reload is rmmod + insmod, which is how the parameters are changed;
#   * every failure is recorded in $STATE_FILE and never aborts the boot or
#     loops on retries.
#
# Optional keys, read from the A-side flat config
# (/data/misc/keystore/ommega/config):
#   soter_hide=0            disable this script entirely
#   soter_hide_prefer=skip  when the service cannot be reached, prefer keeping
#                           the path visible instead of masking it
#   soter_package=...       package name used by the process tier
#   soter_service=...       comma-separated binder service names to probe
#   pathmask_target=...     path to mask (default /system/priv-app/SoterService)
#   pathmask_takeover=1     take over an already-loaded foreign instance

MODDIR=${0%/*}
KMOD_DIR="$MODDIR/pathmask"
CONF_PATH=${KMOD_CONF_PATH:-/data/misc/keystore/ommega/config}
STATE_DIR=/data/adb/ommega
STATE_FILE="$STATE_DIR/pathmask.state"
OWNED_FILE="$STATE_DIR/pathmask.owned"

TARGET_PATH=/system/priv-app/SoterService
SOTER_PKG=com.tencent.soter.soterserver
PROBE_BUDGET_MS=2000
TAKEOVER=0
PREFER=hide
# KMOD_DRY_RUN=1 logs the decisions without touching /proc/modules - used for
# on-device verification and debugging (see README).
DRY_RUN=${KMOD_DRY_RUN:-0}

log() { echo "[kmod-loader] $*"; }

now_ms() {
  local s n
  s=$(date +%s 2>/dev/null) || s=0
  n=$(date +%N 2>/dev/null)
  case "$n" in
    ''|*[!0-9]*) echo $((s * 1000)) ;;
    *) echo $((s * 1000 + n / 1000000)) ;;
  esac
}

conf_get() {
  [ -f "$CONF_PATH" ] || return 0
  sed -n "s/^[[:space:]]*$1[[:space:]]*:[[:space:]]*\(.*\)$/\1/p" "$CONF_PATH" 2>/dev/null | head -n1
}

write_state() {
  mkdir -p "$STATE_DIR" 2>/dev/null
  printf 'state=%s\nupdated=%s\ndetail=%s\n' "$1" "$(date +%s 2>/dev/null)" "$2" > "$STATE_FILE" 2>/dev/null
  log "state=$1 detail=$2"
}

kernel_series() {
  local rel major rest minor
  rel=$(uname -r 2>/dev/null) || return 1
  major=${rel%%.*}
  rest=${rel#*.}
  minor=${rest%%.*}
  case "$major.$minor" in
    5.10|5.15|6.1|6.6|6.12|6.18) echo "$major.$minor" ;;
    *) return 1 ;;
  esac
}

# Preferred candidate first: the variant whose Android tag matches `uname -r`
# (GKI kernels embed it, e.g. 6.1.145-android14-11); then the rest of the series.
ko_candidates() {
  local series="$1" rel android_tag preferred f
  rel=$(uname -r 2>/dev/null)
  android_tag=$(echo "$rel" | sed -n 's/.*-android\([0-9][0-9]\).*/\1/p')
  preferred=""
  if [ -n "$android_tag" ] && [ -f "$KMOD_DIR/android${android_tag}-${series}_pathmask.ko" ]; then
    preferred="$KMOD_DIR/android${android_tag}-${series}_pathmask.ko"
    echo "$preferred"
  fi
  for f in "$KMOD_DIR"/*-"${series}"_pathmask.ko; do
    [ -f "$f" ] || continue
    [ "$f" = "$preferred" ] && continue
    echo "$f"
  done
}

pathmask_loaded() { grep -q '^pathmask ' /proc/modules 2>/dev/null; }

unload_pathmask() {
  pathmask_loaded || return 0
  if [ "$DRY_RUN" = "1" ]; then
    log "dry-run: would run 'rmmod pathmask'"
    return 0
  fi
  rmmod pathmask 2>/dev/null || toybox rmmod pathmask 2>/dev/null || return 1
  local i=0
  while pathmask_loaded && [ "$i" -lt 10 ]; do
    sleep 0.1
    i=$((i + 1))
  done
  pathmask_loaded && return 1
  return 0
}

# Binder names belonging to the SoterService package.  Matched against the
# package name on purpose: unrelated vendor HALs (e.g. Qualcomm's
# vendor.qti.hardware.soter) merely contain "soter" and say nothing about
# whether the SoterService app works.
soter_binder_names() {
  local explicit
  explicit=$(conf_get soter_service)
  if [ -n "$explicit" ]; then
    echo "$explicit" | tr ',' ' '
    return 0
  fi
  service list 2>/dev/null | grep -F "$SOTER_PKG" \
    | sed 's/^[0-9]*[[:space:]]*//; s/:.*$//' | tr '\n' ' '
}

# 0 = reachable (healthy), 1 = not reachable within the budget.
soter_service_available() {
  local deadline names name
  deadline=$(( $(now_ms) + PROBE_BUDGET_MS ))
  while :; do
    names=$(soter_binder_names)
    for name in $names; do
      [ -n "$name" ] || continue
      # `service check` exits 0 even for "not found" - the text is the signal.
      case "$(service check "$name" 2>/dev/null)" in
        *": found"*) return 0 ;;
      esac
    done
    # A running (or on-demand started) SoterService process counts as healthy.
    pidof "$SOTER_PKG" >/dev/null 2>&1 && return 0
    [ "$(now_ms)" -ge "$deadline" ] && return 1
    sleep 0.2
  done
}

# 0 = loaded, 1 = failed, 2 = refused (foreign instance, no takeover).
load_pathmask() {
  local ko="$1" targets="$2" resolved err
  if pathmask_loaded; then
    if [ -f "$OWNED_FILE" ] || [ "$TAKEOVER" = "1" ]; then
      unload_pathmask || { write_state "failed-rmmod" "$(basename "$ko")"; return 1; }
    else
      write_state "conflict-already-loaded" \
        "another pathmask instance is loaded; set pathmask_takeover=1 to take over"
      return 2
    fi
  fi
  [ -n "$targets" ] || return 0
  if [ "$DRY_RUN" = "1" ]; then
    log "dry-run: would run 'insmod $(basename "$ko") target_paths=$targets hide_dirents=1 scope_mode=global ...'"
    write_state "dry-run-would-load" "$(basename "$ko") target=$targets"
    return 0
  fi
  if ! err=$(insmod "$ko" \
      target_paths="$targets" \
      hide_dirents=1 \
      scope_mode=global \
      deny_uids= \
      enable_syscall_hooks=1 \
      syscall_hooks=newfstatat,statx,faccessat2,readlinkat,openat,openat2 \
      write_op_policy=passthrough 2>&1); then
    write_state "failed-insmod" "$(basename "$ko"): $err"
    return 1
  fi
  touch "$OWNED_FILE" 2>/dev/null
  resolved=$(cat /sys/module/pathmask/parameters/resolved_count 2>/dev/null)
  write_state "loaded" "$(basename "$ko") target=$targets resolved=${resolved:-unknown}"
  return 0
}

mask_path_visible_again() {
  rm -f "$OWNED_FILE" 2>/dev/null
  pathmask_loaded || return 0
  unload_pathmask && write_state "healthy-unmasked" "soter binder service reachable"
}

main() {
  local start series ko rc
  start=$(now_ms)

  # The bundled .ko are arm64 builds; on any other ABI there is nothing to do.
  case "$(uname -m 2>/dev/null)" in
    aarch64|arm64) ;;
    *) write_state "skipped-arch" "uname -m=$(uname -m 2>/dev/null)"; return 0 ;;
  esac

  if [ "$(conf_get soter_hide)" = "0" ]; then
    write_state "skipped-disabled" "soter_hide=0"
    return 0
  fi
  [ "$(conf_get soter_hide_prefer)" = "skip" ] && PREFER=skip
  [ "$(conf_get pathmask_takeover)" = "1" ] && TAKEOVER=1
  ko=$(conf_get pathmask_target)
  [ -n "$ko" ] && TARGET_PATH="$ko"

  series=$(kernel_series) || { write_state "skipped-kernel" "uname=$(uname -r 2>/dev/null)"; return 0; }

  if soter_service_available; then
    mask_path_visible_again
    write_state "healthy-skip" "soter binder service reachable"
    log "elapsed=$(( $(now_ms) - start ))ms"
    return 0
  fi

  if [ "$PREFER" = "skip" ]; then
    write_state "prefer-skip" "service not reachable and soter_hide_prefer=skip"
    return 0
  fi
  if [ ! -e "$TARGET_PATH" ] && ! pathmask_loaded; then
    write_state "skipped-target-missing" "$TARGET_PATH"
    return 0
  fi

  for ko in $(ko_candidates "$series"); do
    load_pathmask "$ko" "$TARGET_PATH"
    rc=$?
    [ "$rc" = "0" ] && break
    [ "$rc" = "2" ] && break
  done
  [ "$rc" != "0" ] && [ "$rc" != "2" ] && write_state "failed-no-usable-ko" "series=$series"
  log "elapsed=$(( $(now_ms) - start ))ms"
}

main "$@"
