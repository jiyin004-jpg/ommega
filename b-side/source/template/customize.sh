# shellcheck disable=SC2034
# KernelSU/Magisk auto-unpack the whole module zip, then run this script. All
# module files are already present under $MODPATH (relay binary at
# $MODPATH/libs/<abi>/relay, etc.), so we only set permissions and perform
# light setup here — we never re-unzip.

if [ "$BOOTMODE" != "true" ]; then
  abort "! Please install via Magisk/KernelSU app"
fi

# 1.6.1 之前模块 id 叫 ommegaclient_b，跟安装包名 ommega-b-release-*.zip 对不上，已统一成
# ommega-b。改 id 就等于换了安装目录，老装机上那份旧目录还在、service.sh 还挂着，不清掉
# 会同时跑两个 relay。这里只删「确认是旧 id 的那份」，别的一概不碰。
OLD_ID_DIR=/data/adb/modules/ommegaclient_b
if [ -d "$OLD_ID_DIR" ] && [ "$OLD_ID_DIR" != "$MODPATH" ] && \
   grep -q '^id=ommegaclient_b' "$OLD_ID_DIR/module.prop" 2>/dev/null; then
  ui_print "- Removing previous module id dir: $OLD_ID_DIR"
  pkill -f "modules/ommegaclient_b" 2>/dev/null || true
  rm -rf "$OLD_ID_DIR"
fi

ui_print "- Installing ommega-b B-side relay agent"

# Ensure the relay binary and the uninstall hook are executable.
chmod 0755 "$MODPATH/libs/arm64-v8a/relay" "$MODPATH/libs/x86_64/relay" \
  "$MODPATH/adbr-daemon.sh" \
  "$MODPATH/uninstall.sh" 2>/dev/null || true

# sepolicy 工具链：规则文件 + 「把规则打进去」那段逻辑 + 模块自带的兜底工具。
# 三个缺一件也能开机，只是那条路退回到「靠管理器自己重放」。
chmod 0755 "$MODPATH/sepolicy_apply.sh" 2>/dev/null || true
chmod 0755 "$MODPATH/libs/arm64-v8a/ommega-policy" \
  "$MODPATH/libs/x86_64/ommega-policy" 2>/dev/null || true

# adbrd 只有 arm64 一份（上游只给这个架构），别的架构装完就是没有这个文件，
# 开关写了也当没写 —— 不要 abort。
chmod 0755 "$MODPATH/libs/arm64-v8a/adbrd" 2>/dev/null || true

# spl_daemon 也不是每个包都有（构建时没找到 NDK 就会缺），缺了就该退回改属性那条路。
chmod 0755 "$MODPATH/libs/arm64-v8a/spl_daemon" 2>/dev/null || true

# WebUI 面板由 KernelSU/APatch 管理器自己 serve（模块里的 webroot/），不需要
# 另起 http 服务；管理器会自动注入 window.ksu。
[ -f "$MODPATH/webroot/index.html" ] || ui_print "! webroot/index.html 缺失，WebUI 不可用"

# Verify the expected binary exists for this ABI.
case "$ARCH" in
  arm64|arm64-v8a)
    [ -f "$MODPATH/libs/arm64-v8a/relay" ] || abort "! Missing libs/arm64-v8a/relay"
    ;;
  x64|x86_64)
    [ -f "$MODPATH/libs/x86_64/relay" ] || abort "! Missing libs/x86_64/relay"
    ;;
  *)
    abort "! Unsupported platform: $ARCH"
    ;;
esac

ui_print "- Done"
