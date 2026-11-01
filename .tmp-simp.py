import io
p = 'template/service.sh'
t = io.open(p, encoding='utf-8').read()
old = '''if [ -f "$MODDIR/sepolicy.rule" ]; then
  for ksud_bin in /data/adb/ksu/bin/ksud /data/adb/magisk/magiskpolicy; do
    [ -x "$ksud_bin" ] || continue
    case "$ksud_bin" in
      *ksud) "$ksud_bin" sepolicy apply "$MODDIR/sepolicy.rule" >/dev/null 2>&1 ;;
    esac
    break
  done
fi'''
new = '''if [ -x /data/adb/ksu/bin/ksud ] && [ -f "$MODDIR/sepolicy.rule" ]; then
  /data/adb/ksu/bin/ksud sepolicy apply "$MODDIR/sepolicy.rule" >/dev/null 2>&1
fi'''
if old in t:
    io.open(p, 'w', encoding='utf-8', newline='\n').write(t.replace(old, new, 1))
    print('简化完成')
else:
    print('!! 未匹配')
