import io, os

def edit(path, pairs):
    t = io.open(path, encoding='utf-8').read()
    for old, new in pairs:
        if old not in t:
            print('  !! %s 未匹配' % path)
            continue
        t = t.replace(old, new, 1)
    io.open(path, 'w', encoding='utf-8', newline='\n').write(t)

# 源码 + [[bin]]
p = 'ommega-injector/src/bin/inject_watchdog.rs'
if os.path.exists(p):
    os.remove(p)
    print('  删除', p)
edit('ommega-injector/Cargo.toml', [(
    '[[bin]]\nname = "inject-watchdog"\npath = "src/bin/inject_watchdog.rs"\n\n', '')])

# build.py
edit('build.py', [(
    '    {"package": "ommega-injector", "bin": "inject-watchdog", "output_name": "inject-watchdog"},\n', '')])

# customize.sh
edit('template/customize.sh', [
    ("  # 文件变化驱动的注入器调度器（替掉 shell 版每轮的定时轮询）\n"
     "  extract \"$ZIPFILE\" 'libs/arm64-v8a/inject-watchdog' \"$MODPATH\"\n", ''),
    ("for f in keymint ommega-inject soterta-ta resetprop adbrd inject-watchdog; do",
     "for f in keymint ommega-inject soterta-ta resetprop adbrd; do"),
    ('chmod 755 "$BINDIR/keymint" "$BINDIR/ommega-inject" "$BINDIR/resetprop"',
     'chmod 755 "$BINDIR/keymint" "$BINDIR/ommega-inject" "$BINDIR/resetprop"'),
])

# uninstall.sh
edit('template/uninstall.sh', [(
    'pkill -9 -f "$STATE_DIR/bin/inject-watchdog" 2>/dev/null\n', '')])

# daemon-injector 注释
edit('template/daemon-injector', [
    ('# --once：跑完一轮就退出（由 Rust 的 inject-watchdog 在文件变化时叫它）。',
     '# --once：跑完一轮就退出（调试用）。'),
])

print('--- 剩余')
for f in ('build.py', 'template/service.sh', 'template/customize.sh',
          'template/uninstall.sh', 'template/post-fs-data.sh'):
    t = io.open(f, encoding='utf-8').read()
    print('  %-28s inject-watchdog=%d' % (f, t.count('inject-watchdog')))
