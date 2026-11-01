import io, os, re

def edit(path, pairs):
    t = io.open(path, encoding='utf-8').read()
    for old, new in pairs:
        if old not in t:
            print('  !! 未匹配 %s: %r' % (os.path.basename(path), old.splitlines()[0][:60]))
            continue
        t = t.replace(old, new, 1)
    io.open(path, 'w', encoding='utf-8', newline='\n').write(t)

# base64.sh：resetprop 二进制：只认模块目录，打包后直接可执行，不需要拷进状态目录
edit('template/customize.sh', [
    ('BIN_DIR=$CONFIG_DIR/bin\n', ''),
    ('mkdir -p "$CONFIG_DIR" "$BIN_DIR" "$CONF_DIR" "$RUN_DIR" "$DB_DIR" "$CONFIG_DIR/logs"',
     'mkdir -p "$CONFIG_DIR" "$CONF_DIR" "$RUN_DIR" "$DB_DIR" "$CONFIG_DIR/logs"'),
    # 平铺 → bin/ 的搬家：bin 布局已废弃，这段整块删掉
    ('''# 老版本平铺在根目录的文件先搬进新子目录（只支持新路径，不做读取兜底）。
for f in keymint ommega-inject soterta-ta resetprop adbrd; do
  [ -f "$CONFIG_DIR/$f" ] && [ ! -e "$BIN_DIR/$f" ] && mv -f "$CONFIG_DIR/$f" "$BIN_DIR/$f"
done
''',
     '''# 只支持新路径，不做旧布局搬运：运行文件在模块 `libs/<abi>/`，状态在 conf/run/db/logs。
'''),
    ('rm -f "$BIN_DIR/keymint" "$BIN_DIR/ommega-inject" "$CONFIG_DIR/injector" # clean up old hot-update binaries\n',
     'rm -f "$CONFIG_DIR/injector" "$CONFIG_DIR/keymint" "$CONFIG_DIR/ommega-inject" 2>/dev/null\n'),
])

# 三处只剩“定义”没有用法的 BIN_DIR
for f in ('template/service.sh', 'template/post-fs-data.sh', 'template/daemon-injector'):
    t = io.open(f, encoding='utf-8').read()
    body = t.replace('BIN_DIR=$STATE_DIR/bin\n', '')
    if 'BIN_DIR' not in body:
        io.open(f, 'w', encoding='utf-8', newline='\n').write(body)
        print('  删除 BIN_DIR 定义:', os.path.basename(f))
    else:
        print('  仍有引用，保留:', os.path.basename(f),
              [l.strip() for l in body.splitlines() if 'BIN_DIR' in l][:3])

print('--- 剩余 bin 引用')
for f in ('template/customize.sh', 'template/service.sh', 'template/post-fs-data.sh',
          'template/daemon-injector', 'template/layout.sh', 'template/uninstall.sh'):
    src = io.open(f, encoding='utf-8').read()
    for i, line in enumerate(src.splitlines(), 1):
        if 'BIN_DIR' in line or 'bin/' in line:
            print('  %-20s %4d| %s' % (os.path.basename(f), i, line.strip()[:100]))
