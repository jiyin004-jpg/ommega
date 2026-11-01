import io, os, glob

K = '/data/misc/keystore/ommega'
M = '/data/misc/ommega'

# 脚本里所有 K 引用都是「数据」引用（config / remote_identity / 软链 / 日志 / uninstall），
# 密钥材料（keybox_*.xml）和 IPC（rpc.peers/sock）只在 Rust 侧引用，脚本里没有。
changed = []
for p in glob.glob('template/*.sh') + ['template/daemon-injector']:
    t = io.open(p, encoding='utf-8').read()
    if K not in t:
        continue
    n = t.count(K)
    t = t.replace(K, M)
    io.open(p, 'w', encoding='utf-8', newline='\n').write(t)
    changed.append((p, n))

print('--- 脚本路径统一')
for p, n in changed:
    print('  %-24s %d 处' % (os.path.basename(p), n))

# ---------------- customize.sh：加一次性迁移 ----------------
p = 'template/customize.sh'
t = io.open(p, encoding='utf-8').read()
old = '''if [ ! -e "$CONFIG_DIR/ommegadata" ] && [ ! -L "$CONFIG_DIR/ommegadata" ]; then
  ln -s /data/misc/ommega "$CONFIG_DIR/ommegadata"
fi'''
new = '''if [ ! -e "$CONFIG_DIR/ommegadata" ] && [ ! -L "$CONFIG_DIR/ommegadata" ]; then
  ln -s /data/misc/ommega "$CONFIG_DIR/ommegadata"
fi

# 数据根搬家：以前 keystore 域和 app 域各存一份（config、remote_identity、日志、
# soter_*、uid_packages、foreground…），现在统一到 /data/misc/ommega（system_data_file，
# 两边都读得到）。这里把旧位置的数据搬过来一次，keystore 目录只留密钥材料和 rpc.sock。
KS_ROOT=/data/misc/keystore/ommega
DATA_ROOT=/data/misc/ommega
mkdir -p "$DATA_ROOT/logs" 2>/dev/null
for f in config.toml config remote_identity soter_cpu_id uid_packages foreground \\
         soter_attk.pem soter_asks.json injector.toml target.txt unlock.state \\
         remote_identity.applied remote_identity.updated; do
  [ -f "$KS_ROOT/$f" ] || continue
  [ -e "$DATA_ROOT/$f" ] || mv -f "$KS_ROOT/$f" "$DATA_ROOT/$f" 2>/dev/null
  rm -f "$KS_ROOT/$f" 2>/dev/null
done
for f in "$KS_ROOT"/logs/*; do
  [ -f "$f" ] || continue
  [ -e "$DATA_ROOT/logs/${f##*/}" ] || mv -f "$f" "$DATA_ROOT/logs/" 2>/dev/null
  rm -f "$f" 2>/dev/null
done
# keystore 目录里只该剩：keybox_tee.xml / keybox_strongbox.xml / data/ / rpc.peers / rpc.sock'''
if old not in t:
    print('  !! customize.sh 软链段未匹配')
else:
    t = t.replace(old, new, 1)
    io.open(p, 'w', encoding='utf-8', newline='\n').write(t)
    print('  customize.sh: 加入一次性迁移')

print('--- 脚本里剩余 keystore 引用')
for p in glob.glob('template/*.sh') + ['template/daemon-injector']:
    for i, line in enumerate(io.open(p, encoding='utf-8').read().splitlines(), 1):
        if 'keystore/ommega' in line:
            print('  %-22s %4d| %s' % (os.path.basename(p), i, line.strip()[:95]))
