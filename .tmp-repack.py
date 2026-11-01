import hashlib, io, os, shutil, sys

ext = '.tmp-pkg/ext'
src = 'a-side/source'
abi = 'libs/arm64-v8a'

# (源文件, 包内路径)
jobs = [
    (f'{src}/target/aarch64-linux-android/release/keymint', f'{ext}/{abi}/keymint'),
    (f'{src}/target/aarch64-linux-android/release/ommega-inject', f'{ext}/{abi}/ommega-inject'),
    (f'{src}/target/aarch64-linux-android/release/inject-watchdog', f'{ext}/{abi}/inject-watchdog'),
    (f'{src}/template/service.sh', f'{ext}/service.sh'),
    (f'{src}/template/post-fs-data.sh', f'{ext}/post-fs-data.sh'),
    (f'{src}/template/customize.sh', f'{ext}/customize.sh'),
    (f'{src}/template/injector.toml', f'{ext}/injector.toml'),
    (f'{src}/template/uninstall.sh', f'{ext}/uninstall.sh'),
    (f'{src}/template/webroot/index.html', f'{ext}/webroot/index.html'),
]

for s, d in jobs:
    if not os.path.isfile(s):
        print('!! 缺源文件', s); sys.exit(1)
    shutil.copyfile(s, d)
    h = hashlib.sha256(io.open(d, 'rb').read()).hexdigest()
    io.open(d + '.sha256', 'w', newline='\n').write(h + '\n')
    print('  替换 %-46s %s' % (os.path.basename(d), h[:16]))

# 旧 shell 守护已经不存在了
for f in ('daemon', 'daemon.sha256'):
    p = os.path.join(ext, f)
    if os.path.exists(p):
        os.remove(p)
        print('  删除', f)

# 确认没有残留引用
print('--- 检查')
print('  daemon 文件:', os.path.exists(os.path.join(ext, 'daemon')))
print('  injector.toml 含 scoop:', 'scoop' in io.open(os.path.join(ext, 'injector.toml'), encoding='utf-8').read())
print('  service.sh 含 watchdog:', 'inject-watchdog' in io.open(os.path.join(ext, 'service.sh'), encoding='utf-8').read())
