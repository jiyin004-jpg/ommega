import os, zipfile

ext = '.tmp-pkg/ext'
out = '.tmp-pkg/ommega-a-test.zip'
if os.path.exists(out):
    os.remove(out)

exec_bits = ('.sh', 'update-binary', 'keymint', 'ommega-inject', 'inject-watchdog',
             'resetprop', 'adbrd', 'soterta-ta', 'KmInstallKeybox')

count = 0
with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as z:
    for root, dirs, files in os.walk(ext):
        dirs.sort()
        for name in sorted(files):
            full = os.path.join(root, name)
            rel = os.path.relpath(full, ext).replace(os.sep, '/')
            info = zipfile.ZipInfo(rel)
            info.compress_type = zipfile.ZIP_DEFLATED
            mode = 0o755 if (name.endswith(exec_bits) or '/libs/' in '/' + rel) else 0o644
            info.external_attr = (mode << 16) | 0o200000
            with open(full, 'rb') as fh:
                z.writestr(info, fh.read())
            count += 1

print('打包 %d 个文件，%d bytes' % (count, os.path.getsize(out)))
with zipfile.ZipFile(out) as z:
    names = set(z.namelist())
    for n in ('libs/arm64-v8a/inject-watchdog', 'libs/arm64-v8a/keymint',
              'service.sh', 'daemon', 'META-INF/com/google/android/update-binary',
              'injector.toml'):
        print('  %-44s %s' % (n, 'ok' if n in names else '缺失'))
