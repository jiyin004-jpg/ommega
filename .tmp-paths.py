import io, os, re

def edit(path, pairs, must=True):
    t = io.open(path, encoding='utf-8').read()
    for old, new in pairs:
        if old not in t:
            if must:
                print('  !! %s 未匹配: %s' % (path, old[:70]))
            continue
        t = t.replace(old, new)
    io.open(path, 'w', encoding='utf-8', newline='\n').write(t)

K = '/data/misc/keystore/ommega'
M = '/data/misc/ommega'

# ---------------- keymint：config / remote_identity / logs / uid_packages / foreground ----------------
edit('src/config.rs', [
    ('const CONFIG_PATH: &str = "/data/misc/keystore/ommega/config.toml";',
     'const CONFIG_PATH: &str = "/data/misc/ommega/config.toml";'),
    ('const CLIENTA_CONFIG_PATH: &str = "/data/misc/keystore/ommega/config";',
     'const CLIENTA_CONFIG_PATH: &str = "/data/misc/ommega/config";'),
], must=False)

edit('src/consts.rs', [
    ('pub const REMOTE_IDENTITY_STATE: &str = "/data/misc/keystore/ommega/remote_identity";',
     'pub const REMOTE_IDENTITY_STATE: &str = "/data/misc/ommega/remote_identity";'),
], must=False)

edit('src/daemon.rs', [
    ('const CONF_PATH: &str = "/data/misc/keystore/ommega/config";',
     'const CONF_PATH: &str = "/data/misc/ommega/config";'),
    ('const LOG_FILE: &str = "/data/misc/keystore/ommega/logs/daemon.log";',
     'const LOG_FILE: &str = "/data/misc/ommega/logs/daemon.log";'),
    ('const REMOTE_IDENTITY: &str = "/data/misc/keystore/ommega/remote_identity";',
     'const REMOTE_IDENTITY: &str = "/data/misc/ommega/remote_identity";'),
], must=False)

edit('src/logging.rs', [
    ('const DEFAULT_LOG_PATH: &str = "/data/misc/keystore/ommega/logs/keymint.log";',
     'const DEFAULT_LOG_PATH: &str = "/data/misc/ommega/logs/keymint.log";'),
], must=False)

edit('src/plat/utils.rs', [
    ('const UID_PACKAGES_PATH: &str = "/data/misc/keystore/ommega/uid_packages";',
     'const UID_PACKAGES_PATH: &str = "/data/misc/ommega/uid_packages";'),
    ('const FOREGROUND_PATH: &str = "/data/misc/keystore/ommega/foreground";',
     'const FOREGROUND_PATH: &str = "/data/misc/ommega/foreground";'),
], must=False)

# ---------------- injector：注入器配置 / 面板写入点 ----------------
edit('ommega-injector/src/config.rs', [
    ('pub const DEFAULT_CONFIG_PATH: &str = "/data/misc/keystore/ommega/injector.toml";',
     'pub const DEFAULT_CONFIG_PATH: &str = "/data/misc/ommega/injector.toml";'),
    ('const CLIENTA_TARGET_PATH: &str = "/data/misc/keystore/ommega/target.txt";',
     'const CLIENTA_TARGET_PATH: &str = "/data/misc/ommega/target.txt";'),
    ('const CLIENTA_CONFIG_PATH: &str = "/data/misc/keystore/ommega/config";',
     'const CLIENTA_CONFIG_PATH: &str = "/data/misc/ommega/config";'),
], must=False)

edit('ommega-injector/src/hook/rewrite/replay/state.rs', [
    ('pub(super) const DEFAULT_STATE_PATH: &str = "/data/misc/keystore/ommega/unlock.state";',
     'pub(super) const DEFAULT_STATE_PATH: &str = "/data/misc/ommega/unlock.state";'),
], must=False)

# ---------------- 多路径兜底：只保留 misc/ommega 一处 ----------------
edit('ommega-injector/src/config.rs', [
    ('''/// `/data/misc/ommega` 的 context 是 `system_data_file`，system_app 读得动
pub const FALLBACK_CONFIG_PATH: &str = "/data/misc/ommega/injector.toml";''',
     '''/// `/data/misc/ommega` 的 context 是 `system_data_file`，system_app 和 keystore
/// 域都读得动 —— 它现在是**唯一**的数据根，不再有第二份可选路径。
pub const CONFIG_PATH: &str = "/data/misc/ommega/injector.toml";'''),
], must=False)

print('--- 剩余 keystore 引用（应该只剩密钥材料 + IPC）')
for root in ('src', 'ommega-injector/src'):
    for dirpath, _, files in os.walk(root):
        if 'target' in dirpath:
            continue
        for fn in files:
            if not fn.endswith('.rs'):
                continue
            p = os.path.join(dirpath, fn)
            for i, line in enumerate(io.open(p, encoding='utf-8').read().splitlines(), 1):
                if K in line and not line.strip().startswith('//'):
                    print('  %-42s %4d| %s' % (p, i, line.strip()[:95]))
