# 发版流程

[English](RELEASING.en.md)

## 版本号

三端同号，唯一来源是仓库根的 `VERSION`：

- `a-side/source/Cargo.toml`、`b-side/source/Cargo.toml`、`server/source/Cargo.toml` 的
  `version` 必须跟它一致。`build.py` 会逐个核对，不一致直接退出（「两个都要改，别只改一个」）
- b-app（`b-app/source/app/build.gradle.kts`）和 server（`src/config.rs`）都是直接读这个文件，
  不用单独改

versionCode 由版本号推出：`major * 1000000 + minor * 1000 + patch`，模块那边还会再加一个
偏移，下面单独说。

### versionCode 和那个热修偏移

模块的 versionCode 是「公式值 + `VERSION_CODE_OFFSET`」，偏移量写在 `a-side/source/build.py` 和
`b-side/source/build.py` 里。两边各是一套，重发哪端就抬哪端 —— 只改一边是正常的，别把两边
对齐（不然仓库里算出来的数会跟已经发出去的那个包对不上）。

偏移是为了修一段历史：A / B 模块经历过几次「版本号不动、只重新发一次」的热修（1.6.1 /
1.6.2 / 1.6.3），每次都得把 versionCode 手工抬高，攒到 1.6.4 时模块实际发出去的是
`1006014`，而公式值只有 `1006004`。Magisk 判断有没有更新只看这个数，要是照公式发 1.6.5
会算出 `1006005`，比 1006014 小，装过 1.6.4 的机器就收不到更新。

差的这 10 就是 `VERSION_CODE_OFFSET` 的来历，所以：

- 正常发版什么都不用做，公式值加上各自那个偏移自然一路递增
- 万一又要同版本号重发，把那一端的 `VERSION_CODE_OFFSET` 往上加（10 → 11 → 12），不要手工传
  `--version-code`，那个参数只是应急口子
- 目前的偏移：A 端 10（1.6.4 → 1006014），B 端 11（2026-10-03 重发，1.6.4 → 1006015）
- b-app 没这东西（它没重发过），一直是纯公式值，1.6.4 是 `1006004`，跟模块不是一套数，
  不要拿它对账

## 发版步骤

1. 确认 master 上的 CI 是绿的
2. 改 `VERSION`，同步三个 `Cargo.toml` 的 `version`
3. 更新 `CHANGELOG.md`（A / B 端）和 `CHANGELOG-B.md`
4. 构建产物（见下）
5. 打 annotated tag：`git tag -a v<版本> -m "..."`。tag 要指在**产出这批产物的那个提交**上——
   模块里的 `version` 带了那一刻的短 hash（如 `1.6.4-17be4f5`），tag 指错就对不上号
6. 建 Release，标题写 `v<版本>`
7. 上传附件
8. 更新 `update.json` / `b-update.json` 的 `version` / `versionCode` / `zipUrl`
9. 验证（见下）

### 构建

| 产物 | 在哪跑 | 命令 |
| --- | --- | --- |
| A 端模块 | `a-side/source` | `python build.py --release` |
| B 端模块 | `b-side/source` | `python build.py --release` |
| b-app | `b-app/source` | `./gradlew :app:assembleRelease`（Windows 用 `gradlew.bat`） |
| 服务端 | `server/source` | `cargo build --release --target <triple>` |

服务端的二进制落在 `server/source/target/<triple>/release/`，不是 `target/release/`。

### 验证

- 包内 `module.prop`：`version` 带的 hash 跟 tag 对得上，`versionCode` 比上一版大
- `update.json` / `b-update.json` 的 `versionCode` 跟包内一致
- 附件能下：HEAD 返回 200，`Content-Length` 跟本地文件一致
- 刷到真机后确认跑的就是模块里那份二进制：
  `readlink /proc/$(pgrep -f ommega/relay)/exe` 要落在
  `/data/adb/modules/ommega-b/libs/<abi>/relay`。`/data/adb/ommega/relay` 是「热更新」放
  二进制的口子（`uninstall.sh` 里就叫 hot-update relay binary），而 `service.sh` 的
  `find_module_relay()` 让它优先于模块目录 —— 实测（一加 PLC110 / KernelSU 3.3.0，
  2026-10-03 12:46）：模块已经刷成 `1.6.4-5c41c1a`，`/proc/<pid>/exe` 还指着上一次热更新
  塞进去的旧二进制，光刷模块只换了 `module.prop`。刷完要么把那份副本删掉（让模块里的
  生效），要么手工换掉它。

## 服务端上线

服务端不走 OTA，是手工换二进制：`scp` 到 `/tmp`，校验 sha，停服再换（跑着的时候 `cp`
会 `Text file busy`），换完留备份：

```sh
cp -a /opt/relay/relay_rs /opt/relay/relay_rs.pre<改动名>-$(date +%Y%m%d-%H%M%S)
systemctl stop relay_rs
install -m 755 /tmp/relay_rs.new /opt/relay/relay_rs
systemctl start relay_rs
systemctl is-active relay_rs; sha256sum /opt/relay/relay_rs
```

验活看两个口子（2026-10-03 实测）：`curl -s http://127.0.0.1:10886/api/status/` 是明文 200，
TLS 在 `https://127.0.0.1:8443/api/status/`。别再拿 https 打 10886，那个口子不答 TLS，
会拿到空内容、看着像没起来。业务日志全在 `/opt/relay/relay.out.log`（带 ANSI 颜色，
先 `sed -r 's/\x1b\[[0-9;]*m//g'` 去掉），systemd 那边只有起停记录。

换完记得把 Release 里的 `relay_rs-*` 附件一起换掉（`gh release upload <tag> <文件> --clobber`），
不然「master == Release == 线上」这条对不上。

### 长期状态都在这一个库里（`data/relay_state.db`）

2026-10-03 起，服务端「要长期保留的东西」不再各写各的 JSON，统一进一个 SQLite 文件
（WAL，代码在 `server/source/src/statedb.rs`）：

- `sessions`：原来 `data/sessions.json` 那份（实测 11714 条 / 73.9 MB / 每条 7.9 KB，
  以前每出一条新会话就把整份序列化重写一遍，约 400 次/天 ≈ 25~30 GB 写放大）
- `soter_slots` / `soter_slot_owners`：原来 `data/soter_slots.json` 里的钉子（layer +
  时间戳）和「这个槽位上认过哪些账号」。一个账号一行，同一个槽位堆几百个号也只是多几百行。
  旧的那份 JSON 是**整份重写且没有 tmp+rename**，崩在写盘中间就解不开，`load_slots`
  直接按空算（钉子全丢）—— 进库之后这条没了
- 两份旧 JSON **只在库里是空的时候导一次**（字段逐字节搬，`leaf_key_pem` 里那份 Fernet
  密文不重新加密），导完留在原地当回滚源。2026-10-03 拿线上真数据演练过：11596 条会话
  逐条比对一致、1471 个槽位 / 5043 条账号指纹全对上，导入耗时 2.5 s
- 单个槽位每一族最多记 512 个账号指纹（原来是三族合计 64，实测最大的 uid 已经 33 个号、
  三族 95 条指纹，早就在截断了）。满了不是拒收新号，而是把这一族里最久没见到的那条
  换出去（LRU）；**拔钉子（清钥匙）只删「钉层」那一行，账号记录留着** —— 它是判据，
  不能跟着 uid 一起清。账号记录按最后一次见到算 TTL（30 天），太久没见的自动丢弃
  
  两个坑（2026-10-03 都真踩过）：
  - 旧 JSON 里没有时间，导入时给的是 0。**0 一律按「未知」算**：开库时拿当下回填、
    TTL 清理跳过它、内存里查也当成还有效。不这么写，一挂上 TTL 的第一次启动就会把
    整张表当成「过期了几辈子」清光（实测 5298 条剩 386 条，靠迁移前的 `.backup` 补回来）
  - 一次清掉几百条以上会在日志里出 WARN，看到就去查时间戳，别当正常过期
- 会话表的过期按「最后一次使用」算（7 天，不再是创建时间），条数上限 20000 条、超了按 LRU
  淘汰最久没用的；启动只把最近用过的 8000 条装进内存，其余的留在库里按 alias 单查
  —— 内存那层是热缓存，库才是权威，重启不会丢会话
- **备份 / 回滚这个库得把 `-wal`、`-shm` 一起挪**。SQLite 开的是 WAL 模式，最近写入可能
  还在 `data/relay_state.db-wal` 里，只搬 `.db` 会拿到一个偏旧的库。要么先
  `sqlite3 data/relay_state.db 'PRAGMA wal_checkpoint(TRUNCATE)'` 再搬，要么三个文件一起搬
- **回滚到旧二进制时**：把 `data/relay_state.db`（连 `-wal`、`-shm`）挪走
  （`mv data/relay_state.db* data/relay_state.db.bak-<时间>`）。不然下次再升上来，库非空就不再
  导旧 JSON，库会比 JSON 旧

### 账号指纹登记表（`soter_slot_owners`）

靠它决定收到 uid 级全清（`remove_all_uid_key`）时要不要转发：槽位上有两个以上账号时只答
成功、不往下转发，免得一发全清把同 uid 其它号的开通记录一起废掉。

这份表正常是运行时慢慢认出来的，认到新账号时日志会打
`槽位 <设备>|<uid> 上认到第 N 个账号指纹（<族>）`，拦下全清打 `uid 级全清会连坐`
（2026-10-03 实测：种表后 2536 个 op 里有 71 次清空请求，30 次被拦下）。换机 / 清库 /
新数据目录时它是空的，头几个小时等于没保护 —— 日志里有全部「别名 ↔ (设备, uid)」的历史，
种一次即可。种表脚本直接改旧 JSON（`data/soter_slots.json`），**只适用于跑着 1.6.4 及更早
服务端、或者要在升级前把库喂饱的场合**（库是空的时候才会导这份 JSON）：

```sh
python3 server/deploy/seed_soter_owners.py            # 先看统计
cp -a /opt/relay/data/soter_slots.json /opt/relay/data/soter_slots.json.bak-$(date +%Y%m%d-%H%M%S)
systemctl stop relay_rs
python3 server/deploy/seed_soter_owners.py --apply    # 写 /tmp/soter_slots.merged.json
install -m 644 /tmp/soter_slots.merged.json /opt/relay/data/soter_slots.json
systemctl start relay_rs
```

必须停服再换：进程里那份 map 是权威，跑着的时候它下一次写盘会盖掉手工改的内容。脚本只动
`owners`，各槽位的钉子（`layer` / `at_millis`）原样保留。库已经在跑之后就不用它了 —— 登记
是写穿到 `soter_slot_owners` 的。

## B 端的会话也进了一个库（`/data/adb/ommega/sessions.db`）

2026-10-03 起，B 端（`b-side/source/src/keymaster/session_db.rs`）不再「一个别名一个
JSON 文件」，改成 SQLite 一个文件，规则跟服务端那套对齐：

- 过期按**最后一次使用**算（7 天），条数上限 20000，超了 LRU 淘汰最久没用的
  （`used_ms` 上建索引，清理是两条 DELETE）。取用会顺手把 `used_ms` 顶到当下，
  但节流 5 分钟一次 —— 不刷新就是 2026-10-03 那个 bug 的翻版：正在用的 alias 被当成
  闲置的清掉，紧接着签名报 `no key for alias ... (call attest first)`
- 内存里只留最近用过的 2000 条（原来那份 map 是全量常驻，实测到过 19967 条 ≈ 160 MB），
  其余按 alias 单查库；库才是权威，重启不丢会话
- 旧目录 `/data/adb/ommega/sessions/` **原样留着**：只在库空的时候导一次
  （别名从 JSON 里取，文件名是哈希反推不出来；「最后使用时间」用文件 mtime，跟老版本的
  LRU 依据是同一个），导完不再动它，等于现成的回滚源。确认没问题之后手工
  `rm -rf /data/adb/ommega/sessions` 就收回那一百多 MB
- 刷回旧版本（只认 JSON 目录的那版）之前，先把 `sessions.db*` 挪走，否则旧版会从
  旧目录读到一份落后的会话表；反过来再升上来时，库非空就不再导旧 JSON
- 跟服务端一样，**挪库要连 `-wal`、`-shm` 一起**（WAL 模式）。relay 每次重启都是
  `pkill -9`，这正是 WAL 该处理的场景，不用特地关库

## Release 规范

- 标题一律 `vX.Y.Z`，跟 tag 一字不差。不带项目名（`Ommega 1.6.0` 那种）、不带端侧名和
  中文描述（`服务端 v1.4.5 — ...` 那种）
- 说明用 Markdown 分端写（A 端 / B 端 / 服务端），末尾附产物表：文件名 + 大小 + SHA256
- 刚发、还没经过用户验证的先勾 pre-release，验证过再转正式
- tag 一律用 annotated（从 1.6.4 起）

## 历史遗留

1.5.0 之前 A / B / 服务端是各自独立发版的，所以老 Release 标题里出现过端侧名和中文描述，
这些已经统一改成 `vX.Y.Z`。更早的 tag（1.6.3 及以前）是 lightweight，按「不改历史」的原则
不再动，annotated 只从 1.6.4 往后算。
