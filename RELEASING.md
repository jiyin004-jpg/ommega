# 发版流程

## 版本号

三端同号，唯一来源是仓库根的 `VERSION`：

- `a-side/source/Cargo.toml`、`b-side/source/Cargo.toml`、`server/source/Cargo.toml` 的
  `version` 必须跟它一致。`build.py` 会逐个核对，不一致直接退出（「两个都要改，别只改一个」）
- b-app（`b-app/source/app/build.gradle.kts`）和 server（`src/config.rs`）都是直接读这个文件，
  不用单独改

versionCode 由版本号推出：`major * 1000000 + minor * 1000 + patch`（1.6.4 → 1006004）。

### versionCode 上有个坑，别照公式想当然

A/B 模块经历过几次「版本号不动、只重新发一次」的热修（1.6.1 / 1.6.2 / 1.6.3），每次都得把
versionCode 手工抬高，攒下来的结果是：**1.6.4 的模块实际是 `1006014`，比公式值 `1006004`
高 10**。Magisk 判断有没有更新只看 versionCode，所以下一个 1.6.x 不能让这个数掉下去：

- 发 1.6.5 这种小版本时，模块必须显式传 `--version-code 1006015`，别用默认值，
  不然装过 1.6.4 的机器收不到更新
- 发 1.7.0 则没事，公式值 1007000 本来就比 1006014 大
- b-app 从没被覆盖过，一直是公式值（1.6.4 → 1006004），跟模块不是一套数，不要拿它对账

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
