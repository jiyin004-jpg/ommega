# B 端模块更新日志

这里只写 B 端模块（`ommegaclient_b`）的改动。A 端模块、服务端和 b-app 的改动看
[CHANGELOG.md](CHANGELOG.md)。

## 未发布

- **证书链为空时不再当成认证成功上报**。KeyMint HAL 如果对 `generateKey` 返回成功、却给了空证书链，
  此前会被当成成功上报成 `cert_chain: []`，服务端只能看到一句「empty cert chain」，看不出是谁掉的。
  现在直接报错并带上原因（`real keymint … returned an empty certificate chain (key_blob NB)`），
  StrongBox 分支也会把这种情况标成「HAL 接受了生成请求但没给认证证书链」。顺带不再把这种空链 session
  写进 `/data/adb/ommega/sessions`。
  服务端对「报错」和「空链」的处理本来就一样（进下一层 / StrongBox 降级），所以行为不变。

## 1.3.2

（B 端模块 1.3.2，versionCode 29；对应 A 端 1.4.3）

- relay 增加守护循环，进程退出后自动重启。
- session 文件增加过期时间与数量上限，不再无限增长。
- `module.prop` 补上 `updateJson`，B 端模块管理器可以直接检查更新（指向本文件所在的
  `b-update.json`，与 A 端的 `update.json` 分开）。

## 1.3.1

（B 端模块 1.3.1，包名不再带 ABI 后缀；对应 A 端 1.4.2）

- **模块包改回「单包多 ABI」**（2026-09-21）。`build.py` 之前按 `--abi` 逐个出包
  （`ommegaclient-b-release-arm64-v8a-….zip`），但入库的却是多 ABI 合并包，两边对不上。现在默认把
  B 端全部受支持 ABI 打进**一个** zip（arm64-v8a / x86_64），包名不再带 ABI 后缀，安装时由
  `customize.sh` 按 `$ARCH` 释放对应的 `libs/<abi>/`。要只打某个 ABI 用 `--abi`（仍是单包），要每个
  ABI 各出一个包用 `--split`。
- **修掉单包多 ABI 下的架构选择 bug**。`b-side/template/service.sh` 找二进制是「arm64-v8a 不存在就试
  x86_64」的顺序 fallback —— 单 ABI 包时没暴露，一旦同一个包里同时带多个 ABI，x86_64 设备就会拿到
  arm64 的二进制。现在先按 `ro.product.cpu.abi`（拿不到再退回 `uname -m`）解析出本机 ABI，再取
  `libs/<abi>/`；都拿不到才退化成任意可用 ABI。
- **修掉 B 端启动即崩（编译配置错）**（2026-09-21 真机定位）。`scripts/setup_cargo_config.py`
  生成的 rustflags 里多了 `-L native=<NDK>/sysroot/usr/lib/<triple>`，而那个目录只放静态库
  （`libc.a` / `libm.a` / `libdl.a`，版本化的 `.so` stub 都在 `21/`~`35/` 这些 API 子目录、本来就在
  clang 默认搜索路径上）。linker 因此把 bionic 静态链了进去，`NEEDED` 只剩 `liblog.so`，relay 一走到
  `rsbinder::ProcessState::init_default()` 就空指针 SIGSEGV（`uptime 0s`、无日志、module.prop 卡在
  「⏳ 启动中」）。去掉这行后依赖恢复成 `liblog/libdl/libm/libc`，真机跑通轮询与任务派发。
  这个 config 是 `build.py` 首次自动生成的，上一版是手工传 linker 编的所以没踩到，a-side 同名脚本
  没这行、一直正常。修完顺手删了变成死代码的 `toml_escape()`。

## 1.3.0

- 远程 TEE 转发（B 端）、StrongBox 三段模式、Auto Keybox 等，见仓库提交记录。

更早版本见：https://github.com/jiyin004-jpg/ommega/commits/master
