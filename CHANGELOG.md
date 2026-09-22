# 更新日志

## 1.4.3

（A 端模块 1.4.3；B 端模块同步升到 1.3.2；b-app 未改动，仍为 1.3.1）

- **任务回传加守卫（server）**。`TaskStore::complete_task` 原来不校验状态、不校验归属：
  `task.assigned_device_id` 是拿上报的 `device_id` **覆盖**上去的，于是任何一个带合法共享
  B token 的请求都能终结任意 task，晚到或重复的回传会盖掉已完成的结果，还会把同一条
  task 二次塞进 `completed_queue`。现在只接受 `Assigned` / `Pending` 状态的回传，已完结的
  当幂等处理直接返回（b 端最多重试 4 次，重申不该被当成错误），并且只认任务认领时那台设备
  报上来的结果（任一侧 device_id 为空时不拦，兼容老客户端）。`Pending` 仍然放行：分配超时
  回收后原设备的晚到结果依旧有效。
- **修掉“时限倒挂”（server / b-side）**。b 端 `post_result` 最多尝试 4 次，每次
  connect 3s + read 30s，退避 1s+2s+4s，最坏 139s；而服务端 `RELAY_WAIT_RESULT_TIMEOUT`
  默认 120s —— 也就是 A 端已经放弃等待、b 端还在重试，结果没人接。服务端默认值改为
  **180s**，并在 `config.rs` 里把这个推导写成了注释，以后改 b 端重试参数时能对上。
- **B 端 relay 加上守护循环**。`b-side/template/service.sh` 原来只是 `"$TARGET" &` 再等 10s
  就退出，relay 一旦崩掉就没人拉起来 —— 而 B 端是要 7×24 挂着领任务的。现在把它放进子
  shell 后台的 `while true` 里（跟 A 端 `daemon` 同构）：退出就重启，间隔 2s，日志进
  `$STATE_DIR/logs/service.log`。重装/重启仍然走原有的 `kill_all` 清场逻辑。
- **sessions 目录不再只进不出**（b-side）。A 端每要一个新 key 就落一个 session 文件，代码里
  没有任何清理，真机上已经积到 19967 个 / 162 MB，启动 `load_all_sessions()` 要 12 秒。
  现在加了 TTL（7 天）与数量上限（2000 个），启动时清一轮、运行时每 200 次保存清一轮，
  留下的总是最新的那批。
- **公开状态接口不再吐 Knox 挑战值**（server）。`/api/status/` 是无鉴权的，它吐出的 `knox`
  块里含 `challenge` —— 那是服务端自己下发的会话随机数，状态页展示它没有意义。其余字段
  （`id_attest` / `record_hash` / 完整性状态）是状态页要用的摘要，不带密钥材料，继续公开。
- **EAT 解析失败不再静默**（server）。`device_boot_info_from_chain` 里的 `let _ = eat::read(...)`
  会让畸形 CBOR 把整条 claim 悄悄丢掉；现在解析失败会打一条 `warn`，并带上长度与首字节。
  “解析失败不影响证书本身”这个原有语义不变。（复审里提到的另一处 `cert.rs:2112` 在
  `#[cfg(test)]` 里，是测试故意遍历截断，不是问题。）
- **状态页 Knox 状态表语义修正**（server）。`status_ui.html` 的 `KNOX_STATE` 是 4 项的
  （多了一个 `3: 未认证`），而 `KnoxInfo` 里完整性与调用方认证字段只有 0/1/2 三个取值，
  一旦设备上报 3 就会显示成错误语义。去掉多余的项并注明取值来源。
- **“自动刷新开关开着”与“后台线程真在跑”区分开**（server）。后台线程只在
  `KEYBOX_REFRESH_ENABLED=true` 时由 main 启动一次，而管理接口可以直接 `set_enabled(true)`，
  造成状态页报 enabled、实际永不刷新的假象。现在多记一个 `STARTED` 标记，`is_running()`
  要求两者都成立；线程没启动时切换开关会返回 409 并提示去改配置。
- **relay token 改定长比较**（server）。`check_static_token` 原本用 `==`，同文件里
  `verify_admin` 已经用的是 `ct_eq_secret`，现在统一。（token 本身公开属于设计取舍，
  这里防的只是时序侧信道。）
- **README 补开发提示**：b-side 依赖的 `rsproperties` 只对 Linux / Android target 生效，
  Windows 上裸跑 `cargo check` 会编译失败，需带 `--target`。

## 1.4.2

（A 端模块 1.4.2，versionCode 24；B 端模块同步升到 1.3.1，包名不再带 ABI 后缀）

- **模块包改回「单包多 ABI」**（2026-09-21）。`build.py` 之前按 `--abi` 逐个出包
  （`ommega-a-release-arm64-v8a-….zip`、`ommegaclient-b-release-arm64-v8a-….zip`），但入库的
  却是多 ABI 合并包，两边对不上。现在默认把全部受支持 ABI 打进**一个** zip
  （A 端 arm64-v8a / armeabi-v7a / x86 / x86_64，B 端 arm64-v8a / x86_64），包名不再带 ABI 后缀，
  安装时由 `customize.sh` 按 `$ARCH` 释放对应的 `libs/<abi>/`。要只打某个 ABI 用 `--abi`
  （仍是单包），要每个 ABI 各出一个包用 `--split`。
- **修掉单包多 ABI 下的架构选择 bug**。`a-side/template/daemon`、`a-side/template/daemon-injector`
  和 `b-side/template/service.sh` 找二进制都是「arm64-v8a 不存在就试 x86_64」的顺序 fallback ——
  单 ABI 包时没暴露，一旦同一个包里同时带多个 ABI，x86_64 设备就会拿到 arm64 的二进制。现在都先按
  `ro.product.cpu.abi`（拿不到再退回 `uname -m`）解析出本机 ABI，再取 `libs/<abi>/`；都拿不到才
  退化成任意可用 ABI。
- **WebUI 远程配置的复选框不再被长文案挤扁**。`webroot/index.html` 里 5 个 `label.config-option`
  用的是 `align-items:center` + `gap:4px`，而 `md-checkbox` 在 flex 里没有 `flex-shrink:0`，
  文案一长就把勾选框压成一半。改成 `align-items:flex-start` + `gap:8px`，勾选框 `flex-shrink:0`、
  文字 `flex:1;min-width:0`（多行也能正常换行）；同时把「声明不支持安全模块 StrongBox（应用将视为
  设备没有安全模块；重启后生效）」压成「声明不支持 StrongBox（重启后生效）」，中简 / 中繁 / 英三语同步。
- **修掉 B 端启动即崩（编译配置错）**（2026-09-21 真机定位）。`b-side/scripts/setup_cargo_config.py`
  生成的 rustflags 里多了 `-L native=<NDK>/sysroot/usr/lib/<triple>`，而那个目录只放静态库
  （`libc.a` / `libm.a` / `libdl.a`，版本化的 `.so` stub 都在 `21/`~`35/` 这些 API 子目录、本来就在
  clang 默认搜索路径上）。linker 因此把 bionic 静态链了进去，`NEEDED` 只剩 `liblog.so`，relay 一走到
  `rsbinder::ProcessState::init_default()` 就空指针 SIGSEGV（`uptime 0s`、无日志、module.prop 卡在
  「⏳ 启动中」）。去掉这行后依赖恢复成 `liblog/libdl/libm/libc`，真机跑通轮询与任务派发。
  这个 config 是 `build.py` 本轮首次自动生成的，上一版是手工传 linker 编的所以没踩到；a-side 同名
  脚本没这行，一直正常。修完顺手删了变成死代码的 `toml_escape()`。

- **b-app 的 StrongBox 拒绝原因与 b-side 对齐**（2026-09 复审）。b-app 走 Android Keystore API，
  `setIsStrongBoxBacked` 在无 StrongBox 的设备上会静默降级 TEE（官方行为，链如实标 TEE），此前它不管
  什么情况都只把 framework 的 `e.message` 丢出去，跟 b-side 那两句固定英文对不上，server 的 Smart 模式
  认不出来 —— 结果是「有 HAL 但不可用」被当成「不确定」走到回退，跟 b-side 的「surface 给调用方」不等价。
  现在三处对齐：① 生成后复核 `KeyInfo.getSecurityLevel()`，若设备在 PackageManager 里声明了
  `android.hardware.strongbox_keystore` 而 key 却落在别处，报 `HAL exists but hardware type unavailable`；
  ② 异常链里挖 `KeyStoreException.getErrorCode()`（`@hide`（`@TestApi`）的 public 方法，只能反射）
  转成 -74 / -68 对应文本，也认 framework 直接抛的 `StrongBoxUnavailableException`；③ 判定函数从
  `Boolean` 改成 `Boolean?` —— API < 31 判断不出实际落在哪层时返回 `null`，原先固定回 `false` 会把
  一台真有 StrongBox 的老设备谎报成不可用。设备本来就没 StrongBox 时照旧静默降级（与真实设备一致），
  那条 TEE 链由 server 的安全级别校验兜住。（b-app 源码首次改动。）
- **服务端智能模式（Smart）不再把 B 端静默降级成 TEE 的链当成 StrongBox 成交**（2026-09 复审）。b-app 那条
  relay 走 Android Keystore API，`setIsStrongBoxBacked` 在无 StrongBox 的设备上是官方静默降级行为，链如实
  标 `TRUSTED_ENVIRONMENT`；但 Smart 模式此前只判 `error` 字段是否为空，会把这条 TEE 链当成「B 端真 StrongBox
  成交」直接返回，调用方请求的是 StrongBox 却拿到 TEE 认证，服务端 keybox（能出 StrongBox 标记链）根本没轮到。
  现在 B 端分支会读链叶子的 `attestationSecurityLevel`（ASN.1 那份是裸 ENUMERATED 直读；EAT 那份按
  `EatClaim.SECURITY_LEVEL` 的 1/3/4 映射成 0/1/2，与 vvb2060 KeyAttestation 的
  `eatSecurityLevelToKeymintSecurityLevel` 同款），只有 `2` 才算成交；TEE 链和读不出来的链一律继续走原有的
  服务端 keybox → A 端本地 keybox 回退。新增的 `DeviceBootInfo::security_level` 刻意不进 `is_empty()`，
  免得只有安全级别的链在状态页多出一个空启动块。
- **A 端模块支持 APatch 安装**：之前 customize.sh 只放行 KernelSU/Magisk，APatch 会被拒绝。APatch 的 apd 在脚本
  环境里设 `APATCH=true`，且它的 installer.sh 会伪装 `MAGISK_VER_CODE=30000`（兼容老模块），因此 APatch 分支
  必须放在 Magisk 分支之前判断。挂载方面 APatch 与 Magisk/KSU 一致（同为 system 目录 + whiteout 语义，新版
  同样走 metamodule/overlayfs），StrongBox whiteout 标记无需特殊处理；另新增安装时 `resetprop` 存在性探测，
  缺失时明确提示属性伪装不可用，而不是静默失败。
- **A 端 WebUI 远程配置新增「声明不支持安全模块（StrongBox）」开关**。勾选后整条链路都表现得像一台没有
  StrongBox 的设备：安装时（customize.sh）现场检测系统里声明 `android.hardware.security.strongbox_keystore`
  的 feature XML 落在哪个分区，在模块 `system/<分区>/etc/permissions/` 对应路径放 0:0 dummy 设备
  （Magisk/KSU 的标准 whiteout 语义），挂载完全由 root 管理器自己完成，PackageManager 开机后即报不支持
  （KeyAttestation 等应用直接不再显示「使用安全模块」选项）；keystore 守护进程同步读取同一开关（config
  watcher 热生效），不再注册 STRONGBOX security level，硬闯的调用拿到 `HARDWARE_TYPE_UNAVAILABLE`，
  与真无 StrongBox 设备一致。PackageManager 那半边随重启生效/还原（post-fs-data.sh 只按开关增删标记，
  不做手动 mount）。配套：flat config 新增 `hide_strongbox` 键（兼容 `no_strongbox` 别名），
  `webui` 的 JSON API 同步支持。
- **A 端支持 KeyMint 的 EAT（CBOR）认证扩展**（OID `…11129.2.1.25`）。此前只认 ASN.1 那份
  （`…2.1.17`），碰到发 EAT 的机器就取不到挑战值和 verified boot hash —— 表现是 A 端「原始 boot
  hash」探测失败、退化成随机值（日志里 `original verified boot hash unavailable`）。现在两种
  编码都认，证书里带哪份就用哪份。
- **服务端状态页同样支持 EAT**：链里是 CBOR 那份时按 EAT 读，弹窗里的字段（Boot Key / 锁定状态 /
  启动校验 / 系统·厂商·内核补丁日期）与以前一致。
- **服务端新增三星 Knox 扩展**（OID `…236.11.3.23.7`）：链里带 Knox 块时，启动状态弹窗额外显示
  Knox 挑战值、ID 认证、完整性状态（TrustBoot / Warranty / ICD / 内核 / 系统）、记录哈希与调用方
  认证结果。非三星设备这一段不出现。
- **补齐仓库自带的提交钩子**（`.cargo-husky/hooks/pre-commit`）：以前 `.cargo-husky/hooks` 目录不存在，
  `cargo build/test` 一律在编译期报错，只能靠设 `CARGO_HUSKY_DONT_INSTALL_HOOKS=1` 绕过。现在钩子随仓库
  走，提交前对改动过的 workspace 跑一遍 `cargo fmt --check`，不用再设环境变量。
- **门禁与 lint 清零**：A 端 32 位 ABI 上 `timespec` 字段的加宽改走 `Into`，64 位下既不算多余转换
  也不算无用转换，`clippy -D warnings` 通过；服务端把常年没跑过的 `cargo fmt` / `cargo clippy` 一并清了
  （27 处），行为不变。
- **真机证书回归对拍**（测试用）：`OMMEGA_REAL_CERTS` 指向 `keyattestation` 的 `testdata` 目录时，
  用 23 张真机证书跑一遍解析，和 AOSP 自己给出的期望值逐字段对拍；不设该变量就跳过。
- **三端源码审计修复**（2026-05-10 审计，详见会话报告）：
  - A 端：customize.sh 的 StrongBox whiteout 路径算错（`${var%/*}` 丢掉 `permissions` 段，安装时放错位置，
    PackageManager 层隐藏无效）改为整段相对路径；post-fs-data.sh 与 WebUI JS 补认 `hide_strongbox_keystore`
    别名，与 daemon 三键一致；boot_key.rs 两个缓存的 `advance_boot_level` 遇「拒绝增长」不再越界
    `split_off`（原先 `resetprop keystore.boot_level` 给大值会 panic 毒化写锁、重启复现），legacy 缓存补上
    与主缓存同款的 4096 增长上限；ta/begin.rs 远程 RSA 解密对 `PADDING_NONE` 不再静默换成 PKCS#1
    （改回 `RSA/ECB/NoPadding`，其它 padding 显式报错）；db.rs v2→v3 迁移给 EAT 链的密钥也打回收元数据；
    attestation.rs EAT 解析拒绝顶层 map 后的尾随数据；injector 全局作用域下 `deny_packages` 压过 scoop
    显式收录（安全阀不失效），`android` 系统包前缀不再误吞 `androidx.*`。
  - 服务端：cert.rs `take_tlv` 长度加法防回绕（原先 B 端上报畸形证书可远程触发 panic）；707/708 不再当
    vendor/boot patch 别名（那是 AOSP 的 UNIQUE_ID/ATTESTATION_CHALLENGE，会被拼出假 patch 值）；attestation
    扩展按内容啄探分派 ASN.1/CBOR（个别设备把 CBOR 挂在旧 OID 下也能解析）；notBefore 2050+ 用
    GeneralizedTime（与 notAfter 同规则）；EAT 解析拒绝尾随数据；queue.rs 回收重试的任务重置创建时间
    （原先重试即超时失败 —— 只重置时间的话毒任务会无限重试，见下方复审修复）；autokeybox 后台线程禁用后挂起等待而非退出（toggle 回开即恢复，原先永久停摆）；
    db.rs `record_token_use` 中途失败先 ROLLBACK 再还连接（原先行锁泄漏阻塞后续请求）；verify_admin 拒绝
    空密码；pay 下单加 30s 总超时。

- **三端源码审计复审修复**（2026-09-21 复审，上一轮修复遗下的回归项）：
  - **A 端 hide_strongbox 的开机崩溃循环**：开关打开后，GC 碰到 StrongBox 绑定的 blob 会在 `.unwrap()`
    上撞到 `HARDWARE_TYPE_UNAVAILABLE`，release 下 `panic=abort` 直接把 keystore 崩掉；而 DB 删行要等
    invalidate 成功才提交，崩一次没提交，下次开机又选中同一批 blob —— 现在 GC 遇到「该安全级别不可用」
    跳过不处理，其它错误照旧上抛。
  - **A 端 hide_strongbox 不再污染 level-zero key 选源**：新增 `get_or_none_probing_real_hardware`，探测
    只看真实硬件，否则开关一开，既有 StrongBox 绑定的 blob 全部解不开。
  - **A 端模板脚本路径**：`$MODPATH/system/$rel` 对 `/system` 多拼出一层 `system/system/`，已改正（Magisk
    模块镜像就是 `$MODPATH/system/<分区>/...`，`$MODPATH/vendor` 只是自动生成的 symlink，不能手动建）；
    `post-fs-data.sh` 的 `WL_RELS` 同步去掉 `system/` 前缀，检测行与写入行口径一致。
  - **A 端 customize.sh 不再无条件放 StrongBox whiteout 标记**：改成先读 flat config 里那个开关（默认关着
    的时候也隐藏声明，跟 daemon 行为矛盾，恰恰是对抗检测里最好认的指纹）。
  - **A 端 injector 的 `is_system_package_name`** 改成按前缀带不带点区分，`androidx.*` / `androidauto.*`
    不再被误当成系统包。
  - **A 端 TA 支持 EAT 链**：`ta/cert.rs` 提取远端 root-of-trust 时只认 ASN.1（`…11129.2.1.17`），B 端发
    的链是 EAT（`…11129.2.1.25`）时就默默退回本地 ROT 和版本号，和 attestation key 对不上会被判篡改 ——
    现在按扩展载荷首字节分派，两种编码都认，EAT 里没有 `verifiedBootState` 就从 `DEVICE_LOCKED` 推（锁着
    =Verified，没锁=Unverified）。EAT/CBOR 解析器提到 `kmr-common::eat`，HAL 侧和 TA 侧共用一份，带 10 项
    单测（ROT、挑战值、verified boot hash、尾随数据、嵌套深度、不定长拒绍）。
  - **服务端 queue.rs 不再无限重试**：`Task` 加 `attempts` 字段，超过 `MAX_ASSIGN_ATTEMPTS = 5` 直接判
    失败进 `failed_queue`。
  - **服务端 cert.rs 的 notAfter 兜底**：notBefore 已经是 2050 以后时给到 notBefore+1 天（原先一律沿用
    2048 默认值，做出 notBefore > notAfter 的「尚未生效」空有效期证书）。
  - **服务端 db.rs `deliver_order_with_token`** 第一条语句失败补上 ROLLBACK（`record_token_use` 上轮修了，
    兄弟函数漏了）；`auth.rs` 密码比较改恒定时间；陈旧注释里的 707/708 改成 718/719。
  - **仓库杂项**：`cargo fmt` 两边真正清零（上一轮声称清了，实际还有三处没过，提交钩子会直接挡）；README
    里 A 端安装包版本号按实际改成 1.4.1；两个 `build.py` 在 `.cargo/config.toml` 缺失时自动调
    `scripts/setup_cargo_config.py` 生成（`.cargo/` 不入库，干净 clone 直接跑 build.py 会一路编到最后链接
    阶段才报错）。

## 1.4.1

- **修复：开「全局作用域」后设备开机立刻重启/断电。** 根因是全局作用域把 ROM 的系统服务也接管了：这类应用
  在系统 keystore 里已有钥匙，被 ommega 接管后钥匙解不开（日志里 `AES finish failed / ErrorCode(-30)`），
  关键服务一崩系统就循环重启（实测中兴 `com.zte.usebalance`）。
- **全局作用域的新语义**（按实际使用需求定）：
  - **普通应用**：一律接管（无需进名单）；
  - **Google 系组件**（`com.google.*`、`com.android.vending`）：**即使没列进名单也接管**；
  - **ROM/厂商系统组件**（`com.zte.*` / `com.qualcomm.*` / `com.oplus.*` / `com.miui.*` …）：**不碰**，
    除非在名单里显式列出（列了就接管）；
  - **非应用 UID**（init / system_server / keystore / root / shell）：**任何情况都不接管**；
  - `deny_packages` 依旧生效，是额外的安全阀（出问题的包加进去即可豁免）。
- 拦截日志里新增 `RejectedSystemPackage`，便于区分"被全局作用域跳过"和"不在名单里"。

## 1.4.0

- **多架构**：A 端模块现在同时打包 **arm64-v8a / armeabi-v7a / x86 / x86_64** 四套库，安装时按设备
  `$ARCH` 自动选择对应的 `libs/<arch>`（`SUPPORTED_ABIS` 同时声明四者），发布件仍是单个 zip。
- **WebUI「全局作用域」开关**（远程配置里）：开启后**谁来调用都处理** —— 不再看 `target.txt`/`scoop`
  名单、`deny_packages` 与未知包名规则，所有 keystore 调用一律由 ommega 接管；本地/远程的判定逻辑不变。
  默认关闭，可随时在 WebUI 里勾选/取消（热生效，无需重启）。
- WebUI「远程配置」里新增**查看在线 B 端设备 ID**入口，一键打开 `/status`；提示会说明可以点设备 ID
  查看该设备的启动状态。
- **状态页（服务端）**：点在线设备的 ID 可查看它认证记录里的 **Boot Key / 锁定状态 / 启动校验
  （Verified 等）/ Boot Hash / 系统·厂商·内核三项补丁日期** —— 服务端直接解析 B 端回包里的证书链，
  不改协议、不加轮询。
- **内置 PathMask 内核模块**（官方 v2.8.0 资产，7 个内核系列变体，构建期校验 sha256）：
  开机按 `uname -r` 的 主.次 选型加载（不看补丁号，仅 arm64）；先探测 SoterService 的 binder 服务，
  正常就完全不动作，探测不到才以 `scope_mode=global` 隐藏 `/system/priv-app/SoterService`。
  全程 3 秒内完成、不阻塞开机；检测到别的 pathmask 实例时默认不抢占（`pathmask_takeover=1` 可接管）。

## 1.3.1

- **A 端 `ommegadata` 自愈**：若 `/data/adb/ommega/ommegadata` 被旧版本或手工操作留成真目录（或杂散文件），
  开机时会把其中的 `config` / `target.txt` / `system_app` / `keybox.xml`（较新者胜）迁移进
  `/data/misc/keystore/ommega`，再把该路径替换为符号链接。此前这种情况下 WebUI 保存的远程配置与应用列表
  会写进没人读的影子文件，且不报错（表现为：改了配置却不生效、请求被负载均衡到别的 B 端）。
- 启动属性对齐：`resetprop sys.oem_unlock_allowed 0`、`resetprop ro.secureboot.devicelock 1`。
- `module.prop` 增加 `updateJson`，模块管理器可直接检查更新。

## 1.3.0

- 远程 TEE 转发（A/B 端）、StrongBox 三段模式、Auto Keybox 等，见仓库提交记录。

更早版本见：https://github.com/jiyin004-jpg/ommega/commits/master
