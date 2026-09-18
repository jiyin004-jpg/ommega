# 更新日志

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
