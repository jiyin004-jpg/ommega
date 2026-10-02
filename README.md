# Ommega

Ommega 是一个三端远程 TEE 认证系统：A 端是服务请求端，B 端提供真实硬件 TEE 能力，server 在中转调度。A 端应用发起的密钥认证（attestation）、签名（sign）、解密（decrypt）请求，经 server 转发到 B 端，由本机真实硬件 TEE（KeyMint / StrongBox）执行后原样回传。B 端另有一套配套的管理 App（b-app）。

当前版本与下载见 [Releases](https://github.com/jiyin004-jpg/ommega/releases) 页面。

## 系统组成

| 端 | 角色 | 形态 | 安装方式 |
|----|------|------|----------|
| **A 端（a-side）** | 服务请求端。keymint 守护进程 + inject 注入器拦截本机 keystore 调用，转发到远程 B 端 | Magisk 模块（arm64-v8a / armeabi-v7a / x86 / x86_64） | Magisk / KernelSU 刷入 zip |
| **B 端（b-side）** | 服务提供端。relay 守护进程长轮询 server 领任务，交给本机硬件 TEE 执行后回传 | Magisk 模块（arm64-v8a / x86_64） | Magisk / KernelSU 刷入 zip |
| **服务端（server）** | 中转与调度中心。任务队列、设备管理、卡片计费、密钥盒管理、在线状态页 | 独立二进制 | Linux x86_64 / Windows x86_64 部署 |
| **B 端 App（b-app）** | B 端的配套管理界面，看设备状态、配连接参数 | Android APK | 直接安装 APK |

## 主要功能

- **真实硬件 TEE 远程认证**：B 端使用真实 KeyMint / StrongBox 生成 attestation 证书链，A 端应用获得真实硬件安全级别（StrongBox / TEE）的认证结果
- **远程签名与解密**：A 端密钥操作完整转发到 B 端真实 TEE 执行
- **KeyMint 版本自适应**：自动探测并兼容不同 Android 版本的 KeyMint HAL 接口
- **StrongBox 优先与降级策略**：优先使用 StrongBox 安全级别，按策略处理不可用场景
- **在线设备状态页**：server 提供公开的设备在线状态展示界面
- **卡片计费体系**：server 内置卡片购买、激活与用量管理
- **管理后台**：设备管理、任务查看、密钥盒上传与自动刷新

## 快速使用（官方在线服务）

不想自己搭建的话，直接使用官方在线服务即可，以下配置填入即用：

| 项目 | 值 |
|------|-----|
| 在线设备展示 | `http://110.40.170.96:10886/status/` |
| 配置 URL（A 端 / B 端 / App 统一填写） | `http://110.40.170.96:10886` |
| A 端 Token | `aY7kRSDDR6PMmamlKwtgf7mQgr-X5uFd` |
| B 端 Token | `Mytju8b0_lhLlqTKcEUhuwSbAsAtjom0` |
| 设备 ID（B 端默认，也是官方预注册的那台） | `device-b-2` |

### B 端配置（b-side 模块 + b-app）

1. 安装 [Releases](https://github.com/jiyin004-jpg/ommega/releases) 里的 `client-b-app-release.apk`，刷入同页的 `ommega-b-release-<版本>.zip` 并重启（该 zip 同时包含 arm64-v8a 与 x86_64，安装时按设备架构自动选）
2. 编辑 `/data/adb/ommega/relay.conf`，填入官方配置：

```
OMMEGA_RELAY_SERVER=http://110.40.170.96:10886
OMMEGA_RELAY_DEVICE_ID=device-b-2
OMMEGA_RELAY_TOKEN=Mytju8b0_lhLlqTKcEUhuwSbAsAtjom0
```

3. 执行 `touch /data/adb/ommega/restart.all` 重启 relay 服务

### A 端配置（a-side 模块）

1. 刷入 [Releases](https://github.com/jiyin004-jpg/ommega/releases) 里的 `ommega-a-release-<版本>.zip` 并重启（该 zip 同时包含 arm64-v8a / armeabi-v7a / x86 / x86_64，安装时按设备架构自动选择）
2. 编辑 `/data/adb/ommega/ommegadata/config`（或模块 WebUI 中配置），填入官方配置：

```
url: http://110.40.170.96:10886
token: aY7kRSDDR6PMmamlKwtgf7mQgr-X5uFd
device_id: device-b-2
tls_insecure: true
remote: on
```

> 路径注意：`ommegadata` 是指向 `/data/misc/keystore/ommega` 的软链，守护进程真正读的就是
> `/data/misc/keystore/ommega/config`。**没有 `ommegadata` 那一层**的
> `/data/adb/ommega/config` 是另一个文件，写了不生效（改完不用重启，配置有 watch）。

配置后 A 端认证/签名/解密请求即通过官方 server 中转，由在线 B 端设备的真实 TEE 执行。
`device_id` 必须是**当前在线**那台 B 端的设备 ID（在 `/status/` 页面的「在线 B 端设备」里核对；
只在「已保存证书的设备」里出现不算在线）。指定设备不在线时，服务器会把任务派给**当前最闲的在线 B 端**
（真机层允许由别的 B 端顶替），并把实际派发写进日志——这时你拿到的证书链就是那台顶替设备的，
所以别拿一个离线 ID 当目标。

## 自行部署

### 目录结构

```
ommega/
├── .github/workflows/       # CI：三端 fmt / clippy / 测试门禁
├── .cargo-husky/hooks/      # 提交前钩子脚本（由 cargo-husky 装到 .git/hooks，只查格式）
├── a-side/source/           # A 端（Magisk 模块）Rust 源码：keymint 守护进程 + ommega-inject 注入器
├── b-side/source/           # B 端（Magisk 模块）Rust 源码：relay 守护进程
├── b-app/source/            # B 端 Android App（Kotlin + Gradle）
├── server/source/           # 服务端 Rust 源码 + 运维脚本
└── VERSION                  # 三端共用的版本号
```

仓库只保存源码与文档，构建产物（模块 zip、APK、服务端二进制）一律以 Release 附件形式发布。

### 服务端部署

1. 从 [Releases](https://github.com/jiyin004-jpg/ommega/releases) 下载对应二进制：
   - Linux x86_64：`relay_rs-linux-x86_64-musl`（musl 静态编译，无 libc 依赖，`chmod +x` 后直接运行）
   - Windows x86_64：`relay_rs-windows-x86_64-msvc.exe`
2. 参考 `server/source/.env.pay.example` 的格式创建并配置 `.env`：RELAY_TOKEN、MySQL 连接、TLS 证书、HTTP/HTTPS 端口（默认 10886 / 8443）
3. 运行二进制即完成部署，管理后台与设备状态页自动可用

### 模块与 App 构建

- A/B 端模块：在 `a-side/source`、`b-side/source` 下执行 `python build.py --release` 生成 zip。
  默认产出一个**包含全部受支持 ABI 的单一 zip**（A 端 arm64-v8a / armeabi-v7a / x86 / x86_64，
  B 端 arm64-v8a / x86_64），安装时由模块的 `customize.sh` 检查设备架构并释放对应的
  `libs/<abi>/` 二进制；运行时守护脚本也按 `ro.product.cpu.abi` 选二进制，不靠目录顺序。
  用 `--abi <name>` 可只把指定 ABI 打进包里（仍是单包，可重复传），`--split` 才会每个 ABI 各出一个 zip。
- B 端 App：在 `b-app/source` 下执行 Gradle 构建生成 APK

构建完成后把 zip / APK / 服务端二进制作为 Release 附件上传即可，不需要提交进仓库。

> 开发提示：`b-side` 依赖 `rsproperties`，它只对 Linux / Android target 生效，所以在
> Windows 上直接跑裸 `cargo check`（不带 `--target`）会编译失败，看着像代码坏了。
> 加上目标平台就行：`cargo check --target aarch64-linux-android`（需先设好 NDK 环境变量
> `ANDROID_NDK_ROOT` / `ANDROID_NDK_HOME`）。A 端与 server 没有这个限制。

## 开发门禁

三个工作区各自独立，CI（`.github/workflows/ci.yml`）对每个都跑同一套：`cargo clippy` 带
`-D warnings`、`cargo fmt --all -- --check`、以及测试。server 是 host 目标，测试真跑；
A / B 端只能编到 `aarch64-linux-android`，CI 里只编测试二进制（`--no-run`），真机上跑那步由人工完成。
本地提交前另有一道轻量钩子，只查被改工作区的格式，脚本在仓库根的 `.cargo-husky/hooks/`。

A 端本地开发需要自备两项，缺了编译不过：

- `protoc`：`build.rs` 用 prost 把 `proto/storage.proto` 生成到 `src/proto/`（生成物不入库）
- `a-side/source/ommega-injector/assets/soter_ask.pem`：本地兜底 ASK 私钥，被 `.gitignore` 的
  `**/*.pem` 排掉、不进仓库，但 injector 的 `include_bytes!` 要求它在场。CI 里是现生成一把
  编译占位顶上的，它不参与任何发布产物

## 参考项目

Ommega 参考并借鉴了以下开源项目，在此致谢（排名不分先后）：

| 项目 | 作者 | GitHub |
|------|------|--------|
| Tricky Store | 5ec1cff | [5ec1cff/TrickyStore](https://github.com/5ec1cff/TrickyStore) |
| Tricky Addon | KOWX712 | [KOWX712/Tricky-Addon-Update-Target-List](https://github.com/KOWX712/Tricky-Addon-Update-Target-List) |
| OhMyKeymint | James Clef（qwq233） | [qwq233/OhMyKeymint](https://github.com/qwq233/OhMyKeymint) |
| KeyAttestation | vvb2060 | [vvb2060/KeyAttestation](https://github.com/vvb2060/KeyAttestation) |
| TEESimulator-RS | Enginex0 | [Enginex0/TEESimulator-RS](https://github.com/Enginex0/TEESimulator-RS) |
| PathMask | Andrea-lyz | [Andrea-lyz/LKM-PathMask](https://github.com/Andrea-lyz/LKM-PathMask) |

## 交流与支持

QQ 群：**2167063739**
