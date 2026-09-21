# Ommega

Ommega 是一个三端远程 TEE 认证系统：让一台设备（B 端）的真实硬件 TEE 能力通过网络提供给另一台设备（A 端）使用。A 端应用发起的密钥认证（attestation）、签名（sign）、解密（decrypt）请求，经过 server 中转调度，由 B 端设备的真实硬件 TEE（KeyMint / StrongBox）执行并返回结果，从而为 A 端应用提供真实可信的硬件级安全认证。

源码版本：1.4.2（打包日期：2026-09-21）

## 系统组成

| 端 | 角色 | 形态 | 安装方式 |
|----|------|------|----------|
| **A 端（a-side）** | 服务请求端。keymint 守护进程 + inject 注入器拦截本机 keystore 调用，将认证/签名/解密请求转发到远程 B 端真实 TEE | Magisk 模块（arm64-v8a / armeabi-v7a / x86 / x86_64） | Magisk / KernelSU 刷入 zip |
| **B 端（b-side）** | 服务提供端。relay 守护进程长轮询 server 领取任务，调用本机真实硬件 TEE 执行认证/签名/解密并回传结果 | Magisk 模块（arm64-v8a / x86_64） | Magisk / KernelSU 刷入 zip |
| **B 端 App（b-app）** | B 端管理界面，用于查看设备状态、配置连接参数 | Android APK | 直接安装 APK |
| **Server（server）** | 中转与调度中心。任务队列、设备管理、卡片计费、密钥盒（keybox）管理、在线设备状态展示 | 独立二进制 | Linux x86_64 / Windows x86_64 部署 |

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
| 设备 ID（B 端默认） | `device-b-2` |

### B 端配置（b-side 模块 + b-app）

1. 安装 `client-b-app-release.apk`，刷入 `ommegaclient-b-release-1.3.1.zip` 并重启（该 zip 同时包含 arm64-v8a 与 x86_64，安装时按设备架构自动选）
2. 编辑 `/data/adb/ommega/relay.conf`，填入官方配置：

```
OMMEGA_RELAY_SERVER=http://110.40.170.96:10886
OMMEGA_RELAY_DEVICE_ID=device-b-2
OMMEGA_RELAY_TOKEN=Mytju8b0_lhLlqTKcEUhuwSbAsAtjom0
```

3. 执行 `touch /data/adb/ommega/restart.all` 重启 relay 服务

### A 端配置（a-side 模块）

1. 刷入 `ommega-a-release-1.4.2.zip` 并重启（该 zip 同时包含 arm64-v8a / armeabi-v7a / x86 / x86_64，安装时按设备架构自动选择）
2. 编辑 `/data/adb/ommega/ommegadata/config`（或模块 WebUI 中配置），填入官方配置：

```
url: http://110.40.170.96:10886
token: aY7kRSDDR6PMmamlKwtgf7mQgr-X5uFd
device_id: device-b-2
tls_insecure: true
remote: on
```

> ⚠️ 路径注意：`ommegadata` 是指向 `/data/misc/keystore/ommega` 的软链，守护进程真正读的就是
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
├── a-side/                  # A 端（Magisk 模块）
│   ├── source/              #   Rust 源码（keymint 守护进程 + ommega-inject 注入器）
│   └── build/               #   ommega-a-release-1.4.2.zip 安装包（arm64-v8a + armeabi-v7a + x86 + x86_64）
├── b-side/                  # B 端（Magisk 模块）
│   ├── source/              #   Rust 源码（relay 守护进程）
│   └── build/               #   ommegaclient-b-release-1.3.1.zip 安装包（arm64-v8a + x86_64）
├── b-app/                   # B 端 Android App（Kotlin 工程）
│   ├── source/              #   app 源码 + Gradle 配置
│   └── build/               #   client-b-app-release.apk
└── server/                  # 服务端
    ├── source/              #   Rust 源码 + 运维脚本
    └── build/               #   relay_rs-linux-x86_64-musl / relay_rs-windows-x86_64-msvc.exe
```

### Server 部署

1. 按系统选择二进制：
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

## 参考项目

Ommega 参考并借鉴了以下开源项目，在此致谢（排名不分先后）：

| 项目 | 作者 | GitHub |
|------|------|--------|
| Tricky Store | 5ec1cff | [5ec1cff/TrickyStore](https://github.com/5ec1cff/TrickyStore) |
| Tricky Addon | KOWX712 | [KOWX712/Tricky-Addon-Update-Target-List](https://github.com/KOWX712/Tricky-Addon-Update-Target-List) |
| OhMyKeymint | James Clef（qwq233） | [qwq233/OhMyKeymint](https://github.com/qwq233/OhMyKeymint) |
| KeyAttestation | vvb2060 | [vvb2060/KeyAttestation](https://github.com/vvb2060/KeyAttestation) |
| TEESimulator-RS | Enginex0 | [Enginex0/TEESimulator-RS](https://github.com/Enginex0/TEESimulator-RS) |

## 交流与支持

QQ 群：**2167063739**
