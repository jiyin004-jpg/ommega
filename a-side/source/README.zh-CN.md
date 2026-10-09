# Ommega A 端中继（A-side Relay）

[English](README.md)

这是远程 TEE 认证中继的 A 端 keystore 实现：一份完整实现 AOSP AIDL 接口的 keystore
实现，跑在 A 端设备上；开启远程模式后，把 attestation / sign / decrypt 经
relay_server 转发到 B 端的真实硬件 TEE 执行。

## 工作原理

- **本地模式**（`remote: false`）：用随包附带的软件 keybox 生成认证链，跟一般的
  keystore 伪造模块一样。
- **远程模式**（`remote: true`）：attestation（tag 709）由 B 端真实硬件 TEE 经
  relay_server 生成；远程密钥的 sign / decrypt 同样转发。中继不可达时回落到本地
  （`fallback_local`）。

## 安装与配置

**需要 Android 12 或以上。**

1. 安装本模块（KernelSU / APatch，或者 Magisk）。

2. 配置 `/data/adb/ommega/ommegadata/config`（A 端唯一那份共用配置；`ommegadata`
   是指向 `/data/misc/keystore/ommega` 的软链，守护进程真正读的就是那个路径）：

   ```
   url: http://<relay-server>:<port>
   device_id: <b-side-device-id>
   token: <relay-token>
   remote: true
   local_hw: true
   tls_insecure: true
   debug_logging: false
   ```

   `bind_iface` 是可选项（默认 `auto`）：没有 VPN 起来时什么都不绑，交给系统自己跟着
   网络走；有 VPN 时守护进程会去找一条真能到中继的出口 —— 先看物理链路，靠一次短的
   可达性探测决定，而不是看接口名 —— 一条都不通就保持不绑。`none` 从不绑，`always`
   每次都探，其他值按接口名处理。

3. 把要接管的 App 加到 `/data/adb/ommega/ommegadata/target.txt`（一行一个包名；
   `!` = 强制生成，`?` = 强制打补丁）。KernelSU 下用 WebUI（`webroot/`）管它也成。

4. 想让本地模式用你自己的密钥认证，就把模板里的 `keybox.xml` 换掉。

> **路径注意**：`/data/adb/` 只有 root 进得去，所以 keystore 进程（uid 1017）读不了
> `/data/adb/ommega/*`。唯一的数据位置是 `/data/misc/keystore/ommega/`，在
> `/data/adb/ommega/ommegadata` 这层露出（`post-fs-data.sh` 建的软链）。`config` 和
> `target.txt` 都是从那里读的 —— **没有任何东西会读
> `/data/adb/ommega/config` 或 `/data/adb/ommega/target.txt`**（不存在同步或拷贝那一步，
> 写在那两个路径上的文件是被静默忽略的）。这两个文件都有 watch，改完不用重启。
>
> 手动改？就用 `/data/adb/ommega/ommegadata/config`，或者干脆在模块 WebUI 里点 ——
> WebUI 就是通过那个软链写进去的。

### 全局接管（`global_scope`）

同一个 `config` 里写 `global_scope: true`（或者在 WebUI 的远程配置对话框里勾上），
注入器就会处理**每一个**调用方：`scoop` 列表、`target.txt`、`deny_packages`、
安卓包名规则和未知包名规则全部跳过。想彻底关掉接管，只剩
`[filter].enabled = false` 这一条路。

它是每条事件现读的，所以开关立即生效，不用重启注入器或 keystore2。一笔被接管的请求
最后由本地还是远程中继来答复，是别处决定的，**不**随这个开关变。

### 随包附带的 PathMask 内核模块（`kmod-loader.sh`）

模块里带着官方 PathMask 的 `.ko` 构建（见 `template/pathmask/UPSTREAM.md`），开机时由
`service.sh` 加载其中一个：

* 内核的 **major.minor**（`uname -r`，例如 `6.1.145-android14-11` → `6.1`）决定候选；
  patch 级别不看，一系列有多个官方 Android 版本时按顺序试；
* 探测 SoterService binder 最多约 2 秒（整轮 < 3 秒）：答得上就什么都不遮，并且把本模块
  之前装过的遮罩撤掉；答不上就用 `scope_mode=global` 把
  `/system/priv-app/SoterService` 遮起来；
* 已经加载、但不是本模块加载的 `pathmask` 实例不碰（想接管就设
  `pathmask_takeover: 1`）。

WebUI 上的 **Mask SOTER** 开关（平铺配置键 `soter_hide`，默认关）管着整套行为：
开关关着时加载器不会去加载内核模块，并且会把本模块自己那份还挂着的遮罩撤掉，服务就重新
可见。这个开关必须显式打开，配置里没有这个键就是关。其他可选键也从同一个 `config` 读：
`soter_hide_prefer: skip`（探测够不到服务时保持路径可见）、`pathmask_target: <path>`、
`soter_service: <逗号分隔的,binder,名>`、`soter_package: <pkg>`。
想空跑（只记决策、绝不碰 `/proc/modules`）：
`KMOD_DRY_RUN=1 sh /data/adb/modules/ommega/kmod-loader.sh`；再加
`KMOD_CONF_PATH=/path/to/config` 与 `KMOD_STATE_DIR=/some/scratch/dir`，就能拿一份临时
配置试，而不动真状态。

## 重启 keymint 与 injector

模块带两个后台守护：一个管 `keymint`，一个管 `injector`。重启用：

```sh
# 只换影子 TA：keystore2 不重启
touch /data/adb/ommega/restart.keymint
# 只换注入载荷：keystore2 会被替换并重新注入
touch /data/adb/ommega/restart.injector
# 两个都换
touch /data/adb/ommega/restart.all
```

**能用小的就别用大的。** keystore2 里那份载荷是唯一拿着框架解锁材料的地方（auth-bound
密钥背后的 LSKF 材料），换掉 keystore2 会让之后每一次 auth-bound 密钥初始化都回
`LOCKED`，直到用户再解锁一次设备。只换了 `keymint` 二进制的话，
`restart.keymint` 就够，那份材料不受影响；`scripts/deploy_hot_update.py` 会按「到底哪个
二进制变了」自动选目标（`--restart auto`，默认）。

## 开源许可

`AGPL-3.0-or-later`

```plaintext
ommega - Custom keymint implementation for Android Keystore Spoofer
Copyright (C) 2025 jiyin004

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
```

## 致谢

部分代码来自 [AOSP](https://source.android.com/)

License: `Apache-2.0`

```plaintext
Copyright 2022, The Android Open Source Project

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
