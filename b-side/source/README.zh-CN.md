# Ommega B 端中继（模块 id `ommega-b`）

[English](README.md)

远程 TEE 认证方案里的 B 端中继代理。

这份构建只保留了**新的 B 端中继代理**：不再带软件 keystore 主体（`keymint` 守护）、
`injector`（keystore2 钩子）、软件 keybox 认证，也不带任何 A 端组件。它只做一件事 ——
从 relay_server 领一个任务，调用**设备上真实的硬件 TEE** 生成一条内嵌调用方指定的
application id（tag 709）的认证证书链，再把结果回传。

## 这是什么

装了这个模块的设备，就是远程 TEE 认证方案里的 **B 端**。一台配套的 A 端设备（解锁
bootloader 之后它自己的 TEE 不再提供正常服务）会向 relay_server 要一份有效的硬件 TEE
认证。服务器把这份请求当作任务推给本机；`relay` 守护拿真实 TEE 执行，把证书链回传，
A 端设备就能过 Google Play Integrity。

## 安装与配置

**需要 Android 12 或以上。**

1. 安装本模块。
2. 编辑 `/data/adb/ommega/relay.conf`（首次安装时从 `template/relay.conf` 生成）：

```ini
OMMEGA_RELAY_SERVER=https://<relay-server>:8443
OMMEGA_RELAY_DEVICE_ID=device-b-2
OMMEGA_RELAY_MACHINE_ID=
OMMEGA_RELAY_TOKEN=<relay-token>
OMMEGA_RELAY_LOG_ENABLED=true
OMMEGA_RELAY_LOG_LEVEL=debug
OMMEGA_RELAY_LOGCAT_ENABLED=true
OMMEGA_RELAY_LOGCAT_LEVEL=info
```

- `OMMEGA_RELAY_SERVER` —— relay_server 的基地址（必填；`http://` 和 `https://` 都
  支持，中继也接受自签证书）。
- `OMMEGA_RELAY_DEVICE_ID` —— 本 B 端设备在 relay_server 上注册的 id（必填）。
- `OMMEGA_RELAY_MACHINE_ID` —— `b/poll` 查询里带的机器 id（可选）。
- `OMMEGA_RELAY_TOKEN` —— B 端 token，放在 `X-Relay-Token` 里发（必填）。
- 四个日志键统一在一处（`relay.conf`）管，中继启动时读一次，**不**热重载；
  `touch /data/adb/ommega/restart.all`（或者重启）才会生效：
  - `OMMEGA_RELAY_LOG_ENABLED` —— `true` 写 `/data/adb/ommega/logs/relay.log`
    （默认），`false` 关掉文件日志。
  - `OMMEGA_RELAY_LOG_LEVEL` —— 文件日志级别（开着时）：
    `off|error|warn|info|debug|trace`（默认 `debug`）。
  - `OMMEGA_RELAY_LOGCAT_ENABLED` —— `true` 保留 Android logcat 输出（tag
    `ommega-b`，默认），`false` 让 logcat 彻底安静。
  - `OMMEGA_RELAY_LOGCAT_LEVEL` —— logcat 级别：
    `off|error|warn|info|debug|trace`（默认 `info`）。

3. 中继**运行时热重载配置**：`relay` 进程里有一个后台线程盯着 `relay.conf` 和
   `restart.all` 标记，就地更新活配置 —— **不用重启进程**。改完文件想立刻生效：

```sh
touch /data/adb/ommega/restart.all
```

## 中继守护

模块只带一个守护：`relay`，由 `service.sh` 直接启动（先杀掉残留实例，再起一个新的）。
`relay` 进程自己盯着 `/data/adb/ommega/relay.conf`，变了就重载；外层包装不会去杀它，
所以两者不会互相打架。

日志进 logcat（tag `ommega-b`）和 `/data/adb/ommega/logs/relay.log`。每次轮询、配置
重载、收到任务、任务结果（带耗时）、以及 `b/result` 提交都会记一条。

实现的 B 端协议：`GET /api/b/poll/` + `POST /api/b/result/`。

处理的任务类型：`attest`、`sign`、`decrypt`。

## 开源许可

`AGPL-3.0-or-later`

```plaintext
ommega-b - B-side relay agent for the ommega remote-TEE attestation setup
Copyright (C) 2026 ommegaclient

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
