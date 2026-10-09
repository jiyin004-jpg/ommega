# Ommega B-side Relay (module id `ommega-b`)

[中文](README.zh-CN.md)

B-side relay agent for the ommega remote-TEE attestation setup.

This build has been stripped down to the **new B-side relay agent** only. It no
longer ships the software keystore body (`keymint` daemon), the `injector`
(keystore2 hook), software keybox attestation, or any A-side components. It
exists for one purpose: receive a task from the relay_server, call the **real
on-device hardware TEE** to mint an attestation certificate chain embedding a
caller-supplied application id (tag 709), and forward the result back.

## What is this?

The device this module is installed on acts as the **B-side** of a remote TEE
attestation setup. A companion A-side device (whose own TEE no longer serves
after unlocking the bootloader) asks the relay_server for valid, hardware-TEE
attestation. The server pushes the request as a task to this device; the `relay`
daemon executes it against the real TEE and returns the certificate chain so the
A-side device can pass Google Play Integrity.

## Install and configure

**Android 12 or above required.**

1. Install this module.
2. Edit `/data/adb/ommega/relay.conf` (first installed from `template/relay.conf`):

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

- `OMMEGA_RELAY_SERVER` — base URL of the relay_server (required; both `http://`
  and `https://` are supported, and the relay accepts self-signed certs).
- `OMMEGA_RELAY_DEVICE_ID` — this B-side device's id as registered on the
  relay_server (required).
- `OMMEGA_RELAY_MACHINE_ID` — machine id used in the `b/poll` query (optional).
- `OMMEGA_RELAY_TOKEN` — B-side token sent as `X-Relay-Token` (required).
- All four logging keys are managed in one place (`relay.conf`), read at relay
  startup, **not** hot-reloaded; `touch /data/adb/ommega/restart.all` (or
  reboot) applies a change:
  - `OMMEGA_RELAY_LOG_ENABLED` — `true` writes `/data/adb/ommega/logs/relay.log`
    (default), `false` disables the file log.
  - `OMMEGA_RELAY_LOG_LEVEL` — file log level when enabled:
    `off|error|warn|info|debug|trace` (default `debug`).
  - `OMMEGA_RELAY_LOGCAT_ENABLED` — `true` keeps Android logcat output (tag
    `ommega-b`, default), `false` silences logcat completely.
  - `OMMEGA_RELAY_LOGCAT_LEVEL` — logcat level:
    `off|error|warn|info|debug|trace` (default `info`).

3. The relay **hot-reloads config at runtime**: a background thread inside the
   `relay` process watches `relay.conf` for changes and the `restart.all`
   marker, and updates the live config in place — **no process restart needed**.
   To force an immediate reload
   after editing the file:

```sh
touch /data/adb/ommega/restart.all
```

## Relay daemon

The module ships one daemon, `relay`. It is started directly by
`service.sh` (which kills stale instances first, then spawns a fresh one). The
`relay` process itself monitors `/data/adb/ommega/relay.conf` and reloads on
change; the wrapper never kills it, so the two never conflict.

Logs go to logcat (tag `ommega-b`) and `/data/adb/ommega/logs/relay.log`.
Each poll, config reload, task receipt, task outcome (with duration), and
`b/result` submission is logged.

B-side protocol implemented: `GET /api/b/poll/` + `POST /api/b/result/`.

Task types handled: `attest`, `sign`, and `decrypt`.

## License

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

## Credit

Some code from [AOSP](https://source.android.com/)

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
