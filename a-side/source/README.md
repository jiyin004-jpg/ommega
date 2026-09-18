# Ommega A-side Relay

Custom keystore implementation for remote TEE attestation relay (A-side).

This is a full keystore implementation that fully implements the AOSP AIDL
interface. It runs on the A-side device and, when remote mode is enabled,
forwards attestation / sign / decrypt to a B-side real hardware TEE through the
relay_server.

## How it works

- **Local mode** (`remote: false`): uses the bundled software keybox to mint
  attestation chains, like a regular keystore spoofer.
- **Remote mode** (`remote: true`): attestation (tag 709) is minted by the
  B-side real hardware TEE via the relay_server. Sign/decrypt for remote keys
  are forwarded too. Falls back to local when the relay is unreachable
  (`fallback_local`).

## Install and configure

**Android 12 or above required.**

1. Install this module (KernelSU/APatch, or Magisk).

2. Configure `/data/adb/ommega/ommegadata/config` (the single shared A-side
   config; `ommegadata` is a symlink to `/data/misc/keystore/ommega`, which is
   the path the daemon actually reads):

   ```
   url: http://<relay-server>:<port>
   device_id: <b-side-device-id>
   token: <relay-token>
   remote: true
   local_hw: true
   tls_insecure: true
   debug_logging: false
   ```

3. Add the apps you want to intercept to `/data/adb/ommega/ommegadata/target.txt`
   (one package per line; `!` = force generate, `?` = force patch). The WebUI
   (`webroot/`) manages this for you under KernelSU.

4. Replace the template `keybox.xml` if you want local-mode attestation with
   your own keys.

> **Path note**: `/data/adb/` is root-only, so the keystore process (uid 1017)
> cannot read `/data/adb/ommega/*` directly. The single data location is
> `/data/misc/keystore/ommega/`, exposed at `/data/adb/ommega/ommegadata`
> (a symlink created by `post-fs-data.sh`). `config` and `target.txt` are read
> from there — **nothing reads `/data/adb/ommega/config` or
> `/data/adb/ommega/target.txt`** (there is no sync/copy step; a file written
> at that path is silently ignored). Both files are watched, so edits take
> effect without a reboot.
>
> Editing by hand? Use `/data/adb/ommega/ommegadata/config`, or just toggle it
> in the module WebUI, which writes through the symlink.

### Global scope (intercept every caller)

`global_scope: true` in that same `config` file — or the checkbox in the
WebUI's remote-config dialog — makes the injector handle **every** caller: the
`scoop` list, `target.txt`, `deny_packages`, the android-package rule and the
unknown-package rule are all skipped. `[filter].enabled = false` remains the
only way to turn interception off completely.

It is re-read on every event, so toggling it takes effect immediately, with no
restart of the injector or keystore2. Whether a handled request is served
locally or by the remote relay is decided elsewhere and does **not** change
with this switch.

### Bundled PathMask kernel module (`kmod-loader.sh`)

The module ships the official PathMask `.ko` builds (see
`template/pathmask/UPSTREAM.md`) and loads one at boot from `service.sh`:

* the kernel's **major.minor** (`uname -r`, e.g. `6.1.145-android14-11` → `6.1`)
  selects the candidate; the patch level is ignored, and when a series has
  several official Android variants they are tried in order;
* the SoterService binder is probed for at most ~2 s (whole run < 3 s): if it
  answers, nothing is masked and any mask this module installed earlier is
  removed; if it does not, `/system/priv-app/SoterService` is masked with
  `scope_mode=global`;
* an already-loaded `pathmask` instance that this module did not load is left
  untouched (set `pathmask_takeover: 1` to take it over).

Outcome is written to `/data/adb/ommega/pathmask.state`, the full log to
`/data/adb/ommega/kmod-loader.log`. Optional keys, read from the same `config`
file: `soter_hide: 0` (disable), `soter_hide_prefer: skip` (keep the path
visible when the probe cannot reach the service), `pathmask_target: <path>`,
`soter_service: <comma,separated,binder/names>`, `soter_package: <pkg>`.
For a dry run (logs decisions, never touches `/proc/modules`):
`KMOD_DRY_RUN=1 sh /data/adb/modules/ommega/kmod-loader.sh`.

## Restarting keymint and injector

The module ships two background daemons: one for `keymint`, one for `injector`.
Restart them with:

```sh
touch /data/adb/ommega/restart.keymint
touch /data/adb/ommega/restart.injector
touch /data/adb/ommega/restart.all
```

## License

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
