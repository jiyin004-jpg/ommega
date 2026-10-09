# Ommega

[中文说明](README.md)

Ommega is a three-part remote TEE attestation system: the A side issues the requests, the B side provides real hardware TEE capability, and the server relays and schedules between them. Attestation, signing and decryption requests made by apps on the A side are forwarded through the server to the B side, executed by that machine's real hardware TEE (KeyMint / StrongBox), and returned unchanged. The B side also has a companion management app (b-app).

Current version and downloads are on the [Releases](https://github.com/jiyin004-jpg/ommega/releases) page.

## Components

| Part | Role | Form | Install |
|------|------|------|---------|
| **A side (a-side)** | Request side. A keymint daemon plus an injector intercepts this machine's keystore calls and forwards them to the remote B side | Magisk module (arm64-v8a / armeabi-v7a / x86 / x86_64) | Flash the zip with Magisk / KernelSU |
| **B side (b-side)** | Provider side. A relay daemon long-polls the server for tasks and hands them to the local hardware TEE, then returns the result | Magisk module (arm64-v8a / x86_64) | Flash the zip with Magisk / KernelSU |
| **Server** | Relay and scheduling. Task queue, device management, card billing, keybox management, public status page | Standalone binary | Deploy on Linux x86_64 / Windows x86_64 |
| **B-side app (b-app)** | Management UI for the B side: device status, connection settings | Android APK | Install the APK directly |

## Features

- **Remote attestation on real hardware TEE**: the B side generates the attestation certificate chain with its real KeyMint / StrongBox, so apps on the A side get genuinely hardware-backed security levels (StrongBox / TEE)
- **Remote signing and decryption**: key operations on the A side are forwarded in full and executed inside the B side's real TEE
- **KeyMint version adaptation**: detects and supports the KeyMint HAL interface of different Android versions
- **StrongBox first, with a fallback policy**: prefers the StrongBox security level and handles the unavailable case according to policy
- **Public device status page**: the server exposes a public page showing which devices are online
- **Card billing**: card purchase, activation and usage accounting built into the server
- **Admin backend**: device management, task inspection, keybox upload and automatic refresh

## Quick start (official online service)

If you would rather not host anything yourself, just use the official online service — the settings below are ready to use:

| Item | Value |
|------|-------|
| Online device status | `http://110.40.170.96:10886/status/` |
| Config URL (same for A side / B side / app) | `http://110.40.170.96:10886` |
| A-side token | `aY7kRSDDR6PMmamlKwtgf7mQgr-X5uFd` |
| B-side token | `Mytju8b0_lhLlqTKcEUhuwSbAsAtjom0` |
| Device ID (B-side default, and the machine pre-registered on the official service) | `device-b-2` |

### B-side setup (b-side module + b-app)

1. Install `client-b-app-release.apk` from [Releases](https://github.com/jiyin004-jpg/ommega/releases), flash `ommega-b-release-<version>.zip` from the same page and reboot (one zip carries both arm64-v8a and x86_64; the installer picks the one matching the device)
2. Edit `/data/adb/ommega/relay.conf` and fill in the official settings:

```
OMMEGA_RELAY_SERVER=http://110.40.170.96:10886
OMMEGA_RELAY_DEVICE_ID=device-b-2
OMMEGA_RELAY_TOKEN=Mytju8b0_lhLlqTKcEUhuwSbAsAtjom0
```

3. Run `touch /data/adb/ommega/restart.all` to restart the relay service

### A-side setup (a-side module)

1. Flash `ommega-a-release-<version>.zip` from [Releases](https://github.com/jiyin004-jpg/ommega/releases) and reboot (one zip carries arm64-v8a / armeabi-v7a / x86 / x86_64; the installer picks the one matching the device)
2. Edit `/data/adb/ommega/ommegadata/config` (or use the module's WebUI) and fill in the official settings:

```
url: http://110.40.170.96:10886
token: aY7kRSDDR6PMmamlKwtgf7mQgr-X5uFd
device_id: device-b-2
tls_insecure: true
remote: on
```

> Path note: `ommegadata` is a symlink to `/data/misc/keystore/ommega`, and the daemon really reads
> `/data/misc/keystore/ommega/config`. `/data/adb/ommega/config` — the path **without** the
> `ommegadata` level — is a different file, and writing there has no effect (no restart is needed
> after a change; the config is watched).

After that, attestation / signing / decryption requests on the A side go through the official server and are executed by the real TEE of an online B-side device. `device_id` must be the ID of a B-side device that is **currently online** (check it under "online B-side devices" on the `/status/` page; appearing only under "devices with certificates on file" does not mean online). When the named device is offline the server hands the task to **the idlest online B-side** instead (the real-device layer allows another B side to stand in) and records the actual assignment in the log — in that case the certificate chain you get is that stand-in's, so do not treat an offline ID as a target.

## Self-hosting

### Repository layout

```
ommega/
├── .github/workflows/       # CI: fmt / clippy / test gates for all three parts
├── .cargo-husky/hooks/      # pre-commit hook scripts (installed into .git/hooks by cargo-husky; format check only)
├── a-side/source/           # A-side (Magisk module) Rust sources: keymint daemon + ommega-inject payload
├── b-side/source/           # B-side (Magisk module) Rust sources: relay daemon
├── b-app/source/            # B-side Android app (Kotlin + Gradle)
├── server/source/           # server Rust sources + operations scripts
└── VERSION                  # version number shared by all three
```

The repository holds sources and documentation only; build products (module zips, APK, server binaries) are published exclusively as Release assets.

### Server deployment

1. Download the matching binary from [Releases](https://github.com/jiyin004-jpg/ommega/releases):
   - Linux x86_64: `relay_rs-linux-x86_64-musl` (static musl build, no libc dependency; `chmod +x` and run)
   - Windows x86_64: `relay_rs-windows-x86_64-msvc.exe`
2. Create and fill in `.env` following the format of `server/source/.env.pay.example`: RELAY_TOKEN, MySQL connection, TLS certificates, HTTP/HTTPS ports (default 10886 / 8443)
3. Run the binary and the deployment is done — the admin backend and the device status page are available immediately

### Building the modules and the app

- A/B modules: run `python build.py --release` under `a-side/source` and `b-side/source` to produce a zip.
  By default this yields a **single zip carrying every supported ABI** (A side: arm64-v8a / armeabi-v7a /
  x86 / x86_64; B side: arm64-v8a / x86_64). At install time `customize.sh` checks the device
  architecture and extracts the matching `libs/<abi>/` binaries; the runtime daemon scripts also pick
  their binary by `ro.product.cpu.abi` rather than by directory order. Use `--abi <name>` to include
  only the named ABI (still a single package, repeatable), and `--split` to emit one zip per ABI.
- B-side app: run `./gradlew :app:assembleRelease` under `b-app/source` to produce the APK (`gradlew.bat` on Windows)

After building, upload the zips / APK / server binaries as Release assets; they do not need to be committed.

> Development note: `b-side` depends on `rsproperties`, which only applies to Linux / Android targets,
> so a bare `cargo check` on Windows (without `--target`) fails and looks like broken code. Add the
> target: `cargo check --target aarch64-linux-android` (set `ANDROID_NDK_ROOT` / `ANDROID_NDK_HOME`
> first). The A side and the server have no such restriction.

## Development gates

The three workspaces are independent, and CI (`.github/workflows/ci.yml`) runs the same set for each:
`cargo clippy` with `-D warnings`, `cargo fmt --all -- --check`, and the tests. The server builds for
the host target, so its tests really run; the A / B sides only build for `aarch64-linux-android`, so CI
merely compiles the test binaries (`--no-run`) and running them on a real device stays a manual step.
A light pre-commit hook additionally checks the format of whichever workspace was touched; the scripts
live in `.cargo-husky/hooks/` at the repository root.

Local A-side development needs two extra things, without which it will not compile:

- `protoc`: `build.rs` uses prost to generate `proto/storage.proto` into `src/proto/` (the generated code is not committed)
- `a-side/source/ommega-injector/assets/soter_ask.pem`: the local-fallback ASK private key. It is
  excluded by the `.gitignore` rule `**/*.pem` and never enters the repository, but the injector's
  `include_bytes!` requires it to be present. CI generates a throwaway key on the spot to satisfy the
  compiler; it takes no part in any release artifact

## Credits

Ommega learned from and borrowed ideas from the following open-source projects (in no particular order):

| Project | Author | GitHub |
|---------|--------|--------|
| Tricky Store | 5ec1cff | [5ec1cff/TrickyStore](https://github.com/5ec1cff/TrickyStore) |
| Tricky Addon | KOWX712 | [KOWX712/Tricky-Addon-Update-Target-List](https://github.com/KOWX712/Tricky-Addon-Update-Target-List) |
| OhMyKeymint | James Clef (qwq233) | [qwq233/OhMyKeymint](https://github.com/qwq233/OhMyKeymint) |
| KeyAttestation | vvb2060 | [vvb2060/KeyAttestation](https://github.com/vvb2060/KeyAttestation) |
| TEESimulator-RS | Enginex0 | [Enginex0/TEESimulator-RS](https://github.com/Enginex0/TEESimulator-RS) |
| PathMask | Andrea-lyz | [Andrea-lyz/LKM-PathMask](https://github.com/Andrea-lyz/LKM-PathMask) |

## Community and support

QQ group: **2167063739**
