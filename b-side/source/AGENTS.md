# ommega-b Agent Guide

This repository is the **new B-side relay agent**. It receives tasks from the
relay_server (ommega-old), calls the **real on-device hardware TEE** to mint
attestation certificate chains that embed a caller-supplied application id
(tag 709), and forwards the result back. The software keystore body, the
`injector`, `ta/`, `crypto/` and related components have been removed.

## Project Boundaries

- Android is the only production and acceptance target. Target-specific build,
  check, and test commands must use `aarch64-linux-android`; host or x86_64
  success alone is insufficient.
- Compatibility scope: Android 12-17. Preserve behavior across this range.
- Do not introduce new non-Rust product or runtime code without explicit
  approval. Existing Python build/deployment scripts and shell packaging assets
  are tooling, not precedent for new runtime components.

## Review Scope

- Do not report or fix scenarios that require multiple independently abnormal,
  low-probability conditions and are unreachable through normal supported
  operation.
- When excluding such a scenario, state the concrete conditions that must
  coincide and why normal supported paths cannot reach it.

## Architecture

```
src/
├── lib.rs                     # crate root, AIDL generation (include!(aidl.rs))
├── logging.rs                 # relay daemon logging (/data/adb/ommega/logs/relay.log)
├── macros.rs                  # err! and related macros
├── bin/relay.rs               # B-side daemon: poll tasks -> execute -> post results
├── keymaster/
│   ├── relay_tee.rs           # minimal bridge to the real TEE
│   │                          #   (get_system_keymint, key_params_to_aidl, KEY_MINT_V*)
│   ├── attest_proxy.rs        # real-TEE attestation with caller-supplied appid (tag 709)
│   ├── tee_ops.rs             # TEE operation layer (generateKey/begin/update/finish/abort)
│   └── mod.rs
└── plat/
    └── aaid.rs                # AttestationApplicationId DER parsing (der crate only)
```

The relay daemon supports every task type the relay_server can dispatch:
`attest`, `sign`, and `decrypt`.

## Behavioral Invariants

### Real-TEE Attestation

- The real keymint HAL does **not** validate the `ATTESTATION_APPLICATION_ID`
  blob passed to `generateKey`; it only signs it into the attestation extension.
  This is what lets us embed an arbitrary appid requested by the A-side.
- The resulting certificate chain is minted by the **real** on-device TEE, so
  `rootOfTrust`, OS version and patch level reflect the B-side device. These
  cannot be forged.
- `get_system_keymint` connects directly to the TEE HAL Binder service and
  caches the proxy with a death recipient; reuse the cache, do not reconnect
  per request.

### Relay Protocol

- Long-poll `GET /api/b/poll/` (query: `device_id`, `machine_id`, `timeout`,
  header `X-Relay-Token`); a `200` returns `{task_id, task_type, payload,
  target_device_id}`, a `204` means no task.
- Submit results with `POST /api/b/result/` body `{task_id, result, device_id}`.
- `OMMEGA_RELAY_SERVER`, `OMMEGA_RELAY_DEVICE_ID`, `OMMEGA_RELAY_TOKEN` are required
  (loaded from `/data/adb/ommega/relay.conf` by `template/service.sh`).
- Logging keys (all four, managed together in `relay.conf`): file log
  `OMMEGA_RELAY_LOG_ENABLED` (default `true`) / `OMMEGA_RELAY_LOG_LEVEL`
  (default `debug`), and logcat `OMMEGA_RELAY_LOGCAT_ENABLED` (default `true`)
  / `OMMEGA_RELAY_LOGCAT_LEVEL` (default `info`). They are read by
  `src/bin/relay.rs`'s `preload_log_config()` before the full config is loaded,
  so they are honored even when the rest of `relay.conf` is broken. They are
  startup-only (not hot-reloaded); changing them needs a relay restart.
- `template/service.sh` kills leftover/duplicate `relay` processes
  (`kill_all`) before each start and keeps `module.prop`'s `description`
  in sync (✅ 运行中 / ❌ 启动失败 / ⏳ 启动中), mirroring client-a.
- Both `http://` and `https://` are supported; the relay accepts self-signed
  certificates (the relay_server uses a self-signed cert).

### Persistent and Temporary Files

- Obtain the user's explicit approval before creating any file that requires
  permanent storage.
- Delete every temporary probe artifact immediately after the probe completes.
- Persistent runtime state lives in `/data/adb/ommega/`.

## Repository Conventions

- Use targeted `rg` searches. Keep edits ASCII unless the file already uses
  non-ASCII.
- `template/` and `src/` must stay consistent: the relay config keys
  (`OMMEGA_RELAY_*`) must match between `template/service.sh` and
  `template/relay.conf`.
- AIDL generation in `build.rs` should remain minimal: only the keymint HAL
  types plus the secureclock data types they reference. Do not re-add
  keystore2/authorization/metrics or the software-keystore AIDL.

## Validation and Deployment

- For Rust code changes, run the repository's Android gate before handoff:

  ```sh
  cargo fmt --all -- --check
  cargo clippy --target aarch64-linux-android --workspace --all-targets -- -D warnings
  cargo test --target aarch64-linux-android --workspace --no-run
  ```

- This project uses an unstable Rust feature (`OnceCell::get_or_try_init`),
  so builds require the **nightly** toolchain, e.g.:

  ```sh
  RUSTUP_TOOLCHAIN=nightly python build.py --abi arm64-v8a
  ```

- For binary updates, rebuild and reinstall the module zip:

  ```sh
  RUSTUP_TOOLCHAIN=nightly python build.py --debug --abi arm64-v8a
  ```

  then install the produced `target/ommega-b-*.zip`, or push the `relay`
  binary to the device.
- Verify the relay daemon is running and polling after deployment
  (`logcat` tag `ommega-b`, or `/data/adb/ommega/logs/relay.log`).
- Do not add `#[allow(...)]` solely to silence Clippy. Any necessary exception
  must have a concrete, documented reason and direct approval from user.
