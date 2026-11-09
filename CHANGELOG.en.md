# A-side module changelog

[中文](CHANGELOG.md)

## 1.7.16

- When the relay is unavailable and the caller supplied its own attestation key, stop failing with `UnknownError(-1000)`: with `fallback_local` on, mint locally with the local keybox instead.
- The local path now checks where that attestation key's private key lives first: `KeyMaterial::Remote` ones are dropped instead of being used to sign locally.
- `sepolicy_apply.sh`: the module's own `ommega-policy` is now always tried first (bundled → ksud → magiskpolicy, each step verified). It does not depend on the manager's return value: it writes `/sys/fs/selinux/load` itself and can verify the result.
- `soterta.sh`: the single-instance lock probes whether `flock` actually works and falls back to a `mkdir` lock; a stock HAL that will not stop is no longer retried every cycle.
- `sepolicy.rule`: add the permissions the software SOTER TA needs to register its service name.
- Background services now appear as system services in the process list, without module details in their environment.
- SOTER takeover now decides on the service name alone, so a stock HAL coming back no longer rebuilds the TA repeatedly.
- If the in-process service goes quiet, it now falls back to a standalone process instead of failing silently.
- When the in-process path cannot start on this device (the reason is recorded), it now goes straight to the standalone process instead of waiting out the boot grace period.

## 1.7.15

- SOTER gains a server-key mode: material is minted from an uploaded ATTK identity, picked per requesting device, without occupying the B device.
- New SOTER panel in the console: mode, ATTK upload / enable / delete / default, identity bindings, real-app allowlist, slot view.
- SOTER material and deletion records are isolated per user, app and device.
- Deleted SOTER keys no longer come back on their own (matches a real device), and it survives restarts.
- Certificate and device-id shapes now follow the real device on both Qualcomm and MediaTek platforms.
- Fixed missing device-property attestation entries in some attestation paths.
- Fixed the boot-state claim in certificates minted with a self-supplied attest key.
- SOTER compatibility: no longer affected by system service interface naming differences on some devices.
- Fixed SOTER checks failing on some devices.
