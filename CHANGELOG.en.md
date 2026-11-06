# A-side module changelog

[中文](CHANGELOG.md)

## 1.7.15

- SOTER gains a server-key mode: material is minted from an uploaded ATTK identity, picked per requesting device, without occupying the B device.
- New SOTER panel in the console: mode, ATTK upload / enable / delete / default, identity bindings, real-app allowlist, slot view.
- SOTER material and deletion records are isolated per user, app and device.
- Deleted SOTER keys no longer come back on their own (matches a real device), and it survives restarts.
- Certificate and device-id shapes now follow the real device on both Qualcomm and MediaTek platforms.
- Fixed missing device-property attestation entries in some attestation paths.
