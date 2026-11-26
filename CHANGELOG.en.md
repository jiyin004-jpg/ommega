# A-side module changelog

[中文](CHANGELOG.md)

## 1.7.18

- Device information used for device ID attestation is now read from the live system values, so device ID attestation no longer fails after changing the model or after the remote identity changes.
- The device identity declared by the remote side is now written to this device correctly.
- Fixed the display of model entries on the spoofing settings page.
- Key attributes reported to apps now match the attestation certificate, so the key security level no longer conflicts in some cases.
- Key access rate limiting follows the system standard.
- Toggling the local SOTER service now takes over or releases it completely, applying immediately without a restart.
- Fixed SOTER key preparation failing on Qualcomm platforms.
- Upgrading the module no longer clears the saved server address, token or managed app list.
- Attestation data is completed and made consistent; TEE verdicts in some checks are no longer off.
- Key time authorizations are now enforced at the standard point of the key lifecycle.
- Stability and compatibility improvements.
