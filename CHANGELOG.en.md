# A-side module changelog

[中文](CHANGELOG.md)

## 1.7.14

- The patch dates in certificates follow the system image itself; when image metadata is unreadable they follow the vendor patch date, so all three stay consistent.
- The verified boot key and hash in certificates are derived from the device's own data instead of coming out empty or wrong.
- Disguise settings are applied at boot only, so properties and certificates always agree.
- Remote SOTER is now its own switch, independent from remote attestation.
- SOTER takeover closes one more gap: on devices whose system SOTER service is unusable and never reaches the hardware, apps' SOTER requests are answered properly now.
- ECDSA signing in certificates now behaves like the platform's own implementation (long digests are truncated by bit length, every signature is randomized).
- Nothing is written to /data/local/tmp at runtime any more: the sepolicy application log and the panel's temporary package lists live under the data directory.
