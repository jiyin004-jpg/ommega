# A-side module changelog

[中文](CHANGELOG.md)

## 1.7.14

- The patch dates in certificates follow the system image itself; when image metadata is unreadable they follow the vendor patch date, so all three stay consistent.
- The verified boot key and hash in certificates are derived from the device's own data instead of coming out empty or wrong.
- Disguise settings are applied at boot only, so properties and certificates always agree.
