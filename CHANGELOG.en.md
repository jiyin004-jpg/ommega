# A-side module changelog

[中文](CHANGELOG.md)

## 1.7.14

- The patch dates in certificates now follow the system image itself, fixing boot patch dates that did not match the system on some devices.
- The verified boot key and hash in certificates are derived from the device's own data instead of coming out empty or wrong.
- Disguise settings take effect as soon as they are saved, with no restart needed; what you write is what gets used.
