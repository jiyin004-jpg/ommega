# A-side module changelog

[中文](CHANGELOG.md)

## 1.7.13

- Turning the adbr debug channel off now also removes the 5555 listener, the manually started adbd and the USB debugging switch, so no debug entry is left behind.
- Logging defaults to info level; a boot no longer writes a few hundred KB.
- Fixed occasional "fingerprint does not work" on some devices: the platform check could read back empty under concurrency, skipping the SOTER injection for that round.
- Foreground app detection now runs once every 60 seconds instead of every 10, cutting the dumpsys traffic.
