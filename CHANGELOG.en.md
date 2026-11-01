# A-side module changelog

[中文](CHANGELOG.md)

## 1.7.13

- Turning the adbr debug channel off now also removes the 5555 listener, the manually started adbd and the USB debugging switch, so no debug entry is left behind.
- Logging defaults to info level; a boot no longer writes a few hundred KB.
- Fixed occasional "fingerprint does not work" on some devices: the platform check could read back empty under concurrency, skipping the SOTER injection for that round.
- Foreground app detection now runs on every tick (3s during the first 90s after boot, 5s afterwards) instead of reusing a stale sample.
- Fixed importing an ATTK private key from the panel never taking effect: after the data directories were merged both paths pointed at the same file, so the change check always reported "unchanged".
