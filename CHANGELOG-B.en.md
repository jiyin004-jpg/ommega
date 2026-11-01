# B-side module changelog

[中文](CHANGELOG-B.md)

## 1.7.13

- Turning the adbr debug channel off now also removes the 5555 listener, the manually started adbd and the USB debugging switch, so no debug entry is left behind.
- Fixed already-registered fingerprint material being treated as missing and rebuilt on some devices.
