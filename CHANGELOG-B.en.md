# B-side module changelog

[中文](CHANGELOG-B.md)

## 1.7.13

- The SELinux allow rules are now applied by the module itself: before, this relied on Magisk / APatch replaying `sepolicy.rule` at boot, which the KernelSU family never does, leaving those devices without any rules. `post-fs-data` applies them once and the service loop re-applies only what is missing, trying ksud, then magiskpolicy, then the bundled `ommega-policy`.
- Turning the adbr debug channel off now also removes the 5555 listener, the manually started adbd and the USB debugging switch, so no debug entry is left behind.
- Fixed already-registered fingerprint material being treated as missing and rebuilt on some devices.
