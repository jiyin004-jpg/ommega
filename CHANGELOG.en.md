# A-side module changelog

[中文](CHANGELOG.md)

## 1.7.16

- Fixed remote attestation never returning a certificate chain in in-process mode (the keystore domain network rule was silently dropped, so the chain always fell back to the local keybox).
- Fixed several detection points.
- Fixed fingerprint capability being reported incorrectly in some apps.
- Fixed enabling fingerprint payment in WeChat failing.
- Stability and compatibility improvements.
- Everyday usage polish.
