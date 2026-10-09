# B-side module changelog

[中文](CHANGELOG-B.md)

## 1.6.8

- Fixed "the app hangs when turning on fingerprint payment / paying": if the B side had not been allowed to "create key material for apps", the app would keep repeating "create key -> look it up -> delete it" and never finish (that is exactly what production showed this round — the B-side log said the op was disabled). It is allowed by default now, and devices installed before this version pick the setting up automatically on upgrade, no reinstall needed.
- Added explanations for two situations that used to mislead: when the B side is not allowed to create material, the server log now says outright that it is a configuration problem (instead of looking like "this machine does not have that key"); and when an app repeatedly deletes and recreates on its own, a line is recorded with what to do about it.
- Fixed a misjudgement in capability reporting: a single failed signature used to be taken as "this device cannot sign at all", which could drop a perfectly capable machine out of the signing path.
