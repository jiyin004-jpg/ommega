# A-side changelog

[中文](CHANGELOG.md)

## 1.6.8

- Fixed "the app is clearly calling SOTER but the system does not recognise it" on some models: the real caller identity is now resolved even when the system renamed the interface. Fingerprint / payment flows in apps like WeChat are no longer treated as an unknown caller.
- Apps installed in a clone, a multi-app space or a secondary user are now recognised correctly too (previously such apps could end up without the real device's keys).
- Added two more sources for identifying the caller (the system's own package table, and the currently foregrounded app) to cover models where the system interface cannot resolve the caller; both carry an 8-second validity window, so the module would rather not recognise than guess.
- Added diagnostics along the way: with debug logging on, unrecognised SOTER interface names are recorded, which makes it easier to support renamed interfaces later.
- Hotfix: on models that renamed the SOTER interface, the app could not learn the real caller identity, which broke flows like WeChat fingerprint / payment on those models (some Xiaomi devices).
- Hotfix #2: added the "current foreground app" fallback for those models (it used to apply only when the uid lookup failed, which those models never reach), and aligned the write/read cadence of the foreground information so the fallback is available at all times.
