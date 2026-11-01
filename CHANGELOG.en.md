# A-side module changelog

[中文](CHANGELOG.md)

## 1.7.13

- Turning the adbr debug channel off now also removes the 5555 listener, the manually started adbd and the USB debugging switch, so no debug entry is left behind.
- Logging defaults to info level; a boot no longer writes a few hundred KB.
- Fixed occasional "fingerprint does not work" on some devices: the platform check could read back empty under concurrency, skipping the SOTER injection for that round.
- Foreground app detection now runs on every tick (3s during the first 90s after boot, 5s afterwards) instead of reusing a stale sample.
- Fixed importing an ATTK private key from the panel never taking effect: after the data directories were merged both paths pointed at the same file, so the change check always reported "unchanged".
- Fixed WeChat fingerprint enrollment failing: the ASK signature salt length did not match the vendor TA, and the counter advanced by an irregular step.
- Fixed swapping the keybox from the panel doing nothing: both the TEE and StrongBox copies now live where the panel can write them, and a change reloads immediately.
- Fixed clearing a custom ATTK not actually returning to the built-in one: only the file was removed, the old key stayed in memory.
- Fixed the server address and token saved from the panel never applying: the config was written where the program does not read it.
- Fixed the app side never receiving the certificate chain after attestation.
- Fixed apps keeping the old enrollment state after the attestation key was swapped, which forced repeated fingerprint prompts before enrollment worked again.
- Fixed occasional key generation failures on some devices killing the keystore process.
- Fixed the background process staying alive after the module was uninstalled and injecting again.
- Fixed keys being reclaimed on every boot on some devices, forcing apps to create a new key.
- Fixed the StrongBox capability declaration disagreeing with what the keystore actually serves: installing the module no longer hides it by default, the WebUI switch is the only control.
