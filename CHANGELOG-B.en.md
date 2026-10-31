# B-side module changelog

[中文](CHANGELOG-B.md)

## 1.7.12

- Pairs with the latest 1.7.12 hotfix of the A side; no other changes.
- Attestation-key child signing now prefers the local session and only falls back to the key blob in the request.
- Pairs with A-side 1.7.12: reject `agree` outright (it used to wedge the TEE with
  `-49`), report the device fingerprint for private-card binding, long-poll for 5s,
  cache the KeyMint version probe, and fix the patch-level follow-up check.
