# A-side module changelog

[中文](CHANGELOG.md)

## 1.7.12

- The boot patch level in the panel now writes `ro.bootimage.build.date.utc`, so the property and the chain's boot patch always agree.
- Values explicitly entered in the panel are written unconditionally instead of being skipped when the device lacks that property.
- Attestation-key child signing now returns to the layer that minted the key, instead of failing with `issuer key not available` after a policy switch.
- MODULE_HASH now follows the HAL version: nothing is written below KeyMint 4, matching real devices, so Duck Detector's MODULE_HASH check no longer contradicts itself.
- Importing an ATTK from the panel now syncs cpu_id: a `cpu_id:` line in the file is honoured, otherwise the forced value is cleared and recomputed locally.
- Fix `getKey` occasionally returning null when several threads read the same key at once (AProbe L04 concurrent signing).
- Fix `Invalid key blob` from KeyAttestation's "use attestation key": the attest key follows the policy when minted, while child keys are always signed back at the key's origin layer.
- ECDH for key-agreement-only keys now runs locally, so it can no longer wedge the
  B-side TEE (a single attempt used to break signing on that device).
- The locally minted attestation key now carries the same boot state as the remote
  chain, clearing Duck Detector's root-of-trust divergence.
- Private cards bind to a device on both the A and B side; changing devices needs an
  unbind first (public cards are unaffected).
- Faster remote attestation: the interface pick is cached and the B side long-polls;
  several SOTER forwarding issues are fixed as well.
