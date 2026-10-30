# A-side module changelog

[中文](CHANGELOG.md)

## 1.7.12

- ECDH for key-agreement-only keys now runs locally, so it can no longer wedge the
  B-side TEE (a single attempt used to break signing on that device).
- The locally minted attestation key now carries the same boot state as the remote
  chain, clearing Duck Detector's root-of-trust divergence.
- Private cards bind to a device on both the A and B side; changing devices needs an
  unbind first (public cards are unaffected).
- Faster remote attestation: the interface pick is cached and the B side long-polls;
  several SOTER forwarding issues are fixed as well.
