# Outbound proxy and asset refresh on the server

[中文](README.md)

This machine (Tencent Cloud) cannot reach `android.googleapis.com` directly, nor the
subscription site of the proxy provider, but `raw.githubusercontent.com` is reachable. So it is
built in two hops:

```
GitHub Actions (outside) -> relay-assets branch (raw)
                              ^ every 6 hours
        ommega-relay-assets.sh (scheduled pull on this box; only these two files)
                              |-> decrypt clash-subscription.enc -> /etc/mihomo/providers/sub.yaml
                              |-> /opt/relay/attestation_status.json -> revocation-list fallback cache
mihomo (127.0.0.1:7890) <- relay_rs goes through it explicitly when pulling the official revocation list
```

The node table is kept in the repository as **ciphertext** (`clash-subscription.enc`, openssl
AES-256-CBC + PBKDF2, iter 300000, md sha256). The passphrase exists in two places: the
repository secret `SUB_PASSPHRASE` (used by Actions to encrypt) and
`/etc/mihomo/relay-assets.key` on the server (root 600, used to decrypt locally). Both sides
must use the same parameters; changing one means changing the other. The local copy of the
passphrase is backed up at `D:\keys\ommega-archive\relay-assets-passphrase.txt`.

The key point: **mihomo binds only 127.0.0.1, `allow-lan: false`, rule set is `MATCH,PROXY`**,
with no TUN / iptables takeover whatsoever. In other words it only serves requests that
explicitly carry `-x` — the relay traffic of both the A and B sides never goes through it, and
the system routing is left alone.

## Install

```sh
# 1. kernel (unpacked from the mihomo release, linux-amd64-compatible build, ~60MB)
install -m 755 mihomo /usr/local/bin/mihomo

# 2. config
mkdir -p /etc/mihomo/providers
install -m 644 mihomo/config.yaml /etc/mihomo/config.yaml
# providers/sub.yaml (the node table; the plaintext carries the provider's keys) is not committed.
# ommega-relay-assets.timer pulls the ciphertext and writes it after decryption; in a hurry, copy
# one over from your local machine first:
#   scp sub.yaml root@host:/etc/mihomo/providers/sub.yaml

# 2.5 decryption passphrase (the same value as the repository secret SUB_PASSPHRASE; never commit
#     it — take it from the keys folder on D:)
install -m 600 /dev/stdin /etc/mihomo/relay-assets.key <<'EOF'
<paste the passphrase here, one line>
EOF

# 3. units
install -m 644 systemd/mihomo.service /etc/systemd/system/mihomo.service
install -m 755 mihomo/ommega-relay-assets.sh /usr/local/bin/ommega-relay-assets.sh
install -m 644 systemd/ommega-relay-assets.service /etc/systemd/system/
install -m 644 systemd/ommega-relay-assets.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now mihomo.service ommega-relay-assets.timer
```

## Verify

```sh
# direct fails, through the proxy works
curl -sS -o /dev/null -w '%{http_code}\n' --max-time 8 https://android.googleapis.com/attestation/status   # 000
curl -sS -x http://127.0.0.1:7890 -o /dev/null -w '%{http_code}\n' \
  --max-time 20 https://android.googleapis.com/attestation/status                                            # 200
```

## Notes

- This machine is tight on memory as it is (swap pegged most of the time), so
  `mihomo.service` sets `GOMEMLIMIT=80MiB` / `MemoryMax=192M`; measured usage sits around 60MB.
- The node table comes from the provider's subscription, but it has to be fetched **with
  mihomo's UA**: a clash-style UA gets you placeholder nodes (every `server` is written as
  127.0.0.1). The conversion script is `.github/scripts/sub_to_clash.js`. The resulting table
  carries node keys, so it **must be encrypted before it is committed**; plaintext only ever
  exists on the server.
- The repository is public (before 2026-09-28 the node table was pushed in plaintext here and
  the subscription URL sat in the workflow, i.e. the subscription was exposed on the internet;
  that has been cleaned up and moved to encryption). Hence two hard rules: the subscription URL
  goes into the repository secret `CLASH_SUB_URL` only, and the node table is pushed to the
  branch only as the `clash-subscription.enc` ciphertext.
- The relay-assets branch is an orphan holding exactly two files,
  `attestation-status.json` and `clash-subscription.enc`, force-pushed every time; do not let it
  carry repository snapshots again.
- The proxy address defaults to `http://127.0.0.1:7890`; the server can override it with the
  environment variable `OMMEGA_OUT_PROXY`.
- Both the node table and the revocation list are fetched as "download to a temp file, decrypt /
  verify, then replace", so a network hiccup or a wrong passphrase never wipes a good config;
  a failed decryption leaves a `keep old` line in the journal.
