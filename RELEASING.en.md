# Release process

[中文](RELEASING.md)

## Version number

All three parts share one number; the single source of truth is `VERSION` at the repository root:

- the `version` in `a-side/source/Cargo.toml`, `b-side/source/Cargo.toml` and
  `server/source/Cargo.toml` must match it. `build.py` checks them one by one and exits on a
  mismatch ("both have to change, not just one")
- b-app (`b-app/source/app/build.gradle.kts`) and the server (`src/config.rs`) read the file
  directly, so they need no separate edit

The versionCode is derived from the version: `major * 1000000 + minor * 1000 + patch`, plus an
offset for the modules, described separately below.

### versionCode and that hotfix offset

A module's versionCode is "formula value + `VERSION_CODE_OFFSET`", and the offset lives in
`a-side/source/build.py` and `b-side/source/build.py`. There is one set per side, and re-releasing
one side bumps that side only — changing just one is normal, do not align the two (or the number
computed here stops matching the package already out there).

The offset exists to repair a piece of history: the A / B modules went through several hotfixes
that were re-released "same version number, build again" (1.6.1 / 1.6.2 / 1.6.3), each of which
had to raise the versionCode by hand. By the time 1.6.4 shipped, the module's actual versionCode
was `1006014` while the formula gives `1006004`. Magisk only looks at that number to decide
whether an update exists, so releasing 1.6.5 by formula would compute `1006005`, which is smaller
than 1006014, and machines already on 1.6.4 would never see the update.

That gap of 10 is where `VERSION_CODE_OFFSET` comes from, hence:

- a normal release needs nothing; the formula value plus each side's offset increases on its own
- if the same version number has to be re-released, raise that side's `VERSION_CODE_OFFSET`
  (10 -> 11 -> 12); do not pass `--version-code` by hand, that parameter is an emergency hatch only
- current offsets: A side 10 (1.6.4 -> 1006014), B side 11 (re-released 2026-10-03, 1.6.4 ->
  1006015)
- b-app has none of this (it was never re-released): it always uses the plain formula value,
  `1006004` for 1.6.4, which is not the same series as the modules — do not use it for checks

## Release steps

1. Make sure CI on master is green
2. Change `VERSION` and sync the `version` in the three `Cargo.toml` files
3. Update `CHANGELOG.md` (A / B side) and `CHANGELOG-B.md`
4. Build the artifacts (see below)
5. Tag it annotated: `git tag -a v<version> -m "..."`. The tag must point at **the commit that
   produced these artifacts** — the module's `version` carries the short hash of that moment
   (e.g. `1.6.4-17be4f5`), and pointing the tag elsewhere makes them disagree
6. Create the Release, titled `v<version>`
7. Upload the assets
8. Update `version` / `versionCode` / `zipUrl` in `update.json` / `b-update.json`
9. Verify (see below)

### Build

| Artifact | Where | Command |
| --- | --- | --- |
| A-side module | `a-side/source` | `python build.py --release` |
| B-side module | `b-side/source` | `python build.py --release` |
| b-app | `b-app/source` | `./gradlew :app:assembleRelease` (`gradlew.bat` on Windows) |
| Server | `server/source` | `cargo build --release --target <triple>` |

The server binary lands in `server/source/target/<triple>/release/`, not `target/release/`.

### Verification

- `module.prop` inside the package: the hash in `version` matches the tag, and `versionCode` is
  larger than the previous release
- the `versionCode` in `update.json` / `b-update.json` matches the one inside the package
- the assets download: HEAD returns 200 and `Content-Length` matches the local file
- after flashing, confirm the running binary really is the one inside the module:
  `readlink /proc/$(pgrep -f ommega/relay)/exe` must land in
  `/data/adb/modules/ommega-b/libs/<abi>/relay`. `/data/adb/ommega/relay` is the hatch for
  putting a binary in by "hot update" (it is literally called hot-update relay binary in
  `uninstall.sh`), and `service.sh`'s `find_module_relay()` gives it priority over the module
  directory — measured (OnePlus PLC110 / KernelSU 3.3.0, 2026-10-03 12:46): the module had
  already been flashed to `1.6.4-5c41c1a` while `/proc/<pid>/exe` still pointed at the old binary
  a previous hot update had dropped in; flashing the module alone only replaced `module.prop`.
  After flashing, either delete that copy (so the one inside the module wins) or replace it by
  hand.

## Server rollout

The server has no OTA; it is a manual binary swap: `scp` to `/tmp`, verify the sha, stop the
service before swapping (`cp` while it runs gives `Text file busy`), and keep a backup:

```sh
cp -a /opt/relay/relay_rs /opt/relay/relay_rs.pre<change>-$(date +%Y%m%d-%H%M%S)
systemctl stop relay_rs
install -m 755 /tmp/relay_rs.new /opt/relay/relay_rs
systemctl start relay_rs
systemctl is-active relay_rs; sha256sum /opt/relay/relay_rs
```

Check liveness on two ports (measured 2026-10-03): `curl -s http://127.0.0.1:10886/api/status/`
returns a plaintext 200, and TLS is on `https://127.0.0.1:8443/api/status/`. Do not hit 10886
with https: that port does not answer TLS, you get empty output and it looks like the service is
down. All business logs are in `/opt/relay/relay.out.log` (with ANSI colours — strip them first
with `sed -r 's/\x1b\[[0-9;]*m//g'`); systemd only holds start/stop records.

After swapping, remember to replace the `relay_rs-*` assets in the Release too
(`gh release upload <tag> <file> --clobber`), or "master == Release == production" stops holding.

### All long-lived state lives in one database (`data/relay_state.db`)

Since 2026-10-03 the server's "things that must be kept long term" are no longer separate JSON
files; they all live in one SQLite file (WAL; code in `server/source/src/statedb.rs`):

- `sessions`: the old `data/sessions.json` (measured 11714 entries / 73.9 MB / 7.9 KB each;
  every new session used to serialize and rewrite the whole file, roughly 400 times a day ≈
  25–30 GB of write amplification)
- `soter_slots` / `soter_slot_owners`: the pins from `data/soter_slots.json` (layer +
  timestamp) and "which accounts were seen on this slot". One row per account, so a few hundred
  accounts on one slot simply means a few hundred rows. The old JSON was **rewritten whole with
  no tmp+rename**, so a crash mid-write left it unparseable and `load_slots` treated it as empty
  (every pin lost) — that is gone now that it is in the database
- the two old JSON files are imported **only once, when the database is empty** (fields are
  copied byte for byte, the Fernet ciphertext inside `leaf_key_pem` is not re-encrypted), and
  stay in place afterwards as a rollback source. Rehearsed against real production data on
  2026-10-03: 11596 sessions compared one by one and matching, 1471 slots / 5043 account
  fingerprints all accounted for, import took 2.5 s
- a single slot keeps at most 512 account fingerprints per family (it used to be 64 across all
  three families, while the largest uid measured already had 33 accounts and 95 fingerprints
  across the three families, i.e. it had long been truncating). A full slot does not reject new
  accounts; it evicts the least recently seen row of that family (LRU). **Pulling a pin (clearing
  keys) deletes only the "pin layer" row and keeps the account records** — they are evidence and
  must not be wiped along with the uid. Account records use a TTL based on last sighting (30
  days); anything unseen for longer is dropped

  Two traps (both actually hit on 2026-10-03):
  - the old JSON carries no time, so the import gives 0. **0 always means "unknown"**: refill it
    with the current time when opening the database, skip it in TTL cleanup, and treat it as
    still valid in memory. Otherwise the first start after a TTL is attached wipes the whole
    table as "expired ages ago" (measured: 5298 rows down to 386; recovered from the `.backup`
    taken before the migration)
  - clearing several hundred rows or more logs a WARN; when you see it, check the timestamps
    instead of assuming normal expiry
- session expiry is based on **last use** (7 days, no longer creation time), the cap is 20000
  rows with LRU eviction of the least recently used, and only the 8000 most recently used are
  loaded into memory at startup while the rest stay in the database for per-alias lookups — the
  in-memory layer is a hot cache, the database is authoritative, and a restart does not lose
  sessions
- **backing up / rolling back this database means moving `-wal` and `-shm` too**. SQLite runs in
  WAL mode, so recent writes may still be in `data/relay_state.db-wal`; moving only `.db` gets
  you a slightly stale database. Either run
  `sqlite3 data/relay_state.db 'PRAGMA wal_checkpoint(TRUNCATE)'` first, or move all three files
  together
- **when rolling back to an older binary**: move `data/relay_state.db` (with `-wal` and `-shm`)
  out of the way (`mv data/relay_state.db* data/relay_state.db.bak-<time>`). Otherwise, the next
  time you upgrade, the database is non-empty so the old JSON is not imported and the database
  ends up older than the JSON

### Account fingerprint registry (`soter_slot_owners`)

It decides whether a uid-level wipe (`remove_all_uid_key`) is forwarded: with two or more
accounts on the slot, the request is only answered with success and not forwarded, so that one
wipe cannot take out the registration records of the other accounts under the same uid.

This table is normally learned at runtime — when a new account is recognised the log says
`槽位 <device>|<uid> 上认到第 N 个账号指纹（<family>）` ("recognised fingerprint N on this
slot"), and a blocked wipe says `uid 级全清会连坐` ("a uid-level wipe takes bystanders down
with it") (measured 2026-10-03: after seeding the table, of 2536 ops, 71 were wipe requests and
30 were blocked). It is empty after a device change / a database wipe / a new data directory,
which means the first few hours have no protection at all — the logs hold the complete history of
"alias ↔ (device, uid)", so seeding once is enough. The seeding script edits the old JSON
(`data/soter_slots.json`) directly and **only applies when a 1.6.4-or-earlier server is running,
or when you want to fatten the database before upgrading** (the JSON is imported only while the
database is empty):

```sh
python3 server/deploy/seed_soter_owners.py            # look at the stats first
cp -a /opt/relay/data/soter_slots.json /opt/relay/data/soter_slots.json.bak-$(date +%Y%m%d-%H%M%S)
systemctl stop relay_rs
python3 server/deploy/seed_soter_owners.py --apply    # writes /tmp/soter_slots.merged.json
install -m 644 /tmp/soter_slots.merged.json /opt/relay/data/soter_slots.json
systemctl start relay_rs
```

The service must be stopped before swapping: the map in the running process is authoritative and
its next write would overwrite the hand-edited content. The script only touches `owners`; the
per-slot pins (`layer` / `at_millis`) are preserved. Once the database is in use the script is
not needed any more — registrations are written through to `soter_slot_owners`.

## B-side sessions moved into a database too (`/data/adb/ommega/sessions.db`)

Since 2026-10-03 the B side (`b-side/source/src/keymaster/session_db.rs`) no longer stores "one
JSON file per alias"; it is one SQLite file with rules aligned to the server's:

- expiry is based on **last use** (7 days), cap 20000 rows with LRU eviction of the least
  recently used (index on `used_ms`, cleanup is two DELETEs). A lookup bumps `used_ms` to now, but
  throttled to once every 5 minutes — without that refresh you get a replay of the 2026-10-03
  bug: an alias in active use is cleaned up as idle, and the very next signature fails with
  `no key for alias ... (call attest first)`
- only the 2000 most recently used sessions stay in memory (the old map was fully resident;
  measured up to 19967 entries ≈ 160 MB), the rest are looked up per alias in the database — the
  database is authoritative and a restart does not lose sessions
- the old directory `/data/adb/ommega/sessions/` **stays exactly as it is**: it is imported only
  once, while the database is empty (the alias comes from the JSON, the file name is a hash you
  cannot reverse; "last use" uses the file mtime, the same basis as the old LRU), and afterwards
  it is left alone as a ready-made rollback source. Once you are satisfied, a manual
  `rm -rf /data/adb/ommega/sessions` reclaims those hundred-odd MB
- before flashing back to an older version (the one that only knows the JSON directory), move
  `sessions.db*` out of the way, otherwise the old version reads a stale session table from the
  old directory; and upgrading again afterwards will not import the JSON because the database is
  non-empty
- as with the server, **moving the database means moving `-wal` and `-shm` with it** (WAL mode).
  The relay is `pkill -9`ed on every restart, which is exactly the scenario WAL is there for, so
  there is no need to close the database first

## Release conventions

- the title is always `vX.Y.Z`, character for character the same as the tag. No project name
  (`Ommega 1.6.0`), no side name and no Chinese description (`服务端 v1.4.5 — ...`)
- the description is Markdown split by side (A side / B side / server), ending with an artifact
  table: file name + size + SHA256
- freshly released and not yet validated by users: tick pre-release first, then switch to a
  normal release once validated
- tags are always annotated (since 1.6.4)

## Legacy

Before 1.5.0 the A / B sides and the server were released independently, so old Release titles
carry side names and Chinese descriptions; those have been normalised to `vX.Y.Z`. Even older
tags (1.6.3 and before) are lightweight, and following the rule of "do not rewrite history" they
are left alone — annotated tags are only used from 1.6.4 onwards.
