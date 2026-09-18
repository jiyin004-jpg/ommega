#!/usr/bin/env python3
"""Combine the per-ABI build zips into the single zip that gets published.

`build.py --abi arm64-v8a --abi x86_64` produces one zip per ABI, but a module
manager downloads exactly one archive from `update.json`.  This script merges
them: the result carries every ABI's `libs/<abi>/` (plus each file's `.sha256`),
and `customize.sh` is rewritten to announce all supported module arches, so the
installer extracts the binaries matching the device's `$ARCH` (see
`template/customize.sh`).

Everything outside `libs/` must be byte-identical between the inputs; the only
per-ABI difference build.py introduces is the `SUPPORTED_ABIS=` line.

Usage:
    python scripts/pack_combined.py --out ../build/ommega-a-release-1.4.0.zip \
        target/ommega-a-release-arm64-v8a-*.zip target/ommega-a-release-x86_64-*.zip
"""
from __future__ import annotations

import argparse
import hashlib
import io
import sys
import zipfile
from pathlib import Path

ALL_ARCHES = "arm64 arm64-v8a arm armeabi-v7a x64 x86_64 x86"


def read_zip(path: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(path) as zf:
        return {name: zf.read(name) for name in zf.namelist()}


def rewrite_supported_abis(customize: bytes) -> bytes:
    lines = customize.decode("utf-8").splitlines(keepends=True)
    out = []
    replaced = False
    for line in lines:
        if line.startswith("SUPPORTED_ABIS="):
            ending = "\n" if line.endswith("\n") else ""
            out.append(f'SUPPORTED_ABIS="{ALL_ARCHES}"{ending}')
            replaced = True
        else:
            out.append(line)
    if not replaced:
        raise SystemExit("customize.sh has no SUPPORTED_ABIS= line")
    return "".join(out).encode("utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("zips", nargs="+", type=Path)
    args = ap.parse_args()

    merged: dict[str, bytes] = {}
    abis: list[str] = []
    for path in args.zips:
        if not path.exists():
            raise SystemExit(f"input zip not found: {path}")
        content = read_zip(path)
        lib_abis = sorted(
            {n.split("/")[1] for n in content if n.startswith("libs/") and n.count("/") >= 2}
        )
        abis.extend(lib_abis)
        for name, data in content.items():
            if name.startswith("libs/"):
                continue
            if name == "customize.sh":
                # Differs per ABI by design (SUPPORTED_ABIS); taken from the
                # last input and rewritten below.
                merged[name] = data
                continue
            if name == "customize.sh.sha256":
                # Regenerated from the rewritten customize.sh.
                continue
            if name in merged and merged[name] != data:
                raise SystemExit(f"{path.name}: {name} differs between ABIs")
            merged[name] = data
        for name, data in content.items():
            if name.startswith("libs/"):
                merged[name] = data

    customize = rewrite_supported_abis(merged["customize.sh"])
    merged["customize.sh"] = customize
    merged["customize.sh.sha256"] = hashlib.sha256(customize).hexdigest().encode()

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(args.out, "w", zipfile.ZIP_DEFLATED) as zf:
        for name in sorted(merged):
            zf.writestr(name, merged[name])

    # Self-check: every `.sha256` entry has to match its file, otherwise the
    # installer's verify.sh aborts mid-flash.
    with zipfile.ZipFile(args.out) as zf:
        names = zf.namelist()
        bad = [
            n[: -len(".sha256")]
            for n in names
            if n.endswith(".sha256")
            and n[: -len(".sha256")] in names
            and hashlib.sha256(zf.read(n[: -len(".sha256")])).hexdigest()
            != zf.read(n).decode().strip()
        ]
    if bad:
        raise SystemExit(f"hash mismatch in the packed zip: {bad}")

    print(f"wrote {args.out} ({args.out.stat().st_size} bytes, {len(merged)} entries)")
    print(f"  ABIs: {', '.join(sorted(set(abis)))}")
    print(f"  SUPPORTED_ABIS={ALL_ARCHES}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
