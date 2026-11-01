# PathMask kernel module (third-party asset, shipped with the ommega A-side module)

[中文](UPSTREAM.md)

Source: <https://github.com/Andrea-lyz/LKM-PathMask> — release **v2.8.0** (published 2026-09-14)

The `.ko` files in this directory are the native assets uploaded one by one in the official
release (not unpacked from a zip), and their file names match the upstream asset names exactly,
so that "source ↔ file ↔ hash" can be compared one to one:

| File | Size | Upstream sha256 |
|---|---|---|
| `android12-5.10_pathmask.ko` | 62656 | `a529f89da593c9078712cb9142de8fd94d90ea99a75802f7bf11217e4408d493` |
| `android13-5.10_pathmask.ko` | 60360 | `ba12e54a1bdf37df43daa204831aba3a782d970c1bfab5b8610628f22fd3f577` |
| `android13-5.15_pathmask.ko` | 62544 | `3c650cb1b2fb2da8a3f08d64a953b1a4828b67298e28e1cdda6f5ddf73f8e9d3` |
| `android14-5.15_pathmask.ko` | 66776 | `7f17772c1c3f626095ddd8252d65997606a29cee4c4fa3a60d41bb4b484eff6c` |
| `android14-6.1_pathmask.ko` | 65824 | `dd912e7d69ba3f2ec267d07880601c954fbf80470f6b2a0b27da82538768584b` |
| `android15-6.6_pathmask.ko` | 60392 | `d1f4a8da78f407d561b3c8207fa23a33111da2f25face9b1d0b5a7ed2d7e5ad0` |
| `android16-6.12_pathmask.ko` | 65400 | `6f20c7407235cc78b066ebc710fcdbba45b97fbceb2629e14698a30a2cf5c85f` |

(The hashes were verified in both directions, between the asset digests of the upstream release
and the local files; `PATHMASK_KO_SHA256` in `build.py` checks the same table at build time, so
breaking any one file fails packaging.)

## Selection and use

- `../kmod-loader.sh` picks one at boot (late_start service) and `insmod`s it: the series comes
  from the **major.minor** of `uname -r` (5.10 / 5.15 / 6.1 / 6.6 / 6.12 / 6.18), the patch
  level is ignored. When a series has several Android variants, the one matching `-androidNN`
  in `uname -r` is tried first, then the remaining candidates in order.
- Only its path-masking ability is used (`scope_mode=global`), and the default target is
  `/system/priv-app/SoterService`; `procguard.ko` is neither shipped nor loaded (this module
  does not touch the `/proc` detection surface of isolated processes).

## License

The upstream repository **has no LICENSE file**, but the source declares
`MODULE_LICENSE("GPL")`. The kernel module binaries are redistributed here in a GPL-compatible
way; the corresponding source is at <https://github.com/Andrea-lyz/LKM-PathMask>
(`kernel/pathmask.c`). For redistribution or commercial use, check with the upstream author
first.
