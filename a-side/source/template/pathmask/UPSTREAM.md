# PathMask 内核模块（第三方资产，随 ommega A 端模块分发）

来源：<https://github.com/Andrea-lyz/LKM-PathMask> — release **v2.8.0**（2026-09-14 发布）

本目录里的 `.ko` 是官方 release 逐个上传的原生资产（不是从 zip 里解出来的），
文件名与上游资产名完全一致，便于「来源 ↔ 文件 ↔ 哈希」一一对照：

| 文件 | 大小 | 上游 sha256 |
|---|---|---|
| `android12-5.10_pathmask.ko` | 62656 | `a529f89da593c9078712cb9142de8fd94d90ea99a75802f7bf11217e4408d493` |
| `android13-5.10_pathmask.ko` | 60360 | `ba12e54a1bdf37df43daa204831aba3a782d970c1bfab5b8610628f22fd3f577` |
| `android13-5.15_pathmask.ko` | 62544 | `3c650cb1b2fb2da8a3f08d64a953b1a4828b67298e28e1cdda6f5ddf73f8e9d3` |
| `android14-5.15_pathmask.ko` | 66776 | `7f17772c1c3f626095ddd8252d65997606a29cee4c4fa3a60d41bb4b484eff6c` |
| `android14-6.1_pathmask.ko` | 65824 | `dd912e7d69ba3f2ec267d07880601c954fbf80470f6b2a0b27da82538768584b` |
| `android15-6.6_pathmask.ko` | 60392 | `d1f4a8da78f407d561b3c8207fa23a33111da2f25face9b1d0b5a7ed2d7e5ad0` |
| `android16-6.12_pathmask.ko` | 65400 | `6f20c7407235cc78b066ebc710fcdbba45b97fbceb2629e14698a30a2cf5c85f` |

（哈希已在上游 release 的 asset digest 与本地文件之间双向核对过；`build.py` 里的
`PATHMASK_KO_SHA256` 会对同一个表做构建期校验，改坏任何一个文件都会让打包失败。）

## 选择与使用

- 由 `../kmod-loader.sh` 在开机（late_start service）时选择并 `insmod`：
  按 `uname -r` 的 **主.次** 版本（5.10 / 5.15 / 6.1 / 6.6 / 6.12 / 6.18）选系列，忽略补丁号；
  同系列有多个安卓变体时，先试 `uname -r` 里 `-androidNN` 精确匹配的那个，再依次试其余候选。
- 只用它的路径遮罩能力（`scope_mode=global`），默认目标是 `/system/priv-app/SoterService`；
  `procguard.ko` 不随包、也不加载（本模块不涉及隔离进程的 `/proc` 检测面）。

## 许可

上游仓库**没有 LICENSE 文件**，但源码声明 `MODULE_LICENSE("GPL")`。这里按 GPL 兼容方式再分发
内核模块二进制，对应源码地址：<https://github.com/Andrea-lyz/LKM-PathMask>（`kernel/pathmask.c`）。
若要再发布或商用，建议先与上游作者确认授权。
