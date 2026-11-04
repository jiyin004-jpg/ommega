# spl daemon（B 端第二种补丁日期改法）

运行中直接改 KeyMint TA 的 attestation 配置：`os_version` / `system_patch_level` /
`vendor_patch_level` 三项。不碰系统属性、不重启 keymint HAL、不重启 keystore2，
下一次 `generateKey` 的证书立刻是新值，签完再改回来。

第一种（`src/plat/patchlevel.rs`）是 resetprop + 弹 HAL，慢两三秒、全局生效；这一种
是亚毫秒级、窗口只有签发那几十毫秒。代价是它依赖高通 vendor 库里那条私有通道，而且
必须在 uid 1000 的进程里跑（root 域读不到 vendor 下那几个库）。

## 为什么是独立进程

relay 是 root 跑的，它进不了 uid 1000 的域；反过来这个 daemon 也不能跑在 root 域。
所以拆成一个单独的小二进制，relay 通过 abstract unix socket 指挥它：

```
relay（root） --unix socket @spl-daemon--> spl_daemon（uid 1000）
                                              └── dlopen libqtikeymint.so /
                                                  libkeymasterdeviceutils.so
                                                  └── KeymasterUtils::sendCmd → TA
```

`service.sh` 负责拉起它（`su 1000 -c ...`），60 秒失败退避一次；relay 那边每次
`APPLY` 连不上就当场退回改属性那条路，不会因为这台机器没这条路而把链弄错。

## 协议

一行一条，纯文本，应答以 `OK` 开头：

| 请求 | 应答 | 说明 |
|---|---|---|
| `PING` | `OK pong` | 探活 |
| `STATUS` | `OK base=os/sys/vendor/flag cur=... applied=0/1 hold_ms_left=...` | `base` 是开机时从属性推的基线 |
| `APPLY <os> <sys> <vendor> [flag] [hold_ms]` | `OK applied us=.. rc=.. hold_ms=..` | `rc` 可能是 16，那是 TA 的「已配置」提示，值已经生效 |
| `RESTORE` | `OK restored in ..ms` | 回基线 |
| `BASELINE [os sys vendor flag]` | `OK base=...` | 改 daemon 记的基线（不带参数就是读） |

`APPLY` 一定要带 `hold_ms`：relay 中间崩了、没来 `RESTORE`，到点 daemon 自己回基线。
TA 状态没有回读接口，所以 `RESTORE` 不能因为「看起来没变」就跳过。

## 编、测、装

`build.py` 会在能找到 NDK 时自动把它编进 `libs/arm64-v8a/spl_daemon`（找不到就跳过，
包里少这个文件，`live` 自动退回 `prop`）。手动：

```powershell
# Android arm64
& "$env:ANDROID_NDK_HOME\toolchains\llvm\prebuilt\windows-x86_64\bin\clang.exe" `
  --target=aarch64-linux-android24 `
  --sysroot="$env:ANDROID_NDK_HOME\toolchains\llvm\prebuilt\windows-x86_64\sysroot" `
  -std=gnu11 -O2 -Wall -Wextra -I src -o build\spl_daemon `
  src\spl_daemon.c src\lib\spl_ta.c src\lib\spl_req.c -ldl -llog

# 主机单测（纯逻辑层，不需要设备）
gcc -std=c11 -O1 -Wall -Wextra -I src tests\test_units.c src\lib\spl_req.c -o build\test_units.exe
build\test_units.exe
```

## 只能改这三项

`boot_patch_level`、`root_of_trust`（verifiedBootKey/Hash、deviceLocked、
verifiedBootState）、安全等级都来自真实启动链或硬件，TA 的 configure 根本不收，
这套东西改不了。别把「补丁日期对了」当成「设备状态也对了」。

## 两个坑

1. tag 高 4 位是类型，`0x3` = UINT；写成 `0x6` TA 直接回 `-40`。
2. `sendCmd` 返回 `16` 不代表失败。判断生效只能看实际签出来的证书。

还有一个不是 TA 的坑：**不能直接从 `/data/adb` 下执行**。那里的文件是
`u:object_r:adb_data_file:s0`，uid 1000 执行时报 `inaccessible or not found`。
1.7.14 及以前的做法是每次拉起前把二进制拷到 `shell_data_file` 的
`/data/local/tmp/spl_daemon` 再跑。现在已经不往那个公共目录写东西了：
`sepolicy.rule` 里加了两条放行（`allow shell adb_data_file dir/file …`），直接
在原位置以 uid 1000 跑。规则没打进去时这里就起不来，live 自动退回 prop
（`spl.log` 里能看到失败的启动行）。

原始研究与实测记录在仓库外的 `D:\keymint-spl-live\`（小米 peridot / Android 16 /
QTI 上跑的：单次 0.4–0.6ms，200 轮压测全 rc=0）。这里只搬了设备侧要用的三个文件，
`0x44878` 这个 vtable 偏移是那台机器那个固件版本的，换固件要重新对。
