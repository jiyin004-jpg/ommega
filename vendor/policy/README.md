# vendor/policy —— 自带的 sepolicy 工具

`ommega-policy`：把 `sepolicy.rule` 打进内核正在用的 SELinux policy。
模块两侧（A/B）都带一份，只有在「root 管理器既没给 ksud、也没给 magiskpolicy」
的时候才会用到（见 `*/source/template/sepolicy_apply.sh` 的三级候选）。

## 文件

| 文件 | 内容 |
|---|---|
| `ommega_policy.c` | 我们自己的 CLI：读 policy → 插 allow 规则 → 单次 write 到 `/sys/fs/selinux/load` |
| `libsepol/` | AOSP `external/selinux` 的 libsepol（只放 `src/` 和 `include/`，CIL 不用） |
| `build.py` | 用 NDK 交叉编四个 ABI，产物在 `out/<abi>/ommega-policy`（不进 git） |

## 顺序：自带优先，但只在运行中

`sepolicy_apply.sh` 的顺序是 **自带 → ksud → magiskpolicy**。

自带这份不依赖管理器，是最稳的一条路，所以放第一。但它直接重写整份 policy，
只能在**运行中**（service 阶段，传 `OMMEGA_POLICY_RUNTIME=1`）用。

**2026-11-22 实测：`post-fs-data` 阶段写 `/sys/fs/selinux/load` 会把 policy 写坏。**

在 peridot（小米 24069RA21C / Android 16）上`--live --apply`之后：规则本身确实进去了，
但同时丢了基础域的权限 —— `zygote → device:file { read write }`（也就是`/dev/null`）
一次开机就刷出几百条 avc denied，app 进程 fork 完一开 `/dev/null` 就 SIGABRT，
`system_server`、`keystore`、`dex2oat` 也跟着缺权限。现象是「规则生效了，但整台机器崩」。

同一个工具、同一份规则，**运行中再写就没问题**（policy 149843 → 149844 条、
zygote 零新增 denied、注入正常）。所以开机早期跳过它、交给管理器，service 阶段再用它。

## 编译

```powershell
python vendor/policy/build.py arm64-v8a     # 也可以 host：本机 Linux/WSL 自测用
```

需要 NDK（`ANDROID_NDK_ROOT`，或本机 `D:\android-ndk-r27d`，CI 上找
`/usr/local/lib/android/sdk/ndk/*`）。libsepol 只编 core，不编 CIL，所以**不需要**
flex/bison。中间产物缓存在 `.build/<abi>/<hash>/`。

## 语法

只认 `sepolicy.rule` 里用到的那一种：

```
allow <类型>{集合} <类型>{集合} <类> <权限>{集合}|*
```

`self` 表示源类型自己。规则里 policy 不存在的类型/类/权限**只跳过并记一行**，不会
把整份文件作废 —— 那份文件本来就是「各机型的域名都列上、谁有谁用」。

## 验证过什么

2026-11-02 在 Linux 上拿真 policy 走过：

- Fedora 系自带的 `policy.33`（3.7MB、85314 条规则）：加两条 allow 后
  `sepol_compute_av` 能看到权限从无到有；同一份再打一次字节一致（幂等）。
- 按 `sepolicy.rule` 里出现的类型/类/权限现造一份 Android 形状的 policy：
  131 条语句全部落上（142 处改动），零跳过；`keystore → system_file:unix_dgram_socket`
  从空变成 `getattr read recvfrom`，`system_file → keystore` 变成 `sendto`。

没验证的：真机上写 `/sys/fs/selinux/load` 那一下（要设备在线才能试）。这一层
magiskpolicy 走的是同样的路径，风险不高，但没实测就是没实测。

2026-11-22 补上了这个实测：**在 peridot 上，`post-fs-data` 阶段写完，基础域对 `/dev/null`
的权限丢了**（zygote / system_server / keystore 全中），app 进程一起就崩；同一个工具
在 service 阶段写则一切正常。见上面「顺序：自带优先，但只在运行中」。

## 授权

`libsepol/` 来自 AOSP `external/selinux`（同步点见 `libsepol/VERSION`），
LGPL-2.1，许可证全文在 `libsepol/LICENSE`。我们只是把它作为静态库链进
`ommega-policy`，源码随仓库一起分发，改动为零。
