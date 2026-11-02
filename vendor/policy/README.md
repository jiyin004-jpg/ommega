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

## 为什么只在最后一级用

管理器原生工具跟系统 policy 是同一代编出来的，兼容性最好；我们这份是「谁都没给
工具」时的保底。三级顺序写在 `sepolicy_apply.sh` 里：ksud → magiskpolicy → 自带。

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

## 授权

`libsepol/` 来自 AOSP `external/selinux`（同步点见 `libsepol/VERSION`），
LGPL-2.1，许可证全文在 `libsepol/LICENSE`。我们只是把它作为静态库链进
`ommega-policy`，源码随仓库一起分发，改动为零。
