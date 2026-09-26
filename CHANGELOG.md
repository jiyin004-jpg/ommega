# A 端更新日志

## 1.6.0

本版四端同号：A 端模块、B 端模块、b-app、服务端都是 1.6.0。SOTER 注入开关、调试日志总闸、payload 统一走 memfd 都在这版里；注意本版没做任何密钥操作，TEE 里的签名计数器、RPMB、keybox 都没碰。

- **remote 配置多了「SOTER 注入」这一项**（`soter_inject`，默认关）：WebUI 的 remote 配置里能开关，关着的时候模块完全不碰 SOTER 宿主 —— 不把 `com.tencent.soter.soterserver` 拉起来、不注入、也不占它的进程；开着才在启动时把它拉起来再注进去。这项注入器是每轮热读的，改完几秒内就生效（拉不起服务也不影响：宿主被系统拉起后会直接被注）；关掉只停新的注入与拉起，已经注过的那个宿主会一直带到它自己重起为止。remote 那几个配置项也按从浅到深重排了一遍顺序，SOTER 的两项（伪装 / 注入）挨着放。
  - **真机结果**：关着杀掉宿主，系统把它重新拉起之后线程记号一个都没有（没被注入）；开着再杀一次，宿主重起后立刻被注入（线程记号 `injector-config` 在）。
- **调试日志开关变成总闸，关着一个字节都不写**：`debug_logging` 关的时候文件、stdout、logcat、脚本自己那份 `kmod-loader.log` 全都不写，日志等级设多低都没用 —— keymint daemon、`daemon-injector`、`daemon` 三个都是先看开关再决定建不建日志后端，关着连 logger 都不初始化。`daemon-injector` 还会把开关落成一行 `log_flag: 0|1` 放到 `/data/misc/ommega/`：payload 落进读不到 keystore 那个目录的域时（比如 SOTER 宿主是 uid 1000）就按它决定写不写，内容没变就不动文件，不会周期性写盘。位置选 `/data/misc` 而不是 `/data/adb`，是因为后者是 0700 root，uid 1000 的宿主连门都进不去 —— 放那儿等于开关根本没生效（实测 `Permission denied`）。
  - **真机结果**：`log-on` 时 `keymint.log`、`injector.log` 都在长，`daemon` 的 stdout 里是完整的启动日志；改成 `log-off` 后再把两个目标进程重启一遍（开关是进程起来那一下读的）并跑一次 `keystore_cli_v2 list`，两个日志的字节数和 mtime 一个没动，干净环境下 `daemon` 的 stdout 是 0 字节。
- **A 端日志改成只落文件，不再写 logcat**：keymint daemon、payload（keystore2 域和 SOTER 宿主那个 app 域）、`daemon-injector` 几处全切了 —— 三个 Rust logger 摘掉 `android_logger` / `multi_log`，改 `log4rs` 单后端；共享的 `build_console_file_config` 改名 `build_file_config` 并去掉 stdout appender；shell 侧的 `log()` / `log_line()` 从 `echo` 改成追加到文件。payload 按「keystore 目录 → `/data/misc/ommega/logs`」顺序挑第一个写得动的位置：宿主是 uid 1000 的 system_app，进不去 keystore 那个 0770 目录，所以 app 域单独落一份。两个坑记一下：一是日志 appender 原来延迟到第一条日志才 open，「这个位置能不能写」的判断对不可写目录也返回真、备选路径永远试不到（改成构造时就 open）；二是 `ksud sepolicy apply` 返回 0 不代表生效 —— KernelSU/Magisk 的规则语法不带冒号和分号，写成 AOSP 那样会被静默丢弃。app 域要额外放行 `system_data_file` 的 dir/file 权限（其中 `lock` 是 `flock` 目录要的，不给就文件建出来一直 0 字节）。
  - **真机结果**：app 域 `injector.log` 7347 B、`0660 system:system`，avc 干净；logcat 里零条 ommega；重启后 keymint daemon 进程的 fd 里 logd socket 数为 0。

- **服务端 SOTER 改成跟认证一样的多层链**：原先 `/api/soter/` 只有一条 “挑一台在线 B 端” 的路，现在跟 `attest` / `sign` / `decrypt` 共用同一套层序 —— 物理模式是 `B 端设备 → 服务端密钥(keybox) → 服务端自签`，serverbox 模式是 `服务端密钥 → B 端设备 → 服务端自签`。哪层做不了就回退下一层，三层都不行才把错误回给 A 端，A 端据此用本地密钥、本地也不行就透原生。B 端层仍旧优先点名的设备，它做不了才按负载换一台报过支持的。
- **服务端两层 SOTER 的实现**（新增 `soter_mint.rs`）：服务端拿自己的 RSA 物料按 SOTER 的格式造 ASK —— `[i32 小端 JSON 长度][JSON][256 字节签名]`，JSON 的键序和字段名照现场抓到的来（`pub_key` / `cpu_id` / `counter` / `uid`（字符串）/ `rsa_pss_saltlen=32`），签名是 RSA-PSS-SHA256、盐长 32，所以 ASK 的签名拿同一层导出的 ATTK 公钥一定验得过。keybox 层用库里这台设备名下的服务端身份（只有 RSA 才签得动 SOTER，EC 就是这层没物料、直接回退）；自签层现生成一把 RSA-2048、进程内复用，服务端一重启就等于换了新身份。腾讯那边的根谁也拿不到，这两层不假装自己是腾讯认得的东西，作用只是让 A 端本地流程先能闭环。
- **状态页显示设备能力**：点开设备 id 的弹窗里多了“SOTER 转发 / StrongBox”两行，取值是支持、不支持、未上报（老版本 B 端不会上报，写清楚免得当成“不支持”看）。设备列表里支持的行会挂个小标签。
- **B 端交回结果时先把链放给 A 端，状态页那份设备记录随后补**：原来在队列锁里先干完三件事 —— 解析 leaf 证书拿启动信息、写进设备记录、剪掉过期任务 —— 最后才唤醒等这条结果的 A 端请求。解析是两次纯 CPU 的 DER/CBOR 遍历，A 端等于陪着多等一趟，而且这段时间整把队列锁都被占着（所有 A/B 请求都在后面排队）。现在顺序反过来：任务本身（结果 + 状态 + 归属 + 队列）一落定就放锁、立刻通知，解析挪到锁外做，设备记录和剪枝最后再补一次锁。状态页晚几十微秒更新没有任何人受影响，省下的那一小段却正落在 A 端的响应关键路径上。
  - **量级**：拿真机链（`omk-remote-*.chain.der`，3399 字节的 leaf）跑同一条叶子上的「启动信息 + AAID」两个解析，debug 构建 166.6 µs/次（50 次全命中，release 还要快几倍）。绝对值本身不大 —— B 端那趟真 TEE 操作是几百毫秒起步 —— 改的主要是“不在锁里、不在关键路径上排队”这件事。
- **A 端 remote 多了 SOTER 转发入口**（`RemoteRelay::soter`）：拿不到结果时和 `sign` / `decrypt` 一样返回“不可用”，由调用方决定本地怎么走。A 端自己的 SOTER 服务替身还没接，这次只把通道和政策打通。
  - **A 端注入器多认一个目标：SOTER 的宿主进程**（`com.tencent.soter.soterserver`）。App 的 SOTER 调用都是这个进程转成对高通 HAL 的调用发出去的，hook 得在它进程里才看得到那条 transaction。keystore2 注不进去算启动失败（跟以前一样），SOTER 宿主注不进去只记一条日志，不影响主路。新加环境变量 `OMMEGA_INJECT_TARGETS`（`keystore2` / `soter` / `all`）可以在调试时只注其中一个，平时不设就是两个都注。
  - **A 端 hook 新增 SOTER 识别层**（`hook/soter.rs`，只认只记、不改写）：在写出去的 binder transaction 里认出 `vendor.qti.hardware.soter.ISoter`（宿主发出去的）和 `com.tencent.soter.soterserver.ISoterService`（App 发给宿主的）两族调用，按各自真实的 transact 号解析参数（uid / alias / challenge / session / key），日志一条 `event=soter`，建钥匙和删钥匙那几个会标 `mutation=1`。两个接口号码不通用（同一个号在两边是不同方法），所以各带一张表。识别层不影响任何现有行为：认不出来就一声不吭回去。
  - **A 端模块的 SELinux 规则补了 SOTER 宿主那一份**：注入器把 payload 镜像的 fd 通过 unix dgram socket 递进目标进程，A 端这台机器的 SOTER 宿主跑在 `system_app` 域，原来只有 `keystore` 的那三条规则，所以补上 `system_app` 对应的三条（`unix_dgram_socket` 收发、`file` 读写执行）。各机器上这个进程的域不一定一样，换机时得对着 AVC 日志改。
  - **注入器递 payload 统一走 memfd（老路只当回落）**：往目标进程递 fd 那条老路在 A 端这台上碰壁 —— 内核只送来 SCM_CREDENTIALS、把 SCM_RIGHTS 丢掉（`MSG_CTRUNC`），跟目标是什么域无关，换台机器、换个域就得再加一条 SELinux 规则，而且文件回落也被拒（SOTER 宿主那个域连 `/data/local/tmp` 都搜索不了）。现在两个目标一个路子：先在目标进程里 memfd_create 出一个匿名文件，payload 按 32 KB 一块块写进目标栈上一块固定的暂存区、再用目标自己的 write() 落进去，最后把这个 fd 交给 android_dlopen_ext；memfd 这条不成了才按「跨进程递 fd → 按路径直接打开」的顺序回落。全程不跨进程递 fd、不需要目标有任何读文件权限，也不依赖 SELinux 放行。memfd 会先带上 `MFD_EXEC` 要一次可执行（Android 内核不给这个位的话 mmap PROT_EXEC 会被拒），老内核不认这个位就退回去只留 `MFD_CLOEXEC`。
    - **真机结果**：SOTER 宿主走成 memfd，一次写进去 2368944 字节，`/proc/<pid>/maps` 里挂的是 `/memfd:lib<hash>.so (deleted)`；keystore2 这条目标上远程 `write` 回 `errno=13`，回落成递 fd（maps 里还是模块目录那个路径）—— 功能一样，只是没走成 memfd；`vendor.qti.hardware.soter-service` 三条路都被拒，这个目标还是注不进去，只记一条 `soter hal injection skipped`。
  - **同一个目标不会注第二遍**：payload 是同一个可执行文件，dlopen 第二次就是第二份代码、各持一套全局状态，两边初始化一撞，目标进程直接 `SIGABRT`（实测把已经注过的 SOTER 宿主再注一次，宿主当场没了）。现在注入前先看目标里有没有我们自己起的线程（`injector-config` / `ommega-mirror-r` / `ommega-binder-p`），有就跳过；`entry` 里还放了一道一样的检查当后手，而且必须放在最前面 —— `config::get()` 一起手就会起叫 `injector-config` 的线程，查晚了自己把自己的记号看成了前一份，反而把 hook 跳过。
  - **payload 状态文件按 pid 记多行**：多个目标（keystore2、SOTER 宿主）都往 `injector.payload` 里记，以前是直接覆写，后注的会把先注的那行顶掉，daemon 会以为前面那个没注过。现在写的时候保留别的行、只替换本 pid 那行。
  - **真机结果**：keystore2 从模块目录映射（老路）、SOTER 宿主 `com.tencent.soter.soterserver` 从 `/memfd:…`（新路），两个进程里都能看到 payload 的线程和拦截日志；重跑一次启动器时 SOTER 宿主被跳过（日志里 `already carries the payload; skipping injection`），没有重复注入。`keystore_cli_v2 list` 能直接从 keystore2 的日志里看到一条 `event=reply handling service ListEntries`。
  - **hook 看到的 SOTER 事件现在能传回 daemon**：注入进程写不了 keystore 的日志目录、logcat 里也没有它们的输出，所以在 RPC 上加了 `reportHookEvent`。hook 认出一条 SOTER 调用就把它塞进队列（独立 `ommega-event` 线程，200 ms 轮一次，队列满丢最老的），由那条线程回给 daemon，daemon 落一条 `hook event: …`。整条路不阻塞 binder 线程，传不出去也只记一条日志，不影响目标进程干活。
    - **观察点按角色分方向**：服务端角色的进程（SOTER 宿主、HAL）收到的请求走的是 **read** 侧，write 侧只有它自己发出去的回复。只挂 write 侧的话宿主那半边永远是空的。现在两侧都看（read 侧那条加在 synthetic 判断之后、`handle_br_transaction` 之前）。
    - **interface token 的布局比想的乱，认错了就一条都看不见**：`match_descriptor` 原来只试 0 / 4 两个前缀，实测 app_process（也就是 SOTER 宿主这种 Java 进程）写出来的是 `[strict-mode policy][work source]['SYST'][len][字符][0][参数]` —— 12 个字节的头，而且这里的 `len` 是**字符数**、结尾那个 0 是**单另一个 u32**；老的 String16 写法把结尾 0 算进 `len` 里、也没有单另一个 0。前缀少试一个，App 侧的 SOTER 流量就一条都认不出来；终结符那 4 个字节算错，uid 会一直读成 0。现在 0 / 4 / 8 / 12 都试，12 那个再把两种终结符写法都过一遍（谁解出来的串正好等于描述符就用谁）。
    - **触发工具**：`tools/cecli/SoterPoke.java`（javac + d8 打成 jar，`app_process` 起，全反射不碰 hidden API）：拿任意已注册服务的 binder，用 SOTER 的 interface token 和号码 `transact` 一发，专门用来在没法真跑 App 的时候喂一条 SOTER 形状的流量。`code` 传负数就只把 `marshall` 出来的字节打出来，不 transact（对 token 布局用的）。
    - **真机结果**：往 keystore2 打一发 HAL 形状的 `exportAskPublicKey(uid=10373)`，daemon 日志里落下 `hook event: event=soter side=hal code=1 op=exportAskPublicKey uid=10373 …`，注入进程自己那条 `event=soter` 也同时落盘 —— 解析出的 uid 和发出去的完全一致。
    - **生成代码的 clippy 放行补全**：`build.rs` 原来只给第一棵包树（`top`）加 `#[allow(clippy::all)]`，新增的 `vendor` 包树没盖到，clippy 在生成的 `FIRST_CALL_TRANSACTION + 0` 上报 `identity_op` 直接失败。现在 `android` / `top` / `vendor` 三棵都加，只动刚生成出来的那个文件。

## 1.5.1

本版四端同号：A 端模块、B 端模块、b-app、服务端都是 1.5.1。

- **模块卡片的状态显示更稳**：状态写入改成一次性替换，断电或进程被强杀时不会把模块信息写成空白。
- **服务端状态页显示自身版本号**。
- **服务端 TEE 自检**：B 端设备一连上就自动检查一次 TEE，结果显示在状态页。
- **状态页显示证书的签发身份（AAID）**：可以直接看出这条链是设备自己的应用签发的，还是模块替请求方签发的。
- **失败回退在 3 秒内完成**：等 B 端设备返回结果的上限是 3 秒，超时立刻改用备用出证方式，A 端能拿到一条可用的证书。
- 回退日志按层说明失败原因（服务端密钥 / 服务端自签 / B 端设备）。

A 端模块没有功能改动。
