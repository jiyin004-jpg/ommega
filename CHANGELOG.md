# A 端模块更新日志

[English](CHANGELOG.en.md)

## 1.7.12

- ECDH 只用于协商的 key（`PURPOSE_AGREE_KEY` 且没有签名/解密用途）不再转发到 B，本地 keybox 生成、本地算 —— B 的 TEE 被 `begin(AGREE_KEY)` 进去一次就会掉进 `-49` 且不恢复，之后连普通签名都 `-1000`。
- B 端收到 `agree` 直接回 `unsupported`，不再把任务挂在 binder 上（以前会卡死、服务端反复重投，整条链跟着废）。
- 本地签的 ATTEST_KEY 子钥证书改用远程证书里的 RootOfTrust（`remote_identity` 里的 `device_locked` / `verified_boot_state` / `vbmeta_digest`），两条路径说法一致，Duck Detector 的 `ROOT_OF_TRUST_DIVERGENCE` 不再命中。
- 同一套身份同步按 `remote` 开关走：本地模式下不跟远程的值，并把上次留下的 `orange/unlocked` 主动改回 `green/locked`（daemon 每 2 秒自检，切模式不用重启）。
- 设备指纹（`ro.serialno` / `ro.boot.serialno`）现在 A、B 两端都随请求上报，服务端对私卡（`pair` / `private`）在 A 和 B 两侧都做首次绑定和一致性校验，`public` 卡照旧不受限。
- 选路：绑定的接口先探测再绑、结论缓存 60 秒、请求失败立刻作废并回退；`uplink_absent` / `vpn_present` 这两个每笔都要走的 sysfs 检查缓存 3 秒。
- B 端长轮询从 0 改成 5 秒（必须小于 8 秒的墙钟看门狗），任务到达少等一个轮询间隔；KeyMint HAL 版本探测按 service 名缓存，不再每笔问一次。
- 服务端鉴权结果缓存 10 秒（A 端连发几十笔时只查一次库），`run_a_side_task` 的全量 ctx 日志降到 debug。
- 修正 B 端补丁日期跟随的判断：只比当前值，值变回原值也会真的写回并重读（以前拿固定的基线比，改回原值时会被跳过）。

## 1.7.11

- 能力声明隐藏（`hide_strongbox` / `hide_device_ids`）改成完全自己挂：模块里不再放 `system/` 目录，mountify 这类 metamodule 的 auto 模式也就不会再纳管 ommega。生效方式是 post-fs-data 里把厂商那份权限 XML 拓一份、删掉对应 `<feature>` 行再单文件 bind 回去，`service.sh` 等到 `sys.boot_completed` 之后 `umount -l` 撤掉，`mountinfo` 里只在开机头几十秒看得到。代价是软重启（只重启 system_server）后会重读 XML，需要再冷重启一次。
- 私卡绑定设备：A 端第一次成功请求时，服务端把 `api_token` 的 `bound_serial` / `bound_sn` 记成当前机器的 `ro.serialno` / `ro.boot.serialno`，之后每次请求都要对得上，换设备直接被拒（401）。公开卡和配对卡不参与绑定。
- 卡密自助页：`/card` 底部加了「查询卡密 / 解绑设备」。完整输入卡密才显示内容，能看到卡密、备注、作用域、首次激活、有效期、当前绑定设备，并能就地解绑。
- 控制台 Token 管理加了「绑定设备」列和解绑按钮（只对私卡显示），公开卡照旧不受限。
- MODULE_HASH 的 bootstrap 不再按 KeyMint 版本卡：framework 只在 KM4+ 上主动调 setAdditionalAttestationInfo，但 getSupplementaryAttestationInfo(MODULE_HASH) 不看 HAL 版本、照样返回本机 APEX 摘要，KM3 设备上就成了「证书没有 724、接口却给出 bundle」的矛盾，远程铸证也因此转发不了。现在 bundle 拿得到就写上，本地和转发两条路都有 724。
- 远程铸证补上 MODULE_HASH（tag 724）：本地路径一直有，走中继时 A 端从来不转发这个摘要，铸出的叶子缺 724，设备侧 getSupplementaryAttestationInfo(MODULE_HASH) 却仍返回本机 APEX 摘要，校验方据此报缺失。现在 A 端从 SetAdditionalAttestationInfo 取值原样下发，服务端按 [724] EXPLICIT OCTET STRING 写出（PR #11）。
- 面板「AOSP 密钥」预设换成仍然有效的那条 AOSP 软件链（RSA，2035-12-30 到期）：原来那条 EC 中级证书 2026-01-08 就过期了，同块的 RSA 条目还缺证书链，keybox.rs 会判整份 keybox 无效、根本加载不上。
- 内置两把 keybox：主 `keybox_tee.xml` 是 TEE 级别（001 那份三级链），`keybox_strongbox.xml` 是 StrongBox 级别，安装时都写入设备。两个级别不再共用一份密钥，TEE 请求不会再拿到 StrongBox 自签的那套。
- 在线源（服务器公开库、Yuri、AOSP）只更新 TEE 那份；StrongBox 那份只能在面板里选文件或恢复内置，没有在线来源。
- 服务端出链：security level 2 的请求只认控制台钉死的 StrongBox 身份，没钉就明确拒绝，不再借用 TEE 身份；源采集也不会写 StrongBox 身份。

- 本地兜底的 SOTER 材料改成真机的形状：一把 ATTK 下面每个 uid 各一把 ASK（用到才生成、落盘复用），ASK 再各自挂 AuthKey。ATTK 不再内置固定密钥：每次发版构建时现生成一把自签（带生成时间），编进 payload 后就不变（除非手动换文件）；ASK 不内置，用到时现生成。
- 上层只需要提供 ATTK 一把（WebUI 或发版内置），ASK 由程序自己生成，对用户透明；removeAllUidKey 会连该 uid 的 ASK 一起删掉。
- 修掉锁屏/解锁周期后整条 ommega 路由变成 SYSTEM_ERROR 4 的问题：零身份的 auth token 不再被当成错误拒绝，镜像恢复也不会因为一条业务拒绝就把所有路由 fail-close（PR #10）。
- 本地兜底 SOTER 的每 uid ASK、AuthKey 都收进 soter_asks.json 一个文件，不再按 uid 散成一堆 pem；AuthKey 也落盘了，payload 重新注入后不用重建。
- 内置的兜底 ATTK 换了一把（自签），旧的那把作废。
