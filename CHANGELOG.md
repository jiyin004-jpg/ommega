# A 端模块更新日志

[English](CHANGELOG.en.md)

## 1.7.11

- 面板「AOSP 密钥」预设换成仍然有效的那条 AOSP 软件链（RSA，2035-12-30 到期）：原来那条 EC 中级证书 2026-01-08 就过期了，同块的 RSA 条目还缺证书链，keybox.rs 会判整份 keybox 无效、根本加载不上。
- 内置两把 keybox：主 `keybox_tee.xml` 是 TEE 级别（001 那份三级链），`keybox_strongbox.xml` 是 StrongBox 级别，安装时都写入设备。两个级别不再共用一份密钥，TEE 请求不会再拿到 StrongBox 自签的那套。
- 在线源（服务器公开库、Yuri、AOSP）只更新 TEE 那份；StrongBox 那份只能在面板里选文件或恢复内置，没有在线来源。
- 服务端出链：security level 2 的请求只认控制台钉死的 StrongBox 身份，没钉就明确拒绝，不再借用 TEE 身份；源采集也不会写 StrongBox 身份。

- 本地兜底的 SOTER 材料改成真机的形状：一把 ATTK 下面每个 uid 各一把 ASK（用到才生成、落盘复用），ASK 再各自挂 AuthKey。ATTK 不再内置固定密钥：每次发版构建时现生成一把自签（带生成时间），编进 payload 后就不变（除非手动换文件）；ASK 不内置，用到时现生成。
- 上层只需要提供 ATTK 一把（WebUI 或发版内置），ASK 由程序自己生成，对用户透明；removeAllUidKey 会连该 uid 的 ASK 一起删掉。
- 修掉锁屏/解锁周期后整条 ommega 路由变成 SYSTEM_ERROR 4 的问题：零身份的 auth token 不再被当成错误拒绝，镜像恢复也不会因为一条业务拒绝就把所有路由 fail-close（PR #10）。
- 本地兜底 SOTER 的每 uid ASK、AuthKey 都收进 soter_asks.json 一个文件，不再按 uid 散成一堆 pem；AuthKey 也落盘了，payload 重新注入后不用重建。
- 内置的兜底 ATTK 换了一把（自签），旧的那把作废。
