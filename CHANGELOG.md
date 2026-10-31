# A 端模块更新日志

[English](CHANGELOG.en.md)

## 1.7.12

- 面板「伪装参数」里的启动补丁日期改成写 `ro.bootimage.build.date.utc`：属性与证书里的 boot 补丁天然一致。
- 面板里显式填写的伪装项一律强写，不再因设备本身没有那个属性而静默失效。
- 证明密钥签子钥时回到它出生的那一层，不再因切换策略而报 `issuer key not available`。
- MODULE_HASH 按 HAL 版本自适应：KeyMint 4 以下不再写 724，和真机保持一致，Duck Detector 的 MODULE_HASH 不再报矛盾。
- 面板导入 ATTK 时同步 cpu_id：文件带 `cpu_id:` 行就用它，不带就清掉强制值、回到本机现算。
- 修复多线程同时读同一个密钥时 `getKey` 偶发返回空（AProbe 的 L04 并发签名）。
- 修复 KeyAttestation「使用认证密钥」报 `Invalid key blob`：证明密钥按策略铸、子钥回它的出生地签发，不再因切策略错配到另一层。
- 本地 ECDH 协商改在本机完成，不再把 B 端的 TEE 拖进坏状态（之前一碰就整台签名失效）。
- 本地证明密钥的启动状态与远程证书对齐，Duck Detector 的根不一致不再命中。
- 私卡在 A / B 两端都绑定设备，换机需要先解绑（公开卡不受限）。
- 远程出证更快：选路结果缓存、B 端长轮询；另修复若干 SOTER 转发问题。
