# B 端模块更新日志

[English](CHANGELOG-B.en.md)

## 1.7.13

- 补上 SELinux 放行规则的应用：以前这块只靠 Magisk / APatch 开机自己重放 `sepolicy.rule`，KernelSU 系根本不重放，那些机器上 B 端一直是裸奔的。现在 post-fs-data 先打一次、service 巡检里缺了再补，工具按 ksud → magiskpolicy → 自带的 `ommega-policy` 依次试。
- 关闭 adbr 调试通道后，设备上的 5555 端口、手动起的 adbd 和 USB 调试开关会一起收掉，不再留调试入口。
- 修复个别机型上已经注册过的指纹材料被当成缺失而重建的问题。
