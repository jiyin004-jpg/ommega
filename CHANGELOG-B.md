# B 端模块更新日志

## 1.6.0

版本号与 A 端模块、b-app、服务端统一为 1.6.0。

- **SOTER 转发**：B 端可以接管 SOTER 调用了。微信、支付宝那套 `vendor.trustonic.hardware.soter.ITrustonicSoter` 一共 14 个调用全部实现，参数原样送进真 HAL、结果原样带回去；`op=probe` 用来先问一句这台设备能不能做。
- **会改设备状态的操作默认关着**：建 key / 删 key 那几个（`generate_*_key_pair`、`remove_*_key`）要放行得在 `relay.conf` 里写 `OMMEGA_RELAY_SOTER_MUTATION=1`，默认配置下调用会被拒绝并说明原因。
- **每次 poll 上报本机能力**（`caps=soter` / `caps=strongbox`，都没有就是空串）：服务端靠它把 SOTER 任务发给真能做的设备，状态页也显示。这个探测只问 servicemanager 服务在不在，不碰 HAL，特别是不会动 TEE 里的签名计数器。
- **参数校验提到开 HAL 之前**：请求本身缺 `uid` / `alias` 这类必填参数时直接回错，不再先去连 HAL —— 不然「服务没起」或者 SELinux 拦下来这种错误会把「你参数没给」盖掉。

## 1.5.1

版本号与 A 端模块、b-app、服务端统一为 1.5.1。

- **模块卡片的状态显示更稳**：状态写入改成一次性替换，进程被强杀时不会把模块信息写成空白；模块目录名不是默认值时也能正常更新状态。
- **KeyMint 连接失败会说明真实原因**：状态页能看到是系统拒绝了访问、服务没注册，还是设备只有旧版接口。
- **实例名自动选择**：请求 `/default` 失败时，如果设备上恰好只注册了另一个非 StrongBox 的 KeyMint 实例，会自动改用它。StrongBox 请求不回退。
