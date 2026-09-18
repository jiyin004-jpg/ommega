# 更新日志

## 1.3.1

- **WebUI「全局作用域」开关**（远程配置里）：开启后**谁来调用都处理** —— 不再看 `target.txt`/`scoop`
  名单、`deny_packages` 与未知包名规则，所有 keystore 调用一律由 ommega 接管；本地/远程的判定逻辑不变。
  默认关闭，可随时在 WebUI 里勾选/取消（热生效，无需重启）。
- WebUI 远程配置里新增「查看在线 B 端设备 ID」入口，一键打开 `/status` 页面。
- **内置 PathMask 内核模块**（官方 v2.8.0 资产，7 个内核系列变体，构建期做 sha256 校验）：
  开机按 `uname -r` 的 主.次 选型加载（不看补丁号）；先探测 SoterService 的 binder 服务，
  正常就完全不动作，探测不到才以 `scope_mode=global` 隐藏 `/system/priv-app/SoterService`。
  全程 3 秒内完成、不阻塞开机；检测到别的 pathmask 实例时默认不抢占（可用 `pathmask_takeover=1` 接管）。
- **A 端 `ommegadata` 自愈**：若 `/data/adb/ommega/ommegadata` 被旧版本或手工操作留成真目录（或杂散文件），
  开机时会把其中的 `config` / `target.txt` / `system_app` / `keybox.xml`（较新者胜）迁移进
  `/data/misc/keystore/ommega`，再把该路径替换为符号链接。此前这种情况下 WebUI 保存的远程配置与应用列表
  会写进没人读的影子文件，且不报错（表现为：改了配置却不生效、请求被负载均衡到别的 B 端）。
- 启动属性对齐：`resetprop sys.oem_unlock_allowed 0`、`resetprop ro.secureboot.devicelock 1`。
- `module.prop` 增加 `updateJson`，模块管理器可直接检查更新。

## 1.3.0

- 远程 TEE 转发（A/B 端）、StrongBox 三段模式、Auto Keybox 等，见仓库提交记录。

更早版本见：https://github.com/jiyin004-jpg/ommega/commits/master
