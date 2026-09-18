# 更新日志

## 1.3.0

- **A 端 `ommegadata` 自愈**：若 `/data/adb/ommega/ommegadata` 被旧版本或手工操作留成真目录（或杂散文件），
  开机时会把其中的 `config` / `target.txt` / `system_app` / `keybox.xml`（较新者胜）迁移进
  `/data/misc/keystore/ommega`，再把该路径替换为符号链接。此前这种情况下 WebUI 保存的远程配置与应用列表
  会写进没人读的影子文件，且不报错。
- 启动属性补充 `resetprop sys.oem_unlock_allowed 0`、`resetprop ro.secureboot.devicelock 1`。
- `module.prop` 增加 `updateJson`，支持模块管理器在线更新检查。

## 1.2.x 及更早

见仓库提交记录：https://github.com/jiyin004-jpg/ommega/commits/master
