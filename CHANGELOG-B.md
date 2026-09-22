# B 端模块更新日志

## 1.3.3

（B 端模块 1.3.3，versionCode 32）

- **证书链为空时不再当成认证成功上报**：KeyMint HAL 如果对 `generateKey` 返回成功、却给了空证书链，
  此前会被当成成功上报成 `cert_chain: []`，服务端只能看到一句「empty cert chain」，看不出是谁掉的。
  现在直接报错并带上原因（`real keymint … returned an empty certificate chain (key_blob NB)`），
  StrongBox 分支也会标成「HAL 接受了生成请求但没给认证证书链」；顺带不再把这种空链 session 写进
  `/data/adb/ommega/sessions`。服务端对「报错」和「空链」的处理本来就一样（进下一层 / StrongBox 降级），
  所以行为不变。
