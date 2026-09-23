# B 端模块更新日志

## 1.3.4

（B 端模块 1.3.4，versionCode 34）

- **KeyMint 连接失败不再只说一句 `NameNotFound`**：以前把「service manager 连不上 / SELinux 拒绝
  `find`」和「服务确实没注册」压成同一句话，日志和服务端状态页都看不出区别。现在真实错误码原样
  上报，并附上三项体检结论：`decl=`（VINTF 是否声明该服务）、`aidl=`（实际注册的
  IKeyMint/IKeymaster 实例名）、`hidl_km=`（设备上存在的 HIDL keymaster 客户端库版本）。服务端
  TEE 自检拿到的 `tee_error` 会直接带这些信息——只有 HIDL keymaster、没有 AIDL KeyMint 的老机型
  一眼可辨。
- **实例名不再写死 `/default`**：请求 `/default` 失败时，如果服务管理器里恰好注册了另一个非
  strongbox 的 KeyMint 实例，会自动改用它（AOSP keystore2 同样按 VINTF 声明枚举实例），并留一条
  warn 日志。StrongBox 请求不走这条回退：缺 StrongBox 就该失败、由 A 端降级到本地密钥，不能拿
  TEE 链冒充。
