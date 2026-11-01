# Ommega A 端真实缺口调查与探针检测器

调查对象：本工作区当前 Ommega A 端模块 2.0.1（HEAD b7375d8），不是 wt-release-214 的 2.1.4。
对照基准：Android 17 AOSP android17-release
- platform/system/security @ cbb2ef1617a94d6cdf2dc2ccb7a545575dbb20cb（keystore2）
- platform/system/keymint @ cfeefc94bf8c4f19d19dca193d376a1fc05e8e3e（kmr / KeyMint reference）
- platform/hardware/interfaces/security/keymint（HAL v5 / ML-DSA）
- platform/frameworks/base/keystore/java（AndroidKeyStore provider）

> 本文只做静态调查与检测器实现。没有修改 A 端模块源码，没有部署、重启或探测 B 端。
> 当前 ADB 只连接了 B（e73a228c / PHB110），A 不在线，因此检测器尚未在 A 上执行；
> APK 已构建，安装后即可在 UI 上逐项列出结果。

## 0. 结论摘要

当前 A 端模块不是“完全等价于 Android 17 KeyMint 的软件 TA”，而是“以 AOSP kmr/keystore2
为底、为远程 relay 和检测器兼容做了显式改写的代理”。调查确认了 23 类真实缺口/检测点（F-23 为 AOSP 权限门误报，不计入缺口）
真实缺口；其中 6 类可由普通 Android Keystore API 直接观察到，2 类需要 raw Binder/Parcel 或
root 文件证据，2 类是 Android 17 新增合同/证书后处理路径缺失。

最严重的两条：

1. 所有远程密钥的 begin(SIGN) 必然失败：remote_sign_algorithm 从 begin 参数取
   ALGORITHM，但 KeyMint 合同里 ALGORITHM 是密钥特征，不是 begin 入参。命中后返回
   UNSUPPORTED_ALGORITHM(-4)，应用侧表现为 SERVICE_ERROR / Failed to begin operation。
   这条在 2.1.3 的 29376de 才修复。
2. 同一台设备上“带 challenge / 不带 challenge”的密钥会报告不同的 SPL 版本标签：
   本地路径用 A 的 [trust]/HAL 属性，远程路径用 B 证书里的标签；当前树没有 2.1.3 的
   remote_version_tags profile 交换。Luna 的 F17/F22 探针就是抓这个。

## 1. 缺口清单

| ID | 严重度 | 缺口 | 代码证据（当前树） | AOSP 17 依据 | 检测项 |
|---|---|---|---|---|---|
| F-01 | P0 | 远程 EC/RSA/ECDSA 的 begin(SIGN) 拿不到 ALGORITHM，全部失败 | ta/src/operation/begin.rs:325、:561-562 | kmr ta/src/operation/begin.rs 的 check_begin_params 从 key characteristics 取 algorithm；begin 参数不含 ALGORITHM | R01/R02/R03/R06/R07/R08 |
| F-02 | P0 | 生成/导入/升级的 705/706/718/719 与 challenge 证书不一致 | ta/src/lib.rs:1437-1446；ta/src/keys.rs:752；无 remote_version_tags | KeyMintVersionTags / profile 取真实 HAL 版本（2.1.3 797d376） | A10-A14、S06 |
| F-03 | P0 | 3DES CBC/ECB PKCS7 解密失败 | crypto/src/des.rs:131-160 | kmr-crypto des.rs 的 final-block/padding 语义 | C01/C02 |
| F-04 | P0 | NONEwithRSA 签名验不过 | crypto/src/rsa.rs:95-120、:287-310 | kmr-crypto rsa.rs 使用 new_unprefixed() + blinding | C03 |
| F-05 | P0 | AES-CTR 只使用前 12 字节计数器 | crypto/src/aes.rs:185-220 | kmr-crypto CTR 使用完整 16 字节初始计数器 | C04 |
| F-06 | P0 | AES-192-GCM 与 12-15 字节 GCM tag 不支持 | crypto/src/aes.rs:269-292 | kmr-crypto 支持 128/192/256 + GcmTag12..16 | C05/C06.* |
| F-07 | P0 | CBC/ECB PKCS7 接受非块对齐密文尾部 | crypto/src/des.rs:131-160；aes.rs 同类 update 缓冲 | kmr-crypto 在 update/finish 检查块对齐 | C07/C08 |
| F-08 | P1 | raw RSA NoPadding 解密接受 c >= n | crypto/src/rsa.rs:139-170 | kmr-crypto 对代表值范围检查 | C09 |
| F-09 | P0 | 非零 Parcelable presence marker 被拒（Android Parcel 语义） | ommega-injector/src/parcel.rs 无 impl_android_deserialize_for_parcelable；build.rs 无替换 | Android Parcel.readTypedObject：0=null，任意非 0=present（2.1.3 1ce292d） | K02/K03 |
| F-10 | P0 | 软件 keyblob 的 patchlevel/version 反降级被禁用，upgradeKey 允许降级 | ta/src/lib.rs:521-529（check 恒 Ok）；ta/src/keys.rs:1318-1338（Greater 时写回 curr） | kmr ta/src/lib.rs 对 < 返回 KeyRequiresUpgrade、对 > 返回 InvalidKeyBlob | 需 root/SPL 变更，检测器 F02/F03 只取证 |
| F-11 | P1 | 本地 ATTEST_KEY 子钥被 sleep 对齐到远程 RTT，规避 Duck 时序探针 | ta/src/keys.rs:49-88、:535-569 | AOSP 无该 EWMA/padding 逻辑 | T03/T04 |
| F-12 | P1 | 普通 app 的认证绑定证书被改成 NO_AUTH_REQUIRED，只有特定 alias 保留 | ta/src/keys.rs:648-657；common/src/auth_signing.rs:86-118 | KeyMint 证书必须反映真实 502/504/503；不能按 alias 特判 | A29/A30/A31 |
| F-13 | P1 | verified boot 属性被 resetprop，/proc/cmdline/bootconfig 仍是原始值 | template/post-fs-data.sh；ta/src/lib.rs:649-681 | RootOfTrust 必须来自真实 bootloader；属性/证书不能与内核命令行矛盾 | B03/B04、A09 |
| F-14 | P1 | Android 17 RKP 证书后处理服务未实现，RKP 链总是 concat 塞进一个 Certificate | src/keymaster/security_level.rs:943-948 | AOSP 17 security_level.rs:777-801 调 process_certificate_chain（受 remote_provisioning.use_cert_processor） | A19/A20、F04 |
| F-15 | P2 | destroyAttestationIds 仍走删除实现，而 Android 17 要求 UNIMPLEMENTED | keymint_device.rs:763-766；ta/src/lib.rs:1222-1237 | Android 17 IKeyMintDevice.aidl 把该方法标为 deprecated，必须返回 UNIMPLEMENTED | F07（root/raw HAL 才可达） |
| F-16 | P2 | 默认 scoop 把检测器包名写死；改名/新检测器直接走 System | template/injector.toml:12；ommega-injector/src/config.rs:137 | 路由应按调用者和配置，不应依赖检测器包名列表 | F01/F04 |
| F-17 | P2 | auth_signing 的 known_probe 只匹配 TrustAttestor_silent_auth_<UUIDv4> 的精确参数 | common/src/auth_signing.rs:86-118 | 不应按 alias 形状改变认证策略 | A30 |
| F-18 | P1 | 远程 attestation 证书链未做可信根/逐级签名/吊销校验 | src/remote/backend.rs:89-137；ta/src/cert.rs:473-529 只校验叶 challenge/appId/level | keystore2 应把链交给可信的证书后处理/校验路径；不能让任意 relay 叶证书通过 | A19（检测器自行逐跳验签） |
| F-19 | P1 | 镜像 HAT 路径跳过系统 MAC 校验并重新本地化 | src/keymaster/authorization.rs:322-336；keymint_device.rs:977-998 | 直接 addAuthToken 必须校验原始 MAC；不能仅凭调用来源跳过 | 静态/root raw（K 组不做 HAT 注入） |
| F-20 | P1 | 错误文本中的源码路径被改写成 AOSP 路径，直接规避 TrustAttestor 指纹 | src/keymaster/error.rs:198-212（normalize_source_path） | AOSP 不重写错误路径；调用者看到真实构建路径是正常行为 | F07（root 二进制字符串） |
| F-21 | P0 | setDevicePropertiesAttestationIncluded(true) 的密钥生成在 A 上失败 | src/att_mgr.rs；src/plat/device_ids.rs；ta/src/cert.rs:1010-1015（CannotAttestIds） | Android 17 要求设备属性 attestation 可用；B stock 同代码通过 | A07（r18 起独立探测） |
| F-22 | P0 | A 的 ML-DSA-65/87 在 API 37 上不可用 | src/plat/keymint_profile.rs:40-75（沿用 B profile 200）；ta/src/keys.rs ML-DSA 分支 | Android 17 TEE 必须支持 ML-DSA-65/87、证书 tag 11、KeyInfo keySize=-1 | M01-M04 |
| F-23 | — | A16 uniqueId 失败是 AOSP 权限门，不是 Ommega 缺口 | src/keymaster/security_level.rs:621-628；AOSP 17 security_level.rs:506-511 同样检查 GenUniqueId/permission | AOSP 要求普通 app 无权限时拒绝；B vendor 宽松，A 正确 | A16（应改为 PASS/SKIP，不是 HIT） |
| F-24 | P1 | A 端全局 CPU/设备属性视图把 Build.MODEL/DEVICE/SOC_MODEL 改成 B 的值，与 Build.FINGERPRINT/构建号不一致 | a-side/source/cpu-mask/；template/post-fs-data.sh | 应用进程看到的 Build.* 应自洽；A07 若拿被改写的 Build 做比较会假通过 | B07（记录）+ 建议新增 B09 |

## 2. 重点缺口的可观察形态

### F-01 远程 SIGN 全灭

当前 KeyMintTa::begin 的 KeyMaterial::Remote 分支：

    KeyPurpose::Sign => CryptoOperation::RemoteSign {
        alias: remote.alias.clone(),
        algorithm: remote_sign_algorithm(&params)?,   // params = begin 入参
        data: Vec::new(),
    },

remote_sign_algorithm 第一行：

    let algo = get_algorithm(params)?;   // begin 参数没有 ALGORITHM

KeyMint 合同：begin 的参数是 PURPOSE、DIGEST、PADDING、MGF_DIGEST 等 operation 参数；
ALGORITHM 是 getKeyCharacteristics 返回的密钥特征。因此：

- 任何“带 challenge 且走 remote”的 EC/RSA 密钥，在 begin(SIGN) 时都会得到
  Hal(UnsupportedAlgorithm, missing tag Algorithm)；
- keystore2 把它映射为 SERVICE_ERROR / Failed to begin operation；
- 远端签名永远不会进入 event=remote_sign。

历史证据：检测器/TEE检测/keymint-A.log 内 11 次 failing DeviceBegin ... common/src/tag.rs:188 ...
missing tag Algorithm，event=remote_sign 0 次；检测器/TEE检测/A端-10项异常-归因.md 已给出同一根因。
2.1.3 的 29376de 才把 get_algorithm(key_chars) 传入。

检测器：R01-R08 用标准 Signature/KeyAgreement/Cipher 直接复现；失败详情保留异常类名和
getMessage()，并在 F02 日志检查中统计 event=remote_sign 与 missing tag Algorithm。

### F-02 版本标签 A/B 混用

当前 add_keymint_tags：

    if let Some(hal_info) = &self.hal_info {
        kc.authorizations.try_extend_from_slice(&[
            KeyParam::OsVersion(hal_info.os_version),
            KeyParam::OsPatchlevel(hal_info.os_patchlevel),
            KeyParam::VendorPatchlevel(hal_info.vendor_patchlevel),
        ])?;
    }

远程路径又用 overlay_remote_version_tags 把证书里的值覆盖到 chars。结果：

- 不带 challenge（本地生成）：705/706/718/719 来自 A 的 [trust] / 属性；
- 带 challenge（远程生成）：来自 B 的真 HAL 证书；
- 两者在同一次启动、同一台 A 上可以不同（B 的 boot patchlevel 与 A 不同）。

Android 17 的 KeyMint profile 语义要求同一实现/同一后端给出一致的版本授权；Luna F17/F22
就是按“同设备两次生成”比较。2.1.3 797d376 新增 B 端一次性 AES-GCM 读 HAL
KeyCharacteristics，A 端 KeyMintVersionTags profile 字段，并拒绝证书与 profile 不一致。

检测器：A10-A14 直接比较 ec_att（challenge）与 ec_plain（无 challenge）的 705/706/718/719；
S06 再做一次同样比较。A14 是“命中即证据”，不依赖 B 是否可达；若远程不可用，A14 会把
ec_att 生成失败显示为 HIT/异常，需结合 A01/R01 判断。

### 2.4 实测证书样本（只读解析）

用本检测器的 DER 解析器（与 APK 内同一份 Attestation.java）解析历史样本
artifacts/cleanup-20261022/root-temp/.tmp-paytm_batch_signing_v3-leaf.der：

    subject=CN=Android Keystore Key serial=1
    attestationVersion=200 level=1/1 challenge=32
    hwTags=[1,2,3,5,10,503,702,704,705,706,718,719]
    705=170000 706=202609 719=20251201
    purpose=[2,3] algorithm=3 keySize=256 ecCurve=1
    RootOfTrust locked=true state=0 keyLen=32
    sw 709: pkg=[net.one97.paytm] version=[722033] signatures=1

这张真实 A 端链同时印证两件事：

- 硬件授权列表里有 503 NO_AUTH_REQUIRED，没有 502/504。Paytm 是普通 app，不是
  TrustAttestor_silent_auth_<uuid>，正好落在 F-12 的“普通 alias 被改写”路径上；
- 706=202609，719=20251201。OS patch 与 boot patch 不同源；如果同次启动再生成一张
  不带 challenge 的本地证书，A14 期望它们相同，当前实现无法保证。

样本只用于验证解析器与缺口形态，不证明所有 A 端密钥都长这样；检测器在 A 上重新生成
的 ec_att/ec_plain 才是本次验收证据。

### F-03 至 F-08 软件 crypto 合同

当前 crypto/src 是 Ommega 自己的 kmr-crypto-ommega，不是 AOSP kmr-crypto 的完整移植。
2.1.3 2cb8f23 的 release 报告列出了六类差异，本树全部存在：

| 检测项 | 当前行为 | AOSP/KeyMint 期望 |
|---|---|---|
| C01/C02 | 3DES CBC/ECB 解密保留最终块/填充处理错误 | 解密 update 保留最后一块，finish 去填充；CBC 链值跨调用保存 |
| C03 | NONEwithRSA 套了 DigestInfo | PKCS#1 v1.5 type-1 00 01 FF..FF 00 || data，new_unprefixed |
| C04 | CTR 只用 12 字节 nonce，后 4 字节清零 | 完整 16 字节初始计数器，大端 128 位进位 |
| C05 | AES-192-GCM 走错 key size / 不支持 | 128/192/256 全支持 |
| C06.* | 只接受 16 字节 tag | 12/13/14/15/16 字节 tag |
| C07/C08 | 非整块尾部被缓冲吞掉 | DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH |
| C09 | c >= n 直接模幂 | 拒绝代表值范围 |

检测器按 KmProbe 的 10 项扩展为 15 项，并加入 3DES 双模式、GCM 四档 tag、CBC/ECB 两种
截断、RSA NoPadding c=n、RSA 五 digest、ECDSA 三曲线、GCM AAD/篡改、HMAC、32 KiB 边界。

### F-09 Parcel presence marker

Android Parcel.readTypedObject 的规则是：0 表示 null，任意非 0 的 32 位整数表示 present。
当前 injector 的 generated deserializer 仍使用 rsbinder 默认实现（只认 canonical 1）。
因此 raw getKeyEntry 用 marker 2/-1 时，injector 会把它当非法/空对象，表现为：

- 直接返回解析错误；或
- 同一 alias 在“标准 Java 调用”与“非零 marker 的 raw 调用”之间出现分裂视图。

2.1.3 1ce292d 在 ommega-injector/src/parcel.rs 加了
impl_android_deserialize_for_parcelable!，并在 build.rs 替换生成的
rsbinder::impl_deserialize_for_parcelable!。当前树没有这段。

检测器：K02 用同一 alias 分别发 marker 1/2/-1 的 getKeyEntry；K03 发 marker 0（必须
拒绝），K04 发错误 interface token（必须传输层失败），K05 发 trailing int（必须拒绝）。

### F-10 反降级禁用

当前 ta/src/lib.rs：

    // Patch-level / version anti-downgrade checks are intentionally
    // disabled: Ommega lets the user override the security patch date ...
    fn check(_v: &u32, _curr: u32, _name: &str) -> Result<(), Error> {
        Ok(())
    }

upgrade_key 中：

    Ordering::Greater => {
        // We allow patchlevel downgrades.
        *v = curr;
        Ok(true)
    }

AOSP 17 kmr 的行为：Less -> KeyRequiresUpgrade；Greater -> InvalidKeyBlob。
影响：

- 用高 SPL 生成的 keyblob，在低 SPL 下仍可加载/使用；
- upgradeKey 会把 keyblob 内记录的标签改成当前较低值，等于把“升级”做成“降级 + 重签”；
- 检测器需要在 SPL 变更窗口读取 keyblob 才能观察；普通 app 没有 upgradeKey API，
  因此本检测器只做静态/日志取证（F02/F03），不提供自动改 SPL。

### F-11 时序整形（反 Duck Detector）

ta/src/keys.rs 顶部：

    /// Duck Detector's Keystore2PostProcessingProbe pairs a challenge-only
    /// generateKey (RKP / batch-key arm, which we send remote) against a
    /// challenge+ATTEST_KEY generateKey (UserGenerated arm, which we keep local).
    /// It flags TIMING_DETECTED when the remote arm is >= 120ms slower ...
    static REMOTE_ATTEST_EWMA_NS: Mutex<u64> = Mutex::new(0);

pad_local_attest_key 时：

    if pad_local_attest_key {
        equalize_to_remote_attest_duration(started);
    }

这是明确的检测规避代码，不是 AOSP 行为。检测器 T03 用“本地无 challenge 父钥 + challenged
子钥”触发 local arm，比较 plain/child 中位数；若 child > max(3x plain, plain+50ms) 且
>80ms，判为整形。T04 再做 Duck 风格的配对差（>120ms 且 >3x control 记录为 HIT）。

### F-12 认证策略与 known probe alias

ta/src/keys.rs 远程参数：

    if a_authorized_signing {
        remote_params.user_auth.retain(|(tag, _)| *tag == 509);
        remote_params.user_auth.push((503, 1));
    }

普通 app 的 auth-bound key 走 A authorization 时，B 证书被写成 NO_AUTH_REQUIRED；
而 A 自己在本地 keyblob 里保留 502/504/505，并继续要求 HAT。common/src/auth_signing.rs
的 known_probe 只对以下 alias 保留原策略：

    let Some(uuid) = alias.and_then(|a| a.strip_prefix("TrustAttestor_silent_auth_")) ...
    uuid_v4 && eligible(params) && ... exact params ...

普通 alias（例如支付 app 的 payment_key）不会命中，因此证书里的认证要求与 A 实际执行
不一致；反过来说，检测器只要换一个 alias 就能让 Ommega 选择不同策略，这是可检测的
实现指纹。检测器 A29/A30/A31：

- A29 普通 alias：证书应含 502/504，不能有 503；
- A30 known alias 与普通 alias 的授权集合应相同；
- A31 KeyInfo.isUserAuthenticationRequired() 与证书一致。

### F-13 RootOfTrust 与内核命令行

post-fs-data.sh 会在框架启动前 resetprop：ro.boot.verifiedbootstate、ro.boot.flash.locked、
ro.boot.veritymode、ro.boot.warranty_bit 等；README 明确说内核自己的 /proc/bootconfig、
/proc/cmdline 保持原值（第 160-169 行）。

A 端证书的 RootOfTrust 由 set_boot_info 的 boot_info 生成，而 boot_info 来自属性层。
因此可观察形状是：

- 证书 704：locked=true、state=Verified(0)；
- getprop ro.boot.verifiedbootstate：green（被 resetprop）；
- /proc/cmdline：androidboot.verifiedbootstate=orange（未被 resetprop）。

检测器 B03/B04 直接比较属性与 cmdline/bootconfig；A09 再比证书 704 与属性。
这不是“A 端 KeyMint 的证书字段错误”，而是“属性层伪装与内核事实不一致”，属于最容易被
严格检测器抓的点。

### F-14 Android 17 RKP 证书后处理

AOSP 17 keystore2/src/security_level.rs 在 RKP 分支：

    if read_bool("remote_provisioning.use_cert_processor", false).unwrap_or(false) {
        result.certificateChain = process_certificate_chain(result.certificateChain, attestation_certs);
    } else {
        result.certificateChain.push(Certificate { encodedCertificate: attestation_certs });
    }

当前 A 端 src/keymaster/security_level.rs:943-948 只有 push 分支，没有
IKeystoreCertificatePostProcessor 调用；aidl/ 也没有 Android 17 新增的
android/security/postprocessor/ 两个 AIDL。若设备启用了该 flag（新版本 GMS/ROM 可能），
RKP 链不会经过后处理，链内容与 stock 不同。检测器目前通过 A19/A20 检查链闭合与
issuer 身份；如果要在 A 上强制触发 use_cert_processor，需要 root setprop，本工具不自动做。

### F-15 destroyAttestationIds 语义

Android 17 IKeyMintDevice.aidl 已把 destroyAttestationIds() 标为 deprecated：

> This method is deprecated. Implementations must return ErrorCode::UNIMPLEMENTED.

当前 keymint_device.rs:763 仍把它转给 TA，ta/src/lib.rs:1222 会清空缓存的 attestation
IDs 并调用 destroy_all()；若 dev.attest_ids 为 None，返回 Unimplemented，但为 Some 时
会真的删除。普通 app 无权限调用，只有 raw HAL/root 可达；检测器把它列为 F07 静态项。


### F-18 远程证书链信任边界

src/remote/backend.rs 只做 base64 解码和 x509_cert::Certificate::from_der 解析，随后把 chain 原样返回给 TA；TA 的 validate_remote_attestation 只检查：

- 叶证书有 attestation 扩展；
- challenge、applicationId、attestationSecurityLevel/keymintSecurityLevel 与请求一致。

没有检查链上每一跳的签名、根证书是否可信、BasicConstraints/KeyUsage、吊销或 keybox 身份。README 也写明“尚未完成完整证书链的可信根、逐级签名及撤销校验”。这意味着：如果 relay/Server 被攻破或返回错误链，A 仍会保存并返回该链；只有应用自己验链时才会发现。检测器 A19 对 A 返回的链逐跳验签，A19 命中即可证明 A 没有拒绝坏链；但正常 B 链会通过 A19，因此 A19 不是“信任根校验”的完整替代。

### F-19 镜像 HAT 的 MAC 跳过

src/keymaster/authorization.rs 对 mirrored/config fallback 的 authType 走 should_skip_system_auth_token_verification，直接跳过 verify_system_auth_token；随后 localize_auth_token_for_source 用本地 HMAC 重新计算 MAC，而不是验证原始 MAC。注释明确说“不要在 mirrored 路径上应用 ommega-only shape/MAC checks”。普通 app 没有 IKeystoreAuthorization.addAuthToken 权限，因此不是普通 API 可观察缺口；但任何拥有该权限的系统组件或被注入的 system_server 调用都可以注入任意 SID/challenge 的 HAT，A 会把它当作有效 token。检测器没有自动注入 HAT，只在报告中列为静态边界。


### F-20 错误路径指纹洗白

src/keymaster/error.rs 的 normalize_source_path 把 anyhow 错误链里的：

- src\\keymaster\\security_level.rs
- src/keymaster/security_level.rs

替换成 system/security/keystore2/src/security_level.rs。代码注释直接写明目的：TrustAttestor 的 parameter_fingerprint/backend_provenance 会把 src/keymaster 判成软件转发器，把 system/security/keystore2/src 判成 AOSP；重写让文本“与真机一致”，避免暴露派生链。

这不是 AOSP 行为，而是针对检测器的字符串级规避。普通 app 触发一个 KeyMint 错误后，看到的错误文本已经是洗白后的路径；检测器无法仅凭错误文本区分。F07 改为在 root 下直接 grep keymint 二进制，查找重写表里的 src.keymaster 字符串；命中说明该实现仍携带这段洗白逻辑。


### F-21 设备属性 attestation 在 A 上失败

A 端实测（PJZ110，API 37）中，只要 KeyGenParameterSpec 带 setDevicePropertiesAttestationIncluded(true)，所有非对称密钥生成都抛 ProviderException: Failed to generate key pair；同一台设备上不带该参数的认证绑定密钥（A29/A30/A34）可以生成。B stock 用同一段探针可以通过。

A 端路径：

- src/att_mgr.rs 负责收集 brand/device/product/manufacturer/model；
- src/plat/device_ids.rs 负责设备 ID 与属性；
- ta/src/cert.rs 的 AuthorizationList::new 在请求 ID 但快照为空时返回 CannotAttestIds（no attestation IDs provisioned）。

因此这不是“探针不会写参数”，而是 A 端设备属性 attestation 的真实失败。r18 已把设备属性从所有基础 fixture 中拆出，A07 单独请求并捕获异常；其余 A/R/C 检查不再被它连带成 ERROR。

### F-22 A 上的 ML-DSA 不可用

A 端实测 API 37，ML-DSA-65/87 的 generateKey 均 ProviderException；M05（StrongBox 拒绝）和 M06（SIGN+ATTEST_KEY 拒绝）能返回正常错误，说明请求到达了 KeyMint，但 ML-DSA 能力本身没有暴露。

当前 A 端软件 TA 代码含 ML-DSA 实现（common/src/crypto/mldsa.rs、crypto/src/mldsa.rs、ta/src/cert.rs tag 11），但 src/plat/keymint_profile.rs 在 remote 模式沿用 B 的 KeyMint profile（实测 B 为 200）。AndroidKeyStore 只有在 HAL 版本/能力达到 v5 时才开放 ML-DSA；A 端因此表现为 API 37 但 ML-DSA 不可用。这是“身份/版本标签”与“新算法能力”耦合的真实缺口。

## 3. Android 17 其他合同与当前实现

### 3.1 ML-DSA

AOSP 17 要求 TEE KeyMint 支持 ML-DSA-65/87、禁止 StrongBox、raw/PKCS#8 seed 导入、
ML_DSA_VARIANT(11) 证书标签、KeyInfo.getKeySize() == -1、purpose 只能 SIGN 或
ATTEST_KEY（不能同时）、digest 只能 NONE。当前树已有：
common/src/crypto/mldsa.rs、crypto/src/mldsa.rs、ta/src/cert.rs tag 11、
common/src/tag.rs 的 StrongBox 拒绝。检测器 M01-M06 逐项检查；M06 覆盖 purpose 组合，
M07 未单独实现。没有证据表明 ML-DSA 已完全对齐，因此 M 组在 A 上若出现 HIT，应优先按
AOSP 17 AIDL 的 ML-DSA 段落复核。

### 3.2 StrongBox

README 180-199 已说明：
- 没有 keybox-strongbox.xml 时，StrongBox 证明失败 ATTESTATION_KEYS_NOT_PROVISIONED；
- 不得把 TEE 链标成 StrongBox；
- 没有原生 StrongBox HAL 时 HARDWARE_TYPE_UNAVAILABLE。

当前 keymint_device.rs:960-964 在 strongbox_keymint_present() 为 false 时直接
HARDWARE_TYPE_UNAVAILABLE；keybox.rs 的专用材料逻辑存在。检测器 S01-S06 检查
feature/请求/证书/专用 keybox 的一致性。注意 A 的 StrongBoxCapabilityMask 只在
system_server 功能表层隐藏 feature，不改变 KeyMint 层的真实请求结果；两者可能被
不同进程看到不同值，这是另一个“功能声明 vs 请求结果”检测点。

### 3.3 操作上限

当前 ta/src/lib.rs:385 的 set_max_operations 是 Ommega 增加的“镜像 B 实现”的配置，
AOSP KeyMint 没有 HAL API 暴露该值。默认 16（TEE）/4（StrongBox）与 AOSP kmr 一致；
若 B profile 的 max_operations 与 B 实际不符，A 会按错误值限制。检测器 L01 只测本地
16 上限，F02/F03 读取 profile 日志；不把“可配置”本身判成缺口。

## 4. 检测器

位置：检测器/AProbe/
- 源码：app/src/main/java/aprobes/
- APK：app/build/outputs/apk/debug/app-debug.apk
- 构建：Gradle 8.13.2 / compileSdk 37 / minSdk 31 / arm64-v8a JNI
- JNI：app/src/main/cpp/hiddenapi.cpp -> libhiddenapi.so，仅用于
  VMRuntime.setHiddenApiExemptions(new String[]{"L"})，让 raw keystore2 AIDL 可反射；
  不修改系统、不注入其他进程。

UI：
- 顶部显示机型/Android/API/补丁级别/uid/ABI；
- 按 B/A/R/C/M/K/S/T/L/F 分组，每项一张卡片：状态、ID、标题、AOSP 期望、本机结果；
- 顶部汇总 通过 / 命中 / 跳过 / 不确定 / 异常；
- “重新运行”只重跑探针；“复制结果”把 files/a-gap-probe.txt 放入剪贴板；
- 结果同时写 getExternalFilesDir()/a-gap-probe.txt（/sdcard/Android/data/aprobes.agap/files/）。

检测项共 105 个（B08 + A38 + R12 + C18 + M06 + K06 + S06 + T04 + L04 + F09（实际 110））。
其中 6 个是“控制/记录”项（B01/B07/B08/T01/T02/A28），不作为失败判据；其余按
PASS / HIT / SKIP / INCONCLUSIVE / ERROR 区分。

运行前提：
- A 端模块已安装并重启 Zygisk/KeyMint；
- 目标包 aprobes.agap 加入 Ommega 作用域（否则所有请求走 System，探针会显示 stock 结果）；
- 可选 root（KernelSU/APatch su）用于 F 组只读文件/日志；无 root 时 F 组 SKIP；
- 检测器不会调用 su 写入、重启、杀进程或改属性；只 cat/test/getprop。

## 5. B 端操作与边界

仓库根 AGENTS.md 禁止在主 B 上安装 APK、推探针、改属性、重启或做直接 HAL/TEE 实验。本次在用户明确批准“安装并重跑修正版探针”后执行了以下只影响探针 App 的操作：

- 只读预检：序列号 e73a228c、PHB110、transport 12、sys.boot_completed=1、user 0 RUNNING_UNLOCKED、SELinux Enforcing；
- adb install / uninstall / install -r 探针 APK；am start/force-stop 仅针对 aprobes.agap；
- 未重启设备、未重载 KeyMint/服务、未改 SPL/属性、未做 direct IKeyMintDevice/IKeyMintOperation 调用；
- R05 AGREE_KEY 在 PHB110 上强制 SKIP，遵守 incident guard；
- 回滚：uninstall aprobes.agap 即可移除探针；探针只使用自己的 aprobes_* 别名并在运行后清理。

## 6. 复现与构建

    $env:GRADLE_USER_HOME='D:\Users\Andrea-TB\Desktop\ommega\.gradle-home'
    $env:ANDROID_USER_HOME='D:\Users\Andrea-TB\Desktop\ommega\.android-home'
    cd 检测器\AProbe
    & 'E:\Buildcache\gradle\wrapper\dists\gradle-9.2.0-bin\11i5gvueggl8a5cioxuftxrik\gradle-9.2.0\bin\gradle.bat' assembleDebug --no-daemon

产物：检测器/AProbe/app/build/outputs/apk/debug/app-debug.apk（debug 签名，安装前卸载旧包）。


## 7. B 端首版实测与校准（2026-10-30 12:54）

设备：OnePlus PHB110 / Android 17（API 36）/ patch 2026-09-01 / uid 10351。
首版 APK（106 项）结果：61 PASS、13 HIT、4 ERROR、2 INCONCLUSIVE、26 SKIP。
原始输出：BASELINE-B-20261030.txt。

13 个 HIT 中没有一个是“A 端 Ommega 缺口”；全部是探针假设错误或 B 厂商/基线差异：

- A12：718 是 YYYYMMDD（20260901），旧探针按 YYYYMM 截成 202609；已改为 8 位。
- A14/S06：无 challenge 的 stock 密钥根本没有 attestation 扩展，旧探针却把“无扩展”判 HIT。A14 已改为“本地 ATTEST_KEY 子钥证书 vs 远程 challenge 证书”的标签比较；无扩展则 SKIP。
- A17：B vendor HAL 证书没有 701；已改为若存在则检查、缺失则 SKIP。
- A18：B stock notAfter=2048，不是 9999；已改为只要求当前有效期。
- A27：B 的 KeyInfo.origin=1 与证书 origin=0 不一致；按 B 标准改为 INCONCLUSIVE 记录。
- A29/A31：KeyMint 有意不把 502 USER_SECURE_ID 写进证书（encode_sid=false）；旧探针要求 502 是错的。已改为 504 present、503 absent。
- A36：B 证书 506=true、KeyInfo=false；按 B 标准改为 INCONCLUSIVE。
- R07：探针给 P-384 密钥只申请 SHA-256 digest，却用 SHA384withECDSA；已改为 SHA-384 digest。
- C14/L01/L02：Java provider 会分块/延迟，不能用 JCA 观察 raw HAL 的 32 KiB 或 16 operation 上限；已改为 INCONCLUSIVE。

4 个 ERROR：

- A35：B 的 KeyInfo 没有 isUnlockedDeviceRequired 方法；已改为反射缺失时 SKIP。
- C09：NoPadding RSA 密钥没设 setRandomizedEncryptionRequired(false)；已修复，等待复测。
- C12：AES-GCM 显式 IV 与 randomized 冲突；已改为 false，等待复测。
- T03：本地父钥不是 PURPOSE_ATTEST_KEY；已改为 genAttestKeyLocal，等待复测。

2 个 INCONCLUSIVE：

- A20：B 的 CA subject 没有 T/O 标签；已按 B 标准改为 PASS/记录。
- A28：KeyInfo purpose bitmask 12 对应证书 [2,3]；已实现 bitmask 与 digest 映射，下一版应为 PASS。

26 个 SKIP 中：

- M01-M06：B 是 API 36，ML-DSA 是 Android 17/API 37 合同，跳过正确。
- K01-K06：首版用 Java 反射拿 hidden API 失败；本版已新增 JNI raw Binder（ServiceManager/Parcel/IBinder，事务号 2），K02-K05 不再依赖 hidden API；K01/K06 仍可回退。
- S03-S05、F01-F06：B 无 root，只读文件检查不可用；A 端 root 下可运行。

### 校准后的产物

- APK：app/build/outputs/apk/debug/app-debug.apk（192,896 B，SHA-256 CEB825CD43931E08A460BCF2DBD9A379D83ADFD91824C0A500B16F078D66DC14）
- 111 项：B08 + A38 + R12 + C18 + M06 + K06 + S06 + T04 + L04 + F09（实际 110）
- 本版已在 B 上重装并重跑（r11 基线）：76 PASS、0 HIT、0 ERROR、6 INCONCLUSIVE、28 SKIP。K02 已 PASS：手工 Parcel 原先漏了 rsbinder 的 sized_write 4 字节 size 前缀，补上后 marker 1/2/-1 都被 stock B 接受；K05 改为记录 stock 的 sized_read 忽略尾部字节。首版崩溃（HiddenApi JNI 对 VMRuntime 静态方法调用 SIGABRT）已通过移除 native exemption 调用修复；K02/K04/K05 仍受手动 Parcel/IAE 限制，保持 INCONCLUSIVE/SKIP。
- 最新 B 基线：BASELINE-B-20261030-r14.txt（111 项；77 PASS、0 HIT、0 ERROR、6 INCONCLUSIVE、28 SKIP；B09 PASS）。
- 最新 A 原始输出：用户提供的 a-gap-probe1.txt（r18，110 项）。6 个 INCONCLUSIVE：A27（厂商 KeyInfo origin 1 vs 证书 0）、A36（厂商 KeyInfo on-body false vs 证书 506 true）、C14/L01/L02（JCA 不能观察 raw HAL 的 32 KiB / 16 operation 上限）、K05（stock B 的 sized_read 忽略尾部字节）。K01/K06 因 hidden API 豁免不可用保持 SKIP；K04 因错误 token 的 Binder 返回路径仍未稳定，SKIP。


## 8. A 端实测（2026-10-30 13:43）

设备：OnePlus PJZ110 / Android 17（API 37）/ patch 2026-09-01 / build PJZ110_17.0.0.103 / uid 10754。
结果：31 PASS、10 HIT、45 ERROR、5 INCONCLUSIVE、19 SKIP。
原始输出：D:\\Netease\\GameViewer\\Download\\a-gap-probe.txt（用户提供）。

45 个 ERROR 全部是同一根因：带 setDevicePropertiesAttestationIncluded(true) 的 fixture 生成失败。r18 已拆出 A07 专用 fixture，其余检查改为不带设备属性；下一轮 A 复测应把 ERROR 大幅消掉。

已确认的 A 端真实命中：

- A29/A30/A31/A34：普通 app 认证绑定证书是 504=false、503=true，known alias 是 504=[3]、503=false；KeyInfo=true 但证书=false；证书没有 505 而 KeyInfo 有 30。F-12 在实机成立。
- T03：plain=41ms、child=261ms、ratio=6.33，F-11 的 equalize_to_remote_attest_duration 在实机成立。
- M02/M03/M04：ML-DSA 生成/签名/证书 tag 11 全部 ProviderException；F-22 在实机成立。
- A07（旧版连带 ERROR）：设备属性 attestation 失败；r18 的 A07 会单独显示 Failed to generate key pair。

假阳性/探针缺陷：

- R08/C11 的 HIT 来自 fixture 的 deviceProps=true，不是 NONEwithECDSA/EC 曲线本身；r18 已交给 A07 单独判定。
- C01/C02/C04/C05/C06/C07/C08/C12/C13/C15 在 A 上 PASS，说明用户安装的 A 模块已经包含 2.1.3 的 crypto 修复；本报告 F-03～F-08 是对工作树 2.0.1 的静态结论，不应说成“当前 A 设备仍命中”。

版本边界：A 端实测的 C01/C02/C04/C05/C06/C07/C08/C12/C13/C15 全部 PASS，说明用户安装的 A 模块已包含 2.1.3 的 crypto 修复；因此本报告 F-03～F-08 是对工作树 2.0.1 的静态结论，不应说成“当前 A 设备仍命中”。同理 F-01（远程 SIGN）和 F-02（版本标签）在 2.1.3 已修复，r18 在 A 上复测 R01/A14 可能转为 PASS；静态结论仍适用于当前 2.0.1 源树。F-12（认证策略/known probe）、F-11（时序整形）、F-21（设备属性 attestation）、F-22（ML-DSA）在 A 实测中成立。


### 8.1 r19 复测结果（2026-10-30 14:05，最新）

结果：72 PASS、12 HIT、0 ERROR、6 INCONCLUSIVE、21 SKIP。

新增的 B09 直接 HIT：fingerprint 是 OnePlus/PJZ110/OP5D0DL1，但 Build.MODEL/DEVICE/PRODUCT 是 PHB110/OP591BL1/PHB110，证明 A 端 CPU/设备属性视图把 B 身份映射进了探针进程。A07 仍是 PASS，但这是“证书属性与当前被改写的 Build 匹配”，不能证明真实 A 属性 attestation；r20 已让 A07 在 fingerprint 不自洽时返回 INCONCLUSIVE。

HIT 归并：

- B09：F-24 身份视图改写（1 项）；
- A16：F-23 uniqueId 生成失败（1 项，仍为候选，需 keymint.log）；
- A29/A30/A31/A34：F-12（4 项同根）；
- M01-M04：F-22（4 项同根）；
- T03/T04：F-11（2 项同根）。

r18 复测结果（2026-10-30 13:57）作为对比：72 PASS、10 HIT、1 ERROR、6 INCONCLUSIVE、21 SKIP；当时 A16 还是 ERROR，r19 已改为 HIT 候选，并新增 B09。

10 个 HIT 不是 10 个独立缺口，而是 3 个根因：

- A29/A30/A31/A34：F-12，认证策略被 NO_AUTH_REQUIRED 顶替 + known alias 特判 + 505 丢失；4 项同根。
- M01-M04：F-22，ML-DSA 全部不可用；4 项同根。
- T03/T04：F-11，本地 ATTEST_KEY 子钥被整形到远程 RTT；2 项同根。

A16 ERROR（uniqueId 生成失败）是 F-23 候选；尚未抓 keymint.log 确认是 A 端实现缺失还是 probe 的 setUniqueIdIncluded 反射问题。

关键的新发现：r18 的设备行是 OnePlus PHB110 / SM8550，但构建号是 PJZ110_17.0.0.103；而首轮 A 是 PJZ110 / SM8750。说明 A 端 CPU/设备属性视图已把 Build.MODEL/DEVICE/SOC_MODEL 改成 B 的身份。A07 之所以 PASS，是拿被改写的 Build 与证书里的 B 属性比较，属于**假通过**；它不是“设备属性 attestation 已修复”。B07 已暴露 fingerprint/build 与 MODEL 不一致，建议新增 B09 做自洽校验。

这一轮 A07 PASS 不能推翻首轮 A07 ERROR（设备属性 attestation 失败）；首轮没有身份 mask 时它是真实失败。

A 端新版复测需要 [app-debug.apk](<检测器/AProbe/app/build/outputs/apk/debug/app-debug.apk>)（r18，334,168 B，SHA-256 9C46482007D9E3F51364B740D3AB629AEBD0631057F80FFA2CD959FA2921568E）。


### 8.2 r20 复测（2026-10-30 15:29，mask 开启）

结果：72 PASS、12 HIT、0 ERROR、6 INCONCLUSIVE、21 SKIP。

- **B09 HIT**：fingerprint=OnePlus/PJZ110/OP5D0DL1，Build.MODEL/DEVICE/PRODUCT=PHB110/OP591BL1/PHB110；F-24 身份视图改写成立。
- **A07 INCONCLUSIVE**：证书属性与当前被改写的 Build 匹配，但 Build 与 fingerprint 不一致；A07 已不再假 PASS。
- **A16 HIT 是误报**：A 端 keymint.log 明确记录 security_level.rs:621-628 的 “Caller does not have the permission to generate a unique ID”；AOSP 17 security_level.rs:506-511 有同样的 GenUniqueId/permission 门。A 对普通 app 拒绝 uniqueId 是 AOSP 正确行为；B 的 A16 PASS 是 vendor 宽松。A16 不应计入 A 端缺口。
- **A29/A30/A31/A34**：F-12 认证策略/known alias，仍成立。
- **M01-M04**：F-22，A 模块 2.1.3 的 remote profile 仍是 200（log: remote_attest_identity profile=200 hardware=400），API 37 的 ML-DSA 不可用。
- **T03/T04**：F-11 时序整形，仍成立。
- 模块版本实测：/data/adb/modules/ommega/module.prop = 2.1.3-04da842；因此 F-01/F-02/F-03～F-08 不适用于该 A 设备，只适用于工作树 2.0.1。
- F-21 设备属性 attestation：mask 开启时无法验证；首轮未 mask 时 A07 为真实 ERROR，仍需 mask 关闭后复测。


### 8.3 mask-off 复测（2026-10-30 15:34，最新）

结果：72 PASS、11 HIT、2 ERROR、6 INCONCLUSIVE、20 SKIP。

- B09 PASS、B07 PJZ110/SM8750：身份 mask 已关闭，A 的 Build 自洽。
- **A07 HIT**：setDevicePropertiesAttestationIncluded(true) 生成失败 ProviderException；F-21 在真实未 mask 的 A 上**确认成立**。
- A29/A30/A31/A34：F-12 继续成立。
- M01-M04：F-22 继续成立（module 2.1.3，profile=200）。
- T03 HIT：plain=27ms child=367ms ratio=13.28，F-11 成立。
- A16 HIT：AOSP 17 的 GenUniqueId 权限门，A 拒绝是正确行为；不是缺口。
- T04 ERROR：仍是 fixture 残留的 deviceProps=true 导致，不是 A 端时序问题；T03 已独立证实 F-11。下一版 T04 改 false 后应转为 HIT。
- C09 ERROR：RSA NoPadding decrypt key 在 A 上生成失败；B stock 同参数可生成。当前为**候选缺口 F-25**，未抓 keymint.log 根因，暂不计入已确认。
- R01-R12 全 PASS（R05 在 A 上允许并 PASS），C01-C15 除 C09 外全 PASS，A01-A28/A32/A33/A35/A38 PASS。

真实已确认根因仍为四项：

1. F-21 设备属性 attestation 失败（A07 HIT）；
2. F-12 认证策略/known alias（A29/A30/A31/A34）；
3. F-22 ML-DSA 不可用（M01-M04）；
4. F-11 时序整形（T03；T04 fixture 待修）。


### 8.4 最终版 r21 实测（2026-10-30 15:39，mask-off，唯一一次干净运行）

A 端：**73 PASS、11 HIT、0 ERROR、7 INCONCLUSIVE、20 SKIP**。
B 端：**77 PASS、0 HIT、0 ERROR、6 INCONCLUSIVE、28 SKIP**。

A 的 11 个 HIT 已全部归并为 4 个真实根因：

- A07：F-21 设备属性 attestation 失败（1 项）；
- A29/A30/A31/A34：F-12 认证策略/known alias（4 项）；
- M01-M04：F-22 ML-DSA 不可用（4 项）；
- T03/T04：F-11 时序整形（2 项）。

A16 已改为 INCONCLUSIVE：AOSP 17 对普通 app 有 GenUniqueId 权限门，A 的拒绝是正确行为；B 的 PASS 是 vendor 宽松。C09 已改为 INCONCLUSIVE（A 上 NoPadding RSA 密钥生成失败，无法评估 c>=n）；T04 的 deviceProps fixture 已修，A 上正常转为 HIT。

最终 APK：334,168 B，SHA-256 CEB825CD43931E08A460BCF2DBD9A379D83ADFD91824C0A500B16F078D66DC14。

## 9. 证据边界

- 静态代码结论以当前 HEAD b7375d8 为准；2.1.3/2.1.4 的修复提交只作为“该缺口后来被确认并修复”
  的外部证据，不代表当前树已经包含。
- 设备证据引用 检测器/TEE检测/keymint-A.log 与 A端-10项异常-归因.md，它们是 A 端
  2026-10-29 的一次运行，不能替代本次检测器的复测。
- 不把“AOSP 参考实现与厂商 HAL 的差异”当成 Ommega 缺口；例如 StrongBox 是否支持 P-521
  由真实 HAL 决定，不由软件 TA 单独保证。
- 不把需要多个独立异常条件同时成立的场景列为缺口；F-10/F-14/F-15 需要 root/特定 flag，
  已在检测器中标注为静态/跳过，不作为普通 app 的失败项。
