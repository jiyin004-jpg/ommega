package org.ommega.deviceb

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.cert.Certificate
import java.security.interfaces.RSAPrivateKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec
import java.util.Date
import javax.crypto.Cipher
import javax.security.auth.x500.X500Principal

object KeystoreHelper {
    private const val TAG = "DeviceB.KeystoreHelper"
    private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
    private const val DEFAULT_ALIAS = "deviceb_attest_key"
    private const val DEFAULT_RSA_KEY_SIZE = 2048
    private val DEFAULT_RSA_EXPONENT = BigInteger.valueOf(65537)

    // b-side 二进制 relay 上报「有 StrongBox HAL 但用不了」时用的两句话
    // （relay.rs）。server 的 Smart 模式靠子串匹配这两句决定把错误如实回传给
    // 调用方（而不是回退到服务端 keybox），所以本端报同样句子，两条 relay 对
    // server 才是等价的。
    private const val REASON_KEYS_NOT_PROVISIONED =
        "HAL exists but attestation keys not provisioned (factory provisioning issue)"
    private const val REASON_HW_UNAVAILABLE = "HAL exists but hardware type unavailable"

    // ---------------------------------------------------------------------
    // KeyMint AIDL enum -> Android Keystore Java constant mapping
    //
    // NOTE on types: `KeyProperties.PURPOSE_*` are `int` BITMASKS
    // (ENCRYPT=1, DECRYPT=2, SIGN=4, VERIFY=8, WRAP_KEY=16, AGREE_KEY=32,
    //  ATTEST_KEY=64) and `KeyGenParameterSpec.Builder(alias, purpose)` takes a
    // SINGLE combined int. `DIGEST_*`, `ENCRYPTION_PADDING_*` and
    // `SIGNATURE_PADDING_*` are `String` constants.
    // ---------------------------------------------------------------------

    /** KeyMint KeyPurpose (0/1/2/3/5/6/7) -> KeyProperties.PURPOSE_* bitmask. */
    private fun purposeToJava(km: Int): Int? = when (km) {
        TaskKeySpec.PURPOSE_ENCRYPT -> KeyProperties.PURPOSE_ENCRYPT
        TaskKeySpec.PURPOSE_DECRYPT -> KeyProperties.PURPOSE_DECRYPT
        TaskKeySpec.PURPOSE_SIGN -> KeyProperties.PURPOSE_SIGN
        TaskKeySpec.PURPOSE_VERIFY -> KeyProperties.PURPOSE_VERIFY
        TaskKeySpec.PURPOSE_WRAP_KEY -> KeyProperties.PURPOSE_WRAP_KEY
        TaskKeySpec.PURPOSE_AGREE_KEY -> KeyProperties.PURPOSE_AGREE_KEY
        TaskKeySpec.PURPOSE_ATTEST_KEY -> KeyProperties.PURPOSE_ATTEST_KEY
        else -> null
    }

    /** KeyMint Digest (0-6) -> KeyProperties.DIGEST_* string. */
    private fun digestToJava(km: Int): String? = when (km) {
        TaskKeySpec.DIGEST_NONE -> KeyProperties.DIGEST_NONE
        TaskKeySpec.DIGEST_MD5 -> KeyProperties.DIGEST_MD5
        TaskKeySpec.DIGEST_SHA1 -> KeyProperties.DIGEST_SHA1
        TaskKeySpec.DIGEST_SHA_2_224 -> KeyProperties.DIGEST_SHA224
        TaskKeySpec.DIGEST_SHA_2_256 -> KeyProperties.DIGEST_SHA256
        TaskKeySpec.DIGEST_SHA_2_384 -> KeyProperties.DIGEST_SHA384
        TaskKeySpec.DIGEST_SHA_2_512 -> KeyProperties.DIGEST_SHA512
        else -> null
    }

    /** KeyMint PaddingMode -> (encryptionPadding, signaturePadding). The Java
     * API splits encryption vs signature paddings, so map to a pair. */
    private fun paddingsToJava(km: Int): Pair<String?, String?> = when (km) {
        TaskKeySpec.PADDING_NONE -> KeyProperties.ENCRYPTION_PADDING_NONE to null
        TaskKeySpec.PADDING_RSA_OAEP -> KeyProperties.ENCRYPTION_PADDING_RSA_OAEP to null
        TaskKeySpec.PADDING_RSA_PSS -> null to KeyProperties.SIGNATURE_PADDING_RSA_PSS
        TaskKeySpec.PADDING_RSA_PKCS1_5_ENC -> KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1 to null
        TaskKeySpec.PADDING_RSA_PKCS1_5_SIGN -> null to KeyProperties.SIGNATURE_PADDING_RSA_PKCS1
        TaskKeySpec.PADDING_PKCS7 -> KeyProperties.ENCRYPTION_PADDING_PKCS7 to null
        else -> null to null
    }

    private fun ecCurveName(curve: Int): String = when (curve) {
        2 -> "secp384r1"
        3 -> "secp521r1"
        else -> "secp256r1"
    }

    private fun keyAlgorithmString(spec: TaskKeySpec): String =
        if (spec.isRsa) KeyProperties.KEY_ALGORITHM_RSA else KeyProperties.KEY_ALGORITHM_EC

    /** On Android < 12 (API 31) PURPOSE_ATTEST_KEY is unsupported; substitute
     * SIGN so key generation still succeeds with an attestable key. */
    private fun sanitizePurpose(purpose: Int): Int {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) return purpose
        return if (purpose and KeyProperties.PURPOSE_ATTEST_KEY != 0) {
            (purpose and KeyProperties.PURPOSE_ATTEST_KEY.inv()) or KeyProperties.PURPOSE_SIGN
        } else purpose
    }

    /** Combine a KeyMint purpose list into a single Java bitmask. */
    private fun combinePurposes(spec: TaskKeySpec, default: Int): Int {
        if (spec.purposes.isEmpty()) return sanitizePurpose(default)
        val mask = spec.purposes
            .mapNotNull(::purposeToJava)
            .fold(0) { acc, p -> acc or p }
        return sanitizePurpose(if (mask != 0) mask else default)
    }

    /**
     * Build a [KeyGenParameterSpec] honoring the requested KeyMint params.
     * `defaultPurpose` is a Java PURPOSE_* bitmask used when the payload
     * carries no purpose list. `signingAttestKeyAlias` (Android 12+) makes the
     * generated key's leaf signed by the given attest key (A-side TBS flow).
     */
    private fun buildKeyGenSpec(
        alias: String,
        challenge: ByteArray?,
        spec: TaskKeySpec,
        defaultPurpose: Int,
        signingAttestKeyAlias: String? = null,
    ): KeyGenParameterSpec {
        val purpose = combinePurposes(spec, defaultPurpose)
        val builder = KeyGenParameterSpec.Builder(alias, purpose)

        if (spec.isRsa) {
            val keySize = spec.keySize ?: DEFAULT_RSA_KEY_SIZE
            val exponent = spec.rsaPublicExponent?.let { BigInteger.valueOf(it) } ?: DEFAULT_RSA_EXPONENT
            builder.setKeySize(keySize)
            builder.setAlgorithmParameterSpec(RSAKeyGenParameterSpec(keySize, exponent))
        } else {
            val curve = spec.ecCurve ?: when (spec.keySize) {
                384 -> 2
                521 -> 3
                else -> 1
            }
            builder.setAlgorithmParameterSpec(ECGenParameterSpec(ecCurveName(curve)))
        }

        // 对齐二进制 B 端：总是确保 SHA-256 在 digest 集合里（relay 用 SHA-256
        // 签名，且生成 key 时若不显式授权 SHA-256，后续 sign 会报 Incompatible
        // digest -13）。A 端显式指定的 digest 保留，SHA-256 缺失则补上。
        val digests = spec.digests.mapNotNull(::digestToJava).toMutableList()
        if (KeyProperties.DIGEST_SHA256 !in digests) {
            digests.add(KeyProperties.DIGEST_SHA256)
        }
        builder.setDigests(*digests.toTypedArray())

        if (spec.paddings.isNotEmpty()) {
            val enc = mutableListOf<String>()
            val sig = mutableListOf<String>()
            for (p in spec.paddings) {
                val (e, s) = paddingsToJava(p)
                if (e != null) enc.add(e)
                if (s != null) sig.add(s)
            }
            if (enc.isNotEmpty()) builder.setEncryptionPaddings(*enc.toTypedArray())
            if (sig.isNotEmpty()) builder.setSignaturePaddings(*sig.toTypedArray())
        }

        spec.certificateSubjectDer?.let { der ->
            // DER-encoded X.500 Name (A-side sends tag 503 bytes)
            builder.setCertificateSubject(X500Principal(der))
        }
        spec.certificateSerial?.let { bytes ->
            builder.setCertificateSerialNumber(BigInteger(1, bytes))
        }
        spec.certificateNotBeforeMs?.let { ms -> builder.setCertificateNotBefore(Date(ms)) }
        spec.certificateNotAfterMs?.let { ms -> builder.setCertificateNotAfter(Date(ms)) }

        if (spec.mgfDigest != null) {
            Log.w(TAG, "mgf_digest=${spec.mgfDigest} requested but the Android Keystore API cannot set an MGF1 digest; using the system default")
        }

        challenge?.let { builder.setAttestationChallenge(it) }

        // StrongBox（securityLevel==2，A 端 forwarded 请求）：交给 Android
        // Keystore 原生行为处理。setIsStrongBoxBacked 在无 StrongBox 的设备上
        // 会静默回退 TEE（官方文档行为，链如实标记 TRUSTED_ENVIRONMENT），
        // 这是 Android 的标准降级行为，结果与真实设备一致 —— 生成后由
        // attest() 复核记录实际级别（仅诊断，不再拒绝）。
        if (spec.securityLevel == 2) {
            applyStrongBoxBacked(builder)
                ?: throw IllegalStateException("StrongBox requires Android 9+ (API 28)")
        }

        if (signingAttestKeyAlias != null) {
            return applyAttestationKeyAlias(builder, signingAttestKeyAlias)
                ?.build() ?: throw IllegalStateException("setAttestationKeyAlias unavailable")
        }
        return builder.build()
    }

    // ---------------------------------------------------------------------
    // Public operations
    // ---------------------------------------------------------------------

    fun getCertChain(context: Context, alias: String = DEFAULT_ALIAS): JSONObject {
        val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        if (!ks.containsAlias(alias)) {
            return JSONObject().put("error", "key not found for alias: $alias (call attest first)")
        }
        val chain: Array<Certificate> = ks.getCertificateChain(alias) ?: emptyArray()
        val certsJson = JSONArray()
        chain.forEach { cert -> certsJson.put(Base64.encodeToString(cert.encoded, Base64.NO_WRAP)) }
        return JSONObject().apply {
            put("alias", alias)
            put("cert_chain", certsJson)
            if (chain.isNotEmpty()) {
                put("public_key", Base64.encodeToString(chain[0].publicKey.encoded, Base64.NO_WRAP))
            }
        }
    }

    /**
     * 使用系统 TEE 对 challenge 进行 key attestation，返回原始证书链。
     * 密钥参数（算法/曲线/用途/digest/padding/证书字段）由 [spec] 指定；
     * 未指定时默认 EC P-256 + SHA-256 + SIGN。
     * 注意：Android Keystore 的 attestation application ID (tag 709) 固定为
     * 调用方应用自身（无法自定义），因此不接收外部 appid。
     */
    fun attest(
        context: Context,
        challengeB64: String,
        alias: String = DEFAULT_ALIAS,
        spec: TaskKeySpec = TaskKeySpec(),
    ): JSONObject {
        val challenge = try {
            Base64.decode(challengeB64, Base64.NO_WRAP)
        } catch (e: Exception) {
            return JSONObject().put("error", "invalid challenge base64")
        }
        return try {
            val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
            if (ks.containsAlias(alias)) ks.deleteEntry(alias)
            val keyGenSpec = buildKeyGenSpec(alias, challenge, spec, KeyProperties.PURPOSE_SIGN)
            KeyPairGenerator.getInstance(keyAlgorithmString(spec), KEYSTORE_PROVIDER)
                .apply { initialize(keyGenSpec) }
                .generateKeyPair()

            // StrongBox 请求：设备声明了 StrongBox 却让 key 落在别处，属于
            // 「有 HAL 但不可用」，如实上报 —— 跟 b-side 二进制 relay 直连 HAL
            // 拿到的 -68 同一个语义，由 server 的 Smart 模式决定是 surface 给
            // 调用方还是回退服务端 keybox。
            //
            // 设备本来就没有 StrongBox（或 API < 31 压根判断不了实际落在哪层）
            // 时不报：setIsStrongBoxBacked 静默降级 TEE 是官方行为，链上如实
            // 标记 TRUSTED_ENVIRONMENT，与真实设备表现一致；这条 TEE 链会被
            // server 的安全级别校验挡下来，不会冒充 StrongBox 成交。
            if (spec.securityLevel == 2 && isStrongBoxBacked(alias) == false &&
                declaresStrongBox(context)
            ) {
                Log.w(TAG, "attest: StrongBox requested but key landed outside StrongBox ($alias)")
                return JSONObject().put("error", "strongbox not supported: $REASON_HW_UNAVAILABLE")
            }

            ks.load(null)
            val chain: Array<Certificate> = ks.getCertificateChain(alias) ?: emptyArray()
            val certsJson = JSONArray()
            chain.forEach { cert -> certsJson.put(Base64.encodeToString(cert.encoded, Base64.NO_WRAP)) }
            JSONObject().apply {
                put("alias", alias)
                put("cert_chain", certsJson)
            }
        } catch (e: Exception) {
            Log.e(TAG, "attest failed alias=$alias", e)
            val reason = if (spec.securityLevel == 2) strongboxRefusalReason(e) else null
            JSONObject().put(
                "error",
                reason?.let { "strongbox not supported: $it" } ?: (e.message ?: "attest error"),
            )
        }
    }

    /**
     * 使用 alias 对应的 TEE 私钥对数据进行签名。
     * 返回字段名为 "data"，与 A 端 OmegaTee RemoteAttestClient.parseBytes() 对齐。
     */
    fun sign(
        context: Context,
        dataB64: String,
        alias: String = DEFAULT_ALIAS,
        algorithm: String = "SHA256withECDSA"
    ): JSONObject {
        val data = try {
            Base64.decode(dataB64, Base64.NO_WRAP)
        } catch (e: Exception) {
            return JSONObject().put("error", "invalid data base64")
        }
        val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        val privateKey = ks.getKey(alias, null)
            ?: return JSONObject().put("error", "private key not found for alias: $alias")
        return try {
            val sig = Signature.getInstance(algorithm).apply {
                initSign(privateKey as java.security.PrivateKey)
                update(data)
            }.sign()
            JSONObject().apply {
                put("alias", alias)
                put("algorithm", algorithm)
                put("data", Base64.encodeToString(sig, Base64.NO_WRAP))
            }
        } catch (e: Exception) {
            Log.e(TAG, "sign failed for alias=$alias algo=$algorithm", e)
            JSONObject().put("error", e.message ?: "sign error")
        }
    }

    /**
     * 使用 alias 对应的 TEE 私钥对数据进行解密。
     * 仅支持 RSA 密钥。
     * 返回字段名为 "data"，与 sign 函数对齐。
     */
    fun decrypt(
        context: Context,
        dataB64: String,
        alias: String = DEFAULT_ALIAS,
        algorithm: String = "RSA/ECB/PKCS1Padding"
    ): JSONObject {
        val data = try {
            Base64.decode(dataB64, Base64.NO_WRAP)
        } catch (e: Exception) {
            return JSONObject().put("error", "invalid data base64")
        }
        val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        val privateKey = ks.getKey(alias, null)
            ?: return JSONObject().put("error", "private key not found for alias: $alias")
        return try {
            val cipher = Cipher.getInstance(algorithm).apply {
                init(Cipher.DECRYPT_MODE, privateKey as java.security.PrivateKey)
            }
            val decrypted = cipher.doFinal(data)
            JSONObject().apply {
                put("alias", alias)
                put("algorithm", algorithm)
                put("data", Base64.encodeToString(decrypted, Base64.NO_WRAP))
            }
        } catch (e: Exception) {
            Log.e(TAG, "decrypt failed for alias=$alias algo=$algorithm", e)
            JSONObject().put("error", e.message ?: "decrypt error")
        }
    }

    private fun applyAttestationKeyAlias(
        builder: KeyGenParameterSpec.Builder,
        attestKeyAlias: String,
    ): KeyGenParameterSpec.Builder? {
        return runCatching {
            val method =
                KeyGenParameterSpec.Builder::class.java.getMethod(
                    "setAttestationKeyAlias",
                    String::class.java,
                )
            method.invoke(builder, attestKeyAlias) as KeyGenParameterSpec.Builder
        }.getOrNull()
    }

    /**
     * 请求由设备的 StrongBox 安全芯片保存密钥。
     * setIsStrongBoxBacked 是 API 28+ 公共 API（项目 minSdk=26，用反射保兼容）；
     * API < 28 无法表达该要求，返回 null。
     * 注意：官方行为是无 StrongBox 时静默回退 TEE（不抛异常），这是 Android
     * 标准降级行为，链上会如实标记 TRUSTED_ENVIRONMENT，由
     * [isStrongBoxBacked] 在生成后复核。
     */
    private fun applyStrongBoxBacked(builder: KeyGenParameterSpec.Builder): KeyGenParameterSpec.Builder? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return null
        return runCatching {
            val method = KeyGenParameterSpec.Builder::class.java.getMethod(
                "setIsStrongBoxBacked",
                Boolean::class.javaPrimitiveType,
            )
            method.invoke(builder, true) as KeyGenParameterSpec.Builder
        }.getOrNull()
    }

    /**
     * alias 的私钥到底落在哪一层：true = 确定在 StrongBox，false = 确定不在，
     * null = 这个 API 级别判断不了。
     *
     * 只有 API 31+ 的 KeyInfo.getSecurityLevel() 能区分 StrongBox 与 TEE；
     * 更早版本没有任何公共 API 能证明密钥位于 StrongBox（isInsideSecureHardware
     * 对 TEE 密钥同样返回 true），所以返回 null 而不是 false —— 把「判断不了」
     * 当成「不在 StrongBox」会把一台真有 StrongBox 的老设备谎报成不可用。
     */
    private fun isStrongBoxBacked(alias: String): Boolean? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return null
        return try {
            val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
            val privateKey = ks.getKey(alias, null) ?: return null
            val kf = KeyFactory.getInstance(privateKey.algorithm, KEYSTORE_PROVIDER)
            val keyInfo = kf.getKeySpec(privateKey, KeyInfo::class.java)
            keyInfo.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX
        } catch (e: Exception) {
            Log.e(TAG, "isStrongBoxBacked failed alias=$alias", e)
            null
        }
    }

    /**
     * 设备是否在 PackageManager 里声明了 StrongBox
     * (`android.hardware.strongbox_keystore`，API 28+ 的 feature)。
     *
     * 没声明的设备上 setIsStrongBoxBacked 静默降级 TEE 是官方行为，本端照旧
     * 放行（与真实设备一致）；声明了却拿不到才是「有 HAL 但不可用」。
     */
    private fun declaresStrongBox(context: Context): Boolean =
        context.packageManager.hasSystemFeature("android.hardware.strongbox_keystore")

    /**
     * 把 Android 给的 KeyMint 错误码翻成 b-side relay 那套固定文本，好让 server
     * 的 Smart 模式把错误如实回传给调用方；挖不出可识别的错误时返回 null，调用
     * 方继续用原始 e.message。
     *
     * KeyStoreException.getErrorCode() 能拿到未经裁剪的 KeyMint 错误码
     * (-68 = hardware type unavailable, -74 = attestation keys not provisioned)，
     * 但它是 @hide（@TestApi）的 public 方法，只能反射——SDK 里没这个符号。
     * 部分 ROM 也可能直接抛 android.security.keystore.StrongBoxUnavailableException。
     * framework 会把原始异常包一层，所以沿 cause 链找。
     */
    private fun strongboxRefusalReason(e: Throwable): String? {
        var cause: Throwable? = e
        var depth = 0
        while (cause != null && depth++ < 8) {
            when (cause.javaClass.name) {
                "android.security.keystore.StrongBoxUnavailableException" ->
                    return REASON_HW_UNAVAILABLE
                "android.security.KeyStoreException" -> {
                    val code = runCatching {
                        cause.javaClass.getMethod("getErrorCode").invoke(cause) as? Int
                    }.getOrNull()
                    when (code) {
                        -74 -> return REASON_KEYS_NOT_PROVISIONED
                        -68 -> return REASON_HW_UNAVAILABLE
                    }
                }
            }
            cause = cause.cause
        }
        return null
    }
}
