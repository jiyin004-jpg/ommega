package io.github.a13e300.unifiedaudit;

import android.os.SystemClock;
import android.security.keystore.KeyInfo;
import io.github.a13e300.unifiedaudit.Der;
import java.io.ByteArrayInputStream;
import java.lang.reflect.Array;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Predicate;
import javax.crypto.Cipher;
import javax.security.auth.x500.X500Principal;

/* loaded from: classes.dex */
public class Probes {
    final AuditRun app;
    final KeyStore ks;
    final RawBridge raw;
    Set<String> selection;
    final String run = "u52_" + UUID.randomUUID().toString().replace("-", "").substring(0, 12) + "_";
    final Set<String> aliases = ConcurrentHashMap.newKeySet();

    interface Test {
        String run() throws Exception;
    }

    void saveCert(String str, Object obj) throws Exception {
    }

    static final class Skip extends Exception {
        Skip(String str) {
            super(str);
        }
    }

    static final class Hit extends Exception {
        Hit(String str) {
            super(str);
        }
    }

    Probes(AuditRun auditRun) throws Exception {
        RawBridge rawBridge;
        this.app = auditRun;
        try {
            rawBridge = new RawBridge();
        } catch (Throwable unused) {
            rawBridge = null;
        }
        this.raw = rawBridge;
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        this.ks = keyStore;
        keyStore.load(null);
    }

    String alias(String str) {
        String str2 = this.run + str;
        AuditLedger.register(str2);
        this.aliases.add(str2);
        return str2;
    }

    /* JADX WARN: Code restructure failed: missing block: B:47:0x0034, code lost:
    
        if ("hack".equals(r1) != false) goto L12;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    void run() throws java.lang.Exception {
        /*
            Method dump skipped, instructions count: 315
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: io.github.a13e300.unifiedaudit.Probes.run():void");
    }

    void test(String str, String str2, Test test) {
        String error;
        String str3;
        Set<String> set = this.selection;
        if (set == null || set.contains(str)) {
            this.app.before(str);
            try {
                error = test.run();
                str3 = "CLEAR";
            } catch (Hit e) {
                error = e.getMessage();
                str3 = "HIT";
            } catch (Skip e2) {
                error = e2.getMessage();
                str3 = "UNAVAILABLE";
            } catch (Throwable th) {
                error = error(th);
                str3 = "INCONCLUSIVE";
            }
            this.app.add(str, str2, str3, error);
        }
    }

    static String error(Throwable th) {
        return th.getClass().getSimpleName() + " code=" + RawBridge.errorCode(th) + " " + th.getMessage();
    }

    static String rotOfParameters(Object obj) throws Exception {
        Object invoke;
        byte[] bArr = null;
        if (obj == null) {
            return null;
        }
        for (int i = 0; i < Array.getLength(obj); i++) {
            Object field = RawBridge.field(Array.get(obj, i), "keyParameter");
            if ((((Number) RawBridge.field(field, "tag")).intValue() & 268435455) == 704) {
                Object field2 = RawBridge.field(field, "value");
                try {
                    invoke = RawBridge.field(field2, "rootOfTrust");
                } catch (Exception unused) {
                    invoke = RawBridge.invoke(field2, "getRootOfTrust", new Object[0]);
                }
                Object invoke2 = RawBridge.invoke(invoke, "getVerifiedBootState", new Object[0]);
                byte[] bArr2 = (byte[]) RawBridge.field(invoke, "verifiedBootKey");
                try {
                    bArr = (byte[]) RawBridge.field(invoke, "verifiedBootHash");
                } catch (Exception unused2) {
                }
                return "locked=" + String.valueOf(RawBridge.field(invoke, "deviceLocked")) + ",state=" + String.valueOf(invoke2) + ",key=" + hex(bArr2) + ",hash=" + hex(bArr);
            }
        }
        return null;
    }

    String metadataRot(Object obj) throws Exception {
        return rotOfParameters(RawBridge.field(obj, "authorizations"));
    }

    static String bootStateOf(Der der) {
        if (der == null) {
            return null;
        }
        List<Der> children = der.children();
        if (children.size() >= 3) {
            if (children.get(1).value.length != 0) {
                return (children.get(1).value[0] != 0) + "/" + children.get(2).integer();
            }
        }
        return null;
    }

    String metadataBootState(Object obj) throws Exception {
        Object invoke;
        Object field = RawBridge.field(obj, "authorizations");
        if (field == null) {
            return null;
        }
        for (int i = 0; i < Array.getLength(field); i++) {
            Object field2 = RawBridge.field(Array.get(field, i), "keyParameter");
            if ((((Number) RawBridge.field(field2, "tag")).intValue() & 268435455) == 704) {
                Object field3 = RawBridge.field(field2, "value");
                try {
                    invoke = RawBridge.field(field3, "rootOfTrust");
                } catch (Exception unused) {
                    invoke = RawBridge.invoke(field3, "getRootOfTrust", new Object[0]);
                }
                return String.valueOf(RawBridge.field(invoke, "deviceLocked")) + "/" + String.valueOf(RawBridge.invoke(invoke, "getVerifiedBootState", new Object[0]));
            }
        }
        return null;
    }

    static byte[] nonce() {
        byte[] bArr = new byte[32];
        new SecureRandom().nextBytes(bArr);
        return bArr;
    }

    static String hex(byte[] bArr) {
        if (bArr == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder();
        for (byte b : bArr) {
            sb.append(String.format(Locale.US, "%02x", Byte.valueOf(b)));
        }
        return sb.toString();
    }

    static String hash(byte[] bArr) throws Exception {
        return hex(MessageDigest.getInstance("SHA-256").digest(bArr));
    }

    X509Certificate cert(Object obj) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream((byte[]) RawBridge.field(obj, "certificate")));
    }

    Object meta(Object obj) throws Exception {
        return RawBridge.field(obj, "metadata");
    }

    long id(Object obj) throws Exception {
        return ((Number) RawBridge.field(RawBridge.field(obj, "key"), "nspace")).longValue();
    }

    Object gen(String str, byte[] bArr, int i) throws Exception {
        RawBridge rawBridge = this.raw;
        return rawBridge.generate(str, null, rawBridge.ec(bArr, i));
    }

    KeyPair localEc() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));
        return keyPairGenerator.generateKeyPair();
    }

    void verifySign(String str, Object obj) throws Exception {
        RawBridge rawBridge = this.raw;
        Object begin = rawBridge.begin(str, rawBridge.signing());
        byte[] bArr = {5, 4, 3, 2, 1};
        byte[] finish = this.raw.finish(begin, bArr);
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initVerify(cert(obj).getPublicKey());
        signature.update(bArr);
        if (!signature.verify(finish)) {
            throw new Skip("签名正对照失败");
        }
    }

    String rejectedWrite() throws Exception {
        String alias = alias("denied");
        Object gen = gen(alias, nonce(), 2);
        verifySign(alias, gen);
        byte[] bArr = (byte[]) RawBridge.field(this.raw.metadata(alias), "certificate");
        try {
            this.raw.update(this.raw.descriptor(2, id(gen), alias), bArr, new byte[0]);
            throw new Skip("跨域负对照未拒绝，不能解释为缓存问题");
        } catch (Skip e) {
            throw e;
        } catch (Exception e2) {
            Integer errorCode = RawBridge.errorCode(e2);
            byte[] bArr2 = (byte[]) RawBridge.field(this.raw.metadata(alias), "certificate");
            saveCert("H01-before", gen);
            saveCert("H01-after", this.raw.metadata(alias));
            if (Arrays.equals(bArr, bArr2)) {
                return "拒绝码=" + errorCode + "，证书字节未变";
            }
            throw new Hit("拒绝码=" + errorCode + "；同KEY_ID证书变化 " + hash(bArr) + " -> " + hash(bArr2));
        }
    }

    String importBootState() throws Exception {
        Object importKey;
        boolean z;
        Der.Record record;
        Der.Record record2;
        String metadataBootState;
        if (this.raw == null) {
            throw new Skip("Raw interface unavailable");
        }
        String alias = alias("generated");
        String alias2 = alias("imported");
        byte[] nonce = nonce();
        byte[] nonce2 = nonce();
        Object gen = gen(alias, nonce, 2);
        KeyPair localEc = localEc();
        boolean z2 = false;
        Der.Record record3 = null;
        try {
            RawBridge rawBridge = this.raw;
            importKey = rawBridge.importKey(alias2, null, rawBridge.ec(nonce2, 2), localEc.getPrivate().getEncoded());
            z = true;
        } catch (Exception e) {
            try {
                RawBridge rawBridge2 = this.raw;
                importKey = rawBridge2.importKey(alias2, null, rawBridge2.ec(null, 2), localEc.getPrivate().getEncoded());
                z = false;
            } catch (Exception e2) {
                throw new Skip("Attested and unattested import both rejected: " + error(e) + " / " + error(e2));
            }
        }
        X509Certificate cert = cert(gen);
        X509Certificate cert2 = cert(importKey);
        if (!Arrays.equals(cert2.getPublicKey().getEncoded(), localEc.getPublic().getEncoded())) {
            throw new Skip("Imported public key control failed");
        }
        if (z) {
            try {
                record = new Der.Record(cert);
                try {
                    record2 = new Der.Record(cert2);
                    z2 = z;
                } catch (Exception unused) {
                    record2 = null;
                    record3 = record;
                    if (z2) {
                        if (Arrays.equals(record3.challenge(), nonce)) {
                        }
                        throw new Skip("Challenge control failed");
                    }
                    metadataBootState = metadataBootState(gen);
                    String metadataBootState2 = metadataBootState(importKey);
                    if (metadataBootState != null) {
                    }
                    throw new Skip("Import attestation unavailable and KeyMetadata has no RootOfTrust");
                }
            } catch (Exception unused2) {
                record = null;
            }
            record3 = record;
        } else {
            z2 = z;
            record2 = null;
        }
        if (z2 && record3 != null && record2 != null) {
            if (Arrays.equals(record3.challenge(), nonce) || !Arrays.equals(record2.challenge(), nonce2)) {
                throw new Skip("Challenge control failed");
            }
            saveCert("H02-generated", gen);
            saveCert("H02-imported", importKey);
            String bootStateOf = bootStateOf(record3.tag(704));
            String bootStateOf2 = bootStateOf(record2.tag(704));
            if (bootStateOf != null && bootStateOf2 != null) {
                if (!bootStateOf.equals(bootStateOf2)) {
                    throw new Hit("Boot state differs between generated and imported attestation: " + bootStateOf + " vs " + bootStateOf2 + " (" + record3.rot() + " / " + record2.rot() + ")");
                }
                return "boot lock/state equal (" + bootStateOf + "); vendor hash may differ";
            }
        }
        metadataBootState = metadataBootState(gen);
        String metadataBootState22 = metadataBootState(importKey);
        if (metadataBootState != null || metadataBootState22 == null) {
            throw new Skip("Import attestation unavailable and KeyMetadata has no RootOfTrust");
        }
        if (!metadataBootState.equals(metadataBootState22)) {
            throw new Hit("Same boot/level generated/imported KeyMetadata boot state differ: " + metadataBootState + " / " + metadataBootState22);
        }
        return "KeyMetadata boot state equal; certificate attestation unavailable";
    }

    String concurrentRead() throws Exception {
        for (int i = 0; i < 5; i++) {
            final String alias = alias("readrace" + i);
            final AtomicBoolean atomicBoolean = new AtomicBoolean();
            final List synchronizedList = Collections.synchronizedList(new ArrayList());
            new AtomicReference();
            Thread thread = new Thread(new Runnable() { // from class: io.github.a13e300.unifiedaudit.Probes.4
                @Override // java.lang.Runnable
                public final void run() {
                    Probes.this.m48lambda$concurrentRead$0$iogithuba13e300unifiedauditProbes(atomicBoolean, synchronizedList, alias);
                }
            });
            thread.start();
            try {
                Object gen = gen(alias, nonce(), 2);
                atomicBoolean.set(true);
                thread.join(18000L);
                if (thread.isAlive()) {
                    this.app.halt();
                }
                long id = id(gen);
                byte[] bArr = (byte[]) RawBridge.field(gen, "certificate");
                synchronizedList.add(this.raw.metadata(alias));
                for (Object obj : synchronizedList) {
                    if (id(obj) == id && !Arrays.equals(bArr, (byte[]) RawBridge.field(obj, "certificate"))) {
                        saveCert("H03-generated", gen);
                        saveCert("H03-read", obj);
                        throw new Hit("同KEY_ID=" + id + "生成/读取DER不同；round=" + i + " reads=" + synchronizedList.size());
                    }
                }
            } catch (Throwable th) {
                atomicBoolean.set(true);
                thread.join(18000L);
                throw th;
            }
        }
        return "5轮同KEY_ID响应/读取一致";
    }

    /* renamed from: lambda$concurrentRead$0$io-github-a13e300-unifiedaudit-Probes, reason: not valid java name */
    /* synthetic */ void m48lambda$concurrentRead$0$iogithuba13e300unifiedauditProbes(AtomicBoolean atomicBoolean, List list, String str) {
        long elapsedRealtime = SystemClock.elapsedRealtime() + 15000;
        while (!atomicBoolean.get() && SystemClock.elapsedRealtime() < elapsedRealtime) {
            try {
                list.add(this.raw.metadata(str));
            } catch (Exception unused) {
            }
            SystemClock.sleep(8L);
        }
    }

    String emptyTail() throws Exception {
        String alias = alias("emptytail");
        Object gen = gen(alias, nonce(), 2);
        byte[] bArr = (byte[]) RawBridge.field(gen, "certificate");
        Object field = RawBridge.field(gen, "key");
        this.raw.update(field, bArr, new byte[0]);
        Object metadata = this.raw.metadata(alias);
        byte[] bArr2 = (byte[]) RawBridge.field(metadata, "certificateChain");
        if (!Arrays.equals(bArr, (byte[]) RawBridge.field(metadata, "certificate"))) {
            throw new Skip("叶证书写回控制失败");
        }
        this.raw.update(field, bArr, null);
        byte[] bArr3 = (byte[]) RawBridge.field(this.raw.metadata(alias), "certificateChain");
        if (bArr2 != null && bArr2.length == 0 && bArr3 == null) {
            return "empty保留0字节，null保留缺失";
        }
        throw new Hit("写入empty回读=" + String.valueOf(bArr2 == null ? "null" : Integer.valueOf(bArr2.length)) + "；写入null回读=" + String.valueOf(bArr3 != null ? Integer.valueOf(bArr3.length) : "null"));
    }

    String oldKeyId() throws Exception {
        String alias = alias("rebind");
        Object gen = gen(alias, nonce(), 2);
        Object field = RawBridge.field(gen, "key");
        byte[] encoded = cert(gen).getPublicKey().getEncoded();
        Object gen2 = gen(alias, nonce(), 2);
        if (id(gen) == id(gen2)) {
            throw new Hit("同名替换重用了KEY_ID");
        }
        if (Arrays.equals(encoded, cert(gen2).getPublicKey().getEncoded())) {
            throw new Skip("新公钥未变化");
        }
        try {
            if (!Arrays.equals(encoded, cert(meta(this.raw.entry(field))).getPublicKey().getEncoded())) {
                throw new Hit("旧KEY_ID返回新/第三把公钥");
            }
            return "旧KEY_ID仍指向旧对象；新ID=" + id(gen2);
        } catch (Hit e) {
            throw e;
        } catch (Exception e2) {
            Integer num = 7;
            if (num.equals(RawBridge.errorCode(e2))) {
                return "旧KEY_ID已失效(KEY_NOT_FOUND)，符合合同";
            }
            throw e2;
        }
    }

    Object limited(String str, int i) throws Exception {
        List<Object> ec = this.raw.ec(nonce(), 2);
        ec.add(this.raw.param(805306773, "integer", Integer.valueOf(i)));
        return this.raw.generate(str, null, ec);
    }

    int remaining(String str) throws Exception {
        PrivateKey privateKey = (PrivateKey) this.ks.getKey(str, null);
        return ((KeyInfo) KeyFactory.getInstance(privateKey.getAlgorithm(), "AndroidKeyStore").getKeySpec(privateKey, KeyInfo.class)).getRemainingUsageCount();
    }

    String abortUsage() throws Exception {
        String str;
        String alias = alias("abortlimit");
        Object limited = limited(alias, 2);
        int remaining = remaining(alias);
        if (remaining != 2) {
            throw new Skip("次数正对照未报告2，actual=" + remaining);
        }
        RawBridge rawBridge = this.raw;
        this.raw.abort(rawBridge.begin(alias, rawBridge.signing()));
        int remaining2 = remaining(alias);
        int i = 0;
        for (int i2 = 0; i2 < 2; i2++) {
            try {
                verifySign(alias, limited);
                i++;
            } catch (Exception e) {
                str = error(e);
            }
        }
        str = "none";
        if (i == 2 && remaining2 == 2) {
            return "abort未消耗计数，两次后续签名成功";
        }
        throw new Hit("abort前=" + remaining + " 后=" + remaining2 + "；本应剩余2次，实际成功=" + i + "；" + str);
    }

    String remainingUsage() throws Exception {
        int i;
        Integer errorCode;
        String alias = alias("remaining");
        Object limited = limited(alias, 2);
        int remaining = remaining(alias);
        if (remaining != 2) {
            throw new Skip("次数正对照不支持，initial=" + remaining);
        }
        verifySign(alias, limited);
        int remaining2 = remaining(alias);
        verifySign(alias, limited);
        boolean containsAlias = this.ks.containsAlias(alias);
        try {
            i = remaining(alias);
        } catch (Exception unused) {
            i = -999;
        }
        try {
            RawBridge rawBridge = this.raw;
            this.raw.abort(rawBridge.begin(alias, rawBridge.signing()));
            errorCode = null;
        } catch (Exception e) {
            errorCode = RawBridge.errorCode(e);
        }
        if (remaining2 == 1 && !containsAlias && errorCode != null) {
            return "remaining=2→1，用尽后条目移除，error=" + errorCode;
        }
        throw new Hit("成功签名后remaining=" + remaining + "→" + remaining2 + "→" + i + "；用尽后exists=" + containsAlias + " nextError=" + errorCode + "（需与平台同参数对照）");
    }

    static /* synthetic */ boolean lambda$longEcdsa$1(Object obj) {
        return ((Number) RawBridge.field(obj, "tag")).intValue() == 536870917;
    }

    String longEcdsa() throws Exception {
        String alias = alias("longdigest");
        List<Object> ec = this.raw.ec(nonce(), 2);
        ec.removeIf(new Predicate() { // from class: io.github.a13e300.unifiedaudit.Probes.2
            @Override // java.util.function.Predicate
            public final boolean test(Object obj) {
                return Probes.lambda$longEcdsa$1(obj);
            }
        });
        ec.add(this.raw.param(536870917, "digest", 0));
        Object generate = this.raw.generate(alias, null, ec);
        List<Object> asList = Arrays.asList(this.raw.param(536870913, "keyPurpose", 2), this.raw.param(536870917, "digest", 0));
        byte[] bArr = new byte[128];
        new SecureRandom().nextBytes(bArr);
        byte[] copyOf = Arrays.copyOf(bArr, 32);
        byte[] finish = this.raw.finish(this.raw.begin(alias, asList), copyOf);
        Signature signature = Signature.getInstance("NONEwithECDSA");
        signature.initVerify(cert(generate).getPublicKey());
        signature.update(copyOf);
        if (!signature.verify(finish)) {
            throw new Skip("短摘要正对照失败");
        }
        try {
            RawBridge rawBridge = this.raw;
            byte[] finish2 = rawBridge.finish(rawBridge.begin(alias, asList), bArr);
            signature.initVerify(cert(generate).getPublicKey());
            signature.update(copyOf);
            if (signature.verify(finish2)) {
                return "128字节摘要成功，按左侧256位验证通过";
            }
            throw new Hit("长摘要签名不符合P-256左侧截断语义");
        } catch (Exception e) {
            throw new Hit("32字节成功，128字节原始ECDSA失败：" + error(e) + "；需按原生对照归因");
        }
    }

    List<Object> rsaParams(byte[] bArr, int i, int i2) throws Exception {
        ArrayList arrayList = new ArrayList();
        arrayList.add(this.raw.param(268435458, "algorithm", 1));
        arrayList.add(this.raw.param(805306371, "integer", 2048));
        arrayList.add(this.raw.param(1342177480, "longInteger", 65537L));
        arrayList.add(this.raw.param(536870913, "keyPurpose", Integer.valueOf(i)));
        arrayList.add(this.raw.param(536870918, "paddingMode", Integer.valueOf(i2)));
        arrayList.add(this.raw.param(536870917, "digest", 4));
        arrayList.add(this.raw.param(1879048695, "boolValue", true));
        arrayList.add(this.raw.param(1610613744, "dateTime", 0L));
        arrayList.add(this.raw.param(1610613745, "dateTime", 2461449600000L));
        if (bArr != null) {
            arrayList.add(this.raw.param(-1879047484, "blob", bArr));
        }
        return arrayList;
    }

    String rsaLength() throws Exception {
        String alias = alias("rsalength");
        Object generate = this.raw.generate(alias, null, rsaParams(nonce(), 1, 4));
        List<Object> asList = Arrays.asList(this.raw.param(536870913, "keyPurpose", 1), this.raw.param(536870918, "paddingMode", 4));
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(1, cert(generate).getPublicKey());
        byte[] bArr = {1, 3, 5, 7};
        byte[] doFinal = cipher.doFinal(bArr);
        RawBridge rawBridge = this.raw;
        if (!Arrays.equals(bArr, rawBridge.finish(rawBridge.begin(alias, asList), doFinal))) {
            throw new Skip("RSA合法密文正对照失败");
        }
        try {
            RawBridge rawBridge2 = this.raw;
            rawBridge2.finish(rawBridge2.begin(alias, asList), new byte[257]);
            throw new Hit("超过RSA模数长度的密文被接受");
        } catch (Hit e) {
            throw e;
        } catch (Exception e2) {
            Integer errorCode = RawBridge.errorCode(e2);
            Integer num = -21;
            if (num.equals(errorCode)) {
                return "合法密文成功，超长密文=-21";
            }
            throw new Hit("257字节RSA密文错误码=" + errorCode + "；预期INVALID_INPUT_LENGTH=-21，正常密文往返成功");
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:33:0x010b  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    java.lang.String duplicateBinding() throws java.lang.Exception {
        /*
            Method dump skipped, instructions count: 279
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: io.github.a13e300.unifiedaudit.Probes.duplicateBinding():java.lang.String");
    }

    void bindingSignature(String str, Object obj, List<Object> list) throws Exception {
        Object begin = this.raw.begin(str, list);
        try {
            byte[] nonce = nonce();
            byte[] finish = this.raw.finish(begin, nonce);
            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initVerify(cert(obj));
            signature.update(nonce);
            if (signature.verify(finish)) {
            } else {
                throw new Hit("Bound signature does not verify");
            }
        } finally {
            this.raw.abort(begin);
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:21:0x00de, code lost:
    
        throw new io.github.a13e300.unifiedaudit.Probes.Hit("Authorization enforcement mismatch");
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    java.lang.String metadataConsistency() throws java.lang.Exception {
        /*
            Method dump skipped, instructions count: 388
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: io.github.a13e300.unifiedaudit.Probes.metadataConsistency():java.lang.String");
    }

    static /* synthetic */ List lambda$metadataConsistency$2(Integer num) {
        return new ArrayList();
    }

    Object importedParent(String str, KeyPair keyPair) throws Exception {
        try {
            RawBridge rawBridge = this.raw;
            Object importKey = rawBridge.importKey(str, null, rawBridge.ec(null, 7), keyPair.getPrivate().getEncoded());
            if (Arrays.equals(cert(importKey).getPublicKey().getEncoded(), keyPair.getPublic().getEncoded())) {
                return importKey;
            }
            throw new Skip("Imported parent public key control failed");
        } catch (Exception e) {
            throw new Skip("Imported parent unavailable: " + error(e));
        }
    }

    void checkChild(Object obj, PublicKey publicKey, X500Principal x500Principal) throws Exception {
        X509Certificate cert = cert(obj);
        try {
            cert.verify(publicKey);
            if (cert.getIssuerX500Principal().equals(x500Principal)) {
                return;
            }
            throw new Hit("委托叶issuer不是请求父证书subject：issuer=" + cert.getIssuerX500Principal().getName() + " subject=" + x500Principal.getName());
        } catch (Exception e) {
            throw new Hit("委托叶签名不能被请求父公钥验证：" + error(e));
        }
    }

    String concurrentDelegation() throws Exception {
        if (this.raw == null) {
            throw new Skip("Raw interface unavailable");
        }
        final String alias = alias("raceparent");
        KeyPair localEc = localEc();
        Object importedParent = importedParent(alias, localEc);
        String alias2 = alias("racecontrol");
        try {
            RawBridge rawBridge = this.raw;
            checkChild(rawBridge.generate(alias2, rawBridge.app(alias), this.raw.ec(nonce(), 2)), localEc.getPublic(), cert(importedParent).getSubjectX500Principal());
            int i = 0;
            while (i < 5) {
                final String alias3 = this.alias("delegate" + i);
                final String alias4 = this.alias("ordinary" + i);
                final CountDownLatch countDownLatch = new CountDownLatch(1);
                final AtomicReference atomicReference = new AtomicReference();
                final AtomicReference atomicReference2 = new AtomicReference();
                final AtomicReference atomicReference3 = new AtomicReference();
                Probes probes = this;
                Thread thread = new Thread(new Runnable() { // from class: io.github.a13e300.unifiedaudit.Probes.0
                    @Override // java.lang.Runnable
                    public final void run() {
                        Probes.this.m46x26a0194f(countDownLatch, atomicReference, alias3, alias, atomicReference2);
                    }
                });
                Thread thread2 = new Thread(new Runnable() { // from class: io.github.a13e300.unifiedaudit.Probes.1
                    @Override // java.lang.Runnable
                    public final void run() {
                        Probes.this.m47xefa11090(countDownLatch, alias4, atomicReference3);
                    }
                });
                thread.start();
                thread2.start();
                countDownLatch.countDown();
                thread.join(30000L);
                thread2.join(30000L);
                if (thread.isAlive() || thread2.isAlive()) {
                    probes.app.halt();
                }
                if (atomicReference2.get() != null) {
                    throw new Skip("委托并发请求失败：" + error((Throwable) atomicReference2.get()));
                }
                if (atomicReference3.get() != null) {
                    throw new Skip("普通并发请求失败：" + error((Throwable) atomicReference3.get()));
                }
                probes.checkChild(atomicReference.get(), localEc.getPublic(), probes.cert(importedParent).getSubjectX500Principal());
                i++;
                this = probes;
            }
            return "单次正对照与5轮并发均保持父公钥及issuer绑定";
        } catch (Exception e) {
            throw new Skip("Delegated generation unavailable: " + error(e));
        }
    }

    /* renamed from: lambda$concurrentDelegation$3$io-github-a13e300-unifiedaudit-Probes, reason: not valid java name */
    /* synthetic */ void m46x26a0194f(CountDownLatch countDownLatch, AtomicReference atomicReference, String str, String str2, AtomicReference atomicReference2) {
        try {
            countDownLatch.await();
            RawBridge rawBridge = this.raw;
            atomicReference.set(rawBridge.generate(str, rawBridge.app(str2), this.raw.ec(nonce(), 2)));
        } catch (Throwable th) {
            atomicReference2.set(th);
        }
    }

    /* renamed from: lambda$concurrentDelegation$4$io-github-a13e300-unifiedaudit-Probes, reason: not valid java name */
    /* synthetic */ void m47xefa11090(CountDownLatch countDownLatch, String str, AtomicReference atomicReference) {
        try {
            countDownLatch.await();
            gen(str, nonce(), 2);
        } catch (Throwable th) {
            atomicReference.set(th);
        }
    }

    String chainSignatures() throws Exception {
        Object gen = gen(alias("chain"), nonce(), 2);
        ArrayList arrayList = new ArrayList();
        arrayList.add(cert(gen));
        byte[] bArr = (byte[]) RawBridge.field(gen, "certificateChain");
        if (bArr != null) {
            Iterator<? extends Certificate> it = CertificateFactory.getInstance("X.509").generateCertificates(new ByteArrayInputStream(bArr)).iterator();
            while (it.hasNext()) {
                arrayList.add((X509Certificate) it.next());
            }
        }
        if (arrayList.size() < 2) {
            throw new Skip("普通挑战请求没有可校验的多证书链");
        }
        int i = 0;
        while (true) {
            int i2 = i + 1;
            if (i2 >= arrayList.size()) {
                X509Certificate x509Certificate = (X509Certificate) arrayList.get(arrayList.size() - 1);
                if (x509Certificate.getSubjectX500Principal().equals(x509Certificate.getIssuerX500Principal())) {
                    x509Certificate.verify(x509Certificate.getPublicKey());
                }
                saveCert("A03-leaf", gen);
                return arrayList.size() + "张证书的相邻签名均通过；不以链长或缺根单独判异常";
            }
            X509Certificate x509Certificate2 = (X509Certificate) arrayList.get(i);
            X509Certificate x509Certificate3 = (X509Certificate) arrayList.get(i2);
            if (!x509Certificate2.getIssuerX500Principal().equals(x509Certificate3.getSubjectX500Principal())) {
                throw new Hit("链第" + i + "跳issuer/subject断开");
            }
            try {
                x509Certificate2.verify(x509Certificate3.getPublicKey());
                i = i2;
            } catch (Exception e) {
                throw new Hit("链第" + i + "跳签名失败：" + error(e));
            }
        }
    }

    String concurrentChallenge() throws Exception {
        int i = 0;
        while (i < 5) {
            final String alias = this.alias("noncerace" + i);
            final byte[] nonce = nonce();
            final byte[] nonce2 = nonce();
            final CountDownLatch countDownLatch = new CountDownLatch(1);
            final AtomicReference atomicReference = new AtomicReference();
            final AtomicReference atomicReference2 = new AtomicReference();
            final AtomicReference atomicReference3 = new AtomicReference();
            final AtomicReference atomicReference4 = new AtomicReference();
            Probes probes = this;
            Thread thread = new Thread(new Runnable() { // from class: io.github.a13e300.unifiedaudit.Probes.5
                @Override // java.lang.Runnable
                public final void run() {
                    Probes.this.m44xaf5221e4(countDownLatch, atomicReference, alias, nonce, atomicReference3);
                }
            });
            Thread thread2 = new Thread(new Runnable() { // from class: io.github.a13e300.unifiedaudit.Probes.6
                @Override // java.lang.Runnable
                public final void run() {
                    Probes.this.m45x78531925(countDownLatch, atomicReference2, alias, nonce2, atomicReference4);
                }
            });
            thread.start();
            thread2.start();
            countDownLatch.countDown();
            thread.join(30000L);
            thread2.join(30000L);
            if (thread.isAlive() || thread2.isAlive()) {
                probes.app.halt();
            }
            if (atomicReference3.get() != null || atomicReference4.get() != null) {
                throw new Skip("并发生成存在失败，不能比较证书：" + String.valueOf(atomicReference3.get()) + " / " + String.valueOf(atomicReference4.get()));
            }
            if (!Arrays.equals(nonce, new Der.Record(probes.cert(atomicReference.get())).challenge()) || !Arrays.equals(nonce2, new Der.Record(probes.cert(atomicReference2.get())).challenge())) {
                probes.saveCert("A04-response1", atomicReference.get());
                probes.saveCert("A04-response2", atomicReference2.get());
                throw new Hit("同名并发生成把请求nonce与响应混配，round=" + i);
            }
            i++;
            this = probes;
        }
        return "5轮同名并发，两个响应各自绑定自己的challenge";
    }

    /* renamed from: lambda$concurrentChallenge$5$io-github-a13e300-unifiedaudit-Probes, reason: not valid java name */
    /* synthetic */ void m44xaf5221e4(CountDownLatch countDownLatch, AtomicReference atomicReference, String str, byte[] bArr, AtomicReference atomicReference2) {
        try {
            countDownLatch.await();
            atomicReference.set(gen(str, bArr, 2));
        } catch (Throwable th) {
            atomicReference2.set(th);
        }
    }

    /* renamed from: lambda$concurrentChallenge$6$io-github-a13e300-unifiedaudit-Probes, reason: not valid java name */
    /* synthetic */ void m45x78531925(CountDownLatch countDownLatch, AtomicReference atomicReference, String str, byte[] bArr, AtomicReference atomicReference2) {
        try {
            countDownLatch.await();
            atomicReference.set(gen(str, bArr, 2));
        } catch (Throwable th) {
            atomicReference2.set(th);
        }
    }

    String failedParentImport() throws Exception {
        if (this.raw == null) {
            throw new Skip("Raw interface unavailable");
        }
        String alias = alias("poisonparent");
        String alias2 = alias("poisoncontrol");
        String alias3 = alias("poisonchild");
        KeyPair localEc = localEc();
        Object importedParent = importedParent(alias, localEc);
        try {
            RawBridge rawBridge = this.raw;
            checkChild(rawBridge.generate(alias2, rawBridge.app(alias), this.raw.ec(nonce(), 2)), localEc.getPublic(), cert(importedParent).getSubjectX500Principal());
            try {
                byte[] bArr = (byte[]) RawBridge.field(this.raw.metadata(alias), "certificate");
                KeyPair localEc2 = localEc();
                List<Object> ec = this.raw.ec(null, 7);
                for (Object obj : ec) {
                    if (((Number) RawBridge.field(obj, "tag")).intValue() == 805306371) {
                        RawBridge.set(obj, "value", RawBridge.field(this.raw.param(805306371, "integer", 384), "value"));
                    }
                }
                try {
                    this.raw.importKey(alias, null, ec, localEc2.getPrivate().getEncoded());
                    throw new Skip("非法替换未被拒绝，不能评估失败的原子性");
                } catch (Skip e) {
                    throw e;
                } catch (Exception e2) {
                    Integer errorCode = RawBridge.errorCode(e2);
                    try {
                        if (!Arrays.equals(bArr, (byte[]) RawBridge.field(this.raw.metadata(alias), "certificate"))) {
                            throw new Hit("失败导入已改变父证书；error=" + errorCode);
                        }
                        try {
                            RawBridge rawBridge2 = this.raw;
                            Object generate = rawBridge2.generate(alias3, rawBridge2.app(alias), this.raw.ec(nonce(), 2));
                            try {
                                checkChild(generate, localEc.getPublic(), cert(importedParent).getSubjectX500Principal());
                                return "替换拒绝=" + errorCode + "；父证书与后续委托签名保持原值";
                            } catch (Hit e3) {
                                saveCert("A05-parent", importedParent);
                                saveCert("A05-child", generate);
                                throw new Hit("非法替换error=" + errorCode + "、父证书未变，但后续委托签名损坏：" + e3.getMessage());
                            }
                        } catch (Exception e4) {
                            throw new Hit("非法替换 error=" + errorCode + " 后委托签发失败：" + error(e4));
                        }
                    } catch (Exception e5) {
                        throw new Skip("Parent metadata unreadable after rejected replacement: " + error(e5));
                    }
                }
            } catch (Exception e6) {
                throw new Skip("Parent metadata unavailable: " + error(e6));
            }
        } catch (Exception e7) {
            throw new Skip("Delegated generation unavailable: " + error(e7));
        }
    }
}
