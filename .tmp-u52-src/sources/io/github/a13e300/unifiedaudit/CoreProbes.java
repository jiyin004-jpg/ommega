package io.github.a13e300.unifiedaudit;

import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Process;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProtection;
import io.github.a13e300.unifiedaudit.Der;
import io.github.a13e300.unifiedaudit.Probes;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.TreeMap;
import java.util.TreeSet;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/* loaded from: classes.dex */
final class CoreProbes extends Probes {
    private static final long NOT_AFTER = 1893456000000L;
    private static final long NOT_BEFORE = 1704067200000L;
    private SecretKey aes;
    private String aesAlias;
    private Exception attestationFailure;
    private Sample attested;
    private KeyPair ec;
    private String ecAlias;
    private KeyPair rsa;

    static boolean inLevel(long j) {
        return j >= 0 && j <= 2;
    }

    static final class Sample {
        String alias;
        X509Certificate[] chain;
        X509Certificate leaf;
        byte[] nonce;
        KeyPair pair;
        Der.Record record;

        Sample() {
        }
    }

    CoreProbes(AuditRun auditRun) throws Exception {
        super(auditRun);
    }

    /* renamed from: lambda$runExtra$0$io-github-a13e300-unifiedaudit-CoreProbes, reason: not valid java name */
    /* synthetic */ String m8lambda$runExtra$0$iogithuba13e300unifiedauditCoreProbes() throws Exception {
        verifyPair(ec(), "SHA256withECDSA");
        return "";
    }

    void runExtra() throws Exception {
        try {
            test("EC_SIGN", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.CoreProbes.0
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return CoreProbes.this.m8lambda$runExtra$0$iogithuba13e300unifiedauditCoreProbes();
                }
            });
            test("RSA_SIGN", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.CoreProbes.11
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return CoreProbes.this.m9lambda$runExtra$1$iogithuba13e300unifiedauditCoreProbes();
                }
            });
            test("GCM_ROUNDTRIP", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.CoreProbes.22
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return CoreProbes.this.m18lambda$runExtra$2$iogithuba13e300unifiedauditCoreProbes();
                }
            });
            test("GCM_TAMPER", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.CoreProbes.23
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return CoreProbes.this.m19lambda$runExtra$3$iogithuba13e300unifiedauditCoreProbes();
                }
            });
            test("HMAC_IMPORT", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.CoreProbes.24
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return CoreProbes.this.hmac();
                }
            });
            test("PRIVATE_OPAQUE", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.CoreProbes.25
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return CoreProbes.this.m20lambda$runExtra$4$iogithuba13e300unifiedauditCoreProbes();
                }
            });
            test("SECRET_OPAQUE", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.CoreProbes.26
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return CoreProbes.this.m21lambda$runExtra$5$iogithuba13e300unifiedauditCoreProbes();
                }
            });
            test("CHALLENGE", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.CoreProbes.27
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return CoreProbes.this.m22lambda$runExtra$6$iogithuba13e300unifiedauditCoreProbes();
                }
            });
            test("PUBLIC_BINDING", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.CoreProbes.28
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return CoreProbes.this.m23lambda$runExtra$7$iogithuba13e300unifiedauditCoreProbes();
                }
            });
            test("CERT_READBACK", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.CoreProbes.29
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return CoreProbes.this.m24lambda$runExtra$8$iogithuba13e300unifiedauditCoreProbes();
                }
            });
            test("APP_PACKAGES", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.CoreProbes.1
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return CoreProbes.this.applicationPackages();
                }
            });
            test("APP_SIGNATURES", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.CoreProbes.2
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return CoreProbes.this.applicationSignatures();
                }
            });
            test("APP_AUTH_LOCATION", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.CoreProbes.3
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return CoreProbes.this.m25lambda$runExtra$9$iogithuba13e300unifiedauditCoreProbes();
                }
            });
            test("SECURITY_ENUMS", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.CoreProbes.4
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return CoreProbes.this.m10lambda$runExtra$10$iogithuba13e300unifiedauditCoreProbes();
                }
            });
            test("ROOT_OF_TRUST", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.CoreProbes.5
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return CoreProbes.this.rootStructure();
                }
            });
            test("BOOT_STABILITY", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.CoreProbes.6
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return CoreProbes.this.bootStability();
                }
            });
            test("OS_PATCH", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.CoreProbes.7
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return CoreProbes.this.osPatch();
                }
            });
            test("BOOT_PROPERTIES", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.CoreProbes.8
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return CoreProbes.this.bootProperties();
                }
            });
            test("EXPLICIT_VALIDITY", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.CoreProbes.9
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return CoreProbes.this.m11lambda$runExtra$11$iogithuba13e300unifiedauditCoreProbes();
                }
            });
            test("ISSUER_AUTHORITY", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.CoreProbes.10
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return CoreProbes.this.issuerAuthority();
                }
            });
            test("KEYINFO_LEVEL", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.CoreProbes.12
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return CoreProbes.this.keyInfoLevel();
                }
            });
            test("KEY_ORIGINS", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.CoreProbes.13
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return CoreProbes.this.origins();
                }
            });
            test("EC_PARAMETERS", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.CoreProbes.14
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return CoreProbes.this.ecParameters();
                }
            });
            test("ALIAS_KEYID", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.CoreProbes.15
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return CoreProbes.this.aliasKeyId();
                }
            });
            test("FINISH_LIFECYCLE", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.CoreProbes.16
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return CoreProbes.this.m12lambda$runExtra$12$iogithuba13e300unifiedauditCoreProbes();
                }
            });
            test("ABORT_LIFECYCLE", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.CoreProbes.17
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return CoreProbes.this.m13lambda$runExtra$13$iogithuba13e300unifiedauditCoreProbes();
                }
            });
            test("UPDATE_LIMIT", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.CoreProbes.18
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return CoreProbes.this.m14lambda$runExtra$14$iogithuba13e300unifiedauditCoreProbes();
                }
            });
            test("UPDATE_OVERFLOW", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.CoreProbes.19
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return CoreProbes.this.m15lambda$runExtra$15$iogithuba13e300unifiedauditCoreProbes();
                }
            });
            test("FINISH_LIMIT", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.CoreProbes.20
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return CoreProbes.this.m16lambda$runExtra$16$iogithuba13e300unifiedauditCoreProbes();
                }
            });
            test("FINISH_OVERFLOW", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.CoreProbes.21
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return CoreProbes.this.m17lambda$runExtra$17$iogithuba13e300unifiedauditCoreProbes();
                }
            });
        } finally {
            Iterator<String> it = this.aliases.iterator();
            while (it.hasNext()) {
                try {
                    this.ks.deleteEntry(it.next());
                } catch (Exception unused) {
                }
            }
        }
    }

    /* renamed from: lambda$runExtra$1$io-github-a13e300-unifiedaudit-CoreProbes, reason: not valid java name */
    /* synthetic */ String m9lambda$runExtra$1$iogithuba13e300unifiedauditCoreProbes() throws Exception {
        verifyPair(rsa(), "SHA256withRSA");
        return "";
    }

    /* renamed from: lambda$runExtra$2$io-github-a13e300-unifiedaudit-CoreProbes, reason: not valid java name */
    /* synthetic */ String m18lambda$runExtra$2$iogithuba13e300unifiedauditCoreProbes() throws Exception {
        return gcm(false);
    }

    /* renamed from: lambda$runExtra$3$io-github-a13e300-unifiedaudit-CoreProbes, reason: not valid java name */
    /* synthetic */ String m19lambda$runExtra$3$iogithuba13e300unifiedauditCoreProbes() throws Exception {
        return gcm(true);
    }

    /* renamed from: lambda$runExtra$4$io-github-a13e300-unifiedaudit-CoreProbes, reason: not valid java name */
    /* synthetic */ String m20lambda$runExtra$4$iogithuba13e300unifiedauditCoreProbes() throws Exception {
        require(ec().getPrivate().getEncoded() == null, "Private key exported");
        return "";
    }

    /* renamed from: lambda$runExtra$5$io-github-a13e300-unifiedaudit-CoreProbes, reason: not valid java name */
    /* synthetic */ String m21lambda$runExtra$5$iogithuba13e300unifiedauditCoreProbes() throws Exception {
        require(aes().getEncoded() == null, "Secret key exported");
        return "";
    }

    /* renamed from: lambda$runExtra$6$io-github-a13e300-unifiedaudit-CoreProbes, reason: not valid java name */
    /* synthetic */ String m22lambda$runExtra$6$iogithuba13e300unifiedauditCoreProbes() throws Exception {
        Sample attested = attested();
        require(Arrays.equals(attested.nonce, attested.record.challenge()), "Challenge mismatch");
        return "";
    }

    /* renamed from: lambda$runExtra$7$io-github-a13e300-unifiedaudit-CoreProbes, reason: not valid java name */
    /* synthetic */ String m23lambda$runExtra$7$iogithuba13e300unifiedauditCoreProbes() throws Exception {
        Sample attested = attested();
        require(Arrays.equals(attested.pair.getPublic().getEncoded(), attested.leaf.getPublicKey().getEncoded()), "Public key mismatch");
        verifyPair(attested.pair, "SHA256withECDSA");
        return "";
    }

    /* renamed from: lambda$runExtra$8$io-github-a13e300-unifiedaudit-CoreProbes, reason: not valid java name */
    /* synthetic */ String m24lambda$runExtra$8$iogithuba13e300unifiedauditCoreProbes() throws Exception {
        Sample attested = attested();
        require(Arrays.equals(attested.leaf.getEncoded(), this.ks.getCertificate(attested.alias).getEncoded()), "Readback mismatch");
        return "";
    }

    /* renamed from: lambda$runExtra$9$io-github-a13e300-unifiedaudit-CoreProbes, reason: not valid java name */
    /* synthetic */ String m25lambda$runExtra$9$iogithuba13e300unifiedauditCoreProbes() throws Exception {
        Der.Record record = attested().record;
        require(record.sw.containsKey(709) && !record.hw.containsKey(709), "Application ID enforcement location");
        return "";
    }

    /* renamed from: lambda$runExtra$10$io-github-a13e300-unifiedaudit-CoreProbes, reason: not valid java name */
    /* synthetic */ String m10lambda$runExtra$10$iogithuba13e300unifiedauditCoreProbes() throws Exception {
        Der.Record record = attested().record;
        require(inLevel(record.fields.get(1).integer()) && inLevel(record.fields.get(3).integer()), "Security enum");
        return "";
    }

    /* renamed from: lambda$runExtra$11$io-github-a13e300-unifiedaudit-CoreProbes, reason: not valid java name */
    /* synthetic */ String m11lambda$runExtra$11$iogithuba13e300unifiedauditCoreProbes() throws Exception {
        X509Certificate x509Certificate = attested().leaf;
        require(x509Certificate.getNotBefore().getTime() == NOT_BEFORE && x509Certificate.getNotAfter().getTime() == NOT_AFTER, "Requested validity mismatch");
        return "";
    }

    /* renamed from: lambda$runExtra$12$io-github-a13e300-unifiedaudit-CoreProbes, reason: not valid java name */
    /* synthetic */ String m12lambda$runExtra$12$iogithuba13e300unifiedauditCoreProbes() throws Exception {
        return lifecycle(false);
    }

    /* renamed from: lambda$runExtra$13$io-github-a13e300-unifiedaudit-CoreProbes, reason: not valid java name */
    /* synthetic */ String m13lambda$runExtra$13$iogithuba13e300unifiedauditCoreProbes() throws Exception {
        return lifecycle(true);
    }

    /* renamed from: lambda$runExtra$14$io-github-a13e300-unifiedaudit-CoreProbes, reason: not valid java name */
    /* synthetic */ String m14lambda$runExtra$14$iogithuba13e300unifiedauditCoreProbes() throws Exception {
        return boundary(false, false);
    }

    /* renamed from: lambda$runExtra$15$io-github-a13e300-unifiedaudit-CoreProbes, reason: not valid java name */
    /* synthetic */ String m15lambda$runExtra$15$iogithuba13e300unifiedauditCoreProbes() throws Exception {
        return boundary(false, true);
    }

    /* renamed from: lambda$runExtra$16$io-github-a13e300-unifiedaudit-CoreProbes, reason: not valid java name */
    /* synthetic */ String m16lambda$runExtra$16$iogithuba13e300unifiedauditCoreProbes() throws Exception {
        return boundary(true, false);
    }

    /* renamed from: lambda$runExtra$17$io-github-a13e300-unifiedaudit-CoreProbes, reason: not valid java name */
    /* synthetic */ String m17lambda$runExtra$17$iogithuba13e300unifiedauditCoreProbes() throws Exception {
        return boundary(true, true);
    }

    static void require(boolean z, String str) throws Probes.Hit {
        if (!z) {
            throw new Probes.Hit(str);
        }
    }

    KeyPair ec() throws Exception {
        if (this.ec == null) {
            this.ecAlias = alias("control_ec");
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "AndroidKeyStore");
            keyPairGenerator.initialize(new KeyGenParameterSpec.Builder(this.ecAlias, 4).setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1")).setDigests("SHA-256").build());
            this.ec = keyPairGenerator.generateKeyPair();
        }
        return this.ec;
    }

    KeyPair rsa() throws Exception {
        if (this.rsa == null) {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
            keyPairGenerator.initialize(new KeyGenParameterSpec.Builder(alias("control_rsa"), 4).setKeySize(2048).setDigests("SHA-256").setSignaturePaddings("PKCS1").build());
            this.rsa = keyPairGenerator.generateKeyPair();
        }
        return this.rsa;
    }

    SecretKey aes() throws Exception {
        if (this.aes == null) {
            this.aesAlias = alias("control_aes");
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", "AndroidKeyStore");
            keyGenerator.init(new KeyGenParameterSpec.Builder(this.aesAlias, 3).setKeySize(256).setBlockModes("GCM").setEncryptionPaddings("NoPadding").build());
            this.aes = keyGenerator.generateKey();
        }
        return this.aes;
    }

    static void verifyPair(KeyPair keyPair, String str) throws Exception {
        byte[] nonce = nonce();
        Signature signature = Signature.getInstance(str);
        signature.initSign(keyPair.getPrivate());
        signature.update(nonce);
        byte[] sign = signature.sign();
        Signature signature2 = Signature.getInstance(str);
        signature2.initVerify(keyPair.getPublic());
        signature2.update(nonce);
        require(signature2.verify(sign), "Signature mismatch");
        nonce[0] = (byte) (nonce[0] ^ 1);
        signature2.initVerify(keyPair.getPublic());
        signature2.update(nonce);
        require(!signature2.verify(sign), "Negative signature control");
    }

    String gcm(boolean z) throws Exception {
        byte[] nonce = nonce();
        byte[] nonce2 = nonce();
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(1, aes());
        cipher.updateAAD(nonce2);
        byte[] doFinal = cipher.doFinal(nonce);
        Cipher cipher2 = Cipher.getInstance("AES/GCM/NoPadding");
        cipher2.init(2, aes(), new GCMParameterSpec(128, cipher.getIV()));
        cipher2.updateAAD(nonce2);
        require(Arrays.equals(nonce, cipher2.doFinal(doFinal)), "GCM positive control");
        if (z) {
            int length = doFinal.length - 1;
            doFinal[length] = (byte) (doFinal[length] ^ 1);
            Cipher cipher3 = Cipher.getInstance("AES/GCM/NoPadding");
            cipher3.init(2, aes(), new GCMParameterSpec(128, cipher.getIV()));
            cipher3.updateAAD(nonce2);
            try {
                cipher3.doFinal(doFinal);
                throw new Probes.Hit("Tampered tag accepted");
            } catch (AEADBadTagException unused) {
                return "";
            }
        }
        return "";
    }

    String hmac() throws Exception {
        byte[] nonce = nonce();
        byte[] nonce2 = nonce();
        String alias = alias("hmac");
        SecretKeySpec secretKeySpec = new SecretKeySpec(nonce, "HmacSHA256");
        this.ks.setEntry(alias, new KeyStore.SecretKeyEntry(secretKeySpec), new KeyProtection.Builder(4).setDigests("SHA-256").build());
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init((SecretKey) this.ks.getKey(alias, null));
        Mac mac2 = Mac.getInstance("HmacSHA256");
        mac2.init(secretKeySpec);
        require(Arrays.equals(mac.doFinal(nonce2), mac2.doFinal(nonce2)), "HMAC mismatch");
        Arrays.fill(nonce, (byte) 0);
        return "";
    }

    Sample newAttested(String str) throws Exception {
        Sample sample = new Sample();
        sample.alias = alias(str);
        sample.nonce = nonce();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "AndroidKeyStore");
        keyPairGenerator.initialize(new KeyGenParameterSpec.Builder(sample.alias, 4).setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1")).setDigests("SHA-256").setAttestationChallenge(sample.nonce).setCertificateNotBefore(new Date(NOT_BEFORE)).setCertificateNotAfter(new Date(NOT_AFTER)).build());
        sample.pair = keyPairGenerator.generateKeyPair();
        sample.leaf = (X509Certificate) this.ks.getCertificate(sample.alias);
        Certificate[] certificateChain = this.ks.getCertificateChain(sample.alias);
        if (sample.leaf == null || certificateChain == null || certificateChain.length == 0) {
            throw new Probes.Skip("No attestation certificate");
        }
        sample.chain = new X509Certificate[certificateChain.length];
        for (int i = 0; i < certificateChain.length; i++) {
            sample.chain[i] = (X509Certificate) certificateChain[i];
        }
        sample.record = new Der.Record(sample.leaf);
        return sample;
    }

    Sample attested() throws Exception {
        if (this.attestationFailure != null) {
            throw new Probes.Skip("Attestation control unavailable");
        }
        if (this.attested == null) {
            try {
                this.attested = newAttested("attest");
            } catch (Exception e) {
                this.attestationFailure = e;
                throw e;
            }
        }
        return this.attested;
    }

    List<Der> appId() throws Exception {
        Der tag = attested().record.tag(709);
        if (tag == null || tag.tag != 4) {
            throw new Probes.Skip("Application ID absent");
        }
        List<Der> children = Der.one(tag.value).children();
        if (children.size() == 2) {
            return children;
        }
        throw new Probes.Hit("Invalid application ID");
    }

    String applicationPackages() throws Exception {
        TreeMap treeMap = new TreeMap();
        TreeMap treeMap2 = new TreeMap();
        Iterator<Der> it = appId().get(0).children().iterator();
        while (it.hasNext()) {
            List<Der> children = it.next().children();
            if (children.size() != 2) {
                throw new Probes.Hit("Invalid package entry");
            }
            if (treeMap.put(new String(children.get(0).value, StandardCharsets.UTF_8), Long.valueOf(children.get(1).integer())) != null) {
                throw new Probes.Hit("Duplicate package");
            }
        }
        PackageManager packageManager = this.app.context.getPackageManager();
        String[] packagesForUid = packageManager.getPackagesForUid(Process.myUid());
        if (packagesForUid == null || packagesForUid.length == 0) {
            throw new Probes.Skip("Caller package control unavailable");
        }
        for (String str : packagesForUid) {
            treeMap2.put(str, Long.valueOf(packageManager.getPackageInfo(str, 0).getLongVersionCode()));
        }
        require(treeMap.equals(treeMap2), "Caller package/version mismatch");
        return "";
    }

    String applicationSignatures() throws Exception {
        TreeSet treeSet = new TreeSet();
        TreeSet treeSet2 = new TreeSet();
        Iterator<Der> it = appId().get(1).children().iterator();
        while (it.hasNext()) {
            treeSet.add(hex(it.next().value));
        }
        PackageManager packageManager = this.app.context.getPackageManager();
        String[] packagesForUid = packageManager.getPackagesForUid(Process.myUid());
        if (packagesForUid == null) {
            throw new Probes.Skip("No caller packages");
        }
        for (String str : packagesForUid) {
            PackageInfo packageInfo = packageManager.getPackageInfo(str, 134217728);
            if (packageInfo.signingInfo == null) {
                throw new Probes.Skip("No signing identity");
            }
            for (android.content.pm.Signature signature : packageInfo.signingInfo.getApkContentsSigners()) {
                treeSet2.add(hash(signature.toByteArray()));
            }
        }
        require(!treeSet2.isEmpty() && treeSet2.equals(treeSet), "Signing identity mismatch");
        return "";
    }

    String rootStructure() throws Exception {
        Der.Record record = attested().record;
        long integer = record.fields.get(3).integer();
        Der tag = record.tag(704);
        if (integer == 0 && tag == null) {
            return "";
        }
        require(tag != null, "Missing root of trust");
        if (integer != 0) {
            require(record.hw.containsKey(704) && !record.sw.containsKey(704), "Root of trust location");
        }
        List<Der> children = tag.children();
        require(children.size() == ((record.fields.get(2).integer() > 4L ? 1 : (record.fields.get(2).integer() == 4L ? 0 : -1)) >= 0 ? 4 : 3), "Root of trust arity");
        require(children.get(0).tag == 4 && children.get(1).tag == 1 && children.get(1).value.length == 1 && children.get(2).tag == 10, "Root of trust types");
        long integer2 = children.get(2).integer();
        require(integer2 >= 0 && integer2 <= 3, "Boot state enum");
        if (children.size() == 4) {
            require(children.get(3).tag == 4, "Boot hash type");
        }
        return "";
    }

    String bootStability() throws Exception {
        Sample attested = attested();
        Sample newAttested = newAttested("attest_again");
        require(Arrays.equals(newAttested.nonce, newAttested.record.challenge()), "Second challenge mismatch");
        Der tag = attested.record.tag(704);
        Der tag2 = newAttested.record.tag(704);
        if (tag == null || tag2 == null) {
            throw new Probes.Skip("Root of trust not supplied");
        }
        require(attested.record.fields.get(3).integer() == newAttested.record.fields.get(3).integer(), "Changed security level");
        require(Arrays.equals(tag.encoded, tag2.encoded), "Unstable boot record");
        return "";
    }

    String osPatch() throws Exception {
        String str = Build.VERSION.SECURITY_PATCH;
        if (!str.matches("[0-9]{4}-[0-9]{2}-[0-9]{2}")) {
            throw new Probes.Skip("No OS patch control");
        }
        long number = attested().record.number(706);
        if (number == Long.MIN_VALUE) {
            throw new Probes.Skip("OS patch absent");
        }
        require(number == Long.parseLong(str.substring(0, 7).replace("-", "")), "OS patch mismatch");
        return "";
    }

    String property(String str) throws Exception {
        if (RawBridge.enableReflection()) {
            return (String) Class.forName("android.os.SystemProperties").getMethod("get", String.class).invoke(null, str);
        }
        throw new Probes.Skip("System property interface unavailable");
    }

    String bootProperties() throws Exception {
        int i;
        Der tag = attested().record.tag(704);
        if (tag == null) {
            throw new Probes.Skip("Boot record unavailable");
        }
        List<Der> children = tag.children();
        if (children.size() < 3) {
            throw new Probes.Skip("Boot record incomplete");
        }
        String property = property("ro.boot.vbmeta.device_state");
        if ("locked".equals(property) || "unlocked".equals(property)) {
            require((children.get(1).value[0] != 0) == "locked".equals(property), "Boot lock disagreement");
            i = 1;
        } else {
            i = 0;
        }
        int indexOf = Arrays.asList("green", "yellow", "orange", "red").indexOf(property("ro.boot.verifiedbootstate"));
        if (indexOf >= 0) {
            require(children.get(2).integer() == ((long) indexOf), "Boot state disagreement");
            i++;
        }
        if (i != 0) {
            return "";
        }
        throw new Probes.Skip("Boot properties unavailable");
    }

    String issuerAuthority() throws Exception {
        X509Certificate[] x509CertificateArr = attested().chain;
        if (x509CertificateArr.length < 2) {
            throw new Probes.Skip("Issuer unavailable");
        }
        int i = 0;
        while (true) {
            int i2 = i + 1;
            if (i2 < x509CertificateArr.length) {
                X509Certificate x509Certificate = x509CertificateArr[i];
                X509Certificate x509Certificate2 = x509CertificateArr[i2];
                require(x509Certificate.getIssuerX500Principal().equals(x509Certificate2.getSubjectX500Principal()), "Issuer name mismatch");
                try {
                    x509Certificate.verify(x509Certificate2.getPublicKey());
                    require(x509Certificate2.getBasicConstraints() >= 0, "Issuer is not CA");
                    boolean[] keyUsage = x509Certificate2.getKeyUsage();
                    if (keyUsage != null) {
                        require(keyUsage.length > 5 && keyUsage[5], "Issuer cannot sign certificates");
                    }
                    i = i2;
                } catch (GeneralSecurityException unused) {
                    throw new Probes.Hit("Issuer signature mismatch");
                }
            } else {
                return "";
            }
        }
    }

    String keyInfoLevel() throws Exception {
        Sample attested = attested();
        int securityLevel = ((KeyInfo) KeyFactory.getInstance("EC", "AndroidKeyStore").getKeySpec(attested.pair.getPrivate(), KeyInfo.class)).getSecurityLevel();
        if (securityLevel < 0 || securityLevel > 2) {
            throw new Probes.Skip("Unknown local security level");
        }
        require(attested.record.fields.get(3).integer() == ((long) securityLevel), "KeyInfo/attestation disagreement");
        return "";
    }

    String origins() throws Exception {
        require(((KeyInfo) KeyFactory.getInstance("EC", "AndroidKeyStore").getKeySpec(ec().getPrivate(), KeyInfo.class)).getOrigin() == 1, "Generated origin");
        String alias = alias("import_origin");
        byte[] nonce = nonce();
        this.ks.setEntry(alias, new KeyStore.SecretKeyEntry(new SecretKeySpec(nonce, "AES")), new KeyProtection.Builder(3).setBlockModes("GCM").setEncryptionPaddings("NoPadding").build());
        require(((KeyInfo) SecretKeyFactory.getInstance("AES", "AndroidKeyStore").getKeySpec((SecretKey) this.ks.getKey(alias, null), KeyInfo.class)).getOrigin() == 2, "Imported origin");
        Arrays.fill(nonce, (byte) 0);
        return "";
    }

    String ecParameters() throws Exception {
        Sample attested = attested();
        require(((ECPublicKey) attested.leaf.getPublicKey()).getParams().getOrder().bitLength() == 256, "EC public key size");
        require(attested.record.number(3) == 256 && attested.record.number(10) == 1, "EC authorization mismatch");
        return "";
    }

    Object rawControl(String str) throws Exception {
        if (this.raw == null) {
            throw new Probes.Skip("Raw interface unavailable");
        }
        String alias = alias(str);
        Object gen = gen(alias, null, 2);
        verifySign(alias, gen);
        return gen;
    }

    String aliasKeyId() throws Exception {
        if (this.raw == null) {
            throw new Probes.Skip("Raw interface unavailable");
        }
        String alias = alias("addressing");
        Object gen = gen(alias, null, 2);
        verifySign(alias, gen);
        Object meta = meta(this.raw.entry(RawBridge.field(gen, "key")));
        Object metadata = this.raw.metadata(alias);
        require(id(meta) == id(metadata) && Arrays.equals((byte[]) RawBridge.field(meta, "certificate"), (byte[]) RawBridge.field(metadata, "certificate")), "Addressing mismatch");
        return "";
    }

    void expectInvalid(Object obj) throws Exception {
        String[] strArr = {"update", "finish", "abort"};
        for (int i = 0; i < 3; i++) {
            String str = strArr[i];
            boolean z = true;
            try {
                if ("finish".equals(str)) {
                    RawBridge.invoke(obj, str, new byte[]{1}, null);
                } else if ("update".equals(str)) {
                    RawBridge.invoke(obj, str, new byte[]{1});
                } else {
                    RawBridge.invoke(obj, str, new Object[0]);
                }
                throw new Probes.Hit("Finished operation accepted");
            } catch (Probes.Hit e) {
                throw e;
            } catch (Exception e2) {
                Integer errorCode = RawBridge.errorCode(e2);
                if (errorCode == null) {
                    throw new Probes.Skip("No structured error");
                }
                if (errorCode.intValue() != -28) {
                    z = false;
                }
                require(z, "Wrong terminal handle error");
            }
        }
    }

    String lifecycle(boolean z) throws Exception {
        Object rawControl = rawControl("lifecycle");
        Object beginDescriptor = this.raw.beginDescriptor(RawBridge.field(rawControl, "key"), this.raw.signing());
        try {
            if (z) {
                RawBridge.invoke(beginDescriptor, "abort", new Object[0]);
            } else {
                byte[] nonce = nonce();
                verifyRaw(rawControl, nonce, this.raw.finish(beginDescriptor, nonce));
            }
            expectInvalid(beginDescriptor);
            return "";
        } finally {
            this.raw.abort(beginDescriptor);
        }
    }

    void verifyRaw(Object obj, byte[] bArr, byte[] bArr2) throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initVerify(cert(obj));
        signature.update(bArr);
        require(signature.verify(bArr2), "Raw operation signature mismatch");
    }

    String boundary(boolean z, boolean z2) throws Exception {
        byte[] finish;
        Object rawControl = rawControl("boundary");
        Object beginDescriptor = this.raw.beginDescriptor(RawBridge.field(rawControl, "key"), this.raw.signing());
        byte[] bArr = new byte[z2 ? 32769 : 32768];
        new SecureRandom().nextBytes(bArr);
        try {
            if (z2) {
                try {
                    try {
                        if (!z) {
                            RawBridge.invoke(beginDescriptor, "update", bArr);
                        } else {
                            this.raw.finish(beginDescriptor, bArr);
                        }
                        throw new Probes.Hit("Oversized request accepted");
                    } catch (Probes.Hit e) {
                        throw e;
                    }
                } catch (Exception e2) {
                    Integer errorCode = RawBridge.errorCode(e2);
                    if (errorCode == null) {
                        throw new Probes.Skip("No structured size error");
                    }
                    require(errorCode.intValue() == 21, "Incorrect size error class");
                    expectInvalid(beginDescriptor);
                }
            } else {
                if (!z) {
                    RawBridge.invoke(beginDescriptor, "update", bArr);
                    finish = this.raw.finish(beginDescriptor, new byte[0]);
                } else {
                    finish = this.raw.finish(beginDescriptor, bArr);
                }
                verifyRaw(rawControl, bArr, finish);
            }
            this.raw.abort(beginDescriptor);
            return "";
        } catch (Throwable th) {
            this.raw.abort(beginDescriptor);
            throw th;
        }
    }
}
