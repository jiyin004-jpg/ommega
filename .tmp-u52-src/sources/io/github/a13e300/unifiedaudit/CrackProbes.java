package io.github.a13e300.unifiedaudit;

import io.github.a13e300.unifiedaudit.Der;
import io.github.a13e300.unifiedaudit.Probes;
import java.io.ByteArrayInputStream;
import java.lang.reflect.Array;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import javax.security.auth.x500.X500Principal;

/* loaded from: classes.dex */
final class CrackProbes extends Probes {
    private static final String ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17";

    CrackProbes(AuditRun auditRun) throws Exception {
        super(auditRun);
    }

    void runCrack() throws Exception {
        try {
            test("SERIAL_FIDELITY", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.CrackProbes.0
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return CrackProbes.this.serialFidelity();
                }
            });
            test("SUBJECT_FIDELITY", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.CrackProbes.6
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return CrackProbes.this.subjectFidelity();
                }
            });
            test("EXTENSION_UNIQUENESS", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.CrackProbes.7
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return CrackProbes.this.extensionUniqueness();
                }
            });
            test("OPERATION_ROT", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.CrackProbes.8
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return CrackProbes.this.operationRootOfTrust();
                }
            });
            test("CHAIN_VIEW", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.CrackProbes.9
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return CrackProbes.this.chainView();
                }
            });
            test("CHALLENGE_LIMIT", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.CrackProbes.10
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return CrackProbes.this.challengeLimit();
                }
            });
            test("MAX_USES_PER_BOOT", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.CrackProbes.11
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return CrackProbes.this.maxUsesPerBoot();
                }
            });
            test("ACTIVE_TIME_GATE", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.CrackProbes.12
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return CrackProbes.this.activeTimeGate();
                }
            });
            test("ORIGINATION_EXPIRE_GATE", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.CrackProbes.13
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return CrackProbes.this.originationExpireGate();
                }
            });
            test("EARLY_BOOT_IMPORT", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.CrackProbes.14
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return CrackProbes.this.earlyBootImport();
                }
            });
            test("UNIQUE_ID_CONSISTENCY", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.CrackProbes.1
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return CrackProbes.this.uniqueIdConsistency();
                }
            });
            test("UNATTESTED_CHAIN_SHAPE", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.CrackProbes.2
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return CrackProbes.this.unattestedChainShape();
                }
            });
            test("IMPORT_CERT_SHAPE", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.CrackProbes.3
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return CrackProbes.this.importCertificateShape();
                }
            });
            test("READ_STABILITY", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.CrackProbes.4
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return CrackProbes.this.readStability();
                }
            });
            test("TAIL_STABILITY", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.CrackProbes.5
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return CrackProbes.this.tailStability();
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

    String serialFidelity() throws Exception {
        if (this.raw == null) {
            throw new Probes.Skip("Raw interface unavailable");
        }
        byte[] bArr = {10, 27, 44, 61, 78, 95, 96, 113};
        byte[] bArr2 = {17, 34, 51, 68, 85, 102, 119, 8};
        String alias = alias("serial_first");
        String alias2 = alias("serial_second");
        Object generateWithSerial = generateWithSerial(alias, bArr);
        Object generateWithSerial2 = generateWithSerial(alias2, bArr2);
        BigInteger bigInteger = new BigInteger(bArr);
        BigInteger bigInteger2 = new BigInteger(bArr2);
        X509Certificate cert = cert(generateWithSerial);
        X509Certificate cert2 = cert(generateWithSerial2);
        if (!bigInteger.equals(cert.getSerialNumber())) {
            throw new Probes.Hit("Explicit CERTIFICATE_SERIAL not preserved: " + String.valueOf(cert.getSerialNumber()) + " != " + String.valueOf(bigInteger));
        }
        if (!bigInteger2.equals(cert2.getSerialNumber())) {
            throw new Probes.Hit("Explicit CERTIFICATE_SERIAL not preserved: " + String.valueOf(cert2.getSerialNumber()) + " != " + String.valueOf(bigInteger2));
        }
        if (cert.getSerialNumber().equals(cert2.getSerialNumber())) {
            throw new Probes.Hit("Two distinct serial requests return one serial");
        }
        return "explicit serials preserved";
    }

    Object generateWithSerial(String str, byte[] bArr) throws Exception {
        ArrayList arrayList = new ArrayList(this.raw.ec(nonce(), 2));
        arrayList.add(this.raw.param(-2147482642, "blob", bArr));
        try {
            return this.raw.generate(str, null, arrayList);
        } catch (Exception e) {
            if (vendorGap(e)) {
                throw new Probes.Skip("Vendor rejects explicit CERTIFICATE_SERIAL");
            }
            throw e;
        }
    }

    static boolean vendorGap(Exception exc) {
        Integer errorCode = RawBridge.errorCode(exc);
        if (errorCode != null) {
            return errorCode.intValue() == -39 || errorCode.intValue() == -38 || errorCode.intValue() == -100;
        }
        return false;
    }

    static boolean authorizationUnsupported(Exception exc) {
        Integer errorCode = RawBridge.errorCode(exc);
        if (errorCode != null) {
            return errorCode.intValue() == -39 || errorCode.intValue() == -38 || errorCode.intValue() == -100 || errorCode.intValue() == -3 || errorCode.intValue() == -6 || errorCode.intValue() == -17;
        }
        return false;
    }

    static boolean platformUnavailable(Throwable th) {
        while (th != null) {
            String message = th.getMessage();
            if (message != null && (message.contains("User ECDH key missing") || message.contains("super encryption"))) {
                return true;
            }
            Integer errorCode = RawBridge.errorCode(th);
            if (errorCode != null && (errorCode.intValue() == -74 || errorCode.intValue() == -100)) {
                return true;
            }
            th = th.getCause();
        }
        return false;
    }

    String subjectFidelity() throws Exception {
        if (this.raw == null) {
            throw new Probes.Skip("Raw interface unavailable");
        }
        byte[] encoded = new X500Principal("CN=U52 Subject Fidelity,O=Rkp Audit,C=CN").getEncoded();
        String alias = alias("subject_fidelity");
        ArrayList arrayList = new ArrayList(this.raw.ec(nonce(), 2));
        arrayList.add(this.raw.param(-1879047185, "blob", encoded));
        try {
            X509Certificate cert = cert(this.raw.generate(alias, null, arrayList));
            if (!Arrays.equals(encoded, cert.getSubjectX500Principal().getEncoded())) {
                throw new Probes.Hit("Explicit CERTIFICATE_SUBJECT not preserved: " + cert.getSubjectX500Principal().getName());
            }
            return "";
        } catch (Exception e) {
            if (vendorGap(e)) {
                throw new Probes.Skip("Vendor rejects explicit CERTIFICATE_SUBJECT");
            }
            throw e;
        }
    }

    String extensionUniqueness() throws Exception {
        X509Certificate cert = cert(gen(alias("extensions"), nonce(), 2));
        if (cert.getVersion() != 3) {
            throw new Probes.Hit("Leaf certificate is not X.509 v3");
        }
        List<String> extensionOids = extensionOids(cert);
        if (extensionOids == null) {
            throw new Probes.Skip("Extension structure unavailable");
        }
        if (new HashSet(extensionOids).size() != extensionOids.size()) {
            throw new Probes.Hit("Duplicate certificate extension OID");
        }
        int frequency = Collections.frequency(extensionOids, ATTESTATION_OID);
        if (frequency == 0) {
            throw new Probes.Skip("Attestation extension absent from control");
        }
        if (frequency != 1) {
            throw new Probes.Hit("Multiple attestation extensions in one leaf");
        }
        Set<String> criticalExtensionOIDs = cert.getCriticalExtensionOIDs();
        if (criticalExtensionOIDs == null || !criticalExtensionOIDs.contains(ATTESTATION_OID)) {
            return "unique extensions, single non-critical attestation extension";
        }
        throw new Probes.Hit("Attestation extension marked critical");
    }

    static List<String> extensionOids(X509Certificate x509Certificate) throws Exception {
        Der der;
        Der one = Der.one(x509Certificate.getEncoded());
        if (one.tag != 16) {
            return null;
        }
        List<Der> children = one.children();
        if (children.size() >= 2 && children.get(0).tag == 16) {
            Iterator<Der> it = children.get(0).children().iterator();
            while (true) {
                if (!it.hasNext()) {
                    der = null;
                    break;
                }
                der = it.next();
                if (der.tag == 3 && der.tagClass == 128) {
                    break;
                }
            }
            if (der == null) {
                return new ArrayList();
            }
            List<Der> children2 = der.children();
            if (children2.size() == 1 && children2.get(0).tag == 16) {
                ArrayList arrayList = new ArrayList();
                Iterator<Der> it2 = children2.get(0).children().iterator();
                while (it2.hasNext()) {
                    List<Der> children3 = it2.next().children();
                    if (children3.isEmpty() || children3.get(0).tag != 6 || children3.get(0).tagClass != 0) {
                        return null;
                    }
                    arrayList.add(oid(children3.get(0).value));
                }
                return arrayList;
            }
        }
        return null;
    }

    static String oid(byte[] bArr) {
        StringBuilder sb = new StringBuilder();
        int i = bArr[0] & 255;
        if (i < 80) {
            sb.append(i / 40);
            sb.append('.');
            sb.append(i % 40);
        } else {
            sb.append("2.");
            sb.append(i - 80);
        }
        boolean z = false;
        long j = 0;
        for (int i2 = 1; i2 < bArr.length; i2++) {
            j = (j << 7) | (r7 & Byte.MAX_VALUE);
            if ((bArr[i2] & 128) == 0) {
                sb.append('.');
                sb.append(j);
                z = false;
                j = 0;
            } else {
                z = true;
            }
        }
        if (z) {
            sb.append('.');
            sb.append(j);
        }
        return sb.toString();
    }

    String operationRootOfTrust() throws Exception {
        String str;
        if (this.raw == null) {
            throw new Probes.Skip("Raw interface unavailable");
        }
        String alias = alias("operation_rot");
        Object gen = gen(alias, nonce(), 2);
        String metadataRot = metadataRot(gen);
        String rot = new Der.Record(cert(gen)).rot();
        if (metadataRot == null || "missing".equals(rot)) {
            throw new Probes.Skip("RootOfTrust absent from key views");
        }
        Object beginResponse = this.raw.beginResponse(alias, this.raw.signing());
        Object field = RawBridge.field(beginResponse, "iOperation");
        try {
            Object field2 = RawBridge.field(beginResponse, "keyCharacteristics");
            if (field2 != null) {
                for (int i = 0; i < Array.getLength(field2); i++) {
                    str = rotOfParameters(RawBridge.field(Array.get(field2, i), "authorizations"));
                    if (str != null) {
                        break;
                    }
                }
            }
            str = null;
            if (str == null) {
                throw new Probes.Skip("Operation characteristics omit RootOfTrust");
            }
            if (!str.equals(metadataRot) || !str.equals(rot)) {
                throw new Probes.Hit("RootOfTrust differs between operation/metadata/certificate: " + str + " / " + metadataRot + " / " + rot);
            }
            return "operation, metadata and attestation agree on RootOfTrust";
        } finally {
            this.raw.abort(field);
        }
    }

    String chainView() throws Exception {
        if (this.raw == null) {
            throw new Probes.Skip("Raw interface unavailable");
        }
        String alias = alias("chain_view");
        Object gen = gen(alias, nonce(), 2);
        Certificate[] certificateChain = this.ks.getCertificateChain(alias);
        if (certificateChain == null || certificateChain.length == 0) {
            throw new Probes.Skip("Java chain unavailable");
        }
        ArrayList arrayList = new ArrayList();
        arrayList.add((byte[]) RawBridge.field(gen, "certificate"));
        byte[] bArr = (byte[]) RawBridge.field(gen, "certificateChain");
        if (bArr != null && bArr.length > 0) {
            Iterator<? extends Certificate> it = CertificateFactory.getInstance("X.509").generateCertificates(new ByteArrayInputStream(bArr)).iterator();
            while (it.hasNext()) {
                arrayList.add(it.next().getEncoded());
            }
        }
        if (certificateChain.length != arrayList.size()) {
            throw new Probes.Hit("Java/raw chain length " + certificateChain.length + " vs " + arrayList.size());
        }
        for (int i = 0; i < certificateChain.length; i++) {
            if (!Arrays.equals(certificateChain[i].getEncoded(), (byte[]) arrayList.get(i))) {
                throw new Probes.Hit("Java/raw chain differs at certificate " + i);
            }
        }
        verifySign(alias, gen);
        return certificateChain.length + "-certificate chain identical in both views";
    }

    /* JADX WARN: Code restructure failed: missing block: B:16:0x007c, code lost:
    
        if (r5 >= 0) goto L40;
     */
    /* JADX WARN: Code restructure failed: missing block: B:18:0x0085, code lost:
    
        throw new io.github.a13e300.unifiedaudit.Probes.Skip("No accepted attestation challenge size");
     */
    /* JADX WARN: Code restructure failed: missing block: B:20:0x0086, code lost:
    
        r7 = r5 + 1;
        r11.raw.generate(alias("challenge_over"), null, new java.util.ArrayList(r11.raw.ec(new byte[r7], 2)));
     */
    /* JADX WARN: Code restructure failed: missing block: B:21:0x00c3, code lost:
    
        throw new io.github.a13e300.unifiedaudit.Probes.Hit("Challenge of " + r7 + " bytes accepted (limit observed " + r5 + ")");
     */
    /* JADX WARN: Code restructure failed: missing block: B:23:0x0108, code lost:
    
        r11 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:24:0x0109, code lost:
    
        throw r11;
     */
    /* JADX WARN: Code restructure failed: missing block: B:25:0x00c4, code lost:
    
        r11 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:26:0x00c5, code lost:
    
        r11 = io.github.a13e300.unifiedaudit.RawBridge.errorCode(r11);
        r0 = -21;
     */
    /* JADX WARN: Code restructure failed: missing block: B:27:0x00d1, code lost:
    
        if (r0.equals(r11) != false) goto L30;
     */
    /* JADX WARN: Code restructure failed: missing block: B:29:0x00ee, code lost:
    
        return r5 + "-byte challenge accepted, " + (r5 + 1) + " rejected -21";
     */
    /* JADX WARN: Code restructure failed: missing block: B:31:0x0107, code lost:
    
        throw new io.github.a13e300.unifiedaudit.Probes.Hit("Oversized challenge rejected with " + r11 + " instead of INVALID_INPUT_LENGTH");
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    java.lang.String challengeLimit() throws java.lang.Exception {
        /*
            Method dump skipped, instructions count: 274
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: io.github.a13e300.unifiedaudit.CrackProbes.challengeLimit():java.lang.String");
    }

    String maxUsesPerBoot() throws Exception {
        if (this.raw == null) {
            throw new Probes.Skip("Raw interface unavailable");
        }
        String alias = alias("perboot");
        ArrayList arrayList = new ArrayList(this.raw.ec(nonce(), 2));
        arrayList.add(this.raw.param(805306772, "integer", 1));
        try {
            Object generate = this.raw.generate(alias, null, arrayList);
            verifySign(alias, generate);
            try {
                verifySign(alias, generate);
                throw new Probes.Hit("MAX_USES_PER_BOOT=1 allowed a second signature before reboot");
            } catch (Probes.Hit e) {
                throw e;
            } catch (Probes.Skip e2) {
                throw e2;
            } catch (Exception e3) {
                return "second signature rejected code=" + RawBridge.errorCode(e3);
            }
        } catch (Exception e4) {
            if (authorizationUnsupported(e4)) {
                throw new Probes.Skip("Vendor rejects MAX_USES_PER_BOOT");
            }
            throw e4;
        }
    }

    String activeTimeGate() throws Exception {
        if (this.raw == null) {
            throw new Probes.Skip("Raw interface unavailable");
        }
        String alias = alias("future_active");
        ArrayList arrayList = new ArrayList(this.raw.ec(null, 2));
        arrayList.add(this.raw.param(1610613136, "dateTime", Long.valueOf(System.currentTimeMillis() + 3600000)));
        try {
            try {
                verifySign(alias, this.raw.generate(alias, null, arrayList));
                throw new Probes.Hit("A key whose ACTIVE_DATETIME is one hour away already signs");
            } catch (Probes.Hit e) {
                throw e;
            } catch (Probes.Skip e2) {
                throw e2;
            } catch (Exception e3) {
                return "not-yet-active key use rejected code=" + RawBridge.errorCode(e3);
            }
        } catch (Exception e4) {
            if (authorizationUnsupported(e4)) {
                throw new Probes.Skip("Vendor rejects ACTIVE_DATETIME");
            }
            throw e4;
        }
    }

    String originationExpireGate() throws Exception {
        if (this.raw == null) {
            throw new Probes.Skip("Raw interface unavailable");
        }
        String alias = alias("orig_expire");
        List<Object> rsaParams = rsaParams(null, 0, 4);
        rsaParams.add(this.raw.param(1610613137, "dateTime", Long.valueOf(System.currentTimeMillis() - 3600000)));
        try {
            this.raw.generate(alias, null, rsaParams);
            try {
                try {
                    this.raw.abort(this.raw.begin(alias, Arrays.asList(this.raw.param(536870913, "keyPurpose", 0), this.raw.param(536870918, "paddingMode", 4))));
                    throw new Probes.Hit("A key past ORIGINATION_EXPIRE_DATETIME still starts an encryption operation");
                } catch (Exception e) {
                    String str = "expired origination key use rejected code=" + RawBridge.errorCode(e);
                    this.raw.abort(null);
                    return str;
                }
            } catch (Throwable th) {
                this.raw.abort(null);
                throw th;
            }
        } catch (Exception e2) {
            Integer errorCode = RawBridge.errorCode(e2);
            if (authorizationUnsupported(e2)) {
                return "expired origination key rejected at generation";
            }
            Integer num = -25;
            if (num.equals(errorCode)) {
                return "expired origination key rejected at generation";
            }
            throw new Probes.Skip("Unexpected origination rejection code=" + errorCode);
        }
    }

    String earlyBootImport() throws Exception {
        if (this.raw == null) {
            throw new Probes.Skip("Raw interface unavailable");
        }
        KeyPair localEc = localEc();
        ArrayList arrayList = new ArrayList(this.raw.ec(nonce(), 7));
        arrayList.add(this.raw.param(1879048497, "boolValue", true));
        try {
            this.raw.importKey(alias("earlyboot_import"), null, arrayList, localEc.getPrivate().getEncoded());
            throw new Probes.Hit("EARLY_BOOT_ONLY key imported after early boot");
        } catch (Exception e) {
            Integer errorCode = RawBridge.errorCode(e);
            if (authorizationUnsupported(e)) {
                return "early-boot-only import rejected";
            }
            Integer num = -73;
            if (num.equals(errorCode)) {
                return "early-boot-only import rejected";
            }
            throw new Probes.Skip("Unexpected early-boot import code=" + errorCode);
        }
    }

    String uniqueIdConsistency() throws Exception {
        if (this.raw == null) {
            throw new Probes.Skip("Raw interface unavailable");
        }
        Der.Record uniqueIdRecord = uniqueIdRecord("unique_first");
        Der.Record uniqueIdRecord2 = uniqueIdRecord("unique_second");
        byte[] bArr = uniqueIdRecord.fields.get(5).value;
        byte[] bArr2 = uniqueIdRecord2.fields.get(5).value;
        if (bArr.length == 0 || bArr2.length == 0) {
            throw new Probes.Hit("INCLUDE_UNIQUE_ID requested but attestation uniqueId is empty");
        }
        if (!Arrays.equals(bArr, bArr2)) {
            throw new Probes.Hit("Two keys in one boot report different uniqueId values");
        }
        return "uniqueId present and stable across two keys";
    }

    Der.Record uniqueIdRecord(String str) throws Exception {
        String alias = alias(str);
        ArrayList arrayList = new ArrayList(this.raw.ec(nonce(), 2));
        arrayList.add(this.raw.param(1879048394, "boolValue", true));
        try {
            return new Der.Record(cert(this.raw.generate(alias, null, arrayList)));
        } catch (Exception e) {
            Integer errorCode = RawBridge.errorCode(e);
            if (errorCode != null && (errorCode.intValue() == 6 || errorCode.intValue() == -32)) {
                throw new Probes.Skip("INCLUDE_UNIQUE_ID requires a permission ordinary apps do not hold");
            }
            if (authorizationUnsupported(e)) {
                throw new Probes.Skip("Vendor rejects INCLUDE_UNIQUE_ID");
            }
            throw e;
        }
    }

    String unattestedChainShape() throws Exception {
        if (this.raw == null) {
            throw new Probes.Skip("Raw interface unavailable");
        }
        String alias = alias("unattested_shape");
        Object generate = this.raw.generate(alias, null, this.raw.ec(null, 2));
        X509Certificate cert = cert(generate);
        List<X509Certificate> metadataChain = metadataChain(generate);
        if (metadataChain.size() != 1) {
            throw new Probes.Hit("Unattested key returns " + metadataChain.size() + " certificates instead of one self-signed leaf");
        }
        if (!cert.getIssuerX500Principal().equals(cert.getSubjectX500Principal())) {
            throw new Probes.Hit("Unattested leaf is not self-signed");
        }
        try {
            cert.verify(cert.getPublicKey());
            if (cert.getExtensionValue(ATTESTATION_OID) != null) {
                throw new Probes.Hit("Unattested key carries an attestation extension");
            }
            Certificate[] certificateChain = this.ks.getCertificateChain(alias);
            if (certificateChain == null || certificateChain.length != 1) {
                throw new Probes.Hit("Java view returns " + certificateChain.length + " certificates for an unattested key");
            }
            verifySign(alias, generate);
            return "unattested key: one self-signed leaf, no attestation extension";
        } catch (GeneralSecurityException unused) {
            throw new Probes.Hit("Unattested leaf self-signature does not verify");
        }
    }

    String importCertificateShape() throws Exception {
        if (this.raw == null) {
            throw new Probes.Skip("Raw interface unavailable");
        }
        KeyPair localEc = localEc();
        Object importKey = this.raw.importKey(alias("import_shape"), null, this.raw.ec(null, 7), localEc.getPrivate().getEncoded());
        X509Certificate cert = cert(importKey);
        if (!Arrays.equals(cert.getPublicKey().getEncoded(), localEc.getPublic().getEncoded())) {
            throw new Probes.Skip("Imported public key control failed");
        }
        List<X509Certificate> metadataChain = metadataChain(importKey);
        if (metadataChain.size() != 1) {
            throw new Probes.Hit("Unattested import returns " + metadataChain.size() + " certificates instead of one self-signed leaf");
        }
        if (!cert.getIssuerX500Principal().equals(cert.getSubjectX500Principal())) {
            throw new Probes.Hit("Unattested import leaf is not self-signed");
        }
        if (cert.getExtensionValue(ATTESTATION_OID) != null) {
            throw new Probes.Hit("Unattested import carries an attestation extension");
        }
        return "unattested import: one self-signed leaf, no attestation extension";
    }

    String readStability() throws Exception {
        if (this.raw == null) {
            throw new Probes.Skip("Raw interface unavailable");
        }
        String alias = alias("read_stability");
        Object gen = gen(alias, nonce(), 2);
        byte[] bArr = (byte[]) RawBridge.field(gen, "certificate");
        for (int i = 0; i < 3; i++) {
            if (!Arrays.equals(bArr, (byte[]) RawBridge.field(this.raw.metadata(alias), "certificate"))) {
                throw new Probes.Hit("Leaf bytes changed on read " + (i + 1));
            }
            Certificate[] certificateChain = this.ks.getCertificateChain(alias);
            if (certificateChain == null || certificateChain.length == 0 || !Arrays.equals(bArr, certificateChain[0].getEncoded())) {
                throw new Probes.Hit("Java leaf changed on read " + (i + 1));
            }
        }
        verifySign(alias, gen);
        return "3 rereads return the generated leaf";
    }

    /* JADX WARN: Removed duplicated region for block: B:12:0x0044  */
    /* JADX WARN: Removed duplicated region for block: B:15:0x0052  */
    /* JADX WARN: Removed duplicated region for block: B:19:0x0046  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    java.lang.String tailStability() throws java.lang.Exception {
        /*
            r7 = this;
            io.github.a13e300.unifiedaudit.RawBridge r0 = r7.raw
            if (r0 == 0) goto L88
            java.lang.String r0 = "tail_stability"
            java.lang.String r0 = r7.alias(r0)
            byte[] r1 = nonce()
            r2 = 2
            java.lang.Object r1 = r7.gen(r0, r1, r2)
            java.lang.String r2 = "certificateChain"
            java.lang.Object r3 = io.github.a13e300.unifiedaudit.RawBridge.field(r1, r2)
            byte[] r3 = (byte[]) r3
            r4 = 0
        L1c:
            r5 = 3
            if (r4 >= r5) goto L82
            io.github.a13e300.unifiedaudit.RawBridge r5 = r7.raw
            java.lang.Object r5 = r5.metadata(r0)
            java.lang.Object r5 = io.github.a13e300.unifiedaudit.RawBridge.field(r5, r2)
            byte[] r5 = (byte[]) r5
            if (r3 != 0) goto L30
            if (r5 == 0) goto L39
            goto L3c
        L30:
            if (r5 == 0) goto L3c
            boolean r6 = java.util.Arrays.equals(r3, r5)
            if (r6 != 0) goto L39
            goto L3c
        L39:
            int r4 = r4 + 1
            goto L1c
        L3c:
            io.github.a13e300.unifiedaudit.Probes$Hit r7 = new io.github.a13e300.unifiedaudit.Probes$Hit
            int r4 = r4 + 1
            java.lang.String r0 = "null"
            if (r3 != 0) goto L46
            r1 = r0
            goto L4b
        L46:
            int r1 = r3.length
            java.lang.Integer r1 = java.lang.Integer.valueOf(r1)
        L4b:
            java.lang.String r1 = java.lang.String.valueOf(r1)
            if (r5 != 0) goto L52
            goto L57
        L52:
            int r0 = r5.length
            java.lang.Integer r0 = java.lang.Integer.valueOf(r0)
        L57:
            java.lang.String r0 = java.lang.String.valueOf(r0)
            java.lang.StringBuilder r2 = new java.lang.StringBuilder
            java.lang.String r3 = "Chain tail changed on read "
            r2.<init>(r3)
            r2.append(r4)
            java.lang.String r3 = " ("
            r2.append(r3)
            r2.append(r1)
            java.lang.String r1 = " vs "
            r2.append(r1)
            r2.append(r0)
            java.lang.String r0 = ")"
            r2.append(r0)
            java.lang.String r0 = r2.toString()
            r7.<init>(r0)
            throw r7
        L82:
            r7.verifySign(r0, r1)
            java.lang.String r7 = "chain tail stable across rereads"
            return r7
        L88:
            io.github.a13e300.unifiedaudit.Probes$Skip r7 = new io.github.a13e300.unifiedaudit.Probes$Skip
            java.lang.String r0 = "Raw interface unavailable"
            r7.<init>(r0)
            throw r7
        */
        throw new UnsupportedOperationException("Method not decompiled: io.github.a13e300.unifiedaudit.CrackProbes.tailStability():java.lang.String");
    }

    List<X509Certificate> metadataChain(Object obj) throws Exception {
        ArrayList arrayList = new ArrayList();
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        arrayList.add((X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream((byte[]) RawBridge.field(obj, "certificate"))));
        byte[] bArr = (byte[]) RawBridge.field(obj, "certificateChain");
        if (bArr != null && bArr.length > 0) {
            Iterator<? extends Certificate> it = certificateFactory.generateCertificates(new ByteArrayInputStream(bArr)).iterator();
            while (it.hasNext()) {
                arrayList.add((X509Certificate) it.next());
            }
        }
        return arrayList;
    }
}
