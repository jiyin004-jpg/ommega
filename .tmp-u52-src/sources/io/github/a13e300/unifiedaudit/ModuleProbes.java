package io.github.a13e300.unifiedaudit;

import android.security.keystore.KeyGenParameterSpec;
import io.github.a13e300.unifiedaudit.Der;
import io.github.a13e300.unifiedaudit.Probes;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONObject;

/* loaded from: classes.dex */
final class ModuleProbes extends Probes {
    private JSONObject omk;

    ModuleProbes(AuditRun auditRun) throws Exception {
        super(auditRun);
    }

    void runModules() throws Exception {
        try {
            test("SOFTWARE_CA", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.ModuleProbes.0
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return ModuleProbes.this.softwareIssuer();
                }
            });
            test("TEESIM_TIMING", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.ModuleProbes.1
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return ModuleProbes.this.m32lambda$runModules$0$iogithuba13e300unifiedauditModuleProbes();
                }
            });
            test("MIXED_CONTRACT", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.ModuleProbes.2
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return ModuleProbes.this.mixedContract();
                }
            });
            test("ATTEST_PARENT", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.ModuleProbes.3
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return ModuleProbes.this.m33lambda$runModules$1$iogithuba13e300unifiedauditModuleProbes();
                }
            });
            test("OMK_READ", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.ModuleProbes.4
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return ModuleProbes.this.m34lambda$runModules$2$iogithuba13e300unifiedauditModuleProbes();
                }
            });
            test("OMK_VIEWS", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.ModuleProbes.5
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return ModuleProbes.this.m35lambda$runModules$3$iogithuba13e300unifiedauditModuleProbes();
                }
            });
            test("REPLACEMENT_OPERATION", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.ModuleProbes.6
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return ModuleProbes.this.replacementOperation();
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

    /* renamed from: lambda$runModules$0$io-github-a13e300-unifiedaudit-ModuleProbes, reason: not valid java name */
    /* synthetic */ String m32lambda$runModules$0$iogithuba13e300unifiedauditModuleProbes() throws Exception {
        return verdict(TeeTimingChecker.probe().state.name());
    }

    /* renamed from: lambda$runModules$1$io-github-a13e300-unifiedaudit-ModuleProbes, reason: not valid java name */
    /* synthetic */ String m33lambda$runModules$1$iogithuba13e300unifiedauditModuleProbes() throws Exception {
        parentControl();
        return "";
    }

    /* renamed from: lambda$runModules$2$io-github-a13e300-unifiedaudit-ModuleProbes, reason: not valid java name */
    /* synthetic */ String m34lambda$runModules$2$iogithuba13e300unifiedauditModuleProbes() throws Exception {
        return omkView(0);
    }

    /* renamed from: lambda$runModules$3$io-github-a13e300-unifiedaudit-ModuleProbes, reason: not valid java name */
    /* synthetic */ String m35lambda$runModules$3$iogithuba13e300unifiedauditModuleProbes() throws Exception {
        return omkView(1);
    }

    String replacementOperation() throws Exception {
        if (this.raw == null) {
            throw new Probes.Skip("Raw interface unavailable");
        }
        String alias = alias("operation_replace");
        Object gen = gen(alias, null, 2);
        verifySign(alias, gen);
        Object begin = this.raw.begin(alias, this.raw.signing());
        byte[] nonce = nonce();
        try {
            RawBridge.invoke(begin, "update", Arrays.copyOf(nonce, 16));
            Object gen2 = gen(alias, null, 2);
            verifySign(alias, gen2);
            if (id(gen) == id(gen2) || Arrays.equals(cert(gen).getPublicKey().getEncoded(), cert(gen2).getPublicKey().getEncoded())) {
                throw new Probes.Hit("Replacement control failed");
            }
            byte[] finish = this.raw.finish(begin, Arrays.copyOfRange(nonce, 16, nonce.length));
            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initVerify(cert(gen));
            signature.update(nonce);
            CoreProbes.require(signature.verify(finish), "Existing operation lost its key binding");
            signature.initVerify(cert(gen2));
            signature.update(nonce);
            CoreProbes.require(!signature.verify(finish), "Existing operation rebound to replacement");
            return "";
        } finally {
            this.raw.abort(begin);
        }
    }

    String verdict(String str) throws Exception {
        if ("HIT".equals(str) || str.startsWith("HIT_")) {
            throw new Probes.Hit("Controlled finding");
        }
        if ("PASS".equals(str) || "CLEAR".equals(str)) {
            return "";
        }
        throw new Probes.Skip("Probe unavailable or inconclusive: " + str);
    }

    String omkView(int i) throws Exception {
        if (this.omk == null) {
            this.omk = new OmkProbe(this.app.context, null).run();
        }
        JSONArray optJSONArray = this.omk.optJSONArray("checks");
        if (optJSONArray == null || optJSONArray.length() != 2) {
            throw new Probes.Skip("Missing OMK controls");
        }
        return verdict(optJSONArray.getJSONObject(i).getString("verdict"));
    }

    String softwareIssuer() throws Exception {
        String alias = alias("software_ca");
        byte[] nonce = nonce();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "AndroidKeyStore");
        keyPairGenerator.initialize(new KeyGenParameterSpec.Builder(alias, 4).setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1")).setDigests("SHA-256").setAttestationChallenge(nonce).build());
        KeyPair generateKeyPair = keyPairGenerator.generateKeyPair();
        Certificate[] certificateChain = this.ks.getCertificateChain(alias);
        if (certificateChain == null || certificateChain.length < 2) {
            throw new Probes.Skip("Incomplete issuer chain");
        }
        X509Certificate x509Certificate = (X509Certificate) certificateChain[0];
        X509Certificate x509Certificate2 = (X509Certificate) certificateChain[1];
        Der.Record record = new Der.Record(x509Certificate);
        if (!Arrays.equals(nonce, record.challenge()) || !Arrays.equals(generateKeyPair.getPublic().getEncoded(), x509Certificate.getPublicKey().getEncoded())) {
            throw new Probes.Skip("Invalid certificate binding control");
        }
        CoreProbes.verifyPair(generateKeyPair, "SHA256withECDSA");
        if (!x509Certificate.getIssuerX500Principal().equals(x509Certificate2.getSubjectX500Principal()) || x509Certificate2.getBasicConstraints() < 0) {
            throw new Probes.Skip("Issuer control unavailable");
        }
        try {
            x509Certificate.verify(x509Certificate2.getPublicKey());
            long integer = record.fields.get(1).integer();
            long integer2 = record.fields.get(3).integer();
            if (integer != 1 && integer != 2) {
                return "";
            }
            if ((integer2 == 1 || integer2 == 2) && softwareCa(x509Certificate2)) {
                throw new Probes.Hit("Software authority signs hardware claim");
            }
            return "";
        } catch (GeneralSecurityException unused) {
            throw new Probes.Skip("Issuer signature control failed");
        }
    }

    static boolean softwareCa(X509Certificate x509Certificate) {
        Iterator<Der> it = Der.one(x509Certificate.getSubjectX500Principal().getEncoded()).children().iterator();
        while (it.hasNext()) {
            Iterator<Der> it2 = it.next().children().iterator();
            while (it2.hasNext()) {
                List<Der> children = it2.next().children();
                if (children.size() == 2 && Arrays.equals(children.get(0).value, new byte[]{85, 4, 3}) && new String(children.get(1).value, StandardCharsets.UTF_8).startsWith("Android Keystore Software Attestation")) {
                    return true;
                }
            }
        }
        return false;
    }

    Object parentControl() throws Exception {
        if (this.raw == null) {
            throw new Probes.Skip("Raw interface unavailable");
        }
        String alias = alias("ordinary_control");
        verifySign(alias, gen(alias, null, 2));
        String alias2 = alias("parent_control");
        Object gen = gen(alias2, nonce(), 7);
        String alias3 = alias("child_control");
        byte[] nonce = nonce();
        Object generate = this.raw.generate(alias3, this.raw.app(alias2), this.raw.ec(nonce, 2));
        checkChild(generate, cert(gen).getPublicKey(), cert(gen).getSubjectX500Principal());
        CoreProbes.require(Arrays.equals(nonce, new Der.Record(cert(generate)).challenge()), "Child challenge mismatch");
        verifySign(alias3, generate);
        return gen;
    }

    String mixedContract() throws Exception {
        parentControl();
        int[] iArr = new int[2];
        int i = 0;
        while (i < 2) {
            String alias = alias("mixed" + i);
            List<Object> ec = this.raw.ec(i == 0 ? null : nonce(), 2);
            ec.add(this.raw.param(536870913, "keyPurpose", 7));
            try {
                Object generate = this.raw.generate(alias, null, ec);
                verifySign(alias, generate);
                String alias2 = alias("mixed_child" + i);
                byte[] nonce = nonce();
                Object generate2 = this.raw.generate(alias2, this.raw.app(alias), this.raw.ec(nonce, 2));
                checkChild(generate2, cert(generate).getPublicKey(), cert(generate).getSubjectX500Principal());
                CoreProbes.require(Arrays.equals(nonce, new Der.Record(cert(generate2)).challenge()), "Mixed child challenge mismatch");
                verifySign(alias2, generate2);
                iArr[i] = 1;
            } catch (Exception e) {
                e = e;
                Integer errorCode = RawBridge.errorCode(e);
                Integer num = -3;
                if (!num.equals(errorCode)) {
                    Integer num2 = -49;
                    if (num2.equals(errorCode)) {
                        boolean z = false;
                        while (e != null) {
                            if (e.getMessage() != null && e.getMessage().contains("Error::Km(UNSUPPORTED_TAG)")) {
                                z = true;
                            }
                            e = e.getCause();
                        }
                        if (z) {
                            iArr[i] = 2;
                        }
                    }
                    throw new Probes.Skip("Unsupported mixed-purpose response");
                }
                iArr[i] = 0;
            }
            i++;
        }
        parentControl();
        int i2 = iArr[0];
        if (i2 != iArr[1]) {
            throw new Probes.Skip("Mixed responses inconsistent");
        }
        if (i2 != 2) {
            return "";
        }
        throw new Probes.Hit("Contradictory structured error mapping");
    }
}
