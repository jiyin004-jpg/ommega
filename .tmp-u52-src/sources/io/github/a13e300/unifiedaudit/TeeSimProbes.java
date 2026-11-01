package io.github.a13e300.unifiedaudit;

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import io.github.a13e300.unifiedaudit.Der;
import io.github.a13e300.unifiedaudit.Probes;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Iterator;
import java.util.List;
import java.util.UUID;
import org.json.JSONObject;

/* loaded from: classes.dex */
final class TeeSimProbes extends Probes {
    private static final String BASELINE = "teesim-baseline.json";
    private static final Object LOCK = new Object();
    private Snapshot current;

    TeeSimProbes(AuditRun auditRun) throws Exception {
        super(auditRun);
    }

    void runTeeSim() throws Exception {
        try {
            test("H06", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.TeeSimProbes.0
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return TeeSimProbes.this.patchLevelAgainstBaseline();
                }
            });
            test("H07", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.TeeSimProbes.1
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return TeeSimProbes.this.lockedAgainstBaseline();
                }
            });
            test("H08", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.TeeSimProbes.2
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return TeeSimProbes.this.stateAgainstBaseline();
                }
            });
            test("H09", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.TeeSimProbes.3
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return TeeSimProbes.this.bootKeyAgainstBaseline();
                }
            });
            test("H10", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.TeeSimProbes.4
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return TeeSimProbes.this.issuerAgainstBaseline();
                }
            });
            test("G06", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.TeeSimProbes.1
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return TeeSimProbes.this.lockedAgainstBaseline();
                }
            });
            test("G07", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.TeeSimProbes.2
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return TeeSimProbes.this.stateAgainstBaseline();
                }
            });
            test("G08", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.TeeSimProbes.3
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return TeeSimProbes.this.bootKeyAgainstBaseline();
                }
            });
            test("G09", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.TeeSimProbes.4
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return TeeSimProbes.this.issuerAgainstBaseline();
                }
            });
            test("G10", "", new Probes.Test() { // from class: io.github.a13e300.unifiedaudit.TeeSimProbes.0
                @Override // io.github.a13e300.unifiedaudit.Probes.Test
                public final String run() {
                    return TeeSimProbes.this.patchLevelAgainstBaseline();
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

    String lockedAgainstBaseline() throws Exception {
        return compare(baseline(), "locked", String.valueOf(current().locked));
    }

    String stateAgainstBaseline() throws Exception {
        return compare(baseline(), "state", String.valueOf(current().state));
    }

    String bootKeyAgainstBaseline() throws Exception {
        return compare(baseline(), "bootKey", current().bootKey);
    }

    String issuerAgainstBaseline() throws Exception {
        return compare(baseline(), "issuer", current().issuer);
    }

    String patchLevelAgainstBaseline() throws Exception {
        JSONObject baseline = baseline();
        Snapshot current = current();
        if (!baseline.has("osPatch")) {
            throw new Probes.Skip("Baseline has no patch levels");
        }
        String str = baseline.optString("osPatch") + "/" + baseline.optString("vendorPatch") + "/" + baseline.optString("bootPatch");
        String str2 = current.osPatch + "/" + current.vendorPatch + "/" + current.bootPatch;
        if (!str.equals(str2)) {
            throw new Probes.Hit("patch levels differ from genuine baseline: " + str + " -> " + str2);
        }
        return "patch levels match baseline (" + str2 + ")";
    }

    String compare(JSONObject jSONObject, String str, String str2) throws Exception {
        String optString = jSONObject.optString(str, null);
        if (optString == null) {
            throw new Probes.Skip("Baseline has no " + str);
        }
        if (!optString.equals(str2)) {
            throw new Probes.Hit(str + " differs from genuine baseline: " + optString + " -> " + str2);
        }
        return str + " matches baseline (" + str2 + ")";
    }

    JSONObject baseline() throws Exception {
        JSONObject jSONObject;
        synchronized (LOCK) {
            File file = new File(this.app.context.getFilesDir(), BASELINE);
            if (!file.exists()) {
                throw new Probes.Skip("No genuine baseline; capture it with TEESimulator inactive");
            }
            try {
                jSONObject = new JSONObject(new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8));
            } catch (Exception e) {
                throw new Probes.Skip("Baseline unreadable: " + e.getClass().getSimpleName());
            }
        }
        return jSONObject;
    }

    X509Certificate attestedCertificate(String str) throws Exception {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "AndroidKeyStore");
            keyPairGenerator.initialize(new KeyGenParameterSpec.Builder(str, 4).setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1")).setDigests("SHA-256").setAttestationChallenge(nonce()).build());
            keyPairGenerator.generateKeyPair();
            Certificate[] certificateChain = this.ks.getCertificateChain(str);
            if (certificateChain == null || certificateChain.length == 0) {
                throw new Probes.Skip("Attestation chain unavailable");
            }
            return (X509Certificate) certificateChain[0];
        } catch (Probes.Skip e) {
            throw e;
        } catch (Exception e2) {
            throw new Probes.Skip("Attestation unavailable: " + e2.getClass().getSimpleName());
        }
    }

    /* JADX WARN: Finally extract failed */
    Snapshot current() throws Exception {
        Snapshot snapshot = this.current;
        if (snapshot != null) {
            return snapshot;
        }
        String alias = alias("teesim_snapshot");
        try {
            try {
                try {
                    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "AndroidKeyStore");
                    keyPairGenerator.initialize(new KeyGenParameterSpec.Builder(alias, 4).setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1")).setDigests("SHA-256").setAttestationChallenge(nonce()).build());
                    keyPairGenerator.generateKeyPair();
                    Certificate[] certificateChain = this.ks.getCertificateChain(alias);
                    if (certificateChain == null || certificateChain.length == 0) {
                        throw new Probes.Skip("Attestation chain unavailable");
                    }
                    this.current = Snapshot.of((X509Certificate) certificateChain[0], certificateChain.length, (X509Certificate) certificateChain[certificateChain.length - 1]);
                    try {
                        this.ks.deleteEntry(alias);
                    } catch (Exception unused) {
                    }
                    this.aliases.remove(alias);
                    return this.current;
                } catch (Throwable th) {
                    try {
                        this.ks.deleteEntry(alias);
                    } catch (Exception unused2) {
                    }
                    this.aliases.remove(alias);
                    throw th;
                }
            } catch (Exception e) {
                throw new Probes.Skip("Attestation unavailable: " + e.getClass().getSimpleName());
            }
        } catch (Probes.Skip e2) {
            throw e2;
        }
    }

    static final class Snapshot {
        String bootHash;
        String bootKey;
        String bootPatch;
        int chainLength;
        String issuer;
        boolean locked;
        String osPatch;
        String rootSpki;
        int state;
        String vendorPatch;

        Snapshot() {
        }

        static Snapshot of(X509Certificate x509Certificate, int i, X509Certificate x509Certificate2) throws Exception {
            Snapshot snapshot = new Snapshot();
            Der.Record record = new Der.Record(x509Certificate);
            Der tag = record.tag(704);
            if (tag == null) {
                throw new Probes.Skip("Root of trust absent");
            }
            List<Der> children = tag.children();
            if (children.size() < 3) {
                throw new Probes.Skip("Root of trust incomplete");
            }
            snapshot.locked = children.get(1).value[0] != 0;
            snapshot.state = (int) children.get(2).integer();
            snapshot.bootKey = Probes.hex(children.get(0).value);
            snapshot.bootHash = children.size() > 3 ? Probes.hex(children.get(3).value) : "";
            snapshot.issuer = x509Certificate.getIssuerX500Principal().getName();
            snapshot.chainLength = i;
            snapshot.osPatch = String.valueOf(record.number(706));
            snapshot.vendorPatch = String.valueOf(record.number(718));
            snapshot.bootPatch = String.valueOf(record.number(719));
            snapshot.rootSpki = Probes.hash(x509Certificate2.getPublicKey().getEncoded());
            return snapshot;
        }

        JSONObject json() throws Exception {
            return new JSONObject().put("locked", this.locked).put("state", this.state).put("bootKey", this.bootKey).put("bootHash", this.bootHash).put("issuer", this.issuer).put("rootSpki", this.rootSpki).put("chainLength", this.chainLength).put("osPatch", this.osPatch).put("vendorPatch", this.vendorPatch).put("bootPatch", this.bootPatch).put("capturedAt", System.currentTimeMillis());
        }
    }

    static void captureBaseline(Context context) throws Exception {
        synchronized (LOCK) {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            String str = "teesim_baseline_" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
            try {
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "AndroidKeyStore");
                KeyGenParameterSpec.Builder attestationChallenge = new KeyGenParameterSpec.Builder(str, 4).setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1")).setDigests("SHA-256").setAttestationChallenge(randomBytes());
                attestationChallenge.setDevicePropertiesAttestationIncluded(true);
                keyPairGenerator.initialize(attestationChallenge.build());
                keyPairGenerator.generateKeyPair();
                Certificate[] certificateChain = keyStore.getCertificateChain(str);
                if (certificateChain == null || certificateChain.length == 0) {
                    throw new IllegalStateException("attestation chain unavailable");
                }
                Snapshot of = Snapshot.of((X509Certificate) certificateChain[0], certificateChain.length, (X509Certificate) certificateChain[certificateChain.length - 1]);
                FileOutputStream fileOutputStream = new FileOutputStream(new File(context.getFilesDir(), BASELINE));
                try {
                    fileOutputStream.write(of.json().toString(2).getBytes("UTF-8"));
                } finally {
                    fileOutputStream.close();
                }
            } finally {
                try {
                    keyStore.deleteEntry(str);
                } catch (Exception unused) {
                }
            }
        }
    }

    static byte[] randomBytes() {
        byte[] bArr = new byte[32];
        new SecureRandom().nextBytes(bArr);
        return bArr;
    }
}
