package io.github.a13e300.unifiedaudit;

import android.content.Context;
import android.os.IBinder;
import android.security.keystore.KeyGenParameterSpec;
import android.util.Base64;
import java.lang.reflect.Array;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.json.JSONArray;
import org.json.JSONObject;

/* loaded from: classes.dex */
public abstract class ProbeBase {
    static final String KM = "android.hardware.security.keymint.";
    static final String KS = "android.system.keystore2.";
    private final Context context;
    Class<?> dc;
    Object level;
    Class<?> pc;
    KeyStore store;
    Object svc;
    List<String> aliases = new ArrayList();
    String prefix = "omk_demo_" + UUID.randomUUID().toString().replace("-", "") + "_";

    interface Action {
        void run(JSONObject jSONObject) throws Exception;
    }

    abstract void emit(JSONObject jSONObject);

    ProbeBase(Context context) {
        this.context = context.getApplicationContext();
    }

    Context getTargetContext() {
        return this.context;
    }

    void test(String str, Action action) {
        JSONObject jSONObject = new JSONObject();
        try {
            jSONObject.put("test", str);
            action.run(jSONObject);
            jSONObject.put("execution", "OK");
        } catch (Throwable th) {
            try {
                jSONObject.put("execution", "ERROR_OR_UNAVAILABLE").put("error", error(th));
            } catch (Exception unused) {
            }
        }
        emit(jSONObject);
    }

    String alias(String str) {
        String str2 = this.prefix + str + this.aliases.size();
        AuditLedger.register(str2);
        this.aliases.add(str2);
        return str2;
    }

    static String error(Throwable th) {
        StringBuilder sb = new StringBuilder();
        int i = 0;
        while (i < 8 && th != null) {
            if (i > 0) {
                sb.append(" <- ");
            }
            sb.append(th.getClass().getName());
            sb.append(": ");
            sb.append(th.getMessage());
            try {
                Object obj = th.getClass().getField("errorCode").get(th);
                sb.append(" [serviceCode=");
                sb.append(obj);
                sb.append(']');
            } catch (Exception unused) {
            }
            i++;
            th = th.getCause();
        }
        return sb.toString();
    }

    static Integer serviceCode(Throwable th) {
        int i = 0;
        while (i < 8 && th != null) {
            try {
                try {
                    return (Integer) th.getClass().getField("errorCode").get(th);
                } catch (Exception unused) {
                    i++;
                    th = th.getCause();
                }
            } catch (Exception unused2) {
                Class[] clsArr = new Class[0];
                return (Integer) th.getClass().getMethod("getErrorCode", null).invoke(th, null);
            }
        }
        return null;
    }

    static Object field(Object obj, String str) throws Exception {
        return obj.getClass().getField(str).get(obj);
    }

    static String b64(byte[] bArr) {
        if (bArr == null) {
            return null;
        }
        return Base64.encodeToString(bArr, 2);
    }

    static String sha(byte[] bArr) throws Exception {
        if (bArr == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder();
        for (byte b : MessageDigest.getInstance("SHA-256").digest(bArr)) {
            sb.append(String.format("%02x", Byte.valueOf(b)));
        }
        return sb.toString();
    }

    static byte[] nonce() {
        byte[] bArr = new byte[32];
        new SecureRandom().nextBytes(bArr);
        return bArr;
    }

    KeyGenParameterSpec.Builder spec(String str, int i) {
        return new KeyGenParameterSpec.Builder(str, i).setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1")).setDigests("SHA-256");
    }

    KeyPair gen(KeyGenParameterSpec.Builder builder) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "AndroidKeyStore");
        keyPairGenerator.initialize(builder.build());
        return keyPairGenerator.generateKeyPair();
    }

    JSONObject cert(X509Certificate x509Certificate) throws Exception {
        return new JSONObject().put("sha256", sha(x509Certificate.getEncoded())).put("der", b64(x509Certificate.getEncoded())).put("spki", sha(x509Certificate.getPublicKey().getEncoded())).put("subject", x509Certificate.getSubjectX500Principal().getName()).put("issuer", x509Certificate.getIssuerX500Principal().getName()).put("sigAlg", x509Certificate.getSigAlgName()).put("sigAlgOid", x509Certificate.getSigAlgOID()).put("sigParams", b64(x509Certificate.getSigAlgParams())).put("notBefore", x509Certificate.getNotBefore().getTime()).put("notAfter", x509Certificate.getNotAfter().getTime());
    }

    JSONObject chain(String str) throws Exception {
        Certificate[] certificateChain = this.store.getCertificateChain(str);
        JSONArray jSONArray = new JSONArray();
        if (certificateChain != null) {
            for (Certificate certificate : certificateChain) {
                jSONArray.put(cert((X509Certificate) certificate));
            }
        }
        JSONObject put = new JSONObject().put("chain", jSONArray);
        if (certificateChain != null) {
            boolean z = true;
            int i = 0;
            while (true) {
                int i2 = i + 1;
                if (i2 >= certificateChain.length) {
                    break;
                }
                try {
                    certificateChain[i].verify(certificateChain[i2].getPublicKey());
                } catch (Exception e) {
                    put.put("signatureError", error(e));
                    z = false;
                }
                i = i2;
            }
            put.put("adjacentSignaturesValid", z);
        }
        return put;
    }

    Object descriptor(String str) throws Exception {
        Class[] clsArr = new Class[0];
        Object newInstance = this.dc.getConstructor(null).newInstance(null);
        this.dc.getField("domain").setInt(newInstance, 0);
        this.dc.getField("nspace").setLong(newInstance, -1L);
        this.dc.getField("alias").set(newInstance, str);
        return newInstance;
    }

    /* JADX WARN: Multi-variable type inference failed */
    Object param(int i, String str, Object obj) throws Exception {
        Class[] clsArr = new Class[0];
        Object newInstance = this.pc.getConstructor(null).newInstance(null);
        this.pc.getField("tag").setInt(newInstance, i);
        this.pc.getField("value").set(newInstance, Class.forName("android.hardware.security.keymint.KeyParameterValue").getMethod(str, obj instanceof Integer ? Integer.TYPE : obj instanceof Long ? Long.TYPE : obj instanceof Boolean ? Boolean.TYPE : byte[].class).invoke(null, obj));
        return newInstance;
    }

    List<Object> base(boolean z) throws Exception {
        ArrayList arrayList = new ArrayList();
        arrayList.add(param(268435458, "algorithm", 3));
        arrayList.add(param(805306371, "integer", 256));
        arrayList.add(param(268435466, "ecCurve", 1));
        arrayList.add(param(536870913, "keyPurpose", 2));
        arrayList.add(param(536870917, "digest", 4));
        arrayList.add(param(1879048695, "boolValue", true));
        arrayList.add(param(1610613744, "dateTime", 1704067200000L));
        arrayList.add(param(1610613745, "dateTime", 1893456000000L));
        if (z) {
            arrayList.add(param(-1879047484, "blob", nonce()));
        }
        return arrayList;
    }

    Object rawGen(String str, List<Object> list, int i) throws Exception {
        Object newInstance = Array.newInstance(this.pc, list.size());
        for (int i2 = 0; i2 < list.size(); i2++) {
            Array.set(newInstance, i2, list.get(i2));
        }
        Class<?> cls = Class.forName("android.system.keystore2.IKeystoreSecurityLevel");
        Class<?> cls2 = this.dc;
        return cls.getMethod("generateKey", cls2, cls2, newInstance.getClass(), Integer.TYPE, byte[].class).invoke(this.level, descriptor(str), null, newInstance, Integer.valueOf(i), new byte[0]);
    }

    Object getMeta(String str) throws Exception {
        return field(Class.forName("android.system.keystore2.IKeystoreService").getMethod("getKeyEntry", this.dc).invoke(this.svc, descriptor(str)), "metadata");
    }

    JSONObject meta(Object obj) throws Exception {
        Object obj2;
        JSONObject jSONObject = new JSONObject();
        Object field = field(obj, "key");
        jSONObject.put("keyDomain", field(field, "domain")).put("keyId", field(field, "nspace")).put("mtime", field(obj, "modificationTimeMs")).put("certificateSha256", sha((byte[]) field(obj, "certificate"))).put("certificateDer", b64((byte[]) field(obj, "certificate")));
        Object field2 = field(obj, "authorizations");
        JSONArray jSONArray = new JSONArray();
        if (field2 != null) {
            for (int i = 0; i < Array.getLength(field2); i++) {
                Object obj3 = Array.get(field2, i);
                Object field3 = field(obj3, "keyParameter");
                Object field4 = field(field3, "value");
                Class[] clsArr = new Class[0];
                int intValue = ((Integer) field4.getClass().getMethod("getTag", null).invoke(field4, null)).intValue();
                String[] strArr = {"getInvalid", "getAlgorithm", "getBlockMode", "getPaddingMode", "getDigest", "getEcCurve", "getOrigin", "getKeyPurpose", "getHardwareAuthenticatorType", "getSecurityLevel", "getBoolValue", "getInteger", "getLongInteger", "getDateTime", "getBlob"};
                if (intValue < 0 || intValue >= 15) {
                    obj2 = "unknown";
                } else {
                    Class<?> cls = field4.getClass();
                    String str = strArr[intValue];
                    Class[] clsArr2 = new Class[0];
                    obj2 = cls.getMethod(str, null).invoke(field4, null);
                }
                JSONObject put = new JSONObject().put("tag", field(field3, "tag")).put("level", field(obj3, "securityLevel"));
                if (obj2 instanceof byte[]) {
                    obj2 = b64((byte[]) obj2);
                }
                jSONArray.put(put.put("value", obj2));
            }
        }
        return jSONObject.put("authorizations", jSONArray);
    }

    void setupRaw() throws Exception {
        if (!RawBridge.enableReflection()) {
            throw new IllegalStateException("Non-SDK interface unavailable");
        }
        this.svc = Class.forName("android.system.keystore2.IKeystoreService$Stub").getMethod("asInterface", IBinder.class).invoke(null, (IBinder) Class.forName("android.os.ServiceManager").getMethod("getService", String.class).invoke(null, "android.system.keystore2.IKeystoreService/default"));
        this.level = Class.forName("android.system.keystore2.IKeystoreService").getMethod("getSecurityLevel", Integer.TYPE).invoke(this.svc, 1);
        this.dc = Class.forName("android.system.keystore2.KeyDescriptor");
        this.pc = Class.forName("android.hardware.security.keymint.KeyParameter");
    }
}
