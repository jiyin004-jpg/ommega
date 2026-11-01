package io.github.a13e300.unifiedaudit;

import android.content.Context;
import android.os.Build;
import android.os.IInterface;
import android.os.Parcel;
import android.os.Parcelable;
import android.os.Process;
import io.github.a13e300.unifiedaudit.ProbeBase;
import java.io.ByteArrayInputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import org.json.JSONArray;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class ParcelChecks extends ProbeBase {
    final Sink sink;

    interface Sink {
        void emit(JSONObject jSONObject);
    }

    ParcelChecks(Context context, Sink sink) {
        super(context);
        this.sink = sink;
    }

    @Override // io.github.a13e300.unifiedaudit.ProbeBase
    void emit(JSONObject jSONObject) {
        this.sink.emit(jSONObject);
    }

    int code(String str, String str2) throws Exception {
        Class<?> cls = Class.forName("android.system.keystore2." + str + "$Stub");
        StringBuilder sb = new StringBuilder("TRANSACTION_");
        sb.append(str2);
        Field declaredField = cls.getDeclaredField(sb.toString());
        declaredField.setAccessible(true);
        return declaredField.getInt(null);
    }

    Object readTyped(Parcel parcel, String str) throws Exception {
        return parcel.readTypedObject((Parcelable.Creator) Class.forName("android.system.keystore2." + str).getField("CREATOR").get(null));
    }

    void writeDescriptor(Parcel parcel, Object obj, int i, String str) throws Exception {
        parcel.writeInt(i);
        int dataPosition = parcel.dataPosition();
        parcel.writeInt(0);
        parcel.writeInt(((Integer) field(obj, "domain")).intValue());
        parcel.writeLong(((Long) field(obj, "nspace")).longValue());
        parcel.writeString((String) field(obj, "alias"));
        if (!str.equals("omit_blob")) {
            parcel.writeByteArray((byte[]) field(obj, "blob"));
        }
        if (str.equals("extension")) {
            parcel.writeInt(324478056);
            parcel.writeInt(610800471);
        }
        int dataPosition2 = parcel.dataPosition();
        parcel.setDataPosition(dataPosition);
        parcel.writeInt(dataPosition2 - dataPosition);
        parcel.setDataPosition(dataPosition2);
    }

    JSONObject lookup(Object obj, int i, String str, byte[] bArr) throws Exception {
        Parcel obtain = Parcel.obtain();
        Parcel obtain2 = Parcel.obtain();
        JSONObject put = new JSONObject().put("presence", i).put("mode", str);
        try {
            obtain.writeInterfaceToken("android.system.keystore2.IKeystoreService");
            writeDescriptor(obtain, obj, i, str);
            if (str.equals("trailing")) {
                obtain.writeInt(324478056);
            }
            put.put("request", b64(obtain.marshall())).put("transacted", ((IInterface) this.svc).asBinder().transact(code("IKeystoreService", "getKeyEntry"), obtain, obtain2, 0));
            obtain2.readException();
            Object readTyped = readTyped(obtain2, "KeyEntryResponse");
            Object field = field(readTyped, "metadata");
            boolean z = true;
            JSONObject put2 = put.put("accepted", true).put("metadata", meta(field)).put("certificateChain", b64((byte[]) field(field, "certificateChain"))).put("chainSha256", sha((byte[]) field(field, "certificateChain")));
            if (field(readTyped, "iSecurityLevel") == null) {
                z = false;
            }
            put2.put("hasSecurityLevel", z).put("matches", Arrays.equals(bArr, (byte[]) field(field, "certificate"))).put("remaining", obtain2.dataAvail());
        } finally {
            try {
                return put;
            } finally {
            }
        }
        return put;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* renamed from: readMatrix, reason: merged with bridge method [inline-methods] */
    public void m40lambda$run$3$iogithuba13e300unifiedauditParcelChecks(JSONObject jSONObject) throws Exception {
        String str;
        Object descriptor;
        String alias = alias("parcel");
        int i = 1;
        Object rawGen = rawGen(alias, base(true), 0);
        byte[] bArr = (byte[]) field(rawGen, "certificate");
        jSONObject.put("metadata", meta(rawGen)).put("chain", chain(alias));
        JSONArray jSONArray = new JSONArray();
        String[] strArr = {"alias", "keyid", "missing"};
        int i2 = 0;
        while (i2 < 3) {
            String str2 = strArr[i2];
            if (str2.equals("keyid")) {
                descriptor = field(rawGen, "key");
            } else {
                if (str2.equals("missing")) {
                    str = this.prefix + "not_created";
                } else {
                    str = alias;
                }
                descriptor = descriptor(str);
            }
            Object obj = rawGen;
            int[] iArr = {i, 2, -1, Integer.MAX_VALUE, i};
            int i3 = 0;
            while (i3 < 5) {
                jSONArray.put(lookup(descriptor, iArr[i3], "standard", bArr).put("kind", str2));
                i3++;
                iArr = iArr;
            }
            String[] strArr2 = {"omit_blob", "extension", "trailing"};
            int i4 = 0;
            while (i4 < 3) {
                jSONArray.put(lookup(descriptor, 1, strArr2[i4], bArr).put("kind", str2));
                i4++;
                strArr2 = strArr2;
            }
            i = 1;
            i2++;
            rawGen = obj;
        }
        jSONObject.put("requests", jSONArray).put("readbackUnchanged", Arrays.equals(bArr, (byte[]) field(getMeta(alias), "certificate")));
    }

    JSONObject rawSign(Object obj, int i, byte[] bArr) throws Exception {
        Object obj2;
        Method method;
        JSONObject put = new JSONObject().put("presence", i);
        Parcel obtain = Parcel.obtain();
        Parcel obtain2 = Parcel.obtain();
        try {
            try {
                obtain.writeInterfaceToken("android.system.keystore2.IKeystoreSecurityLevel");
                writeDescriptor(obtain, obj, i, "standard");
                obtain.writeInt(2);
                obtain.writeTypedObject((Parcelable) param(536870913, "keyPurpose", 2), 0);
                obtain.writeTypedObject((Parcelable) param(536870917, "digest", 4), 0);
                obtain.writeInt(0);
                put.put("transacted", ((IInterface) this.level).asBinder().transact(code("IKeystoreSecurityLevel", "createOperation"), obtain, obtain2, 0));
                obtain2.readException();
                obj2 = field(readTyped(obtain2, "CreateOperationResponse"), "iOperation");
            } catch (Throwable th) {
                th = th;
                obj2 = null;
            }
        } catch (Throwable unused) {
        }
        try {
            byte[] nonce = nonce();
            byte[] bArr2 = (byte[]) Class.forName("android.system.keystore2.IKeystoreOperation").getMethod("finish", byte[].class, byte[].class).invoke(obj2, nonce, null);
            X509Certificate x509Certificate = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(bArr));
            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initVerify(x509Certificate);
            signature.update(nonce);
            put.put("accepted", true).put("valid", signature.verify(bArr2)).put("message", b64(nonce)).put("signature", b64(bArr2)).put("certificateDer", b64(bArr));
        } catch (Throwable th2) {
            th = th2;
            try {
                put.put("accepted", false).put("code", serviceCode(th)).put("error", error(th));
                if (obj2 != null) {
                    Class[] clsArr = new Class[0];
                    method = Class.forName("android.system.keystore2.IKeystoreOperation").getMethod("abort", null);
                    method.invoke(obj2, null);
                }
                obtain.recycle();
                obtain2.recycle();
                return put;
            } catch (Throwable th3) {
                if (obj2 != null) {
                    try {
                        Class[] clsArr2 = new Class[0];
                        Class.forName("android.system.keystore2.IKeystoreOperation").getMethod("abort", null).invoke(obj2, null);
                    } catch (Throwable unused2) {
                    }
                }
                obtain.recycle();
                obtain2.recycle();
                throw th3;
            }
        }
        if (obj2 != null) {
            Class[] clsArr3 = new Class[0];
            method = Class.forName("android.system.keystore2.IKeystoreOperation").getMethod("abort", null);
            method.invoke(obj2, null);
        }
        obtain.recycle();
        obtain2.recycle();
        return put;
    }

    JSONObject rawDelete(String str, int i) throws Exception {
        Parcel obtain = Parcel.obtain();
        Parcel obtain2 = Parcel.obtain();
        JSONObject put = new JSONObject().put("presence", i);
        try {
            obtain.writeInterfaceToken("android.system.keystore2.IKeystoreService");
            writeDescriptor(obtain, descriptor(str), i, "standard");
            put.put("transacted", ((IInterface) this.svc).asBinder().transact(code("IKeystoreService", "deleteKey"), obtain, obtain2, 0));
            obtain2.readException();
            put.put("accepted", true);
        } finally {
            try {
                return put;
            } finally {
            }
        }
        return put;
    }

    JSONObject rawCertificate(String str, int i, byte[] bArr) throws Exception {
        Parcel obtain = Parcel.obtain();
        Parcel obtain2 = Parcel.obtain();
        JSONObject put = new JSONObject().put("presence", i);
        try {
            obtain.writeInterfaceToken("android.system.keystore2.IKeystoreService");
            writeDescriptor(obtain, descriptor(str), i, "standard");
            obtain.writeByteArray(null);
            obtain.writeByteArray(bArr);
            put.put("request", b64(obtain.marshall())).put("transacted", ((IInterface) this.svc).asBinder().transact(code("IKeystoreService", "updateSubcomponent"), obtain, obtain2, 0));
            obtain2.readException();
            put.put("accepted", true).put("remaining", obtain2.dataAvail());
        } finally {
            try {
                return put;
            } finally {
            }
        }
        return put;
    }

    boolean found(JSONObject jSONObject) {
        return jSONObject.optBoolean("accepted") && jSONObject.optBoolean("matches") && jSONObject.optInt("remaining", -1) == 0;
    }

    boolean absent(JSONObject jSONObject) {
        return !jSONObject.optBoolean("accepted") && jSONObject.optInt("code", -1) == 7;
    }

    boolean signed(JSONObject jSONObject) {
        return jSONObject.optBoolean("accepted") && jSONObject.optBoolean("valid");
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* JADX WARN: Removed duplicated region for block: B:64:0x0207  */
    /* JADX WARN: Removed duplicated region for block: B:68:0x020e  */
    /* renamed from: certificateViews, reason: merged with bridge method [inline-methods] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void m41lambda$run$4$iogithuba13e300unifiedauditParcelChecks(org.json.JSONObject r21) throws java.lang.Exception {
        /*
            Method dump skipped, instructions count: 552
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: io.github.a13e300.unifiedaudit.ParcelChecks.m41lambda$run$4$iogithuba13e300unifiedauditParcelChecks(org.json.JSONObject):void");
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* renamed from: control, reason: merged with bridge method [inline-methods] and merged with bridge method [inline-methods] */
    public void m42lambda$run$5$iogithuba13e300unifiedauditParcelChecks(JSONObject jSONObject) throws Exception {
        String alias = alias("control");
        Object rawGen = rawGen(alias, base(true), 0);
        byte[] bArr = (byte[]) field(rawGen, "certificate");
        jSONObject.put("metadata", meta(rawGen)).put("chain", chain(alias)).put("readback", lookup(descriptor(alias), 1, "standard", bArr)).put("operation", rawSign(field(rawGen, "key"), 1, bArr));
    }

    /* renamed from: lambda$run$0$io-github-a13e300-unifiedaudit-ParcelChecks, reason: not valid java name */
    /* synthetic */ void m37lambda$run$0$iogithuba13e300unifiedauditParcelChecks(JSONObject jSONObject) throws Exception {
        jSONObject.put("uid", Process.myUid()).put("pid", Process.myPid()).put("package", getTargetContext().getPackageName()).put("sdk", Build.VERSION.SDK_INT).put("targetSdk", getTargetContext().getApplicationInfo().targetSdkVersion).put("context", new String(Files.readAllBytes(Paths.get("/proc/self/attr/current", new String[0]))).trim()).put("status", new String(Files.readAllBytes(Paths.get("/proc/self/status", new String[0]))));
        JSONObject jSONObject2 = new JSONObject();
        String[] strArr = {"android.permission.DUMP", "android.permission.READ_PRIVILEGED_PHONE_STATE", "android.permission.MANAGE_USERS", "android.permission.GRANT_RUNTIME_PERMISSIONS"};
        for (int i = 0; i < 4; i++) {
            String str = strArr[i];
            jSONObject2.put(str, getTargetContext().checkSelfPermission(str));
        }
        jSONObject.put("permissions", jSONObject2);
    }

    public void run() {
        ProbeBase.Action action;
        try {
            this.store = KeyStore.getInstance("AndroidKeyStore");
            this.store.load(null);
            test("identity", new ProbeBase.Action() { // from class: io.github.a13e300.unifiedaudit.ParcelChecks.0
                @Override // io.github.a13e300.unifiedaudit.ProbeBase.Action
                public final void run(JSONObject jSONObject) {
                    ParcelChecks.this.m37lambda$run$0$iogithuba13e300unifiedauditParcelChecks(jSONObject);
                }
            });
            test("setup", new ProbeBase.Action() { // from class: io.github.a13e300.unifiedaudit.ParcelChecks.1
                @Override // io.github.a13e300.unifiedaudit.ProbeBase.Action
                public final void run(JSONObject jSONObject) {
                    ParcelChecks.this.m38lambda$run$1$iogithuba13e300unifiedauditParcelChecks(jSONObject);
                }
            });
            test("control_before", new ProbeBase.Action() { // from class: io.github.a13e300.unifiedaudit.ParcelChecks.2
                @Override // io.github.a13e300.unifiedaudit.ProbeBase.Action
                public final void run(JSONObject jSONObject) {
                    ParcelChecks.this.m39lambda$run$2$iogithuba13e300unifiedauditParcelChecks(jSONObject);
                }
            });
            test("read_equivalence", new ProbeBase.Action() { // from class: io.github.a13e300.unifiedaudit.ParcelChecks.3
                @Override // io.github.a13e300.unifiedaudit.ProbeBase.Action
                public final void run(JSONObject jSONObject) {
                    ParcelChecks.this.m40lambda$run$3$iogithuba13e300unifiedauditParcelChecks(jSONObject);
                }
            });
            test("certificate_views", new ProbeBase.Action() { // from class: io.github.a13e300.unifiedaudit.ParcelChecks.4
                @Override // io.github.a13e300.unifiedaudit.ProbeBase.Action
                public final void run(JSONObject jSONObject) {
                    ParcelChecks.this.m41lambda$run$4$iogithuba13e300unifiedauditParcelChecks(jSONObject);
                }
            });
            test("control_after", new ProbeBase.Action() { // from class: io.github.a13e300.unifiedaudit.ParcelChecks.5
                @Override // io.github.a13e300.unifiedaudit.ProbeBase.Action
                public final void run(JSONObject jSONObject) {
                    ParcelChecks.this.m42lambda$run$5$iogithuba13e300unifiedauditParcelChecks(jSONObject);
                }
            });
            action = new ProbeBase.Action() { // from class: io.github.a13e300.unifiedaudit.ParcelChecks.6
                @Override // io.github.a13e300.unifiedaudit.ProbeBase.Action
                public final void run(JSONObject jSONObject) {
                    ParcelChecks.this.m43lambda$run$7$iogithuba13e300unifiedauditParcelChecks(jSONObject);
                }
            };
        } catch (Throwable th) {
            try {
                test("fatal", new ProbeBase.Action() { // from class: io.github.a13e300.unifiedaudit.ParcelChecks.7
                    @Override // io.github.a13e300.unifiedaudit.ProbeBase.Action
                    public final void run(JSONObject jSONObject) {
                        ParcelChecks.lambda$run$6(th, jSONObject);
                    }
                });
                action = new ProbeBase.Action() { // from class: io.github.a13e300.unifiedaudit.ParcelChecks.6
                    @Override // io.github.a13e300.unifiedaudit.ProbeBase.Action
                    public final void run(JSONObject jSONObject) {
                        ParcelChecks.this.m43lambda$run$7$iogithuba13e300unifiedauditParcelChecks(jSONObject);
                    }
                };
            } catch (Throwable th2) {
                test("cleanup", new ProbeBase.Action() { // from class: io.github.a13e300.unifiedaudit.ParcelChecks.6
                    @Override // io.github.a13e300.unifiedaudit.ProbeBase.Action
                    public final void run(JSONObject jSONObject) {
                        ParcelChecks.this.m43lambda$run$7$iogithuba13e300unifiedauditParcelChecks(jSONObject);
                    }
                });
                throw th2;
            }
        }
        test("cleanup", action);
    }

    /* renamed from: lambda$run$1$io-github-a13e300-unifiedaudit-ParcelChecks, reason: not valid java name */
    /* synthetic */ void m38lambda$run$1$iogithuba13e300unifiedauditParcelChecks(JSONObject jSONObject) throws Exception {
        setupRaw();
        jSONObject.put("ready", true).put("getKeyEntryCode", code("IKeystoreService", "getKeyEntry"));
    }

    static /* synthetic */ void lambda$run$6(Throwable th, JSONObject jSONObject) throws Exception {
        throw new Exception(error(th));
    }

    /* renamed from: lambda$run$7$io-github-a13e300-unifiedaudit-ParcelChecks, reason: not valid java name */
    /* synthetic */ void m43lambda$run$7$iogithuba13e300unifiedauditParcelChecks(JSONObject jSONObject) throws Exception {
        JSONArray jSONArray = new JSONArray();
        for (String str : this.aliases) {
            JSONObject put = new JSONObject().put("alias", str);
            try {
                put.put("alternateDelete", rawDelete(str, 2));
                this.store.deleteEntry(str);
                boolean z = true;
                JSONObject lookup = lookup(descriptor(str), 1, "standard", null);
                JSONObject lookup2 = lookup(descriptor(str), 2, "standard", null);
                put.put("canonical", lookup).put("alternate", lookup2);
                if (lookup.optBoolean("accepted") || lookup.optInt("code") != 7 || lookup2.optBoolean("accepted") || lookup2.optInt("code") != 7) {
                    z = false;
                }
                put.put("absent", z);
            } catch (Throwable th) {
                put.put("error", error(th));
            }
            jSONArray.put(put);
        }
        jSONObject.put("keys", jSONArray);
    }
}
