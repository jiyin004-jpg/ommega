package io.github.a13e300.unifiedaudit;

import android.os.IBinder;
import io.github.a13e300.unifiedaudit.Probes;
import java.lang.reflect.Array;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/* loaded from: classes.dex */
public final class RawBridge {
    static final int ACTIVE_DATETIME = 1610613136;
    static final int ALGORITHM = 268435458;
    static final int APPLICATION_DATA = -1879047492;
    static final int APPLICATION_ID = -1879047591;
    static final int BOOT_PATCHLEVEL = 805307087;
    static final int CALLER_NONCE = 1879048199;
    static final int CHALLENGE = -1879047484;
    static final int DIGEST = 536870917;
    static final int EARLY_BOOT_ONLY = 1879048497;
    static final int EC_CURVE = 268435466;
    static final int INCLUDE_UNIQUE_ID = 1879048394;
    static final int KEY_SIZE = 805306371;
    static final int MAX_USES_PER_BOOT = 805306772;
    static final int MIN_SECONDS_BETWEEN_OPS = 805306771;
    static final int NOT_AFTER = 1610613745;
    static final int NOT_BEFORE = 1610613744;
    static final int NO_AUTH = 1879048695;
    static final int ORIGINATION_EXPIRE_DATETIME = 1610613137;
    static final int PADDING = 536870918;
    static final int PURPOSE = 536870913;
    static final int ROLLBACK_RESISTANCE = 1879048495;
    static final int RSA_EXPONENT = 1342177480;
    static final int SERIAL = -2147482642;
    static final int SUBJECT = -1879047185;
    static final int UNLOCKED_DEVICE_REQUIRED = 1879048701;
    static final int USAGE_COUNT = 805306773;
    static final int USAGE_EXPIRE_DATETIME = 1610613138;
    static final int USER_AUTH_TYPE = 536871416;
    static final int VENDOR_PATCHLEVEL = 805307086;
    private static boolean reflectionReady;
    final Class<?> descriptorClass;
    final Object level;
    final Class<?> parameterClass;
    final Object service;
    final Class<?> valueClass;

    private static native boolean enableReflectionNative();

    static {
        System.loadLibrary("modeaudit");
    }

    public static synchronized boolean enableReflection() {
        boolean z;
        synchronized (RawBridge.class) {
            if (!reflectionReady) {
                reflectionReady = enableReflectionNative();
            }
            z = reflectionReady;
        }
        return z;
    }

    public RawBridge() throws Exception {
        if (!enableReflection()) {
            throw new IllegalStateException("Non-SDK reflection unavailable");
        }
        IBinder iBinder = (IBinder) Class.forName("android.os.ServiceManager").getMethod("getService", String.class).invoke(null, "android.system.keystore2.IKeystoreService/default");
        if (iBinder == null) {
            throw new IllegalStateException("Keystore2 unavailable to this UID");
        }
        this.descriptorClass = Class.forName("android.system.keystore2.KeyDescriptor");
        this.parameterClass = Class.forName("android.hardware.security.keymint.KeyParameter");
        this.valueClass = Class.forName("android.hardware.security.keymint.KeyParameterValue");
        Object invoke = Class.forName("android.system.keystore2.IKeystoreService$Stub").getMethod("asInterface", IBinder.class).invoke(null, iBinder);
        this.service = invoke;
        this.level = invoke(invoke, "getSecurityLevel", 1);
    }

    static Object field(Object obj, String str) throws Exception {
        return obj.getClass().getField(str).get(obj);
    }

    static void set(Object obj, String str, Object obj2) throws Exception {
        obj.getClass().getField(str).set(obj, obj2);
    }

    static Object invoke(Object obj, String str, Object... objArr) throws Exception {
        Method method = null;
        int i = -1;
        for (Method method2 : obj.getClass().getMethods()) {
            if (method2.getName().equals(str) && method2.getParameterCount() == objArr.length) {
                Class<?>[] parameterTypes = method2.getParameterTypes();
                int i2 = 0;
                int i3 = 0;
                while (true) {
                    if (i2 < parameterTypes.length) {
                        Object obj2 = objArr[i2];
                        if (obj2 == null) {
                            if (parameterTypes[i2].isPrimitive()) {
                                break;
                            }
                            i2++;
                        } else if (compatible(parameterTypes[i2], obj2.getClass())) {
                            i3++;
                            i2++;
                        }
                    } else if (i3 > i) {
                        method = method2;
                        i = i3;
                    }
                }
            }
        }
        if (method == null) {
            throw new Probes.Skip("Keystore2 interface changed: " + str);
        }
        method.setAccessible(true);
        try {
            return method.invoke(obj, objArr);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof Exception) {
                throw ((Exception) cause);
            }
            throw new RuntimeException(cause);
        }
    }

    static boolean compatible(Class<?> cls, Class<?> cls2) {
        if (cls.isAssignableFrom(cls2)) {
            return true;
        }
        return (cls == Integer.TYPE && cls2 == Integer.class) || (cls == Long.TYPE && cls2 == Long.class) || ((cls == Boolean.TYPE && cls2 == Boolean.class) || (cls == Byte.TYPE && cls2 == Byte.class));
    }

    Object descriptor(int i, long j, String str) throws Exception {
        Class[] clsArr = new Class[0];
        Object newInstance = this.descriptorClass.getConstructor(null).newInstance(null);
        set(newInstance, "domain", Integer.valueOf(i));
        set(newInstance, "nspace", Long.valueOf(j));
        set(newInstance, "alias", str);
        return newInstance;
    }

    Object app(String str) throws Exception {
        return descriptor(0, -1L, str);
    }

    Object entry(String str) throws Exception {
        return invoke(this.service, "getKeyEntry", app(str));
    }

    Object entry(Object obj) throws Exception {
        return invoke(this.service, "getKeyEntry", obj);
    }

    Object metadata(String str) throws Exception {
        return field(entry(str), "metadata");
    }

    Object keyId(String str) throws Exception {
        return field(metadata(str), "key");
    }

    Object param(int i, String str, Object obj) throws Exception {
        Class[] clsArr = new Class[0];
        Object newInstance = this.parameterClass.getConstructor(null).newInstance(null);
        set(newInstance, "tag", Integer.valueOf(i));
        for (Method method : this.valueClass.getMethods()) {
            if (method.getName().equals(str) && Modifier.isStatic(method.getModifiers()) && method.getParameterCount() == 1) {
                set(newInstance, "value", method.invoke(null, obj));
                return newInstance;
            }
        }
        throw new NoSuchMethodException("KeyParameterValue." + str);
    }

    Object params(List<Object> list) {
        Object newInstance = Array.newInstance(this.parameterClass, list.size());
        for (int i = 0; i < list.size(); i++) {
            Array.set(newInstance, i, list.get(i));
        }
        return newInstance;
    }

    Object generate(String str, Object obj, List<Object> list) throws Exception {
        return invoke(this.level, "generateKey", app(str), obj, params(list), 0, new byte[32]);
    }

    Object importKey(String str, Object obj, List<Object> list, byte[] bArr) throws Exception {
        return invoke(this.level, "importKey", app(str), obj, params(list), 0, bArr);
    }

    Object begin(String str, List<Object> list) throws Exception {
        return beginDescriptor(keyId(str), list);
    }

    Object beginDescriptor(Object obj, List<Object> list) throws Exception {
        return field(invoke(this.level, "createOperation", obj, params(list), false), "iOperation");
    }

    byte[] finish(Object obj, byte[] bArr) throws Exception {
        return (byte[]) invoke(obj, "finish", bArr, null);
    }

    Object beginResponse(String str, List<Object> list) throws Exception {
        return invoke(this.level, "createOperation", keyId(str), params(list), false);
    }

    void abort(Object obj) {
        try {
            invoke(obj, "abort", new Object[0]);
        } catch (Exception unused) {
        }
    }

    void update(Object obj, byte[] bArr, byte[] bArr2) throws Exception {
        invoke(this.service, "updateSubcomponent", obj, bArr, bArr2);
    }

    void delete(String str) throws Exception {
        invoke(this.service, "deleteKey", app(str));
    }

    static Integer errorCode(Throwable th) {
        while (th != null) {
            try {
                try {
                    return Integer.valueOf(th.getClass().getField("errorCode").getInt(th));
                } catch (Exception unused) {
                    th = th.getCause();
                }
            } catch (Exception unused2) {
                Class[] clsArr = new Class[0];
                return (Integer) th.getClass().getMethod("getErrorCode", null).invoke(th, null);
            }
        }
        return null;
    }

    List<Object> ec(byte[] bArr, int i) throws Exception {
        ArrayList arrayList = new ArrayList();
        arrayList.add(param(ALGORITHM, "algorithm", 3));
        arrayList.add(param(EC_CURVE, "ecCurve", 1));
        arrayList.add(param(KEY_SIZE, "integer", 256));
        arrayList.add(param(PURPOSE, "keyPurpose", Integer.valueOf(i)));
        arrayList.add(param(DIGEST, "digest", 4));
        arrayList.add(param(NO_AUTH, "boolValue", true));
        arrayList.add(param(NOT_BEFORE, "dateTime", 0L));
        arrayList.add(param(NOT_AFTER, "dateTime", 2461449600000L));
        if (bArr != null) {
            arrayList.add(param(CHALLENGE, "blob", bArr));
        }
        return arrayList;
    }

    List<Object> signing() throws Exception {
        return Arrays.asList(param(PURPOSE, "keyPurpose", 2), param(DIGEST, "digest", 4));
    }
}
