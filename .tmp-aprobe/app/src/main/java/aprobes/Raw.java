package aprobes;

import android.os.IBinder;
import android.os.Parcel;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

/** Raw keystore2 Binder probes.  Requires {@link HiddenApi#exempt()} to run. */
public final class Raw {
    public static final String SERVICE = "android.system.keystore2.IKeystoreService/default";
    public static final String DESCRIPTOR = "android.system.keystore2.IKeystoreService";

    private Raw() {}

    private static IBinder binder() throws Exception {
        Class<?> sm = Class.forName("android.os.ServiceManager");
        Method get = sm.getDeclaredMethod("getService", String.class);
        get.setAccessible(true);
        Object b = get.invoke(null, SERVICE);
        if (!(b instanceof IBinder)) throw new IllegalStateException("keystore2 service not found");
        return (IBinder) b;
    }

    public static Object service() throws Exception {
        IBinder b = binder();
        Class<?> stub = Class.forName("android.system.keystore2.IKeystoreService$Stub");
        Method asInterface = stub.getDeclaredMethod("asInterface", IBinder.class);
        asInterface.setAccessible(true);
        return asInterface.invoke(null, b);
    }

    public static Object descriptor(int domain, long nspace, String alias, byte[] blob) throws Exception {
        Class<?> dc = Class.forName("android.system.keystore2.KeyDescriptor");
        Object d = dc.getDeclaredConstructor().newInstance();
        Field f = dc.getDeclaredField("domain");
        f.setAccessible(true);
        f.set(d, Enum.valueOf((Class<Enum>) Class.forName("android.system.keystore2.Domain"), domainName(domain)));
        set(d, "nspace", nspace);
        set(d, "alias", alias);
        set(d, "blob", blob);
        return d;
    }

    private static String domainName(int domain) {
        switch (domain) {
            case 0: return "APP";
            case 1: return "GRANT";
            case 2: return "SELINUX";
            case 3: return "BLOB";
            case 4: return "KEY_ID";
            default: throw new IllegalArgumentException("domain " + domain);
        }
    }

    private static void set(Object o, String field, Object value) throws Exception {
        Field f = o.getClass().getDeclaredField(field);
        f.setAccessible(true);
        f.set(o, value);
    }

    private static Object get(Object o, String field) throws Exception {
        Field f = o.getClass().getDeclaredField(field);
        f.setAccessible(true);
        return f.get(o);
    }

    public static final class Entry {
        public long keyId = Long.MIN_VALUE;
        public int keyDomain = -1;
        public byte[] cert;
        public byte[] chain;
        public int securityLevel = -1;
        public String error;
    }

    public static Entry entry(int domain, long nspace, String alias) {
        Entry out = new Entry();
        try {
            Object svc = service();
            Object d = descriptor(domain, nspace, alias, null);
            Method m = null;
            for (Method candidate : svc.getClass().getMethods()) {
                if (candidate.getName().equals("getKeyEntry") && candidate.getParameterCount() == 1) {
                    m = candidate;
                    break;
                }
            }
            if (m == null) throw new NoSuchMethodException("getKeyEntry");
            Object resp = m.invoke(svc, d);
            Object metadata = get(resp, "metadata");
            Object key = get(metadata, "key");
            out.keyId = (long) get(key, "nspace");
            Object dom = get(key, "domain");
            out.keyDomain = ((Enum<?>) dom).ordinal();
            out.cert = (byte[]) get(metadata, "certificate");
            out.chain = (byte[]) get(metadata, "certificateChain");
            Object sl = get(metadata, "keySecurityLevel");
            out.securityLevel = ((Enum<?>) sl).ordinal();
        } catch (Throwable t) {
            out.error = t.getClass().getSimpleName() + ": " + t.getMessage();
        }
        return out;
    }

    /** Number of the getKeyEntry transaction in IKeystoreService.Stub. */
    public static int getKeyEntryCode() {
        try {
            Class<?> stub = Class.forName("android.system.keystore2.IKeystoreService$Stub");
            for (Field f : stub.getDeclaredFields()) {
                if (f.getName().contains("getKeyEntry")) return f.getInt(null);
            }
            // IKeystoreService.getKeyEntry is the second AIDL method (code 2).
            return 2;
        } catch (Throwable t) {
            return 2;
        }
    }

    /**
     * Send a raw getKeyEntry frame with an arbitrary typed-object presence marker.
     * Returns the AIDL exception code (0 = accepted), or -999 for a local failure.
     */
    public static native int nativeRawGetEntry(String alias, int marker, boolean wrongToken, boolean trailing);

    public static int rawGetEntry(String alias, int marker, boolean wrongToken) {
        int nativeCode = nativeRawGetEntry(alias, marker, wrongToken, false);
        if (nativeCode > -900) return nativeCode;
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(wrongToken
                    ? "android.security.maintenance.IKeystoreMaintenance" : DESCRIPTOR);
            data.writeInt(marker);
            if (marker != 0) {
                // AIDL structured parcelables are sized: [size][fields], where size
                // includes the 4-byte size word itself (rsbinder::sized_write).
                int sizePos = data.dataPosition();
                data.writeInt(0);
                int start = data.dataPosition();
                data.writeInt(0);       // Domain.APP
                data.writeLong(0);      // nspace
                data.writeString(alias);
                data.writeByteArray(null);
                int end = data.dataPosition();
                data.setDataPosition(sizePos);
                data.writeInt(end - sizePos);
                data.setDataPosition(end);
            }
            int code = getKeyEntryCode();
            if (code < 0) return -998;
            binder().transact(code, data, reply, 0);
            return reply.readInt();
        } catch (Throwable t) {
            android.util.Log.i("AGapProbe", "rawGetEntry failed: " + t, t);
            return -999;
        } finally {
            data.recycle();
            reply.recycle();
        }
    }

    /**
     * Raw frame using the real KeyDescriptor.writeToParcel serializer.  This avoids
     * re-implementing the structured-parcelable field order by hand.
     */
    public static int rawGetEntryTyped(String alias, int marker, boolean wrongToken, boolean trailing) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(wrongToken
                    ? "android.security.maintenance.IKeystoreMaintenance" : DESCRIPTOR);
            data.writeInt(marker);
            if (marker != 0) {
                Object kd = descriptor(0, 0, alias, null);
                Method wp = kd.getClass().getMethod("writeToParcel", Parcel.class, int.class);
                wp.setAccessible(true);
                wp.invoke(kd, data, 0);
            }
            if (trailing) data.writeInt(0x12345678);
            int code = getKeyEntryCode();
            if (code < 0) return -998;
            binder().transact(code, data, reply, 0);
            return reply.readInt();
        } catch (Throwable t) {
            android.util.Log.i("AGapProbe", "rawGetEntryTyped failed: " + t, t);
            return -999;
        } finally {
            data.recycle();
            reply.recycle();
        }
    }

    public static int rawGetEntryNoMarker(String alias) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(DESCRIPTOR);
            data.writeInt(0);       // domain APP
            data.writeLong(0);      // nspace
            data.writeString(alias);
            data.writeByteArray(null);
            binder().transact(getKeyEntryCode(), data, reply, 0);
            return reply.readInt();
        } catch (Throwable t) {
            android.util.Log.i("AGapProbe", "rawGetEntryNoMarker failed: " + t, t);
            return -999;
        } finally {
            data.recycle();
            reply.recycle();
        }
    }

    public static int rawGetEntryTrailing(String alias) {
        int nativeCode = nativeRawGetEntry(alias, 1, false, true);
        if (nativeCode > -900) return nativeCode;
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(DESCRIPTOR);
            data.writeInt(1);
            int sizePos = data.dataPosition();
            data.writeInt(0);
            int start = data.dataPosition();
            data.writeInt(0);
            data.writeLong(0);
            data.writeString(alias);
            data.writeByteArray(null);
            int end = data.dataPosition();
            data.setDataPosition(sizePos);
            data.writeInt(end - sizePos);
            data.setDataPosition(end);
            data.writeInt(0x12345678);
            int code = getKeyEntryCode();
            if (code < 0) return -998;
            binder().transact(code, data, reply, 0);
            return reply.readInt();
        } catch (Throwable t) {
            android.util.Log.i("AGapProbe", "rawGetEntryTrailing failed: " + t, t);
            return -999;
        } finally {
            data.recycle();
            reply.recycle();
        }
    }

    public static String exceptionText(int code) {
        switch (code) {
            case 0: return "OK(0)";
            case -998: return "transaction code unavailable";
            case -999: return "local Binder/Parcel failure";
            default: return "exception=" + code;
        }
    }
}
