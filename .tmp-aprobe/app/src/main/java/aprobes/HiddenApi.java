package aprobes;

import java.lang.reflect.Method;

/** Loads the JNI shim or a Java fallback that exempts hidden APIs. */
public final class HiddenApi {
    private static Boolean loaded;
    private static boolean available;

    private HiddenApi() {}

    public static synchronized void exempt() {
        if (loaded != null) return;
        loaded = Boolean.TRUE;
        try {
            // Load the JNI library for the raw Binder probe, but do not call the
            // VMRuntime exemption native method: on Android 17 the method shape is
            // vendor/version dependent and a bad JNI method id aborts the process.
            System.loadLibrary("hiddenapi");
            android.util.Log.i("AGapProbe", "hiddenapi raw library loaded");
        } catch (Throwable t) {
            android.util.Log.i("AGapProbe", "hiddenapi load failed: " + t);
        }
        available = false;
        if (!available) {
            try {
                Class<?> vm = Class.forName("dalvik.system.VMRuntime");
                Method get = vm.getDeclaredMethod("getRuntime");
                get.setAccessible(true);
                Object runtime = get.invoke(null);
                Method set = vm.getDeclaredMethod("setHiddenApiExemptions", String[].class);
                set.setAccessible(true);
                set.invoke(runtime, (Object) new String[]{"L"});
                available = true;
                android.util.Log.i("AGapProbe", "hiddenapi java fallback ok");
            } catch (Throwable t) {
                android.util.Log.i("AGapProbe", "hiddenapi java fallback failed: " + t);
                available = false;
            }
        }
    }

    public static boolean available() {
        return available;
    }

    private static native boolean exemptNative();
}
