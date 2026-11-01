package aprobes;

import java.lang.reflect.Method;

/** Hidden SystemProperties access, with a safe fallback. */
public final class Sys {
    private static Method get;

    private Sys() {}

    public static String get(String name, String dflt) {
        try {
            if (get == null) {
                Class<?> c = Class.forName("android.os.SystemProperties");
                get = c.getMethod("get", String.class, String.class);
            }
            Object v = get.invoke(null, name, dflt);
            return v == null ? dflt : String.valueOf(v);
        } catch (Throwable t) {
            return dflt;
        }
    }

    public static int getInt(String name, int dflt) {
        try { return Integer.parseInt(get(name, String.valueOf(dflt)).trim()); }
        catch (Throwable t) { return dflt; }
    }

    public static boolean getBool(String name, boolean dflt) {
        String v = get(name, dflt ? "1" : "0").trim();
        return "1".equals(v) || "true".equalsIgnoreCase(v) || "yes".equalsIgnoreCase(v);
    }

    public static String readFile(String path) {
        try (java.io.BufferedReader r = new java.io.BufferedReader(new java.io.FileReader(path))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = r.readLine()) != null) {
                if (sb.length() > 200_000) break;
                sb.append(line).append('\n');
            }
            return sb.toString();
        } catch (Throwable t) {
            if (Root.available()) return Root.cat(path);
            return null;
        }
    }

    public static String cmdlineValue(String key) {
        String cmdline = readFile("/proc/cmdline");
        if (cmdline == null) return null;
        for (String tok : cmdline.trim().split("\\s+")) {
            int eq = tok.indexOf('=');
            if (eq > 0 && tok.substring(0, eq).equals(key)) return tok.substring(eq + 1);
        }
        return null;
    }

    public static String bootconfigValue(String key) {
        String s = readFile("/proc/bootconfig");
        if (s == null) return null;
        for (String line : s.split("\n")) {
            line = line.trim();
            int eq = line.indexOf('=');
            if (eq > 0 && line.substring(0, eq).trim().equals(key)) {
                String v = line.substring(eq + 1).trim();
                if (v.startsWith("\"") && v.endsWith("\"") && v.length() >= 2) v = v.substring(1, v.length() - 1);
                return v;
            }
        }
        return null;
    }
}
