package aprobes;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.concurrent.TimeUnit;

/** Read-only root helper.  Never writes, never uses broad kill/restart commands. */
public final class Root {
    private static Boolean available;

    private Root() {}

    public static synchronized boolean available() {
        if (available != null) return available;
        String out = exec("id -u", 2000);
        available = out != null && out.trim().equals("0");
        return available;
    }

    public static String exec(String command, int timeoutMs) {
        Process p = null;
        try {
            p = new ProcessBuilder("su", "-c", command).redirectErrorStream(true).start();
            StringBuilder sb = new StringBuilder();
            try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                String line;
                while ((line = r.readLine()) != null) {
                    if (sb.length() < 200_000) sb.append(line).append('\n');
                }
            }
            if (!p.waitFor(timeoutMs, TimeUnit.MILLISECONDS)) {
                p.destroy();
                return null;
            }
            return sb.toString();
        } catch (Throwable t) {
            if (p != null) p.destroy();
            return null;
        }
    }

    public static String cat(String path) {
        return exec("cat '" + path.replace("'", "'\\''") + "' 2>/dev/null", 4000);
    }

    public static boolean exists(String path) {
        String out = exec("test -e '" + path.replace("'", "'\\''") + "' && echo yes || echo no", 3000);
        return out != null && out.trim().equals("yes");
    }

    public static String prop(String name) {
        String out = exec("getprop '" + name.replace("'", "'\\''") + "'", 2000);
        return out == null ? null : out.trim();
    }
}
