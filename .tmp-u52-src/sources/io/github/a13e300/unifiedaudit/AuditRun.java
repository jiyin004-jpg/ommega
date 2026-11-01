package io.github.a13e300.unifiedaudit;

import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.Process;
import android.os.SystemClock;
import android.util.Log;
import java.io.File;
import java.io.FileOutputStream;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;
import java.util.function.BiFunction;
import org.json.JSONArray;
import org.json.JSONObject;

/* loaded from: classes.dex */
final class AuditRun {
    static volatile boolean debugLog;
    private final Map<String, Long> active;
    private String cached;
    private boolean closed;
    final Context context;
    private final Map<String, Long> durations;
    private long firstResultMs;
    private int groupsRunning;
    private long lastPersisted;
    private long lastProgress;
    private final Listener listener;
    private int peakGroups;
    final JSONObject report;
    private final long started;
    private final Map<String, String> states;

    interface Listener {
        void snapshot(String str);
    }

    AuditRun(Context context) throws Exception {
        this(context, null);
    }

    AuditRun(Context context, Listener listener) throws Exception {
        JSONObject jSONObject = new JSONObject();
        this.report = jSONObject;
        this.states = new LinkedHashMap();
        this.active = new HashMap();
        this.durations = new TreeMap();
        long elapsedRealtime = SystemClock.elapsedRealtime();
        this.started = elapsedRealtime;
        this.lastProgress = elapsedRealtime;
        this.firstResultMs = -1L;
        this.context = context;
        this.listener = listener;
        jSONObject.put("schema", 2).put("runId", UUID.randomUUID().toString()).put("package", context.getPackageName()).put("uid", Process.myUid()).put("sdk", Build.VERSION.SDK_INT).put("targetSdk", context.getApplicationInfo().targetSdkVersion).put("status", "RUNNING").put("parallelism", 4).put("phase", "PREPARE");
        save();
    }

    Intent getIntent() {
        return new Intent();
    }

    File getExternalFilesDir(String str) {
        return this.context.getFilesDir();
    }

    synchronized void beginGroup() {
        int i = this.groupsRunning + 1;
        this.groupsRunning = i;
        this.peakGroups = Math.max(this.peakGroups, i);
    }

    synchronized void endGroup() {
        this.groupsRunning--;
    }

    synchronized void phase(String str) throws Exception {
        this.report.put("phase", str);
        save();
    }

    synchronized void before(String str) {
        if (this.closed) {
            throw new IllegalStateException("Closed run");
        }
        CheckCatalog.index(str);
        if (this.active.put(str, Long.valueOf(SystemClock.elapsedRealtime())) != null) {
            throw new IllegalStateException("Duplicate running check");
        }
    }

    synchronized void add(String str, String str2, String str3, String str4) {
        if (this.closed) {
            return;
        }
        CheckCatalog.index(str);
        if (this.states.containsKey(str)) {
            throw new IllegalStateException("Duplicate completed check");
        }
        long elapsedRealtime = SystemClock.elapsedRealtime();
        Long remove = this.active.remove(str);
        this.durations.put(OutcomePolicy.label(CheckCatalog.index(str)), Long.valueOf(remove == null ? 0L : elapsedRealtime - remove.longValue()));
        this.states.put(str, str3);
        this.lastProgress = elapsedRealtime;
        if (this.firstResultMs < 0) {
            this.firstResultMs = elapsedRealtime - this.started;
        }
        if (debugLog) {
            try {
                Log.i("U52AUDIT", str + "|" + str3 + "|" + (str4 == null ? "" : str4));
            } catch (Throwable unused) {
            }
        }
        appendDiagnostic(str, str3, str4);
        try {
            save();
        } catch (Exception e) {
            throw new IllegalStateException("Result write failed", e);
        }
    }

    private void appendDiagnostic(String str, String str2, String str3) {
        try {
            if (new File(this.context.getFilesDir(), "debug-on").exists()) {
                String str4 = CheckCatalog.index(str) + "|" + str + "|" + str2 + "|" + (str3 == null ? "" : str3.replace('\n', ' ').replace('\r', ' ')) + "\n";
                FileOutputStream fileOutputStream = new FileOutputStream(new File(this.context.getFilesDir(), "debug.jsonl"), true);
                try {
                    fileOutputStream.write(str4.getBytes("UTF-8"));
                } finally {
                    fileOutputStream.close();
                }
            }
        } catch (Exception unused) {
        }
    }

    synchronized void unavailable(String[] strArr) {
        for (String str : strArr) {
            if (!this.states.containsKey(str)) {
                add(str, "", "UNAVAILABLE", "");
            }
        }
    }

    synchronized String snapshot() {
        return this.cached;
    }

    synchronized void save() throws Exception {
        JSONArray jSONArray = new JSONArray();
        JSONArray jSONArray2 = new JSONArray();
        for (int i = 0; i < CheckCatalog.IDS.length; i++) {
            String str = CheckCatalog.IDS[i];
            String str2 = this.states.get(str);
            if (str2 != null) {
                jSONArray.put(new JSONObject().put("id", OutcomePolicy.label(i)).put("state", str2).put("status", OutcomePolicy.display(str2)));
            }
            if (this.active.containsKey(str)) {
                jSONArray2.put(OutcomePolicy.label(i));
            }
        }
        long elapsedRealtime = SystemClock.elapsedRealtime();
        this.report.put("checks", jSONArray).put("elapsedMs", elapsedRealtime - this.started).put("firstResultMs", this.firstResultMs).put("peakParallelGroups", this.peakGroups).put("active", jSONArray2).put("durationMs", new JSONObject(this.durations));
        String jSONObject = this.report.toString();
        this.cached = jSONObject;
        Listener listener = this.listener;
        if (listener != null) {
            listener.snapshot(jSONObject);
        }
        long j = this.lastPersisted;
        if (j == 0 || elapsedRealtime - j >= 250 || "COMPLETE".equals(this.report.optString("status"))) {
            AuditStorage.write(this.context, this.report);
            this.lastPersisted = elapsedRealtime;
        }
    }

    synchronized void finish(boolean z) throws Exception {
        if (this.closed) {
            return;
        }
        for (String str : CheckCatalog.IDS) {
            this.states.putIfAbsent(str, "UNAVAILABLE");
        }
        if (!z) {
            this.states.replaceAll(new BiFunction() { // from class: io.github.a13e300.unifiedaudit.AuditRun.0
                @Override // java.util.function.BiFunction
                public final Object apply(Object obj, Object obj2) {
                    return AuditRun.lambda$finish$0((String) obj, (String) obj2);
                }
            });
        }
        this.active.clear();
        this.report.put("cleanupComplete", z).put("status", "COMPLETE").put("phase", "COMPLETE");
        save();
        this.closed = true;
    }

    static /* synthetic */ String lambda$finish$0(String str, String str2) {
        return OutcomePolicy.passed(str2) ? "INCONCLUSIVE" : str2;
    }

    void halt() {
        try {
            finish(false);
        } catch (Exception unused) {
        }
        Process.killProcess(Process.myPid());
        throw new IllegalStateException("Worker termination");
    }

    /* JADX WARN: Code restructure failed: missing block: B:24:0x0042, code lost:
    
        if ((r2 - r10.started) > 600000) goto L21;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    synchronized boolean timedOut() {
        /*
            r10 = this;
            monitor-enter(r10)
            boolean r0 = r10.closed     // Catch: java.lang.Throwable -> L47
            r1 = 0
            if (r0 == 0) goto L8
            monitor-exit(r10)
            return r1
        L8:
            long r2 = android.os.SystemClock.elapsedRealtime()     // Catch: java.lang.Throwable -> L47
            java.util.Map<java.lang.String, java.lang.Long> r0 = r10.active     // Catch: java.lang.Throwable -> L47
            java.util.Collection r0 = r0.values()     // Catch: java.lang.Throwable -> L47
            java.util.Iterator r0 = r0.iterator()     // Catch: java.lang.Throwable -> L47
        L16:
            boolean r4 = r0.hasNext()     // Catch: java.lang.Throwable -> L47
            r5 = 1
            r6 = 120000(0x1d4c0, double:5.9288E-319)
            if (r4 == 0) goto L32
            java.lang.Object r4 = r0.next()     // Catch: java.lang.Throwable -> L47
            java.lang.Long r4 = (java.lang.Long) r4     // Catch: java.lang.Throwable -> L47
            long r8 = r4.longValue()     // Catch: java.lang.Throwable -> L47
            long r8 = r2 - r8
            int r4 = (r8 > r6 ? 1 : (r8 == r6 ? 0 : -1))
            if (r4 <= 0) goto L16
            monitor-exit(r10)
            return r5
        L32:
            long r8 = r10.lastProgress     // Catch: java.lang.Throwable -> L47
            long r8 = r2 - r8
            int r0 = (r8 > r6 ? 1 : (r8 == r6 ? 0 : -1))
            if (r0 > 0) goto L44
            long r6 = r10.started     // Catch: java.lang.Throwable -> L47
            long r2 = r2 - r6
            r6 = 600000(0x927c0, double:2.964394E-318)
            int r0 = (r2 > r6 ? 1 : (r2 == r6 ? 0 : -1))
            if (r0 <= 0) goto L45
        L44:
            r1 = r5
        L45:
            monitor-exit(r10)
            return r1
        L47:
            r0 = move-exception
            monitor-exit(r10)     // Catch: java.lang.Throwable -> L47
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: io.github.a13e300.unifiedaudit.AuditRun.timedOut():boolean");
    }
}
