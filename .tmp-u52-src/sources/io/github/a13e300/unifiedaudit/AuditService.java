package io.github.a13e300.unifiedaudit;

import android.app.Service;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.Message;
import android.os.Messenger;
import android.os.RemoteException;
import android.util.Log;
import io.github.a13e300.unifiedaudit.AuditRun;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;
import org.json.JSONArray;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class AuditService extends Service {
    static final int REGISTER = 1;
    static final int RESULT = 3;
    static final int UNREGISTER = 2;
    private final ArrayList<Messenger> clients = new ArrayList<>();
    private volatile AuditRun current;
    private final Runnable deliver;
    private final Handler handler;
    private final Messenger messenger;
    private volatile String pending;
    private volatile boolean running;
    private final Runnable watchdog;

    public AuditService() {
        Handler handler = new Handler(Looper.getMainLooper(), new Handler.Callback() { // from class: io.github.a13e300.unifiedaudit.AuditService.4
            @Override // android.os.Handler.Callback
            public final boolean handleMessage(Message message) {
                return AuditService.this.m3lambda$new$0$iogithuba13e300unifiedauditAuditService(message);
            }
        });
        this.handler = handler;
        this.messenger = new Messenger(handler);
        this.deliver = new Runnable() { // from class: io.github.a13e300.unifiedaudit.AuditService.5
            @Override // java.lang.Runnable
            public final void run() {
                AuditService.this.m4lambda$new$1$iogithuba13e300unifiedauditAuditService();
            }
        };
        this.watchdog = new Runnable() { // from class: io.github.a13e300.unifiedaudit.AuditService.1
            @Override // java.lang.Runnable
            public void run() {
                if (AuditService.this.running) {
                    if (AuditService.this.current == null || !AuditService.this.current.timedOut()) {
                        AuditService.this.handler.postDelayed(this, 1000L);
                    } else {
                        AuditService.this.current.halt();
                    }
                }
            }
        };
    }

    /* renamed from: lambda$new$0$io-github-a13e300-unifiedaudit-AuditService, reason: not valid java name */
    /* synthetic */ boolean m3lambda$new$0$iogithuba13e300unifiedauditAuditService(Message message) {
        JSONObject read;
        if (message.what == REGISTER && message.replyTo != null) {
            removeClient(message.replyTo);
            this.clients.add(message.replyTo);
            String snapshot = this.current == null ? null : this.current.snapshot();
            if (snapshot == null && (read = AuditStorage.read(this)) != null) {
                snapshot = read.toString();
            }
            if (snapshot != null) {
                send(message.replyTo, snapshot);
            }
            return true;
        }
        if (message.what != UNREGISTER || message.replyTo == null) {
            return false;
        }
        removeClient(message.replyTo);
        return true;
    }

    /* renamed from: lambda$new$1$io-github-a13e300-unifiedaudit-AuditService, reason: not valid java name */
    /* synthetic */ void m4lambda$new$1$iogithuba13e300unifiedauditAuditService() {
        String str = this.pending;
        if (str == null) {
            return;
        }
        for (int size = this.clients.size() - 1; size >= 0; size--) {
            if (!send(this.clients.get(size), str)) {
                this.clients.remove(size);
            }
        }
    }

    static /* synthetic */ boolean lambda$removeClient$2(Messenger messenger, Messenger messenger2) {
        return messenger2.getBinder().equals(messenger.getBinder());
    }

    private void removeClient(final Messenger messenger) {
        this.clients.removeIf(new Predicate() { // from class: io.github.a13e300.unifiedaudit.AuditService.8
            @Override // java.util.function.Predicate
            public final boolean test(Object obj) {
                return AuditService.lambda$removeClient$2(messenger, (Messenger) obj);
            }
        });
    }

    private boolean send(Messenger messenger, String str) {
        try {
            Message obtain = Message.obtain((Handler) null, RESULT);
            Bundle bundle = new Bundle();
            bundle.putString("snapshot", str);
            obtain.setData(bundle);
            messenger.send(obtain);
            return true;
        } catch (RemoteException unused) {
            return false;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void publish(String str) {
        this.pending = str;
        this.handler.removeCallbacks(this.deliver);
        this.handler.postDelayed(this.deliver, 25L);
    }

    @Override // android.app.Service
    public void onCreate() {
        super.onCreate();
        JSONObject read = AuditStorage.read(this);
        if (read == null || !"RUNNING".equals(read.optString("status"))) {
            return;
        }
        try {
            JSONArray optJSONArray = read.optJSONArray("checks");
            HashMap hashMap = new HashMap();
            if (optJSONArray != null) {
                for (int i = 0; i < optJSONArray.length(); i += REGISTER) {
                    JSONObject jSONObject = optJSONArray.getJSONObject(i);
                    hashMap.put(jSONObject.getString("id"), jSONObject);
                }
            }
            JSONArray jSONArray = new JSONArray();
            for (int i2 = 0; i2 < CheckCatalog.IDS.length; i2 += REGISTER) {
                String label = OutcomePolicy.label(i2);
                JSONObject jSONObject2 = (JSONObject) hashMap.get(label);
                if (jSONObject2 == null || OutcomePolicy.passed(jSONObject2.optString("state"))) {
                    jSONObject2 = new JSONObject().put("id", label).put("state", "INCONCLUSIVE").put("status", "异常");
                }
                jSONArray.put(jSONObject2);
            }
            read.put("checks", jSONArray).put("status", "COMPLETE").put("cleanupComplete", false).put("active", new JSONArray()).put("phase", "INTERRUPTED");
            AuditStorage.write(this, read);
        } catch (Exception unused) {
        }
    }

    @Override // android.app.Service
    public IBinder onBind(Intent intent) {
        return this.messenger.getBinder();
    }

    @Override // android.app.Service
    public int onStartCommand(Intent intent, int i, final int i2) {
        if (this.running) {
            if (this.current != null) {
                publish(this.current.snapshot());
            }
            return UNREGISTER;
        }
        if (intent != null && intent.getBooleanExtra("teesim_baseline", false)) {
            try {
                TeeSimProbes.captureBaseline(this);
                Log.i("U52AUDIT", "baseline captured");
            } catch (Throwable th) {
                Log.w("U52AUDIT", "baseline capture failed", th);
            }
            stopSelf(i2);
            return UNREGISTER;
        }
        this.running = true;
        AuditRun.debugLog = intent != null && intent.getBooleanExtra("debug_log", false);
        try {
            this.current = new AuditRun(this, new AuditRun.Listener() { // from class: io.github.a13e300.unifiedaudit.AuditService.6
                @Override // io.github.a13e300.unifiedaudit.AuditRun.Listener
                public final void snapshot(String str) {
                    AuditService.this.publish(str);
                }
            });
            final AuditRun auditRun = this.current;
            this.handler.post(this.watchdog);
            new Thread(new Runnable() { // from class: io.github.a13e300.unifiedaudit.AuditService.7
                @Override // java.lang.Runnable
                public final void run() {
                    AuditService.this.m7x17b29f32(auditRun, i2);
                }
            }, "Audit-Coordinator").start();
            return UNREGISTER;
        } catch (Exception unused) {
            this.running = false;
            stopSelf(i2);
            return UNREGISTER;
        }
    }

    /* renamed from: lambda$onStartCommand$6$io-github-a13e300-unifiedaudit-AuditService, reason: not valid java name */
    /* synthetic */ void m7x17b29f32(final AuditRun auditRun, final int i) {
        Handler handler;
        Runnable runnable;
        try {
            try {
                AuditLedger.initialize(this);
            } catch (Throwable unused) {
                auditRun.finish(false);
                handler = this.handler;
                runnable = new Runnable() { // from class: io.github.a13e300.unifiedaudit.AuditService.0
                    @Override // java.lang.Runnable
                    public final void run() {
                        AuditService.this.m6x7d11dcb1(auditRun, i);
                    }
                };
                handler.post(runnable);
            }
        } catch (Exception unused2) {
            handler = this.handler;
            runnable = new Runnable() { // from class: io.github.a13e300.unifiedaudit.AuditService.0
                @Override // java.lang.Runnable
                public final void run() {
                    AuditService.this.m6x7d11dcb1(auditRun, i);
                }
            };
            handler.post(runnable);
        } catch (Throwable th) {
            this.handler.post(new Runnable() { // from class: io.github.a13e300.unifiedaudit.AuditService.0
                @Override // java.lang.Runnable
                public final void run() {
                    AuditService.this.m6x7d11dcb1(auditRun, i);
                }
            });
            throw th;
        }
        if (!AuditLedger.cleanup(this)) {
            auditRun.finish(false);
            this.handler.post(new Runnable() { // from class: io.github.a13e300.unifiedaudit.AuditService.0
                @Override // java.lang.Runnable
                public final void run() {
                    AuditService.this.m6x7d11dcb1(auditRun, i);
                }
            });
            return;
        }
        auditRun.phase("PARALLEL");
        final AtomicInteger atomicInteger = new AtomicInteger();
        ExecutorService newFixedThreadPool = Executors.newFixedThreadPool(4, new ThreadFactory() { // from class: io.github.a13e300.unifiedaudit.AuditService.2
            @Override // java.util.concurrent.ThreadFactory
            public final Thread newThread(Runnable runnable2) {
                return AuditService.lambda$onStartCommand$3(atomicInteger, runnable2);
            }
        });
        ArrayList arrayList = new ArrayList();
        for (final int i2 = 0; i2 < ProbePlan.GROUPS.length; i2 += REGISTER) {
            try {
                try {
                    arrayList.add(newFixedThreadPool.submit(new Runnable() { // from class: io.github.a13e300.unifiedaudit.AuditService.3
                        @Override // java.lang.Runnable
                        public final void run() {
                            AuditService.this.m5xe2711a30(auditRun, i2);
                        }
                    }));
                } finally {
                    newFixedThreadPool.shutdownNow();
                }
            } catch (Throwable unused3) {
                auditRun.halt();
            }
        }
        Iterator it = arrayList.iterator();
        while (it.hasNext()) {
            ((Future) it.next()).get();
        }
        auditRun.phase("TIMING");
        try {
            ModuleProbes moduleProbes = new ModuleProbes(auditRun);
            moduleProbes.selection = ProbePlan.select(ProbePlan.QUIET);
            moduleProbes.runModules();
        } catch (Throwable unused4) {
            auditRun.unavailable(ProbePlan.QUIET);
        }
        auditRun.phase("CLEANUP");
        auditRun.finish(AuditLedger.cleanup(this));
        handler = this.handler;
        runnable = new Runnable() { // from class: io.github.a13e300.unifiedaudit.AuditService.0
            @Override // java.lang.Runnable
            public final void run() {
                AuditService.this.m6x7d11dcb1(auditRun, i);
            }
        };
        handler.post(runnable);
    }

    static /* synthetic */ Thread lambda$onStartCommand$3(AtomicInteger atomicInteger, Runnable runnable) {
        return new Thread(runnable, "Audit-" + atomicInteger.incrementAndGet());
    }

    /* renamed from: lambda$onStartCommand$5$io-github-a13e300-unifiedaudit-AuditService, reason: not valid java name */
    /* synthetic */ void m6x7d11dcb1(AuditRun auditRun, int i) {
        if (this.current == auditRun) {
            this.running = false;
            this.handler.removeCallbacks(this.watchdog);
        }
        stopSelf(i);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: runGroup, reason: merged with bridge method [inline-methods] */
    public void m5xe2711a30(AuditRun auditRun, int i) {
        Probes coreProbes;
        auditRun.beginGroup();
        try {
            try {
                if (i < RESULT) {
                    coreProbes = new Probes(auditRun);
                } else {
                    coreProbes = i < 6 ? new CoreProbes(auditRun) : i == 6 ? new ModuleProbes(auditRun) : i < 9 ? new CrackProbes(auditRun) : new TeeSimProbes(auditRun);
                }
                coreProbes.selection = ProbePlan.select(ProbePlan.GROUPS[i]);
                if (coreProbes instanceof CoreProbes) {
                    ((CoreProbes) coreProbes).runExtra();
                } else if (coreProbes instanceof ModuleProbes) {
                    ((ModuleProbes) coreProbes).runModules();
                } else if (coreProbes instanceof CrackProbes) {
                    ((CrackProbes) coreProbes).runCrack();
                } else if (coreProbes instanceof TeeSimProbes) {
                    ((TeeSimProbes) coreProbes).runTeeSim();
                } else {
                    coreProbes.run();
                }
            } finally {
                auditRun.endGroup();
            }
        } catch (Throwable unused) {
            auditRun.unavailable(ProbePlan.GROUPS[i]);
        }
    }
}
