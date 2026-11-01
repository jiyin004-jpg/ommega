package io.github.a13e300.unifiedaudit;

import android.content.Context;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.json.JSONObject;

/* loaded from: classes.dex */
final class AuditLedger {
    private static File ledger;

    static /* synthetic */ void lambda$cleanup$0(JSONObject jSONObject) {
    }

    AuditLedger() {
    }

    static synchronized void initialize(Context context) {
        synchronized (AuditLedger.class) {
            ledger = new File(context.getFilesDir(), "owned-aliases.txt");
        }
    }

    static synchronized void register(String str) {
        synchronized (AuditLedger.class) {
            if (ledger == null || str == null || str.indexOf(10) >= 0) {
                throw new IllegalStateException("Alias journal unavailable");
            }
            try {
                FileOutputStream fileOutputStream = new FileOutputStream(ledger, true);
                try {
                    fileOutputStream.write((str + "\n").getBytes(StandardCharsets.UTF_8));
                    fileOutputStream.getFD().sync();
                    fileOutputStream.close();
                } catch (Throwable th) {
                    try {
                        fileOutputStream.close();
                    } catch (Throwable th2) {
                        th.addSuppressed(th2);
                    }
                    throw th;
                }
            } catch (IOException e) {
                throw new IllegalStateException("Alias journal failed", e);
            }
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:60:0x00cb, code lost:
    
        if (r9.startsWith("omk_demo_") != false) goto L52;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:53:0x00d3 A[Catch: Exception -> 0x0127, all -> 0x012d, TRY_ENTER, TryCatch #3 {Exception -> 0x0127, blocks: (B:15:0x0027, B:19:0x0043, B:20:0x0058, B:22:0x005e, B:25:0x006b, B:27:0x0073, B:29:0x007b, B:31:0x0083, B:66:0x008b, B:53:0x00d3, B:75:0x00da, B:83:0x0113, B:96:0x0126, B:95:0x0123), top: B:14:0x0027 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    static synchronized boolean cleanup(android.content.Context r17) {
        /*
            Method dump skipped, instructions count: 304
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: io.github.a13e300.unifiedaudit.AuditLedger.cleanup(android.content.Context):boolean");
    }
}
