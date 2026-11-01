package io.github.a13e300.unifiedaudit;

import android.content.Context;
import android.os.SystemClock;
import io.github.a13e300.unifiedaudit.ParcelChecks;
import java.util.LinkedHashMap;
import java.util.Map;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class OmkProbe {
    private final Context context;
    private final Progress progress;

    public interface Progress {
        void onStep(String str);
    }

    public OmkProbe(Context context, Progress progress) {
        this.context = context.getApplicationContext();
        this.progress = progress;
    }

    public JSONObject run() {
        long elapsedRealtime = SystemClock.elapsedRealtime();
        final LinkedHashMap linkedHashMap = new LinkedHashMap();
        new ParcelChecks(this.context, new ParcelChecks.Sink() { // from class: io.github.a13e300.unifiedaudit.OmkProbe.0
            @Override // io.github.a13e300.unifiedaudit.ParcelChecks.Sink
            public final void emit(JSONObject jSONObject) {
                OmkProbe.this.m36lambda$run$0$iogithuba13e300unifiedauditOmkProbe(linkedHashMap, jSONObject);
            }
        }).run();
        return ProbeResults.finish(linkedHashMap, SystemClock.elapsedRealtime() - elapsedRealtime);
    }

    /* renamed from: lambda$run$0$io-github-a13e300-unifiedaudit-OmkProbe, reason: not valid java name */
    /* synthetic */ void m36lambda$run$0$iogithuba13e300unifiedauditOmkProbe(Map map, JSONObject jSONObject) {
        String optString = jSONObject.optString("test");
        map.put(optString, jSONObject);
        Progress progress = this.progress;
        if (progress != null) {
            progress.onStep(optString);
        }
    }
}
