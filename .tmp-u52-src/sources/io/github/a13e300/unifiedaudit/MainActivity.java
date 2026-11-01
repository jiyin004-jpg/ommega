package io.github.a13e300.unifiedaudit;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.content.ServiceConnection;
import android.graphics.Typeface;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.Message;
import android.os.Messenger;
import android.os.RemoteException;
import android.widget.ScrollView;
import android.widget.TextView;
import org.json.JSONArray;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class MainActivity extends Activity {
    private boolean autoOnNextStart;
    private boolean baseline;
    private boolean bound;
    private final ServiceConnection connection;
    private boolean debugLog;
    private final Handler handler;
    private TextView output;
    private String previousRun;
    private final Messenger receiver;
    private String rendered;
    private Messenger service;
    private boolean waiting;

    public MainActivity() {
        Handler handler = new Handler(Looper.getMainLooper(), new Handler.Callback() { // from class: io.github.a13e300.unifiedaudit.MainActivity.0
            @Override // android.os.Handler.Callback
            public final boolean handleMessage(Message message) {
                return MainActivity.this.m31lambda$new$0$iogithuba13e300unifiedauditMainActivity(message);
            }
        });
        this.handler = handler;
        this.receiver = new Messenger(handler);
        this.previousRun = "";
        this.rendered = "";
        this.connection = new ServiceConnection() { // from class: io.github.a13e300.unifiedaudit.MainActivity.1
            @Override // android.content.ServiceConnection
            public void onServiceConnected(ComponentName componentName, IBinder iBinder) {
                MainActivity.this.service = new Messenger(iBinder);
                MainActivity.this.subscribe(1);
                if (MainActivity.this.autoOnNextStart) {
                    MainActivity.this.autoOnNextStart = false;
                    MainActivity.this.startOrJoin();
                }
            }

            @Override // android.content.ServiceConnection
            public void onServiceDisconnected(ComponentName componentName) {
                MainActivity.this.service = null;
            }
        };
    }

    /* renamed from: lambda$new$0$io-github-a13e300-unifiedaudit-MainActivity, reason: not valid java name */
    /* synthetic */ boolean m31lambda$new$0$iogithuba13e300unifiedauditMainActivity(Message message) {
        if (message.what != 3) {
            return false;
        }
        try {
            render(new JSONObject(message.getData().getString("snapshot", "{}")));
            return true;
        } catch (Exception unused) {
            return true;
        }
    }

    @Override // android.app.Activity
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        boolean z = false;
        this.autoOnNextStart = bundle == null;
        this.debugLog = getIntent() != null && getIntent().getBooleanExtra("debug_log", false);
        if (getIntent() != null && getIntent().getBooleanExtra("teesim_baseline", false)) {
            z = true;
        }
        this.baseline = z;
        if (bundle != null) {
            this.waiting = bundle.getBoolean("waiting");
            this.previousRun = bundle.getString("previousRun", "");
        }
        TextView textView = new TextView(this);
        this.output = textView;
        textView.setTextColor(-16777216);
        this.output.setTextSize(16.0f);
        this.output.setTypeface(Typeface.MONOSPACE);
        this.output.setTextIsSelectable(true);
        int round = Math.round(getResources().getDisplayMetrics().density * 12.0f);
        this.output.setPadding(round, round, round, round);
        this.output.setText("检测 Demo\n\n检测中  0/" + CheckCatalog.IDS.length + "\n");
        ScrollView scrollView = new ScrollView(this);
        scrollView.setBackgroundColor(-1);
        scrollView.addView(this.output);
        setContentView(scrollView);
    }

    @Override // android.app.Activity
    protected void onStart() {
        super.onStart();
        this.bound = bindService(new Intent(this, (Class<?>) AuditService.class), this.connection, 1);
    }

    @Override // android.app.Activity
    protected void onStop() {
        subscribe(2);
        if (this.bound) {
            unbindService(this.connection);
            this.bound = false;
        }
        if (!isChangingConfigurations()) {
            this.autoOnNextStart = true;
        }
        super.onStop();
    }

    @Override // android.app.Activity
    protected void onSaveInstanceState(Bundle bundle) {
        bundle.putBoolean("waiting", this.waiting);
        bundle.putString("previousRun", this.previousRun);
        super.onSaveInstanceState(bundle);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void startOrJoin() {
        JSONObject read = AuditStorage.read(this);
        if (read != null && "RUNNING".equals(read.optString("status"))) {
            this.waiting = false;
            render(read);
            return;
        }
        this.previousRun = read == null ? "" : read.optString("runId");
        this.waiting = true;
        this.rendered = "";
        this.output.setText("检测 Demo\n\n检测中  0/" + CheckCatalog.IDS.length + "\n");
        getWindow().addFlags(128);
        try {
            startService(new Intent(this, (Class<?>) AuditService.class).putExtra("debug_log", this.debugLog).putExtra("teesim_baseline", this.baseline));
        } catch (RuntimeException unused) {
            this.waiting = false;
            StringBuilder sb = new StringBuilder("检测 Demo\n\n");
            for (int i = 0; i < CheckCatalog.IDS.length; i++) {
                sb.append(OutcomePolicy.label(i));
                sb.append("  异常\n");
            }
            this.output.setText(sb.toString());
            subscribe(2);
            getWindow().clearFlags(128);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void subscribe(int i) {
        if (this.service == null) {
            return;
        }
        try {
            Message obtain = Message.obtain((Handler) null, i);
            obtain.replyTo = this.receiver;
            this.service.send(obtain);
        } catch (RemoteException unused) {
        }
    }

    private void render(JSONObject jSONObject) {
        int labelIndex;
        if (jSONObject != null) {
            if (this.waiting && this.previousRun.equals(jSONObject.optString("runId"))) {
                return;
            }
            this.waiting = false;
            String str = jSONObject.optString("runId") + ":" + jSONObject.optString("status") + ":" + jSONObject.optLong("elapsedMs");
            if (str.equals(this.rendered)) {
                return;
            }
            this.rendered = str;
            JSONArray optJSONArray = jSONObject.optJSONArray("checks");
            int length = optJSONArray == null ? 0 : optJSONArray.length();
            StringBuilder sb = new StringBuilder();
            String[] strArr = new String[CheckCatalog.IDS.length];
            int i = 0;
            for (int i2 = 0; i2 < length; i2++) {
                JSONObject optJSONObject = optJSONArray.optJSONObject(i2);
                if (optJSONObject != null && (labelIndex = labelIndex(optJSONObject.optString("id"))) >= 0) {
                    boolean passed = OutcomePolicy.passed(optJSONObject.optString("state"));
                    if (passed) {
                        i++;
                    }
                    strArr[labelIndex] = passed ? "通过" : "异常";
                }
            }
            for (int i3 = 0; i3 < CheckCatalog.IDS.length; i3++) {
                sb.append(OutcomePolicy.label(i3));
                sb.append("  ");
                String str2 = strArr[i3];
                if (str2 == null) {
                    str2 = "";
                }
                sb.append(str2);
                sb.append('\n');
            }
            boolean equals = "RUNNING".equals(jSONObject.optString("status"));
            TextView textView = this.output;
            String str3 = equals ? "检测中  " : "检测完成  ";
            textView.setText("检测 Demo\n\n" + str3 + length + "/" + CheckCatalog.IDS.length + "\n通过 " + i + "  异常 " + (length - i) + "\n\n" + String.valueOf(sb));
            if (equals) {
                getWindow().addFlags(128);
            } else {
                getWindow().clearFlags(128);
            }
        }
    }

    private static int labelIndex(String str) {
        for (int i = 0; i < CheckCatalog.IDS.length; i++) {
            if (OutcomePolicy.label(i).equals(str)) {
                return i;
            }
        }
        return -1;
    }
}
