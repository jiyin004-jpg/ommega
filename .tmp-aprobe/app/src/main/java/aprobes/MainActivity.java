package aprobes;

import android.app.Activity;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Build;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.File;
import java.io.FileWriter;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

public final class MainActivity extends Activity {
    private LinearLayout list;
    private TextView summary;
    private TextView status;
    private Button rerun;
    private volatile boolean running;
    private File outFile;
    private final List<Catalog.Item> items = new ArrayList<>();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        File dir = getExternalFilesDir(null);
        if (dir == null) dir = getFilesDir();
        outFile = new File(dir, "a-gap-probe.txt");
        setContentView(buildUi());
        HiddenApi.exempt();
        rerun.setOnClickListener(v -> start());
        start();
    }

    private View buildUi() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(Color.parseColor("#0E1116"));
        int pad = dp(14);
        root.setPadding(pad, dp(10), pad, 0);

        TextView title = new TextView(this);
        title.setText("A 端 KeyMint 缺口探针");
        title.setTextColor(Color.WHITE);
        title.setTextSize(21);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        root.addView(title);

        TextView dev = new TextView(this);
        dev.setText(deviceLine());
        dev.setTextColor(Color.parseColor("#8FA3B0"));
        dev.setTextSize(11);
        dev.setPadding(0, dp(4), 0, dp(8));
        root.addView(dev);

        summary = new TextView(this);
        summary.setText("准备运行…");
        summary.setTextColor(Color.WHITE);
        summary.setTextSize(14);
        summary.setTypeface(Typeface.DEFAULT_BOLD);
        summary.setPadding(0, 0, 0, dp(6));
        root.addView(summary);

        status = new TextView(this);
        status.setText("");
        status.setTextColor(Color.parseColor("#8FA3B0"));
        status.setTextSize(11);
        status.setPadding(0, 0, 0, dp(6));
        root.addView(status);

        LinearLayout buttons = new LinearLayout(this);
        buttons.setOrientation(LinearLayout.HORIZONTAL);
        rerun = new Button(this);
        rerun.setText("重新运行");
        buttons.addView(rerun, new LinearLayout.LayoutParams(dp(130), LinearLayout.LayoutParams.WRAP_CONTENT));
        Button copy = new Button(this);
        copy.setText("复制结果");
        copy.setOnClickListener(v -> copyResults());
        buttons.addView(copy, new LinearLayout.LayoutParams(dp(130), LinearLayout.LayoutParams.WRAP_CONTENT));
        root.addView(buttons);

        ScrollView scroll = new ScrollView(this);
        list = new LinearLayout(this);
        list.setOrientation(LinearLayout.VERTICAL);
        list.setPadding(0, dp(4), 0, dp(24));
        scroll.addView(list);
        root.addView(scroll, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f));
        return root;
    }

    private String deviceLine() {
        return Build.MANUFACTURER + " " + Build.MODEL
                + " · Android " + Build.VERSION.RELEASE + " (API " + Build.VERSION.SDK_INT + ")"
                + "\n" + Build.DISPLAY + " · patch " + Build.VERSION.SECURITY_PATCH
                + "\nuid " + android.os.Process.myUid() + " · " + Build.SUPPORTED_ABIS[0];
    }

    private int dp(int v) {
        return Math.round(v * getResources().getDisplayMetrics().density);
    }

    private void start() {
        if (running) return;
        running = true;
        rerun.setEnabled(false);
        list.removeAllViews();
        summary.setText("运行中…");
        status.setText("");
        if (outFile != null && outFile.exists()) outFile.delete();
        log("===== A Probe " + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(new Date()) + " =====");
        log("DEVICE|" + Build.MANUFACTURER + "|" + Build.MODEL + "|" + Build.VERSION.RELEASE
                + "|" + Build.VERSION.SDK_INT + "|" + Build.VERSION.SECURITY_PATCH
                + "|" + Build.DISPLAY + "|uid=" + android.os.Process.myUid());
        new Thread(() -> {
            Catalog.Ctx ctx;
            try {
                ctx = new Catalog.Ctx(this);
            } catch (Throwable t) {
                runOnUiThread(() -> {
                    summary.setText("KeyStore 初始化失败: " + t);
                    summary.setTextColor(Color.parseColor("#FF6B6B"));
                    rerun.setEnabled(true);
                    running = false;
                });
                return;
            }
            items.clear();
            items.addAll(Catalog.build(ctx));
            int pass = 0, hit = 0, skip = 0, inc = 0, err = 0;
            long t0 = System.currentTimeMillis();
            String lastGroup = null;
            for (Catalog.Item item : items) {
                if (!TextUtils.equals(lastGroup, item.group)) {
                    lastGroup = item.group;
                    final String g = item.group;
                    runOnUiThread(() -> addGroup(g));
                }
                Catalog.Result r;
                try {
                    r = item.body.run();
                } catch (Throwable t) {
                    r = Catalog.Result.error(t.getClass().getSimpleName() + ": " + t.getMessage());
                }
                switch (r.status) {
                    case Catalog.PASS: pass++; break;
                    case Catalog.HIT: hit++; break;
                    case Catalog.SKIP: skip++; break;
                    case Catalog.INCONCLUSIVE: inc++; break;
                    default: err++; break;
                }
                log("RESULT|" + item.id + "|" + r.status + "|" + item.title + "|" + oneLine(r.detail));
                final Catalog.Result shown = r;
                final Catalog.Item it = item;
                runOnUiThread(() -> addCard(it, shown));
                final int p = pass, h = hit, s = skip, i = inc, e = err;
                runOnUiThread(() -> summary.setText(
                        "通过 " + p + " · 命中 " + h + " · 跳过 " + s + " · 不确定 " + i + " · 异常 " + e
                                + "   (" + items.size() + " 项)"));
            }
            long ms = System.currentTimeMillis() - t0;
            final int p = pass, h = hit, s = skip, i = inc, e = err;
            runOnUiThread(() -> {
                summary.setText("通过 " + p + " · 命中 " + h + " · 跳过 " + s + " · 不确定 " + i
                        + " · 异常 " + e + "   (" + items.size() + " 项, " + ms + " ms)");
                summary.setTextColor(h > 0 ? Color.parseColor("#FF6B6B")
                        : e > 0 ? Color.parseColor("#FFB347") : Color.parseColor("#4CD964"));
                status.setText("结果已写入 " + (outFile == null ? "私有目录" : outFile.getAbsolutePath()));
                rerun.setEnabled(true);
                running = false;
            });
            ctx.cleanup();
        }, "a-gap-probe").start();
    }

    private void addGroup(String group) {
        TextView tv = new TextView(this);
        tv.setText(group);
        tv.setTextColor(Color.parseColor("#7FD4FF"));
        tv.setTextSize(13);
        tv.setTypeface(Typeface.DEFAULT_BOLD);
        tv.setPadding(0, dp(14), 0, dp(4));
        list.addView(tv);
    }

    private void addCard(Catalog.Item item, Catalog.Result r) {
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(dp(10), dp(8), dp(10), dp(8));
        box.setBackgroundColor(Color.parseColor("#171D24"));

        TextView head = new TextView(this);
        head.setText(mark(r.status) + "  " + item.id + "  " + item.title);
        head.setTextColor(Color.parseColor(statusColor(r.status)));
        head.setTextSize(13);
        head.setTypeface(Typeface.DEFAULT_BOLD);
        box.addView(head);

        TextView expected = new TextView(this);
        expected.setText("AOSP 期望：" + item.expected);
        expected.setTextColor(Color.parseColor("#93A4B5"));
        expected.setTextSize(11);
        expected.setPadding(0, dp(3), 0, 0);
        expected.setTextIsSelectable(true);
        box.addView(expected);

        TextView detail = new TextView(this);
        detail.setText("本机结果：" + (r.detail == null ? "" : r.detail));
        detail.setTextColor(Color.parseColor("#D7DEE7"));
        detail.setTextSize(11);
        detail.setTypeface(Typeface.MONOSPACE);
        detail.setPadding(0, dp(3), 0, 0);
        detail.setTextIsSelectable(true);
        box.addView(detail);

        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        lp.bottomMargin = dp(6);
        list.addView(box, lp);
    }

    private static String oneLine(String s) {
        return s == null ? "" : s.replace('\n', ' ').replace('|', '/');
    }

    private static String mark(String s) {
        switch (s) {
            case Catalog.PASS: return "[通过]";
            case Catalog.HIT: return "[命中]";
            case Catalog.SKIP: return "[跳过]";
            case Catalog.INCONCLUSIVE: return "[待定]";
            default: return "[异常]";
        }
    }

    private static String statusColor(String s) {
        switch (s) {
            case Catalog.PASS: return "#4CD964";
            case Catalog.HIT: return "#FF6B6B";
            case Catalog.SKIP: return "#8FA3B0";
            case Catalog.INCONCLUSIVE: return "#FFD166";
            default: return "#FF9F43";
        }
    }

    private void log(String s) {
        android.util.Log.i("AGapProbe", s);
        if (outFile == null) return;
        try (FileWriter w = new FileWriter(outFile, true)) {
            w.write(s + "\n");
        } catch (Throwable ignored) {
        }
    }

    private void copyResults() {
        if (outFile == null || !outFile.exists()) return;
        StringBuilder sb = new StringBuilder();
        try (java.io.BufferedReader r = new java.io.BufferedReader(new java.io.FileReader(outFile))) {
            String line;
            while ((line = r.readLine()) != null) sb.append(line).append('\n');
        } catch (Throwable ignored) {
        }
        android.content.ClipboardManager cm = (android.content.ClipboardManager)
                getSystemService(CLIPBOARD_SERVICE);
        cm.setPrimaryClip(android.content.ClipData.newPlainText("A probe", sb.toString()));
        status.setText("已复制 " + sb.length() + " 字符到剪贴板");
    }
}
