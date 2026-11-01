package io.github.a13e300.unifiedaudit;

import android.content.Context;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import org.json.JSONObject;

/* loaded from: classes.dex */
final class AuditStorage {
    AuditStorage() {
    }

    static void write(Context context, JSONObject jSONObject) throws Exception {
        Path path = new File(context.getFilesDir(), "latest.json").toPath();
        Path path2 = new File(context.getFilesDir(), "latest.json.pending").toPath();
        FileOutputStream fileOutputStream = new FileOutputStream(path2.toFile());
        try {
            fileOutputStream.write(jSONObject.toString().getBytes(StandardCharsets.UTF_8));
            fileOutputStream.getFD().sync();
            fileOutputStream.close();
            Files.move(path2, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (Throwable th) {
            try {
                fileOutputStream.close();
            } catch (Throwable th2) {
                th.addSuppressed(th2);
            }
            throw th;
        }
    }

    static JSONObject read(Context context) {
        try {
            return new JSONObject(new String(Files.readAllBytes(new File(context.getFilesDir(), "latest.json").toPath()), StandardCharsets.UTF_8));
        } catch (Exception unused) {
            return null;
        }
    }
}
