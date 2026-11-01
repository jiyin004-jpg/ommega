package io.github.a13e300.unifiedaudit;

import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class ProbeResults {
    public static final String VERSION = "1.2.0";

    static boolean ok(JSONObject jSONObject) {
        return jSONObject != null && "OK".equals(jSONObject.optString("execution"));
    }

    static boolean found(JSONObject jSONObject) {
        return jSONObject != null && jSONObject.optBoolean("accepted") && jSONObject.optBoolean("matches") && jSONObject.optInt("remaining", -1) == 0;
    }

    static boolean absent(JSONObject jSONObject) {
        return (jSONObject == null || jSONObject.optBoolean("accepted") || jSONObject.optInt("code", -1) != 7) ? false : true;
    }

    static boolean control(JSONObject jSONObject) {
        if (ok(jSONObject) && found(jSONObject.optJSONObject("readback"))) {
            JSONObject optJSONObject = jSONObject.optJSONObject("operation");
            JSONObject optJSONObject2 = jSONObject.optJSONObject("chain");
            if (optJSONObject != null && optJSONObject.optBoolean("accepted") && optJSONObject.optBoolean("valid") && optJSONObject2 != null && optJSONObject2.optBoolean("adjacentSignaturesValid") && optJSONObject2.optJSONArray("chain") != null && optJSONObject2.optJSONArray("chain").length() >= 2) {
                return true;
            }
        }
        return false;
    }

    static String readVerdict(JSONObject jSONObject) {
        if (ok(jSONObject) && jSONObject.optBoolean("readbackUnchanged")) {
            JSONArray optJSONArray = jSONObject.optJSONArray("requests");
            JSONObject optJSONObject = jSONObject.optJSONObject("chain");
            if (optJSONArray != null && optJSONArray.length() == 24 && optJSONObject != null && optJSONObject.optBoolean("adjacentSignaturesValid")) {
                int i = 0;
                int i2 = 0;
                int i3 = 0;
                int i4 = 0;
                for (int i5 = 0; i5 < optJSONArray.length(); i5++) {
                    JSONObject optJSONObject2 = optJSONArray.optJSONObject(i5);
                    if (optJSONObject2 == null) {
                        return "UNAVAILABLE";
                    }
                    String optString = optJSONObject2.optString("kind");
                    if ("missing".equals(optString)) {
                        if (!absent(optJSONObject2)) {
                            return "UNAVAILABLE";
                        }
                        i2++;
                    } else {
                        if (!"alias".equals(optString) && !"keyid".equals(optString)) {
                            return "UNAVAILABLE";
                        }
                        if (optJSONObject2.optInt("presence") == 1) {
                            if (!found(optJSONObject2)) {
                                return "UNAVAILABLE";
                            }
                            i++;
                        } else if (found(optJSONObject2)) {
                            i4++;
                        } else {
                            if (!absent(optJSONObject2)) {
                                return "UNAVAILABLE";
                            }
                            i3++;
                        }
                    }
                }
                if (i == 10 && i2 == 8) {
                    if (i3 == 6) {
                        return "HIT_EQUIVALENT_READ_DIVERGENCE";
                    }
                    if (i4 == 6) {
                        return "CLEAR";
                    }
                    return "INCONCLUSIVE";
                }
            }
        }
        return "UNAVAILABLE";
    }

    static JSONObject item(String str, String str2, String str3, String str4) throws JSONException {
        return new JSONObject().put("id", str).put("mechanism", "S06").put("title", str2).put("verdict", str3).put("description", str4);
    }

    private static String describeRead(String str) {
        return str.startsWith("HIT") ? "同一自有密钥在等价参数下出现回读差异；存在与不存在对象的对照均有效。" : "CLEAR".equals(str) ? "等价参数均返回同一自有密钥，未发现目标回读差异。" : "INCONCLUSIVE".equals(str) ? "等价参数的返回不一致，但未形成完整证据，暂不能判断。" : "接口、签名控制或清理条件不足，本项无法有效评估。";
    }

    private static String describeViews(String str) {
        return str.startsWith("HIT") ? "同一别名出现独立的私钥与证书条目；删除证书条目后，原私钥仍可有效签名。" : "CLEAR".equals(str) ? "两种入口共享同一对象，更新与删除同步，未发现目标存储视图异常。" : "INCONCLUSIVE".equals(str) ? "读写流程已执行，但对象状态未满足完整判据，暂不能判断。" : "接口、签名控制或清理条件不足，本项无法有效评估。";
    }

    public static JSONObject finish(Map<String, JSONObject> map, long j) {
        try {
            JSONObject jSONObject = map.get("identity");
            JSONObject jSONObject2 = map.get("cleanup");
            boolean z = ok(jSONObject) && jSONObject.optInt("uid") >= 10000 && jSONObject.optString("context").contains("untrusted_app") && jSONObject.optString("status").contains("CapEff:\t0000000000000000");
            if (z) {
                JSONObject optJSONObject = jSONObject.optJSONObject("permissions");
                if (optJSONObject != null && optJSONObject.length() != 0) {
                    Iterator<String> keys = optJSONObject.keys();
                    while (keys.hasNext()) {
                        if (optJSONObject.optInt(keys.next()) != -1) {
                            z = false;
                        }
                    }
                }
                z = false;
            }
            JSONArray optJSONArray = jSONObject2 == null ? null : jSONObject2.optJSONArray("keys");
            boolean z2 = ok(jSONObject2) && optJSONArray != null && optJSONArray.length() > 0;
            if (z2) {
                for (int i = 0; i < optJSONArray.length(); i++) {
                    JSONObject jSONObject3 = optJSONArray.getJSONObject(i);
                    z2 &= jSONObject3.optBoolean("absent") && absent(jSONObject3.optJSONObject("canonical")) && absent(jSONObject3.optJSONObject("alternate"));
                }
            }
            boolean z3 = z && z2 && control(map.get("control_before")) && control(map.get("control_after"));
            String str = "UNAVAILABLE";
            String readVerdict = z3 ? readVerdict(map.get("read_equivalence")) : "UNAVAILABLE";
            JSONObject jSONObject4 = map.get("certificate_views");
            if (z3 && ok(jSONObject4)) {
                str = jSONObject4.optString("verdict", "UNAVAILABLE");
            }
            JSONArray put = new JSONArray().put(item("S06A", "等价参数回读一致性", readVerdict, describeRead(readVerdict))).put(item("S06B", "同名对象读写删除一致性", str, describeViews(str)));
            int i2 = 0;
            int i3 = 0;
            int i4 = 0;
            int i5 = 0;
            int i6 = 0;
            while (i3 < put.length()) {
                String string = put.getJSONObject(i3).getString("verdict");
                JSONArray jSONArray = optJSONArray;
                if (string.startsWith("HIT")) {
                    i4++;
                } else if ("CLEAR".equals(string)) {
                    i5++;
                } else if ("INCONCLUSIVE".equals(string)) {
                    i2++;
                } else {
                    i6++;
                }
                i3++;
                optJSONArray = jSONArray;
            }
            JSONArray jSONArray2 = optJSONArray;
            return new JSONObject().put("schema", 4).put("appVersion", VERSION).put("createdAt", System.currentTimeMillis()).put("elapsedMs", j).put("hitCount", i4).put("clearCount", i5).put("unavailableCount", i6).put("inconclusiveCount", i2).put("confirmedMechanismCount", "HIT_SPLIT_KEYSTORE_VIEW".equals(str) ? 1 : 0).put("sharedMechanism", true).put("controlsValid", z3).put("ordinaryUid", z).put("cleanupComplete", z2).put("registeredAliasCount", jSONArray2 == null ? 0 : jSONArray2.length()).put("identity", jSONObject).put("checks", put).put("records", new JSONObject(map)).put("attribution", "KEYSTORE_ROUTING_CONSISTENCY_ONLY");
        } catch (Exception e) {
            return failure(e);
        }
    }

    public static JSONObject failure(Throwable th) {
        try {
            return new JSONObject().put("schema", 4).put("appVersion", VERSION).put("error", ProbeBase.error(th)).put("hitCount", 0).put("clearCount", 0).put("unavailableCount", 2).put("inconclusiveCount", 0).put("confirmedMechanismCount", 0).put("sharedMechanism", true).put("controlsValid", false).put("cleanupComplete", false).put("checks", new JSONArray().put(item("S06A", "等价参数回读一致性", "UNAVAILABLE", "检测未完成，请查看本次详情。")).put(item("S06B", "同名对象读写删除一致性", "UNAVAILABLE", "检测未完成，请查看本次详情。")));
        } catch (Exception unused) {
            return new JSONObject();
        }
    }

    public static String summary(JSONObject jSONObject) {
        if (jSONObject == null) {
            return "尚未检测";
        }
        StringBuilder sb = new StringBuilder("OMK 检测 Demo 1.2.0\n");
        JSONObject optJSONObject = jSONObject.optJSONObject("identity");
        if (optJSONObject != null) {
            sb.append("UID ");
            sb.append(optJSONObject.optInt("uid"));
            sb.append(" · Android API ");
            sb.append(optJSONObject.optInt("sdk"));
            sb.append('\n');
        }
        JSONArray optJSONArray = jSONObject.optJSONArray("checks");
        if (optJSONArray != null) {
            for (int i = 0; i < optJSONArray.length(); i++) {
                JSONObject optJSONObject2 = optJSONArray.optJSONObject(i);
                sb.append('\n');
                sb.append(optJSONObject2.optString("title"));
                sb.append(": ");
                sb.append(optJSONObject2.optString("verdict"));
                sb.append('\n');
                sb.append(optJSONObject2.optString("description"));
                sb.append('\n');
            }
        }
        sb.append("\n控制校验: ");
        sb.append(jSONObject.optBoolean("controlsValid") ? "通过" : "不可评估");
        sb.append("\n临时对象清理: ");
        sb.append(jSONObject.optBoolean("cleanupComplete") ? "完成" : "未确认");
        sb.append("\n耗时: ");
        sb.append(String.format(Locale.ROOT, "%.1f 秒", Double.valueOf(jSONObject.optLong("elapsedMs") / 1000.0d)));
        if (jSONObject.has("error")) {
            sb.append("\n\n");
            sb.append(jSONObject.optString("error"));
        }
        sb.append("\n\n两项检查属于同一机制；命中说明存储视图异常，不能唯一确认 OMK。未命中也不证明设备无 Root。");
        return sb.toString();
    }
}
