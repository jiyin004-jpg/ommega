package io.github.a13e300.unifiedaudit;

/* loaded from: classes.dex */
final class OutcomePolicy {
    static final String LABELS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

    OutcomePolicy() {
    }

    static String label(int i) {
        if (i < 0) {
            throw new IllegalArgumentException("check index");
        }
        if (i < 52) {
            return String.valueOf(LABELS.charAt(i));
        }
        int i2 = i - 52;
        int i3 = i2 / 52;
        int i4 = i2 % 52;
        if (i3 >= 52) {
            throw new IllegalArgumentException("check index");
        }
        return String.valueOf(LABELS.charAt(i3)) + LABELS.charAt(i4);
    }

    static boolean passed(String str) {
        return "CLEAR".equals(str) || "PASS".equals(str) || "UNAVAILABLE".equals(str);
    }

    static String display(String str) {
        return passed(str) ? "通过" : "异常";
    }
}
