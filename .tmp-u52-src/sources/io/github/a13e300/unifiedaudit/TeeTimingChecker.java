package io.github.a13e300.unifiedaudit;

import android.os.SystemClock;
import android.security.keystore.KeyGenParameterSpec;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/* loaded from: classes.dex */
public final class TeeTimingChecker {
    private static final long MIN_MEASUREMENT_FLOOR_NS = 750000;
    private static final int PAIRS = 8;

    public enum State {
        PASS,
        HIT,
        UNAVAILABLE
    }

    public static final class Result {
        public final String detail;
        public final State state;

        private Result(State state, String str) {
            this.state = state;
            this.detail = str;
        }
    }

    private TeeTimingChecker() {
    }

    public static synchronized Result probe() {
        Class<TeeTimingChecker> cls;
        KeyStore keyStore;
        Class<TeeTimingChecker> cls2 = TeeTimingChecker.class;
        synchronized (cls2) {
            try {
                try {
                    String str = "cq_tee_timing_" + String.valueOf(UUID.randomUUID());
                    AuditLedger.register(str);
                    try {
                        keyStore = KeyStore.getInstance("AndroidKeyStore");
                        try {
                            keyStore.load(null);
                            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", "AndroidKeyStore");
                            keyGenerator.init(new KeyGenParameterSpec.Builder(str, 3).setKeySize(256).setBlockModes("GCM").setEncryptionPaddings("NoPadding").build());
                            SecretKey generateKey = keyGenerator.generateKey();
                            byte[] bArr = new byte[97];
                            byte[] bArr2 = new byte[23];
                            new SecureRandom().nextBytes(bArr);
                            new SecureRandom().nextBytes(bArr2);
                            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                            cipher.init(1, generateKey);
                            cipher.updateAAD(bArr2);
                            byte[] doFinal = cipher.doFinal(bArr);
                            GCMParameterSpec gCMParameterSpec = new GCMParameterSpec(128, cipher.getIV());
                            sample(generateKey, gCMParameterSpec, bArr2, doFinal);
                            int i = 0;
                            sample(generateKey, gCMParameterSpec, bArr2, tamper(doFinal, 0));
                            ArrayList arrayList = new ArrayList();
                            ArrayList arrayList2 = new ArrayList();
                            ArrayList arrayList3 = new ArrayList();
                            int i2 = 0;
                            int i3 = 0;
                            while (i2 < PAIRS) {
                                byte[] tamper = tamper(doFinal, i2);
                                boolean z = (i2 & 1) == 0;
                                Sample sample = z ? sample(generateKey, gCMParameterSpec, bArr2, tamper) : sample(generateKey, gCMParameterSpec, bArr2, doFinal);
                                Sample sample2 = z ? sample(generateKey, gCMParameterSpec, bArr2, doFinal) : sample(generateKey, gCMParameterSpec, bArr2, tamper);
                                Sample sample3 = z ? sample2 : sample;
                                if (z) {
                                    sample2 = sample;
                                }
                                SecretKey secretKey = generateKey;
                                if (!sample3.accepted || !Arrays.equals(bArr, sample3.plaintext) || sample3.error != null || sample2.accepted || !isAuthenticationFailure(sample2.error)) {
                                    i3++;
                                }
                                cls = cls2;
                                try {
                                    arrayList.add(Long.valueOf(sample3.elapsedNs));
                                    arrayList2.add(Long.valueOf(sample2.elapsedNs));
                                    long j = sample3.elapsedNs - sample2.elapsedNs;
                                    arrayList3.add(Long.valueOf(j));
                                    if (j > 0) {
                                        i++;
                                    }
                                    i2++;
                                    generateKey = secretKey;
                                    cls2 = cls;
                                } catch (Throwable th) {
                                    th = th;
                                    try {
                                        Result result = new Result(State.UNAVAILABLE, "Timing probe unavailable: " + describe(th));
                                        if (keyStore != null) {
                                            try {
                                                keyStore.deleteEntry(str);
                                            } catch (Throwable unused) {
                                            }
                                        }
                                        return result;
                                    } catch (Throwable th2) {
                                        if (keyStore != null) {
                                            try {
                                                keyStore.deleteEntry(str);
                                            } catch (Throwable unused2) {
                                            }
                                        }
                                        throw th2;
                                    }
                                }
                            }
                            Class<TeeTimingChecker> cls3 = cls2;
                            if (i3 != 0) {
                                Result result2 = new Result(State.UNAVAILABLE, "GCM contract controls failed; mismatches=" + i3);
                                if (keyStore != null) {
                                    try {
                                        keyStore.deleteEntry(str);
                                    } catch (Throwable unused3) {
                                    }
                                }
                                return result2;
                            }
                            long median = median(arrayList);
                            long median2 = median(arrayList2);
                            long median3 = median(arrayList3);
                            long mad = mad(arrayList3, median3);
                            long max = Math.max(MIN_MEASUREMENT_FLOOR_NS, 3 * mad);
                            Result result3 = new Result(i >= 6 && median3 > max && 100 * median >= 125 * median2 ? State.HIT : State.PASS, "pairs=8; positive=" + i + "/8; success_median_ms=" + formatMs(median) + "; failure_median_ms=" + formatMs(median2) + "; delta_median_ms=" + formatMs(median3) + "; delta_mad_ms=" + formatMs(mad) + "; adaptive_floor_ms=" + formatMs(max) + "; contract_mismatches=0");
                            if (keyStore != null) {
                                try {
                                    keyStore.deleteEntry(str);
                                } catch (Throwable unused4) {
                                }
                            }
                            return result3;
                        } catch (Throwable th3) {
                            th = th3;
                            cls = cls2;
                        }
                    } catch (Throwable th4) {
                        th = th4;
                        cls = cls2;
                        keyStore = null;
                    }
                } catch (Throwable th5) {
                    th = th5;
                    throw th;
                }
            } catch (Throwable th6) {
                th = th6;
                cls = cls2;
                throw th;
            }
        }
    }

    private static Sample sample(SecretKey secretKey, GCMParameterSpec gCMParameterSpec, byte[] bArr, byte[] bArr2) {
        boolean z;
        Throwable th;
        byte[] bArr3;
        long elapsedRealtimeNanos = SystemClock.elapsedRealtimeNanos();
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(2, secretKey, gCMParameterSpec);
            cipher.updateAAD(bArr);
            z = true;
            bArr3 = cipher.doFinal(bArr2);
            th = null;
        } catch (Throwable th2) {
            z = false;
            th = th2;
            bArr3 = null;
        }
        return new Sample(SystemClock.elapsedRealtimeNanos() - elapsedRealtimeNanos, z, th, bArr3);
    }

    private static byte[] tamper(byte[] bArr, int i) {
        byte[] bArr2 = (byte[]) bArr.clone();
        int length = ((i * 7) + 3) % bArr2.length;
        bArr2[length] = (byte) (((byte) ((i & 3) + 1)) ^ bArr2[length]);
        return bArr2;
    }

    private static long median(List<Long> list) {
        ArrayList arrayList = new ArrayList(list);
        Collections.sort(arrayList);
        return ((Long) arrayList.get(arrayList.size() / 2)).longValue();
    }

    private static long mad(List<Long> list, long j) {
        ArrayList arrayList = new ArrayList();
        Iterator<Long> it = list.iterator();
        while (it.hasNext()) {
            arrayList.add(Long.valueOf(Math.abs(it.next().longValue() - j)));
        }
        return median(arrayList);
    }

    private static String formatMs(long j) {
        return String.format(Locale.US, "%.3f", Double.valueOf(j / 1000000.0d));
    }

    private static String describe(Throwable th) {
        StringBuilder sb = new StringBuilder();
        int i = 0;
        while (th != null && i < 5) {
            sb.append(th.getClass().getSimpleName());
            sb.append(": ");
            sb.append(th.getMessage());
            sb.append(" | ");
            i++;
            th = th.getCause();
        }
        return sb.toString();
    }

    private static boolean hasCause(Throwable th, Class<? extends Throwable> cls) {
        while (th != null) {
            if (cls.isInstance(th)) {
                return true;
            }
            th = th.getCause();
        }
        return false;
    }

    private static boolean isAuthenticationFailure(Throwable th) {
        if (hasCause(th, AEADBadTagException.class)) {
            return true;
        }
        if (!hasCause(th, BadPaddingException.class)) {
            return false;
        }
        while (th != null) {
            String message = th.getMessage();
            if (message != null && message.toUpperCase(Locale.US).contains("BAD_DECRYPT")) {
                return true;
            }
            th = th.getCause();
        }
        return false;
    }

    private static final class Sample {
        final boolean accepted;
        final long elapsedNs;
        final Throwable error;
        final byte[] plaintext;

        Sample(long j, boolean z, Throwable th, byte[] bArr) {
            this.plaintext = bArr;
            this.elapsedNs = j;
            this.accepted = z;
            this.error = th;
        }
    }
}
