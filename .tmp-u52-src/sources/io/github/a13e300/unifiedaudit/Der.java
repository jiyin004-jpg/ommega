package io.github.a13e300.unifiedaudit;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

/* loaded from: classes.dex */
final class Der {
    final byte[] encoded;
    final int tag;
    final int tagClass;
    final byte[] value;

    Der(int i, int i2, byte[] bArr, byte[] bArr2) {
        this.tag = i;
        this.tagClass = i2;
        this.value = bArr;
        this.encoded = bArr2;
    }

    static Der one(byte[] bArr) {
        if (bArr == null || bArr.length > 1048576) {
            throw new IllegalArgumentException("DER size");
        }
        int[] iArr = {0};
        Der read = read(bArr, iArr);
        if (iArr[0] == bArr.length) {
            return read;
        }
        throw new IllegalArgumentException("trailing DER");
    }

    static Der read(byte[] bArr, int[] iArr) {
        int i;
        byte b;
        int i2 = iArr[0];
        if (i2 >= bArr.length) {
            throw new IllegalArgumentException("short DER");
        }
        iArr[0] = i2 + 1;
        byte b2 = bArr[i2];
        int i3 = b2 & 192;
        int i4 = b2 & 31;
        if (i4 == 31) {
            int i5 = 0;
            int i6 = 0;
            do {
                i5++;
                if (i5 > 5 || (i = iArr[0]) >= bArr.length) {
                    throw new IllegalArgumentException("bad DER tag");
                }
                iArr[0] = i + 1;
                b = bArr[i];
                i6 = (i6 << 7) | (b & Byte.MAX_VALUE);
            } while ((b & 128) != 0);
            i4 = i6;
        }
        int i7 = iArr[0];
        if (i7 >= bArr.length) {
            throw new IllegalArgumentException("short DER length");
        }
        int i8 = i7 + 1;
        iArr[0] = i8;
        int i9 = bArr[i7];
        int i10 = i9 & 255;
        if ((i9 & 128) != 0) {
            int i11 = i9 & 127;
            if (i11 == 0 || i11 > 4 || i8 + i11 > bArr.length) {
                throw new IllegalArgumentException("bad DER length");
            }
            i10 = 0;
            for (int i12 = 0; i12 < i11; i12++) {
                int i13 = iArr[0];
                iArr[0] = i13 + 1;
                i10 = (i10 << 8) | (bArr[i13] & 255);
            }
        }
        if (i10 >= 0) {
            int length = bArr.length;
            int i14 = iArr[0];
            if (i10 <= length - i14) {
                byte[] copyOfRange = Arrays.copyOfRange(bArr, i14, i14 + i10);
                int i15 = iArr[0] + i10;
                iArr[0] = i15;
                return new Der(i4, i3, copyOfRange, Arrays.copyOfRange(bArr, i2, i15));
            }
        }
        throw new IllegalArgumentException("DER overflow");
    }

    List<Der> children() {
        ArrayList arrayList = new ArrayList();
        int[] iArr = {0};
        while (true) {
            int i = iArr[0];
            byte[] bArr = this.value;
            if (i >= bArr.length) {
                return arrayList;
            }
            arrayList.add(read(bArr, iArr));
        }
    }

    long integer() {
        return new BigInteger(this.value).longValueExact();
    }

    Der inner() {
        return one(this.value);
    }

    static List<Long> numericValues(Der der) {
        ArrayList arrayList = new ArrayList();
        if (der != null) {
            int i = der.tag;
            if (i != 17 && i != 16) {
                arrayList.add(Long.valueOf(der.integer()));
                return arrayList;
            }
            Iterator<Der> it = der.children().iterator();
            while (it.hasNext()) {
                arrayList.add(Long.valueOf(it.next().integer()));
            }
        }
        return arrayList;
    }

    static final class Record {
        final List<Der> fields;
        final Map<Integer, Der> sw = new HashMap();
        final Map<Integer, Der> hw = new HashMap();

        /* JADX WARN: Code restructure failed: missing block: B:23:0x0070, code lost:
        
            throw new java.lang.IllegalArgumentException("attestation field type");
         */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        Record(java.security.cert.X509Certificate r6) {
            /*
                Method dump skipped, instructions count: 300
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: io.github.a13e300.unifiedaudit.Der.Record.<init>(java.security.cert.X509Certificate):void");
        }

        byte[] challenge() {
            return this.fields.get(4).value;
        }

        Der tag(int i) {
            return (this.hw.containsKey(Integer.valueOf(i)) ? this.hw : this.sw).get(Integer.valueOf(i));
        }

        String rot() {
            Der tag = tag(704);
            if (tag == null) {
                return "missing";
            }
            List<Der> children = tag.children();
            return "locked=" + (children.get(1).value[0] != 0) + ",state=" + children.get(2).integer() + ",key=" + Probes.hex(children.get(0).value) + ",hash=" + (children.size() > 3 ? Probes.hex(children.get(3).value) : "none");
        }

        long number(int i) {
            Der tag = tag(i);
            if (tag == null) {
                return Long.MIN_VALUE;
            }
            return tag.integer();
        }

        List<Long> numbers(int i) {
            TreeSet treeSet = new TreeSet();
            treeSet.addAll(Der.numericValues(this.sw.get(Integer.valueOf(i))));
            treeSet.addAll(Der.numericValues(this.hw.get(Integer.valueOf(i))));
            return new ArrayList(treeSet);
        }
    }
}
