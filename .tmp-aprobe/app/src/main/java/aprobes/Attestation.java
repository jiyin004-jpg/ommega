package aprobes;

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal DER reader for the Android key attestation extension
 * (OID 1.3.6.1.4.1.11129.2.1.17).  X.509 itself is read through the platform
 * X509Certificate API; only the KeyDescription inside the extension is parsed.
 */
public final class Attestation {
    public static final String OID = "1.3.6.1.4.1.11129.2.1.17";

    public final int attestationVersion;
    public final int attestationSecurityLevel;
    public final int keymintVersion;
    public final int keymintSecurityLevel;
    public final byte[] challenge;
    public final byte[] uniqueId;
    public final AuthList sw;
    public final AuthList hw;

    private Attestation(int av, int asl, int kv, int ksl, byte[] ch, byte[] uid,
                        AuthList sw, AuthList hw) {
        this.attestationVersion = av;
        this.attestationSecurityLevel = asl;
        this.keymintVersion = kv;
        this.keymintSecurityLevel = ksl;
        this.challenge = ch;
        this.uniqueId = uid;
        this.sw = sw;
        this.hw = hw;
    }

    public static Attestation parse(X509Certificate cert) throws Exception {
        byte[] ext = cert.getExtensionValue(OID);
        if (ext == null) return null;
        Tlv outer = Tlv.read(ext, 0, ext.length);
        if (outer.tag != 0x04) throw new IllegalArgumentException("extension is not OCTET STRING");
        Tlv seq = Tlv.read(ext, outer.valueStart, outer.valueEnd);
        if (seq.tag != 0x30 || seq.children.size() < 8) {
            throw new IllegalArgumentException("KeyDescription is not a SEQUENCE with 8 fields");
        }
        int av = (int) seq.children.get(0).asLong();
        int asl = (int) seq.children.get(1).asLong();
        int kv = (int) seq.children.get(2).asLong();
        int ksl = (int) seq.children.get(3).asLong();
        byte[] ch = seq.children.get(4).value();
        byte[] uid = seq.children.get(5).value();
        AuthList sw = AuthList.parse(seq.children.get(6));
        AuthList hw = AuthList.parse(seq.children.get(7));
        return new Attestation(av, asl, kv, ksl, ch, uid, sw, hw);
    }

    public static final class RootOfTrust {
        public final byte[] verifiedBootKey;
        public final boolean deviceLocked;
        public final int verifiedBootState;
        public final byte[] verifiedBootHash;

        RootOfTrust(byte[] key, boolean locked, int state, byte[] hash) {
            this.verifiedBootKey = key;
            this.deviceLocked = locked;
            this.verifiedBootState = state;
            this.verifiedBootHash = hash;
        }
    }

    public static final class AuthList {
        public final Map<Integer, List<Tlv>> tags = new LinkedHashMap<>();

        static AuthList parse(Tlv seq) throws Exception {
            if (seq.tag != 0x30) throw new IllegalArgumentException("AuthorizationList not SEQUENCE");
            AuthList out = new AuthList();
            for (Tlv child : seq.children) {
                if (!child.context) continue;
                out.tags.put(child.tag, new ArrayList<>(child.children));
            }
            return out;
        }

        public boolean has(int tag) { return tags.containsKey(tag); }

        public Tlv first(int tag) {
            List<Tlv> v = tags.get(tag);
            return v == null || v.isEmpty() ? null : v.get(0);
        }

        /** Descend through EXPLICIT wrappers until a primitive value is reached. */
        private static Tlv value(Tlv t) {
            int guard = 0;
            while (t != null && t.context && t.children.size() == 1 && guard++ < 8) {
                t = t.children.get(0);
            }
            return t;
        }

        public long integer(int tag, long dflt) {
            Tlv t = value(first(tag));
            if (t == null) return dflt;
            try { return t.asLong(); } catch (Exception e) { return dflt; }
        }

        public List<Long> integers(int tag) {
            List<Long> out = new ArrayList<>();
            for (Tlv raw : tags.getOrDefault(tag, new ArrayList<>())) {
                Tlv t = value(raw);
                if (t == null) continue;
                if (t.tag == 0x31) {
                    for (Tlv n : t.children) {
                        try { out.add(value(n).asLong()); } catch (Exception ignored) {}
                    }
                } else {
                    try { out.add(t.asLong()); } catch (Exception ignored) {}
                }
            }
            return out;
        }

        public byte[] bytes(int tag) {
            Tlv t = value(first(tag));
            if (t == null) return null;
            return t.value();
        }

        public String utf8(int tag) {
            byte[] b = bytes(tag);
            return b == null ? null : new String(b, StandardCharsets.UTF_8);
        }

        public boolean isNull(int tag) {
            Tlv t = value(first(tag));
            return t != null && t.tag == 0x05;
        }

        public RootOfTrust rootOfTrust() {
            Tlv t = value(first(704));
            if (t == null) return null;
            try {
                if (t.tag != 0x30 || t.children.size() < 4) return null;
                byte[] key = t.children.get(0).value();
                boolean locked = t.children.get(1).asLong() != 0;
                int state = (int) t.children.get(2).asLong();
                byte[] hash = t.children.get(3).value();
                return new RootOfTrust(key, locked, state, hash);
            } catch (Exception e) {
                return null;
            }
        }
    }

    /** AttestationApplicationId payload (tag 709). */
    public static final class AppId {
        public final List<String> packages = new ArrayList<>();
        public final List<Long> versions = new ArrayList<>();
        public final List<byte[]> signatures = new ArrayList<>();

        public static AppId parse(byte[] der) {
            AppId out = new AppId();
            if (der == null) return out;
            try {
                Tlv seq = Tlv.read(der, 0, der.length);
                if (seq.tag != 0x30) return out;
                int set = 0;
                for (Tlv field : seq.children) {
                    if (field.tag != 0x31) continue;
                    set++;
                    if (set == 1) {
                        for (Tlv pi : field.children) {
                            if (pi.tag != 0x30) continue;
                            for (Tlv f : pi.children) {
                                if (f.tag == 0x04) out.packages.add(new String(f.value(), StandardCharsets.UTF_8));
                                else if (f.tag == 0x02) out.versions.add(f.asLong());
                            }
                        }
                    } else if (set == 2) {
                        for (Tlv d : field.children) {
                            if (d.tag == 0x04) out.signatures.add(d.value());
                        }
                    }
                }
            } catch (Exception ignored) {
            }
            return out;
        }
    }

    /** One DER TLV.  For context-specific tags {@code tag} is the tag number; for
     *  universal tags it is the first identifier byte. */
    public static final class Tlv {
        public final int tag;
        public final boolean context;
        public final boolean constructed;
        public final int start;
        public final int valueStart;
        public final int valueEnd;
        public final int end;
        public final List<Tlv> children = new ArrayList<>();
        private final byte[] source;

        private Tlv(byte[] source, int tag, boolean context, boolean constructed,
                    int start, int valueStart, int valueEnd) {
            this.source = source;
            this.tag = tag;
            this.context = context;
            this.constructed = constructed;
            this.start = start;
            this.valueStart = valueStart;
            this.valueEnd = valueEnd;
            this.end = valueEnd;
        }

        public byte[] value() {
            return Arrays.copyOfRange(source, valueStart, valueEnd);
        }

        public long asLong() throws Exception {
            if (tag != 0x02 && tag != 0x0a && tag != 0x01) {
                if (children.size() == 1) return children.get(0).asLong();
                throw new IllegalArgumentException("not an integer tag 0x" + Integer.toHexString(tag));
            }
            byte[] v = value();
            if (tag == 0x01) return v.length > 0 && v[0] != 0 ? 1 : 0;
            long r = 0;
            for (byte b : v) r = (r << 8) | (b & 0xff);
            if (v.length > 1 && (v[0] & 0x80) != 0) {
                r -= 1L << (v.length * 8);
            }
            return r;
        }

        static Tlv read(byte[] data, int off, int end) {
            int p = off;
            int first = data[p++] & 0xff;
            boolean context = (first & 0xc0) == 0x80;
            boolean constructed = (first & 0x20) != 0;
            int number = first & 0x1f;
            if (number == 0x1f) {
                number = 0;
                while (p < end) {
                    int b = data[p++] & 0xff;
                    number = (number << 7) | (b & 0x7f);
                    if ((b & 0x80) == 0) break;
                }
            }
            int lenByte = data[p++] & 0xff;
            int len;
            if ((lenByte & 0x80) == 0) {
                len = lenByte;
            } else {
                int n = lenByte & 0x7f;
                len = 0;
                for (int i = 0; i < n; i++) len = (len << 8) | (data[p++] & 0xff);
            }
            int valueStart = p;
            int valueEnd = p + len;
            Tlv t = new Tlv(data, context ? number : first, context, constructed,
                    off, valueStart, valueEnd);
            if (constructed) {
                int q = valueStart;
                while (q < valueEnd) {
                    Tlv child = read(data, q, valueEnd);
                    t.children.add(child);
                    q = child.end;
                }
            }
            return t;
        }
    }
}
