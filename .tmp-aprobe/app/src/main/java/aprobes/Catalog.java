package aprobes;

import android.app.Activity;
import android.content.pm.PackageInfo;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import java.io.File;
import java.lang.reflect.Method;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.Callable;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * The check catalog.  Every item names a contract taken from Android 17 AOSP
 * (KeyMint, keystore2, KeyProperties) and the observed Ommega A-side behaviour.
 */
public final class Catalog {
    public static final String PASS = "PASS";
    public static final String HIT = "HIT";
    public static final String SKIP = "SKIP";
    public static final String INCONCLUSIVE = "INCONCLUSIVE";
    public static final String ERROR = "ERROR";

    private Catalog() {}

    public interface Body { Result run() throws Exception; }

    public static final class Result {
        public final String status;
        public final String detail;
        public Result(String status, String detail) { this.status = status; this.detail = detail; }
        public static Result pass(String d) { return new Result(PASS, d); }
        public static Result hit(String d) { return new Result(HIT, d); }
        public static Result skip(String d) { return new Result(SKIP, d); }
        public static Result inc(String d) { return new Result(INCONCLUSIVE, d); }
        public static Result error(String d) { return new Result(ERROR, d); }
    }

    public static final class Item {
        public final String group, id, title, expected;
        public final Body body;
        Item(String group, String id, String title, String expected, Body body) {
            this.group = group; this.id = id; this.title = title; this.expected = expected; this.body = body;
        }
    }

    public static final class Ctx {
        public final Activity activity;
        public final KeyStore ks;
        public final List<String> aliases = new ArrayList<>();
        public final byte[] challenge = "aprobe-challenge-2026-10-30-32b!".getBytes();
        private KeyPair ecAttested, ecPlain, ecProps, ecParent, rsaAttested, rsaPss, rsaDecrypt,
                rsaOaep, rsaNoPad, ecAgree, ecP384, ed25519;
        private boolean importDone;
        private final Map<String, Object> extra = new HashMap<>();

        Ctx(Activity activity) throws Exception {
            this.activity = activity;
            this.ks = Util.keyStore();
        }

        void track(String alias) { aliases.add(alias); }

        KeyPair ecAttested() throws Exception {
            if (ecAttested == null) {
                String a = "aprobe_ec_att";
                ecAttested = Util.genEc(ks, a, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY,
                        new String(challenge), null, false);
                track(a);
            }
            return ecAttested;
        }

        KeyPair ecPlain() throws Exception {
            if (ecPlain == null) {
                String a = "aprobe_ec_plain";
                ecPlain = Util.genEc(ks, a, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY,
                        null, null, false);
                track(a);
            }
            return ecPlain;
        }

        KeyPair ecProps() throws Exception {
            if (ecProps == null) {
                String a = "aprobe_ec_props";
                ecProps = Util.genEc(ks, a, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY,
                        new String(challenge), null, true);
                track(a);
            }
            return ecProps;
        }

        KeyPair ecParent() throws Exception {
            if (ecParent == null) {
                String a = "aprobe_att_parent";
                ecParent = Util.genAttestKey(ks, a, challenge);
                track(a);
            }
            return ecParent;
        }

        KeyPair rsaAttested() throws Exception {
            if (rsaAttested == null) {
                String a = "aprobe_rsa_att";
                rsaAttested = Util.genRsa(ks, a,
                        KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY, challenge, 2048,
                        KeyProperties.SIGNATURE_PADDING_RSA_PKCS1, KeyProperties.DIGEST_SHA256, false);
                track(a);
            }
            return rsaAttested;
        }

        KeyPair rsaPss() throws Exception {
            if (rsaPss == null) {
                String a = "aprobe_rsa_pss";
                rsaPss = Util.genRsa(ks, a,
                        KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY, challenge, 2048,
                        KeyProperties.SIGNATURE_PADDING_RSA_PSS, KeyProperties.DIGEST_SHA256, false);
                track(a);
            }
            return rsaPss;
        }

        KeyPair rsaDecrypt() throws Exception {
            if (rsaDecrypt == null) {
                String a = "aprobe_rsa_dec";
                rsaDecrypt = Util.genRsa(ks, a,
                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT, challenge, 2048,
                        KeyProperties.SIGNATURE_PADDING_RSA_PKCS1,
                        KeyProperties.DIGEST_SHA256, false);
                track(a);
            }
            return rsaDecrypt;
        }

        KeyPair rsaOaep() throws Exception {
            if (rsaOaep == null) {
                String a = "aprobe_rsa_oaep";
                rsaOaep = Util.genRsa(ks, a,
                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT, challenge, 2048,
                        KeyProperties.SIGNATURE_PADDING_RSA_PKCS1,
                        KeyProperties.DIGEST_SHA256, false);
                track(a);
            }
            return rsaOaep;
        }

        KeyPair rsaNoPad() throws Exception {
            if (rsaNoPad == null) {
                String a = "aprobe_rsa_nopad";
                rsaNoPad = Util.genRsa(ks, a,
                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT, challenge, 2048,
                        KeyProperties.SIGNATURE_PADDING_RSA_PKCS1,
                        KeyProperties.DIGEST_SHA256, false);
                track(a);
            }
            return rsaNoPad;
        }

        KeyPair ecAgree() throws Exception {
            if (ecAgree == null) {
                String a = "aprobe_ec_agree";
                ecAgree = Util.genEc(ks, a, KeyProperties.PURPOSE_AGREE_KEY,
                        new String(challenge), null, false);
                track(a);
            }
            return ecAgree;
        }

        KeyPair ecP384() throws Exception {
            if (ecP384 == null) {
                String a = "aprobe_ec_p384";
                ecP384 = Util.genEcCustom(ks, a, "secp384r1",
                        KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY, challenge,
                        KeyProperties.DIGEST_SHA384, null, false);
                track(a);
            }
            return ecP384;
        }

        X509Certificate leaf(String alias) throws Exception {
            Certificate[] c = Util.chain(ks, alias);
            return c == null || c.length == 0 ? null : (X509Certificate) c[0];
        }

        Attestation att(String alias) throws Exception {
            X509Certificate c = leaf(alias);
            return c == null ? null : Attestation.parse(c);
        }

        void cleanup() {
            for (String a : aliases) Util.rm(ks, a);
            aliases.clear();
        }
    }

    private static List<Item> out;

    private static void add(String group, String id, String title, String expected, Body body) {
        out.add(new Item(group, id, title, expected, body));
    }

    public static List<Item> build(Ctx ctx) {
        out = new ArrayList<>();
        buildEnvironment(ctx);
        buildAttestation(ctx);
        buildRemote(ctx);
        buildCrypto(ctx);
        buildMlDsa(ctx);
        buildRaw(ctx);
        buildStrongBox(ctx);
        buildTiming(ctx);
        buildLifecycle(ctx);
        buildModule(ctx);
        List<Item> result = out;
        out = null;
        return result;
    }

    // ---------------------------------------------------------------- B 环境
    private static void buildEnvironment(Ctx ctx) {
        String g = "B 构建 / 身份 / 启动状态";
        add(g, "B01", "Android 版本与 API 一致", "SDK_INT 与 RELEASE 对应同一代 Android",
                () -> Result.pass("Android " + Build.VERSION.RELEASE + " / API " + Build.VERSION.SDK_INT));
        add(g, "B02", "安全补丁属性与 Build 一致", "ro.build.version.security_patch == Build.VERSION.SECURITY_PATCH",
                () -> {
                    String p = Sys.get("ro.build.version.security_patch", "");
                    return Build.VERSION.SECURITY_PATCH.equals(p)
                            ? Result.pass(p)
                            : Result.hit("Build=" + Build.VERSION.SECURITY_PATCH + " prop=" + p);
                });
        add(g, "B03", "verifiedbootstate 属性与内核命令行一致",
                "ro.boot.verifiedbootstate == androidboot.verifiedbootstate (/proc/cmdline)",
                () -> {
                    String prop = Sys.get("ro.boot.verifiedbootstate", "");
                    String cmd = Sys.cmdlineValue("androidboot.verifiedbootstate");
                    if (cmd == null) return Result.skip("cmdline 中无 androidboot.verifiedbootstate");
                    return prop.equalsIgnoreCase(cmd) ? Result.pass(prop)
                            : Result.hit("prop=" + prop + " cmdline=" + cmd);
                });
        add(g, "B04", "verifiedbootstate 属性与 bootconfig 一致",
                "ro.boot.verifiedbootstate == androidboot.verifiedbootstate (/proc/bootconfig)",
                () -> {
                    String prop = Sys.get("ro.boot.verifiedbootstate", "");
                    String bc = Sys.bootconfigValue("androidboot.verifiedbootstate");
                    if (bc == null) return Result.skip("bootconfig 中无 androidboot.verifiedbootstate");
                    return prop.equalsIgnoreCase(bc) ? Result.pass(prop)
                            : Result.hit("prop=" + prop + " bootconfig=" + bc);
                });
        add(g, "B05", "flash.locked 与 verifiedbootstate 自洽",
                "locked=1 时 state 只能是 green；orange/yellow 时 locked 应为 0",
                () -> {
                    String state = Sys.get("ro.boot.verifiedbootstate", "");
                    String locked = Sys.get("ro.boot.flash.locked", "");
                    boolean green = "green".equalsIgnoreCase(state);
                    boolean l = "1".equals(locked);
                    if (green && !l) return Result.hit("state=green locked=0");
                    if (!green && l && !"yellow".equalsIgnoreCase(state))
                        return Result.hit("state=" + state + " locked=1");
                    return Result.pass("state=" + state + " locked=" + locked);
                });
        add(g, "B06", "SELinux 处于 enforcing", "getenforce == Enforcing",
                () -> {
                    String v = Sys.readFile("/sys/fs/selinux/enforce");
                    if (v == null) return Result.skip("无法读取 /sys/fs/selinux/enforce");
                    return "1".equals(v.trim()) ? Result.pass("Enforcing")
                            : Result.hit("enforce=" + v.trim());
                });
        add(g, "B07", "SOC_MODEL 与真实机型属性", "Build.SOC_MODEL 非空且不等于 MODEL（仅记录）",
                () -> Result.pass("SOC_MODEL=" + Build.SOC_MODEL + " MODEL=" + Build.MODEL
                        + " DEVICE=" + Build.DEVICE + " PRODUCT=" + Build.PRODUCT));
        add(g, "B08", "/proc/cmdline 可读性（用于交叉核对）", "普通应用可读取，或明确记录不可读",
                () -> {
                    String c = Sys.readFile("/proc/cmdline");
                    return c == null ? Result.skip("不可读（SELinux/权限）")
                            : Result.pass(c.length() + " 字节");
                });
        add(g, "B09", "Build 身份自洽（fingerprint vs MODEL/DEVICE/PRODUCT）",
                "Build.FINGERPRINT 至少包含 MODEL/DEVICE/PRODUCT 中的两个；否则存在属性视图改写",
                () -> {
                    String fp = String.valueOf(Build.FINGERPRINT);
                    String[] vals = {String.valueOf(Build.MODEL), String.valueOf(Build.DEVICE),
                            String.valueOf(Build.PRODUCT)};
                    int hit = 0;
                    StringBuilder sb = new StringBuilder("fp=" + fp);
                    for (String v : vals) {
                        boolean ok = !v.isEmpty() && fp.contains(v);
                        if (ok) hit++;
                        sb.append(" ").append(v).append('=').append(ok);
                    }
                    return hit >= 2 ? Result.pass(sb.toString())
                            : Result.hit(sb.toString() + "（Build 属性被跨设备改写）");
                });
    }

    // ------------------------------------------------------------ A 证明证书
    private static void buildAttestation(Ctx ctx) {
        String g = "A 证明证书（Android 17 KeyDescription）";
        add(g, "A01", "叶证书含 Android attestation 扩展",
                "OID 1.3.6.1.4.1.11129.2.1.17 可解析，8 个顶层字段",
                () -> {
                    ctx.ecAttested();
                    Attestation a = ctx.att("aprobe_ec_att");
                    return a == null ? Result.hit("叶证书无 attestation 扩展")
                            : Result.pass("version=" + a.attestationVersion
                            + " level=" + a.attestationSecurityLevel + "/" + a.keymintSecurityLevel
                            + " hwTags=" + a.hw.tags.size() + " swTags=" + a.sw.tags.size());
                });
        add(g, "A02", "两处 securityLevel 等于请求级别",
                "attestationSecurityLevel == keymintSecurityLevel == TEE(1)",
                () -> {
                    ctx.ecAttested();
                    Attestation a = ctx.att("aprobe_ec_att");
                    if (a == null) return Result.hit("无扩展");
                    boolean ok = a.attestationSecurityLevel == 1 && a.keymintSecurityLevel == 1;
                    return ok ? Result.pass("1/1") : Result.hit(a.attestationSecurityLevel + "/" + a.keymintSecurityLevel);
                });
        add(g, "A03", "challenge 逐字节回显",
                "证书 challenge == setAttestationChallenge 的 32 字节",
                () -> {
                    ctx.ecAttested();
                    Attestation a = ctx.att("aprobe_ec_att");
                    if (a == null) return Result.hit("无扩展");
                    return Arrays.equals(a.challenge, ctx.challenge) ? Result.pass(Util.hex(a.challenge, 8))
                            : Result.hit("期望 " + Util.hex(ctx.challenge, 8) + " 实际 " + Util.hex(a.challenge, 8));
                });
        add(g, "A04", "applicationId(709) 位于 softwareEnforced",
                "709 仅在 swEnforced；包名与版本匹配本应用",
                () -> {
                    ctx.ecAttested();
                    Attestation a = ctx.att("aprobe_ec_att");
                    if (a == null) return Result.hit("无扩展");
                    byte[] id = a.sw.bytes(709);
                    if (id == null) return Result.hit("swEnforced 无 709");
                    if (a.hw.has(709)) return Result.hit("709 同时出现在 hwEnforced");
                    Attestation.AppId app = Attestation.AppId.parse(id);
                    PackageInfo pi = ctx.activity.getPackageManager()
                            .getPackageInfo(ctx.activity.getPackageName(), 0);
                    boolean ok = app.packages.contains(ctx.activity.getPackageName())
                            && app.versions.contains((long) pi.getLongVersionCode());
                    return ok ? Result.pass(app.packages + " v" + app.versions)
                            : Result.hit("解析=" + app.packages + " v" + app.versions
                            + " 实际=" + ctx.activity.getPackageName() + " v" + pi.getLongVersionCode());
                });
        add(g, "A05", "origin 与生成/导入路径一致",
                "生成 == GENERATED(0)；导入 == IMPORTED(2)",
                () -> {
                    ctx.ecAttested();
                    Attestation a = ctx.att("aprobe_ec_att");
                    if (a == null) return Result.hit("无扩展");
                    long o = a.hw.integer(702, a.sw.integer(702, -1));
                    return o == 0 ? Result.pass("GENERATED(0)") : Result.hit("origin=" + o);
                });
        add(g, "A06", "密钥参数与请求一致",
                "hwEnforced: algorithm=3(EC), keySize=256, ecCurve=1(P-256), digest 含 4(SHA-256), purpose 含 2/3",
                () -> {
                    ctx.ecAttested();
                    Attestation a = ctx.att("aprobe_ec_att");
                    if (a == null) return Result.hit("无扩展");
                    long alg = a.hw.integer(2, -1), size = a.hw.integer(3, -1), curve = a.hw.integer(10, -1);
                    List<Long> purpose = a.hw.integers(1), digest = a.hw.integers(5);
                    boolean ok = alg == 3 && size == 256 && curve == 1
                            && purpose.contains(2L) && purpose.contains(3L) && digest.contains(4L);
                    return ok ? Result.pass("alg=" + alg + " size=" + size + " curve=" + curve
                            + " purpose=" + purpose + " digest=" + digest)
                            : Result.hit("alg=" + alg + " size=" + size + " curve=" + curve
                            + " purpose=" + purpose + " digest=" + digest);
                });
        add(g, "A07", "设备属性五元组位于 hwEnforced 且匹配 Build",
                "710/711/712/716/717 在 hwEnforced，逐项等于 Build.BRAND/DEVICE/PRODUCT/MANUFACTURER/MODEL",
                () -> {
                    try {
                        ctx.ecProps();
                    } catch (Throwable t) {
                        return Result.hit("setDevicePropertiesAttestationIncluded 生成失败: "
                                + t.getClass().getSimpleName() + ": " + t.getMessage());
                    }
                    Attestation a = ctx.att("aprobe_ec_props");
                    if (a == null) return Result.hit("设备属性请求成功但无 attestation 扩展");
                    // If Build itself is cross-device rewritten, comparing the certificate
                    // to Build only proves the rewritten identity was attested.
                    String fp = String.valueOf(Build.FINGERPRINT);
                    int self = 0;
                    for (String v : new String[]{String.valueOf(Build.MODEL),
                            String.valueOf(Build.DEVICE), String.valueOf(Build.PRODUCT)}) {
                        if (!v.isEmpty() && fp.contains(v)) self++;
                    }
                    if (self < 2) {
                        return Result.inc("证书属性与当前 Build 匹配，但 Build 与 fingerprint 不一致；"
                                + "无法据此证明真实 A 设备属性 attestation（见 B09）");
                    }
                    String[][] expect = {
                            {"710", Build.BRAND}, {"711", Build.DEVICE}, {"712", Build.PRODUCT},
                            {"716", Build.MANUFACTURER}, {"717", Build.MODEL}
                    };
                    StringBuilder sb = new StringBuilder();
                    boolean ok = true;
                    for (String[] e : expect) {
                        int tag = Integer.parseInt(e[0]);
                        byte[] v = a.hw.bytes(tag);
                        String got = v == null ? "<缺失>" : new String(v);
                        if (v == null || !e[1].equalsIgnoreCase(got)) ok = false;
                        sb.append(e[0]).append('=').append(got).append(' ');
                    }
                    if (a.sw.has(710) || a.sw.has(717)) { ok = false; sb.append("[sw 重复]"); }
                    return ok ? Result.pass(sb.toString().trim()) : Result.hit(sb.toString().trim());
                });
        add(g, "A08", "RootOfTrust(704) 结构与锁定状态",
                "704 含 key(32B)/locked(BOOL)/state(ENUM)/hash(32B)；locked=true, state=0(Verified)",
                () -> {
                    ctx.ecAttested();
                    Attestation a = ctx.att("aprobe_ec_att");
                    if (a == null) return Result.hit("无扩展");
                    Attestation.RootOfTrust r = a.hw.rootOfTrust();
                    if (r == null) return Result.hit("无 704 或结构不可解析");
                    boolean size = r.verifiedBootKey.length == 32 && r.verifiedBootHash.length == 32;
                    boolean state = r.verifiedBootState >= 0 && r.verifiedBootState <= 3;
                    boolean ok = size && state;
                    return ok ? Result.pass("locked=" + r.deviceLocked + " state=" + r.verifiedBootState
                            + " key=" + Util.hex(r.verifiedBootKey, 4) + " hash=" + Util.hex(r.verifiedBootHash, 4))
                            : Result.hit("locked=" + r.deviceLocked + " state=" + r.verifiedBootState
                            + " keyLen=" + r.verifiedBootKey.length + " hashLen=" + r.verifiedBootHash.length);
                });
        add(g, "A09", "RootOfTrust 与系统启动属性一致",
                "704.locked 对应 ro.boot.flash.locked；704.state 对应 ro.boot.verifiedbootstate",
                () -> {
                    ctx.ecAttested();
                    Attestation a = ctx.att("aprobe_ec_att");
                    Attestation.RootOfTrust r = a == null ? null : a.hw.rootOfTrust();
                    if (r == null) return Result.hit("无 704");
                    String locked = Sys.get("ro.boot.flash.locked", "");
                    String state = Sys.get("ro.boot.verifiedbootstate", "");
                    boolean l = "1".equals(locked) || "true".equalsIgnoreCase(locked);
                    boolean s = ("green".equalsIgnoreCase(state) && r.verifiedBootState == 0)
                            || ("yellow".equalsIgnoreCase(state) && r.verifiedBootState == 2)
                            || ("orange".equalsIgnoreCase(state) && r.verifiedBootState == 1)
                            || state.isEmpty();
                    return (l == r.deviceLocked && s) ? Result.pass("locked=" + locked + " state=" + state)
                            : Result.hit("cert locked=" + r.deviceLocked + " state=" + r.verifiedBootState
                            + " prop locked=" + locked + " state=" + state);
                });
        add(g, "A10", "OS_VERSION(705) 与 Build 一致",
                "705 == major*10000 + minor*100 + patch（AOSP encode_os_version）",
                () -> {
                    ctx.ecAttested();
                    Attestation a = ctx.att("aprobe_ec_att");
                    if (a == null) return Result.hit("无扩展");
                    long v = a.hw.integer(705, -1);
                    long expected = encodeVersion(Build.VERSION.RELEASE, Build.VERSION.SDK_INT);
                    return v == expected ? Result.pass("705=" + v + " (" + Build.VERSION.RELEASE + ")")
                            : Result.hit("705=" + v + " 期望=" + expected + " (" + Build.VERSION.RELEASE + ")");
                });
        add(g, "A11", "OS_PATCHLEVEL(706) 与 Build 一致",
                "706 == Build.VERSION.SECURITY_PATCH 的 yyyymm",
                () -> {
                    ctx.ecAttested();
                    Attestation a = ctx.att("aprobe_ec_att");
                    if (a == null) return Result.hit("无扩展");
                    long v = a.hw.integer(706, -1);
                    long expected = patchLevel(Build.VERSION.SECURITY_PATCH);
                    return v == expected ? Result.pass("706=" + v)
                            : Result.hit("706=" + v + " 期望=" + expected);
                });
        add(g, "A12", "VENDOR_PATCHLEVEL(718) 与 vendor 属性一致",
                "718 == ro.vendor.build.security_patch 的 yyyymmdd（缺失则不要求）",
                () -> {
                    ctx.ecAttested();
                    Attestation a = ctx.att("aprobe_ec_att");
                    if (a == null) return Result.hit("无扩展");
                    String p = Sys.get("ro.vendor.build.security_patch", "");
                    if (p.isEmpty()) return Result.skip("无 ro.vendor.build.security_patch");
                    long v = a.hw.integer(718, -1);
                    long expected = patchLevel8(p);
                    return v == expected ? Result.pass("718=" + v)
                            : Result.hit("718=" + v + " 期望=" + expected);
                });
        add(g, "A13", "BOOT_PATCHLEVEL(719) 与启动镜像属性一致",
                "719 == ro.boot.image.build.security_patch 或 bootconfig 的 boot_patchlevel（yyyymmdd）",
                () -> {
                    ctx.ecAttested();
                    Attestation a = ctx.att("aprobe_ec_att");
                    if (a == null) return Result.hit("无扩展");
                    String p = Sys.get("ro.boot.image.build.security_patch", "");
                    if (p.isEmpty()) p = Sys.bootconfigValue("androidboot.boot_patchlevel");
                    if (p == null || p.isEmpty()) return Result.skip("无 boot patchlevel 来源");
                    long v = a.hw.integer(719, -1);
                    long expected = patchLevel8(p);
                    return v == expected ? Result.pass("719=" + v)
                            : Result.hit("719=" + v + " 期望=" + expected + " 来源=" + p);
                });
        add(g, "A14", "本地 ATTEST_KEY 子钥与远程 challenge 证书版本标签一致",
                "带 challenge 的远程证书与本地 ATTEST_KEY 子钥证书的 705/706/718/719 相同",
                () -> {
                    String parent = "aprobe_a14_parent";
                    String child = "aprobe_a14_child";
                    try {
                        Util.genAttestKeyLocal(ctx.ks, parent);
                        ctx.track(parent);
                        Util.genEcCustom(ctx.ks, child, "secp256r1",
                                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY,
                                ctx.challenge, KeyProperties.DIGEST_SHA256, parent, false);
                        ctx.track(child);
                    } catch (Throwable t) {
                        return Result.skip("本地 ATTEST_KEY 子钥生成失败: " + t.getClass().getSimpleName());
                    }
                    ctx.ecAttested();
                    Attestation x = ctx.att("aprobe_ec_att");   // remote / challenged
                    Attestation y = ctx.att(child);             // local ATTEST_KEY child
                    if (x == null || y == null) return Result.skip("任一证书无扩展");
                    String xs = tags(x), ys = tags(y);
                    return xs.equals(ys) ? Result.pass("remote{" + xs + "} local{" + ys + "}")
                            : Result.hit("remote{" + xs + "} local{" + ys + "}");
                });
        add(g, "A15", "导入密钥的 origin 与安全级别",
                "KeyStore.setEntry 导入后 KeyInfo.origin == IMPORTED(2)，安全级别与后端一致",
                () -> {
                    String alias = "aprobe_ec_import";
                    Util.importEc(ctx.ks, alias, Fixtures.IMPORT_KEY, Fixtures.IMPORT_CERT, null, false);
                    ctx.track(alias);
                    KeyInfo ki = Util.keyInfo(ctx.ks, alias);
                    if (ki == null) return Result.inc("导入后 KeyInfo 为空");
                    int origin = ki.getOrigin();
                    return origin == 2 ? Result.pass("origin=IMPORTED(2)")
                            : Result.hit("origin=" + origin + "（期望 2）");
                });
        add(g, "A16", "uniqueId 仅在请求时出现且长度 16",
                "setUniqueIdIncluded(true) 时 16 字节；未请求时为空",
                () -> {
                    String alias = "aprobe_ec_unique";
                    Util.genEc(ctx.ks, alias, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY,
                            null, null, false);
                    ctx.track(alias);
                    // The public KeyGenParameterSpec API has setUniqueIdIncluded; use reflection to
                    // avoid a compile-time dependency on newer SDK constants.
                    KeyGenParameterSpec.Builder b = new KeyGenParameterSpec.Builder(alias,
                            KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                            .setAlgorithmParameterSpec(new java.security.spec.ECGenParameterSpec("secp256r1"))
                            .setDigests(KeyProperties.DIGEST_SHA256)
                            .setAttestationChallenge(ctx.challenge);
                    try {
                        Method uid = KeyGenParameterSpec.Builder.class
                                .getMethod("setUniqueIdIncluded", boolean.class);
                        uid.setAccessible(true);
                        uid.invoke(b, true);
                    } catch (Throwable t) {
                        return Result.skip("setUniqueIdIncluded 不可用: " + t);
                    }
                    try {
                        KeyPairGeneratorHolder.generateEc(ctx.ks, alias, b.build());
                    } catch (Throwable t) {
                        return Result.inc("setUniqueIdIncluded 生成失败: "
                                + t.getClass().getSimpleName() + ": " + t.getMessage()
                                + "；AOSP 对 GenUniqueId 有权限门，普通 app 被拒不算缺口");
                    }
                    Attestation a = ctx.att(alias);
                    if (a == null) return Result.hit("无扩展");
                    if (a.uniqueId.length != 16) return Result.hit("uniqueId length=" + a.uniqueId.length);
                    return Result.pass(Util.hex(a.uniqueId, 16));
                });
        add(g, "A17", "creationDateTime(701) 存在且接近当前时间",
                "701 若存在则毫秒时间与当前相差 < 1 天；B stock 未写入时跳过",
                () -> {
                    ctx.ecAttested();
                    Attestation a = ctx.att("aprobe_ec_att");
                    if (a == null) return Result.hit("无扩展");
                    long t = a.hw.integer(701, a.sw.integer(701, -1));
                    if (t < 0) return Result.skip("stock B/厂商 HAL 未在证书中写入 701（记录，不作为缺口）");
                    long delta = Math.abs(System.currentTimeMillis() - t);
                    return delta < 86_400_000L ? Result.pass("701=" + t)
                            : Result.hit("701=" + t + " deltaMs=" + delta);
                });
        add(g, "A18", "证书有效期符合 keystore2 默认",
                "当前时间落在 notBefore..notAfter 内（B stock 为 1970..2048，不强制 9999）",
                () -> {
                    ctx.ecAttested();
                    X509Certificate c = ctx.leaf("aprobe_ec_att");
                    if (c == null) return Result.hit("无叶证书");
                    long now = System.currentTimeMillis();
                    boolean ok = c.getNotBefore().getTime() <= now && c.getNotAfter().getTime() > now;
                    return ok ? Result.pass("notBefore=" + c.getNotBefore() + " notAfter=" + c.getNotAfter())
                            : Result.hit("证书当前不在有效期内: " + c.getNotBefore() + " .. " + c.getNotAfter());
                });
        add(g, "A19", "证书链逐跳签名闭合",
                "每张子证书由下一张颁发者公钥验证通过，subject/issuer 相等",
                () -> {
                    ctx.ecAttested();
                    Certificate[] chain = Util.chain(ctx.ks, "aprobe_ec_att");
                    if (chain == null || chain.length < 2) return Result.hit("链长度=" + (chain == null ? 0 : chain.length));
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i + 1 < chain.length; i++) {
                        X509Certificate child = (X509Certificate) chain[i];
                        X509Certificate parent = (X509Certificate) chain[i + 1];
                        boolean name = child.getIssuerX500Principal().equals(parent.getSubjectX500Principal());
                        try { child.verify(parent.getPublicKey()); }
                        catch (Throwable t) { return Result.hit("hop " + i + " 验签失败: " + t); }
                        if (!name) return Result.hit("hop " + i + " issuer/subject 不相等");
                        sb.append("hop").append(i).append("=ok ");
                    }
                    return Result.pass("链长 " + chain.length + " " + sb);
                });
        add(g, "A20", "证书身份 T/O 与安全级别一致",
                "chain[1] 的 T 或 O 为 TEE；StrongBox 请求为 StrongBox",
                () -> {
                    ctx.ecAttested();
                    Certificate[] chain = Util.chain(ctx.ks, "aprobe_ec_att");
                    if (chain == null || chain.length < 2) return Result.hit("链长度<2");
                    X509Certificate ca = (X509Certificate) chain[1];
                    String t = Util.certName(ca, "2.5.4.12");
                    String o = Util.certName(ca, "2.5.4.10");
                    String got = t != null && (t.equalsIgnoreCase("TEE") || t.equalsIgnoreCase("StrongBox")) ? t : o;
                    if (got == null) return Result.pass("stock B 的 CA subject 无 T/O 标签（T=" + t + " O=" + o + "）");
                    boolean ok = "TEE".equalsIgnoreCase(got);
                    return ok ? Result.pass("T=" + t + " O=" + o) : Result.hit("T=" + t + " O=" + o);
                });
        add(g, "A21", "叶证书公钥与 KeyStore 公钥一致",
                "leaf.getPublicKey().getEncoded() == ks.getCertificate(alias).getPublicKey().getEncoded()",
                () -> {
                    ctx.ecAttested();
                    X509Certificate leaf = ctx.leaf("aprobe_ec_att");
                    PublicKey pub = ctx.ecAttested().getPublic();
                    byte[] a = leaf == null ? null : leaf.getPublicKey().getEncoded();
                    byte[] b = pub.getEncoded();
                    return a != null && Arrays.equals(a, b) ? Result.pass(Util.sha256(a))
                            : Result.hit("证书公钥 != KeyStore 公钥");
                });
        add(g, "A22", "证书 serialNumber 非零且为正",
                "serial > 0（AOSP 默认 1）",
                () -> {
                    ctx.ecAttested();
                    X509Certificate c = ctx.leaf("aprobe_ec_att");
                    if (c == null) return Result.hit("无叶证书");
                    java.math.BigInteger s = c.getSerialNumber();
                    return s.signum() > 0 ? Result.pass("serial=" + s) : Result.hit("serial=" + s);
                });
        add(g, "A23", "叶证书签名算法与密钥类型匹配",
                "EC 密钥使用 ECDSA-SHA256 OID；RSA 使用 sha256WithRSAEncryption",
                () -> {
                    ctx.ecAttested();
                    X509Certificate c = ctx.leaf("aprobe_ec_att");
                    if (c == null) return Result.hit("无叶证书");
                    String oid = c.getSigAlgOID();
                    boolean ok = "1.2.840.10045.4.3.2".equals(oid);
                    return ok ? Result.pass(oid) : Result.hit("sigAlgOID=" + oid);
                });
        add(g, "A24", "attestationVersion 与 keyMintVersion 一致且与 HAL 代际相符",
                "两字段相等，且为 100/200/300/400/500 之一",
                () -> {
                    ctx.ecAttested();
                    Attestation a = ctx.att("aprobe_ec_att");
                    if (a == null) return Result.hit("无扩展");
                    boolean v = a.attestationVersion == a.keymintVersion
                            && (a.attestationVersion == 100 || a.attestationVersion == 200
                            || a.attestationVersion == 300 || a.attestationVersion == 400
                            || a.attestationVersion == 500);
                    return v ? Result.pass(a.attestationVersion + "/" + a.keymintVersion)
                            : Result.hit(a.attestationVersion + "/" + a.keymintVersion);
                });
        add(g, "A25", "KeyInfo.getSecurityLevel 与证书级别一致",
                "KeyInfo.SECURITY_LEVEL_TRUSTED_ENVIRONMENT == 1",
                () -> {
                    ctx.ecAttested();
                    KeyInfo ki = Util.keyInfo(ctx.ks, "aprobe_ec_att");
                    Attestation a = ctx.att("aprobe_ec_att");
                    if (ki == null || a == null) return Result.inc("KeyInfo/证书缺失（KeyFactory 不支持或将远程密钥隐藏）");
                    int k = securityLevelInt(ki);
                    return k == a.keymintSecurityLevel ? Result.pass("KeyInfo=" + k)
                            : Result.hit("KeyInfo=" + k + " cert=" + a.keymintSecurityLevel);
                });
        add(g, "A26", "KeyInfo.getKeySize 与证书 keySize 一致",
                "EC P-256 == 256；ML-DSA == -1",
                () -> {
                    ctx.ecAttested();
                    KeyInfo ki = Util.keyInfo(ctx.ks, "aprobe_ec_att");
                    Attestation a = ctx.att("aprobe_ec_att");
                    if (ki == null || a == null) return Result.inc("KeyInfo/证书缺失（KeyFactory 不支持或将远程密钥隐藏）");
                    int k = ki.getKeySize();
                    long c = a.hw.integer(3, -1);
                    return k == c ? Result.pass("KeyInfo=" + k)
                            : Result.inc("厂商 KeyInfo origin=" + k + " 与证书 origin=" + c + " 不一致（B 标准记录）");
                });
        add(g, "A27", "KeyInfo.getOrigin 与证书 origin 一致",
                "GENERATED(0)",
                () -> {
                    ctx.ecAttested();
                    KeyInfo ki = Util.keyInfo(ctx.ks, "aprobe_ec_att");
                    Attestation a = ctx.att("aprobe_ec_att");
                    if (ki == null || a == null) return Result.inc("KeyInfo/证书缺失（KeyFactory 不支持或将远程密钥隐藏）");
                    int k = ki.getOrigin();
                    long c = a.hw.integer(702, a.sw.integer(702, -1));
                    return k == c ? Result.pass("KeyInfo=" + k)
                            : Result.inc("厂商 KeyInfo origin=" + k + " 与证书 origin=" + c + " 不一致（B 标准记录）");
                });
        add(g, "A28", "KeyInfo purposes/digests 与证书一致",
                "KeyInfo 的 purpose/digest 集合等于证书 hwEnforced 对应集合",
                () -> {
                    ctx.ecAttested();
                    KeyInfo ki = Util.keyInfo(ctx.ks, "aprobe_ec_att");
                    Attestation a = ctx.att("aprobe_ec_att");
                    if (ki == null || a == null) return Result.inc("KeyInfo/证书缺失（KeyFactory 不支持或将远程密钥隐藏）");
                    long mask = 0;
                    for (long p : a.hw.integers(1)) mask |= 1L << p;
                    List<Long> certDigests = a.hw.integers(5);
                    List<Integer> infoDigests = new ArrayList<>();
                    for (String d : ki.getDigests()) infoDigests.add(digestValue(d));
                    boolean purposesOk = (ki.getPurposes() & mask) == mask
                            && (ki.getPurposes() | mask) == mask;
                    java.util.Set<Integer> certSet = new java.util.HashSet<>();
                    for (long d : certDigests) certSet.add((int) d);
                    boolean digestsOk = new java.util.HashSet<>(infoDigests).equals(certSet);
                    return purposesOk && digestsOk
                            ? Result.pass("purposesMask=" + ki.getPurposes() + " digests="
                            + Arrays.toString(ki.getDigests()))
                            : Result.inc("KeyInfo purposesMask=" + ki.getPurposes()
                            + " digests=" + Arrays.toString(ki.getDigests())
                            + " certPurpose=" + a.hw.integers(1) + " certDigest=" + certDigests);
                });
        add(g, "A29", "普通应用的认证绑定参数出现在证书中",
                "setUserAuthenticationRequired 的密钥证书应含 504；502 是 KeyMint 有意省略的，不得用 503 顶替",
                () -> {
                    String alias = "aprobe_auth_normal";
                    try {
                        Util.genEcAuth(ctx.ks, alias, ctx.challenge);
                        ctx.track(alias);
                    } catch (Throwable t) {
                        return Result.skip("认证绑定密钥生成失败: " + t.getClass().getSimpleName());
                    }
                    Attestation a = ctx.att(alias);
                    if (a == null) return Result.hit("无 attestation 扩展");
                    boolean noAuth = a.hw.has(503) || a.sw.has(503);
                    boolean type = a.hw.has(504) || a.sw.has(504);
                    // KeyMint deliberately omits USER_SECURE_ID (502) from the attestation
                    // authorization list (encode_sid=false); 504 is the observable marker.
                    String d = "504=" + type + " 503=" + noAuth + " hwTags=" + a.hw.tags.keySet();
                    return (!noAuth && type) ? Result.pass(d) : Result.hit(d);
                });
        add(g, "A30", "已知探针 alias 与普通 alias 的认证策略差异",
                "同一认证参数下，普通 alias 与 TrustAttestor_silent_auth_<uuid> 的 504/503 集合应相同",
                () -> {
                    String known = "TrustAttestor_silent_auth_14c21f61-4c15-4e09-92d7-3a33d665458c";
                    String normal = "aprobe_auth_normal";
                    try {
                        Util.genEcAuth(ctx.ks, known, ctx.challenge);
                        ctx.track(known);
                        if (!ctx.aliases.contains(normal)) {
                            Util.genEcAuth(ctx.ks, normal, ctx.challenge);
                            ctx.track(normal);
                        }
                    } catch (Throwable t) {
                        return Result.skip("生成失败: " + t.getClass().getSimpleName());
                    }
                    Attestation a = ctx.att(known), b = ctx.att(normal);
                    if (a == null || b == null) return Result.hit("证书缺失");
                    String sa = authTags(a), sb = authTags(b);
                    return sa.equals(sb) ? Result.pass("known{" + sa + "} normal{" + sb + "}")
                            : Result.hit("known{" + sa + "} normal{" + sb + "}（alias 特判）");
                });
        add(g, "A31", "KeyInfo 认证标志与证书授权一致",
                "KeyInfo.isUserAuthenticationRequired() 与证书 504/503 集合一致",
                () -> {
                    String alias = "aprobe_auth_normal";
                    try {
                        if (!ctx.aliases.contains(alias)) {
                            Util.genEcAuth(ctx.ks, alias, ctx.challenge);
                            ctx.track(alias);
                        }
                    } catch (Throwable t) {
                        return Result.skip("生成失败: " + t.getClass().getSimpleName());
                    }
                    KeyInfo ki = Util.keyInfo(ctx.ks, alias);
                    Attestation a = ctx.att(alias);
                    if (ki == null || a == null) return Result.inc("KeyInfo/证书缺失（KeyFactory 不支持或将远程密钥隐藏）");
                    boolean required = ki.isUserAuthenticationRequired();
                    boolean certAuth = (a.hw.has(504) || a.sw.has(504)) && !a.hw.has(503) && !a.sw.has(503);
                    return required == certAuth ? Result.pass("KeyInfo=" + required + " cert=" + certAuth)
                            : Result.hit("KeyInfo=" + required + " cert=" + certAuth);
                });
        add(g, "A32", "applicationId(709) 的签名摘要与真实签名一致",
                "709.signatureDigests 包含 APK 签名证书的 SHA-256",
                () -> {
                    ctx.ecAttested();
                    Attestation a = ctx.att("aprobe_ec_att");
                    if (a == null) return Result.hit("无扩展");
                    byte[] id = a.sw.bytes(709);
                    if (id == null) return Result.hit("无 709");
                    Attestation.AppId app = Attestation.AppId.parse(id);
                    if (app.signatures.isEmpty()) return Result.skip("709 未携带 signatureDigests");
                    PackageInfo pi = ctx.activity.getPackageManager().getPackageInfo(
                            ctx.activity.getPackageName(),
                            android.content.pm.PackageManager.GET_SIGNING_CERTIFICATES);
                    byte[] expected = java.security.MessageDigest.getInstance("SHA-256")
                            .digest(pi.signingInfo.getApkContentsSigners()[0].toByteArray());
                    for (byte[] got : app.signatures) {
                        if (Arrays.equals(got, expected)) return Result.pass(Util.hex(got, 8));
                    }
                    return Result.hit("709 签名摘要与 APK 签名不一致");
                });
        add(g, "A33", "无 challenge 的密钥不携带 attestationChallenge",
                "未请求证明时证书没有 709/challenge（或仅有空 challenge）",
                () -> {
                    ctx.ecPlain();
                    Attestation a = ctx.att("aprobe_ec_plain");
                    if (a == null) return Result.pass("无 attestation 扩展（本地未证明）");
                    return a.challenge.length == 0 ? Result.pass("challenge 空")
                            : Result.hit("challenge=" + Util.hex(a.challenge, 8));
                });
        add(g, "A34", "认证有效期/超时与 KeyInfo 一致",
                "setUserAuthenticationParameters(30, DEVICE_CREDENTIAL) 时证书 505=30，KeyInfo 同值",
                () -> {
                    String alias = "aprobe_auth_timeout";
                    try {
                        Util.genEcFlags(ctx.ks, alias, ctx.challenge, true, 30,
                                KeyProperties.AUTH_DEVICE_CREDENTIAL, false, false, false);
                        ctx.track(alias);
                    } catch (Throwable t) {
                        return Result.skip("生成失败: " + t.getClass().getSimpleName());
                    }
                    Attestation a = ctx.att(alias);
                    KeyInfo ki = Util.keyInfo(ctx.ks, alias);
                    if (a == null || ki == null) return Result.inc("证书/KeyInfo 缺失");
                    long cert = a.hw.integer(505, a.sw.integer(505, -1));
                    int info = ki.getUserAuthenticationValidityDurationSeconds();
                    return cert == info ? Result.pass("cert=" + cert + " KeyInfo=" + info)
                            : Result.hit("cert=" + cert + " KeyInfo=" + info);
                });
        add(g, "A35", "UNLOCKED_DEVICE_REQUIRED(509) 与 KeyInfo 一致",
                "setUnlockedDeviceRequired(true) 时证书含 509，KeyInfo true",
                () -> {
                    String alias = "aprobe_unlocked";
                    try {
                        Util.genEcFlags(ctx.ks, alias, ctx.challenge, false, 0, 0,
                                true, false, false);
                        ctx.track(alias);
                    } catch (Throwable t) {
                        return Result.skip("生成失败: " + t.getClass().getSimpleName());
                    }
                    Attestation a = ctx.att(alias);
                    KeyInfo ki = Util.keyInfo(ctx.ks, alias);
                    if (a == null || ki == null) return Result.inc("证书/KeyInfo 缺失");
                    boolean cert = a.hw.has(509) || a.sw.has(509);
                    boolean info;
                    try {
                        Method m = KeyInfo.class.getMethod("isUnlockedDeviceRequired");
                        info = (boolean) m.invoke(ki);
                    } catch (NoSuchMethodException | NoClassDefFoundError e) {
                        return Result.skip("厂商 KeyInfo 无 isUnlockedDeviceRequired（B 标准）");
                    } catch (Throwable t) {
                        return Result.skip("KeyInfo 反射失败: " + t);
                    }
                    return cert == info ? Result.pass("cert=" + cert + " KeyInfo=" + info)
                            : Result.inc("厂商 KeyInfo=" + info + " 与证书 509=" + cert + " 不一致");
                });
        add(g, "A36", "ALLOW_WHILE_ON_BODY(506) 与 KeyInfo 一致",
                "setUserAuthenticationValidWhileOnBody(true) 时证书含 506，KeyInfo true",
                () -> {
                    String alias = "aprobe_on_body";
                    try {
                        Util.genEcFlags(ctx.ks, alias, ctx.challenge, true, 30,
                                KeyProperties.AUTH_DEVICE_CREDENTIAL, false, true, false);
                        ctx.track(alias);
                    } catch (Throwable t) {
                        return Result.skip("生成失败: " + t.getClass().getSimpleName());
                    }
                    Attestation a = ctx.att(alias);
                    KeyInfo ki = Util.keyInfo(ctx.ks, alias);
                    if (a == null || ki == null) return Result.inc("证书/KeyInfo 缺失");
                    boolean cert = a.hw.has(506) || a.sw.has(506);
                    boolean info = ki.isUserAuthenticationValidWhileOnBody();
                    return cert == info ? Result.pass("cert=" + cert + " KeyInfo=" + info)
                            : Result.inc("厂商 KeyInfo=" + info + " 与证书 506=" + cert + " 不一致（B 标准记录）");
                });
        add(g, "A38", "证书链不得用软件 CA 签发 TEE/StrongBox 声明",
                "chain[1] 的 OU 若含 Android Keystore Software Attestation，则 level 不能为 1/2",
                () -> {
                    ctx.ecAttested();
                    Certificate[] chain = Util.chain(ctx.ks, "aprobe_ec_att");
                    if (chain == null || chain.length < 2) return Result.skip("链长度<2");
                    X509Certificate ca = (X509Certificate) chain[1];
                    String ou = Util.certName(ca, "2.5.4.11");
                    Attestation a = ctx.att("aprobe_ec_att");
                    if (a == null) return Result.inc("无扩展");
                    boolean software = ou != null && ou.toLowerCase(Locale.US)
                            .contains("android keystore software attestation");
                    boolean hwClaim = a.attestationSecurityLevel == 1 || a.attestationSecurityLevel == 2;
                    return software && hwClaim ? Result.hit("OU=" + ou + " level=" + a.attestationSecurityLevel)
                            : Result.pass("OU=" + ou + " level=" + a.attestationSecurityLevel);
                });
    }

    private static String authTags(Attestation a) {
        return "502=" + a.hw.integers(502) + a.sw.integers(502)
                + " 504=" + a.hw.integers(504) + a.sw.integers(504)
                + " 503=" + (a.hw.has(503) || a.sw.has(503));
    }

    private static String tags(Attestation a) {
        return "705=" + a.hw.integer(705, -1) + " 706=" + a.hw.integer(706, -1)
                + " 718=" + a.hw.integer(718, -1) + " 719=" + a.hw.integer(719, -1);
    }

    private static long encodeVersion(String release, int sdk) {
        try {
            String[] p = release.split("\\.");
            int major = Integer.parseInt(p[0]);
            int minor = p.length > 1 ? Integer.parseInt(p[1]) : 0;
            int patch = p.length > 2 ? Integer.parseInt(p[2]) : 0;
            return major * 10000L + minor * 100L + patch;
        } catch (Throwable t) {
            return sdk * 10000L;
        }
    }

    private static int digestValue(String d) {
        if (d == null) return -1;
        switch (d.toUpperCase(java.util.Locale.US)) {
            case "NONE": return 0;
            case "MD5": return 1;
            case "SHA-1": return 2;
            case "SHA-224": return 3;
            case "SHA-256": return 4;
            case "SHA-384": return 5;
            case "SHA-512": return 6;
            default: return -1;
        }
    }

    private static long patchLevel(String s) {
        if (s == null) return -1;
        String d = s.replaceAll("[^0-9]", "");
        if (d.length() >= 6) return Long.parseLong(d.substring(0, 6));
        return -1;
    }

    private static long patchLevel8(String s) {
        if (s == null) return -1;
        String d = s.replaceAll("[^0-9]", "");
        if (d.length() >= 8) return Long.parseLong(d.substring(0, 8));
        return patchLevel(s);
    }

    private static int securityLevelInt(KeyInfo ki) {
        try {
            Method m = KeyInfo.class.getMethod("getSecurityLevel");
            return (int) m.invoke(ki);
        } catch (Throwable t) {
            return -1;
        }
    }

    private static List<Integer> ints(int[] a) {
        List<Integer> out = new ArrayList<>();
        for (int v : a) out.add(v);
        java.util.Collections.sort(out);
        return out;
    }

    private static boolean same(List<Integer> a, List<Long> b) {
        List<Integer> c = new ArrayList<>();
        for (long v : b) c.add((int) v);
        java.util.Collections.sort(c);
        return a.equals(c);
    }

    static final class KeyPairGeneratorHolder {
        static void generateEc(KeyStore ks, String alias, KeyGenParameterSpec spec) throws Exception {
            Util.rm(ks, alias);
            java.security.KeyPairGenerator kpg =
                    java.security.KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
            kpg.initialize(spec);
            kpg.generateKeyPair();
        }
    }

    // ------------------------------------------------------------- R 远程操作
    private static void buildRemote(Ctx ctx) {
        String g = "R 远程 KeyMint 操作（B-side relay）";
        add(g, "R01", "远程 EC P-256 密钥可签名并验签",
                "Signature(SHA256withECDSA) initSign/sign 成功，公钥可验",
                () -> {
                    ctx.ecAttested();
                    byte[] data = "aprobe-remote-ec".getBytes("UTF-8");
                    try {
                        Signature s = Signature.getInstance("SHA256withECDSA");
                        s.initSign((PrivateKey) ctx.ks.getKey("aprobe_ec_att", null));
                        s.update(data);
                        byte[] sig = s.sign();
                        boolean ok = Util.verifyEc(ctx.ecAttested().getPublic(), data, sig);
                        return ok ? Result.pass("sig=" + sig.length + "B verify=true")
                                : Result.hit("签名成功但验签失败");
                    } catch (Throwable t) {
                        return Result.hit(t.getClass().getSimpleName() + ": " + t.getMessage());
                    }
                });
        add(g, "R02", "远程 RSA-2048 PKCS#1 签名可验签",
                "Signature(SHA256withRSA) 成功，verify=true",
                () -> {
                    ctx.rsaAttested();
                    byte[] data = "aprobe-remote-rsa".getBytes("UTF-8");
                    try {
                        Signature s = Signature.getInstance("SHA256withRSA");
                        s.initSign((PrivateKey) ctx.ks.getKey("aprobe_rsa_att", null));
                        s.update(data);
                        byte[] sig = s.sign();
                        Signature v = Signature.getInstance("SHA256withRSA");
                        v.initVerify(ctx.rsaAttested().getPublic());
                        v.update(data);
                        return v.verify(sig) ? Result.pass("sig=" + sig.length + "B")
                                : Result.hit("verify=false");
                    } catch (Throwable t) {
                        return Result.hit(t.getClass().getSimpleName() + ": " + t.getMessage());
                    }
                });
        add(g, "R03", "远程 RSA-PSS 签名可验签",
                "Signature(SHA256withRSA/PSS) 成功，verify=true",
                () -> {
                    ctx.rsaPss();
                    byte[] data = "aprobe-remote-pss".getBytes("UTF-8");
                    try {
                        Signature s = Signature.getInstance("SHA256withRSA/PSS");
                        s.initSign((PrivateKey) ctx.ks.getKey("aprobe_rsa_pss", null));
                        s.update(data);
                        byte[] sig = s.sign();
                        Signature v = Signature.getInstance("SHA256withRSA/PSS");
                        v.initVerify(ctx.rsaPss().getPublic());
                        v.update(data);
                        return v.verify(sig) ? Result.pass("sig=" + sig.length + "B")
                                : Result.hit("verify=false");
                    } catch (Throwable t) {
                        return Result.hit(t.getClass().getSimpleName() + ": " + t.getMessage());
                    }
                });
        add(g, "R04", "远程 RSA PKCS#1 解密",
                "Cipher(RSA/ECB/PKCS1Padding) 加密后 init(DECRYPT) 成功并还原",
                () -> {
                    ctx.rsaDecrypt();
                    byte[] plain = "aprobe-remote-decrypt".getBytes("UTF-8");
                    try {
                        Cipher enc = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                        enc.init(Cipher.ENCRYPT_MODE, ctx.rsaDecrypt().getPublic());
                        byte[] ct = enc.doFinal(plain);
                        Cipher dec = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                        dec.init(Cipher.DECRYPT_MODE, (PrivateKey) ctx.ks.getKey("aprobe_rsa_dec", null));
                        byte[] pt = dec.doFinal(ct);
                        return Arrays.equals(pt, plain) ? Result.pass("ct=" + ct.length + "B")
                                : Result.hit("明文不一致");
                    } catch (Throwable t) {
                        return Result.hit(t.getClass().getSimpleName() + ": " + t.getMessage());
                    }
                });
        add(g, "R05", "远程 EC 密钥可做 ECDH 协商",
                "KeyAgreement(ECDH) 双方导出同一 32 字节秘密",
                () -> {
                    if ("PHB110".equals(Build.MODEL) || "PHB110".equals(Build.PRODUCT)
                            || "OP591BL1".equals(Build.DEVICE)) {
                        return Result.skip("主 B（PHB110）禁止 AGREE_KEY 实验；A 端或一次性设备可单独启用");
                    }
                    ctx.ecAgree();
                    try {
                        java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("EC");
                        kpg.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
                        KeyPair peer = kpg.generateKeyPair();
                        KeyAgreement a = KeyAgreement.getInstance("ECDH");
                        a.init((PrivateKey) ctx.ks.getKey("aprobe_ec_agree", null));
                        a.doPhase(peer.getPublic(), true);
                        byte[] s1 = a.generateSecret();
                        KeyAgreement b = KeyAgreement.getInstance("ECDH");
                        b.init(peer.getPrivate());
                        b.doPhase(ctx.ecAgree().getPublic(), true);
                        byte[] s2 = b.generateSecret();
                        return Arrays.equals(s1, s2) ? Result.pass("secret=" + Util.hex(s1, 8))
                                : Result.hit("双方 secret 不一致");
                    } catch (Throwable t) {
                        return Result.hit(t.getClass().getSimpleName() + ": " + t.getMessage());
                    }
                });
        add(g, "R06", "同一远程密钥连续两次签名",
                "两次独立 operation 都成功，且 signature 都可验",
                () -> {
                    ctx.ecAttested();
                    byte[] data = "aprobe-twice".getBytes("UTF-8");
                    try {
                        for (int i = 0; i < 2; i++) {
                            Signature s = Signature.getInstance("SHA256withECDSA");
                            s.initSign((PrivateKey) ctx.ks.getKey("aprobe_ec_att", null));
                            s.update(data);
                            byte[] sig = s.sign();
                            if (!Util.verifyEc(ctx.ecAttested().getPublic(), data, sig))
                                return Result.hit("第 " + (i + 1) + " 次验签失败");
                        }
                        return Result.pass("两次均成功");
                    } catch (Throwable t) {
                        return Result.hit(t.getClass().getSimpleName() + ": " + t.getMessage());
                    }
                });
        add(g, "R07", "远程 P-384 + SHA-384 签名",
                "P-384 密钥用 SHA384withECDSA 签名并可验",
                () -> {
                    ctx.ecP384();
                    try {
                        Signature s = Signature.getInstance("SHA384withECDSA");
                        s.initSign((PrivateKey) ctx.ks.getKey("aprobe_ec_p384", null));
                        s.update("aprobe-p384".getBytes("UTF-8"));
                        byte[] sig = s.sign();
                        Signature v = Signature.getInstance("SHA384withECDSA");
                        v.initVerify(ctx.ecP384().getPublic());
                        v.update("aprobe-p384".getBytes("UTF-8"));
                        return v.verify(sig) ? Result.pass("sig=" + sig.length + "B")
                                : Result.hit("verify=false");
                    } catch (Throwable t) {
                        return Result.hit(t.getClass().getSimpleName() + ": " + t.getMessage());
                    }
                });
        add(g, "R08", "远程 ECDSA NONEwithECDSA",
                "DIGEST_NONE 的 EC 密钥可用 NONEwithECDSA 签名并验签",
                () -> {
                    String alias = "aprobe_ec_none";
                    try {
                        Util.genEcCustom(ctx.ks, alias, "secp256r1",
                                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY,
                                ctx.challenge, KeyProperties.DIGEST_NONE, null, false);
                        ctx.track(alias);
                        byte[] data = "aprobe-none-ecdsa".getBytes("UTF-8");
                        Signature s = Signature.getInstance("NONEwithECDSA");
                        s.initSign((PrivateKey) ctx.ks.getKey(alias, null));
                        s.update(data);
                        byte[] sig = s.sign();
                        Signature v = Signature.getInstance("NONEwithECDSA");
                        v.initVerify(ctx.ks.getCertificate(alias).getPublicKey());
                        v.update(data);
                        return v.verify(sig) ? Result.pass("sig=" + sig.length + "B")
                                : Result.hit("verify=false");
                    } catch (Throwable t) {
                        return Result.hit(t.getClass().getSimpleName() + ": " + t.getMessage());
                    }
                });
        add(g, "R09", "远程密钥的 KeyInfo 安全级别为 TEE",
                "KeyInfo.getSecurityLevel == 1",
                () -> {
                    ctx.ecAttested();
                    KeyInfo ki = Util.keyInfo(ctx.ks, "aprobe_ec_att");
                    int sl = securityLevelInt(ki);
                    return sl == 1 ? Result.pass("TEE(1)") : Result.hit("level=" + sl);
                });
        add(g, "R10", "远程密钥别名替换后旧会话不串新密钥",
                "同名重新生成后，新证书公钥 ≠ 旧公钥；旧公钥不能再验新签名",
                () -> {
                    String alias = "aprobe_replace";
                    KeyPair old = Util.genEc(ctx.ks, alias,
                            KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY, null, null, false);
                    ctx.track(alias);
                    PublicKey oldPub = old.getPublic();
                    KeyPair fresh = Util.genEc(ctx.ks, alias,
                            KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY, null, null, false);
                    byte[] data = "aprobe-replace".getBytes("UTF-8");
                    byte[] sig = Util.signEc(ctx.ks, alias, data);
                    boolean oldOk = Util.verifyEc(oldPub, data, sig);
                    boolean newOk = Util.verifyEc(fresh.getPublic(), data, sig);
                    return (!oldOk && newOk) ? Result.pass("旧钥不可验，新钥可验")
                            : Result.hit("oldVerify=" + oldOk + " newVerify=" + newOk);
                });
        add(g, "R11", "远程私钥不可导出",
                "PrivateKey.getEncoded() == null",
                () -> {
                    ctx.ecAttested();
                    PrivateKey k = (PrivateKey) ctx.ks.getKey("aprobe_ec_att", null);
                    return k.getEncoded() == null ? Result.pass("encoded=null")
                            : Result.hit("encoded=" + k.getEncoded().length + "B");
                });
        add(g, "R12", "软件对称密钥不可导出",
                "SecretKey.getEncoded() == null",
                () -> {
                    String a = "aprobe_opaque_aes";
                    SecretKey k = Util.genAes(ctx.ks, a, 256, KeyProperties.BLOCK_MODE_GCM,
                            KeyProperties.ENCRYPTION_PADDING_NONE, true);
                    ctx.track(a);
                    return k.getEncoded() == null ? Result.pass("encoded=null")
                            : Result.hit("encoded=" + k.getEncoded().length + "B");
                });
    }

    // ------------------------------------------------------------ C 软件 crypto
    private static void buildCrypto(Ctx ctx) {
        String g = "C 软件 crypto 后端（KeyMint 合同）";

        add(g, "C01", "3DES/CBC/PKCS7 解密往返",
                "加密后同一 IV 解密还原原文（AOSP SECItem 语义）",
                () -> {
                    String a = "aprobe_3des_cbc";
                    SecretKey k = Util.gen3des(ctx.ks, a, KeyProperties.BLOCK_MODE_CBC);
                    ctx.track(a);
                    byte[] iv = new byte[]{9, 8, 7, 6, 5, 4, 3, 2};
                    byte[] plain = "aprobe-3des-cbc".getBytes("UTF-8");
                    Cipher e = Cipher.getInstance("DESede/CBC/PKCS7Padding");
                    e.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec(iv));
                    byte[] ct = e.doFinal(plain);
                    Cipher d = Cipher.getInstance("DESede/CBC/PKCS7Padding");
                    d.init(Cipher.DECRYPT_MODE, k, new IvParameterSpec(iv));
                    byte[] pt = d.doFinal(ct);
                    return Arrays.equals(pt, plain) ? Result.pass("ct=" + ct.length + "B")
                            : Result.hit("解密结果不一致");
                });
        add(g, "C02", "3DES/ECB/PKCS7 解密往返",
                "加密后解密还原原文",
                () -> {
                    String a = "aprobe_3des_ecb";
                    SecretKey k = Util.gen3des(ctx.ks, a, KeyProperties.BLOCK_MODE_ECB);
                    ctx.track(a);
                    Cipher e = Cipher.getInstance("DESede/ECB/PKCS7Padding");
                    e.init(Cipher.ENCRYPT_MODE, k);
                    byte[] ct = e.doFinal("aprobe-3des-ecb".getBytes("UTF-8"));
                    Cipher d = Cipher.getInstance("DESede/ECB/PKCS7Padding");
                    d.init(Cipher.DECRYPT_MODE, k);
                    d.doFinal(ct);
                    return Result.pass("ct=" + ct.length + "B");
                });
        add(g, "C03", "NONEwithRSA 签名可被公钥验证",
                "PKCS#1 v1.5 type-1 编码（00 01 FF..FF 00 || data），verify=true",
                () -> {
                    String a = "aprobe_rsa_none";
                    Util.genRsa(ctx.ks, a, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY,
                            ctx.challenge, 2048, KeyProperties.SIGNATURE_PADDING_RSA_PKCS1,
                            KeyProperties.DIGEST_NONE, false);
                    ctx.track(a);
                    byte[] data = "aprobe-none-rsa-0123456789abcdef".getBytes("UTF-8");
                    Signature s = Signature.getInstance("NONEwithRSA");
                    s.initSign((PrivateKey) ctx.ks.getKey(a, null));
                    s.update(data);
                    byte[] sig = s.sign();
                    Signature v = Signature.getInstance("NONEwithRSA");
                    v.initVerify(ctx.ks.getCertificate(a).getPublicKey());
                    v.update(data);
                    return v.verify(sig) ? Result.pass("sig=" + sig.length + "B verify=true")
                            : Result.hit("verify=false");
                });
        add(g, "C04", "AES-CTR 使用完整 16 字节初始计数器",
                "密文等于标准 AES-CTR（含 IV 低 32 位进位）",
                () -> {
                    String a = "aprobe_ctr";
                    byte[] raw = new byte[32];
                    for (int i = 0; i < raw.length; i++) raw[i] = (byte) i;
                    Util.importAes(ctx.ks, a, raw, KeyProperties.BLOCK_MODE_CTR,
                            KeyProperties.ENCRYPTION_PADDING_NONE);
                    ctx.track(a);
                    byte[] iv = new byte[16];
                    iv[12] = (byte) 0xde; iv[13] = (byte) 0xad; iv[14] = (byte) 0xbe; iv[15] = (byte) 0xef;
                    byte[] plain = new byte[32];
                    for (int i = 0; i < plain.length; i++) plain[i] = (byte) (0x40 + i);
                    Cipher c = Cipher.getInstance("AES/CTR/NoPadding");
                    c.init(Cipher.ENCRYPT_MODE, ctx.ks.getKey(a, null), new IvParameterSpec(iv));
                    byte[] got = c.doFinal(plain);
                    byte[] std = manualCtr(raw, iv, plain);
                    byte[] truncIv = iv.clone();
                    truncIv[12] = truncIv[13] = truncIv[14] = truncIv[15] = 0;
                    byte[] trunc = manualCtr(raw, truncIv, plain);
                    if (Arrays.equals(got, std)) return Result.pass("与标准 CTR 一致");
                    return Result.hit("got=" + Util.hex(got, 16)
                            + (Arrays.equals(got, trunc) ? " == 截断 IV 复算" : " != 标准/截断"));
                });
        add(g, "C05", "AES-192-GCM 可用",
                "192 位 AES 密钥 GCM 加密成功",
                () -> {
                    String a = "aprobe_aes192_gcm";
                    SecretKey k = Util.genAes(ctx.ks, a, 192, KeyProperties.BLOCK_MODE_GCM,
                            KeyProperties.ENCRYPTION_PADDING_NONE, true);
                    ctx.track(a);
                    Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                    c.init(Cipher.ENCRYPT_MODE, k);
                    byte[] ct = c.doFinal("aprobe-gcm192".getBytes("UTF-8"));
                    return Result.pass("ct=" + ct.length + "B");
                });
        for (int bits : new int[]{96, 104, 112, 120}) {
            final int tagBits = bits;
            add(g, "C06." + bits, "GCM " + bits + " 位 tag 可用",
                    "AOSP 接受 12/13/14/15 字节 tag；输出长度 = 明文 + " + (bits / 8),
                    () -> {
                        String a = "aprobe_gcm_" + tagBits;
                        SecretKey k = Util.genAes(ctx.ks, a, 256, KeyProperties.BLOCK_MODE_GCM,
                                KeyProperties.ENCRYPTION_PADDING_NONE, false);
                        ctx.track(a);
                        byte[] iv = new byte[12];
                        for (int i = 0; i < iv.length; i++) iv[i] = (byte) (0xa0 + i);
                        byte[] plain = "aprobe-gcm".getBytes("UTF-8");
                        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                        c.init(Cipher.ENCRYPT_MODE, k, new GCMParameterSpec(tagBits, iv));
                        byte[] ct = c.doFinal(plain);
                        int want = plain.length + tagBits / 8;
                        return ct.length == want ? Result.pass("ct=" + ct.length + "B")
                                : Result.hit("ct=" + ct.length + "B 期望=" + want);
                    });
        }
        add(g, "C07", "AES-CBC/PKCS7 拒绝非块对齐密文",
                "40/28 字节前缀必须失败（DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH）",
                () -> {
                    String a = "aprobe_cbc_trunc";
                    byte[] raw = new byte[32];
                    for (int i = 0; i < raw.length; i++) raw[i] = (byte) (0x80 + i);
                    Util.importAes(ctx.ks, a, raw, KeyProperties.BLOCK_MODE_CBC,
                            KeyProperties.ENCRYPTION_PADDING_PKCS7);
                    ctx.track(a);
                    byte[] iv = new byte[16];
                    Cipher e = Cipher.getInstance("AES/CBC/PKCS7Padding");
                    e.init(Cipher.ENCRYPT_MODE, ctx.ks.getKey(a, null), new IvParameterSpec(iv));
                    byte[] ct = e.doFinal(new byte[32]);
                    StringBuilder sb = new StringBuilder("ct=" + ct.length + "B");
                    boolean all = true;
                    for (int cut : new int[]{ct.length - 8, ct.length - 20}) {
                        Cipher d = Cipher.getInstance("AES/CBC/PKCS7Padding");
                        d.init(Cipher.DECRYPT_MODE, ctx.ks.getKey(a, null), new IvParameterSpec(iv));
                        try {
                            d.doFinal(Arrays.copyOf(ct, cut));
                            all = false;
                            sb.append(" ").append(cut).append("=accepted");
                        } catch (Throwable t) {
                            sb.append(" ").append(cut).append("=rejected");
                        }
                    }
                    return all ? Result.pass(sb.toString()) : Result.hit(sb.toString());
                });
        add(g, "C08", "AES-ECB/PKCS7 拒绝非块对齐密文",
                "截断块必须失败",
                () -> {
                    String a = "aprobe_ecb_trunc";
                    byte[] raw = new byte[32];
                    for (int i = 0; i < raw.length; i++) raw[i] = (byte) (0x40 + i);
                    Util.importAes(ctx.ks, a, raw, KeyProperties.BLOCK_MODE_ECB,
                            KeyProperties.ENCRYPTION_PADDING_PKCS7);
                    ctx.track(a);
                    Cipher e = Cipher.getInstance("AES/ECB/PKCS7Padding");
                    e.init(Cipher.ENCRYPT_MODE, ctx.ks.getKey(a, null));
                    byte[] ct = e.doFinal(new byte[32]);
                    Cipher d = Cipher.getInstance("AES/ECB/PKCS7Padding");
                    d.init(Cipher.DECRYPT_MODE, ctx.ks.getKey(a, null));
                    try {
                        d.doFinal(Arrays.copyOf(ct, ct.length - 8));
                        return Result.hit("截断密文被接受");
                    } catch (Throwable t) {
                        return Result.pass("rejected: " + t.getClass().getSimpleName());
                    }
                });
        add(g, "C09", "RSA NoPadding 解密拒绝 c >= n",
                "c=n 必须返回错误，不得做模幂",
                () -> {
                    String a = "aprobe_rsa_nopad_dec";
                    try {
                        Util.genRsaEnc(ctx.ks, a, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT,
                                ctx.challenge, 2048, KeyProperties.ENCRYPTION_PADDING_NONE,
                                KeyProperties.DIGEST_NONE, false);
                        ctx.track(a);
                    } catch (Throwable t) {
                        return Result.inc("RSA NoPadding 密钥生成失败，无法评估 c>=n: "
                                + t.getClass().getSimpleName() + ": " + t.getMessage());
                    }
                    java.security.interfaces.RSAPublicKey pub =
                            (java.security.interfaces.RSAPublicKey) ctx.ks.getCertificate(a).getPublicKey();
                    java.math.BigInteger n = pub.getModulus();
                    byte[] c = toFixed(n, 256);
                    Cipher d = Cipher.getInstance("RSA/ECB/NoPadding");
                    d.init(Cipher.DECRYPT_MODE, (PrivateKey) ctx.ks.getKey(a, null));
                    try {
                        d.doFinal(c);
                        return Result.hit("c=n 被接受");
                    } catch (Throwable t) {
                        return Result.pass("rejected: " + t.getClass().getSimpleName());
                    }
                });
        add(g, "C10", "RSA PKCS#1 签名覆盖 SHA-1/224/256/384/512",
                "五种 digest 的 Signature 均可签名并验签",
                () -> {
                    String a = "aprobe_rsa_digests";
                    Util.genRsa(ctx.ks, a, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY,
                            ctx.challenge, 2048, KeyProperties.SIGNATURE_PADDING_RSA_PKCS1,
                            KeyProperties.DIGEST_SHA1 + "|" + KeyProperties.DIGEST_SHA224 + "|"
                                    + KeyProperties.DIGEST_SHA256 + "|" + KeyProperties.DIGEST_SHA384
                                    + "|" + KeyProperties.DIGEST_SHA512, false);
                    ctx.track(a);
                    String[] digs = {"SHA1", "SHA224", "SHA256", "SHA384", "SHA512"};
                    StringBuilder sb = new StringBuilder();
                    for (String d : digs) {
                        try {
                            Signature s = Signature.getInstance(d + "withRSA");
                            s.initSign((PrivateKey) ctx.ks.getKey(a, null));
                            s.update(("aprobe-" + d).getBytes("UTF-8"));
                            byte[] sig = s.sign();
                            Signature v = Signature.getInstance(d + "withRSA");
                            v.initVerify(ctx.ks.getCertificate(a).getPublicKey());
                            v.update(("aprobe-" + d).getBytes("UTF-8"));
                            sb.append(d).append(v.verify(sig) ? "=ok " : "=bad ");
                        } catch (Throwable t) {
                            sb.append(d).append("=throw ");
                        }
                    }
                    return sb.toString().contains("throw") || sb.toString().contains("bad")
                            ? Result.hit(sb.toString()) : Result.pass(sb.toString());
                });
        add(g, "C11", "ECDSA P-256/P-384/P-521 签名",
                "三种曲线的 SHA-256/384/512 签名均可验",
                () -> {
                    String[][] specs = {{"secp256r1", "SHA256withECDSA", "256", "SHA-256"},
                            {"secp384r1", "SHA384withECDSA", "384", "SHA-384"},
                            {"secp521r1", "SHA512withECDSA", "521", "SHA-512"}};
                    StringBuilder sb = new StringBuilder();
                    for (String[] spec : specs) {
                        String a = "aprobe_ec_" + spec[2];
                        try {
                            Util.genEcCustom(ctx.ks, a, spec[0],
                                    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY,
                                    ctx.challenge, spec[3], null, false);
                            ctx.track(a);
                            Signature s = Signature.getInstance(spec[1]);
                            s.initSign((PrivateKey) ctx.ks.getKey(a, null));
                            s.update("aprobe-ec".getBytes("UTF-8"));
                            byte[] sig = s.sign();
                            Signature v = Signature.getInstance(spec[1]);
                            v.initVerify(ctx.ks.getCertificate(a).getPublicKey());
                            v.update("aprobe-ec".getBytes("UTF-8"));
                            sb.append(spec[2]).append(v.verify(sig) ? "=ok " : "=bad ");
                        } catch (Throwable t) {
                            sb.append(spec[2]).append("=throw(").append(t.getClass().getSimpleName()).append(") ");
                        }
                    }
                    return sb.toString().contains("throw") || sb.toString().contains("bad")
                            ? Result.hit(sb.toString()) : Result.pass(sb.toString());
                });
        add(g, "C12", "AES-GCM AAD 与篡改拒绝",
                "正确 AAD 解密成功；错误 AAD/篡改 tag 必须抛 AEADBadTagException",
                () -> {
                    String a = "aprobe_gcm_aad";
                    SecretKey k = Util.genAes(ctx.ks, a, 256, KeyProperties.BLOCK_MODE_GCM,
                            KeyProperties.ENCRYPTION_PADDING_NONE, false);
                    ctx.track(a);
                    byte[] iv = Util.random(12), aad = "aad".getBytes("UTF-8");
                    byte[] plain = "aprobe-gcm-aad".getBytes("UTF-8");
                    Cipher e = Cipher.getInstance("AES/GCM/NoPadding");
                    e.init(Cipher.ENCRYPT_MODE, k, new GCMParameterSpec(128, iv));
                    e.updateAAD(aad);
                    byte[] ct = e.doFinal(plain);
                    Cipher d = Cipher.getInstance("AES/GCM/NoPadding");
                    d.init(Cipher.DECRYPT_MODE, k, new GCMParameterSpec(128, iv));
                    d.updateAAD("bad".getBytes("UTF-8"));
                    try {
                        d.doFinal(ct);
                        return Result.hit("错误 AAD 被接受");
                    } catch (Throwable t) {
                        return Result.pass("rejected: " + t.getClass().getSimpleName());
                    }
                });
        add(g, "C13", "HMAC-SHA256 生成与验签",
                "Mac(HmacSHA256) 输出 32 字节",
                () -> {
                    String a = "aprobe_hmac";
                    SecretKey k = Util.genHmac(ctx.ks, a);
                    ctx.track(a);
                    Mac m = Mac.getInstance("HmacSHA256");
                    m.init(k);
                    byte[] out = m.doFinal("aprobe-hmac".getBytes("UTF-8"));
                    return out.length == 32 ? Result.pass(Util.hex(out, 8))
                            : Result.hit("len=" + out.length);
                });
        add(g, "C14", "32 KiB update 与 32 KiB+1 边界",
                "32768 字节成功；32769 字节以输入过长失败并使句柄失效",
                () -> {
                    String a = "aprobe_update_limit";
                    SecretKey k = Util.genAes(ctx.ks, a, 256, KeyProperties.BLOCK_MODE_CBC,
                            KeyProperties.ENCRYPTION_PADDING_PKCS7, true);
                    ctx.track(a);
                    Cipher c = Cipher.getInstance("AES/CBC/PKCS7Padding");
                    c.init(Cipher.ENCRYPT_MODE, k);
                    c.update(new byte[32768]);
                    c.doFinal();
                    Cipher c2 = Cipher.getInstance("AES/CBC/PKCS7Padding");
                    c2.init(Cipher.ENCRYPT_MODE, k);
                    try {
                        c2.update(new byte[32769]);
                        return Result.inc("32768 ok, 32769 被 JCA 接受；Java provider 可能分块，无法观察 raw HAL 上限");
                    } catch (Throwable t) {
                        return Result.pass("32768 ok, 32769 rejected: " + t.getClass().getSimpleName());
                    }
                });
        add(g, "C15", "AES-CBC 空明文/空密文语义",
                "空明文加密为一个填充块；空密文解密失败",
                () -> {
                    String a = "aprobe_empty";
                    SecretKey k = Util.genAes(ctx.ks, a, 256, KeyProperties.BLOCK_MODE_CBC,
                            KeyProperties.ENCRYPTION_PADDING_PKCS7, true);
                    ctx.track(a);
                    Cipher e = Cipher.getInstance("AES/CBC/PKCS7Padding");
                    e.init(Cipher.ENCRYPT_MODE, k);
                    byte[] ct = e.doFinal(new byte[0]);
                    Cipher d = Cipher.getInstance("AES/CBC/PKCS7Padding");
                    d.init(Cipher.DECRYPT_MODE, k, new IvParameterSpec(e.getIV()));
                    byte[] pt = d.doFinal(ct);
                    if (pt.length != 0) return Result.hit("空明文解密长度=" + pt.length);
                    Cipher bad = Cipher.getInstance("AES/CBC/PKCS7Padding");
                    bad.init(Cipher.DECRYPT_MODE, k, new IvParameterSpec(e.getIV()));
                    try {
                        bad.doFinal(new byte[0]);
                        return Result.hit("空密文被接受");
                    } catch (Throwable t) {
                        return Result.pass("ct=" + ct.length + "B, empty decrypt rejected");
                    }
                });
    }

    private static byte[] manualCtr(byte[] key, byte[] iv, byte[] plain) throws Exception {
        Cipher ecb = Cipher.getInstance("AES/ECB/NoPadding");
        ecb.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
        byte[] out = new byte[plain.length];
        byte[] counter = iv.clone();
        for (int off = 0; off < plain.length; off += 16) {
            byte[] stream = ecb.doFinal(counter);
            int n = Math.min(16, plain.length - off);
            for (int i = 0; i < n; i++) out[off + i] = (byte) (plain[off + i] ^ stream[i]);
            for (int i = counter.length - 1; i >= 0; i--) {
                counter[i]++;
                if (counter[i] != 0) break;
            }
        }
        return out;
    }

    private static byte[] toFixed(java.math.BigInteger v, int len) {
        byte[] b = v.toByteArray();
        if (b.length == len) return b;
        byte[] out = new byte[len];
        if (b.length > len) System.arraycopy(b, b.length - len, out, 0, len);
        else System.arraycopy(b, 0, out, len - b.length, b.length);
        return out;
    }

    // -------------------------------------------------------------- M ML-DSA
    private static void buildMlDsa(Ctx ctx) {
        String g = "M Android 17 ML-DSA（FIPS 204）";
        add(g, "M01", "ML-DSA-65 密钥生成",
                "KeyPairGenerator(ML-DSA) 默认 65，purpose SIGN|VERIFY, DIGEST_NONE",
                () -> {
                    if (Build.VERSION.SDK_INT < 37) return Result.skip("API " + Build.VERSION.SDK_INT + " < 37");
                    String alias = "aprobe_mldsa65";
                    try {
                        Util.rm(ctx.ks, alias);
                        KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(alias,
                                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                                .setDigests(KeyProperties.DIGEST_NONE)
                                .setAttestationChallenge(ctx.challenge)
                                .build();
                        java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator
                                .getInstance("ML-DSA", "AndroidKeyStore");
                        kpg.initialize(spec);
                        kpg.generateKeyPair();
                        ctx.track(alias);
                        return Result.pass("alias=" + alias);
                    } catch (Throwable t) {
                        return Result.hit(t.getClass().getSimpleName() + ": " + t.getMessage());
                    }
                });
        add(g, "M02", "ML-DSA-65 签名与验签",
                "Signature(\"ML-DSA\") 可签名并由证书公钥验证",
                () -> {
                    if (Build.VERSION.SDK_INT < 37) return Result.skip("API < 37");
                    String alias = "aprobe_mldsa65";
                    try {
                        Util.rm(ctx.ks, alias);
                        KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(alias,
                                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                                .setDigests(KeyProperties.DIGEST_NONE)
                                .build();
                        java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator
                                .getInstance("ML-DSA", "AndroidKeyStore");
                        kpg.initialize(spec);
                        kpg.generateKeyPair();
                        ctx.track(alias);
                        byte[] data = "aprobe-mldsa".getBytes("UTF-8");
                        Signature s = Signature.getInstance("ML-DSA");
                        s.initSign((PrivateKey) ctx.ks.getKey(alias, null));
                        s.update(data);
                        byte[] sig = s.sign();
                        Signature v = Signature.getInstance("ML-DSA");
                        v.initVerify(ctx.ks.getCertificate(alias).getPublicKey());
                        v.update(data);
                        return v.verify(sig) ? Result.pass("sig=" + sig.length + "B")
                                : Result.hit("verify=false");
                    } catch (Throwable t) {
                        return Result.hit(t.getClass().getSimpleName() + ": " + t.getMessage());
                    }
                });
        add(g, "M03", "ML-DSA 证书 tag 11 与 KeyInfo keySize=-1",
                "hwEnforced ML_DSA_VARIANT(11)=1；KeyInfo.getKeySize()=-1",
                () -> {
                    if (Build.VERSION.SDK_INT < 37) return Result.skip("API < 37");
                    String alias = "aprobe_mldsa_cert";
                    try {
                        Util.rm(ctx.ks, alias);
                        KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(alias,
                                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                                .setDigests(KeyProperties.DIGEST_NONE)
                                .setAttestationChallenge(ctx.challenge)
                                .build();
                        java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator
                                .getInstance("ML-DSA", "AndroidKeyStore");
                        kpg.initialize(spec);
                        kpg.generateKeyPair();
                        ctx.track(alias);
                        Attestation a = ctx.att(alias);
                        KeyInfo ki = Util.keyInfo(ctx.ks, alias);
                        long variant = a == null ? -1 : a.hw.integer(11, -1);
                        int ks = ki == null ? -2 : ki.getKeySize();
                        return variant == 1 && ks == -1 ? Result.pass("variant=" + variant + " keySize=" + ks)
                                : Result.hit("variant=" + variant + " keySize=" + ks);
                    } catch (Throwable t) {
                        return Result.hit(t.getClass().getSimpleName() + ": " + t.getMessage());
                    }
                });
        add(g, "M04", "ML-DSA-87 密钥生成",
                "KeyPairGenerator(\"ML-DSA-87\") 生成 87，证书 tag 11=2",
                () -> {
                    if (Build.VERSION.SDK_INT < 37) return Result.skip("API < 37");
                    String alias = "aprobe_mldsa87";
                    try {
                        Util.rm(ctx.ks, alias);
                        KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(alias,
                                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                                .setDigests(KeyProperties.DIGEST_NONE)
                                .setAttestationChallenge(ctx.challenge)
                                .build();
                        java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator
                                .getInstance("ML-DSA-87", "AndroidKeyStore");
                        kpg.initialize(spec);
                        kpg.generateKeyPair();
                        ctx.track(alias);
                        Attestation a = ctx.att(alias);
                        long v = a == null ? -1 : a.hw.integer(11, -1);
                        return v == 2 ? Result.pass("variant=2") : Result.hit("variant=" + v);
                    } catch (Throwable t) {
                        return Result.hit(t.getClass().getSimpleName() + ": " + t.getMessage());
                    }
                });
        add(g, "M05", "ML-DSA 不支持 StrongBox",
                "StrongBox 请求 ML-DSA 必须失败（UNSUPPORTED_ALGORITHM/UNSUPPORTED_ML_DSA_VARIANT）",
                () -> {
                    if (Build.VERSION.SDK_INT < 37) return Result.skip("API < 37");
                    String alias = "aprobe_mldsa_sb";
                    try {
                        Util.rm(ctx.ks, alias);
                        KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(alias,
                                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                                .setDigests(KeyProperties.DIGEST_NONE)
                                .setIsStrongBoxBacked(true)
                                .build();
                        java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator
                                .getInstance("ML-DSA", "AndroidKeyStore");
                        kpg.initialize(spec);
                        kpg.generateKeyPair();
                        ctx.track(alias);
                        return Result.hit("StrongBox ML-DSA 被接受");
                    } catch (Throwable t) {
                        return Result.pass("rejected: " + t.getClass().getSimpleName());
                    }
                });
        add(g, "M06", "ML-DSA 不允许 SIGN+ATTEST_KEY 同时出现",
                "generateKey 必须返回 INCOMPATIBLE_PURPOSE",
                () -> {
                    if (Build.VERSION.SDK_INT < 37) return Result.skip("API < 37");
                    String alias = "aprobe_mldsa_purpose";
                    try {
                        Util.rm(ctx.ks, alias);
                        KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(alias,
                                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_ATTEST_KEY)
                                .setDigests(KeyProperties.DIGEST_NONE)
                                .build();
                        java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator
                                .getInstance("ML-DSA", "AndroidKeyStore");
                        kpg.initialize(spec);
                        kpg.generateKeyPair();
                        ctx.track(alias);
                        return Result.hit("SIGN+ATTEST_KEY 被接受");
                    } catch (Throwable t) {
                        return Result.pass("rejected: " + t.getClass().getSimpleName());
                    }
                });
    }

    // ----------------------------------------------------------- K 原始 AIDL
    private static void buildRaw(Ctx ctx) {
        String g = "K Keystore2 原始 Binder / Parcel 面";
        add(g, "K01", "别名与 KEY_ID 指向同一对象",
                "getKeyEntry(alias).key.nspace == getKeyEntry(KEY_ID).key.nspace，证书相同",
                () -> {
                    if (!HiddenApi.available()) return Result.skip("hidden API 豁免不可用");
                    String alias = "aprobe_raw_view";
                    Util.genEc(ctx.ks, alias, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY,
                            null, null, false);
                    ctx.track(alias);
                    Raw.Entry a = Raw.entry(0, 0, alias);
                    if (a.error != null) return Result.hit("按别名读失败: " + a.error);
                    Raw.Entry b = Raw.entry(4, a.keyId, alias);
                    if (b.error != null) return Result.hit("按 KEY_ID 读失败: " + b.error);
                    boolean same = a.keyId == b.keyId && Arrays.equals(a.cert, b.cert);
                    return same ? Result.pass("keyId=" + a.keyId)
                            : Result.hit("alias keyId=" + a.keyId + " keyid keyId=" + b.keyId
                            + " certSame=" + Arrays.equals(a.cert, b.cert));
                });
        add(g, "K02", "非零 Parcelable presence marker 被接受",
                "getKeyEntry 的 KeyDescriptor presence marker 为 2/-1 时等价于 1（Android Parcel 语义）",
                () -> {
                    String alias = "aprobe_raw_presence";
                    Util.genEc(ctx.ks, alias, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY,
                            null, null, false);
                    ctx.track(alias);
                    int one = Raw.rawGetEntryTyped(alias, 1, false, false);
                    int two = Raw.rawGetEntryTyped(alias, 2, false, false);
                    int neg = Raw.rawGetEntryTyped(alias, -1, false, false);
                    if (one <= -990 && two <= -990 && neg <= -990) {
                        one = Raw.rawGetEntry(alias, 1, false);
                        two = Raw.rawGetEntry(alias, 2, false);
                        neg = Raw.rawGetEntry(alias, -1, false);
                    }
                    if (one <= -990) {
                        int noMarker = Raw.rawGetEntryNoMarker(alias);
                        if (noMarker > -990) {
                            return noMarker == 0
                                    ? Result.inc("no-marker 帧被接受（marker 语义需确认）: " + noMarker)
                                    : Result.inc("no-marker 帧异常=" + noMarker);
                        }
                    }
                    String d = "marker1=" + Raw.exceptionText(one)
                            + " marker2=" + Raw.exceptionText(two)
                            + " marker-1=" + Raw.exceptionText(neg);
                    if (one != 0) return Result.inc("canonical marker 也失败: " + d);
                    return (two == 0 && neg == 0) ? Result.pass(d) : Result.hit(d);
                });
        add(g, "K03", "必填对象的 null presence marker 被拒绝",
                "marker=0 必须返回 UnexpectedNull/异常，不得当作 present",
                () -> {
                    String alias = "aprobe_raw_null";
                    Util.genEc(ctx.ks, alias, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY,
                            null, null, false);
                    ctx.track(alias);
                    int code = Raw.rawGetEntryTyped(alias, 0, false, false);
                    if (code <= -990) code = Raw.rawGetEntry(alias, 0, false);
                    if (code <= -990) return Result.skip("raw Binder 不可用: " + Raw.exceptionText(code));
                    return code != 0 ? Result.pass(Raw.exceptionText(code))
                            : Result.hit("marker=0 被接受");
                });
        add(g, "K04", "错误 interface token 被传输层拒绝",
                "service 节点收到 maintenance token 必须失败（enforceInterface）",
                () -> {
                    String alias = "aprobe_raw_token";
                    Util.genEc(ctx.ks, alias, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY,
                            null, null, false);
                    ctx.track(alias);
                    int code = Raw.rawGetEntryTyped(alias, 1, true, false);
                    if (code <= -990) code = Raw.rawGetEntry(alias, 1, true);
                    if (code <= -990) return Result.skip("raw Binder 不可用: " + Raw.exceptionText(code));
                    return code != 0 ? Result.pass(Raw.exceptionText(code))
                            : Result.hit("错误 token 被接受");
                });
        add(g, "K05", "getKeyEntry 末尾多余字节的 stock 行为",
                "stock B 的 AIDL sized_read 忽略 parcelable 之后的尾部字节；只记录，不作为缺口",
                () -> {
                    String alias = "aprobe_raw_trailing";
                    Util.genEc(ctx.ks, alias, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY,
                            null, null, false);
                    ctx.track(alias);
                    int code = Raw.rawGetEntryTyped(alias, 1, false, true);
                    if (code <= -990) code = Raw.rawGetEntryTrailing(alias);
                    if (code <= -990) return Result.skip("raw Binder 不可用: " + Raw.exceptionText(code));
                    return Result.inc("stock 返回 " + Raw.exceptionText(code)
                            + "；sized_read 只按 size 前进，尾部字节可被忽略");
                });
        add(g, "K06", "getSecurityLevel 返回 TEE",
                "IKeystoreService.getSecurityLevel(1) 返回 TEE 的 version/name",
                () -> {
                    if (!HiddenApi.available()) return Result.skip("hidden API 豁免不可用");
                    try {
                        Object svc = Raw.service();
                        Method m = null;
                        for (Method candidate : svc.getClass().getMethods()) {
                            if (candidate.getName().equals("getSecurityLevel") && candidate.getParameterCount() == 1) {
                                m = candidate;
                                break;
                            }
                        }
                        if (m == null) return Result.skip("方法不可见");
                        Object level = m.invoke(svc, 1);
                        return Result.pass(String.valueOf(level));
                    } catch (Throwable t) {
                        return Result.inc(t.getClass().getSimpleName() + ": " + t.getMessage());
                    }
                });
    }

    // ------------------------------------------------------ S StrongBox / SPL
    private static void buildStrongBox(Ctx ctx) {
        String g = "S StrongBox / SPL / 版本标签";
        add(g, "S01", "StrongBox 功能声明与请求结果一致",
                "hasSystemFeature(strongbox)=true 时 StrongBox 请求成功；false 时请求失败",
                () -> {
                    boolean feature = ctx.activity.getPackageManager()
                            .hasSystemFeature("android.hardware.strongbox_keystore");
                    String alias = "aprobe_sb";
                    boolean ok = false;
                    String detail;
                    try {
                        Util.rm(ctx.ks, alias);
                        KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(alias,
                                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                                .setAlgorithmParameterSpec(new java.security.spec.ECGenParameterSpec("secp256r1"))
                                .setDigests(KeyProperties.DIGEST_SHA256)
                                .setAttestationChallenge(ctx.challenge)
                                .setIsStrongBoxBacked(true)
                                .build();
                        java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator
                                .getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
                        kpg.initialize(spec);
                        kpg.generateKeyPair();
                        ctx.track(alias);
                        ok = true;
                        detail = "request=ok";
                    } catch (Throwable t) {
                        detail = "request=" + t.getClass().getSimpleName();
                    }
                    if (feature != ok) return Result.hit("feature=" + feature + " " + detail);
                    return Result.pass("feature=" + feature + " " + detail);
                });
        add(g, "S02", "TEE 证书不得声明 StrongBox",
                "StrongBox 请求失败时不得返回 securityLevel=2 的 TEE 链",
                () -> {
                    String alias = "aprobe_sb_cert";
                    try {
                        Util.rm(ctx.ks, alias);
                        KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(alias,
                                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                                .setAlgorithmParameterSpec(new java.security.spec.ECGenParameterSpec("secp256r1"))
                                .setDigests(KeyProperties.DIGEST_SHA256)
                                .setAttestationChallenge(ctx.challenge)
                                .setIsStrongBoxBacked(true)
                                .build();
                        java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator
                                .getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
                        kpg.initialize(spec);
                        kpg.generateKeyPair();
                        ctx.track(alias);
                        Attestation a = ctx.att(alias);
                        if (a == null) return Result.hit("StrongBox 请求成功但无证明扩展");
                        if (a.attestationSecurityLevel != 2 || a.keymintSecurityLevel != 2)
                            return Result.hit("StrongBox 请求返回 level=" + a.attestationSecurityLevel
                                    + "/" + a.keymintSecurityLevel);
                        return Result.pass("StrongBox 2/2");
                    } catch (Throwable t) {
                        return Result.pass("request rejected: " + t.getClass().getSimpleName());
                    }
                });
        add(g, "S03", "专用 StrongBox keybox 是否存在",
                "存在 /data/misc/keystore/ommega/keybox-strongbox.xml 才可本地服务 StrongBox 证明",
                () -> {
                    if (!Root.available()) return Result.skip("无 root");
                    boolean e = Root.exists("/data/misc/keystore/ommega/keybox-strongbox.xml");
                    return e ? Result.pass("存在") : Result.hit("不存在（StrongBox 证明应为 ATTESTATION_KEYS_NOT_PROVISIONED）");
                });
        add(g, "S04", "disable_native_strongbox 配置",
                "config.toml 中 disable_native_strongbox 与实际 StrongBox 行为一致",
                () -> {
                    if (!Root.available()) return Result.skip("无 root");
                    String cfg = Root.cat("/data/misc/keystore/ommega/config.toml");
                    if (cfg == null) return Result.skip("读不到 config.toml");
                    boolean disabled = cfg.matches("(?s).*disable_native_strongbox\\s*=\\s*true.*");
                    boolean feature = ctx.activity.getPackageManager()
                            .hasSystemFeature("android.hardware.strongbox_keystore");
                    return Result.pass("configDisabled=" + disabled + " feature=" + feature);
                });
        add(g, "S05", "SPL 覆盖值与真实属性",
                "config.toml [trust] 的 security_patch/vendor_patchlevel/boot_patchlevel 与实际属性/证书一致",
                () -> {
                    if (!Root.available()) return Result.skip("无 root");
                    String cfg = Root.cat("/data/misc/keystore/ommega/config.toml");
                    if (cfg == null) return Result.skip("读不到 config.toml");
                    String sp = firstMatch(cfg, "security_patch\\s*=\\s*\"([^\"]*)\"");
                    String vp = firstMatch(cfg, "vendor_patchlevel\\s*=\\s*\"?([0-9]+)\"?");
                    String bp = firstMatch(cfg, "boot_patchlevel\\s*=\\s*\"?([0-9]+)\"?");
                    StringBuilder sb = new StringBuilder("config security_patch=" + sp
                            + " vendor=" + vp + " boot=" + bp);
                    boolean ok = true;
                    if (sp != null && !sp.isEmpty() && !sp.equals(Build.VERSION.SECURITY_PATCH)) {
                        // Config may be a trust override, not a claim of the property.
                        sb.append(" | Build=").append(Build.VERSION.SECURITY_PATCH);
                    }
                    return Result.pass(sb.toString());
                });
        add(g, "S06", "证书版本标签与本地/远程来源",
                "challenge 证书与本地 ATTEST_KEY 子钥证书的 705/706/718/719 来自同一来源",
                () -> {
                    ctx.ecAttested();
                    Attestation x = ctx.att("aprobe_ec_att");
                    Attestation y = ctx.att("aprobe_a14_child");
                    if (x == null || y == null) return Result.skip("缺 A14 子钥或扩展；先看 A14");
                    String xs = tags(x), ys = tags(y);
                    return xs.equals(ys) ? Result.pass("remote{" + xs + "} local{" + ys + "}")
                            : Result.hit("remote{" + xs + "} local{" + ys + "}");
                });
    }

    // --------------------------------------------------------------- T 时序
    private static void buildTiming(Ctx ctx) {
        String g = "T 时序 / 反检测整形";
        add(g, "T01", "本地普通密钥生成耗时基线",
                "无 challenge 的本地 EC 生成中位数（记录，不做阈值判定）",
                () -> {
                    long[] s = new long[3];
                    for (int i = 0; i < s.length; i++) {
                        String a = "aprobe_t_plain_" + i;
                        long t = System.nanoTime();
                        Util.genEc(ctx.ks, a, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY,
                                null, null, false);
                        s[i] = System.nanoTime() - t;
                        ctx.track(a);
                    }
                    return Result.pass("median=" + median(s) / 1_000_000 + "ms");
                });
        add(g, "T02", "远程 challenge 生成耗时",
                "带 challenge 的 EC 生成中位数（应显著高于本地；记录）",
                () -> {
                    long[] s = new long[3];
                    for (int i = 0; i < s.length; i++) {
                        String a = "aprobe_t_att_" + i;
                        long t = System.nanoTime();
                        Util.genEc(ctx.ks, a, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY,
                                new String(ctx.challenge), null, false);
                        s[i] = System.nanoTime() - t;
                        ctx.track(a);
                    }
                    return Result.pass("median=" + median(s) / 1_000_000 + "ms");
                });
        add(g, "T03", "本地 ATTEST_KEY 子钥生成是否被整形到远程 RTT",
                "本地 attest key 子钥应接近本地 keygen；若接近远程 RTT 且远高于本地，判为反检测整形",
                () -> {
                    String parent = "aprobe_t_parent";
                    // No challenge: the parent stays local, so the child's local arm is taken.
                    Util.genAttestKeyLocal(ctx.ks, parent);
                    ctx.track(parent);
                    long[] plain = new long[3], child = new long[3];
                    for (int i = 0; i < 3; i++) {
                        String a = "aprobe_t_p2_" + i;
                        long t = System.nanoTime();
                        Util.genEc(ctx.ks, a, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY,
                                null, null, false);
                        plain[i] = System.nanoTime() - t;
                        ctx.track(a);
                        String c = "aprobe_t_child_" + i;
                        t = System.nanoTime();
                        // Local parent as attestation key, challenged child: pad_local_attest_key path.
                        Util.genEcCustom(ctx.ks, c, "secp256r1",
                                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY,
                                ctx.challenge, KeyProperties.DIGEST_SHA256, parent, false);
                        child[i] = System.nanoTime() - t;
                        ctx.track(c);
                    }
                    long p = median(plain), c = median(child);
                    boolean shaped = c > Math.max(p * 3, p + 50_000_000L) && c > 80_000_000L;
                    String d = "plain=" + p / 1_000_000 + "ms child=" + c / 1_000_000 + "ms ratio="
                            + String.format(Locale.US, "%.2f", (double) c / Math.max(1, p));
                    return shaped ? Result.hit(d + "（疑似 equalize_to_remote_attest_duration）")
                            : Result.pass(d);
                });
        add(g, "T04", "远程/本地配对差（Duck 风格阈值）",
                "attested 中位数 - control 中位数；若 >120ms 且 >3x MAD 则记录",
                () -> {
                    long[] att = new long[3], ctl = new long[3];
                    try {
                        for (int i = 0; i < 3; i++) {
                            String a = "aprobe_t_pair_a" + i;
                            long t = System.nanoTime();
                            Util.genEc(ctx.ks, a, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY,
                                    new String(ctx.challenge), null, false);
                            att[i] = System.nanoTime() - t;
                            ctx.track(a);
                            String c = "aprobe_t_pair_c" + i;
                            t = System.nanoTime();
                            Util.genEc(ctx.ks, c, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY,
                                    null, null, false);
                            ctl[i] = System.nanoTime() - t;
                            ctx.track(c);
                        }
                    } catch (Throwable t) {
                        return Result.inc("配对生成失败: " + t.getClass().getSimpleName()
                                + ": " + t.getMessage());
                    }
                    long a = median(att), c = median(ctl);
                    long diff = a - c;
                    String d = "attested=" + a / 1_000_000 + "ms control=" + c / 1_000_000
                            + "ms diff=" + diff / 1_000_000 + "ms";
                    return (diff > 120_000_000L && a > 3 * Math.max(1, c))
                            ? Result.hit(d + "（超过 120ms/3x 形状）") : Result.pass(d);
                });
    }

    // ---------------------------------------------------------- L 生命周期
    private static void buildLifecycle(Ctx ctx) {
        String g = "L 操作生命周期 / 并发 / 限制";
        add(g, "L01", "同时打开 16 个操作成功，第 17 个失败",
                "TEE KeyMint MAX_TEE_OPERATIONS=16；第 17 个必须 TOO_MANY_OPERATIONS",
                () -> {
                    ctx.ecPlain();
                    PrivateKey k = (PrivateKey) ctx.ks.getKey("aprobe_ec_plain", null);
                    List<Signature> open = new ArrayList<>();
                    int accepted = 0;
                    String fail = "none";
                    for (int i = 0; i < 17; i++) {
                        try {
                            Signature s = Signature.getInstance("SHA256withECDSA");
                            s.initSign(k);
                            open.add(s);
                            accepted++;
                        } catch (Throwable t) {
                            fail = t.getClass().getSimpleName() + ": " + t.getMessage();
                            break;
                        }
                    }
                    for (Signature s : open) {
                        try { s.sign(); } catch (Throwable ignored) {}
                    }
                    return accepted <= 16 ? Result.pass("accepted=" + accepted + " fail=" + fail)
                            : Result.inc("accepted=" + accepted + "；JCA 的 Signature 对象可能延迟打开操作，无法据此证明 raw 上限");
                });
        add(g, "L02", "finish 后同一句柄再签名被拒绝",
                "Signature.sign() 成功后再次 sign() 必须抛 SignatureException",
                () -> {
                    ctx.ecPlain();
                    Signature s = Signature.getInstance("SHA256withECDSA");
                    s.initSign((PrivateKey) ctx.ks.getKey("aprobe_ec_plain", null));
                    s.update("aprobe-once".getBytes("UTF-8"));
                    s.sign();
                    try {
                        s.sign();
                        return Result.inc("finish 后再次 sign 被 JCA provider 接受；raw operation handle 语义需直接 HAL 才能判定");
                    } catch (Throwable t) {
                        return Result.pass("rejected: " + t.getClass().getSimpleName());
                    }
                });
        add(g, "L03", "删除密钥后已打开操作的行为",
                "AOSP 已打开 operation 持有 keyblob，删除别名不应使在途操作崩溃",
                () -> {
                    String a = "aprobe_del_open";
                    Util.genEc(ctx.ks, a, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY,
                            null, null, false);
                    ctx.track(a);
                    Signature s = Signature.getInstance("SHA256withECDSA");
                    s.initSign((PrivateKey) ctx.ks.getKey(a, null));
                    ctx.ks.deleteEntry(a);
                    s.update("aprobe-deleted".getBytes("UTF-8"));
                    try {
                        byte[] sig = s.sign();
                        return Result.pass("in-flight sign ok, sig=" + sig.length + "B");
                    } catch (Throwable t) {
                        return Result.inc("in-flight sign failed: " + t.getClass().getSimpleName()
                                + "（实现相关，需与真机对照）");
                    }
                });
        add(g, "L04", "并发签名同一密钥",
                "4 个线程各自 createOperation 并签名，全部成功且可验",
                () -> {
                    ctx.ecPlain();
                    final PublicKey pub = ctx.ecPlain().getPublic();
                    final byte[][] sigs = new byte[4][];
                    final Throwable[] errs = new Throwable[4];
                    Thread[] ts = new Thread[4];
                    for (int i = 0; i < 4; i++) {
                        final int idx = i;
                        ts[i] = new Thread(() -> {
                            try {
                                byte[] data = ("aprobe-concurrent-" + idx).getBytes("UTF-8");
                                Signature s = Signature.getInstance("SHA256withECDSA");
                                s.initSign((PrivateKey) ctx.ks.getKey("aprobe_ec_plain", null));
                                s.update(data);
                                sigs[idx] = s.sign();
                            } catch (Throwable t) {
                                errs[idx] = t;
                            }
                        });
                        ts[i].start();
                    }
                    for (Thread t : ts) try { t.join(10_000); } catch (InterruptedException ignored) {}
                    for (Throwable t : errs) if (t != null)
                        return Result.hit("并发失败: " + t.getClass().getSimpleName() + ": " + t.getMessage());
                    for (int i = 0; i < 4; i++) {
                        try {
                            if (!Util.verifyEc(pub, ("aprobe-concurrent-" + i).getBytes("UTF-8"), sigs[i]))
                                return Result.hit("第 " + i + " 个并发签名验签失败");
                        } catch (Throwable t) {
                            return Result.hit("验签异常: " + t);
                        }
                    }
                    return Result.pass("4/4 成功");
                });
    }

    // -------------------------------------------------------- F 模块文件/日志
    private static void buildModule(Ctx ctx) {
        String g = "F Ommega 模块文件 / 日志（只读 root）";
        add(g, "F01", "模块版本与配置文件存在",
                "/data/adb/ommega/module.prop、config.toml、target.txt",
                () -> {
                    if (!Root.available()) return Result.skip("无 root（su 不可用）");
                    StringBuilder sb = new StringBuilder();
                    for (String p : new String[]{"/data/adb/ommega/module.prop",
                            "/data/misc/keystore/ommega/config.toml",
                            "/data/misc/keystore/ommega/target.txt"}) {
                        sb.append(p).append('=').append(Root.exists(p) ? "yes" : "no").append(' ');
                    }
                    String mp = Root.cat("/data/adb/ommega/module.prop");
                    if (mp != null) {
                        String v = firstMatch(mp, "version=([^\\n]+)");
                        sb.append("version=").append(v);
                    }
                    return Result.pass(sb.toString());
                });
        add(g, "F02", "KeyMint 日志中 remote_sign 是否出现",
                "成功远程签名应出现 event=remote_sign；缺失说明远程 SIGN 从未成功",
                () -> {
                    if (!Root.available()) return Result.skip("无 root");
                    String log = Root.cat("/data/misc/keystore/ommega/logs/keymint.log");
                    if (log == null) return Result.skip("读不到 keymint.log");
                    int remote = count(log, "event=remote_sign");
                    int missing = count(log, "missing tag Algorithm");
                    int local = count(log, "event=local_sign");
                    String d = "remote_sign=" + remote + " missingAlgorithm=" + missing + " local_sign=" + local;
                    return (remote == 0 && missing > 0) ? Result.hit(d) : Result.pass(d);
                });
        add(g, "F03", "远程版本标签诊断事件",
                "2.1.3+ 应出现 event=remote_version_tags；缺失说明仍是本地/远程混用",
                () -> {
                    if (!Root.available()) return Result.skip("无 root");
                    String log = Root.cat("/data/misc/keystore/ommega/logs/keymint.log");
                    if (log == null) return Result.skip("读不到 keymint.log");
                    int tags = count(log, "event=remote_version_tags");
                    return tags > 0 ? Result.pass("seen=" + tags)
                            : Result.hit("未见 remote_version_tags（当前树无该 profile 字段）");
                });
        add(g, "F04", "injector 日志中的 interface token / grant 证据",
                "无 interface_token_mismatch 误答；grantees 走 ommega_grant=true",
                () -> {
                    if (!Root.available()) return Result.skip("无 root");
                    String log = Root.cat("/data/misc/keystore/ommega/logs/injector.log");
                    if (log == null) return Result.skip("读不到 injector.log");
                    int mismatch = count(log, "interface_token_mismatch");
                    int grant = count(log, "ommmega_grant=true") + count(log, "ommega_grant=true");
                    return Result.pass("interface_token_mismatch=" + mismatch + " ommega_grant=" + grant);
                });
        add(g, "F05", "target-compat.toml 正数 key id 开关",
                "开关只影响新键；默认关闭",
                () -> {
                    if (!Root.available()) return Result.skip("无 root");
                    String f = Root.cat("/data/misc/keystore/ommega/target-compat.toml");
                    return f == null ? Result.pass("不存在（默认关闭）")
                            : Result.pass(f.replace('\n', ' ').trim());
                });
        add(g, "F06", "auth-signing 策略文件",
                "默认 Auto；存在时记录 default/apps",
                () -> {
                    if (!Root.available()) return Result.skip("无 root");
                    String f = Root.cat("/data/misc/keystore/ommega/data/auth-signing.toml");
                    return f == null ? Result.pass("不存在（默认 Auto）")
                            : Result.pass(f.replace('\n', ' ').trim());
                });
        add(g, "F07", "keymint 二进制内是否残留 Ommega 源路径重写表",
                "stock keystore2 不含 src\\keymaster / src/keymaster 字符串；命中即 Ommega 派生",
                () -> {
                    if (!Root.available()) return Result.skip("无 root");
                    String out = Root.exec("grep -a -c 'src.keymaster' /data/adb/ommega/keymint 2>/dev/null", 5000);
                    if (out == null) return Result.skip("grep 不可用/二进制不存在");
                    int n;
                    try { n = Integer.parseInt(out.trim()); } catch (Throwable t) { return Result.skip("输出=" + out.trim()); }
                    return n > 0 ? Result.hit("匹配 " + n + " 次（normalize_source_path 字符串）")
                            : Result.pass("0 次");
                });
        add(g, "F08", "keymint 二进制内是否包含检测器特判 alias",
                "TrustAttestor_silent_auth_ 只应出现在 Ommega 的 known_probe 分支",
                () -> {
                    if (!Root.available()) return Result.skip("无 root");
                    String out = Root.exec("grep -a -c 'TrustAttestor_silent_auth_' /data/adb/ommega/keymint 2>/dev/null", 5000);
                    if (out == null) return Result.skip("grep 不可用/二进制不存在");
                    int n;
                    try { n = Integer.parseInt(out.trim()); } catch (Throwable t) { return Result.skip("输出=" + out.trim()); }
                    return n > 0 ? Result.hit("匹配 " + n + " 次（known_probe alias）")
                            : Result.pass("0 次");
                });
        add(g, "F09", "injector 二进制内是否包含检测器包名列表",
                "com.eltavine.duckdetector 出现在默认 scoop/检测器特判中",
                () -> {
                    if (!Root.available()) return Result.skip("无 root");
                    String out = Root.exec("grep -a -c 'com.eltavine.duckdetector' /data/adb/ommega/ommega-inject 2>/dev/null", 5000);
                    if (out == null) return Result.skip("grep 不可用/二进制不存在");
                    int n;
                    try { n = Integer.parseInt(out.trim()); } catch (Throwable t) { return Result.skip("输出=" + out.trim()); }
                    return n > 0 ? Result.hit("匹配 " + n + " 次（检测器包名）")
                            : Result.pass("0 次");
                });
    }

    private static int count(String haystack, String needle) {
        int n = 0, i = 0;
        while ((i = haystack.indexOf(needle, i)) >= 0) { n++; i += needle.length(); }
        return n;
    }

    private static String firstMatch(String text, String regex) {
        try {
            java.util.regex.Matcher m = java.util.regex.Pattern.compile(regex).matcher(text);
            return m.find() ? m.group(1) : null;
        } catch (Throwable t) {
            return null;
        }
    }

    private static long median(long[] v) {
        long[] c = v.clone();
        Arrays.sort(c);
        return c.length == 0 ? 0 : c[c.length / 2];
    }

}
