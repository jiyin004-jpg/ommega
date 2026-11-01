package aprobes;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.security.keystore.KeyProtection;

import java.io.ByteArrayOutputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class Util {
    private Util() {}

    public static KeyStore keyStore() throws Exception {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        return ks;
    }

    public static byte[] random(int n) {
        byte[] b = new byte[n];
        new java.security.SecureRandom().nextBytes(b);
        return b;
    }

    public static void rm(KeyStore ks, String alias) {
        try { if (ks.containsAlias(alias)) ks.deleteEntry(alias); } catch (Throwable ignored) {}
    }

    public static KeyPair genEc(KeyStore ks, String alias, int purposes, String challengeAlias,
                                String parentAlias, boolean deviceProps) throws Exception {
        rm(ks, alias);
        KeyGenParameterSpec.Builder b = new KeyGenParameterSpec.Builder(alias, purposes)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256);
        if (challengeAlias != null) b.setAttestationChallenge(challengeAlias.getBytes("UTF-8"));
        if (parentAlias != null) b.setAttestKeyAlias(parentAlias);
        if (deviceProps) b.setDevicePropertiesAttestationIncluded(true);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
        kpg.initialize(b.build());
        return kpg.generateKeyPair();
    }

    public static KeyPair genEcCurve(KeyStore ks, String alias, String curve, int purposes,
                                     byte[] challenge, boolean deviceProps) throws Exception {
        rm(ks, alias);
        KeyGenParameterSpec.Builder b = new KeyGenParameterSpec.Builder(alias, purposes)
                .setAlgorithmParameterSpec(new ECGenParameterSpec(curve))
                .setDigests(KeyProperties.DIGEST_SHA256);
        if (challenge != null) b.setAttestationChallenge(challenge);
        if (deviceProps) b.setDevicePropertiesAttestationIncluded(true);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
        kpg.initialize(b.build());
        return kpg.generateKeyPair();
    }

    public static KeyPair genEcCustom(KeyStore ks, String alias, String curve, int purposes,
                                      byte[] challenge, String digest, String parentAlias,
                                      boolean deviceProps) throws Exception {
        rm(ks, alias);
        KeyGenParameterSpec.Builder b = new KeyGenParameterSpec.Builder(alias, purposes)
                .setAlgorithmParameterSpec(new ECGenParameterSpec(curve))
                .setDigests(digest);
        if (challenge != null) b.setAttestationChallenge(challenge);
        if (parentAlias != null) b.setAttestKeyAlias(parentAlias);
        if (deviceProps) b.setDevicePropertiesAttestationIncluded(true);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
        kpg.initialize(b.build());
        return kpg.generateKeyPair();
    }

    public static KeyPair genEcAuth(KeyStore ks, String alias, byte[] challenge) throws Exception {
        rm(ks, alias);
        KeyGenParameterSpec.Builder b = new KeyGenParameterSpec.Builder(alias,
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(0,
                        KeyProperties.AUTH_BIOMETRIC_STRONG | KeyProperties.AUTH_DEVICE_CREDENTIAL)
                .setAttestationChallenge(challenge);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
        kpg.initialize(b.build());
        return kpg.generateKeyPair();
    }

    public static KeyPair genEcFlags(KeyStore ks, String alias, byte[] challenge,
                                     boolean auth, int timeout, int authType,
                                     boolean unlocked, boolean onBody, boolean trustedConfirm)
            throws Exception {
        rm(ks, alias);
        KeyGenParameterSpec.Builder b = new KeyGenParameterSpec.Builder(alias,
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(challenge);
        if (auth) {
            b.setUserAuthenticationRequired(true);
            b.setUserAuthenticationParameters(timeout, authType);
            if (onBody) b.setUserAuthenticationValidWhileOnBody(true);
        }
        if (unlocked) b.setUnlockedDeviceRequired(true);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
        kpg.initialize(b.build());
        return kpg.generateKeyPair();
    }

    public static KeyPair genAttestKeyLocal(KeyStore ks, String alias) throws Exception {
        rm(ks, alias);
        KeyGenParameterSpec.Builder b = new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ATTEST_KEY)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
        kpg.initialize(b.build());
        return kpg.generateKeyPair();
    }

    public static KeyPair genAttestKey(KeyStore ks, String alias, byte[] challenge) throws Exception {
        rm(ks, alias);
        KeyGenParameterSpec.Builder b = new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ATTEST_KEY)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(challenge);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
        kpg.initialize(b.build());
        return kpg.generateKeyPair();
    }

    public static KeyPair genRsa(KeyStore ks, String alias, int purposes, byte[] challenge,
                                 int bits, String padding, String digest, boolean deviceProps) throws Exception {
        rm(ks, alias);
        KeyGenParameterSpec.Builder b = new KeyGenParameterSpec.Builder(alias, purposes)
                .setKeySize(bits)
                .setDigests(digest.split("\\|"))
                .setSignaturePaddings(padding)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1);
        if (challenge != null) b.setAttestationChallenge(challenge);
        if (deviceProps) b.setDevicePropertiesAttestationIncluded(true);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
        kpg.initialize(b.build());
        return kpg.generateKeyPair();
    }

    public static KeyPair genRsaEnc(KeyStore ks, String alias, int purposes, byte[] challenge,
                                    int bits, String encPadding, String digest, boolean deviceProps) throws Exception {
        rm(ks, alias);
        KeyGenParameterSpec.Builder b = new KeyGenParameterSpec.Builder(alias, purposes)
                .setKeySize(bits)
                .setDigests(digest)
                .setEncryptionPaddings(encPadding)
                .setRandomizedEncryptionRequired(false);
        if (challenge != null) b.setAttestationChallenge(challenge);
        if (deviceProps) b.setDevicePropertiesAttestationIncluded(true);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
        kpg.initialize(b.build());
        return kpg.generateKeyPair();
    }

    public static SecretKey genAes(KeyStore ks, String alias, int bits, String blockMode,
                                   String padding, boolean randomized) throws Exception {
        rm(ks, alias);
        KeyGenerator kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        kg.init(new KeyGenParameterSpec.Builder(alias,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(bits)
                .setBlockModes(blockMode)
                .setEncryptionPaddings(padding)
                .setRandomizedEncryptionRequired(randomized)
                .build());
        return kg.generateKey();
    }

    public static SecretKey gen3des(KeyStore ks, String alias, String blockMode) throws Exception {
        rm(ks, alias);
        KeyGenerator kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_3DES, "AndroidKeyStore");
        kg.init(new KeyGenParameterSpec.Builder(alias,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(blockMode)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                .setRandomizedEncryptionRequired(false)
                .build());
        return kg.generateKey();
    }

    public static SecretKey genHmac(KeyStore ks, String alias) throws Exception {
        rm(ks, alias);
        KeyGenerator kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, "AndroidKeyStore");
        kg.init(new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .build());
        return kg.generateKey();
    }

    public static void importAes(KeyStore ks, String alias, byte[] raw, String mode, String padding) throws Exception {
        rm(ks, alias);
        KeyProtection p = new KeyProtection.Builder(KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(mode)
                .setEncryptionPaddings(padding)
                .setRandomizedEncryptionRequired(false)
                .build();
        ks.setEntry(alias, new KeyStore.SecretKeyEntry(new SecretKeySpec(raw, "AES")), p);
    }

    public static void importEc(KeyStore ks, String alias, byte[] pkcs8, byte[] certDer,
                                byte[] challenge, boolean deviceProps) throws Exception {
        rm(ks, alias);
        PrivateKey key = KeyFactory.getInstance("EC").generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(pkcs8));
        java.security.cert.Certificate cert = java.security.cert.CertificateFactory.getInstance("X.509")
                .generateCertificate(new java.io.ByteArrayInputStream(certDer));
        KeyProtection.Builder ec = new KeyProtection.Builder(KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setDigests(KeyProperties.DIGEST_SHA256);
        ks.setEntry(alias, new KeyStore.PrivateKeyEntry(key, new java.security.cert.Certificate[]{cert}), ec.build());
    }

    public static Certificate[] chain(KeyStore ks, String alias) throws Exception {
        return ks.getCertificateChain(alias);
    }

    public static X509Certificate leaf(KeyStore ks, String alias) throws Exception {
        Certificate[] c = chain(ks, alias);
        if (c == null || c.length == 0) return null;
        return (X509Certificate) c[0];
    }

    public static KeyInfo keyInfo(KeyStore ks, String alias) throws Exception {
        try {
            PrivateKey k = (PrivateKey) ks.getKey(alias, null);
            if (k == null) return null;
            KeyFactory f = KeyFactory.getInstance(k.getAlgorithm(), "AndroidKeyStore");
            return f.getKeySpec(k, KeyInfo.class);
        } catch (Throwable t) {
            return null;
        }
    }

    public static byte[] signEc(KeyStore ks, String alias, byte[] data) throws Exception {
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initSign((PrivateKey) ks.getKey(alias, null));
        s.update(data);
        return s.sign();
    }

    public static boolean verifyEc(PublicKey pub, byte[] data, byte[] sig) throws Exception {
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initVerify(pub);
        s.update(data);
        return s.verify(sig);
    }

    public static String hex(byte[] b, int max) {
        if (b == null) return "null";
        StringBuilder sb = new StringBuilder();
        int n = Math.min(b.length, max);
        for (int i = 0; i < n; i++) sb.append(String.format("%02x", b[i]));
        if (b.length > max) sb.append("..");
        return sb.toString();
    }

    public static String b64(byte[] b) {
        return b == null ? "null" : Base64.getEncoder().encodeToString(b);
    }

    public static byte[] unb64(String s) {
        return Base64.getDecoder().decode(s);
    }

    public static String bytes(byte[] b) {
        if (b == null) return "null";
        String s;
        try { s = new String(b, "UTF-8"); } catch (Exception e) { return hex(b, 64); }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 0x20 || c > 0x7e) return hex(b, 64);
        }
        return "\"" + s + "\"";
    }

    public static String certName(X509Certificate c, String oid) {
        return rdn(c.getSubjectX500Principal().getName(), oid);
    }

    public static String issuerName(X509Certificate c, String oid) {
        return rdn(c.getIssuerX500Principal().getName(), oid);
    }

    /** Extract a short RDN value (O=, OU=, T=) from an RFC2253 name. */
    public static String rdn(String dn, String oid) {
        String label;
        if ("2.5.4.12".equals(oid)) label = "T";
        else if ("2.5.4.10".equals(oid)) label = "O";
        else if ("2.5.4.11".equals(oid)) label = "OU";
        else label = oid;
        try {
            java.util.regex.Matcher m = java.util.regex.Pattern
                    .compile("(?:^|,)\\s*" + label + "=([^,]+)").matcher(dn);
            if (m.find()) return m.group(1).replace("\\,", ",").trim();
        } catch (Throwable ignored) {
        }
        return null;
    }

    public static String sha256(byte[] b) throws Exception {
        return hex(java.security.MessageDigest.getInstance("SHA-256").digest(b), 32);
    }

    public static String nowIso() {
        return new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss", java.util.Locale.US)
                .format(new java.util.Date());
    }
}
