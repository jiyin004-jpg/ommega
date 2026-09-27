/*
 * Vendor Qualcomm SOTER HAL (AIDL flavour).
 *
 * Reconstructed from the SOTER host APK the device ships
 * (`/system_ext/app/SoterService/SoterService.apk`): its
 * `vendor.qti.hardware.soter.ISoter$Proxy` carries the transaction numbers as
 * literals (`transact(1, ...)`, `transact(3, ...)` …), and the parcelable it
 * reads replies into (`b.b`) shows the body layout byte for byte.  The numbers
 * agree with the ones the A-side hook has been using on live devices.
 *
 * Transaction codes are the declaration order below (1..14).  AIDL only puts
 * the numbers in the wire form; the *outer* framing differs from the Trustonic
 * HAL, see `src/soter/hal.rs`.
 *
 * NOTE: 2/6/14 are placeholders.  The host never sends them, so the vendor's
 * own declarations for those slots were never observable, and they are
 * deliberately never sent (on the Trustonic HAL, code 6 is
 * `generateAttkKeyPair` — a state change — so guessing is not an option).
 *
 * NOTE: only the service lookup goes through this declaration (rsbinder stamps
 * this interface's descriptor onto the resolved proxy, which the HAL verifies
 * as the transaction interface token).  Requests/replies are marshalled by
 * `src/soter/hal.rs` against the wire form recovered from the host APK.
 */
package vendor.qti.hardware.soter;

@VintfStability
interface ISoter {
    /** ASK (app signing key) public key + TEE signature for a caller uid. */
    void exportAskPublicKey(int uid);
    /** Placeholder — see the file comment. */
    void reserved2();
    /** Per-uid, per-alias auth key public key. */
    void exportAuthKeyPublicKey(int uid, String alias);
    /** Completes a signing session started by `initSign`. */
    void finishSign(long session);
    /** Creates the ASK for a uid (device state change). */
    void generateAskKeyPair(int uid);
    /** Placeholder — see the file comment. */
    void reserved6();
    /** Creates a per-uid, per-alias auth key (device state change). */
    void generateAuthKeyPair(int uid, String alias);
    /** Stable device id (32 hex chars). */
    void getDeviceId();
    /** 0 when the uid already has an ASK, -5 when it does not. */
    void hasAskAlready(int uid);
    /** 0 when the auth key exists. */
    void hasAuthKey(int uid, String alias);
    /** Starts a signing session against an auth key. */
    void initSign(int uid, String alias, String challenge);
    /** Removes every key of a uid (device state change). */
    void removeAllUidKey(int uid);
    /** Removes one auth key (device state change). */
    void removeAuthKey(int uid, String alias);
    /** Placeholder — see the file comment. */
    void reserved14();
}
