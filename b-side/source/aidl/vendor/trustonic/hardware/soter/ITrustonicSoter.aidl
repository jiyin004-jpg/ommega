/*
 * Vendor Trustonic SOTER HAL.
 *
 * Reconstructed from the shipped `vendor.trustonic.hardware.soter-V1-ndk.so`
 * (interface version 1, descriptor `vendor.trustonic.hardware.soter.ITrustonicSoter`).
 *
 * Transaction codes are the AIDL declaration order below (1..14) and match the
 * vendor Bp stubs.  All methods are synchronous; methods returning `int`
 * return a SOTER/TEE error code (0 = success, -5 = key not found, ...).
 *
 * NOTE: only the service lookup goes through this declaration (rsbinder stamps
 * this interface's descriptor onto the resolved proxy, which the HAL verifies
 * as the transaction interface token).  Requests/replies are marshalled by
 * `src/soter/hal.rs`, because the vendor's wire form is known byte-exactly and
 * the generated stubs do not reproduce all of it.
 */
package vendor.trustonic.hardware.soter;

import vendor.trustonic.hardware.soter.SoterData;
import vendor.trustonic.hardware.soter.SoterSession;

@VintfStability
interface ITrustonicSoter {
    /** ASK (app signing key) public key + TEE signature for a caller uid. */
    SoterData exportAskPublicKey(int uid);
    /** Device ATTK (attestation key) public key. */
    SoterData exportAttkPublicKey();
    /** Per-uid, per-alias auth key public key. */
    SoterData exportAuthKeyPublicKey(int uid, String alias);
    /** Completes a signing session started by `initSign`. */
    SoterData finishSign(long session);
    /** Creates the ASK for a uid (device state change). */
    int generateAskKeyPair(int uid);
    /** Creates the device ATTK (device state change). */
    int generateAttkKeyPair(byte userId);
    /** Creates a per-uid, per-alias auth key (device state change). */
    int generateAuthKeyPair(int uid, String alias);
    /** Stable device id (32 hex chars). */
    SoterData getDeviceId();
    /** 0 when the uid already has an ASK, -5 when it does not. */
    int hasAskAlready(int uid);
    /** 0 when the auth key exists. */
    int hasAuthKey(int uid, String alias);
    /** Starts a signing session against an auth key. */
    SoterSession initSign(int uid, String alias, String challenge);
    /** Removes every key of a uid (device state change). */
    int removeAllUidKey(int uid);
    /** Removes one auth key (device state change). */
    int removeAuthKey(int uid, String alias);
    /** Verifies the device ATTK key pair. */
    int verifyAttkKeyPair();
}
