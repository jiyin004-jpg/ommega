/*
 * Signing session handle returned by `initSign`.
 *
 * On the wire: [int32 totalSize = 16][int32 errorCode][int64 session].
 *
 * The vendor generator emits the size header even though this declaration
 * looks fixed-size, so the generated stub cannot be used to read replies;
 * `src/soter/hal.rs` handles it (and reads the session id as a signed 64-bit
 * value in the same byte order the vendor stub uses).
 */
package vendor.trustonic.hardware.soter;

@VintfStability
parcelable SoterSession {
    int errorCode;
    long session;
}
