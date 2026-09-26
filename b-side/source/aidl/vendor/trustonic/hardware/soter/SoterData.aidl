/*
 * Payload of every SOTER HAL call that carries data back.
 *
 * On the wire (verified against replies captured from a live OPPO PLC110):
 *   [int32 totalSize incl. itself][int32 errorCode][int32 len][len bytes, 4-byte padded][int32 length]
 *
 * The leading `totalSize` header is what the vendor's parcelable generator
 * emits for this type (the vendor's reader seeks to `start + totalSize`, so
 * extra fields stay forward compatible).
 *
 * NOTE: the marshalling code generated for this type is not used for SOTER
 * traffic.  `src/soter/hal.rs` decodes the wire form explicitly, because the
 * generated AIDL stubs do not reproduce every vendor quirk (see that file).
 * The declaration exists so rsbinder can resolve the interface and stamp the
 * correct interface descriptor onto the proxy.
 */
package vendor.trustonic.hardware.soter;

@VintfStability
parcelable SoterData {
    int errorCode;
    byte[] data;
    int length;
}
