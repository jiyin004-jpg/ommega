package aprobes;

import java.util.Base64;

/** Fixed software EC key + self-signed certificate used for importKey checks. */
public final class Fixtures {
    private Fixtures() {}

    public static final byte[] IMPORT_KEY = Base64.getDecoder().decode(
            "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCDmmwvtmc0egPzF6jgrQcqfiFuMV0in4ijVCo9N0fFITw==");
    public static final byte[] IMPORT_CERT = Base64.getDecoder().decode(
            "MIIBczCCARmgAwIBAgIIW+LS1nAHDp4wCgYIKoZIzj0EAwIwLjEOMAwGA1UEChMFUHJvYmUxHDAaBgNVBAMTE09tbWVnYSBQcm9iZSBJbXBvcnQwHhcNMjYxMDMwMTExOTMyWhcNMzYxMDI3MTExOTMyWjAuMQ4wDAYDVQQKEwVQcm9iZTEcMBoGA1UEAxMTT21tZWdhIFByb2JlIEltcG9ydDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABE5CJyJkbsA0FT6j6HaslM1tzjLGn2Qqa5Eyg7ksCjnG/1CWB3lG1F5RONC8FkhtPGfA9mKhslLj7gkigs7bfMqjITAfMB0GA1UdDgQWBBTGzSUqRthrF0oqhU3FnM/iZxNGfzAKBggqhkjOPQQDAgNIADBFAiBArbpFGcNABGLD4a6G2ruqzjHczqibC0WEcC2tcvEplAIhAOCzXQ0IiZRg553fRL3SBo1AR0Y9SAl6smcZQK97rHDq");
}
