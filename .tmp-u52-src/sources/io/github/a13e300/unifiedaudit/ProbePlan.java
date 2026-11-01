package io.github.a13e300.unifiedaudit;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/* loaded from: classes.dex */
final class ProbePlan {
    static final String[][] GROUPS = {new String[]{"A01", "A02", "A03", "A04", "A05"}, new String[]{"H01", "H02", "H03", "H04", "H05"}, new String[]{"G01", "G02", "G03", "G04", "G05"}, new String[]{"EC_SIGN", "RSA_SIGN", "GCM_ROUNDTRIP", "GCM_TAMPER", "HMAC_IMPORT", "PRIVATE_OPAQUE", "SECRET_OPAQUE", "KEY_ORIGINS"}, new String[]{"CHALLENGE", "PUBLIC_BINDING", "CERT_READBACK", "APP_PACKAGES", "APP_SIGNATURES", "APP_AUTH_LOCATION", "SECURITY_ENUMS", "ROOT_OF_TRUST", "BOOT_STABILITY", "OS_PATCH", "BOOT_PROPERTIES", "EXPLICIT_VALIDITY", "ISSUER_AUTHORITY", "KEYINFO_LEVEL", "EC_PARAMETERS"}, new String[]{"ALIAS_KEYID", "FINISH_LIFECYCLE", "ABORT_LIFECYCLE", "UPDATE_LIMIT", "UPDATE_OVERFLOW", "FINISH_LIMIT", "FINISH_OVERFLOW"}, new String[]{"SOFTWARE_CA", "MIXED_CONTRACT", "ATTEST_PARENT", "OMK_READ", "OMK_VIEWS", "REPLACEMENT_OPERATION"}, new String[]{"SERIAL_FIDELITY", "SUBJECT_FIDELITY", "EXTENSION_UNIQUENESS", "OPERATION_ROT", "CHAIN_VIEW", "CHALLENGE_LIMIT"}, new String[]{"MAX_USES_PER_BOOT", "ACTIVE_TIME_GATE", "ORIGINATION_EXPIRE_GATE", "EARLY_BOOT_IMPORT", "UNIQUE_ID_CONSISTENCY", "UNATTESTED_CHAIN_SHAPE", "IMPORT_CERT_SHAPE", "READ_STABILITY", "TAIL_STABILITY"}, new String[]{"H06", "H07", "H08", "H09", "H10"}, new String[]{"G06", "G07", "G08", "G09", "G10"}};
    static final String[] QUIET = {"TEESIM_TIMING"};
    static final int WORKERS = 4;

    ProbePlan() {
    }

    static Set<String> select(String[] strArr) {
        return new HashSet(Arrays.asList(strArr));
    }
}
