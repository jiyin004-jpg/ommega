package top.jiyin004.ommega;

import android.system.keystore2.Domain;
import android.system.keystore2.KeyDescriptor;
import top.jiyin004.ommega.CallerInfo;

interface IMaintenanceService {
    void onUserAdded(in @nullable CallerInfo ctx, in int userId);
    void initUserSuperKeys(in @nullable CallerInfo ctx, in int userId, in byte[] password,
            in boolean allowExisting);
    void onUserRemoved(in @nullable CallerInfo ctx, in int userId);
    void onUserLskfRemoved(in @nullable CallerInfo ctx, in int userId);
    void clearNamespace(in @nullable CallerInfo ctx, in Domain domain, in long nspace);
    void earlyBootEnded(in @nullable CallerInfo ctx);
    void migrateKeyNamespace(in @nullable CallerInfo ctx, in KeyDescriptor source,
            in KeyDescriptor destination);
    void deleteAllKeys(in @nullable CallerInfo ctx);
    long[] getAppUidsAffectedBySid(in @nullable CallerInfo ctx, in int userId, in long sid);
    void onUserPasswordChanged(in @nullable CallerInfo ctx, in int userId,
            in @nullable byte[] password);
    // Hook observations from an injected process travel back this way. An app-domain target
    // cannot write the keystore log file (0700 directory) and logcat stays empty for the
    // injected image, so RPC is the only channel that makes them visible at all. One string:
    // the hook formats its own line. No caller context: the observation is about someone
    // else's transaction, and the peer is already identified by the socket itself.
    void reportHookEvent(in String message);
}
