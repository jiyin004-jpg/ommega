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

    // 宿主拦到一笔 SOTER HAL 调用后，问 daemon 这笔该由谁答。回的是一个自描述的小 blob：
    // 第一个字节是结论（0 = 后面跟着远程答案、1 = 用 A 端本地自签、2 = 透传真 HAL），
    // 布局在 `common/src/soter_relay.rs`，payload 与 daemon 共用那一份实现。
    //
    // 决策为什么在 daemon 这边：宿主是 uid 1000,而配置躺在 0770 的 keystore 目录里，
    // 它根本打不开（debug_logging 就是为此另做了一份 log_flag 副本）；daemon 又盯着那个
    // 文件，所以 WebUI 改完开关下一笔调用就按新值走。没有 caller context 要查：能走到
    // 这里的 peer 已经过了 socket 鉴权，跟 reportHookEvent 同理。
    byte[] forwardSoter(in String request);
}
