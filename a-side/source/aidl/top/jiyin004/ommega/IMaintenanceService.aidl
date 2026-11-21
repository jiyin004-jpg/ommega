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

    // 宿主拦到一笔 SOTER HAL 调用后，问 daemon 这笔该由谁答。回的是一个自描述的小 blob
    // （第一个字节是结论：0 = 后面跟着远程答案、1 = 用 A 端本地自签、2 = 透传看 HAL），
    // 布局在 `common/src/soter_relay.rs`，payload 与 daemon 共用那一份实现。
    //
    // 决策为什么在 daemon 这边：宿主是 uid 1000，配置和数据根在 0770 的 keystore 目录里，
    // 它根本打不开（debug_logging 就是为此另做了一份 log_flag 副本）；daemon 又盯着那个
    // 文件，所以 WebUI 改完开关下一笔调用就按新值走。没有 caller context 要查：能走到
    // 这里的 peer 已经过了 socket 鉴权，跟 reportHookEvent 同理。
    byte[] forwardSoter(in String request);

    // 把整份 SOTER 料库文本落盘。app 域的进程（SOTER 宿主是 platform_app、带 MLS
    // 类别）读不到也写不动那个文件——数据根现在在 0700 的 `/data/misc/keystore` 底下。
    // 所以那半边只能把整份文本交给 daemon 代写。
    // 跟 forwardSoter 同理：能走到这里的 peer 已经过了 socket 鉴权，不需要 caller context。
    boolean writeSoterStore(in String text);

    // 料库那半边的读：daemon 读出来原样交给调用方，没有这个文件就回 null。
    // 写走上面的 writeSoterStore，读走这里——两边必须成对，不然调用方读到的是「空」，
    // 它按空料库做一次读-改-写就把别人的键整段铲掉了。
    @nullable String readSoterStore();

    // 数据根里其它小件（log_flag / config / soter_ok / soter_counter / cpu_id …）
    // 的按名读写。只认单层文件名，daemon 那边按数据根拼路径并挡掉越界。
    // app 域的那半边全靠这一对活着：它连目录都进不去。
    @nullable String readState(in String name);
    boolean writeState(in String name, in String data);
}
