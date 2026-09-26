// 高通那个 SOTER HAL 的接口，只截了观察层认得的那些号。
//
// 号码和参数形状都是从 SOTER 宿主 APK 里那份 `vendor.qti.hardware.soter.ISoter$Stub$Proxy`
// 反查出来的（`transact(n, …)` 的 n 加参数顺序），跟设备上真实 HAL 的 AIDL 对得上。声明成
// `void` 是有意的：这个文件只给侦察客户端用，不读回包，返回值注水也无所谓 —— 真 HAL 返回
// 什么类型都不影响请求那半段字节。2 / 6 / 14 是空号，占位是为了把后面的号码顶到正确位置。
package vendor.qti.hardware.soter;

interface ISoter {
    void exportAskPublicKey(int uid);
    void reserved2();
    void exportAuthKeyPublicKey(int uid, String alias);
    void finishSign(long session);
    void generateAskKeyPair(int uid);
    void reserved6();
    void generateAuthKeyPair(int uid, String alias);
    void getDeviceId();
    void hasAskAlready(int uid);
    void hasAuthKey(int uid, String alias);
    void initSign(int uid, String alias, String challenge);
    void removeAllUidKey(int uid);
    void removeAuthKey(int uid, String alias);
    void reserved14();
}
