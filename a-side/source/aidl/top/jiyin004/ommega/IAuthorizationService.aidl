package top.jiyin004.ommega;

import android.hardware.security.keymint.HardwareAuthToken;
import android.hardware.security.keymint.HardwareAuthenticatorType;
import android.security.authorization.AuthorizationTokens;
import top.jiyin004.ommega.CallerInfo;

interface IAuthorizationService {
    void addAuthToken(in @nullable CallerInfo ctx, in HardwareAuthToken authToken);

    void onDeviceUnlocked(in @nullable CallerInfo ctx, in int userId, in @nullable byte[] password);

    // 查一个用户的 super key 状态，给注入器 replay 完回查用：
    // 0 = Uninitialized（没 super key）、1 = CeLocked（有但没解开）、2 = CeUnlocked。
    // onDeviceUnlocked 内部失败只记一行 error，binder 照旧回 Ok，光看返回值骗人。
    int getUserState(in @nullable CallerInfo ctx, in int userId);

    void onDeviceLocked(in @nullable CallerInfo ctx, in int userId, in long[] unlockingSids,
            in boolean weakUnlockEnabled);

    void onUserStorageLocked(in @nullable CallerInfo ctx, in int userId);

    void onWeakUnlockMethodsExpired(in @nullable CallerInfo ctx, in int userId);

    void onNonLskfUnlockMethodsExpired(in @nullable CallerInfo ctx, in int userId);

    AuthorizationTokens getAuthTokensForCredStore(in @nullable CallerInfo ctx, in long challenge,
            in long secureUserId, in long authTokenMaxAgeMillis);

    long getLastAuthTime(in @nullable CallerInfo ctx, in long secureUserId,
            in HardwareAuthenticatorType[] authTypes);
}
