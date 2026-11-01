# A端缺口探针 · 源码包

最终 APK（构建产物）单独提供：`a-gap-probe-final.apk`。本包只含源码、Gradle 工程、报告和预编译 JNI 库，不含日志、构建缓存、基线输出或 APK。

## 结构

    app/src/main/java/aprobes/
      MainActivity.java       UI、运行调度、结果导出
      Catalog.java            111 项检测目录
      Attestation.java        KeyDescription / AuthorizationList DER 解析
      Raw.java                raw keystore2 Binder 帧（sized parcelable）
      Util.java               KeyStore/KeyGenParameterSpec/证书辅助
      Sys.java                SystemProperties / /proc 读取
      Root.java               只读 su 辅助
      Fixtures.java           导入测试用 EC key + 自签证书
      HiddenApi.java          仅为加载 JNI 库；不调用 VMRuntime 豁免
    app/src/main/cpp/
      hiddenapi.cpp           JNI 库加载/兼容（不再调用 setHiddenApiExemptions）
      rawnative.cpp           ServiceManager/Parcel/IBinder raw getKeyEntry
    app/src/main/jniLibs/arm64-v8a/libhiddenapi.so
                             由上面两份 cpp 生成，Gradle 直接打包
    GAP-REPORT.md             AOSP 17 对照、F-01..F-25、A/B 实测与校准
    README.md                 安装/运行说明
    BUILD.md                  本文件

## 构建

    $env:ANDROID_HOME='<Android SDK>'
    $env:ANDROID_USER_HOME='<可写目录>/.android'
    $env:GRADLE_USER_HOME='<可写目录>/.gradle'
    cd AProbe
    .\gradlew.bat assembleDebug

产物：`app/build/outputs/apk/debug/app-debug.apk`（debug 签名）。

## 重建 JNI 库

Gradle 工程当前直接使用 `app/src/main/jniLibs/arm64-v8a/libhiddenapi.so`，不强制 CMake。若修改了 cpp，可用 NDK 重新生成：

    $NDK='<Android NDK>'
    & "$NDK\toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android31-clang++.cmd" ^
      -shared -fPIC -O2 -std=c++17 -static-libstdc++ ^
      app/src/main/cpp/hiddenapi.cpp app/src/main/cpp/rawnative.cpp ^
      -o app/src/main/jniLibs/arm64-v8a/libhiddenapi.so -llog

必须使用 `-static-libstdc++`，否则 Android 上会因缺少 `libc++_shared.so` 加载失败。

## 检测项与状态

- 111 项，B 基线：77 PASS、0 HIT、0 ERROR、6 INCONCLUSIVE、28 SKIP。
- A（mask-off，模块 2.1.3）：73 PASS、11 HIT、0 ERROR、7 INCONCLUSIVE、20 SKIP。
- A 的 11 HIT 归并为 4 个根因：F-21 设备属性 attestation、F-12 认证策略/known alias、F-22 ML-DSA、F-11 时序整形。
- 详见 `GAP-REPORT.md`。

## 安全边界

- 本工程只使用标准 AndroidKeyStore 和 raw keystore2 Binder 读取，不修改 A/B 模块源码、SPL、属性或服务。
- 主 B（PHB110 / e73a228c）上 R05 AGREE_KEY 强制 SKIP。
- 不包含任何设备日志、私钥材料（Fixtures 是公开测试用的自签 EC 密钥/证书）或生产配置。
