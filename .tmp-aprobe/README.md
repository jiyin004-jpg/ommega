# A端缺口探针（AProbe）

这是根据 Android 17 AOSP 对当前 Ommega A 端模块 2.0.1 做静态调查后生成的探针检测器。
调查结论、代码行号和 AOSP 依据见 [GAP-REPORT.md](GAP-REPORT.md)。

## 产物

- APK：app/build/outputs/apk/debug/app-debug.apk（debug 签名，包名 aprobes.agap，SHA-256 CEB825CD43931E08A460BCF2DBD9A379D83ADFD91824C0A500B16F078D66DC14）
- 源码：app/src/main/java/aprobes/
- 111 个检测项，按 B/A/R/C/M/K/S/T/L/F 分组；UI 卡片显示 状态 / ID / 标题 / AOSP 期望 / 本机结果
- 结果文件：/sdcard/Android/data/aprobes.agap/files/a-gap-probe.txt

## 在 A 上运行

1. 卸载旧版（签名不同）后安装 app-debug.apk。
2. 确认 A 端 Ommega 已安装、KeyMint/Injector 已启动。
3. 把 aprobes.agap 加入 Ommega 的 target.txt 或 WebUI 应用作用域；否则请求会走 System，
   探针只能看到 stock KeyMint。
4. 打开应用，等待自动运行结束；点“重新运行”可复测，点“复制结果”导出文本。
5. 可选：授予 KernelSU/APatch 的 su 权限，F 组会只读检查模块文件和 keymint.log；
   无 root 时 F 组显示“跳过”。

## 注意

- 不要在 B（PHB110 / e73a228c）上安装或运行；仓库 AGENTS.md 禁止在主 B 上做 APK/HAL 探针。
- 检测器不会修改属性、不会重启服务、不会杀进程、不会写模块目录；root 只执行 cat/test/getprop。
- 部分检测项（A29-A31、M01-M06、K02-K05）依赖 A 的 Android 17 / KeyMint 能力；失败时先看
  “AOSP 期望”和“本机结果”的具体异常，不要把 SKIP/INCONCLUSIVE 当作通过。

## 构建

    $env:GRADLE_USER_HOME='D:\Users\Andrea-TB\Desktop\ommega\.gradle-home'
    $env:ANDROID_USER_HOME='D:\Users\Andrea-TB\Desktop\ommega\.android-home'
    cd 检测器\AProbe
    & 'E:\Buildcache\gradle\wrapper\dists\gradle-9.2.0-bin\11i5gvueggl8a5cioxuftxrik\gradle-9.2.0\bin\gradle.bat' assembleDebug --no-daemon

JNI 只编译一个 arm64-v8a 的 libhiddenapi.so，用于 VMRuntime.setHiddenApiExemptions；
源码在 app/src/main/cpp/hiddenapi.cpp。
