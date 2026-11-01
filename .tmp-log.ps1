$adb = "D:\android-sdk\platform-tools\adb.exe"
$cmd = 'logcat -d -t 400 2>/dev/null | grep -iE "ommega|keymint|keystore" | tail -22'
& $adb -s 320143945328 shell "su -c '$cmd'" 2>&1 | Select-Object -First 26
