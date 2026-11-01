#include <jni.h>
#include <string>

extern "C" JNIEXPORT jboolean JNICALL
Java_aprobes_HiddenApi_exemptNative(JNIEnv* env, jclass) {
    jclass vm_runtime = env->FindClass("dalvik/system/VMRuntime");
    if (vm_runtime == nullptr) {
        env->ExceptionClear();
        return JNI_FALSE;
    }
    jclass string_class = env->FindClass("java/lang/String");
    jobjectArray exemptions = env->NewObjectArray(1, string_class, nullptr);
    env->SetObjectArrayElement(exemptions, 0, env->NewStringUTF("L"));

    // Android 16/17 exposes this as a static method; older releases used an
    // instance method obtained through VMRuntime.getRuntime().  Try both.
    jmethodID static_set = env->GetStaticMethodID(vm_runtime, "setHiddenApiExemptions",
                                                  "([Ljava/lang/String;)V");
    if (static_set != nullptr) {
        env->CallStaticVoidMethod(vm_runtime, static_set, exemptions);
        if (!env->ExceptionCheck()) return JNI_TRUE;
        env->ExceptionClear();
    }
    jmethodID get_runtime = env->GetStaticMethodID(vm_runtime, "getRuntime",
                                                   "()Ldalvik/system/VMRuntime;");
    if (get_runtime == nullptr) {
        env->ExceptionClear();
        return JNI_FALSE;
    }
    jobject runtime = env->CallStaticObjectMethod(vm_runtime, get_runtime);
    jmethodID instance_set = env->GetMethodID(vm_runtime, "setHiddenApiExemptions",
                                              "([Ljava/lang/String;)V");
    if (instance_set == nullptr) {
        env->ExceptionClear();
        return JNI_FALSE;
    }
    env->CallVoidMethod(runtime, instance_set, exemptions);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        return JNI_FALSE;
    }
    return JNI_TRUE;
}
