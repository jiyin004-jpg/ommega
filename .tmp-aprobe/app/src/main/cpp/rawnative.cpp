#include <jni.h>
#include <string>

static jclass find(JNIEnv* env, const char* name) {
    jclass c = env->FindClass(name);
    if (env->ExceptionCheck()) env->ExceptionClear();
    return c;
}

static jmethodID method(JNIEnv* env, jclass c, const char* name, const char* sig, bool isStatic) {
    if (c == nullptr) return nullptr;
    jmethodID m = isStatic ? env->GetStaticMethodID(c, name, sig) : env->GetMethodID(c, name, sig);
    if (env->ExceptionCheck()) env->ExceptionClear();
    return m;
}

extern "C" JNIEXPORT jint JNICALL
Java_aprobes_Raw_nativeRawGetEntry(JNIEnv* env, jclass, jstring jalias, jint marker,
                                   jboolean wrongToken, jboolean trailing) {
    jclass sm = find(env, "android/os/ServiceManager");
    jmethodID getService = method(env, sm, "getService",
            "(Ljava/lang/String;)Landroid/os/IBinder;", true);
    if (getService == nullptr) return -998;
    jstring service = env->NewStringUTF("android.system.keystore2.IKeystoreService/default");
    jobject binder = env->CallStaticObjectMethod(sm, getService, service);
    if (env->ExceptionCheck()) { env->ExceptionClear(); return -997; }
    if (binder == nullptr) return -996;

    jclass pc = find(env, "android/os/Parcel");
    jmethodID obtain = method(env, pc, "obtain", "()Landroid/os/Parcel;", true);
    jmethodID recycle = method(env, pc, "recycle", "()V", false);
    jmethodID writeToken = method(env, pc, "writeInterfaceToken", "(Ljava/lang/String;)V", false);
    jmethodID writeInt = method(env, pc, "writeInt", "(I)V", false);
    jmethodID writeLong = method(env, pc, "writeLong", "(J)V", false);
    jmethodID writeString = method(env, pc, "writeString", "(Ljava/lang/String;)V", false);
    jmethodID writeBytes = method(env, pc, "writeByteArray", "([B)V", false);
    jmethodID readInt = method(env, pc, "readInt", "()I", false);
    if (obtain == nullptr || writeToken == nullptr || writeInt == nullptr
            || writeLong == nullptr || writeString == nullptr || writeBytes == nullptr
            || readInt == nullptr) return -995;

    jobject data = env->CallStaticObjectMethod(pc, obtain);
    jobject reply = env->CallStaticObjectMethod(pc, obtain);
    if (data == nullptr || reply == nullptr) return -994;

    jstring token = env->NewStringUTF(wrongToken ? "android.security.maintenance.IKeystoreMaintenance"
                                                : "android.system.keystore2.IKeystoreService");
    env->CallVoidMethod(data, writeToken, token);
    env->CallVoidMethod(data, writeInt, marker);
    env->CallVoidMethod(data, writeInt, 0);      // Domain.APP
    env->CallVoidMethod(data, writeLong, 0L);    // nspace
    env->CallVoidMethod(data, writeString, jalias);
    env->CallVoidMethod(data, writeBytes, nullptr);
    if (trailing) env->CallVoidMethod(data, writeInt, 0x12345678);
    if (env->ExceptionCheck()) { env->ExceptionClear(); return -993; }

    jclass ib = find(env, "android/os/IBinder");
    jmethodID transact = method(env, ib, "transact",
            "(ILandroid/os/Parcel;Landroid/os/Parcel;I)Z", false);
    if (transact == nullptr) return -992;
    env->CallBooleanMethod(binder, transact, 2, data, reply, 0); // TRANSACTION_getKeyEntry
    if (env->ExceptionCheck()) { env->ExceptionClear(); return -991; }
    jint code = env->CallIntMethod(reply, readInt);
    if (env->ExceptionCheck()) { env->ExceptionClear(); return -990; }
    if (recycle) {
        env->CallVoidMethod(data, recycle);
        env->CallVoidMethod(reply, recycle);
        if (env->ExceptionCheck()) env->ExceptionClear();
    }
    return code;
}
