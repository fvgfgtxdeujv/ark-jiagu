#include "ArkVMP.h"
#include "VmpRuntime.h"

#include <string>
#include <android/log.h>

#define LOG_TAG "ArkVMP_ArkVMP"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

extern "C"
__attribute__((used))
__attribute__((visibility("default")))
__attribute__((section(".Ark是一款开源离线免费加固工具，支持dex加密/VMP抽代码/签名校验等，倒卖死妈，加固工具作者QQ2380494437_By菜鸟八哥。特别是有个叫易固安全的傻逼，加固圈的诈骗犯，你妈死了。")))
const char g_ark_vmp_section[] = "还看，看你妈呢";

extern "C"
__attribute__((used))
__attribute__((visibility("default")))
const void *ArkVmpKeepCustomSection() {
    return g_ark_vmp_section;
}


static JavaVM *g_vm = nullptr;

extern "C" void ArkVMP_SetContext(JNIEnv *env, jobject context) {
    VmpRuntime_SetContext(env, context);
}

static std::string jstringToString(JNIEnv *env, jstring str) {
    if (str == nullptr) {
        return "";
    }

    const char *chars = env->GetStringUTFChars(str, nullptr);
    if (chars == nullptr) {
        return "";
    }

    std::string result(chars);
    env->ReleaseStringUTFChars(str, chars);

    return result;
}

// ==================== 第二代嵌入式方案 ====================
// VMP 类名固定为 com/ark/safe/VMP
// 不再通过 System.getProperty("ark") 查找壳类名
// VMP 类通过 <clinit> 中的 System.loadLibrary 自动触发 SO 加载
// ==========================================================
static const char *VMP_CLASS_NAME = "com/ark/safe/VMP";

static void native_callVoid(JNIEnv *env, jclass clazz, jint methodId, jobject thiz, jobjectArray args) {
    //LOGI("callVoid methodId=%d", methodId);
    VmpRuntime_Execute(env, methodId, thiz, args);
}

static jboolean native_callBoolean(JNIEnv *env, jclass clazz, jint methodId, jobject thiz, jobjectArray args) {
    //LOGI("callBoolean methodId=%d", methodId);
    return VmpRuntime_Execute(env, methodId, thiz, args).booleanValue;
}

static jbyte native_callByte(JNIEnv *env, jclass clazz, jint methodId, jobject thiz, jobjectArray args) {
    //LOGI("callByte methodId=%d", methodId);
    return VmpRuntime_Execute(env, methodId, thiz, args).byteValue;
}

static jshort native_callShort(JNIEnv *env, jclass clazz, jint methodId, jobject thiz, jobjectArray args) {
    //LOGI("callShort methodId=%d", methodId);
    return VmpRuntime_Execute(env, methodId, thiz, args).shortValue;
}

static jchar native_callChar(JNIEnv *env, jclass clazz, jint methodId, jobject thiz, jobjectArray args) {
    //LOGI("callChar methodId=%d", methodId);
    return VmpRuntime_Execute(env, methodId, thiz, args).charValue;
}

static jint native_callInt(JNIEnv *env, jclass clazz, jint methodId, jobject thiz, jobjectArray args) {
    //LOGI("callInt methodId=%d", methodId);
    return VmpRuntime_Execute(env, methodId, thiz, args).intValue;
}

static jlong native_callLong(JNIEnv *env, jclass clazz, jint methodId, jobject thiz, jobjectArray args) {
    //LOGI("callLong methodId=%d", methodId);
    return VmpRuntime_Execute(env, methodId, thiz, args).longValue;
}

static jfloat native_callFloat(JNIEnv *env, jclass clazz, jint methodId, jobject thiz, jobjectArray args) {
    //LOGI("callFloat methodId=%d", methodId);
    return VmpRuntime_Execute(env, methodId, thiz, args).floatValue;
}

static jdouble native_callDouble(JNIEnv *env, jclass clazz, jint methodId, jobject thiz, jobjectArray args) {
    //LOGI("callDouble methodId=%d", methodId);
    return VmpRuntime_Execute(env, methodId, thiz, args).doubleValue;
}

static jobject native_callObject(JNIEnv *env, jclass clazz, jint methodId, jobject thiz, jobjectArray args) {
    //LOGI("callObject methodId=%d", methodId);
    return VmpRuntime_Execute(env, methodId, thiz, args).objectValue;
}

static JNINativeMethod g_methods[] = {
        {"callVoid", "(ILjava/lang/Object;[Ljava/lang/Object;)V", (void *) native_callVoid},
        {"callBoolean", "(ILjava/lang/Object;[Ljava/lang/Object;)Z", (void *) native_callBoolean},
        {"callByte", "(ILjava/lang/Object;[Ljava/lang/Object;)B", (void *) native_callByte},
        {"callShort", "(ILjava/lang/Object;[Ljava/lang/Object;)S", (void *) native_callShort},
        {"callChar", "(ILjava/lang/Object;[Ljava/lang/Object;)C", (void *) native_callChar},
        {"callInt", "(ILjava/lang/Object;[Ljava/lang/Object;)I", (void *) native_callInt},
        {"callLong", "(ILjava/lang/Object;[Ljava/lang/Object;)J", (void *) native_callLong},
        {"callFloat", "(ILjava/lang/Object;[Ljava/lang/Object;)F", (void *) native_callFloat},
        {"callDouble", "(ILjava/lang/Object;[Ljava/lang/Object;)D", (void *) native_callDouble},
        {"callObject", "(ILjava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", (void *) native_callObject}
};

extern "C" jint ArkVMP_OnLoad(JavaVM *vm) {
    g_vm = vm;
    (void) ArkVmpKeepCustomSection();//引用自定义字符串信息防止被编译器优化
    JNIEnv *env = nullptr;
    if (vm->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        //LOGE("ArkVMP 获取 JNIEnv 失败");
        return JNI_ERR;
    }

    // 第二代嵌入式方案：直接 FindClass VMP 类
    // VMP 类通过 <clinit> 中的 System.loadLibrary 触发本 SO 加载
    jclass vmpClass = env->FindClass(VMP_CLASS_NAME);
    if (vmpClass == nullptr) {
        env->ExceptionClear();
        //LOGE("找不到VMP类：%s", VMP_CLASS_NAME);
        return JNI_ERR;
    }

    //LOGI("ArkVMP 开始注册call方法到VMP类：%s", VMP_CLASS_NAME);

    int methodCount = sizeof(g_methods) / sizeof(g_methods[0]);

    if (env->RegisterNatives(vmpClass, g_methods, methodCount) != JNI_OK) {
        env->ExceptionClear();
        //LOGE("ArkVMP RegisterNatives失败，VMP类：%s", VMP_CLASS_NAME);
        return JNI_ERR;
    }

    //LOGI("ArkVMP注册成功，VMP类：%s", VMP_CLASS_NAME);

    return JNI_VERSION_1_6;
}
