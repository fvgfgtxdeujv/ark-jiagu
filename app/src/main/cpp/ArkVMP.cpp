#include "ArkVMP.h"
#include "VmpRuntime.h"
#include "ArkAntiDebug.h"

#include <string>
#include <android/log.h>
#include <dlfcn.h>
#include <zlib.h>
#include <fcntl.h>

#define LOG_TAG "ArkVMP_ArkVMP"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// ==================== SO 自校验（魔改#9） ====================
// 在 JNI_OnLoad 时计算 SO 的 CRC32，后续定期校验是否被 patch
uLong g_selfCrc32 = 0;
bool g_selfCrcValid = false;

// 从 /proc/self/maps 读取 SO 文件路径
static std::string getSelfSoPath() {
    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0) return "";

    char buf[4096];
    ssize_t len = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (len <= 0) return "";

    buf[len] = '\0';

    // 查找包含 "r-xp" 且以 ".so" 结尾的行
    char *line = buf;
    while (line) {
        char *next = strstr(line, "\n");
        if (next) *next = '\0';

        // 查找 r-xp 权限段
        if (strstr(line, "r-xp")) {
            // 查找路径（最后一个空格之后）
            char *path = strrchr(line, ' ');
            if (path && *(path + 1) != '\0') {
                path++;
                if (strstr(path, ".so") || strstr(path, ".so")) {
                    std::string result(path);
                    // 去掉可能的注释部分
                    size_t space = result.find(' ');
                    if (space != std::string::npos) {
                        result = result.substr(0, space);
                    }
                    return result;
                }
            }
        }

        line = next ? next + 1 : nullptr;
    }

    return "";
}

// 计算文件的 CRC32
static uLong computeFileCrc32(const std::string &filePath) {
    int fd = open(filePath.c_str(), O_RDONLY);
    if (fd < 0) return 0;

    uLong crc = crc32(0L, Z_NULL, 0);
    char buf[4096];
    ssize_t len;

    while ((len = read(fd, buf, sizeof(buf))) > 0) {
        crc = crc32(crc, (const Bytef *)buf, len);
    }

    close(fd);
    return crc;
}

// 初始化 SO 自校验基线
static bool initSelfCrc32() {
    if (g_selfCrcValid) return true;

    std::string soPath = getSelfSoPath();
    if (soPath.empty()) {
        LOGE("SO自校验：找不到SO路径");
        return false;
    }

    g_selfCrc32 = computeFileCrc32(soPath);
    if (g_selfCrc32 == 0) {
        LOGE("SO自校验：CRC计算失败 path=%s", soPath.c_str());
        return false;
    }

    g_selfCrcValid = true;
    LOGI("SO自校验基线已建立 path=%s crc=0x%lx", soPath.c_str(), g_selfCrc32);
    return true;
}

// 校验 SO 是否被修改
bool checkSelfIntegrity() {
    if (!g_selfCrcValid) {
        // 还没建立基线，先建立
        return initSelfCrc32();
    }

    std::string soPath = getSelfSoPath();
    if (soPath.empty()) {
        LOGE("SO自校验：找不到SO路径");
        return false;
    }

    uLong currentCrc = computeFileCrc32(soPath);
    if (currentCrc != g_selfCrc32) {
        LOGE("SO自校验失败：CRC不匹配 baseline=0x%lx current=0x%lx path=%s",
             g_selfCrc32, currentCrc, soPath.c_str());
        return false;
    }

    return true;
}
// ====================================================

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

// ==================== 第二代嵌入式方案 ====================
// VMP 类名固定为 com/ark/safe/VMP
// 不再通过 System.getProperty("ark") 查找壳类名
// VMP 类通过 <clinit> 中的 System.loadLibrary 自动触发 SO 加载
// ==========================================================
static const char *VMP_CLASS_NAME = "com/ark/safe/VMP";

static void native_callVoid(JNIEnv *env, jclass clazz, jint methodId, jobject thiz, jobjectArray args, jboolean isDebuggable) {
    //LOGI("callVoid methodId=%d", methodId);
    VmpRuntime_Execute(env, methodId, thiz, args, isDebuggable);
}

static jboolean native_callBoolean(JNIEnv *env, jclass clazz, jint methodId, jobject thiz, jobjectArray args, jboolean isDebuggable) {
    //LOGI("callBoolean methodId=%d", methodId);
    return VmpRuntime_Execute(env, methodId, thiz, args, isDebuggable).booleanValue;
}

static jbyte native_callByte(JNIEnv *env, jclass clazz, jint methodId, jobject thiz, jobjectArray args, jboolean isDebuggable) {
    //LOGI("callByte methodId=%d", methodId);
    return VmpRuntime_Execute(env, methodId, thiz, args, isDebuggable).byteValue;
}

static jshort native_callShort(JNIEnv *env, jclass clazz, jint methodId, jobject thiz, jobjectArray args, jboolean isDebuggable) {
    //LOGI("callShort methodId=%d", methodId);
    return VmpRuntime_Execute(env, methodId, thiz, args, isDebuggable).shortValue;
}

static jchar native_callChar(JNIEnv *env, jclass clazz, jint methodId, jobject thiz, jobjectArray args, jboolean isDebuggable) {
    //LOGI("callChar methodId=%d", methodId);
    return VmpRuntime_Execute(env, methodId, thiz, args, isDebuggable).charValue;
}

static jint native_callInt(JNIEnv *env, jclass clazz, jint methodId, jobject thiz, jobjectArray args, jboolean isDebuggable) {
    //LOGI("callInt methodId=%d", methodId);
    return VmpRuntime_Execute(env, methodId, thiz, args, isDebuggable).intValue;
}

static jlong native_callLong(JNIEnv *env, jclass clazz, jint methodId, jobject thiz, jobjectArray args, jboolean isDebuggable) {
    //LOGI("callLong methodId=%d", methodId);
    return VmpRuntime_Execute(env, methodId, thiz, args, isDebuggable).longValue;
}

static jfloat native_callFloat(JNIEnv *env, jclass clazz, jint methodId, jobject thiz, jobjectArray args, jboolean isDebuggable) {
    //LOGI("callFloat methodId=%d", methodId);
    return VmpRuntime_Execute(env, methodId, thiz, args, isDebuggable).floatValue;
}

static jdouble native_callDouble(JNIEnv *env, jclass clazz, jint methodId, jobject thiz, jobjectArray args, jboolean isDebuggable) {
    //LOGI("callDouble methodId=%d", methodId);
    return VmpRuntime_Execute(env, methodId, thiz, args, isDebuggable).doubleValue;
}

static jobject native_callObject(JNIEnv *env, jclass clazz, jint methodId, jobject thiz, jobjectArray args, jboolean isDebuggable) {
    //LOGI("callObject methodId=%d", methodId);
    return VmpRuntime_Execute(env, methodId, thiz, args, isDebuggable).objectValue;
}

static JNINativeMethod g_methods[] = {
        {"callVoid", "(ILjava/lang/Object;[Ljava/lang/Object;Z)V", (void *) native_callVoid},
        {"callBoolean", "(ILjava/lang/Object;[Ljava/lang/Object;Z)Z", (void *) native_callBoolean},
        {"callByte", "(ILjava/lang/Object;[Ljava/lang/Object;Z)B", (void *) native_callByte},
        {"callShort", "(ILjava/lang/Object;[Ljava/lang/Object;Z)S", (void *) native_callShort},
        {"callChar", "(ILjava/lang/Object;[Ljava/lang/Object;Z)C", (void *) native_callChar},
        {"callInt", "(ILjava/lang/Object;[Ljava/lang/Object;Z)I", (void *) native_callInt},
        {"callLong", "(ILjava/lang/Object;[Ljava/lang/Object;Z)J", (void *) native_callLong},
        {"callFloat", "(ILjava/lang/Object;[Ljava/lang/Object;Z)F", (void *) native_callFloat},
        {"callDouble", "(ILjava/lang/Object;[Ljava/lang/Object;Z)D", (void *) native_callDouble},
        {"callObject", "(ILjava/lang/Object;[Ljava/lang/Object;Z)Ljava/lang/Object;", (void *) native_callObject}
};

extern "C" jint ArkVMP_OnLoad(JavaVM *vm) {
    g_vm = vm;
    (void) ArkVmpKeepCustomSection();//引用自定义字符串信息防止被编译器优化

    JNIEnv *env = nullptr;
    if (vm->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK) {
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
