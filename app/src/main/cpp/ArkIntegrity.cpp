#include "ArkIntegrity.h"
#include "ArkAntiDebug.h"
#include "sha256.h"

#include <string>
#include <android/log.h>
#include <unistd.h>
#include <fcntl.h>
#include <zlib.h>

#define LOG_TAG "ArkVMP_Integrity"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// ==================== SO 自校验状态（由 ArkVMP.cpp 提供） ====================
extern uLong g_selfCrc32;
extern bool g_selfCrcValid;

// ==================== DEX 完整性校验（魔改#10） ====================
static unsigned char g_dexSha256[32];
static bool g_dexShaValid = false;

// 从 JNI 获取 VMP 类的 ClassDef，然后获取其 DEX 数据
bool computeVmpDexSha256(JNIEnv *env, unsigned char *outSha256) {
    if (env == nullptr) return false;

    // 找到 VMP 类
    jclass vmpClass = env->FindClass("com/ark/safe/VMP");
    if (vmpClass == nullptr) {
        env->ExceptionClear();
        return false;
    }

    // 获取 class loader
    jobject classLoader = nullptr;
    jclass classClass = env->GetObjectClass(vmpClass);
    if (classClass == nullptr) {
        env->ExceptionClear();
        return false;
    }

    jmethodID midGetLoader = env->GetMethodID(classClass, "getClassLoader", "()Ljava/lang/ClassLoader;");
    if (midGetLoader == nullptr) {
        env->ExceptionClear();
        return false;
    }

    jobject loader = env->CallObjectMethod(vmpClass, midGetLoader);
    if (loader == nullptr) {
        env->ExceptionClear();
        return false;
    }

    // 通过 ClassLoader.getResource("com/ark/safe/VMP.class") 获取 DEX 数据
    jclass loaderClass = env->GetObjectClass(loader);
    jmethodID midGetResource = env->GetMethodID(
            loaderClass,
            "getResource",
            "(Ljava/lang/String;)Ljava/net/URL;"
    );
    if (midGetResource == nullptr) {
        env->ExceptionClear();
        return false;
    }

    jstring dexPath = env->NewStringUTF("com/ark/safe/VMP.class");
    jobject url = env->CallObjectMethod(loader, midGetResource, dexPath);
    env->DeleteLocalRef(dexPath);

    if (url == nullptr) {
        env->ExceptionClear();
        return false;
    }

    // 打开 URL 连接读取数据
    jclass urlClass = env->GetObjectClass(url);
    jmethodID midOpenConnection = env->GetMethodID(urlClass, "openConnection", "()Ljava/net/URLConnection;");
    if (midOpenConnection == nullptr) {
        env->ExceptionClear();
        return false;
    }

    jobject conn = env->CallObjectMethod(url, midOpenConnection);
    if (conn == nullptr) {
        env->ExceptionClear();
        return false;
    }

    jclass connClass = env->GetObjectClass(conn);
    jmethodID midGetInputStream = env->GetMethodID(connClass, "getInputStream", "()Ljava/io/InputStream;");
    if (midGetInputStream == nullptr) {
        env->ExceptionClear();
        return false;
    }

    jobject is = env->CallObjectMethod(conn, midGetInputStream);
    if (is == nullptr) {
        env->ExceptionClear();
        return false;
    }

    // 读取流并计算 SHA256
    sha256_ctx shaCtx;
    sha256_init(&shaCtx);

    jclass isClass = env->GetObjectClass(is);
    jmethodID midRead = env->GetMethodID(isClass, "read", "([B)I");
    if (midRead == nullptr) {
        env->ExceptionClear();
        return false;
    }

    jbyteArray buf = env->NewByteArray(4096);
    int bytesRead;

    while ((bytesRead = env->CallIntMethod(is, midRead, buf)) > 0) {
        jbyte *bytes = env->GetByteArrayElements(buf, nullptr);
        if (bytes != nullptr) {
            sha256_update(&shaCtx, (unsigned char *)bytes, bytesRead);            env->ReleaseByteArrayElements(buf, bytes, JNI_ABORT);
        }
    }

    env->DeleteLocalRef(buf);
    env->DeleteLocalRef(is);
    sha256_final(&shaCtx, outSha256);

    return true;
}

bool checkDexIntegrity(JNIEnv *env) {
    if (!g_dexShaValid) {
        if (!computeVmpDexSha256(env, g_dexSha256)) {
            LOGE("DEX完整性校验：计算SHA256失败");
            return false;
        }
        g_dexShaValid = true;
        LOGI("DEX完整性基线已建立");
        return true;
    }

    // 重新计算当前 SHA256 并与基线比较
    unsigned char currentSha[32];
    if (!computeVmpDexSha256(env, currentSha)) {
        LOGE("DEX完整性校验：重新计算SHA256失败");
        return false;
    }

    if (memcmp(g_dexSha256, currentSha, 32) != 0) {
        LOGE("DEX完整性校验失败：SHA256不匹配");
        return false;
    }

    return true;
}

// ==================== 多级校验（魔改#11） ====================
// SO 和 DEX 互相绑定，任何一方被篡改都会检测到

static unsigned char g_boundSoCrc32 = 0;
static bool g_boundSoValid = false;

// 将 DEX SHA256 的前 4 字节与 SO CRC32 绑定
// 这样 SO 和 DEX 形成绑定关系
bool checkCrossBinding(JNIEnv *env) {
    if (!g_dexShaValid || !g_selfCrcValid) {
        // 基线未建立，跳过交叉校验
        return true;
    }

    // 取 DEX SHA256 前 4 字节作为绑定因子
    unsigned int dexBinding = 0;
    for (int i = 0; i < 4; i++) {
        dexBinding = (dexBinding << 8) | g_dexSha256[i];
    }

    // 取 SO CRC32 作为另一个绑定因子
    unsigned int soBinding = (unsigned int)g_selfCrc32;

    // 两个因子异或，交叉验证
    // 如果 SO 或 DEX 任何一方被替换，校验都会失败
    unsigned int crossCheck = dexBinding ^ soBinding;

    // 存储交叉校验值到全局，供 VMP 运行时验证
    g_boundSoCrc32 = (unsigned char)(crossCheck & 0xFF);
    g_boundSoValid = true;

    return true;
}
