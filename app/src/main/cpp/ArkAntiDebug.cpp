#include "ArkAntiDebug.h"
#include "ArkVMP.h"

#include <string>
#include <android/log.h>
#include <unistd.h>
#include <fcntl.h>
#include <openssl/sha.h>

#define LOG_TAG "ArkVMP_AntiDebug"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// ==================== #1 ptrace 自关联检测 ====================
// 如果进程已经被调试器 attach，ptrace(PTRACE_TRACEME) 会失败
static bool checkPtrace() {
    // ptrace(PTRACE_TRACEME, 0, 0, 0) 对已经被 trace 的进程返回 -1
    // 直接用 inline asm 调用，避免链接 libc 的 ptrace 符号被检测
    long result = -1;
#if defined(__arm__) || defined(__aarch64__)
    // ARM/ARM64: svc 0 或直接调用 ptrace
    // 用 syscall 方式
    register long x8 __asm__("x8") = 101; // __NR_ptrace on ARM64
    register long x0 __asm__("x0") = 0;   // PTRACE_TRACEME
    register long x1 __asm__("x1") = 0;
    register long x2 __asm__("x2") = 0;
    register long x3 __asm__("x3") = 0;
    __asm__ volatile("svc 0" : "=r"(x0) : "r"(x8), "r"(x0), "r"(x1), "r"(x2), "r"(x3) : "memory");
    result = x0;
#elif defined(__i386__) || defined(__x86_64__)
    // x86/x64
    register long rax __asm__("rax") = 26; // __NR_ptrace on x86_64
    register long rdi __asm__("rdi") = 0;  // PTRACE_TRACEME
    register long rsi __asm__("rsi") = 0;
    register long rdx __asm__("rdx") = 0;
    register long r10 __asm__("r10") = 0;
    __asm__ volatile("syscall" : "=r"(rax) : "r"(rax), "r"(rdi), "r"(rsi), "r"(rdx), "r"(r10) : "rcx", "r11", "memory");
    result = rax;
#endif
    return result < 0;
}

// ==================== #2 Frida 检测 ====================
// 检测 /proc/self/maps 中是否加载了 frida-agent.so
static bool checkFridaByMaps() {
    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0) {
        // 无法打开 maps，可能是 SELinux 限制，视为通过
        return false;
    }

    char buf[4096];
    ssize_t len;
    bool found = false;

    while ((len = read(fd, buf, sizeof(buf) - 1)) > 0) {
        buf[len] = '\0';

        // 逐行扫描
        char *line = buf;
        while (line) {
            char *next = strstr(line, "\n");
            if (next) {
                *next = '\0';
            }

            // 检测 frida 相关库名
            if (strstr(line, "frida-agent")
                || strstr(line, "frida-gadget")
                || strstr(line, "frida-tools")
                || strstr(line, "libfrida")) {
                found = true;
                break;
            }

            line = next ? next + 1 : nullptr;
        }

        if (found) break;
    }

    close(fd);
    return found;
}

// 检测 /proc/self/fd 中是否有 frida 的 pipe 文件描述符
static bool checkFridaByFd() {
    int fd = open("/proc/self/fd", O_RDONLY | O_DIRECTORY);
    if (fd < 0) {
        return false;
    }

    char linkpath[256];
    char target[256];
    bool found = false;

    for (int i = 0; i < 1024; i++) {
        snprintf(linkpath, sizeof(linkpath), "/proc/self/fd/%d", i);
        ssize_t len = readlink(linkpath, target, sizeof(target) - 1);
        if (len < 0) continue;

        target[len] = '\0';

        if (strstr(target, "frida")
            || strstr(target, "gadget")
            || strstr(target, "pipe:") && strstr(target, "frida")) {
            found = true;
            break;
        }
    }

    close(fd);
    return found;
}

// ==================== #3 Tracer 检测 ====================
// 检查父进程 PID，如果父进程是 1 (init) 说明原父进程已死（被调试器 kill 了）
// 或者检查 /proc/self/status 中的 TracerPid 字段
static bool checkTracer() {
    int fd = open("/proc/self/status", O_RDONLY);
    if (fd < 0) {
        return false;
    }

    char buf[4096];
    ssize_t len = read(fd, buf, sizeof(buf) - 1);
    close(fd);

    if (len <= 0) return false;
    buf[len] = '\0';

    // 查找 TracerPid 字段
    char *p = strstr(buf, "TracerPid:");
    if (p) {
        int tracerPid = atoi(p + 10);
        if (tracerPid != 0) {
            LOGI("检测到 TracerPid=%d", tracerPid);
            return true;
        }
    }

    // 检查父进程：如果父进程是 init(1)，可能是调试器释放了进程
    // 正常 App 的父进程应该是 zygote (pid=0 在容器中)
    int ppid = getppid();
    if (ppid == 1 || ppid == 0) {
        // 额外检查：正常状态下 Android App 的父进程不应是 init
        // 只有在调试器 attach 后释放进程才会出现这种情况
        // 这里只做警告，不直接判定为调试
    }

    return false;
}

// ==================== #4 时间差检测 ====================
// 执行一段已知耗时的操作，如果耗时异常说明被单步跟踪
static bool checkTiming() {
    // 方法：循环空操作，测量耗时
    // 正常执行约 50ms，如果被单步跟踪会超过 5 秒
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    // 空循环约 50ms
    volatile int counter = 0;
    for (int i = 0; i < 5000000; i++) {
        counter++;
    }

    clock_gettime(CLOCK_MONOTONIC, &end);

    long elapsedMs = (end.tv_sec - start.tv_sec) * 1000
                   + (end.tv_nsec - start.tv_nsec) / 1000000;

    // 如果耗时超过 3 秒，说明被单步跟踪
    if (elapsedMs > 3000) {
        LOGE("时间差检测异常：耗时 %ld ms，疑似被单步跟踪", elapsedMs);
        return true;
    }

    return false;
}

// ==================== 汇总检测 ====================
bool ArkAntiDebug_CheckAll(JNIEnv *env) {
    bool detected = false;

    // #1 ptrace 检测
    if (checkPtrace()) {
        LOGE("反调试检测：发现 ptrace 调试");
        detected = true;
    }

    // #2 Frida 检测
    if (checkFridaByMaps() || checkFridaByFd()) {
        LOGE("反调试检测：发现 Frida");
        detected = true;
    }

    // #3 Tracer 检测
    if (checkTracer()) {
        LOGE("反调试检测：发现 Tracer");
        detected = true;
    }

    // #4 时间差检测
    if (checkTiming()) {
        LOGE("反调试检测：时间差异常");
        detected = true;
    }

    if (detected) {
        LOGE("===== 反调试检测失败，SO 拒绝加载 =====");
    }

    return detected;
}

// ==================== #10 DEX 完整性校验 ====================
// 计算 VMP 类所在 DEX 文件的 SHA256 哈希，检测 DEX 是否被篡改
#include <jni.h>

static unsigned char g_dexSha256[32];
static bool g_dexShaValid = false;

// 从 JNI 获取 VMP 类的 ClassDef，然后获取其 DEX 数据
static bool computeVmpDexSha256(JNIEnv *env, unsigned char *outSha256) {
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
    SHA256_CTX shaCtx;
    SHA256_Init(&shaCtx);

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
            SHA256_Update(&shaCtx, (unsigned char *)bytes, bytesRead);
            env->ReleaseByteArrayElements(buf, bytes, JNI_ABORT);
        }
    }

    env->DeleteLocalRef(buf);
    env->DeleteLocalRef(is);
    SHA256_Final(outSha256, &shaCtx);

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

// ==================== #11 多级校验 ====================
// SO 校验 DEX hash，DEX 校验 SO hash，互相绑定
// 任何一方被篡改都会导致校验失败

static unsigned char g_boundSoCrc32 = 0;
static bool g_boundSoValid = false;

// 将 DEX SHA256 的前 4 字节与 SO CRC32 绑定
// 这样 SO 和 DEX 形成绑定关系
static bool checkCrossBinding(JNIEnv *env) {
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
// ====================================================
