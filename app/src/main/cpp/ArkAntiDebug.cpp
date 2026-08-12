#include "ArkAntiDebug.h"
#include "ArkIntegrity.h"
#include "ArkVMP.h"

#include <string>
#include <android/log.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>

#define LOG_TAG "ArkVMP_AntiDebug"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// ==================== #1 ptrace 自关联检测 ====================
// 如果进程已经被调试器 attach，ptrace(PTRACE_TRACEME) 会失败
static bool checkPtrace() {
    // ptrace(PTRACE_TRACEME, 0, 0, 0) 对已经被 trace 的进程返回 -1
    // 直接用 syscall() 绕过 libc 的 ptrace 包装符号
    long result = syscall(SYS_ptrace, PTRACE_TRACEME, 0, 0, 0);
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
