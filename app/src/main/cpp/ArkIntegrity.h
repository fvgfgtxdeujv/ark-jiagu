#ifndef ARK_INTEGRITY_H
#define ARK_INTEGRITY_H

#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * SO 自校验 + DEX 完整性计算：计算 VMP 类所在 DEX 文件的 SHA256
 * outHash 必须是 32 字节缓冲区
 * 返回 true 表示计算成功
 */
bool computeVmpDexSha256(JNIEnv *env, unsigned char outHash[32]);

/**
 * DEX 完整性校验：计算 VMP 类所在 DEX 的 SHA256 并校验
 * 首次调用建立基线，后续调用与基线比较
 * 返回 true 表示 DEX 未被篡改
 */
bool checkDexIntegrity(JNIEnv *env);

/**
 * 多级交叉校验：SO 和 DEX 互相绑定
 * 任何一方被篡改都会导致校验失败
 * 返回 true 表示校验通过
 */
bool checkCrossBinding(JNIEnv *env);

#ifdef __cplusplus
}
#endif

#endif // ARK_INTEGRITY_H
