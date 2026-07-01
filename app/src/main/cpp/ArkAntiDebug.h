#ifndef ARK_ANTI_DEBUG_H
#define ARK_ANTI_DEBUG_H

#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * SO 自校验 + DEX 完整性计算：计算 VMP 类所在 DEX 的 SHA256
 * env: JNI 环境指针，outHash: 32 字节输出缓冲区
 * 返回 true 表示计算成功
 */
bool computeVmpDexSha256(JNIEnv *env, unsigned char outHash[32]);

/**
 * 反调试检测集合
 * 返回 true 表示检测到调试/分析环境，SO 不应继续加载
 */
bool ArkAntiDebug_CheckAll(JNIEnv *env);

/**
 * SO 自校验：检查 SO 文件是否被 patch/篡改
 * 返回 true 表示完整性校验通过
 */
bool checkSelfIntegrity();

#ifdef __cplusplus
}
#endif

#endif // ARK_ANTI_DEBUG_H
