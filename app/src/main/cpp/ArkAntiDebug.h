#ifndef ARK_ANTI_DEBUG_H
#define ARK_ANTI_DEBUG_H

#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif

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

/**
 * DEX 完整性校验：计算 VMP 类所在 DEX 的 SHA256 并校验
 * 返回 true 表示 DEX 未被篡改
 */
bool checkDexIntegrity(JNIEnv *env);

#ifdef __cplusplus
}
#endif

#endif // ARK_ANTI_DEBUG_H
