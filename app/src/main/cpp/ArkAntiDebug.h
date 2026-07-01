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

#ifdef __cplusplus
}
#endif

#endif // ARK_ANTI_DEBUG_H
