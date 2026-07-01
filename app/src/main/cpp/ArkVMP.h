#ifndef ARK_VMP_H
#define ARK_VMP_H

#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif

jint ArkVMP_OnLoad(JavaVM *vm);

void ArkVMP_SetContext(JNIEnv *env, jobject context);

#ifdef __cplusplus
}
#endif

#endif