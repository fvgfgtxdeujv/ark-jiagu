#ifndef VMP_RUNTIME_H
#define VMP_RUNTIME_H

#include <jni.h>
#include "VmpTypes.h"

void VmpRuntime_SetContext(JNIEnv *env, jobject context);

jobject VmpRuntime_GetContext();

VmResult VmpRuntime_Execute(
        JNIEnv *env,
        jint methodId,
        jobject thiz,
        jobjectArray args,
        jboolean isDebuggable  // 调试模式标记，true 时跳过反调试
);

#endif