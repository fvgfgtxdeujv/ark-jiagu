#ifndef VM_CONTEXT_H
#define VM_CONTEXT_H

#include <jni.h>
#include <vector>
#include <string>
#include <unordered_map>
#include <stdint.h>
#include "VmpTypes.h"

enum VmRegKind {
    VM_REG_UNKNOWN = 0,
    VM_REG_INT = 1,
    VM_REG_LONG = 2,
    VM_REG_OBJECT = 3
};


struct VmRegister {
    jobject objectValue = nullptr;
    int intValue = 0;
    int64_t longValue = 0;
    VmRegKind kind = VM_REG_UNKNOWN;
};

struct VmContext {
    JNIEnv *env = nullptr;

    const VmpMethod *method = nullptr;

    jobject thiz = nullptr;
    jobjectArray args = nullptr;

    // ==================== 栈混淆：寄存器别名（魔改#16） ====================
    // 运行时动态映射：logicalReg -> physicalReg
    // 每次方法执行生成不同的映射，使静态分析无法追踪寄存器流向
    std::vector<int> regPerm;
    // ====================================================

    std::vector<VmRegister> regs;

    jobject lastResultObject = nullptr;
    int lastResultInt;
    int64_t lastResultLong = 0;
    jobject currentException = nullptr;



    // ==================== 控制流扁平化（魔改#13） ====================
    // dispatch state 代替直接 pc++，将线性控制流"压平"为大 switch
    // 每个指令对应唯一 state ID，handler 执行后设置下一个 state
    // 使静态分析无法从代码结构推断真实执行顺序
    int dispatchState = 0;
    bool useDispatch = false;
    // ====================================================

    int pc = 0;
    bool running = true;

    VmResult result;

    std::unordered_map<int, int> offsetToIndex;
};

bool VmContext_Init(
        VmContext &ctx,
        JNIEnv *env,
        const VmpMethod &method,
        jobject thiz,
        jobjectArray args
);

int VmContext_FindInstructionIndexByOffset(
        VmContext &ctx,
        int codeUnitOffset
);

// ==================== 寄存器混淆辅助（魔改#16） ====================
// 将逻辑寄存器索引映射到物理寄存器索引
// 用于运行时动态混淆寄存器分配
int VmContext_GetPhysicalReg(const VmContext &ctx, int logicalReg);

#endif