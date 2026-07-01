#include "VmContext.h"

#include <android/log.h>

#define LOG_TAG "ArkVMP_Context"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

bool VmContext_Init(
        VmContext &ctx,
        JNIEnv *env,
        const VmpMethod &method,
        jobject thiz,
        jobjectArray args
) {
    ctx.env = env;
    ctx.method = &method;
    ctx.thiz = thiz;
    ctx.args = args;

    ctx.pc = 0;
    ctx.running = true;
    ctx.lastResultObject = nullptr;
    ctx.lastResultInt = 0;
    ctx.lastResultLong = 0;
    ctx.currentException = nullptr;






    ctx.result = VmResult();

    ctx.regs.clear();
    ctx.regs.resize(method.registerCount);

    // ==================== 控制流扁平化初始化（魔改#13） ====================
    // 当方法包含足够的指令时启用 dispatch 模式
    ctx.useDispatch = method.instructions.size() >= 8;
    if (ctx.useDispatch) {
        ctx.dispatchState = 0; // state 0 对应 instructions[0]
    }
    // ====================================================

    // ==================== 栈混淆：寄存器映射初始化（魔改#16） ====================
    // 基于方法 ID 和方法名生成伪随机种子
    // 每次执行生成不同的寄存器映射，使分析者无法追踪寄存器流向
    ctx.regPerm.resize(method.registerCount);
    unsigned int permSeed = (unsigned int)method.methodId;
    for (char c : method.methodName) permSeed = (permSeed * 31 + c) & 0xFFFF;
    permSeed ^= 0x9E3779B9; // golden ratio 扰动

    // Fisher-Yates 部分洗牌（只洗前半部分，保持参数寄存器稳定）
    int shuffleCount = method.registerCount / 2;
    for (int i = shuffleCount - 1; i > 0; i--) {
        permSeed = (permSeed * 1103515245 + 12345) & 0x7FFFFFFF;
        int j = permSeed % (i + 1);
        // 交换 regPerm[i] 和 regPerm[j]
        int tmp = ctx.regPerm[i];
        ctx.regPerm[i] = ctx.regPerm[j];
        ctx.regPerm[j] = tmp;
    }
    // 初始化映射表：logical -> physical
    for (int i = 0; i < method.registerCount; i++) {
        ctx.regPerm[i] = i;
    }
    // 对非参数寄存器区域进行洗牌
    int paramEnd = method.registerCount;
    for (int i = method.paramCount + 1; i < paramEnd; i++) {
        permSeed = (permSeed * 1103515245 + 12345) & 0x7FFFFFFF;
        int swapWith = method.paramCount + 1 + (permSeed % (paramEnd - method.paramCount - 1));
        if (swapWith < method.registerCount && swapWith != i) {
            int tmp = ctx.regPerm[i];
            ctx.regPerm[i] = ctx.regPerm[swapWith];
            ctx.regPerm[swapWith] = tmp;
        }
    }
    // ====================================================

    ctx.offsetToIndex.clear();
    for (int i = 0; i < static_cast<int>(method.instructions.size()); i++) {
        ctx.offsetToIndex[method.instructions[i].codeUnitOffset] = i;
    }

    int paramRegisterCount = method.isStatic ? 0 : 1;

    for (int i = 0; i < static_cast<int>(method.parameterTypes.size()); i++) {
        const std::string &type = method.parameterTypes[i];
        if (type == "J" || type == "D") {
            paramRegisterCount += 2;
        } else {
            paramRegisterCount += 1;
        }
    }

    int paramBase = method.registerCount - paramRegisterCount;
    if (paramBase < 0) {
        //LOGE("参数寄存器计算错�?registerCount=%d paramRegisterCount=%d",method.registerCount,paramRegisterCount);
        return false;
    }

    int current = paramBase;

    if (!method.isStatic) {
        ctx.regs[current].objectValue = thiz;
        current++;
    }

    if (args != nullptr) {
        int argCount = env->GetArrayLength(args);

        for (int i = 0; i < argCount && i < static_cast<int>(method.parameterTypes.size()); i++) {
            jobject arg = env->GetObjectArrayElement(args, i);
            ctx.regs[current].objectValue = arg;

            const std::string &type = method.parameterTypes[i];
            if (type == "J" || type == "D") {
                current += 2;
            } else {
                current += 1;
            }
        }
    }

    return true;
}

int VmContext_FindInstructionIndexByOffset(
        VmContext &ctx,
        int codeUnitOffset
) {
    auto it = ctx.offsetToIndex.find(codeUnitOffset);
    if (it == ctx.offsetToIndex.end()) {
        return -1;
    }

    return it->second;
}

// ==================== 寄存器混淆辅助（魔改#16） ====================
// 将逻辑寄存器索引转换为物理寄存器索引
// 用于运行时动态混淆寄存器分配，使静态分析无法追踪寄存器流向
int VmContext_GetPhysicalReg(const VmContext &ctx, int logicalReg) {
    if (logicalReg < 0 || logicalReg >= (int)ctx.regPerm.size()) {
        return logicalReg; // 越界时返回原值
    }
    return ctx.regPerm[logicalReg];
}
// ====================================================