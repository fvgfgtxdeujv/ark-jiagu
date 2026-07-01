#include "VmpInterpreter.h"
#include "VmContext.h"
#include "VmOpcodeHandler.h"
#include <android/log.h>
#include <vector>
#include <unordered_map>

#define LOG_TAG "ArkVMP_Interpreter"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)


// ==================== 控制流扁平化辅助（魔改#13） ====================
// 构建 dispatch table：state ID -> instruction index 的映射
// 在解释器执行前预先构建，运行时通过 state 而非 pc 来索引指令
static std::unordered_map<int, int> buildDispatchTable(const VmpMethod &method) {
    std::unordered_map<int, int> table;
    int insnCount = static_cast<int>(method.instructions.size());
    for (int i = 0; i < insnCount; i++) {
        table[i] = i; // state = instruction index
    }
    return table;
}

// 根据 dispatch state 获取对应的指令索引
static int getPcFromState(const std::unordered_map<int, int> &dispatchTable, int state) {
    auto it = dispatchTable.find(state);
    if (it != dispatchTable.end()) {
        return it->second;
    }
    return -1; // 未知 state，终止执行
}
// ====================================================

VmResult VmpInterpreter_Execute(
        JNIEnv *env,
        const VmpMethod &method,
        jobject thiz,
        jobjectArray args
) {
    VmResult emptyResult;

    VmContext ctx;
    if (!VmContext_Init(ctx, env, method, thiz, args)) {
        //LOGE("VmContext 初始化失败");
        return emptyResult;
    }

    // ==================== 控制流扁平化（魔改#13） ====================
    // 构建 dispatch table，将指令索引映射到 state ID
    std::unordered_map<int, int> dispatchTable = buildDispatchTable(method);
    int insnCount = static_cast<int>(method.instructions.size());

    int stepCount = 0;
    const int maxStepCount = 200000;

    while (ctx.running) {
        stepCount++;

        if (stepCount > maxStepCount) {
            //LOGE("VM执行步数超限 methodId=%d step=%d",method.methodId,stepCount);
            break;
        }

        int currentPc;

        // ==================== Dispatch 模式（控制流扁平化） ====================
        // 使用 dispatch state 代替直接 pc 索引
        // 外部观察者只能看到 dispatch state 的变化，无法推断真实执行路径
        if (ctx.useDispatch && !dispatchTable.empty()) {
            currentPc = getPcFromState(dispatchTable, ctx.dispatchState);
            if (currentPc < 0 || currentPc >= insnCount) {
                // 无效 state，终止执行
                break;
            }
            // 默认下一个 state = 当前 state + 1（线性顺序）
            ctx.dispatchState = currentPc + 1;
        } else {
            // 回退到传统线性执行（方法指令较少时）
            currentPc = ctx.pc;
            ctx.pc++;
        }
        // ====================================================

        const VmpInstruction &insn = method.instructions[currentPc];

        //LOGI("step=%d pc=%d state=%d offset=%d vmOpcode=0x%02x realOpcode=0x%x opcode=%s",
        //     stepCount, currentPc, ctx.dispatchState, insn.codeUnitOffset,
        //     insn.vmOpcode, insn.realOpcode, insn.opcodeName.c_str());

        VmHandler handler = getHandlerByRealOpcode(insn.realOpcode);
        if (handler == nullptr) {
            //LOGE("未支持的指令realOpcode=0x%x opcode=%s",insn.realOpcode,insn.opcodeName.c_str());
            break;
        }

        if (!handler(ctx, insn)) {
            //LOGE("handler执行失败 realOpcode=0x%x opcode=%s",insn.realOpcode,insn.opcodeName.c_str());
            break;
        }
    }

    return ctx.result;
}
