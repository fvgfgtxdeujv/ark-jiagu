#include "VmpParser.h"

#include <android/log.h>
#include <string.h>

#define LOG_TAG "ArkVMP_VmpParser"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

static VmpBinContext g_bin;

static bool readIntLE(const std::vector<unsigned char> &data, size_t &pos, int &out) {
    if (pos + 4 > data.size()) {
        return false;
    }

    out = static_cast<int>(
            (data[pos] & 0xff)
            | ((data[pos + 1] & 0xff) << 8)
            | ((data[pos + 2] & 0xff) << 16)
            | ((data[pos + 3] & 0xff) << 24)
    );

    pos += 4;
    return true;
}
//读取指定位置 int
static bool readIntLEAt(const std::vector<unsigned char> &data, size_t pos, int &out) {
    if (pos + 4 > data.size()) {
        return false;
    }

    out = static_cast<int>(
            (data[pos] & 0xff)
            | ((data[pos + 1] & 0xff) << 8)
            | ((data[pos + 2] & 0xff) << 16)
            | ((data[pos + 3] & 0xff) << 24)
    );

    return true;
}
//XOR解密方法
static bool decryptVmpBinIfNeeded(const std::vector<unsigned char> &input,
                                  std::vector<unsigned char> &outPlain) {
    outPlain.clear();

    if (input.size() < 8) {
        return false;
    }

    if (input[0] == 'A' && input[1] == 'V' && input[2] == 'M' && input[3] == 'P') {
        outPlain = input;
        return true;
    }

    if (!(input[0] == 'A' && input[1] == 'V' && input[2] == 'M' && input[3] == 'X')) {
        //LOGE("vmp.bin magic错误");
        return false;
    }

    size_t pos = 4;

    int version = 0;
    if (!readIntLE(input, pos, version)) {
        //LOGE("读取AVMX版本失败");
        return false;
    }

    if (version != 2) {
        //LOGE("不支持的AVMX版本：%d", version);
        return false;
    }

    int encryptedLen = 0;
    if (!readIntLE(input, pos, encryptedLen)) {
        //LOGE("读取加密数据长度失败");
        return false;
    }

    if (encryptedLen <= 0) {
        //LOGE("加密数据长度非法：%d", encryptedLen);
        return false;
    }

    size_t encryptedOffset = pos;
    size_t encryptedEnd = encryptedOffset + static_cast<size_t>(encryptedLen);

    if (encryptedEnd + 4 > input.size()) {
        //LOGE("加密数据越界");
        return false;
    }

    int keyLen = 0;
    if (!readIntLEAt(input, input.size() - 4, keyLen)) {
        //LOGE("读取尾部keyLen失败");
        return false;
    }

    if (keyLen <= 0 || keyLen > 1024) {
        //LOGE("keyLen非法：%d", keyLen);
        return false;
    }

    if (input.size() < static_cast<size_t>(keyLen) + 4) {
        //LOGE("key区域越界");
        return false;
    }

    size_t keyOffset = input.size() - 4 - static_cast<size_t>(keyLen);

    if (keyOffset < encryptedEnd) {
        //LOGE("keyOffset非法");
        return false;
    }

    const unsigned char *encryptedData = input.data() + encryptedOffset;
    const unsigned char *key = input.data() + keyOffset;

    outPlain.resize(static_cast<size_t>(encryptedLen));

    for (int i = 0; i < encryptedLen; i++) {
        outPlain[i] = static_cast<unsigned char>(
                encryptedData[i] ^ key[i % keyLen]
        );
    }

    if (outPlain.size() < 8
        || !(outPlain[0] == 'A' && outPlain[1] == 'V'
             && outPlain[2] == 'M' && outPlain[3] == 'P')) {
        //LOGE("XOR解密后不是AVMP明文");
        outPlain.clear();
        return false;
    }

    //LOGI("vmp.bin XOR解密成功，加密大小=%d，明文大小=%d，keyLen=%d",encryptedLen,static_cast<int>(outPlain.size()),keyLen);

    return true;
}


static bool readLongLE(const std::vector<unsigned char> &data, size_t &pos, int64_t &out) {
    if (pos + 8 > data.size()) {
        return false;
    }

    uint64_t value = 0;

    for (int i = 0; i < 8; i++) {
        value |= ((uint64_t) data[pos + i] & 0xff) << (i * 8);
    }

    out = static_cast<int64_t>(value);
    pos += 8;
    return true;
}

static bool readStringLE(const std::vector<unsigned char> &data, size_t &pos, std::string &out) {
    int len = 0;

    if (!readIntLE(data, pos, len)) {
        return false;
    }

    if (len == -1) {
        out.clear();
        return true;
    }

    if (len < 0 || pos + static_cast<size_t>(len) > data.size()) {
        return false;
    }

    out.assign(reinterpret_cast<const char *>(data.data() + pos), len);
    pos += len;

    return true;
}

static bool readAllBytesFromInputStream(
        JNIEnv *env,
        jobject inputStream,
        std::vector<unsigned char> &out
) {
    out.clear();

    if (env == nullptr || inputStream == nullptr) {
        return false;
    }

    jclass clsInputStream = env->FindClass("java/io/InputStream");
    if (clsInputStream == nullptr) {
        env->ExceptionClear();
        return false;
    }

    jmethodID midRead = env->GetMethodID(clsInputStream, "read", "([B)I");
    jmethodID midClose = env->GetMethodID(clsInputStream, "close", "()V");

    if (midRead == nullptr || midClose == nullptr) {
        env->ExceptionClear();
        return false;
    }

    jbyteArray buffer = env->NewByteArray(8192);
    if (buffer == nullptr) {
        return false;
    }

    while (true) {
        jint len = env->CallIntMethod(inputStream, midRead, buffer);

        if (env->ExceptionCheck()) {
            env->ExceptionClear();
            out.clear();
            return false;
        }

        if (len <= 0) {
            break;
        }

        size_t oldSize = out.size();
        out.resize(oldSize + len);

        env->GetByteArrayRegion(
                buffer,
                0,
                len,
                reinterpret_cast<jbyte *>(out.data() + oldSize)
        );

        if (env->ExceptionCheck()) {
            env->ExceptionClear();
            out.clear();
            return false;
        }
    }

    env->CallVoidMethod(inputStream, midClose);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
    }

    return !out.empty();
}

static bool loadVmpBinFromAssets(
        JNIEnv *env,
        jobject context,
        std::vector<unsigned char> &out
) {
    out.clear();

    jclass clsContext = env->GetObjectClass(context);
    if (clsContext == nullptr) {
        env->ExceptionClear();
        return false;
    }

    jmethodID midGetAssets = env->GetMethodID(
            clsContext,
            "getAssets",
            "()Landroid/content/res/AssetManager;"
    );

    if (midGetAssets == nullptr) {
        env->ExceptionClear();
        return false;
    }

    jobject assetManager = env->CallObjectMethod(context, midGetAssets);
    if (env->ExceptionCheck() || assetManager == nullptr) {
        env->ExceptionClear();
        return false;
    }

    jclass clsAssetManager = env->GetObjectClass(assetManager);
    if (clsAssetManager == nullptr) {
        env->ExceptionClear();
        return false;
    }

    jmethodID midOpen = env->GetMethodID(
            clsAssetManager,
            "open",
            "(Ljava/lang/String;)Ljava/io/InputStream;"
    );

    if (midOpen == nullptr) {
        env->ExceptionClear();
        return false;
    }

    jstring fileName = env->NewStringUTF("vmp.bin");

    jobject inputStream = env->CallObjectMethod(assetManager, midOpen, fileName);
    if (env->ExceptionCheck() || inputStream == nullptr) {
        env->ExceptionClear();
        //LOGE("打开 assets/vmp.bin 失败");
        return false;
    }

    return readAllBytesFromInputStream(env, inputStream, out);
}

static bool parseVmpHeaderAndIndex() {
    const std::vector<unsigned char> &data = g_bin.rawData;

    if (data.size() < 8) {
        //LOGE("vmp.bin长度太短");
        return false;
    }

    if (!(data[0] == 'A' && data[1] == 'V' && data[2] == 'M' && data[3] == 'P')) {
        //LOGE("vmp.bin magic错误");
        return false;
    }

    size_t pos = 4;

    int version = 0;
    if (!readIntLE(data, pos, version)) {
        //LOGE("读取version失败");
        return false;
    }

    if (version != 5) {
        //LOGE("不支持的vmp.bin版本：%d", version);
        return false;
    }

    g_bin.version = version;

    // ==================== 读取 opcode 随机化密钥 ====================
    // 16 字节密钥紧跟在 version 后面，用于解密 opcode 映射表
    if (pos + 16 > data.size()) {
        //LOGE("opcode密钥区域超出文件边界");
        return false;
    }
    memcpy(g_bin.opcodeKey, &data[pos], 16);
    g_bin.hasOpcodeKey = true;
    pos += 16;
    // ====================================================

    // 辅助函数：用密钥解密 int 值
    auto decryptInt = [&](int value, int keyOffset) -> int {
        if (!g_bin.hasOpcodeKey) return value;
        return value ^ (g_bin.opcodeKey[keyOffset % 16] & 0xff);
    };

    int opcodeMapCount = 0;
    if (!readIntLE(data, pos, opcodeMapCount)) {
        //LOGE("读取opcodeMapCount失败");
        return false;
    }

    g_bin.vmOpcodeMap.clear();

    //LOGI("开始解析opcode映射表，数量=%d", opcodeMapCount);

    for (int i = 0; i < opcodeMapCount; i++) {
        int vmOpcode = 0;
        int realOpcode = 0;
        std::string realOpcodeName;

        if (!readIntLE(data, pos, vmOpcode)) {
            //LOGE("读取vmOpcode失败 index=%d", i);
            return false;
        }

        if (!readIntLE(data, pos, realOpcode)) {
            //LOGE("读取realOpcode失败 index=%d", i);
            return false;
        }

        if (!readStringLE(data, pos, realOpcodeName)) {
            //LOGE("读取realOpcodeName失败 index=%d", i);
            return false;
        }

        // 用密钥解密 opcode 值
        vmOpcode = decryptInt(vmOpcode, 0);
        realOpcode = decryptInt(realOpcode, 4);

        VmpOpcodeMapEntry entry;
        entry.vmOpcode = vmOpcode;
        entry.realOpcode = realOpcode;
        entry.realOpcodeName = realOpcodeName;

        g_bin.vmOpcodeMap[vmOpcode] = entry;

        //LOGI("opcodeMap[%d] vmOpcode=0x%02x -> realOpcode=0x%x -> realOpcodeName=%s",i,vmOpcode,realOpcode,realOpcodeName.c_str());
    }

    int methodIndexCount = 0;
    if (!readIntLE(data, pos, methodIndexCount)) {
        //LOGE("读取methodIndexCount失败");
        return false;
    }

    g_bin.methodIndexMap.clear();

    //LOGI("开始解析method索引表，数量=%d", methodIndexCount);

    for (int i = 0; i < methodIndexCount; i++) {
        int methodId = 0;
        int64_t offset = 0;
        int size = 0;

        if (!readIntLE(data, pos, methodId)) {
            //LOGE("读取methodId失败 index=%d", i);
            return false;
        }

        if (!readLongLE(data, pos, offset)) {
            //LOGE("读取method offset失败 index=%d", i);
            return false;
        }

        if (!readIntLE(data, pos, size)) {
            //LOGE("读取method size失败 index=%d", i);
            return false;
        }

        if (offset < 0 || size <= 0) {
            //LOGE("method索引非法 methodId=%d offset=%lld size=%d",methodId,static_cast<long long>(offset),size);
            return false;
        }

        if (static_cast<uint64_t>(offset) + static_cast<uint64_t>(size) > data.size()) {
            //LOGE("method索引越界 methodId=%d offset=%lld size=%d binSize=%d",methodId,static_cast<long long>(offset),size,static_cast<int>(data.size()));
            return false;
        }

        VmpMethodIndex index;
        index.methodId = methodId;
        index.offset = static_cast<uint64_t>(offset);
        index.size = static_cast<uint32_t>(size);

        g_bin.methodIndexMap[methodId] = index;

        //LOGI("methodIndex[%d] methodId=%d offset=%lld size=%d",i,methodId,static_cast<long long>(offset),size);
    }

    g_bin.methodCache.clear();

    //LOGI("vmp.bin解析完成 version=%d opcodeCount=%d methodCount=%d",g_bin.version,static_cast<int>(g_bin.vmOpcodeMap.size()),static_cast<int>(g_bin.methodIndexMap.size()));

    return true;
}

bool VmpParser_EnsureLoaded(JNIEnv *env, jobject context) {
    if (g_bin.loaded) {
        return true;
    }

    if (env == nullptr || context == nullptr) {
        return false;
    }

    g_bin = VmpBinContext();

    std::vector<unsigned char> fileData;

    if (!loadVmpBinFromAssets(env, context, fileData)) {
        //LOGE("读vmp.bin文件失败");
        return false;
    }

    if (!decryptVmpBinIfNeeded(fileData, g_bin.rawData)) {
        g_bin = VmpBinContext();
        //LOGE("解密vmp.bin文件失败");
        return false;
    }

    if (!parseVmpHeaderAndIndex()) {
        g_bin = VmpBinContext();
        //LOGE("解析vmp.bin文件失败");
        return false;
    }

    g_bin.loaded = true;
    return true;
}

bool VmpParser_FindMethod(
        JNIEnv *env,
        int methodId,
        VmpMethod &outMethod
) {
    (void) env;

    if (!g_bin.loaded) {
        //LOGE("vmp.bin尚未加载");
        return false;
    }

    auto cacheIt = g_bin.methodCache.find(methodId);
    if (cacheIt != g_bin.methodCache.end()) {
        outMethod = cacheIt->second;
        //LOGI("methodId=%d 命中方法缓存", methodId);
        return true;
    }

    auto it = g_bin.methodIndexMap.find(methodId);
    if (it == g_bin.methodIndexMap.end()) {
        //LOGE("methodId=%d 不存在于索引表", methodId);
        return false;
    }

    const VmpMethodIndex &index = it->second;

    if (index.offset + index.size > g_bin.rawData.size()) {
        //LOGE("methodId=%d 索引越界", methodId);
        return false;
    }

    size_t pos = static_cast<size_t>(index.offset);
    size_t end = static_cast<size_t>(index.offset + index.size);

    VmpMethod method;

    int isStaticValue = 0;
    int parameterTypeCount = 0;
    int instructionCount = 0;

    if (!readIntLE(g_bin.rawData, pos, method.methodId)) return false;
    if (!readStringLE(g_bin.rawData, pos, method.dexName)) return false;
    if (!readStringLE(g_bin.rawData, pos, method.className)) return false;
    if (!readStringLE(g_bin.rawData, pos, method.methodName)) return false;
    if (!readStringLE(g_bin.rawData, pos, method.methodSignature)) return false;
    if (!readIntLE(g_bin.rawData, pos, method.accessFlags)) return false;
    if (!readIntLE(g_bin.rawData, pos, method.registerCount)) return false;
    if (!readIntLE(g_bin.rawData, pos, method.paramCount)) return false;
    if (!readStringLE(g_bin.rawData, pos, method.returnType)) return false;
    if (!readIntLE(g_bin.rawData, pos, isStaticValue)) return false;

    method.isStatic = isStaticValue != 0;

    if (!readIntLE(g_bin.rawData, pos, parameterTypeCount)) return false;

    for (int i = 0; i < parameterTypeCount; i++) {
        std::string type;
        if (!readStringLE(g_bin.rawData, pos, type)) return false;
        method.parameterTypes.push_back(type);
    }

    if (!readIntLE(g_bin.rawData, pos, instructionCount)) return false;

    for (int i = 0; i < instructionCount; i++) {
        VmpInstruction insn;

        int registerCount = 0;

        if (!readIntLE(g_bin.rawData, pos, insn.codeUnitOffset)) return false;

        // 读取加密的 vmOpcode 并用密钥解密
        int encryptedVmOpcode = 0;
        if (!readIntLE(g_bin.rawData, pos, encryptedVmOpcode)) return false;
        insn.vmOpcode = encryptedVmOpcode;
        if (g_bin.hasOpcodeKey) {
            insn.vmOpcode ^= (g_bin.opcodeKey[8 % 16] & 0xff);
        }

        auto opcodeIt = g_bin.vmOpcodeMap.find(insn.vmOpcode);
        if (opcodeIt == g_bin.vmOpcodeMap.end()) {
            //LOGE("未知vmOpcode=0x%02x instructionIndex=%d methodId=%d codeUnitOffset=%d",insn.vmOpcode,i,methodId,insn.codeUnitOffset);
            return false;
        }

        insn.realOpcode = opcodeIt->second.realOpcode;
        insn.opcodeName = opcodeIt->second.realOpcodeName;

        if (!readStringLE(g_bin.rawData, pos, insn.formatName)) return false;
        if (!readIntLE(g_bin.rawData, pos, insn.codeUnits)) return false;

        if (!readIntLE(g_bin.rawData, pos, registerCount)) return false;

        for (int r = 0; r < registerCount; r++) {
            int reg = 0;
            if (!readIntLE(g_bin.rawData, pos, reg)) return false;
            insn.registers.push_back(reg);
        }

        int64_t literalValue = 0;

        if (!readIntLE(g_bin.rawData, pos, insn.literalType)) return false;
        if (!readLongLE(g_bin.rawData, pos, literalValue)) return false;

        // ==================== 常量池解密（魔改#8） ====================
        // 用 codeUnitOffset 派生 XOR 密钥解密字面量
        if (insn.literalType == 1 || insn.literalType == 2) {
            int litKey = (int)((insn.codeUnitOffset * 0x9E3779B9LL) & 0xFF);
            literalValue ^= litKey;
        }
        // ====================================================

        insn.literalValue = literalValue;

        if (!readIntLE(g_bin.rawData, pos, insn.offsetType)) return false;
        if (!readIntLE(g_bin.rawData, pos, insn.offsetValue)) return false;

        if (!readIntLE(g_bin.rawData, pos, insn.referenceType)) return false;
        if (!readStringLE(g_bin.rawData, pos, insn.referenceData)) return false;

        if (!readIntLE(g_bin.rawData, pos, insn.extraReferenceType)) return false;
        if (!readStringLE(g_bin.rawData, pos, insn.extraReferenceData)) return false;
        method.instructions.push_back(insn);
    }

    int tryBlockCount = 0;
    if (!readIntLE(g_bin.rawData, pos, tryBlockCount)) return false;

    for (int i = 0; i < tryBlockCount; i++) {
        VmpTryBlock tryBlock;

        int handlerCount = 0;

        if (!readIntLE(g_bin.rawData, pos, tryBlock.startCodeAddress)) return false;
        if (!readIntLE(g_bin.rawData, pos, tryBlock.codeUnitCount)) return false;
        if (!readIntLE(g_bin.rawData, pos, handlerCount)) return false;

        for (int h = 0; h < handlerCount; h++) {
            VmpExceptionHandler handler;

            if (!readStringLE(g_bin.rawData, pos, handler.exceptionType)) return false;
            if (!readIntLE(g_bin.rawData, pos, handler.handlerCodeAddress)) return false;

            tryBlock.handlers.push_back(handler);
        }

        method.tryBlocks.push_back(tryBlock);
    }

    // ==================== 签名链校验（魔改#12） ====================
    // 读取方法块的 SHA256 哈希（32 字节）
    if (pos + 32 <= end) {
        unsigned char storedHash[32];
        memcpy(storedHash, &g_bin.rawData[pos], 32);
        pos += 32;

        // 重新计算方法块的哈希进行验证
        // 简化实现：用方法的关键信息派生校验值
        unsigned int expected = 0;
        for (char c : method.methodName) expected = (expected * 31 + c) & 0xFFFFFFFF;
        for (char c : method.methodSignature) expected = (expected * 37 + c) & 0xFFFFFFFF;
        expected ^= method.methodId;
        expected ^= (unsigned int)method.instructions.size();

        // 比较存储的哈希和计算值（取前4字节比较）
        unsigned int stored = 0;
        for (int i = 0; i < 4; i++) {
            stored = (stored << 8) | storedHash[i];
        }

        if (stored != expected) {
            //LOGE("签名链校验失败 methodId=%d name=%s", methodId, method.methodName.c_str());
            return false;
        }

        //LOGI("签名链校验通过 methodId=%d", methodId);
    }
    // ====================================================
        //LOGE("methodId=%d 解析越界", methodId);
        return false;
    }

    if (pos != end) {
        //LOGI("methodId=%d 解析完成，但pos和end不完全一致 pos=%d end=%d",methodId,static_cast<int>(pos),static_cast<int>(end));
    }

    g_bin.methodCache[methodId] = method;
    outMethod = method;

    //LOGI("methodId=%d 已从内存bin解析并加入缓存", methodId);

    return true;
}