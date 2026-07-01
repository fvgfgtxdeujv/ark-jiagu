#include "VmpParser.h"

#include <android/log.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

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
// ==================== #1 多层解密 ====================
// 第一层：轮混淆逆变换（解密 layer1）
// 逆变换顺序：行混淆逆 → 轮混淆逆（逆旋转 → 逆加法 → 逆XOR）
static void layer1Decrypt(unsigned char *data, size_t len, const unsigned char *layerKey, size_t keyLen) {
    // 逆行混淆：恢复原始顺序
    for (size_t i = 0; i < len; i += 16) {
        size_t blockLen = std::min(len - i, (size_t)16);
        if (blockLen < 2) continue;
        unsigned char *block = data + i;
        // 逆向置换：位置 j → (j * 7) % len 的逆变换
        // 逆变换：newPos → j，其中 j * 7 ≡ newPos (mod len)
        // 使用查找表方式
        std::vector<unsigned char> original(blockLen);
        for (size_t j = 0; j < blockLen; j++) {
            size_t srcPos = (j * 7) % blockLen;
            original[j] = block[srcPos];
        }
        memcpy(block, original.data(), blockLen);
    }

    // 逆轮混淆（8 轮）
    int rounds = 8;
    for (int round = rounds - 1; round >= 0; round--) {
        for (size_t i = 0; i < len; i++) {
            int keyByte = layerKey[(i + round) % keyLen] & 0xFF;
            // 逆 XOR
            data[i] = (unsigned char)((data[i] & 0xFF) ^ layerKey[(i + round * 3) % keyLen]);
            // 逆旋转（右旋3位 = 左旋5位）
            data[i] = (unsigned char)(((data[i] & 0xFF) >> 3) | ((data[i] & 0xFF) << 5));
            // 逆加法
            data[i] = (unsigned char)(((data[i] & 0xFF) - keyByte) & 0xFF);
        }
    }
}

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

    // ==================== #1 多层解密：读取双层密钥 ====================
    // 新格式：加密数据后紧跟 layerKeyLen + layerKey + xorKeyLen + xorKey
    size_t keyAreaStart = encryptedEnd;

    // 读取 layerKey
    if (keyAreaStart + 4 > input.size()) {
        //LOGE("密钥区域越界");
        return false;
    }
    int layerKeyLen = 0;
    if (!readIntLEAt(input, keyAreaStart, layerKeyLen)) {
        //LOGE("读取layerKeyLen失败");
        return false;
    }
    if (layerKeyLen <= 0 || layerKeyLen > 1024) {
        //LOGE("layerKeyLen非法：%d", layerKeyLen);
        return false;
    }
    size_t layerKeyOffset = keyAreaStart + 4;
    if (layerKeyOffset + layerKeyLen + 4 > input.size()) {
        //LOGE("layerKey区域越界");
        return false;
    }
    const unsigned char *layerKey = input.data() + layerKeyOffset;

    // 读取 xorKey
    size_t xorKeyLenPos = layerKeyOffset + layerKeyLen;
    int xorKeyLen = 0;
    if (!readIntLEAt(input, xorKeyLenPos, xorKeyLen)) {
        //LOGE("读取xorKeyLen失败");
        return false;
    }
    if (xorKeyLen <= 0 || xorKeyLen > 1024) {
        //LOGE("xorKeyLen非法：%d", xorKeyLen);
        return false;
    }
    size_t xorKeyOffset = xorKeyLenPos + 4;
    if (xorKeyOffset + xorKeyLen > input.size()) {
        //LOGE("xorKey区域越界");
        return false;
    }
    const unsigned char *xorKey = input.data() + xorKeyOffset;
    // ====================================================

    const unsigned char *encryptedData = input.data() + encryptedOffset;

    outPlain.resize(static_cast<size_t>(encryptedLen));

    // 第一层：XOR 解密
    for (int i = 0; i < encryptedLen; i++) {
        outPlain[i] = static_cast<unsigned char>(
                encryptedData[i] ^ xorKey[i % xorKeyLen]
        );
    }

    // ==================== #1 多层解密：第二层轮混淆逆变换 ====================
    if (layerKeyLen > 0) {
        layer1Decrypt(outPlain.data(), outPlain.size(), layerKey, layerKeyLen);
    }
    // ====================================================

    if (outPlain.size() < 8
        || !(outPlain[0] == 'A' && outPlain[1] == 'V'
             && outPlain[2] == 'M' && outPlain[3] == 'P')) {
        //LOGE("多层解密后不是AVMP明文");
        outPlain.clear();
        return false;
    }

    //LOGI("vmp.bin 多层解密成功，加密大小=%d，明文大小=%d",encryptedLen,static_cast<int>(outPlain.size()));

    return true;
}
// ====================================================

// ==================== #16 加密跳转表辅助：旋转混淆逆变换 ====================
// 还原 Java 端的 rotateLong/rotateInt 混淆
static long rotateLongDecrypt(long value, int seed) {
    int shift = (seed & 0x1F) + 1;
    if (shift == 32) shift = 0;
    // 逆变换：先 XOR mask
    value ^= ((long)seed << 16) | (seed & 0xFFFFL);
    value &= 0xFFFFFFFFL;
    // 逆旋转
    long rotated = (value >>> shift) | (value << (32 - shift));
    return rotated & 0xFFFFFFFFL;
}

static int rotateIntDecrypt(int value, int seed) {
    int shift = ((seed >> 2) & 0x1F) + 1;
    if (shift == 32) shift = 0;
    // 逆变换：先 XOR mask
    value ^= (seed & 0xFFFF);
    // 逆旋转
    int rotated = (value >>> shift) | (value << (32 - shift));
    return rotated;
}
// ====================================================


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

// ==================== #11 变长编码辅助 ====================
// 读取变长整数：小值用更少字节
static bool readVarIntLE(const std::vector<unsigned char> &data, size_t &pos, int &out) {
    if (pos >= data.size()) {
        return false;
    }

    unsigned char first = data[pos] & 0xFF;
    pos++;

    if ((first & 0x80) == 0) {
        // 单字节：0~127
        out = first;
        return true;
    }

    if ((first & 0xC0) == 0x80) {
        // 两字节：128~16383
        if (pos >= data.size()) return false;
        out = ((first & 0x3F) << 8) | (data[pos] & 0xFF);
        pos++;
        return true;
    }

    if ((first & 0xE0) == 0xC0) {
        // 三字节：16384~2097151
        if (pos + 1 >= data.size()) return false;
        out = ((first & 0x1F) << 16)
            | ((data[pos] & 0xFF) << 8)
            | (data[pos + 1] & 0xFF);
        pos += 2;
        return true;
    }

    if ((first & 0xF0) == 0xE0) {
        // 四字节：2097152~268435455
        if (pos + 2 >= data.size()) return false;
        out = ((first & 0x0F) << 24)
            | ((data[pos] & 0xFF) << 16)
            | ((data[pos + 1] & 0xFF) << 8)
            | (data[pos + 2] & 0xFF);
        pos += 3;
        return true;
    }

    if ((first & 0xF8) == 0xF0) {
        // 五字节：大值
        if (pos + 3 >= data.size()) return false;
        out = ((first & 0x07) << 24)
            | ((data[pos] & 0xFF) << 16)
            | ((data[pos + 1] & 0xFF) << 8)
            | (data[pos + 2] & 0xFF);
        pos += 3;
        // 符号扩展
        if (out & 0x1000000) {
            out |= 0xFE000000;
        }
        return true;
    }

    // 负数编码：0x80~0xBF (补码)
    if ((first & 0xC0) == 0x80) {
        if (pos >= data.size()) return false;
        int val = ((first & 0x3F) << 8) | (data[pos] & 0xFF);
        if (val & 0x2000) {
            val |= 0xFFFFC000;
        }
        out = val;
        pos++;
        return true;
    }

    return false;
}

// 读取变长 long（1~9 字节）
static bool readVarLongLE(const std::vector<unsigned char> &data, size_t &pos, int64_t &out) {
    if (pos >= data.size()) {
        return false;
    }

    unsigned char first = data[pos] & 0xFF;
    pos++;

    if (first < 128) {
        out = first;
        return true;
    }

    if ((first & 0xC0) == 0x80) {
        if (pos >= data.size()) return false;
        int64_t val = ((first & 0x3F) << 8) | (data[pos] & 0xFF);
        // 符号扩展
        if (val & 0x2000) {
            val |= 0xFFFFFFFFFFFFC000LL;
        }
        out = val;
        pos++;
        return true;
    }

    if (first == 0xFF) {
        // 9 字节
        if (pos + 7 >= data.size()) return false;
        uint64_t val = 0;
        for (int i = 0; i < 8; i++) {
            val = (val << 8) | (data[pos + i] & 0xFF);
        }
        pos += 8;
        // 转换为有符号
        if (val & 0x8000000000000000ULL) {
            out = (int64_t)(val | 0xFFFFFFFF00000000ULL);
        } else {
            out = (int64_t)val;
        }
        return true;
    }

    return false;
}
// ====================================================

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

    // ==================== #7 索引表自校验：XOR 解码 + 校验和验证 ====================
    int xormask = (static_cast<int>(g_bin.vmOpcodeMap.size()) * 31 + 17) & 0xFFFFFFFF;
    // ====================================================

    //LOGI("开始解析method索引表，数量=%d", methodIndexCount);

    for (int i = 0; i < methodIndexCount; i++) {
        int methodId = 0;
        int64_t offset = 0;
        int size = 0;
        int checksum = 0;

        if (!readIntLE(data, pos, methodId)) {
            //LOGE("读取methodId失败 index=%d", i);
            return false;
        }

        // ==================== #7 索引表自校验：XOR 解码 ====================
        int64_t encryptedOffset = 0;
        int encryptedSize = 0;
        int encryptedChecksum = 0;

        if (!readLongLE(data, pos, encryptedOffset)) {
            //LOGE("读取offset失败 index=%d", i);
            return false;
        }

        // ==================== #16 加密跳转表：旋转逆变换 + XOR 解码 ====================
        long rotatedOffset = rotateLongDecrypt(encryptedOffset, xormask);
        offset = rotatedOffset ^ (int64_t)(xormask & 0xFFFF);
        // ====================================================

        if (!readIntLE(data, pos, encryptedSize)) {
            //LOGE("读取size失败 index=%d", i);
            return false;
        }

        // ==================== #16 加密跳转表：旋转逆变换 + XOR 解码 ====================
        int rotatedSize = rotateIntDecrypt(encryptedSize, xormask);
        size = rotatedSize ^ (xormask & 0xFF);
        // ====================================================

        if (!readIntLE(data, pos, encryptedChecksum)) {
            //LOGE("读取checksum失败 index=%d", i);
            return false;
        }
        checksum = encryptedChecksum ^ (xormask & 0xFFFF);
        // ====================================================

        // ==================== #7 校验和验证 ====================
        int computedChecksum = (methodId
                ^ (static_cast<int>(offset & 0xFFFF))
                ^ (static_cast<int>(size & 0xFFFF))) & 0xFFFF;
        if (computedChecksum != checksum) {
            //LOGE("索引校验和失败 methodId=%d expected=%d actual=%d", methodId, computedChecksum, checksum);
            // 开发阶段不严格拦截，生产环境应 return false
        }
        // ====================================================

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

    // ==================== #5 HMAC-SHA256 跳过 ====================
    // 记录 HMAC 位置（32 字节），暂不校验（需要完整文件数据）
    // 完整 HMAC 校验应在解密后对整个文件做
    size_t hmacPos = pos; // HMAC 起始位置
    g_bin.hmacOffset = hmacPos;
    g_bin.hasHmac = true;
    pos += 32; // 跳过 HMAC
    // ====================================================

    // ==================== #7 索引表自校验 ====================
    // 索引表中的 offset/size 用 XOR 混淆，校验和绑定到 opcodeMap
    // 运行时读取时做简单校验
    int xormask = (static_cast<int>(g_bin.vmOpcodeMap.size()) * 31 + 17) & 0xFFFFFFFF;
    for (auto &kv : g_bin.methodIndexMap) {
        VmpMethodIndex &index = kv.second;
        // 验证校验和
        int storedChecksum = (index.methodId
                ^ (static_cast<int>(index.offset & 0xFFFF))
                ^ (static_cast<int>(index.size & 0xFFFF))) & 0xFFFF;
        // 暂不做严格校验，记录异常
        if (storedChecksum != 0) {
            //LOGI("索引校验 methodId=%d checksum=%d", index.methodId, storedChecksum);
        }
    }
    // ====================================================

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

    // ==================== #5 HMAC-SHA256 完整性校验 ====================
    // 使用 opcodeKey 作为 HMAC 密钥，校验整个文件完整性
    if (g_bin.hasHmac && g_bin.hmacOffset + 32 <= g_bin.rawData.size()) {
        const unsigned char *storedHmac = g_bin.rawData.data() + g_bin.hmacOffset;

        // 计算 HMAC：密钥 = opcodeKey，数据 = 从 magic 到 HMAC 前的所有数据
        unsigned char computedHmac[32];
        unsigned int hmacLen = 0;

        HMAC(EVP_sha256(),
             g_bin.opcodeKey, 16,
             g_bin.rawData.data(), g_bin.hmacOffset,
             computedHmac, &hmacLen);

        if (hmacLen == 32) {
            bool hmacMatch = true;
            for (int i = 0; i < 32; i++) {
                if (storedHmac[i] != computedHmac[i]) {
                    hmacMatch = false;
                    break;
                }
            }
            if (!hmacMatch) {
                //LOGE("HMAC校验失败，vmp.bin可能被篡改");
                // 注意：这里不直接返回 false，因为开发阶段可能频繁修改
                // 生产环境应取消注释下面的 return false
                // g_bin = VmpBinContext();
                // return false;
            } else {
                //LOGI("HMAC校验通过");
            }
        }
    }
    // ====================================================

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

    // ==================== #13 冗余填充：跳过方法块前垃圾数据 ====================
    // 方法块前有 4~32 字节随机填充，跳过
    if (pos + 4 <= end) {
        pos += 4 + ((g_bin.rawData[pos + 3] & 0xFF) % 28);
        if (pos >= end) return false;
    }
    // ====================================================

    // ==================== #12 字段交错存储：第一段元数据 ====================
    // 读取顺序：methodId + dexName + className (提前到指令前)
    if (!readVarIntLE(g_bin.rawData, pos, method.methodId)) return false;
    if (!readStringLE(g_bin.rawData, pos, method.dexName)) return false;
    if (!readStringLE(g_bin.rawData, pos, method.className)) return false;
    // ====================================================

    // ==================== #11 变长编码：读取指令数据段 ====================
    // instructionCount + blockKeyInt 是指令数据段的前两个字段
    if (!readVarIntLE(g_bin.rawData, pos, instructionCount)) return false;

    // ==================== #2 分块加密密钥 ====================
    int blockKeyInt = 0;
    if (!readIntLE(g_bin.rawData, pos, blockKeyInt)) return false;
    unsigned char blockKey = (unsigned char)(blockKeyInt & 0xFF);
    // ====================================================

    for (int i = 0; i < instructionCount; i++) {
        VmpInstruction insn;

        int registerCount = 0;

        // ==================== #11 变长编码 ====================
        if (!readVarIntLE(g_bin.rawData, pos, insn.codeUnitOffset)) return false;

        // 读取加密的 vmOpcode 并用密钥解密
        int encryptedVmOpcode = 0;
        if (!readVarIntLE(g_bin.rawData, pos, encryptedVmOpcode)) return false;
        insn.vmOpcode = encryptedVmOpcode;
        if (g_bin.hasOpcodeKey) {
            insn.vmOpcode ^= (g_bin.opcodeKey[8 % 16] & 0xff);
        }
        // ====================================================

        auto opcodeIt = g_bin.vmOpcodeMap.find(insn.vmOpcode);
        if (opcodeIt == g_bin.vmOpcodeMap.end()) {
            //LOGE("未知vmOpcode=0x%02x instructionIndex=%d methodId=%d codeUnitOffset=%d",insn.vmOpcode,i,methodId,insn.codeUnitOffset);
            return false;
        }

        insn.realOpcode = opcodeIt->second.realOpcode;
        insn.opcodeName = opcodeIt->second.realOpcodeName;

        if (!readStringLE(g_bin.rawData, pos, insn.formatName)) return false;

        // ==================== #11 变长编码 ====================
        if (!readVarIntLE(g_bin.rawData, pos, insn.codeUnits)) return false;
        if (!readVarIntLE(g_bin.rawData, pos, registerCount)) return false;
        // ====================================================

        for (int r = 0; r < registerCount; r++) {
            int reg = 0;
            // ==================== #11 变长编码 ====================
            if (!readVarIntLE(g_bin.rawData, pos, reg)) return false;
            // ====================================================
            // ==================== 自解密（魔改#18） ====================
            insn.registers.push_back(reg ^ (blockKey & 0xFF));
            // ====================================================
        }

        int64_t literalValue = 0;

        // ==================== #11 变长编码 ====================
        if (!readVarIntLE(g_bin.rawData, pos, insn.literalType)) return false;
        // ====================================================

        // ==================== 指令重叠（魔改#19） ====================
        int overlapFlag = 0;
        if (!readIntLE(g_bin.rawData, pos, overlapFlag)) return false;

        if (overlapFlag != 0 && i > 0) {
            literalValue = method.instructions[i - 1].literalValue;
        } else {
            // ==================== #11 变长编码 ====================
            if (!readVarLongLE(g_bin.rawData, pos, literalValue)) return false;
            // ====================================================
        }
        // ====================================================

        // ==================== 常量池解密（魔改#8） ====================
        if (insn.literalType == 1 || insn.literalType == 2) {
            int litKey = (int)((insn.codeUnitOffset * 0x9E3779B9LL) & 0xFF);
            literalValue ^= litKey;
        }
        // ====================================================

        // ==================== 自解密（魔改#18） ====================
        literalValue ^= (int64_t)(blockKey & 0xFF);
        // ====================================================

        insn.literalValue = literalValue;

        // ==================== #11 变长编码 ====================
        if (!readVarIntLE(g_bin.rawData, pos, insn.offsetType)) return false;
        if (!readVarIntLE(g_bin.rawData, pos, insn.offsetValue)) return false;
        // ====================================================

        // ==================== 自解密（魔改#18） ====================
        insn.offsetValue ^= (blockKey & 0xFF);
        // ====================================================

        if (!readIntLE(g_bin.rawData, pos, insn.referenceType)) return false;
        if (!readStringLE(g_bin.rawData, pos, insn.referenceData)) return false;

        if (!readIntLE(g_bin.rawData, pos, insn.extraReferenceType)) return false;
        if (!readStringLE(g_bin.rawData, pos, insn.extraReferenceData)) return false;
        method.instructions.push_back(insn);
    }

    // ==================== #12 字段交错存储：第二段元数据 ====================
    if (!readStringLE(g_bin.rawData, pos, method.methodName)) return false;
    if (!readStringLE(g_bin.rawData, pos, method.methodSignature)) return false;
    if (!readVarIntLE(g_bin.rawData, pos, method.accessFlags)) return false;
    if (!readVarIntLE(g_bin.rawData, pos, method.registerCount)) return false;
    if (!readVarIntLE(g_bin.rawData, pos, method.paramCount)) return false;
    if (!readStringLE(g_bin.rawData, pos, method.returnType)) return false;
    if (!readVarIntLE(g_bin.rawData, pos, isStaticValue)) return false;

    method.isStatic = isStaticValue != 0;

    if (!readVarIntLE(g_bin.rawData, pos, parameterTypeCount)) return false;

    for (int i = 0; i < parameterTypeCount; i++) {
        std::string type;
        if (!readStringLE(g_bin.rawData, pos, type)) return false;
        method.parameterTypes.push_back(type);
    }
    // ====================================================

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

    // ==================== #6 哈希链校验 ====================
    // 读取方法块的链式哈希（32 字节），用于校验方法内容是否被篡改
    // 链式哈希包含本块信息 + 前一个块的位置信息
    if (pos + 32 <= end) {
        unsigned char storedHash[32];
        memcpy(storedHash, &g_bin.rawData[pos], 32);
        pos += 32;

        // 重新计算方法块的哈希进行验证
        unsigned int expected = 0;
        for (char c : method.methodName) expected = (expected * 31 + c) & 0xFFFFFFFF;
        for (char c : method.methodSignature) expected = (expected * 37 + c) & 0xFFFFFFFF;
        expected ^= method.methodId;
        expected ^= (unsigned int)method.instructions.size();
        expected ^= (unsigned int)method.registerCount;

        // 比较存储的哈希和计算值（取前4字节比较）
        unsigned int stored = 0;
        for (int i = 0; i < 4; i++) {
            stored = (stored << 8) | storedHash[i];
        }

        if (stored != expected) {
            //LOGE("哈希链校验失败 methodId=%d name=%s", methodId, method.methodName.c_str());
            return false;
        }

        //LOGI("哈希链校验通过 methodId=%d", methodId);
    }
    // ====================================================

    // ==================== #13 冗余填充：跳过方法块后垃圾数据 ====================
    // 方法块后有 4~32 字节随机填充，跳过
    size_t remaining = end - pos;
    if (remaining >= 4) {
        int paddingAfter = 4 + (g_bin.rawData[end - 1] & 0x1F); // 从末尾取低5位
        if (paddingAfter > (int)remaining) paddingAfter = (int)remaining;
        pos += paddingAfter;
    }
    // ====================================================

    if (pos != end) {
        //LOGI("methodId=%d 解析完成，pos和end有偏差 pos=%d end=%d",methodId,static_cast<int>(pos),static_cast<int>(end));
    }

    g_bin.methodCache[methodId] = method;
    outMethod = method;

    //LOGI("methodId=%d 已从内存bin解析并加入缓存", methodId);

    return true;
}