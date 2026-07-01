#include "ArkDexBlock.h"

#include <jni.h>
#include <cstring>

#define ARK_BLOCK_USE_SIGN_KEY_FLAG {0x41, 0x52, 0x4B, 0x53} // "ARKS"

static const unsigned char ARK_BLOCK_USE_SIGN_KEY_FLAG[4] = {
        0x41, 0x52, 0x4B, 0x53 // "ARKS"
};

static uint32_t readLe32(const unsigned char *p) {
    return ((uint32_t) p[0])
           | ((uint32_t) p[1] << 8)
           | ((uint32_t) p[2] << 16)
           | ((uint32_t) p[3] << 24);
}

static std::vector<unsigned char> xorData(
        const unsigned char *data,
        size_t len,
        const unsigned char *key,
        size_t keyLen) {

    std::vector<unsigned char> out;
    out.resize(len);

    for (size_t i = 0; i < len; i++) {
        out[i] = data[i] ^ key[i % keyLen];
    }

    return out;
}

static bool readLe32FromVector(
        const std::vector<unsigned char> &data,
        size_t &pos,
        uint32_t &out
) {
    if (pos + 4 > data.size()) {
        return false;
    }

    out = readLe32(data.data() + pos);
    pos += 4;
    return true;
}

static bool parsePayloadIndexPlainBytes(
        const std::vector<unsigned char> &plain,
        std::vector<ArkPayloadIndexEntry> &outEntries
) {
    outEntries.clear();

    if (plain.size() < 12) {
        return false;
    }

    if (!(plain[0] == 'A'
          && plain[1] == 'K'
          && plain[2] == 'I'
          && plain[3] == 'T')) {
        return false;
    }

    size_t pos = 4;

    uint32_t version = 0;
    uint32_t entryCount = 0;

    if (!readLe32FromVector(plain, pos, version)) {
        return false;
    }

    if (version != 1) {
        return false;
    }

    if (!readLe32FromVector(plain, pos, entryCount)) {
        return false;
    }

    if (entryCount == 0 || entryCount > 256) {
        return false;
    }

    if (pos + entryCount * 16 > plain.size()) {
        return false;
    }

    for (uint32_t i = 0; i < entryCount; i++) {
        uint32_t type = 0;
        uint32_t index = 0;
        uint32_t offset = 0;
        uint32_t size = 0;

        if (!readLe32FromVector(plain, pos, type)) return false;
        if (!readLe32FromVector(plain, pos, index)) return false;
        if (!readLe32FromVector(plain, pos, offset)) return false;
        if (!readLe32FromVector(plain, pos, size)) return false;

        if (size == 0) {
            return false;
        }

        ArkPayloadIndexEntry entry;
        entry.type = static_cast<int>(type);
        entry.index = static_cast<int>(index);
        entry.offset = static_cast<size_t>(offset);
        entry.size = static_cast<size_t>(size);

        outEntries.push_back(entry);
    }
    return true;
}

static bool parseEncryptedBlockInfoByIndex(
        const std::vector<unsigned char> &allData,
        size_t blockOffset,
        size_t blockSize,
        ArkDexBlockInfo &outInfo,
        const unsigned char *signKey64
) {
    if (blockSize < 8) {
        return false;
    }

    if (blockOffset + blockSize > allData.size()) {
        return false;
    }

    bool useSignKey = false;

    const unsigned char *blockStart = allData.data() + blockOffset;
    const unsigned char *blockEnd = blockStart + blockSize;

    if (blockSize >= 4) {
        const unsigned char *tail = blockEnd - 4;

        if (memcmp(tail, ARK_BLOCK_USE_SIGN_KEY_FLAG, 4) == 0) {
            useSignKey = true;
        }
    }

    const unsigned char *key = nullptr;
    size_t lenOffset = 0;

    if (useSignKey) {
        if (signKey64 == nullptr) {
            return false;
        }

        key = signKey64;

        if (blockSize < 8) {
            return false;
        }

        lenOffset = blockOffset + blockSize - 8;
    } else {
        if (blockSize < 68) {
            return false;
        }

        size_t keyOffset = blockOffset + blockSize - 64;
        key = allData.data() + keyOffset;
        lenOffset = keyOffset - 4;
    }

    std::vector<unsigned char> lenPlain = xorData(
            allData.data() + lenOffset,
            4,
            key,
            64
    );

    uint32_t plainLen = readLe32(lenPlain.data());

    if (plainLen <= 0) {
        return false;
    }

    size_t dataOffset = blockOffset;

    if (dataOffset + plainLen > allData.size()) {
        return false;
    }

    if (dataOffset + plainLen > lenOffset) {
        return false;
    }

    outInfo.dataOffset = dataOffset;
    outInfo.plainLen = plainLen;
    memcpy(outInfo.key, key, 64);

    return true;
}

static bool parseOneEncryptedBlockBackward(
        JNIEnv *env,
        const std::vector<unsigned char> &allData,
        size_t &cursor,
        std::vector<unsigned char> &outPlain,
        const unsigned char *signKey64) {

    if (cursor < 8) {
        return false;
    }

    bool useSignKey = false;

    if (cursor >= 4) {
        const unsigned char *tail = allData.data() + cursor - 4;

        if (memcmp(tail, ARK_BLOCK_USE_SIGN_KEY_FLAG, 4) == 0) {
            useSignKey = true;
        }
    }

    const unsigned char *key = nullptr;
    size_t lenOffset = 0;

    if (useSignKey) {
        if (signKey64 == nullptr) {
            return false;
        }

        key = signKey64;

        if (cursor < 8) {
            return false;
        }

        // 新格式：
        // [加密数据][加密长度4字节][ARKS特征4字节]
        lenOffset = cursor - 4 - 4;
    } else {
        if (cursor < 68) {
            return false;
        }

        // 老格式：
        // [加密数据][加密长度4字节][随机密钥64字节]
        size_t keyOffset = cursor - 64;
        key = allData.data() + keyOffset;
        lenOffset = keyOffset - 4;
    }

    std::vector<unsigned char> lenPlain = xorData(
            allData.data() + lenOffset,
            4,
            key,
            64
    );

    uint32_t plainLen = readLe32(lenPlain.data());

    if (plainLen <= 0 || lenOffset < plainLen) {
        return false;
    }

    size_t dataOffset = lenOffset - plainLen;

    outPlain = xorData(
            allData.data() + dataOffset,
            plainLen,
            key,
            64
    );

    cursor = dataOffset;
    return true;
}

static bool parseOneEncryptedBlockInfoBackward(
        const std::vector<unsigned char> &allData,
        size_t &cursor,
        ArkDexBlockInfo &outInfo,
        const unsigned char *signKey64) {

    if (cursor < 8) {
        return false;
    }

    bool useSignKey = false;

    if (cursor >= 4) {
        const unsigned char *tail = allData.data() + cursor - 4;
        if (memcmp(tail, ARK_BLOCK_USE_SIGN_KEY_FLAG, 4) == 0) {
            useSignKey = true;
        }
    }

    const unsigned char *key = nullptr;
    size_t lenOffset = 0;

    if (useSignKey) {
        if (signKey64 == nullptr) {
            return false;
        }

        key = signKey64;
        lenOffset = cursor - 8;
    } else {
        if (cursor < 68) {
            return false;
        }

        size_t keyOffset = cursor - 64;
        key = allData.data() + keyOffset;
        lenOffset = keyOffset - 4;
    }

    std::vector<unsigned char> lenPlain = xorData(
            allData.data() + lenOffset,
            4,
            key,
            64
    );

    uint32_t plainLen = readLe32(lenPlain.data());

    if (plainLen <= 0 || lenOffset < plainLen) {
        return false;
    }

    size_t dataOffset = lenOffset - plainLen;

    outInfo.dataOffset = dataOffset;
    outInfo.plainLen = plainLen;
    memcpy(outInfo.key, key, 64);

    cursor = dataOffset;
    return true;
}
