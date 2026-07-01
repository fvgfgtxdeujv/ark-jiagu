#include "ArkTool.h"

#include "ArkCrypto.h"
#include "ArkDexBlock.h"

#include <jni.h>
#include <vector>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <cstdio>
#include <unistd.h>
#include <stdint.h>

#if __has_include(<sys/random.h>)
#include <sys/random.h>
#endif
static const unsigned char ARK_BLOCK_USE_SIGN_KEY_FLAG[4] = {
        0x41, 0x52, 0x4B, 0x53 // "ARKS"
};
static void intToLe4Bytes(int value, unsigned char out[4]) {
    out[0] = static_cast<unsigned char>(value & 0xff);
    out[1] = static_cast<unsigned char>((value >> 8) & 0xff);
    out[2] = static_cast<unsigned char>((value >> 16) & 0xff);
    out[3] = static_cast<unsigned char>((value >> 24) & 0xff);
}

//写 int 到 vector
static void appendIntLE(std::vector<unsigned char> &out, int value) {
    unsigned char buf[4];
    intToLe4Bytes(value, buf);
    out.insert(out.end(), buf, buf + 4);
}
//生成明文索引表
static std::vector<unsigned char> buildPayloadIndexPlainBytes(
        const std::vector<ArkPayloadIndexEntry> &entries
) {
    std::vector<unsigned char> out;

    out.push_back('A');
    out.push_back('K');
    out.push_back('I');
    out.push_back('T');

    appendIntLE(out, 1);
    appendIntLE(out, static_cast<int>(entries.size()));

    for (size_t i = 0; i < entries.size(); i++) {
        appendIntLE(out, entries[i].type);
        appendIntLE(out, entries[i].index);
        appendIntLE(out, entries[i].offset);
        appendIntLE(out, entries[i].size);
    }

    return out;
}
//添加索引项
static void addPayloadIndexEntry(
        std::vector<ArkPayloadIndexEntry> &indexTable,
        int type,
        int index,
        size_t offset,
        size_t size
) {
    ArkPayloadIndexEntry entry;
    entry.type = type;
    entry.index = index;
    entry.offset = offset;
    entry.size = size;

    indexTable.push_back(entry);
}



static bool readOptionalByteArray(
        JNIEnv *env,
        jbyteArray array,
        std::vector<unsigned char> &out
) {
    out.clear();

    if (array == nullptr) {
        return true;
    }

    jsize len = env->GetArrayLength(array);
    if (len != 64) {
        return false;
    }

    out.resize(64);

    env->GetByteArrayRegion(
            array,
            0,
            64,
            reinterpret_cast<jbyte *>(out.data())
    );

    return !env->ExceptionCheck();
}
static jbyteArray makeByteArray(JNIEnv *env, const unsigned char *data, int len) {
    if (data == nullptr || len < 0) {
        return nullptr;
    }

    jbyteArray out = env->NewByteArray(len);
    if (out == nullptr) {
        return nullptr;
    }

    if (len > 0) {
        env->SetByteArrayRegion(
                out,
                0,
                len,
                reinterpret_cast<const jbyte *>(data)
        );
    }

    return out;
}

static bool readByteArray(JNIEnv *env, jbyteArray array, std::vector<unsigned char> &out) {
    if (array == nullptr) {
        return false;
    }

    jsize len = env->GetArrayLength(array);
    if (len <= 0) {
        return false;
    }

    out.resize(len);

    env->GetByteArrayRegion(
            array,
            0,
            len,
            reinterpret_cast<jbyte *>(out.data())
    );

    return !env->ExceptionCheck();
}


static void xorBytes(
        const unsigned char *data,
        int dataLen,
        const unsigned char *key,
        int keyLen,
        std::vector<unsigned char> &out
) {
    out.resize(dataLen);

    for (int i = 0; i < dataLen; i++) {
        out[i] = data[i] ^ key[i % keyLen];
    }
}

static bool fillRandomBytes(unsigned char *buffer, int len) {
    if (buffer == nullptr || len <= 0) {
        return false;
    }

#if defined(SYS_getrandom)
    ssize_t n = getrandom(buffer, len, 0);
    if (n == len) {
        return true;
    }
#endif

    FILE *fp = fopen("/dev/urandom", "rb");
    if (fp != nullptr) {
        size_t n = fread(buffer, 1, len, fp);
        fclose(fp);

        if (n == static_cast<size_t>(len)) {
            return true;
        }
    }

    srand(static_cast<unsigned int>(time(nullptr) ^ getpid()));

    for (int i = 0; i < len; i++) {
        buffer[i] = static_cast<unsigned char>(rand() & 0xff);
    }

    return true;
}

static jbyteArray native_buildEncryptedBlock(JNIEnv *env, jobject thiz, jbyteArray plainData) {
    std::vector<unsigned char> plain;

    if (!readByteArray(env, plainData, plain)) {
        return nullptr;
    }

    unsigned char key[64];
    if (!fillRandomBytes(key, sizeof(key))) {
        return nullptr;
    }

    std::vector<unsigned char> encryptedData;
    xorBytes(
            plain.data(),
            static_cast<int>(plain.size()),
            key,
            sizeof(key),
            encryptedData
    );

    unsigned char lenBytes[4];
    intToLe4Bytes(static_cast<int>(plain.size()), lenBytes);

    std::vector<unsigned char> encryptedLen;
    xorBytes(
            lenBytes,
            4,
            key,
            sizeof(key),
            encryptedLen
    );

    std::vector<unsigned char> result;
    result.reserve(encryptedData.size() + encryptedLen.size() + sizeof(key));

    result.insert(result.end(), encryptedData.begin(), encryptedData.end());
    result.insert(result.end(), encryptedLen.begin(), encryptedLen.end());
    result.insert(result.end(), key, key + sizeof(key));

    return makeByteArray(env, result.data(), static_cast<int>(result.size()));
}

static jbyteArray native_fixDexHeader(JNIEnv *env, jobject thiz, jbyteArray dexData) {
    std::vector<unsigned char> dex;

    if (!readByteArray(env, dexData, dex)) {
        return nullptr;
    }

    if (dex.size() < 0x70) {
        return nullptr;
    }

    int fileSize = static_cast<int>(dex.size());

    unsigned char fileSizeBytes[4];
    intToLe4Bytes(fileSize, fileSizeBytes);
    memcpy(dex.data() + 32, fileSizeBytes, 4);

    unsigned char signature[20];
    sha1Bytes(dex.data() + 32, dex.size() - 32, signature);
    memcpy(dex.data() + 12, signature, 20);

    uint32_t checksum = adler32Bytes(dex.data() + 12, dex.size() - 12);

    unsigned char checksumBytes[4];
    intToLe4Bytes(static_cast<int>(checksum), checksumBytes);
    memcpy(dex.data() + 8, checksumBytes, 4);

    return makeByteArray(env, dex.data(), static_cast<int>(dex.size()));
}

static jboolean native_isValidDex(JNIEnv *env, jobject thiz, jbyteArray data) {
    if (data == nullptr) {
        return JNI_FALSE;
    }

    jsize len = env->GetArrayLength(data);
    if (len < 0x70) {
        return JNI_FALSE;
    }

    unsigned char magic[4];

    env->GetByteArrayRegion(
            data,
            0,
            4,
            reinterpret_cast<jbyte *>(magic)
    );

    if (env->ExceptionCheck()) {
        return JNI_FALSE;
    }

    if (magic[0] == 'd'
        && magic[1] == 'e'
        && magic[2] == 'x'
        && magic[3] == '\n') {
        return JNI_TRUE;
    }

    return JNI_FALSE;
}

static jbyteArray native_intToLe4(JNIEnv *env, jobject thiz, jint value) {
    unsigned char out[4];
    intToLe4Bytes(value, out);
    return makeByteArray(env, out, 4);
}

static void throwRuntimeException(JNIEnv *env, const char *msg) {
    jclass cls = env->FindClass("java/lang/RuntimeException");
    if (cls != nullptr) {
        env->ThrowNew(cls, msg);
    }
}

static jstring getFileAbsolutePath(JNIEnv *env, jobject fileObj) {
    jclass clsFile = env->FindClass("java/io/File");
    jmethodID midGetAbsolutePath = env->GetMethodID(
            clsFile,
            "getAbsolutePath",
            "()Ljava/lang/String;"
    );

    return (jstring) env->CallObjectMethod(fileObj, midGetAbsolutePath);
}

static std::vector<unsigned char> readAllBytesFromInputStream(JNIEnv *env, jobject inputStream) {
    std::vector<unsigned char> result;

    jclass clsInputStream = env->FindClass("java/io/InputStream");
    jmethodID midRead = env->GetMethodID(clsInputStream, "read", "([B)I");
    jmethodID midClose = env->GetMethodID(clsInputStream, "close", "()V");

    jbyteArray buffer = env->NewByteArray(8192);

    while (true) {
        jint len = env->CallIntMethod(inputStream, midRead, buffer);
        if (env->ExceptionCheck()) {
            result.clear();
            return result;
        }

        if (len <= 0) {
            break;
        }

        size_t oldSize = result.size();
        result.resize(oldSize + len);

        env->GetByteArrayRegion(
                buffer,
                0,
                len,
                reinterpret_cast<jbyte *>(result.data() + oldSize)
        );

        if (env->ExceptionCheck()) {
            result.clear();
            return result;
        }
    }

    env->CallVoidMethod(inputStream, midClose);
    return result;
}

static std::vector<unsigned char> readAllBytesFromFile(JNIEnv *env, jobject fileObj) {
    std::vector<unsigned char> result;

    jclass clsFileInputStream = env->FindClass("java/io/FileInputStream");
    jmethodID midInit = env->GetMethodID(
            clsFileInputStream,
            "<init>",
            "(Ljava/io/File;)V"
    );

    jobject fis = env->NewObject(clsFileInputStream, midInit, fileObj);
    if (env->ExceptionCheck() || fis == nullptr) {
        result.clear();
        return result;
    }

    return readAllBytesFromInputStream(env, fis);
}

static bool writeAllBytesToFile(JNIEnv *env, jobject fileObj, const std::vector<unsigned char> &data) {
    jclass clsFileOutputStream = env->FindClass("java/io/FileOutputStream");
    jmethodID midInit = env->GetMethodID(
            clsFileOutputStream,
            "<init>",
            "(Ljava/io/File;)V"
    );

    jobject fos = env->NewObject(clsFileOutputStream, midInit, fileObj);
    if (env->ExceptionCheck() || fos == nullptr) {
        return false;
    }

    jmethodID midWrite = env->GetMethodID(clsFileOutputStream, "write", "([B)V");
    jmethodID midFlush = env->GetMethodID(clsFileOutputStream, "flush", "()V");
    jmethodID midClose = env->GetMethodID(clsFileOutputStream, "close", "()V");

    jbyteArray arr = makeByteArray(
            env,
            data.data(),
            static_cast<int>(data.size())
    );

    env->CallVoidMethod(fos, midWrite, arr);
    if (env->ExceptionCheck()) {
        return false;
    }

    env->CallVoidMethod(fos, midFlush);
    env->CallVoidMethod(fos, midClose);

    return !env->ExceptionCheck();
}

static void appendLogOnUiNative(JNIEnv *env, jobject thiz, const char *msg) {
    jclass cls = env->GetObjectClass(thiz);
    jmethodID mid = env->GetMethodID(
            cls,
            "appendLogOnUi",
            "(Ljava/lang/String;)V"
    );

    if (mid == nullptr) {
        env->ExceptionClear();
        return;
    }

    jstring text = env->NewStringUTF(msg);
    env->CallVoidMethod(thiz, mid, text);

    if (env->ExceptionCheck()) {
        env->ExceptionClear();
    }
}

static bool isValidDexBytes(const std::vector<unsigned char> &data) {
    return data.size() >= 0x70
           && data[0] == 'd'
           && data[1] == 'e'
           && data[2] == 'x'
           && data[3] == '\n';
}

static std::vector<unsigned char> buildEncryptedBlockBytes(
        const unsigned char *data,
        int len,
        const unsigned char *externalKey,
        int externalKeyLen
) {
    std::vector<unsigned char> result;

    if (data == nullptr || len <= 0) {
        return result;
    }

    bool useExternalKey = externalKey != nullptr && externalKeyLen == 64;

    unsigned char randomKey[64];

    const unsigned char *key = nullptr;
    int keyLen = 64;

    if (useExternalKey) {
        key = externalKey;
    } else {
        if (!fillRandomBytes(randomKey, sizeof(randomKey))) {
            return result;
        }

        key = randomKey;
    }

    std::vector<unsigned char> encryptedData;
    xorBytes(data, len, key, keyLen, encryptedData);

    unsigned char lenBytes[4];
    intToLe4Bytes(len, lenBytes);

    std::vector<unsigned char> encryptedLen;
    xorBytes(lenBytes, 4, key, keyLen, encryptedLen);

    if (useExternalKey) {
        // 格式：
        // [加密数据][加密长度4字节][特征4字节]
        result.reserve(
                encryptedData.size()
                + encryptedLen.size()
                + sizeof(ARK_BLOCK_USE_SIGN_KEY_FLAG)
        );

        result.insert(result.end(), encryptedData.begin(), encryptedData.end());
        result.insert(result.end(), encryptedLen.begin(), encryptedLen.end());
        result.insert(
                result.end(),
                ARK_BLOCK_USE_SIGN_KEY_FLAG,
                ARK_BLOCK_USE_SIGN_KEY_FLAG + sizeof(ARK_BLOCK_USE_SIGN_KEY_FLAG)
        );
    } else {
        // 原格式：
        // [加密数据][加密长度4字节][随机密钥64字节]
        result.reserve(
                encryptedData.size()
                + encryptedLen.size()
                + sizeof(randomKey)
        );

        result.insert(result.end(), encryptedData.begin(), encryptedData.end());
        result.insert(result.end(), encryptedLen.begin(), encryptedLen.end());
        result.insert(result.end(), randomKey, randomKey + sizeof(randomKey));
    }

    return result;
}

static std::vector<unsigned char> fixDexHeaderBytes(std::vector<unsigned char> dex) {
    if (dex.size() < 0x70) {
        dex.clear();
        return dex;
    }

    unsigned char fileSizeBytes[4];
    intToLe4Bytes(static_cast<int>(dex.size()), fileSizeBytes);
    memcpy(dex.data() + 32, fileSizeBytes, 4);

    unsigned char signature[20];
    sha1Bytes(dex.data() + 32, dex.size() - 32, signature);
    memcpy(dex.data() + 12, signature, 20);

    uint32_t checksum = adler32Bytes(dex.data() + 12, dex.size() - 12);

    unsigned char checksumBytes[4];
    intToLe4Bytes(static_cast<int>(checksum), checksumBytes);
    memcpy(dex.data() + 8, checksumBytes, 4);

    return dex;
}

static void native_buildEncryptedShellDex(
        JNIEnv *env,
        jobject thiz,
        jobject dexDir,
        jobject shellDexFile,
        jstring realApplicationName,
        jbyteArray signHash64
) {
    if (dexDir == nullptr || shellDexFile == nullptr || realApplicationName == nullptr) {
        throwRuntimeException(env, "参数为空");
        return;
    }

    std::vector<unsigned char> signKey;

    if (!readOptionalByteArray(env, signHash64, signKey)) {
        throwRuntimeException(env, "签名密钥必须为空或64字节");
        return;
    }

    const unsigned char *dexKey = signKey.empty() ? nullptr : signKey.data();
    int dexKeyLen = signKey.empty() ? 0 : static_cast<int>(signKey.size());

    std::vector<unsigned char> shellDex = readAllBytesFromFile(env, shellDexFile);
    if (env->ExceptionCheck()) {
        return;
    }

    if (!isValidDexBytes(shellDex)) {
        throwRuntimeException(env, "壳 dex 非法");
        return;
    }

    jstring dexDirPathJ = getFileAbsolutePath(env, dexDir);
    if (dexDirPathJ == nullptr) {
        throwRuntimeException(env, "获取 dex 目录失败");
        return;
    }

    const char *dexDirPath = env->GetStringUTFChars(dexDirPathJ, nullptr);
    if (dexDirPath == nullptr) {
        throwRuntimeException(env, "读取 dex 目录路径失败");
        return;
    }

    jclass clsFile = env->FindClass("java/io/File");
    if (clsFile == nullptr) {
        env->ReleaseStringUTFChars(dexDirPathJ, dexDirPath);
        throwRuntimeException(env, "找不到 File 类");
        return;
    }

    jmethodID midFileInit = env->GetMethodID(
            clsFile,
            "<init>",
            "(Ljava/lang/String;Ljava/lang/String;)V"
    );

    if (midFileInit == nullptr) {
        env->ReleaseStringUTFChars(dexDirPathJ, dexDirPath);
        throwRuntimeException(env, "获取 File 构造方法失败");
        return;
    }

    jmethodID midExists = env->GetMethodID(
            clsFile,
            "exists",
            "()Z"
    );

    if (midExists == nullptr) {
        env->ReleaseStringUTFChars(dexDirPathJ, dexDirPath);
        throwRuntimeException(env, "获取 File.exists 失败");
        return;
    }

    std::vector<unsigned char> payload;
    std::vector<ArkPayloadIndexEntry> indexTable;

    int dexCount = 0;

    for (int i = 1; ; i++) {
        char dexName[64];

        if (i == 1) {
            snprintf(dexName, sizeof(dexName), "classes.dex");
        } else {
            snprintf(dexName, sizeof(dexName), "classes%d.dex", i);
        }

        jstring parentJ = env->NewStringUTF(dexDirPath);
        jstring nameJ = env->NewStringUTF(dexName);

        jobject dexFileObj = env->NewObject(
                clsFile,
                midFileInit,
                parentJ,
                nameJ
        );

        if (env->ExceptionCheck() || dexFileObj == nullptr) {
            env->ReleaseStringUTFChars(dexDirPathJ, dexDirPath);
            return;
        }

        jboolean exists = env->CallBooleanMethod(dexFileObj, midExists);

        if (env->ExceptionCheck()) {
            env->ReleaseStringUTFChars(dexDirPathJ, dexDirPath);
            return;
        }

        if (!exists) {
            break;
        }

        std::vector<unsigned char> dexData = readAllBytesFromFile(env, dexFileObj);
        if (env->ExceptionCheck()) {
            env->ReleaseStringUTFChars(dexDirPathJ, dexDirPath);
            return;
        }

        if (!isValidDexBytes(dexData)) {
            char logText[160];
            snprintf(logText, sizeof(logText), "发现非法 dex，停止处理：%s", dexName);
            appendLogOnUiNative(env, thiz, logText);
            break;
        }

        std::vector<unsigned char> block = buildEncryptedBlockBytes(
                dexData.data(),
                static_cast<int>(dexData.size()),
                dexKey,
                dexKeyLen
        );

        if (block.empty()) {
            env->ReleaseStringUTFChars(dexDirPathJ, dexDirPath);
            throwRuntimeException(env, "dex 加密失败");
            return;
        }

        int blockOffset = static_cast<int>(payload.size());
        int blockSize = static_cast<int>(block.size());

        payload.insert(payload.end(), block.begin(), block.end());

        addPayloadIndexEntry(
                indexTable,
                1,
                i,
                blockOffset,
                blockSize
        );

        dexCount++;

        char logText[160];
        /*snprintf(
                logText,
                sizeof(logText),
                "已加密：%s，大小：%d，偏移：%d，块大小：%d",
                dexName,
                static_cast<int>(dexData.size()),
                blockOffset,
                blockSize
        );*/
        snprintf(
                logText,
                sizeof(logText),
                "已加密：%s，大小：%d",
                dexName,
                static_cast<int>(dexData.size())
        );
        appendLogOnUiNative(env, thiz, logText);
    }

    env->ReleaseStringUTFChars(dexDirPathJ, dexDirPath);

    if (dexCount <= 0) {
        throwRuntimeException(env, "dex目录中没有找到合法 dex");
        return;
    }

    const char *appNameChars = env->GetStringUTFChars(realApplicationName, nullptr);
    if (appNameChars == nullptr) {
        throwRuntimeException(env, "获取入口类名失败");
        return;
    }

    int appNameLen = static_cast<int>(strlen(appNameChars));

    std::vector<unsigned char> appBlock = buildEncryptedBlockBytes(
            reinterpret_cast<const unsigned char *>(appNameChars),
            appNameLen,
            nullptr,
            0
    );

    char appLog[256];
    snprintf(appLog, sizeof(appLog), "已加密入口：%s", appNameChars);
    appendLogOnUiNative(env, thiz, appLog);

    env->ReleaseStringUTFChars(realApplicationName, appNameChars);

    if (appBlock.empty()) {
        throwRuntimeException(env, "入口类名加密失败");
        return;
    }

    int appBlockOffset = static_cast<int>(payload.size());
    int appBlockSize = static_cast<int>(appBlock.size());

    payload.insert(payload.end(), appBlock.begin(), appBlock.end());

    addPayloadIndexEntry(
            indexTable,
            2,
            0,
            appBlockOffset,
            appBlockSize
    );

    std::vector<unsigned char> indexPlain = buildPayloadIndexPlainBytes(indexTable);

    std::vector<unsigned char> indexBlock = buildEncryptedBlockBytes(
            indexPlain.data(),
            static_cast<int>(indexPlain.size()),
            nullptr,
            0
    );

    if (indexBlock.empty()) {
        throwRuntimeException(env, "索引表加密失败");
        return;
    }

    payload.insert(payload.end(), indexBlock.begin(), indexBlock.end());

    unsigned char indexMagic[4] = {
            0x41, 0x4B, 0x49, 0x58 // "AKIX"
    };
    payload.insert(payload.end(), indexMagic, indexMagic + 4);

    char indexLog[256];
    /*snprintf(
            indexLog,
            sizeof(indexLog),
            "已写入加密索引表，索引数量：%d，索引明文大小：%d，加密块大小：%d",
            static_cast<int>(indexTable.size()),
            static_cast<int>(indexPlain.size()),
            static_cast<int>(indexBlock.size())
    );
    appendLogOnUiNative(env, thiz, indexLog);*/

    std::vector<unsigned char> finalDex;
    finalDex.reserve(shellDex.size() + payload.size());
    finalDex.insert(finalDex.end(), shellDex.begin(), shellDex.end());
    finalDex.insert(finalDex.end(), payload.begin(), payload.end());

    std::vector<unsigned char> fixedDex = fixDexHeaderBytes(finalDex);
    if (fixedDex.empty()) {
        throwRuntimeException(env, "修复 dex 头失败");
        return;
    }

    if (!writeAllBytesToFile(env, shellDexFile, fixedDex)) {
        throwRuntimeException(env, "写入壳 dex 失败");
        return;
    }
}

static JNINativeMethod gMethods[] = {
        {
                const_cast<char *>("buildEncryptedBlock"),
                const_cast<char *>("([B)[B"),
                reinterpret_cast<void *>(native_buildEncryptedBlock)
        },
        {
                const_cast<char *>("fixDexHeader"),
                const_cast<char *>("([B)[B"),
                reinterpret_cast<void *>(native_fixDexHeader)
        },
        {
                const_cast<char *>("isValidDex"),
                const_cast<char *>("([B)Z"),
                reinterpret_cast<void *>(native_isValidDex)
        },
        {
                const_cast<char *>("intToLe4"),
                const_cast<char *>("(I)[B"),
                reinterpret_cast<void *>(native_intToLe4)
        },
        {
                const_cast<char *>("buildEncryptedShellDex"),
                const_cast<char *>("(Ljava/io/File;Ljava/io/File;Ljava/lang/String;[B)V"),
                reinterpret_cast<void *>(native_buildEncryptedShellDex)
        },
};

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env = nullptr;

    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    jclass clazz = env->FindClass("com/ark/jiagu/MainActivity");
    if (clazz == nullptr) {
        return JNI_ERR;
    }

    jint ret = env->RegisterNatives(
            clazz,
            gMethods,
            sizeof(gMethods) / sizeof(gMethods[0])
    );

    if (ret != JNI_OK) {
        return JNI_ERR;
    }

    return JNI_VERSION_1_6;
}
