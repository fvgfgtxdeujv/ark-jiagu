#ifndef ARK_DEX_BLOCK_H
#define ARK_DEX_BLOCK_H

#include <vector>
#include <cstdint>

// Block info struct - only records encrypted dex block metadata, not plaintext dex
struct ArkDexBlockInfo {
    size_t dataOffset;
    size_t plainLen;
    unsigned char key[64];
};

// Index entry struct for the payload index table
struct ArkPayloadIndexEntry {
    int type;
    int index;
    size_t offset;
    size_t size;
};

// Helper: read a little-endian 32-bit integer from a byte pointer
uint32_t readLe32(const unsigned char *p);

// Helper: XOR data with a repeating key
std::vector<unsigned char> xorData(
        const unsigned char *data,
        size_t len,
        const unsigned char *key,
        size_t keyLen);

// Helper: read a LE32 from a vector at current position, advancing the position
bool readLe32FromVector(
        const std::vector<unsigned char> &data,
        size_t &pos,
        uint32_t &out);

// Parse the plaintext payload index table (starts with "AKIT" magic, version 1)
bool parsePayloadIndexPlainBytes(
        const std::vector<unsigned char> &plain,
        std::vector<ArkPayloadIndexEntry> &outEntries);

// Parse encrypted block info (key offset + plaintext length) from an index entry
bool parseEncryptedBlockInfoByIndex(
        const std::vector<unsigned char> &allData,
        size_t blockOffset,
        size_t blockSize,
        ArkDexBlockInfo &outInfo,
        const unsigned char *signKey64);

// Parse one encrypted block backward (decrypts the plaintext immediately)
// Used for the app name block and index table block which are small
bool parseOneEncryptedBlockBackward(
        JNIEnv *env,
        const std::vector<unsigned char> &allData,
        size_t &cursor,
        std::vector<unsigned char> &outPlain,
        const unsigned char *signKey64);

// Parse one encrypted block backward (only records metadata, does NOT decrypt)
// Used for dex payload blocks in format 2 to avoid holding all plaintext dex in memory
bool parseOneEncryptedBlockInfoBackward(
        const std::vector<unsigned char> &allData,
        size_t &cursor,
        ArkDexBlockInfo &outInfo,
        const unsigned char *signKey64);

#endif
