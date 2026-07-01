#ifndef ARK_CRYPTO_H
#define ARK_CRYPTO_H

#include <cstdint>

uint32_t leftRotate(uint32_t value, uint32_t bits);
void sha1Bytes(const unsigned char *data, size_t len, unsigned char out[20]);
uint32_t adler32Bytes(const unsigned char *data, size_t len);

#endif
