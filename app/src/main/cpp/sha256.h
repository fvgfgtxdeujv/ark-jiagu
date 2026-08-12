#ifndef ARK_SHA256_H
#define ARK_SHA256_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t data[64];
    uint32_t datalen;
} sha256_ctx;

void sha256_init(sha256_ctx *ctx);
void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len);
void sha256_final(sha256_ctx *ctx, uint8_t hash[32]);
void sha256_hex(const void *data, size_t len, char out[65]);
void hmac_sha256(const uint8_t *key, size_t keyLen,
                 const uint8_t *data, size_t len,
                 uint8_t out[32]);

#ifdef __cplusplus
}
#endif

#endif
