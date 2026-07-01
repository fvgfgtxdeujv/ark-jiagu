#include "ArkCrypto.h"

#include <cstring>
#include <vector>

uint32_t leftRotate(uint32_t value, uint32_t bits) {
    return (value << bits) | (value >> (32 - bits));
}

void sha1Bytes(const unsigned char *data, size_t len, unsigned char out[20]) {
    uint32_t h0 = 0x67452301;
    uint32_t h1 = 0xEFCDAB89;
    uint32_t h2 = 0x98BADCFE;
    uint32_t h3 = 0x10325476;
    uint32_t h4 = 0xC3D2E1F0;

    uint64_t bitLen = static_cast<uint64_t>(len) * 8;

    size_t newLen = len + 1;
    while ((newLen % 64) != 56) {
        newLen++;
    }

    std::vector<unsigned char> msg(newLen + 8);
    memcpy(msg.data(), data, len);
    msg[len] = 0x80;

    for (int i = 0; i < 8; i++) {
        msg[newLen + i] = static_cast<unsigned char>((bitLen >> ((7 - i) * 8)) & 0xff);
    }

    for (size_t offset = 0; offset < msg.size(); offset += 64) {
        uint32_t w[80];

        for (int i = 0; i < 16; i++) {
            size_t j = offset + i * 4;
            w[i] = (static_cast<uint32_t>(msg[j]) << 24)
                   | (static_cast<uint32_t>(msg[j + 1]) << 16)
                   | (static_cast<uint32_t>(msg[j + 2]) << 8)
                   | static_cast<uint32_t>(msg[j + 3]);
        }

        for (int i = 16; i < 80; i++) {
            w[i] = leftRotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        }

        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;
        uint32_t e = h4;

        for (int i = 0; i < 80; i++) {
            uint32_t f;
            uint32_t k;

            if (i < 20) {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999;
            } else if (i < 40) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            } else if (i < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            } else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }

            uint32_t temp = leftRotate(a, 5) + f + e + k + w[i];
            e = d;
            d = c;
            c = leftRotate(b, 30);
            b = a;
            a = temp;
        }

        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
    }

    uint32_t h[5] = {h0, h1, h2, h3, h4};

    for (int i = 0; i < 5; i++) {
        out[i * 4] = static_cast<unsigned char>((h[i] >> 24) & 0xff);
        out[i * 4 + 1] = static_cast<unsigned char>((h[i] >> 16) & 0xff);
        out[i * 4 + 2] = static_cast<unsigned char>((h[i] >> 8) & 0xff);
        out[i * 4 + 3] = static_cast<unsigned char>(h[i] & 0xff);
    }
}

uint32_t adler32Bytes(const unsigned char *data, size_t len) {
    const uint32_t MOD_ADLER = 65521;

    uint32_t a = 1;
    uint32_t b = 0;

    for (size_t i = 0; i < len; i++) {
        a = (a + data[i]) % MOD_ADLER;
        b = (b + a) % MOD_ADLER;
    }

    return (b << 16) | a;
}
