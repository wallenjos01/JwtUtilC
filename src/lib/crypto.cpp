#include "crypto.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>

namespace {

constexpr char B64URL_LOOKUP[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

constexpr char B64URL_REVERSE_LOOKUP[256] = {
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  62, 0,  0,  52, 53, 54, 55, 56, 57, 58, 59, 60,
    61, 0,  0,  0,  0,  0,  0,  0,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10,
    11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 0,  0,  0,  0,
    63, 0,  26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
    43, 44, 45, 46, 47, 48, 49, 50, 51, 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,
};

} // namespace

size_t jwt::b64url::getEncodedLength(size_t dataLength) {
    size_t chunks = dataLength / 3;
    size_t rem = dataLength % 3;
    return (4 * chunks) + ((rem > 0) * (rem + 1));
}

size_t jwt::b64url::getDecodedLength(size_t encodedLength) {
    size_t chunks = encodedLength / 4;
    size_t rem = encodedLength % 4;
    return (chunks * 3) + rem;
}

int32_t jwt::b64url::decode(const char* encoded, size_t encodedLength,
                            char* outputBuffer, size_t outputBufferLength) {

    if (outputBufferLength < getDecodedLength(encodedLength)) {
        return -1;
    }

    size_t outputPos = 0;
    for (size_t i = 0; i < encodedLength;) {

        char chunk[4] = {encoded[i++], i < encodedLength ? encoded[i++] : '=',
                         i < encodedLength ? encoded[i++] : '=',
                         i < encodedLength ? encoded[i++] : '='};

        uint8_t indices[4];
        for (auto i = 0; i < 4; i++) {
            char c = chunk[i];
            indices[i] = B64URL_REVERSE_LOOKUP[c];
        }

        uint32_t joined = (indices[0] << 18) | (indices[1] << 12) |
                          (indices[2] << 6) | (indices[3]);

        outputBuffer[outputPos++] = (joined >> 16) & 0xFF;
        outputBuffer[outputPos++] = (joined >> 8) & 0xFF;
        outputBuffer[outputPos++] = joined & 0xFF;
    }

    return 0;
}

int32_t jwt::b64url::encode(const char* data, size_t dataLength,
                            char* outputBuffer, size_t outputBufferLength) {

    if (outputBufferLength < getEncodedLength(dataLength)) {
        return -1;
    }

    size_t outputPos = 0;
    for (size_t i = 0; i < dataLength;) {

        uint8_t b1 = data[i++];
        uint8_t b2 = i < dataLength ? data[i++] : 0;
        uint8_t b3 = i < dataLength ? data[i++] : 0;

        uint32_t joined = (b1 << 16) | (b2 << 8) | b3;

        outputBuffer[outputPos++] = B64URL_LOOKUP[(joined >> 18) & 0b111111];
        outputBuffer[outputPos++] = B64URL_LOOKUP[(joined >> 12) & 0b111111];
        outputBuffer[outputPos++] = B64URL_LOOKUP[(joined >> 6) & 0b111111];
        outputBuffer[outputPos++] = B64URL_LOOKUP[joined & 0b111111];
    }

    return 0;
}
