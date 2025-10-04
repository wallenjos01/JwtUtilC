#pragma once

#include <jwt/core.h>
#include <jwt/key.h>

#include <cstdint>
#include <cstdlib>

#include <openssl/evp.h>

#include "util.hpp"

namespace jwt {

int32_t parseAlgorithm(JwtAlgorithm* alg, JwtString str);

int32_t generateHmac(Span<uint8_t> input, JwtKey key, JwtAlgorithm algorithm,
                     Span<uint8_t> output, size_t* macLength);

int32_t generateSignature(Span<uint8_t> input, JwtKey key,
                          JwtAlgorithm algorithm, Span<uint8_t> output,
                          size_t* sigLength);

namespace b64url {

size_t getEncodedLength(size_t dataLength);

size_t getDataLength(size_t encodedLength);

int32_t decode(const char* encoded, size_t encodedLength, uint8_t* outputBuffer,
               size_t outputBufferLength);

inline int32_t decodeNew(const char* encoded, size_t encodedLength,
                         uint8_t** outputBuffer, size_t* outputBufferLength) {

    *outputBufferLength = getDataLength(encodedLength);
    *outputBuffer = new uint8_t[*outputBufferLength];

    return decode(encoded, encodedLength, *outputBuffer, *outputBufferLength);
}

inline int32_t decodeNew(const char* encoded, size_t encodedLength,
                         Span<uint8_t>* outputBuffer) {
    outputBuffer->owned = true;
    return decodeNew(encoded, encodedLength, &outputBuffer->data,
                     &outputBuffer->length);
}

int32_t encode(const uint8_t* data, size_t dataLength, char* outputBuffer,
               size_t outputBufferLength);

} // namespace b64url

} // namespace jwt
