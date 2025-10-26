#pragma once

#include <jwt/core.h>
#include <jwt/key.h>

#include <cstdint>
#include <cstdlib>

#include "jwt/stream.h"
#include "util.hpp"

namespace jwt {

int32_t parseAlgorithm(JwtAlgorithm* alg, JwtString str);

int32_t generateHmac(Span<uint8_t> input, JwtKey key, JwtAlgorithm algorithm,
                     Span<uint8_t> output, size_t* macLength);

int32_t generateSignature(Span<uint8_t> input, JwtKey key,
                          JwtAlgorithm algorithm, Span<uint8_t> output,
                          size_t* sigLength);

namespace b64url {

int32_t encode(const void* data, size_t dataLength, JwtWriter writer);

int32_t decode(const void* encoded, size_t encodedLength, JwtWriter writer);

size_t getEncodedLength(size_t dataLength);

size_t getDataLength(size_t encodedLength);

int32_t decodeNew(const void* encoded, size_t encodedLength, Span<uint8_t>* output);

} // namespace b64url

} // namespace jwt
