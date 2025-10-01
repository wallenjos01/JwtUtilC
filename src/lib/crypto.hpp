#pragma once

#include <cstdint>
#include <cstdlib>

namespace jwt {

namespace b64url {

size_t getEncodedLength(size_t dataLength);

size_t getDecodedLength(size_t encodedLength);

int32_t decode(const char* encoded, size_t encodedLength, char* outputBuffer,
               size_t outputBufferLength);

int32_t encode(const char* data, size_t dataLength, char* outputBuffer,
               size_t outputBufferLength);

} // namespace b64url

} // namespace jwt
