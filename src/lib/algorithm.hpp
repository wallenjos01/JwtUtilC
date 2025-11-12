#pragma oncealgorith

#include <jwt/core.h>
#include <jwt/key.h>

#include <cstdint>
#include <cstdlib>

#include "jwt/stream.h"
#include "util.hpp"

namespace jwt {


const char* getAlgorithmName(JwtAlgorithm alg);
const char* getDigestForAlgorithm(JwtAlgorithm alg);


namespace hmac {

int32_t generate(Span<uint8_t> input, JwtKey* key, JwtAlgorithm algorithm,
                     Span<uint8_t> output, size_t* macLength);

int32_t validate(Span<uint8_t> input, Span<uint8_t> mac, JwtKey* key, 
                     JwtAlgorithm algorithm);
}

namespace sig {


int32_t generate(Span<uint8_t> input, JwtKey* key,
                          JwtAlgorithm algorithm, Span<uint8_t> output,
                          size_t* sigLength);

int32_t validate(Span<uint8_t> input, Span<uint8_t> signature, 
                          JwtKey* key, JwtAlgorithm algorithm);

}

namespace enc {

const char* getCryptAlgorithmName(JwtCryptAlgorithm alg);

size_t getIvLength(JwtCryptAlgorithm algorithm);
size_t getKeyLength(JwtCryptAlgorithm algorithm);

int32_t encryptAndProtect(Span<uint8_t> input, Span<uint8_t> aad, Span<uint8_t> iv, 
                       Span<uint8_t> key, JwtCryptAlgorithm algorithm, 
                       Span<uint8_t> output, size_t* outputLength, size_t* contentLength);

int32_t decryptAndVerify(Span<uint8_t> cipherText, Span<uint8_t> tag, Span<uint8_t> aad,
                         Span<uint8_t> iv, Span<uint8_t> key, JwtCryptAlgorithm algorithm,
                         Span<uint8_t> output, size_t* outputLength);
}

namespace b64url {

int32_t encode(const void* data, size_t dataLength, JwtWriter writer);

int32_t decode(const void* encoded, size_t encodedLength, JwtWriter writer);

size_t getEncodedLength(size_t dataLength);

size_t getDataLength(size_t encodedLength);

int32_t decodeNew(const void* encoded, size_t encodedLength, Span<uint8_t>* output);

} // namespace b64url

} // namespace jwt
