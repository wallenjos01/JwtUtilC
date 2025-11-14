#pragma oncealgorith

#include <jwt/core.h>
#include <jwt/key.h>
#include <jwt/result.h>
#include <jwt/stream.h>

#include <cstdint>
#include <cstdlib>

#include "util.hpp"

namespace jwt {


const char* getAlgorithmName(JwtAlgorithm alg);
const char* getDigestForAlgorithm(JwtAlgorithm alg);


namespace hmac {

JwtResult generate(Span<uint8_t> input, JwtKey* key, JwtAlgorithm algorithm,
                     Span<uint8_t> output, size_t* macLength);

JwtResult validate(Span<uint8_t> input, Span<uint8_t> mac, JwtKey* key, 
                     JwtAlgorithm algorithm);
}

namespace sig {


JwtResult generate(Span<uint8_t> input, JwtKey* key,
                          JwtAlgorithm algorithm, Span<uint8_t> output,
                          size_t* sigLength);

JwtResult validate(Span<uint8_t> input, Span<uint8_t> signature, 
                          JwtKey* key, JwtAlgorithm algorithm);

}

namespace enc {

const char* getCryptAlgorithmName(JwtCryptAlgorithm alg);

size_t getIvLength(JwtCryptAlgorithm algorithm);
size_t getKeyLength(JwtCryptAlgorithm algorithm);

JwtResult generateCek(JwtJsonObject* header, JwtKey* key, JwtAlgorithm algorithm, 
                      JwtCryptAlgorithm crypt, Span<uint8_t>* cek, Span<uint8_t>* encryptedKey);

JwtResult deriveCek(JwtJsonObject* header, Span<uint8_t> encryptedKey, JwtKey* key, 
                    JwtAlgorithm algorithm, JwtCryptAlgorithm crypt, Span<uint8_t>* output);

JwtResult encryptAndProtect(Span<uint8_t> input, Span<uint8_t> aad, Span<uint8_t> iv, 
                       Span<uint8_t> key, JwtCryptAlgorithm algorithm, 
                       Span<uint8_t>* output, Span<uint8_t>* tag);

JwtResult decryptAndVerify(Span<uint8_t> cipherText, Span<uint8_t> tag, Span<uint8_t> aad,
                         Span<uint8_t> iv, Span<uint8_t> key, JwtCryptAlgorithm algorithm,
                         Span<uint8_t>* output);
}

namespace b64url {

JwtResult encode(const void* data, size_t dataLength, JwtWriter writer);

JwtResult decode(const void* encoded, size_t encodedLength, JwtWriter writer);

size_t getEncodedLength(size_t dataLength);

size_t getDataLength(size_t encodedLength);

JwtResult encodeString(const void* data, size_t dataLength, JwtString* string);

JwtResult decodeNew(const void* encoded, size_t encodedLength, Span<uint8_t>* output);

} // namespace b64url

} // namespace jwt
