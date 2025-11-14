/**
 * Josh Wallentine
 * Created 11/13/25
 * Modified 11/13/25
 *
 * Partial implementation of algorithm.hpp
 * See also algorithm.cpp, algorithm_b64url.cpp, algorithm_cek.cpp
 */

#include "util.hpp"
#include "crypt.hpp"
#include "algorithm.hpp"

#include <cstring>

#include <jwt/key.h>
#include <jwt/result.h>

#include <openssl/evp.h>
#include <openssl/aes.h>

namespace {

const char* getDigestName(JwtCryptAlgorithm algorithm) {

    switch(algorithm) {
        case JWT_CRYPT_ALGORITHM_A128CBC_HS256: 
            return "sha256";
        case JWT_CRYPT_ALGORITHM_A192CBC_HS384: 
            return "sha384";
        case JWT_CRYPT_ALGORITHM_A256CBC_HS512: 
            return "sha512";
        default: 
            return "";
    }

}

}

size_t jwt::enc::getIvLength(JwtCryptAlgorithm algorithm) {
    switch (algorithm) {
        case JWT_CRYPT_ALGORITHM_A128CBC_HS256:
        case JWT_CRYPT_ALGORITHM_A192CBC_HS384:
        case JWT_CRYPT_ALGORITHM_A256CBC_HS512:
            return 16;
        case JWT_CRYPT_ALGORITHM_A128GCM:
        case JWT_CRYPT_ALGORITHM_A192GCM:
        case JWT_CRYPT_ALGORITHM_A256GCM:
            return 12;
        default:
            return 0;
    }
}

size_t jwt::enc::getKeyLength(JwtCryptAlgorithm algorithm) {

    switch (algorithm) {
        case JWT_CRYPT_ALGORITHM_A128CBC_HS256:
            return 32;
        case JWT_CRYPT_ALGORITHM_A192CBC_HS384:
            return 48;
        case JWT_CRYPT_ALGORITHM_A256CBC_HS512:
            return 64;
        case JWT_CRYPT_ALGORITHM_A128GCM:
            return 16;
        case JWT_CRYPT_ALGORITHM_A192GCM:
            return 24;
        case JWT_CRYPT_ALGORITHM_A256GCM:
            return 32;
        default:
            return 0;
    }
}

JwtResult jwt::enc::encryptAndProtect(Span<uint8_t> input, Span<uint8_t> aad, Span<uint8_t> iv, 
                       Span<uint8_t> key, JwtCryptAlgorithm algorithm, 
                       Span<uint8_t>* output, Span<uint8_t>* tag) {

    crypt::AesContext ctx = {};
    JWT_CHECK(jwt::crypt::getContextForCryptAlgorithm(algorithm, &ctx));

    switch(algorithm) {

        case JWT_CRYPT_ALGORITHM_A128CBC_HS256:
        case JWT_CRYPT_ALGORITHM_A192CBC_HS384:
        case JWT_CRYPT_ALGORITHM_A256CBC_HS512: {

        const char* digestName;
            const EVP_CIPHER* cipher;
            size_t macLen;
            size_t keyLen;
            Span<uint8_t> cryptKey = key;
            cryptKey.length = key.length / 2;

            Span<uint8_t> macKey = key;
            macKey.data = cryptKey.data + key.length - cryptKey.length;
            macKey.length = key.length - cryptKey.length;

            JWT_CHECK(ctx.cipher(input, cryptKey, iv, output, crypt::CipherMode::ENCRYPT));

            crypt::HmacContext mac = {};
            JWT_CHECK(crypt::HmacContext::init(&mac, macKey, getDigestName(algorithm)));

            uint64_t numBits = aad.length * 8;
            JWT_CHECK(mac.update(aad));
            JWT_CHECK(mac.update(iv));
            JWT_CHECK(mac.update(*output));
            JWT_CHECK(mac.update(Span<uint8_t>::wrap(reinterpret_cast<uint8_t*>(&numBits), 8)));
            
            JWT_CHECK(mac.final(tag));
            return JWT_RESULT_SUCCESS;
        }

        case JWT_CRYPT_ALGORITHM_A128GCM:
        case JWT_CRYPT_ALGORITHM_A192GCM:
        case JWT_CRYPT_ALGORITHM_A256GCM: {
        
            return ctx.cipherGcm(input, aad, key, iv, output, tag, crypt::CipherMode::ENCRYPT);
        }

        default:
            return JWT_RESULT_INVALID_ALGORITHM;
    }

}

JwtResult jwt::enc::decryptAndVerify(Span<uint8_t> cipherText, Span<uint8_t> tag, Span<uint8_t> aad,
                         Span<uint8_t> iv, Span<uint8_t> key, JwtCryptAlgorithm algorithm,
                         Span<uint8_t>* output) {

    crypt::AesContext ctx = {};
    JWT_CHECK(jwt::crypt::getContextForCryptAlgorithm(algorithm, &ctx));

    switch(algorithm) {

        case JWT_CRYPT_ALGORITHM_A128CBC_HS256:
        case JWT_CRYPT_ALGORITHM_A192CBC_HS384:
        case JWT_CRYPT_ALGORITHM_A256CBC_HS512: {

        const char* digestName;
            const EVP_CIPHER* cipher;
            size_t macLen;
            size_t keyLen;
            Span<uint8_t> cryptKey = key;
            cryptKey.length = key.length / 2;

            Span<uint8_t> macKey = key;
            macKey.data = cryptKey.data + key.length - cryptKey.length;
            macKey.length = key.length - cryptKey.length;

            JWT_CHECK(ctx.cipher(cipherText, cryptKey, iv, output, crypt::CipherMode::DECRYPT));

            crypt::HmacContext mac = {};
            JWT_CHECK(crypt::HmacContext::init(&mac, macKey, getDigestName(algorithm)));

            uint64_t numBits = aad.length * 8;
            JWT_CHECK(mac.update(aad));
            JWT_CHECK(mac.update(iv));
            JWT_CHECK(mac.update(cipherText));
            JWT_CHECK(mac.update(Span<uint8_t>::wrap(reinterpret_cast<uint8_t*>(&numBits), 8)));
            
            Span<uint8_t> outTag = {};
            JWT_CHECK(mac.final(&outTag));

            if(outTag.length != tag.length || memcmp(outTag.data, tag.data, tag.length) != 0) {
                return JWT_RESULT_VERIFICATION_FAILED;
            }

            return JWT_RESULT_SUCCESS;
        }

        case JWT_CRYPT_ALGORITHM_A128GCM:
        case JWT_CRYPT_ALGORITHM_A192GCM:
        case JWT_CRYPT_ALGORITHM_A256GCM: {
        
            return ctx.cipherGcm(cipherText, aad, key, iv, output, &tag, crypt::CipherMode::DECRYPT);
        }

        default:
            return JWT_RESULT_INVALID_ALGORITHM;
    }


}

