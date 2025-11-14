/**
 * Josh Wallentine
 * Created 11/11/25
 * Modified 11/12/25
 *
 * Partial implementation of algorithm.hpp
 * See also algorithm.cpp, algorithm_b64url.cpp, algorithm_sig.cpp, algorithm_crypt.cpp, algorithm_cek.cpp
*/

#include "algorithm.hpp"
#include "jwt/result.h"
#include "util.hpp"

#include <jwt/key.h>
#include <openssl/err.h>
#include <openssl/evp.h>


JwtResult jwt::hmac::generate(Span<uint8_t> input, JwtKey* key,
                          JwtAlgorithm algorithm, Span<uint8_t> output,
                          size_t* macLength) {

    if (key->type != JWT_KEY_TYPE_OCTET_SEQUENCE) {
        return JWT_RESULT_INVALID_KEY_TYPE;
    }

    const char* digestName = getDigestForAlgorithm(algorithm);
    if (digestName == nullptr) {
        return JWT_RESULT_INVALID_ALGORITHM;
    }

    EVP_MAC* mac = EVP_MAC_fetch(nullptr, "hmac", nullptr);
    EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
    if (ctx == nullptr) {
        JWT_REPORT_ERROR("EVP_MAC_CTX_new() failed");
        ERR_print_errors_fp(stderr);
        return JWT_RESULT_UNEXPECTED_ERROR;
    }

    Span<uint8_t>* keyData = static_cast<Span<uint8_t>*>(key->keyData);

    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(
        "digest", const_cast<char*>(digestName), 0);
    params[1] = OSSL_PARAM_construct_end();
    if (!EVP_MAC_init(ctx, keyData->data, keyData->length, params)) {
        JWT_REPORT_ERROR("EVP_MAC_init() failed");
        ERR_print_errors_fp(stderr);
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return JWT_RESULT_UNEXPECTED_ERROR;
    }

    EVP_MAC_update(ctx, input.data, input.length);
    size_t outputSize = 0;
    EVP_MAC_final(ctx, nullptr, &outputSize, 0);

    if (macLength)
        *macLength = outputSize;

    if (output.data == nullptr) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return JWT_RESULT_SUCCESS;
    }

    if (outputSize > output.length) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return JWT_RESULT_SHORT_BUFFER;
    }

    EVP_MAC_final(ctx, output.data, &outputSize, output.length);

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);

    return JWT_RESULT_SUCCESS;
}


JwtResult jwt::hmac::validate(Span<uint8_t> input, Span<uint8_t> mac, JwtKey* key, 
                     JwtAlgorithm algorithm) {

    Span<uint8_t> newMac(new uint8_t[mac.length], mac.length);

    size_t macLength = 0;
    JWT_CHECK(generate(input, key, algorithm, newMac, &macLength));
    if(macLength == mac.length && memcmp(newMac.data, mac.data, mac.length) == 0) {
        return JWT_RESULT_SUCCESS;
    }

    return JWT_RESULT_VERIFICATION_FAILED;
}
