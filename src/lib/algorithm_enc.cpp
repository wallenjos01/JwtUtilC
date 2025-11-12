/**
 * Josh Wallentine
 * Created 11/11/25
 * Modified 11/11/25
 *
 * Partial implementation of algorithm.hpp
 * See also algorithm.cpp, algorithm_b64url.cpp, algorithm_hmac.cpp, algorithm_sig.cpp
*/

#include "algorithm.hpp"
#include "util.hpp"

#include <jwt/key.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>


namespace {

int32_t encryptAndHmac(Span<uint8_t> input, Span<uint8_t> aad, Span<uint8_t> iv, 
                       Span<uint8_t> key, JwtCryptAlgorithm algorithm, 
                       Span<uint8_t> output, size_t* outputLength, size_t* contentLength) {

    const char* digestName;
    const EVP_CIPHER* cipher;
    size_t macLen;
    size_t keyLen;
    switch(algorithm) {
        case JWT_CRYPT_ALGORITHM_A128CBC_HS256: 
            digestName = "sha256";
            cipher = EVP_aes_128_cbc();
            keyLen = 16; 
            macLen = 32;
            break;
        case JWT_CRYPT_ALGORITHM_A192CBC_HS384: 
            digestName = "sha384";
            cipher = EVP_aes_192_cbc();
            keyLen = 24;
            macLen = 48;
            break;
        case JWT_CRYPT_ALGORITHM_A256CBC_HS512: 
            digestName = "sha512";
            cipher = EVP_aes_256_cbc();
            keyLen = 32;
            macLen = 64;
            break;
        default: 
            return -99;
    }

    if(contentLength) {
        *contentLength = input.length + AES_BLOCK_SIZE;
    }
    if(outputLength) {
        *outputLength = input.length + AES_BLOCK_SIZE + macLen;
    }
    if(output.data == nullptr) {
        return 0;
    }

    if(iv.length != 16) {
        return -2;
    }

    if(output.length < input.length + AES_BLOCK_SIZE + macLen) {
        return -5;
    }

    if(key.length != keyLen * 2) {
        return -1;
    }

    Span<uint8_t> macKey = {};
    macKey.length = keyLen;
    macKey.data = key.data;

    Span<uint8_t> encKey = {};
    encKey.length = keyLen;
    encKey.data = key.data + key.length - keyLen;

    EVP_CIPHER_CTX* cipherCtx = EVP_CIPHER_CTX_new();

    int32_t result = 0;
    int32_t encLen = 0;
    int32_t finalLen = 0;

    if(EVP_EncryptInit_ex(cipherCtx, cipher, nullptr, encKey.data, iv.data) <= 0) {
        ERR_print_errors_fp(stderr);
        result = -3;
        goto cleanup;
    }

    if(EVP_EncryptUpdate(cipherCtx, output.data, &encLen, input.data, input.length) <= 0) {
        ERR_print_errors_fp(stderr);
        result = -4;
        goto cleanup;
    }

    if(EVP_EncryptFinal(cipherCtx, output.data + encLen, &finalLen) <= 0) {
        ERR_print_errors_fp(stderr);
        result = -6;
        goto cleanup;
    }

    if(contentLength) {
        *contentLength = encLen + finalLen;
    }

    {
        EVP_MAC* mac = EVP_MAC_fetch(nullptr, "hmac", nullptr);
        EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
        if (ctx == nullptr) {
            return -7;
        }

        OSSL_PARAM params[2];
        params[0] = OSSL_PARAM_construct_utf8_string("digest", const_cast<char*>(digestName), 0);
        params[1] = OSSL_PARAM_construct_end();
        if (!EVP_MAC_init(ctx, macKey.data, macKey.length, params)) {
            ERR_print_errors_fp(stderr);
            EVP_MAC_CTX_free(ctx);
            EVP_MAC_free(mac);
            result = -8;
            goto cleanup;
        }

        uint64_t numBits = aad.length * 8;

        if(EVP_MAC_update(ctx, aad.data, aad.length) <= 0
            || EVP_MAC_update(ctx, iv.data, iv.length) <= 0
            || EVP_MAC_update(ctx, output.data, encLen + finalLen) <= 0
            || EVP_MAC_update(ctx, reinterpret_cast<uint8_t*>(&numBits), 8) <= 0
            || EVP_MAC_final(ctx, output.data + encLen + finalLen, &macLen, output.length) <= 0
        ) {
            ERR_print_errors_fp(stderr);
            EVP_MAC_CTX_free(ctx);
            EVP_MAC_free(mac);
            result = -9;
            goto cleanup;
        }
        

        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
    }

    if(outputLength) {
        *outputLength = encLen + finalLen + macLen;
    }

cleanup:
    EVP_CIPHER_CTX_free(cipherCtx);
    return result;
}

int32_t decryptAndHmac(Span<uint8_t> cipherText, Span<uint8_t> tag, Span<uint8_t> aad,
                         Span<uint8_t> iv, Span<uint8_t> key, JwtCryptAlgorithm algorithm,
                         Span<uint8_t> output, size_t* outputLength) {

    if(outputLength) {
        *outputLength = cipherText.length;
    }
    if(output.data == nullptr) {
        return 0;
    }

    const char* digestName;
    const EVP_CIPHER* cipher;
    size_t macLen;
    size_t keyLen;
    switch(algorithm) {
        case JWT_CRYPT_ALGORITHM_A128CBC_HS256: 
            digestName = "sha256";
            cipher = EVP_aes_128_cbc();
            keyLen = 16; 
            macLen = 32;
            break;
        case JWT_CRYPT_ALGORITHM_A192CBC_HS384: 
            digestName = "sha384";
            cipher = EVP_aes_192_cbc();
            keyLen = 24;
            macLen = 48;
            break;
        case JWT_CRYPT_ALGORITHM_A256CBC_HS512: 
            digestName = "sha512";
            cipher = EVP_aes_256_cbc();
            keyLen = 32;
            macLen = 64;
            break;
        default: 
            return -99;
    }

    if(iv.length != 16) {
        return -2;
    }

    if(key.length != keyLen * 2) {
        return -1;
    }
    if(tag.length != macLen) {
        return 1;
    }

    Span<uint8_t> macKey = {};
    macKey.length = keyLen;
    macKey.data = key.data;

    Span<uint8_t> encKey = {};
    encKey.length = keyLen;
    encKey.data = key.data + key.length - keyLen;

    EVP_CIPHER_CTX* cipherCtx = EVP_CIPHER_CTX_new();
    int32_t result = 0;
    int32_t decLen = 0;
    int32_t finalLen;

    if(EVP_DecryptInit_ex(cipherCtx, cipher, nullptr, encKey.data, iv.data) <= 0) {
        ERR_print_errors_fp(stderr);
        result = -3;
        goto cleanup;
    }
    
    if(EVP_DecryptUpdate(cipherCtx, output.data, &decLen, cipherText.data, cipherText.length) <= 0) {
        ERR_print_errors_fp(stderr);
        result = -4;
        goto cleanup;
    }

    if(EVP_DecryptFinal(cipherCtx, output.data + decLen, &finalLen) <= 0) {
        ERR_print_errors_fp(stderr);
        result = -6;
        goto cleanup;
    }

    if(outputLength) {
        *outputLength = decLen + finalLen;
    }

    {
        EVP_MAC* mac = EVP_MAC_fetch(nullptr, "hmac", nullptr);
        EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
        if (ctx == nullptr) {
            return -7;
        }

        OSSL_PARAM params[2];
        params[0] = OSSL_PARAM_construct_utf8_string("digest", const_cast<char*>(digestName), 0);
        params[1] = OSSL_PARAM_construct_end();
        if (!EVP_MAC_init(ctx, macKey.data, macKey.length, params)) {
            ERR_print_errors_fp(stderr);
            EVP_MAC_CTX_free(ctx);
            EVP_MAC_free(mac);
            result = -8;
            goto cleanup;
        }

        uint64_t numBits = aad.length * 8;

        uint8_t macBuffer[64];

        if(EVP_MAC_update(ctx, aad.data, aad.length) <= 0
            || EVP_MAC_update(ctx, iv.data, iv.length) <= 0
            || EVP_MAC_update(ctx, cipherText.data, cipherText.length) <= 0
            || EVP_MAC_update(ctx, reinterpret_cast<uint8_t*>(&numBits), 8) <= 0
            || EVP_MAC_final(ctx, macBuffer, &macLen, macLen) <= 0
        ) {
            ERR_print_errors_fp(stderr);
            EVP_MAC_CTX_free(ctx);
            EVP_MAC_free(mac);
            result = -9;
            goto cleanup;
        }

        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);

        if(memcmp(tag.data, macBuffer, macLen) != 0) {
            result = 1;
            goto cleanup;
        }

    }


cleanup:

    EVP_CIPHER_CTX_free(cipherCtx);
    return result;
}


int32_t encryptGCM(Span<uint8_t> input, Span<uint8_t> aad, Span<uint8_t> iv, 
                   Span<uint8_t> key, JwtCryptAlgorithm algorithm, 
                   Span<uint8_t> output, size_t* outputLength, size_t* contentLength) {

    if(contentLength) {
        *contentLength = input.length + AES_BLOCK_SIZE;
    }
    if(outputLength) {
        *outputLength = input.length + AES_BLOCK_SIZE + 16;
    }
    if(output.data == nullptr) {
        return 0;
    }

    const EVP_CIPHER* cipher;
    size_t keyLen;
    switch(algorithm) {
        case JWT_CRYPT_ALGORITHM_A128GCM: 
            cipher = EVP_aes_128_gcm();
            keyLen = 16; 
            break;
        case JWT_CRYPT_ALGORITHM_A192GCM: 
            cipher = EVP_aes_192_gcm();
            keyLen = 24;
            break;
        case JWT_CRYPT_ALGORITHM_A256GCM: 
            cipher = EVP_aes_256_gcm();
            keyLen = 32;
            break;
        default: 
            return -99;
    }

    if(key.length != keyLen) {
        return -1;
    }
    if(iv.length != 12) {
        return -2;
    }

    if(output.length < input.length + AES_BLOCK_SIZE + 16) {
        return -5;
    }

    EVP_CIPHER_CTX* cipherCtx = EVP_CIPHER_CTX_new();

    int32_t result = 0;
    int32_t encLen = 0;
    int32_t aadLen = 0;
    int32_t finalLen = 0;

    if(EVP_EncryptInit_ex(cipherCtx, cipher, nullptr, key.data, iv.data) <= 0) {
        ERR_print_errors_fp(stderr);
        result = -3;
        goto cleanup;
    }

    if(EVP_EncryptUpdate(cipherCtx, nullptr, &aadLen, aad.data, aad.length) <= 0) {
        ERR_print_errors_fp(stderr);
        result = -4;
        goto cleanup;
    }

    if(EVP_EncryptUpdate(cipherCtx, output.data, &encLen, input.data, input.length) <= 0) {
        ERR_print_errors_fp(stderr);
        result = -4;
        goto cleanup;
    }


    if(EVP_EncryptFinal(cipherCtx, output.data + encLen, &finalLen) <= 0) {
        ERR_print_errors_fp(stderr);
        result = -6;
        goto cleanup;
    }

    if(EVP_CIPHER_CTX_ctrl(cipherCtx, EVP_CTRL_GCM_GET_TAG, 16, output.data + encLen + finalLen) <= 0) {
        ERR_print_errors_fp(stderr);
        result = -7;
        goto cleanup;
    }

    if(contentLength) {
        *contentLength = encLen + finalLen;
    }
    if(outputLength) {
        *outputLength = encLen + finalLen + 16;
    }

cleanup:

    EVP_CIPHER_CTX_free(cipherCtx);
    return result;
}

int32_t decryptGCM(Span<uint8_t> cipherText, Span<uint8_t> tag, Span<uint8_t> aad,
                   Span<uint8_t> iv, Span<uint8_t> key, JwtCryptAlgorithm algorithm,
                   Span<uint8_t> output, size_t* outputLength) {

    if(outputLength) {
        *outputLength = cipherText.length;
    }
    if(output.data == nullptr) {
        return 0;
    }
    if(tag.length != 16) {
        return 1;
    }

    const EVP_CIPHER* cipher;
    size_t keyLen;
    switch(algorithm) {
        case JWT_CRYPT_ALGORITHM_A128GCM: 
            cipher = EVP_aes_128_gcm();
            keyLen = 16; 
            break;
        case JWT_CRYPT_ALGORITHM_A192GCM: 
            cipher = EVP_aes_192_gcm();
            keyLen = 24;
            break;
        case JWT_CRYPT_ALGORITHM_A256GCM: 
            cipher = EVP_aes_256_gcm();
            keyLen = 32;
            break;
        default: 
            return -99;
    }

    if(key.length != keyLen) {
        return -1;
    }
    if(iv.length != 12) {
        return -2;
    }

    if(output.length < cipherText.length) {
        return -5;
    }

    EVP_CIPHER_CTX* cipherCtx = EVP_CIPHER_CTX_new();

    int32_t result = 0;
    int32_t decLen = 0;
    int32_t aadLen = 0;
    int32_t finalLen = 0;

    if(EVP_DecryptInit_ex(cipherCtx, cipher, nullptr, key.data, iv.data) <= 0) {
        ERR_print_errors_fp(stderr);
        result = -3;
        goto cleanup;
    }

    if(EVP_DecryptUpdate(cipherCtx, nullptr, &aadLen, aad.data, aad.length) <= 0) {
        ERR_print_errors_fp(stderr);
        result = -4;
        goto cleanup;
    }

    if(EVP_DecryptUpdate(cipherCtx, output.data, &decLen, cipherText.data, cipherText.length) <= 0) {
        ERR_print_errors_fp(stderr);
        result = -4;
        goto cleanup;
    }

    if(EVP_CIPHER_CTX_ctrl(cipherCtx, EVP_CTRL_GCM_SET_TAG, 16, tag.data) <= 0) {
        ERR_print_errors_fp(stderr);
        result = -7;
        goto cleanup;
    }

    if(EVP_DecryptFinal(cipherCtx, output.data + decLen, &finalLen) <= 0) {
        ERR_print_errors_fp(stderr);
        result = -6;
        goto cleanup;
    }

    if(outputLength) {
        *outputLength = decLen + finalLen;
    }

cleanup:

    EVP_CIPHER_CTX_free(cipherCtx);
    return result;
}

} // namespace

int32_t jwt::enc::encryptAndProtect(Span<uint8_t> input, Span<uint8_t> aad, Span<uint8_t> iv, 
                       Span<uint8_t> key, JwtCryptAlgorithm algorithm, 
                       Span<uint8_t> output, size_t* outputLength, size_t* contentLength) {

    if(algorithm == JWT_CRYPT_ALGORITHM_A128CBC_HS256 
    || algorithm == JWT_CRYPT_ALGORITHM_A192CBC_HS384 
    || algorithm == JWT_CRYPT_ALGORITHM_A256CBC_HS512) {

        return encryptAndHmac(input, aad, iv, key, algorithm, output, outputLength, contentLength);

    } else {
        return encryptGCM(input, aad, iv, key, algorithm, output, outputLength, contentLength);
    }
}

int32_t jwt::enc::decryptAndVerify(Span<uint8_t> cipherText, Span<uint8_t> tag, Span<uint8_t> aad,
                         Span<uint8_t> iv, Span<uint8_t> key, JwtCryptAlgorithm algorithm,
                         Span<uint8_t> output, size_t* outputLength) {

    if(algorithm == JWT_CRYPT_ALGORITHM_A128CBC_HS256 
    || algorithm == JWT_CRYPT_ALGORITHM_A192CBC_HS384 
    || algorithm == JWT_CRYPT_ALGORITHM_A256CBC_HS512) {

        return decryptAndHmac(cipherText, tag, aad, iv, key, algorithm, output, outputLength);

    } else {
        return decryptGCM(cipherText, tag, aad, iv, key, algorithm, output, outputLength);
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


