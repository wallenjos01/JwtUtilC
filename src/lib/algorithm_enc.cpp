/**
 * Josh Wallentine
 * Created 11/11/25
 * Modified 11/12/25
 *
 * Partial implementation of algorithm.hpp
 * See also algorithm.cpp, algorithm_b64url.cpp, algorithm_hmac.cpp, algorithm_sig.cpp
*/

#include "algorithm.hpp"
#include "util.hpp"

#include <cstdio>
#include <jwt/key.h>
#include <jwt/result.h>

#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/param_build.h>


namespace {


JwtResult encryptCekRsa(Span<uint8_t> cek, JwtKey* key, JwtAlgorithm algorithm, Span<uint8_t> output, size_t* outputLength) {

    if(key->type != JWT_KEY_TYPE_RSA) {
        return JWT_RESULT_INVALID_KEY_TYPE;
    }

    JwtResult result = JWT_RESULT_SUCCESS;
    EVP_PKEY* pkey = *static_cast<EVP_PKEY**>(key->keyData);
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, pkey, nullptr);
    if(ctx == nullptr) {
        ERR_print_errors_fp(stderr);
        return JWT_RESULT_UNEXPECTED_ERROR;
    }

    OSSL_PARAM_BLD* builder = OSSL_PARAM_BLD_new();
    OSSL_PARAM* params = nullptr;
    size_t cryptLength;

    switch(algorithm) {
        case JWT_ALGORITHM_RSA1_5:
            OSSL_PARAM_BLD_push_utf8_string(builder, OSSL_ASYM_CIPHER_PARAM_PAD_MODE, OSSL_PKEY_RSA_PAD_MODE_PKCSV15, 0);
            break;
        case JWT_ALGORITHM_RSA_OAEP:
            OSSL_PARAM_BLD_push_utf8_string(builder, OSSL_ASYM_CIPHER_PARAM_PAD_MODE, OSSL_PKEY_RSA_PAD_MODE_OAEP, 0);
            break;
        case JWT_ALGORITHM_RSA_OAEP_256:
            OSSL_PARAM_BLD_push_utf8_string(builder, OSSL_ASYM_CIPHER_PARAM_PAD_MODE, OSSL_PKEY_RSA_PAD_MODE_OAEP, 0);
            OSSL_PARAM_BLD_push_utf8_string(builder, OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, "sha256", 0);
            OSSL_PARAM_BLD_push_utf8_string(builder, OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, "sha256", 0);
            break;
        default:
            result = JWT_RESULT_INVALID_ALGORITHM;
            goto cleanup;
    }

    params = OSSL_PARAM_BLD_to_param(builder);

    if(EVP_PKEY_encrypt_init_ex(ctx, params) <= 0) {
        ERR_print_errors_fp(stderr);
        result = JWT_RESULT_UNEXPECTED_ERROR;
        goto cleanup;
    }

    if(EVP_PKEY_encrypt(ctx, nullptr, &cryptLength, cek.data, cek.length) <= 0) {
        ERR_print_errors_fp(stderr);
        result = JWT_RESULT_UNEXPECTED_ERROR;
        goto cleanup;
    }

    if(outputLength) {
        *outputLength = cryptLength;
    }
    if(output.data == nullptr) {
        goto cleanup;
    }

    if(EVP_PKEY_encrypt(ctx, output.data, &cryptLength, cek.data, cek.length) <= 0) {
        ERR_print_errors_fp(stderr);
        result = JWT_RESULT_UNEXPECTED_ERROR;
        goto cleanup;
    }

cleanup:

    EVP_PKEY_CTX_free(ctx);
    return result;
}


JwtResult encryptAndHmac(Span<uint8_t> input, Span<uint8_t> aad, Span<uint8_t> iv, 
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
            return JWT_RESULT_INVALID_ALGORITHM;
    }

    if(contentLength) {
        *contentLength = input.length + AES_BLOCK_SIZE;
    }
    if(outputLength) {
        *outputLength = input.length + AES_BLOCK_SIZE + macLen;
    }
    if(output.data == nullptr) {
        return JWT_RESULT_SUCCESS;
    }

    if(iv.length != 16) {
        return JWT_RESULT_INVALID_IV_LENGTH;
    }

    if(output.length < input.length + AES_BLOCK_SIZE + macLen) {
        return JWT_RESULT_SHORT_BUFFER;
    }

    if(key.length != keyLen * 2) {
        return JWT_RESULT_INVALID_CEK_LENGTH;
    }

    Span<uint8_t> macKey = {};
    macKey.length = keyLen;
    macKey.data = key.data;

    Span<uint8_t> encKey = {};
    encKey.length = keyLen;
    encKey.data = key.data + key.length - keyLen;

    EVP_CIPHER_CTX* cipherCtx = EVP_CIPHER_CTX_new();

    JwtResult result = JWT_RESULT_SUCCESS;
    int32_t encLen = 0;
    int32_t finalLen = 0;

    if(EVP_EncryptInit_ex(cipherCtx, cipher, nullptr, encKey.data, iv.data) <= 0) {
        JWT_REPORT_ERROR("EVP_EncryptInit_ex() failed");
        ERR_print_errors_fp(stderr);
        result = JWT_RESULT_UNEXPECTED_ERROR;
        goto cleanup;
    }

    if(EVP_EncryptUpdate(cipherCtx, output.data, &encLen, input.data, input.length) <= 0) {
        JWT_REPORT_ERROR("EVP_EncryptUpdate() failed");
        ERR_print_errors_fp(stderr);
        result = JWT_RESULT_UNEXPECTED_ERROR;
        goto cleanup;
    }

    if(EVP_EncryptFinal(cipherCtx, output.data + encLen, &finalLen) <= 0) {
        JWT_REPORT_ERROR("EVP_EncryptFinal() failed");
        ERR_print_errors_fp(stderr);
        result = JWT_RESULT_UNEXPECTED_ERROR;
        goto cleanup;
    }

    if(contentLength) {
        *contentLength = encLen + finalLen;
    }

    {
        EVP_MAC* mac = EVP_MAC_fetch(nullptr, "hmac", nullptr);
        EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
        if (ctx == nullptr) {
            JWT_REPORT_ERROR("EVP_MAC_CTX_new() failed");
            ERR_print_errors_fp(stderr);
            EVP_MAC_free(mac);
            result = JWT_RESULT_UNEXPECTED_ERROR;
            goto cleanup;
        }

        OSSL_PARAM params[2];
        params[0] = OSSL_PARAM_construct_utf8_string("digest", const_cast<char*>(digestName), 0);
        params[1] = OSSL_PARAM_construct_end();
        if (!EVP_MAC_init(ctx, macKey.data, macKey.length, params)) {
            JWT_REPORT_ERROR("EVP_MAC_init() failed");
            ERR_print_errors_fp(stderr);
            EVP_MAC_CTX_free(ctx);
            EVP_MAC_free(mac);
            result = JWT_RESULT_UNEXPECTED_ERROR;
            goto cleanup;
        }

        uint64_t numBits = aad.length * 8;

        if(EVP_MAC_update(ctx, aad.data, aad.length) <= 0
            || EVP_MAC_update(ctx, iv.data, iv.length) <= 0
            || EVP_MAC_update(ctx, output.data, encLen + finalLen) <= 0
            || EVP_MAC_update(ctx, reinterpret_cast<uint8_t*>(&numBits), 8) <= 0
            || EVP_MAC_final(ctx, output.data + encLen + finalLen, &macLen, output.length) <= 0
        ) {
            JWT_REPORT_ERROR("EVP_MAC_update() failed");
            ERR_print_errors_fp(stderr);
            EVP_MAC_CTX_free(ctx);
            EVP_MAC_free(mac);
            result = JWT_RESULT_UNEXPECTED_ERROR;
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

JwtResult decryptAndHmac(Span<uint8_t> cipherText, Span<uint8_t> tag, Span<uint8_t> aad,
                         Span<uint8_t> iv, Span<uint8_t> key, JwtCryptAlgorithm algorithm,
                         Span<uint8_t> output, size_t* outputLength) {

    if(outputLength) {
        *outputLength = cipherText.length;
    }
    if(output.data == nullptr) {
        return JWT_RESULT_SUCCESS;
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
            return JWT_RESULT_INVALID_ALGORITHM;
    }

    if(iv.length != 16) {
        return JWT_RESULT_INVALID_IV_LENGTH;
    }

    if(key.length != keyLen * 2) {
        return JWT_RESULT_INVALID_CEK_LENGTH;
    }
    if(tag.length != macLen) {
        return JWT_RESULT_VERIFICATION_FAILED;
    }

    Span<uint8_t> macKey = {};
    macKey.length = keyLen;
    macKey.data = key.data;

    Span<uint8_t> encKey = {};
    encKey.length = keyLen;
    encKey.data = key.data + key.length - keyLen;

    EVP_CIPHER_CTX* cipherCtx = EVP_CIPHER_CTX_new();
    JwtResult result = JWT_RESULT_SUCCESS;
    int32_t decLen = 0;
    int32_t finalLen;

    if(EVP_DecryptInit_ex(cipherCtx, cipher, nullptr, encKey.data, iv.data) <= 0) {
        JWT_REPORT_ERROR("EVP_DecryptInit_ex() failed");
        ERR_print_errors_fp(stderr);
        result = JWT_RESULT_UNEXPECTED_ERROR;
        goto cleanup;
    }
    
    if(EVP_DecryptUpdate(cipherCtx, output.data, &decLen, cipherText.data, cipherText.length) <= 0) {
        JWT_REPORT_ERROR("EVP_DecryptUpdate() failed");
        ERR_print_errors_fp(stderr);
        result = JWT_RESULT_UNEXPECTED_ERROR;
        goto cleanup;
    }

    if(EVP_DecryptFinal(cipherCtx, output.data + decLen, &finalLen) <= 0) {
        JWT_REPORT_ERROR("EVP_DecryptFinal() failed");
        ERR_print_errors_fp(stderr);
        result = JWT_RESULT_UNEXPECTED_ERROR;
        goto cleanup;
    }

    if(outputLength) {
        *outputLength = decLen + finalLen;
    }

    {
        EVP_MAC* mac = EVP_MAC_fetch(nullptr, "hmac", nullptr);
        EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
        if (ctx == nullptr) {
            JWT_REPORT_ERROR("EVP_MAC_CTX_new() failed");
            ERR_print_errors_fp(stderr);
            EVP_MAC_free(mac);
            result = JWT_RESULT_UNEXPECTED_ERROR;
            goto cleanup;
        }

        OSSL_PARAM params[2];
        params[0] = OSSL_PARAM_construct_utf8_string("digest", const_cast<char*>(digestName), 0);
        params[1] = OSSL_PARAM_construct_end();
        if (!EVP_MAC_init(ctx, macKey.data, macKey.length, params)) {
            JWT_REPORT_ERROR("EVP_MAC_init() failed");
            ERR_print_errors_fp(stderr);
            EVP_MAC_CTX_free(ctx);
            EVP_MAC_free(mac);
            result = JWT_RESULT_UNEXPECTED_ERROR;
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
            JWT_REPORT_ERROR("EVP_MAC_update() failed");
            ERR_print_errors_fp(stderr);
            EVP_MAC_CTX_free(ctx);
            EVP_MAC_free(mac);
            result = JWT_RESULT_UNEXPECTED_ERROR;
            goto cleanup;
        }

        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);

        if(memcmp(tag.data, macBuffer, macLen) != 0) {
            result = JWT_RESULT_VERIFICATION_FAILED;
            goto cleanup;
        }

    }


cleanup:

    EVP_CIPHER_CTX_free(cipherCtx);
    return result;
}


JwtResult encryptGCM(Span<uint8_t> input, Span<uint8_t> aad, Span<uint8_t> iv, 
                   Span<uint8_t> key, JwtCryptAlgorithm algorithm, 
                   Span<uint8_t> output, size_t* outputLength, size_t* contentLength) {

    if(contentLength) {
        *contentLength = input.length + AES_BLOCK_SIZE;
    }
    if(outputLength) {
        *outputLength = input.length + AES_BLOCK_SIZE + 16;
    }
    if(output.data == nullptr) {
        return JWT_RESULT_SUCCESS;
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
            return JWT_RESULT_INVALID_ALGORITHM;
    }

    if(key.length != keyLen) {
        return JWT_RESULT_INVALID_CEK_LENGTH;
    }
    if(iv.length != 12) {
        return JWT_RESULT_INVALID_IV_LENGTH;
    }

    if(output.length < input.length + AES_BLOCK_SIZE + 16) {
        return JWT_RESULT_SHORT_BUFFER;
    }

    EVP_CIPHER_CTX* cipherCtx = EVP_CIPHER_CTX_new();

    JwtResult result = JWT_RESULT_SUCCESS;
    int32_t encLen = 0;
    int32_t aadLen = 0;
    int32_t finalLen = 0;

    if(EVP_EncryptInit_ex(cipherCtx, cipher, nullptr, key.data, iv.data) <= 0) {
        JWT_REPORT_ERROR("EVP_EncryptInit_ex() failed");
        ERR_print_errors_fp(stderr);
        result = JWT_RESULT_UNEXPECTED_ERROR;
        goto cleanup;
    }

    if(EVP_EncryptUpdate(cipherCtx, nullptr, &aadLen, aad.data, aad.length) <= 0) {
        JWT_REPORT_ERROR("EVP_EncryptUpdate() failed");
        ERR_print_errors_fp(stderr);
        result = JWT_RESULT_UNEXPECTED_ERROR;
        goto cleanup;
    }

    if(EVP_EncryptUpdate(cipherCtx, output.data, &encLen, input.data, input.length) <= 0) {
        JWT_REPORT_ERROR("EVP_EncryptUpdate() failed");
        ERR_print_errors_fp(stderr);
        result = JWT_RESULT_UNEXPECTED_ERROR;
        goto cleanup;
    }


    if(EVP_EncryptFinal(cipherCtx, output.data + encLen, &finalLen) <= 0) {
        JWT_REPORT_ERROR("EVP_EncryptFinal() failed");
        ERR_print_errors_fp(stderr);
        result = JWT_RESULT_UNEXPECTED_ERROR;
        goto cleanup;
    }

    if(EVP_CIPHER_CTX_ctrl(cipherCtx, EVP_CTRL_GCM_GET_TAG, 16, output.data + encLen + finalLen) <= 0) {
        JWT_REPORT_ERROR("EVP_CIPHER_CTX_ctrl() failed");
        ERR_print_errors_fp(stderr);
        result = JWT_RESULT_UNEXPECTED_ERROR;
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

JwtResult decryptGCM(Span<uint8_t> cipherText, Span<uint8_t> tag, Span<uint8_t> aad,
                   Span<uint8_t> iv, Span<uint8_t> key, JwtCryptAlgorithm algorithm,
                   Span<uint8_t> output, size_t* outputLength) {

    if(outputLength) {
        *outputLength = cipherText.length;
    }
    if(output.data == nullptr) {
        return JWT_RESULT_SUCCESS;
    }
    if(tag.length != 16) {
        return JWT_RESULT_VERIFICATION_FAILED;
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
            return JWT_RESULT_INVALID_ALGORITHM;
    }

    if(key.length != keyLen) {
        return JWT_RESULT_INVALID_CEK_LENGTH;
    }
    if(iv.length != 12) {
        return JWT_RESULT_INVALID_IV_LENGTH;
    }

    if(output.length < cipherText.length) {
        return JWT_RESULT_SHORT_BUFFER;
    }

    EVP_CIPHER_CTX* cipherCtx = EVP_CIPHER_CTX_new();

    JwtResult result = JWT_RESULT_SUCCESS;
    int32_t decLen = 0;
    int32_t aadLen = 0;
    int32_t finalLen = 0;

    if(EVP_DecryptInit_ex(cipherCtx, cipher, nullptr, key.data, iv.data) <= 0) {
        JWT_REPORT_ERROR("EVP_DecryptInit_ex() failed");
        ERR_print_errors_fp(stderr);
        result = JWT_RESULT_UNEXPECTED_ERROR;
        goto cleanup;
    }

    if(EVP_DecryptUpdate(cipherCtx, nullptr, &aadLen, aad.data, aad.length) <= 0) {
        JWT_REPORT_ERROR("EVP_DecryptUpdate() failed");
        ERR_print_errors_fp(stderr);
        result = JWT_RESULT_UNEXPECTED_ERROR;
        goto cleanup;
    }

    if(EVP_DecryptUpdate(cipherCtx, output.data, &decLen, cipherText.data, cipherText.length) <= 0) {
        JWT_REPORT_ERROR("EVP_DecryptUpdate() failed");
        ERR_print_errors_fp(stderr);
        result = JWT_RESULT_UNEXPECTED_ERROR;
        goto cleanup;
    }

    if(EVP_CIPHER_CTX_ctrl(cipherCtx, EVP_CTRL_GCM_SET_TAG, 16, tag.data) <= 0) {
        JWT_REPORT_ERROR("EVP_CIPHER_CTX_ctrl() failed");
        ERR_print_errors_fp(stderr);
        result = JWT_RESULT_UNEXPECTED_ERROR;
        goto cleanup;
    }

    if(EVP_DecryptFinal(cipherCtx, output.data + decLen, &finalLen) <= 0) {
        ERR_print_errors_fp(stderr);
        result = JWT_RESULT_VERIFICATION_FAILED;
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

JwtResult jwt::enc::encryptCek(JwtJsonObject* header, Span<uint8_t> cek, JwtKey* key, 
                               JwtAlgorithm algorithm, Span<uint8_t> output, size_t* outputLength) {

    if(key->use != JWT_KEY_USE_UNKNOWN && key->use != JWT_KEY_USE_ENCRYPTION) {
        return JWT_RESULT_INVALID_KEY_USE;
    }
    if(key->operations != 0 && (key->operations & JWT_KEY_OP_WRAP_KEY) == 0) {
        return JWT_RESULT_INVALID_KEY_OPERATION;
    }
    if(cek.length < 16 || cek.length > 64) {
        return JWT_RESULT_BAD_CEK;
    }

    return JWT_RESULT_SUCCESS;
}
JwtResult jwt::enc::decryptCek(JwtJsonObject* header, Span<uint8_t> encryptedKey, JwtKey* key, 
                               JwtAlgorithm algorithm, Span<uint8_t> output, size_t* outputLength) {

    if(key->use != JWT_KEY_USE_UNKNOWN && key->use != JWT_KEY_USE_ENCRYPTION) {
        return JWT_RESULT_INVALID_KEY_USE;
    }
    if(key->operations != 0 && (key->operations & JWT_KEY_OP_UNWRAP_KEY) == 0) {
        return JWT_RESULT_INVALID_KEY_OPERATION;
    }

    return JWT_RESULT_SUCCESS;
}

JwtResult jwt::enc::encryptAndProtect(Span<uint8_t> input, Span<uint8_t> aad, Span<uint8_t> iv, 
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

JwtResult jwt::enc::decryptAndVerify(Span<uint8_t> cipherText, Span<uint8_t> tag, Span<uint8_t> aad,
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

