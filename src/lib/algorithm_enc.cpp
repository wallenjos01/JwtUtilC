/**
 * Josh Wallentine
 * Created 11/11/25
 * Modified 11/12/25
 *
 * Partial implementation of algorithm.hpp
 * See also algorithm.cpp, algorithm_b64url.cpp, algorithm_hmac.cpp, algorithm_sig.cpp
*/

#include "algorithm.hpp"
#include "jwt/json.h"
#include "key.hpp"
#include "util.hpp"

#include <cstdio>
#include <jwt/key.h>
#include <jwt/result.h>

#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/param_build.h>
#include <openssl/rand.h>


namespace {


// CEK encryption for RSA1_5, RSA-OAEP, RSA-OAEP-256
JwtResult encryptCekRsa(Span<uint8_t> cek, JwtKey* key, JwtAlgorithm algorithm, Span<uint8_t> output, size_t* outputLength) {

    if(key->type != JWT_KEY_TYPE_RSA) {
        return JWT_RESULT_INVALID_KEY_TYPE;
    }

    JwtResult result = JWT_RESULT_SUCCESS;
    EVP_PKEY* pkey = static_cast<EVP_PKEY*>(key->keyData);
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

    if(outputLength) {
        *outputLength = cryptLength;
    }

cleanup:

    EVP_PKEY_CTX_free(ctx);
    return result;
}

// CEK decryption for RSA1_5, RSA-OAEP, RSA-OAEP-256
JwtResult decryptCekRsa(Span<uint8_t> cek, JwtKey* key, JwtAlgorithm algorithm, Span<uint8_t> output, size_t* outputLength) {

    if(key->type != JWT_KEY_TYPE_RSA) {
        return JWT_RESULT_INVALID_KEY_TYPE;
    }

    JwtResult result = JWT_RESULT_SUCCESS;
    EVP_PKEY* pkey = static_cast<EVP_PKEY*>(key->keyData);
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, pkey, nullptr);
    if(ctx == nullptr) {
        ERR_print_errors_fp(stderr);
        return JWT_RESULT_UNEXPECTED_ERROR;
    }

    OSSL_PARAM_BLD* builder = OSSL_PARAM_BLD_new();
    OSSL_PARAM* params = nullptr;
    size_t keyLength;

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

    if(EVP_PKEY_decrypt_init_ex(ctx, params) <= 0) {
        JWT_REPORT_ERROR("EVP_PKEY_decrypt_init_ex() failed");
        ERR_print_errors_fp(stderr);
        result = JWT_RESULT_UNEXPECTED_ERROR;
        goto cleanup;
    }

    if(EVP_PKEY_decrypt(ctx, nullptr, &keyLength, cek.data, cek.length) <= 0) {
        JWT_REPORT_ERROR("EVP_PKEY_decrypt() failed");
        ERR_print_errors_fp(stderr);
        result = JWT_RESULT_UNEXPECTED_ERROR;
        goto cleanup;
    }

    if(outputLength) {
        *outputLength = keyLength;
    }
    if(output.data == nullptr) {
        goto cleanup;
    }

    if(EVP_PKEY_decrypt(ctx, output.data, &keyLength, cek.data, cek.length) <= 0) {
        JWT_REPORT_ERROR("EVP_PKEY_decrypt_init_ex() failed");
        ERR_print_errors_fp(stderr);
        result = JWT_RESULT_UNEXPECTED_ERROR;
        goto cleanup;
    }
    if(outputLength) {
        *outputLength = keyLength;
    }

cleanup:

    EVP_PKEY_CTX_free(ctx);
    return result;
}

// CEK encryption for A128KW, A192KW, A256KW
JwtResult encryptCekAes(Span<uint8_t> cek, JwtKey* key, JwtAlgorithm algorithm, Span<uint8_t> output, size_t* outputLength) {

    if(key->type != JWT_KEY_TYPE_OCTET_SEQUENCE) {
        return JWT_RESULT_INVALID_KEY_TYPE;
    }
    Span<uint8_t> keyBytes = *static_cast<Span<uint8_t>*>(key->keyData);

    const EVP_CIPHER* cipher;
    switch(algorithm) {
        case JWT_ALGORITHM_A128KW:
        case JWT_ALGORITHM_ECDH_ES_A128KW:
            cipher = EVP_aes_128_wrap();
            break;
        case JWT_ALGORITHM_A192KW:
        case JWT_ALGORITHM_ECDH_ES_A192KW:
            cipher = EVP_aes_192_wrap();
            break;
        case JWT_ALGORITHM_A256KW:
        case JWT_ALGORITHM_ECDH_ES_A256KW:
            cipher = EVP_aes_256_wrap();
            break;
        default:
            return JWT_RESULT_INVALID_ALGORITHM;
    }

    size_t expectedLength = cek.length + AES_BLOCK_SIZE;

    if(outputLength) {
        *outputLength = expectedLength;
    }
    if(output.data == nullptr) {
        return JWT_RESULT_SUCCESS;
    }


    if(output.length < expectedLength) {
        return JWT_RESULT_SHORT_BUFFER;
    }

    EVP_CIPHER_CTX* cipherCtx = EVP_CIPHER_CTX_new();

    JwtResult result = JWT_RESULT_SUCCESS;
    int32_t encLen = 0;
    int32_t finalLen = 0;

    if(EVP_EncryptInit_ex(cipherCtx, cipher, nullptr, keyBytes.data, nullptr) <= 0) {
        JWT_REPORT_ERROR("EVP_EncryptInit_ex() failed");
        ERR_print_errors_fp(stderr);
        result = JWT_RESULT_UNEXPECTED_ERROR;
        goto cleanup;
    }

    if(EVP_EncryptUpdate(cipherCtx, output.data, &encLen, cek.data, cek.length) <= 0) {
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

    if(outputLength) {
        *outputLength = encLen + finalLen;
    }

    if(encLen + finalLen > expectedLength) {
        JWT_REPORT_ERROR("Key was too long for buffer! " << (encLen + finalLen) << " > " << expectedLength);
        exit(1);
    }

cleanup:

    EVP_CIPHER_CTX_free(cipherCtx);
    return result;
}

// CEK decryption for A128KW, A192KW, A256KW 
JwtResult decryptCekAes(Span<uint8_t> cek, JwtKey* key, JwtAlgorithm algorithm, Span<uint8_t> output, size_t* outputLength) {

    if(key->type != JWT_KEY_TYPE_OCTET_SEQUENCE) {
        return JWT_RESULT_INVALID_KEY_TYPE;
    }
    Span<uint8_t> keyBytes = *static_cast<Span<uint8_t>*>(key->keyData);

    const EVP_CIPHER* cipher;
    size_t keyLen;
    switch(algorithm) {
        case JWT_ALGORITHM_A128KW:
        case JWT_ALGORITHM_ECDH_ES_A128KW:
            cipher = EVP_aes_128_wrap();
            keyLen = 16;
            break;
        case JWT_ALGORITHM_A192KW:
        case JWT_ALGORITHM_ECDH_ES_A192KW:
            cipher = EVP_aes_192_wrap();
            keyLen = 24;
            break;
        case JWT_ALGORITHM_A256KW:
        case JWT_ALGORITHM_ECDH_ES_A256KW:
            cipher = EVP_aes_256_wrap();
            keyLen = 32;
            break;
        default:
            return JWT_RESULT_INVALID_ALGORITHM;
    }

    size_t expectedLength = keyLen + AES_BLOCK_SIZE;

    if(outputLength) {
        *outputLength = expectedLength;
    }
    if(output.data == nullptr) {
        return JWT_RESULT_SUCCESS;
    }

    if(output.length < expectedLength) {
        return JWT_RESULT_SHORT_BUFFER;
    }

    EVP_CIPHER_CTX* cipherCtx = EVP_CIPHER_CTX_new();

    JwtResult result = JWT_RESULT_SUCCESS;
    int32_t decLen = 0;
    int32_t finalLen = 0;

    if(EVP_DecryptInit_ex(cipherCtx, cipher, nullptr, keyBytes.data, nullptr) <= 0) {
        JWT_REPORT_ERROR("EVP_DecryptInit_ex() failed");
        ERR_print_errors_fp(stderr);
        result = JWT_RESULT_UNEXPECTED_ERROR;
        goto cleanup;
    }

    if(EVP_DecryptUpdate(cipherCtx, output.data, &decLen, cek.data, cek.length) <= 0) {
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

    if(decLen + finalLen > expectedLength) {
        JWT_REPORT_ERROR("Key was too long for buffer! " << (decLen + finalLen) << " > " << expectedLength);
        exit(1);
    }

cleanup:

    EVP_CIPHER_CTX_free(cipherCtx);
    return result;
}

JwtResult generateCekEc(JwtJsonObject* header, JwtKey* key, JwtAlgorithm algorithm, 
                        JwtCryptAlgorithm crypt, JwtKey* epk) {

    JwtEcCurve curve = {};
    JWT_CHECK(jwt::getKeyCurve(key, &curve));

    JWT_CHECK(jwtKeyGenerateEc(epk, curve));
    epk->isPrivateKey = false;

    JwtJsonObject keyObj = {};
    jwtJsonObjectCreate(&keyObj);
    JWT_CHECK(jwtKeyEncode(epk, &keyObj));
    epk->isPrivateKey = true;

    jwtJsonObjectSetObject(header, "epk", keyObj);
    return JWT_RESULT_SUCCESS;
}

JwtResult getEpk(JwtJsonObject* header, JwtKey* epk, size_t* keyLen) {

    JwtCryptAlgorithm crypt;
    JWT_CHECK(jwtCryptAlgorithmParse(&crypt, jwtJsonObjectGetString(header, "enc").data));
    *keyLen = jwt::enc::getKeyLength(crypt);

    JwtJsonObject epkObj = jwtJsonObjectGetObject(header, "epk");
    if(epkObj.buckets == nullptr) {
        return JWT_RESULT_MISSING_REQUIRED_HEADER_CLAIM;
    }

    JWT_CHECK(jwtKeyParse(epk, &epkObj));
    if(epk->isPrivateKey || epk->type != JWT_KEY_TYPE_ELLIPTIC_CURVE) {
        jwtKeyDestroy(epk);
        return JWT_RESULT_BAD_EPK;
    }

    return JWT_RESULT_SUCCESS;
}

JwtResult deriveCekEc(JwtKey* epk, JwtKey* key, 
                       JwtAlgorithm algorithm, Span<uint8_t> output, size_t keyLen) {
    
    JwtResult result = JWT_RESULT_SUCCESS;
    size_t encLen = keyLen;
    
    EVP_PKEY* pkey = static_cast<EVP_PKEY*>(key->keyData);
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, pkey, nullptr);

    EVP_PKEY* epkey = static_cast<EVP_PKEY*>(epk->keyData);

    OSSL_PARAM_BLD* builder = OSSL_PARAM_BLD_new();
    //OSSL_PARAM_BLD_push_utf8_string(builder, OSSL_EXCHANGE_PARAM_KDF_TYPE, "X963KDF", 0);
    OSSL_PARAM_BLD_push_size_t(builder, OSSL_EXCHANGE_PARAM_KDF_OUTLEN, keyLen);

    OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(builder);
    if(EVP_PKEY_derive_init_ex(ctx, params) <= 0) {
        JWT_REPORT_ERROR("EVP_PKEY_derive_init() failed");
        OSSL_PARAM_free(params);
        ERR_print_errors_fp(stderr);
        result = JWT_RESULT_UNEXPECTED_ERROR;
        goto cleanup;
    }
    OSSL_PARAM_free(params);

    if(EVP_PKEY_derive_set_peer(ctx, epkey) <= 0) {
        JWT_REPORT_ERROR("EVP_PKEY_derive_set_peer() failed");
        ERR_print_errors_fp(stderr);
        result = JWT_RESULT_UNEXPECTED_ERROR;
        goto cleanup;
    }

    // if(EVP_PKEY_derive(ctx, nullptr, &encLen) <= 0) {
    //     JWT_REPORT_ERROR("EVP_PKEY_derive() failed");
    //     ERR_print_errors_fp(stderr);
    //     result = JWT_RESULT_UNEXPECTED_ERROR;
    //     goto cleanup;
    // }
    // if(encLen != keyLen) {
    //     JWT_REPORT_ERROR("Key was the wrong length!");
    //     result = JWT_RESULT_UNEXPECTED_ERROR;
    //     goto cleanup;
    // }

    if(EVP_PKEY_derive(ctx, output.data, &encLen) <= 0) {
        JWT_REPORT_ERROR("EVP_PKEY_derive() failed");
        ERR_print_errors_fp(stderr);
        result = JWT_RESULT_UNEXPECTED_ERROR;
        goto cleanup;
    }

cleanup:

    EVP_PKEY_CTX_free(ctx);
    return result;
}

// Content encryption for A128CBC-HS256, A192CBC-HS384, A256CBC-HS512
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

// Content decryption for A128CBC-HS256, A192CBC-HS384, A256CBC-HS512
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


// Content encryption for A128GCM, A192GCM, A256GCM
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

// Content decryption for A128GCM, A192GCM, A256GCM
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
        std::cerr << key.length << " != " << keyLen;
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

JwtResult jwt::enc::generateCek(JwtJsonObject* header, JwtKey* key, JwtAlgorithm algorithm, 
                                JwtCryptAlgorithm crypt, Span<uint8_t>* cek, Span<uint8_t>* encryptedKey) {

    if(key->use != JWT_KEY_USE_UNKNOWN && key->use != JWT_KEY_USE_ENCRYPTION) {
        return JWT_RESULT_INVALID_KEY_USE;
    }

    JwtKeyOperation op;
    switch(algorithm) {
        case JWT_ALGORITHM_DIRECT:
            op = JWT_KEY_OP_ENCRYPT;
        case JWT_ALGORITHM_ECDH_ES:
            op = JWT_KEY_OP_DERIVE_KEY;
            break;
        case JWT_ALGORITHM_ECDH_ES_A128KW:
        case JWT_ALGORITHM_ECDH_ES_A192KW:
        case JWT_ALGORITHM_ECDH_ES_A256KW:
            op = JWT_KEY_OP_DERIVE_BITS;
            break;
        default:
            op = JWT_KEY_OP_WRAP_KEY;
    }

    if(key->operations != 0 && (key->operations & op) == 0) {
        return JWT_RESULT_INVALID_KEY_OPERATION;
    }

    size_t keyLen = getKeyLength(crypt);

    switch(algorithm) {
        case JWT_ALGORITHM_RSA1_5:
        case JWT_ALGORITHM_RSA_OAEP:
        case JWT_ALGORITHM_RSA_OAEP_256: {
            *cek = Span<uint8_t>(new uint8_t[keyLen], keyLen);
            RAND_bytes(cek->data, cek->length);
            size_t encLen;
            JWT_CHECK(encryptCekRsa(*cek, key, algorithm, {}, &encLen));

            encryptedKey->length = encLen;
            encryptedKey->data = new uint8_t[encLen];
            encryptedKey->owned = true;
            JWT_CHECK(encryptCekRsa(*cek, key, algorithm, *encryptedKey, &encLen));

            encryptedKey->length = encLen;
            return JWT_RESULT_SUCCESS;
        } 
        case JWT_ALGORITHM_A128KW:
        case JWT_ALGORITHM_A192KW:
        case JWT_ALGORITHM_A256KW: {
            *cek = Span<uint8_t>(new uint8_t[keyLen], keyLen);
            RAND_bytes(cek->data, cek->length);
            size_t encLen;
            JWT_CHECK(encryptCekAes(*cek, key, algorithm, {}, &encLen));

            encryptedKey->length = encLen;
            encryptedKey->data = new uint8_t[encLen];
            encryptedKey->owned = true;
            JWT_CHECK(encryptCekAes(*cek, key, algorithm, *encryptedKey, &encLen));

            encryptedKey->length = encLen;
            return JWT_RESULT_SUCCESS;
        }
        case JWT_ALGORITHM_DIRECT:
            if(key->type != JWT_KEY_TYPE_OCTET_SEQUENCE) 
                return JWT_RESULT_INVALID_KEY_TYPE;
            *cek = *static_cast<Span<uint8_t>*>(key->keyData);
            if(cek->length != keyLen) {
                return JWT_RESULT_INVALID_CEK_LENGTH;
            }
            return JWT_RESULT_SUCCESS;
        case JWT_ALGORITHM_ECDH_ES: {
            JwtKey epk = {};
            JWT_CHECK(generateCekEc(header, key, algorithm, crypt, &epk));

            *cek = Span<uint8_t>(new uint8_t[keyLen], keyLen);
            return deriveCekEc(&epk, key, algorithm, *cek, keyLen);
        }
        case JWT_ALGORITHM_ECDH_ES_A128KW:
        case JWT_ALGORITHM_ECDH_ES_A192KW:
        case JWT_ALGORITHM_ECDH_ES_A256KW: {

            JwtKey epk = {};
            JWT_CHECK(generateCekEc(header, key, algorithm, crypt, &epk));
            size_t wrapKeyLen = 0;
            switch(algorithm) {
                case JWT_ALGORITHM_ECDH_ES_A128KW:
                    wrapKeyLen = 16;
                    break;
                case JWT_ALGORITHM_ECDH_ES_A192KW:
                    wrapKeyLen = 24;
                    break;
                case JWT_ALGORITHM_ECDH_ES_A256KW:
                    wrapKeyLen = 32;
                    break;
                default:
                    return JWT_RESULT_UNEXPECTED_ERROR;
            }

            Span<uint8_t> wrapKey = Span<uint8_t>(new uint8_t[wrapKeyLen], wrapKeyLen);
            JWT_CHECK(deriveCekEc(&epk, key, algorithm, wrapKey, wrapKeyLen));

            *cek = Span<uint8_t>(new uint8_t[keyLen], keyLen);
            RAND_bytes(cek->data, cek->length);
            size_t encLen = 0;

            JwtKey wrap = {};
            wrap.type = JWT_KEY_TYPE_OCTET_SEQUENCE;
            wrap.keyData = &wrapKey;
            JWT_CHECK(encryptCekAes(*cek, &wrap, algorithm, {}, &encLen));

            encryptedKey->length = encLen;
            encryptedKey->data = new uint8_t[encLen];
            encryptedKey->owned = true;
            JWT_CHECK(encryptCekAes(*cek, &wrap, algorithm, *encryptedKey, &encLen));

            encryptedKey->length = encLen;

            return JWT_RESULT_SUCCESS;
        }

        default:
            return JWT_RESULT_UNIMPLEMENTED;
    }
}
JwtResult jwt::enc::decryptCek(JwtJsonObject* header, Span<uint8_t> encryptedKey, JwtKey* key, 
                               JwtAlgorithm algorithm, Span<uint8_t> output, size_t* outputLength) {

    if(key->use != JWT_KEY_USE_UNKNOWN && key->use != JWT_KEY_USE_ENCRYPTION) {
        return JWT_RESULT_INVALID_KEY_USE;
    }

    JwtKeyOperation op;
    switch(algorithm) {
        case JWT_ALGORITHM_ECDH_ES:
            op = JWT_KEY_OP_DERIVE_KEY;
            break;
        case JWT_ALGORITHM_ECDH_ES_A128KW:
        case JWT_ALGORITHM_ECDH_ES_A192KW:
        case JWT_ALGORITHM_ECDH_ES_A256KW:
            op = JWT_KEY_OP_DERIVE_BITS;
            break;
        default:
            op = JWT_KEY_OP_UNWRAP_KEY;
    }

    if(key->operations != 0 && (key->operations & op) == 0) {
        return JWT_RESULT_INVALID_KEY_OPERATION;
    }

    switch(algorithm) {
        case JWT_ALGORITHM_RSA1_5:
        case JWT_ALGORITHM_RSA_OAEP:
        case JWT_ALGORITHM_RSA_OAEP_256:
            return decryptCekRsa(encryptedKey, key, algorithm, output, outputLength);
        case JWT_ALGORITHM_A128KW:
        case JWT_ALGORITHM_A192KW:
        case JWT_ALGORITHM_A256KW:
            return decryptCekAes(encryptedKey, key, algorithm, output, outputLength);
        case JWT_ALGORITHM_ECDH_ES: {
            JwtKey epk = {};
            size_t keyLen = 0;
            JWT_CHECK(getEpk(header, &epk, &keyLen));

            if(outputLength) { 
                *outputLength = keyLen;
            }
            if(output.data == nullptr) {
                return JWT_RESULT_SUCCESS;
            }
            if(output.length < keyLen) {
                return JWT_RESULT_SHORT_BUFFER;
            }
            return deriveCekEc(&epk, key, algorithm, output, keyLen);
        }
        case JWT_ALGORITHM_ECDH_ES_A128KW:
        case JWT_ALGORITHM_ECDH_ES_A192KW:
        case JWT_ALGORITHM_ECDH_ES_A256KW: {
            JwtKey epk = {};
            size_t keyLen = 0;
            JWT_CHECK(getEpk(header, &epk, &keyLen));

            size_t wrapKeyLen = 0;
            switch(algorithm) {
                case JWT_ALGORITHM_ECDH_ES_A128KW:
                    wrapKeyLen = 16;
                    break;
                case JWT_ALGORITHM_ECDH_ES_A192KW:
                    wrapKeyLen = 24;
                    break;
                case JWT_ALGORITHM_ECDH_ES_A256KW:
                    wrapKeyLen = 32;
                    break;
                default:
                    return JWT_RESULT_UNEXPECTED_ERROR;
            }

            Span<uint8_t> wrapKey = Span<uint8_t>(new uint8_t[wrapKeyLen], wrapKeyLen);
            JWT_CHECK(deriveCekEc(&epk, key, algorithm, wrapKey, wrapKeyLen));

            JwtKey wrap = {};
            wrap.type = JWT_KEY_TYPE_OCTET_SEQUENCE;
            wrap.keyData = &wrapKey;

            return decryptCekAes(encryptedKey, &wrap, algorithm, output, outputLength);
        }
        default:
            return JWT_RESULT_UNIMPLEMENTED;
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

