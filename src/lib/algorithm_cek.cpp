/**
 * Josh Wallentine
 * Created 11/13/25
 * Modified 11/13/25
 *
 * Partial implementation of algorithm.hpp
 * See also algorithm.cpp, algorithm_b64url.cpp, algorithm_crypt.cpp
 */

#include "algorithm.hpp"
#include "crypt.hpp"
#include "key.hpp"
#include "util.hpp"

#include <jwt/result.h>
#include <jwt/key.h>
#include <jwt/token.h>

#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>

namespace {

// RSA
void getRsaParams(JwtAlgorithm algorithm, OSSL_PARAM* params) {
    switch(algorithm) {
        case JWT_ALGORITHM_RSA1_5:
            params[0] = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, OSSL_PKEY_RSA_PAD_MODE_PKCSV15, 0);
            params[1] = OSSL_PARAM_construct_end();
            break;
        case JWT_ALGORITHM_RSA_OAEP:
            params[0] = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, OSSL_PKEY_RSA_PAD_MODE_OAEP, 0);
            params[1] = OSSL_PARAM_construct_end();
            break;
        case JWT_ALGORITHM_RSA_OAEP_256:
            params[0] = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, OSSL_PKEY_RSA_PAD_MODE_OAEP, 0);
            params[1] = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, const_cast<char*>("sha256"), 0);
            params[2] = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, const_cast<char*>("sha256"), 0);
            params[3] = OSSL_PARAM_construct_end();
            break;
        default:
            break;
    }
}

JwtResult generateCekRsa(JwtJsonObject* header, JwtKey* key, JwtAlgorithm algorithm, 
                         JwtCryptAlgorithm crypt, Span<uint8_t>* cek, Span<uint8_t>* encryptedKey) {

    size_t keyLen = jwt::enc::getKeyLength(crypt);
    *cek = Span<uint8_t>::allocate(keyLen);
    RAND_bytes(cek->data, cek->length);

    EVP_PKEY* pkey = nullptr;
    JWT_CHECK(jwt::getKeyPkey(key, &pkey));

    OSSL_PARAM params[4];
    getRsaParams(algorithm, params);

    jwt::crypt::RsaContext ctx = {};
    JWT_CHECK(jwt::crypt::RsaContext::init(&ctx, pkey));

    return ctx.encrypt(*cek, encryptedKey, params);
}

JwtResult deriveCekRsa(JwtJsonObject* header, Span<uint8_t> encryptedKey, JwtKey* key, 
                       JwtAlgorithm algorithm, JwtCryptAlgorithm crypt, Span<uint8_t>* output) {

    EVP_PKEY* pkey = nullptr;
    JWT_CHECK(jwt::getKeyPkey(key, &pkey));

    OSSL_PARAM params[4];
    getRsaParams(algorithm, params);

    jwt::crypt::RsaContext ctx = {};
    JWT_CHECK(jwt::crypt::RsaContext::init(&ctx, pkey));

    return ctx.decrypt(encryptedKey, output, params);

}


// AESKW
JwtResult generateCekAes(JwtJsonObject* header, JwtKey* key, JwtAlgorithm algorithm, 
                         JwtCryptAlgorithm crypt, Span<uint8_t>* cek, Span<uint8_t>* encryptedKey) {

    Span<uint8_t> keyBytes = {};
    JWT_CHECK(jwt::getKeyBytes(key, &keyBytes));

    size_t keyLen = jwt::enc::getKeyLength(crypt);
    *cek = Span<uint8_t>::allocate(keyLen);
    RAND_bytes(cek->data, cek->length);

    const EVP_CIPHER* cipher;
    switch(algorithm) {
        case JWT_ALGORITHM_A128KW:
            cipher = EVP_aes_128_wrap(); break;
        case JWT_ALGORITHM_A192KW:
            cipher = EVP_aes_192_wrap(); break;
        case JWT_ALGORITHM_A256KW: 
            cipher = EVP_aes_256_wrap(); break;
        default:
            return JWT_RESULT_INVALID_ALGORITHM;
    }

    jwt::crypt::AesContext ctx = {};
    JWT_CHECK(jwt::crypt::AesContext::create(&ctx, cipher));

    return ctx.cipher(*cek, keyBytes, {}, encryptedKey, jwt::crypt::CipherMode::ENCRYPT);
}
JwtResult deriveCekAes(JwtJsonObject* header, Span<uint8_t> encryptedKey, JwtKey* key, 
                       JwtAlgorithm algorithm, JwtCryptAlgorithm crypt, Span<uint8_t>* output) {

    Span<uint8_t> keyBytes = {};
    JWT_CHECK(jwt::getKeyBytes(key, &keyBytes));
 
    const EVP_CIPHER* cipher;
    switch(algorithm) {
        case JWT_ALGORITHM_A128KW:
            cipher = EVP_aes_128_wrap(); break;
        case JWT_ALGORITHM_A192KW:
            cipher = EVP_aes_192_wrap(); break;
        case JWT_ALGORITHM_A256KW: 
            cipher = EVP_aes_256_wrap(); break;
        default:
            return JWT_RESULT_INVALID_ALGORITHM;
    }

    jwt::crypt::AesContext ctx = {};
    JWT_CHECK(jwt::crypt::AesContext::create(&ctx, cipher));

    return ctx.cipher(encryptedKey, keyBytes, {}, output, jwt::crypt::CipherMode::DECRYPT);
}


// ECDH-DS
JwtResult getEpk(JwtJsonObject* header, JwtKey* epk) {

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

JwtResult generateCekEc(JwtJsonObject* header, JwtKey* key, JwtAlgorithm algorithm, 
                        JwtCryptAlgorithm crypt, Span<uint8_t>* cek, Span<uint8_t>* encryptedKey) {

    JwtKey epk = {};
    JwtEcCurve curve = {};
    JWT_CHECK(jwt::getKeyCurve(key, &curve));

    JWT_CHECK(jwtKeyGenerateEc(&epk, curve));
    epk.isPrivateKey = false;

    JwtJsonObject keyObj = {};
    jwtJsonObjectCreate(&keyObj);
    JWT_CHECK(jwtKeyEncode(&epk, &keyObj));
    epk.isPrivateKey = true;

    jwtJsonObjectSetObject(header, "epk", keyObj);

    EVP_PKEY* pkey = nullptr;
    JWT_CHECK(jwt::getKeyPkey(key, &pkey));

    EVP_PKEY* peer = nullptr;
    JWT_CHECK(jwt::getKeyPkey(key, &peer));

    jwt::crypt::EcContext ctx = {};
    JWT_CHECK(jwt::crypt::EcContext::init(&ctx, pkey));

    size_t keyLen = 0;
    const EVP_CIPHER* cipher = nullptr;
    switch(algorithm) {
        case JWT_ALGORITHM_ECDH_ES:
            keyLen = jwt::enc::getKeyLength(crypt);
            break;
        case JWT_ALGORITHM_ECDH_ES_A128KW:
            keyLen = 16;
            cipher = EVP_aes_128_wrap();
            break;
        case JWT_ALGORITHM_ECDH_ES_A192KW:
            keyLen = 24;
            cipher = EVP_aes_192_wrap();
            break;
        case JWT_ALGORITHM_ECDH_ES_A256KW:
            keyLen = 32;
            cipher = EVP_aes_256_wrap();
            break;
        default:
            return JWT_RESULT_INVALID_ALGORITHM;
    }

    Span<uint8_t> derived = {};
    JWT_CHECK(ctx.diffieHelman(peer, keyLen, &derived));

    if(algorithm == JWT_ALGORITHM_ECDH_ES) {
        *cek = std::move(derived);
        return JWT_RESULT_SUCCESS;
    }
    
    jwt::crypt::AesContext aCtx = {};
    JWT_CHECK(jwt::crypt::AesContext::create(&aCtx, cipher));

    size_t cekLen = jwt::enc::getKeyLength(crypt);
    *cek = Span<uint8_t>::allocate(cekLen);
    RAND_bytes(cek->data, cek->length);

    return aCtx.cipher(*cek, derived, {}, encryptedKey, jwt::crypt::CipherMode::ENCRYPT);
}

JwtResult deriveCekEc(JwtJsonObject* header, Span<uint8_t> encryptedKey, JwtKey* key, 
                      JwtAlgorithm algorithm, JwtCryptAlgorithm crypt, Span<uint8_t>* output) {

    JwtKey epk = {};
    JWT_CHECK(getEpk(header, &epk));

    EVP_PKEY* pkey = nullptr;
    JWT_CHECK(jwt::getKeyPkey(key, &pkey));

    EVP_PKEY* peer = nullptr;
    JWT_CHECK(jwt::getKeyPkey(key, &peer));

    jwt::crypt::EcContext ctx = {};
    JWT_CHECK(jwt::crypt::EcContext::init(&ctx, pkey));

    size_t keyLen = 0;
    const EVP_CIPHER* cipher = nullptr;
    switch(algorithm) {
        case JWT_ALGORITHM_ECDH_ES:
            keyLen = jwt::enc::getKeyLength(crypt);
            break;
        case JWT_ALGORITHM_ECDH_ES_A128KW:
            keyLen = 16;
            cipher = EVP_aes_128_wrap();
            break;
        case JWT_ALGORITHM_ECDH_ES_A192KW:
            keyLen = 24;
            cipher = EVP_aes_192_wrap();
            break;
        case JWT_ALGORITHM_ECDH_ES_A256KW:
            keyLen = 32;
            cipher = EVP_aes_256_wrap();
            break;
        default:
            return JWT_RESULT_INVALID_ALGORITHM;
    }

    Span<uint8_t> derived = {};
    JWT_CHECK(ctx.diffieHelman(peer, keyLen, &derived));

    if(algorithm == JWT_ALGORITHM_ECDH_ES) {
        *output = std::move(derived);
        return JWT_RESULT_SUCCESS;
    }
    
    jwt::crypt::AesContext aCtx = {};
    JWT_CHECK(jwt::crypt::AesContext::create(&aCtx, cipher));

    return aCtx.cipher(encryptedKey, derived, {}, output, jwt::crypt::CipherMode::DECRYPT);
}


// AESGCM
JwtResult generateCekAesGcm(JwtJsonObject* header, JwtKey* key, JwtAlgorithm algorithm, 
                         JwtCryptAlgorithm crypt, Span<uint8_t>* cek, Span<uint8_t>* encryptedKey) {

    Span<uint8_t> keyBytes = {};
    JWT_CHECK(jwt::getKeyBytes(key, &keyBytes));

    size_t keyLen = jwt::enc::getKeyLength(crypt);
    *cek = Span<uint8_t>::allocate(keyLen);
    RAND_bytes(cek->data, cek->length);

    uint8_t ivBytes[12];
    Span<uint8_t> iv = {};
    iv.length = 12;
    iv.data = ivBytes;
    RAND_bytes(iv.data, iv.length);


    JwtString ivB64 = {};
    JWT_CHECK(jwt::b64url::encodeString(iv.data, iv.length, &ivB64));
    jwtJsonObjectSetString(header, "iv", ivB64.data);
    jwtStringDestroy(&ivB64);

    const EVP_CIPHER* cipher;
    switch(algorithm) {
        case JWT_ALGORITHM_A128GCMKW:
            cipher = EVP_aes_128_gcm(); break;
        case JWT_ALGORITHM_A192GCMKW:
            cipher = EVP_aes_192_gcm(); break;
        case JWT_ALGORITHM_A256GCMKW: 
            cipher = EVP_aes_256_gcm(); break;
        default:
            return JWT_RESULT_INVALID_ALGORITHM;
    }

    jwt::crypt::AesContext ctx = {};
    JWT_CHECK(jwt::crypt::AesContext::create(&ctx, cipher));

    Span<uint8_t> tag = {};
    JWT_CHECK(ctx.cipherGcm(*cek, {}, keyBytes, iv, encryptedKey, &tag, jwt::crypt::CipherMode::ENCRYPT));

    JwtString tagB64 = {};
    JWT_CHECK(jwt::b64url::encodeString(tag.data, tag.length, &tagB64));
    jwtJsonObjectSetString(header, "tag", tagB64.data);
    jwtStringDestroy(&tagB64);

    return JWT_RESULT_SUCCESS;
}
JwtResult deriveCekAesGcm(JwtJsonObject* header, Span<uint8_t> encryptedKey, JwtKey* key, 
                       JwtAlgorithm algorithm, JwtCryptAlgorithm crypt, Span<uint8_t>* output) {

    JwtString ivB64 = jwtJsonObjectGetString(header, "iv");
    Span<uint8_t> iv = {};
    JWT_CHECK(jwt::b64url::decodeNew(ivB64.data, ivB64.length, &iv));

    JwtString tagB64 = jwtJsonObjectGetString(header, "tag");
    Span<uint8_t> tag = {};
    JWT_CHECK(jwt::b64url::decodeNew(tagB64.data, tagB64.length, &tag));

    Span<uint8_t> keyBytes = {};
    JWT_CHECK(jwt::getKeyBytes(key, &keyBytes));
 
    const EVP_CIPHER* cipher;
    switch(algorithm) {
        case JWT_ALGORITHM_A128GCMKW:
            cipher = EVP_aes_128_gcm(); break;
        case JWT_ALGORITHM_A192GCMKW:
            cipher = EVP_aes_192_gcm(); break;
        case JWT_ALGORITHM_A256GCMKW: 
            cipher = EVP_aes_256_gcm(); break;
        default:
            return JWT_RESULT_INVALID_ALGORITHM;
    }

    jwt::crypt::AesContext ctx = {};
    JWT_CHECK(jwt::crypt::AesContext::create(&ctx, cipher));

    return ctx.cipherGcm(encryptedKey, {}, keyBytes, iv, output, &tag, jwt::crypt::CipherMode::DECRYPT);
}

// PBES2
JwtResult generateCekPbes(JwtJsonObject* header, JwtKey* key, JwtAlgorithm algorithm, 
                         JwtCryptAlgorithm crypt, Span<uint8_t>* cek, Span<uint8_t>* encryptedKey) {

    Span<uint8_t> keyBytes = {};
    JWT_CHECK(jwt::getKeyBytes(key, &keyBytes));

    size_t keyLen = jwt::enc::getKeyLength(crypt);
    *cek = Span<uint8_t>::allocate(keyLen);
    RAND_bytes(cek->data, cek->length);

    uint8_t saltBytes[32];
    RAND_bytes(saltBytes, 32);

    Span<uint8_t> salt = {};
    salt.data = saltBytes;
    salt.length = 32;

    int32_t iterations = 2048;

    JwtString saltB64 = {};
    jwt::b64url::encodeString(saltBytes, 32, &saltB64);

    jwtJsonObjectSetInt(header, "p2c", iterations);
    jwtJsonObjectSetString(header, "p2s", saltB64.data);
    jwtStringDestroy(&saltB64);

    const EVP_MD* digest = nullptr;
    const EVP_CIPHER* cipher = nullptr;
    size_t wrapKeyLen = 0;
    switch(algorithm) {
        case JWT_ALGORITHM_PBES_HS256_A128KW:
            digest = EVP_sha256(); 
            cipher = EVP_aes_128_wrap();
            wrapKeyLen = 16;
            break;
        case JWT_ALGORITHM_PBES_HS384_A192KW:
            digest = EVP_sha384(); 
            cipher = EVP_aes_192_wrap();
            wrapKeyLen = 24;
            break;
        case JWT_ALGORITHM_PBES_HS512_A256KW: 
            digest = EVP_sha512(); 
            cipher = EVP_aes_256_wrap();
            wrapKeyLen = 32;
            break;
        default:
            return JWT_RESULT_INVALID_ALGORITHM;
    }

    Span<uint8_t> wrapKey = Span<uint8_t>::allocate(wrapKeyLen);
    if(PKCS5_PBKDF2_HMAC(
        reinterpret_cast<char*>(keyBytes.data), keyBytes.length, 
        salt.data, salt.length, 
        iterations, digest,
        wrapKeyLen, wrapKey.data) <= 0) {

        JWT_REPORT_ERROR("PKCS5_PBKDF2_HMAC() failed");
        ERR_print_errors_fp(stderr);
        return JWT_RESULT_UNEXPECTED_ERROR;
    }

    jwt::crypt::AesContext ctx = {};
    JWT_CHECK(jwt::crypt::AesContext::create(&ctx, cipher));

    return ctx.cipher(*cek, wrapKey, {}, encryptedKey, jwt::crypt::CipherMode::ENCRYPT);

}

JwtResult deriveCekPbes(JwtJsonObject* header, Span<uint8_t> encryptedKey, JwtKey* key, 
                        JwtAlgorithm algorithm, JwtCryptAlgorithm crypt, Span<uint8_t>* output) {

    Span<uint8_t> keyBytes = {};
    JWT_CHECK(jwt::getKeyBytes(key, &keyBytes));


    JwtString saltB64 = jwtJsonObjectGetString(header, "p2s");
    uint64_t iterations = jwtJsonObjectGetUint(header, "p2c");
    if(saltB64.data == nullptr || iterations < 1000) {
        return JWT_RESULT_MISSING_REQUIRED_HEADER_CLAIM;
    }

    Span<uint8_t> salt = {};
    jwt::b64url::decodeNew(saltB64.data, saltB64.length, &salt);

    const EVP_MD* digest = nullptr;
    const EVP_CIPHER* cipher = nullptr;
    size_t wrapKeyLen = 0;
    switch(algorithm) {
        case JWT_ALGORITHM_PBES_HS256_A128KW:
            digest = EVP_sha256(); 
            cipher = EVP_aes_128_wrap();
            wrapKeyLen = 16;
            break;
        case JWT_ALGORITHM_PBES_HS384_A192KW:
            digest = EVP_sha384(); 
            cipher = EVP_aes_192_wrap();
            wrapKeyLen = 24;
            break;
        case JWT_ALGORITHM_PBES_HS512_A256KW: 
            digest = EVP_sha512(); 
            cipher = EVP_aes_256_wrap();
            wrapKeyLen = 32;
            break;
        default:
            return JWT_RESULT_INVALID_ALGORITHM;
    }

    Span<uint8_t> wrapKey = Span<uint8_t>::allocate(wrapKeyLen);
    if(PKCS5_PBKDF2_HMAC(
        reinterpret_cast<char*>(keyBytes.data), keyBytes.length, 
        salt.data, salt.length, 
        iterations, digest,
        wrapKeyLen, wrapKey.data) <= 0) {

        JWT_REPORT_ERROR("PKCS5_PBKDF2_HMAC() failed");
        ERR_print_errors_fp(stderr);
        return JWT_RESULT_UNEXPECTED_ERROR;
    }


    jwt::crypt::AesContext ctx = {};
    JWT_CHECK(jwt::crypt::AesContext::create(&ctx, cipher));

    return ctx.cipher(encryptedKey, wrapKey, {}, output, jwt::crypt::CipherMode::DECRYPT);

}


} // namespace


JwtResult jwt::enc::generateCek(JwtJsonObject* header, JwtKey* key, JwtAlgorithm algorithm, 
                                JwtCryptAlgorithm crypt, Span<uint8_t>* cek, Span<uint8_t>* encryptedKey) {

    switch(algorithm) {
        case JWT_ALGORITHM_RSA1_5:
        case JWT_ALGORITHM_RSA_OAEP:
        case JWT_ALGORITHM_RSA_OAEP_256: 
            return generateCekRsa(header, key, algorithm, crypt, cek, encryptedKey);
        case JWT_ALGORITHM_A128KW:
        case JWT_ALGORITHM_A192KW:
        case JWT_ALGORITHM_A256KW: 
            return generateCekAes(header, key, algorithm, crypt, cek, encryptedKey);
        case JWT_ALGORITHM_DIRECT: {
            return jwt::getKeyBytes(key, cek);
        }
        case JWT_ALGORITHM_ECDH_ES: 
        case JWT_ALGORITHM_ECDH_ES_A128KW:
        case JWT_ALGORITHM_ECDH_ES_A192KW:
        case JWT_ALGORITHM_ECDH_ES_A256KW: {
            return generateCekEc(header, key, algorithm, crypt, cek, encryptedKey);
        }
        case JWT_ALGORITHM_A128GCMKW:
        case JWT_ALGORITHM_A192GCMKW:
        case JWT_ALGORITHM_A256GCMKW: {
            return generateCekAesGcm(header, key, algorithm, crypt, cek, encryptedKey);
        }
        case JWT_ALGORITHM_PBES_HS256_A128KW:
        case JWT_ALGORITHM_PBES_HS384_A192KW:
        case JWT_ALGORITHM_PBES_HS512_A256KW: {
            return generateCekPbes(header, key, algorithm, crypt, cek, encryptedKey);
        }
        default:
            return JWT_RESULT_INVALID_ALGORITHM;

    }


}

JwtResult jwt::enc::deriveCek(JwtJsonObject* header, Span<uint8_t> encryptedKey, JwtKey* key, 
                              JwtAlgorithm algorithm, JwtCryptAlgorithm crypt, Span<uint8_t>* output) {

    switch(algorithm) {
        case JWT_ALGORITHM_RSA1_5:
        case JWT_ALGORITHM_RSA_OAEP:
        case JWT_ALGORITHM_RSA_OAEP_256: 
            return deriveCekRsa(header, encryptedKey, key, algorithm, crypt, output);
        case JWT_ALGORITHM_A128KW:
        case JWT_ALGORITHM_A192KW:
        case JWT_ALGORITHM_A256KW: 
            return deriveCekAes(header, encryptedKey, key, algorithm, crypt, output);
        case JWT_ALGORITHM_DIRECT: {
            return jwt::getKeyBytes(key, output);
        }
        case JWT_ALGORITHM_ECDH_ES: 
        case JWT_ALGORITHM_ECDH_ES_A128KW:
        case JWT_ALGORITHM_ECDH_ES_A192KW:
        case JWT_ALGORITHM_ECDH_ES_A256KW: {
            return deriveCekEc(header, encryptedKey, key, algorithm, crypt, output);
        }
        case JWT_ALGORITHM_A128GCMKW:
        case JWT_ALGORITHM_A192GCMKW:
        case JWT_ALGORITHM_A256GCMKW: {
            return deriveCekAesGcm(header, encryptedKey, key, algorithm, crypt, output);
        }
        case JWT_ALGORITHM_PBES_HS256_A128KW:
        case JWT_ALGORITHM_PBES_HS384_A192KW:
        case JWT_ALGORITHM_PBES_HS512_A256KW: {
            return deriveCekPbes(header, encryptedKey, key, algorithm, crypt, output);
        }
        default:
            return JWT_RESULT_INVALID_ALGORITHM;

    }

}
