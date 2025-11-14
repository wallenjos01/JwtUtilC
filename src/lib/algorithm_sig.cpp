/**
 * Josh Wallentine
 * Created 11/11/25
 * Modified 11/12/25
 *
 * Partial implementation of algorithm.hpp
 * See also algorithm.cpp, algorithm_b64url.cpp, algorithm_hmac.cpp, algorithm_crypt.cpp, algorithm_cek.cpp
*/

#include "algorithm.hpp"
#include "jwt/result.h"
#include "util.hpp"

#include <jwt/key.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>

namespace {

JwtResult setupContextForAlgorithm(EVP_PKEY_CTX* keyContext,
                                 JwtAlgorithm algorithm) {

    switch (algorithm) {
    case JWT_ALGORITHM_RS256:
    case JWT_ALGORITHM_RS384:
    case JWT_ALGORITHM_RS512:
        if(EVP_PKEY_CTX_set_rsa_padding(keyContext, RSA_PKCS1_PADDING) <= 0) {
            ERR_print_errors_fp(stderr);
            return JWT_RESULT_UNEXPECTED_ERROR;
        }
        break;
    case JWT_ALGORITHM_ES256:
    case JWT_ALGORITHM_ES384:
    case JWT_ALGORITHM_ES512:
        break;
    case JWT_ALGORITHM_PS256:
    case JWT_ALGORITHM_PS384:
    case JWT_ALGORITHM_PS512:
        if(EVP_PKEY_CTX_set_rsa_padding(keyContext, RSA_PKCS1_PSS_PADDING) <= 0) {
            ERR_print_errors_fp(stderr);
            return JWT_RESULT_UNEXPECTED_ERROR;
        }
        break;
    default:
        return JWT_RESULT_INVALID_ALGORITHM;
    }

    return JWT_RESULT_SUCCESS;
}

}

extern "C" {

// This is in a private OpenSSL header, but all other methods to get these
// numbers for an EC signature are deprecated.
typedef struct ECDSA_SIG_st {
    BIGNUM* r;
    BIGNUM* s;
} ECDSA_SIG_st;

}


JwtResult jwt::sig::generate(Span<uint8_t> input, JwtKey* key,
                               JwtAlgorithm algorithm, Span<uint8_t> output,
                               size_t* sigLength) {
 
    if (input.length == 0 || input.data == nullptr) {
        return JWT_RESULT_SUCCESS;
    }
    if (key->type == JWT_KEY_TYPE_OCTET_SEQUENCE) {
        return JWT_RESULT_INVALID_KEY_TYPE;
    }
    if (key->keyData == nullptr) {
        return JWT_RESULT_INVALID_KEY_DATA;
    }

    size_t requiredLen = 0;
    JwtResult result = JWT_RESULT_SUCCESS;

    const char* digest = getDigestForAlgorithm(algorithm);
    if (digest == nullptr) {
        return JWT_RESULT_INVALID_ALGORITHM;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_MD* md = EVP_MD_fetch(nullptr, digest, nullptr);

    EVP_PKEY* pkey = static_cast<EVP_PKEY*>(key->keyData);
    EVP_PKEY_CTX* pctx = nullptr;

    if(EVP_DigestSignInit(ctx, &pctx, md, nullptr, pkey) <= 0) {
        JWT_REPORT_ERROR("EVP_DigestSignInit() failed");
        ERR_print_errors_fp(stderr);
        result = JWT_RESULT_UNEXPECTED_ERROR;
        goto cleanup;
    }

    JWT_CHECK_GOTO(setupContextForAlgorithm(pctx, algorithm), result, cleanup);

    if(EVP_DigestSignUpdate(ctx, input.data, input.length) <= 0) {
        JWT_REPORT_ERROR("EVP_DigestSignUpdate() failed");
        ERR_print_errors_fp(stderr);
        result = JWT_RESULT_UNEXPECTED_ERROR;
        goto cleanup;
    }

    if(EVP_DigestSignFinal(ctx, nullptr, &requiredLen) <= 0) {
        JWT_REPORT_ERROR("EVP_DigestSignFinal() failed");
        ERR_print_errors_fp(stderr);
        result = JWT_RESULT_UNEXPECTED_ERROR;
        goto cleanup;
    }

    if(sigLength) *sigLength = requiredLen;

    if(output.data == nullptr) {
        goto cleanup;
    }

    if(output.length < requiredLen) {
        result = JWT_RESULT_SHORT_BUFFER;
        goto cleanup;
    }

    if(EVP_DigestSignFinal(ctx, output.data, &requiredLen) <= 0) {
        JWT_REPORT_ERROR("EVP_DigestSignFinal() failed");
        ERR_print_errors_fp(stderr);
        result = JWT_RESULT_UNEXPECTED_ERROR;
        goto cleanup;
    }

    if(key->type == JWT_KEY_TYPE_ELLIPTIC_CURVE) {

        ECDSA_SIG* realSig = nullptr;
        const uint8_t* der = output.data;
        d2i_ECDSA_SIG(&realSig, &der, requiredLen);

        memset(output.data, 0, requiredLen);
        size_t siglen = BN_num_bytes(realSig->r);

        BN_bn2binpad(realSig->r, output.data, siglen);
        BN_bn2binpad(realSig->s, output.data + siglen, siglen);

        if(sigLength) *sigLength = siglen * 2;

    } else {
        if(sigLength) *sigLength = requiredLen;
    }
cleanup:

    EVP_MD_free(md);
    EVP_MD_CTX_destroy(ctx);
    return result;

}

JwtResult jwt::sig::validate(Span<uint8_t> input, Span<uint8_t> signature, 
                          JwtKey* key, JwtAlgorithm algorithm) {

    if (input.length == 0 || input.data == nullptr) {
        return JWT_RESULT_SUCCESS;
    }
    if (key->type == JWT_KEY_TYPE_OCTET_SEQUENCE) {
        return JWT_RESULT_INVALID_KEY_TYPE;
    }
    if (key->keyData == nullptr) {
        return JWT_RESULT_INVALID_KEY_DATA;
    }

    JwtResult result = JWT_RESULT_SUCCESS;
    const char* digest = getDigestForAlgorithm(algorithm);
    if (digest == nullptr) {
        return JWT_RESULT_INVALID_ALGORITHM;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_MD* md = EVP_MD_fetch(nullptr, digest, nullptr);

    EVP_PKEY* pkey = static_cast<EVP_PKEY*>(key->keyData);
    EVP_PKEY_CTX* pctx = nullptr;

    if(EVP_DigestVerifyInit(ctx, &pctx, md, nullptr, pkey) <= 0) {
        JWT_REPORT_ERROR("EVP_DigestVerifyInit() failed");
        ERR_print_errors_fp(stderr);
        result = JWT_RESULT_UNEXPECTED_ERROR;
        goto cleanup;
    }

    if(setupContextForAlgorithm(pctx, algorithm) != 0) {
        JWT_REPORT_ERROR("EVP_DigestVerifyInit() failed");
        ERR_print_errors_fp(stderr);
        result = JWT_RESULT_UNEXPECTED_ERROR;
        goto cleanup;
    }

    if(EVP_DigestVerifyUpdate(ctx, input.data, input.length) <= 0) {
        ERR_print_errors_fp(stderr);
        result = JWT_RESULT_UNEXPECTED_ERROR;
        goto cleanup;
    }


    if(key->type == JWT_KEY_TYPE_ELLIPTIC_CURVE) {

        ECDSA_SIG sig = {};

        size_t length = signature.length / 2;
        sig.r = BN_bin2bn(signature.data, length, nullptr);
        sig.s = BN_bin2bn(signature.data + length, length, nullptr);

        uint8_t realSig[512] = {};
        uint8_t* realSigPtr = realSig;

        size_t sigLength = i2d_ECDSA_SIG(&sig, nullptr);
        if(sigLength > 512) {
            result = JWT_RESULT_UNEXPECTED_ERROR;
            goto cleanup;
        }
        i2d_ECDSA_SIG(&sig, &realSigPtr);
        
        BN_free(sig.r);
        BN_free(sig.s);

        if(EVP_DigestVerifyFinal(ctx, realSig, sigLength) <= 0) {
            ERR_print_errors_fp(stderr);
            result = JWT_RESULT_VERIFICATION_FAILED;
        }

    } else {    

        if(EVP_DigestVerifyFinal(ctx, signature.data, signature.length) <= 0) {
            ERR_print_errors_fp(stderr);
            result = JWT_RESULT_VERIFICATION_FAILED;
        }
    }

cleanup:
    EVP_MD_free(md);
    EVP_MD_CTX_destroy(ctx);

    return result;
}


