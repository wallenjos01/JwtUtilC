/**
 * Josh Wallentine
 * Created 11/11/25
 * Modified 11/11/25
 *
 * Partial implementation of algorithm.hpp
 * See also algorithm.cpp, algorithm_b64url.cpp, algorithm_hmac.cpp, algorithm_enc.cpp
*/

#include "algorithm.hpp"
#include "util.hpp"

#include <jwt/key.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>

namespace {

int32_t setupContextForAlgorithm(EVP_PKEY_CTX* keyContext,
                                 JwtAlgorithm algorithm) {

    switch (algorithm) {
    case JWT_ALGORITHM_RS256:
    case JWT_ALGORITHM_RS384:
    case JWT_ALGORITHM_RS512:
        if(EVP_PKEY_CTX_set_rsa_padding(keyContext, RSA_PKCS1_PADDING) <= 0) return -1;
        break;
    case JWT_ALGORITHM_ES256:
    case JWT_ALGORITHM_ES384:
    case JWT_ALGORITHM_ES512:
        break;
    case JWT_ALGORITHM_PS256:
    case JWT_ALGORITHM_PS384:
    case JWT_ALGORITHM_PS512:
        if(EVP_PKEY_CTX_set_rsa_padding(keyContext, RSA_PKCS1_PSS_PADDING) <= 0) return -1;
        break;
    default:
        return -1; // Unsupported algorithm for PKEY
    }

    return 0;
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


int32_t jwt::sig::generate(Span<uint8_t> input, JwtKey* key,
                               JwtAlgorithm algorithm, Span<uint8_t> output,
                               size_t* sigLength) {
 
    if (input.length == 0 || input.data == nullptr) {
        return 0;
    }
    if (key->keyData == nullptr || key->type == JWT_KEY_TYPE_OCTET_SEQUENCE) {
        return -1;
    }

    size_t requiredLen = 0;
    int32_t result = 0;

    const char* digest = getDigestForAlgorithm(algorithm);
    if (digest == nullptr) {
        std::cerr << "Unable to find digest\n";
        return -2;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_MD* md = EVP_MD_fetch(nullptr, digest, nullptr);

    EVP_PKEY* pkey = static_cast<EVP_PKEY*>(key->keyData);
    EVP_PKEY_CTX* pctx = nullptr;

    if(EVP_DigestSignInit(ctx, &pctx, md, nullptr, pkey) <= 0) {
        ERR_print_errors_fp(stderr);
        result = -3;
        goto cleanup;
    }

    if(setupContextForAlgorithm(pctx, algorithm) != 0) {
        ERR_print_errors_fp(stderr);
        result = -4;
        goto cleanup;
    }

    if(EVP_DigestSignUpdate(ctx, input.data, input.length) <= 0) {
        ERR_print_errors_fp(stderr);
        result = -5;
        goto cleanup;
    }

    if(EVP_DigestSignFinal(ctx, nullptr, &requiredLen) <= 0) {
        ERR_print_errors_fp(stderr);
        result = -6;
        goto cleanup;
    }

    if(sigLength) *sigLength = requiredLen;

    if(output.data == nullptr) {
        goto cleanup;
    }

    if(output.length < requiredLen) {
        ERR_print_errors_fp(stderr);
        result = -7;
        goto cleanup;
    }

    if(EVP_DigestSignFinal(ctx, output.data, &requiredLen) <= 0) {
        ERR_print_errors_fp(stderr);
        result = -8;
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

int32_t jwt::sig::validate(Span<uint8_t> input, Span<uint8_t> signature, 
                          JwtKey* key, JwtAlgorithm algorithm) {

    if (input.length == 0 || input.data == nullptr) {
        return 0;
    }
    if (key->keyData == nullptr || key->type == JWT_KEY_TYPE_OCTET_SEQUENCE) {
        return -1;
    }

    int32_t result = 0;
    const char* digest = getDigestForAlgorithm(algorithm);
    if (digest == nullptr) {
        std::cerr << "Unable to find digest\n";
        return -2;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_MD* md = EVP_MD_fetch(nullptr, digest, nullptr);

    EVP_PKEY* pkey = static_cast<EVP_PKEY*>(key->keyData);
    EVP_PKEY_CTX* pctx = nullptr;

    if(EVP_DigestVerifyInit(ctx, &pctx, md, nullptr, pkey) <= 0) {
        ERR_print_errors_fp(stderr);
        result = -3;
        goto cleanup;
    }

    if(setupContextForAlgorithm(pctx, algorithm) != 0) {
        ERR_print_errors_fp(stderr);
        result = -4;
        goto cleanup;
    }

    if(EVP_DigestVerifyUpdate(ctx, input.data, input.length) <= 0) {
        ERR_print_errors_fp(stderr);
        result = -5;
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
            result = -6;
            goto cleanup;
        }
        i2d_ECDSA_SIG(&sig, &realSigPtr);
        
        BN_free(sig.r);
        BN_free(sig.s);

        if(EVP_DigestVerifyFinal(ctx, realSig, sigLength) <= 0) {
            ERR_print_errors_fp(stderr);
            result = 1;
        }

    } else {    

        if(EVP_DigestVerifyFinal(ctx, signature.data, signature.length) <= 0) {
            ERR_print_errors_fp(stderr);
            result = 1;
        }
    }

cleanup:
    EVP_MD_free(md);
    EVP_MD_CTX_destroy(ctx);

    return result;
}


