#include "../crypt.hpp"
#include "jwt/result.h"

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/param_build.h>

extern "C" {

// This is in a private OpenSSL header, but all other methods to get these
// numbers for an EC signature are deprecated.
typedef struct ECDSA_SIG_st {
    BIGNUM* r;
    BIGNUM* s;
} ECDSA_SIG_st;

}


JwtResult jwt::crypt::EcContext::init(EcContext* out, EVP_PKEY* pkey) {
    out->_pkey = pkey;
    out->_ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, pkey, nullptr);
    if(out->_ctx == nullptr) {
        JWT_REPORT_ERROR("EVP_PKEX_CTX_new_from_pkey() failed");
        ERR_print_errors_fp(stderr);
        return JWT_RESULT_UNEXPECTED_ERROR;
    }

    return JWT_RESULT_SUCCESS;
}

JwtResult jwt::crypt::EcContext::sign(Span<uint8_t> input, const char* digest, Span<uint8_t>* signature) {
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_MD* md = EVP_MD_fetch(nullptr, digest, nullptr);

    size_t requiredLen = 0;
    JwtResult result = JWT_RESULT_SUCCESS;

    if(EVP_DigestSignInit(ctx, &_ctx, md, nullptr, _pkey) <= 0) {
        JWT_REPORT_ERROR("EVP_DigestSignInit() failed");
        ERR_print_errors_fp(stderr);
        result = JWT_RESULT_UNEXPECTED_ERROR;
        goto cleanup;
    }

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
    } else {

        Span<uint8_t> der = Span<uint8_t>::allocate(requiredLen);

        if(EVP_DigestSignFinal(ctx, der.data, &der.length) <= 0) {
            JWT_REPORT_ERROR("EVP_DigestSignFinal() failed");
            ERR_print_errors_fp(stderr);
            result = JWT_RESULT_UNEXPECTED_ERROR;
            goto cleanup;
        }

        ECDSA_SIG* realSig = nullptr;
        const uint8_t* derBytes = der.data;
        d2i_ECDSA_SIG(&realSig, &derBytes, requiredLen);

        size_t siglen = BN_num_bytes(realSig->r);
        *signature = Span<uint8_t>::allocate(siglen * 2);

        BN_bn2binpad(realSig->r, signature->data, siglen);
        BN_bn2binpad(realSig->s, signature->data + siglen, siglen);
    }
cleanup:

    EVP_MD_free(md);
    EVP_MD_CTX_free(ctx);

    return result;
}

JwtResult jwt::crypt::EcContext::verify(Span<uint8_t> input, const char* digest, Span<uint8_t> signature) {

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_MD* md = EVP_MD_fetch(nullptr, digest, nullptr);

    size_t requiredLen;
    JwtResult result = JWT_RESULT_SUCCESS;

    if(EVP_DigestVerifyInit(ctx, &_ctx, md, nullptr, _pkey) <= 0) {
        JWT_REPORT_ERROR("EVP_DigestVerifyInit() failed");
        ERR_print_errors_fp(stderr);
        result = JWT_RESULT_UNEXPECTED_ERROR;
        goto cleanup;
    }

    if(EVP_DigestVerifyUpdate(ctx, input.data, input.length) <= 0) {
        JWT_REPORT_ERROR("EVP_DigestVerifyUpdate() failed");
        ERR_print_errors_fp(stderr);
        result = JWT_RESULT_UNEXPECTED_ERROR;
        goto cleanup;
    }

    if(EVP_DigestVerifyFinal(ctx, signature.data, signature.length) <= 0) {
        ERR_print_errors_fp(stderr);
        result = JWT_RESULT_VERIFICATION_FAILED;
        goto cleanup;
    } else {

        ECDSA_SIG sig = {};

        size_t length = signature.length / 2;
        sig.r = BN_bin2bn(signature.data, length, nullptr);
        sig.s = BN_bin2bn(signature.data + length, length, nullptr);

        size_t sigLength = i2d_ECDSA_SIG(&sig, nullptr);
        Span<uint8_t> der = Span<uint8_t>::allocate(sigLength);

        if(sigLength > 512) {
            result = JWT_RESULT_UNEXPECTED_ERROR;
            goto cleanup;
        }
        i2d_ECDSA_SIG(&sig, &der.data);
        
        BN_free(sig.r);
        BN_free(sig.s);

        if(EVP_DigestVerifyFinal(ctx, der.data, der.length) <= 0) {
            ERR_print_errors_fp(stderr);
            result = JWT_RESULT_VERIFICATION_FAILED;
        }
    }

cleanup:

    EVP_MD_free(md);
    EVP_MD_CTX_free(ctx);

    return result;
}

JwtResult jwt::crypt::EcContext::diffieHelman(EVP_PKEY* peer, size_t keyLen, Span<uint8_t>* key) {


    OSSL_PARAM_BLD* builder = OSSL_PARAM_BLD_new();
    //OSSL_PARAM_BLD_push_utf8_string(builder, OSSL_EXCHANGE_PARAM_KDF_TYPE, "X963KDF", 0);
    OSSL_PARAM_BLD_push_size_t(builder, OSSL_EXCHANGE_PARAM_KDF_OUTLEN, keyLen);

    OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(builder);
    if(EVP_PKEY_derive_init_ex(_ctx, params) <= 0) {
        JWT_REPORT_ERROR("EVP_PKEY_derive_init() failed");
        OSSL_PARAM_free(params);
        ERR_print_errors_fp(stderr);
        return JWT_RESULT_UNEXPECTED_ERROR;
    }
    OSSL_PARAM_free(params);

    if(EVP_PKEY_derive_set_peer(_ctx, peer) <= 0) {
        JWT_REPORT_ERROR("EVP_PKEY_derive_set_peer() failed");
        ERR_print_errors_fp(stderr);
        return JWT_RESULT_UNEXPECTED_ERROR;
    }

    size_t realLen = 0;
    if(EVP_PKEY_derive(_ctx, nullptr, &realLen) <= 0) {
        JWT_REPORT_ERROR("EVP_PKEY_derive() failed");
        ERR_print_errors_fp(stderr);
        return JWT_RESULT_UNEXPECTED_ERROR;
    }

    *key = Span<uint8_t>::allocate(realLen);
    if(EVP_PKEY_derive(_ctx, key->data, &key->length) <= 0) {
        JWT_REPORT_ERROR("EVP_PKEY_derive() failed");
        ERR_print_errors_fp(stderr);
        return JWT_RESULT_UNEXPECTED_ERROR;
    }

    return JWT_RESULT_SUCCESS;
}


