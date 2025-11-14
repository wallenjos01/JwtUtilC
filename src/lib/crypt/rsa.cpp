#include "../crypt.hpp"
#include "jwt/result.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

JwtResult jwt::crypt::RsaContext::init(jwt::crypt::RsaContext* out, EVP_PKEY *pkey) {

    out->_pkey = pkey;
    return JWT_RESULT_SUCCESS;
}

JwtResult jwt::crypt::RsaContext::sign(Span<uint8_t> input, const char* digest, Span<uint8_t>* signature, int32_t padding) {

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    size_t requiredLen = 0;
    JwtResult result = JWT_RESULT_SUCCESS;

    EVP_PKEY_CTX* pctx = nullptr;

    if(EVP_DigestSignInit_ex(ctx, &pctx, digest, nullptr, nullptr, _pkey, nullptr) <= 0) {
        JWT_REPORT_ERROR("EVP_DigestSignInit_ex() failed");
        ERR_print_errors_fp(stderr);
        result = JWT_RESULT_UNEXPECTED_ERROR;
        goto cleanup;
    }
    if(padding != 0 && EVP_PKEY_CTX_set_rsa_padding(pctx, padding) <= 0) {
        JWT_REPORT_ERROR("EVP_PKEY_CTX_set_rsa_padding() failed");
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
    }

    *signature = Span<uint8_t>::allocate(requiredLen);

    if(EVP_DigestSignFinal(ctx, signature->data, &signature->length) <= 0) {
        JWT_REPORT_ERROR("EVP_DigestSignFinal() failed");
        ERR_print_errors_fp(stderr);
        result = JWT_RESULT_UNEXPECTED_ERROR;
        goto cleanup;
    }

cleanup:

    EVP_MD_CTX_destroy(ctx);

    return result;
}

JwtResult jwt::crypt::RsaContext::verify(Span<uint8_t> input, const char* digest, Span<uint8_t> signature, int32_t padding) {

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX* pctx = nullptr;

    size_t requiredLen = 0;
    JwtResult result = JWT_RESULT_SUCCESS;

    if(EVP_DigestVerifyInit_ex(ctx, &pctx, digest, nullptr, nullptr, _pkey, nullptr) <= 0) {
        JWT_REPORT_ERROR("EVP_DigestVerifyInit_ex() failed");
        ERR_print_errors_fp(stderr);
        result = JWT_RESULT_UNEXPECTED_ERROR;
        goto cleanup;
    }
    if(padding != 0 && EVP_PKEY_CTX_set_rsa_padding(pctx, padding) <= 0) {
        JWT_REPORT_ERROR("EVP_PKEY_CTX_set_rsa_padding() failed");
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
    }

cleanup:

    EVP_MD_CTX_destroy(ctx);

    return result;
}


JwtResult jwt::crypt::RsaContext::encrypt(Span<uint8_t> input, Span<uint8_t>* output, const OSSL_PARAM* params) {

    JwtResult result = JWT_RESULT_SUCCESS;
    size_t cryptLength = 0;

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, _pkey, nullptr);
    if(ctx == nullptr) {
        JWT_REPORT_ERROR("EVP_PKEX_CTX_new_from_pkey() failed");
        ERR_print_errors_fp(stderr);
        result = JWT_RESULT_UNEXPECTED_ERROR;
        goto cleanup;
    }

    if(EVP_PKEY_encrypt_init_ex(ctx, params) <= 0) {
        JWT_REPORT_ERROR("EVP_PKEY_encrypt_init() failed");
        ERR_print_errors_fp(stderr);
        result = JWT_RESULT_UNEXPECTED_ERROR;
        goto cleanup;
    }

    if(EVP_PKEY_encrypt(ctx, nullptr, &cryptLength, input.data, input.length) <= 0) {
        JWT_REPORT_ERROR("EVP_PKEY_encrypt() failed");
        ERR_print_errors_fp(stderr);
        result = JWT_RESULT_UNEXPECTED_ERROR;
        goto cleanup;
    }
    *output = Span<uint8_t>::allocate(cryptLength);

    if(EVP_PKEY_encrypt(ctx, output->data, &output->length, input.data, input.length) <= 0) {
        JWT_REPORT_ERROR("EVP_PKEY_encrypt() failed");
        ERR_print_errors_fp(stderr);
        result = JWT_RESULT_UNEXPECTED_ERROR;
        goto cleanup; 
    }

cleanup:

    EVP_PKEY_CTX_free(ctx);
    return result; 
}

JwtResult jwt::crypt::RsaContext::decrypt(Span<uint8_t> input, Span<uint8_t>* output, const OSSL_PARAM* params) {

    JwtResult result = JWT_RESULT_SUCCESS;
    size_t cryptLength = 0;

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, _pkey, nullptr);
    if(ctx == nullptr) {
        JWT_REPORT_ERROR("EVP_PKEX_CTX_new_from_pkey() failed");
        ERR_print_errors_fp(stderr);
        result = JWT_RESULT_UNEXPECTED_ERROR;
        goto cleanup;
    }


    if(EVP_PKEY_decrypt_init_ex(ctx, params) <= 0) {
        JWT_REPORT_ERROR("EVP_PKEY_decrypt_init() failed");
        ERR_print_errors_fp(stderr);
        result = JWT_RESULT_UNEXPECTED_ERROR;
        goto cleanup;
    }

    if(EVP_PKEY_decrypt(ctx, nullptr, &cryptLength, input.data, input.length) <= 0) {
        JWT_REPORT_ERROR("EVP_PKEY_decrypt() failed");
        ERR_print_errors_fp(stderr);
        result = JWT_RESULT_UNEXPECTED_ERROR;
        goto cleanup;
    }
    *output = Span<uint8_t>::allocate(cryptLength);

    if(EVP_PKEY_decrypt(ctx, output->data, &output->length, input.data, input.length) <= 0) {
        ERR_print_errors_fp(stderr);
        result = JWT_RESULT_UNEXPECTED_ERROR;
        goto cleanup;
    }

cleanup:

    EVP_PKEY_CTX_free(ctx);
    return result; 

}

