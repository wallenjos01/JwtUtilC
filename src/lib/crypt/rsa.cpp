#include "../crypt.hpp"

#include <openssl/err.h>
#include <openssl/evp.h>

JwtResult jwt::crypt::RsaContext::init(jwt::crypt::RsaContext* out, EVP_PKEY *pkey) {

    out->_pkey = pkey;
    out->_ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, pkey, nullptr);
    if(out->_ctx == nullptr) {
        JWT_REPORT_ERROR("EVP_PKEX_CTX_new_from_pkey() failed");
        ERR_print_errors_fp(stderr);
        return JWT_RESULT_UNEXPECTED_ERROR;
    }

    return JWT_RESULT_SUCCESS;
}

JwtResult jwt::crypt::RsaContext::sign(Span<uint8_t> input, const char* digest, Span<uint8_t>* signature, const OSSL_PARAM* params) {

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

    if(params != nullptr && EVP_PKEY_CTX_set_params(_ctx, params) <= 0) {
        JWT_REPORT_ERROR("EVP_PKEX_CTX_set_params() failed");
        ERR_print_errors_fp(stderr);
        return JWT_RESULT_UNEXPECTED_ERROR;
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

    EVP_MD_free(md);
    EVP_MD_CTX_free(ctx);

    return result;
}

JwtResult jwt::crypt::RsaContext::verify(Span<uint8_t> input, const char* digest, Span<uint8_t> signature, const OSSL_PARAM* params) {

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

    if(params != nullptr && EVP_PKEY_CTX_set_params(_ctx, params) <= 0) {
        JWT_REPORT_ERROR("EVP_PKEX_CTX_set_params() failed");
        ERR_print_errors_fp(stderr);
        return JWT_RESULT_UNEXPECTED_ERROR;
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

    EVP_MD_free(md);
    EVP_MD_CTX_free(ctx);

    return result;
}


JwtResult jwt::crypt::RsaContext::encrypt(Span<uint8_t> input, Span<uint8_t>* output, const OSSL_PARAM* params) {

    if(EVP_PKEY_encrypt_init_ex(_ctx, params) <= 0) {
        JWT_REPORT_ERROR("EVP_PKEY_encrypt_init() failed");
        ERR_print_errors_fp(stderr);
        return JWT_RESULT_UNEXPECTED_ERROR;
    }

    size_t cryptLength = 0;
    if(EVP_PKEY_encrypt(_ctx, nullptr, &cryptLength, input.data, input.length) <= 0) {
        JWT_REPORT_ERROR("EVP_PKEY_encrypt() failed");
        ERR_print_errors_fp(stderr);
        return JWT_RESULT_UNEXPECTED_ERROR;
    }
    *output = Span<uint8_t>::allocate(cryptLength);

    if(EVP_PKEY_encrypt(_ctx, output->data, &output->length, input.data, input.length) <= 0) {
        ERR_print_errors_fp(stderr);
        return JWT_RESULT_UNEXPECTED_ERROR;
    }

    return JWT_RESULT_SUCCESS;
}

JwtResult jwt::crypt::RsaContext::decrypt(Span<uint8_t> input, Span<uint8_t>* output, const OSSL_PARAM* params) {

    if(EVP_PKEY_decrypt_init_ex(_ctx, params) <= 0) {
        JWT_REPORT_ERROR("EVP_PKEY_decrypt_init() failed");
        ERR_print_errors_fp(stderr);
        return JWT_RESULT_UNEXPECTED_ERROR;
    }

    size_t cryptLength = 0;
    if(EVP_PKEY_decrypt(_ctx, nullptr, &cryptLength, input.data, input.length) <= 0) {
        JWT_REPORT_ERROR("EVP_PKEY_decrypt() failed");
        ERR_print_errors_fp(stderr);
        return JWT_RESULT_UNEXPECTED_ERROR;
    }
    *output = Span<uint8_t>::allocate(cryptLength);

    if(EVP_PKEY_decrypt(_ctx, output->data, &output->length, input.data, input.length) <= 0) {
        ERR_print_errors_fp(stderr);
        return JWT_RESULT_UNEXPECTED_ERROR;
    }

    return JWT_RESULT_SUCCESS;

}

