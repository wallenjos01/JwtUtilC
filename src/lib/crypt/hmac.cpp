#include "../crypt.hpp"

#include <openssl/err.h>
#include <openssl/evp.h>

JwtResult jwt::crypt::HmacContext::init(HmacContext* out, Span<uint8_t> key, const char* digest) {

    out->_mac = EVP_MAC_fetch(nullptr, "hmac", nullptr);
    if(out->_mac == nullptr) {
        JWT_REPORT_ERROR("EVP_MAC_fetch() failed");
        ERR_print_errors_fp(stderr);
        return JWT_RESULT_UNEXPECTED_ERROR;
    }

    out->_ctx = EVP_MAC_CTX_new(out->_mac);
    if(out->_ctx == nullptr) {
        JWT_REPORT_ERROR("EVP_MAC_CTX_new() failed");
        ERR_print_errors_fp(stderr);
        return JWT_RESULT_UNEXPECTED_ERROR;
    }

    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string("digest", const_cast<char*>(digest), 0);
    params[1] = OSSL_PARAM_construct_end();
    if (EVP_MAC_init(out->_ctx, key.data, key.length, params) <= 0) {
        JWT_REPORT_ERROR("EVP_MAC_init() failed");
        ERR_print_errors_fp(stderr);
        return JWT_RESULT_UNEXPECTED_ERROR;
    }

    return JWT_RESULT_SUCCESS;
}

JwtResult jwt::crypt::HmacContext::update(Span<uint8_t> input) {

    if(EVP_MAC_update(_ctx, input.data, input.length) <= 0) {
        JWT_REPORT_ERROR("EVP_MAC_update() failed");
        ERR_print_errors_fp(stderr);
        return JWT_RESULT_UNEXPECTED_ERROR;
    }
    return JWT_RESULT_SUCCESS;
}

JwtResult jwt::crypt::HmacContext::final(Span<uint8_t>* output) {

    size_t outSize = 0;
    if(EVP_MAC_final(_ctx, nullptr, &outSize, 0) <= 0) {
        JWT_REPORT_ERROR("EVP_MAC_final() failed");
        ERR_print_errors_fp(stderr);
        return JWT_RESULT_UNEXPECTED_ERROR;
    }

    output->data = new uint8_t[outSize];
    output->owned = true;
    
    if(EVP_MAC_final(_ctx, output->data, &outSize, outSize) <= 0) {
        JWT_REPORT_ERROR("EVP_MAC_final() failed");
        ERR_print_errors_fp(stderr);
        return JWT_RESULT_UNEXPECTED_ERROR;
    }
    output->length = outSize;

    return JWT_RESULT_SUCCESS;
}

