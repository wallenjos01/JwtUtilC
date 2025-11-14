#include "../crypt.hpp"

#include <openssl/err.h>
#include <openssl/evp.h>


JwtResult jwt::crypt::AesContext::create(jwt::crypt::AesContext* out, const EVP_CIPHER* cipher) {

    out->_ctx = EVP_CIPHER_CTX_new();
    if(out->_ctx == nullptr) {
        JWT_REPORT_ERROR("EVP_CIPHER_CTX_new() failed");
        ERR_print_errors_fp(stderr);
        return JWT_RESULT_UNEXPECTED_ERROR;
    }

    out->_cipher = cipher;
    return JWT_RESULT_SUCCESS;

}

JwtResult jwt::crypt::getContextForCryptAlgorithm(JwtCryptAlgorithm alg, AesContext* ctx) {
    switch(alg) {
        case JWT_CRYPT_ALGORITHM_A128CBC_HS256:
            return AesContext::create(ctx, EVP_aes_128_cbc());
        case JWT_CRYPT_ALGORITHM_A192CBC_HS384:
            return AesContext::create(ctx, EVP_aes_192_cbc());
        case JWT_CRYPT_ALGORITHM_A256CBC_HS512:
            return AesContext::create(ctx, EVP_aes_256_cbc());

        case JWT_CRYPT_ALGORITHM_A128GCM:
            return AesContext::create(ctx, EVP_aes_128_gcm());
        case JWT_CRYPT_ALGORITHM_A192GCM:
            return AesContext::create(ctx, EVP_aes_192_gcm());
        case JWT_CRYPT_ALGORITHM_A256GCM:
            return AesContext::create(ctx, EVP_aes_256_gcm());

        default:
            return JWT_RESULT_INVALID_ALGORITHM;

    }

    return JWT_RESULT_SUCCESS;
}

JwtResult jwt::crypt::AesContext::cipher(Span<uint8_t> input, Span<uint8_t> key, 
                                             Span<uint8_t> iv, Span<uint8_t>* output, CipherMode mode) {

    if(EVP_CipherInit_ex2(_ctx, _cipher, key.data, iv.data, static_cast<int32_t>(mode), nullptr) <= 0) {
        JWT_REPORT_ERROR("EVP_CipherInit_ex2() failed");
        ERR_print_errors_fp(stderr);
        return JWT_RESULT_UNEXPECTED_ERROR;
    }

    size_t blockSize = EVP_CIPHER_block_size(_cipher);
    output->data = new uint8_t[input.length + blockSize];
    output->owned = true;

    int32_t tempLength;
    int32_t finalLength = 0;
    if(EVP_CipherUpdate(_ctx, output->data, &finalLength, input.data, input.length) <= 0) {
        JWT_REPORT_ERROR("EVP_CipherUpdate() failed");
        ERR_print_errors_fp(stderr);
        return JWT_RESULT_UNEXPECTED_ERROR;
    }

    if(EVP_CipherFinal(_ctx, output->data + finalLength, &tempLength) <= 0) {
        JWT_REPORT_ERROR("EVP_CipherFinal() failed");
        ERR_print_errors_fp(stderr);
        return JWT_RESULT_UNEXPECTED_ERROR;
    }
    finalLength += tempLength;

    output->length = finalLength;
    return JWT_RESULT_SUCCESS;
}

JwtResult jwt::crypt::AesContext::cipherGcm(Span<uint8_t> input, Span<uint8_t> aad, Span<uint8_t> key, 
                                               Span<uint8_t> iv, Span<uint8_t>* output, Span<uint8_t>* tag,
                                               CipherMode mode) {

    if(EVP_CipherInit_ex2(_ctx, _cipher, key.data, iv.data, static_cast<int32_t>(mode), nullptr) <= 0) {
        JWT_REPORT_ERROR("EVP_CipherInit_ex2() failed");
        ERR_print_errors_fp(stderr);
        return JWT_RESULT_UNEXPECTED_ERROR;
    }

    if(mode == CipherMode::DECRYPT) {
        if(EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_GCM_SET_TAG, tag->length, tag->data) <= 0) {
            JWT_REPORT_ERROR("EVP_CIPHER_CTX_ctrl() failed");
            ERR_print_errors_fp(stderr);
            return JWT_RESULT_UNEXPECTED_ERROR;
        }
    }

    size_t blockSize = EVP_CIPHER_block_size(_cipher);
    output->data = new uint8_t[input.length + blockSize];
    output->owned = true;

    int32_t tempLength = 0;
    int32_t finalLength = 0;
    if(aad.length > 0) {
        if(EVP_CipherUpdate(_ctx, nullptr, &tempLength, aad.data, aad.length) <= 0) {
            JWT_REPORT_ERROR("EVP_CipherUpdate() failed");
            ERR_print_errors_fp(stderr);
            return JWT_RESULT_UNEXPECTED_ERROR;
        }
    }

    if(EVP_CipherUpdate(_ctx, output->data, &finalLength, input.data, input.length) <= 0) {
        JWT_REPORT_ERROR("EVP_CipherUpdate() failed");
        ERR_print_errors_fp(stderr);
        return JWT_RESULT_UNEXPECTED_ERROR;
    }

    if(EVP_CipherFinal(_ctx, output->data + finalLength, &tempLength) <= 0) {
        JWT_REPORT_ERROR("EVP_CipherFinal() failed");
        ERR_print_errors_fp(stderr);
        return JWT_RESULT_UNEXPECTED_ERROR;
    }
    finalLength += tempLength;
    output->length = finalLength;

    if(mode == CipherMode::ENCRYPT) {
        tag->data = new uint8_t[16];
        tag->owned = true;
        tag->length = 16;

        if(EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_GCM_GET_TAG, 16, tag->data) <= 0) {
            JWT_REPORT_ERROR("EVP_CIPHER_CTX_ctrl() failed");
            ERR_print_errors_fp(stderr);
            return JWT_RESULT_UNEXPECTED_ERROR;
        }
    }

    return JWT_RESULT_SUCCESS;
}

