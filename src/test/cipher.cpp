#include "../lib/crypt.hpp"
#include "jwt/result.h"

#include <gtest/gtest.h>
#include <openssl/evp.h>

uint8_t KEY[32] = {
    0x0b, 0xa8, 0xc1, 0xd5, 0x61, 0xd0, 0x7a, 0x0c, 0xde, 0x15, 0x23, 0x9c, 0xa5, 0xf6, 0xe1, 0x7f,
    0x89, 0x67, 0x44, 0x4b, 0x7c, 0x44, 0x77, 0x47, 0x48, 0x1f, 0x3f, 0x37, 0x49, 0x50, 0xe3, 0xc5,
};
uint8_t IV[16] = {
    0x9d, 0x90, 0xeb, 0x89, 0x88, 0x14, 0xb3, 0x4c, 0x51, 0xe8, 0xfb, 0x83, 0x08, 0x39, 0xd6, 0xe3,
};

TEST(Cipher, AES128CBC) {

    jwt::crypt::AesContext ctx = {};
    ASSERT_EQ(JWT_RESULT_SUCCESS, jwt::crypt::AesContext::create(&ctx, EVP_aes_128_cbc()));

    uint8_t inputData[13] = {};
    memcpy(inputData, "Hello, world", 13);
    Span<uint8_t> input = {};
    input.data = inputData;
    input.length = 13;

    Span<uint8_t> key = {};
    key.data = KEY;
    key.length = 16;

    Span<uint8_t> iv = {};
    iv.data = IV;
    iv.length = 16;

    Span<uint8_t> output = {};
    ASSERT_EQ(JWT_RESULT_SUCCESS, 
              ctx.cipher(input, key, iv, &output, jwt::crypt::CipherMode::ENCRYPT));

    Span<uint8_t> decrypted = {};
    ASSERT_EQ(JWT_RESULT_SUCCESS, 
              ctx.cipher(output, key, iv, &decrypted, jwt::crypt::CipherMode::DECRYPT));

    ASSERT_EQ(input.length, decrypted.length);
    ASSERT_EQ(0, memcmp(decrypted.data, input.data, input.length));

}

TEST(Cipher, AES192CBC) {

    jwt::crypt::AesContext ctx = {};
    ASSERT_EQ(JWT_RESULT_SUCCESS, jwt::crypt::AesContext::create(&ctx, EVP_aes_192_cbc()));

    uint8_t inputData[13] = {};
    memcpy(inputData, "Hello, world", 13);
    Span<uint8_t> input = {};
    input.data = inputData;
    input.length = 13;

    Span<uint8_t> key = {};
    key.data = KEY;
    key.length = 24;

    Span<uint8_t> iv = {};
    iv.data = IV;
    iv.length = 16;

    Span<uint8_t> output = {};
    ASSERT_EQ(JWT_RESULT_SUCCESS, 
              ctx.cipher(input, key, iv, &output, jwt::crypt::CipherMode::ENCRYPT));

    Span<uint8_t> decrypted = {};
    ASSERT_EQ(JWT_RESULT_SUCCESS, 
              ctx.cipher(output, key, iv, &decrypted, jwt::crypt::CipherMode::DECRYPT));

    ASSERT_EQ(input.length, decrypted.length);
    ASSERT_EQ(0, memcmp(decrypted.data, input.data, input.length));

}

TEST(Cipher, AES256CBC) {

    jwt::crypt::AesContext ctx = {};
    ASSERT_EQ(JWT_RESULT_SUCCESS, jwt::crypt::AesContext::create(&ctx, EVP_aes_256_cbc()));

    uint8_t inputData[13] = {};
    memcpy(inputData, "Hello, world", 13);
    Span<uint8_t> input = {};
    input.data = inputData;
    input.length = 13;

    Span<uint8_t> key = {};
    key.data = KEY;
    key.length = 32;

    Span<uint8_t> iv = {};
    iv.data = IV;
    iv.length = 16;

    Span<uint8_t> output = {};
    ASSERT_EQ(JWT_RESULT_SUCCESS, 
              ctx.cipher(input, key, iv, &output, jwt::crypt::CipherMode::ENCRYPT));

    Span<uint8_t> decrypted = {};
    ASSERT_EQ(JWT_RESULT_SUCCESS, 
              ctx.cipher(output, key, iv, &decrypted, jwt::crypt::CipherMode::DECRYPT));

    ASSERT_EQ(input.length, decrypted.length);
    ASSERT_EQ(0, memcmp(decrypted.data, input.data, input.length));

}



TEST(Cipher, AES128GCM) {

    jwt::crypt::AesContext ctx = {};
    ASSERT_EQ(JWT_RESULT_SUCCESS, jwt::crypt::AesContext::create(&ctx, EVP_aes_128_gcm()));

    uint8_t inputData[13] = {};
    memcpy(inputData, "Hello, world", 13);
    Span<uint8_t> input = {};
    input.data = inputData;
    input.length = 13;

    uint8_t aadData[5] = {};
    memcpy(aadData, "12345", 5);
    Span<uint8_t> aad = {};
    aad.data = aadData;
    aad.length = 5;

    Span<uint8_t> key = {};
    key.data = KEY;
    key.length = 16;

    Span<uint8_t> iv = {};
    iv.data = IV;
    iv.length = 16;

    Span<uint8_t> output = {};
    Span<uint8_t> tag = {};
    ASSERT_EQ(JWT_RESULT_SUCCESS, 
              ctx.cipherGcm(input, aad, key, iv, &output, &tag, jwt::crypt::CipherMode::ENCRYPT));

    Span<uint8_t> decrypted = {};
    ASSERT_EQ(JWT_RESULT_SUCCESS, 
              ctx.cipherGcm(output, aad, key, iv, &decrypted, &tag, jwt::crypt::CipherMode::DECRYPT));

    ASSERT_EQ(input.length, decrypted.length);
    ASSERT_EQ(0, memcmp(decrypted.data, input.data, input.length));

}

TEST(Cipher, AES192GCM) {

    jwt::crypt::AesContext ctx = {};
    ASSERT_EQ(JWT_RESULT_SUCCESS, jwt::crypt::AesContext::create(&ctx, EVP_aes_192_gcm()));

    uint8_t inputData[13] = {};
    memcpy(inputData, "Hello, world", 13);
    Span<uint8_t> input = {};
    input.data = inputData;
    input.length = 13;

    uint8_t aadData[5] = {};
    memcpy(aadData, "12345", 5);
    Span<uint8_t> aad = {};
    aad.data = aadData;
    aad.length = 5;

    Span<uint8_t> key = {};
    key.data = KEY;
    key.length = 24;

    Span<uint8_t> iv = {};
    iv.data = IV;
    iv.length = 16;

    Span<uint8_t> output = {};
    Span<uint8_t> tag = {};
    ASSERT_EQ(JWT_RESULT_SUCCESS, 
              ctx.cipherGcm(input, aad, key, iv, &output, &tag, jwt::crypt::CipherMode::ENCRYPT));

    Span<uint8_t> decrypted = {};
    ASSERT_EQ(JWT_RESULT_SUCCESS, 
              ctx.cipherGcm(output, aad, key, iv, &decrypted, &tag, jwt::crypt::CipherMode::DECRYPT));

    ASSERT_EQ(input.length, decrypted.length);
    ASSERT_EQ(0, memcmp(decrypted.data, input.data, input.length));

}
TEST(Cipher, AES256GCM) {

    jwt::crypt::AesContext ctx = {};
    ASSERT_EQ(JWT_RESULT_SUCCESS, jwt::crypt::AesContext::create(&ctx, EVP_aes_256_gcm()));

    uint8_t inputData[13] = {};
    memcpy(inputData, "Hello, world", 13);
    Span<uint8_t> input = {};
    input.data = inputData;
    input.length = 13;

    uint8_t aadData[5] = {};
    memcpy(aadData, "12345", 5);
    Span<uint8_t> aad = {};
    aad.data = aadData;
    aad.length = 5;

    Span<uint8_t> key = {};
    key.data = KEY;
    key.length = 32;

    Span<uint8_t> iv = {};
    iv.data = IV;
    iv.length = 16;

    Span<uint8_t> output = {};
    Span<uint8_t> tag = {};
    ASSERT_EQ(JWT_RESULT_SUCCESS, 
              ctx.cipherGcm(input, aad, key, iv, &output, &tag, jwt::crypt::CipherMode::ENCRYPT));

    Span<uint8_t> decrypted = {};
    ASSERT_EQ(JWT_RESULT_SUCCESS, 
              ctx.cipherGcm(output, aad, key, iv, &decrypted, &tag, jwt::crypt::CipherMode::DECRYPT));

    ASSERT_EQ(input.length, decrypted.length);
    ASSERT_EQ(0, memcmp(decrypted.data, input.data, input.length));

}
