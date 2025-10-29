/**
 * Josh Wallentine
 * Created 10/3/25
 * Modified 10/4/25
 *
 * Partial implementation of key.hpp
 * See also key.cpp, key_ec.cpp
 */

#include <cstdio>
#include <jwt/key.h>

#include "algorithm.hpp"
#include "jwt/core.h"
#include "key.hpp"
#include "util.hpp"

#include <string>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/rsa.h>

namespace {

struct RsaFactors {
    BIGNUM** allocation;
    std::string* names;
    size_t numPrimes;

    RsaFactors(size_t num)
        : allocation(new BIGNUM*[num * 3]), names(new std::string[num * 3]),
          numPrimes(num) {

        for (auto i = 0; i < numPrimes; i++) {
            names[i] = "rsa-factor" + std::to_string(i + 1);
            names[i + numPrimes] = "rsa-exponent" + std::to_string(i + 1);
            names[i + (2 * numPrimes)] =
                "rsa-coefficient" + std::to_string(i + 1);
        }
    }

    ~RsaFactors() {

        for (auto i = 0; i < numPrimes * 3; i++) {
            if (allocation[i]) {
                BN_free(allocation[i]);
            }
        }

        delete[] allocation;
        delete[] names;
    }

    BIGNUM* getPrime(size_t index) { return allocation[index]; }
    BIGNUM* getExponent(size_t index) { return allocation[index + numPrimes]; }
    BIGNUM* getCoefficient(size_t index) {
        return allocation[index + (numPrimes * 2)];
    }

    int32_t decode(JwtString b64, size_t absoluteIndex) {
        Span<uint8_t> s = {};
        CHECK(jwt::b64url::decodeNew(b64.data, b64.length, &s), -1);
        allocation[absoluteIndex] = BN_bin2bn(s.data, s.length, nullptr);
        return 0;
    }

    int32_t decodePrime(JwtString b64, size_t index) {
        return decode(b64, index);
    }

    int32_t decodeExponent(JwtString b64, size_t index) {
        return decode(b64, index + numPrimes);
    }

    int32_t decodeCoefficient(JwtString b64, size_t index) {
        return decode(b64, index + (2 * numPrimes));
    }

    const std::string& getPrimeName(size_t index) { return names[index]; }
    const std::string& getExponentName(size_t index) {
        return names[index + numPrimes];
    }
    const std::string& getCoefficientName(size_t index) {
        return names[index + (numPrimes * 2)];
    }
};

} // namespace

JwtKeyParseResult jwt::parseRsaKey(JwtKey* key, JwtJsonObject* obj) {

    // TODO: Pad these numbers when converting from Base64
    JwtString nB64 = jwtJsonObjectGetString(obj, "n"); // Modulus
    JwtString eB64 = jwtJsonObjectGetString(obj, "e"); // Exponent

    // Required params
    if (nB64.data == nullptr || eB64.data == nullptr) {
        return JWT_KEY_PARSE_RESULT_MISSING_REQURIED_PARAM;
    }

    JwtString dB64 = jwtJsonObjectGetString(obj, "d"); // Private Exponent

    JwtString pB64 = jwtJsonObjectGetString(obj, "p"); // First Prime Factor
    JwtString qB64 = jwtJsonObjectGetString(obj, "q"); // Second Prime Factor

    // If one is present, both must be
    if ((pB64.data == nullptr) != (qB64.data == nullptr)) {
        return JWT_KEY_PARSE_RESULT_MISSING_REQURIED_PARAM;
    }

    JwtString dpB64 =
        jwtJsonObjectGetString(obj, "dp"); // First Factor Exponent
    JwtString dqB64 =
        jwtJsonObjectGetString(obj, "dq"); // Second Factor Exponent

    JwtString qiB64 =
        jwtJsonObjectGetString(obj, "qi"); // Second Factor Coefficient

    size_t numPrimes = pB64.data ? 2 : 0;

    JwtJsonArray oth = jwtJsonObjectGetArray(obj, "oth");
    if (numPrimes == 0 && oth.head != nullptr) {
        return JWT_KEY_PARSE_RESULT_MISSING_REQURIED_PARAM;
    }

    // If any prime factors are present, then this is a private key and d must
    // be present
    if (numPrimes > 0 && dB64.data == nullptr) {
        return JWT_KEY_PARSE_RESULT_MISSING_REQURIED_PARAM;
    }

    RsaFactors factors = RsaFactors(numPrimes);
    if (numPrimes > 0) {

        CHECK(factors.decodePrime(pB64, 0),
              JWT_KEY_PARSE_RESULT_BASE64_DECODE_FAILED)
        CHECK(factors.decodePrime(qB64, 1),
              JWT_KEY_PARSE_RESULT_BASE64_DECODE_FAILED)

        if (dpB64.data) {
            CHECK(factors.decodeExponent(dpB64, 0),
                  JWT_KEY_PARSE_RESULT_BASE64_DECODE_FAILED)
        }
        if (dqB64.data) {
            CHECK(factors.decodeExponent(dqB64, 1),
                  JWT_KEY_PARSE_RESULT_BASE64_DECODE_FAILED)
        }

        if (qiB64.data) {
            CHECK(factors.decodeCoefficient(qiB64, 1),
                  JWT_KEY_PARSE_RESULT_BASE64_DECODE_FAILED);
        }

        for (auto i = 0; i < oth.size; i++) {

            size_t index = i + 2;
            if (index > 9)
                break;

            numPrimes++;

            JwtJsonObject other = jwtJsonArrayGetObject(&oth, i);
            JwtString orB64 = jwtJsonObjectGetString(&other, "r"); // Factor
            JwtString odB64 = jwtJsonObjectGetString(&other, "d"); // Exponent
            JwtString otB64 =
                jwtJsonObjectGetString(&other, "t"); // Coefficient

            if (orB64.data == nullptr || odB64.data == nullptr ||
                otB64.data == nullptr) {

                return JWT_KEY_PARSE_RESULT_MISSING_REQURIED_PARAM;
            }

            CHECK(factors.decodePrime(orB64, index),
                  JWT_KEY_PARSE_RESULT_BASE64_DECODE_FAILED);
            CHECK(factors.decodeExponent(odB64, index),
                  JWT_KEY_PARSE_RESULT_BASE64_DECODE_FAILED);
            CHECK(factors.decodeCoefficient(otB64, index),
                  JWT_KEY_PARSE_RESULT_BASE64_DECODE_FAILED);
        }
    }

    Span<uint8_t> nd = {};
    Span<uint8_t> ed = {};
    Span<uint8_t> dd = {};
    CHECK(jwt::b64url::decodeNew(nB64.data, nB64.length, &nd),
          JWT_KEY_PARSE_RESULT_BASE64_DECODE_FAILED);
    CHECK(jwt::b64url::decodeNew(eB64.data, eB64.length, &ed),
          JWT_KEY_PARSE_RESULT_BASE64_DECODE_FAILED);

    if (dB64.data) {
        CHECK(jwt::b64url::decodeNew(dB64.data, dB64.length, &dd),
              JWT_KEY_PARSE_RESULT_BASE64_DECODE_FAILED);
    }

    BIGNUM* n = BN_bin2bn(nd.data, nd.length, nullptr);
    BIGNUM* e = BN_bin2bn(ed.data, ed.length, nullptr);
    BIGNUM* d;
    if (dd.data) {
        d = BN_bin2bn(dd.data, dd.length, nullptr);
    }

    OSSL_PARAM_BLD* paramBuilder = OSSL_PARAM_BLD_new();

    OSSL_PARAM_BLD_push_BN(paramBuilder, "n", n);
    OSSL_PARAM_BLD_push_BN(paramBuilder, "e", e);
    if (d) {
        OSSL_PARAM_BLD_push_BN(paramBuilder, "d", d);
    }

    size_t paramIndex = 3;
    for (auto i = 0; i < numPrimes; i++) {
        BIGNUM* prime = factors.getPrime(i);
        BIGNUM* exponent = factors.getExponent(i);
        BIGNUM* coefficient = factors.getCoefficient(i);

        if (prime) {
            OSSL_PARAM_BLD_push_BN(paramBuilder,
                                   factors.getPrimeName(i).c_str(), prime);
        }
        if (exponent) {
            OSSL_PARAM_BLD_push_BN(
                paramBuilder, factors.getExponentName(i).c_str(), exponent);
        }
        if (i != 0 && coefficient) {
            OSSL_PARAM_BLD_push_BN(paramBuilder,
                                   factors.getCoefficientName(i).c_str(),
                                   coefficient);
        }
    }

    OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(paramBuilder);
    OSSL_PARAM_BLD_free(paramBuilder);
    BN_free(n);
    BN_free(e);
    BN_free(d);

    int selection =
        dB64.data != nullptr ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY;

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);
    if (ctx == nullptr) {
        return JWT_KEY_PARSE_RESULT_UNEXPECTED_ERROR;
    }

    JwtKeyParseResult result = JWT_KEY_PARSE_RESULT_SUCCESS;

    EVP_PKEY_fromdata_init(ctx);
    EVP_PKEY** pkey = reinterpret_cast<EVP_PKEY**>(&key->keyData);
    if (EVP_PKEY_fromdata(ctx, pkey, selection, params) != 1) {
        ERR_print_errors_fp(stderr);
        result = JWT_KEY_PARSE_RESULT_KEY_CREATE_FAILED;
    }

    OSSL_PARAM_free(params);
    EVP_PKEY_CTX_free(ctx);

    return result;
}
