/**
 * Josh Wallentine
 * Created 10/3/25
 * Modified 11/12/25
 *
 * Partial implementation of key.hpp
 * See also key.cpp, key_rsa.cpp
 */

#include "algorithm.hpp"
#include "hash.hpp"
#include "jwt/core.h"
#include "key.hpp"
#include "util.hpp"

#include <jwt/json.h>
#include <jwt/key.h>
#include <jwt/result.h>

#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/param_build.h>
#include <openssl/params.h>


namespace {

constexpr size_t COORD_LEN[3] = {32, 48, 66};

const char* getCurveName(JwtEcCurve curve) {
    switch (curve) {
    case JWT_EC_CURVE_P256:
        return "P-256";
    case JWT_EC_CURVE_P384:
        return "P-384";
    case JWT_EC_CURVE_P521:
        return "P-521";
    default:
        return nullptr;
    }
}

int32_t getCurveNid(JwtEcCurve curve) {
    switch(curve) {
        case JWT_EC_CURVE_P256: return NID_X9_62_prime256v1;
        case JWT_EC_CURVE_P384: return NID_secp384r1;
        case JWT_EC_CURVE_P521: return NID_secp521r1;
    }
    return -1;
}

} // namespace

JwtResult jwtCurveParse(JwtEcCurve* curve, JwtString str) {

    size_t hash = hashString(str.data, str.length);
    switch (hash) {
        case hashCString("p256"):
        case hashCString("P-256"):
        case hashCString("prime256v1"):
            *curve = JWT_EC_CURVE_P256;
            return JWT_RESULT_SUCCESS;
        case hashCString("p384"):
        case hashCString("P-384"):
        case hashCString("secp384r1"):
            *curve = JWT_EC_CURVE_P384;
            return JWT_RESULT_SUCCESS;
        case hashCString("p521"):
        case hashCString("P-521"):
        case hashCString("secp521r1"):
            *curve = JWT_EC_CURVE_P521;
            return JWT_RESULT_SUCCESS;
        default:
            return JWT_RESULT_UNKNOWN_CURVE;
    }
}

JwtResult jwt::parseEcKey(JwtKey* key, JwtJsonObject* obj) {


    JwtString crv = jwtJsonObjectGetString(obj, "crv");
    if (crv.data == nullptr) {
        return JWT_RESULT_MISSING_REQUIRED_KEY_PARAM;
    }

    JwtEcCurve curve = JWT_EC_CURVE_P256;
    JWT_CHECK(jwtCurveParse(&curve, crv));

    JwtString xB64 = jwtJsonObjectGetString(obj, "x");
    JwtString yB64 = jwtJsonObjectGetString(obj, "y");
    if (xB64.data == nullptr || yB64.data == nullptr) {
        return JWT_RESULT_MISSING_REQUIRED_KEY_PARAM;
    }

    JwtString dB64 = jwtJsonObjectGetString(obj, "d");

    Span<uint8_t> xs = {};
    Span<uint8_t> ys = {};
    Span<uint8_t> ds = {};

    BIGNUM* d = nullptr;

    JWT_CHECK(jwt::b64url::decodeNew(xB64.data, xB64.length, &xs));
    JWT_CHECK(jwt::b64url::decodeNew(yB64.data, yB64.length, &ys));

    if (dB64.data) {
        JWT_CHECK(jwt::b64url::decodeNew(dB64.data, dB64.length, &ds));
    }

    size_t coordLen = COORD_LEN[curve];
    if(xs.length != coordLen || ys.length != coordLen) {
        return JWT_RESULT_INVALID_COORDINATE_LENGTH;
    }

    size_t keyLen = (coordLen * 2) + 1;
    Span<uint8_t> publicKey(new uint8_t[keyLen], keyLen);
    publicKey[0] = 4;
    memcpy(publicKey.data + 1, xs.data, xs.length);
    memcpy(publicKey.data + 1 + coordLen, ys.data, ys.length);

    if (ds.data) {
        d = BN_bin2bn(ds.data, ds.length, nullptr);
    }
    const char* curveName = getCurveName(curve);

    OSSL_PARAM_BLD* paramBuilder = OSSL_PARAM_BLD_new();

    OSSL_PARAM_BLD_push_utf8_string(paramBuilder, OSSL_PKEY_PARAM_GROUP_NAME,
                                    curveName, strlen(curveName));
    OSSL_PARAM_BLD_push_octet_string(paramBuilder, OSSL_PKEY_PARAM_PUB_KEY, publicKey.data, publicKey.length);

    if (d) {
        OSSL_PARAM_BLD_push_BN(paramBuilder, OSSL_PKEY_PARAM_PRIV_KEY, d);
    }

    OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(paramBuilder);
    OSSL_PARAM_BLD_free(paramBuilder);
    BN_free(d);

    JwtResult result = JWT_RESULT_SUCCESS;

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    if (ctx == nullptr) {
        JWT_REPORT_ERROR("EVP_PKEY_CTX_new_from_name() failed");
        ERR_print_errors_fp(stderr);
        OSSL_PARAM_free(params);
        return JWT_RESULT_UNEXPECTED_ERROR;
    }

    int selection = EVP_PKEY_PUBLIC_KEY;
    if(dB64.data != nullptr) {
        selection = EVP_PKEY_KEYPAIR;
        key->isPrivateKey = true;
    }

    EVP_PKEY** pkey = reinterpret_cast<EVP_PKEY**>(&key->keyData);
    EVP_PKEY_fromdata_init(ctx);
    if (EVP_PKEY_fromdata(ctx, pkey, selection, params) != 1) {
        JWT_REPORT_ERROR("EVP_PKEY_fromdata() failed");
        ERR_print_errors_fp(stderr);
        result = JWT_RESULT_KEY_CREATE_FAILED;
    }

    OSSL_PARAM_free(params);
    EVP_PKEY_CTX_free(ctx);
    return result;
}

JwtResult jwt::writeEcKey(JwtKey *key, JwtJsonObject *obj) {

    JwtResult result = JWT_RESULT_SUCCESS;
    EVP_PKEY* pkey = static_cast<EVP_PKEY*>(key->keyData);
    int selection = key->isPrivateKey ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY;

    JwtEcCurve curve;
    JWT_CHECK(jwt::getKeyCurve(key, &curve));
    jwtJsonObjectSetString(obj, "crv", getCurveName(curve));

    JWT_CHECK(writeBnToObject(obj, pkey, OSSL_PKEY_PARAM_EC_PUB_X, "x", JWT_RESULT_MISSING_REQUIRED_KEY_PARAM));
    JWT_CHECK(writeBnToObject(obj, pkey, OSSL_PKEY_PARAM_EC_PUB_Y, "y", JWT_RESULT_MISSING_REQUIRED_KEY_PARAM));

    if(key->isPrivateKey) {
        JWT_CHECK(writeBnToObject(obj, pkey, OSSL_PKEY_PARAM_PRIV_KEY, "d", JWT_RESULT_MISSING_REQUIRED_KEY_PARAM));
    }

    return JWT_RESULT_SUCCESS;
}


JwtResult jwtKeyGenerateEc(JwtKey* key, JwtEcCurve curve) {

    EVP_PKEY* pkey = EVP_EC_gen(getCurveName(curve));
    if(pkey == nullptr) {
        return JWT_RESULT_ILLEGAL_ARGUMENT;
    }

    key->keyData = pkey;
    key->type = JWT_KEY_TYPE_ELLIPTIC_CURVE;
    key->isPrivateKey = true;

    return JWT_RESULT_SUCCESS;

}
