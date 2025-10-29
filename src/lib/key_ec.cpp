/**
 * Josh Wallentine
 * Created 10/3/25
 * Modified 10/27/25
 *
 * Partial implementation of key.hpp
 * See also key.cpp, key_rsa.cpp
 */

#include <jwt/json.h>
#include <jwt/key.h>
#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/param_build.h>
#include <openssl/params.h>

#include "algorithm.hpp"
#include "hash.hpp"
#include "key.hpp"
#include "util.hpp"

namespace {

enum Curve { P256 = 0, P384 = 1, P521 = 2 };

constexpr size_t COORD_LEN[3] = {32, 48, 66};

int32_t parseCurve(Curve* curve, JwtString str) {

    size_t hash = hashString(str.data, str.length);
    switch (hash) {
    case hashCString("p256"):
    case hashCString("P-256"):
        *curve = P256;
        return 0;
    case hashCString("p384"):
    case hashCString("P-384"):
        *curve = P384;
        return 0;
    case hashCString("p521"):
    case hashCString("P-521"):
        *curve = P521;
        return 0;
    default:
        return 1;
    }
}

const char* getCurveName(Curve curve) {
    switch (curve) {
    case P256:
        return "P-256";
    case P384:
        return "P-384";
    case P521:
        return "P-521";
    default:
        return nullptr;
    }
}

int32_t getCurveNid(Curve curve) {
    switch(curve) {
        case P256: return NID_X9_62_prime256v1;
        case P384: return NID_secp384r1;
        case P521: return NID_secp521r1;
    }
    return -1;
}

} // namespace

JwtKeyParseResult jwt::parseEcKey(JwtKey* key, JwtJsonObject* obj) {


    JwtString crv = jwtJsonObjectGetString(obj, "crv");
    if (crv.data == nullptr) {
        return JWT_KEY_PARSE_RESULT_MISSING_REQURIED_PARAM;
    }

    Curve curve;
    if (parseCurve(&curve, crv) != 0) {
        return JWT_KEY_PARSE_RESULT_UNKNOWN_CURVE;
    }

    JwtString xB64 = jwtJsonObjectGetString(obj, "x");
    JwtString yB64 = jwtJsonObjectGetString(obj, "y");
    if (xB64.data == nullptr || yB64.data == nullptr) {
        return JWT_KEY_PARSE_RESULT_MISSING_REQURIED_PARAM;
    }

    JwtString dB64 = jwtJsonObjectGetString(obj, "d");

    Span<uint8_t> xs = {};
    Span<uint8_t> ys = {};
    Span<uint8_t> ds = {};

    //BIGNUM* x;
    //BIGNUM* y;
    BIGNUM* d;

    CHECK(jwt::b64url::decodeNew(xB64.data, xB64.length, &xs),
          JWT_KEY_PARSE_RESULT_BASE64_DECODE_FAILED);
    CHECK(jwt::b64url::decodeNew(yB64.data, yB64.length, &ys),
          JWT_KEY_PARSE_RESULT_BASE64_DECODE_FAILED);

    if (dB64.data) {
        CHECK(jwt::b64url::decodeNew(dB64.data, dB64.length, &ds),
              JWT_KEY_PARSE_RESULT_BASE64_DECODE_FAILED);
    }

    size_t coordLen = COORD_LEN[curve];
    if(xs.length != coordLen || ys.length != coordLen) {
        return JWT_KEY_PARSE_RESULT_KEY_CREATE_FAILED;
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

    JwtKeyParseResult result = JWT_KEY_PARSE_RESULT_SUCCESS;

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    if (ctx == nullptr) {
        OSSL_PARAM_free(params);
        return JWT_KEY_PARSE_RESULT_UNEXPECTED_ERROR;
    }

    int selection =
        dB64.data != nullptr ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY;

    EVP_PKEY** pkey = reinterpret_cast<EVP_PKEY**>(&key->keyData);
    EVP_PKEY_fromdata_init(ctx);
    if (EVP_PKEY_fromdata(ctx, pkey, selection, params) != 1) {
        ERR_print_errors_fp(stderr);
        result = JWT_KEY_PARSE_RESULT_KEY_CREATE_FAILED;
    }

    OSSL_PARAM_free(params);
    EVP_PKEY_CTX_free(ctx);
    return result;
}
