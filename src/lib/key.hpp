#pragma once

#include "algorithm.hpp"

#include <jwt/result.h>
#include <jwt/key.h>

#include <openssl/core.h>
#include <openssl/evp.h>

namespace jwt {

JwtResult parseRsaKey(JwtKey* key, JwtJsonObject* obj);
JwtResult parseEcKey(JwtKey* key, JwtJsonObject* obj);
JwtResult parseOctKey(JwtKey* key, JwtJsonObject* obj);

JwtResult writeRsaKey(JwtKey* key, JwtJsonObject* obj);
JwtResult writeEcKey(JwtKey* key, JwtJsonObject* obj);
JwtResult writeOctKey(JwtKey* key, JwtJsonObject* obj);

inline JwtResult writeBnToObject(JwtJsonObject* object, EVP_PKEY* pkey, const char* param, const char* key, JwtResult notPresent) {

    BIGNUM* n = nullptr;
    EVP_PKEY_get_bn_param(pkey, param, &n);
    if(n == nullptr) return notPresent;
    
    size_t numSize = BN_num_bytes(n);
    uint8_t* nBin = new uint8_t[numSize];
    BN_bn2bin(n, nBin);
    JwtString nB64 = {};
    JwtResult result = jwt::b64url::encodeString(nBin, numSize, &nB64);
    
    jwtJsonObjectSetString(object, key, nB64.data);

    BN_free(n);
    delete[] nBin;

    return result;
}

} // namespace jwt
