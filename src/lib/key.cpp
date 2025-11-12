/**
 * Josh Wallentine
 * Created 9/30/25
 * Modified 10/3/25
 *
 * Implementation of include/jwt/key.h
 * Partial implementation of key.hpp
 * See also key_ec.cpp, key_rsa.cpp
 */

#include <jwt/json.h>
#include <jwt/key.h>

#include <openssl/evp.h>
#include <openssl/params.h>

#include "algorithm.hpp"
#include "hash.hpp"
#include "key.hpp"
#include "jwt/result.h"
#include "util.hpp"

namespace {

JwtResult parseKeyType(JwtKeyType* type, JwtString str) {

    size_t hash = hashString(str.data, str.length);
    switch (hash) {
    case hashCString("EC"):
        *type = JWT_KEY_TYPE_ELLIPTIC_CURVE;
        return JWT_RESULT_SUCCESS;
    case hashCString("RSA"):
        *type = JWT_KEY_TYPE_RSA;
        return JWT_RESULT_SUCCESS;
    case hashCString("oct"):
        *type = JWT_KEY_TYPE_OCTET_SEQUENCE;
        return JWT_RESULT_SUCCESS;
    default:
        return JWT_RESULT_UNKNOWN_KEY_TYPE;
    }
}

JwtResult parseKeyUse(JwtKeyUse* use, JwtString str) {
    size_t hash = hashString(str.data, str.length);
    switch (hash) {
    case hashCString("sig"):
        *use = JWT_KEY_USE_SIGNING;
        return JWT_RESULT_SUCCESS;
    case hashCString("enc"):
        *use = JWT_KEY_USE_ENCRYPTION;
        return JWT_RESULT_SUCCESS;
    default:
        return JWT_RESULT_UNKNOWN_KEY_USE;
    }
}

JwtResult parseKeyOps(uint8_t* bitset, JwtJsonArray array) {

    for (auto i = 0; i < array.size; i++) {
        JwtJsonElement element = jwtJsonArrayGet(&array, i);
        if (element.type != JWT_JSON_ELEMENT_TYPE_STRING) {
            return JWT_RESULT_UNKNOWN_KEY_OPERATION;
        }

        JwtString str = element.string;
        size_t hash = hashString(str.data, str.length);
        switch (hash) {
        case hashCString("sign"):
            *bitset |= JWT_KEY_OP_SIGN;
            break;
        case hashCString("verify"):
            *bitset |= JWT_KEY_OP_VERIFY;
            break;
        case hashCString("encrypt"):
            *bitset |= JWT_KEY_OP_ENCRYPT;
            break;
        case hashCString("decrypt"):
            *bitset |= JWT_KEY_OP_DECRYPT;
            break;
        case hashCString("wrapKey"):
            *bitset |= JWT_KEY_OP_WRAP_KEY;
            break;
        case hashCString("unwrapKey"):
            *bitset |= JWT_KEY_OP_UNWRAP_KEY;
            break;
        case hashCString("deriveKey"):
            *bitset |= JWT_KEY_OP_DERIVE_KEY;
            break;
        case hashCString("deriveBits"):
            *bitset |= JWT_KEY_OP_DERIVE_BITS;
            break;
        default:
            return JWT_RESULT_UNKNOWN_KEY_OPERATION;
        }
    }

    return JWT_RESULT_SUCCESS;
}

} // namespace

JwtResult jwtKeyParse(JwtKey* key, JwtJsonObject* obj) {

    JwtString kty = jwtJsonObjectGetString(obj, "kty");
    if (kty.data == nullptr || parseKeyType(&key->type, kty) != 0) {
        return JWT_RESULT_UNKNOWN_KEY_TYPE;
    }

    JwtString use = jwtJsonObjectGetString(obj, "use");
    key->use = JWT_KEY_USE_UNKNOWN;
    if (use.data) {
        JWT_CHECK(parseKeyUse(&key->use, use));
    }

    JwtJsonArray keyOps = jwtJsonObjectGetArray(obj, "key_ops");
    key->operations = 0;
    if (keyOps.head) {
        JWT_CHECK(parseKeyOps(&key->operations, keyOps));
    }

    JwtString alg = jwtJsonObjectGetString(obj, "alg");
    key->algorithm = JWT_ALGORITHM_UNKNOWN;
    if (alg.data) {
        JWT_CHECK(jwtAlgorithmParse(&key->algorithm, alg.data));
    }

    switch (key->type) {
    case JWT_KEY_TYPE_ELLIPTIC_CURVE:
        return jwt::parseEcKey(key, obj);
    case JWT_KEY_TYPE_RSA:
        return jwt::parseRsaKey(key, obj);
    case JWT_KEY_TYPE_OCTET_SEQUENCE:
        return jwt::parseOctKey(key, obj);
    }

    return JWT_RESULT_SUCCESS;
}

void jwtKeyDestroy(JwtKey* key) {

    switch (key->type) {
    case JWT_KEY_TYPE_ELLIPTIC_CURVE:
    case JWT_KEY_TYPE_RSA:
        EVP_PKEY_free(static_cast<EVP_PKEY*>(key->keyData));
        return;
    case JWT_KEY_TYPE_OCTET_SEQUENCE:
        delete static_cast<Span<uint8_t>*>(key->keyData);
        return;
    }
}

JwtResult jwt::parseOctKey(JwtKey* key, JwtJsonObject* obj) {

    JwtString kB64 = jwtJsonObjectGetString(obj, "k"); // Key data
    if (kB64.data == nullptr) {
        return JWT_RESULT_MISSING_REQUIRED_KEY_PARAM;
    }

    Span<uint8_t>* k = new Span<uint8_t>();
    key->keyData = k;
    JWT_CHECK(jwt::b64url::decodeNew(kB64.data, kB64.length, k));

    return JWT_RESULT_SUCCESS;
}



JwtResult jwtKeySetParse(JwtKeySet* keySet, JwtJsonObject* obj) {

    JwtJsonElement encodedKeys = jwtJsonObjectGet(obj, "keys");
    if(encodedKeys.type != JWT_JSON_ELEMENT_TYPE_ARRAY) {
        return JWT_RESULT_NOT_A_LIST;
    }
    if(encodedKeys.array.size == 0) {
        keySet->keys = nullptr;
        keySet->count = 0;
    }

    JwtResult result = JWT_RESULT_SUCCESS;
    JwtKey* keys = new JwtKey[encodedKeys.array.size];

    for(auto i = 0 ; i < encodedKeys.array.size ; i++) {
        JwtJsonElement obj = jwtJsonArrayGet(&encodedKeys.array, i);
        if(obj.type != JWT_JSON_ELEMENT_TYPE_OBJECT) {
            return JWT_RESULT_NOT_AN_OBJECT;
        }
        result = jwtKeyParse(&keys[i], &obj.object);
        if(result != JWT_RESULT_SUCCESS) {
            goto error;
        }

        if(keys[i].keyId.data != nullptr) {
            for(auto j = 0 ; j < i ; j++) {
                JwtKey* other = &keys[j];
                if(other->keyId.data != nullptr 
                    && other->keyId.length == keys[i].keyId.length 
                    && memcmp(other->keyId.data, keys[i].keyId.data, keys[i].keyId.length) == 0) {

                    result = JWT_RESULT_DUPLICATE_KEY_ID;
                    goto error;
                }
            }
        }
    }

    keySet->keys = keys;
    keySet->count = encodedKeys.array.size;
    return JWT_RESULT_SUCCESS;

error:

    delete[] keys;
    return result;
}

void jwtKeySetDestroy(JwtKeySet* keySet) {
    if(keySet->keys) {
        delete[] keySet->keys;
        keySet->keys = nullptr;
    }
    keySet->count = 0;
}
