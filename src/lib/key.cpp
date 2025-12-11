/**
 * Josh Wallentine
 * Created 9/30/25
 * Modified 11/12/25
 *
 * Implementation of include/jwt/key.h
 * Partial implementation of key.hpp
 * See also key_ec.cpp, key_rsa.cpp
 */

#include <jwt/json.h>
#include <jwt/key.h>

#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/rand.h>

#include "algorithm.hpp"
#include "hash.hpp"
#include "key.hpp"
#include "jwt/core.h"
#include "jwt/result.h"
#include "jwt/stream.h"
#include "util.hpp"

namespace {

const char* getKeyTypeName(JwtKeyType type) {
    switch(type) {
        case JWT_KEY_TYPE_ELLIPTIC_CURVE:
            return "EC";
        case JWT_KEY_TYPE_RSA:
            return "RSA";
        case JWT_KEY_TYPE_OCTET_SEQUENCE:
            return "oct";
        default: 
            return "";
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

const char* getKeyUseName(JwtKeyUse type) {
    switch(type) {
        case JWT_KEY_USE_SIGNING:
            return "sig";
        case JWT_KEY_USE_ENCRYPTION:
            return "enc";
        default:
            return "";
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

constexpr const char* getKeyOpName(JwtKeyOperation op) {
    switch(op) {
        case JWT_KEY_OP_SIGN:
            return "sign";
        case JWT_KEY_OP_VERIFY:
            return "verify";
        case JWT_KEY_OP_ENCRYPT:
            return "encrypt";
        case JWT_KEY_OP_DECRYPT:
            return "decrypt";
        case JWT_KEY_OP_WRAP_KEY:
            return "wrapKey";
        case JWT_KEY_OP_UNWRAP_KEY:
            return "unwrapKey";
        case JWT_KEY_OP_DERIVE_KEY:
            return "deriveKey";
        case JWT_KEY_OP_DERIVE_BITS:
            return "deriveBits";
        default:
            return "";
    }
}

} // namespace

JwtResult jwtKeyTypeParse(JwtKeyType* type, JwtString name) {
    size_t hash = hashString(name.data, name.length);
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

JwtKeyType jwtKeyTypeForAlgorithm(JwtAlgorithm algorithm) {
    switch(algorithm) {
        case JWT_ALGORITHM_UNKNOWN:
        case JWT_ALGORITHM_NONE:
        default:
            return JWT_KEY_TYPE_UNKNOWN;
        case JWT_ALGORITHM_HS256:
        case JWT_ALGORITHM_HS384:
        case JWT_ALGORITHM_HS512:
        case JWT_ALGORITHM_A128KW:
        case JWT_ALGORITHM_A192KW:
        case JWT_ALGORITHM_A256KW:
        case JWT_ALGORITHM_DIRECT:
        case JWT_ALGORITHM_A128GCMKW:
        case JWT_ALGORITHM_A192GCMKW:
        case JWT_ALGORITHM_A256GCMKW:
        case JWT_ALGORITHM_PBES_HS256_A128KW:
        case JWT_ALGORITHM_PBES_HS384_A192KW:
        case JWT_ALGORITHM_PBES_HS512_A256KW:
            return JWT_KEY_TYPE_OCTET_SEQUENCE;
        case JWT_ALGORITHM_RS256:
        case JWT_ALGORITHM_RS384:
        case JWT_ALGORITHM_RS512:
        case JWT_ALGORITHM_PS256:
        case JWT_ALGORITHM_PS384:
        case JWT_ALGORITHM_PS512:
        case JWT_ALGORITHM_RSA1_5:
        case JWT_ALGORITHM_RSA_OAEP:
        case JWT_ALGORITHM_RSA_OAEP_256:
            return JWT_KEY_TYPE_RSA;
        case JWT_ALGORITHM_ES256:
        case JWT_ALGORITHM_ES384:
        case JWT_ALGORITHM_ES512:
        case JWT_ALGORITHM_ECDH_ES:
        case JWT_ALGORITHM_ECDH_ES_A128KW:
        case JWT_ALGORITHM_ECDH_ES_A192KW:
        case JWT_ALGORITHM_ECDH_ES_A256KW:
            return JWT_KEY_TYPE_ELLIPTIC_CURVE;
    }
}

size_t jwtGetMinKeyLengthForAlgorithm(JwtAlgorithm algorithm) {
    switch(algorithm) {
        case JWT_ALGORITHM_UNKNOWN:
        case JWT_ALGORITHM_NONE:
        default:
            return 0;
        case JWT_ALGORITHM_PBES_HS256_A128KW:
        case JWT_ALGORITHM_PBES_HS384_A192KW:
        case JWT_ALGORITHM_PBES_HS512_A256KW:
            return 1;
        case JWT_ALGORITHM_A128KW:
        case JWT_ALGORITHM_A128GCMKW:
            return 16;
        case JWT_ALGORITHM_A192KW:
        case JWT_ALGORITHM_A192GCMKW:
            return 24;
        case JWT_ALGORITHM_HS256:
        case JWT_ALGORITHM_A256KW:
        case JWT_ALGORITHM_A256GCMKW:
            return 32;
        case JWT_ALGORITHM_HS384:
            return 48;
        case JWT_ALGORITHM_HS512:
            return 64;
        case JWT_ALGORITHM_DIRECT:
            return 16;
        case JWT_ALGORITHM_RS256:
        case JWT_ALGORITHM_RS384:
        case JWT_ALGORITHM_RS512:
        case JWT_ALGORITHM_PS256:
        case JWT_ALGORITHM_PS384:
        case JWT_ALGORITHM_PS512:
        case JWT_ALGORITHM_RSA1_5:
        case JWT_ALGORITHM_RSA_OAEP:
        case JWT_ALGORITHM_RSA_OAEP_256:
            return 256;
        case JWT_ALGORITHM_ES256:
        case JWT_ALGORITHM_ES384:
        case JWT_ALGORITHM_ES512:
        case JWT_ALGORITHM_ECDH_ES:
        case JWT_ALGORITHM_ECDH_ES_A128KW:
        case JWT_ALGORITHM_ECDH_ES_A192KW:
        case JWT_ALGORITHM_ECDH_ES_A256KW:
            return 0;
    }

}

JwtResult jwtKeyParse(JwtKey* key, JwtJsonObject* obj) {

    JwtString kty = jwtJsonObjectGetString(obj, "kty");
    if (kty.data == nullptr || jwtKeyTypeParse(&key->type, kty) != 0) {
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

    JwtString kid = jwtJsonObjectGetString(obj, "kid");
    if(kid.data) {
        key->keyId = jwtStringCreateSized(kid.data, kid.length);
    }

    switch (key->type) {
    case JWT_KEY_TYPE_ELLIPTIC_CURVE:
        return jwt::parseEcKey(key, obj);
    case JWT_KEY_TYPE_RSA:
        return jwt::parseRsaKey(key, obj);
    case JWT_KEY_TYPE_OCTET_SEQUENCE:
        return jwt::parseOctKey(key, obj);
    default:
        return JWT_RESULT_INVALID_KEY_TYPE;
    }

    return JWT_RESULT_SUCCESS;
}

void jwtKeyDestroy(JwtKey* key) {

    if(key->keyId.data != nullptr) {
        jwtStringDestroy(&key->keyId);
    }

    switch (key->type) {
    case JWT_KEY_TYPE_ELLIPTIC_CURVE:
    case JWT_KEY_TYPE_RSA:
        EVP_PKEY_free(static_cast<EVP_PKEY*>(key->keyData));
        return;
    case JWT_KEY_TYPE_OCTET_SEQUENCE:
        delete static_cast<Span<uint8_t>*>(key->keyData);
    default:
        return;
    }
}

JwtResult jwtKeyEncode(JwtKey* key, JwtJsonObject* obj) {

    jwtJsonObjectSetString(obj, "kty", getKeyTypeName(key->type));
    if(key->algorithm != JWT_ALGORITHM_UNKNOWN) {
        jwtJsonObjectSetString(obj, "alg", jwt::getAlgorithmName(key->algorithm));
    }
    if(key->keyId.data != nullptr) {
        jwtJsonObjectSetString(obj, "kid", key->keyId.data);
    }
    if(key->use != JWT_KEY_USE_UNKNOWN) {
        jwtJsonObjectSetString(obj, "use", getKeyUseName(key->use)); 
    }
    if(key->operations != 0) {
        JwtJsonArray keyOps = {};
        jwtJsonArrayCreate(&keyOps);

        JwtKeyOperation ops[8] = {
            JWT_KEY_OP_SIGN,
            JWT_KEY_OP_VERIFY,
            JWT_KEY_OP_ENCRYPT,
            JWT_KEY_OP_DECRYPT,
            JWT_KEY_OP_WRAP_KEY,
            JWT_KEY_OP_UNWRAP_KEY,
            JWT_KEY_OP_DERIVE_KEY,
            JWT_KEY_OP_DERIVE_BITS
        };
        for(auto i = 0 ; i < 8 ; i++) {
            if(key->operations & ops[i]) {
                jwtJsonArrayPushString(&keyOps, getKeyOpName(ops[i]));
            }
        }
        jwtJsonObjectSetArray(obj, "key_ops", keyOps); 
    }

    switch(key->type) {
        case JWT_KEY_TYPE_RSA:
            return jwt::writeRsaKey(key, obj);
        case JWT_KEY_TYPE_ELLIPTIC_CURVE:
            return jwt::writeEcKey(key, obj);
        case JWT_KEY_TYPE_OCTET_SEQUENCE:
            return jwt::writeOctKey(key, obj);
        default:
            return JWT_RESULT_INVALID_KEY_TYPE;
    }

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

JwtResult jwt::writeOctKey(JwtKey* key, JwtJsonObject* obj) {

    Span<uint8_t> keyBytes = *static_cast<Span<uint8_t>*>(key->keyData);

    JwtWriter b64Writer;
    JWT_CHECK(jwtWriterCreateDynamic(&b64Writer));
    JWT_CHECK(jwt::b64url::encode(keyBytes.data, keyBytes.length, b64Writer));

    JwtString b64;
    JwtList* list = jwtWriterExtractDynamic(&b64Writer);
    *static_cast<uint8_t*>(jwtListPush(list)) = 0;

    b64.length = list->size - 1;
    b64.data = static_cast<char*>(jwtListReclaim(list));

    jwtJsonObjectSetString(obj, "k", b64.data);
    return JWT_RESULT_SUCCESS;
}

JwtResult jwt::getKeyCurve(JwtKey *key, JwtEcCurve *curve) {

    if(key->type != JWT_KEY_TYPE_ELLIPTIC_CURVE) return JWT_RESULT_ILLEGAL_ARGUMENT;

    EVP_PKEY* pkey;
    JWT_CHECK(jwt::getKeyPkey(key, &pkey));

    JwtString str;
    EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME, nullptr, 0, &str.length);

    char* data = new char[str.length + 1];
    EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME, data, str.length, nullptr);
    str.data = data;

    JwtResult result = jwtCurveParse(curve, str);
    jwtStringDestroy(&str);

    return result;
}

JwtResult jwt::getKeyPkey(JwtKey* key, EVP_PKEY** pkey) {

    if(key->type == JWT_KEY_TYPE_OCTET_SEQUENCE) return JWT_RESULT_ILLEGAL_ARGUMENT;

    *pkey = static_cast<EVP_PKEY*>(key->keyData);
    return JWT_RESULT_SUCCESS;
}

JwtResult jwt::getKeyBytes(JwtKey* key, Span<uint8_t>* bytes) {

    if(key->type != JWT_KEY_TYPE_OCTET_SEQUENCE) return JWT_RESULT_ILLEGAL_ARGUMENT;

    *bytes = *static_cast<Span<uint8_t>*>(key->keyData);
    return JWT_RESULT_SUCCESS;
}


JwtResult jwtKeyGenerateOct(JwtKey* key, size_t length) {

    if(length == 0) {
        return JWT_RESULT_ILLEGAL_ARGUMENT;
    }

    Span<uint8_t>* span = new Span<uint8_t>(new uint8_t[length], length);
    RAND_bytes(span->data, length);

    key->keyData = span;
    key->type = JWT_KEY_TYPE_OCTET_SEQUENCE;

    return JWT_RESULT_SUCCESS;
}


JwtResult jwtKeyCreateOct(JwtKey* key, const void* data, size_t length) {

    if(length == 0) {
        return JWT_RESULT_ILLEGAL_ARGUMENT;
    }

    Span<uint8_t>* span = new Span<uint8_t>(new uint8_t[length], length);
    memcpy(span->data, data, length);

    key->keyData = span;
    key->type = JWT_KEY_TYPE_OCTET_SEQUENCE;

    return JWT_RESULT_SUCCESS;
}
