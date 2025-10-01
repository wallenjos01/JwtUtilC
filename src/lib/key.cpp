/**
 * josh wallentine
 * created 9/30/25
 *
 * implementation of include/jwt/key.h
 */

#include <iostream>
#include <jwt/json.h>
#include <jwt/key.h>

#include "hash.hpp"

namespace {

int32_t parseKeyType(JwtKeyType* type, JwtString str) {

    size_t hash = hashString(str.data, str.length);
    switch (hash) {
    case hashCString("EC"):
        *type = JWT_KEY_TYPE_ELLIPTIC_CURVE;
        return 0;
    case hashCString("RSA"):
        *type = JWT_KEY_TYPE_RSA;
        return 0;
    case hashCString("oct"):
        *type = JWT_KEY_TYPE_OCTET_SEQUENCE;
        return 0;
    default:
        return -1;
    }
}

int32_t parseKeyUse(JwtKeyUse* use, JwtString str) {
    size_t hash = hashString(str.data, str.length);
    switch (hash) {
    case hashCString("sig"):
        *use = JWT_KEY_USE_SIGNING;
        return 0;
    case hashCString("enc"):
        *use = JWT_KEY_USE_ENCRYPTION;
        return 0;
    default:
        return -1;
    }
}

int32_t parseKeyOps(uint8_t* bitset, JwtJsonArray array) {

    for (auto i = 0; i < array.size; i++) {
        JwtJsonElement element = jwtJsonArrayGet(&array, i);
        if (element.type != JWT_JSON_ELEMENT_TYPE_STRING) {
            return -1;
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
            return -2;
        }
    }

    return 0;
}

int32_t parseAlgorithm(JwtAlgorithm* alg, JwtString str) {

    size_t hash = hashString(str.data, str.length);
    switch (hash) {
    case hashCString("none"):
        *alg = JWT_ALGORITHM_NONE;
        break;
    case hashCString("HS256"):
        *alg = JWT_ALGORITHM_HS256;
        break;
    case hashCString("HS384"):
        *alg = JWT_ALGORITHM_HS384;
        break;
    case hashCString("HS512"):
        *alg = JWT_ALGORITHM_HS512;
        break;
    case hashCString("RS256"):
        *alg = JWT_ALGORITHM_RS256;
        break;
    case hashCString("RS384"):
        *alg = JWT_ALGORITHM_RS384;
        break;
    case hashCString("RS512"):
        *alg = JWT_ALGORITHM_RS512;
        break;
    case hashCString("ES256"):
        *alg = JWT_ALGORITHM_ES256;
        break;
    case hashCString("ES384"):
        *alg = JWT_ALGORITHM_ES384;
        break;
    case hashCString("ES512"):
        *alg = JWT_ALGORITHM_ES512;
        break;
    case hashCString("PS256"):
        *alg = JWT_ALGORITHM_PS256;
        break;
    case hashCString("PS384"):
        *alg = JWT_ALGORITHM_PS384;
        break;
    case hashCString("PS512"):
        *alg = JWT_ALGORITHM_PS512;
        break;
    case hashCString("RSA1_5"):
        *alg = JWT_ALGORITHM_RSA1_5;
        break;
    case hashCString("RSA-OAEP"):
        *alg = JWT_ALGORITHM_RSA_OAEP;
        break;
    case hashCString("RSA-OAEP-256"):
        *alg = JWT_ALGORITHM_RSA_OAEP_256;
        break;
    case hashCString("A128KW"):
        *alg = JWT_ALGORITHM_A128KW;
        break;
    case hashCString("A192KW"):
        *alg = JWT_ALGORITHM_A192KW;
        break;
    case hashCString("A256KW"):
        *alg = JWT_ALGORITHM_A256KW;
        break;
    case hashCString("dir"):
        *alg = JWT_ALGORITHM_DIRECT;
        break;
    case hashCString("ECDH-ES"):
        *alg = JWT_ALGORITHM_ECDH_ES;
        break;
    case hashCString("ECDH-ES+A128KW"):
        *alg = JWT_ALGORITHM_ECDH_ES_A128KW;
        break;
    case hashCString("ECDH-ES+A192KW"):
        *alg = JWT_ALGORITHM_ECDH_ES_A192KW;
        break;
    case hashCString("ECDH-ES+A256KW"):
        *alg = JWT_ALGORITHM_ECDH_ES_A256KW;
        break;
    case hashCString("A128GCMKW"):
        *alg = JWT_ALGORITHM_A128GCMKW;
        break;
    case hashCString("A192GCMKW"):
        *alg = JWT_ALGORITHM_A192GCMKW;
        break;
    case hashCString("A256GCMKW"):
        *alg = JWT_ALGORITHM_A256GCMKW;
        break;
    case hashCString("PBES2-HS256+A128KW"):
        *alg = JWT_ALGORITHM_PBES_HS256_A128KW;
        break;
    case hashCString("PBES2-HS384+A192KW"):
        *alg = JWT_ALGORITHM_PBES_HS384_A192KW;
        break;
    case hashCString("PBES2-HS512+A256KW"):
        *alg = JWT_ALGORITHM_PBES_HS512_A256KW;
        break;
    case hashCString("A128CBC-HS256"):
        *alg = JWT_ALGORITHM_A128CBC_HS256;
        break;
    case hashCString("A192CBC-HS384"):
        *alg = JWT_ALGORITHM_A192CBC_HS384;
        break;
    case hashCString("A256CBC-HS512"):
        *alg = JWT_ALGORITHM_A256CBC_HS512;
        break;
    case hashCString("A128GCM"):
        *alg = JWT_ALGORITHM_A128GCM;
        break;
    case hashCString("A192GCM"):
        *alg = JWT_ALGORITHM_A192GCM;
        break;
    case hashCString("A256GCM"):
        *alg = JWT_ALGORITHM_A256GCM;
        break;
    default:
        return -1;
    }

    return 0;
}

} // namespace

JwtKeyParseResult jwtKeyParse(JwtKey* key, JwtJsonObject obj) {

    JwtString kty = jwtJsonObjectGetString(&obj, "kty");
    if (kty.data == nullptr || parseKeyType(&key->type, kty) != 0) {
        return JWT_KEY_PARSE_RESULT_UNKNOWN_KEY_TYPE;
    }

    JwtString use = jwtJsonObjectGetString(&obj, "use");
    key->use = JWT_KEY_USE_UNKNOWN;
    if (use.data && parseKeyUse(&key->use, use) != 0) {
        return JWT_KEY_PARSE_RESULT_UNKNOWN_KEY_USE;
    }

    JwtJsonArray keyOps = jwtJsonObjectGetArray(&obj, "key_ops");
    key->operations = 0;
    if (keyOps.head && parseKeyOps(&key->operations, keyOps) != 0) {
        return JWT_KEY_PARSE_RESULT_UNKNOWN_OPERATION;
    }

    JwtString alg = jwtJsonObjectGetString(&obj, "alg");
    key->algorithm = JWT_ALGORITHM_UNKNOWN;
    if (alg.data && parseAlgorithm(&key->algorithm, alg) != 0) {
        return JWT_KEY_PARSE_RESULT_UNKNOWN_ALGORITHM;
    }

    return JWT_KEY_PARSE_RESULT_SUCCESS;
}
