/**
 * josh wallentine
 * created 9/30/25
 *
 * implementation of include/jwt/key.h
 */

#include <jwt/json.h>
#include <jwt/key.h>

#include "hash.hpp"

namespace {

int32_t parseKeyType(JwtKeyType* type, JwtString str) {

    uint32_t hash = hashString(str.data, str.length);
    switch (hash) {
    case hashString("EC", 2):
        *type = JWT_KEY_TYPE_ELLIPTIC_CURVE;
        return 0;
    case hashString("RSA", 3):
        *type = JWT_KEY_TYPE_RSA;
        return 0;
    case hashString("oct", 3):
        *type = JWT_KEY_TYPE_OCTET_SEQUENCE;
        return 0;
    }

    return -1;
}

} // namespace

int32_t jwtKeyParse(JwtKey* key, JwtJsonObject obj) {

    JwtString kty = jwtJsonObjectGetString(&obj, "kty");
    if (parseKeyType(&key->type, kty) != 0) {
        return -1; // Unknown key type
    }

    return 0;
}
