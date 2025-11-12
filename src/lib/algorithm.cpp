/**
 * Josh Wallentine
 * Created 9/30/25
 * Modified 11/11/25
 *
 * Partial implementation of algorithm.hpp, key.h
 * See also algorithm_b64url.cpp, algorithm_hmac.cpp, algorithm_sig.cpp, algorithm_enc.cpp
*/

#include "algorithm.hpp"
#include "hash.hpp"

#include <jwt/key.h>


int32_t jwtAlgorithmParse(JwtAlgorithm* alg, const char* str) {

    size_t hash = hashString(str, strlen(str));
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
    default:
        return -1;
    }

    return 0;
}

int32_t jwtCryptAlgorithmParse(JwtCryptAlgorithm* alg, const char* str) {

    size_t hash = hashString(str, strlen(str));
    switch (hash) {
    case hashCString("A128CBC-HS256"):
        *alg = JWT_CRYPT_ALGORITHM_A128CBC_HS256;
        break;
    case hashCString("A192CBC-HS384"):
        *alg = JWT_CRYPT_ALGORITHM_A192CBC_HS384;
        break;
    case hashCString("A256CBC-HS512"):
        *alg = JWT_CRYPT_ALGORITHM_A256CBC_HS512;
        break;
    case hashCString("A128GCM"):
        *alg = JWT_CRYPT_ALGORITHM_A128GCM;
        break;
    case hashCString("A192GCM"):
        *alg = JWT_CRYPT_ALGORITHM_A192GCM;
        break;
    case hashCString("A256GCM"):
        *alg = JWT_CRYPT_ALGORITHM_A256GCM;
        break;
    default:
        return -1;
    }
    return 0;
}

const char* jwt::getAlgorithmName(JwtAlgorithm algorithm) {
    switch (algorithm) {
        case JWT_ALGORITHM_NONE: return "none";
        case JWT_ALGORITHM_HS256: return "HS256";
        case JWT_ALGORITHM_HS384: return "HS384";
        case JWT_ALGORITHM_HS512: return "HS512";
        case JWT_ALGORITHM_RS256: return "RS256";
        case JWT_ALGORITHM_RS384: return "RS384";
        case JWT_ALGORITHM_RS512: return "RS512";
        case JWT_ALGORITHM_ES256: return "ES256";
        case JWT_ALGORITHM_ES384: return "ES384";
        case JWT_ALGORITHM_ES512: return "ES512";
        case JWT_ALGORITHM_PS256: return "PS256";
        case JWT_ALGORITHM_PS384: return "PS384";
        case JWT_ALGORITHM_PS512: return "PS512";
        case JWT_ALGORITHM_RSA1_5: return "RSA1_5";
        case JWT_ALGORITHM_RSA_OAEP: return "RSA-OAEP";
        case JWT_ALGORITHM_RSA_OAEP_256: return "RSA-OAEP-256";
        case JWT_ALGORITHM_A128KW: return "A128KW";
        case JWT_ALGORITHM_A192KW: return "A192KW";
        case JWT_ALGORITHM_A256KW: return "A256KW";
        case JWT_ALGORITHM_DIRECT: return "dir";
        case JWT_ALGORITHM_ECDH_ES: return "ECDH-ES";
        case JWT_ALGORITHM_ECDH_ES_A128KW: return "ECDH-ES+A128KW";
        case JWT_ALGORITHM_ECDH_ES_A192KW: return "ECDH-ES+A192KW";
        case JWT_ALGORITHM_ECDH_ES_A256KW: return "ECDH-ES+A256KW";
        case JWT_ALGORITHM_A128GCMKW: return "A128GCMKW";
        case JWT_ALGORITHM_A192GCMKW: return "A192GCMKW";
        case JWT_ALGORITHM_A256GCMKW: return "A256GCMKW";
        case JWT_ALGORITHM_PBES_HS256_A128KW: return "PBES2-HS256+A128KW";
        case JWT_ALGORITHM_PBES_HS384_A192KW: return "PBES2-HS384+A192KW";
        case JWT_ALGORITHM_PBES_HS512_A256KW: return "PBES2-HS512+A256KW";
        default: return nullptr;
    }
}

const char* jwt::getDigestForAlgorithm(JwtAlgorithm alg) {
    switch (alg) {
        case JWT_ALGORITHM_HS256:
        case JWT_ALGORITHM_RS256:
        case JWT_ALGORITHM_ES256:
        case JWT_ALGORITHM_PS256:
            return "sha256";
        case JWT_ALGORITHM_HS384:
        case JWT_ALGORITHM_RS384:
        case JWT_ALGORITHM_ES384:
        case JWT_ALGORITHM_PS384:
            return "sha384";
        case JWT_ALGORITHM_HS512:
        case JWT_ALGORITHM_RS512:
        case JWT_ALGORITHM_ES512:
        case JWT_ALGORITHM_PS512:
            return "sha512";
        default:
            return nullptr;
    }
}

const char* jwt::enc::getCryptAlgorithmName(JwtCryptAlgorithm algorithm) {
    switch (algorithm) {
        case JWT_CRYPT_ALGORITHM_A128CBC_HS256: return "A128CBC-HS256";
        case JWT_CRYPT_ALGORITHM_A192CBC_HS384: return "A192CBC-HS384";
        case JWT_CRYPT_ALGORITHM_A256CBC_HS512: return "A256CBC-HS512";
        case JWT_CRYPT_ALGORITHM_A128GCM: return "A128GCM";
        case JWT_CRYPT_ALGORITHM_A192GCM: return "A192GCM";
        case JWT_CRYPT_ALGORITHM_A256GCM: return "A256GCM";
        default: return nullptr;
    }
}
