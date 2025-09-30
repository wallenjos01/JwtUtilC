#ifndef JWT_TOKEN_H
#define JWT_TOKEN_H

#ifdef __cplusplus
extern "C" {
#endif

#include <jwt/json.h>
#include <jwt/key.h>

const char* const JWT_CLAIM_ISSUER = "iss";
const char* const JWT_CLAIM_SUBJECT = "sub";
const char* const JWT_CLAIM_AUDIENCE = "aud";
const char* const JWT_CLAIM_EXPIRATION = "exp";
const char* const JWT_CLAIM_NOT_BEFORE = "nbf";
const char* const JWT_CLAIM_ISSUED_AT = "iat";
const char* const JWT_CLAIM_JWT_ID = "jti";

/**
 * Creates an unprotected JSON Web Token with the given payload.
 */
JwtString jwtCreateUnprotectedToken(JwtJsonObject payload);

/**
 * Creates a JSON Web Token with the given payload, protected with the
 * given key.
 */
JwtString jwtCreateToken(JwtJsonObject payload, JwtKey key);

#ifdef __cplusplus
}
#endif

#endif // JWT_TOKEN_H
