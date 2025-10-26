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
 * @return A heap-allocated string containing an unsecured JWT in compact form
 * @see RFC 7519 (https://www.rfc-editor.org/rfc/rfc7519#section-6)
 */
JwtString jwtCreateUnprotectedToken(JwtJsonObject payload);

/**
 * Creates a JSON Web Token with the given payload, protected with the given key and algorithm.
 * @return A heap-allocated string containing a JWT in compact form
 * @see RFC 7519 (https://www.rfc-editor.org/rfc/rfc7519#appendix-A.1)
 */
JwtString jwtCreateToken(JwtJsonObject payload, JwtKey key, JwtAlgorithm algorithm);

#ifdef __cplusplus
}
#endif

#endif // JWT_TOKEN_H
