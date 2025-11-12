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
 * @param payload The JWT payload
 * @param out A pointer to a string which will be filled with a heap-allocated string containing an unsecured JWT in compact form
 * @return 0 on success, or some error code
 * @see RFC 7519 (https://www.rfc-editor.org/rfc/rfc7519#section-6)
 */
JwtResult jwtCreateUnprotectedToken(JwtJsonObject* payload, JwtString* out);

/**
 * Creates a JSON Web Token with the given payload, signed with the given key and algorithm.
 * @param payload The JWT payload
 * @param key The key to use to project the token
 * @param algorithm The algorithm to use to sign the token
 * @param out A pointer to a string which will be filled with a heap-allocated string containing a JWT in compact form
 * @return 0 on success, or some error code
 * @see RFC 7519 (https://www.rfc-editor.org/rfc/rfc7519#appendix-A.1)
 */
JwtResult jwtCreateSignedToken(JwtJsonObject* payload, JwtKey* key, JwtAlgorithm algorithm, JwtString* out);

/**
 * Creates a JSON Web Token with the given payload, encrypted with the given key and algorithms.
 * @param payload The JWT payload
 * @param key The key to use to project the token
 * @param algorithm The algorithm to use to encrypt the CEK
 * @param crypt The algorithm to use to encrypt the token payload
 * @param out A pointer to a string which will be filled with a heap-allocated string containing a JWT in compact form
 * @return 0 on success, or some error code
 * @see RFC 7519 (https://www.rfc-editor.org/rfc/rfc7519#appendix-A.1)
 */
JwtResult jwtCreateEncryptedToken(JwtJsonObject* payload, JwtKey* key, JwtAlgorithm algorithm, JwtCryptAlgorithm crypt, JwtString* out);


JwtResult jwtReadTokenHeader(JwtString token, JwtJsonObject* out);


typedef struct JwtParsedToken {
    JwtJsonObject header;
    JwtJsonObject payload;
    JwtAlgorithm algorithm;
} JwtParsedToken;

enum JwtVerifyFlag : uint8_t {
    JWT_VERIFY_FLAG_ALLOW_UNPROTECTED = 0x1,
    JWT_VERIFY_FLAG_ALLOW_EXPIRED = 0x2,
    JWT_VERIFY_FLAG_ALLOW_EARLY = 0x4,
};

typedef uint8_t JwtVerifyFlags;

void jwtParsedTokenDestroy(JwtParsedToken* token);

JwtResult jwtVerifyToken(JwtString token, JwtKey* key, JwtParsedToken* out, JwtVerifyFlags flags);

JwtResult jwtVerifyTokenWithSet(JwtString token, JwtKey* key, JwtParsedToken* out, JwtVerifyFlags flags);


#ifdef __cplusplus
}
#endif

#endif // JWT_TOKEN_H
