#ifndef JWT_KEY_H
#define JWT_KEY_H

#ifdef __cplusplus
extern "C" {
#endif

#include <jwt/json.h>

/**
 * Enumerates all registered JWAs (JSON Web Algorithms)
 * @see https://www.rfc-editor.org/rfc/rfc7518.html
 */
enum JwtAlgorithm : uint8_t {
    JWT_ALGORITHM_NONE,
    // Signing Algorithms
    JWT_ALGORITHM_HS256,
    JWT_ALGORITHM_HS384,
    JWT_ALGORITHM_HS512,
    JWT_ALGORITHM_RS256,
    JWT_ALGORITHM_RS384,
    JWT_ALGORITHM_RS512,
    JWT_ALGORITHM_ES256,
    JWT_ALGORITHM_ES384,
    JWT_ALGORITHM_ES512,
    JWT_ALGORITHM_PS256,
    JWT_ALGORITHM_PS384,
    JWT_ALGORITHM_PS512,
    // Encryption Algorithms
    JWT_ALGORITHM_RSA1_5,
    JWT_ALGORITHM_RSA_OAEP,
    JWT_ALGORITHM_RSA_OAEP_256,
    JWT_ALGORITHM_A128KW,
    JWT_ALGORITHM_A192KW,
    JWT_ALGORITHM_A256KW,
    JWT_ALGORITHM_DIRECT,
    JWT_ALGORITHM_ECDH_ES,
    JWT_ALGORITHM_ECDH_ES_A128KW,
    JWT_ALGORITHM_ECDH_ES_A192KW,
    JWT_ALGORITHM_ECDH_ES_A256KW,
    JWT_ALGORITHM_A128GCMKW,
    JWT_ALGORITHM_A192GCMKW,
    JWT_ALGORITHM_A256GCMKW,
    JWT_ALGORITHM_PBES_HS256_A128KW,
    JWT_ALGORITHM_PBES_HS384_A192KW,
    JWT_ALGORITHM_PBES_HS512_A256KW,
};

/**
 * Enumerates JWK types.
 * @see https://www.rfc-editor.org/rfc/rfc7517.html
 */
enum JwtKeyType : uint8_t {
    JWT_KEY_TYPE_ELLIPTIC_CURVE,
    JWT_KEY_TYPE_RSA,
    JWT_KEY_TYPE_OCTET_SEQUENCE,
};

/**
 * Enumerates JWK uses.
 * @see https://www.rfc-editor.org/rfc/rfc7517.html
 */
enum JwtKeyUse : uint8_t {
    JWT_KEY_USE_SIGNING,
    JWT_KEY_USE_ENCRYPTION,
};

/**
 * Enumerates JWK operations.
 * @see https://www.rfc-editor.org/rfc/rfc7517.html
 */
enum JwtKeyOperation : uint8_t {
    JWT_KEY_OP_SIGN = 1,
    JWT_KEY_OP_VERIFY = 2,
    JWT_KEY_OP_ENCRYPT = 4,
    JWT_KEY_OP_DECRYPT = 8,
    JWT_KEY_OP_WRAP_KEY = 16,
    JWT_KEY_OP_UNWRAP_KEY = 32,
    JWT_KEY_OP_DERIVE_KEY = 64,
    JWT_KEY_OP_DERIVE_BITS = 128,
};

/**
 * Represents the X.509 certificate information part of a JWK
 */
typedef struct JwtCertInfo {
    /**
     * @brief X.509 URL. A URI pointing to a X.509 certificate corresponding to
     * this key.
     */
    JwtString x5u;

    /**
     * @brief X.509 Certificate Chain. A list of URIs pointing to X.509
     * certificates corresponding to this key.
     */
    struct {
        JwtString* head;
        size_t length;
    } x5c;

    /**
     * @brief X.509 SHA-1 Thumbprint. A 20-byte buffer containing the SHA-1
     * digest of the above certificate.
     */
    char* x5t;

    /**
     * @brief X.509 SHA-256 Thumbprint. A 32-byte buffer containing the SHA-256
     * digest of the above certificate.
     */
    char* x5t256;
} JwtCertInfo;

/**
 * Represents a JWK (JSON Web Key)
 * @see https://www.rfc-editor.org/rfc/rfc7517.html
 */
typedef struct JwtKey {

    /**
     * @brief A string ID for the JWK. A key id pointing to null should be
     * considered not present.
     */
    JwtString keyId;

    /**
     * @brief Some key data. Contents depends on key type.
     */
    void* keyData;

    /**
     * @brief The type of key.
     */
    JwtKeyType type;

    /**
     * @brief The valid use for this key.
     */
    JwtKeyUse use;

    /**
     * @brief The algorithm to use this key with.
     */
    JwtAlgorithm algorithm;

    /**
     * A bitset of valid operations to use this key for.
     * @see JwtKeyOperation
     */
    uint8_t operations;

} JwtKey;

/**
 * @brief Attempts to parse a JWK from the given JSON object
 * @param key A pointer to the place to store the output key
 * @param obj The object to parse
 * @return 0 on success, or some error code
 */
int32_t jwtKeyParse(JwtKey* key, JwtJsonObject obj);

/**
 * @brief Creates a new JWK with the given algorithm and operations
 * @param key A pointer to the place to store the output key
 * @param algorithm The algorithm to use for the key
 * @param operations The operations valid for this key
 * @return 0 on success, or some error code
 */
int32_t jwtKeyGenerate(JwtKey* key, JwtAlgorithm algorithm, uint8_t operations);

/**
 * @brief Destroys the given JWK
 * @param key The key to destroy
 */
void jwtKeyDestroy(JwtKey* key);

#ifdef __cplusplus
}
#endif

#endif // JWT_KEY_H
