#ifndef JWT_KEY_H
#define JWT_KEY_H

#include "jwt/result.h"
#ifdef __cplusplus
extern "C" {
#endif

#include <jwt/json.h>

/**
 * Enumerates all registered JWAs (JSON Web Algorithms)
 * @see https://www.rfc-editor.org/rfc/rfc7518.html
 */
enum JwtAlgorithm : uint8_t {
    JWT_ALGORITHM_UNKNOWN = 0,
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
 * Enumerates the valid algorithms for encrypting and signing the payload of an encrypted JWT.
 * @see RFC 7518 (https://www.rfc-editor.org/rfc/rfc7518#section-5)
 */
enum JwtCryptAlgorithm {
    JWT_CRYPT_ALGORITHM_UNKNOWN,
    JWT_CRYPT_ALGORITHM_A128CBC_HS256,
    JWT_CRYPT_ALGORITHM_A192CBC_HS384,
    JWT_CRYPT_ALGORITHM_A256CBC_HS512,
    JWT_CRYPT_ALGORITHM_A128GCM,
    JWT_CRYPT_ALGORITHM_A192GCM,
    JWT_CRYPT_ALGORITHM_A256GCM
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
    JWT_KEY_USE_UNKNOWN = 0,
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

typedef uint8_t JwtKeyOperations;

/**
 * Enumerates supported Elliptic Curve curves
 */
enum JwtEcCurve {
    JWT_EC_CURVE_P256,
    JWT_EC_CURVE_P384,
    JWT_EC_CURVE_P521
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
     * @brief X.509 Certificate info. May be null.
     */
    JwtCertInfo* cert;

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
     * @brief A bitset of valid operations to use this key for.
     * @see JwtKeyOperation
     */
    JwtKeyOperations operations;

    /**
     * @brief True if the key contains private key parameters
     */
    bool isPrivateKey;

} JwtKey;

/**
 * @brief Attempts to parse a JWA by name from the given string.
 * @param algorithm The place to store the parsed algorithm.
 * @param name The algorithm name to parse
 * @return 0 on success, or some error code
 */
JwtResult jwtAlgorithmParse(JwtAlgorithm* algorithm, const char* name);

/**
 * @brief Attempts to parse an encryption algorithm by name from the given string.
 * @param algorithm The place to store the parsed algorithm.
 * @param name The algorithm name to parse
 * @return 0 on success, or some error code
 */
JwtResult jwtCryptAlgorithmParse(JwtCryptAlgorithm* algorithm, const char* name);

inline bool jwtIsEncryptionAlgorithm(JwtAlgorithm algorithm) {
    return algorithm >= JWT_ALGORITHM_RSA1_5;
}


/**
 * Attempts to parse an EC curve by name
 */
JwtResult jwtKeyTypeParse(JwtKeyType* out, JwtString name);

/**
 * @brief Attempts to parse a JWK from the given JSON object
 * @param key A pointer to the place to store the output key
 * @param obj The object to parse
 * @return 0 on success, or some error code
 */
JwtResult jwtKeyParse(JwtKey* key, JwtJsonObject* obj);

/**
 * @brief Destroys the given JWK
 * @param key The key to destroy
 */
void jwtKeyDestroy(JwtKey* key);

/**
 * @brief Attempts to write the given JWK to the given JSON object
 * @param key The key to write
 * @param obj The object to write to
 * @return 0 on success, or some error code
 */
JwtResult jwtKeyEncode(JwtKey* key, JwtJsonObject* obj);

/**
 * @brief Generates a new RSA keypair
 * @param out Where to store the generated key.
 * @param bits The number of bits in the key.
 */
JwtResult jwtKeyGenerateRsa(JwtKey* out, size_t bits);

/**
 * @brief Generates a new octet sequence key for AES or HMAC
 * @param out Where to store the generated key.
 * @param bytes The number of bytes in the key.
 */
JwtResult jwtKeyGenerateOct(JwtKey* out, size_t bytes);

/**
 * @brief Generates a new EC keypair
 * @param out Where to store the generated key.
 * @param curve The curve the key belongs to.
 */
JwtResult jwtKeyGenerateEc(JwtKey* out, JwtEcCurve curve);

/**
 * @brief Creates a new octet sequence key for AES or HMAC
 * @param out Where to store the generated key.
 * @param data The key data.
 * @param length The number of bytes in the key
 */
JwtResult jwtKeyCreateOct(JwtKey* out, const void* data, size_t length);

/**
 * Attempts to parse an EC curve by name
 */
JwtResult jwtCurveParse(JwtEcCurve* out, JwtString name);

/**
 * Represents a set of zero or more JWKs
 */
typedef struct JwtKeySet {
    JwtKey* keys;
    size_t count;
} JwtKeySet;

/**
 * @brief Attempts to parse a JWK set from the given JSON object
 * @param keySet A pointer to the place to store the output keys
 * @param obj The object to parse
 * @return 0 on success, or some error code
 */
JwtResult jwtKeySetParse(JwtKeySet* keySet, JwtJsonObject* obj);

/**
 * @brief Destroys the given JWK set
 * @param keySet The key set to destroy
 */
void jwtKeySetDestroy(JwtKeySet* keySet);

#ifdef __cplusplus
}
#endif

#endif // JWT_KEY_H
