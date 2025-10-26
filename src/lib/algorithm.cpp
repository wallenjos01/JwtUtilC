/**
 * Josh Wallentine
 * Created 9/30/25
 * Modified 10/23/25
 *
 * Implementation of algorithm.hpp
 */

#include "algorithm.hpp"
#include "hash.hpp"
#include "util.hpp"
#include "jwt/key.h"
#include "jwt/stream.h"

#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/rsa.h>

namespace {

constexpr char B64URL_LOOKUP[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

constexpr char B64URL_REVERSE_LOOKUP[256] = {
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  62, 0,  0,  52, 53, 54, 55, 56, 57, 58, 59, 60,
    61, 0,  0,  0,  0,  0,  0,  0,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10,
    11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 0,  0,  0,  0,
    63, 0,  26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
    43, 44, 45, 46, 47, 48, 49, 50, 51, 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,
};

constexpr const char* getDigestForAlgorithm(JwtAlgorithm alg) {
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

int32_t setupContextForAlgorithm(EVP_PKEY_CTX* keyContext,
                                 JwtAlgorithm algorithm) {

    switch (algorithm) {
    case JWT_ALGORITHM_RS256:
    case JWT_ALGORITHM_RS384:
    case JWT_ALGORITHM_RS512:
        EVP_PKEY_CTX_set_rsa_padding(keyContext, RSA_PKCS1_PADDING);
        break;
    case JWT_ALGORITHM_ES256:
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(keyContext,
                                               NID_X9_62_prime256v1);
        break;
    case JWT_ALGORITHM_ES384:
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(keyContext, NID_secp384r1);
        break;
    case JWT_ALGORITHM_ES512:
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(keyContext, NID_secp521r1);
        break;
    case JWT_ALGORITHM_PS256:
    case JWT_ALGORITHM_PS384:
    case JWT_ALGORITHM_PS512:
        EVP_PKEY_CTX_set_rsa_padding(keyContext, RSA_PKCS1_PSS_PADDING);
        break;
    default:
        return -1; // Unsupported algorithm for PKEY
    }

    return 0;
}

} // namespace

int32_t jwt::parseAlgorithm(JwtAlgorithm* alg, JwtString str) {

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

int32_t jwt::generateHmac(Span<uint8_t> input, JwtKey key,
                          JwtAlgorithm algorithm, Span<uint8_t> output,
                          size_t* macLength) {

    if (key.type != JWT_KEY_TYPE_OCTET_SEQUENCE) {
        return -1;
    }

    const char* digestName = getDigestForAlgorithm(algorithm);
    if (digestName == nullptr) {
        return -2;
    }

    EVP_MAC* mac = EVP_MAC_fetch(nullptr, "hmac", nullptr);
    EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
    if (ctx == nullptr) {
        return -3;
    }

    Span<uint8_t>* keyData = static_cast<Span<uint8_t>*>(key.keyData);

    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(
        "digest", const_cast<char*>(digestName), 0);
    params[1] = OSSL_PARAM_construct_end();
    if (!EVP_MAC_init(ctx, keyData->data, keyData->length, params)) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return -4;
    }

    EVP_MAC_update(ctx, input.data, input.length);
    size_t outputSize = 0;
    EVP_MAC_final(ctx, nullptr, &outputSize, 0);

    if (macLength)
        *macLength = outputSize;

    if (output.data == nullptr) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return 0;
    }

    if (outputSize > output.length) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return -5;
    }

    EVP_MAC_final(ctx, output.data, &outputSize, output.length);

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);

    return 0;
}

int32_t jwt::generateSignature(Span<uint8_t> input, JwtKey key,
                               JwtAlgorithm algorithm, Span<uint8_t> output,
                               size_t* sigLength) {

    if (input.length == 0 || input.data == nullptr) {
        return 0;
    }
    if (key.keyData == nullptr || key.type == JWT_KEY_TYPE_OCTET_SEQUENCE) {
        return -1;
    }

    EVP_PKEY* pkey = static_cast<EVP_PKEY*>(key.keyData);
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, pkey, nullptr);
    if (ctx == nullptr) {
        return -2;
    }

    if (setupContextForAlgorithm(ctx, algorithm) != 0) {
        EVP_PKEY_CTX_free(ctx);
        return -3;
    }

    const char* digest = getDigestForAlgorithm(algorithm);
    if (digest == nullptr) {
        EVP_PKEY_CTX_free(ctx);
        return -4;
    }

    EVP_MD* md = EVP_MD_fetch(nullptr, digest, nullptr);
    if (md == nullptr) {
        EVP_PKEY_CTX_free(ctx);
        return -5;
    }

    EVP_PKEY_CTX_set_signature_md(ctx, md);

    if (EVP_PKEY_sign_init(ctx) <= 0) {
        EVP_MD_free(md);
        EVP_PKEY_CTX_free(ctx);
        return -6;
    }

    size_t outputSize = 0;
    if (EVP_PKEY_sign(ctx, nullptr, &outputSize, input.data, input.length) !=
        1) {
        EVP_MD_free(md);
        EVP_PKEY_CTX_free(ctx);
        ERR_print_errors_fp(stderr);
        return -7;
    }

    if (sigLength)
        *sigLength = outputSize;

    if (output.data == nullptr) {
        EVP_MD_free(md);
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    if (outputSize > output.length) {
        EVP_MD_free(md);
        EVP_PKEY_CTX_free(ctx);
        return -8;
    }

    if (EVP_PKEY_sign(ctx, output.data, &outputSize, input.data,
                      input.length) <= 0) {

        EVP_MD_free(md);
        EVP_PKEY_CTX_free(ctx);
        ERR_print_errors_fp(stderr);
        return -9;
    }

    EVP_MD_free(md);
    EVP_PKEY_CTX_free(ctx);
    return 0;
}

int32_t jwt::b64url::encode(const void *data, size_t dataLength, JwtWriter writer) {

    const uint8_t* dataBytes = static_cast<const uint8_t*>(data);

    size_t position = 0;
    while(dataLength - position >= 3) {

        uint32_t encodedChunk = 
            (dataBytes[position] << 16) |
            (dataBytes[position + 1] << 8) |
            (dataBytes[position + 2]);

        position += 3;

        uint8_t c1 = encodedChunk & 0x3F;
        uint8_t c2 = (encodedChunk >> 6) & 0x3F;
        uint8_t c3 = (encodedChunk >> 12) & 0x3F;
        uint8_t c4 = (encodedChunk >> 18) & 0x3F;

        char chunk[4] = { 
            B64URL_LOOKUP[c4], 
            B64URL_LOOKUP[c3], 
            B64URL_LOOKUP[c2], 
            B64URL_LOOKUP[c1] 
        };

        if(jwtWriterWriteAll(writer, chunk, 4, nullptr) != 0) {
            return -1;
        }
    }

    size_t remaining = dataLength - position;
    if(remaining == 2) {

        uint32_t encodedChunk = 
            ((dataBytes[position] << 8) |
            (dataBytes[position + 1])) << 2;

        position += 2;

        uint8_t c1 = encodedChunk & 0x3F;
        uint8_t c2 = (encodedChunk >> 6) & 0x3F;
        uint8_t c3 = (encodedChunk >> 12) & 0x3F;

        char chunk[3] = {
            B64URL_LOOKUP[c3],
            B64URL_LOOKUP[c2],
            B64URL_LOOKUP[c1]
        };

        if(jwtWriterWriteAll(writer, chunk, 3, nullptr) != 0) {
            return -1;
        }
    }
    else if(remaining == 1) {
        uint32_t encodedChunk = 
            (dataBytes[position]) << 4;

        position += 1;

        uint8_t c1 = encodedChunk & 0x3F;
        uint8_t c2 = (encodedChunk >> 6) & 0x3F;

        char chunk[2] = {
            B64URL_LOOKUP[c2],
            B64URL_LOOKUP[c1]
        };

        if(jwtWriterWriteAll(writer, chunk, 2, nullptr) != 0) {
            return -1;
        }
    }

    return 0;
}

int32_t jwt::b64url::decode(const void *encoded, size_t encodedLength, JwtWriter writer) {

    const uint8_t* encodedBytes = static_cast<const uint8_t*>(encoded);

    size_t position = 0;

    while((encodedLength - position) >= 4) {

        uint8_t c1 = B64URL_REVERSE_LOOKUP[encodedBytes[position]];
        uint8_t c2 = B64URL_REVERSE_LOOKUP[encodedBytes[position + 1]];
        uint8_t c3 = B64URL_REVERSE_LOOKUP[encodedBytes[position + 2]];
        uint8_t c4 = B64URL_REVERSE_LOOKUP[encodedBytes[position + 3]];

        position += 4;

        uint32_t chunk = (c1 << 18) | (c2 << 12) | (c3 << 6) | c4;
        uint8_t data[3] = { 
            static_cast<uint8_t>((chunk >> 16) & 0xFF), 
            static_cast<uint8_t>((chunk >> 8) & 0xFF), 
            static_cast<uint8_t>(chunk & 0xFF) 
        };
        if(jwtWriterWriteAll(writer, reinterpret_cast<char*>(data), 3, nullptr) != 0) {
            return -1;
        }
    }

    size_t remaining = encodedLength - position;
    if(remaining == 3) {
        uint8_t c1 = B64URL_REVERSE_LOOKUP[encodedBytes[position]];
        uint8_t c2 = B64URL_REVERSE_LOOKUP[encodedBytes[position + 1]];
        uint8_t c3 = B64URL_REVERSE_LOOKUP[encodedBytes[position + 2]];

        position += 3;

        uint32_t chunk = ((c1 << 12) | (c2 << 6) | c3) >> 2;
        uint8_t data[2] = { 
            static_cast<uint8_t>((chunk >> 8) & 0xFF), 
            static_cast<uint8_t>(chunk & 0xFF) 
        };
        if(jwtWriterWriteAll(writer, reinterpret_cast<char*>(data), 2, nullptr) != 0) {
            return -1;
        }
    } else if(remaining == 2) {
        uint8_t c1 = B64URL_REVERSE_LOOKUP[encodedBytes[position]];
        uint8_t c2 = B64URL_REVERSE_LOOKUP[encodedBytes[position + 1]];

        position += 2;

        uint32_t chunk = ((c1 << 6) | c2) >> 4;
        uint8_t data = static_cast<uint8_t>(chunk & 0xFF);
        if(jwtWriterWriteAll(writer, reinterpret_cast<char*>(&data), 1, nullptr) != 0) {
            return -1;
        }
    } else if(remaining == 1) {
        uint8_t c1 = B64URL_REVERSE_LOOKUP[encodedBytes[position]];
        position += 1;

        if(jwtWriterWriteAll(writer, reinterpret_cast<char*>(&c1), 1, nullptr) != 0) {
            return -1;
        }
    }

    return 0;
}

size_t jwt::b64url::getEncodedLength(size_t dataLength) {
    size_t chunks = dataLength / 3;
    size_t rem = dataLength % 3;
    return (4 * chunks) + ((rem > 0) * (rem + 1));
}

size_t jwt::b64url::getDataLength(size_t encodedLength) {
    if(encodedLength <= 1) return encodedLength;
    size_t chunks = encodedLength / 4;
    size_t rem = encodedLength % 4;
    return (chunks * 3) + ((rem > 0) * (rem - 1));
}

int32_t jwt::b64url::decodeNew(const void* encoded, size_t encodedLength, Span<uint8_t> *output) {

    size_t decodedLength = getDataLength(encodedLength);
    output->data = new uint8_t[decodedLength];
    output->length = decodedLength;
    output->owned = true;

    int32_t result = 0;

    JwtWriter writer;
    if(jwtWriterCreateForBuffer(&writer, output->data, output->length) != 0) {
        result = 1;
        goto cleanup;
    }

    result = decode(encoded, encodedLength, writer);

cleanup:

    jwtWriterClose(&writer);
    return result;
}
