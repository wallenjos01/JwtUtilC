/**
 * Josh Wallentine
 * Created 10/32/25
 * Modified 11/12/25
 *
 * Implementation of token.h
 */


#include "algorithm.hpp"
#include "jwt/result.h"
#include "util.hpp"

#include <chrono>
#include <cstdint>
#include <jwt/key.h>
#include <jwt/json.h>
#include <jwt/token.h>
#include <jwt/core.h>
#include <jwt/stream.h>

#include <openssl/rand.h>

namespace {


JwtResult writeJsonObjectB64(JwtJsonObject* object, JwtWriter writer) {

    JwtResult result = JWT_RESULT_SUCCESS;

    JwtWriter objectWriter = {};
    JWT_CHECK(jwtWriterCreateDynamic(&objectWriter));
    JwtList* json;

    JWT_CHECK_GOTO(jwtWriteJsonObjectWriter(object, objectWriter), result, cleanup); 

    json = jwtWriterExtractDynamic(&objectWriter);
    jwt::b64url::encode(json->head, json->size, writer);

cleanup:

    jwtWriterClose(&objectWriter);
    return JWT_RESULT_SUCCESS;
}

bool isHmacAlgorithm(JwtAlgorithm algorithm) {
    return algorithm > JWT_ALGORITHM_NONE && algorithm <= JWT_ALGORITHM_HS512;
}

bool isSigningAlgorithm(JwtAlgorithm algorithm) {
    return algorithm > JWT_ALGORITHM_HS512 && algorithm <= JWT_ALGORITHM_PS512;
}

bool isEncryptionAlgorithm(JwtAlgorithm algorithm) {
    return algorithm > JWT_ALGORITHM_PS512;
}

JwtResult writeHmacToken(JwtJsonObject* header, JwtJsonObject* payload, JwtKey* key, JwtAlgorithm algorithm, JwtWriter out) {

    JWT_CHECK(writeJsonObjectB64(header, out));
    JWT_CHECK(jwtWriterWrite(out, ".", 1, nullptr));

    JWT_CHECK(writeJsonObjectB64(payload, out));

    const JwtList* toSign = jwtWriterExtractDynamic(&out);
    Span<uint8_t> toSignData(
        static_cast<uint8_t*>(toSign->head),
        toSign->size
    );
    toSignData.owned = false;

    size_t length;
    JWT_CHECK(jwt::hmac::generate(toSignData, key, algorithm, {}, &length));

    Span<uint8_t> span(new uint8_t[length], length);
    JWT_CHECK(jwt::hmac::generate(toSignData, key, algorithm, span, &length));

    JWT_CHECK(jwtWriterWrite(out, ".", 1, nullptr));
    JWT_CHECK(jwt::b64url::encode(span.data, span.length, out));

    return JWT_RESULT_SUCCESS;
}

JwtResult writeSignedToken(JwtJsonObject* header, JwtJsonObject* payload, JwtKey* key, JwtAlgorithm algorithm, JwtWriter out) {

    JWT_CHECK(writeJsonObjectB64(header, out));
    JWT_CHECK(jwtWriterWrite(out, ".", 1, nullptr));

    JWT_CHECK(writeJsonObjectB64(payload, out));

    const JwtList* toSign = jwtWriterExtractDynamic(&out);
    Span<uint8_t> toSignData(
        static_cast<uint8_t*>(toSign->head),
        toSign->size
    );
    toSignData.owned = false;

    size_t length;
    JWT_CHECK(jwt::sig::generate(toSignData, key, algorithm, {}, &length));

    Span<uint8_t> span(new uint8_t[length], length);
    JWT_CHECK(jwt::sig::generate(toSignData, key, algorithm, span, &length));

    JWT_CHECK(jwtWriterWrite(out, ".", 1, nullptr));
    JWT_CHECK(jwt::b64url::encode(span.data, length, out));

    return JWT_RESULT_SUCCESS;
}



JwtResult writeEncryptedToken(JwtJsonObject* header, JwtJsonObject* payload, JwtKey* key, JwtAlgorithm algorithm, JwtCryptAlgorithm crypt, JwtWriter out) {

    // Header
    JWT_CHECK(writeJsonObjectB64(header, out));
    JWT_CHECK(jwtWriterWrite(out, ".", 1, nullptr));


    // CEK
    size_t keyLength = jwt::enc::getKeyLength(crypt);
    Span<uint8_t> cek = {};
    Span<uint8_t> encryptedKey = {};
    JWT_CHECK(jwt::enc::generateCek(header, key, algorithm, crypt, &cek, &encryptedKey));
    if(encryptedKey.length > 0) {
        JWT_CHECK(jwt::b64url::encode(encryptedKey.data, encryptedKey.length, out));
    }
    JWT_CHECK(jwtWriterWrite(out, ".", 1, nullptr));

    // Initialization Vector
    size_t ivLength = jwt::enc::getIvLength(crypt);
    Span<uint8_t> iv = Span<uint8_t>(new uint8_t[ivLength], ivLength);
    RAND_bytes(iv.data, iv.length);

    JWT_CHECK(jwt::b64url::encode(iv.data, iv.length, out));
    JWT_CHECK(jwtWriterWrite(out, ".", 1, nullptr));

    // Ciphertext and authentication tag
    JwtWriter aadWriter = {};
    JWT_CHECK(jwtWriterCreateDynamic(&aadWriter));
    JwtResult res = writeJsonObjectB64(header, aadWriter);
    if(res != JWT_RESULT_SUCCESS) {
        jwtWriterClose(&aadWriter);
        return res;
    }

    JwtList* aad = jwtWriterExtractDynamic(&aadWriter);
    size_t aadLen = aad->size;
    Span<uint8_t> aadData = Span<uint8_t>(static_cast<uint8_t*>(jwtListReclaim(aad)), aadLen);
    jwtWriterClose(&aadWriter);

    JwtWriter payloadWriter = {};
    JWT_CHECK(jwtWriterCreateDynamic(&payloadWriter));
    res = jwtWriteJsonObjectWriter(payload, payloadWriter);
    if(res != JWT_RESULT_SUCCESS) {
        jwtWriterClose(&payloadWriter);
        return res;
    }
    JwtList* payloadJson = jwtWriterExtractDynamic(&payloadWriter);
    size_t payloadLen = payloadJson->size;
    Span<uint8_t> payloadData = Span<uint8_t>(static_cast<uint8_t*>(jwtListReclaim(payloadJson)), payloadLen);
    jwtWriterClose(&payloadWriter);

    size_t outputLength = 0;
    JWT_CHECK(jwt::enc::encryptAndProtect(payloadData, aadData, iv, cek, crypt, {}, &outputLength, nullptr));

    size_t contentLength = 0;
    Span<uint8_t> cipherText = Span<uint8_t>(new uint8_t[outputLength], outputLength);
    JWT_CHECK(jwt::enc::encryptAndProtect(payloadData, aadData, iv, cek, crypt, cipherText, &outputLength, &contentLength));
    
    JWT_CHECK(jwt::b64url::encode(cipherText.data, contentLength, out));
    jwtWriterWrite(out, ".", 1, nullptr);

    JWT_CHECK(jwt::b64url::encode(cipherText.data + contentLength, outputLength - contentLength, out));

    return JWT_RESULT_SUCCESS;
}

}


JwtResult jwtCreateUnprotectedToken(JwtJsonObject* payload, JwtString* out) {

    JwtResult result = JWT_RESULT_SUCCESS;
    JwtWriter tokenWriter;
    jwtWriterCreateDynamic(&tokenWriter);

    JwtJsonObject header;
    jwtJsonObjectCreate(&header);
    jwtJsonObjectSetString(&header, "alg", "none");
    jwtJsonObjectSetString(&header, "typ", "jwt");

    JwtWriter headerWriter;
    jwtWriterCreateDynamic(&headerWriter);

    JWT_CHECK_GOTO(writeJsonObjectB64(&header, tokenWriter), result, cleanup);
    JWT_CHECK_GOTO(jwtWriterWrite(tokenWriter, ".", 1, nullptr), result, cleanup);

    JWT_CHECK_GOTO(writeJsonObjectB64(payload, tokenWriter), result, cleanup);
    JWT_CHECK_GOTO(jwtWriterWrite(tokenWriter, ".", 1, nullptr), result, cleanup);

    {
        jwtWriterWrite(tokenWriter, "\0", 1, nullptr);
        JwtList* tokenData = jwtWriterExtractDynamic(&tokenWriter);
        size_t length = tokenData->size;
        void* buffer = jwtListReclaim(tokenData);

        *out = {
            .length = length - 1,
            .data = static_cast<char*>(buffer)
        };
    }

cleanup:

    jwtJsonObjectDestroy(&header);
    jwtWriterClose(&tokenWriter);
    return result;
}

JwtResult jwtCreateSignedToken(JwtJsonObject* payload, JwtKey* key, JwtAlgorithm algorithm, JwtString* out) {

    if(key->algorithm != JWT_ALGORITHM_UNKNOWN && key->algorithm != algorithm) {
        return JWT_RESULT_INVALID_ALGORITHM;
    }
    JwtResult result = JWT_RESULT_SUCCESS;

    JwtJsonObject header;
    jwtJsonObjectCreate(&header);
    jwtJsonObjectSetString(&header, "alg", jwt::getAlgorithmName(algorithm));
    jwtJsonObjectSetString(&header, "typ", "jwt");

    JwtWriter writer;
    jwtWriterCreateDynamic(&writer);

    if(isHmacAlgorithm(algorithm)) {
        result = writeHmacToken(&header, payload, key, algorithm, writer);
        if(result != JWT_RESULT_SUCCESS)
            goto cleanup;
    } else if(isSigningAlgorithm(algorithm)) {
        result = writeSignedToken(&header, payload, key, algorithm, writer);
        if(result != JWT_RESULT_SUCCESS)
            goto cleanup;
    } else {
        result = JWT_RESULT_INVALID_ALGORITHM;
        goto cleanup;
    }

    {
        jwtWriterWrite(writer, "\0", 1, nullptr);
        JwtList* tokenData = jwtWriterExtractDynamic(&writer);
        size_t length = tokenData->size;
        void* buffer = jwtListReclaim(tokenData);

        *out = {
            .length = length - 1,
            .data = static_cast<char*>(buffer)
        };
    }

cleanup:

    jwtWriterClose(&writer);
    jwtJsonObjectDestroy(&header);
    return result;

}

JwtResult jwtCreateEncryptedToken(JwtJsonObject* payload, JwtKey* key, JwtAlgorithm algorithm, JwtCryptAlgorithm crypt, JwtString* out) {

    if(key->algorithm != JWT_ALGORITHM_UNKNOWN && key->algorithm != algorithm) {
        return JWT_RESULT_INVALID_ALGORITHM;
    }
    if(!isEncryptionAlgorithm(algorithm)) {
        return JWT_RESULT_INVALID_ALGORITHM;
    }


    JwtJsonObject header;
    jwtJsonObjectCreate(&header);
    jwtJsonObjectSetString(&header, "alg", jwt::getAlgorithmName(algorithm));
    jwtJsonObjectSetString(&header, "enc", jwt::enc::getCryptAlgorithmName(crypt));
    jwtJsonObjectSetString(&header, "typ", "jwt");

    JwtWriter writer;
    jwtWriterCreateDynamic(&writer);

    JwtResult result = writeEncryptedToken(&header, payload, key, algorithm, crypt, writer);

    if(result == 0) {
        jwtWriterWrite(writer, "\0", 1, nullptr);
        JwtList* tokenData = jwtWriterExtractDynamic(&writer);
        size_t length = tokenData->size;
        void* buffer = jwtListReclaim(tokenData);

        *out = {
            .length = length - 1,
            .data = static_cast<char*>(buffer)
        };
    }

    jwtWriterClose(&writer);
    return result;
}


JwtResult jwtReadTokenHeader(JwtString token, JwtJsonObject* out) {

    size_t firstDot = 0;
    if(firstIndexOf(token, '.', &firstDot) == -1) {
        return JWT_RESULT_MALFORMED_JWT;
    }

    Span<uint8_t> json = {};
    JWT_CHECK(jwt::b64url::decodeNew(token.data, firstDot, &json));

    JwtReader headerReader = {};
    jwtReaderCreateForBuffer(&headerReader, json.data, json.length);

    JwtJsonElement header = {};
    JWT_CHECK(jwtReadJsonReader(&header, headerReader));
    if(header.type != JWT_JSON_ELEMENT_TYPE_OBJECT) {
        jwtJsonElementDestroy(&header);
        return JWT_RESULT_NOT_AN_OBJECT;
    }

    *out = header.object;
    return JWT_RESULT_SUCCESS;
}


void jwtParsedTokenDestroy(JwtParsedToken *token) {

    jwtJsonObjectDestroy(&token->header);
    jwtJsonObjectDestroy(&token->payload);
    token->algorithm = JWT_ALGORITHM_UNKNOWN;

}

JwtResult jwtVerifyToken(JwtString token, JwtKey* key, JwtParsedToken* out, JwtVerifyFlags flags) {

    size_t firstDot;
    size_t lastDot;
    if(firstIndexOf(token, '.', &firstDot) != 0 || lastIndexOf(token, '.', &lastDot) != 0 && firstDot == lastDot) {
        return JWT_RESULT_MALFORMED_JWT;
    }

    JWT_CHECK(jwtReadTokenHeader(token, &out->header));

    JwtString keyId = jwtJsonObjectGetString(&out->header, "kid");
    JwtString algStr = jwtJsonObjectGetString(&out->header, "alg");

    if(keyId.data != nullptr 
        && (key->keyId.data == nullptr 
            || key->keyId.length != keyId.length 
            || memcmp(key->keyId.data, keyId.data, keyId.length) != 0)) {

        return JWT_RESULT_INVALID_KEY_ID;
    }

    JWT_CHECK(jwtAlgorithmParse(&out->algorithm, algStr.data));

    bool allowUnprotected = flags & JWT_VERIFY_FLAG_ALLOW_UNPROTECTED;
    if(out->algorithm == JWT_ALGORITHM_NONE) {
        if(!allowUnprotected) {
            return JWT_RESULT_UNPROTECTED_TOKEN;
        }
    } else if(key == nullptr || (key->algorithm != JWT_ALGORITHM_UNKNOWN && key->algorithm != out->algorithm)) {
        return JWT_RESULT_INVALID_KEY;
    }

    if(isEncryptionAlgorithm(out->algorithm)) {

        JwtCryptAlgorithm crypt = JWT_CRYPT_ALGORITHM_UNKNOWN;
        JWT_CHECK(jwtCryptAlgorithmParse(&crypt, jwtJsonObjectGetString(&out->header, "enc").data));

        size_t dotIndex = 0;
        size_t searchIndex = 0;
        size_t dots[4] = {};
        while(dotIndex < 4 && nextIndexOf(token, '.', searchIndex, &dots[dotIndex]) == 0) {
            searchIndex = dots[dotIndex] + 1;
            dotIndex++;
        }

        if(dots[0] != firstDot || dots[3] != lastDot) {
            return JWT_RESULT_MALFORMED_JWT;
        }

        Span<uint8_t> aad = {};
        aad.data = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(token.data));
        aad.length = firstDot;

        Span<uint8_t> keyData;
        if(out->algorithm == JWT_ALGORITHM_DIRECT) {
            if(key->type != JWT_KEY_TYPE_OCTET_SEQUENCE) {
                return JWT_RESULT_INVALID_KEY_TYPE;
            }
            if(key->operations != 0 && (key->operations & JWT_KEY_OP_DECRYPT) == 0) {
                return JWT_RESULT_INVALID_KEY_OPERATION;
            }
            keyData = *static_cast<Span<uint8_t>*>(key->keyData);
        } else {
            Span<uint8_t> encryptedKey = {};
            JWT_CHECK(jwt::b64url::decodeNew(token.data + dots[0] + 1, dots[1] - dots[0] - 1, &encryptedKey));

            size_t outputLength = 0;
            JWT_CHECK(jwt::enc::decryptCek(&out->header, encryptedKey, key, out->algorithm, {}, &outputLength));
            
            keyData = Span<uint8_t>(new uint8_t[outputLength], outputLength);
            JWT_CHECK(jwt::enc::decryptCek(&out->header, encryptedKey, key, out->algorithm, keyData, &keyData.length));
        }

        Span<uint8_t> iv = {};
        JWT_CHECK(jwt::b64url::decodeNew(token.data + dots[1] + 1, dots[2] - dots[1] - 1, &iv));

        Span<uint8_t> cipherText = {};
        JWT_CHECK(jwt::b64url::decodeNew(token.data + dots[2] + 1, dots[3] - dots[2] - 1, &cipherText));

        Span<uint8_t> tag = {};
        JWT_CHECK(jwt::b64url::decodeNew(token.data + lastDot + 1, token.length - lastDot - 1, &tag));

        size_t payloadLen = 0;
    
        jwt::enc::decryptAndVerify(cipherText, tag, aad, iv, keyData, crypt, {}, &payloadLen);

        Span<uint8_t> decodedPayload = Span<uint8_t>(new uint8_t[payloadLen], payloadLen);
        JWT_CHECK(jwt::enc::decryptAndVerify(cipherText, tag, aad, iv, keyData, crypt, decodedPayload, &payloadLen));

        JwtJsonElement payload;
        JWT_CHECK(jwtReadJsonString(&payload, reinterpret_cast<char*>(decodedPayload.data), payloadLen));

        if(payload.type != JWT_JSON_ELEMENT_TYPE_OBJECT) {
            jwtJsonElementDestroy(&payload);
            return JWT_RESULT_NOT_AN_OBJECT;
        }

        out->payload = payload.object;

    } else {

        Span<uint8_t> remaining = {};
        remaining.data = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(token.data));
        remaining.length = lastDot;

        if(isHmacAlgorithm(out->algorithm)) {

            Span<uint8_t> mac = {};
            jwt::b64url::decodeNew(token.data + lastDot + 1, token.length - lastDot - 1, &mac);
            JWT_CHECK(jwt::hmac::validate(remaining, mac, key, out->algorithm));

        } else if(isSigningAlgorithm(out->algorithm)) {

            Span<uint8_t> sig = {};
            jwt::b64url::decodeNew(token.data + lastDot + 1, token.length - lastDot - 1, &sig);
            JWT_CHECK(jwt::sig::validate(remaining, sig, key, out->algorithm));

        }


        Span<uint8_t> payloadData = {};
        payloadData.data = remaining.data + firstDot + 1;
        payloadData.length = lastDot - firstDot - 1;

        JwtJsonElement payload = {};
        Span<uint8_t> payloadJson = {};
        jwt::b64url::decodeNew(payloadData.data, payloadData.length, &payloadJson);
        JWT_CHECK(jwtReadJsonString(&payload, reinterpret_cast<char*>(payloadJson.data), payloadJson.length));
        if(payload.type != JWT_JSON_ELEMENT_TYPE_OBJECT) {
            jwtJsonElementDestroy(&payload);
            return JWT_RESULT_NOT_AN_OBJECT;
        }

        out->payload = payload.object;
    }

    bool allowExpired = flags & JWT_VERIFY_FLAG_ALLOW_EXPIRED;
    bool allowEarly = flags & JWT_VERIFY_FLAG_ALLOW_EARLY;

    if(!allowExpired) {
        JwtJsonElement exp = jwtJsonObjectGet(&out->payload, JWT_CLAIM_EXPIRATION);
        if(exp.type != JWT_JSON_ELEMENT_TYPE_NULL) {
            if(exp.type != JWT_JSON_ELEMENT_TYPE_NUMERIC) {
                return JWT_RESULT_NOT_A_NUMBER;
            }
            uint64_t now = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            
            JwtNumeric number = jwtJsonElementAsNumber(exp);
            if(number.type == JWT_NUMBER_TYPE_UNSIGNED && number.u64 < now) {
                return JWT_RESULT_EXPIRED_TOKEN;
            }
            if(number.type == JWT_NUMBER_TYPE_SIGNED && number.i64 < now) {
                return JWT_RESULT_EXPIRED_TOKEN;
            }
            if(number.type == JWT_NUMBER_TYPE_FLOAT && number.f64 < now) {
                return JWT_RESULT_EXPIRED_TOKEN;
            }
        }

    }
    if(!allowEarly) {

        JwtJsonElement nbf = jwtJsonObjectGet(&out->payload, JWT_CLAIM_NOT_BEFORE);
        if(nbf.type != JWT_JSON_ELEMENT_TYPE_NULL) {
            if(nbf.type != JWT_JSON_ELEMENT_TYPE_NUMERIC) {
                return JWT_RESULT_NOT_A_NUMBER;
            }
            uint64_t now = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            
            JwtNumeric number = jwtJsonElementAsNumber(nbf);
            if(number.type == JWT_NUMBER_TYPE_UNSIGNED && number.u64 > now) {
                return JWT_RESULT_EARLY_TOKEN;
            }
            if(number.type == JWT_NUMBER_TYPE_SIGNED && number.i64 > now) {
                return JWT_RESULT_EARLY_TOKEN;
            }
            if(number.type == JWT_NUMBER_TYPE_FLOAT && number.f64 > now) {
                return JWT_RESULT_EARLY_TOKEN;
            }
        }
    }

    return JWT_RESULT_SUCCESS;
}


JwtResult jwtVerifyTokenWithSet(JwtString token, JwtKey* key, JwtParsedToken* out, JwtVerifyFlags flags) {
    return JWT_RESULT_UNIMPLEMENTED;
}
