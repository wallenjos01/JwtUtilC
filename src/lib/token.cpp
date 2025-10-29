/**
 * Josh Wallentine
 * Created 10/32/25
 * Modified 10/27/25
 *
 * Implementation of token.h
 */


#include "algorithm.hpp"
#include "util.hpp"

#include <jwt/key.h>
#include <jwt/json.h>
#include <jwt/token.h>
#include <jwt/core.h>
#include <jwt/stream.h>

namespace {


int32_t writeJsonObjectB64(JwtJsonObject* object, JwtWriter writer) {

    JwtJsonElement payloadElement = {
        .type = JWT_JSON_ELEMENT_TYPE_OBJECT,
        .object = *object
    };
    JwtWriter objectWriter = {};
    jwtWriterCreateDynamic(&objectWriter);
    if(jwtWriteJsonWriter(&payloadElement, objectWriter) != 0) {
        jwtWriterClose(&objectWriter);
        return -1;
    }

    JwtList* json = jwtWriterExtractDynamic(&objectWriter);
    jwt::b64url::encode(json->head, json->size, writer);
    jwtWriterClose(&objectWriter);

    return 0;
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

int32_t writeHmacToken(JwtJsonObject* header, JwtJsonObject* payload, JwtKey* key, JwtAlgorithm algorithm, JwtWriter out) {

    JWT_CHECK(writeJsonObjectB64(header, out));
    jwtWriterWrite(out, ".", 1, nullptr);

    JWT_CHECK(writeJsonObjectB64(payload, out));

    const JwtList* toSign = jwtWriterExtractDynamic(&out);
    Span<uint8_t> toSignData(
        static_cast<uint8_t*>(toSign->head),
        toSign->size
    );
    toSignData.owned = false;

    size_t length;
    JWT_CHECK(jwt::generateHmac(toSignData, key, algorithm, {}, &length));

    Span<uint8_t> span(new uint8_t[length], length);
    JWT_CHECK(jwt::generateHmac(toSignData, key, algorithm, span, &length));

    jwtWriterWrite(out, ".", 1, nullptr);
    jwt::b64url::encode(span.data, span.length, out);

    return 0;
}

int32_t writeSignedToken(JwtJsonObject* header, JwtJsonObject* payload, JwtKey* key, JwtAlgorithm algorithm, JwtWriter out) {

    JWT_CHECK(writeJsonObjectB64(header, out));
    jwtWriterWrite(out, ".", 1, nullptr);

    JWT_CHECK(writeJsonObjectB64(payload, out));

    const JwtList* toSign = jwtWriterExtractDynamic(&out);
    Span<uint8_t> toSignData(
        static_cast<uint8_t*>(toSign->head),
        toSign->size
    );
    toSignData.owned = false;

    size_t length;
    JWT_CHECK(jwt::generateSignature(toSignData, key, algorithm, {}, &length));

    Span<uint8_t> span(new uint8_t[length], length);
    JWT_CHECK(jwt::generateSignature(toSignData, key, algorithm, span, &length));

    jwtWriterWrite(out, ".", 1, nullptr);
    jwt::b64url::encode(span.data, length, out);

    return 0;
}

int32_t writeEncryptedToken(JwtJsonObject* header, JwtJsonObject* payload, JwtKey* key, JwtAlgorithm algorithm, JwtWriter out) {

    return -1;
}


}


int32_t jwtCreateUnprotectedToken(JwtJsonObject* payload, JwtString* out) {

    int32_t result = 0;
    JwtWriter tokenWriter;
    jwtWriterCreateDynamic(&tokenWriter);

    JwtJsonObject header;
    jwtJsonObjectCreate(&header);
    jwtJsonObjectSetString(&header, "alg", "none");
    jwtJsonObjectSetString(&header, "typ", "jwt");

    JwtWriter headerWriter;
    jwtWriterCreateDynamic(&headerWriter);

    if(writeJsonObjectB64(&header, tokenWriter) != 0) {
        result = -1;
        goto cleanup;
    }
    jwtWriterWrite(tokenWriter, ".", 1, nullptr);

    if(writeJsonObjectB64(payload, tokenWriter) != 0) {
        result = -2;
        goto cleanup;
    }
    jwtWriterWrite(tokenWriter, ".", 1, nullptr);

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

int32_t jwtCreateToken(JwtJsonObject* payload, JwtKey* key, JwtAlgorithm algorithm, JwtString* out) {

    if(key->algorithm != JWT_ALGORITHM_UNKNOWN && key->algorithm != algorithm) {
        return -101;
    }
    int32_t result = 0;

    JwtJsonObject header;
    jwtJsonObjectCreate(&header);
    jwtJsonObjectSetString(&header, "alg", jwt::getAlgorithmName(algorithm));
    jwtJsonObjectSetString(&header, "typ", "jwt");

    JwtWriter writer;
    jwtWriterCreateDynamic(&writer);

    if(isHmacAlgorithm(algorithm)) {
        result = writeHmacToken(&header, payload, key, algorithm, writer);
        if(result != 0)
            goto cleanup;
    } else if(isSigningAlgorithm(algorithm)) {
        result = writeSignedToken(&header, payload, key, algorithm, writer);
        if(result != 0)
            goto cleanup;
    } else if(isEncryptionAlgorithm(algorithm)) {
        result = writeEncryptedToken(&header, payload, key, algorithm, writer);
        if(result != 0)
            goto cleanup;
    } else {
        result = -102;
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


int32_t jwtReadTokenHeader(JwtString token, JwtJsonObject* out) {

    size_t firstDot = 0;
    if(firstIndexOf(token, '.', &firstDot) == -1) {
        return -1;
    }

    Span<uint8_t> json = {};
    if(jwt::b64url::decodeNew(token.data, firstDot, &json) != 0) {
        return -2;
    }

    JwtReader headerReader = {};
    jwtReaderCreateForBuffer(&headerReader, json.data, json.length);

    JwtJsonElement header = {};
    if(jwtReadJsonReader(&header, headerReader) != 0) {
        return -3;
    }
    if(header.type != JWT_JSON_ELEMENT_TYPE_OBJECT) {
        jwtJsonElementDestroy(&header);
        return -4;
    }

    *out = header.object;
    return 0;
}


int32_t jwtVerifyToken(JwtString token, JwtKey* key, JwtParsedToken* out, bool allowUnprotected) {

    size_t firstDot;
    size_t lastDot;
    if(firstIndexOf(token, '.', &firstDot) != 0 || lastIndexOf(token, '.', &lastDot) != 0 && firstDot == lastDot) {
        return -1;
    }

    JwtJsonObject header;
    if(jwtReadTokenHeader(token, &header) != 0) {
        return -2;
    }

    int32_t result = 0;

    JwtString keyId = jwtJsonObjectGetString(&header, "kid");
    JwtString algStr = jwtJsonObjectGetString(&header, "alg");
    JwtAlgorithm alg;

    if(keyId.data != nullptr 
        && (key->keyId.data == nullptr 
            || key->keyId.length != keyId.length 
            || memcmp(key->keyId.data, keyId.data, keyId.length) != 0)) {

        result = -3;
        goto cleanup;
    }

    if(jwt::parseAlgorithm(&alg, algStr) != 0) {
        result = -4;
        goto cleanup;
    }

    if(alg == JWT_ALGORITHM_NONE) {
        result = allowUnprotected ? 0 : -6;
        goto cleanup;
    }

    if(key == nullptr || (key->algorithm != JWT_ALGORITHM_UNKNOWN && key->algorithm != alg)) {
        result = -5;
        goto cleanup;
    }

    if(isEncryptionAlgorithm(alg)) {
        // TODO

    } else if(isHmacAlgorithm(alg)) {

        Span<uint8_t> remaining = {};
        remaining.data = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(token.data));
        remaining.length = lastDot;

        Span<uint8_t> mac = {};
        jwt::b64url::decodeNew(token.data + lastDot + 1, token.length - lastDot - 1, &mac);
        result = jwt::validateHmac(remaining, mac, key, alg);

    } else {
        // Signing algorithm
        Span<uint8_t> remaining = {};
        remaining.data = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(token.data));
        remaining.length = lastDot;

        Span<uint8_t> sig = {};
        jwt::b64url::decodeNew(token.data + lastDot + 1, token.length - lastDot - 1, &sig);
        result = jwt::validateSignature(remaining, sig, key, alg);
    }

cleanup:

    jwtJsonObjectDestroy(&header);
    return result;
}


int32_t jwtVerifyTokenWithSet(JwtString token, JwtKey* key, JwtParsedToken* out, bool allowUnprotected) {
    return 0;
}
