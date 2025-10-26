#include "algorithm.hpp"
#include <jwt/json.h>
#include <jwt/token.h>
#include <jwt/core.h>
#include <jwt/stream.h>

JwtString jwtCreateUnprotectedToken(JwtJsonObject payload) {


    JwtJsonElement header = {
       .type = JWT_JSON_ELEMENT_TYPE_OBJECT
    };
    jwtJsonObjectCreate(&header.object);

    JwtWriter headerWriter;
    jwtWriterCreateDynamic(&headerWriter);
    jwtJsonObjectSetString(&header.object, "alg", "none");
    jwtJsonObjectSetString(&header.object, "typ", "jwt");

    if(jwtWriteJsonWriter(&header, headerWriter) != 0) {
        return {};
    }
    jwtJsonElementDestroy(&header);

    JwtJsonElement payloadElement = {
        .type = JWT_JSON_ELEMENT_TYPE_OBJECT,
        .object = payload
    };
    JwtWriter payloadWriter;
    jwtWriterCreateDynamic(&payloadWriter);
    if(jwtWriteJsonWriter(&payloadElement, payloadWriter) != 0) {
        return {};
    }

    JwtWriter tokenWriter;
    jwtWriterCreateDynamic(&tokenWriter);

    JwtList* headerJson = jwtWriterExtractDynamic(&headerWriter);
    jwt::b64url::encode(headerJson->head, headerJson->size, tokenWriter);
    jwtWriterWrite(tokenWriter, ".", 1, nullptr);

    JwtList* payloadJson = jwtWriterExtractDynamic(&payloadWriter);
    jwt::b64url::encode(payloadJson->head, payloadJson->size, tokenWriter);
    jwtWriterWrite(tokenWriter, ".", 1, nullptr);

    jwtWriterClose(&headerWriter);
    jwtWriterClose(&payloadWriter);

    JwtList* tokenData = jwtWriterExtractDynamic(&tokenWriter);
    size_t length = tokenData->size;
    void* buffer = jwtListReclaim(tokenData);

    jwtWriterClose(&tokenWriter);

    return {
        .length = length,
        .data = static_cast<char*>(buffer)
    };
}

