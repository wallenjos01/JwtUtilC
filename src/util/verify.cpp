#include "app.hpp"
#include "jwt/key.h"

#include <functional>
#include <jwt/json.h>
#include <jwt/token.h>

int verifyToken(argparse::ArgumentParser &args) {

    std::string tokenStr = args.get("token");
    JwtString token = { .length = tokenStr.length(), .data = tokenStr.c_str() };

    JwtJsonObject header;
    if(jwtReadTokenHeader(token, &header) != 0) {
        std::cerr << "Unable to parse token header!\n";
        return 1;
    }

    JwtAlgorithm algorithm;
    if(jwtAlgorithmParse(&algorithm, jwtJsonObjectGetString(&header, "alg").data) != 0) {
        std::cerr << "Unable to parse token algorithm!\n";
        return 1;
    }

    JwtKey key = {};
    if(algorithm != JWT_ALGORITHM_NONE) {
        JwtReader keyReader = {};
        if(jwtReaderCreateForFile(&keyReader, args.get("key").c_str()) != 0) {
            std::cerr << "Unable to open key file at!\n";
            return 1;
        }
        
        JwtJsonElement keyJson = {};
        JwtJsonParseResult result = jwtReadJsonReader(&keyJson, keyReader);
        if(result != JWT_JSON_PARSE_RESULT_SUCCESS) {
            jwtReaderClose(&keyReader);
            std::cerr << "Unable to read key file! (" << result << ")\n";
            return 1;
        }
        jwtReaderClose(&keyReader);

        if(keyJson.type != JWT_JSON_ELEMENT_TYPE_OBJECT) {
            std::cerr << "Key is not a JSON object!\n";
            jwtJsonElementDestroy(&keyJson);
            return 1;
        }

        if(jwtKeyParse(&key, &keyJson.object) != JWT_KEY_PARSE_RESULT_SUCCESS) {
            std::cerr << "Key is not a valid JWK!\n";
            jwtJsonElementDestroy(&keyJson);
            return 1;
        }
        jwtJsonElementDestroy(&keyJson);
    } 

    JwtParsedToken parsed = {};
    JwtVerifyFlags flags = 0;
    if(args.is_used("--allow-unprotected")) {
        flags |= JWT_VERIFY_FLAG_ALLOW_UNPROTECTED;
    }
    if(args.is_used("--allow-expired")) {
        flags |= JWT_VERIFY_FLAG_ALLOW_EXPIRED;
    }
    if(args.is_used("--allow-early")) {
        flags |= JWT_VERIFY_FLAG_ALLOW_EARLY;
    }

    int32_t result = jwtVerifyToken(token, &key, &parsed, flags);
    if(result < 0) {
        std::cerr << "Failed to parse token!\n";
        goto cleanup;
    }
    else if(result > 0) {
        std::cerr << "Unable to verify token!\n";
        goto cleanup;
    }

    if(!args.is_used("--output")) {

        std::cout << "Verification successful!\n";
        
        JwtString headerStr = {};
        JwtJsonElement headerElement = { .type = JWT_JSON_ELEMENT_TYPE_OBJECT, .object = parsed.header };
        jwtWriteJsonString(&headerElement, &headerStr);

        std::cout << "Header: " << headerStr.data << "\n";

        JwtString payloadStr = {};
        JwtJsonElement payloadElement = { .type = JWT_JSON_ELEMENT_TYPE_OBJECT, .object = parsed.payload };
        jwtWriteJsonString(&payloadElement, &payloadStr);

        std::cout << "Payload: " << payloadStr.data << "\n";

    } else {

        std::string output = args.get("--output");
        if(output == "json") {

            JwtString headerStr = {};
            JwtJsonElement headerElement = { .type = JWT_JSON_ELEMENT_TYPE_OBJECT, .object = parsed.header };
            jwtWriteJsonString(&headerElement, &headerStr);

            std::cout << "{\"header\":" << headerStr.data << ",";

            JwtString payloadStr = {};
            JwtJsonElement payloadElement = { .type = JWT_JSON_ELEMENT_TYPE_OBJECT, .object = parsed.payload };
            jwtWriteJsonString(&payloadElement, &payloadStr);

            std::cout << "\"payload\":" << payloadStr.data << "}\n";


        } else if(output == "payload") {

            JwtString payloadStr = {};
            JwtJsonElement payloadElement = { .type = JWT_JSON_ELEMENT_TYPE_OBJECT, .object = parsed.payload };
            jwtWriteJsonString(&payloadElement, &payloadStr);

            std::cout << payloadStr.data << "\n";
        
        } else if(output == "header") {

            JwtString headerStr = {};
            JwtJsonElement headerElement = { .type = JWT_JSON_ELEMENT_TYPE_OBJECT, .object = parsed.header };
            jwtWriteJsonString(&headerElement, &headerStr);

            std::cout << headerStr.data << "\n";
        }
    }

cleanup:

    jwtParsedTokenDestroy(&parsed);
    return result;
}
