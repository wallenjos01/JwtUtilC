#include "app.hpp"
#include "jwt/key.h"
#include "jwt/result.h"

#include <jwt/json.h>
#include <jwt/token.h>

JwtResult verifyToken(argparse::ArgumentParser &args) {

    std::string tokenStr = args.get("token");
    JwtString token = { .length = tokenStr.length(), .data = tokenStr.c_str() };

    JwtJsonObject header;
    JWT_CHECK(jwtReadTokenHeader(token, &header));

    JwtAlgorithm algorithm;
    JWT_CHECK(jwtAlgorithmParse(&algorithm, jwtJsonObjectGetString(&header, "alg").data));

    JwtKey key = {};
    if(algorithm != JWT_ALGORITHM_NONE) {
        if(args.is_used("--key")) {
            JwtReader keyReader = {};
            JWT_CHECK(jwtReaderCreateForFile(&keyReader, args.get("--key").c_str()));
            
            JwtJsonElement keyJson = {};
            JwtResult result = jwtReadJsonReader(&keyJson, keyReader);
            if(result != JWT_RESULT_SUCCESS) {
                jwtReaderClose(&keyReader);
                std::cerr << "Unable to read key file!\n";
                return result;
            }
            jwtReaderClose(&keyReader);

            if(keyJson.type != JWT_JSON_ELEMENT_TYPE_OBJECT) {
                std::cerr << "Key is not a JSON object!\n";
                jwtJsonElementDestroy(&keyJson);
                return JWT_RESULT_NOT_AN_OBJECT;
            }

            result = jwtKeyParse(&key, &keyJson.object);
            if(result != JWT_RESULT_SUCCESS) {
                std::cerr << "Key is not a valid JWK!\n";
                jwtJsonElementDestroy(&keyJson);
                return result;
            }
            jwtJsonElementDestroy(&keyJson);
        } else if(args.is_used("--password")) {
            std::string pwd = args.get("--password");
            JWT_CHECK(jwtKeyCreateOct(&key, pwd.c_str(), pwd.length()));
        } else {
            std::cerr << "A key is required!\n";
            return JWT_RESULT_INVALID_KEY;
        }
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

    JwtResult result = jwtVerifyToken(token, &key, &parsed, flags);

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
        JWT_CHECK_GOTO(jwtWriteJsonObjectString(&header, &headerStr), result, cleanup);

        std::cout << "Header: " << headerStr.data << "\n";

        JwtString payloadStr = {};
        JWT_CHECK_GOTO(jwtWriteJsonObjectString(&parsed.payload, &payloadStr), result, cleanup);

        std::cout << "Payload: " << payloadStr.data << "\n";

    } else {

        std::string output = args.get("--output");
        if(output == "json") {

            JwtString headerStr = {};
            JWT_CHECK_GOTO(jwtWriteJsonObjectString(&header, &headerStr), result, cleanup);

            std::cout << "{\"header\":" << headerStr.data << ",";

            JwtString payloadStr = {};
            JWT_CHECK_GOTO(jwtWriteJsonObjectString(&parsed.payload, &payloadStr), result, cleanup);

            std::cout << "\"payload\":" << payloadStr.data << "}\n";


        } else if(output == "payload") {

            JwtString payloadStr = {};
            JWT_CHECK_GOTO(jwtWriteJsonObjectString(&parsed.payload, &payloadStr), result, cleanup);

            std::cout << payloadStr.data << "\n";
        
        } else if(output == "header") {

            JwtString headerStr = {};
            JWT_CHECK_GOTO(jwtWriteJsonObjectString(&header, &headerStr), result, cleanup);

            std::cout << headerStr.data << "\n";
        }
    }

cleanup:

    jwtParsedTokenDestroy(&parsed);
    return result;
}
