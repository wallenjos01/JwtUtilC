#include "app.hpp"

#include <jwt/core.h>
#include <jwt/key.h>
#include <jwt/json.h>
#include <jwt/stream.h>
#include <jwt/token.h>

int createToken(argparse::ArgumentParser &args) {

    JwtAlgorithm algorithm = JWT_ALGORITHM_UNKNOWN;
    if(jwtAlgorithmParse(&algorithm, args.get("algorithm").c_str()) != 0) {
        std::cerr << "Invalid algorithm!\n";
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

    JwtJsonObject payload = {};
    if(args.is_used("--payload")) {
        std::string payloadText = args.get("--payload");
        JwtJsonElement parsed = {};
        if(jwtReadJsonString(&parsed, payloadText.c_str(), payloadText.length()) != JWT_JSON_PARSE_RESULT_SUCCESS) {
            std::cerr << "Payload is not valid JSON!\n";
            jwtKeyDestroy(&key);
            return 1;
        }
        if(parsed.type != JWT_JSON_ELEMENT_TYPE_OBJECT) {
            std::cerr << "Payload is not a JSON object!\n";
            jwtJsonElementDestroy(&parsed);
            jwtKeyDestroy(&key);
            return 1;
        }
        payload = parsed.object;
    } else {
        jwtJsonObjectCreate(&payload);
    }

    JwtString token;
    if(algorithm == JWT_ALGORITHM_NONE) {
        if(jwtCreateUnprotectedToken(&payload, &token) != 0) {
            std::cerr << "Token creation failed!\n";
            jwtJsonObjectDestroy(&payload);
            return 1;
        }
    } else {
        if(jwtCreateToken(&payload, &key, algorithm, &token) != 0) {
            std::cerr << "Token creation failed!\n";
            jwtJsonObjectDestroy(&payload);
            jwtKeyDestroy(&key);
            return 1;
        }
    }

    std::cout << token.data << std::endl;

    jwtJsonObjectDestroy(&payload);
    jwtKeyDestroy(&key);

    return 0;
}
