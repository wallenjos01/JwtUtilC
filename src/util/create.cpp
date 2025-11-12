#include "app.hpp"

#include <jwt/core.h>
#include <jwt/key.h>
#include <jwt/json.h>
#include <jwt/stream.h>
#include <jwt/token.h>
#include <jwt/result.h>

JwtResult createToken(argparse::ArgumentParser &args) {

    JwtAlgorithm algorithm = JWT_ALGORITHM_UNKNOWN;
    JWT_CHECK(jwtAlgorithmParse(&algorithm, args.get("algorithm").c_str()));

    JwtKey key = {};
    if(algorithm != JWT_ALGORITHM_NONE) {
        JwtReader keyReader = {};
        JWT_CHECK(jwtReaderCreateForFile(&keyReader, args.get("key").c_str()));
        
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
    }

    JwtJsonObject payload = {};
    if(args.is_used("--payload")) {
        std::string payloadText = args.get("--payload");
        JwtJsonElement parsed = {};
        JwtResult res = jwtReadJsonString(&parsed, payloadText.c_str(), payloadText.length());
        if(res != JWT_RESULT_SUCCESS) {
            std::cerr << "Payload is not valid JSON!\n";
            jwtKeyDestroy(&key);
            return res;
        }
        if(parsed.type != JWT_JSON_ELEMENT_TYPE_OBJECT) {
            std::cerr << "Payload is not a JSON object!\n";
            jwtJsonElementDestroy(&parsed);
            jwtKeyDestroy(&key);
            return JWT_RESULT_NOT_AN_OBJECT;
        }
        payload = parsed.object;
    } else {
        jwtJsonObjectCreate(&payload);
    }

    if(args.is_used("--issuer")) {
        jwtJsonObjectSetString(&payload, JWT_CLAIM_ISSUER, args.get("--issuer").c_str());
    }

    if(args.is_used("--audience")) {
        jwtJsonObjectSetString(&payload, JWT_CLAIM_AUDIENCE, args.get("--audience").c_str());
    }

    if(args.is_used("--subject")) {
        jwtJsonObjectSetString(&payload, JWT_CLAIM_SUBJECT, args.get("--subject").c_str());
    }

    if(args.is_used("--id")) {
        jwtJsonObjectSetString(&payload, JWT_CLAIM_JWT_ID, args.get("--id").c_str());
    }

    if(args.is_used("--expires-in")) {
        uint64_t sec = args.get<uint64_t>("--expires-in");
        uint64_t now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        jwtJsonObjectSetUint(&payload, JWT_CLAIM_EXPIRATION, now + sec);
    }
    if(args.is_used("--expires-at")) {
        jwtJsonObjectSetUint(&payload, JWT_CLAIM_EXPIRATION, args.get<uint64_t>("--expires-in"));
    }
    if(args.is_used("--valid-in")) {
        uint64_t sec = args.get<uint64_t>("--expires-in");
        uint64_t now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        jwtJsonObjectSetUint(&payload, JWT_CLAIM_NOT_BEFORE, now + sec);
    }
    if(args.is_used("--not-before")) {
        jwtJsonObjectSetUint(&payload, JWT_CLAIM_NOT_BEFORE, args.get<uint64_t>("--not-before"));
    }

    JwtString token;
    if(algorithm == JWT_ALGORITHM_NONE) {
        JwtResult result = jwtCreateUnprotectedToken(&payload, &token);
        if(result != JWT_RESULT_SUCCESS) {
            std::cerr << "Token creation failed!" << result << "\n";
            jwtJsonObjectDestroy(&payload);
            return result;
        }
    } else if(jwtIsEncryptionAlgorithm(algorithm)) {

        JwtCryptAlgorithm crypt = JWT_CRYPT_ALGORITHM_UNKNOWN;
        JwtResult result = jwtCryptAlgorithmParse(&crypt, args.get("--enc").c_str());
        if(result != JWT_RESULT_SUCCESS) {
            std::cerr << "Invalid or missing encryption algorithm! (--enc)\n";
            return result;
        }

        result = jwtCreateEncryptedToken(&payload, &key, algorithm, crypt, &token);
        if(result != 0) {
            std::cerr << "Token creation failed! " << result << "\n";
            jwtJsonObjectDestroy(&payload);
            jwtKeyDestroy(&key);
            return result;
        }

    } else {
        JwtResult result = jwtCreateSignedToken(&payload, &key, algorithm, &token);
        if(result != 0) {
            std::cerr << "Token creation failed!" << result << "\n";
            jwtJsonObjectDestroy(&payload);
            jwtKeyDestroy(&key);
            return result;
        }
    }

    std::cout << token.data << std::endl;

    jwtJsonObjectDestroy(&payload);
    jwtKeyDestroy(&key);

    return JWT_RESULT_SUCCESS;
}
