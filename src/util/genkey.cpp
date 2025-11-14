#include "app.hpp"

#include <jwt/result.h>
#include <jwt/key.h>
#include <jwt/json.h>
#include <jwt/token.h>

JwtResult generateKey(argparse::ArgumentParser &args) {

    std::string typeStr = args.get("type");

    JwtKeyType kty;
    JWT_CHECK(jwtKeyTypeParse(&kty, { .length = typeStr.length(), .data = typeStr.c_str() }));

    JwtKey key = {};
    switch(kty) {
        case JWT_KEY_TYPE_OCTET_SEQUENCE:
            if(!args.is_used("--length")) {
                std::cerr << "Length (--length) is required for octet sequence keys!\n";
                return JWT_RESULT_ILLEGAL_ARGUMENT;
            }
            JWT_CHECK(jwtKeyGenerateOct(&key, args.get<uint64_t>("--length")));
            break;
        case JWT_KEY_TYPE_RSA:
            if(!args.is_used("--length")) {
                std::cerr << "Length (--length) is required for RSA keys!\n";
                return JWT_RESULT_ILLEGAL_ARGUMENT;
            }
            JWT_CHECK(jwtKeyGenerateRsa(&key, args.get<uint64_t>("--length") * 8));
            break;
        case JWT_KEY_TYPE_ELLIPTIC_CURVE:
            if(!args.is_used("--curve")) {
                std::cerr << "Curve (--curve) is required for EC keys!\n";
                return JWT_RESULT_ILLEGAL_ARGUMENT;
            }
            std::string curveName = args.get("--curve");
            JwtString curveStr = { .length = curveName.length(), .data = curveName.c_str() };
            JwtEcCurve curve;

            JWT_CHECK(jwtCurveParse(&curve, curveStr));
            JWT_CHECK(jwtKeyGenerateEc(&key, curve));

            break;
    }

    JwtResult result = JWT_RESULT_SUCCESS;
    JwtJsonObject keyObj = {};
    jwtJsonObjectCreate(&keyObj);

    JwtString keyJson = {};
    JWT_CHECK_GOTO(jwtKeyEncode(&key, &keyObj), result, cleanup);
    JWT_CHECK_GOTO(jwtWriteJsonObjectString(&keyObj, &keyJson), result, cleanup);

    std::cout << keyJson.data << "\n";

cleanup:

    jwtJsonObjectDestroy(&keyObj);

    return result;
}
