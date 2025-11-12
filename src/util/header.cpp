#include "app.hpp"
#include "jwt/result.h"

#include <jwt/key.h>
#include <jwt/json.h>
#include <jwt/token.h>

JwtResult parseHeader(argparse::ArgumentParser &args) {

    std::string tokenStr = args.get("token");
    JwtString token = { .length = tokenStr.length(), .data = tokenStr.c_str() };

    JwtJsonObject header;
    JWT_CHECK(jwtReadTokenHeader(token, &header));

    JwtString headerStr = {};
    jwtWriteJsonObjectString(&header, &headerStr);

    std::cout << headerStr.data << "\n";

    return JWT_RESULT_SUCCESS;
}
