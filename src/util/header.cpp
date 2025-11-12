#include "app.hpp"

#include <jwt/key.h>
#include <jwt/json.h>
#include <jwt/token.h>

int parseHeader(argparse::ArgumentParser &args) {

     std::string tokenStr = args.get("token");
    JwtString token = { .length = tokenStr.length(), .data = tokenStr.c_str() };

    JwtJsonObject header;
    if(jwtReadTokenHeader(token, &header) != 0) {
        std::cerr << "Unable to parse token header!\n";
        return 1;
    }

    JwtString headerStr = {};
    jwtWriteJsonObjectString(&header, &headerStr);

    std::cout << headerStr.data << "\n";

    return 0;
}
