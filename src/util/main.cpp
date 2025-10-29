#include <iostream>

#include "jwt/json.h"
#include "jwt/key.h"
#include "jwt/token.h"

int main(int argc, char** argv) { 

    const char* keyJson =
        "{\"kty\":\"EC\","
        "\"crv\":\"P-256\","
        "\"x\":\"rrwq-1lwloY2pjJQE_oapmXKOEMkDSu59hU3ROE_1vo\","
        "\"y\":\"I1MuspBp4orW2uIhF3WGcShGr2xT8R59argUv4UbwLE\","
        "\"d\":\"KL78nYZ0H75mAjxj6Bu8rw6cB9aW7OehdvAXOM5TOUA\","  
        "\"use\":\"sig\","
        "\"kid\":\"1\"}";

    JwtJsonElement element = {};
    jwtReadJsonString(&element, keyJson, strlen(keyJson));

    JwtKey key = {};
    jwtKeyParse(&key, &element.object);

    JwtJsonObject obj = {};
    jwtJsonObjectCreate(&obj);
    jwtJsonObjectSetInt(&obj, "test", 42);

    JwtString sig = {};
    jwtCreateToken(&obj, &key, JWT_ALGORITHM_ES256, &sig);

    std::cout << sig.data << std::endl;

    return 0; 
}
