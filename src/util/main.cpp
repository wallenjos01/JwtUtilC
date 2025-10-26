#include <jwt/json.h>
#include <jwt/token.h>
#include <unistd.h>

int main(int argc, char** argv) { 


    JwtJsonObject obj;
    jwtJsonObjectCreate(&obj);

    jwtJsonObjectSetInt(&obj, "test", 42);

    JwtString str = jwtCreateUnprotectedToken(obj);

    write(STDOUT_FILENO, str.data, str.length);

    return 0; 
}
