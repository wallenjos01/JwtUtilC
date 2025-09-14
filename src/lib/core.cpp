/**
 * Josh Wallentine
 * Created 9/9/25
 *
 * Implementation of include/jwt/core.h
 */

#include <jwt/core.h>

JwtString jwtStringCreateSized(const char* str, size_t len) {

    char* data = new char[len + 1];

    memcpy(data, str, len);
    data[len] = 0;
    return {.length = len, .data = data};
}

void jwtStringDestroy(JwtString* str) {
    if (str->data) {
        delete[] str->data;
        str->data = nullptr;
    }
    str->length = 0;
}

int64_t jwtNumericAsInt(JwtNumeric number) {
    switch (number.type) {
    case JWT_NUMBER_TYPE_SIGNED:
    case JWT_NUMBER_TYPE_UNSIGNED:
        return number.i64;
    case JWT_NUMBER_TYPE_FLOAT:
        return static_cast<int64_t>(number.f64);
    }
    return 0;
}
uint64_t jwtNumericAsUint(JwtNumeric number) {
    switch (number.type) {
    case JWT_NUMBER_TYPE_SIGNED:
        return static_cast<uint64_t>(number.i64);
    case JWT_NUMBER_TYPE_UNSIGNED:
        return number.u64;
    case JWT_NUMBER_TYPE_FLOAT:
        return static_cast<uint64_t>(number.f64);
    }
    return 0;
}
double jwtNumericAsDouble(JwtNumeric number) {
    switch (number.type) {
    case JWT_NUMBER_TYPE_SIGNED:
        return static_cast<double>(number.i64);
    case JWT_NUMBER_TYPE_UNSIGNED:
        return static_cast<double>(number.u64);
    case JWT_NUMBER_TYPE_FLOAT:
        return number.f64;
    }
    return 0;
}
