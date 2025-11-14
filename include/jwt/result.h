#ifndef JWT_RESULT_H
#define JWT_RESULT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

enum JwtResult : int32_t {

    JWT_RESULT_SUCCESS = 0,
    JWT_RESULT_EOF = 1,

    JWT_RESULT_VERIFICATION_FAILED = 200,
    JWT_RESULT_UNPROTECTED_TOKEN = 201,
    JWT_RESULT_EXPIRED_TOKEN = 202,
    JWT_RESULT_EARLY_TOKEN = 203,

    JWT_RESULT_ILLEGAL_ARGUMENT = -1,
    JWT_RESULT_ILLEGAL_STATE = -2,
    JWT_RESULT_SHORT_BUFFER = -3,
    JWT_RESULT_MEMORY_ALLOC_FAILED = -4,
    JWT_RESULT_IO_ERROR = -5,
    JWT_RESULT_FILE_OPEN_FAILED = -6,

    JWT_RESULT_JSON_UNEXPECTED_SYMBOL = -100,
    JWT_RESULT_JSON_UNEXPECTED_EOF = -101,
    JWT_RESULT_NOT_A_LIST = -102,
    JWT_RESULT_NOT_AN_OBJECT = -103,
    JWT_RESULT_NOT_A_NUMBER = -104,
    JWT_RESULT_UNKNOWN_ALGORITHM = -110,
    JWT_RESULT_UNKNOWN_CRYPT_ALGORITHM = -111,
    JWT_RESULT_UNKNOWN_KEY_TYPE = -120,
    JWT_RESULT_UNKNOWN_KEY_USE = -121,
    JWT_RESULT_UNKNOWN_KEY_OPERATION = -122,
    JWT_RESULT_MISSING_REQUIRED_KEY_PARAM = -123,
    JWT_RESULT_DUPLICATE_KEY_ID = -124,
    JWT_RESULT_KEY_CREATE_FAILED = -125,
    JWT_RESULT_UNKNOWN_CURVE = -130,
    JWT_RESULT_INVALID_COORDINATE_LENGTH = -131,

    JWT_RESULT_INVALID_KEY_TYPE = -200,
    JWT_RESULT_INVALID_KEY_USE = -201,
    JWT_RESULT_INVALID_KEY_OPERATION = -202,
    JWT_RESULT_INVALID_ALGORITHM = -203,
    JWT_RESULT_INVALID_KEY_DATA = -204,
    JWT_RESULT_INVALID_KEY_ID = -205,
    JWT_RESULT_INVALID_KEY = -206,
    JWT_RESULT_BAD_CEK = -210,
    JWT_RESULT_INVALID_IV_LENGTH = -211,
    JWT_RESULT_INVALID_CEK_LENGTH = -212,
    JWT_RESULT_INVALID_TAG_LENGTH = -213,
    JWT_RESULT_MISSING_REQUIRED_HEADER_CLAIM = -214,
    JWT_RESULT_MALFORMED_JWT = -215,
    JWT_RESULT_BAD_EPK = -216,
    JWT_RESULT_INVALID_PASSWORD = -217,

    JWT_RESULT_UNIMPLEMENTED = -998,
    JWT_RESULT_UNEXPECTED_ERROR = -999

};

#define JWT_CHECK(condition)                                                  \
    {                                                                         \
        JwtResult ret = condition;                                            \
        if(ret != JWT_RESULT_SUCCESS) {                                       \
            return ret;                                                       \
        }                                                                     \
    }

#define JWT_CHECK_OR(condition, ret)                                          \
    if (condition != 0) {                                                     \
        return ret;                                                           \
    }

#define JWT_CHECK_GOTO(condition, result, label)                              \
    {                                                                         \
        JwtResult ret = condition;                                            \
        if(ret != JWT_RESULT_SUCCESS) { result = ret; goto label; }           \
    }

#ifdef __cplusplus
}
#endif

#endif // JWT_RESULT_H
