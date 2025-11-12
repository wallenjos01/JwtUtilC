/**
 * Josh Wallentine
 * Created 9/12/25
 * Modified 11/12/25
 *
 * Partial implementation of include/jwt/json.h
 * See also json.cpp and json_encoder.cpp
 */

#include "jwt/core.h"
#include "jwt/result.h"
#include "utf8.hpp"
#include "util.hpp"
#include <jwt/json.h>
#include <jwt/stream.h>
#include <string>
#include <iostream>

#define NEXT_REAL(reader, lastReadChar)                                        \
    {                                                                          \
        JwtResult nextResult =                                                 \
            nextReal(reader, lastReadChar)                    ;                \
        if (nextResult == JWT_RESULT_EOF) {                                    \
            std::cout << "End of file " __FILE__ ":" << __LINE__ << "\n";      \
            return JWT_RESULT_JSON_UNEXPECTED_EOF;                             \
        } else if(nextResult != JWT_RESULT_SUCCESS) {                          \
            return nextResult;                                                 \
        }                                                                      \
    }

#define NEXT_CHAR(reader, lastReadChar)                                        \
    {                                                                          \
        JwtResult nextResult =                                                 \
            jwtReaderReadAll(reader, lastReadChar, 1, nullptr);                \
        if (nextResult == JWT_RESULT_EOF) {                                    \
            std::cout << "End of file " __FILE__ ":" << __LINE__ << "\n";      \
            return JWT_RESULT_JSON_UNEXPECTED_EOF;                             \
        } else if(nextResult != JWT_RESULT_SUCCESS) {                          \
            return nextResult;                                                 \
        }                                                                      \
    }

namespace {

bool isWhitespace(char c) { return c <= 0x20; }

JwtResult nextReal(JwtReader reader, char* lastReadChar) {

    size_t numRead;
    do {
        JwtResult res = jwtReaderRead(reader, lastReadChar, 1, &numRead);
        if(res < 0) {
            return res;
        }
        if (numRead == 0) {
            return JWT_RESULT_EOF;
        }
    } while (isWhitespace(*lastReadChar));

    return JWT_RESULT_SUCCESS;
}

JwtResult parseJsonElement(JwtJsonElement* outElement,
                                    JwtReader reader, char* lastReadChar);

JwtResult parseString(JwtJsonElement* element, JwtReader reader,
                               char* lastReadChar) {

    std::string stringData = "";

    while (true) {
        NEXT_CHAR(reader, lastReadChar);
        if (*lastReadChar < 0x20) {
            return JWT_RESULT_JSON_UNEXPECTED_SYMBOL;
        }

        if (*lastReadChar == '"') {
            if (nextReal(reader, lastReadChar) < 0) {
                return JWT_RESULT_IO_ERROR;
            }
            element->type = JWT_JSON_ELEMENT_TYPE_STRING;
            element->string =
                jwtStringCreateSized(stringData.c_str(), stringData.length());
            return JWT_RESULT_SUCCESS;
        }

        if (*lastReadChar == '\\') {
            NEXT_CHAR(reader, lastReadChar);
            switch (*lastReadChar) {
            case '"':
                stringData.push_back('"');
                break;
            case '\\':
                stringData.push_back('\\');
                break;
            case '/':
                stringData.push_back('/');
                break;
            case 'b':
                stringData.push_back('\b');
                break;
            case 'f':
                stringData.push_back('\f');
                break;
            case 'n':
                stringData.push_back('\n');
                break;
            case 'r':
                stringData.push_back('\r');
                break;
            case 't':
                stringData.push_back('\t');
                break;
            case 'u': {
                char codePointHex[4];
                if (jwtReaderReadAll(reader, codePointHex, 4, nullptr) != 0) {
                    return JWT_RESULT_JSON_UNEXPECTED_EOF;
                }

                uint32_t codePoint = 0;
                for (auto i = 0; i < 4; i++) {
                    codePoint <<= 4;
                    char c = codePointHex[c];
                    char value = 0;
                    if (c >= 'a' && c <= 'f') {
                        value = c - 'a';
                    } else if (c >= 'A' && c <= 'F') {
                        value = c - 'A';
                    } else if (c >= '0' && c <= '9') {
                        value = c - '0';
                    } else {
                        return JWT_RESULT_JSON_UNEXPECTED_SYMBOL;
                    }

                    codePoint |= value;
                }

                appendCodePoint(stringData, codePoint);
                break;
            }
            }
        } else {
            stringData.push_back(*lastReadChar);
        }
    }
};

template <typename T>
JwtResult parseExponent(JwtJsonElement* output, T* outValue,
                                 JwtReader reader, char* lastRead,
                                 T literalPart, bool& negative) {

    NEXT_CHAR(reader, lastRead);

    negative = negative ^ (*lastRead == '-');
    if (*lastRead == '+' || *lastRead == '-') {
        if (jwtReaderReadAll(reader, lastRead, 1, nullptr) != 0) {
            return JWT_RESULT_JSON_UNEXPECTED_EOF;
        }
    }

    uint64_t exponentPart = 0;
    while (true) {
        int32_t res = nextReal(reader, lastRead);
        if (res < 0) {
            return JWT_RESULT_IO_ERROR;
        }
        if (res == 1 || *lastRead < '0' || *lastRead > '9')
            break;
        exponentPart *= 10;
        exponentPart += (*lastRead) - '0';
    };

    T out = literalPart;
    for (auto i = 0; i < exponentPart; i++) {
        out *= 10;
    }

    *outValue = out;

    return JWT_RESULT_SUCCESS;
}

JwtResult parseDecimalPart(JwtJsonElement* output, JwtReader reader,
                                    char* lastRead, uint64_t wholePart,
                                    bool negative) {

    switch (*lastRead) {
    case '.': {

        uint64_t decimalPart = 0;
        while (true) {
            int32_t res = nextReal(reader, lastRead);
            if (res < 0) {
                return JWT_RESULT_IO_ERROR;
            }
            if (res == 1 || *lastRead < '0' || *lastRead > '9')
                break;
            decimalPart *= 10;
            decimalPart += (*lastRead) - '0';
        };

        double decimal = static_cast<double>(decimalPart);
        while (decimal >= 1.0) {
            decimal /= 10;
        }

        double fullValue = wholePart + decimal;
        if (*lastRead == 'E' || *lastRead == 'e') {
            JWT_CHECK(parseExponent(
                output, &fullValue, reader, lastRead, fullValue, negative));
        }

        if (negative)
            fullValue *= -1;

        output->type = JWT_JSON_ELEMENT_TYPE_NUMERIC;
        output->number.type = JWT_NUMBER_TYPE_FLOAT;
        output->number.f64 = fullValue;

    } break;
    case 'E':
    case 'e': {

        JWT_CHECK(parseExponent(output, &wholePart, reader,
                                               lastRead, wholePart, negative));

        // Fall through to default case
    }
    default: {
        output->type = JWT_JSON_ELEMENT_TYPE_NUMERIC;
        if (negative) {
            output->number.type = JWT_NUMBER_TYPE_SIGNED;
            output->number.i64 = static_cast<int64_t>(wholePart) * -1;
        } else {
            output->number.type = JWT_NUMBER_TYPE_UNSIGNED;
            output->number.u64 = wholePart;
        }
    }
    }

    if (isWhitespace(*lastRead)) {
        nextReal(reader, lastRead);
    }

    return JWT_RESULT_SUCCESS;
}

JwtResult parseNumber(JwtJsonElement* output, JwtReader reader,
                               char* lastRead) {

    bool negative = false;
    if (*lastRead == '-') {
        negative = true;
        NEXT_CHAR(reader, lastRead);
    }

    if (*lastRead == '0') {

        int32_t res = nextReal(reader, lastRead);
        if (res < 0) {
            return JWT_RESULT_IO_ERROR;
        } else if (res == 0) {
            return parseDecimalPart(output, reader, lastRead, 0, negative);
        } else {
            output->type = JWT_JSON_ELEMENT_TYPE_NUMERIC;
            output->number.type = JWT_NUMBER_TYPE_SIGNED;
            output->number.i64 = 0;
            return JWT_RESULT_SUCCESS;
        }
    }

    int64_t wholePart = (*lastRead) - '0';
    while (true) {
        int32_t res = nextReal(reader, lastRead);
        if (res < 0) {
            return JWT_RESULT_IO_ERROR;
        }
        if (res == 1 || *lastRead < '0' || *lastRead > '9')
            break;
        wholePart *= 10;
        wholePart += (*lastRead) - '0';
    }

    return parseDecimalPart(output, reader, lastRead, wholePart, negative);
}

// Assume last read == '['
JwtResult parseArray(JwtJsonElement* output, JwtReader reader,
                              char* lastRead) {
    NEXT_REAL(reader, lastRead);
    if (*lastRead == ']') {

        if (nextReal(reader, lastRead) < 0) {
            return JWT_RESULT_IO_ERROR;
        }

        // Empty array
        output->type = JWT_JSON_ELEMENT_TYPE_ARRAY;
        jwtJsonArrayCreate(&output->array);
        return JWT_RESULT_SUCCESS;
    }

    JwtJsonArray array = {};
    jwtJsonArrayCreate(&array);

    while (true) {

        JwtJsonElement* element =
            static_cast<JwtJsonElement*>(jwtListPush(&array));
        JWT_CHECK(parseJsonElement(element, reader, lastRead));

        if (*lastRead == ']') {
            break;
        } else if (*lastRead == ',') {
            NEXT_REAL(reader, lastRead);
        } else {
            return JWT_RESULT_JSON_UNEXPECTED_SYMBOL;
        }
    }

    if (nextReal(reader, lastRead) < 0) {
        return JWT_RESULT_IO_ERROR;
    }

    output->type = JWT_JSON_ELEMENT_TYPE_ARRAY;
    output->array = array;

    return JWT_RESULT_SUCCESS;
}

// Assume last read == '{'
JwtResult parseObject(JwtJsonElement* output, JwtReader reader,
                      char* lastRead) {

    NEXT_REAL(reader, lastRead);
    if (*lastRead == '}') {

        if (nextReal(reader, lastRead) < 0) {
            return JWT_RESULT_IO_ERROR;
        }
        // Empty object
        output->type = JWT_JSON_ELEMENT_TYPE_OBJECT;
        jwtJsonObjectCreate(&output->object);
        return JWT_RESULT_SUCCESS;
    }

    JwtJsonObject object = {};
    jwtJsonObjectCreate(&object);

    size_t count = 0;
    while (true) {

        if (*lastRead != '"') {
            return JWT_RESULT_JSON_UNEXPECTED_SYMBOL;
        }

        JwtJsonElement key = {};
        JWT_CHECK(parseString(&key, reader, lastRead));

        if (*lastRead != ':') {
            return JWT_RESULT_JSON_UNEXPECTED_SYMBOL;
        }

        NEXT_REAL(reader, lastRead);

        JwtJsonElement value = {};
        JWT_CHECK(parseJsonElement(&value, reader, lastRead));

        jwtJsonObjectSetWithString(&object, key.string, value);

        count++;
        if (*lastRead == '}') {
            break;
        } else if (*lastRead == ',') {
            NEXT_REAL(reader, lastRead);
        } else {
            return JWT_RESULT_JSON_UNEXPECTED_SYMBOL;
        }
    }

    if (nextReal(reader, lastRead) < 0) {
        return JWT_RESULT_IO_ERROR;
    }

    output->type = JWT_JSON_ELEMENT_TYPE_OBJECT;
    output->object = object;

    return JWT_RESULT_SUCCESS;
}

JwtResult parseJsonElement(JwtJsonElement* outElement,
                                    JwtReader reader, char* lastReadChar) {

    switch (*lastReadChar) {
    case '{': { // Object
        return parseObject(outElement, reader, lastReadChar);
    }
    case '[': { // Array
        return parseArray(outElement, reader, lastReadChar);
    }
    case '"': { // String
        return parseString(outElement, reader, lastReadChar);
    }
    case 't': { // True
        char word[3];
        if (jwtReaderReadAll(reader, word, 3, nullptr) != 0 ||
            memcmp("rue", word, 3) != 0) {
            return JWT_RESULT_JSON_UNEXPECTED_SYMBOL;
        }
        if (nextReal(reader, lastReadChar) < 0) {
            return JWT_RESULT_IO_ERROR;
        }

        outElement->type = JWT_JSON_ELEMENT_TYPE_BOOLEAN;
        outElement->boolean = true;
        break;
    }
    case 'f': { // False
        char word[4];
        if (jwtReaderReadAll(reader, word, 4, nullptr) != 0 ||
            memcmp("alse", word, 4) != 0) {
            return JWT_RESULT_JSON_UNEXPECTED_SYMBOL;
        }
        if (nextReal(reader, lastReadChar) < 0) {
            return JWT_RESULT_IO_ERROR;
        }
        outElement->type = JWT_JSON_ELEMENT_TYPE_BOOLEAN;
        outElement->boolean = false;
        break;
    }
    case 'n': { // Null
        char word[3];
        if (jwtReaderReadAll(reader, word, 3, nullptr) != 0 ||
            memcmp("ull", word, 3) != 0) {
            return JWT_RESULT_JSON_UNEXPECTED_SYMBOL;
        }
        if (nextReal(reader, lastReadChar) < 0) {
            return JWT_RESULT_IO_ERROR;
        }

        memset(outElement, 0, sizeof(JwtJsonElement));
        outElement->type = JWT_JSON_ELEMENT_TYPE_NULL;
        break;
    }
    default: {
        if ((*lastReadChar >= '0' && *lastReadChar <= '9') ||
            *lastReadChar == '-') { // Number
            return parseNumber(outElement, reader, lastReadChar);
        } else { // Invalid
            return JWT_RESULT_JSON_UNEXPECTED_SYMBOL;
        }
    }
    }

    return JWT_RESULT_SUCCESS;
}

} // namespace

JwtResult jwtReadJsonReader(JwtJsonElement* outElement,
                                     JwtReader reader) {

    char lastReadChar;
    NEXT_REAL(reader, &lastReadChar);

    JwtResult out = parseJsonElement(outElement, reader, &lastReadChar);
    if(out < 0) {
        jwtJsonElementDestroy(outElement);
    }
    return out;
}

JwtResult jwtReadJsonString(JwtJsonElement* outElement,
                                     const char* data, size_t length) {

    JwtReader reader;
    jwtReaderCreateForBuffer(&reader, data, length);

    JwtResult result = jwtReadJsonReader(outElement, reader);

    jwtReaderClose(&reader);

    return result;
}
