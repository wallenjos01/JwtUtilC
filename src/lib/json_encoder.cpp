/**
 * Josh Wallentine
 * Created 9/14/25
 *
 * Partial implementation of include/jwt/json.h
 * See also json_decoder.cpp and json.cpp
 */

#include "jwt/core.h"
#include "jwt/stream.h"
#include <jwt/json.h>
#include <string>

#define CHECK(expression)                                                      \
    {                                                                          \
        int32_t result = expression;                                           \
        if (result < 0)                                                        \
            return result;                                                     \
    }

namespace {

int32_t writeString(JwtString string, JwtWriter writer) {
    CHECK(jwtWriterWrite(writer, "\"", 1, nullptr));

    for (auto i = 0; i < string.length; i++) {
        char c = string.data[i];
        switch (c) {
        case '"':
        case '\\':
        case '/':
            CHECK(jwtWriterWrite(writer, "\\", 1, nullptr));
            CHECK(jwtWriterWrite(writer, &c, 1, nullptr));
            break;
        case '\b':
            CHECK(jwtWriterWrite(writer, "\\b", 2, nullptr));
            break;
        case '\f':
            CHECK(jwtWriterWrite(writer, "\\f", 2, nullptr));
            break;
        case '\n':
            CHECK(jwtWriterWrite(writer, "\\n", 2, nullptr));
            break;
        case '\r':
            CHECK(jwtWriterWrite(writer, "\\r", 2, nullptr));
            break;
        case '\t':
            CHECK(jwtWriterWrite(writer, "\\t", 2, nullptr));
            break;
        default:
            if (c < 0x20)
                continue;
            CHECK(jwtWriterWrite(writer, &c, 1, nullptr));
        }
    }

    CHECK(jwtWriterWrite(writer, "\"", 1, nullptr));
    return 0;
}

} // namespace

int32_t jwtWriteJsonWriter(JwtJsonElement* element, JwtWriter writer) {

    switch (element->type) {
    case JWT_JSON_ELEMENT_TYPE_NULL:
        return jwtWriterWrite(writer, "null", 4, nullptr);
    case JWT_JSON_ELEMENT_TYPE_BOOLEAN:
        if (element->boolean) {
            return jwtWriterWrite(writer, "true", 4, nullptr);
        } else {
            return jwtWriterWrite(writer, "false", 5, nullptr);
        }
    case JWT_JSON_ELEMENT_TYPE_NUMERIC: {
        std::string num;
        switch (element->number.type) {
        case JWT_NUMBER_TYPE_SIGNED:
            num = std::to_string(element->number.i64);
            break;
        case JWT_NUMBER_TYPE_UNSIGNED:
            num = std::to_string(element->number.u64);
            break;
        case JWT_NUMBER_TYPE_FLOAT:
            num = std::to_string(element->number.f64);
            num.erase(num.find_last_not_of('0') + 1, std::string::npos);
            break;
        }
        return jwtWriterWrite(writer, num.c_str(), num.size(), nullptr);
    }
    case JWT_JSON_ELEMENT_TYPE_STRING: {
        return writeString(element->string, writer);
    }
    case JWT_JSON_ELEMENT_TYPE_ARRAY: {

        CHECK(jwtWriterWrite(writer, "[", 1, nullptr));

        JwtJsonArray arr = jwtJsonElementAsArray(*element);
        for (auto i = 0; i < arr.length; i++) {
            if (i > 0) {
                CHECK(jwtWriterWrite(writer, ",", 1, nullptr));
            }
            JwtJsonElement element = jwtJsonArrayGet(&arr, i);
            CHECK(jwtWriteJsonWriter(&element, writer));
        }

        CHECK(jwtWriterWrite(writer, "]", 1, nullptr));
        break;
    }
    case JWT_JSON_ELEMENT_TYPE_OBJECT: {

        CHECK(jwtWriterWrite(writer, "{", 1, nullptr));

        JwtJsonObject obj = jwtJsonElementAsObject(*element);
        JwtJsonObjectIterator it = jwtJsonObjectIteratorCreate(&obj);

        size_t index = 0;
        while (jwtJsonObjectIteratorNext(&it) != nullptr) {
            if (index > 0) {
                CHECK(jwtWriterWrite(writer, ",", 1, nullptr));
            }
            JwtJsonObjectEntry* entry = it.entry;
            CHECK(writeString(entry->key, writer));
            CHECK(jwtWriterWrite(writer, ":", 1, nullptr));
            CHECK(jwtWriteJsonWriter(&entry->element, writer));
            index++;
        }

        CHECK(jwtWriterWrite(writer, "}", 1, nullptr));
        break;
    }
    }

    return 0;
}
