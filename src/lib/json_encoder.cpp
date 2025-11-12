/**
 * Josh Wallentine
 * Created 9/14/25
 * Modified 11/12/25
 *
 * Partial implementation of include/jwt/json.h
 * See also json_decoder.cpp and json.cpp
 */

#include "jwt/result.h"
#include "util.hpp"

#include <jwt/core.h>
#include <jwt/stream.h>
#include <jwt/json.h>

#include <string>

namespace {

JwtResult writeString(JwtString string, JwtWriter writer) {
    JWT_CHECK(jwtWriterWrite(writer, "\"", 1, nullptr));

    for (auto i = 0; i < string.length; i++) {
        char c = string.data[i];
        switch (c) {
        case '"':
        case '\\':
        case '/':
            JWT_CHECK(jwtWriterWrite(writer, "\\", 1, nullptr));
            JWT_CHECK(jwtWriterWrite(writer, &c, 1, nullptr));
            break;
        case '\b':
            JWT_CHECK(jwtWriterWrite(writer, "\\b", 2, nullptr));
            break;
        case '\f':
            JWT_CHECK(jwtWriterWrite(writer, "\\f", 2, nullptr));
            break;
        case '\n':
            JWT_CHECK(jwtWriterWrite(writer, "\\n", 2, nullptr));
            break;
        case '\r':
            JWT_CHECK(jwtWriterWrite(writer, "\\r", 2, nullptr));
            break;
        case '\t':
            JWT_CHECK(jwtWriterWrite(writer, "\\t", 2, nullptr));
            break;
        default:
            if (c < 0x20)
                continue;
            JWT_CHECK(jwtWriterWrite(writer, &c, 1, nullptr));
        }
    }

    JWT_CHECK(jwtWriterWrite(writer, "\"", 1, nullptr));
    return JWT_RESULT_SUCCESS;
}

} // namespace

JwtResult jwtWriteJsonWriter(JwtJsonElement* element, JwtWriter writer) {

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

        JWT_CHECK(jwtWriterWrite(writer, "[", 1, nullptr));

        JwtJsonArray arr = jwtJsonElementAsArray(*element);
        for (auto i = 0; i < arr.size; i++) {
            if (i > 0) {
                JWT_CHECK(jwtWriterWrite(writer, ",", 1, nullptr));
            }
            JwtJsonElement element = jwtJsonArrayGet(&arr, i);
            JWT_CHECK(jwtWriteJsonWriter(&element, writer));
        }

        JWT_CHECK(jwtWriterWrite(writer, "]", 1, nullptr));
        break;
    }
    case JWT_JSON_ELEMENT_TYPE_OBJECT: 
        jwtWriteJsonObjectWriter(&element->object, writer);
    }

    return JWT_RESULT_SUCCESS;
}


JwtResult jwtWriteJsonString(JwtJsonElement* element, JwtString* string) {

    JwtWriter writer = {};
    JWT_CHECK(jwtWriterCreateDynamic(&writer));
    JWT_CHECK(jwtWriteJsonWriter(element, writer));

    JwtList* list = jwtWriterExtractDynamic(&writer);
    string->length = list->size;
    string->data = static_cast<char*>(jwtListReclaim(list));
 
    return JWT_RESULT_SUCCESS;
}


JwtResult jwtWriteJsonObjectWriter(JwtJsonObject* object, JwtWriter writer) {

    JWT_CHECK(jwtWriterWrite(writer, "{", 1, nullptr));

    JwtJsonObjectIterator it = jwtJsonObjectIteratorCreate(object);

    size_t index = 0;
    JwtJsonObjectEntry* entry = jwtJsonObjectIteratorNext(&it);
    while (entry != nullptr) {
        if (index > 0) {
            JWT_CHECK(jwtWriterWrite(writer, ",", 1, nullptr));
        }
        JWT_CHECK(writeString(entry->key, writer));
        JWT_CHECK(jwtWriterWrite(writer, ":", 1, nullptr));
        JWT_CHECK(jwtWriteJsonWriter(&entry->element, writer));
        index++;

        entry = jwtJsonObjectIteratorNext(&it);
    }

    JWT_CHECK(jwtWriterWrite(writer, "}", 1, nullptr));
    return JWT_RESULT_SUCCESS;
}

JwtResult jwtWriteJsonObjectString(JwtJsonObject* object, JwtString* string) {

    JwtWriter writer = {};
    JWT_CHECK(jwtWriterCreateDynamic(&writer));
    JWT_CHECK(jwtWriteJsonObjectWriter(object, writer));

    JwtList* list = jwtWriterExtractDynamic(&writer);
    string->length = list->size;
    string->data = static_cast<char*>(jwtListReclaim(list));
 
    return JWT_RESULT_SUCCESS;
}
