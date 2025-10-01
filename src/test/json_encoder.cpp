#include "jwt/core.h"
#include "jwt/json.h"
#include "jwt/stream.h"
#include <gtest/gtest.h>

TEST(JsonEncoder, TrueLiteral) {

    JwtJsonElement element = {};
    element.type = JWT_JSON_ELEMENT_TYPE_BOOLEAN;
    element.boolean = true;

    char buffer[1024] = {};
    JwtWriter writer = {};
    jwtWriterCreateForBuffer(&writer, buffer, 1024);

    int32_t result = jwtWriteJsonWriter(&element, writer);
    EXPECT_EQ(0, jwtWriterWriteAll(writer, "\0", 1, nullptr));

    EXPECT_EQ(0, result);
    EXPECT_STREQ(buffer, "true");
    jwtJsonElementDestroy(&element);
}

TEST(JsonEncoder, FalseLiteral) {

    JwtJsonElement element = {};
    element.type = JWT_JSON_ELEMENT_TYPE_BOOLEAN;
    element.boolean = false;

    char buffer[1024] = {};
    JwtWriter writer = {};
    jwtWriterCreateForBuffer(&writer, buffer, 1024);

    int32_t result = jwtWriteJsonWriter(&element, writer);
    EXPECT_EQ(0, jwtWriterWriteAll(writer, "\0", 1, nullptr));

    EXPECT_EQ(0, result);
    EXPECT_STREQ(buffer, "false");
    jwtJsonElementDestroy(&element);
}

TEST(JsonEncoder, NullLiteral) {

    JwtJsonElement element = {};
    element.type = JWT_JSON_ELEMENT_TYPE_NULL;

    char buffer[1024] = {};
    JwtWriter writer = {};
    jwtWriterCreateForBuffer(&writer, buffer, 1024);

    int32_t result = jwtWriteJsonWriter(&element, writer);
    EXPECT_EQ(0, jwtWriterWriteAll(writer, "\0", 1, nullptr));

    EXPECT_EQ(0, result);
    EXPECT_STREQ(buffer, "null");
    jwtJsonElementDestroy(&element);
}

TEST(JsonEncoder, Int) {

    JwtJsonElement element = {};
    element.type = JWT_JSON_ELEMENT_TYPE_NUMERIC;
    element.number.type = JWT_NUMBER_TYPE_SIGNED;
    element.number.i64 = -42;

    char buffer[1024] = {};
    JwtWriter writer = {};
    jwtWriterCreateForBuffer(&writer, buffer, 1024);

    int32_t result = jwtWriteJsonWriter(&element, writer);
    EXPECT_EQ(0, jwtWriterWriteAll(writer, "\0", 1, nullptr));

    EXPECT_EQ(0, result);
    EXPECT_STREQ(buffer, "-42");
    jwtJsonElementDestroy(&element);
}
TEST(JsonEncoder, Uint) {

    JwtJsonElement element = {};
    element.type = JWT_JSON_ELEMENT_TYPE_NUMERIC;
    element.number.type = JWT_NUMBER_TYPE_UNSIGNED;
    element.number.u64 = 42;

    char buffer[1024] = {};
    JwtWriter writer = {};
    jwtWriterCreateForBuffer(&writer, buffer, 1024);

    int32_t result = jwtWriteJsonWriter(&element, writer);
    EXPECT_EQ(0, jwtWriterWriteAll(writer, "\0", 1, nullptr));

    EXPECT_EQ(0, result);
    EXPECT_STREQ(buffer, "42");
    jwtJsonElementDestroy(&element);
}
TEST(JsonEncoder, Float) {

    JwtJsonElement element = {};
    element.type = JWT_JSON_ELEMENT_TYPE_NUMERIC;
    element.number.type = JWT_NUMBER_TYPE_FLOAT;
    element.number.f64 = 12.25;

    char buffer[1024] = {};
    JwtWriter writer = {};
    jwtWriterCreateForBuffer(&writer, buffer, 1024);

    int32_t result = jwtWriteJsonWriter(&element, writer);
    EXPECT_EQ(0, jwtWriterWriteAll(writer, "\0", 1, nullptr));

    EXPECT_EQ(0, result);
    EXPECT_STREQ(buffer, "12.25");
    jwtJsonElementDestroy(&element);
}
TEST(JsonEncoder, String) {

    JwtJsonElement element = {};
    element.type = JWT_JSON_ELEMENT_TYPE_STRING;
    element.string = jwtStringCreate("Hello");

    char buffer[1024] = {};
    JwtWriter writer = {};
    jwtWriterCreateForBuffer(&writer, buffer, 1024);

    int32_t result = jwtWriteJsonWriter(&element, writer);
    EXPECT_EQ(0, jwtWriterWriteAll(writer, "\0", 1, nullptr));

    EXPECT_EQ(0, result);
    EXPECT_STREQ(buffer, "\"Hello\"");
    jwtJsonElementDestroy(&element);
}
TEST(JsonEncoder, Array) {

    JwtJsonElement element = {};
    element.type = JWT_JSON_ELEMENT_TYPE_ARRAY;
    jwtJsonArrayCreate(&element.array);
    jwtJsonArrayPushInt(&element.array, 1);
    jwtJsonArrayPushInt(&element.array, 2);
    jwtJsonArrayPushInt(&element.array, 3);

    char buffer[1024] = {};
    JwtWriter writer = {};
    jwtWriterCreateForBuffer(&writer, buffer, 1024);

    int32_t result = jwtWriteJsonWriter(&element, writer);
    EXPECT_EQ(0, jwtWriterWriteAll(writer, "\0", 1, nullptr));

    EXPECT_EQ(0, result);
    EXPECT_STREQ(buffer, "[1,2,3]");

    jwtJsonElementDestroy(&element);
}
TEST(JsonEncoder, Object) {

    JwtJsonElement element = {};
    element.type = JWT_JSON_ELEMENT_TYPE_OBJECT;
    jwtJsonObjectCreate(&element.object);
    jwtJsonObjectSetInt(&element.object, "int", 13);
    jwtJsonObjectSetString(&element.object, "str", "Hello");
    jwtJsonObjectSetBool(&element.object, "bool", true);

    char buffer[1024] = {};
    JwtWriter writer = {};
    jwtWriterCreateForBuffer(&writer, buffer, 1024);

    int32_t result = jwtWriteJsonWriter(&element, writer);
    EXPECT_EQ(0, jwtWriterWriteAll(writer, "\0", 1, nullptr));

    EXPECT_EQ(0, result);
    EXPECT_STREQ(buffer, "{\"int\":13,\"bool\":true,\"str\":\"Hello\"}");

    jwtJsonElementDestroy(&element);
}
