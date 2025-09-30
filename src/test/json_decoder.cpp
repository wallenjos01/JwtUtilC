#include <gtest/gtest.h>

#include <jwt/json.h>

TEST(JsonDecoder, Int) {

    const char* json = "-10";

    JwtJsonElement element = {};
    JwtJsonParseResult result = jwtReadJsonString(&element, json, strlen(json));

    ASSERT_EQ(JWT_JSON_PARSE_RESULT_SUCCESS, result);
    ASSERT_EQ(JWT_JSON_ELEMENT_TYPE_NUMERIC, element.type);

    ASSERT_EQ(-10, jwtJsonElementAsInt(element));

    jwtJsonElementDestroy(&element);
}

TEST(JsonDecoder, Uint) {

    const char* json = "12";

    JwtJsonElement element = {};
    JwtJsonParseResult result = jwtReadJsonString(&element, json, strlen(json));

    ASSERT_EQ(JWT_JSON_PARSE_RESULT_SUCCESS, result);
    ASSERT_EQ(JWT_JSON_ELEMENT_TYPE_NUMERIC, element.type);

    ASSERT_EQ(12, jwtJsonElementAsUint(element));

    jwtJsonElementDestroy(&element);
}

TEST(JsonDecoder, Double) {

    const char* json = "10.25";

    JwtJsonElement element = {};
    JwtJsonParseResult result = jwtReadJsonString(&element, json, strlen(json));

    ASSERT_EQ(JWT_JSON_PARSE_RESULT_SUCCESS, result);
    ASSERT_EQ(JWT_JSON_ELEMENT_TYPE_NUMERIC, element.type);

    ASSERT_DOUBLE_EQ(10.25, jwtJsonElementAsDouble(element));

    jwtJsonElementDestroy(&element);
}

TEST(JsonDecoder, String) {

    const char* json = "\"Hello, World\"";

    JwtJsonElement element = {};
    JwtJsonParseResult result = jwtReadJsonString(&element, json, strlen(json));

    ASSERT_EQ(JWT_JSON_PARSE_RESULT_SUCCESS, result);
    ASSERT_EQ(JWT_JSON_ELEMENT_TYPE_STRING, element.type);

    ASSERT_STREQ("Hello, World", jwtJsonElementAsString(element).data);

    jwtJsonElementDestroy(&element);
}

TEST(JsonDecoder, TrueLiteral) {

    const char* json = "true";
    JwtJsonElement element = {};
    JwtJsonParseResult result = jwtReadJsonString(&element, json, strlen(json));

    ASSERT_EQ(JWT_JSON_PARSE_RESULT_SUCCESS, result);
    ASSERT_EQ(JWT_JSON_ELEMENT_TYPE_BOOLEAN, element.type);

    ASSERT_TRUE(element.boolean);

    jwtJsonElementDestroy(&element);
}

TEST(JsonDecoder, FalseLiteral) {

    const char* json = "false";
    JwtJsonElement element = {};
    JwtJsonParseResult result = jwtReadJsonString(&element, json, strlen(json));

    ASSERT_EQ(JWT_JSON_PARSE_RESULT_SUCCESS, result);
    ASSERT_EQ(JWT_JSON_ELEMENT_TYPE_BOOLEAN, element.type);

    ASSERT_FALSE(element.boolean);

    jwtJsonElementDestroy(&element);
}

TEST(JsonDecoder, NullLiteral) {

    const char* json = "null";
    JwtJsonElement element = {};
    JwtJsonParseResult result = jwtReadJsonString(&element, json, strlen(json));

    ASSERT_EQ(JWT_JSON_PARSE_RESULT_SUCCESS, result);
    ASSERT_EQ(JWT_JSON_ELEMENT_TYPE_NULL, element.type);

    jwtJsonElementDestroy(&element);
}

TEST(JsonDecoder, ArrayEmpty) {

    const char* json = "[]";
    JwtJsonElement element = {};
    JwtJsonParseResult result = jwtReadJsonString(&element, json, strlen(json));

    ASSERT_EQ(JWT_JSON_PARSE_RESULT_SUCCESS, result);
    ASSERT_EQ(JWT_JSON_ELEMENT_TYPE_ARRAY, element.type);

    ASSERT_EQ(0, element.array.size);

    jwtJsonElementDestroy(&element);
}

TEST(JsonDecoder, ArraySingle) {

    const char* json = "[ 10 ]";
    JwtJsonElement element = {};
    JwtJsonParseResult result = jwtReadJsonString(&element, json, strlen(json));

    ASSERT_EQ(JWT_JSON_PARSE_RESULT_SUCCESS, result);
    ASSERT_EQ(JWT_JSON_ELEMENT_TYPE_ARRAY, element.type);

    ASSERT_EQ(1, element.array.size);

    JwtJsonElement first = jwtJsonArrayGet(&element.array, 0);
    ASSERT_EQ(JWT_JSON_ELEMENT_TYPE_NUMERIC, first.type);
    ASSERT_EQ(10, jwtJsonElementAsUint(first));

    jwtJsonElementDestroy(&element);
}

TEST(JsonDecoder, ArrayDouble) {

    const char* json = "[ 10, true ]";
    JwtJsonElement element = {};
    JwtJsonParseResult result = jwtReadJsonString(&element, json, strlen(json));

    ASSERT_EQ(JWT_JSON_PARSE_RESULT_SUCCESS, result);
    ASSERT_EQ(JWT_JSON_ELEMENT_TYPE_ARRAY, element.type);

    ASSERT_EQ(2, element.array.size);

    JwtJsonElement first = jwtJsonArrayGet(&element.array, 0);
    ASSERT_EQ(JWT_JSON_ELEMENT_TYPE_NUMERIC, first.type);
    ASSERT_EQ(10, jwtJsonElementAsUint(first));

    JwtJsonElement second = jwtJsonArrayGet(&element.array, 1);
    ASSERT_EQ(JWT_JSON_ELEMENT_TYPE_BOOLEAN, second.type);
    ASSERT_TRUE(jwtJsonElementAsBool(second));

    jwtJsonElementDestroy(&element);
}

TEST(JsonDecoder, ArrayComplex) {

    const char* json =
        "[ -33, false, \"Hello\", [1,2,3], {\"key\":\"value\"} ]";
    JwtJsonElement element = {};
    JwtJsonParseResult result = jwtReadJsonString(&element, json, strlen(json));

    ASSERT_EQ(JWT_JSON_PARSE_RESULT_SUCCESS, result);
    ASSERT_EQ(JWT_JSON_ELEMENT_TYPE_ARRAY, element.type);

    ASSERT_EQ(5, element.array.size);

    JwtJsonElement first = jwtJsonArrayGet(&element.array, 0);
    ASSERT_EQ(JWT_JSON_ELEMENT_TYPE_NUMERIC, first.type);
    ASSERT_EQ(-33, jwtJsonElementAsInt(first));

    JwtJsonElement second = jwtJsonArrayGet(&element.array, 1);
    ASSERT_EQ(JWT_JSON_ELEMENT_TYPE_BOOLEAN, second.type);
    ASSERT_FALSE(jwtJsonElementAsBool(second));

    JwtJsonElement third = jwtJsonArrayGet(&element.array, 2);
    ASSERT_EQ(JWT_JSON_ELEMENT_TYPE_STRING, third.type);
    ASSERT_STREQ("Hello", third.string.data);

    JwtJsonElement fourth = jwtJsonArrayGet(&element.array, 3);
    ASSERT_EQ(JWT_JSON_ELEMENT_TYPE_ARRAY, fourth.type);

    JwtJsonArray subArray = jwtJsonElementAsArray(fourth);
    ASSERT_EQ(3, subArray.size);
    ASSERT_EQ(1, jwtJsonArrayGetUint(&subArray, 0));
    ASSERT_EQ(2, jwtJsonArrayGetUint(&subArray, 1));
    ASSERT_EQ(3, jwtJsonArrayGetUint(&subArray, 2));

    JwtJsonElement fifth = jwtJsonArrayGet(&element.array, 4);
    ASSERT_EQ(JWT_JSON_ELEMENT_TYPE_OBJECT, fifth.type);

    JwtJsonObject obj = jwtJsonElementAsObject(fifth);
    ASSERT_EQ(1, obj.size);
    ASSERT_STREQ("value", jwtJsonObjectGetString(&obj, "key").data);

    jwtJsonElementDestroy(&element);
}

TEST(JsonDecoder, ObjectEmpty) {

    const char* json = "{}";
    JwtJsonElement element = {};
    JwtJsonParseResult result = jwtReadJsonString(&element, json, strlen(json));

    ASSERT_EQ(JWT_JSON_PARSE_RESULT_SUCCESS, result);
    ASSERT_EQ(JWT_JSON_ELEMENT_TYPE_OBJECT, element.type);

    ASSERT_EQ(0, element.object.size);

    jwtJsonElementDestroy(&element);
}

TEST(JsonDecoder, ObjectSingle) {

    const char* json = "{\"key\":10}";
    JwtJsonElement element = {};
    JwtJsonParseResult result = jwtReadJsonString(&element, json, strlen(json));

    ASSERT_EQ(JWT_JSON_PARSE_RESULT_SUCCESS, result);
    ASSERT_EQ(JWT_JSON_ELEMENT_TYPE_OBJECT, element.type);

    JwtJsonObject obj = jwtJsonElementAsObject(element);
    ASSERT_EQ(1, obj.size);
    ASSERT_EQ(10, jwtJsonObjectGetUint(&obj, "key"));

    jwtJsonElementDestroy(&element);
}

TEST(JsonDecoder, ObjectComplex) {

    const char* json = "{\"num\":10,\"bool\":true,\"str\":\"Hello\",\"array\":["
                       "1,2,3],\"obj\":{\"key\":\"value\"}}";
    JwtJsonElement element = {};
    JwtJsonParseResult result = jwtReadJsonString(&element, json, strlen(json));

    ASSERT_EQ(JWT_JSON_PARSE_RESULT_SUCCESS, result);
    ASSERT_EQ(JWT_JSON_ELEMENT_TYPE_OBJECT, element.type);

    JwtJsonObject obj = jwtJsonElementAsObject(element);
    ASSERT_EQ(5, obj.size);
    ASSERT_EQ(10, jwtJsonObjectGetUint(&obj, "num"));
    ASSERT_TRUE(jwtJsonObjectGetBool(&obj, "bool"));
    ASSERT_STREQ("Hello", jwtJsonObjectGetString(&obj, "str").data);

    JwtJsonArray subArray = jwtJsonObjectGetArray(&obj, "array");
    ASSERT_EQ(3, subArray.size);
    ASSERT_EQ(1, jwtJsonArrayGetUint(&subArray, 0));
    ASSERT_EQ(2, jwtJsonArrayGetUint(&subArray, 1));
    ASSERT_EQ(3, jwtJsonArrayGetUint(&subArray, 2));

    JwtJsonObject subObject = jwtJsonObjectGetObject(&obj, "obj");
    ASSERT_EQ(1, subObject.size);
    ASSERT_STREQ("value", jwtJsonObjectGetString(&subObject, "key").data);

    jwtJsonElementDestroy(&element);
}
