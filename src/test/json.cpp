#include "jwt/json.h"
#include "jwt/core.h"
#include <gtest/gtest.h>

#include <jwt.h>

TEST(JsonArray, Empty) {

    JwtJsonArray arr = jwtJsonArrayCreate();
    ASSERT_EQ(0, jwtJsonArrayLength(&arr));
    jwtJsonArrayDestroy(&arr);
}

TEST(JsonArray, Push) {

    JwtJsonArray arr = jwtJsonArrayCreate();
    ASSERT_EQ(0, jwtJsonArrayLength(&arr));

    jwtJsonArrayPush(&arr,
                     {.type = JWT_JSON_ELEMENT_TYPE_BOOLEAN, .boolean = true});

    ASSERT_EQ(1, jwtJsonArrayLength(&arr));
    JwtJsonElement element = jwtJsonArrayGet(&arr, 0);
    ASSERT_EQ(JWT_JSON_ELEMENT_TYPE_BOOLEAN, element.type);
    ASSERT_TRUE(element.boolean);

    jwtJsonArrayDestroy(&arr);
}

TEST(JsonArray, Bool) {

    JwtJsonArray obj = jwtJsonArrayCreate();
    jwtJsonArrayPushBool(&obj, true);

    ASSERT_EQ(1, obj.length);

    JwtJsonElement element = jwtJsonArrayGet(&obj, 0);
    ASSERT_EQ(JWT_JSON_ELEMENT_TYPE_BOOLEAN, element.type);
    ASSERT_TRUE(element.boolean);
    jwtJsonArrayDestroy(&obj);
}

TEST(JsonArray, Int) {

    JwtJsonArray obj = jwtJsonArrayCreate();
    jwtJsonArrayPushInt(&obj, -42);

    ASSERT_EQ(1, obj.length);

    JwtJsonElement element = jwtJsonArrayGet(&obj, 0);
    ASSERT_EQ(JWT_JSON_ELEMENT_TYPE_NUMERIC, element.type);
    ASSERT_EQ(JWT_NUMBER_TYPE_SIGNED, element.number.type);
    ASSERT_EQ(-42, element.number.i64);
    jwtJsonArrayDestroy(&obj);
}

TEST(JsonArray, Uint) {

    JwtJsonArray obj = jwtJsonArrayCreate();
    jwtJsonArrayPushUint(&obj, 42);

    ASSERT_EQ(1, obj.length);

    JwtJsonElement element = jwtJsonArrayGet(&obj, 0);
    ASSERT_EQ(JWT_JSON_ELEMENT_TYPE_NUMERIC, element.type);
    ASSERT_EQ(JWT_NUMBER_TYPE_UNSIGNED, element.number.type);
    ASSERT_EQ(42, element.number.u64);
    jwtJsonArrayDestroy(&obj);
}

TEST(JsonArray, Float) {

    JwtJsonArray obj = jwtJsonArrayCreate();
    jwtJsonArrayPushDouble(&obj, 12.25);

    ASSERT_EQ(1, obj.length);

    JwtJsonElement element = jwtJsonArrayGet(&obj, 0);
    ASSERT_EQ(JWT_JSON_ELEMENT_TYPE_NUMERIC, element.type);
    ASSERT_EQ(JWT_NUMBER_TYPE_FLOAT, element.number.type);
    ASSERT_EQ(12.25, element.number.f64);
    jwtJsonArrayDestroy(&obj);
}

TEST(JsonArray, String) {

    JwtJsonArray arr = jwtJsonArrayCreate();
    ASSERT_EQ(0, jwtJsonArrayLength(&arr));

    jwtJsonArrayPushString(&arr, "Hello");

    ASSERT_EQ(1, jwtJsonArrayLength(&arr));
    JwtJsonElement element = jwtJsonArrayGet(&arr, 0);
    ASSERT_EQ(JWT_JSON_ELEMENT_TYPE_STRING, element.type);
    ASSERT_TRUE(strcmp("Hello", element.string.data) == 0);

    jwtJsonArrayDestroy(&arr);
}

TEST(JsonObject, Empty) {

    JwtJsonObject obj = jwtJsonObjectCreate();
    ASSERT_EQ(0, obj.size);
    jwtJsonObjectDestroy(&obj);
}

TEST(JsonObject, Set) {

    JwtJsonObject obj = jwtJsonObjectCreate();
    jwtJsonObjectSet(&obj, "test",
                     {.type = JWT_JSON_ELEMENT_TYPE_BOOLEAN, .boolean = true});

    ASSERT_EQ(1, obj.size);

    JwtJsonElement element = jwtJsonObjectGet(&obj, "test");
    ASSERT_EQ(JWT_JSON_ELEMENT_TYPE_BOOLEAN, element.type);
    ASSERT_TRUE(element.boolean);
    jwtJsonObjectDestroy(&obj);
}

TEST(JsonObject, Bool) {

    JwtJsonObject obj = jwtJsonObjectCreate();
    jwtJsonObjectSetBool(&obj, "test", true);

    ASSERT_EQ(1, obj.size);
    ASSERT_TRUE(jwtJsonObjectGetBool(&obj, "test"));
    jwtJsonObjectDestroy(&obj);
}

TEST(JsonObject, Int) {

    JwtJsonObject obj = jwtJsonObjectCreate();
    jwtJsonObjectSetInt(&obj, "test", -42);

    ASSERT_EQ(1, obj.size);
    ASSERT_EQ(-42, jwtJsonObjectGetInt(&obj, "test"));
    jwtJsonObjectDestroy(&obj);
}

TEST(JsonObject, Uint) {

    JwtJsonObject obj = jwtJsonObjectCreate();
    jwtJsonObjectSetUint(&obj, "test", 42);

    ASSERT_EQ(1, obj.size);
    ASSERT_EQ(42, jwtJsonObjectGetUint(&obj, "test"));
    jwtJsonObjectDestroy(&obj);
}

TEST(JsonObject, Float) {

    JwtJsonObject obj = jwtJsonObjectCreate();
    jwtJsonObjectSetDouble(&obj, "test", 12.25);

    ASSERT_EQ(1, obj.size);
    ASSERT_EQ(12.25, jwtJsonObjectGetDouble(&obj, "test"));
    jwtJsonObjectDestroy(&obj);
}

TEST(JsonObject, String) {

    JwtJsonObject obj = jwtJsonObjectCreate();
    jwtJsonObjectSetString(&obj, "test", "Hello");

    ASSERT_EQ(1, obj.size);
    ASSERT_EQ(0, strcmp("Hello", jwtJsonObjectGetString(&obj, "test").data));
    jwtJsonObjectDestroy(&obj);
}

TEST(JsonObject, Remove) {

    JwtJsonObject obj = jwtJsonObjectCreate();

    jwtJsonObjectSetInt(&obj, "test", -42);
    ASSERT_EQ(1, obj.size);
    ASSERT_EQ(-42, jwtJsonObjectGetInt(&obj, "test"));

    jwtJsonObjectRemove(&obj, "test");
    ASSERT_EQ(0, obj.size);

    jwtJsonObjectDestroy(&obj);
}

TEST(JsonObject, Overwrite) {

    JwtJsonObject obj = jwtJsonObjectCreate();

    jwtJsonObjectSetInt(&obj, "test", -42);
    ASSERT_EQ(1, obj.size);

    JwtJsonElement element = jwtJsonObjectGet(&obj, "test");
    ASSERT_EQ(JWT_JSON_ELEMENT_TYPE_NUMERIC, element.type);
    ASSERT_EQ(JWT_NUMBER_TYPE_SIGNED, element.number.type);
    ASSERT_EQ(-42, element.number.i64);

    jwtJsonObjectSetInt(&obj, "test", 42);
    ASSERT_EQ(1, obj.size);

    element = jwtJsonObjectGet(&obj, "test");
    ASSERT_EQ(JWT_JSON_ELEMENT_TYPE_NUMERIC, element.type);
    ASSERT_EQ(JWT_NUMBER_TYPE_SIGNED, element.number.type);
    ASSERT_EQ(42, element.number.i64);

    jwtJsonObjectDestroy(&obj);
}

TEST(JsonObject, Complex) {

    JwtJsonObject obj = jwtJsonObjectCreate();
    jwtJsonObjectSetString(&obj, "str", "Hello");
    jwtJsonObjectSetInt(&obj, "int", 11);
    jwtJsonObjectSetUint(&obj, "uint", 44);
    jwtJsonObjectSetDouble(&obj, "float", -55.1);
    jwtJsonObjectSetBool(&obj, "bool", false);

    JwtJsonArray subArray = jwtJsonArrayCreate();
    jwtJsonArrayPushString(&subArray, "World");
    jwtJsonArrayPushInt(&subArray, -6000);
    jwtJsonObjectSetArray(&obj, "array", subArray);

    JwtJsonObject subObject = jwtJsonObjectCreate();
    jwtJsonObjectSetString(&subObject, "sub", "object");
    jwtJsonObjectSetObject(&obj, "obj", subObject);

    ASSERT_EQ(7, obj.size);

    ASSERT_EQ(
        0, strcmp("Hello",
                  jwtJsonElementAsString(jwtJsonObjectGet(&obj, "str")).data));
    ASSERT_EQ(11, jwtNumericAsInt(
                      jwtJsonElementAsNumber(jwtJsonObjectGet(&obj, "int"))));
    ASSERT_EQ(44, jwtNumericAsUint(
                      jwtJsonElementAsNumber(jwtJsonObjectGet(&obj, "uint"))));
    ASSERT_EQ(-55.1, jwtNumericAsDouble(jwtJsonElementAsNumber(
                         jwtJsonObjectGet(&obj, "float"))));
    ASSERT_FALSE(jwtJsonElementAsBool(jwtJsonObjectGet(&obj, "bool")));

    JwtJsonElement subArrayElement = jwtJsonObjectGet(&obj, "array");
    ASSERT_EQ(JWT_JSON_ELEMENT_TYPE_ARRAY, subArrayElement.type);
    ASSERT_EQ(2, jwtJsonElementAsArray(subArrayElement).length);
    ASSERT_EQ(0,
              strcmp("World",
                     jwtJsonArrayGet(&subArrayElement.array, 0).string.data));
    ASSERT_EQ(-6000, jwtJsonArrayGet(&subArrayElement.array, 1).number.i64);

    JwtJsonElement subObjectElement = jwtJsonObjectGet(&obj, "obj");
    ASSERT_EQ(0, strcmp("object",
                        jwtJsonElementAsString(
                            jwtJsonObjectGet(&subObjectElement.object, "sub"))
                            .data));
}

TEST(JsonObjectIterator, Empty) {

    JwtJsonObject obj = jwtJsonObjectCreate();
    JwtJsonObjectIterator it = jwtJsonObjectIteratorCreate(&obj);

    JwtJsonObjectEntry* ent = jwtJsonObjectIteratorNext(&it);
    ASSERT_EQ(nullptr, ent);

    jwtJsonObjectDestroy(&obj);
}

TEST(JsonObjectIterator, Single) {

    JwtJsonObject obj = jwtJsonObjectCreate();
    jwtJsonObjectSetInt(&obj, "test", 11);

    JwtJsonObjectIterator it = jwtJsonObjectIteratorCreate(&obj);

    JwtJsonObjectEntry* ent = jwtJsonObjectIteratorNext(&it);
    ASSERT_EQ(0, strcmp("test", ent->key.data));
    ASSERT_EQ(JWT_JSON_ELEMENT_TYPE_NUMERIC, ent->element.type);
    ASSERT_EQ(JWT_NUMBER_TYPE_SIGNED, ent->element.number.type);
    ASSERT_EQ(11, ent->element.number.i64);

    jwtJsonObjectDestroy(&obj);
}

TEST(JsonObjectIterator, Double) {

    JwtJsonObject obj = jwtJsonObjectCreate();
    jwtJsonObjectSetInt(&obj, "test1", 11);
    jwtJsonObjectSetInt(&obj, "test2", 12);

    bool foundTest1 = false;
    bool foundTest2 = false;

    JwtJsonObjectIterator it = jwtJsonObjectIteratorCreate(&obj);

    size_t index = 0;
    JwtJsonObjectEntry* ent;
    while ((ent = jwtJsonObjectIteratorNext(&it)) != nullptr) {
        index++;
        if (strcmp("test1", ent->key.data) == 0) {
            ASSERT_FALSE(foundTest1);
            ASSERT_EQ(JWT_JSON_ELEMENT_TYPE_NUMERIC, ent->element.type);
            ASSERT_EQ(JWT_NUMBER_TYPE_SIGNED, ent->element.number.type);
            ASSERT_EQ(11, ent->element.number.i64);
            foundTest1 = true;
        } else if (strcmp("test2", ent->key.data) == 0) {
            ASSERT_FALSE(foundTest2);
            ASSERT_EQ(JWT_JSON_ELEMENT_TYPE_NUMERIC, ent->element.type);
            ASSERT_EQ(JWT_NUMBER_TYPE_SIGNED, ent->element.number.type);
            ASSERT_EQ(12, ent->element.number.i64);
            foundTest2 = true;
        } else {
            ASSERT_TRUE(false);
        }
    }

    ASSERT_EQ(index, 2);
    ASSERT_TRUE(foundTest1);
    ASSERT_TRUE(foundTest2);

    jwtJsonObjectDestroy(&obj);
}
