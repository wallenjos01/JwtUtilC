/**
 * Josh Wallentine
 * Created 9/11/25
 * Modified 9/30/25
 *
 * Partial implementation of include/jwt/json.h
 * See also json_decoder.cpp and json_encoder.cpp
 */

#include <jwt/core.h>
#include <jwt/json.h>

#include <cstdlib>

#include "hash.hpp"

namespace {

JwtHashFunctions jsonFunctions = {
    .entrySize = sizeof(JwtJsonObjectEntry),
    .pfnHashKey =
        [](void* key) {
            JwtString* str = static_cast<JwtString*>(key);
            return hashString(str->data, str->length);
        },
    .pfnCompareKey =
        [](void* key, void* entry) {
            JwtString* str = static_cast<JwtString*>(key);
            JwtJsonObjectEntry* ent = static_cast<JwtJsonObjectEntry*>(entry);
            if (str->length != ent->key.length) {
                return -1;
            }
            return memcmp(str->data, ent->key.data, str->length);
        }};

} // namespace

void jwtJsonArrayDestroy(JwtJsonArray* array) {
    for (auto i = 0; i < array->size; i++) {
        jwtJsonElementDestroy(
            static_cast<JwtJsonElement*>(jwtListGet(array, i)));
    }
    jwtListDestroy(array);
}

void jwtJsonObjectCreate(JwtJsonObject* object) {
    return jwtHashTableCreate(object, &jsonFunctions);
}

void jwtJsonObjectCreateSized(JwtJsonObject* object, size_t numBuckets) {
    return jwtHashTableCreateSized(object, &jsonFunctions, numBuckets);
}

void jwtJsonObjectDestroy(JwtJsonObject* object) {
    jwtJsonObjectClear(object);
    jwtHashTableDestroy(object);
}

JwtJsonElement jwtJsonObjectGet(JwtJsonObject* object, const char* key) {

    JwtString keyView = {.length = strlen(key), .data = key};
    JwtJsonObjectEntry* entry =
        static_cast<JwtJsonObjectEntry*>(jwtHashTableGet(object, &keyView));
    if (entry == nullptr) {
        return {};
    }

    return entry->element;
}
void jwtJsonObjectSetWithString(JwtJsonObject* object, JwtString key,
                                JwtJsonElement value) {

    JwtJsonObjectEntry* entry =
        static_cast<JwtJsonObjectEntry*>(jwtHashTablePut(object, &key));

    entry->key = key;
    entry->element = value;
}

void jwtJsonObjectRemove(JwtJsonObject* object, const char* key) {
    JwtString keyView = {.length = strlen(key), .data = key};
    JwtJsonObjectEntry* entry =
        static_cast<JwtJsonObjectEntry*>(jwtHashTableReclaim(object, &keyView));

    if (entry != nullptr) {
        jwtStringDestroy(&entry->key);
        jwtJsonElementDestroy(&entry->element);
        free(entry);
    }
}

JwtJsonElement jwtJsonElementReclaim(JwtJsonObject* object, const char* key) {
    JwtString keyView = {.length = strlen(key), .data = key};
    JwtJsonObjectEntry* entry =
        static_cast<JwtJsonObjectEntry*>(jwtHashTableReclaim(object, &keyView));

    if (entry) {
        JwtJsonElement out = entry->element;
        jwtStringDestroy(&entry->key);
        free(entry);
        return out;
    } else {
        return {};
    }
}

void jwtJsonObjectClear(JwtJsonObject* object) {

    JwtJsonObjectIterator it = jwtJsonObjectIteratorCreate(object);
    jwtHashTableIteratorNext(&it);

    while (it.current != nullptr) {
        JwtJsonObjectEntry* entry =
            static_cast<JwtJsonObjectEntry*>(jwtHashTableIteratorReclaim(&it));
        jwtStringDestroy(&entry->key);
        jwtJsonElementDestroy(&entry->element);

        free(entry);
    }
}

JwtJsonObjectEntry* jwtJsonObjectIteratorNext(JwtJsonObjectIterator* it) {
    jwtHashTableIteratorNext(it);
    if (it->current == nullptr)
        return nullptr;
    return static_cast<JwtJsonObjectEntry*>(it->current->data);
}

void jwtJsonElementDestroy(JwtJsonElement* element) {
    switch (element->type) {
    case JWT_JSON_ELEMENT_TYPE_STRING:
        jwtStringDestroy(&element->string);
        break;
    case JWT_JSON_ELEMENT_TYPE_ARRAY:
        jwtJsonArrayDestroy(&element->array);
        break;
    case JWT_JSON_ELEMENT_TYPE_OBJECT:
        jwtJsonObjectDestroy(&element->object);
        break;
    default:
        break;
    }

    element->type = JWT_JSON_ELEMENT_TYPE_NULL;
    element->boolean = false;
}

JwtJsonElementType jwtJsonElementType(JwtJsonElement element) {
    return element.type;
}
JwtString jwtJsonElementAsString(JwtJsonElement element) {
    if (element.type != JWT_JSON_ELEMENT_TYPE_STRING)
        return {.length = 0, .data = nullptr};
    return element.string;
}
JwtNumeric jwtJsonElementAsNumber(JwtJsonElement element) {
    if (element.type != JWT_JSON_ELEMENT_TYPE_NUMERIC)
        return {.i64 = 0, .type = JWT_NUMBER_TYPE_SIGNED};
    return element.number;
}
bool jwtJsonElementAsBool(JwtJsonElement element) {
    if (element.type != JWT_JSON_ELEMENT_TYPE_BOOLEAN)
        return false;
    return element.boolean;
}
JwtJsonArray jwtJsonElementAsArray(JwtJsonElement element) {
    if (element.type != JWT_JSON_ELEMENT_TYPE_ARRAY) {
        JwtJsonArray arr = {};
        jwtJsonArrayCreate(&arr);
        return arr;
    }
    return element.array;
}
JwtJsonObject jwtJsonElementAsObject(JwtJsonElement element) {
    if (element.type != JWT_JSON_ELEMENT_TYPE_OBJECT) {
        JwtJsonObject obj = {};
        jwtJsonObjectCreate(&obj);
        return obj;
    }
    return element.object;
}
