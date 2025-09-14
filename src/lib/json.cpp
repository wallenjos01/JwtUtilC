/**
 * Josh Wallentine
 * Created 9/11/25
 *
 * Partial implementation of include/jwt/json.h
 * See also json_decoder.cpp and json_encoder.cpp
 */

#include <cstdlib>
#include <jwt/core.h>
#include <jwt/json.h>
#include <utility>

#include "hash.hpp"

namespace {} // namespace

JwtJsonArray jwtJsonArrayCreate() {
    JwtJsonArray out = {};
    out.length = 0;
    out.capacity = 0;
    out.data = nullptr;
    return out;
}
void jwtJsonArrayDestroy(JwtJsonArray* array) {
    for (auto i = 0; i < array->length; i++) {
        jwtJsonElementDestroy(&array->data[i]);
    }
    if (array->data) {
        free(array->data);
        array->data = nullptr;
    }
    array->capacity = 0;
    array->length = 0;
}

JwtJsonElement jwtJsonArrayGet(JwtJsonArray* array, size_t index) {
    if (index >= array->length) {
        return {.type = JWT_JSON_ELEMENT_TYPE_NULL, .boolean = false};
    }
    return array->data[index];
}
void jwtJsonArrayPush(JwtJsonArray* array, JwtJsonElement element) {
    if (array->length == array->capacity) {
        // Realloc
        size_t newCapacity;
        if (array->capacity > 0) {
            newCapacity = array->capacity * 2;
        } else {
            newCapacity = 2;
        }

        size_t toAlloc = newCapacity * sizeof(JwtJsonElement);

        void* newData;
        if (array->data == nullptr) {
            newData = malloc(toAlloc);
        } else {
            newData = realloc(array->data, toAlloc);
        }

        array->capacity = newCapacity;
        array->data = static_cast<JwtJsonElement*>(newData);
    }

    array->data[array->length++] = element;
}
void jwtJsonArraySet(JwtJsonArray* array, JwtJsonElement element,
                     size_t index) {
    if (index >= array->length) {
        return;
    }
    array->data[index] = element;
}
void jwtJsonArrayRemove(JwtJsonArray* array, size_t index) {
    if (index > array->length) {
        return;
    }

    jwtJsonElementDestroy(&array->data[index]);
    memmove(array->data + index - 1, array->data + index,
            array->length - index);
    array->length -= 1;
}

JwtJsonObject jwtJsonObjectCreate() { return jwtJsonObjectCreateSized(16); }

JwtJsonObject jwtJsonObjectCreateSized(size_t numBuckets) {
    JwtJsonObject out = {.numBuckets = numBuckets,
                         .size = 0,
                         .buckets = new JwtJsonObjectEntry*[numBuckets]};

    memset(out.buckets, 0, sizeof(JwtJsonObjectEntry*) * numBuckets);
    return out;
}

void jwtJsonObjectDestroy(JwtJsonObject* object) {

    jwtJsonObjectClear(object);
    if (object->buckets) {
        delete[] object->buckets;
        object->buckets = nullptr;
    }
    object->numBuckets = 0;
}

JwtJsonElement jwtJsonObjectGet(JwtJsonObject* object, const char* key) {
    size_t len = strlen(key);
    size_t bucket = hashString(key, len) % object->numBuckets;

    if (object->numBuckets == 0)
        return {.type = JWT_JSON_ELEMENT_TYPE_NULL, .boolean = false};

    JwtJsonObjectEntry* entry = object->buckets[bucket];
    while (entry != nullptr &&
           (entry->key.length != len || memcmp(key, entry->key.data, len))) {
        entry = entry->next;
    }
    if (entry == nullptr) {
        return {.type = JWT_JSON_ELEMENT_TYPE_NULL, .boolean = false};
    }

    return entry->element;
}
void jwtJsonObjectSetWithString(JwtJsonObject* object, JwtString key,
                                JwtJsonElement value) {

    if (object->numBuckets == 0)
        return;

    if (object->size >= object->numBuckets * 0.8) {
        jwtJsonObjectReindex(object, object->numBuckets * 2);
    }

    size_t bucket = hashString(key.data, key.length) % object->numBuckets;

    JwtJsonObjectEntry* entry = object->buckets[bucket];
    while (entry != nullptr &&
           (entry->key.length != key.length ||
            memcmp(key.data, entry->key.data, key.length))) {
        entry = entry->next;
    }
    if (entry != nullptr) {
        // Overwrite existing value
        jwtStringDestroy(&entry->key);
        jwtJsonElementDestroy(&entry->element);
    } else {
        // Insert new value
        JwtJsonObjectEntry* prev = object->buckets[bucket];
        entry = new JwtJsonObjectEntry();
        entry->next = prev;
        object->buckets[bucket] = entry;
        object->size++;
    }

    entry->key = key;
    entry->element = value;
}

void jwtJsonObjectReindex(JwtJsonObject* obj, size_t len) {
    JwtJsonObject reindexed = jwtJsonObjectCreateSized(len);

    for (auto i = 0; i < obj->numBuckets; i++) {
        JwtJsonObjectEntry* entry = obj->buckets[i];
        while (entry != nullptr) {
            jwtJsonObjectSetWithString(&reindexed, entry->key, entry->element);
        }
    }

    std::swap(reindexed, *obj);

    delete[] reindexed.buckets;
    reindexed.buckets = nullptr;
    reindexed.numBuckets = 0;
    reindexed.size = 0;
}

void jwtJsonObjectRemove(JwtJsonObject* object, const char* key) {

    if (object->numBuckets == 0)
        return;

    size_t len = strlen(key);
    size_t bucket = hashString(key, len) % object->numBuckets;

    JwtJsonObjectEntry* entry = object->buckets[bucket];
    JwtJsonObjectEntry* prev = entry;
    while (entry != nullptr &&
           (entry->key.length != len || memcmp(key, entry->key.data, len))) {
        prev = entry;
        entry = entry->next;
    }

    if (entry != nullptr) {
        prev->next = entry->next;
        jwtStringDestroy(&entry->key);
        jwtJsonElementDestroy(&entry->element);
        delete entry;
        object->size--;
    }

    if (entry == prev) {
        object->buckets[bucket] = nullptr;
    }
}
void jwtJsonObjectClear(JwtJsonObject* object) {
    for (auto i = 0; i < object->numBuckets; i++) {
        JwtJsonObjectEntry* entry = object->buckets[i];
        while (entry != nullptr) {
            jwtStringDestroy(&entry->key);
            jwtJsonElementDestroy(&entry->element);
            JwtJsonObjectEntry* prev = entry;

            entry = entry->next;
            delete prev;
        }
        object->buckets[i] = nullptr;
    }
    object->size = 0;
}

JwtJsonObjectIterator jwtJsonObjectIteratorCreate(JwtJsonObject* obj) {
    return {
        .obj = obj, .entry = nullptr, .bucketIndex = static_cast<size_t>(-1)};
}
JwtJsonObjectEntry* jwtJsonObjectIteratorNext(JwtJsonObjectIterator* it) {
    if (it->entry != nullptr) {
        it->entry = it->entry->next;
    }

    while (it->entry == nullptr) {
        if (it->bucketIndex + 1 == it->obj->numBuckets) {
            break;
        }
        it->bucketIndex++;
        it->entry = it->obj->buckets[it->bucketIndex];
    }

    return it->entry;
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
    if (element.type != JWT_JSON_ELEMENT_TYPE_ARRAY)
        return {.length = 0, .capacity = 0, .data = nullptr};
    return element.array;
}
JwtJsonObject jwtJsonElementAsObject(JwtJsonElement element) {
    if (element.type != JWT_JSON_ELEMENT_TYPE_OBJECT)
        return {.numBuckets = 0, .size = 0, .buckets = nullptr};
    return element.object;
}
