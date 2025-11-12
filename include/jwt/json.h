#ifndef JWT_JSON_H
#define JWT_JSON_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include "core.h"
#include "stream.h"

/**
 * Enumerates all valid types for JSON Elements
 */
enum JwtJsonElementType {
    JWT_JSON_ELEMENT_TYPE_NULL,
    JWT_JSON_ELEMENT_TYPE_STRING,
    JWT_JSON_ELEMENT_TYPE_NUMERIC,
    JWT_JSON_ELEMENT_TYPE_BOOLEAN,
    JWT_JSON_ELEMENT_TYPE_ARRAY,
    JWT_JSON_ELEMENT_TYPE_OBJECT
};

/**
 * Enumerates all possible result codes from a call to jwtReadJson*();
 */
enum JwtJsonParseResult : int32_t {
    JWT_JSON_PARSE_RESULT_SUCCESS = 0,
    JWT_JSON_PARSE_RESULT_UNEXPECTED_SYMBOL = -1,
    JWT_JSON_PARSE_RESULT_UNEXPECTED_EOF = -2,
    JWT_JSON_PARSE_RESULT_IO_ERROR = -3
};

/**
 * Represents a JSON array, which can contain any number of JSON elements
 */
typedef JwtList JwtJsonArray;

/**
 * Represents a JSON object, which is a key-value mapping from strings to JSON
 * elements
 */
typedef JwtHashTable JwtJsonObject;

/**
 * A typed union representing a JSON element, which is one of: a string, a
 * number, a boolean, a JSON array, a JSON object, or null
 */
typedef struct JwtJsonElement {
    /**
     * @brief The element type.
     */
    JwtJsonElementType type;

    /**
     * @brief The element data.
     */
    union {
        JwtString string;
        JwtNumeric number;
        bool boolean;
        JwtJsonArray array;
        JwtJsonObject object;
    };
} JwtJsonElement;

/**
 * Represents a key-value pair in a JSON Object
 */
typedef struct JwtJsonObjectEntry {
    /**
     * @brief The string key associated with the element
     */
    JwtString key;
    /**
     * @brief The element in the JSON object
     */
    JwtJsonElement element;
} JwtJsonObjectEntry;

/**
 * Utility struct for iterating over JSON Object entries
 */
typedef JwtHashTableIterator JwtJsonObjectIterator;

/**
 * @brief Destroys the given JSON element, if necessary.
 * For example: if the element is a String, jwtStringDestroy() is called.
 * @param element The element to destroy
 */
void jwtJsonElementDestroy(JwtJsonElement* element);

/**
 * @brief Retrieves the given JSON element's type.
 * Equivalent to element.type
 * @param element The element to get the type of
 * @return The element's type
 */
JwtJsonElementType jwtJsonElementType(JwtJsonElement element);

/**
 * @brief Gets the string contained within the element, if possible.
 * If the given element is not a string, an empty string is returned instead.
 * @param element The element to get a string from
 * @return A string
 */
JwtString jwtJsonElementAsString(JwtJsonElement element);

/**
 * @brief Gets the number contained within the element, if possible.
 * If the given element is not a number, 0 is returned instead.
 * @param element The element to get a number from from
 * @return A number
 */
JwtNumeric jwtJsonElementAsNumber(JwtJsonElement element);

/**
 * @brief Gets the number contained within the element as a signed integer, if
 * possible. If the given element is not a number, 0 is returned instead.
 * @param element The element to get a number from from
 * @return A number
 */
inline int64_t jwtJsonElementAsInt(JwtJsonElement element) {
    return jwtNumericAsInt(jwtJsonElementAsNumber(element));
}

/**
 * @brief Gets the number contained within the element as an unsigned integer,
 * if possible. If the given element is not a number, 0 is returned instead.
 * @param element The element to get a number from from
 * @return A number
 */
inline uint64_t jwtJsonElementAsUint(JwtJsonElement element) {
    return jwtNumericAsUint(jwtJsonElementAsNumber(element));
}

/**
 * @brief Gets the number contained within the element as a double, if possible.
 * If the given element is not a number, 0.0 is returned instead.
 * @param element The element to get a number from from
 * @return A number
 */
inline double jwtJsonElementAsDouble(JwtJsonElement element) {
    return jwtNumericAsDouble(jwtJsonElementAsNumber(element));
}

/**
 * @brief Gets the boolean contained within the element, if possible.
 * If the given element is not a boolean, false is returned instead.
 * @param element The element to get a boolean from
 * @return A boolean
 */
bool jwtJsonElementAsBool(JwtJsonElement element);

/**
 * @brief Gets the JSON array contained within the element, if possible.
 * If the given element is not an array, an empty array is returned instead.
 * @param element The element to get an array from
 * @return A JSON array
 */
JwtJsonArray jwtJsonElementAsArray(JwtJsonElement element);

/**
 * @brief Gets the JSON Object contained within the element, if possible.
 * If the given element is not an object, a null object is returned instead.
 * @param element The element to get an object from
 * @return An object
 */
JwtJsonObject jwtJsonElementAsObject(JwtJsonElement element);

/**
 * @brief Creates an empty JSON array.
 * All JSON arrays created in this way need to be destroyed with
 * jwtJsonArrayDestroy()
 * @return An empty JSON array.
 */
inline void jwtJsonArrayCreate(JwtJsonArray* array) {
    jwtListCreate(array, sizeof(JwtJsonElement));
}

/**
 * @brief Destroys the given JSON array.
 * @param array A pointer to the array to destroy.
 */
void jwtJsonArrayDestroy(JwtJsonArray* array);

/**
 * @brief Retrieves the length of the given JSON array.
 * Equivalient to array->length;
 * @param array The array to get the length for.
 * @return The array's size
 */
inline size_t jwtJsonArrayLength(JwtJsonArray* array) { return array->size; }

/**
 * @brief Gets an element in the given array at the given index.
 * If the index is out of bounds, a null object is returned instead.
 * @param array The array get from.
 * @param index The element index to get.
 * @return An JSON element.
 */
inline JwtJsonElement jwtJsonArrayGet(JwtJsonArray* array, size_t index) {
    return *static_cast<JwtJsonElement*>(jwtListGet(array, index));
}

/**
 * @brief Gets an element in the given array at the given index as a string.
 * If the index is out of bounds, a null string is returned instead.
 * @param array The array get from.
 * @param index The element index to get.
 * @return An JSON element.
 */
inline JwtString jwtJsonArrayGetString(JwtJsonArray* array, size_t index) {
    return jwtJsonElementAsString(jwtJsonArrayGet(array, index));
}

/**
 * @brief Gets an element in the given array at the given index as a number.
 * If the index is out of bounds, 0 is returned instead.
 * @param array The array get from.
 * @param index The element index to get.
 * @return An JSON element.
 */
inline JwtNumeric jwtJsonArrayGetNumeric(JwtJsonArray* array, size_t index) {
    return jwtJsonElementAsNumber(jwtJsonArrayGet(array, index));
}

/**
 * @brief Gets an element in the given array at the given index as a signed
 * integer. If the index is out of bounds, 0 is returned instead.
 * @param array The array get from.
 * @param index The element index to get.
 * @return An JSON element.
 */
inline int64_t jwtJsonArrayGetInt(JwtJsonArray* array, size_t index) {
    return jwtNumericAsInt(jwtJsonArrayGetNumeric(array, index));
}

/**
 * @brief Gets an element in the given array at the given index as an unsigned
 * integer. If the index is out of bounds, 0 is returned instead.
 * @param array The array get from.
 * @param index The element index to get.
 * @return An JSON element.
 */
inline uint64_t jwtJsonArrayGetUint(JwtJsonArray* array, size_t index) {
    return jwtNumericAsUint(jwtJsonArrayGetNumeric(array, index));
}

/**
 * @brief Gets an element in the given array at the given index as a double.
 * If the index is out of bounds, 0.0 is returned instead.
 * @param array The array get from.
 * @param index The element index to get.
 * @return An JSON element.
 */
inline double jwtJsonArrayGetDouble(JwtJsonArray* array, size_t index) {
    return jwtNumericAsDouble(jwtJsonArrayGetNumeric(array, index));
}

/**
 * @brief Gets an element in the given array at the given index as an array.
 * If the index is out of bounds, an empty array is returned instead.
 * @param array The array get from.
 * @param index The element index to get.
 * @return An JSON element.
 */
inline JwtJsonArray jwtJsonArrayGetArray(JwtJsonArray* array, size_t index) {
    return jwtJsonElementAsArray(jwtJsonArrayGet(array, index));
}

/**
 * @brief Gets an element in the given array at the given index as an object.
 * If the index is out of bounds, a null object is returned instead.
 * @param array The array get from.
 * @param index The element index to get.
 * @return An JSON element.
 */
inline JwtJsonObject jwtJsonArrayGetObject(JwtJsonArray* array, size_t index) {
    return jwtJsonElementAsObject(jwtJsonArrayGet(array, index));
}

/**
 * @brief Pushes the given element onto the given array.
 * @param array The array to push onto.
 * @param element The element to push
 */
inline void jwtJsonArrayPush(JwtJsonArray* array, JwtJsonElement element) {
    *static_cast<JwtJsonElement*>(jwtListPush(array)) = element;
}

/**
 * @brief Pushes the given string onto the given array.
 * @param array The array to push onto.
 * @param value The string to push
 */
inline void jwtJsonArrayPushString(JwtJsonArray* array, const char* value) {
    jwtJsonArrayPush(array, {.type = JWT_JSON_ELEMENT_TYPE_STRING,
                             .string = jwtStringCreate(value)});
}

/**
 * @brief Pushes the given signed integer onto the given array.
 * @param array The array to push onto.
 * @param value The value to push
 */
inline void jwtJsonArrayPushInt(JwtJsonArray* array, int64_t value) {
    jwtJsonArrayPush(
        array, {.type = JWT_JSON_ELEMENT_TYPE_NUMERIC,
                .number = {.i64 = value, .type = JWT_NUMBER_TYPE_SIGNED}});
}

/**
 * @brief Pushes the given unsigned integer onto the given array.
 * @param array The array to push onto.
 * @param value The value to push
 */
inline void jwtJsonArrayPushUint(JwtJsonArray* array, uint64_t value) {
    jwtJsonArrayPush(
        array, {.type = JWT_JSON_ELEMENT_TYPE_NUMERIC,
                .number = {.u64 = value, .type = JWT_NUMBER_TYPE_UNSIGNED}});
}

/**
 * @brief Pushes the given double onto the given array.
 * @param array The array to push onto.
 * @param value The value to push
 */
inline void jwtJsonArrayPushDouble(JwtJsonArray* array, double value) {
    jwtJsonArrayPush(array,
                     {.type = JWT_JSON_ELEMENT_TYPE_NUMERIC,
                      .number = {.f64 = value, .type = JWT_NUMBER_TYPE_FLOAT}});
}

/**
 * @brief Pushes the given boolean onto the given array.
 * @param array The array to push onto.
 * @param value The value to push
 */
inline void jwtJsonArrayPushBool(JwtJsonArray* array, bool value) {
    jwtJsonArrayPush(array,
                     {.type = JWT_JSON_ELEMENT_TYPE_BOOLEAN, .boolean = value});
}

/**
 * @brief Pushes the given array onto the given array.
 * @param array The array to push onto.
 * @param value The array to push
 */
inline void jwtJsonArrayPushArray(JwtJsonArray* array, JwtJsonArray value) {
    jwtJsonArrayPush(array,
                     {.type = JWT_JSON_ELEMENT_TYPE_ARRAY, .array = value});
}

/**
 * @brief Pushes the given object onto the given array.
 * @param array The array to push onto.
 * @param object The object to push
 */
inline void jwtJsonArrayPushObject(JwtJsonArray* array, JwtJsonObject value) {
    jwtJsonArrayPush(array,
                     {.type = JWT_JSON_ELEMENT_TYPE_OBJECT, .object = value});
}

/**
 * @brief Changes the element at the given array index.
 * If the given index is out of bounds, nothing happens.
 * @param array The array to modify
 * @param element The new element
 * @param index The index of the element to change
 */
inline void jwtJsonArraySet(JwtJsonArray* array, JwtJsonElement element,
                            size_t index) {

    *static_cast<JwtJsonElement*>(jwtListGet(array, index)) = element;
}

/**
 * @brief Changes the element at the given array index to be the given string.
 * If the given index is out of bounds, nothing happens.
 * @param array The array to modify
 * @param value The new string
 * @param index The index of the element to change
 */
inline void jwtJsonArraySetString(JwtJsonArray* array, const char* value,
                                  size_t index) {
    jwtJsonArraySet(array,
                    {.type = JWT_JSON_ELEMENT_TYPE_STRING,
                     .string = jwtStringCreate(value)},
                    index);
}

/**
 * @brief Changes the element at the given array index to have the given signed
 * integer value.
 * If the given index is out of bounds, nothing happens.
 * @param array The array to modify
 * @param value The new value
 * @param index The index of the element to change
 */
inline void jwtJsonArraySetInt(JwtJsonArray* array, int64_t value,
                               size_t index) {
    jwtJsonArraySet(array,
                    {.type = JWT_JSON_ELEMENT_TYPE_NUMERIC,
                     .number = {.i64 = value, .type = JWT_NUMBER_TYPE_SIGNED}},
                    index);
}

/**
 * @brief Changes the element at the given array index to have the given
 * unsigned integer value.
 * If the given index is out of bounds, nothing happens.
 * @param array The array to modify
 * @param value The new value
 * @param index The index of the element to change
 */
inline void jwtJsonArraySetUint(JwtJsonArray* array, uint64_t value,
                                size_t index) {
    jwtJsonArraySet(
        array,
        {.type = JWT_JSON_ELEMENT_TYPE_NUMERIC,
         .number = {.u64 = value, .type = JWT_NUMBER_TYPE_UNSIGNED}},
        index);
}

/**
 * @brief Changes the element at the given array index to have the given float
 * value.
 * If the given index is out of bounds, nothing happens.
 * @param array The array to modify
 * @param value The new value
 * @param index The index of the element to change
 */
inline void jwtJsonArraySetFloat(JwtJsonArray* array, double value,
                                 size_t index) {
    jwtJsonArraySet(array,
                    {.type = JWT_JSON_ELEMENT_TYPE_NUMERIC,
                     .number = {.f64 = value, .type = JWT_NUMBER_TYPE_FLOAT}},
                    index);
}

/**
 * @brief Changes the element at the given array index to have the given boolean
 * value.
 * If the given index is out of bounds, nothing happens.
 * @param array The array to modify
 * @param value The new value
 * @param index The index of the element to change
 */
inline void jwtJsonArraySetBool(JwtJsonArray* array, bool value, size_t index) {
    jwtJsonArraySet(array,
                    {.type = JWT_JSON_ELEMENT_TYPE_BOOLEAN, .boolean = value},
                    index);
}

/**
 * @brief Changes the element at the given array index to be the given new
 * array.
 * If the given index is out of bounds, nothing happens.
 * @param array The array to modify
 * @param value The new array
 * @param index The index of the element to change
 */
inline void jwtJsonArraySetArray(JwtJsonArray* array, JwtJsonArray value,
                                 size_t index) {
    jwtJsonArraySet(
        array, {.type = JWT_JSON_ELEMENT_TYPE_ARRAY, .array = value}, index);
}

/**
 * @brief Changes the element at the given array index to be the given object.
 * If the given index is out of bounds, nothing happens.
 * @param array The array to modify
 * @param value The new object
 * @param index The index of the element to change
 */
inline void jwtJsonArraySetObject(JwtJsonArray* array, JwtJsonObject value,
                                  size_t index) {
    jwtJsonArraySet(
        array, {.type = JWT_JSON_ELEMENT_TYPE_OBJECT, .object = value}, index);
}

/**
 * @brief Removes the element at the given index from the given array.
 * If the given index is out of bounds, nothing happens.
 * @param array The array to remove from.
 * @param index The index of the element to remove.
 */
inline void jwtJsonArrayRemove(JwtJsonArray* array, size_t index) {
    jwtListRemove(array, index);
}

/**
 * @brief Creates an empty JSON object.
 * All JSON objects created in this way need to be destroyed with
 * jwtJsonObjectDestroy()
 * @return An empty JSON object.
 */
void jwtJsonObjectCreate(JwtJsonObject* object);

/**
 * @brief Creates an empty JSON object with the given number of buckets.
 * All JSON objects created in this way need to be destroyed with
 * jwtJsonObjectDestroy()
 * @param numBuckets The number of buckets to allocate at first.
 * @return An empty JSON object.
 */
void jwtJsonObjectCreateSized(JwtJsonObject* object, size_t numBuckets);

/**
 * @brief Destroys the given JSON object.
 * @param object The object to destroy.
 */
void jwtJsonObjectDestroy(JwtJsonObject* object);

/**
 * @brief Retrieves the given JSON object's size.
 * Equivalent to object-> size;
 * @param object The object to retrieve the size of.
 * @return The object's size
 */
inline size_t jwtJsonObjectSize(JwtJsonObject* object) { return object->size; }

/**
 * @brief Gets the JSON object element associated with the given key.
 * @param object The object to look up
 * @param key The which the element is associated with
 * @return The JSON element associated with the given key, or a null object if
 * the key is not present.
 */
JwtJsonElement jwtJsonObjectGet(JwtJsonObject* object, const char* key);

/**
 * @brief Gets the JSON object element associated with the given key as a
 * String.
 * @param object The object to look up
 * @param key The which the element is associated with
 * @return The JSON element associated with the given key, or a null string if
 * the key is not present.
 */
inline JwtString jwtJsonObjectGetString(JwtJsonObject* object,
                                        const char* key) {

    return jwtJsonElementAsString(jwtJsonObjectGet(object, key));
}

/**
 * @brief Gets the JSON object element associated with the given key as a signed
 * integer.
 * @param object The object to look up
 * @param key The which the element is associated with
 * @return The JSON element associated with the given key, or 0 if
 * the key is not present.
 */
inline int64_t jwtJsonObjectGetInt(JwtJsonObject* object, const char* key) {

    return jwtJsonElementAsInt(jwtJsonObjectGet(object, key));
}

/**
 * @brief Gets the JSON object element associated with the given key as an
 * unsigned integer.
 * @param object The object to look up
 * @param key The which the element is associated with
 * @return The JSON element associated with the given key, or 0 if
 * the key is not present.
 */
inline uint64_t jwtJsonObjectGetUint(JwtJsonObject* object, const char* key) {

    return jwtJsonElementAsUint(jwtJsonObjectGet(object, key));
}

/**
 * @brief Gets the JSON object element associated with the given key as a
 * double.
 * @param object The object to look up
 * @param key The which the element is associated with
 * @return The JSON element associated with the given key, or 0.0 if
 * the key is not present.
 */
inline double jwtJsonObjectGetDouble(JwtJsonObject* object, const char* key) {

    return jwtJsonElementAsDouble(jwtJsonObjectGet(object, key));
}

/**
 * @brief Gets the JSON object element associated with the given key as a bool.
 * @param object The object to look up
 * @param key The which the element is associated with
 * @return The JSON element associated with the given key, or false if
 * the key is not present.
 */
inline bool jwtJsonObjectGetBool(JwtJsonObject* object, const char* key) {

    return jwtJsonElementAsBool(jwtJsonObjectGet(object, key));
}

/**
 * @brief Gets the JSON object element associated with the given key as an
 * array.
 * @param object The object to look up
 * @param key The which the element is associated with
 * @return The JSON array associated with the given key, or an empty array if
 * the key is not present.
 */
inline JwtJsonArray jwtJsonObjectGetArray(JwtJsonObject* object,
                                          const char* key) {

    return jwtJsonElementAsArray(jwtJsonObjectGet(object, key));
}

/**
 * @brief Gets the JSON object element associated with the given key as an
 * object.
 * @param object The object to look up
 * @param key The which the element is associated with
 * @return The JSON object associated with the given key, or a null object if
 * the key is not present.
 */
inline JwtJsonObject jwtJsonObjectGetObject(JwtJsonObject* object,
                                            const char* key) {

    return jwtJsonElementAsObject(jwtJsonObjectGet(object, key));
}

/**
 * @brief Associates the given value with the given key within the given JSON
 * object
 * @param object The object to modify
 * @param key The value's new key
 * @param value The value to store in the object
 */
void jwtJsonObjectSetWithString(JwtJsonObject* object, JwtString key,
                                JwtJsonElement value);

/**
 * @brief Associates the given value with the given key within the given JSON
 * object
 * @param object The object to modify
 * @param key The value's new key
 * @param value The value to store in the object
 */
inline void jwtJsonObjectSet(JwtJsonObject* object, const char* key,
                             JwtJsonElement value) {
    jwtJsonObjectSetWithString(object, jwtStringCreate(key), value);
}

/**
 * @brief Associates the given string with the given key within the given JSON
 * object
 * @param object The object to modify
 * @param key The value's new key
 * @param value The value to store in the object
 */
inline void jwtJsonObjectSetString(JwtJsonObject* object, const char* key,
                                   const char* value) {
    jwtJsonObjectSet(object, key,
                     {.type = JWT_JSON_ELEMENT_TYPE_STRING,
                      .string = jwtStringCreate(value)});
}
/**
 * @brief Associates the given signed integer with the given key within the
 * given JSON object
 * @param object The object to modify
 * @param key The value's new key
 * @param value The value to store in the object
 */
inline void jwtJsonObjectSetInt(JwtJsonObject* object, const char* key,
                                int64_t value) {
    jwtJsonObjectSet(
        object, key,
        {.type = JWT_JSON_ELEMENT_TYPE_NUMERIC,
         .number = {.i64 = value, .type = JWT_NUMBER_TYPE_SIGNED}});
}

/**
 * @brief Associates the given unsigned integer with the given key within the
 * given JSON object
 * @param object The object to modify
 * @param key The value's new key
 * @param value The value to store in the object
 */
inline void jwtJsonObjectSetUint(JwtJsonObject* object, const char* key,
                                 uint64_t value) {
    jwtJsonObjectSet(
        object, key,
        {.type = JWT_JSON_ELEMENT_TYPE_NUMERIC,
         .number = {.u64 = value, .type = JWT_NUMBER_TYPE_UNSIGNED}});
}

/**
 * @brief Associates the given double with the given key within the given JSON
 * object
 * @param object The object to modify
 * @param key The value's new key
 * @param value The value to store in the object
 */
inline void jwtJsonObjectSetDouble(JwtJsonObject* object, const char* key,
                                   double value) {
    jwtJsonObjectSet(object, key,
                     {.type = JWT_JSON_ELEMENT_TYPE_NUMERIC,
                      .number = {.f64 = value, .type = JWT_NUMBER_TYPE_FLOAT}});
}

/**
 * @brief Associates the given boolean with the given key within the given JSON
 * object
 * @param object The object to modify
 * @param key The value's new key
 * @param value The value to store in the object
 */
inline void jwtJsonObjectSetBool(JwtJsonObject* object, const char* key,
                                 bool value) {
    jwtJsonObjectSet(object, key,
                     {.type = JWT_JSON_ELEMENT_TYPE_BOOLEAN, .boolean = value});
}

/**
 * @brief Associates the given array with the given key within the given JSON
 * object
 * @param object The object to modify
 * @param key The value's new key
 * @param value The value to store in the object
 */
inline void jwtJsonObjectSetArray(JwtJsonObject* object, const char* key,
                                  JwtJsonArray value) {
    jwtJsonObjectSet(object, key,
                     {.type = JWT_JSON_ELEMENT_TYPE_ARRAY, .array = value});
}

/**
 * @brief Associates the given object with the given key within the given JSON
 * object
 * @param object The object to modify
 * @param key The value's new key
 * @param value The value to store in the object
 */
inline void jwtJsonObjectSetObject(JwtJsonObject* object, const char* key,
                                   JwtJsonObject value) {
    jwtJsonObjectSet(object, key,
                     {.type = JWT_JSON_ELEMENT_TYPE_OBJECT, .object = value});
}

/**
 * @brief Reindexes the backing hashtable of the given JSON object to use the
 * given number of buckets.
 * @param object The JSON object to reindex.
 * @param numBuckets The new number of buckets.
 */
inline void jwtJsonObjectReindex(JwtJsonObject* object, size_t numBuckets) {
    jwtHashTableReindex(object, numBuckets);
}

/**
 * @brief Removes the value associated with the given key from the given object.
 * @param object The object to modify.
 * @param key The key associated with the value to remove.
 */
void jwtJsonObjectRemove(JwtJsonObject* object, const char* key);

/**
 * @brief Removes the value associated with the given key from the given object,
 * but does not destroy it.
 * @param object The object to modify.
 * @param key The key associated with the value to remove.
 * @return The element removed from the object.
 */
JwtJsonElement jwtJsonElementReclaim(JwtJsonObject* object, const char* key);

/**
 * @brief Removes all values from the given JSON object.
 * @param object The object to modify.
 */
void jwtJsonObjectClear(JwtJsonObject* object);

/**
 * @brief Creates an iterator for the given JSON object.
 * @param object The object to iterate over.
 * @return A new JSON object iterator.
 */
inline JwtJsonObjectIterator
jwtJsonObjectIteratorCreate(JwtJsonObject* object) {
    return jwtHashTableIteratorCreate(object);
}

/**
 * @brief Advances the given iterator to the next value in its assocaited JSON
 * object.
 * @param iterator The iterator to advance.
 * @return The JSON object entry the iterator just advanced to.
 */
JwtJsonObjectEntry* jwtJsonObjectIteratorNext(JwtJsonObjectIterator* iterator);

/**
 * @brief Parses a JSON element from the given reader, and stores it in the
 * given struct.
 * @param outElement Where to store the parsed element.
 * @param reader The JSON reader
 * @return 0 if successful, or some value indicating an error code otherwise
 */
JwtJsonParseResult jwtReadJsonReader(JwtJsonElement* outElement,
                                     JwtReader reader);

/**
 * @brief Parses a JSON element from the given string, and stores it in the
 * given struct.
 * @param outElement Where to store the parsed element.
 * @param data The JSON string data
 * @param length The length of the JSON string
 * @return 0 if successful, or some value indicating an error code otherwise
 */
JwtJsonParseResult jwtReadJsonString(JwtJsonElement* outElement,
                                     const char* data, size_t length);

/**
 * @brief Writes a JSON element into the given writer.
 * @param element The element to write.
 * @param writer The writer to write to.
 * @return 0 on success, -1 on error
 */
int32_t jwtWriteJsonWriter(JwtJsonElement* element, JwtWriter writer);

/**
 * @brief Writes a JSON element into the given string.
 * @param element The element to write.
 * @param writer The string to create.
 * @return 0 on success, -1 on error
 */
int32_t jwtWriteJsonString(JwtJsonElement* element, JwtString* string);

#ifdef __cplusplus
}
#endif

#endif // JWT_JSON_H
