#ifndef JWT_CORE_H
#define JWT_CORE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/**
 * Represents a heap-allocated string
 */
typedef struct JwtString {
    size_t length;
    const char* data;
} JwtString;

/**
 * @brief Creates a new string by copying the given character array onto the
 * heap.
 * @param str The string data.
 * @param length The string length.
 * @return A new string.
 */
JwtString jwtStringCreateSized(const char* str, size_t length);

/**
 * @brief Creates a new string by copying the given character array onto the
 * heap.
 * @param str The string data. Must be null-terminated.
 * @return A new string.
 */
inline JwtString jwtStringCreate(const char* str) {
    return jwtStringCreateSized(str, strlen(str));
}

/**
 * @brief Destroys a heap-allocated string.
 * @param str The string to destroy.
 */
void jwtStringDestroy(JwtString* str);

/**
 * Enumerates the types of numbers parseable from JSON by this library
 */
enum JwtNumberType {
    JWT_NUMBER_TYPE_SIGNED,
    JWT_NUMBER_TYPE_UNSIGNED,
    JWT_NUMBER_TYPE_FLOAT
};

/**
 * Represents a number parsed from JSON
 */
typedef struct JwtNumeric {
    union {
        int64_t i64;
        uint64_t u64;
        double f64;
    };
    JwtNumberType type;
} JwtNumeric;

/**
 * @brief If the given number is a signed integer it is returned, otherwise the
 * underlying data is cast to a signed integer.
 * @param number The number to lookup.
 */
int64_t jwtNumericAsInt(JwtNumeric number);

/**
 * @brief If the given number is an unsigned integer it is returned, otherwise
 * the underlying data is cast to a unsigned integer.
 * @param number The number to lookup.
 */
uint64_t jwtNumericAsUint(JwtNumeric number);

/**
 * @brief If the given number is a float it is returned, otherwise the
 * underlying data is cast to a float.
 * @param number The number to lookup.
 */
double jwtNumericAsDouble(JwtNumeric number);

/**
 * Represents a dynamic array.
 */
typedef struct JwtList {
    void* head;
    size_t size;
    size_t capacity;
    size_t step;
} JwtList;

/**
 * @brief Creates a new list.
 * @param list A pointer to the memory to store the newly created list.
 * @param step The size of each item in the list
 */
void jwtListCreate(JwtList* list, size_t step);

/**
 * @brief Destroys a list
 * @param list A pointer to the list to destroy
 */
void jwtListDestroy(JwtList* list);

/**
 * @brief Pushes a new item onto the list.
 * @param list A pointer to the list to expand.
 * @return A pointer to the newly accessible memory.
 */
void* jwtListPush(JwtList* list);

/**
 * @brief Gets the item at the given index of the list.
 * @param list A pointer to the list to query.
 * @param index The index to get at.
 */
void* jwtListGet(const JwtList* list, size_t index);

/**
 * @brief Removes the last item from the list.
 * @param list The list to pop from.
 */
void jwtListPop(JwtList* list);

/**
 * @brief Removes a particular item from the list.
 * @param list The list to pop from.
 * @param index The index of the item to remove.
 */
void jwtListRemove(JwtList* list, size_t index);

#ifdef __cplusplus
}
#endif

#endif // JWT_CORE_H
