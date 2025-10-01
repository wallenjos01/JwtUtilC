#ifndef JWT_CORE_H
#define JWT_CORE_H

#include <cstddef>
#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/**
 * Represents a string
 */
typedef struct JwtString {
    /**
     * @brief The number of bytes in the string.
     */
    size_t length;
    /**
     * @brief The string data.
     */
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
    /**
     * @brief The number data, in one of 3 different interpretations.
     */
    union {
        int64_t i64;
        uint64_t u64;
        double f64;
    };
    /**
     * @brief The type of number
     */
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
    /**
     * @brief A pointer to the start of the array's list.
     * This buffer's size will be capacity * step.
     */
    void* head;
    /**
     * @brief The number of elements in the list.
     */
    size_t size;
    /**
     * @brief The number of elements the buffer can hold.
     */
    size_t capacity;
    /**
     * @brief The size of each element in the list.
     */
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

/**
 * Dynamic-dispatch table for specializations of hash tables.
 * Defines the size of each entry, and logic for hashing/comparing keys.
 */
typedef struct JwtHashFunctions {
    /**
     * @brief The size (in bytes) of each entry in hash tables using this
     * struct.
     */
    size_t entrySize;

    /**
     * @brief A pointer to a function which hashes a key.
     * @param key Some key data.
     * @return The hash of the key.
     */
    size_t (*pfnHashKey)(void* key);

    /**
     * @brief A pointer to a function which compares a key to an entry.
     * @param key Some key data.
     * @param entry Some entry data.
     * @return 0 if identical, or some other value.
     */
    int32_t (*pfnCompareKey)(void* key, void* entry);
} JwtHashFunctions;

/**
 * Represents an entry in a hash table
 */
struct JwtHashTableEntry {
    /**
     * @brief A pointer to the next entry in the bucket. May be null
     */
    JwtHashTableEntry* next;

    /**
     * @brief The full hash of the key used to create this entry
     */
    size_t hash;

    /**
     * @brief The user-supplied data for this entry.
     */
    void* data;
};

/**
 * Represents a generic hashtable
 */
typedef struct JwtHashTable {
    /**
     * @brief The number of entries in the hash table
     */
    size_t size;

    /**
     * @brief The number of buckets in the hash table
     */
    size_t numBuckets;

    /**
     * @brief An array of pointers to entries. Will be numBuckets pointers long
     */
    JwtHashTableEntry** buckets;

    /**
     * @brief The specialization functions for this hash table.
     */
    JwtHashFunctions* functions;
} JwtMap;

/**
 * @brief Creates a hash table specialization with the given functions.
 * @param table The memory to store the newly created table.
 * @param functions The dynamic functions to use when manipulating the table.
 */
void jwtHashTableCreate(JwtHashTable* table, JwtHashFunctions* functions);

/**
 * @brief Creates a hash table specialization with the given functions and
 * initial bucket count.
 * @param table The memory to store the newly created table.
 * @param functions The dynamic functions to use when manipulating the table.
 * @param numBuckets The number of buckets to allocate.
 */
void jwtHashTableCreateSized(JwtHashTable* table, JwtHashFunctions* functions,
                             size_t numBuckets);
/**
 * @brief Destroys the given hash table.
 * @param table The hash table to destroy
 */
void jwtHashTableDestroy(JwtHashTable* table);

/**
 * @brief Inserts a new entry, or overwrites the existing entry associated with
 * the given key into the hashtable.
 * @param table The table to modify.
 * @param key The key to associate the new entry with. Should be of a type
 * recognizable by table->functions.
 * @return A buffer to store the new entry. This will be
 * table->functions->entrySize bytes large.
 */
void* jwtHashTablePut(JwtHashTable* table, void* key);

/**
 * @brief Gets the value associated with the given key in the table.
 * @param table The table to get from.
 * @param key The key to look up.
 * @return A buffer containing the entry.
 */
void* jwtHashTableGet(JwtHashTable* table, void* key);

/**
 * @brief Removes the value associated with the given key in the table.
 * @param table The table to remove from.
 * @param key The key to look up.
 * @return A buffer containing the entry which was just removed.
 */
void* jwtHashTableReclaim(JwtHashTable* table, void* key);

/**
 * @brief Removes and destroys the value associated with the given key in the
 * table.
 * @param table The table to remove from.
 * @param key The key to look up.
 */
void jwtHashTableRemove(JwtHashTable* table, void* key);

/**
 * @brief Reindexes the hash table so it has the given number of buckets.
 * @param table The table to reindex.
 * @param numBuckets The new number of buckets.
 */
void jwtHashTableReindex(JwtHashTable* table, size_t numBuckets);

/**
 * Utility struct for iterating over the entries in a hash table
 */
typedef struct JwtHashTableIterator {
    /**
     * @brief The table being iterated over
     */
    JwtHashTable* const table;

    /**
     * @brief The current entry.
     */
    JwtHashTableEntry* current;

    /**
     * @brief The previous entry in the current bucket.
     */
    JwtHashTableEntry* prev;

    /**
     * @brief The current bucket in the table being iterated over.
     */
    size_t bucketIndex;
} JwtHashTableIterator;

/**
 * @brief Creates a new hash table iterator for the given table.
 * @param table The table to create an iterator for.
 */
JwtHashTableIterator jwtHashTableIteratorCreate(JwtHashTable* table);

/**
 * @brief Advances the given iterator to the next entry in the table.
 * @param it The iterator to advance.
 */
void jwtHashTableIteratorNext(JwtHashTableIterator* it);

/**
 * @brief Removes the current entry from the table and frees it, then advances
 * it to the next entry in the table.
 * @param it The iterator to advance.
 */
void jwtHashTableIteratorRemove(JwtHashTableIterator* it);

/**
 * @brief Removes the current entry from the table, then advances it to the next
 * entry in the table.
 * @param it The iterator to advance.
 * @return The data for the entry which was just removed.
 */
void* jwtHashTableIteratorReclaim(JwtHashTableIterator* it);

#ifdef __cplusplus
}
#endif

#endif // JWT_CORE_H
