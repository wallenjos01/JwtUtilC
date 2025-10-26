/**
 * Josh Wallentine
 * Created 9/9/25
 * Modified 9/30/25
 *
 * Implementation of include/jwt/core.h
 */

#include <cassert>
#include <jwt/core.h>

namespace {} // namespace

JwtString jwtStringCreateSized(const char* str, size_t len) {

    char* data = new char[len + 1];

    memcpy(data, str, len);
    data[len] = 0;
    return {.length = len, .data = data};
}

void jwtStringDestroy(JwtString* str) {
    if (str->data) {
        delete[] str->data;
        str->data = nullptr;
    }
    str->length = 0;
}

int64_t jwtNumericAsInt(JwtNumeric number) {
    switch (number.type) {
    case JWT_NUMBER_TYPE_SIGNED:
    case JWT_NUMBER_TYPE_UNSIGNED:
        return number.i64;
    case JWT_NUMBER_TYPE_FLOAT:
        return static_cast<int64_t>(number.f64);
    }
    return 0;
}
uint64_t jwtNumericAsUint(JwtNumeric number) {
    switch (number.type) {
    case JWT_NUMBER_TYPE_SIGNED:
        return static_cast<uint64_t>(number.i64);
    case JWT_NUMBER_TYPE_UNSIGNED:
        return number.u64;
    case JWT_NUMBER_TYPE_FLOAT:
        return static_cast<uint64_t>(number.f64);
    }
    return 0;
}
double jwtNumericAsDouble(JwtNumeric number) {
    switch (number.type) {
    case JWT_NUMBER_TYPE_SIGNED:
        return static_cast<double>(number.i64);
    case JWT_NUMBER_TYPE_UNSIGNED:
        return static_cast<double>(number.u64);
    case JWT_NUMBER_TYPE_FLOAT:
        return number.f64;
    }
    return 0;
}

void jwtListCreate(JwtList* list, size_t step) {
    list->step = step;
    list->size = 0;
    list->capacity = 0;
    list->head = nullptr;
}

void jwtListDestroy(JwtList* list) {

    list->size = 0;
    list->capacity = 0;
    if (list->head) {
        free(list->head);
        list->head = nullptr;
    }
}

void* jwtListPush(JwtList* list) {
    return jwtListPushN(list, 1);
}

void* jwtListPushN(JwtList* list, size_t n) {
    if(list->step == 0) return nullptr;
    if (list->size + n > list->capacity) {

        size_t newCapacity = (list->capacity + n) + (list->capacity * 1.5);
        if(newCapacity < list->capacity 
            || newCapacity < list->size + n 
            || newCapacity > SIZE_MAX / list->step) {
            return nullptr;
        }
        
        list->capacity = newCapacity;
        list->head = realloc(list->head, list->capacity * list->step);
    }

    list->size += n;
    return jwtListGet(list, list->size - n);
}

void* jwtListGet(const JwtList* list, size_t index) {

    if (index >= list->size) {
        return nullptr;
    }
    return static_cast<char*>(list->head) + (index * list->step);
}

void jwtListPop(JwtList* list) { list->size--; }

void jwtListRemove(JwtList* list, size_t index) {
    if (index >= list->size) {
        return;
    }

    if (index < list->size - 1) {
        void* removedStart = jwtListGet(list, index);
        void* removedEnd = static_cast<char*>(removedStart) + list->step;
        size_t numElements = list->size - index - 1;
        memmove(removedStart, removedEnd, numElements * list->step);
    }
    list->size--;
}

void* jwtListReclaim(JwtList* list) {
    void* out = list->head;
    list->size = 0;
    list->capacity = 0;
    list->head = nullptr;
    return out;
}

void jwtHashTableCreate(JwtHashTable* table, JwtHashFunctions* functions) {
    table->size = 0;
    table->functions = functions;
    table->numBuckets = 0;
    table->buckets = nullptr;
}

void jwtHashTableCreateSized(JwtHashTable* table, JwtHashFunctions* functions,
                             size_t numBuckets) {
    table->size = 0;
    table->functions = functions;
    table->numBuckets = numBuckets;
    table->buckets =
        static_cast<JwtHashTableEntry**>(malloc(sizeof(void*) * numBuckets));
}

void jwtHashTableDestroy(JwtHashTable* table) {

    JwtHashTableEntry** buckets =
        static_cast<JwtHashTableEntry**>(table->buckets);
    for (auto i = 0; i < table->numBuckets; i++) {

        JwtHashTableEntry* current = buckets[i];
        while (current != nullptr) {

            JwtHashTableEntry* working = current;
            current = current->next;

            free(working->data);
            free(working);
        }
    }

    table->size = 0;
    table->numBuckets = 0;
    if (table->buckets) {
        free(table->buckets);
        table->buckets = nullptr;
    }
}

void* jwtHashTablePut(JwtHashTable* table, void* key) {

    if ((table->size + 1) * 1.2 >= table->numBuckets) {

        size_t targetBuckets =
            table->numBuckets == 0 ? 1 : table->numBuckets * 2;
        jwtHashTableReindex(table, targetBuckets);
    }

    size_t hash = table->functions->pfnHashKey(key);
    size_t bucketIndex = hash % table->numBuckets;

    JwtHashTableEntry** buckets =
        static_cast<JwtHashTableEntry**>(table->buckets);
    JwtHashTableEntry* current = buckets[bucketIndex];
    while (current != nullptr) {
        void* data = current->data;
        if (table->functions->pfnCompareKey(key, data) == 0) {
            return data;
        }
        current = current->next;
    }

    JwtHashTableEntry* newEntry =
        static_cast<JwtHashTableEntry*>(malloc(sizeof(JwtHashTableEntry)));
    newEntry->next = buckets[bucketIndex];
    newEntry->hash = hash;
    newEntry->data = malloc(table->functions->entrySize);
    memset(newEntry->data, 0, table->functions->entrySize);

    buckets[bucketIndex] = newEntry;

    table->size++;
    return newEntry->data;
}

void* jwtHashTableGet(JwtHashTable* table, void* key) {

    size_t hash = table->functions->pfnHashKey(key);
    size_t bucketIndex = hash % table->numBuckets;

    JwtHashTableEntry** buckets =
        static_cast<JwtHashTableEntry**>(table->buckets);
    JwtHashTableEntry* current = buckets[bucketIndex];
    while (current != nullptr) {
        if (table->functions->pfnCompareKey(key, current->data) == 0) {
            return current->data;
        }
        current = current->next;
    }

    return nullptr;
}

void jwtHashTableRemove(JwtHashTable* table, void* key) {

    void* entryData = jwtHashTableReclaim(table, key);
    free(entryData);
}

void* jwtHashTableReclaim(JwtHashTable* table, void* key) {

    size_t hash = table->functions->pfnHashKey(key);
    size_t bucketIndex = hash % table->numBuckets;
    JwtHashTableEntry** buckets =
        static_cast<JwtHashTableEntry**>(table->buckets);

    JwtHashTableEntry* current = buckets[bucketIndex];
    JwtHashTableEntry* prev = nullptr;

    while (current != nullptr) {
        if (table->functions->pfnCompareKey(key, current->data) == 0) {
            if (prev == nullptr) {
                buckets[bucketIndex] = current->next;
            } else {
                prev->next = current->next;
            }

            table->size--;
            void* out = current->data;
            free(current);
            return out;
        }
        prev = current;
        current = current->next;
    }

    return nullptr;
}

void jwtHashTableReindex(JwtHashTable* table, size_t targetBuckets) {
    JwtHashTableEntry** buckets =
        static_cast<JwtHashTableEntry**>(table->buckets);
    JwtHashTableEntry** newBuckets = nullptr;

    if (targetBuckets > 0) {
        newBuckets = static_cast<JwtHashTableEntry**>(
            malloc(targetBuckets * sizeof(void*)));
        memset(newBuckets, 0, targetBuckets * sizeof(void*));

        for (auto i = 0; i < table->numBuckets; i++) {

            JwtHashTableEntry* current = buckets[i];
            while (current != nullptr) {

                JwtHashTableEntry* working = current;
                current = current->next;

                size_t hash = working->hash;
                size_t bucketIndex = hash % targetBuckets;

                working->next = newBuckets[bucketIndex];
                newBuckets[bucketIndex] = working;
            }
        }
    }

    table->buckets = newBuckets;
    table->numBuckets = targetBuckets;
    if (buckets)
        free(buckets);
}

JwtHashTableIterator jwtHashTableIteratorCreate(JwtHashTable* table) {
    return {.table = table,
            .current = nullptr,
            .prev = nullptr,
            .bucketIndex = static_cast<size_t>(-1)};
}

void jwtHashTableIteratorNext(JwtHashTableIterator* it) {
    if (it->current != nullptr) {
        it->prev = it->current;
        it->current = it->current->next;
    }

    while (it->current == nullptr) {
        if (it->bucketIndex + 1 == it->table->numBuckets) {
            break;
        }
        it->bucketIndex++;
        it->current = it->table->buckets[it->bucketIndex];
        it->prev = nullptr;
    }
}

void jwtHashTableIteratorRemove(JwtHashTableIterator* it) {
    void* data = jwtHashTableIteratorReclaim(it);
    free(data);
}

void* jwtHashTableIteratorReclaim(JwtHashTableIterator* it) {

    if (it->current == nullptr) {
        return nullptr;
    }

    JwtHashTableIterator copy = *it;
    jwtHashTableIteratorNext(it);
    it->prev = nullptr;

    if (copy.prev == nullptr) {
        copy.table->buckets[copy.bucketIndex] = copy.current->next;
    } else {
        copy.prev->next = copy.current->next;
    }

    copy.table->size--;
    void* out = copy.current->data;

    free(copy.current);

    return out;
}
