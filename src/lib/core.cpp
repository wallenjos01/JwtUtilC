/**
 * Josh Wallentine
 * Created 9/9/25
 * Modified 9/30/25
 *
 * Implementation of include/jwt/core.h
 */

#include <cassert>
#include <jwt/core.h>

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
    list->step = 0;
    list->size = 0;
    list->capacity = 0;
    if (list->head) {
        free(list->head);
    }
}

void* jwtListPush(JwtList* list) {
    if (list->size + 1 > list->capacity) {

        list->capacity = list->capacity == 0 ? 1 : list->capacity * 2;
        void* oldHead = list->head;

        if (list->head == nullptr ||
            (list->head = realloc(list->head, list->capacity * list->step)) ==
                nullptr) {

            list->head = malloc(list->capacity * list->step);
            if (list->head == nullptr) {
                return nullptr;
            }

            if (oldHead != nullptr) {
                memcpy(list->head, oldHead, list->size * list->step);
                free(list->head);
            }
        }
    }

    list->size++;
    return jwtListGet(list, list->size - 1);
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
