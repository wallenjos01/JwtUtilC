#pragma once
#include <jwt/core.h>

/**
 * @brief Computes a hash for the given string
 * @param data The string data to consider
 * @param length The length of the string data
 * @return A hash of the data
 */
constexpr size_t hashString(const char* data, size_t length) {
    size_t hash = 5381;
    for (auto i = 0; i < length; i++) {
        hash = ((hash << 5) + hash) + data[i];
    }
    return hash;
}

consteval size_t hashCString(const char* data) {

    size_t i = 0;
    while (data[i] != 0) {
        i++;
    }

    return hashString(data, i);
}
