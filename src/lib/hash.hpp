#pragma once
#include <jwt/core.h>

/**
 * @brief Computes a hash for the given string
 * @param data The string data to consider
 * @param length The length of the string data
 * @return A hash of the data
 */
constexpr uint32_t hashString(const char* data, size_t length) {
    uint32_t hash = 5381;
    for (auto i = 0; i < length; i++) {
        hash = ((hash << 5) + hash) + data[i];
    }
    return hash;
}
