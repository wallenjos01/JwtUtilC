#pragma once

#include <cstdint>
#include <string>

/**
 * @brief Appends the given unicode code point, encoded in UTF-8, to the given
 * string.
 * @param str The string to modify.
 * @param codePoint The code point to add.
 */
void appendCodePoint(std::string& str, uint32_t codePoint);
