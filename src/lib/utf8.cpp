/**
 * Josh Wallentine
 * Created 9/12/25
 *
 * Implementation of src/lib/utf8.hpp
 */

#include "utf8.hpp"

namespace {

constexpr const uint8_t CONTINUE_VALUE = 0b10000000;
constexpr const uint8_t CONTINUE_MASK = 0b11000000;

constexpr const uint8_t ONE_LEN_VALUE = 0b00000000;
constexpr const uint8_t ONE_LEN_MASK = 0b10000000;
constexpr const uint32_t ONE_LEN_MAX = 127;

constexpr const uint8_t TWO_LEN_VALUE = 0b11000000;
constexpr const uint8_t TWO_LEN_MASK = 0b11100000;
constexpr const uint32_t TWO_LEN_MAX = 2047;

constexpr const uint8_t THREE_LEN_VALUE = 0b11100000;
constexpr const uint8_t THREE_LEN_MASK = 0b11110000;
constexpr const uint32_t THREE_LEN_MAX = 65535;

constexpr const uint8_t FOUR_LEN_VALUE = 0b11110000;
constexpr const uint8_t FOUR_LEN_MASK = 0b11111000;
constexpr const uint32_t FOUR_LEN_MAX = 2097151;

} // namespace

void appendCodePoint(std::string& str, uint32_t codePoint) {
    if (codePoint > FOUR_LEN_MAX) { // Invalid code point
        return;
    }

    if (codePoint <= ONE_LEN_MAX) {
        str.push_back(static_cast<char>(codePoint));
    } else if (codePoint <= TWO_LEN_MASK) {
        str.push_back((static_cast<char>(codePoint >> 6) & ~TWO_LEN_MASK) |
                      TWO_LEN_VALUE);
        str.push_back((static_cast<char>(codePoint) & ~CONTINUE_MASK) |
                      CONTINUE_VALUE);

    } else if (codePoint <= THREE_LEN_MASK) {
        str.push_back((static_cast<char>(codePoint >> 12) & ~THREE_LEN_MASK) |
                      THREE_LEN_VALUE);
        str.push_back((static_cast<char>(codePoint >> 6) & ~CONTINUE_MASK) |
                      CONTINUE_VALUE);
        str.push_back((static_cast<char>(codePoint) & ~CONTINUE_MASK) |
                      CONTINUE_VALUE);

    } else {
        str.push_back((static_cast<char>(codePoint >> 18) & ~FOUR_LEN_MASK) |
                      FOUR_LEN_VALUE);
        str.push_back((static_cast<char>(codePoint >> 12) & ~CONTINUE_MASK) |
                      CONTINUE_VALUE);
        str.push_back((static_cast<char>(codePoint >> 6) & ~CONTINUE_MASK) |
                      CONTINUE_VALUE);
        str.push_back((static_cast<char>(codePoint) & ~CONTINUE_MASK) |
                      CONTINUE_VALUE);
    }
}
