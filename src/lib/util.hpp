#pragma once

#include <cstdint>
#include <cstdlib>
#include <string>

#define CHECK(condition, ret)                                                  \
    if (condition != 0) {                                                      \
        return ret;                                                            \
    }

template <typename T> struct Span {
    T* data;
    size_t length;
    bool owned;

    Span() : data(nullptr), length(0), owned(false) {}
    Span(T* data, size_t length) : data(data), length(length), owned(false) {}

    T& operator[](size_t index) { return data[index]; }

    ~Span() {
        if (owned && data) {
            delete[] data;
        }
        data = nullptr;
        length = 0;
    }
};

inline char hexDigit(uint8_t nybble) {
    if (nybble < 10) {
        return '0' + nybble;
    }
    if (nybble < 16) {
        return 'a' + nybble - 10;
    }
    return 'x';
}

inline std::string toHex(const uint8_t* data, size_t length) {

    std::string out = "";
    for (auto i = 0; i < length; i++) {
        uint8_t byte = data[i];
        uint8_t n1 = byte >> 4;
        uint8_t n2 = byte & 0x0F;
        out += hexDigit(n1);
        out += hexDigit(n2);
    }

    return out;
}
