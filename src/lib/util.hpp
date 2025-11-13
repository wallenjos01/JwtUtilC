#pragma once

#include "jwt/core.h"
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <openssl/core.h>
#include <string>

#ifdef NDEBUG
#define JWT_REPORT_ERROR(error)

#else
#define JWT_REPORT_ERROR(error) \
    std::cerr << error << " @" << __FILE__ << ":" << __LINE__ << "\n";
#endif

template <typename T> struct Span {
    T* data;
    size_t length;
    bool owned;

    Span() : data(nullptr), length(0), owned(false) {}
    Span(T* data, size_t length) : data(data), length(length), owned(false) {}

    Span(const Span& other) : data(other.data), length(other.length), owned(false) {}
    Span(Span&& other) : data(other.data), length(other.length), owned(other.owned) {
        other.data = nullptr;
        other.length = 0;
        other.owned = false;
    }

    ~Span() {
        if (owned && data) {
            delete[] data;
        }
        data = nullptr;
        length = 0;
    }

    Span& operator=(const Span& other) {
        if(&other == this) return *this;
        this->~Span();
        
        data = other.data;
        length = other.length;
        owned = false;

        return *this;
    }

    Span& operator=(Span&& other) {
        if(&other == this) return *this;
        this->~Span();

        data = other.data;
        length = other.length;
        owned = other.owned;
        
        other.data = nullptr;
        other.length = 0;
        other.owned = false;
        return *this;
    }

    T& operator[](size_t index) { return data[index]; }
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

inline void printOsslParams(OSSL_PARAM* param) {
    while(param->key != nullptr) {
        std::cout << param->key << ": ";
        switch(param->data_type) {
            case OSSL_PARAM_INTEGER:
                std::cout << *static_cast<int*>(param->data);
                break;
            case OSSL_PARAM_UNSIGNED_INTEGER:
                std::cout << *static_cast<unsigned int*>(param->data);
                break;
            case OSSL_PARAM_REAL:
                std::cout << *static_cast<float*>(param->data);
                break;
            case OSSL_PARAM_UTF8_STRING:
                std::cout << static_cast<char*>(param->data);
                break;
            case OSSL_PARAM_OCTET_STRING:
                for(auto i = 0 ; i < param->data_size ; i++) {
                    unsigned char b = static_cast<unsigned char*>(param->data)[i];
                    std::cout << std::hex << (int) b;
                }
                break;
            case OSSL_PARAM_UTF8_PTR:
                std::cout << *static_cast<char**>(param->data);
                break;
            case OSSL_PARAM_OCTET_PTR:
                for(auto i = 0 ; i < param->data_size ; i++) {
                    unsigned char b = *static_cast<unsigned char**>(param->data)[i];
                    std::cout << std::hex << (int) b;
                }
                break;
        }
        std::cout << "\n";
        param++;
    }
}

inline int32_t firstIndexOf(JwtString str, char c, size_t* index) {
    for(auto i = 0 ; i < str.length ; i++) {
        if(str.data[i] == c) {
            *index = i;
            return 0;
        }
    }
    return -1;
}

inline int32_t nextIndexOf(JwtString str, char c, size_t startIndex, size_t* index) {
    for(auto i = startIndex ; i < str.length ; i++) {
        if(str.data[i] == c) {
            *index = i;
            return 0;
        }
    }
    return -1;
}

inline int32_t lastIndexOf(JwtString str, char c, size_t* index) {
    for(auto i = str.length - 1; i >= 0 ; i--) {
        if(str.data[i] == c) {
            *index = i;
            return 0;
        }
    }
    return -1;
}
