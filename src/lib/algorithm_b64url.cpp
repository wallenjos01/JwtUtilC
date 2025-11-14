/**
 * Josh Wallentine
 * Created 11/11/25
 * Modified 11/12/25
 *
 * Partial implementation of algorithm.hpp
 * See also algorithm.cpp, algorithm_crypt.cpp, algorithm_cek.cpp
*/

#include "algorithm.hpp"
#include "jwt/result.h"

#include <jwt/core.h>
#include <jwt/token.h>
#include <jwt/stream.h>

namespace {

constexpr char B64URL_LOOKUP[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

constexpr char B64URL_REVERSE_LOOKUP[256] = {
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  62, 0,  0,  52, 53, 54, 55, 56, 57, 58, 59, 60,
    61, 0,  0,  0,  0,  0,  0,  0,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10,
    11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 0,  0,  0,  0,
    63, 0,  26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
    43, 44, 45, 46, 47, 48, 49, 50, 51, 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,
};

}

JwtResult jwt::b64url::encode(const void *data, size_t dataLength, JwtWriter writer) {

    const uint8_t* dataBytes = static_cast<const uint8_t*>(data);

    size_t position = 0;
    while(dataLength - position >= 3) {

        uint32_t encodedChunk = 
            (dataBytes[position] << 16) |
            (dataBytes[position + 1] << 8) |
            (dataBytes[position + 2]);

        position += 3;

        uint8_t c1 = encodedChunk & 0x3F;
        uint8_t c2 = (encodedChunk >> 6) & 0x3F;
        uint8_t c3 = (encodedChunk >> 12) & 0x3F;
        uint8_t c4 = (encodedChunk >> 18) & 0x3F;

        char chunk[4] = { 
            B64URL_LOOKUP[c4], 
            B64URL_LOOKUP[c3], 
            B64URL_LOOKUP[c2], 
            B64URL_LOOKUP[c1] 
        };

        JWT_CHECK(jwtWriterWriteAll(writer, chunk, 4, nullptr));
    }

    size_t remaining = dataLength - position;
    if(remaining == 2) {

        uint32_t encodedChunk = 
            ((dataBytes[position] << 8) |
            (dataBytes[position + 1])) << 2;

        position += 2;

        uint8_t c1 = encodedChunk & 0x3F;
        uint8_t c2 = (encodedChunk >> 6) & 0x3F;
        uint8_t c3 = (encodedChunk >> 12) & 0x3F;

        char chunk[3] = {
            B64URL_LOOKUP[c3],
            B64URL_LOOKUP[c2],
            B64URL_LOOKUP[c1]
        };

        JWT_CHECK(jwtWriterWriteAll(writer, chunk, 3, nullptr));
    }
    else if(remaining == 1) {
        uint32_t encodedChunk = 
            (dataBytes[position]) << 4;

        position += 1;

        uint8_t c1 = encodedChunk & 0x3F;
        uint8_t c2 = (encodedChunk >> 6) & 0x3F;

        char chunk[2] = {
            B64URL_LOOKUP[c2],
            B64URL_LOOKUP[c1]
        };

        JWT_CHECK(jwtWriterWriteAll(writer, chunk, 2, nullptr));
    }

    return JWT_RESULT_SUCCESS;
}

JwtResult jwt::b64url::decode(const void *encoded, size_t encodedLength, JwtWriter writer) {

    const uint8_t* encodedBytes = static_cast<const uint8_t*>(encoded);

    size_t position = 0;

    while((encodedLength - position) >= 4) {

        uint8_t c1 = B64URL_REVERSE_LOOKUP[encodedBytes[position]];
        uint8_t c2 = B64URL_REVERSE_LOOKUP[encodedBytes[position + 1]];
        uint8_t c3 = B64URL_REVERSE_LOOKUP[encodedBytes[position + 2]];
        uint8_t c4 = B64URL_REVERSE_LOOKUP[encodedBytes[position + 3]];

        position += 4;

        uint32_t chunk = (c1 << 18) | (c2 << 12) | (c3 << 6) | c4;
        uint8_t data[3] = { 
            static_cast<uint8_t>((chunk >> 16) & 0xFF), 
            static_cast<uint8_t>((chunk >> 8) & 0xFF), 
            static_cast<uint8_t>(chunk & 0xFF) 
        };
        JWT_CHECK(jwtWriterWriteAll(writer, reinterpret_cast<char*>(data), 3, nullptr));
    }

    size_t remaining = encodedLength - position;
    if(remaining == 3) {
        uint8_t c1 = B64URL_REVERSE_LOOKUP[encodedBytes[position]];
        uint8_t c2 = B64URL_REVERSE_LOOKUP[encodedBytes[position + 1]];
        uint8_t c3 = B64URL_REVERSE_LOOKUP[encodedBytes[position + 2]];

        position += 3;

        uint32_t chunk = ((c1 << 12) | (c2 << 6) | c3) >> 2;
        uint8_t data[2] = { 
            static_cast<uint8_t>((chunk >> 8) & 0xFF), 
            static_cast<uint8_t>(chunk & 0xFF) 
        };
        JWT_CHECK(jwtWriterWriteAll(writer, reinterpret_cast<char*>(data), 2, nullptr));

    } else if(remaining == 2) {
        uint8_t c1 = B64URL_REVERSE_LOOKUP[encodedBytes[position]];
        uint8_t c2 = B64URL_REVERSE_LOOKUP[encodedBytes[position + 1]];

        position += 2;

        uint32_t chunk = ((c1 << 6) | c2) >> 4;
        uint8_t data = static_cast<uint8_t>(chunk & 0xFF);
        JWT_CHECK(jwtWriterWriteAll(writer, reinterpret_cast<char*>(&data), 1, nullptr));

    } else if(remaining == 1) {
        uint8_t c1 = B64URL_REVERSE_LOOKUP[encodedBytes[position]];
        position += 1;

        JWT_CHECK(jwtWriterWriteAll(writer, reinterpret_cast<char*>(&c1), 1, nullptr));
    }

    return JWT_RESULT_SUCCESS;
}

size_t jwt::b64url::getEncodedLength(size_t dataLength) {
    size_t chunks = dataLength / 3;
    size_t rem = dataLength % 3;
    return (4 * chunks) + ((rem > 0) * (rem + 1));
}

size_t jwt::b64url::getDataLength(size_t encodedLength) {
    if(encodedLength <= 1) return encodedLength;
    size_t chunks = encodedLength / 4;
    size_t rem = encodedLength % 4;
    return (chunks * 3) + ((rem > 0) * (rem - 1));
}

JwtResult jwt::b64url::encodeString(const void *data, size_t dataLength, JwtString *string) {

    size_t encodedLength = getEncodedLength(dataLength);

    char* stringData = new char[encodedLength + 1]{};
    string->data = stringData;
    string->length = encodedLength;

    JwtWriter writer = {};
    JWT_CHECK(jwtWriterCreateForBuffer(&writer, stringData, encodedLength));
    stringData[encodedLength] = 0;

    JwtResult result = encode(data, dataLength, writer);
    jwtWriterClose(&writer);

    return result;
}

JwtResult jwt::b64url::decodeNew(const void* encoded, size_t encodedLength, Span<uint8_t> *output) {

    if(encodedLength == 0 || encoded == nullptr) {
        return JWT_RESULT_ILLEGAL_ARGUMENT;
    }

    size_t decodedLength = getDataLength(encodedLength);
    output->data = new uint8_t[decodedLength];
    output->length = decodedLength;
    output->owned = true;

    JwtResult result = JWT_RESULT_SUCCESS;

    JwtWriter writer = {};
    JWT_CHECK(jwtWriterCreateForBuffer(&writer, output->data, output->length));

    result = decode(encoded, encodedLength, writer);

cleanup:

    jwtWriterClose(&writer);
    return result;
}
