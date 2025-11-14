#include "../lib/algorithm.hpp"
#include "jwt/json.h"
#include "jwt/stream.h"

#include <gtest/gtest.h>

TEST(Base64Url, Basic) {

    const char* message = "Hello, World";
    size_t len = strlen(message);

    size_t encLen = jwt::b64url::getEncodedLength(len);
    char* encoded = new char[encLen + 1];
    encoded[encLen] = '\0';
    JwtWriter encodeWriter;
    jwtWriterCreateForBuffer(&encodeWriter, encoded, encLen);

    jwt::b64url::encode(reinterpret_cast<const uint8_t*>(message), len, encodeWriter);

    ASSERT_STREQ(encoded, "SGVsbG8sIFdvcmxk");

    uint8_t* decoded = new uint8_t[len];
    JwtWriter decodeWriter;
    jwtWriterCreateForBuffer(&decodeWriter, decoded, len);
    jwt::b64url::decode(encoded, encLen, decodeWriter);

    ASSERT_STREQ(message, reinterpret_cast<char*>(decoded));

    delete[] encoded;
    delete[] decoded;
}

TEST(Base64Url, Decode) {

    const char* encoded = "dGVzdEtleQ";
    size_t encLen = strlen(encoded);

    size_t decLen = jwt::b64url::getDataLength(encLen);
    ASSERT_EQ(7, decLen);

    uint8_t* decoded = new uint8_t[decLen];
    JwtWriter decodeWriter;
    jwtWriterCreateForBuffer(&decodeWriter, decoded, decLen);

    jwt::b64url::decode(encoded, encLen, decodeWriter);

    ASSERT_STREQ("testKey", reinterpret_cast<char*>(decoded));
}

TEST(Base64Url, Long) {

    const char* encoded =
        "ALzgKcXE-Jx_3_"
        "QRxT0g8Ck6ro3TO8tFY0qE0rLYDxL9hCZykIMigp22kOyQJsvSjXLX21bgLrqjUnXjbV26"
        "2cTMHW37nhIfIuJceX-aDGGUMVl_G_WeXzFiUABl9xFLy9n_"
        "mnUq03FTPlc2juWwxo4k3uu8pOK5vR6aiDZ9CCEClKVsk2zUZhtjcrErdjUYKZ0EMEsGqH"
        "N-GOI4kwqV58i1XH2aZV_IZ2QS1oMaQrqEE3Nq65_"
        "lA40KOwM8dA9dNIFHrQrIhgaGmZWEvAxEBd-Ux0cCOVsC2qQU0aLwL8-Rki_"
        "A8amE0MN9X_zaem45cqn6eY--JHIZ1ZXpm_MdimM";

    size_t encLen = strlen(encoded);
    ASSERT_EQ(encLen, 343);

    size_t decLen = jwt::b64url::getDataLength(encLen);
    ASSERT_EQ(257, decLen);

    uint8_t* decoded = new uint8_t[decLen];
    JwtWriter decodeWriter;
    jwtWriterCreateForBuffer(&decodeWriter, decoded, decLen);

    jwt::b64url::decode(encoded, encLen, decodeWriter);
    std::string hex = toHex(decoded, decLen);

    ASSERT_STREQ(
        hex.c_str(),
        "00bce029c5c4f89c7fdff411c53d20f0293aae8dd33bcb45634a84d2b2d80f12fd8426"
        "72908322829db690ec9026cbd28d72d7db56e02ebaa35275e36d5dbad9c4cc1d6dfb9e"
        "121f22e25c797f9a0c619431597f1bf59e5f3162500065f7114bcbd9ff9a752ad37153"
        "3e57368ee5b0c68e24deebbca4e2b9bd1e9a88367d08210294a56c936cd4661b6372b1"
        "2b763518299d04304b06a8737e18e238930a95e7c8b55c7d9a655fc8676412d6831a42"
        "ba8413736aeb9fe5038d0a3b033c740f5d348147ad0ac8860686999584bc0c4405df94"
        "c74702395b02daa414d1a2f02fcf91922fc0f1a984d0c37d5ffcda7a6e3972a9fa798f"
        "be247219d595e99bf31d8a63");
}
