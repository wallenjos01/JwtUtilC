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

TEST(RSA, ParseAndSign) {
    const char* keyJson =
        "{\"kty\":\"RSA\",\"n\":"
        "\"3i6VGquNawmlVBB1X8SqpY4YBWFhC9ejEViQHXoA8S5Nk2bOt0ehX5oAdPInupdRowN6"
        "67Ii4BZNcwHfxf4XsQ9EB65jJ7DzK2RadcV0rZZpvwCeTR_"
        "DfX1dP7KQnePAg6PcNQDthaFn9oM6czE-clQFg2MJH_"
        "993rtETiMtNqLXpBGvzGzi0UxJDvWCbEpcIqFSlCYjjKXivrx3fphNShbZ4zss9oIFCmK0"
        "-SWuftTVM5Lmh0w_jt0eAHYwoFeRC2edNw0JMG_OoeorMD-tuKmbpn2A-I7ruKk_"
        "aoOQqm65QSxW_t94dYpfxgZBSYvzR3jLrq_lEuz_VQARQNdgTQ\",\"e\":\"AQAB\","
        "\"d\":\"Av3olxfZSygxmDyyf-wjiiAsNaJWjrTEJt8k7aiva4_-"
        "jm4TeYdW5nUp7Wk3XL1d5Y6N8K-Q5aiXOWW8kCt4QTOd7GaOQkIRPDPZPf2_"
        "MPk2ClLlTs-"
        "PL9jo0QtEBERFWuBxfis5h5OhVUH2Hwf6Ocrk2hySymID3WRzKoQxvysSxO4sSDqbOyKsi"
        "yMmSW9em-"
        "kx83EK5sftvAiDT21IqvHcfKhQx27zKkeX51rnpH63MtQqr6PNwHiYM33XIuEmGQyCNXUB"
        "uJNsOJJZiVuasxSUdXCLwEaFW1axeKyzytW5JLhpMhh_"
        "Zvk0RD3HOQ5l01ZpAPuPVbm5A37szqlysQ\",\"p\":\"8Mg-J9RjXMQr3-"
        "69IDrf9ZImYl12itqOjqjW20RtIfqpAGQBxD4XsY-64D7v8jfeUH9xEH3IBIL3OFC2BUB_"
        "sWwE21xNa7cUhCgROI84aoUcnCyfiNR8T2oeURzdMGmDmllizX872qdyauVrM5h9gcCBZA"
        "BqUitTGHe0Pmn0J5k\",\"q\":\"7DllPLhlWN93PTuTyEdFjAyMYi1ns29Gm5o_uh-"
        "ZOp5S5DmEH9Y6Sdb5AGZuTX5pC7mu0CWDPyxJfc-"
        "l4TGjFaqF7YWw6ghTqaAePya3ePVkOsrxyOir4dKpceUrPpfLXNrc2iPqivU5ZEkrF0_"
        "87Xhk0CR2gY_VceWU1kuSntU\",\"dp\":"
        "\"6A51KPne0XcXOfjjOX7Efe5fJAojx2sgXYmHmUd3TnpACupXcYTOXQjC-"
        "IBvzKffkQFiPJyc-wwlq5bN9n3VE2-htrBcxWVrVnsvLa2Kl862ZiXzk3IGZJtHoLEK1C-"
        "88DMZsCfhzbf34-I70Tw0KasYiQKFda_fpAMqKcT_1HE\",\"dq\":"
        "\"zqKmXCcxADz6ISYsb9VokMmpQ3hUbjG4ogScGkPp1c0I1Xs6iF7tPgo-"
        "ZoszkbYyTX9v28P0ux4Sa2tov0ScVCeGX-_"
        "CgfYmuQrHapaDh9uggY1lU0m0kSWl82t0GJzP17nb1zXzxPod6gvXFd1ycogOJ8S9pTgcj"
        "jU1rP8OksE\",\"qi\":"
        "\"yJcyXiqwsaK4ZMjMInUxJ5bFoXgjzAunesbq7l9qkt7mqMSQZSibVmHytHDMJ_"
        "OYoNz1djhGnIKOvLy09Vx1eMN9VdEbKlVbqa4p56aoiC3Vya03gyBdAkVx-"
        "vV1QJlQGDxQVCnQ6qATb4kAwvb7QsGirm0Fu2uEpLhGqIs4png\","
        "\"alg\":\"RS256\",\"use\":\"sig\"}";

    JwtJsonElement element = {};
    jwtReadJsonString(&element, keyJson, strlen(keyJson));

    JwtKey key = {};
    int32_t keyRes = jwtKeyParse(&key, jwtJsonElementAsObject(element));
    ASSERT_EQ(0, keyRes);

    const char* message = "Hello, World";
    uint8_t output[512] = {};
    size_t outputLength = 0;

    int32_t out = jwt::generateSignature(
        Span<uint8_t>(reinterpret_cast<uint8_t*>(const_cast<char*>(message)),
                      strlen(message)),
        &key, JWT_ALGORITHM_PS256, Span<uint8_t>(output, 512), &outputLength);

    ASSERT_EQ(0, out);

    jwtJsonElementDestroy(&element);
    jwtKeyDestroy(&key);
}

TEST(EC, ParseAndSign) {
    const char* keyJson =
        "{\"kty\":\"EC\","
        "\"crv\":\"P-256\","
        "\"x\":\"rrwq-1lwloY2pjJQE_oapmXKOEMkDSu59hU3ROE_1vo\","
        "\"y\":\"I1MuspBp4orW2uIhF3WGcShGr2xT8R59argUv4UbwLE\","
        "\"d\":\"KL78nYZ0H75mAjxj6Bu8rw6cB9aW7OehdvAXOM5TOUA\","  
        "\"use\":\"sig\","
        "\"kid\":\"1\"}";

    JwtJsonElement element = {};
    jwtReadJsonString(&element, keyJson, strlen(keyJson));

    JwtKey key = {};
    int32_t keyRes = jwtKeyParse(&key, jwtJsonElementAsObject(element));
    ASSERT_EQ(0, keyRes);

    const char* message = "Hello, World";
    uint8_t output[512] = {};
    size_t outputLength = 0;

    int32_t out = jwt::generateSignature(
        Span<uint8_t>(reinterpret_cast<uint8_t*>(const_cast<char*>(message)),
                      strlen(message)),
        &key, JWT_ALGORITHM_ES256, Span<uint8_t>(output, 512), &outputLength);

    ASSERT_EQ(0, out);

    jwtJsonElementDestroy(&element);
    jwtKeyDestroy(&key);
}
