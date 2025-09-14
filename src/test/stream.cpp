#include <gtest/gtest.h>

#include <jwt/stream.h>

TEST(Stream, BufferWriter) {

    char buffer[1024] = {};
    JwtWriter writer = {};

    ASSERT_EQ(0, jwtWriterCreateForBuffer(&writer, buffer, 1024));

    jwtWriterWrite(writer, "Hello, World", 12, nullptr);

    ASSERT_EQ(0, memcmp("Hello, World", buffer, 12));
}

TEST(Stream, BufferReader) {

    char buffer[1024] = {};
    memcpy(buffer, "Hello, World", 12);

    JwtReader reader = {};
    ASSERT_EQ(0, jwtReaderCreateForBuffer(&reader, buffer, 1024));

    char readBuffer[1024] = {};

    size_t bytesRead = 0;
    while (bytesRead < 1024) {
        size_t justRead;
        jwtReaderRead(reader, readBuffer, 1024 - bytesRead, &justRead);
        bytesRead += justRead;
    }

    ASSERT_EQ(0, memcmp(readBuffer, buffer, 1024));
}
