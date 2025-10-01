#include "../lib/crypto.hpp"

#include <gtest/gtest.h>

TEST(Base64Url, Basic) {

    const char* message = "Hello, World";
    size_t len = strlen(message);

    size_t encLen = jwt::b64url::getEncodedLength(len);
    char* encoded = new char[encLen + 1];
    encoded[encLen] = '\0';

    jwt::b64url::encode(message, len, encoded, encLen);

    ASSERT_STREQ(encoded, "SGVsbG8sIFdvcmxk");

    char* decoded = new char[len + 1];
    decoded[len] = '\0';

    jwt::b64url::decode(encoded, encLen, decoded, len);
    ASSERT_STREQ(message, decoded);

    delete[] encoded;
    delete[] decoded;
}
