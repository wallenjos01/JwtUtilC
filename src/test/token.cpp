#include "jwt/key.h"
#include "jwt/result.h"
#include <gtest/gtest.h>

#include <jwt/json.h>
#include <jwt/token.h>


constexpr const char* hmacKeyJson = "{\"kty\":\"oct\",\"k\":\"bXktcmVhbGx5LWNvb2wtc2VjcmV0LWtleS10aGF0LWlzLW92ZXItMjU2LWJpdHMtbG9uZwo\"}";

constexpr const char* rsaKeyJson = "{\"kty\": \"RSA\",\"n\": \"6-Z0tsZqaL1DF0oBaz_d1xmX0BNkAJoDlb-ay--kfpwZsBJyketrPiGOvTS0b0t6O1f5C0B0pyRBucsMG5LbC4Kbzk3p_oPOcHOwjnRJ-xuB7CRdFS71VEEuK2bHDk7gqCF6z-EcD-6T9k84t4qSg3yWeDygodH7RICcV0p4cWepxKITKsICULmidic-r6IcWFCkgc7CjTUiZxM72lOumjf8VoUQWXiZ72UPD08LygN0Z-bzlaBUDUsSLl691X5qYtAVeTgrNmDmT7TZN7-9a3qq8wNv2dLnqr1o1NtJjDJvCu5GfL-MNYmVV1SFYL8IWCBonIMA9y6nv-7ndMEaEQ\",\"e\": \"AQAB\",\"d\": \"I5eBxJHrPCJSHRFtZWEdd3bFEP_b9rtGDzH5iQt_JhsnRQmDf8ClTZqCjsmE78XTi2CakrgG4bD2ubGJAiAGLJZoK5hV1bDNVOofmV6yStC7qYVTBf8vxKaQ8LtxDReZjcR_Yx3zvfOhH2iUhhzCPlRt33ZGRiQIZS2CaSkzQui24vgqIPEIZSm5jyMAOgpowD7cbdk8num8FyDMCv-bm0t8UgWKLM9wWjORwM3Q-9gD_Mz_W7_qd6dKdYrF3hvlmeO8Cd2ZrT7JDDIRwwpBOkvzqoM7WoY8Se6MA_AEe0z-HHKcQIPZExoex0ZdlWRsRgx5XDfanTIgmvxFkn6IgQ\",\"p\": \"_cgjJyYqzyV-q7gvCc39TRybeCrIy8NtPzxeEcYJz0PWP4HzZcFRkBeaYl3EExoAYOsFoIJ97LG8PjfwsIKqwD6IsUv5DJwjuJjr5dGkGgkX5cqyVk-nxaK8EJxhWw-MniVh5Njdw71D4ODEMBw8UrMvVlX9yaIPcOZud5VjHKM\",\"q\": \"7fZOh_NRXazVGBDoEVVbAKqG3U4tdb-srUsZVAa7M_lolSC9rJrNotypOdYBz9eLx46qvozwiLcPMAF6mRtF5g5_KQCsYxXgo-b2keuYoMfykGG3reVCkXUVfQYKsosboW3QgXSn9J0Oj_lUjorhHO7dNASf9v6hV6Y3hDPEBbs\",\"dp\": \"87W2zGnCwprnQlDmGyxODDdktcmges15pDh8veTIlto2bVaGPzme8hk4kS4qlY1qv6fzB2lJNHyaocVmxps1Dtj-vASRbqKjSyrPnyvrw3ToFizJhkmIfCsDH5CNjb0o9NZBZFs-3DJtdQ9kWC9FXsXkt6xsw6111p3zh7NWMrE\",\"dq\": \"v5dWd0NCuadUEwJZtssAcDLcTwaIt4tR3lze0bZxt1ESES_BR12EP6JmZfiWkN883blSZAVaDNlG0yH9sZQx3R7C5yJxqX2N1qk40RfdVWZnODRVDR_PTwnz-SuKJWK3JmwiOnjQWbSyat0WZYYP5Zm0ZBNtMBKnmMhtXnXHV80\",\"qi\": \"dQ52omzYWpjz2thXU8KSO_6acJHmAwD7gM3j3YJp6l4wgOvEi2OHXDvgeiaSi3CsA15cXwKQB4qPzwh8JXoXs51CmDcDZU4D1tan24a6lUwGbanJEysKZCNont4Rtj01DzVj4Xzab_oldYMYt4rzqN6ru-QsikOy1Fr8-f_Aq_M\"}";


constexpr const char* ecKeyJson =
        "{\"kty\":\"EC\","
        "\"crv\":\"P-256\","
        "\"x\":\"rrwq-1lwloY2pjJQE_oapmXKOEMkDSu59hU3ROE_1vo\","
        "\"y\":\"I1MuspBp4orW2uIhF3WGcShGr2xT8R59argUv4UbwLE\","
        "\"d\":\"KL78nYZ0H75mAjxj6Bu8rw6cB9aW7OehdvAXOM5TOUA\","  
        "\"use\":\"sig\","
        "\"kid\":\"1\"}";

constexpr const char* aesKeyJson = "{\"kty\":\"oct\",\"k\":\"pkgQf7kLM97PkX8oG2meBN-AxUxVVLgBNErbmGJvedk\"}";

TEST(Token, GenerateUnprotected) {

    JwtJsonObject obj;
    jwtJsonObjectCreate(&obj);
    jwtJsonObjectSetInt(&obj, "test", 42);

    JwtString str;
    jwtCreateUnprotectedToken(&obj, &str);

    JwtParsedToken token = {};
    ASSERT_STREQ(str.data, "eyJ0eXAiOiJqd3QiLCJhbGciOiJub25lIn0.eyJ0ZXN0Ijo0Mn0.");
    ASSERT_EQ(JWT_RESULT_SUCCESS, jwtVerifyToken(str, nullptr, &token, JWT_VERIFY_FLAG_ALLOW_UNPROTECTED));

}

TEST(Token, GenerateHS256) {

    JwtJsonElement element;
    jwtReadJsonString(&element, hmacKeyJson, strlen(hmacKeyJson));

    JwtKey key;
    jwtKeyParse(&key, &element.object);

    JwtJsonObject obj;
    jwtJsonObjectCreate(&obj);
    jwtJsonObjectSetInt(&obj, "test", 42);

    JwtString mac;
    ASSERT_EQ(JWT_RESULT_SUCCESS, jwtCreateSignedToken(&obj, &key, JWT_ALGORITHM_HS256, &mac));

    ASSERT_STREQ(mac.data, "eyJ0eXAiOiJqd3QiLCJhbGciOiJIUzI1NiJ9.eyJ0ZXN0Ijo0Mn0.sawwoMaSsTQpYK7UOtmAXmD_NENPpofcb2MF2ZKN6vY");

    JwtParsedToken token = {};
    ASSERT_EQ(JWT_RESULT_SUCCESS, jwtVerifyToken(mac, &key, &token, 0));

}

TEST(Token, GenerateHS384) {

    JwtJsonElement element;
    jwtReadJsonString(&element, hmacKeyJson, strlen(hmacKeyJson));

    JwtKey key;
    jwtKeyParse(&key, &element.object);

    JwtJsonObject obj;
    jwtJsonObjectCreate(&obj);
    jwtJsonObjectSetInt(&obj, "test", 42);

    JwtString mac;
    ASSERT_EQ(JWT_RESULT_SUCCESS, jwtCreateSignedToken(&obj, &key, JWT_ALGORITHM_HS384, &mac));

    ASSERT_STREQ(mac.data, "eyJ0eXAiOiJqd3QiLCJhbGciOiJIUzM4NCJ9.eyJ0ZXN0Ijo0Mn0.XGh9V7_4aZhToibg7_O6STvudtGr24X0Y0vTPrN2iXgJXliSBi-5-1yr-0c9pgrP");

    JwtParsedToken token = {};
    ASSERT_EQ(JWT_RESULT_SUCCESS, jwtVerifyToken(mac, &key, &token, 0));
}

TEST(Token, GenerateHS512) {

    JwtJsonElement element;
    jwtReadJsonString(&element, hmacKeyJson, strlen(hmacKeyJson));

    JwtKey key;
    jwtKeyParse(&key, &element.object);

    JwtJsonObject obj;
    jwtJsonObjectCreate(&obj);
    jwtJsonObjectSetInt(&obj, "test", 42);

    JwtString mac;
    ASSERT_EQ(JWT_RESULT_SUCCESS, jwtCreateSignedToken(&obj, &key, JWT_ALGORITHM_HS512, &mac));

    ASSERT_STREQ(mac.data, "eyJ0eXAiOiJqd3QiLCJhbGciOiJIUzUxMiJ9.eyJ0ZXN0Ijo0Mn0.mHUKFz9gO_AAsegJVOwwDSa1U2GDCWMMjHgWjElbHPR0sTg5NKot42h-wWu2_g07sHxcbSTtHP3A4N5BDx3B-g");

    JwtParsedToken token = {};
    ASSERT_EQ(JWT_RESULT_SUCCESS, jwtVerifyToken(mac, &key, &token, 0));
}


TEST(Token, GenerateRS256) {


    JwtJsonElement element = {};
    jwtReadJsonString(&element, rsaKeyJson, strlen(rsaKeyJson));

    JwtKey key = {};
    jwtKeyParse(&key, &element.object);

    JwtJsonObject obj = {};
    jwtJsonObjectCreate(&obj);
    jwtJsonObjectSetInt(&obj, "test", 42);

    JwtString sig = {};
    ASSERT_EQ(JWT_RESULT_SUCCESS, jwtCreateSignedToken(&obj, &key, JWT_ALGORITHM_RS256, &sig));

    ASSERT_STREQ(sig.data, "eyJ0eXAiOiJqd3QiLCJhbGciOiJSUzI1NiJ9.eyJ0ZXN0Ijo0Mn0.GE2qm99AkxEEC6izSbqc-U6Zfi2XsTGKtyX63yabcM-j8-QYLRSYEuaquIxZYvZiCuP5wXtUKJl9Qjz2RDr2AFigLc8kMP70Wl8w8JDkychEmAZe7LxkW6AHPufxG7TqjT_3btM0zzui15T0iFzsSOZYgu96IzJRUBzykwIat4SzL5gUYYCH5kkAXWAmlB0k8NkzU2P2QOCrzSnf_H1pfkpCKS5HO0jewdBA5KmPsq4SPhZ8VmLx0Fqba-_MBzcsDn0MK9tZx7TbkSbeITGkZqUEznBJsXx5xuS5QEmTlzLEvttGUceZ0W36ITF-ZlMZdPalQQi6xuPDV87pUMtGRA");

    JwtParsedToken token = {};
    ASSERT_EQ(JWT_RESULT_SUCCESS, jwtVerifyToken(sig, &key, &token, 0));
}

TEST(Token, GenerateRS384) {


    JwtJsonElement element = {};
    jwtReadJsonString(&element, rsaKeyJson, strlen(rsaKeyJson));

    JwtKey key = {};
    jwtKeyParse(&key, &element.object);

    JwtJsonObject obj = {};
    jwtJsonObjectCreate(&obj);
    jwtJsonObjectSetInt(&obj, "test", 42);

    JwtString sig = {};
    ASSERT_EQ(JWT_RESULT_SUCCESS, jwtCreateSignedToken(&obj, &key, JWT_ALGORITHM_RS384, &sig));

    ASSERT_STREQ(sig.data, "eyJ0eXAiOiJqd3QiLCJhbGciOiJSUzM4NCJ9.eyJ0ZXN0Ijo0Mn0.Hufrn6ZtMdTc0kNiN_r7a-8ubSnr8KiMSEtbP6m3Ws8yHyqK3dy51YfwMJPFvao8xb1NYAAePAxm-iMMu_bsYAEuesdXd8jJceytNCQP6Norgm6uZFa65slOCZoBZrhjLzspFeqY_WWZqxscpHASTNpxXNrvOgHmMvqb0bt7YxGtq9pdDhiWxFILVxn1UlN7tQ_bY-XthYHXujXRJfEJCVr-bX6FEuhumMVE4CNhgWh-3qDHMvZ9yE1uTQcd-XuzuvBRSjaQ7TMGW27ryTfapIYfQ9W3RnNXl1fd41ChpDP4aeXSIdFaZF5GnuLgBd3D4UiWZWPJdxpG7uj10UxA3w");

    JwtParsedToken token = {};
    ASSERT_EQ(JWT_RESULT_SUCCESS, jwtVerifyToken(sig, &key, &token, 0));
}

TEST(Token, GenerateRS512) {


    JwtJsonElement element = {};
    jwtReadJsonString(&element, rsaKeyJson, strlen(rsaKeyJson));

    JwtKey key = {};
    jwtKeyParse(&key, &element.object);

    JwtJsonObject obj = {};
    jwtJsonObjectCreate(&obj);
    jwtJsonObjectSetInt(&obj, "test", 42);

    JwtString sig = {};
    ASSERT_EQ(JWT_RESULT_SUCCESS, jwtCreateSignedToken(&obj, &key, JWT_ALGORITHM_RS512, &sig));

    ASSERT_STREQ(sig.data, "eyJ0eXAiOiJqd3QiLCJhbGciOiJSUzUxMiJ9.eyJ0ZXN0Ijo0Mn0.0pJDE94ny_bB_yHIXPqpUpKz4eyNgmLTgGEGwRZoh8WnITotYX7sbfmpSGHdiWpVDHQPKx7upX0mYHMz-hnn-orkG5jNYf__9MkkZHHkSCfPyl8U9zZdQzkSoo2hRaYUt0cWIoFgKo-zx3SQd3doLLDFg0G3VW7pQBvzX540nvzvNYeMuzE-vZgthkwdXb0_QCd6EnFMo8dMHK_EyxUbhF3vzF6ULhQKSMR8tS2sIgjpNEK30ZmuD9OHuLYUlqdy3vUKGt9eHZexoB4N5fHhPxF6gptGwQV_a-4l4-OmqSaHI6CDgA1tXCplOD-LRb1rcnfSWjoqfzxgDAP53ASbyg");

    JwtParsedToken token = {};
    ASSERT_EQ(JWT_RESULT_SUCCESS, jwtVerifyToken(sig, &key, &token, 0));

}

TEST(Token, GeneratePS256) {

    JwtJsonElement element = {};
    jwtReadJsonString(&element, rsaKeyJson, strlen(rsaKeyJson));

    JwtKey key = {};
    jwtKeyParse(&key, &element.object);

    JwtJsonObject obj = {};
    jwtJsonObjectCreate(&obj);
    jwtJsonObjectSetInt(&obj, "test", 42);

    JwtString sig = {};
    ASSERT_EQ(JWT_RESULT_SUCCESS, jwtCreateSignedToken(&obj, &key, JWT_ALGORITHM_PS256, &sig));

    JwtParsedToken token = {};
    ASSERT_EQ(JWT_RESULT_SUCCESS, jwtVerifyToken(sig, &key, &token, 0));
}

TEST(Token, GeneratePS384) {


    JwtJsonElement element = {};
    jwtReadJsonString(&element, rsaKeyJson, strlen(rsaKeyJson));

    JwtKey key = {};
    jwtKeyParse(&key, &element.object);

    JwtJsonObject obj = {};
    jwtJsonObjectCreate(&obj);
    jwtJsonObjectSetInt(&obj, "test", 42);

    JwtString sig = {};
    ASSERT_EQ(JWT_RESULT_SUCCESS, jwtCreateSignedToken(&obj, &key, JWT_ALGORITHM_PS384, &sig));

    JwtParsedToken token = {};
    ASSERT_EQ(JWT_RESULT_SUCCESS, jwtVerifyToken(sig, &key, &token, 0));
}

TEST(Token, GeneratePS512) {


    JwtJsonElement element = {};
    jwtReadJsonString(&element, rsaKeyJson, strlen(rsaKeyJson));

    JwtKey key = {};
    jwtKeyParse(&key, &element.object);

    JwtJsonObject obj = {};
    jwtJsonObjectCreate(&obj);
    jwtJsonObjectSetInt(&obj, "test", 42);

    JwtString sig = {};
    ASSERT_EQ(JWT_RESULT_SUCCESS, jwtCreateSignedToken(&obj, &key, JWT_ALGORITHM_PS512, &sig));

    JwtParsedToken token = {};
    ASSERT_EQ(JWT_RESULT_SUCCESS, jwtVerifyToken(sig, &key, &token, 0));
}

TEST(Token, GenerateES256) {
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
    jwtKeyParse(&key, &element.object);

    JwtJsonObject obj = {};
    jwtJsonObjectCreate(&obj);
    jwtJsonObjectSetInt(&obj, "test", 42);

    JwtString sig = {};
    ASSERT_EQ(JWT_RESULT_SUCCESS, jwtCreateSignedToken(&obj, &key, JWT_ALGORITHM_ES256, &sig));

    JwtParsedToken token = {};
    ASSERT_EQ(JWT_RESULT_SUCCESS, jwtVerifyToken(sig, &key, &token, 0));
}

TEST(Token, GenerateES384) {

    JwtJsonElement element = {};
    jwtReadJsonString(&element, ecKeyJson, strlen(ecKeyJson));

    JwtKey key = {};
    jwtKeyParse(&key, &element.object);

    JwtJsonObject obj = {};
    jwtJsonObjectCreate(&obj);
    jwtJsonObjectSetInt(&obj, "test", 42);

    JwtString sig = {};
    ASSERT_EQ(JWT_RESULT_SUCCESS, jwtCreateSignedToken(&obj, &key, JWT_ALGORITHM_ES384, &sig));

    JwtParsedToken token = {};
    ASSERT_EQ(JWT_RESULT_SUCCESS, jwtVerifyToken(sig, &key, &token, 0));
}

TEST(Token, GenerateES512) {

    JwtJsonElement element = {};
    jwtReadJsonString(&element, ecKeyJson, strlen(ecKeyJson));

    JwtKey key = {};
    jwtKeyParse(&key, &element.object);

    JwtJsonObject obj = {};
    jwtJsonObjectCreate(&obj);
    jwtJsonObjectSetInt(&obj, "test", 42);

    JwtString sig = {};
    ASSERT_EQ(JWT_RESULT_SUCCESS, jwtCreateSignedToken(&obj, &key, JWT_ALGORITHM_ES512, &sig));

    JwtParsedToken token = {};
    ASSERT_EQ(JWT_RESULT_SUCCESS, jwtVerifyToken(sig, &key, &token, 0));
}

TEST(Token, ReadHeader) {

    JwtJsonElement element = {};
    jwtReadJsonString(&element, ecKeyJson, strlen(ecKeyJson));

    JwtKey key = {};
    jwtKeyParse(&key, &element.object);

    JwtJsonObject obj = {};
    jwtJsonObjectCreate(&obj);
    jwtJsonObjectSetInt(&obj, "test", 42);

    JwtString token = {};
    jwtCreateSignedToken(&obj, &key, JWT_ALGORITHM_ES256, &token);

    
    JwtJsonObject header = {};
    ASSERT_EQ(JWT_RESULT_SUCCESS, jwtReadTokenHeader(token, &header));

    
    JwtString alg = jwtJsonObjectGetString(&header, "alg"); 
    ASSERT_STREQ(alg.data, "ES256");

    JwtString typ = jwtJsonObjectGetString(&header, "typ"); 
    ASSERT_STREQ(typ.data, "jwt");

}

TEST(Token, GenerateDirectA128CBC) {

    JwtJsonElement element = {};
    jwtReadJsonString(&element, aesKeyJson, strlen(aesKeyJson));

    JwtKey key = {};
    jwtKeyParse(&key, &element.object);

    JwtJsonObject obj = {};
    jwtJsonObjectCreate(&obj);
    jwtJsonObjectSetInt(&obj, "test", 42);

    JwtString sig = {};
    ASSERT_EQ(JWT_RESULT_SUCCESS, jwtCreateEncryptedToken(&obj, &key, JWT_ALGORITHM_DIRECT, JWT_CRYPT_ALGORITHM_A128CBC_HS256, &sig));

    JwtParsedToken token = {};
    ASSERT_EQ(JWT_RESULT_SUCCESS, jwtVerifyToken(sig, &key, &token, 0));
}

TEST(Token, GenerateDirectA256GCM) {

    JwtJsonElement element = {};
    jwtReadJsonString(&element, aesKeyJson, strlen(aesKeyJson));

    JwtKey key = {};
    jwtKeyParse(&key, &element.object);

    JwtJsonObject obj = {};
    jwtJsonObjectCreate(&obj);
    jwtJsonObjectSetInt(&obj, "test", 42);

    JwtString sig = {};
    ASSERT_EQ(JWT_RESULT_SUCCESS, jwtCreateEncryptedToken(&obj, &key, JWT_ALGORITHM_DIRECT, JWT_CRYPT_ALGORITHM_A256GCM, &sig));

    JwtParsedToken token = {};
    ASSERT_EQ(JWT_RESULT_SUCCESS, jwtVerifyToken(sig, &key, &token, 0));
}
