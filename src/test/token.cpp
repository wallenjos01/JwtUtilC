#include <gtest/gtest.h>


#include <jwt/json.h>
#include <jwt/token.h>

TEST(Token, GenerateUnprotected) {

    JwtJsonObject obj;
    jwtJsonObjectCreate(&obj);
    jwtJsonObjectSetInt(&obj, "test", 42);

    JwtString str;
    jwtCreateUnprotectedToken(&obj, &str);

    ASSERT_STREQ(str.data, "eyJ0eXAiOiJqd3QiLCJhbGciOiJub25lIn0.eyJ0ZXN0Ijo0Mn0.");

}

TEST(Token, GenerateHS256) {

    const char* keyJson = "{\"kty\":\"oct\",\"use\":\"sig\",\"k\":\"bXktcmVhbGx5LWNvb2wtc2VjcmV0LWtleS10aGF0LWlzLW92ZXItMjU2LWJpdHMtbG9uZwo\"}";
    JwtJsonElement element;
    jwtReadJsonString(&element, keyJson, strlen(keyJson));

    JwtKey key;
    jwtKeyParse(&key, element.object);

    JwtJsonObject obj;
    jwtJsonObjectCreate(&obj);
    jwtJsonObjectSetInt(&obj, "test", 42);

    JwtString mac;
    jwtCreateToken(&obj, &key, JWT_ALGORITHM_HS256, &mac);

    ASSERT_STREQ(mac.data, "eyJ0eXAiOiJqd3QiLCJhbGciOiJIUzI1NiJ9.eyJ0ZXN0Ijo0Mn0.sawwoMaSsTQpYK7UOtmAXmD_NENPpofcb2MF2ZKN6vY");

}


TEST(Token, GenerateRS256) {
    const char* keyJson = "{\"kty\": \"RSA\",\"n\": \"6-Z0tsZqaL1DF0oBaz_d1xmX0BNkAJoDlb-ay--kfpwZsBJyketrPiGOvTS0b0t6O1f5C0B0pyRBucsMG5LbC4Kbzk3p_oPOcHOwjnRJ-xuB7CRdFS71VEEuK2bHDk7gqCF6z-EcD-6T9k84t4qSg3yWeDygodH7RICcV0p4cWepxKITKsICULmidic-r6IcWFCkgc7CjTUiZxM72lOumjf8VoUQWXiZ72UPD08LygN0Z-bzlaBUDUsSLl691X5qYtAVeTgrNmDmT7TZN7-9a3qq8wNv2dLnqr1o1NtJjDJvCu5GfL-MNYmVV1SFYL8IWCBonIMA9y6nv-7ndMEaEQ\",\"e\": \"AQAB\",\"d\": \"I5eBxJHrPCJSHRFtZWEdd3bFEP_b9rtGDzH5iQt_JhsnRQmDf8ClTZqCjsmE78XTi2CakrgG4bD2ubGJAiAGLJZoK5hV1bDNVOofmV6yStC7qYVTBf8vxKaQ8LtxDReZjcR_Yx3zvfOhH2iUhhzCPlRt33ZGRiQIZS2CaSkzQui24vgqIPEIZSm5jyMAOgpowD7cbdk8num8FyDMCv-bm0t8UgWKLM9wWjORwM3Q-9gD_Mz_W7_qd6dKdYrF3hvlmeO8Cd2ZrT7JDDIRwwpBOkvzqoM7WoY8Se6MA_AEe0z-HHKcQIPZExoex0ZdlWRsRgx5XDfanTIgmvxFkn6IgQ\",\"p\": \"_cgjJyYqzyV-q7gvCc39TRybeCrIy8NtPzxeEcYJz0PWP4HzZcFRkBeaYl3EExoAYOsFoIJ97LG8PjfwsIKqwD6IsUv5DJwjuJjr5dGkGgkX5cqyVk-nxaK8EJxhWw-MniVh5Njdw71D4ODEMBw8UrMvVlX9yaIPcOZud5VjHKM\",\"q\": \"7fZOh_NRXazVGBDoEVVbAKqG3U4tdb-srUsZVAa7M_lolSC9rJrNotypOdYBz9eLx46qvozwiLcPMAF6mRtF5g5_KQCsYxXgo-b2keuYoMfykGG3reVCkXUVfQYKsosboW3QgXSn9J0Oj_lUjorhHO7dNASf9v6hV6Y3hDPEBbs\",\"dp\": \"87W2zGnCwprnQlDmGyxODDdktcmges15pDh8veTIlto2bVaGPzme8hk4kS4qlY1qv6fzB2lJNHyaocVmxps1Dtj-vASRbqKjSyrPnyvrw3ToFizJhkmIfCsDH5CNjb0o9NZBZFs-3DJtdQ9kWC9FXsXkt6xsw6111p3zh7NWMrE\",\"dq\": \"v5dWd0NCuadUEwJZtssAcDLcTwaIt4tR3lze0bZxt1ESES_BR12EP6JmZfiWkN883blSZAVaDNlG0yH9sZQx3R7C5yJxqX2N1qk40RfdVWZnODRVDR_PTwnz-SuKJWK3JmwiOnjQWbSyat0WZYYP5Zm0ZBNtMBKnmMhtXnXHV80\",\"qi\": \"dQ52omzYWpjz2thXU8KSO_6acJHmAwD7gM3j3YJp6l4wgOvEi2OHXDvgeiaSi3CsA15cXwKQB4qPzwh8JXoXs51CmDcDZU4D1tan24a6lUwGbanJEysKZCNont4Rtj01DzVj4Xzab_oldYMYt4rzqN6ru-QsikOy1Fr8-f_Aq_M\",\"ext\": true,\"kid\": \"6ab5a045324a0e99345b86\",\"alg\": \"RS256\",\"use\": \"sig\"  }";

    JwtJsonElement element = {};
    jwtReadJsonString(&element, keyJson, strlen(keyJson));

    JwtKey key = {};
    jwtKeyParse(&key, element.object);

    JwtJsonObject obj = {};
    jwtJsonObjectCreate(&obj);
    jwtJsonObjectSetInt(&obj, "test", 42);

    JwtString sig = {};
    ASSERT_EQ(0, jwtCreateToken(&obj, &key, JWT_ALGORITHM_RS256, &sig));

    ASSERT_STREQ(sig.data, "eyJ0eXAiOiJqd3QiLCJhbGciOiJSUzI1NiJ9.eyJ0ZXN0Ijo0Mn0.GE2qm99AkxEEC6izSbqc-U6Zfi2XsTGKtyX63yabcM-j8-QYLRSYEuaquIxZYvZiCuP5wXtUKJl9Qjz2RDr2AFigLc8kMP70Wl8w8JDkychEmAZe7LxkW6AHPufxG7TqjT_3btM0zzui15T0iFzsSOZYgu96IzJRUBzykwIat4SzL5gUYYCH5kkAXWAmlB0k8NkzU2P2QOCrzSnf_H1pfkpCKS5HO0jewdBA5KmPsq4SPhZ8VmLx0Fqba-_MBzcsDn0MK9tZx7TbkSbeITGkZqUEznBJsXx5xuS5QEmTlzLEvttGUceZ0W36ITF-ZlMZdPalQQi6xuPDV87pUMtGRA");

}
