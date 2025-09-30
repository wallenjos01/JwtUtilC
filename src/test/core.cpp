#include <gtest/gtest.h>
#include <jwt/core.h>

TEST(List, Empty) {

    JwtList list = {};
    jwtListCreate(&list, 0);

    ASSERT_EQ(0, list.size);

    jwtListDestroy(&list);
    ASSERT_EQ(0, list.size);
    ASSERT_EQ(0, list.capacity);
}

TEST(List, Single) {

    JwtList list = {};
    jwtListCreate(&list, sizeof(int));

    ASSERT_EQ(0, list.size);

    *static_cast<int*>(jwtListPush(&list)) = 1;
    ASSERT_EQ(1, list.size);
    ASSERT_LE(1, list.capacity);

    ASSERT_EQ(1, *static_cast<int*>(jwtListGet(&list, 0)));

    jwtListDestroy(&list);
    ASSERT_EQ(0, list.size);
    ASSERT_EQ(0, list.capacity);
}

TEST(List, Multi) {

    JwtList list = {};
    jwtListCreate(&list, sizeof(int));

    ASSERT_EQ(0, list.size);

    *static_cast<int*>(jwtListPush(&list)) = 1;
    *static_cast<int*>(jwtListPush(&list)) = 2;
    *static_cast<int*>(jwtListPush(&list)) = 3;
    *static_cast<int*>(jwtListPush(&list)) = 4;
    ASSERT_EQ(4, list.size);
    ASSERT_LE(4, list.capacity);

    ASSERT_EQ(1, *static_cast<int*>(jwtListGet(&list, 0)));
    ASSERT_EQ(2, *static_cast<int*>(jwtListGet(&list, 1)));
    ASSERT_EQ(3, *static_cast<int*>(jwtListGet(&list, 2)));
    ASSERT_EQ(4, *static_cast<int*>(jwtListGet(&list, 3)));

    jwtListDestroy(&list);
    ASSERT_EQ(0, list.size);
    ASSERT_EQ(0, list.capacity);
}

TEST(List, Pop) {

    JwtList list = {};
    jwtListCreate(&list, sizeof(int));

    ASSERT_EQ(0, list.size);

    *static_cast<int*>(jwtListPush(&list)) = 1;
    *static_cast<int*>(jwtListPush(&list)) = 2;
    ASSERT_EQ(2, list.size);
    ASSERT_LE(2, list.capacity);

    ASSERT_EQ(1, *static_cast<int*>(jwtListGet(&list, 0)));
    ASSERT_EQ(2, *static_cast<int*>(jwtListGet(&list, 1)));

    jwtListPop(&list);
    ASSERT_EQ(1, *static_cast<int*>(jwtListGet(&list, 0)));
    ASSERT_EQ(1, list.size);

    jwtListPop(&list);
    ASSERT_EQ(0, list.size);

    jwtListDestroy(&list);
    ASSERT_EQ(0, list.size);
    ASSERT_EQ(0, list.capacity);
}

TEST(List, Remove) {

    JwtList list = {};
    jwtListCreate(&list, sizeof(int));

    ASSERT_EQ(0, list.size);

    *static_cast<int*>(jwtListPush(&list)) = 1;
    *static_cast<int*>(jwtListPush(&list)) = 2;
    ASSERT_EQ(2, list.size);
    ASSERT_LE(2, list.capacity);

    ASSERT_EQ(1, *static_cast<int*>(jwtListGet(&list, 0)));
    ASSERT_EQ(2, *static_cast<int*>(jwtListGet(&list, 1)));

    jwtListRemove(&list, 0);
    ASSERT_EQ(2, *static_cast<int*>(jwtListGet(&list, 0)));
    ASSERT_EQ(1, list.size);

    *static_cast<int*>(jwtListPush(&list)) = 3;
    *static_cast<int*>(jwtListPush(&list)) = 4;
    ASSERT_EQ(3, list.size);
    ASSERT_LE(3, list.capacity);

    ASSERT_EQ(2, *static_cast<int*>(jwtListGet(&list, 0)));
    ASSERT_EQ(3, *static_cast<int*>(jwtListGet(&list, 1)));
    ASSERT_EQ(4, *static_cast<int*>(jwtListGet(&list, 2)));

    jwtListRemove(&list, 0);
    ASSERT_EQ(2, list.size);

    jwtListDestroy(&list);
    ASSERT_EQ(0, list.size);
    ASSERT_EQ(0, list.capacity);
}
