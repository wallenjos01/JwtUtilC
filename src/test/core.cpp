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

struct TestEntry {
    int32_t key;
    int32_t value;
};

JwtHashFunctions testFunctions = {
    .entrySize = sizeof(TestEntry),
    .pfnHashKey =
        [](void* key) {
            return static_cast<size_t>(*static_cast<int32_t*>(key));
        },
    .pfnCompareKey =
        [](void* key, void* entry) {
            return *static_cast<int32_t*>(key) -
                   static_cast<TestEntry*>(entry)->key;
        }};

TEST(HashTable, Empty) {
    JwtHashTable map;
    jwtHashTableCreate(&map, &testFunctions);

    ASSERT_EQ(0, map.size);

    jwtHashTableDestroy(&map);
}

TEST(HashTable, Single) {
    JwtHashTable map;
    jwtHashTableCreate(&map, &testFunctions);

    ASSERT_EQ(0, map.size);

    int32_t key = 0;
    TestEntry* inserted = static_cast<TestEntry*>(jwtHashTablePut(&map, &key));
    inserted->key = 0;
    inserted->value = 1;

    ASSERT_EQ(1, map.size);
    ASSERT_LE(1, map.numBuckets);

    TestEntry* retrieved = static_cast<TestEntry*>(jwtHashTableGet(&map, &key));
    ASSERT_EQ(inserted, retrieved);

    jwtHashTableDestroy(&map);
}

TEST(HashTable, Multi) {
    JwtHashTable map;
    jwtHashTableCreate(&map, &testFunctions);

    ASSERT_EQ(0, map.size);

    int32_t key1 = 0;
    TestEntry* inserted1 =
        static_cast<TestEntry*>(jwtHashTablePut(&map, &key1));
    inserted1->key = 0;
    inserted1->value = 1;

    int32_t key2 = 1;
    TestEntry* inserted2 =
        static_cast<TestEntry*>(jwtHashTablePut(&map, &key2));
    inserted2->key = 1;
    inserted2->value = 2;

    ASSERT_EQ(2, map.size);
    ASSERT_LE(2, map.numBuckets);

    ASSERT_EQ(1, static_cast<TestEntry*>(jwtHashTableGet(&map, &key1))->value);
    ASSERT_EQ(2, static_cast<TestEntry*>(jwtHashTableGet(&map, &key2))->value);

    jwtHashTableDestroy(&map);
}

TEST(HashTable, Replace) {
    JwtHashTable map;
    jwtHashTableCreate(&map, &testFunctions);

    ASSERT_EQ(0, map.size);

    int32_t key = 0;
    TestEntry* inserted1 = static_cast<TestEntry*>(jwtHashTablePut(&map, &key));
    inserted1->key = key;
    inserted1->value = 1;

    ASSERT_EQ(1, static_cast<TestEntry*>(jwtHashTableGet(&map, &key))->value);

    TestEntry* inserted2 = static_cast<TestEntry*>(jwtHashTablePut(&map, &key));
    inserted2->key = key;
    inserted2->value = 2;

    ASSERT_EQ(1, map.size);
    ASSERT_LE(1, map.numBuckets);

    ASSERT_EQ(2, static_cast<TestEntry*>(jwtHashTableGet(&map, &key))->value);

    jwtHashTableDestroy(&map);
}

TEST(HashTable, Remove) {
    JwtHashTable map;
    jwtHashTableCreate(&map, &testFunctions);

    ASSERT_EQ(0, map.size);

    int32_t key = 0;
    TestEntry* inserted = static_cast<TestEntry*>(jwtHashTablePut(&map, &key));
    inserted->key = key;
    inserted->value = 1;

    ASSERT_EQ(1, map.size);
    ASSERT_LE(1, map.numBuckets);

    ASSERT_EQ(1, static_cast<TestEntry*>(jwtHashTableGet(&map, &key))->value);

    jwtHashTableRemove(&map, &key);

    ASSERT_EQ(nullptr, jwtHashTableGet(&map, &key));

    ASSERT_EQ(0, map.size);
    ASSERT_LE(0, map.numBuckets);

    jwtHashTableDestroy(&map);
}

TEST(HashTable, Reclaim) {
    JwtHashTable map;
    jwtHashTableCreate(&map, &testFunctions);

    ASSERT_EQ(0, map.size);

    int32_t key = 4;
    TestEntry* inserted = static_cast<TestEntry*>(jwtHashTablePut(&map, &key));
    inserted->key = key;
    inserted->value = 1;

    int32_t key2 = 1;
    TestEntry* inserted2 =
        static_cast<TestEntry*>(jwtHashTablePut(&map, &key2));
    inserted2->key = key2;
    inserted2->value = 3;

    ASSERT_EQ(2, map.size);
    ASSERT_LE(2, map.numBuckets);

    ASSERT_EQ(1, static_cast<TestEntry*>(jwtHashTableGet(&map, &key))->value);
    ASSERT_EQ(3, static_cast<TestEntry*>(jwtHashTableGet(&map, &key2))->value);

    TestEntry* entry = static_cast<TestEntry*>(jwtHashTableReclaim(&map, &key));
    ASSERT_EQ(inserted, entry);

    ASSERT_EQ(1, map.size);
    ASSERT_LE(1, map.numBuckets);

    TestEntry* entry2 =
        static_cast<TestEntry*>(jwtHashTableReclaim(&map, &key2));
    ASSERT_EQ(inserted2, entry2);

    ASSERT_EQ(nullptr, jwtHashTableGet(&map, &key));

    ASSERT_EQ(0, map.size);
    ASSERT_LE(0, map.numBuckets);

    free(entry);
    jwtHashTableDestroy(&map);
    free(entry2);
}
