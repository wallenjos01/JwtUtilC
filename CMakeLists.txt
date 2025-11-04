cmake_minimum_required(VERSION 4.0.0)

project(Jwt LANGUAGES CXX)

set(JWT_VERSION "0.1.0")
set(JWT_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR})
set(JWT_INCLUDE_DIR ${JWT_ROOT_DIR}/include)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
add_custom_target(
    copy-compile-commands ALL
    ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_BINARY_DIR}/compile_commands.json
        ${JWT_ROOT_DIR}/build/compile_commands.json
    )


find_package(OpenSSL REQUIRED)
find_package(GTest REQUIRED)
find_package(argparse REQUIRED)


file(GLOB_RECURSE LibrarySources src/lib/**.cpp)
file(GLOB_RECURSE UtilSources src/util/**.cpp)
file(GLOB_RECURSE TestSources src/test/**.cpp)

add_compile_definitions(JWT_VERSION=\"${JWT_VERSION}\")

add_library(JwtLib STATIC ${LibrarySources})
target_include_directories(JwtLib PUBLIC ${JWT_INCLUDE_DIR})
target_link_libraries(JwtLib openssl::openssl)


add_executable(JwtUtil ${UtilSources})
target_include_directories(JwtUtil PUBLIC ${JWT_INCLUDE_DIR})
target_link_libraries(JwtUtil PRIVATE JwtLib)
target_link_libraries(JwtUtil PRIVATE argparse::argparse)

add_executable(JwtTest ${TestSources})
target_include_directories(JwtTest PUBLIC ${JWT_INCLUDE_DIR})
target_link_libraries(JwtTest PRIVATE JwtLib)
target_link_libraries(JwtTest PRIVATE gtest::gtest)

