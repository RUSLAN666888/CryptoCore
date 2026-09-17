# tests/CMakeLists.txt

include(FetchContent)

FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
)

set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(googletest)

add_executable(cryptocore_tests
    test_hex.cpp
    test_aes128.cpp
    test_padding.cpp
    test_ecb.cpp
)

target_link_libraries(cryptocore_tests PRIVATE
    cryptocore_lib
    GTest::gtest_main
)


include(GoogleTest)
gtest_discover_tests(cryptocore_tests)