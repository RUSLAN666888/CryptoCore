cmake_minimum_required(VERSION 3.16)

project(CryptoCore LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ---- OpenSSL ----
find_package(OpenSSL REQUIRED)

# ---- Library ----
add_library(cryptocore_lib STATIC
    src/crypto/aes128/aes128.cpp
    src/crypto/modes/padding/padding.cpp
    src/crypto/modes/ecb/ecb.cpp
    src/utils/hex/hex.cpp
    src/utils/file_io/file_io.cpp
)

target_include_directories(cryptocore_lib PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/aes128
    ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/modes/ecb
    ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/modes/padding
    ${CMAKE_CURRENT_SOURCE_DIR}/src/utils/hex
    ${CMAKE_CURRENT_SOURCE_DIR}/src/utils/file_io
)

target_link_libraries(cryptocore_lib PUBLIC
    OpenSSL::Crypto
)

# ---- CLI ----
add_executable(CryptoCore
    main.cpp
    src/cli/parser.cpp
)

target_include_directories(CryptoCore PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cli
)

target_link_libraries(CryptoCore PRIVATE
    cryptocore_lib
)

# ---- Install ----
include(GNUInstallDirs)

install(TARGETS CryptoCore
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(TARGETS cryptocore_lib
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

# ---- Tests ----
enable_testing()
add_subdirectory(tests)