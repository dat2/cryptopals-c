cmake_minimum_required(VERSION 3.9)
project(cryptopals)

set(cryptopals_VERSION_MAJOR 1)
set(cryptopals_VERSION_MINOR 0)

# include all `src/*.c` files
file(GLOB SOURCES src/*.c)

# header files in include
include_directories(include)
include_directories(lib/uthash/include)

# main binary
add_executable(cryptopals ${SOURCES})

# openssl
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
target_link_libraries(cryptopals ${OPENSSL_LIBRARIES})
