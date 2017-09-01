cmake_minimum_required(VERSION 3.9)
project(cryptopals)

# VERSION
set(cryptopals_VERSION_MAJOR 1)
set(cryptopals_VERSION_MINOR 0)

file(GLOB SOURCES src/*.c)
include_directories(include)

# add a library
# add_library()

add_executable(cryptopals ${SOURCES})
