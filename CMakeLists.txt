cmake_minimum_required(VERSION 3.24)
project(Keygen)

set(CMAKE_CXX_STANDARD 14)

add_executable(
        Keygen
        main.cpp
        xp.cpp
        server.cpp
        header.h
        utilities.cpp
        key.cpp
)
target_link_libraries(Keygen ${CMAKE_CURRENT_SOURCE_DIR}/lib/libcrypto.lib -static)