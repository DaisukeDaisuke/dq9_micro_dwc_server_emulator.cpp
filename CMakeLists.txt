cmake_minimum_required(VERSION 3.18)
project(dq9-server CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Os -Wall -Wextra")

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

add_executable(dq9-server src/main.cpp)
target_link_libraries(dq9-server ${OPENSSL_LIBRARIES} Threads::Threads)

find_package(Threads REQUIRED)