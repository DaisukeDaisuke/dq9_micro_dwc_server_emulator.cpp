cmake_minimum_required(VERSION 3.18)
project(dq9-server CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(dq9-server src/main.cpp
        src/dns.cpp
        src/dns.h
        src/sockets.h
        src/ServerContext.h
        src/SSLHelper.cpp
        src/SSLHelper.h
        src/HTTPHelper.cpp
        src/HTTPHelper.h
        src/FileHelper.cpp
        src/FileHelper.h
        src/RequestHandler.cpp
        src/RequestHandler.h
        src/terminal.h)



# MinGWビルドかMSVCビルドかを判別するフラグを定義
if(MINGW)
    add_definitions(-DMINGW_BUILD)
    # GCC系（Linux gcc / MinGW gcc）向け
    target_compile_options(dq9-server PRIVATE -O0 -Wall -Wextra -Wpedantic)
elseif(MSVC)
    add_definitions(-DMSVC_BUILD)
endif()

if(MSVC)
    target_compile_options(dq9-server PRIVATE /W4 /MP)  # `/MP` で並列コンパイル
    target_link_options(dq9-server PRIVATE /INCREMENTAL:NO /DEBUG)

    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /Zi /O2")
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} /DEBUG /OPT:REF /OPT:ICF")
endif()

# --- MinGW (Windows GCC) 分岐 ---
if (MINGW)
    target_compile_definitions(dq9-server PRIVATE MINGW_BUILD)

    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=x86-64 -mtune=generic -ffunction-sections -fdata-sections")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=x86-64 -mtune=generic -ffunction-sections -fdata-sections") #  -fno-inline-small-functions
    set(CMAKE_EXE_LINKER_FLAGS "-Wl,--gc-sections")

    # 「どこいったん？」→ここです：MinGW時の既定値として残す
    # ただし上書き可能にする（cmake -DOPENSSL_ROOT_DIR=... で変更できる）
    set(OPENSSL_ROOT_DIR "./openssl/openssl")
endif()

# Windows (MinGW) は Winsock 必須
if (WIN32)
    target_link_libraries(dq9-server PRIVATE ws2_32)
endif()

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

target_include_directories(dq9-server PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(dq9-server PRIVATE ${OPENSSL_LIBRARIES} Threads::Threads)