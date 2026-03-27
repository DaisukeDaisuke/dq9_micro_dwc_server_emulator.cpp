//
// Created by owner on 2026/02/05.
//

#ifndef DQ9_SERVER_SOCKETS_H
#define DQ9_SERVER_SOCKETS_H

#ifdef _WIN32
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#ifdef max
#undef max
#endif
#ifdef min
#undef min
#endif
  using socket_t = SOCKET;
static constexpr socket_t kInvalidSocket = INVALID_SOCKET;
static int socket_close(socket_t s) { return ::closesocket(s); }
static int socket_shutdown_wr(socket_t s) { return ::shutdown(s, SD_SEND); }
static bool socket_set_recv_timeout(socket_t s, int timeout_ms) {
    DWORD timeout = (DWORD)timeout_ms;
    return ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO,
                        reinterpret_cast<const char*>(&timeout),
                        sizeof(timeout)) == 0;
}
static bool socket_set_send_timeout(socket_t s, int timeout_ms) {
    DWORD timeout = (DWORD)timeout_ms;
    return ::setsockopt(s, SOL_SOCKET, SO_SNDTIMEO,
                        reinterpret_cast<const char*>(&timeout),
                        sizeof(timeout)) == 0;
}
static bool socket_set_io_timeout(socket_t s, int timeout_ms) {
    return socket_set_recv_timeout(s, timeout_ms) &&
           socket_set_send_timeout(s, timeout_ms);
}
static void sockets_init_once() {
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::cerr << "WSAStartup failed\n";
        std::terminate();
    }
}
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>
using socket_t = int;
static constexpr socket_t kInvalidSocket = -1;
static int socket_close(socket_t s) { return ::close(s); }
static int socket_shutdown_wr(socket_t s) { return ::shutdown(s, SHUT_WR); }
static bool socket_set_recv_timeout(socket_t s, int timeout_ms) {
    timeval tv{};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    return ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0;
}
static bool socket_set_send_timeout(socket_t s, int timeout_ms) {
    timeval tv{};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    return ::setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == 0;
}
static bool socket_set_io_timeout(socket_t s, int timeout_ms) {
    return socket_set_recv_timeout(s, timeout_ms) &&
           socket_set_send_timeout(s, timeout_ms);
}
static void sockets_init_once() {}
#endif

#endif //DQ9_SERVER_SOCKETS_H
