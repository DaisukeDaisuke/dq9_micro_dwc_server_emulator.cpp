//
// Created by owner on 2026/02/05.
//

#ifndef DQ9_SERVER_SOCKETS_H
#define DQ9_SERVER_SOCKETS_H

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  using socket_t = SOCKET;
static constexpr socket_t kInvalidSocket = INVALID_SOCKET;
static int socket_close(socket_t s) { return ::closesocket(s); }
static int socket_shutdown_wr(socket_t s) { return ::shutdown(s, SD_SEND); }
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
using socket_t = int;
static constexpr socket_t kInvalidSocket = -1;
static int socket_close(socket_t s) { return ::close(s); }
static int socket_shutdown_wr(socket_t s) { return ::shutdown(s, SHUT_WR); }
static void sockets_init_once() {}
#endif

#endif //DQ9_SERVER_SOCKETS_H