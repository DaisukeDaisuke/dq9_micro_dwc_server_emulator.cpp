//
// Created by owner on 2026/02/05.
//

#ifndef DQ9_SERVER_SERVERCONTEXT_H
#define DQ9_SERVER_SERVERCONTEXT_H
#include <atomic>

#include "sockets.h"

struct ServerContext {
    std::atomic<bool> stop{false};
    socket_t dns_sock  = kInvalidSocket;
    socket_t http_sock = kInvalidSocket;
    socket_t https_sock = kInvalidSocket;
};


#endif //DQ9_SERVER_SERVERCONTEXT_H