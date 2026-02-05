//
// Created by owner on 2026/02/05.
//

#include "HTTPHelper.h"

#include <iostream>
#include <string>
#include <memory>
#include <cstring>
#include <sstream>
#include <thread>
#include "sockets.h"

#include <cctype>

#include "dns.h"
#include "ServerContext.h"

void HTTPHelper::run_http_server(ServerContext& ctx, int port) {
    sockets_init_once();

    socket_t sock = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sock == kInvalidSocket) { perror("http socket"); return; }

    ctx.http_sock = sock;

    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)port);

    if (bind(sock, (sockaddr*)&addr, sizeof(addr)) != 0) {
        perror("http bind");
        socket_close(sock);
        return;
    }
    if (listen(sock, 8) != 0) {
        perror("http listen");
        socket_close(sock);
        return;
    }

    std::cerr << "HTTP listening on port " << port << "\n";

    const char resp[] =
        "HTTP/1.1 200 OK\r\n"
        "Date: Wed, 04 Feb 2026 13:42:03 GMT\r\n"
        "Server: Nintendo Wii (http) \r\n"
        "Content-type: text/html\r\n"
        "X-Organization: Nintendo\r\n"
        "Vary: Accept-Encoding\r\n"
        "Connection: close\r\n"
        "\r\n"
        "ok";

    while (true) {
        socket_t client = accept(sock, nullptr, nullptr);
        if (client == kInvalidSocket) {
            if (ctx.stop.load()) break;
            continue;
        }

        if (ctx.stop.load()) {
            socket_close(client);
            break;
        }

        char buf[1024];
        recv(client, buf, (int)sizeof(buf), 0); // 読み捨て

        send(client, resp, (int)(sizeof(resp) - 1), 0);
        socket_close(client);
    }
}
