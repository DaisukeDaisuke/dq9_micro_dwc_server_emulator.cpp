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
#include "terminal.h"

static constexpr int CLIENT_IO_TIMEOUT_MS = 30 * 1000;

void HTTPHelper::run_http_server(ServerContext& ctx, int port) {
    terminal term;

    term << "[http] Starting server on port " << port << std::endl;

    sockets_init_once();

    socket_t sock = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sock == kInvalidSocket) {
        term << "[http] Initializing socket: error" << std::endl;
        perror("http socket"); return;
    }

    ctx.http_sock = sock;
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    term << "[http] Initializing socket: ok" << std::endl;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)port);

    if (bind(sock, (sockaddr*)&addr, sizeof(addr)) != 0) {
        term << "[http] Binding socket: error" << std::endl;
        perror("http bind");
        socket_close(sock);
        return;
    }

    term << "[http] Binding socket: ok" << std::endl;



    if (listen(sock, 8) != 0) {
        term << "[http] Listening on port " << port << ": error" << std::endl;
        perror("http listen");
        socket_close(sock);
        return;
    }

    term << "[http] Listening on port " << port << ": ok" << std::endl;

    term << "[http] HTTP listening on port " << port << std::endl;

    const char resp[] =
        "HTTP/1.1 200 OK\r\n"
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

        if (!socket_set_io_timeout(client, CLIENT_IO_TIMEOUT_MS)) {
            term << "[http] Failed to set client socket timeout" << std::endl;
            socket_close(client);
            continue;
        }

        char buf[1024];
        int r = recv(client, buf, (int)sizeof(buf), 0); // 読み捨て
        if (r <= 0) {
            socket_close(client);
            continue;
        }

        //bufは\x00がないため、出力禁止
        term << "[http] Received conntest request!" << std::endl;

        send(client, resp, (int)(sizeof(resp) - 1), 0);
        socket_close(client);
    }
}
