#include <string>
#include <memory>
#include <thread>
#include "dns.h"
#include "FileHelper.h"
#include "HTTPHelper.h"
#include "ServerContext.h"
#include "SSLHelper.h"

#include <csignal>

#include "terminal.h"

static ServerContext* g_ctx = nullptr;

void on_sigint(int)
{
    if (g_ctx) {
        terminal term;
        g_ctx->stop = true;

        term << "[watchdog] stopping..." << std::endl;

        if (g_ctx->dns_sock   != kInvalidSocket) socket_close(g_ctx->dns_sock);
        if (g_ctx->http_sock  != kInvalidSocket) socket_close(g_ctx->http_sock);
        if (g_ctx->https_sock != kInvalidSocket) socket_close(g_ctx->https_sock);
    }
}

void wait_for_input(ServerContext& ctx)
{
    terminal term;
    term << "[watchdog] Pressing any key will be stop" << std::endl;

    std::string line;
    std::getline(std::cin, line);

    term << "[watchdog] stopping..." << std::endl;

    ctx.stop = true;

    if (ctx.dns_sock   != kInvalidSocket) socket_close(ctx.dns_sock);
    if (ctx.http_sock  != kInvalidSocket) socket_close(ctx.http_sock);
    if (ctx.https_sock != kInvalidSocket) socket_close(ctx.https_sock);
}


int main(int argc, char** argv)
{
    const char* ipconfg = R"(.\ip.txt)";

    ServerContext ctx1;

    g_ctx = &ctx1;
    std::signal(SIGINT, on_sigint);

    std::thread dns_thread(
        dns::run_dns_server_udp_53,
        std::ref(ctx1),
        FileHelper::readAll(ipconfg),
        std::string("nintendowifi.net")
    );
    std::thread http_thread(
        HTTPHelper::run_http_server,
        std::ref(ctx1),
        80
    );

    std::thread ssl_thread(
        SSLHelper::Main,
        std::ref(ctx1)
    );

    std::thread input_thread(
        wait_for_input,
        std::ref(ctx1)
    );

    dns_thread.join();
    http_thread.join();
    ssl_thread.join();
    input_thread.join();

    return 0;
}

