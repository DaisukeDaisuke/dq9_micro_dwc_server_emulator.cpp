#include <string>
#include <memory>
#include <thread>
#include "dns.h"
#include "FileHelper.h"
#include "HTTPHelper.h"
#include "ServerContext.h"
#include "SSLHelper.h"

#include <csignal>

#include "nowdate.h"
#include "terminal.h"

static ServerContext* g_ctx = nullptr;


/**
 * 文字列の先頭から空白文字を削除した新しい文字列を返します。
 * 空白文字として扱われるのは、スペース、タブ、改行、復帰、フォームフィード、および垂直タブです。
 *
 * @param s 対象の文字列
 * @return 先頭の空白文字を削除した新しい文字列
 */
std::string ltrim(const std::string &s) {
    size_t start = s.find_first_not_of(" \t\n\r\f\v");
    return (start == std::string::npos) ? "" : s.substr(start);
}

/**
 * 文字列の末尾から空白文字を除去します。
 * 空白文字として認識されるのは、スペース、タブ、改行、復帰、改ページ、
 * 垂直タブなどのホワイトスペース文字です。
 *
 * @param s 処理対象の文字列
 * @return 空白が除去された新しい文字列
 */
std::string rtrim(const std::string &s) {
    size_t end = s.find_last_not_of(" \t\n\r\f\v");
    return (end == std::string::npos) ? "" : s.substr(0, end + 1);
}


/**
 * 指定された文字列の先頭および末尾に存在する空白文字を削除します。
 * 入力文字列がnullの場合は空の文字列を返します。
 *
 * @param s トリム対象のC文字列
 * @return トリム後の文字列
 */
std::string trim(const char *s) {
    if (s == nullptr) return "";
    std::string str(s);
    return trim(str.c_str());
}

/**
 * 文字列の両端から空白を削除し、トリムされた文字列を返します。
 * 入力文字列の先頭と末尾の空白文字（スペース、タブ、改行など）が取り除かれます。
 *
 * @param s トリム対象の文字列
 * @return トリムされた文字列
 */
std::string trim(const std::string &s) {
    return rtrim(ltrim(s));
}

void on_sigint(int)
{
    if (g_ctx) {
        terminal term;
        g_ctx->stop = true;

        term << "[watchdog] stopping..." << std::endl;

        if (g_ctx->dns_sock   != kInvalidSocket) socket_close(g_ctx->dns_sock);
        if (g_ctx->http_sock  != kInvalidSocket) socket_close(g_ctx->http_sock);
        if (g_ctx->https_sock != kInvalidSocket) socket_close(g_ctx->https_sock);
        if (g_ctx->https_sock2 != kInvalidSocket) socket_close(g_ctx->https_sock2);
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
    if (ctx.https_sock2 != kInvalidSocket) socket_close(ctx.https_sock2);
}


int main(int argc, char** argv)
{
    auto nowdate = nowdate::get_current_time_rfc1123();

    std::cout << "Now: " << nowdate << std::endl;

    const char* ipconfg = R"(.\ip.txt)";

    ServerContext ctx1;

    auto ip = trim(FileHelper::readAll(ipconfg));

    if (ip.empty()) {
        std::cerr << "[main.cpp] ip.txt is empty or not found! Unable to start application!" << std::endl;
        return 1;
    }

    g_ctx = &ctx1;
    std::signal(SIGINT, on_sigint);

    std::thread dns_thread(
        dns::run_dns_server_udp_53,
        std::ref(ctx1),
        ip,
        std::string("nintendowifi.net")
    );
    std::thread http_thread(
        HTTPHelper::run_http_server,
        std::ref(ctx1),
        80
    );

    std::thread ssl_thread(
        SSLHelper::Main,
        std::ref(ctx1),
        443
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

