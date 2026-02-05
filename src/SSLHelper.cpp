//
// Created by owner on 2026/02/05.
//

#include "SSLHelper.h"
#include "RequestHandler.h"
#include <iostream>
#include <vector>
#include <string>
#include <memory>
#include <algorithm>
#include <cstring>
#include <sstream>
#include <fstream>
#include <map>
#include <chrono>
#include <thread>
#include <limits>
#include "sockets.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <cctype>

#include "dns.h"
#include "ServerContext.h"

static const int DEFAULT_PORT = 443;
static const size_t RECV_BUF = 8192;
static const size_t SEND_CHUNK = 768; // tuneable: 512..1024 通らないなら1024にする
static const size_t MAX_BODY_BYTES = 5u * 1024u * 1024u; // 100MB上限




static void ssl_write_split(SSL* ssl, const std::vector<uint8_t>& data) {
    size_t off = 0;
    while (off < data.size()) {
        size_t n = std::min(SEND_CHUNK, data.size() - off);
        int r = SSL_write(ssl, data.data() + off, (int)n);
        if (r <= 0) {
            int err = SSL_get_error(ssl, r);
            std::cerr << "SSL_write error: " << err << "\n";
            break;
        }
        off += r;
        // optional short usleep to shape timing (avoid coalescing). tune if needed.
        // usleep(1000);
    }
}

static std::string read_until_double_crlf(SSL* ssl, std::string &out_body) {
    std::string buf;
    std::vector<char> tmp(RECV_BUF);
    while (true) {
        int r = SSL_read(ssl, tmp.data(), (int)tmp.size());
        if (r <= 0) break;
        buf.append(tmp.data(), r);
        auto pos = buf.find("\r\n\r\n");
        if (pos != std::string::npos) {
            out_body = buf.substr(pos+4);
            return buf.substr(0, pos+4); // headers incl final CRLFCRLF
        }
        if (buf.size() > 64*1024) break;
    }
    return buf;
}

static std::map<std::string,std::string> parse_headers(const std::string& header_block, std::string& request_line) {
    std::istringstream ss(header_block);
    std::string line;
    bool first = true;
    std::map<std::string,std::string> headers;
    while (std::getline(ss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (first) { request_line = line; first = false; continue; }
        if (line.empty()) break;
        auto pos = line.find(":");
        if (pos!=std::string::npos) {
            std::string k = line.substr(0,pos);
            std::string v = line.substr(pos+1);
            // trim
            while(!k.empty() && isspace((unsigned char)k.back())) k.pop_back();
            while(!v.empty() && isspace((unsigned char)v.front())) v.erase(v.begin());
            std::transform(k.begin(), k.end(), k.begin(), ::tolower);
            headers[k] = v;
        }
    }
    return headers;
}

#include <string>
#include <vector>

struct SSL_CTX_RAII {
    SSL_CTX* ctx;
    SSL_CTX_RAII(SSL_CTX* p): ctx(p) {}
    ~SSL_CTX_RAII(){ if(ctx) SSL_CTX_free(ctx); }
};

struct SSL_RAII {
    SSL* ssl;
    SSL_RAII(SSL* s): ssl(s) {}
    ~SSL_RAII(){ if(ssl) SSL_free(ssl); }
};


static void init_openssl() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

int SSLHelper::Main(ServerContext& ctx2) {
    sockets_init_once();
#ifdef _WIN32
    const char* cert_file = R"(.\dummy-certs\server.crt)";
    const char* key_file = R"(.\dummy-certs\server.key)";
    const char* cert_nwc_file = R"(.\dummy-certs\nwc.crt)";

    int port = DEFAULT_PORT;
#else
    const char* cert_file = "/etc/ssl/certs/server.crt";
    const char* key_file = "/etc/ssl/private/server.key";
    const char* cert_nwc_file = "/etc/ssl/certs/nwc.crt";
    int port = DEFAULT_PORT;
#endif

     std::cerr << "Starting server on port " << port << "\n";

    init_openssl();

    // ★ここ：SSLv3ハンドシェイク処理は維持（消さない）
    SSL_CTX* ctx = SSL_CTX_new(SSLv3_server_method());
    if (!ctx) {
        std::cerr << "SSL_CTX_new failed\n";
        ERR_print_errors_fp(stderr);
        return 1;
    }
    SSL_CTX_RAII ctx_raii(ctx);

    std::cerr << "init\n";


    if (!SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) ||
        !SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM)) {
        std::cerr << "Certificate/key load failed1\n";
        ERR_print_errors_fp(stderr);
        return 1;
    }

    SSL_CTX_set_quiet_shutdown(ctx, 1);

    std::cerr << "init2\n";

    auto handle = fopen(cert_nwc_file, "r");

    if (SSL_CTX_add_extra_chain_cert(
        ctx,
        PEM_read_X509(handle, nullptr, nullptr, nullptr)
    ) != 1) {
        std::cerr << "Certificate/key load failed2\n";
        ERR_print_errors_fp(stderr);
        return 1;
    }

    fclose(handle);

    std::cerr << "init3\n";

    if (!SSL_CTX_set_cipher_list(ctx, "RC4-SHA:RC4-MD5")) {
        std::cerr << "Failed to set cipher list\n";
        ERR_print_errors_fp(stderr);
        return 1;
    }

    // socket setup
    socket_t sock = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sock == kInvalidSocket) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    sockaddr_in addr {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)port);

    if (bind(sock, (sockaddr*)&addr, sizeof(addr)) != 0) { perror("bind"); socket_close(sock); return 1; }
    if (listen(sock, 8) != 0) { perror("listen"); socket_close(sock); return 1; }
    std::cerr << "Listening on port " << port << " (SSLv3 + RC4)\n";

    ctx2.https_sock = sock;

    while (true) {
        sockaddr_in peer{};
        socklen_t plen = sizeof(peer);
        socket_t client = accept(sock, (sockaddr*)&peer, &plen);
        if (client == kInvalidSocket) {
            if (ctx2.stop.load()) break;
            continue;
        }
        if (ctx2.stop.load()) {
            socket_close(client);
            break;
        }
        std::cerr << "Accepted connection\n";

        SSL* ssl = SSL_new(ctx);
        if (!ssl) { socket_close(client); continue; }
        SSL_RAII ssl_raii(ssl);

        SSL_set_fd(ssl, (int)client);

        // ★ここ：SSLv3ハンドシェイク（SSL_accept）も維持
        if (SSL_accept(ssl) <= 0) {
            std::cerr << "SSL_accept failed\n";
            ERR_print_errors_fp(stderr);
            socket_close(client);
            continue;
        }
        std::cerr << "SSL handshake ok\n";

        std::string leftover_body;
        std::string header_block = read_until_double_crlf(ssl, leftover_body);
        std::string req_line;
        auto headers = parse_headers(header_block, req_line);

        // if Content-Length exists, read more (100MB制限 + 例外対策)
        size_t content_len = 0;
        auto it = headers.find("content-length");
        std::vector<uint8_t> bodyv;

        if (it != headers.end()) {
            try {
                unsigned long long v = std::stoull(it->second);
                if (v > (unsigned long long)MAX_BODY_BYTES) {
                    std::cerr << "Body too large: " << v << " bytes\n";
                    SSL_shutdown(ssl);
                    socket_close(client);
                    continue;
                }
                if (v > std::numeric_limits<size_t>::max()) {
                    std::cerr << "Content-Length out of range\n";
                    SSL_shutdown(ssl);
                    socket_close(client);
                    continue;
                }
                content_len = (size_t)v;
            } catch (...) {
                std::cerr << "Invalid Content-Length\n";
                content_len = 0;
            }

            bodyv.assign(leftover_body.begin(), leftover_body.end());
            if (bodyv.size() > content_len) bodyv.resize(content_len);

            while (bodyv.size() < content_len) {
                size_t need = content_len - bodyv.size();
                size_t chunk = std::min(need, RECV_BUF);

                std::vector<char> tmp(chunk);
                int r = SSL_read(ssl, tmp.data(), (int)tmp.size());
                if (r <= 0) break;

                size_t can_take = std::min((size_t)r, content_len - bodyv.size());
                bodyv.insert(bodyv.end(), tmp.data(), tmp.data() + can_take);
            }
        }

        // handle
        std::vector<uint8_t> resp;
        RequestHandler::handle_request(req_line, headers, bodyv, resp);

        // send in controlled chunks
        ssl_write_split(ssl, resp);

        SSL_shutdown(ssl);

        socket_close(client);
    }

    socket_close(sock);
    return 0;
}
