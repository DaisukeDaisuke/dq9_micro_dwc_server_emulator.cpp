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
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <cctype>

#include "Safety.h"

#if defined(MSVC_BUILD)
#include "applink.c"
#endif

#include "dns.h"
#include "ServerContext.h"
#include "terminal.h"

static const int DEFAULT_PORT = 443;
static const size_t RECV_BUF = 8192;
static const size_t SEND_CHUNK = 768; // tuneable: 512..1024 通らないなら1024にする
static const size_t MAX_BODY_BYTES = 5u * 1024u * 1024u; // 5MB上限


static constexpr int MAX_SSL_RETRY = 1000;

bool ssl_write_split(SSL* ssl, const std::vector<uint8_t>& data)
{
    size_t off = 0;
    int retry_count = 0;

    while (off < data.size()) {

        size_t n = std::min(SEND_CHUNK, data.size() - off);

        int r = SSL_write(ssl,
                          data.data() + off,
                          (int)n);

        if (r > 0) {
            off += r;
            retry_count = 0;  // 成功したらリセット
            continue;
        }

        int err = SSL_get_error(ssl, r);

        if (err == SSL_ERROR_WANT_READ ||
            err == SSL_ERROR_WANT_WRITE)
        {
            retry_count++;
            if (retry_count > MAX_SSL_RETRY) {
                std::cerr << "SSL_write retry overflow\n";
                return false;
            }
            continue;
        }

        if (err == SSL_ERROR_ZERO_RETURN) {
            // TLS close_notify 受信
            return false;
        }

        // 致命的エラー
        std::cerr << "SSL_write fatal error: " << err << "\n";
        ERR_print_errors_fp(stderr);
        return false;
    }

    return true;
}

static constexpr size_t MAX_HEADER_TOTAL = 32 * 1024;

std::string read_until_double_crlf(
    SSL* ssl,
    std::string &out_body,
    bool &error)
{
    error = false;
    std::string buf;
    std::vector<char> tmp(RECV_BUF);

    while (true) {
        int r = SSL_read(ssl, tmp.data(), (int)tmp.size());

        if (r > 0) {
            buf.append(tmp.data(), r);

            if (buf.size() > MAX_HEADER_TOTAL) {
                error = true; // header too large
                return {};
            }

            auto pos = buf.find("\r\n\r\n");
            if (pos != std::string::npos) {
                out_body = buf.substr(pos + 4);
                return buf.substr(0, pos + 4);
            }

            continue;
        }

        int ssl_err = SSL_get_error(ssl, r);

        if (ssl_err == SSL_ERROR_WANT_READ ||
            ssl_err == SSL_ERROR_WANT_WRITE) {
            continue;
            }

        error = true;
        return {};
    }
}

static constexpr size_t MAX_HEADER_LINE   = 8 * 1024;
static constexpr size_t MAX_HEADER_COUNT  = 200;

std::map<std::string,std::string>
parse_headers(const std::string& header_block,
              std::string& request_line,
              bool& error)
{
    error = false;

    if (header_block.size() > MAX_HEADER_TOTAL) {
        error = true;
        return {};
    }

    std::istringstream ss(header_block);
    std::string line;
    bool first = true;
    size_t header_count = 0;

    std::map<std::string,std::string> headers;

    while (std::getline(ss, line)) {

        if (!line.empty() && line.back() == '\r')
            line.pop_back();

        if (line.size() > MAX_HEADER_LINE) {
            error = true;
            return {};
        }

        // CR/LF 混入チェック
        if (line.find('\r') != std::string::npos ||
            line.find('\n') != std::string::npos) {
            error = true;
            return {};
            }

        if (first) {
            if (line.empty()) {
                error = true;
                return {};
            }
            request_line = line;
            first = false;
            continue;
        }

        if (line.empty())
            break;

        header_count++;
        if (header_count > MAX_HEADER_COUNT) {
            error = true;
            return {};
        }

        auto pos = line.find(':');
        if (pos == std::string::npos) {
            error = true;
            return {};
        }

        std::string k = line.substr(0, pos);
        std::string v = line.substr(pos + 1);

        while (!k.empty() && isspace((unsigned char)k.back()))
            k.pop_back();

        while (!v.empty() && isspace((unsigned char)v.front()))
            v.erase(v.begin());

        if (k.empty()) {
            error = true;
            return {};
        }

        std::transform(k.begin(), k.end(), k.begin(), ::tolower);

        headers[k] = v;
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


void init_openssl() {
    OPENSSL_init_ssl(OPENSSL_INIT_SSL_DEFAULT, nullptr);
    OSSL_PROVIDER_load(nullptr,"base");
    OSSL_PROVIDER_load(nullptr, "default");
    OSSL_PROVIDER_load(nullptr, "legacy");
}

int SSLHelper::Main(ServerContext& ctx2, int port) {
    terminal term;
    
    sockets_init_once();
#ifdef _WIN32
    const char* cert_file = R"(.\dummy-certs\server.crt)";
    const char* key_file = R"(.\dummy-certs\server.key)";
    const char* cert_nwc_file = R"(.\dummy-certs\nwc.crt)";
#else
    const char* cert_file = "/etc/ssl/certs/server.crt";
    const char* key_file = "/etc/ssl/private/server.key";
    const char* cert_nwc_file = "/etc/ssl/certs/nwc.crt";
#endif

     term << "[https][" << port << "] Starting server on port " << port << std::endl;

    init_openssl();



    // ★ここ：SSLv3ハンドシェイク処理は維持（消さない）
    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        std::cerr << "SSL_CTX_new failed" << std::endl;
        ERR_print_errors_fp(stderr);
        std::cerr << std::flush;
        return 1;
    }
    SSL_CTX_RAII ctx_raii(ctx);
    SSL_CTX_set_quiet_shutdown(ctx, 1);
    SSL_CTX_set_security_level(ctx, 0);
    SSL_CTX_set_min_proto_version(ctx, SSL3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, SSL3_VERSION);

    term << "[https][" << port << "] Initializing OpenSSL: ok" << std::endl;

    if (!SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM)) {
        term << "[https][" << port << "] Initializing server.crt: Failed to initialize server.crt" << std::endl;
        std::cerr << "Certificate/key load failed1" << std::endl;
        ERR_print_errors_fp(stderr);
        std::cerr << std::flush;
        return 1;
    }

    term << "[https][" << port << "] Initializing server.crt: ok" << std::endl;

    if (!SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM)) {
        term << "[https][" << port << "] Initializing server.key: Failed to initialize server.key" << std::endl;
        std::cerr << "Certificate/key load failed2" << std::endl;
        ERR_print_errors_fp(stderr);
        std::cerr << std::flush;
        return 1;
    }

    term << "[https][" << port << "] Initializing server.key: ok" << std::endl;

    auto handle = fopen(cert_nwc_file, "r");
    if (!handle) {
        term << "[https][" << port << "] Initializing nwc.crt: file not found" << std::endl;
        term << "[https][" << port << "] Certificate file open failed: " << cert_nwc_file << ", Unable to start application" << std::endl;
        return 1;
    }

    X509* chain_cert = PEM_read_X509(handle, nullptr, nullptr, nullptr);
    if (!chain_cert || SSL_CTX_add_extra_chain_cert(ctx, chain_cert) != 1) {
        if (chain_cert) {
            X509_free(chain_cert);
        }
        term << "[https][" << port << "] Initializing nwc.crt: Failed to load nwc.crt(openssl fault) " << std::endl;
        term << "Certificate/key load failed2" << std::endl;
        ERR_print_errors_fp(stderr);
        std::cerr << std::flush;
        fclose(handle);
        return 1;
    }

    fclose(handle);

    term << "[https][" << port << "] Initializing nwc.crt: ok" << std::endl;

    if (!SSL_CTX_set_cipher_list(ctx, "RC4-SHA:RC4-MD5")) {
        term << "[https][" << port << "] Initializing Cipher: error" << std::endl;
        term << "Failed to set cipher list" << std::endl;
        ERR_print_errors_fp(stderr);
        std::cerr << std::flush;
        return 1;
    }

    term << "[https][" << port << "] Initializing Cipher: ok" << std::endl;

    // socket setup
    socket_t sock = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sock == kInvalidSocket) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    sockaddr_in addr {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)port);

    term << "[https][" << port << "] Initializing socket: ok" << std::endl;



    if (bind(sock, (sockaddr*)&addr, sizeof(addr)) != 0) {
        term << "[https][" << port << "] Binding socket: error" << std::endl;
        perror("bind"); socket_close(sock); return 1;
    }

    if (listen(sock, 8) != 0) {
        term << "[https][" << port << "] Listening on port " << port << ": error" << std::endl;
        perror("listen"); socket_close(sock); return 1;
    }
    term << "[https][" << port << "] Listening on port " << port << ": ok (SSLv3 + RC4)" << std::endl;

    if (ctx2.https_sock == kInvalidSocket) {
        ctx2.https_sock = sock;
    }

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

        SSL* ssl = SSL_new(ctx);
        if (!ssl) { socket_close(client); continue; }
        SSL_RAII ssl_raii(ssl);

        SSL_set_fd(ssl, (int)client);

        // ★ここ：SSLv3ハンドシェイク（SSL_accept）も維持
        if (SSL_accept(ssl) <= 0) {
            term << "[https][" << port << "] Accepted connection... SSL handshake: error" << std::endl;
            term << "[https][" << port << "] SSL_accept failed" << std::endl;
            ERR_print_errors_fp(stderr);
            std::cerr << std::flush;
            socket_close(client);
            continue;
        }
        term << "[https][" << port << "] Accepted connection... SSL handshake: ok" << std::endl;

        bool error = false;
        std::string leftover_body;
        std::string header_block = read_until_double_crlf(ssl, leftover_body, error);
        if (error || leftover_body.empty()) {
            SSL_shutdown(ssl);
            socket_close(client);
            continue;
        }

        std::string req_line;
        bool perr = false;
        auto headers = parse_headers(header_block, req_line, perr);

        if (perr) {
            SSL_shutdown(ssl);
            socket_close(client);
            continue;
        }

        // if Content-Length exists, read more (100MB制限 + 例外対策)
        size_t content_len = 0;
        auto it = headers.find("content-length");
        std::vector<uint8_t> bodyv;

        if (it != headers.end()) {
            try {
                unsigned long long v = std::stoull(it->second);
                if (v > static_cast<unsigned long long>(MAX_BODY_BYTES)) {
                    std::cerr << "[https][" << port << "] Body too large: " << v << " bytes" << std::endl;
                    SSL_shutdown(ssl);
                    socket_close(client);
                    continue;
                }
                if (v > std::numeric_limits<size_t>::max()) {
                    std::cerr << "[https][" << port << "] Content-Length out of range\n";
                    SSL_shutdown(ssl);
                    socket_close(client);
                    continue;
                }
                content_len = (size_t)v;
            } catch (...) {
                std::cerr << "[https][" << port << "] Invalid Content-Length" << std::endl;
                content_len = 0;
                SSL_shutdown(ssl);
                socket_close(client);
                continue;
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

        if (!resp.empty()) {
            // send in controlled chunks
            ssl_write_split(ssl, resp);
        }
        SSL_shutdown(ssl);
        socket_close(client);
    }

    socket_close(sock);
    return 0;
}
