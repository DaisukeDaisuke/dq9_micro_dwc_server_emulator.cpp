// main.cpp — minimal DQ9-compatible TLS+HTTP server (single file)
// build with: cmake, ensure OpenSSL points to your 0.9.8 install at build time

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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>


static void run_http_server(int port) {
    int sock = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("http socket"); return; }

    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(sock, (sockaddr*)&addr, sizeof(addr)) != 0) {
        perror("http bind");
        close(sock);
        return;
    }
    if (listen(sock, 8) != 0) {
        perror("http listen");
        close(sock);
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
        int client = accept(sock, nullptr, nullptr);
        if (client < 0) continue;

        char buf[1024];
        recv(client, buf, sizeof(buf), 0); // 読み捨て

        send(client, resp, sizeof(resp) - 1, 0);
        close(client);
    }
}


static const int DEFAULT_PORT = 443;
static const size_t RECV_BUF = 8192;
static const size_t SEND_CHUNK = 768; // tuneable: 512..1024

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

static std::vector<uint8_t> make_response_bytes(int status, const std::string& reason,
    const std::map<std::string,std::string>& headers, const std::vector<uint8_t>& body) {

    std::ostringstream ss;
    ss << "HTTP/1.1 " << status << " " << reason << "\r\n";
    for (const auto &kv : headers) {
        ss << kv.first << ": " << kv.second << "\r\n";
    }
    ss << "\r\n";
    std::string head = ss.str();
    std::vector<uint8_t> out;
    out.insert(out.end(), head.begin(), head.end());
    out.insert(out.end(), body.begin(), body.end());
    return out;
}

// Minimal handler: mimic server_v3.py behaviour for /download endpoints and login
static void handle_request(const std::string& request_line,
    const std::map<std::string,std::string>& headers,
    const std::vector<uint8_t>& body,
    std::vector<uint8_t>& out_resp) {

    // Very small router based on host header
    auto it = headers.find("host");
    std::string host = (it==headers.end() ? "" : it->second);
    std::string host_only = host;
    auto pos = host_only.find(':'); if (pos!=std::string::npos) host_only = host_only.substr(0,pos);
    std::string method, path, httpv;
    {
        std::istringstream ss(request_line);
        ss >> method >> path >> httpv;
    }

    // Very simplified: if Host==nas.nintendowifi.net => return LOGIN like python
    if (host_only == "nas.nintendowifi.net") {
        // parse body (very naive)
        std::string sbody(body.begin(), body.end());
        if (sbody.find("action=login") != std::string::npos || sbody.find("action=LOGIN") != std::string::npos) {
            std::string b = "returncd=...&date=20100101000000&retry=0";
            std::map<std::string,std::string> h;
            h["Content-Length"] = std::to_string(b.size());
            h["Date"] = "Fri, 01 Jan 2010 00:00:00 GMT";
            std::vector<uint8_t> bodyv(b.begin(), b.end());
            out_resp = make_response_bytes(200, "OK", h, bodyv);
            return;
        }
    } else if (host_only == "dls1.nintendowifi.net") {
        // if path starts with /download and action=list -> return small listing
        if (path.rfind("/download",0) == 0) {
            std::string sbody(body.begin(), body.end());
            if (sbody.find("action=list")!=std::string::npos || sbody.find("action=LIST")!=std::string::npos) {
                std::string lines = "output.bin\t\taction\t\t0\r\n";
                std::map<std::string,std::string> h;
                h["Content-type"] = "text/plain";
                h["Content-Length"] = std::to_string(lines.size());
                std::vector<uint8_t> bodyv(lines.begin(), lines.end());
                out_resp = make_response_bytes(200, "OK", h, bodyv);
                return;
            }
            if (sbody.find("action=contents")!=std::string::npos) {
                // return file (ensure file exists at ./dlc/output.bin)
                std::ifstream ifs("dlc/output.bin", std::ios::binary);
                std::vector<uint8_t> filev;
                if (ifs) {
                    filev.assign( (std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>() );
                    std::map<std::string,std::string> h;
                    h["Content-type"] = "application/x-dsdl";
                    h["Content-Length"] = std::to_string(filev.size());
                    out_resp = make_response_bytes(200, "OK", h, filev);
                    return;
                }
            }
        }
    }

    // default
    std::string d = "err";
    std::map<std::string,std::string> h;
    h["Content-Length"] = std::to_string(d.size());
    std::vector<uint8_t> bodyv(d.begin(), d.end());
    out_resp = make_response_bytes(404, "Not Found", h, bodyv);
}

int main(int argc, char** argv) {
    const char* cert_file = "/etc/ssl/certs/server.crt";
    const char* key_file = "/etc/ssl/private/server.key";
    const char* cert_nwc_file = "/etc/ssl/certs/nwc.crt";
    int port = DEFAULT_PORT;

    std::thread http_thread(run_http_server, 80);
    http_thread.detach();

    if (argc >= 2) port = std::stoi(argv[1]);

    std::cerr << "Starting server on port " << port << "\n";

    init_openssl();
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

    std::cerr << "init2\n";

    if (SSL_CTX_add_extra_chain_cert(
        ctx,
        PEM_read_X509(fopen(cert_nwc_file, "r"), nullptr, nullptr, nullptr)
    ) != 1) {
        std::cerr << "Certificate/key load failed2\n";
        ERR_print_errors_fp(stderr);
        return 1;
    }

    std::cerr << "init3\n";

    if (!SSL_CTX_set_cipher_list(ctx, "RC4-SHA:RC4-MD5")) {
        std::cerr << "Failed to set cipher list\n";
        ERR_print_errors_fp(stderr);
        return 1;
    }

    // socket setup
    int sock = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); return 1; }
    int opt = 1; setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(sock, (sockaddr*)&addr, sizeof(addr)) != 0) { perror("bind"); close(sock); return 1; }
    if (listen(sock, 8) != 0) { perror("listen"); close(sock); return 1; }
    std::cerr << "Listening on port " << port << " (SSLv3 + RC4)\n";

    while (true) {
        sockaddr_in peer{};
        socklen_t plen = sizeof(peer);
        int client = accept(sock, (sockaddr*)&peer, &plen);
        if (client < 0) { perror("accept"); continue; }
        std::cerr << "Accepted connection\n";

        SSL* ssl = SSL_new(ctx);
        if (!ssl) { close(client); continue; }
        SSL_RAII ssl_raii(ssl);

        SSL_set_fd(ssl, client);
        if (SSL_accept(ssl) <= 0) {
            std::cerr << "SSL_accept failed\n";
            ERR_print_errors_fp(stderr);
            close(client);
            continue;
        }
        std::cerr << "SSL handshake ok\n";

        std::string leftover_body;
        std::string header_block = read_until_double_crlf(ssl, leftover_body);
        std::string req_line;
        auto headers = parse_headers(header_block, req_line);

        std::cerr << "Request: " << header_block << "\n";

        // if Content-Length exists, read more
        size_t content_len = 0;
        auto it = headers.find("content-length");
        std::vector<uint8_t> bodyv;
        if (it != headers.end()) {
            content_len = std::stoul(it->second);
            size_t have = leftover_body.size();
            bodyv.assign(leftover_body.begin(), leftover_body.end());
            while (bodyv.size() < content_len) {
                std::vector<char> tmp(RECV_BUF);
                int r = SSL_read(ssl, tmp.data(), (int)tmp.size());
                if (r <= 0) break;
                bodyv.insert(bodyv.end(), tmp.data(), tmp.data()+r);
            }
        }

        // handle
        std::vector<uint8_t> resp;
        handle_request(req_line, headers, bodyv, resp);

        // send in controlled chunks
        ssl_write_split(ssl, resp);

        // orderly shutdown: two-phase
        SSL_shutdown(ssl); // send close_notify
        // shutdown write side of socket to provoke peer close_notify
        shutdown(client, SHUT_WR);
        // try second shutdown to receive peer's close_notify
        SSL_shutdown(ssl);

        close(client);
    }

    close(sock);
    return 0;
}

