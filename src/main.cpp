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

// ... existing code ...

static void run_http_server(int port) {
    sockets_init_once();

    socket_t sock = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sock == kInvalidSocket) { perror("http socket"); return; }

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
        if (client == kInvalidSocket) continue;

        char buf[1024];
        recv(client, buf, (int)sizeof(buf), 0); // 読み捨て

        send(client, resp, (int)(sizeof(resp) - 1), 0);
        socket_close(client);
    }
}
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


static const int DEFAULT_PORT = 443;
static const size_t RECV_BUF = 8192;
static const size_t SEND_CHUNK = 768; // tuneable: 512..1024 通らないなら1024にする
static const size_t MAX_BODY_BYTES = 5u * 1024u * 1024u; // 100MB上限


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

std::string readAll(const std::string& path) {
    std::ifstream ifs(path, std::ios::in);
    if (!ifs) {
        return {};
    }

    std::ostringstream oss;
    oss << ifs.rdbuf();
    return oss.str();
}

bool base64_decode_star_as_pad(const std::string& input, std::string& output) {
    static const int8_t table[256] = {
        -1
    };

    static bool table_initialized = false;
    static int8_t decode_table[256];

    if (!table_initialized) {
        for (int i = 0; i < 256; ++i) decode_table[i] = -1;
        for (char c = 'A'; c <= 'Z'; ++c) decode_table[static_cast<uint8_t>(c)] = c - 'A';
        for (char c = 'a'; c <= 'z'; ++c) decode_table[static_cast<uint8_t>(c)] = c - 'a' + 26;
        for (char c = '0'; c <= '9'; ++c) decode_table[static_cast<uint8_t>(c)] = c - '0' + 52;
        decode_table[static_cast<uint8_t>('+')] = 62;
        decode_table[static_cast<uint8_t>('/')] = 63;
        table_initialized = true;
    }

    std::vector<uint8_t> buf;
    buf.reserve(input.size() * 3 / 4);

    int val = 0;
    int valb = -8;

    for (unsigned char c : input) {
        if (c == '*') {
            c = '='; // '*' を '=' として扱う
        }

        if (c == '=') {
            break;
        }

        int8_t d = decode_table[c];
        if (d == -1) {
            return false; // 不正な文字
        }

        val = (val << 6) + d;
        valb += 6;
        if (valb >= 0) {
            buf.push_back(static_cast<uint8_t>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }

    output.assign(buf.begin(), buf.end());
    return true;
}

#include <string>
#include <vector>

std::string base64_encode_replace(const std::string& input) {
    static const char table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    std::string output;
    output.reserve(((input.size() + 2) / 3) * 4);

    size_t i = 0;
    const size_t len = input.size();

    while (i < len) {
        size_t remain = len - i;

        uint32_t octet_a = static_cast<unsigned char>(input[i++]);
        uint32_t octet_b = remain > 1 ? static_cast<unsigned char>(input[i++]) : 0;
        uint32_t octet_c = remain > 2 ? static_cast<unsigned char>(input[i++]) : 0;

        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        output.push_back(table[(triple >> 18) & 0x3F]);
        output.push_back(table[(triple >> 12) & 0x3F]);

        if (remain > 1)
            output.push_back(table[(triple >> 6) & 0x3F]);
        else
            output.push_back('*');

        if (remain > 2)
            output.push_back(table[triple & 0x3F]);
        else
            output.push_back('*');
    }

    return output;
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

bool isValidGameCd(const std::string& gamecd) {
    if (gamecd.empty()) {
        return false;
    }

    for (unsigned char c : gamecd) {
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))) {
            return false;
        }
    }

    return true;
}

std::string extract_and_decode_param(
    const std::string& sbody,
    const std::string& key_name
) {
    const std::string key = key_name + "=";

    auto pos = sbody.find(key);
    if (pos == std::string::npos) {
        return {};
    }

    auto start = pos + key.size();
    auto end = sbody.find('&', start);

    std::string encoded = sbody.substr(
        start,
        end == std::string::npos ? std::string::npos : end - start
    );

    if (encoded.empty()) {
        return {};
    }

    // %2a / %2A を * に置換（Base64デコード前処理）
    {
        std::string::size_type p = 0;
        while ((p = encoded.find("%2a", p)) != std::string::npos) {
            encoded.replace(p, 3, "*");
            p += 1;
        }
        p = 0;
        while ((p = encoded.find("%2A", p)) != std::string::npos) {
            encoded.replace(p, 3, "*");
            p += 1;
        }
    }

    std::string decoded;
    if (!base64_decode_star_as_pad(encoded, decoded)) {
        return {};
    }

    return decoded;
}

// 追加：CR終端っぽいレコードを「split(\r) -> trim(\r,\n) -> join(\r\n)」で正規化
static inline bool is_crlf_char(uint8_t c) {
    return c == '\r' || c == '\n';
}

static std::vector<uint8_t> normalize_records_cr_terminated(
    const std::vector<uint8_t>& in,
    bool keep_empty_lines = false
) {
    std::vector<uint8_t> out;
    out.reserve(in.size() + 2);

    auto flush_record = [&](size_t b, size_t e) {
        while (b < e && is_crlf_char(in[b])) ++b;
        while (e > b && is_crlf_char(in[e - 1])) --e;

        const bool empty = (b >= e);
        if (empty && !keep_empty_lines) return;

        out.insert(out.end(), in.begin() + (ptrdiff_t)b, in.begin() + (ptrdiff_t)e);
        out.push_back('\r');
        out.push_back('\n');
    };

    size_t start = 0;
    for (size_t i = 0; i < in.size(); ++i) {
        if (in[i] == '\r') {
            flush_record(start, i);
            start = i + 1;
        }
    }
    // 最後が\rで終端していないケースも一応救う（必要なければ消してOK）
    if (start < in.size()) {
        flush_record(start, in.size());
    }

    return out;
}

static std::string normalize_records_cr_terminated(
    const std::string& in,
    bool keep_empty_lines = false
) {
    std::vector<uint8_t> v(in.begin(), in.end());
    auto norm = normalize_records_cr_terminated(v, keep_empty_lines);
    return std::string(norm.begin(), norm.end());
}

static std::size_t count_lines_after_normalize_cr_terminated(const std::string& in) {
    // 正規化後は必ず「1行につき1個の \r\n」を付けるので、行数= "\r\n" の数
    const std::string norm = normalize_records_cr_terminated(in, /*keep_empty_lines=*/false);

    std::size_t count = 0;
    for (size_t i = 0; i + 1 < norm.size(); ++i) {
        if (norm[i] == '\r' && norm[i + 1] == '\n') ++count;
    }
    return count;
}


std::size_t countCRLF(const std::string& data) {
    std::size_t count = 0;
    std::size_t pos = 0;

    while (true) {
        pos = data.find("\r\r", pos);
        if (pos == std::string::npos) {
            break;
        }
        ++count;
        pos += 2; // 重複カウント防止
    }

    return count;
}

bool is_valid_path(const std::string& path) {
    // ".." が含まれていれば不正
    if (path.find("..") != std::string::npos) {
        return false;
    }

    // Windows の場合、バックスラッシュもチェック
    if (path.find('\\') != std::string::npos) {
        return false;
    }

    //「/」も不正
    if (path.find('/') != std::string::npos) {
        return false;
    }

    // 空文字列も無効扱い
    if (path.empty()) {
        return false;
    }

    return true;
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
        std::string sbody(body.begin(), body.end());

        std::string action = extract_and_decode_param(sbody, "action");
        std::string gamecd = extract_and_decode_param(sbody, "gamecd");
        if (action == "login" || action == "LOGIN") {
            std::cerr << "["<< gamecd << "] Processing Login... " << std::endl;
            std::string b =
                    "returncd=" + base64_encode_replace("001") +
                    "&date=" + base64_encode_replace("Fri, 01 Jan 2010 00:00:00 GMT") +
                    "&retry=" + base64_encode_replace("0") +
                    "&locator=" + base64_encode_replace("gamespy.com") +
                    "&challenge=" + base64_encode_replace("RNR1HLAS") +
                    "&token=" + base64_encode_replace(
                        "NDSX0zyY6Wc6SQ6GnvXStABwbFCBjgt+MVQyhs1vMO5qsMnBePlcnGOjjPTcloogWX03yHVP9Q5xnUms8jZUzyd2W9ytWFtlwUOhAcO0x9WfFv2qPNFNr9O0ehktRYRcv89"
                    );

            std::map<std::string, std::string> h;
            h["Content-Length"] = std::to_string(b.size());
            h["Date"] = "Fri, 01 Jan 2010 00:00:00 GMT";
            std::vector<uint8_t> bodyv(b.begin(), b.end());
            out_resp = make_response_bytes(200, "OK", h, bodyv);
            return;
        }
        if (action == "svcloc" || action == "SVCLOC") {
            std::cerr << "request cdn url, game: " << gamecd << std::endl;
            std::string svc = extract_and_decode_param(sbody, "svc");
            std::string b = "returncd=" + base64_encode_replace("007") +
                            "&statusdata=" + base64_encode_replace("Y") +
                            "&retry=" + base64_encode_replace("0") +
                            "&svchost=" + base64_encode_replace("dls1.nintendowifi.net");

            if (svc == "9000") {
                b = b + "&svchost=" + base64_encode_replace(
                        "NDSX0zyY6Wc6SQ6GnvXStABwbFCBjgt+MVQyhs1vMO5qsMnBePlcnGOjjPTcloogWX03yHVP9Q5xnUms8jZUzyd2W9ytWFtlwUOhAcO0x9WfFv2qPNFNr9O0ehktRYRcv89");
            } else {
                b = b + "&servicetoken=" + base64_encode_replace(
                        "NDSX0zyY6Wc6SQ6GnvXStABwbFCBjgt+MVQyhs1vMO5qsMnBePlcnGOjjPTcloogWX03yHVP9Q5xnUms8jZUzyd2W9ytWFtlwUOhAcO0x9WfFv2qPNFNr9O0ehktRYRcv89");
            }

            std::map<std::string, std::string> h;
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
            std::string action = extract_and_decode_param(sbody, "action");
            std::string gamecd = extract_and_decode_param(sbody, "gamecd");

            if (!isValidGameCd(gamecd) || gamecd.empty()) {
                std::string b = "err";
                std::vector<uint8_t> bodyv(b.begin(), b.end());
                std::map<std::string,std::string> h;
                out_resp = make_response_bytes(401, "err", h, bodyv);
                return;
            }

            if (action == "count" || action == "COUNT") {
                std::cerr << "["<< gamecd <<"]sending count..."  << std::endl;

                std::string path = "./dlc/" + gamecd + "/_list.txt";
                std::string data = readAll(path);
                if (data.empty()) {
                    std::string b = "err";
                    std::vector<uint8_t> bodyv(b.begin(), b.end());
                    std::map<std::string,std::string> h;
                    out_resp = make_response_bytes(500, "err", h, bodyv);
                    return;
                }

                std::size_t counts_size = count_lines_after_normalize_cr_terminated(data);
                std::string b = std::to_string(counts_size);  // 件数を文字列化
                std::map<std::string,std::string> h;
                h["Content-type"] = "text/plain";
                h["X-DLS-Host"] = "http://127.0.0.1/";
                h["Content-Length"] = std::to_string(b.size());
                std::vector<uint8_t> bodyv(b.begin(), b.end());
                out_resp = make_response_bytes(200, "OK", h, bodyv);
                return;
            }
            if (action == "LIST" || action == "list") {
                std::string num = extract_and_decode_param(sbody, "num");
                std::string offset = extract_and_decode_param(sbody, "offset");

                std::cerr << "["<< gamecd <<"]sending list... " << std::endl;

                std::string path = "./dlc/" + gamecd + "/_list.txt";
                std::string data = readAll(path);
                if (data.empty()) {
                    std::string b = "err";
                    std::vector<uint8_t> bodyv(b.begin(), b.end());
                    std::map<std::string,std::string> h;
                    out_resp = make_response_bytes(500, "err", h, bodyv);
                    return;
                }

                data = normalize_records_cr_terminated(data, /*keep_empty_lines=*/false);


                std::map<std::string,std::string> h;
                h["Content-type"] = "text/plain";
                h["X-DLS-Host"] = "http://127.0.0.1/";
                h["Content-Length"] = std::to_string(data.size());
                std::vector<uint8_t> bodyv(data.begin(), data.end());
                out_resp = make_response_bytes(200, "OK", h, bodyv);
                return;
            }
            if (action == "CONTENTS" || action == "contents") {
                const std::string contents = extract_and_decode_param(sbody, "contents");
                if (!is_valid_path(contents)) {
                    std::string b = "err";
                    std::vector<uint8_t> bodyv(b.begin(), b.end());
                    std::map<std::string,std::string> h;
                    out_resp = make_response_bytes(400, "err", h, bodyv);
                    return;
                }

                std::cerr << "["<< gamecd <<"]sending " << contents << "..." << std::endl;

                // return file (ensure file exists at ./dlc/output.bin)
                std::string basic_string = "./dlc/" + gamecd + "/" + contents;
                std::ifstream ifs(basic_string, std::ios::binary);
                std::vector<uint8_t> filev;
                if (ifs) {
                    filev.assign( (std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>() );
                    std::map<std::string,std::string> h;
                    h["Content-type"] = "application/x-dsdl";
                    h["Content-Length"] = std::to_string(filev.size());
                    h["X-DLS-Host"] = "http://127.0.0.1/";
                    h["Content-Disposition"] = "attachment; filename=\"" + contents + "\"";
                    out_resp = make_response_bytes(200, "OK", h, filev);
                    return;
                }
                std::string b = "err";
                std::vector<uint8_t> bodyv(b.begin(), b.end());
                std::map<std::string,std::string> h;
                out_resp = make_response_bytes(404, "Not Found", h, bodyv);
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
    sockets_init_once();

#ifdef _WIN32
    const char* cert_file = R"(.\dummy-certs\server.crt)";
    const char* key_file = R"(.\dummy-certs\server.key)";
    const char* cert_nwc_file = R"(.\dummy-certs\nwc.crt)";
    const char* ipconfg = R"(.\ip.txt)";
    int port = DEFAULT_PORT;

#else

    const char* cert_file = "/etc/ssl/certs/server.crt";
    const char* key_file = "/etc/ssl/private/server.key";
    const char* cert_nwc_file = "/etc/ssl/certs/nwc.crt";
    int port = DEFAULT_PORT;
#endif

    std::thread dns_thread(dns::run_dns_server_udp_53, std::string(readAll(ipconfg)), std::string("nintendowifi.net"));
    dns_thread.detach();

    std::thread http_thread(run_http_server, 80);
    http_thread.detach();

    if (argc >= 2) port = std::stoi(argv[1]);

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

    while (true) {
        sockaddr_in peer{};
        socklen_t plen = sizeof(peer);
        socket_t client = accept(sock, (sockaddr*)&peer, &plen);
        if (client == kInvalidSocket) { perror("accept"); continue; }
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
        handle_request(req_line, headers, bodyv, resp);

        // send in controlled chunks
        ssl_write_split(ssl, resp);

        SSL_shutdown(ssl);

        socket_close(client);
    }

    socket_close(sock);
    return 0;
}

