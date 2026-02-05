//
// Created by owner on 2026/02/05.
//

#include "dns.h"

#include "ServerContext.h"
#include "sockets.h"
#include "terminal.h"

struct ServerContext;

static bool ends_with_domain_ci(const std::string& name, const std::string& suffix) {
    auto lower = [](std::string s){
        std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return (char)std::tolower(c); });
        return s;
    };
    std::string n = lower(name);
    std::string s = lower(suffix);
    if (n == s) return true;
    if (n.size() <= s.size()) return false;
    if (n.compare(n.size() - s.size(), s.size(), s) != 0) return false;
    return n[n.size() - s.size() - 1] == '.';
}

static bool dns_read_u16(const std::vector<uint8_t>& msg, size_t& off, uint16_t& out) {
    if (off + 2 > msg.size()) return false;
    out = (uint16_t)((msg[off] << 8) | msg[off + 1]);
    off += 2;
    return true;
}

static void dns_write_u16(std::vector<uint8_t>& out, uint16_t v) {
    out.push_back((uint8_t)((v >> 8) & 0xFF));
    out.push_back((uint8_t)(v & 0xFF));
}

static void dns_write_u32(std::vector<uint8_t>& out, uint32_t v) {
    out.push_back((uint8_t)((v >> 24) & 0xFF));
    out.push_back((uint8_t)((v >> 16) & 0xFF));
    out.push_back((uint8_t)((v >> 8) & 0xFF));
    out.push_back((uint8_t)(v & 0xFF));
}

// 圧縮ポインタ対応でQNAMEを読む（最小実装）
static bool dns_read_name(const std::vector<uint8_t>& msg, size_t& off, std::string& out_name) {
    out_name.clear();
    size_t i = off;
    bool jumped = false;
    size_t jump_back = 0;
    int guard = 0;

    while (true) {
        if (i >= msg.size()) return false;
        uint8_t len = msg[i];

        if ((len & 0xC0) == 0xC0) {
            if (i + 1 >= msg.size()) return false;
            uint16_t ptr = (uint16_t)(((len & 0x3F) << 8) | msg[i + 1]);
            if (ptr >= msg.size()) return false;
            if (!jumped) {
                jump_back = i + 2;
                jumped = true;
            }
            i = ptr;
            if (++guard > 32) return false; // ループ保護
            continue;
        }

        if (len == 0) {
            i += 1;
            break;
        }

        if (i + 1 + len > msg.size()) return false;
        if (!out_name.empty()) out_name.push_back('.');
        out_name.append(reinterpret_cast<const char*>(&msg[i + 1]), reinterpret_cast<const char*>(&msg[i + 1 + len]));
        i += 1 + len;

        if (++guard > 256) return false;
    }

    off = jumped ? jump_back : i;
    return true;
}

static std::vector<uint8_t> build_dns_response_a(
    const std::vector<uint8_t>& req,
    bool match,
    uint32_t a_ipv4_be,   // 例: inet_addr("192.168.0.37") の戻り値（ネットワークバイトオーダ）
    uint32_t ttl_sec = 60
) {
    // req header: 12 bytes
    if (req.size() < 12) return {};
    uint16_t id = (uint16_t)((req[0] << 8) | req[1]);
    uint16_t flags = (uint16_t)((req[2] << 8) | req[3]);
    uint16_t qd = (uint16_t)((req[4] << 8) | req[5]);

    // RDをコピー、QR=1、RA=1。非該当はNXDOMAINにする
    uint16_t rd = (flags & 0x0100);
    uint16_t rcode = match ? 0 : 3; // 0=NOERROR, 3=NXDOMAIN
    uint16_t resp_flags = (uint16_t)(0x8000 | rd | 0x0080 | rcode); // QR | RD | RA | RCODE

    std::vector<uint8_t> out;
    out.reserve(512);

    dns_write_u16(out, id);
    dns_write_u16(out, resp_flags);
    dns_write_u16(out, 1);                 // QDCOUNT=1（1問だけ想定）
    dns_write_u16(out, (uint16_t)(match ? 1 : 0)); // ANCOUNT
    dns_write_u16(out, 0);                 // NSCOUNT
    dns_write_u16(out, 0);                 // ARCOUNT

    // 質問部をそのままコピー（最小実装：最初の質問のみ）
    size_t off = 12;
    std::string qname;
    size_t qname_start = off;
    if (!dns_read_name(req, off, qname)) return {};
    uint16_t qtype = 0, qclass = 0;
    if (!dns_read_u16(req, off, qtype)) return {};
    if (!dns_read_u16(req, off, qclass)) return {};

    // reqの質問部(生バイト)をコピー
    out.insert(out.end(), req.begin() + 12, req.begin() + off);

    if (!match) return out;

    // Answer: NAMEは圧縮ポインタで質問のNAMEへ（先頭質問のNAMEはヘッダ直後=0x000c想定）
    // ※qname_start は基本 12。念のため out 側のNAME先頭に向けるなら 0xC00C でOK
    (void)qname_start;
    dns_write_u16(out, 0xC00C);   // NAME = pointer to offset 12
    dns_write_u16(out, 1);        // TYPE = A
    dns_write_u16(out, 1);        // CLASS = IN
    dns_write_u32(out, ttl_sec);  // TTL
    dns_write_u16(out, 4);        // RDLENGTH
    // RDATA IPv4
    out.push_back((uint8_t)((a_ipv4_be >> 0) & 0xFF));
    out.push_back((uint8_t)((a_ipv4_be >> 8) & 0xFF));
    out.push_back((uint8_t)((a_ipv4_be >> 16) & 0xFF));
    out.push_back((uint8_t)((a_ipv4_be >> 24) & 0xFF));
    return out;
}

void dns::run_dns_server_udp_53(ServerContext& ctx,const std::string& spoof_ip_v4, const std::string& suffix = "nintendowifi.net"){
    sockets_init_once();

    terminal term;

    socket_t s = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (s == kInvalidSocket) { perror("dns socket"); return; }

    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    ctx.dns_sock = s;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(53);

    if (bind(s, (sockaddr*)&addr, sizeof(addr)) != 0) {
        perror("dns bind");
        socket_close(s);
        return;
    }

    uint32_t ip_be = 0;
#ifdef _WIN32
    ip_be = ::inet_addr(spoof_ip_v4.c_str()); // network byte order
#else
    ip_be = ::inet_addr(spoof_ip_v4.c_str());
#endif
    if (ip_be == 0 || ip_be == 0xFFFFFFFFu) {
        std::cerr << "DNS: invalid IPv4: " << spoof_ip_v4 << "\n";
        socket_close(s);
        return;
    }

    term << "[dns] DNS (UDP) listening on :53, spoof *." << suffix << " -> " << spoof_ip_v4 << "\n";

    while (true) {
        uint8_t buf[512];
        sockaddr_in peer{};
#ifdef _WIN32
        int plen = sizeof(peer);
#else
        socklen_t plen = sizeof(peer);
#endif
        int n = recvfrom(s, (char*)buf, (int)sizeof(buf), 0, (sockaddr*)&peer, &plen);
        if (n <= 0) {
            if (ctx.stop.load()) break;
            continue;
        }
        if (ctx.stop.load()) {
            socket_close(s);
            break;
        }

        std::vector<uint8_t> req(buf, buf + n);

        // パースして「最初の質問のQNAME」が suffix にマッチするかだけ判定
        bool match = false;
        if (req.size() >= 12) {
            size_t off = 12;
            std::string qname;
            if (dns_read_name(req, off, qname)) {
                uint16_t qtype = 0, qclass = 0;
                if (dns_read_u16(req, off, qtype) && dns_read_u16(req, off, qclass)) {
                    // A(1) の IN(1) だけ返す（他はNXDOMAIN扱いでもOKだが、まずはシンプルに）
                    if (qtype == 1 && qclass == 1 && ends_with_domain_ci(qname, suffix)) {
                        match = true;
                    }
                }
            }
        }

        if (!match) {
            // 無応答
            continue;
        }

        term << "[dns] DNS matched, returning " <<  spoof_ip_v4 << "..." << std::endl;

        auto resp = build_dns_response_a(req, match, ip_be, 60);
        if (resp.empty()) continue;

        sendto(s, (const char*)resp.data(), (int)resp.size(), 0, (sockaddr*)&peer, plen);
    }

    // unreachable
    // socket_close(s);
}