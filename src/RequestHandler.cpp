//
// Created by owner on 2026/02/05.
//

#include "RequestHandler.h"

#include <fstream>
#include <iostream>
#include <sstream>

#include "FileHelper.h"
#include "terminal.h"


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

// Minimal handler: mimic server_v3.py behaviour for /download endpoints and login
void RequestHandler::handle_request(const std::string& request_line,
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

    terminal term;


    // Very simplified: if Host==nas.nintendowifi.net => return LOGIN like python
    if (host_only == "nas.nintendowifi.net") {
        std::string sbody(body.begin(), body.end());

        std::string action = extract_and_decode_param(sbody, "action");
        std::string gamecd = extract_and_decode_param(sbody, "gamecd");
        if (action == "login" || action == "LOGIN") {
            term << "[https]["<< gamecd << "] Processing Login... " << std::endl;
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
            term << "[https][" << gamecd << "] request cdn url" << std::endl;
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
                 term << "[https]["<< gamecd <<"] sending count..."  << std::endl;

                std::string path = "./dlc/" + gamecd + "/_list.txt";
                std::string data = FileHelper::readAll(path);
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

                 term << "[https]["<< gamecd <<"] sending list... " << std::endl;

                std::string path = "./dlc/" + gamecd + "/_list.txt";
                std::string data = FileHelper::readAll(path);
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

                 term << "[https]["<< gamecd <<"] sending " << contents << "..." << std::endl;

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