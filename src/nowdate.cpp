//
// Created by owner on 2026/02/06.
//

#include "nowdate.h"

#include <chrono>
#include <format>
#include <string>

std::string nowdate::get_current_time_rfc1123() {
    using namespace std::chrono;

    // 現在時刻をUTCで取得
    auto now = system_clock::now();
    auto now_time_t = system_clock::to_time_t(now);

    // UTC時刻に変換
    std::tm tm_utc;
#ifdef _WIN32
    gmtime_s(&tm_utc, &now_time_t);
#else
    gmtime_r(&now_time_t, &tm_utc);
#endif

    // RFC 1123形式でフォーマット
    // 曜日と月の配列
    static const char* weekdays[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
    static const char* months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

    return std::format("{}, {:02d} {} {:04d} {:02d}:{:02d}:{:02d} GMT",
                       weekdays[tm_utc.tm_wday],
                       tm_utc.tm_mday,
                       months[tm_utc.tm_mon],
                       tm_utc.tm_year + 1900,
                       tm_utc.tm_hour,
                       tm_utc.tm_min,
                       tm_utc.tm_sec);
}