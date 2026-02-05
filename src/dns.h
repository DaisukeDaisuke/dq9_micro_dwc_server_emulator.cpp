//
// Created by owner on 2026/02/05.
//

#ifndef DQ9_SERVER_DNS_H
#define DQ9_SERVER_DNS_H

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
#include <cstdint>

class dns {
public:
    static void run_dns_server_udp_53(const std::string &spoof_ip_v4, const std::string &suffix);
};


#endif //DQ9_SERVER_DNS_H