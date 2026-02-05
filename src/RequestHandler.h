//
// Created by owner on 2026/02/05.
//

#ifndef DQ9_SERVER_REQUESTHANDLER_H
#define DQ9_SERVER_REQUESTHANDLER_H
#include <cstdint>
#include <map>
#include <string>
#include <vector>


class RequestHandler {
public:
    static void handle_request(const std::string &request_line,
                               const std::map<std::string, std::string> &headers,
                               const std::vector<uint8_t> &body,
                               std::vector<uint8_t> &out_resp);
};


#endif //DQ9_SERVER_REQUESTHANDLER_H