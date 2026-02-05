//
// Created by owner on 2026/02/05.
//

#ifndef DQ9_SERVER_HTTPHELPER_H
#define DQ9_SERVER_HTTPHELPER_H

struct ServerContext;

class HTTPHelper {
    public:
        static void run_http_server(ServerContext& ctx, int port);
};


#endif //DQ9_SERVER_HTTPHELPER_H