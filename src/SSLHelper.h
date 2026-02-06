//
// Created by owner on 2026/02/05.
//

#ifndef DQ9_SERVER_SSLHELPER_H
#define DQ9_SERVER_SSLHELPER_H
#include "ServerContext.h"


class SSLHelper {
public:
    static int Main(ServerContext& ctx2, int port);
};


#endif //DQ9_SERVER_SSLHELPER_H