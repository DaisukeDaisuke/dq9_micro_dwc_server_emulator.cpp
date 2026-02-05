//
// Created by owner on 2026/02/05.
//

#ifndef DQ9_SERVER_FILEHELPER_H
#define DQ9_SERVER_FILEHELPER_H
#include <string>


class FileHelper {
public:
    static std::string readAll(const std::string &path);
};


#endif //DQ9_SERVER_FILEHELPER_H