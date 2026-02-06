//
// Created by owner on 2026/02/05.
//

#include "FileHelper.h"

#include <fstream>
#include <sstream>
#include <string>

std::string FileHelper::readAll(const std::string& path) {
    std::ifstream ifs(path, std::ios::in);
    if (!ifs) {
        return {};
    }

    std::ostringstream oss;
    oss << ifs.rdbuf();
    return oss.str();
}