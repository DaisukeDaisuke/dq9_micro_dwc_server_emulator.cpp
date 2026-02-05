//
// Created by owner on 2026/02/05.
//

#ifndef DQ9_SERVER_TERMINAL_H
#define DQ9_SERVER_TERMINAL_H
#include <iostream>
#include <syncstream>
#include <sstream>
#include <string_view>

struct terminal {
    template<typename T>
    terminal& operator<<(T&& v) {
        std::osyncstream(std::cout) << std::forward<T>(v);
        return *this;
    }

    // std::endl 等用
    terminal& operator<<(std::ostream& (*manip)(std::ostream&)) {
        std::osyncstream(std::cout) << manip;
        return *this;
    }
};

#endif //DQ9_SERVER_TERMINAL_H