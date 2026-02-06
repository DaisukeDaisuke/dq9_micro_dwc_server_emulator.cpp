//
// Created by owner on 2026/02/06.
//

#ifndef DQ9_SERVER_SAFETY_H
#define DQ9_SERVER_SAFETY_H
#include <string>


class Safety {
public:
    static bool contains_ctl_or_nul(const std::string& s);
};


#endif //DQ9_SERVER_SAFETY_H