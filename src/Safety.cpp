//
// Created by owner on 2026/02/06.
//

#include "Safety.h"

bool Safety::contains_ctl_or_nul(const std::string& s) {
    for (unsigned char c : s) {
        if (c == '\0' || c < 0x20 || c == 0x7F) {
            return true;
        }
    }
    return false;
}
