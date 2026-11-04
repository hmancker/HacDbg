#pragma once

#include <QString>

#include <cstdint>

struct ProcessRecord
{
    std::uint64_t eprocess = 0;
    std::uint64_t pid = 0;
    std::uint64_t parentPid = 0;
    std::uint64_t cr3 = 0;
    QString image;
};
