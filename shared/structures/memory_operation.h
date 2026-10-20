#pragma once
#ifdef __cplusplus
#include <cstdint>

enum class memory_operation_t : std::uint64_t
{
    read_operation,
    write_operation
};
#else
#define memory_operation_t_READ  0
#define memory_operation_t_WRITE 1
#endif
