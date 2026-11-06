#pragma once

#include "Config.h"
#include "wob_comm.h"

#include <cstdint>

#if HACDBG_COMM_WOB
bool wobExchange(std::uint32_t kind, void* body, std::uint32_t bodyBytes);
#endif
