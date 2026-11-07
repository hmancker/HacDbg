#pragma once

#include <cstdint>

#include "process_control.h"
#include "window_protect.h"
#include "kernel_callback.h"

bool kernel_send_process(HACDBG_PROCESS_REQUEST& request);

bool kernel_process_request(std::uint32_t operation, std::uint32_t pid, std::uint32_t parameter, std::uint32_t flags,
                            const wchar_t* path, HACDBG_PROCESS_REQUEST& request_out);

bool kernel_window_request(HACDBG_WINDOW_REQUEST& request);

bool kernel_callback_request(HACDBG_CALLBACK_REQUEST& request);
