#pragma once

#include <cstdint>

#include "process_control.h"
#include "window_protect.h"
#include "kernel_callback.h"
#include "kernel_filter.h"
#include "kernel_minifilter.h"
#include "kernel_timer.h"

bool kernel_send_process(HACDBG_PROCESS_REQUEST& request);

bool kernel_process_request(std::uint32_t operation, std::uint32_t pid, std::uint32_t parameter, std::uint32_t flags,
                            const wchar_t* path, HACDBG_PROCESS_REQUEST& request_out);

bool kernel_window_request(HACDBG_WINDOW_REQUEST& request);

bool kernel_callback_request(HACDBG_CALLBACK_REQUEST& request);
bool kernel_filter_request(HACDBG_FILTER_REQUEST& request);
bool kernel_minifilter_request(HACDBG_MINIFILTER_REQUEST& request);
bool kernel_timer_request(HACDBG_TIMER_REQUEST& request);
