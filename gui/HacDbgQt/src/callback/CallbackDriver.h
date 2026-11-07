#pragma once

#include "kernel_callback.h"

bool callbackDriverQuery(HACDBG_CALLBACK_REQUEST* request);
bool callbackDriverEdit(unsigned int operation, unsigned int type, unsigned long long entry, unsigned long long extra,
                        int* status);
