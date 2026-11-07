#pragma once

#include "kernel_minifilter.h"

bool minifilterDriverQuery(HACDBG_MINIFILTER_REQUEST* request);
bool minifilterDriverOperate(unsigned int operation, unsigned long long filter, HACDBG_MINIFILTER_REQUEST* request,
                             int* status);
