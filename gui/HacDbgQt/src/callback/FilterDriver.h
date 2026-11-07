#pragma once

#include "kernel_filter.h"

bool filterDriverQuery(HACDBG_FILTER_REQUEST* request);
bool filterDriverOperate(unsigned int operation, unsigned long long driver, unsigned long long device,
                         unsigned long long host, HACDBG_FILTER_REQUEST* request, int* status);
