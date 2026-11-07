#pragma once

#include "kernel_timer.h"

bool timerDriverQuery(HACDBG_TIMER_REQUEST* request);
bool timerDriverRemove(unsigned int type, unsigned long long timer, int* status);
