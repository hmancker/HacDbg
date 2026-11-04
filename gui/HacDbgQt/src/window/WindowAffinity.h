#pragma once

#include <Windows.h>

bool setWindowAntiCapture(HWND window, bool enable);
bool queryWindowAffinity(HWND window, unsigned long* affinity);
unsigned long dwmProcessId();
