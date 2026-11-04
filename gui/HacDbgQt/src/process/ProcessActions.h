#pragma once

#include "ProcessRecord.h"

#include <QWidget>

#include <functional>

void showProcessMenu(QWidget* parent, const ProcessRecord& record, const std::function<void()>& dumpRequested,
                     const std::function<void(std::uint32_t)>& protectRequested);
