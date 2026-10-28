#pragma once

#include <QWidget>

#include <hacdbg_core_api.h>

#include <cstdint>
#include <vector>

class QStandardItemModel;
class QTableView;

class BreakpointView : public QWidget
{
    Q_OBJECT

public:
    explicit BreakpointView(QWidget* parent = nullptr);

    void setBreakpoints(const HACDBG_CORE_BREAKPOINT* breakpoints, std::uint32_t count);

signals:
    void addressActivated(quint64 address, quint64 cr3);

private:
    QTableView* m_table = nullptr;
    QStandardItemModel* m_model = nullptr;
    std::vector<HACDBG_CORE_BREAKPOINT> m_rows;
};
