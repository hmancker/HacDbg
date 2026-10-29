#pragma once

#include <QString>
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
    void setMonitors(const HACDBG_CORE_MONITOR* monitors, std::uint32_t count);

signals:
    void addressActivated(quint64 address, quint64 cr3);
    void commandRequested(const QString& command);

private:
    struct Activation
    {
        std::uint64_t address = 0;
        std::uint64_t cr3 = 0;
        std::uint64_t id = 0;
        bool breakpoint = false;
        bool enabled = false;
    };

    void rebuild();
    void deleteSelected();

    QTableView* m_table = nullptr;
    QStandardItemModel* m_model = nullptr;
    std::vector<HACDBG_CORE_BREAKPOINT> m_rows;
    std::vector<HACDBG_CORE_MONITOR> m_monitors;
    std::vector<Activation> m_activation;
};
