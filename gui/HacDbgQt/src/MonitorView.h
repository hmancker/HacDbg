#pragma once

#include <QWidget>

#include <hacdbg_core_api.h>

#include <cstdint>
#include <vector>

class CoreSession;
class MonitorLogModel;
class QLabel;
class QListView;
class QTableWidget;
class RegisterView;

class MonitorView : public QWidget
{
    Q_OBJECT

public:
    explicit MonitorView(QWidget* parent = nullptr);

    void setSession(CoreSession* session);
    void poll();

signals:
    void addressActivated(quint64 address, quint64 cr3);

private:
    bool nearBottom() const;
    void showSelected();
    void updateStatus();
    void clearLog();

    CoreSession* m_session = nullptr;
    QLabel* m_status = nullptr;
    QListView* m_log = nullptr;
    MonitorLogModel* m_model = nullptr;
    RegisterView* m_registers = nullptr;
    QTableWidget* m_stack = nullptr;
    std::vector<HACDBG_CORE_MONITOR_HIT> m_copy;
};
