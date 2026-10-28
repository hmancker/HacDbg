#pragma once

#include <QWidget>

#include <hacdbg_core_api.h>

#include <cstdint>
#include <vector>

class CoreSession;
class QLabel;
class QStandardItemModel;
class QTableView;

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
    void appendHit(const HACDBG_CORE_MONITOR_HIT& hit);
    void trimRows();
    void updateStatus();

    CoreSession* m_session = nullptr;
    QLabel* m_status = nullptr;
    QTableView* m_table = nullptr;
    QStandardItemModel* m_model = nullptr;
    std::vector<std::uint64_t> m_addresses;
    std::uint64_t m_shown = 0;
    std::uint64_t m_skipped = 0;
    bool m_sizedColumns = false;
};
