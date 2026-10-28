#pragma once

#include "CoreSession.h"

#include <QWidget>

#include <cstdint>
#include <vector>

class QLabel;
class QStandardItemModel;
class QTableView;

class SymbolView : public QWidget
{
    Q_OBJECT

public:
    explicit SymbolView(QWidget* parent = nullptr);

    void setSession(CoreSession* session);
    void refresh();
    void poll();

signals:
    void addressActivated(quint64 address, quint64 cr3);
    void reloadRequested();

private:
    struct Row
    {
        std::uint64_t base = 0;
        QString name;
    };

    bool takeCompleted(HACDBG_CORE_VIEW_STATUS* status);

    CoreSession* m_session = nullptr;
    QTableView* m_table = nullptr;
    QStandardItemModel* m_model = nullptr;
    QLabel* m_status = nullptr;
    std::vector<Row> m_rows;
    std::uint64_t m_request = 0;
};
