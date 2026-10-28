#pragma once

#include "CoreSession.h"

#include <QWidget>

#include <cstdint>
#include <vector>

class QLabel;
class QLineEdit;
class QStandardItemModel;
class QTableView;

class ProcessThreadView : public QWidget
{
    Q_OBJECT

public:
    explicit ProcessThreadView(QWidget* parent = nullptr);

    void setSession(CoreSession* session);
    void refresh();
    void poll();

signals:
    void addressActivated(quint64 address, quint64 cr3);

private:
    struct ProcessItem
    {
        std::uint64_t eprocess = 0;
        std::uint64_t pid = 0;
        std::uint64_t parentPid = 0;
        std::uint64_t cr3 = 0;
        QString image;
    };

    struct ThreadItem
    {
        std::uint64_t tid = 0;
        std::uint64_t pid = 0;
        std::uint64_t rip = 0;
        std::uint64_t cr3 = 0;
        QString state;
        QString image;
        QString mode;
        QString priority;
    };

    bool takeCompleted(std::uint32_t view, std::uint64_t* requestId, HACDBG_CORE_VIEW_STATUS* status);
    void showProcesses();
    void showThreads();
    void requestThreadsForSelection();
    bool matchesProcess(const ProcessItem& item) const;
    bool matchesThread(const ThreadItem& item) const;

    CoreSession* m_session = nullptr;
    QLineEdit* m_processFilter = nullptr;
    QLineEdit* m_threadFilter = nullptr;
    QLabel* m_processStatus = nullptr;
    QLabel* m_threadStatus = nullptr;
    QTableView* m_processes = nullptr;
    QTableView* m_threads = nullptr;
    QStandardItemModel* m_processModel = nullptr;
    QStandardItemModel* m_threadModel = nullptr;
    std::vector<ProcessItem> m_processRows;
    std::vector<ProcessItem> m_visibleProcesses;
    std::vector<ThreadItem> m_threadRows;
    std::vector<ThreadItem> m_visibleThreads;
    std::uint64_t m_processRequest = 0;
    std::uint64_t m_threadRequest = 0;
    std::uint64_t m_selectedEprocess = 0;
};
