#include "ProcessThreadView.h"

#include "Format.h"

#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSplitter>
#include <QStandardItemModel>
#include <QTableView>
#include <QVBoxLayout>

namespace
{
void prepareTable(QTableView* table)
{
    QFont font(QStringLiteral("Cascadia Mono"));
    font.setStyleHint(QFont::Monospace);
    font.setPointSize(10);
    table->setFont(font);
    table->setShowGrid(false);
    table->setAlternatingRowColors(true);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setSelectionMode(QAbstractItemView::SingleSelection);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->verticalHeader()->hide();
    table->horizontalHeader()->setStretchLastSection(true);
    table->setWordWrap(false);
}

bool containsToken(const QString& filter, std::uint64_t value, const QString& name)
{
    if (filter.isEmpty())
    {
        return true;
    }

    if (name.contains(filter, Qt::CaseInsensitive))
    {
        return true;
    }

    bool hex = false;
    QString text = filter;

    if (text.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
    {
        text = text.mid(2);
        hex = true;
    }

    bool ok = false;
    const std::uint64_t parsed = text.toULongLong(&ok, hex ? 16 : 10);
    return ok && parsed == value;
}
}

ProcessThreadView::ProcessThreadView(QWidget* parent)
    : QWidget(parent)
{
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    auto* split = new QSplitter(Qt::Vertical, this);

    auto* processPane = new QWidget(split);
    auto* processLayout = new QVBoxLayout(processPane);
    auto* processBar = new QHBoxLayout();
    processBar->addWidget(new QLabel(QStringLiteral("进程"), processPane));
    processBar->addWidget(new QLabel(QStringLiteral("过滤"), processPane));
    m_processFilter = new QLineEdit(processPane);
    m_processFilter->setPlaceholderText(QStringLiteral("PID 或映像名"));
    m_processFilter->setClearButtonEnabled(true);
    processBar->addWidget(m_processFilter, 1);
    m_processStatus = new QLabel(processPane);
    processBar->addWidget(m_processStatus);
    auto* refresh = new QPushButton(QStringLiteral("刷新"), processPane);
    processBar->addWidget(refresh);
    processLayout->addLayout(processBar);
    m_processes = new QTableView(processPane);
    prepareTable(m_processes);
    m_processModel = new QStandardItemModel(this);
    m_processModel->setHorizontalHeaderLabels(
        {QStringLiteral("PID"), QStringLiteral("映像"), QStringLiteral("父 PID"), QStringLiteral("EPROCESS"), QStringLiteral("CR3")});
    m_processes->setModel(m_processModel);
    processLayout->addWidget(m_processes, 1);

    auto* threadPane = new QWidget(split);
    auto* threadLayout = new QVBoxLayout(threadPane);
    auto* threadBar = new QHBoxLayout();
    threadBar->addWidget(new QLabel(QStringLiteral("线程"), threadPane));
    threadBar->addWidget(new QLabel(QStringLiteral("过滤"), threadPane));
    m_threadFilter = new QLineEdit(threadPane);
    m_threadFilter->setPlaceholderText(QStringLiteral("TID、PID 或映像名"));
    m_threadFilter->setClearButtonEnabled(true);
    threadBar->addWidget(m_threadFilter, 1);
    m_threadStatus = new QLabel(threadPane);
    threadBar->addWidget(m_threadStatus);
    threadLayout->addLayout(threadBar);
    m_threads = new QTableView(threadPane);
    prepareTable(m_threads);
    m_threadModel = new QStandardItemModel(this);
    m_threadModel->setHorizontalHeaderLabels(
        {QStringLiteral("TID"), QStringLiteral("状态"), QStringLiteral("RIP"), QStringLiteral("模式"), QStringLiteral("优先级")});
    m_threads->setModel(m_threadModel);
    threadLayout->addWidget(m_threads, 1);

    split->addWidget(processPane);
    split->addWidget(threadPane);
    split->setStretchFactor(0, 3);
    split->setStretchFactor(1, 2);
    layout->addWidget(split);

    connect(refresh, &QPushButton::clicked, this, &ProcessThreadView::refresh);
    connect(m_processFilter, &QLineEdit::textChanged, this, &ProcessThreadView::showProcesses);
    connect(m_threadFilter, &QLineEdit::textChanged, this, &ProcessThreadView::showThreads);
    connect(m_processes->selectionModel(), &QItemSelectionModel::currentRowChanged, this,
            [this](const QModelIndex& current, const QModelIndex&)
            {
                if (current.row() < 0 || current.row() >= static_cast<int>(m_visibleProcesses.size()))
                {
                    return;
                }

                const std::uint64_t eprocess = m_visibleProcesses[static_cast<std::size_t>(current.row())].eprocess;

                if (eprocess != m_selectedEprocess)
                {
                    m_selectedEprocess = eprocess;
                    requestThreadsForSelection();
                }
            });
    connect(m_threads, &QTableView::doubleClicked, this, [this](const QModelIndex& index)
    {
        if (index.row() < 0 || index.row() >= static_cast<int>(m_visibleThreads.size()))
        {
            return;
        }

        const ThreadItem& thread = m_visibleThreads[static_cast<std::size_t>(index.row())];

        if (thread.rip != 0)
        {
            emit addressActivated(thread.rip, thread.cr3);
        }
    });
}

void ProcessThreadView::setSession(CoreSession* session)
{
    m_session = session;
}

void ProcessThreadView::refresh()
{
    if (m_session == nullptr || m_session->isStarted() == false)
    {
        m_processStatus->setText(QStringLiteral("未连接"));
        return;
    }

    m_processRequest = m_session->requestProcesses();
    m_processStatus->setText(m_processRequest == 0 ? QStringLiteral("无法排队") : QStringLiteral("读取中..."));
}

void ProcessThreadView::poll()
{
    HACDBG_CORE_VIEW_STATUS status = {};

    if (takeCompleted(HacDbgViewProcesses, &m_processRequest, &status))
    {
        if (status.Failed != 0)
        {
            m_processStatus->setText(fromField(status.Message, HACDBG_CORE_MESSAGE_SIZE));
        }
        else
        {
            const std::uint32_t capacity = qMin(status.Count == 0 ? 1u : status.Count, HACDBG_CORE_MAX_PROCESSES);
            std::vector<HACDBG_CORE_PROCESS> processes(capacity);
            std::uint32_t count = 0;

            if (m_session->copyProcesses(processes.data(), capacity, &count) == false)
            {
                m_processStatus->setText(QStringLiteral("复制进程失败"));
            }
            else
            {
                count = qMin(count, capacity);
                m_processRows.clear();
                m_processRows.reserve(count);

                for (std::uint32_t index = 0; index < count; ++index)
                {
                    ProcessItem item;
                    item.eprocess = processes[index].Eprocess;
                    item.pid = processes[index].Pid;
                    item.parentPid = processes[index].ParentPid;
                    item.cr3 = processes[index].UserCr3;
                    item.image = fromField(processes[index].Image, HACDBG_CORE_NAME_SIZE);
                    m_processRows.push_back(std::move(item));
                }

                showProcesses();
                m_processStatus->setText(status.Truncated != 0 ? QStringLiteral("%1 个进程，已截断").arg(count)
                                                                : QStringLiteral("%1 个进程").arg(count));
            }
        }
    }

    if (takeCompleted(HacDbgViewThreads, &m_threadRequest, &status))
    {
        if (status.Failed != 0)
        {
            m_threadStatus->setText(fromField(status.Message, HACDBG_CORE_MESSAGE_SIZE));
        }
        else
        {
            const std::uint32_t capacity = qMin(status.Count == 0 ? 1u : status.Count, HACDBG_CORE_MAX_THREADS);
            std::vector<HACDBG_CORE_THREAD> threads(capacity);
            std::uint32_t count = 0;

            if (m_session->copyThreads(threads.data(), capacity, &count) == false)
            {
                m_threadStatus->setText(QStringLiteral("复制线程失败"));
            }
            else
            {
                count = qMin(count, capacity);
                m_threadRows.clear();
                m_threadRows.reserve(count);

                for (std::uint32_t index = 0; index < count; ++index)
                {
                    ThreadItem item;
                    item.tid = threads[index].Tid;
                    item.pid = threads[index].Pid;
                    item.rip = threads[index].InstructionPointer;
                    item.cr3 = threads[index].Cr3;
                    item.state = fromField(threads[index].StateName, HACDBG_CORE_STATE_NAME_SIZE);
                    item.image = fromField(threads[index].Image, HACDBG_CORE_NAME_SIZE);
                    item.mode = threads[index].KernelMode != 0 ? QStringLiteral("内核") : QStringLiteral("用户");
                    item.priority = QString::number(threads[index].Priority);
                    m_threadRows.push_back(std::move(item));
                }

                showThreads();
                m_threadStatus->setText(status.Truncated != 0 ? QStringLiteral("%1 个线程，已截断").arg(count)
                                                               : QStringLiteral("%1 个线程").arg(count));
            }
        }
    }
}

bool ProcessThreadView::takeCompleted(std::uint32_t view, std::uint64_t* requestId, HACDBG_CORE_VIEW_STATUS* status)
{
    if (m_session == nullptr || requestId == nullptr || *requestId == 0 || status == nullptr)
    {
        return false;
    }

    if (m_session->getViewStatus(view, status) == false || status->Pending != 0 || status->CompletedRequestId != *requestId)
    {
        return false;
    }

    *requestId = 0;
    return true;
}

void ProcessThreadView::showProcesses()
{
    const QModelIndex previous = m_processes->currentIndex();
    std::uint64_t keep = m_selectedEprocess;

    if (previous.row() >= 0 && previous.row() < static_cast<int>(m_visibleProcesses.size()))
    {
        keep = m_visibleProcesses[static_cast<std::size_t>(previous.row())].eprocess;
    }

    m_visibleProcesses.clear();
    m_processModel->removeRows(0, m_processModel->rowCount());
    int select = -1;

    for (const ProcessItem& item : m_processRows)
    {
        if (matchesProcess(item) == false)
        {
            continue;
        }

        if (item.eprocess == keep)
        {
            select = static_cast<int>(m_visibleProcesses.size());
        }

        m_visibleProcesses.push_back(item);
        m_processModel->appendRow({
            new QStandardItem(QString::number(item.pid)),
            new QStandardItem(item.image),
            new QStandardItem(QString::number(item.parentPid)),
            new QStandardItem(hex16(item.eprocess)),
            new QStandardItem(item.cr3 == 0 ? QStringLiteral("—") : hex16(item.cr3)),
        });
    }

    if (select >= 0)
    {
        m_processes->selectRow(select);
    }
}

void ProcessThreadView::showThreads()
{
    m_visibleThreads.clear();
    m_threadModel->removeRows(0, m_threadModel->rowCount());

    for (const ThreadItem& item : m_threadRows)
    {
        if (matchesThread(item) == false)
        {
            continue;
        }

        m_visibleThreads.push_back(item);
        m_threadModel->appendRow({
            new QStandardItem(QString::number(item.tid)),
            new QStandardItem(item.state),
            new QStandardItem(item.rip == 0 ? QStringLiteral("—") : hex16(item.rip)),
            new QStandardItem(item.mode),
            new QStandardItem(item.priority),
        });
    }
}

void ProcessThreadView::requestThreadsForSelection()
{
    if (m_session == nullptr || m_session->isStarted() == false || m_selectedEprocess == 0)
    {
        return;
    }

    m_threadRequest = m_session->requestThreads(m_selectedEprocess);
    m_threadStatus->setText(m_threadRequest == 0 ? QStringLiteral("无法排队") : QStringLiteral("读取中..."));
}

bool ProcessThreadView::matchesProcess(const ProcessItem& item) const
{
    return containsToken(m_processFilter->text().trimmed(), item.pid, item.image);
}

bool ProcessThreadView::matchesThread(const ThreadItem& item) const
{
    const QString filter = m_threadFilter->text().trimmed();
    return containsToken(filter, item.tid, item.image) || containsToken(filter, item.pid, item.image);
}
