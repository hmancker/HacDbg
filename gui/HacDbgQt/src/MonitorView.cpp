#include "MonitorView.h"

#include "CoreSession.h"
#include "Format.h"

#include <QHeaderView>
#include <QLabel>
#include <QScrollBar>
#include <QStandardItemModel>
#include <QTableView>
#include <QVBoxLayout>

namespace
{
constexpr int kMaximumRows = 500;
constexpr std::uint32_t kCopyCapacity = 2048;

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

QString stackText(const HACDBG_CORE_MONITOR_HIT& hit)
{
    QString text;

    for (std::uint32_t index = 0; index < HACDBG_CORE_MONITOR_STACK; ++index)
    {
        if (index != 0)
        {
            text.append(QStringLiteral(" "));
        }

        text.append(hex16(hit.Stack[index]));
    }

    return text;
}
}

MonitorView::MonitorView(QWidget* parent)
    : QWidget(parent)
{
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);
    m_status = new QLabel(QStringLiteral("监控记录来自日志邮箱，不必执行 fl。表里保留最近 500 条。"), this);
    m_status->setContentsMargins(8, 4, 8, 4);
    m_table = new QTableView(this);
    prepareTable(m_table);
    m_model = new QStandardItemModel(this);
    m_model->setHorizontalHeaderLabels({
        QStringLiteral("#"),
        QStringLiteral("函数"),
        QStringLiteral("RIP"),
        QStringLiteral("CR3"),
        QStringLiteral("RAX"),
        QStringLiteral("RCX"),
        QStringLiteral("RDX"),
        QStringLiteral("RBX"),
        QStringLiteral("RSP"),
        QStringLiteral("RBP"),
        QStringLiteral("RSI"),
        QStringLiteral("RDI"),
        QStringLiteral("R8"),
        QStringLiteral("R9"),
        QStringLiteral("R10"),
        QStringLiteral("R11"),
        QStringLiteral("R12"),
        QStringLiteral("R13"),
        QStringLiteral("R14"),
        QStringLiteral("R15"),
        QStringLiteral("栈"),
    });
    m_table->setModel(m_model);
    layout->addWidget(m_status);
    layout->addWidget(m_table, 1);
    connect(m_table, &QTableView::doubleClicked, this, [this](const QModelIndex& index)
    {
        if (index.row() < 0 || index.row() >= static_cast<int>(m_addresses.size()))
        {
            return;
        }

        emit addressActivated(m_addresses[static_cast<std::size_t>(index.row())], 0);
    });
}

void MonitorView::setSession(CoreSession* session)
{
    m_session = session;
}

bool MonitorView::nearBottom() const
{
    const QScrollBar* bar = m_table->verticalScrollBar();
    const int line = qMax(1, m_table->fontMetrics().lineSpacing());

    return bar->maximum() - bar->value() <= line * 2;
}

void MonitorView::appendHit(const HACDBG_CORE_MONITOR_HIT& hit)
{
    ++m_shown;
    m_addresses.push_back(hit.Address);
    m_model->appendRow({
        new QStandardItem(QString::number(m_shown)),
        new QStandardItem(hex16(hit.Address)),
        new QStandardItem(hex16(hit.Rip)),
        new QStandardItem(hex16(hit.Cr3)),
        new QStandardItem(hex16(hit.Rax)),
        new QStandardItem(hex16(hit.Rcx)),
        new QStandardItem(hex16(hit.Rdx)),
        new QStandardItem(hex16(hit.Rbx)),
        new QStandardItem(hex16(hit.Rsp)),
        new QStandardItem(hex16(hit.Rbp)),
        new QStandardItem(hex16(hit.Rsi)),
        new QStandardItem(hex16(hit.Rdi)),
        new QStandardItem(hex16(hit.R8)),
        new QStandardItem(hex16(hit.R9)),
        new QStandardItem(hex16(hit.R10)),
        new QStandardItem(hex16(hit.R11)),
        new QStandardItem(hex16(hit.R12)),
        new QStandardItem(hex16(hit.R13)),
        new QStandardItem(hex16(hit.R14)),
        new QStandardItem(hex16(hit.R15)),
        new QStandardItem(stackText(hit)),
    });
}

void MonitorView::trimRows()
{
    const int extra = m_model->rowCount() - kMaximumRows;

    if (extra <= 0)
    {
        return;
    }

    m_model->removeRows(0, extra);
    m_addresses.erase(m_addresses.begin(), m_addresses.begin() + extra);
    m_skipped += static_cast<std::uint64_t>(extra);
}

void MonitorView::updateStatus()
{
    if (m_skipped == 0)
    {
        m_status->setText(QStringLiteral("监控记录来自日志邮箱，不必执行 fl。表里保留最近 500 条。"));
        return;
    }

    m_status->setText(QStringLiteral("监控记录来自日志邮箱，不必执行 fl。表里保留最近 500 条，较早的 %1 条已丢掉。")
                          .arg(m_skipped));
}

void MonitorView::poll()
{
    if (m_session == nullptr || m_session->isStarted() == false)
    {
        return;
    }

    std::vector<HACDBG_CORE_MONITOR_HIT> hits(kCopyCapacity);
    std::uint32_t count = 0;

    if (m_session->copyMonitorHits(hits.data(), kCopyCapacity, &count) == false || count == 0)
    {
        return;
    }

    const bool follow = nearBottom();
    m_table->setUpdatesEnabled(false);

    std::uint32_t begin = 0;

    if (count > static_cast<std::uint32_t>(kMaximumRows))
    {
        begin = count - static_cast<std::uint32_t>(kMaximumRows);
        m_skipped += begin;
    }

    for (std::uint32_t index = begin; index < count; ++index)
    {
        appendHit(hits[index]);
    }

    trimRows();
    m_table->setUpdatesEnabled(true);

    if (m_sizedColumns == false && m_model->rowCount() > 0)
    {
        m_table->resizeColumnsToContents();
        m_sizedColumns = true;
    }

    if (follow)
    {
        m_table->scrollToBottom();
    }

    updateStatus();
}
