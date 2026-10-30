#include "MonitorView.h"

#include "CoreSession.h"
#include "Format.h"
#include "RegisterView.h"

#include <algorithm>
#include <utility>

#include <QAbstractItemView>
#include <QAbstractListModel>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QListView>
#include <QPushButton>
#include <QScrollBar>
#include <QSplitter>
#include <QTableWidget>
#include <QVBoxLayout>

namespace
{
constexpr int kMaximumRows = 20000;
constexpr std::uint32_t kCopyCapacity = 8192;

QString monitorLine(const HACDBG_CORE_MONITOR_HIT& hit, const QString& function)
{
    const QString rip = QString::number(hit.Rip, 16);
    const QString cr3 = QString::number(hit.Cr3, 16);

    if (function.isEmpty())
    {
        return QStringLiteral("HacDbg: monitor rip=0x%1 cr3=0x%2.").arg(rip, cr3);
    }

    return QStringLiteral("HacDbg: monitor %1 rip=0x%2 cr3=0x%3.").arg(function, rip, cr3);
}
}

class MonitorLogModel : public QAbstractListModel
{
public:
    explicit MonitorLogModel(QObject* parent)
        : QAbstractListModel(parent)
    {
    }

    void setSiteSymbol(const std::uint64_t address, const QString& symbol)
    {
        if (address == 0 || symbol.isEmpty())
        {
            return;
        }

        for (std::pair<std::uint64_t, QString>& item : m_symbols)
        {
            if (item.first == address)
            {
                item.second = symbol;
                return;
            }
        }

        m_symbols.emplace_back(address, symbol);
    }

    int rowCount(const QModelIndex& parent = QModelIndex()) const override
    {
        if (parent.isValid())
        {
            return 0;
        }

        return static_cast<int>(m_rows.size());
    }

    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override
    {
        if (index.isValid() == false || index.row() < 0 || index.row() >= rowCount())
        {
            return {};
        }

        if (role != Qt::DisplayRole)
        {
            return {};
        }

        return m_rows[static_cast<std::size_t>(index.row())].line;
    }

    void append(const HACDBG_CORE_MONITOR_HIT* hits, int count)
    {
        if (hits == nullptr || count <= 0)
        {
            return;
        }

        if (count > kMaximumRows)
        {
            const int skip = count - kMaximumRows;
            m_dropped += static_cast<std::uint64_t>(skip);
            m_nextNumber += static_cast<std::uint64_t>(skip);
            hits += skip;
            count = kMaximumRows;
        }

        const int size = rowCount();

        if (size + count <= kMaximumRows)
        {
            beginInsertRows(QModelIndex(), size, size + count - 1);
            m_rows.reserve(static_cast<std::size_t>(size + count));

            for (int index = 0; index < count; ++index)
            {
                m_rows.push_back(makeRow(hits[index]));
            }

            endInsertRows();
            return;
        }

        const int drop = size + count - kMaximumRows;
        m_dropped += static_cast<std::uint64_t>(drop);
        beginResetModel();
        m_rows.erase(m_rows.begin(), m_rows.begin() + drop);
        m_rows.reserve(static_cast<std::size_t>(kMaximumRows));

        for (int index = 0; index < count; ++index)
        {
            m_rows.push_back(makeRow(hits[index]));
        }

        endResetModel();
    }

    bool hit(int row, HACDBG_CORE_MONITOR_HIT* out) const
    {
        if (out == nullptr || row < 0 || row >= rowCount())
        {
            return false;
        }

        *out = m_rows[static_cast<std::size_t>(row)].hit;
        return true;
    }

    std::uint64_t dropped() const
    {
        return m_dropped;
    }

    void clear()
    {
        beginResetModel();
        m_rows.clear();
        m_dropped = 0;
        m_nextNumber = 1;
        m_expected = 0;
        endResetModel();
    }

    void setExpected(std::uint64_t sequence)
    {
        m_expected = sequence;
    }

    void account(const HACDBG_CORE_MONITOR_HIT* hits, int count)
    {
        if (hits == nullptr || count <= 0)
        {
            return;
        }

        //
        // One read can contain a later sequence before an earlier one. Counting
        // that hole and then also keeping the late rows makes the last line
        // number larger than the number of hits. Same sequence twice is one hit.
        //
        std::vector<HACDBG_CORE_MONITOR_HIT> fresh;
        fresh.reserve(static_cast<std::size_t>(count));

        for (int index = 0; index < count; ++index)
        {
            const std::uint64_t sequence = hits[index].Sequence;

            if (sequence == 0 || (m_expected != 0 && sequence <= m_expected))
            {
                continue;
            }

            fresh.push_back(hits[index]);
        }

        if (fresh.empty())
        {
            return;
        }

        std::sort(fresh.begin(), fresh.end(), [](const HACDBG_CORE_MONITOR_HIT& left, const HACDBG_CORE_MONITOR_HIT& right)
        {
            return left.Sequence < right.Sequence;
        });
        fresh.erase(std::unique(fresh.begin(), fresh.end(), [](const HACDBG_CORE_MONITOR_HIT& left, const HACDBG_CORE_MONITOR_HIT& right)
        {
            return left.Sequence == right.Sequence;
        }),
                    fresh.end());

        std::uint64_t accounted = m_expected;
        std::size_t run = 0;

        while (run < fresh.size())
        {
            const std::uint64_t sequence = fresh[run].Sequence;

            if (accounted == 0)
            {
                if (sequence > m_nextNumber)
                {
                    m_dropped += sequence - m_nextNumber;
                    m_nextNumber = sequence;
                }
            }
            else if (sequence > accounted + 1)
            {
                const std::uint64_t gap = sequence - (accounted + 1);
                m_dropped += gap;
                m_nextNumber += gap;
            }

            std::size_t end = run + 1;

            while (end < fresh.size() && fresh[end].Sequence == fresh[end - 1].Sequence + 1)
            {
                end += 1;
            }

            append(fresh.data() + run, static_cast<int>(end - run));
            accounted = fresh[end - 1].Sequence;
            run = end;
        }

        m_expected = accounted;
    }

private:
    struct Row
    {
        HACDBG_CORE_MONITOR_HIT hit = {};
        QString line;
    };

    QString cachedSymbol(const std::uint64_t address) const
    {
        for (const std::pair<std::uint64_t, QString>& item : m_symbols)
        {
            if (item.first == address)
            {
                return item.second;
            }
        }

        return {};
    }

    Row makeRow(const HACDBG_CORE_MONITOR_HIT& hit)
    {
        const std::uint64_t address = hit.Address != 0 ? hit.Address : hit.Rip;
        Row row;
        row.hit = hit;
        row.line = QStringLiteral("%1  %2").arg(m_nextNumber).arg(monitorLine(hit, cachedSymbol(address)));
        m_nextNumber += 1;
        return row;
    }

    std::vector<std::pair<std::uint64_t, QString>> m_symbols;
    std::vector<Row> m_rows;
    std::uint64_t m_dropped = 0;
    std::uint64_t m_nextNumber = 1;
    std::uint64_t m_expected = 0;
};

namespace
{
QFont monoFont()
{
    QFont font(QStringLiteral("Cascadia Mono"));
    font.setStyleHint(QFont::Monospace);
    font.setPointSize(10);
    return font;
}

HACDBG_CORE_REGISTERS registersFromHit(const HACDBG_CORE_MONITOR_HIT& hit)
{
    HACDBG_CORE_REGISTERS registers = {};
    registers.Rax = hit.Rax;
    registers.Rcx = hit.Rcx;
    registers.Rdx = hit.Rdx;
    registers.Rbx = hit.Rbx;
    registers.Rsp = hit.Rsp;
    registers.Rbp = hit.Rbp;
    registers.Rsi = hit.Rsi;
    registers.Rdi = hit.Rdi;
    registers.R8 = hit.R8;
    registers.R9 = hit.R9;
    registers.R10 = hit.R10;
    registers.R11 = hit.R11;
    registers.R12 = hit.R12;
    registers.R13 = hit.R13;
    registers.R14 = hit.R14;
    registers.R15 = hit.R15;
    registers.Rip = hit.Rip;
    registers.Cr3 = hit.Cr3;
    registers.RflagsKnown = 0;
    return registers;
}
}

MonitorView::MonitorView(QWidget* parent)
    : QWidget(parent)
{
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);
    auto* bar = new QHBoxLayout();
    bar->setContentsMargins(8, 4, 8, 4);
    auto* clear = new QPushButton(QStringLiteral("清空"), this);
    bar->addWidget(clear);
    bar->addStretch(1);
    layout->addLayout(bar);
    m_status = new QLabel(this);
    m_status->setContentsMargins(8, 4, 8, 4);
    connect(clear, &QPushButton::clicked, this, &MonitorView::clearLog);
    m_log = new QListView(this);
    m_model = new MonitorLogModel(this);
    m_log->setModel(m_model);
    m_log->setFont(monoFont());
    m_log->setUniformItemSizes(true);
    m_log->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_log->setSelectionMode(QAbstractItemView::SingleSelection);
    m_log->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_log->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    m_log->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    m_log->setTextElideMode(Qt::ElideNone);
    m_registers = new RegisterView(this);
    m_stack = new QTableWidget(HACDBG_CORE_MONITOR_STACK, 2, this);
    m_stack->setFont(monoFont());
    m_stack->setHorizontalHeaderLabels({QStringLiteral("地址"), QStringLiteral("值")});
    m_stack->verticalHeader()->hide();
    m_stack->verticalHeader()->setDefaultSectionSize(m_stack->fontMetrics().height() + 4);
    m_stack->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_stack->setSelectionMode(QAbstractItemView::NoSelection);
    m_stack->setFocusPolicy(Qt::NoFocus);
    m_stack->setShowGrid(false);
    m_stack->horizontalHeader()->setStretchLastSection(true);
    m_stack->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);

    for (int row = 0; row < HACDBG_CORE_MONITOR_STACK; ++row)
    {
        m_stack->setItem(row, 0, new QTableWidgetItem);
        m_stack->setItem(row, 1, new QTableWidgetItem);
    }

    auto* split = new QSplitter(Qt::Horizontal, this);
    auto* right = new QSplitter(Qt::Vertical, split);
    right->setChildrenCollapsible(false);
    right->addWidget(m_registers);
    right->addWidget(m_stack);
    right->setStretchFactor(0, 3);
    right->setStretchFactor(1, 2);
    split->setChildrenCollapsible(false);
    split->addWidget(m_log);
    split->addWidget(right);
    split->setStretchFactor(0, 3);
    split->setStretchFactor(1, 2);
    layout->addWidget(m_status);
    layout->addWidget(split, 1);
    updateStatus();

    connect(m_log->selectionModel(), &QItemSelectionModel::currentChanged, this, [this](const QModelIndex&, const QModelIndex&)
    {
        showSelected();
    });
    connect(m_log, &QListView::doubleClicked, this, [this](const QModelIndex& index)
    {
        HACDBG_CORE_MONITOR_HIT hit = {};

        if (m_model->hit(index.row(), &hit) == false || hit.Rip == 0)
        {
            return;
        }

        emit addressActivated(hit.Rip, hit.Cr3);
    });
}

void MonitorView::setSession(CoreSession* session)
{
    m_session = session;
}

bool MonitorView::nearBottom() const
{
    const QScrollBar* bar = m_log->verticalScrollBar();

    if (bar->maximum() <= 0)
    {
        return true;
    }

    return bar->maximum() - bar->value() <= qMax(bar->singleStep(), m_log->fontMetrics().lineSpacing());
}

void MonitorView::showSelected()
{
    HACDBG_CORE_MONITOR_HIT hit = {};
    const bool selected = m_model->hit(m_log->currentIndex().row(), &hit);

    if (selected == false)
    {
        m_registers->setRegisters({}, false);

        for (int row = 0; row < HACDBG_CORE_MONITOR_STACK; ++row)
        {
            m_stack->item(row, 0)->setText({});
            m_stack->item(row, 1)->setText({});
        }

        return;
    }

    m_registers->setRegisters(registersFromHit(hit), true);

    for (int row = 0; row < HACDBG_CORE_MONITOR_STACK; ++row)
    {
        const std::uint64_t address = hit.Rsp + static_cast<std::uint64_t>(row) * 8;
        m_stack->item(row, 0)->setText(hex16(address));
        m_stack->item(row, 1)->setText(hex16(hit.Stack[row]));
    }
}

void MonitorView::updateStatus()
{
    const std::uint64_t dropped = m_model->dropped();

    if (dropped == 0)
    {
        m_status->setText(QStringLiteral("监控日志来自日志邮箱，不必执行 fl。选中一行后，右侧显示这一次的寄存器和栈。列表保留最近 %1 条。")
                              .arg(kMaximumRows));
        return;
    }

    m_status->setText(QStringLiteral("监控日志来自日志邮箱，不必执行 fl。选中一行后，右侧显示这一次的寄存器和栈。列表保留最近 %1 条，较早的 %2 条已丢掉。")
                          .arg(kMaximumRows)
                          .arg(dropped));
}

void MonitorView::clearLog()
{
    m_model->clear();
    showSelected();
    updateStatus();

    if (m_session == nullptr || m_session->isStarted() == false)
    {
        return;
    }

    if (m_copy.size() != kCopyCapacity)
    {
        m_copy.resize(kCopyCapacity);
    }

    std::uint64_t newest = 0;

    for (int batch = 0; batch < 4; ++batch)
    {
        std::uint32_t count = 0;

        if (m_session->copyMonitorHits(m_copy.data(), kCopyCapacity, &count, &newest) == false || count == 0)
        {
            break;
        }
    }

    m_model->setExpected(newest);
}

void MonitorView::poll()
{
    if (m_session == nullptr || m_session->isStarted() == false)
    {
        return;
    }

    if (m_copy.size() != kCopyCapacity)
    {
        m_copy.resize(kCopyCapacity);
    }

    bool any = false;
    const bool follow = nearBottom() || m_log->selectionModel()->currentIndex().isValid() == false;
    std::vector<HACDBG_CORE_MONITOR> sites(HACDBG_CORE_MAX_MONITORS);
    std::uint32_t siteCount = 0;

    if (m_session->copyMonitors(sites.data(), HACDBG_CORE_MAX_MONITORS, &siteCount))
    {
        for (std::uint32_t index = 0; index < siteCount; ++index)
        {
            m_model->setSiteSymbol(sites[index].Address, QString::fromUtf8(sites[index].Symbol));
        }
    }

    //
    // One poll takes a few fixed batches. Draining until the queue stays
    // empty never returns while a million hits a second are still arriving,
    // and the batch vector keeps every copy until the process runs out of memory.
    //
    for (int batch = 0; batch < 4; ++batch)
    {
        std::uint32_t count = 0;
        std::uint64_t newest = 0;

        if (m_session->copyMonitorHits(m_copy.data(), kCopyCapacity, &count, &newest) == false || count == 0)
        {
            break;
        }

        any = true;
        m_model->account(m_copy.data(), static_cast<int>(count));
    }

    if (any == false)
    {
        return;
    }

    if (follow && m_model->rowCount() > 0)
    {
        const QModelIndex last = m_model->index(m_model->rowCount() - 1, 0);
        m_log->setCurrentIndex(last);
        m_log->scrollTo(last, QAbstractItemView::PositionAtBottom);
    }

    updateStatus();
}
