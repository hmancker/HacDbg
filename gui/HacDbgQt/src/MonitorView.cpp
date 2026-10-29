#include "MonitorView.h"

#include "CoreSession.h"
#include "Format.h"
#include "RegisterView.h"

#include <QAbstractItemView>
#include <QAbstractListModel>
#include <QHeaderView>
#include <QLabel>
#include <QListView>
#include <QScrollBar>
#include <QSplitter>
#include <QTableWidget>
#include <QVBoxLayout>

namespace
{
constexpr int kMaximumRows = 20000;
constexpr std::uint32_t kCopyCapacity = 2048;

QString monitorLine(const HACDBG_CORE_MONITOR_HIT& hit)
{
    return QStringLiteral("HacDbg: monitor rip=0x%1 cr3=0x%2.")
        .arg(QString::number(hit.Rip, 16), QString::number(hit.Cr3, 16));
}
}

class MonitorLogModel : public QAbstractListModel
{
public:
    explicit MonitorLogModel(QObject* parent)
        : QAbstractListModel(parent)
    {
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
            m_dropped += static_cast<std::uint64_t>(count - kMaximumRows);
            hits += count - kMaximumRows;
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

private:
    struct Row
    {
        HACDBG_CORE_MONITOR_HIT hit = {};
        QString line;
    };

    static Row makeRow(const HACDBG_CORE_MONITOR_HIT& hit)
    {
        Row row;
        row.hit = hit;
        row.line = monitorLine(hit);
        return row;
    }

    std::vector<Row> m_rows;
    std::uint64_t m_dropped = 0;
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
    m_status = new QLabel(this);
    m_status->setContentsMargins(8, 4, 8, 4);
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

    std::uint32_t count = 0;

    if (m_session->copyMonitorHits(m_copy.data(), kCopyCapacity, &count) == false || count == 0)
    {
        return;
    }

    const bool follow = nearBottom() || m_log->selectionModel()->currentIndex().isValid() == false;
    m_model->append(m_copy.data(), static_cast<int>(count));

    if (follow && m_model->rowCount() > 0)
    {
        const QModelIndex last = m_model->index(m_model->rowCount() - 1, 0);
        m_log->setCurrentIndex(last);
        m_log->scrollTo(last, QAbstractItemView::PositionAtBottom);
    }

    updateStatus();
}
