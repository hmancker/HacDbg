#include "BreakpointView.h"

#include "Format.h"

#include <QHeaderView>
#include <QHBoxLayout>
#include <QKeySequence>
#include <QPushButton>
#include <QShortcut>
#include <QStandardItemModel>
#include <QTableView>
#include <QVBoxLayout>

#include <QString>

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
}

BreakpointView::BreakpointView(QWidget* parent)
    : QWidget(parent)
{
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);
    auto* bar = new QHBoxLayout();
    bar->setContentsMargins(8, 4, 8, 4);
    auto* remove = new QPushButton(QStringLiteral("删除"), this);
    bar->addWidget(remove);
    bar->addStretch(1);
    layout->addLayout(bar);
    m_table = new QTableView(this);
    prepareTable(m_table);
    m_model = new QStandardItemModel(this);
    m_model->setHorizontalHeaderLabels({QStringLiteral("种类"), QStringLiteral("ID"), QStringLiteral("地址"),
                                        QStringLiteral("CR3"), QStringLiteral("状态"), QStringLiteral("暂停"),
                                        QStringLiteral("次数")});
    m_table->setModel(m_model);
    layout->addWidget(m_table, 1);
    connect(remove, &QPushButton::clicked, this, &BreakpointView::deleteSelected);
    auto* deleteKey = new QShortcut(QKeySequence::Delete, m_table);
    deleteKey->setContext(Qt::WidgetWithChildrenShortcut);
    connect(deleteKey, &QShortcut::activated, this, &BreakpointView::deleteSelected);
    connect(m_table, &QTableView::doubleClicked, this, [this](const QModelIndex& index)
    {
        if (index.row() < 0 || index.row() >= static_cast<int>(m_activation.size()))
        {
            return;
        }

        const Activation& row = m_activation[static_cast<std::size_t>(index.row())];

        if (row.breakpoint)
        {
            const QString command = QStringLiteral("%1 0x%2")
                                        .arg(row.enabled ? QStringLiteral("bd") : QStringLiteral("be"))
                                        .arg(row.id, 0, 16);
            emit commandRequested(command);
            return;
        }

        emit addressActivated(row.address, row.cr3);
    });
}

void BreakpointView::setBreakpoints(const HACDBG_CORE_BREAKPOINT* breakpoints, std::uint32_t count)
{
    if (count > HACDBG_CORE_MAX_BREAKPOINTS)
    {
        count = HACDBG_CORE_MAX_BREAKPOINTS;
    }

    bool same = count == m_rows.size();

    for (std::uint32_t index = 0; same && index < count; ++index)
    {
        const HACDBG_CORE_BREAKPOINT& next = breakpoints[index];
        const HACDBG_CORE_BREAKPOINT& previous = m_rows[index];
        same = next.Id == previous.Id && next.Address == previous.Address && next.Cr3 == previous.Cr3 &&
               next.Enabled == previous.Enabled && next.PausesThread == previous.PausesThread;
    }

    if (same)
    {
        return;
    }

    m_rows.assign(breakpoints, breakpoints + count);
    rebuild();
}

void BreakpointView::setMonitors(const HACDBG_CORE_MONITOR* monitors, std::uint32_t count)
{
    if (count > HACDBG_CORE_MAX_MONITORS)
    {
        count = HACDBG_CORE_MAX_MONITORS;
    }

    bool same = count == m_monitors.size();

    for (std::uint32_t index = 0; same && index < count; ++index)
    {
        const HACDBG_CORE_MONITOR& next = monitors[index];
        const HACDBG_CORE_MONITOR& previous = m_monitors[index];
        same = next.Address == previous.Address && next.Hits == previous.Hits;
    }

    if (same)
    {
        return;
    }

    m_monitors.assign(monitors, monitors + count);
    rebuild();
}

void BreakpointView::deleteSelected()
{
    const int row = m_table->currentIndex().row();

    if (row < 0 || row >= static_cast<int>(m_activation.size()))
    {
        return;
    }

    const Activation& item = m_activation[static_cast<std::size_t>(row)];

    if (item.breakpoint)
    {
        emit commandRequested(QStringLiteral("bc 0x%1").arg(item.id, 0, 16));
        return;
    }

    emit commandRequested(QStringLiteral("rkh 0x%1").arg(item.address, 0, 16));
}

void BreakpointView::rebuild()
{
    const int currentRow = m_table->currentIndex().row();
    Activation selected = {};
    bool keepSelection = false;

    if (currentRow >= 0 && currentRow < static_cast<int>(m_activation.size()))
    {
        selected = m_activation[static_cast<std::size_t>(currentRow)];
        keepSelection = true;
    }

    m_model->removeRows(0, m_model->rowCount());
    m_activation.clear();

    for (const HACDBG_CORE_BREAKPOINT& row : m_rows)
    {
        m_activation.push_back({row.Address, row.Cr3, row.Id, true, row.Enabled != 0});
        m_model->appendRow({
            new QStandardItem(QStringLiteral("断点")),
            new QStandardItem(QString::number(row.Id)),
            new QStandardItem(hex16(row.Address)),
            new QStandardItem(row.Cr3 == 0 ? QStringLiteral("—") : hex16(row.Cr3)),
            new QStandardItem(row.Enabled != 0 ? QStringLiteral("开启") : QStringLiteral("关闭")),
            new QStandardItem(row.PausesThread != 0 ? QStringLiteral("暂停") : QString()),
            new QStandardItem(QStringLiteral("—")),
        });
    }

    for (const HACDBG_CORE_MONITOR& row : m_monitors)
    {
        m_activation.push_back({row.Address, 0, 0, false, true});
        m_model->appendRow({
            new QStandardItem(QStringLiteral("监控")),
            new QStandardItem(QStringLiteral("—")),
            new QStandardItem(hex16(row.Address)),
            new QStandardItem(QStringLiteral("—")),
            new QStandardItem(QStringLiteral("开启")),
            new QStandardItem(QString()),
            new QStandardItem(QString::number(row.Hits)),
        });
    }

    if (keepSelection == false)
    {
        return;
    }

    for (int row = 0; row < static_cast<int>(m_activation.size()); ++row)
    {
        const Activation& item = m_activation[static_cast<std::size_t>(row)];
        const bool same = item.breakpoint == selected.breakpoint &&
                          (item.breakpoint ? item.id == selected.id : item.address == selected.address);

        if (same == false)
        {
            continue;
        }

        const QModelIndex index = m_model->index(row, 0);
        m_table->setCurrentIndex(index);
        m_table->selectionModel()->select(index, QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
        break;
    }
}
