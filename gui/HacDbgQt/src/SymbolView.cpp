#include "SymbolView.h"

#include "Format.h"

#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QPushButton>
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
}

SymbolView::SymbolView(QWidget* parent)
    : QWidget(parent)
{
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(6, 6, 6, 6);
    auto* toolbar = new QHBoxLayout();
    auto* reload = new QPushButton(QStringLiteral("加载符号"), this);
    auto* refresh = new QPushButton(QStringLiteral("刷新"), this);
    m_status = new QLabel(this);
    toolbar->addWidget(reload);
    toolbar->addWidget(refresh);
    toolbar->addWidget(m_status, 1);
    layout->addLayout(toolbar);
    m_table = new QTableView(this);
    prepareTable(m_table);
    m_model = new QStandardItemModel(this);
    m_model->setHorizontalHeaderLabels({QStringLiteral("模块"), QStringLiteral("基址"), QStringLiteral("大小"),
                                        QStringLiteral("类型"), QStringLiteral("符号"), QStringLiteral("路径")});
    m_table->setModel(m_model);
    layout->addWidget(m_table, 1);
    connect(reload, &QPushButton::clicked, this, &SymbolView::reloadRequested);
    connect(refresh, &QPushButton::clicked, this, &SymbolView::refresh);
    connect(m_table, &QTableView::doubleClicked, this, [this](const QModelIndex& index)
    {
        if (index.row() >= 0 && index.row() < static_cast<int>(m_rows.size()))
        {
            emit addressActivated(m_rows[static_cast<std::size_t>(index.row())].base, 0);
        }
    });
}

void SymbolView::setSession(CoreSession* session)
{
    m_session = session;
}

void SymbolView::refresh()
{
    if (m_session == nullptr || m_session->isStarted() == false)
    {
        m_status->setText(QStringLiteral("未连接"));
        return;
    }

    m_request = m_session->requestModules();
    m_status->setText(m_request == 0 ? QStringLiteral("无法排队") : QStringLiteral("读取中..."));
}

void SymbolView::poll()
{
    HACDBG_CORE_VIEW_STATUS status = {};

    if (takeCompleted(&status) == false)
    {
        return;
    }

    if (status.Failed != 0)
    {
        m_status->setText(fromField(status.Message, HACDBG_CORE_MESSAGE_SIZE));
        return;
    }

    const std::uint32_t capacity = qMin(status.Count == 0 ? 1u : status.Count, HACDBG_CORE_MAX_MODULES);
    std::vector<HACDBG_CORE_MODULE> modules(capacity);
    std::uint32_t count = 0;

    if (m_session->copyModules(modules.data(), capacity, &count) == false)
    {
        m_status->setText(QStringLiteral("复制模块失败"));
        return;
    }

    count = qMin(count, capacity);

    m_rows.clear();
    m_model->removeRows(0, m_model->rowCount());

    for (std::uint32_t index = 0; index < count; ++index)
    {
        const HACDBG_CORE_MODULE& module = modules[index];
        Row row;
        row.base = module.Base;
        row.name = fromField(module.Name, HACDBG_CORE_NAME_SIZE);
        m_rows.push_back(row);
        m_model->appendRow({
            new QStandardItem(row.name),
            new QStandardItem(hex16(module.Base)),
            new QStandardItem(QStringLiteral("0x%1").arg(module.Size, 0, 16).toUpper()),
            new QStandardItem(module.Kernel != 0 ? QStringLiteral("内核") : QStringLiteral("用户")),
            new QStandardItem(module.SymbolsLoaded != 0 ? QStringLiteral("已加载") : QStringLiteral("—")),
            new QStandardItem(fromField(module.SymbolPath, HACDBG_CORE_PATH_SIZE)),
        });
    }

    m_status->setText(status.Truncated != 0 ? QStringLiteral("%1 个模块，已截断").arg(count)
                                            : QStringLiteral("%1 个模块").arg(count));
}

bool SymbolView::takeCompleted(HACDBG_CORE_VIEW_STATUS* status)
{
    if (m_session == nullptr || m_request == 0 || status == nullptr)
    {
        return false;
    }

    if (m_session->getViewStatus(HacDbgViewModules, status) == false || status->Pending != 0 ||
        status->CompletedRequestId != m_request)
    {
        return false;
    }

    m_request = 0;
    return true;
}
