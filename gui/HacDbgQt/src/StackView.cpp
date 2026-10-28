#include "StackView.h"

#include "Format.h"

#include <QHeaderView>
#include <QStandardItemModel>

StackView::StackView(QWidget* parent)
    : QTableView(parent)
{
    QFont font(QStringLiteral("Cascadia Mono"));
    font.setStyleHint(QFont::Monospace);
    font.setPointSize(10);
    setFont(font);
    setShowGrid(false);
    setSelectionBehavior(QAbstractItemView::SelectRows);
    setSelectionMode(QAbstractItemView::SingleSelection);
    setEditTriggers(QAbstractItemView::NoEditTriggers);
    verticalHeader()->hide();
    horizontalHeader()->setStretchLastSection(true);
    m_model = new QStandardItemModel(this);
    m_model->setHorizontalHeaderLabels({QStringLiteral("#"), QStringLiteral("Child SP"), QStringLiteral("返回"), QStringLiteral("符号")});
    setModel(m_model);
    connect(this, &QTableView::doubleClicked, this, [this](const QModelIndex& index)
    {
        if (index.row() >= 0 && index.row() < static_cast<int>(m_addresses.size()))
        {
            emit addressActivated(m_addresses[static_cast<std::size_t>(index.row())]);
        }
    });
}

void StackView::setFrames(const HACDBG_CORE_STACK_FRAME* frames, std::uint32_t count)
{
    m_model->removeRows(0, m_model->rowCount());
    m_addresses.clear();

    if (frames == nullptr)
    {
        return;
    }

    for (std::uint32_t index = 0; index < count; ++index)
    {
        const HACDBG_CORE_STACK_FRAME& frame = frames[index];
        const std::uint64_t address = frame.HasReturn != 0 ? frame.ReturnAddress : frame.InstructionPointer;
        m_addresses.push_back(address);
        const QString symbol = fromField(frame.Symbol, HACDBG_CORE_SYMBOL_SIZE);
        m_model->appendRow({
            new QStandardItem(QStringLiteral("%1").arg(index, 2, 10, QLatin1Char('0'))),
            new QStandardItem(hex16(frame.ChildSp)),
            new QStandardItem(frame.HasReturn != 0 ? hex16(frame.ReturnAddress) : QStringLiteral("????????????????")),
            new QStandardItem(symbol),
        });
    }
}
