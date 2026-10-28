#include "StackView.h"

#include "Format.h"

#include <QHeaderView>
#include <QStandardItem>
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
    m_topRip = 0;
    m_topSymbol.clear();

    if (frames == nullptr || count == 0)
    {
        return;
    }

    m_topRip = frames[0].InstructionPointer;
    m_topSymbol = fromField(frames[0].Symbol, HACDBG_CORE_SYMBOL_SIZE);

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

bool StackView::hasFrames() const
{
    return m_model->rowCount() > 0;
}

void StackView::setTopSymbol(const QString& symbol)
{
    QStandardItem* item = m_model->item(0, 3);

    if (item == nullptr || item->text() == symbol)
    {
        return;
    }

    item->setText(symbol);
}

QString StackView::adjustedTopSymbol(std::uint64_t rip) const
{
    if (m_topSymbol.isEmpty() || rip == 0 || rip == m_topRip || m_topSymbol.contains(QLatin1Char('!')) == false)
    {
        return m_topSymbol;
    }

    QString name = m_topSymbol;
    std::uint64_t displacement = 0;
    const int plus = m_topSymbol.lastIndexOf(QStringLiteral("+0x"));
    const int bang = m_topSymbol.indexOf(QLatin1Char('!'));

    if (plus > bang)
    {
        bool ok = false;
        displacement = m_topSymbol.mid(plus + 3).toULongLong(&ok, 16);

        if (ok == false || m_topRip < displacement)
        {
            return m_topSymbol;
        }

        name = m_topSymbol.left(plus);
    }

    const std::uint64_t base = m_topRip - displacement;

    if (rip < base)
    {
        return m_topSymbol;
    }

    const std::uint64_t updated = rip - base;

    //
    // A jump that stays at the same RSP can land in another function. Keep
    // the previous text instead of showing a huge displacement.
    //
    constexpr std::uint64_t kMaxAdjustedDisplacement = 0x1000000;

    if (updated > kMaxAdjustedDisplacement)
    {
        return m_topSymbol;
    }

    if (updated == 0)
    {
        return name;
    }

    return name + QStringLiteral("+0x") + QString::number(updated, 16);
}
