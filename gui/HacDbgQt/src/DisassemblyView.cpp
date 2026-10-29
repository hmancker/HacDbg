#include "DisassemblyView.h"

#include "Format.h"

#include <QKeyEvent>
#include <QMouseEvent>
#include <QPainter>
#include <QScrollBar>

namespace
{
bool parseJumpTarget(const QString& text, std::uint64_t* target)
{
    const QString lower = text.toLower();
    const int space = lower.indexOf(' ');
    const QString mnemonic = space < 0 ? lower : lower.left(space);
    const bool branch = mnemonic.startsWith('j') || mnemonic == QStringLiteral("call") || mnemonic.startsWith(QStringLiteral("loop"));

    if (branch == false || target == nullptr)
    {
        return false;
    }

    int found = -1;

    for (int search = 0; search < lower.size();)
    {
        const int at = lower.indexOf(QStringLiteral("0x"), search);

        if (at < 0)
        {
            break;
        }

        const int bracket = lower.lastIndexOf('[', at);
        const int close = lower.lastIndexOf(']', at);

        if (bracket < 0 || close > bracket)
        {
            found = at;
        }

        search = at + 2;
    }

    if (found < 0)
    {
        return false;
    }

    std::uint64_t value = 0;
    int digits = 0;

    for (int index = found + 2; index < lower.size(); ++index)
    {
        const QChar ch = lower.at(index);
        int nibble = -1;

        if (ch.isDigit())
        {
            nibble = ch.digitValue();
        }
        else if (ch >= 'a' && ch <= 'f')
        {
            nibble = 10 + ch.unicode() - 'a';
        }
        else
        {
            break;
        }

        value = (value << 4) | static_cast<std::uint64_t>(nibble);
        ++digits;
    }

    if (digits == 0)
    {
        return false;
    }

    *target = value;
    return true;
}
}

DisassemblyView::DisassemblyView(QWidget* parent)
    : QAbstractScrollArea(parent)
{
    QFont font(QStringLiteral("Cascadia Mono"));
    font.setStyleHint(QFont::Monospace);
    font.setPointSize(10);
    setFont(font);
    setFocusPolicy(Qt::StrongFocus);
    setFrameShape(QFrame::NoFrame);
    viewport()->installEventFilter(this);
    viewport()->setAutoFillBackground(true);
    QPalette pal = viewport()->palette();
    pal.setColor(QPalette::Base, Qt::white);
    viewport()->setPalette(pal);
}

void DisassemblyView::setRows(std::vector<Row> rows, std::uint64_t rip, const std::vector<std::uint64_t>& breakpoints)
{
    m_rows = std::move(rows);
    m_rip = rip;
    m_breakpoints = breakpoints;
    m_selected = -1;
    const QFontMetrics metrics(font());
    m_bytesWidth = metrics.horizontalAdvance(QStringLiteral("00"));

    for (const Row& row : m_rows)
    {
        m_bytesWidth = qMax(m_bytesWidth, metrics.horizontalAdvance(row.bytes));
    }

    m_bytesWidth += 12;

    for (int index = 0; index < static_cast<int>(m_rows.size()); ++index)
    {
        std::uint64_t target = 0;

        if (parseJumpTarget(m_rows[static_cast<std::size_t>(index)].text, &target))
        {
            for (const Row& row : m_rows)
            {
                if (row.address == target)
                {
                    m_rows[static_cast<std::size_t>(index)].hasJump = true;
                    m_rows[static_cast<std::size_t>(index)].jumpTarget = target;
                    break;
                }
            }
        }

        if (m_selected < 0 && rip != 0 && m_rows[static_cast<std::size_t>(index)].address == rip)
        {
            m_selected = index;
        }
    }

    if (m_selected < 0 && m_rows.empty() == false)
    {
        m_selected = 0;
    }

    updateScroll();

    if (m_selected >= 0)
    {
        scrollToRow(m_selected);
    }

    viewport()->update();
    emit selectionChanged();
}

void DisassemblyView::setRip(std::uint64_t rip, const std::vector<std::uint64_t>& breakpoints)
{
    const bool sameRip = m_rip == rip;
    const bool sameBreakpoints = m_breakpoints == breakpoints;

    if (sameRip && sameBreakpoints)
    {
        return;
    }

    m_rip = rip;
    m_breakpoints = breakpoints;

    if (sameRip == false && rip != 0)
    {
        for (int index = 0; index < static_cast<int>(m_rows.size()); ++index)
        {
            if (m_rows[static_cast<std::size_t>(index)].address != rip)
            {
                continue;
            }

            const bool selectionMoved = m_selected != index;
            m_selected = index;
            scrollToRow(index);
            viewport()->update();

            if (selectionMoved)
            {
                emit selectionChanged();
            }

            return;
        }
    }

    viewport()->update();
}

bool DisassemblyView::containsAddress(std::uint64_t address) const
{
    if (address == 0)
    {
        return false;
    }

    for (const Row& row : m_rows)
    {
        if (row.address == address)
        {
            return true;
        }
    }

    return false;
}

const DisassemblyView::Row* DisassemblyView::selectedRow() const
{
    if (m_selected < 0 || m_selected >= static_cast<int>(m_rows.size()))
    {
        return nullptr;
    }

    return &m_rows[static_cast<std::size_t>(m_selected)];
}

std::uint64_t DisassemblyView::firstAddress() const
{
    return m_rows.empty() ? 0 : m_rows.front().address;
}

std::uint64_t DisassemblyView::lastEnd() const
{
    if (m_rows.empty())
    {
        return 0;
    }

    const Row& last = m_rows.back();
    return last.address + last.length;
}

bool DisassemblyView::eventFilter(QObject* watched, QEvent* event)
{
    if (watched != viewport())
    {
        return QAbstractScrollArea::eventFilter(watched, event);
    }

    if (event->type() == QEvent::MouseButtonPress)
    {
        auto* mouse = static_cast<QMouseEvent*>(event);
        const int row = rowAt(static_cast<int>(mouse->position().y()));

        if (row >= 0)
        {
            m_selected = row;
            setFocus();
            viewport()->update();
            emit selectionChanged();
        }

        return true;
    }

    if (event->type() != QEvent::Paint)
    {
        return QAbstractScrollArea::eventFilter(watched, event);
    }

    QPainter painter(viewport());
    painter.fillRect(viewport()->rect(), Qt::white);
    painter.setFont(font());
    const int height = rowHeight();
    const int first = verticalScrollBar()->value();
    const QFontMetrics metrics(font());
    const int addressWidth = metrics.horizontalAdvance(QStringLiteral("0000000000000000")) + 16;
    const int bytesWidth = m_bytesWidth > 0 ? m_bytesWidth : metrics.horizontalAdvance(QStringLiteral("00")) + 12;
    const int gutter = 36;
    const int symbolWidth = qMin(260, viewport()->width() / 4);
    const int textX = gutter + addressWidth + bytesWidth;
    const int textWidth = qMax(40, viewport()->width() - textX - symbolWidth - 8);

    for (int index = first; index < static_cast<int>(m_rows.size()); ++index)
    {
        const int y = (index - first) * height;

        if (y > viewport()->height())
        {
            break;
        }

        const Row& row = m_rows[static_cast<std::size_t>(index)];
        const bool selected = index == m_selected;
        const bool current = m_rip != 0 && row.address == m_rip;

        if (selected)
        {
            painter.fillRect(0, y, viewport()->width(), height, QColor(0xFF, 0xF3, 0xB0));
        }
        else if (current)
        {
            painter.fillRect(0, y, viewport()->width(), height, QColor(0xE8, 0xF1, 0xFF));
        }

        bool breakpoint = false;

        for (std::uint64_t address : m_breakpoints)
        {
            if (address == row.address)
            {
                breakpoint = true;
                break;
            }
        }

        if (breakpoint)
        {
            painter.setBrush(QColor(0xC0, 0x00, 0x00));
            painter.setPen(Qt::NoPen);
            painter.drawEllipse(QPoint(8, y + height / 2), 4, 4);
        }

        if (current)
        {
            painter.setBrush(QColor(0x1A, 0x5F, 0xB4));
            painter.setPen(Qt::NoPen);
            QPolygon arrow;
            arrow << QPoint(18, y + 4) << QPoint(30, y + height / 2) << QPoint(18, y + height - 4);
            painter.drawPolygon(arrow);
        }

        if (row.hasJump)
        {
            int targetRow = -1;

            for (int other = 0; other < static_cast<int>(m_rows.size()); ++other)
            {
                if (m_rows[static_cast<std::size_t>(other)].address == row.jumpTarget)
                {
                    targetRow = other;
                    break;
                }
            }

            if (targetRow >= 0)
            {
                const int y1 = (index - first) * height + height / 2;
                const int y2 = (targetRow - first) * height + height / 2;
                painter.setPen(QColor(0x1A, 0x5F, 0xB4));
                painter.drawLine(4, y1, 4, y2);
                painter.drawLine(4, y1, 14, y1);
                painter.drawLine(4, y2, 14, y2);
            }
        }

        painter.setPen(QColor(0x00, 0x00, 0x80));
        painter.drawText(gutter, y, addressWidth, height, Qt::AlignVCenter | Qt::AlignLeft, hex16(row.address).mid(2));
        painter.setPen(QColor(0x55, 0x55, 0x55));
        painter.drawText(gutter + addressWidth, y, bytesWidth, height, Qt::AlignVCenter | Qt::AlignLeft, row.bytes);
        const int space = row.text.indexOf(' ');
        const QString mnemonic = space < 0 ? row.text : row.text.left(space);
        const QString operands = space < 0 ? QString() : row.text.mid(space);
        painter.setPen(mnemonicColor(mnemonic));
        const int mnemonicWidth = metrics.horizontalAdvance(mnemonic);
        painter.drawText(textX, y, mnemonicWidth + 4, height, Qt::AlignVCenter | Qt::AlignLeft, mnemonic);
        painter.setPen(Qt::black);
        painter.drawText(textX + mnemonicWidth, y, qMax(0, textWidth - mnemonicWidth), height, Qt::AlignVCenter | Qt::AlignLeft,
                         metrics.elidedText(operands, Qt::ElideRight, qMax(0, textWidth - mnemonicWidth)));
        painter.setPen(QColor(0x80, 0x00, 0x00));
        painter.drawText(viewport()->width() - symbolWidth, y, symbolWidth - 4, height, Qt::AlignVCenter | Qt::AlignLeft,
                         metrics.elidedText(row.symbol, Qt::ElideRight, symbolWidth - 4));
    }

    return true;
}

void DisassemblyView::resizeEvent(QResizeEvent* event)
{
    QAbstractScrollArea::resizeEvent(event);
    updateScroll();
}

void DisassemblyView::keyPressEvent(QKeyEvent* event)
{
    if (m_rows.empty())
    {
        QAbstractScrollArea::keyPressEvent(event);
        return;
    }

    if (event->key() == Qt::Key_Up || event->key() == Qt::Key_Down)
    {
        const int delta = event->key() == Qt::Key_Up ? -1 : 1;
        m_selected = qBound(0, m_selected + delta, static_cast<int>(m_rows.size()) - 1);
        scrollToRow(m_selected);
        viewport()->update();
        emit selectionChanged();
        return;
    }

    QAbstractScrollArea::keyPressEvent(event);
}

int DisassemblyView::rowHeight() const
{
    return fontMetrics().height() + 4;
}

int DisassemblyView::visibleRows() const
{
    return qMax(1, viewport()->height() / rowHeight());
}

void DisassemblyView::updateScroll()
{
    const int maximum = qMax(0, static_cast<int>(m_rows.size()) - visibleRows());
    verticalScrollBar()->setRange(0, maximum);
    verticalScrollBar()->setPageStep(visibleRows());
    verticalScrollBar()->setSingleStep(1);
}

void DisassemblyView::scrollToRow(int row)
{
    const int first = verticalScrollBar()->value();
    const int visible = visibleRows();

    if (row < first)
    {
        verticalScrollBar()->setValue(row);
    }
    else if (row >= first + visible)
    {
        verticalScrollBar()->setValue(row - visible + 1);
    }
}

int DisassemblyView::rowAt(int y) const
{
    const int row = verticalScrollBar()->value() + y / rowHeight();

    if (row < 0 || row >= static_cast<int>(m_rows.size()))
    {
        return -1;
    }

    return row;
}

QColor DisassemblyView::mnemonicColor(const QString& text) const
{
    const QString mnemonic = text.toLower();

    if (mnemonic == QStringLiteral("ret") || mnemonic == QStringLiteral("retn") || mnemonic == QStringLiteral("iret") ||
        mnemonic == QStringLiteral("iretd") || mnemonic == QStringLiteral("iretq"))
    {
        return QColor(0xC0, 0x00, 0x00);
    }

    if (mnemonic == QStringLiteral("int") || mnemonic == QStringLiteral("int3") || mnemonic == QStringLiteral("syscall") ||
        mnemonic == QStringLiteral("sysret"))
    {
        return QColor(0x00, 0x80, 0x00);
    }

    if (mnemonic == QStringLiteral("call"))
    {
        return QColor(0x80, 0x00, 0x80);
    }

    if (mnemonic == QStringLiteral("jmp"))
    {
        return QColor(0x00, 0x00, 0xC0);
    }

    if (mnemonic.startsWith('j') || mnemonic.startsWith(QStringLiteral("loop")))
    {
        return QColor(0xC0, 0x00, 0x00);
    }

    if (mnemonic == QStringLiteral("nop"))
    {
        return QColor(0x80, 0x80, 0x80);
    }

    return Qt::black;
}
