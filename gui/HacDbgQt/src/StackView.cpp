#include "StackView.h"

#include "Format.h"

#include <QEvent>
#include <QMouseEvent>
#include <QPainter>
#include <QScrollBar>

#include <algorithm>
#include <cstring>

namespace
{
constexpr std::uint64_t kUserAddressLimit = 0x00007FFFFFFFFFFFull;

QString hexSlot(std::uint64_t value)
{
    return QStringLiteral("%1").arg(value, 16, 16, QLatin1Char('0')).toUpper();
}

}

void StackView::addRow(std::uint64_t address, std::uint64_t value, std::uint64_t rsp, const std::vector<Note>& notes,
                       const std::vector<Span>& spans)
{
    Row row;
    row.address = address;
    row.value = value;
    row.rsp = rsp != 0 && address == (rsp & ~static_cast<std::uint64_t>(7));

    for (const Note& note : notes)
    {
        if (note.slot == address)
        {
            row.comment = note.text;
            row.isReturn = true;
            break;
        }
    }

    for (const Span& span : spans)
    {
        if (address < span.start || address >= span.end)
        {
            continue;
        }

        row.kernel = span.kernel;

        if (address == span.start)
        {
            row.bracket |= 1;
        }

        if (address + 8 >= span.end)
        {
            row.bracket |= 2;
        }

        if (row.bracket == 0)
        {
            row.bracket = 4;
        }

        break;
    }

    m_rows.push_back(std::move(row));
}

StackView::StackView(QWidget* parent)
    : QAbstractScrollArea(parent)
{
    QFont font(QStringLiteral("Cascadia Mono"));
    font.setStyleHint(QFont::Monospace);
    font.setPointSize(10);
    setFont(font);
    setFocusPolicy(Qt::StrongFocus);
    setFrameShape(QFrame::NoFrame);
    viewport()->installEventFilter(this);
    QPalette pal = viewport()->palette();
    pal.setColor(QPalette::Base, QColor(0xFF, 0xF8, 0xF0));
    viewport()->setPalette(pal);
    viewport()->setAutoFillBackground(true);
}

void StackView::setSnapshot(const HACDBG_CORE_STACK_FRAME* frames, std::uint32_t count, std::uint64_t base,
                            std::uint64_t rsp, const std::uint8_t* bytes, std::uint32_t byteCount)
{
    std::vector<Note> notes;
    std::vector<Span> spans;
    std::vector<std::uint32_t> order;

    m_rows.clear();
    m_selected = -1;

    if (frames != nullptr && count > 0)
    {
        notes.reserve(count);
        order.reserve(count);

        for (std::uint32_t index = 0; index < count; ++index)
        {
            order.push_back(index);
            const HACDBG_CORE_STACK_FRAME& frame = frames[index];

            if (frame.HasReturn == 0 || frame.ChildSp == 0)
            {
                continue;
            }

            QString target;

            if (index + 1 < count)
            {
                target = fromField(frames[index + 1].Symbol, HACDBG_CORE_SYMBOL_SIZE);
            }

            if (target.isEmpty())
            {
                target = hexSlot(frame.ReturnAddress);
            }

            notes.push_back(Note{frame.ChildSp, QStringLiteral("return to ") + target});
        }

        std::sort(order.begin(), order.end(), [frames](std::uint32_t left, std::uint32_t right)
        {
            return frames[left].ChildSp < frames[right].ChildSp;
        });

        for (std::size_t index = 0; index < order.size(); ++index)
        {
            const HACDBG_CORE_STACK_FRAME& frame = frames[order[index]];

            if (frame.HasReturn == 0 || frame.ChildSp == 0)
            {
                continue;
            }

            std::uint64_t end = frame.ChildSp + 8;

            for (std::size_t next = index + 1; next < order.size(); ++next)
            {
                const std::uint64_t child = frames[order[next]].ChildSp;

                if (child > frame.ChildSp)
                {
                    end = child;
                    break;
                }
            }

            spans.push_back(Span{frame.ChildSp, end, frame.InstructionPointer > kUserAddressLimit});
        }
    }

    if (bytes != nullptr && byteCount >= 8 && base != 0)
    {
        const std::uint32_t usable = byteCount & ~std::uint32_t{7};
        m_rows.reserve(usable / 8);

        for (std::uint32_t offset = 0; offset < usable; offset += 8)
        {
            std::uint64_t value = 0;
            std::memcpy(&value, bytes + offset, sizeof(value));
            addRow(base + offset, value, rsp, notes, spans);
        }
    }
    else
    {
        for (const Note& note : notes)
        {
            std::uint64_t value = 0;

            for (std::uint32_t index = 0; frames != nullptr && index < count; ++index)
            {
                if (frames[index].ChildSp == note.slot && frames[index].HasReturn != 0)
                {
                    value = frames[index].ReturnAddress;
                    break;
                }
            }

            addRow(note.slot, value, rsp, notes, spans);
        }
    }

    updateScroll();
    verticalScrollBar()->setValue(0);
    viewport()->update();
}

bool StackView::hasFrames() const
{
    return m_rows.empty() == false;
}

void StackView::resizeEvent(QResizeEvent* event)
{
    QAbstractScrollArea::resizeEvent(event);
    updateScroll();
}

bool StackView::eventFilter(QObject* watched, QEvent* event)
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
            setFocus(Qt::MouseFocusReason);
            viewport()->update();
        }

        return true;
    }

    if (event->type() == QEvent::MouseButtonDblClick)
    {
        auto* mouse = static_cast<QMouseEvent*>(event);
        const int row = rowAt(static_cast<int>(mouse->position().y()));

        if (row >= 0 && m_rows[static_cast<std::size_t>(row)].value != 0)
        {
            m_selected = row;
            viewport()->update();
            emit addressActivated(m_rows[static_cast<std::size_t>(row)].value);
        }

        return true;
    }

    if (event->type() != QEvent::Paint)
    {
        return QAbstractScrollArea::eventFilter(watched, event);
    }

    QPainter painter(viewport());
    paintRows(painter);
    return true;
}

int StackView::rowHeight() const
{
    return fontMetrics().height() + 4;
}

int StackView::rowAt(int y) const
{
    if (y < 0 || m_rows.empty())
    {
        return -1;
    }

    const int row = verticalScrollBar()->value() + y / rowHeight();

    if (row < 0 || row >= static_cast<int>(m_rows.size()))
    {
        return -1;
    }

    return row;
}

void StackView::updateScroll()
{
    const int visible = qMax(1, viewport()->height() / rowHeight());
    verticalScrollBar()->setRange(0, qMax(0, static_cast<int>(m_rows.size()) - visible));
    verticalScrollBar()->setPageStep(visible);
    verticalScrollBar()->setSingleStep(1);
}

void StackView::paintRows(QPainter& painter) const
{
    painter.fillRect(viewport()->rect(), QColor(0xFF, 0xF8, 0xF0));
    painter.setFont(font());
    const int height = rowHeight();
    const QFontMetrics metrics(font());
    const int addressWidth = metrics.horizontalAdvance(QStringLiteral("0000000000000000")) + 8;
    const int valueWidth = addressWidth;
    const int bracketWidth = 12;
    const int first = verticalScrollBar()->value();
    const QColor returnColor(0xFF, 0x00, 0x00);

    for (int row = first; row < static_cast<int>(m_rows.size()); ++row)
    {
        const int y = (row - first) * height;

        if (y > viewport()->height())
        {
            break;
        }

        const Row& item = m_rows[static_cast<std::size_t>(row)];
        const bool selected = row == m_selected;

        if (selected)
        {
            painter.fillRect(0, y, viewport()->width(), height, QColor(0xC0, 0xC0, 0xC0));
        }

        if (item.rsp)
        {
            painter.fillRect(2, y, addressWidth, height, Qt::black);
            painter.setPen(Qt::white);
        }
        else
        {
            painter.setPen(QColor(0x80, 0x80, 0x80));
        }

        painter.drawText(6, y, addressWidth - 4, height, Qt::AlignVCenter | Qt::AlignLeft, hexSlot(item.address));

        const int bracketX = 4 + addressWidth;
        const int valueX = bracketX + bracketWidth;

        if (item.bracket != 0)
        {
            painter.setPen(QPen(item.kernel ? QColor(0x00, 0x00, 0xFF) : Qt::black, 2));
            const int mid = y + height / 2;
            const int tick = y + height / 4;
            const int lower = y + (height * 3) / 4;

            if ((item.bracket & 1) != 0)
            {
                painter.drawLine(bracketX + 7, tick, bracketX + 2, tick);
                painter.drawLine(bracketX + 2, tick, bracketX + 2, mid);
            }
            else
            {
                painter.drawLine(bracketX + 2, y, bracketX + 2, mid);
            }

            if ((item.bracket & 2) != 0)
            {
                painter.drawLine(bracketX + 7, lower, bracketX + 2, lower);
                painter.drawLine(bracketX + 2, lower, bracketX + 2, mid);
            }
            else
            {
                painter.drawLine(bracketX + 2, y + height, bracketX + 2, mid);
            }
        }

        painter.setPen(item.isReturn ? returnColor : Qt::black);
        painter.drawText(valueX, y, valueWidth, height, Qt::AlignVCenter | Qt::AlignLeft, hexSlot(item.value));

        if (item.comment.isEmpty() == false)
        {
            painter.setPen(returnColor);
            painter.drawText(valueX + valueWidth + 8, y, viewport()->width() - valueX - valueWidth - 12, height,
                             Qt::AlignVCenter | Qt::AlignLeft, item.comment);
        }
    }
}
