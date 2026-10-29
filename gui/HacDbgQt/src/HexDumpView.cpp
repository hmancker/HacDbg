#include "HexDumpView.h"

#include "Format.h"

#include <QEvent>
#include <QPainter>
#include <QScrollBar>

HexDumpView::HexDumpView(QWidget* parent)
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

void HexDumpView::setBytes(std::uint64_t base, std::uint64_t cursor, int cursorBytes, std::vector<std::uint8_t> bytes)
{
    const int nextCursorBytes = cursorBytes < 1 ? 1 : cursorBytes;
    const bool keepScroll = base == m_base && cursor == m_cursor && nextCursorBytes == m_cursorBytes;
    const int scroll = verticalScrollBar()->value();
    m_base = base;
    m_cursor = cursor;
    m_cursorBytes = nextCursorBytes;
    m_bytes = std::move(bytes);
    updateScroll();

    if (keepScroll)
    {
        verticalScrollBar()->setValue(scroll);
    }
    else if (m_cursor >= m_base && m_cursor - m_base < m_bytes.size())
    {
        const int row = static_cast<int>((m_cursor - m_base) / 16);
        const int visible = qMax(1, viewport()->height() / rowHeight());
        verticalScrollBar()->setValue(qBound(0, row - visible / 2, verticalScrollBar()->maximum()));
    }

    viewport()->update();
}

void HexDumpView::resizeEvent(QResizeEvent* event)
{
    QAbstractScrollArea::resizeEvent(event);
    updateScroll();
}

bool HexDumpView::eventFilter(QObject* watched, QEvent* event)
{
    if (watched != viewport())
    {
        return QAbstractScrollArea::eventFilter(watched, event);
    }

    if (event->type() == QEvent::MouseButtonPress)
    {
        setFocus(Qt::MouseFocusReason);
        return QAbstractScrollArea::eventFilter(watched, event);
    }

    if (event->type() != QEvent::Paint)
    {
        return QAbstractScrollArea::eventFilter(watched, event);
    }

    QPainter painter(viewport());
    painter.fillRect(viewport()->rect(), Qt::white);
    painter.setFont(font());
    const int height = rowHeight();
    const QFontMetrics metrics(font());
    const int addressWidth = metrics.horizontalAdvance(QStringLiteral("0000000000000000")) + 12;
    const int byteWidth = metrics.horizontalAdvance(QStringLiteral("00"));
    const int gap = metrics.horizontalAdvance(QStringLiteral(" "));
    const int hexWidth = 16 * byteWidth + 15 * gap;
    const int first = verticalScrollBar()->value();
    const int rows = (static_cast<int>(m_bytes.size()) + 15) / 16;

    for (int row = first; row < rows; ++row)
    {
        const int y = (row - first) * height;

        if (y > viewport()->height())
        {
            break;
        }

        const int offset = row * 16;
        painter.setPen(QColor(0x00, 0x00, 0x80));
        painter.drawText(4, y, addressWidth, height, Qt::AlignVCenter | Qt::AlignLeft, hex16(m_base + static_cast<std::uint64_t>(offset)).mid(2));

        QString ascii;

        for (int column = 0; column < 16 && offset + column < static_cast<int>(m_bytes.size()); ++column)
        {
            const int absolute = offset + column;
            const std::uint8_t value = m_bytes[static_cast<std::size_t>(absolute)];
            const bool marked = m_cursor >= m_base &&
                                absolute >= static_cast<int>(m_cursor - m_base) &&
                                absolute < static_cast<int>(m_cursor - m_base) + m_cursorBytes;
            const int x = addressWidth + column * (byteWidth + gap);

            if (marked)
            {
                painter.fillRect(x - 1, y + 1, byteWidth + 2, height - 2, QColor(0xFF, 0xD0, 0xD0));
            }

            painter.setPen(Qt::black);
            painter.drawText(x, y, byteWidth, height, Qt::AlignCenter, QStringLiteral("%1").arg(value, 2, 16, QLatin1Char('0')).toUpper());
            ascii.append(value >= 0x20 && value < 0x7F ? QChar(value) : QChar('.'));
        }

        painter.setPen(QColor(0x33, 0x33, 0x33));
        painter.drawText(addressWidth + hexWidth + 12, y, viewport()->width() - addressWidth - hexWidth - 16, height,
                         Qt::AlignVCenter | Qt::AlignLeft, ascii);
    }

    return true;
}

int HexDumpView::rowHeight() const
{
    return fontMetrics().height() + 4;
}

void HexDumpView::updateScroll()
{
    const int rows = (static_cast<int>(m_bytes.size()) + 15) / 16;
    const int visible = qMax(1, viewport()->height() / rowHeight());
    verticalScrollBar()->setRange(0, qMax(0, rows - visible));
    verticalScrollBar()->setPageStep(visible);
    verticalScrollBar()->setSingleStep(1);
}
