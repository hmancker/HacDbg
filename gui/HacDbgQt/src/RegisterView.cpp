#include "RegisterView.h"

#include "Format.h"

#include <QEvent>
#include <QMouseEvent>
#include <QPainter>
#include <QScrollBar>

namespace
{
constexpr int kFlagBits[9] = {6, 2, 4, 11, 7, 10, 0, 8, 9};
const char* kFlagNames[9] = {"ZF", "PF", "AF", "OF", "SF", "DF", "CF", "TF", "IF"};

std::uint64_t fieldValue(const HACDBG_CORE_REGISTERS& registers, int index)
{
    switch (index)
    {
    case 0: return registers.Rax;
    case 1: return registers.Rbx;
    case 2: return registers.Rcx;
    case 3: return registers.Rdx;
    case 4: return registers.Rbp;
    case 5: return registers.Rsp;
    case 6: return registers.Rsi;
    case 7: return registers.Rdi;
    case 8: return registers.R8;
    case 9: return registers.R9;
    case 10: return registers.R10;
    case 11: return registers.R11;
    case 12: return registers.R12;
    case 13: return registers.R13;
    case 14: return registers.R14;
    case 15: return registers.R15;
    case 16: return registers.Rip;
    case 17: return registers.Rflags;
    case 18: return registers.Cr3;
    default: return 0;
    }
}
}

RegisterView::RegisterView(QWidget* parent)
    : QAbstractScrollArea(parent)
{
    static const char* names[] = {
        "RAX", "RBX", "RCX", "RDX", "RBP", "RSP", "RSI", "RDI",
        "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
        "RIP", "RFLAGS", "CR3"};

    for (int index = 0; index < 19; ++index)
    {
        m_lines[index].name = names[index];
    }

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

void RegisterView::setRegisters(const HACDBG_CORE_REGISTERS& registers, bool paused)
{
    if (paused == false)
    {
        if (m_previousPaused)
        {
            for (Line& line : m_lines)
            {
                line.known = false;
                line.changed = false;
                line.value = 0;
            }

            m_flagKnown = false;
            m_havePrevious = false;
        }

        m_previousPaused = false;
        viewport()->update();
        return;
    }

    const bool rflagsKnown = registers.RflagsKnown != 0;
    bool changedSnapshot = m_havePrevious == false;

    for (int index = 0; changedSnapshot == false && index < 19; ++index)
    {
        const bool known = index == 17 ? rflagsKnown : true;
        const std::uint64_t value = fieldValue(registers, index);

        if (known != m_previousKnown[index] || (known && value != m_previous[index]))
        {
            changedSnapshot = true;
        }
    }

    if (changedSnapshot == false)
    {
        return;
    }

    const bool mark = m_previousPaused && m_havePrevious;

    for (int index = 0; index < 19; ++index)
    {
        const bool known = index == 17 ? rflagsKnown : true;
        const std::uint64_t value = fieldValue(registers, index);
        m_lines[index].known = known;
        m_lines[index].value = value;
        m_lines[index].changed = mark && known && m_previousKnown[index] && value != m_previous[index];
        m_previous[index] = value;
        m_previousKnown[index] = known;
    }

    m_flagKnown = rflagsKnown;

    for (int index = 0; index < 9; ++index)
    {
        const int bit = kFlagBits[index];
        const int value = rflagsKnown ? static_cast<int>((registers.Rflags >> bit) & 1) : 0;
        m_flagChanged[index] = mark && m_previousRflagsKnown && rflagsKnown &&
                               static_cast<int>((m_previousRflags >> bit) & 1) != value;
        m_flagValue[index] = value;
    }

    m_previousRflags = registers.Rflags;
    m_previousRflagsKnown = rflagsKnown;
    m_havePrevious = true;
    m_previousPaused = true;
    updateScroll();
    viewport()->update();
}

bool RegisterView::eventFilter(QObject* watched, QEvent* event)
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

    if (event->type() == QEvent::MouseButtonDblClick)
    {
        auto* mouse = static_cast<QMouseEvent*>(event);
        const int index = (static_cast<int>(mouse->position().y()) + verticalScrollBar()->value()) / lineHeight();

        if (index == 16 && m_lines[16].known && m_lines[16].value != 0)
        {
            emit ripActivated(m_lines[16].value);
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
    const int height = lineHeight();
    const int offset = verticalScrollBar()->value();
    const int nameWidth = fontMetrics().horizontalAdvance(QStringLiteral("RFLAGS")) + 12;

    for (int index = 0; index < 19; ++index)
    {
        const int y = index * height - offset;

        if (y + height < 0)
        {
            continue;
        }

        if (y > viewport()->height())
        {
            break;
        }

        const Line& line = m_lines[index];
        painter.setPen(QColor(0x55, 0x55, 0x55));
        painter.drawText(4, y, nameWidth, height, Qt::AlignVCenter | Qt::AlignLeft, QString::fromLatin1(line.name));
        painter.setPen(line.changed ? QColor(0xC0, 0x00, 0x00) : Qt::black);
        painter.drawText(nameWidth, y, viewport()->width() - nameWidth - 4, height, Qt::AlignVCenter | Qt::AlignLeft,
                         line.known ? hex16(line.value) : QStringLiteral("—"));
    }

    const int gridTop = 19 * height + 6 - offset;

    if (gridTop > viewport()->height())
    {
        return true;
    }

    for (int index = 0; index < 9; ++index)
    {
        const int column = index % 3;
        const int row = index / 3;
        const int x = 4 + column * 72;
        const int y = gridTop + row * height;
        painter.setPen(QColor(0x55, 0x55, 0x55));
        painter.drawText(x, y, 28, height, Qt::AlignVCenter | Qt::AlignLeft, QString::fromLatin1(kFlagNames[index]));
        painter.setPen(m_flagChanged[index] ? QColor(0xC0, 0x00, 0x00) : Qt::black);
        painter.drawText(x + 28, y, 20, height, Qt::AlignVCenter | Qt::AlignLeft,
                         m_flagKnown ? QString::number(m_flagValue[index]) : QStringLiteral("—"));
    }

    return true;
}

void RegisterView::resizeEvent(QResizeEvent* event)
{
    QAbstractScrollArea::resizeEvent(event);
    updateScroll();
}

int RegisterView::lineHeight() const
{
    return fontMetrics().height() + 3;
}

void RegisterView::updateScroll()
{
    const int content = 19 * lineHeight() + 6 + 3 * lineHeight();
    const int maximum = qMax(0, content - viewport()->height());
    verticalScrollBar()->setRange(0, maximum);
    verticalScrollBar()->setPageStep(viewport()->height());
    verticalScrollBar()->setSingleStep(lineHeight());
}
