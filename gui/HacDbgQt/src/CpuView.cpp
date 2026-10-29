#include "CpuView.h"

#include "DisassemblyView.h"
#include "Format.h"
#include "HexDumpView.h"
#include "RegisterView.h"
#include "StackView.h"

#include <QApplication>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QShortcut>
#include <QSplitter>
#include <QTimer>
#include <QVBoxLayout>

namespace
{
constexpr int kMemoryRowBytes = 16;
constexpr int kMemoryCacheLimit = 32;
constexpr int kStackDelayMs = 300;
constexpr std::uint32_t kInstructionCount = 64;

std::uint64_t alignRow(std::uint64_t address)
{
    return address & ~static_cast<std::uint64_t>(kMemoryRowBytes - 1);
}

QWidget* makeGotoBar(QWidget* parent, QLineEdit** address, QLineEdit** cr3)
{
    auto* bar = new QWidget(parent);
    auto* layout = new QHBoxLayout(bar);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->addWidget(new QLabel(QStringLiteral("地址"), bar));
    *address = new QLineEdit(bar);
    layout->addWidget(*address, 2);
    layout->addWidget(new QLabel(QStringLiteral("CR3"), bar));
    *cr3 = new QLineEdit(bar);
    layout->addWidget(*cr3, 1);
    layout->addWidget(new QPushButton(QStringLiteral("Go"), bar));
    bar->hide();
    return bar;
}
}

CpuView::CpuView(QWidget* parent)
    : QWidget(parent)
{
    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(4, 4, 4, 4);
    root->setSpacing(4);

    auto* vertical = new QSplitter(Qt::Vertical, this);
    auto* top = new QSplitter(Qt::Horizontal, vertical);
    auto* bottom = new QSplitter(Qt::Horizontal, vertical);
    auto* disasmPane = new QWidget(top);
    auto* disasmLayout = new QVBoxLayout(disasmPane);
    disasmLayout->setContentsMargins(0, 0, 0, 0);
    disasmLayout->setSpacing(2);
    m_disasmGoto = makeGotoBar(disasmPane, &m_disasmAddress, &m_disasmCr3);
    m_disassembly = new DisassemblyView(disasmPane);
    m_info = new QLabel(disasmPane);
    m_info->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_status = new QLabel(disasmPane);
    disasmLayout->addWidget(m_disasmGoto);
    disasmLayout->addWidget(m_disassembly, 1);
    disasmLayout->addWidget(m_info);
    disasmLayout->addWidget(m_status);
    m_registers = new RegisterView(top);
    top->addWidget(disasmPane);
    top->addWidget(m_registers);
    top->setStretchFactor(0, 77);
    top->setStretchFactor(1, 23);

    auto* dumpPane = new QWidget(bottom);
    auto* dumpLayout = new QVBoxLayout(dumpPane);
    dumpLayout->setContentsMargins(0, 0, 0, 0);
    dumpLayout->setSpacing(2);
    m_memoryGoto = makeGotoBar(dumpPane, &m_memoryAddress, &m_memoryCr3Edit);
    m_memoryStatus = new QLabel(QStringLiteral("内存"), dumpPane);
    m_dump = new HexDumpView(dumpPane);
    dumpLayout->addWidget(m_memoryGoto);
    dumpLayout->addWidget(m_memoryStatus);
    dumpLayout->addWidget(m_dump, 1);
    auto* stackPane = new QWidget(bottom);
    auto* stackLayout = new QVBoxLayout(stackPane);
    stackLayout->setContentsMargins(0, 0, 0, 0);
    stackLayout->setSpacing(2);
    m_stackStatus = new QLabel(QStringLiteral("堆栈"), stackPane);
    m_stack = new StackView(stackPane);
    stackLayout->addWidget(m_stackStatus);
    stackLayout->addWidget(m_stack, 1);
    bottom->addWidget(dumpPane);
    bottom->addWidget(stackPane);
    bottom->setStretchFactor(0, 60);
    bottom->setStretchFactor(1, 40);
    vertical->addWidget(top);
    vertical->addWidget(bottom);
    vertical->setStretchFactor(0, 48);
    vertical->setStretchFactor(1, 62);
    root->addWidget(vertical, 1);

    auto* disasmGo = m_disasmGoto->findChild<QPushButton*>();
    auto* memoryGo = m_memoryGoto->findChild<QPushButton*>();
    connect(disasmGo, &QPushButton::clicked, this, [this] { submitGoto(false); });
    connect(memoryGo, &QPushButton::clicked, this, [this] { submitGoto(true); });
    connect(m_disasmAddress, &QLineEdit::returnPressed, this, [this] { submitGoto(false); });
    connect(m_disasmCr3, &QLineEdit::returnPressed, this, [this] { submitGoto(false); });
    connect(m_memoryAddress, &QLineEdit::returnPressed, this, [this] { submitGoto(true); });
    connect(m_memoryCr3Edit, &QLineEdit::returnPressed, this, [this] { submitGoto(true); });

    auto* gotoShortcut = new QShortcut(QKeySequence(Qt::CTRL | Qt::Key_G), this);
    gotoShortcut->setContext(Qt::WidgetWithChildrenShortcut);
    connect(gotoShortcut, &QShortcut::activated, this, &CpuView::showGoto);
    auto* disasmEsc = new QShortcut(QKeySequence(Qt::Key_Escape), m_disasmGoto);
    disasmEsc->setContext(Qt::WidgetWithChildrenShortcut);
    connect(disasmEsc, &QShortcut::activated, m_disasmGoto, &QWidget::hide);
    auto* memoryEsc = new QShortcut(QKeySequence(Qt::Key_Escape), m_memoryGoto);
    memoryEsc->setContext(Qt::WidgetWithChildrenShortcut);
    connect(memoryEsc, &QShortcut::activated, m_memoryGoto, &QWidget::hide);

    m_followTimer = new QTimer(this);
    m_followTimer->setSingleShot(true);
    m_followTimer->setInterval(kStackDelayMs);
    connect(m_followTimer, &QTimer::timeout, this, &CpuView::flushStack);

    connect(m_disassembly, &DisassemblyView::selectionChanged, this, &CpuView::noteSelection);
    connect(m_stack, &StackView::addressActivated, this, [this](std::uint64_t address)
    {
        hideGoto();
        requestDisassembly(address, m_disassemblyCr3);
    });
    connect(m_registers, &RegisterView::ripActivated, this, [this](std::uint64_t address)
    {
        hideGoto();
        requestDisassembly(address, m_pausedCr3);
    });
}

void CpuView::setSession(CoreSession* session)
{
    m_session = session;
}

void CpuView::openAt(std::uint64_t address, std::uint64_t cr3)
{
    if (address == 0)
    {
        return;
    }

    hideGoto();
    requestDisassembly(address, cr3);
}

void CpuView::onState(const HACDBG_CORE_STATE& state)
{
    m_registers->setRegisters(state.Registers, state.Paused != 0);
    std::vector<std::uint64_t> breakpoints;

    for (std::uint32_t index = 0; index < state.BreakpointCount && index < HACDBG_CORE_MAX_BREAKPOINTS; ++index)
    {
        const HACDBG_CORE_BREAKPOINT& breakpoint = state.Breakpoints[index];

        if (breakpoint.Enabled == 0)
        {
            continue;
        }

        if (breakpoint.Cr3 != 0 && state.Registers.Cr3 != 0 && breakpoint.Cr3 != state.Registers.Cr3)
        {
            continue;
        }

        breakpoints.push_back(breakpoint.Address);
    }

    m_breakpoints = breakpoints;

    if (state.Paused == 0)
    {
        if (m_paused)
        {
            m_stack->setSnapshot(nullptr, 0, 0, 0, nullptr, 0);
            m_stackStatus->setText(QStringLiteral("没有暂停线程"));
        }

        m_paused = false;
        m_pausedCr3 = 0;
        m_lastRip = 0;
        m_lastRsp = 0;
        m_stackRsp = 0;
        m_stackCr3 = 0;
        m_disassemblyStale = false;
        m_stackStale = false;
        m_followTimer->stop();
        m_disassembly->setRip(0, breakpoints);
        return;
    }

    const bool entered = m_paused == false;
    const std::uint64_t rip = state.Registers.Rip;
    const std::uint64_t rsp = state.Registers.Rsp;
    const std::uint64_t cr3 = state.Registers.Cr3;
    const bool ripChanged = entered || m_lastRip != rip;
    const bool rspChanged = entered || m_lastRsp != rsp;
    const bool cr3Changed = entered || m_pausedCr3 != cr3;
    m_paused = true;
    m_pausedCr3 = cr3;
    m_lastRip = rip;
    m_lastRsp = rsp;
    m_disassembly->setRip(rip, breakpoints);

    if ((ripChanged == false && rspChanged == false && cr3Changed == false) || m_session == nullptr || m_session->isStarted() == false)
    {
        return;
    }

    if (rip == 0)
    {
        m_disassemblyStale = false;
        m_stackStale = false;
        m_followTimer->stop();
        return;
    }

    const bool ripVisible = m_disassemblyCr3 == cr3 && m_disassembly->containsAddress(rip);

    if (ripVisible == false)
    {
        hideGoto();
        m_disassemblyStale = true;
    }
    else
    {
        m_disassemblyStale = false;
    }

    const bool stackFresh = m_stack->hasFrames() && m_stackRsp == rsp && m_stackCr3 == cr3;

    if (stackFresh)
    {
        m_stackStale = false;
    }
    else if (m_stackRequest != 0)
    {
        m_stackStale = false;
    }
    else
    {
        m_stackStale = true;
    }

    if (m_stepBurst)
    {
        m_followTimer->stop();
        return;
    }

    if (m_disassemblyStale)
    {
        queueDisassembly();
    }

    if (m_stackStale)
    {
        scheduleStack();
    }
    else
    {
        m_followTimer->stop();
    }
}

void CpuView::setStepBurst(bool burst)
{
    if (m_stepBurst == burst)
    {
        return;
    }

    m_stepBurst = burst;

    if (burst)
    {
        m_followTimer->stop();
        return;
    }

    queueDisassembly();

    if (m_stackStale)
    {
        flushStack();
    }
}

void CpuView::poll()
{
    if (m_session == nullptr || m_session->isStarted() == false)
    {
        return;
    }

    HACDBG_CORE_VIEW_STATUS status = {};

    if (takeCompleted(HacDbgViewResolve, &m_resolveRequest, &status))
    {
        HACDBG_CORE_RESOLVED_ADDRESS resolved = {};

        if (status.Failed != 0 || m_session->copyResolvedAddress(&resolved) == false)
        {
            const QString message = status.Failed != 0 ? fromField(status.Message, HACDBG_CORE_MESSAGE_SIZE) : QStringLiteral("解析失败");

            if (m_resolveForMemory)
            {
                setMemoryStatus(message);
            }
            else
            {
                setDisassemblyStatus(message);
            }
        }
        else
        {
            const QString symbol = fromField(resolved.Symbol, HACDBG_CORE_SYMBOL_SIZE);

            if (m_resolveForMemory)
            {
                requestMemory(resolved.Address, m_resolveCr3, 1);
                hideGoto();

                if (symbol.isEmpty() == false)
                {
                    setMemoryStatus(symbol);
                }
            }
            else
            {
                requestDisassembly(resolved.Address, m_resolveCr3);
                hideGoto();

                if (symbol.isEmpty() == false)
                {
                    setDisassemblyStatus(symbol);
                }
            }
        }
    }

    if (takeCompleted(HacDbgViewDisassembly, &m_disassemblyRequest, &status))
    {
        if (status.Failed != 0)
        {
            setDisassemblyStatus(fromField(status.Message, HACDBG_CORE_MESSAGE_SIZE));
        }
        else
        {
            HACDBG_CORE_INSTRUCTION instructions[HACDBG_CORE_MAX_DISASSEMBLY_LINES] = {};
            std::uint32_t count = 0;

            if (m_session->copyDisassembly(instructions, HACDBG_CORE_MAX_DISASSEMBLY_LINES, &count) == false)
            {
                setDisassemblyStatus(QStringLiteral("复制反汇编失败"));
            }
            else if (count == 0)
            {
                setDisassemblyStatus(QStringLiteral("没有可显示的指令"));
            }
            else
            {
                std::vector<DisassemblyView::Row> rows;
                rows.reserve(count);

                for (std::uint32_t index = 0; index < count; ++index)
                {
                    DisassemblyView::Row row;
                    row.address = instructions[index].Address;
                    row.length = instructions[index].Length;
                    row.bytes = fromField(instructions[index].Bytes, 32);
                    row.text = fromField(instructions[index].Text, 160);
                    row.symbol = fromField(instructions[index].Symbol, HACDBG_CORE_SYMBOL_SIZE);
                    rows.push_back(std::move(row));
                }

                setDisassemblyStatus(status.Truncated != 0 ? QStringLiteral("%1 条，已截断").arg(count) : QStringLiteral("%1 条").arg(count));
                m_suppressSelection = true;
                m_disassembly->setRows(std::move(rows), m_lastRip, m_breakpoints);
                m_suppressSelection = false;
                noteSelection();

                if (m_followRip && m_paused && m_lastRip != 0 && m_disassembly->containsAddress(m_lastRip) == false)
                {
                    m_disassemblyStale = true;
                    queueDisassembly();
                }
                else
                {
                    m_disassemblyStale = false;
                }
            }
        }
    }

    if (takeCompleted(HacDbgViewMemory, &m_memoryRequest, &status))
    {
        if (status.Failed != 0)
        {
            setMemoryStatus(fromField(status.Message, HACDBG_CORE_MESSAGE_SIZE));
        }
        else
        {
            HACDBG_CORE_MEMORY memory = {};

            if (m_session->copyMemory(&memory) == false)
            {
                setMemoryStatus(QStringLiteral("复制内存失败"));
            }
            else
            {
                MemoryPage page;
                page.address = memory.Address;
                page.cr3 = memory.Cr3;
                const std::uint32_t length = memory.BytesValid < HACDBG_CORE_MAX_MEMORY_BYTES ? memory.BytesValid : HACDBG_CORE_MAX_MEMORY_BYTES;
                page.bytes.assign(memory.Data, memory.Data + length);
                m_memoryCache.push_back(page);

                if (m_memoryCache.size() > kMemoryCacheLimit)
                {
                    m_memoryCache.erase(m_memoryCache.begin());
                }

                showMemory(page);
                setMemoryStatus(QStringLiteral("%1/%2 字节 · %3 · CR3 %4")
                                    .arg(memory.BytesValid)
                                    .arg(memory.Requested)
                                    .arg(hex16(m_memoryCursor))
                                    .arg(hex16(memory.Cr3)));
            }
        }
    }

    if (takeCompleted(HacDbgViewStack, &m_stackRequest, &status))
    {
        if (m_paused == false)
        {
            return;
        }

        if (status.Failed != 0)
        {
            m_stack->setSnapshot(nullptr, 0, 0, 0, nullptr, 0);
            m_stackStatus->setText(fromField(status.Message, HACDBG_CORE_MESSAGE_SIZE));
        }
        else
        {
            HACDBG_CORE_STACK_FRAME frames[HACDBG_CORE_MAX_STACK_FRAMES] = {};
            std::uint32_t count = 0;

            if (m_session->copyStack(frames, HACDBG_CORE_MAX_STACK_FRAMES, &count) == false)
            {
                m_stackStatus->setText(QStringLiteral("复制调用栈失败"));
            }
            else if (count > 0 && frames[0].InstructionPointer != m_lastRip)
            {
                m_stackStale = true;
                m_stackStatus->setText(QStringLiteral("读取中..."));

                if (m_stepBurst == false)
                {
                    scheduleStack();
                }
            }
            else
            {
                HACDBG_CORE_STACK_WINDOW window = {};
                const bool haveWindow = m_session->copyStackWindow(&window);
                m_stack->setSnapshot(frames, count, haveWindow ? window.Address : 0, haveWindow ? window.Rsp : m_lastRsp,
                                     haveWindow ? window.Data : nullptr, haveWindow ? window.BytesValid : 0);
                m_stackRsp = m_lastRsp;
                m_stackCr3 = m_pausedCr3;
                m_stackStale = false;
                m_stackStatus->setText(status.Truncated != 0 ? QStringLiteral("%1 帧，已截断").arg(count) : QStringLiteral("%1 帧").arg(count));
            }
        }
    }
}

void CpuView::showGoto()
{
    QWidget* focus = QApplication::focusWidget();
    const bool memory = focus != nullptr &&
                        (m_dump->isAncestorOf(focus) || focus == m_dump ||
                         (m_memoryGoto->isVisible() && m_memoryGoto->isAncestorOf(focus)));
    hideGoto();

    if (memory)
    {
        if (m_memoryCursor != 0)
        {
            m_memoryAddress->setText(hex16(m_memoryCursor));
        }

        m_memoryCr3Edit->setText(m_memoryCr3 == 0 ? QString() : hex16(m_memoryCr3));
        m_memoryGoto->show();
        m_memoryAddress->setFocus();
        m_memoryAddress->selectAll();
        return;
    }

    const DisassemblyView::Row* row = m_disassembly->selectedRow();
    const std::uint64_t address = row != nullptr ? row->address : m_lastRip;

    if (address != 0)
    {
        m_disasmAddress->setText(hex16(address));
    }

    const std::uint64_t cr3 = m_disassemblyCr3 != 0 ? m_disassemblyCr3 : m_pausedCr3;
    m_disasmCr3->setText(cr3 == 0 ? QString() : hex16(cr3));
    m_disasmGoto->show();
    m_disasmAddress->setFocus();
    m_disasmAddress->selectAll();
}

void CpuView::hideGoto()
{
    m_disasmGoto->hide();
    m_memoryGoto->hide();
}

void CpuView::submitGoto(bool memory)
{
    QLineEdit* addressEdit = memory ? m_memoryAddress : m_disasmAddress;
    QLineEdit* cr3Edit = memory ? m_memoryCr3Edit : m_disasmCr3;
    auto setStatus = [this, memory](const QString& text)
    {
        if (memory)
        {
            setMemoryStatus(text);
        }
        else
        {
            setDisassemblyStatus(text);
        }
    };

    if (m_session == nullptr || m_session->isStarted() == false)
    {
        setStatus(QStringLiteral("未连接"));
        return;
    }

    std::uint64_t cr3 = 0;

    if (parseHex(cr3Edit->text(), &cr3, true) == false)
    {
        setStatus(QStringLiteral("CR3 格式无效"));
        return;
    }

    const QString text = addressEdit->text().trimmed();

    if (text.isEmpty())
    {
        setStatus(QStringLiteral("请输入地址或符号"));
        return;
    }

    std::uint64_t address = 0;

    if (parseHex(text, &address, false))
    {
        if (memory)
        {
            requestMemory(address, cr3, 1);
        }
        else
        {
            requestDisassembly(address, cr3);
        }

        hideGoto();
        return;
    }

    m_resolveForMemory = memory;
    m_resolveCr3 = cr3;
    m_resolveRequest = m_session->requestResolve(text);
    setStatus(m_resolveRequest == 0 ? QStringLiteral("无法排队") : QStringLiteral("解析中..."));
}

void CpuView::queueDisassembly()
{
    if (m_stepBurst || m_disassemblyStale == false || m_disassemblyRequest != 0 || m_lastRip == 0 || m_session == nullptr ||
        m_session->isStarted() == false)
    {
        return;
    }

    if (m_disassemblyCr3 == m_pausedCr3 && m_disassembly->containsAddress(m_lastRip))
    {
        m_disassemblyStale = false;
        return;
    }

    hideGoto();
    requestDisassembly(m_lastRip, m_pausedCr3, true);
}

void CpuView::scheduleStack()
{
    //
    // The stack walk shares the worker with the step command. Wait until
    // repeated steps have been idle so the next F10 or F11 is not stuck
    // behind the user-module walk.
    //
    if (m_stepBurst)
    {
        return;
    }

    m_followTimer->start();
}

void CpuView::flushStack()
{
    if (m_stepBurst || m_paused == false || m_session == nullptr || m_session->isStarted() == false)
    {
        return;
    }

    if (m_stackStale == false || m_stackRequest != 0)
    {
        return;
    }

    if (m_stack->hasFrames() && m_stackRsp == m_lastRsp && m_stackCr3 == m_pausedCr3)
    {
        m_stackStale = false;
        return;
    }

    m_stackStale = false;
    m_stackRequest = m_session->requestStack(32);
    m_stackStatus->setText(m_stackRequest == 0 ? QStringLiteral("无法排队") : QStringLiteral("读取中..."));
}

void CpuView::requestDisassembly(std::uint64_t address, std::uint64_t cr3, bool follow)
{
    if (m_session == nullptr || m_session->isStarted() == false || address == 0)
    {
        return;
    }

    if (follow && m_followRip && m_disassemblyRequest != 0)
    {
        m_disassemblyStale = true;
        return;
    }

    m_followRip = follow;

    if (follow == false)
    {
        m_disassemblyStale = false;
    }

    m_disassemblyCr3 = cr3;
    m_disassemblyRequest = m_session->requestDisassembly(address, cr3, kInstructionCount);

    if (follow && m_disassemblyRequest != 0)
    {
        m_disassemblyStale = false;
    }

    setDisassemblyStatus(m_disassemblyRequest == 0 ? QStringLiteral("无法排队") : QStringLiteral("读取中..."));
}

void CpuView::requestMemory(std::uint64_t address, std::uint64_t cr3, int highlightBytes)
{
    if (m_session == nullptr || m_session->isStarted() == false)
    {
        return;
    }

    m_memoryCursor = address;
    m_memoryCr3 = cr3;
    m_memoryCursorBytes = highlightBytes < 1 ? 1 : highlightBytes;
    m_memoryRequest = m_session->requestMemory(alignRow(address), cr3, HACDBG_CORE_MAX_MEMORY_BYTES);
    setMemoryStatus(m_memoryRequest == 0 ? QStringLiteral("无法排队") : QStringLiteral("读取中..."));
}

void CpuView::showMemory(const MemoryPage& page)
{
    m_dump->setBytes(page.address, m_memoryCursor, m_memoryCursorBytes, page.bytes);
}

void CpuView::noteSelection()
{
    if (m_suppressSelection)
    {
        return;
    }

    const DisassemblyView::Row* row = m_disassembly->selectedRow();

    if (row == nullptr)
    {
        m_info->clear();
        return;
    }

    m_info->setText(row->symbol.isEmpty() ? hex16(row->address) : hex16(row->address) + QStringLiteral("  ") + row->symbol);

    if (m_memoryCache.empty())
    {
        return;
    }

    const MemoryPage& page = m_memoryCache.back();
    const int bytes = row->length == 0 ? 1 : static_cast<int>(row->length);

    if (page.cr3 != m_disassemblyCr3 || row->address < page.address || row->address - page.address >= page.bytes.size())
    {
        return;
    }

    m_memoryCursor = row->address;
    m_memoryCursorBytes = bytes;
    showMemory(page);
}

bool CpuView::takeCompleted(std::uint32_t view, std::uint64_t* requestId, HACDBG_CORE_VIEW_STATUS* status)
{
    if (m_session == nullptr || requestId == nullptr || *requestId == 0 || status == nullptr)
    {
        return false;
    }

    if (m_session->getViewStatus(view, status) == false || status->Pending != 0 || status->CompletedRequestId != *requestId)
    {
        return false;
    }

    *requestId = 0;
    return true;
}

void CpuView::setDisassemblyStatus(const QString& text)
{
    m_status->setText(text);
}

void CpuView::setMemoryStatus(const QString& text)
{
    m_memoryStatus->setText(text);
}
