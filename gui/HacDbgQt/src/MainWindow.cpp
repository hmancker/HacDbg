#include "MainWindow.h"

#include "BreakpointView.h"
#include "CommandView.h"
#include "CpuView.h"
#include "Format.h"
#include "ProcessThreadView.h"
#include "SymbolView.h"
#include "TraceWindow.h"

#include <QAction>
#include <QCloseEvent>
#include <QCoreApplication>
#include <QLabel>
#include <QMenuBar>
#include <QPainter>
#include <QPainterPath>
#include <QPixmap>
#include <QShortcut>
#include <QShowEvent>
#include <QStackedWidget>
#include <QStatusBar>
#include <QStyle>
#include <QTabBar>
#include <QTimer>
#include <QToolBar>
#include <QVBoxLayout>

#include <Windows.h>

namespace
{
constexpr std::uint32_t kExpectedHypercallAbi = 1;

enum DebugIcon
{
    IconContinue,
    IconStepOver,
    IconStepInto,
    IconCancel
};

QIcon debugIcon(DebugIcon kind)
{
    QIcon icon;

    for (const int side : {16, 20, 32})
    {
        QPixmap pixmap(side, side);
        pixmap.fill(Qt::transparent);
        QPainter painter(&pixmap);
        painter.setRenderHint(QPainter::Antialiasing, true);
        const qreal scale = side;

        if (kind == IconContinue)
        {
            painter.setPen(Qt::NoPen);
            painter.setBrush(QColor(0x2E, 0xA0, 0x43));
            QPolygonF triangle;
            triangle << QPointF(scale * 0.22, scale * 0.16)
                     << QPointF(scale * 0.82, scale * 0.50)
                     << QPointF(scale * 0.22, scale * 0.84);
            painter.drawPolygon(triangle);
        }
        else if (kind == IconStepInto)
        {
            painter.setPen(Qt::NoPen);
            painter.setBrush(QColor(0x1A, 0x5F, 0xB4));
            painter.drawRect(QRectF(scale * 0.42, scale * 0.12, scale * 0.16, scale * 0.40));
            QPolygonF head;
            head << QPointF(scale * 0.22, scale * 0.48)
                 << QPointF(scale * 0.78, scale * 0.48)
                 << QPointF(scale * 0.50, scale * 0.86);
            painter.drawPolygon(head);
        }
        else if (kind == IconStepOver)
        {
            QPen pen(QColor(0x1A, 0x5F, 0xB4), qMax(1.5, scale * 0.1), Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin);
            painter.setPen(pen);
            painter.setBrush(Qt::NoBrush);
            painter.drawRect(QRectF(scale * 0.12, scale * 0.46, scale * 0.26, scale * 0.30));
            QPainterPath path;
            path.moveTo(scale * 0.25, scale * 0.46);
            path.lineTo(scale * 0.25, scale * 0.28);
            path.cubicTo(scale * 0.25, scale * 0.12, scale * 0.78, scale * 0.12, scale * 0.78, scale * 0.36);
            path.lineTo(scale * 0.78, scale * 0.52);
            painter.drawPath(path);
            painter.setPen(Qt::NoPen);
            painter.setBrush(QColor(0x1A, 0x5F, 0xB4));
            QPolygonF head;
            head << QPointF(scale * 0.60, scale * 0.48)
                 << QPointF(scale * 0.96, scale * 0.48)
                 << QPointF(scale * 0.78, scale * 0.78);
            painter.drawPolygon(head);
        }
        else
        {
            painter.setPen(Qt::NoPen);
            painter.setBrush(QColor(0xC0, 0x1C, 0x28));
            painter.drawEllipse(QRectF(scale * 0.10, scale * 0.10, scale * 0.80, scale * 0.80));
            painter.setPen(QPen(Qt::white, qMax(1.6, scale * 0.12), Qt::SolidLine, Qt::RoundCap));
            painter.drawLine(QPointF(scale * 0.32, scale * 0.32), QPointF(scale * 0.68, scale * 0.68));
            painter.drawLine(QPointF(scale * 0.68, scale * 0.32), QPointF(scale * 0.32, scale * 0.68));
        }

        icon.addPixmap(pixmap);
    }

    return icon;
}

bool stoppedOnBreakpoint(const HACDBG_CORE_STATE& state)
{
    if (state.Paused == 0 || state.Registers.Rip == 0)
    {
        return false;
    }

    for (std::uint32_t index = 0; index < state.BreakpointCount && index < HACDBG_CORE_MAX_BREAKPOINTS; ++index)
    {
        const HACDBG_CORE_BREAKPOINT& breakpoint = state.Breakpoints[index];

        if (breakpoint.Enabled == 0 || breakpoint.Address != state.Registers.Rip)
        {
            continue;
        }

        if (breakpoint.Cr3 != 0 && state.Registers.Cr3 != 0 && breakpoint.Cr3 != state.Registers.Cr3)
        {
            continue;
        }

        return true;
    }

    return false;
}

QString debugTip(const QString& text, const QKeySequence& key)
{
    return QStringLiteral("%1 (%2)").arg(text, key.toString(QKeySequence::NativeText));
}
}

MainWindow::MainWindow(bool connectCore, QWidget* parent)
    : QMainWindow(parent)
    , m_connectCore(connectCore)
{
    setWindowTitle(QStringLiteral("HacDbg"));
    resize(1400, 900);

    auto* fileMenu = menuBar()->addMenu(QStringLiteral("文件"));
    fileMenu->addAction(QStringLiteral("退出"), this, &QWidget::close);
    auto* viewMenu = menuBar()->addMenu(QStringLiteral("视图"));
    viewMenu->addAction(QStringLiteral("实时 trace"), this, &MainWindow::openTrace);
    auto* debugMenu = menuBar()->addMenu(QStringLiteral("调试"));
    debugMenu->addAction(debugIcon(IconContinue), QStringLiteral("继续"), this, [this] { executeCommand(QStringLiteral("g")); });
    debugMenu->addAction(debugIcon(IconStepOver), QStringLiteral("步过"), this, [this] { executeCommand(QStringLiteral("p")); });
    debugMenu->addAction(debugIcon(IconStepInto), QStringLiteral("步入"), this, [this] { executeCommand(QStringLiteral("t")); });
    debugMenu->addAction(debugIcon(IconCancel), QStringLiteral("取消"), this, [this] { m_session.cancel(); });

    auto* toolbar = addToolBar(QStringLiteral("调试"));
    toolbar->setToolButtonStyle(Qt::ToolButtonIconOnly);
    toolbar->setIconSize(QSize(18, 18));
    QAction* continueAction = toolbar->addAction(debugIcon(IconContinue), QStringLiteral("继续"), this, [this] { executeCommand(QStringLiteral("g")); });
    QAction* stepOverAction = toolbar->addAction(debugIcon(IconStepOver), QStringLiteral("步过"), this, [this] { executeCommand(QStringLiteral("p")); });
    QAction* stepIntoAction = toolbar->addAction(debugIcon(IconStepInto), QStringLiteral("步入"), this, [this] { executeCommand(QStringLiteral("t")); });
    QAction* cancelAction = toolbar->addAction(debugIcon(IconCancel), QStringLiteral("取消"), this, [this] { m_session.cancel(); });
    continueAction->setToolTip(debugTip(QStringLiteral("继续"), QKeySequence(Qt::Key_F5)));
    stepOverAction->setToolTip(debugTip(QStringLiteral("步过"), QKeySequence(Qt::Key_F10)));
    stepIntoAction->setToolTip(debugTip(QStringLiteral("步入"), QKeySequence(Qt::Key_F11)));
    cancelAction->setToolTip(debugTip(QStringLiteral("取消"), QKeySequence(Qt::CTRL | Qt::Key_C)));

    auto* central = new QWidget(this);
    auto* layout = new QVBoxLayout(central);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);
    m_tabs = new QTabBar(central);
    m_tabs->setDocumentMode(true);
    m_tabs->setExpanding(false);
    m_tabs->setDrawBase(true);
    m_tabs->setElideMode(Qt::ElideNone);
    m_tabs->setStyleSheet(QStringLiteral(
        "QTabBar::tab { background: #f6f3ec; color: #333333; border: 1px solid #e3dfd6;"
        " border-bottom: none; padding: 6px 14px; margin-right: 1px; }"
        "QTabBar::tab:selected { background: #ffffff; border-top: 2px solid #1a5fb4; }"
        "QTabBar::tab:hover { background: #ffffff; }"));
    const QStyle* tabStyle = style();
    m_tabs->addTab(tabStyle->standardIcon(QStyle::SP_FileDialogDetailedView), QStringLiteral("命令台"));
    m_tabs->addTab(tabStyle->standardIcon(QStyle::SP_ComputerIcon), QStringLiteral("反汇编"));
    m_tabs->addTab(tabStyle->standardIcon(QStyle::SP_MessageBoxCritical), QStringLiteral("断点"));
    m_tabs->addTab(tabStyle->standardIcon(QStyle::SP_FileDialogContentsView), QStringLiteral("符号"));
    m_tabs->addTab(tabStyle->standardIcon(QStyle::SP_FileDialogListView), QStringLiteral("进程/线程"));

    m_stack = new QStackedWidget(central);
    m_command = new CommandView(m_stack);
    m_command->setSession(&m_session);
    m_stack->addWidget(m_command);

    for (int index = PageDisassembly; index <= PageProcesses; ++index)
    {
        m_holders[index] = new QWidget(m_stack);
        auto* holderLayout = new QVBoxLayout(m_holders[index]);
        holderLayout->setContentsMargins(0, 0, 0, 0);
        m_stack->addWidget(m_holders[index]);
    }

    layout->addWidget(m_tabs);
    layout->addWidget(m_stack, 1);
    layout->addWidget(m_command->commandBar());
    setCentralWidget(central);
    m_tabs->setCurrentIndex(PageCommand);
    connect(m_tabs, &QTabBar::currentChanged, this, &MainWindow::onTabChanged);

    m_connection = new QLabel(connectCore ? QStringLiteral("未连接") : QStringLiteral("UI only"), this);
    m_paused = new QLabel(QStringLiteral("—"), this);
    m_cr3 = new QLabel(QStringLiteral("CR3 —"), this);
    m_version = new QLabel(this);
    statusBar()->addWidget(m_connection);
    statusBar()->addWidget(m_paused);
    statusBar()->addWidget(m_cr3);
    statusBar()->addPermanentWidget(m_version);

    connect(m_command, &CommandView::commandSubmitted, this, &MainWindow::executeCommand);
    connect(m_command, &CommandView::interruptRequested, this, [this] { m_session.cancel(); });
    connect(m_command, &CommandView::quitRequested, this, &QWidget::close);

    auto* continueShortcut = new QShortcut(QKeySequence(Qt::Key_F5), this);
    auto* stepOverShortcut = new QShortcut(QKeySequence(Qt::Key_F10), this);
    auto* stepIntoShortcut = new QShortcut(QKeySequence(Qt::Key_F11), this);
    continueShortcut->setContext(Qt::WidgetWithChildrenShortcut);
    stepOverShortcut->setContext(Qt::WidgetWithChildrenShortcut);
    stepIntoShortcut->setContext(Qt::WidgetWithChildrenShortcut);
    connect(continueShortcut, &QShortcut::activated, this, [this] { executeCommand(QStringLiteral("g")); });
    connect(stepOverShortcut, &QShortcut::activated, this, [this] { executeCommand(QStringLiteral("p")); });
    connect(stepIntoShortcut, &QShortcut::activated, this, [this] { executeCommand(QStringLiteral("t")); });

    m_timer = new QTimer(this);
    m_timer->setInterval(100);
    connect(m_timer, &QTimer::timeout, this, &MainWindow::tick);
}

MainWindow::~MainWindow()
{
    m_session.shutdown();
}

void MainWindow::showEvent(QShowEvent* event)
{
    QMainWindow::showEvent(event);

    if (m_shown)
    {
        return;
    }

    m_shown = true;
    m_command->focusInput();
    QTimer::singleShot(0, this, &MainWindow::startCore);
    m_timer->start();
}

void MainWindow::executeCommand(const QString& command)
{
    const QString trimmed = command.trimmed();

    if (trimmed.isEmpty())
    {
        return;
    }

    if (m_session.isStarted() == false)
    {
        m_command->appendLocalError(QStringLiteral("debugger is not connected"));
        return;
    }

    m_command->appendEcho(trimmed);
    m_session.execute(trimmed);
}

void MainWindow::closeEvent(QCloseEvent* event)
{
    if (m_trace != nullptr && m_trace->isBusy())
    {
        event->ignore();

        if (m_closing == false)
        {
            m_closing = true;
            connect(m_trace, &TraceWindow::idle, this, &QWidget::close, Qt::SingleShotConnection);
            m_trace->close();
        }

        return;
    }

    m_session.shutdown();
    event->accept();
}

void MainWindow::startCore()
{
    if (m_connectCore == false)
    {
        m_connection->setText(QStringLiteral("UI only"));
        return;
    }

    if (isAdministrator() == false)
    {
        m_command->appendLocalError(QStringLiteral("GUI 未以管理员身份运行，无法连接驱动。请从 UAC 提示中允许提权后重试。"));
        m_connection->setText(QStringLiteral("未连接"));
        return;
    }

    m_connection->setText(QStringLiteral("正在连接..."));
    connect(&m_session, &CoreSession::startFinished, this, &MainWindow::onStarted);
    m_session.loadAndStartAsync(QCoreApplication::applicationDirPath());
}

void MainWindow::onStarted(quint32 status)
{
    if (status != HacDbgCoreStatusOk)
    {
        const QString detail = m_session.startError();
        m_command->appendLocalError(detail.isEmpty() ? startFailure(status) : detail);
        m_connection->setText(QStringLiteral("未连接"));
        return;
    }

    m_connection->setText(QStringLiteral("已连接"));
    m_command->setInputEnabled(true);
    m_command->focusInput();
}

void MainWindow::tick()
{
    std::vector<CoreSession::OutputRecord> records;
    m_session.drainOutput(2000, &records);
    m_command->appendRecords(records);
    m_command->pollCompletions(&m_session);

    if (m_session.isStarted() == false)
    {
        return;
    }

    HACDBG_CORE_SYMBOL_PROGRESS progress = {};

    if (m_session.getSymbolProgress(&progress) && progress.Active != 0)
    {
        m_connection->setText(QStringLiteral("符号 %1/%2").arg(progress.Completed).arg(progress.Total));
    }

    HACDBG_CORE_STATE state = {};

    if (m_session.getState(&state))
    {
        m_state = state;
        m_haveState = true;
        updateState(state);
        refreshVisiblePage();
    }
}

void MainWindow::onTabChanged(int index)
{
    ensurePage(index);
    m_stack->setCurrentIndex(index);
    refreshVisiblePage();

    if (index == PageCommand)
    {
        m_command->focusInput();
    }
}

void MainWindow::ensurePage(int index)
{
    if (index == PageDisassembly && m_cpu == nullptr)
    {
        m_cpu = new CpuView(holder(index));
        m_cpu->setSession(&m_session);
        holder(index)->layout()->addWidget(m_cpu);
    }
    else if (index == PageBreakpoints && m_breakpoints == nullptr)
    {
        m_breakpoints = new BreakpointView(holder(index));
        holder(index)->layout()->addWidget(m_breakpoints);
        connect(m_breakpoints, &BreakpointView::addressActivated, this, &MainWindow::openDisassembly);
    }
    else if (index == PageSymbols && m_symbols == nullptr)
    {
        m_symbols = new SymbolView(holder(index));
        m_symbols->setSession(&m_session);
        holder(index)->layout()->addWidget(m_symbols);
        connect(m_symbols, &SymbolView::addressActivated, this, &MainWindow::openDisassembly);
        connect(m_symbols, &SymbolView::reloadRequested, this, [this] { executeCommand(QStringLiteral(".reload /f")); });
        m_symbols->refresh();
    }
    else if (index == PageProcesses && m_processes == nullptr)
    {
        m_processes = new ProcessThreadView(holder(index));
        m_processes->setSession(&m_session);
        holder(index)->layout()->addWidget(m_processes);
        connect(m_processes, &ProcessThreadView::addressActivated, this, &MainWindow::openDisassembly);
        m_processes->refresh();
    }
}

void MainWindow::openDisassembly(std::uint64_t address, std::uint64_t cr3)
{
    m_tabs->setCurrentIndex(PageDisassembly);
    ensurePage(PageDisassembly);

    if (m_cpu != nullptr)
    {
        m_cpu->openAt(address, cr3);
    }
}

void MainWindow::refreshVisiblePage()
{
    if (m_haveState == false)
    {
        return;
    }

    switch (m_tabs->currentIndex())
    {
    case PageDisassembly:
        if (m_cpu != nullptr)
        {
            m_cpu->onState(m_state);
            m_cpu->poll();
        }
        break;

    case PageBreakpoints:
        if (m_breakpoints != nullptr)
        {
            m_breakpoints->setBreakpoints(m_state.Breakpoints, m_state.BreakpointCount);
        }
        break;

    case PageSymbols:
        if (m_symbols != nullptr)
        {
            m_symbols->poll();
        }
        break;

    case PageProcesses:
        if (m_processes != nullptr)
        {
            m_processes->poll();
        }
        break;

    default:
        break;
    }
}

QWidget* MainWindow::holder(int index)
{
    return m_holders[index];
}

void MainWindow::openTrace()
{
    if (m_trace == nullptr)
    {
        m_trace = new TraceWindow(&m_session, this);
        connect(m_trace, &TraceWindow::commandRequested, this, &MainWindow::executeCommand);
        connect(m_trace, &TraceWindow::focusCommandRequested, m_command, &CommandView::focusInput);
    }

    m_trace->show();
    m_trace->raise();
    m_trace->activateWindow();
}

void MainWindow::updateState(const HACDBG_CORE_STATE& state)
{
    if (state.Initialized == 0)
    {
        m_connection->setText(QStringLiteral("未连接"));
        m_paused->setText(QStringLiteral("—"));
    }
    else
    {
        m_connection->setText(state.Running != 0 ? QStringLiteral("已连接") : QStringLiteral("已停止"));
        m_paused->setText(state.Paused != 0 ? QStringLiteral("已暂停") : QStringLiteral("运行中"));
        m_command->setInputEnabled(state.Running != 0);
    }

    if (state.Initialized != 0 && state.Registers.Cr3 != 0)
    {
        if (state.Registers.Cr3 != m_shownCr3)
        {
            m_shownCr3 = state.Registers.Cr3;
            m_cr3->setText(QStringLiteral("CR3 %1").arg(hex16(m_shownCr3)));
        }
    }
    else if (m_shownCr3 != 0)
    {
        m_shownCr3 = 0;
        m_cr3->setText(QStringLiteral("CR3 —"));
    }

    const QString userVersion = fromField(state.UserVersion, HACDBG_CORE_VERSION_STRING_SIZE);
    const QString driverVersion = fromField(state.DriverVersion, HACDBG_CORE_VERSION_STRING_SIZE);

    if (userVersion != m_shownUserVersion || driverVersion != m_shownDriverVersion)
    {
        m_shownUserVersion = userVersion;
        m_shownDriverVersion = driverVersion;
        m_version->setText(driverVersion.isEmpty()
                               ? QStringLiteral("usermode %1 / hypervisor —").arg(userVersion)
                               : QStringLiteral("usermode %1 / hypervisor %2").arg(userVersion, driverVersion));

        if (m_versionWarning == false && userVersion.isEmpty() == false && driverVersion.isEmpty() == false && userVersion != driverVersion)
        {
            m_versionWarning = true;
            m_command->appendLocalWarning(QStringLiteral("usermode %1 与 hypervisor %2 版本不一致。").arg(userVersion, driverVersion));
        }

        if (state.Initialized != 0 && state.HypercallAbiVersion != kExpectedHypercallAbi)
        {
            m_command->appendLocalWarning(QStringLiteral("hypercall ABI %1 与 GUI 期望的 %2 不一致。")
                                              .arg(state.HypercallAbiVersion)
                                              .arg(kExpectedHypercallAbi));
        }
    }

    if (state.Initialized == 0 || stoppedOnBreakpoint(state) == false)
    {
        m_breakLatched = false;
        m_breakRip = 0;
        return;
    }

    if (m_breakLatched && m_breakRip == state.Registers.Rip)
    {
        return;
    }

    m_breakLatched = true;
    m_breakRip = state.Registers.Rip;

    if (m_tabs->currentIndex() != PageDisassembly)
    {
        m_tabs->setCurrentIndex(PageDisassembly);
    }
}

bool MainWindow::isAdministrator()
{
    BOOL member = FALSE;
    SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
    PSID admin = nullptr;

    if (AllocateAndInitializeSid(&authority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
                                 0, 0, 0, 0, 0, 0, &admin) == FALSE)
    {
        return false;
    }

    CheckTokenMembership(nullptr, admin, &member);
    FreeSid(admin);
    return member == TRUE;
}

QString MainWindow::startFailure(quint32 status)
{
    switch (status)
    {
    case HacDbgCoreStatusArgument:
        return QStringLiteral("核心启动参数无效。请使用完整发布目录重新运行。");
    case HacDbgCoreStatusState:
        return QStringLiteral("核心处于无效状态，无法启动调试会话。");
    case HacDbgCoreStatusDriver:
        return QStringLiteral("未连接到 HacDbg 驱动。请先加载与 GUI 同版本的驱动，并确认进程具有管理员权限。");
    case HacDbgCoreStatusException:
        return QStringLiteral("核心启动时发生内部异常。请查看驱动调试输出。");
    default:
        return QStringLiteral("核心启动失败 (status %1)。").arg(status);
    }
}
