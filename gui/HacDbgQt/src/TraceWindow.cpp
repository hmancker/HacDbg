#include "TraceWindow.h"

#include "CoreSession.h"

#include <QCloseEvent>
#include <QComboBox>
#include <QEvent>
#include <QFileDialog>
#include <QShowEvent>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QTimer>
#include <QVBoxLayout>

#include <QCoreApplication>

namespace
{
template <typename T>
bool bindProc(HMODULE module, const char* name, T* function)
{
    void* address = reinterpret_cast<void*>(GetProcAddress(module, name));

    if (address == nullptr || function == nullptr)
    {
        return false;
    }

    *function = reinterpret_cast<T>(address);
    return true;
}

HACDBG_TRACE_THEME lightTheme()
{
    HACDBG_TRACE_THEME theme = {};
    theme.Size = sizeof(theme);
    theme.Version = HACDBG_TRACE_THEME_VERSION;
    theme.Background = 0xFFFFFFFFu;
    theme.Surface = 0xFFF3F3F3u;
    theme.SurfaceRaised = 0xFFE8E8E8u;
    theme.Border = 0xFFC8C8C8u;
    theme.Text = 0xFF1A1A1Au;
    theme.Muted = 0xFF666666u;
    theme.Accent = 0xFF1A5FB4u;
    theme.Warning = 0xFFB8860Bu;
    theme.Error = 0xFFB00020u;
    return theme;
}
}

TraceWindow::TraceWindow(CoreSession* session, QWidget* parent)
    : QWidget(parent, Qt::Window)
    , m_session(session)
{
    setWindowTitle(QStringLiteral("实时 trace"));
    resize(1100, 720);
    auto* root = new QVBoxLayout(this);
    auto* toolbar = new QHBoxLayout();
    auto* counters = new QPushButton(QStringLiteral("计数"), this);
    auto* events = new QPushButton(QStringLiteral("事件"), this);
    auto* stop = new QPushButton(QStringLiteral("停止"), this);
    auto* reset = new QPushButton(QStringLiteral("重置"), this);
    auto* exportButton = new QPushButton(QStringLiteral("导出 CSV"), this);
    m_sample = new QComboBox(this);
    m_sample->addItems({QStringLiteral("1"), QStringLiteral("64"), QStringLiteral("256")});
    m_sample->setCurrentIndex(1);
    toolbar->addWidget(counters);
    toolbar->addWidget(events);
    toolbar->addWidget(stop);
    toolbar->addWidget(reset);
    toolbar->addWidget(exportButton);
    toolbar->addWidget(new QLabel(QStringLiteral("采样"), this));
    toolbar->addWidget(m_sample);
    toolbar->addStretch(1);
    root->addLayout(toolbar);
    auto* warning = new QLabel(
        QStringLiteral("事件模式会改变客户退出时序，可能被检测。DurationTsc 当前未采样，延迟直方图显示为不可用。"),
        this);
    warning->setWordWrap(true);
    root->addWidget(warning);
    m_host = new QWidget(this);
    m_host->setAttribute(Qt::WA_NativeWindow);
    m_host->setAttribute(Qt::WA_DontCreateNativeAncestors);
    m_host->setMinimumSize(320, 240);
    m_host->installEventFilter(this);
    root->addWidget(m_host, 1);
    m_error = new QLabel(this);
    m_error->setStyleSheet(QStringLiteral("color: #B00020;"));
    m_status = new QLabel(QStringLiteral("实时 trace 未连接"), this);
    root->addWidget(m_error);
    root->addWidget(m_status);

    m_timer = new QTimer(this);
    m_timer->setInterval(33);
    connect(m_timer, &QTimer::timeout, this, &TraceWindow::poll);
    connect(counters, &QPushButton::clicked, this, [this]
    {
        applyControl(HACDBG_TRACE_CONTROL_ENABLE_COUNTERS | HACDBG_TRACE_CONTROL_SET_SAMPLE_RATE);
    });
    connect(events, &QPushButton::clicked, this, [this]
    {
        applyControl(HACDBG_TRACE_CONTROL_ENABLE_COUNTERS | HACDBG_TRACE_CONTROL_ENABLE_EVENTS |
                     HACDBG_TRACE_CONTROL_SET_SAMPLE_RATE | HACDBG_TRACE_CONTROL_SET_EVENT_MASK);
    });
    connect(stop, &QPushButton::clicked, this, [this]
    {
        applyControl(HACDBG_TRACE_CONTROL_DISABLE);
    });
    connect(reset, &QPushButton::clicked, this, [this]
    {
        m_sequence = 0;
        applyControl(HACDBG_TRACE_CONTROL_RESET | HACDBG_TRACE_CONTROL_SET_SAMPLE_RATE);
    });
    connect(exportButton, &QPushButton::clicked, this, &TraceWindow::exportCsv);
    m_snapshot = std::make_unique<HACDBG_TRACE_SNAPSHOT>();
}

TraceWindow::~TraceWindow()
{
    if (m_detachThread.joinable())
    {
        m_detachThread.join();
    }

    if (m_trace != nullptr && m_detach != nullptr)
    {
        m_detach(m_trace);
        m_trace = nullptr;
    }

    if (m_module != nullptr)
    {
        FreeLibrary(static_cast<HMODULE>(m_module));
        m_module = nullptr;
    }
}

bool TraceWindow::isBusy() const
{
    return m_detaching || m_trace != nullptr;
}

void TraceWindow::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);

    if (m_detaching)
    {
        m_reopen = true;
        return;
    }

    ensureAttached();
}

void TraceWindow::closeEvent(QCloseEvent* event)
{
    if (m_trace == nullptr && m_detaching == false)
    {
        event->accept();
        emit idle();
        return;
    }

    event->ignore();
    beginDetach();
}

bool TraceWindow::eventFilter(QObject* watched, QEvent* event)
{
    if (watched == m_host && event->type() == QEvent::Resize)
    {
        publishGeometry();
    }

    return QWidget::eventFilter(watched, event);
}

bool TraceWindow::loadApi(QString* error)
{
    if (m_module != nullptr)
    {
        return m_attach != nullptr;
    }

    const QString path = QCoreApplication::applicationDirPath() + QStringLiteral("\\HacDbgTrace.dll");
    HMODULE module = LoadLibraryW(reinterpret_cast<const wchar_t*>(path.utf16()));

    if (module == nullptr)
    {
        if (error != nullptr)
        {
            *error = QStringLiteral("缺少 HacDbgTrace.dll。");
        }

        return false;
    }

    const bool bound =
        bindProc(module, "HacDbgTraceApiVersion", &m_apiVersion) &&
        bindProc(module, "HacDbgTraceThemeSize", &m_themeSize) &&
        bindProc(module, "HacDbgTraceLastError", &m_lastError) &&
        bindProc(module, "HacDbgTraceAttach", &m_attach) &&
        bindProc(module, "HacDbgTracePublishSnapshot", &m_publish) &&
        bindProc(module, "HacDbgTraceSetDpi", &m_setDpi) &&
        bindProc(module, "HacDbgTraceSetVisible", &m_setVisible) &&
        bindProc(module, "HacDbgTraceResize", &m_resize) &&
        bindProc(module, "HacDbgTraceSetActionCallback", &m_setCallback) &&
        bindProc(module, "HacDbgTraceExportCsv", &m_exportCsv) &&
        bindProc(module, "HacDbgTraceDetach", &m_detach);

    if (bound == false || m_apiVersion() != HACDBG_TRACE_API_VERSION || m_themeSize() != sizeof(HACDBG_TRACE_THEME))
    {
        FreeLibrary(module);

        if (error != nullptr)
        {
            *error = QStringLiteral("HacDbgTrace.dll ABI 不匹配，实时 trace 已禁用。");
        }

        return false;
    }

    m_module = module;
    return true;
}

void TraceWindow::ensureAttached()
{
    if (m_trace != nullptr || m_detaching)
    {
        return;
    }

    QString error;

    if (loadApi(&error) == false)
    {
        m_error->setText(error);
        return;
    }

    const HACDBG_TRACE_THEME theme = lightTheme();
    m_trace = m_attach(reinterpret_cast<HWND>(m_host->winId()), GetModuleHandleW(nullptr), &theme);

    if (m_trace == nullptr)
    {
        m_error->setText(QStringLiteral("HacDbgTraceAttach 失败 (0x%1)").arg(m_lastError(), 8, 16, QLatin1Char('0')));
        return;
    }

    m_setCallback(m_trace, &TraceWindow::actionThunk, this);
    m_error->clear();
    m_sequence = 0;
    publishGeometry();
    m_timer->start();
}

void TraceWindow::beginDetach()
{
    if (m_detaching)
    {
        return;
    }

    m_timer->stop();

    if (m_session != nullptr && m_session->isStarted())
    {
        m_session->traceControl(HACDBG_TRACE_CONTROL_DISABLE, sampleRate(), HACDBG_TRACE_EVENT_MASK_ALL);
    }

    if (m_trace == nullptr || m_detach == nullptr)
    {
        m_trace = nullptr;
        hide();
        emit idle();
        return;
    }

    m_detaching = true;
    hide();
    HACDBG_TRACE* trace = m_trace;
    m_trace = nullptr;

    if (m_detachThread.joinable())
    {
        m_detachThread.join();
    }

    //
    // Detach joins the render thread. That thread sends messages to this
    // window, so the wait cannot run on the UI thread.
    //
    m_detachThread = std::thread([this, trace]
    {
        m_detach(trace);
        QMetaObject::invokeMethod(this, [this]
        {
            finishDetach();
        }, Qt::QueuedConnection);
    });
}

void TraceWindow::finishDetach()
{
    if (m_detachThread.joinable())
    {
        m_detachThread.join();
    }

    m_detaching = false;

    if (m_reopen && isVisible() == false)
    {
        m_reopen = false;
        show();
        return;
    }

    m_reopen = false;
    emit idle();
}

void TraceWindow::publishGeometry()
{
    if (m_trace == nullptr)
    {
        return;
    }

    const qreal scale = m_host->devicePixelRatioF();
    const auto width = static_cast<std::uint32_t>(qMax(1.0, m_host->width() * scale));
    const auto height = static_cast<std::uint32_t>(qMax(1.0, m_host->height() * scale));
    m_resize(m_trace, width, height);
    m_setDpi(m_trace, static_cast<std::uint32_t>(logicalDpiX()));
    m_setVisible(m_trace, isVisible() ? 1u : 0u);
}

void TraceWindow::poll()
{
    if (m_session == nullptr || m_session->isStarted() == false || m_trace == nullptr)
    {
        if (m_status->text() != QStringLiteral("实时 trace 未连接"))
        {
            m_status->setText(QStringLiteral("实时 trace 未连接"));
        }

        return;
    }

    HACDBG_CORE_TRACE_STATUS status = {};

    if (m_session->getTraceStatus(&status) == false)
    {
        return;
    }

    if (status.Supported == 0)
    {
        m_status->setText(QStringLiteral("当前驱动不支持实时 trace。"));
        return;
    }

    if (status.Capturing != 0)
    {
        m_session->requestTraceRead();
    }

    if (status.SnapshotSequence != 0 && status.SnapshotSequence != m_sequence && m_session->copyTraceSnapshot(m_snapshot.get()))
    {
        m_publish(m_trace, m_snapshot.get());
        m_sequence = status.SnapshotSequence;
    }

    const QString mode = status.Capturing == 0 ? QStringLiteral("已停止")
                         : status.EventsEnabled != 0 ? QStringLiteral("事件模式")
                                                     : QStringLiteral("计数模式");
    m_status->setText(QStringLiteral("%1 · 采样 %2 · CPU %3 · 退出 %4 · 丢弃 %5 · 事件 %6")
                          .arg(mode)
                          .arg(status.SampleRate)
                          .arg(status.CpuCount)
                          .arg(status.TotalExits)
                          .arg(status.DroppedEvents)
                          .arg(status.SnapshotEventCount));
}

void TraceWindow::applyControl(std::uint32_t flags)
{
    if (m_session == nullptr || m_session->isStarted() == false)
    {
        m_error->setText(QStringLiteral("未连接，不能控制 trace。"));
        return;
    }

    std::uint32_t mask = HACDBG_TRACE_EVENT_MASK_ALL;

    if ((flags & HACDBG_TRACE_CONTROL_SET_EVENT_MASK) == 0)
    {
        mask = 0;
    }

    if (m_session->traceControl(flags, sampleRate(), mask) == false)
    {
        m_error->setText(QStringLiteral("trace_control 调用失败。"));
    }
}

void TraceWindow::handleAction(std::uint32_t action)
{
    switch (action)
    {
    case HacDbgTraceActionContinue:
        emit commandRequested(QStringLiteral("g"));
        break;
    case HacDbgTraceActionStepOver:
        emit commandRequested(QStringLiteral("p"));
        break;
    case HacDbgTraceActionStepInto:
        emit commandRequested(QStringLiteral("t"));
        break;
    case HacDbgTraceActionFocusCommand:
        emit focusCommandRequested();
        break;
    case HacDbgTraceActionDeviceError:
        m_error->setText(QStringLiteral("trace 渲染设备初始化失败 (0x%1)。").arg(m_lastError != nullptr ? m_lastError() : 0u, 8, 16, QLatin1Char('0')));
        break;
    default:
        break;
    }
}

void TraceWindow::exportCsv()
{
    if (m_trace == nullptr || m_exportCsv == nullptr)
    {
        return;
    }

    const QString path = QFileDialog::getSaveFileName(this, QStringLiteral("导出 CSV"), QString(), QStringLiteral("CSV (*.csv)"));

    if (path.isEmpty())
    {
        return;
    }

    const std::uint32_t result = m_exportCsv(m_trace, reinterpret_cast<const wchar_t*>(path.utf16()));

    if (result != 0)
    {
        m_error->setText(QStringLiteral("导出失败 (0x%1)。").arg(result, 8, 16, QLatin1Char('0')));
    }
}

std::uint32_t TraceWindow::sampleRate() const
{
    bool ok = false;
    const std::uint32_t rate = m_sample->currentText().toUInt(&ok);
    return ok ? rate : HACDBG_TRACE_DEFAULT_SAMPLE_RATE;
}

void __cdecl TraceWindow::actionThunk(std::uint32_t action, void* context)
{
    auto* window = static_cast<TraceWindow*>(context);

    if (window != nullptr)
    {
        QMetaObject::invokeMethod(window, [window, action]
        {
            window->handleAction(action);
        }, Qt::QueuedConnection);
    }
}
