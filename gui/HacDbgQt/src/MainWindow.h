#pragma once

#include "CoreSession.h"

#include <QMainWindow>

#include <QString>

class BreakpointView;
class CommandView;
class MonitorView;
class CpuView;
class ProcessThreadView;
class QLabel;
class QShowEvent;
class QStackedWidget;
class QTabBar;
class QTimer;
class QWidget;
class SymbolView;
class TraceWindow;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(bool connectCore, QWidget* parent = nullptr);
    ~MainWindow() override;

    void executeCommand(const QString& command);

protected:
    void showEvent(QShowEvent* event) override;
    void closeEvent(QCloseEvent* event) override;

private:
    enum Page
    {
        PageCommand = 0,
        PageDisassembly,
        PageBreakpoints,
        PageMonitors,
        PageSymbols,
        PageProcesses
    };

    void startCore();
    void onStarted(quint32 status);
    void retryCore();
    void tick();
    void executeDebug(const QString& command);
    void beginDebug(const QString& command, bool echoNow);
    void finishDebugCommand(bool failed);
    void refreshDebugViews();
    void openTrace();
    void openMapper();
    void updateState(const HACDBG_CORE_STATE& state);
    void onTabChanged(int index);
    void ensurePage(int index);
    void openDisassembly(std::uint64_t address, std::uint64_t cr3);
    void refreshVisiblePage();
    QWidget* holder(int index);
    static bool isAdministrator();
    static QString startFailure(quint32 status);

    CoreSession m_session;
    CommandView* m_command = nullptr;
    CpuView* m_cpu = nullptr;
    BreakpointView* m_breakpoints = nullptr;
    MonitorView* m_monitors = nullptr;
    SymbolView* m_symbols = nullptr;
    ProcessThreadView* m_processes = nullptr;
    TraceWindow* m_trace = nullptr;
    QTabBar* m_tabs = nullptr;
    QStackedWidget* m_stack = nullptr;
    QWidget* m_holders[6] = {};
    QTimer* m_timer = nullptr;
    QTimer* m_connectRetry = nullptr;
    QTimer* m_debugIdle = nullptr;
    QLabel* m_connection = nullptr;
    QLabel* m_paused = nullptr;
    QLabel* m_cr3 = nullptr;
    QLabel* m_version = nullptr;
    bool m_connectCore = true;
    bool m_shown = false;
    bool m_closing = false;
    bool m_versionWarning = false;
    bool m_haveState = false;
    bool m_breakLatched = false;
    bool m_debugBusy = false;
    bool m_debugFailed = false;
    HACDBG_CORE_STATE m_state = {};
    std::uint64_t m_breakRip = 0;
    std::uint32_t m_debugSerial = 0;
    QString m_debugPending;
    QString m_debugEcho;
    QString m_shownUserVersion;
    QString m_shownDriverVersion;
    std::uint64_t m_shownCr3 = 0;
};
