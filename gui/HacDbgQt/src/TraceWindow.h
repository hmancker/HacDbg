#pragma once

#include <QWidget>

#include <hacdbg_trace_api.h>

#include <cstdint>
#include <memory>
#include <thread>

class CoreSession;
class QLabel;
class QComboBox;
class QTimer;

class TraceWindow : public QWidget
{
    Q_OBJECT

public:
    explicit TraceWindow(CoreSession* session, QWidget* parent = nullptr);
    ~TraceWindow() override;

    bool isBusy() const;

signals:
    void commandRequested(const QString& command);
    void focusCommandRequested();
    void idle();

protected:
    void showEvent(QShowEvent* event) override;
    void closeEvent(QCloseEvent* event) override;
    bool eventFilter(QObject* watched, QEvent* event) override;

private:
    bool loadApi(QString* error);
    void ensureAttached();
    void beginDetach();
    void finishDetach();
    void publishGeometry();
    void poll();
    void applyControl(std::uint32_t flags);
    void handleAction(std::uint32_t action);
    void exportCsv();
    std::uint32_t sampleRate() const;
    static void __cdecl actionThunk(std::uint32_t action, void* context);

    CoreSession* m_session = nullptr;
    QWidget* m_host = nullptr;
    QLabel* m_status = nullptr;
    QLabel* m_error = nullptr;
    QComboBox* m_sample = nullptr;
    QTimer* m_timer = nullptr;
    void* m_module = nullptr;
    HACDBG_TRACE* m_trace = nullptr;
    std::unique_ptr<HACDBG_TRACE_SNAPSHOT> m_snapshot;
    std::uint64_t m_sequence = 0;
    bool m_detaching = false;
    bool m_reopen = false;
    std::thread m_detachThread;

    std::uint32_t (*m_apiVersion)() = nullptr;
    std::uint32_t (*m_themeSize)() = nullptr;
    std::uint32_t (*m_lastError)() = nullptr;
    HACDBG_TRACE* (*m_attach)(HWND host, HINSTANCE instance, const HACDBG_TRACE_THEME* theme) = nullptr;
    void (*m_publish)(HACDBG_TRACE* trace, const HACDBG_TRACE_SNAPSHOT* snapshot) = nullptr;
    void (*m_setDpi)(HACDBG_TRACE* trace, std::uint32_t dpi) = nullptr;
    void (*m_setVisible)(HACDBG_TRACE* trace, std::uint32_t visible) = nullptr;
    void (*m_resize)(HACDBG_TRACE* trace, std::uint32_t width, std::uint32_t height) = nullptr;
    void (*m_setCallback)(HACDBG_TRACE* trace, HACDBG_TRACE_ACTION_CALLBACK callback, void* context) = nullptr;
    std::uint32_t (*m_exportCsv)(HACDBG_TRACE* trace, const wchar_t* path) = nullptr;
    void (*m_detach)(HACDBG_TRACE* trace) = nullptr;
};
