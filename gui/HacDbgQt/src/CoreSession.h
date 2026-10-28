#pragma once

#include <QObject>
#include <QString>

#include <hacdbg_core_api.h>

#include <mutex>
#include <thread>
#include <vector>

class CoreSession : public QObject
{
    Q_OBJECT

public:
    struct OutputRecord
    {
        std::uint32_t kind = 0;
        QString text;
    };

    explicit CoreSession(QObject* parent = nullptr);
    ~CoreSession() override;

    static int checkAbi(const wchar_t* directory, QString* error);

    bool load(const QString& directory, QString* error);
    void loadAndStartAsync(const QString& directory);
    void startAsync();
    void shutdown();
    QString startError() const;

    bool isLoaded() const;
    bool isStarted() const;

    void execute(const QString& command);
    void cancel();
    bool getState(HACDBG_CORE_STATE* state) const;
    bool getSymbolProgress(HACDBG_CORE_SYMBOL_PROGRESS* progress) const;

    std::uint64_t requestModules();
    std::uint64_t requestProcesses();
    std::uint64_t requestThreads(std::uint64_t eprocess);
    std::uint64_t requestStack(std::uint32_t frameCount);
    std::uint64_t requestMemory(std::uint64_t address, std::uint64_t cr3, std::uint32_t size);
    std::uint64_t requestDisassembly(std::uint64_t address, std::uint64_t cr3, std::uint32_t count);
    std::uint64_t requestResolve(const QString& text);
    bool getViewStatus(std::uint32_t view, HACDBG_CORE_VIEW_STATUS* status) const;
    bool copyModules(HACDBG_CORE_MODULE* modules, std::uint32_t capacity, std::uint32_t* count) const;
    bool copyProcesses(HACDBG_CORE_PROCESS* processes, std::uint32_t capacity, std::uint32_t* count) const;
    bool copyThreads(HACDBG_CORE_THREAD* threads, std::uint32_t capacity, std::uint32_t* count) const;
    bool copyStack(HACDBG_CORE_STACK_FRAME* frames, std::uint32_t capacity, std::uint32_t* count) const;
    bool copyMemory(HACDBG_CORE_MEMORY* memory) const;
    bool copyDisassembly(HACDBG_CORE_INSTRUCTION* instructions, std::uint32_t capacity, std::uint32_t* count) const;
    bool copyResolvedAddress(HACDBG_CORE_RESOLVED_ADDRESS* address) const;

    bool traceControl(std::uint32_t flags, std::uint32_t sampleRate, std::uint32_t eventMask);
    bool requestTraceRead();
    bool getTraceStatus(HACDBG_CORE_TRACE_STATUS* status) const;
    bool copyTraceSnapshot(HACDBG_TRACE_SNAPSHOT* snapshot) const;

    bool completeCommands(const QString& token, std::vector<QString>* items) const;
    std::uint64_t requestCompletions(const QString& token);
    bool getCompletionStatus(HACDBG_CORE_COMPLETION_STATUS* status) const;
    bool copyCompletions(std::uint64_t requestId, std::vector<QString>* items) const;

    void drainOutput(int maximum, std::vector<OutputRecord>* records);

signals:
    void startFinished(quint32 status);

private:
    void enqueueOutput(std::uint32_t kind, const char* text, std::uint32_t length);
    static void __cdecl outputThunk(std::uint32_t kind, const char* text, std::uint32_t length, void* context);

    void* m_module = nullptr;
    HACDBG_CORE* m_core = nullptr;
    bool m_started = false;
    QString m_startError;
    std::thread m_startThread;
    std::mutex m_outputLock;
    std::vector<OutputRecord> m_output;

    std::uint32_t (*m_apiVersion)() = nullptr;
    std::uint32_t (*m_stateSize)() = nullptr;
    std::uint32_t (*m_structureSize)(std::uint32_t structure) = nullptr;
    HACDBG_CORE* (*m_create)(HACDBG_OUTPUT_CALLBACK callback, void* context) = nullptr;
    void (*m_destroy)(HACDBG_CORE* core) = nullptr;
    std::uint32_t (*m_start)(HACDBG_CORE* core) = nullptr;
    std::uint32_t (*m_stop)(HACDBG_CORE* core) = nullptr;
    std::uint32_t (*m_execute)(HACDBG_CORE* core, const char* command) = nullptr;
    void (*m_cancel)(HACDBG_CORE* core) = nullptr;
    std::uint32_t (*m_getState)(HACDBG_CORE* core, HACDBG_CORE_STATE* state) = nullptr;
    std::uint32_t (*m_getSymbolProgress)(HACDBG_CORE* core, HACDBG_CORE_SYMBOL_PROGRESS* progress) = nullptr;
    std::uint64_t (*m_requestModules)(HACDBG_CORE* core) = nullptr;
    std::uint64_t (*m_requestProcesses)(HACDBG_CORE* core) = nullptr;
    std::uint64_t (*m_requestThreads)(HACDBG_CORE* core, std::uint64_t eprocess) = nullptr;
    std::uint64_t (*m_requestStack)(HACDBG_CORE* core, std::uint32_t frameCount) = nullptr;
    std::uint64_t (*m_requestMemory)(HACDBG_CORE* core, std::uint64_t address, std::uint64_t cr3, std::uint32_t size) = nullptr;
    std::uint64_t (*m_requestDisassembly)(HACDBG_CORE* core, std::uint64_t address, std::uint64_t cr3, std::uint32_t count) = nullptr;
    std::uint64_t (*m_requestResolve)(HACDBG_CORE* core, const char* text) = nullptr;
    std::uint32_t (*m_getViewStatus)(HACDBG_CORE* core, std::uint32_t view, HACDBG_CORE_VIEW_STATUS* status) = nullptr;
    std::uint32_t (*m_copyModules)(HACDBG_CORE* core, HACDBG_CORE_MODULE* modules, std::uint32_t capacity, std::uint32_t* count) = nullptr;
    std::uint32_t (*m_copyProcesses)(HACDBG_CORE* core, HACDBG_CORE_PROCESS* processes, std::uint32_t capacity, std::uint32_t* count) = nullptr;
    std::uint32_t (*m_copyThreads)(HACDBG_CORE* core, HACDBG_CORE_THREAD* threads, std::uint32_t capacity, std::uint32_t* count) = nullptr;
    std::uint32_t (*m_copyStack)(HACDBG_CORE* core, HACDBG_CORE_STACK_FRAME* frames, std::uint32_t capacity, std::uint32_t* count) = nullptr;
    std::uint32_t (*m_copyMemory)(HACDBG_CORE* core, HACDBG_CORE_MEMORY* memory) = nullptr;
    std::uint32_t (*m_copyDisassembly)(HACDBG_CORE* core, HACDBG_CORE_INSTRUCTION* instructions, std::uint32_t capacity, std::uint32_t* count) = nullptr;
    std::uint32_t (*m_copyResolvedAddress)(HACDBG_CORE* core, HACDBG_CORE_RESOLVED_ADDRESS* address) = nullptr;
    std::uint32_t (*m_traceControl)(HACDBG_CORE* core, std::uint32_t flags, std::uint32_t sampleRate, std::uint32_t eventMask) = nullptr;
    std::uint32_t (*m_requestTraceRead)(HACDBG_CORE* core) = nullptr;
    std::uint32_t (*m_getTraceStatus)(HACDBG_CORE* core, HACDBG_CORE_TRACE_STATUS* status) = nullptr;
    std::uint32_t (*m_copyTraceSnapshot)(HACDBG_CORE* core, HACDBG_TRACE_SNAPSHOT* snapshot) = nullptr;
    std::uint32_t (*m_completeCommands)(const char* token, HACDBG_CORE_COMPLETION* items, std::uint32_t capacity, std::uint32_t* count) = nullptr;
    std::uint64_t (*m_requestCompletions)(HACDBG_CORE* core, const char* token) = nullptr;
    std::uint32_t (*m_getCompletionStatus)(HACDBG_CORE* core, HACDBG_CORE_COMPLETION_STATUS* status) = nullptr;
    std::uint32_t (*m_copyCompletions)(HACDBG_CORE* core, std::uint64_t requestId, HACDBG_CORE_COMPLETION* items, std::uint32_t capacity, std::uint32_t* count) = nullptr;
};
