#include "CoreSession.h"

#include "Format.h"

#include <hacdbg_trace_api.h>

#include <Windows.h>

#include <QByteArray>

namespace
{
constexpr int kMaximumQueuedOutput = 50000;

bool structureMatches(std::uint32_t (*sizeOf)(std::uint32_t), std::uint32_t id, std::size_t expected)
{
    return sizeOf != nullptr && sizeOf(id) == expected;
}

template <typename T>
bool bindProc(HMODULE module, const char* name, T* function)
{
    if (module == nullptr || function == nullptr)
    {
        return false;
    }

    void* address = reinterpret_cast<void*>(GetProcAddress(module, name));

    if (address == nullptr)
    {
        return false;
    }

    *function = reinterpret_cast<T>(address);
    return true;
}
}

CoreSession::CoreSession(QObject* parent)
    : QObject(parent)
{
}

CoreSession::~CoreSession()
{
    shutdown();

    if (m_module != nullptr)
    {
        FreeLibrary(static_cast<HMODULE>(m_module));
        m_module = nullptr;
    }
}

int CoreSession::checkAbi(const wchar_t* directory, QString* error)
{
    const std::wstring corePath = std::wstring(directory) + L"\\HacDbgCore.dll";
    const std::wstring tracePath = std::wstring(directory) + L"\\HacDbgTrace.dll";
    HMODULE core = LoadLibraryW(corePath.c_str());
    HMODULE trace = LoadLibraryW(tracePath.c_str());

    if (core == nullptr || trace == nullptr)
    {
        if (error != nullptr)
        {
            *error = QStringLiteral("缺少 HacDbgCore.dll 或 HacDbgTrace.dll。");
        }

        if (core != nullptr)
        {
            FreeLibrary(core);
        }

        if (trace != nullptr)
        {
            FreeLibrary(trace);
        }

        return 2;
    }

    auto apiVersion = reinterpret_cast<std::uint32_t (*)()>(
        reinterpret_cast<void*>(GetProcAddress(core, "HacDbgCoreApiVersion")));
    auto stateSize = reinterpret_cast<std::uint32_t (*)()>(
        reinterpret_cast<void*>(GetProcAddress(core, "HacDbgCoreStateSize")));
    auto structureSize = reinterpret_cast<std::uint32_t (*)(std::uint32_t)>(
        reinterpret_cast<void*>(GetProcAddress(core, "HacDbgCoreStructureSize")));
    auto traceVersion = reinterpret_cast<std::uint32_t (*)()>(
        reinterpret_cast<void*>(GetProcAddress(trace, "HacDbgTraceApiVersion")));
    auto themeSize = reinterpret_cast<std::uint32_t (*)()>(
        reinterpret_cast<void*>(GetProcAddress(trace, "HacDbgTraceThemeSize")));

    const bool coreOk = apiVersion != nullptr &&
                        stateSize != nullptr &&
                        structureSize != nullptr &&
                        apiVersion() == HACDBG_CORE_API_VERSION &&
                        stateSize() == sizeof(HACDBG_CORE_STATE) &&
                        structureMatches(structureSize, HacDbgStructureViewStatus, sizeof(HACDBG_CORE_VIEW_STATUS)) &&
                        structureMatches(structureSize, HacDbgStructureModule, sizeof(HACDBG_CORE_MODULE)) &&
                        structureMatches(structureSize, HacDbgStructureProcess, sizeof(HACDBG_CORE_PROCESS)) &&
                        structureMatches(structureSize, HacDbgStructureThread, sizeof(HACDBG_CORE_THREAD)) &&
                        structureMatches(structureSize, HacDbgStructureStackFrame, sizeof(HACDBG_CORE_STACK_FRAME)) &&
                        structureMatches(structureSize, HacDbgStructureMemory, sizeof(HACDBG_CORE_MEMORY)) &&
                        structureMatches(structureSize, HacDbgStructureInstruction, sizeof(HACDBG_CORE_INSTRUCTION)) &&
                        structureMatches(structureSize, HacDbgStructureResolvedAddress, sizeof(HACDBG_CORE_RESOLVED_ADDRESS)) &&
                        structureMatches(structureSize, HacDbgStructureTraceStatus, sizeof(HACDBG_CORE_TRACE_STATUS)) &&
                        structureMatches(structureSize, HacDbgStructureTraceSnapshot, sizeof(HACDBG_TRACE_SNAPSHOT)) &&
                        structureMatches(structureSize, HacDbgStructureCompletion, sizeof(HACDBG_CORE_COMPLETION)) &&
                        structureMatches(structureSize, HacDbgStructureCompletionStatus, sizeof(HACDBG_CORE_COMPLETION_STATUS)) &&
                        structureMatches(structureSize, HacDbgStructureMonitor, sizeof(HACDBG_CORE_MONITOR)) &&
                        structureMatches(structureSize, HacDbgStructureMonitorHit, sizeof(HACDBG_CORE_MONITOR_HIT));
    const bool traceOk = traceVersion != nullptr &&
                         themeSize != nullptr &&
                         traceVersion() == HACDBG_TRACE_API_VERSION &&
                         themeSize() == sizeof(HACDBG_TRACE_THEME);

    FreeLibrary(core);
    FreeLibrary(trace);

    if (coreOk == false || traceOk == false)
    {
        if (error != nullptr)
        {
            *error = QStringLiteral("核心或 trace ABI 与 GUI 不匹配。");
        }

        return 1;
    }

    return 0;
}

bool CoreSession::load(const QString& directory, QString* error)
{
    if (m_module != nullptr)
    {
        return true;
    }

    const QString path = directory + QStringLiteral("\\HacDbgCore.dll");
    HMODULE module = LoadLibraryW(reinterpret_cast<const wchar_t*>(path.utf16()));
    m_module = module;

    if (module == nullptr)
    {
        if (error != nullptr)
        {
            *error = QStringLiteral("缺少 HacDbgCore.dll；请把完整的发布目录一起复制。");
        }

        return false;
    }

    const bool bound =
        bindProc(module, "HacDbgCoreApiVersion", &m_apiVersion) &&
        bindProc(module, "HacDbgCoreStateSize", &m_stateSize) &&
        bindProc(module, "HacDbgCoreStructureSize", &m_structureSize) &&
        bindProc(module, "HacDbgCoreCreate", &m_create) &&
        bindProc(module, "HacDbgCoreDestroy", &m_destroy) &&
        bindProc(module, "HacDbgCoreStart", &m_start) &&
        bindProc(module, "HacDbgCoreStop", &m_stop) &&
        bindProc(module, "HacDbgCoreExecute", &m_execute) &&
        bindProc(module, "HacDbgCoreCancel", &m_cancel) &&
        bindProc(module, "HacDbgCoreGetState", &m_getState) &&
        bindProc(module, "HacDbgCoreGetSymbolProgress", &m_getSymbolProgress) &&
        bindProc(module, "HacDbgCoreRequestModules", &m_requestModules) &&
        bindProc(module, "HacDbgCoreRequestProcesses", &m_requestProcesses) &&
        bindProc(module, "HacDbgCoreRequestThreads", &m_requestThreads) &&
        bindProc(module, "HacDbgCoreRequestStack", &m_requestStack) &&
        bindProc(module, "HacDbgCoreRequestMemory", &m_requestMemory) &&
        bindProc(module, "HacDbgCoreRequestDisassembly", &m_requestDisassembly) &&
        bindProc(module, "HacDbgCoreRequestResolve", &m_requestResolve) &&
        bindProc(module, "HacDbgCoreGetViewStatus", &m_getViewStatus) &&
        bindProc(module, "HacDbgCoreCopyModules", &m_copyModules) &&
        bindProc(module, "HacDbgCoreCopyProcesses", &m_copyProcesses) &&
        bindProc(module, "HacDbgCoreCopyThreads", &m_copyThreads) &&
        bindProc(module, "HacDbgCoreCopyStack", &m_copyStack) &&
        bindProc(module, "HacDbgCoreCopyMemory", &m_copyMemory) &&
        bindProc(module, "HacDbgCoreCopyDisassembly", &m_copyDisassembly) &&
        bindProc(module, "HacDbgCoreCopyResolvedAddress", &m_copyResolvedAddress) &&
        bindProc(module, "HacDbgCoreTraceControl", &m_traceControl) &&
        bindProc(module, "HacDbgCoreRequestTraceRead", &m_requestTraceRead) &&
        bindProc(module, "HacDbgCoreGetTraceStatus", &m_getTraceStatus) &&
        bindProc(module, "HacDbgCoreCopyTraceSnapshot", &m_copyTraceSnapshot) &&
        bindProc(module, "HacDbgCoreCompleteCommands", &m_completeCommands) &&
        bindProc(module, "HacDbgCoreRequestCompletions", &m_requestCompletions) &&
        bindProc(module, "HacDbgCoreGetCompletionStatus", &m_getCompletionStatus) &&
        bindProc(module, "HacDbgCoreCopyCompletions", &m_copyCompletions) &&
        bindProc(module, "HacDbgCoreCopyMonitors", &m_copyMonitors) &&
        bindProc(module, "HacDbgCoreCopyMonitorHits", &m_copyMonitorHits);

    if (bound == false ||
        m_apiVersion() != HACDBG_CORE_API_VERSION ||
        m_stateSize() != sizeof(HACDBG_CORE_STATE) ||
        m_structureSize(HacDbgStructureMonitor) != sizeof(HACDBG_CORE_MONITOR) ||
        m_structureSize(HacDbgStructureMonitorHit) != sizeof(HACDBG_CORE_MONITOR_HIT))
    {
        FreeLibrary(module);
        m_module = nullptr;

        if (error != nullptr)
        {
            *error = QStringLiteral("HacDbgCore.dll 的核心 ABI 或结构布局与 GUI 不匹配，请使用同一版本重新构建。");
        }

        return false;
    }

    return true;
}

void CoreSession::loadAndStartAsync(const QString& directory)
{
    if (m_startThread.joinable())
    {
        m_startThread.join();
    }

    m_startThread = std::thread([this, directory]
    {
        QString error;

        if (load(directory, &error) == false)
        {
            m_startError = error;
            QMetaObject::invokeMethod(this, [this]
            {
                emit startFinished(HacDbgCoreStatusState);
            }, Qt::QueuedConnection);
            return;
        }

        m_core = m_create(&CoreSession::outputThunk, this);

        if (m_core == nullptr)
        {
            m_startError = QStringLiteral("核心处于无效状态，无法启动调试会话。");
            QMetaObject::invokeMethod(this, [this]
            {
                emit startFinished(HacDbgCoreStatusState);
            }, Qt::QueuedConnection);
            return;
        }

        const std::uint32_t status = m_start(m_core);
        QMetaObject::invokeMethod(this, [this, status]
        {
            if (m_core == nullptr)
            {
                return;
            }

            m_started = status == HacDbgCoreStatusOk;
            emit startFinished(status);
        }, Qt::QueuedConnection);
    });
}

QString CoreSession::startError() const
{
    return m_startError;
}

void CoreSession::startAsync()
{
    if (m_core != nullptr || m_create == nullptr)
    {
        return;
    }

    m_core = m_create(&CoreSession::outputThunk, this);

    if (m_core == nullptr)
    {
        emit startFinished(HacDbgCoreStatusState);
        return;
    }

    if (m_startThread.joinable())
    {
        m_startThread.join();
    }

    m_startThread = std::thread([this]
    {
        const std::uint32_t status = m_start(m_core);
        QMetaObject::invokeMethod(this, [this, status]
        {
            if (m_core == nullptr)
            {
                return;
            }

            m_started = status == HacDbgCoreStatusOk;
            emit startFinished(status);
        }, Qt::QueuedConnection);
    });
}

void CoreSession::shutdown()
{
    if (m_startThread.joinable())
    {
        m_startThread.join();
    }

    if (m_core != nullptr && m_stop != nullptr)
    {
        m_stop(m_core);
    }

    m_started = false;

    if (m_core != nullptr && m_destroy != nullptr)
    {
        m_destroy(m_core);
        m_core = nullptr;
    }
}

bool CoreSession::isLoaded() const
{
    return m_module != nullptr;
}

bool CoreSession::isStarted() const
{
    return m_started;
}

void CoreSession::execute(const QString& command)
{
    if (m_started == false || m_execute == nullptr)
    {
        return;
    }

    const QByteArray utf8 = command.toUtf8();
    m_execute(m_core, utf8.constData());
}

void CoreSession::cancel()
{
    if (m_started && m_cancel != nullptr)
    {
        m_cancel(m_core);
    }
}

bool CoreSession::getState(HACDBG_CORE_STATE* state) const
{
    return m_started && m_getState != nullptr && state != nullptr && m_getState(m_core, state) == HacDbgCoreStatusOk;
}

bool CoreSession::getSymbolProgress(HACDBG_CORE_SYMBOL_PROGRESS* progress) const
{
    return m_started && m_getSymbolProgress != nullptr && progress != nullptr &&
           m_getSymbolProgress(m_core, progress) == HacDbgCoreStatusOk;
}

std::uint64_t CoreSession::requestModules()
{
    if (m_started == false || m_requestModules == nullptr)
    {
        return 0;
    }

    return m_requestModules(m_core);
}

std::uint64_t CoreSession::requestProcesses()
{
    if (m_started == false || m_requestProcesses == nullptr)
    {
        return 0;
    }

    return m_requestProcesses(m_core);
}

std::uint64_t CoreSession::requestThreads(std::uint64_t eprocess)
{
    if (m_started == false || m_requestThreads == nullptr)
    {
        return 0;
    }

    return m_requestThreads(m_core, eprocess);
}

std::uint64_t CoreSession::requestStack(std::uint32_t frameCount)
{
    if (m_started == false || m_requestStack == nullptr)
    {
        return 0;
    }

    return m_requestStack(m_core, frameCount);
}

std::uint64_t CoreSession::requestMemory(std::uint64_t address, std::uint64_t cr3, std::uint32_t size)
{
    if (m_started == false || m_requestMemory == nullptr)
    {
        return 0;
    }

    return m_requestMemory(m_core, address, cr3, size);
}

std::uint64_t CoreSession::requestDisassembly(std::uint64_t address, std::uint64_t cr3, std::uint32_t count)
{
    if (m_started == false || m_requestDisassembly == nullptr)
    {
        return 0;
    }

    return m_requestDisassembly(m_core, address, cr3, count);
}

std::uint64_t CoreSession::requestResolve(const QString& text)
{
    if (m_started == false || m_requestResolve == nullptr)
    {
        return 0;
    }

    const QByteArray utf8 = text.toUtf8();
    return m_requestResolve(m_core, utf8.constData());
}

bool CoreSession::getViewStatus(std::uint32_t view, HACDBG_CORE_VIEW_STATUS* status) const
{
    return m_started && m_getViewStatus != nullptr && status != nullptr &&
           m_getViewStatus(m_core, view, status) == HacDbgCoreStatusOk;
}

bool CoreSession::copyModules(HACDBG_CORE_MODULE* modules, std::uint32_t capacity, std::uint32_t* count) const
{
    return m_started && m_copyModules != nullptr &&
           m_copyModules(m_core, modules, capacity, count) == HacDbgCoreStatusOk;
}

bool CoreSession::copyProcesses(HACDBG_CORE_PROCESS* processes, std::uint32_t capacity, std::uint32_t* count) const
{
    return m_started && m_copyProcesses != nullptr &&
           m_copyProcesses(m_core, processes, capacity, count) == HacDbgCoreStatusOk;
}

bool CoreSession::copyThreads(HACDBG_CORE_THREAD* threads, std::uint32_t capacity, std::uint32_t* count) const
{
    return m_started && m_copyThreads != nullptr &&
           m_copyThreads(m_core, threads, capacity, count) == HacDbgCoreStatusOk;
}

bool CoreSession::copyStack(HACDBG_CORE_STACK_FRAME* frames, std::uint32_t capacity, std::uint32_t* count) const
{
    return m_started && m_copyStack != nullptr &&
           m_copyStack(m_core, frames, capacity, count) == HacDbgCoreStatusOk;
}

bool CoreSession::copyMemory(HACDBG_CORE_MEMORY* memory) const
{
    return m_started && m_copyMemory != nullptr && m_copyMemory(m_core, memory) == HacDbgCoreStatusOk;
}

bool CoreSession::copyDisassembly(HACDBG_CORE_INSTRUCTION* instructions, std::uint32_t capacity, std::uint32_t* count) const
{
    return m_started && m_copyDisassembly != nullptr &&
           m_copyDisassembly(m_core, instructions, capacity, count) == HacDbgCoreStatusOk;
}

bool CoreSession::copyResolvedAddress(HACDBG_CORE_RESOLVED_ADDRESS* address) const
{
    return m_started && m_copyResolvedAddress != nullptr &&
           m_copyResolvedAddress(m_core, address) == HacDbgCoreStatusOk;
}

bool CoreSession::copyMonitors(HACDBG_CORE_MONITOR* monitors, std::uint32_t capacity, std::uint32_t* count) const
{
    return m_started && m_copyMonitors != nullptr && count != nullptr &&
           m_copyMonitors(m_core, monitors, capacity, count) == HacDbgCoreStatusOk;
}

bool CoreSession::copyMonitorHits(HACDBG_CORE_MONITOR_HIT* hits, std::uint32_t capacity, std::uint32_t* count) const
{
    return m_started && m_copyMonitorHits != nullptr && count != nullptr &&
           m_copyMonitorHits(m_core, hits, capacity, count) == HacDbgCoreStatusOk;
}

bool CoreSession::traceControl(std::uint32_t flags, std::uint32_t sampleRate, std::uint32_t eventMask)
{
    return m_started && m_traceControl != nullptr &&
           m_traceControl(m_core, flags, sampleRate, eventMask) == HacDbgCoreStatusOk;
}

bool CoreSession::requestTraceRead()
{
    return m_started && m_requestTraceRead != nullptr &&
           m_requestTraceRead(m_core) == HacDbgCoreStatusOk;
}

bool CoreSession::getTraceStatus(HACDBG_CORE_TRACE_STATUS* status) const
{
    return m_started && m_getTraceStatus != nullptr && status != nullptr &&
           m_getTraceStatus(m_core, status) == HacDbgCoreStatusOk;
}

bool CoreSession::copyTraceSnapshot(HACDBG_TRACE_SNAPSHOT* snapshot) const
{
    return m_started && m_copyTraceSnapshot != nullptr && snapshot != nullptr &&
           m_copyTraceSnapshot(m_core, snapshot) == HacDbgCoreStatusOk;
}

bool CoreSession::completeCommands(const QString& token, std::vector<QString>* items) const
{
    if (m_completeCommands == nullptr || items == nullptr)
    {
        return false;
    }

    HACDBG_CORE_COMPLETION completions[HACDBG_CORE_MAX_COMPLETIONS] = {};
    std::uint32_t count = 0;
    const QByteArray utf8 = token.toUtf8();

    if (m_completeCommands(utf8.constData(), completions, HACDBG_CORE_MAX_COMPLETIONS, &count) != HacDbgCoreStatusOk)
    {
        return false;
    }

    items->clear();

    for (std::uint32_t index = 0; index < count; ++index)
    {
        items->push_back(fromField(completions[index].Text, HACDBG_CORE_COMPLETION_SIZE));
    }

    return true;
}

std::uint64_t CoreSession::requestCompletions(const QString& token)
{
    if (m_started == false || m_requestCompletions == nullptr)
    {
        return 0;
    }

    const QByteArray utf8 = token.toUtf8();
    return m_requestCompletions(m_core, utf8.constData());
}

bool CoreSession::getCompletionStatus(HACDBG_CORE_COMPLETION_STATUS* status) const
{
    return m_started && m_getCompletionStatus != nullptr && status != nullptr &&
           m_getCompletionStatus(m_core, status) == HacDbgCoreStatusOk;
}

bool CoreSession::copyCompletions(std::uint64_t requestId, std::vector<QString>* items) const
{
    if (m_started == false || m_copyCompletions == nullptr || items == nullptr)
    {
        return false;
    }

    HACDBG_CORE_COMPLETION completions[HACDBG_CORE_MAX_COMPLETIONS] = {};
    std::uint32_t count = 0;

    if (m_copyCompletions(m_core, requestId, completions, HACDBG_CORE_MAX_COMPLETIONS, &count) != HacDbgCoreStatusOk)
    {
        return false;
    }

    items->clear();

    for (std::uint32_t index = 0; index < count; ++index)
    {
        items->push_back(fromField(completions[index].Text, HACDBG_CORE_COMPLETION_SIZE));
    }

    return true;
}

void CoreSession::drainOutput(int maximum, std::vector<OutputRecord>* records)
{
    if (records == nullptr || maximum <= 0)
    {
        return;
    }

    std::lock_guard<std::mutex> guard(m_outputLock);
    const int available = static_cast<int>(m_output.size());
    const int count = available < maximum ? available : maximum;
    records->insert(records->end(), m_output.begin(), m_output.begin() + count);
    m_output.erase(m_output.begin(), m_output.begin() + count);
}

void CoreSession::enqueueOutput(std::uint32_t kind, const char* text, std::uint32_t length)
{
    OutputRecord record;
    record.kind = kind;

    if (text != nullptr && length != 0)
    {
        record.text = QString::fromUtf8(text, static_cast<int>(length));
    }

    std::lock_guard<std::mutex> guard(m_outputLock);
    m_output.push_back(std::move(record));

    if (m_output.size() > kMaximumQueuedOutput)
    {
        m_output.erase(m_output.begin(), m_output.begin() + static_cast<std::ptrdiff_t>(m_output.size() - kMaximumQueuedOutput));
    }
}

void __cdecl CoreSession::outputThunk(std::uint32_t kind, const char* text, std::uint32_t length, void* context)
{
    if (context != nullptr)
    {
        static_cast<CoreSession*>(context)->enqueueOutput(kind, text, length);
    }
}

