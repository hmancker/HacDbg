#include "ProcessActions.h"

#include "HandleDialog.h"
#include "InjectDialog.h"
#include "ProcessDriver.h"

#include "process_control.h"

#include <QCursor>
#include <QDialog>
#include <QMenu>
#include <QMessageBox>

#include <Windows.h>
#include <shlobj.h>
#include <TlHelp32.h>

#ifndef WDA_EXCLUDEFROMCAPTURE
#define WDA_EXCLUDEFROMCAPTURE 0x00000011
#endif

namespace
{
using NtProcess = LONG(NTAPI*)(HANDLE);

QString statusText(std::int32_t status)
{
    return QStringLiteral("0x%1").arg(static_cast<std::uint32_t>(status), 8, 16, QChar('0'));
}

void report(QWidget* parent, const QString& action, bool ok, std::int32_t status)
{
    if (ok)
    {
        return;
    }

    QMessageBox::warning(parent, action, QStringLiteral("%1 失败：%2").arg(action, statusText(status)));
}

bool enableDebugPrivilege()
{
    HANDLE token = nullptr;
    TOKEN_PRIVILEGES privileges = {};
    LUID luid = {};

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token) == FALSE)
    {
        return false;
    }

    if (LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid) == FALSE)
    {
        CloseHandle(token);
        return false;
    }

    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Luid = luid;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    const BOOL adjusted = AdjustTokenPrivileges(token, FALSE, &privileges, 0, nullptr, nullptr);
    CloseHandle(token);
    return adjusted != FALSE && GetLastError() != ERROR_NOT_ALL_ASSIGNED;
}

bool endProcess(std::uint32_t pid, std::int32_t* status)
{
    enableDebugPrivilege();
    const HANDLE process = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (process == nullptr)
    {
        *status = static_cast<std::int32_t>(GetLastError());
        return false;
    }

    const BOOL ended = TerminateProcess(process, 1);
    *status = ended != FALSE ? 0 : static_cast<std::int32_t>(GetLastError());
    CloseHandle(process);
    return ended != FALSE;
}

bool forceProcess(std::uint32_t pid, std::int32_t* status)
{
    if (endProcess(pid, status))
    {
        return true;
    }

    const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    THREADENTRY32 entry = {};
    entry.dwSize = sizeof(entry);
    if (Thread32First(snapshot, &entry) != FALSE)
    {
        do
        {
            if (entry.th32OwnerProcessID != pid)
            {
                continue;
            }

            const HANDLE thread = OpenThread(THREAD_TERMINATE, FALSE, entry.th32ThreadID);
            if (thread != nullptr)
            {
                TerminateThread(thread, 1);
                CloseHandle(thread);
            }
        } while (Thread32Next(snapshot, &entry) != FALSE);
    }

    CloseHandle(snapshot);
    return endProcess(pid, status);
}

bool suspendProcess(std::uint32_t pid, bool resume, std::int32_t* status)
{
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    const auto routine = ntdll == nullptr
                             ? nullptr
                             : reinterpret_cast<NtProcess>(GetProcAddress(ntdll, resume ? "NtResumeProcess" : "NtSuspendProcess"));
    if (routine == nullptr)
    {
        *status = static_cast<std::int32_t>(ERROR_PROC_NOT_FOUND);
        return false;
    }

    enableDebugPrivilege();
    const HANDLE process = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
    if (process == nullptr)
    {
        *status = static_cast<std::int32_t>(GetLastError());
        return false;
    }

    const LONG result = routine(process);
    CloseHandle(process);
    *status = result;
    return result >= 0;
}

bool selectImageFile(const wchar_t* path)
{
    PIDLIST_ABSOLUTE item = nullptr;
    const HRESULT parsed = SHParseDisplayName(path, nullptr, &item, 0, nullptr);
    if (FAILED(parsed) || item == nullptr)
    {
        return false;
    }

    const HRESULT opened = SHOpenFolderAndSelectItems(item, 0, nullptr, 0);
    ILFree(item);
    return SUCCEEDED(opened);
}

void openFileLocation(QWidget* parent, std::uint32_t pid)
{
    wchar_t path[HACDBG_PROCESS_PATH_CHARS] = {};
    std::int32_t status = 0;

    if (processDriverImagePath(pid, path, HACDBG_PROCESS_PATH_CHARS, &status) == false)
    {
        QMessageBox::warning(parent, QStringLiteral("打开文件位置"),
                             QStringLiteral("读不到映像路径：%1").arg(statusText(status)));
        return;
    }

    if (selectImageFile(path) == false)
    {
        QMessageBox::warning(parent, QStringLiteral("打开文件位置"),
                             QStringLiteral("无法在资源管理器中选中：%1").arg(QString::fromWCharArray(path)));
    }
}

struct WindowEnumContext
{
    DWORD pid;
    int changed;
};

BOOL CALLBACK protectOneWindow(HWND window, LPARAM parameter)
{
    auto* found = reinterpret_cast<WindowEnumContext*>(parameter);
    DWORD owner = 0;
    GetWindowThreadProcessId(window, &owner);
    if (owner == found->pid && SetWindowDisplayAffinity(window, WDA_EXCLUDEFROMCAPTURE) != FALSE)
    {
        found->changed++;
    }
    return TRUE;
}

void protectWindows(QWidget* parent, std::uint32_t pid)
{
    WindowEnumContext context{pid, 0};

    EnumWindows(protectOneWindow, reinterpret_cast<LPARAM>(&context));

    if (context.changed == 0)
    {
        QMessageBox::warning(parent, QStringLiteral("窗口保护"), QStringLiteral("没有可排除截图的顶层窗口。"));
    }
}

void injectDll(QWidget* parent, const ProcessRecord& record)
{
    InjectDialog dialog(record.pid, parent);
    if (dialog.exec() != QDialog::Accepted)
    {
        return;
    }

    if (dialog.dllPath().isEmpty())
    {
        QMessageBox::warning(parent, QStringLiteral("注入 DLL"), QStringLiteral("没有选择 DLL。"));
        return;
    }

    std::int32_t status = 0;
    const bool poison = dialog.poisonPage() || dialog.pteMethod();
    const bool ok = processDriverCall(dialog.pteMethod() ? HACDBG_PROCESS_INJECT_PTE : HACDBG_PROCESS_INJECT_APC,
                                      static_cast<std::uint32_t>(record.pid), 0,
                                      poison ? HACDBG_PROCESS_FLAG_POISON : 0,
                                      reinterpret_cast<const wchar_t*>(dialog.dllPath().utf16()), &status);
    report(parent, QStringLiteral("注入 DLL"), ok, status);
}

void driverAction(QWidget* parent, const QString& title, std::uint32_t operation, std::uint32_t pid,
                  std::uint32_t parameter)
{
    std::int32_t status = 0;
    const bool ok = processDriverCall(operation, pid, parameter, 0, nullptr, &status);
    report(parent, title, ok, status);
}

void handleAction(QWidget* parent, const ProcessRecord& record, bool upgrade)
{
    HandleDialog dialog(upgrade, record.image, parent);
    if (dialog.exec() != QDialog::Accepted)
    {
        return;
    }

    const QString actor = dialog.actor();
    const QString victim = dialog.allProcesses() ? QString() : dialog.victim();
    const std::uint32_t parameter = upgrade ? (dialog.allProcesses() ? HACDBG_HANDLE_UPGRADE_ALL : HACDBG_HANDLE_UPGRADE_NAME)
                                            : (dialog.allProcesses() ? HACDBG_HANDLE_DOWNGRADE_ALL : HACDBG_HANDLE_DOWNGRADE_NAME);
    std::int32_t status = 0;
    const bool ok = processDriverHandleCall(parameter, static_cast<std::uint32_t>(record.pid),
                                            reinterpret_cast<const wchar_t*>(actor.utf16()),
                                            victim.isEmpty() ? nullptr : reinterpret_cast<const wchar_t*>(victim.utf16()),
                                            &status);
    report(parent, upgrade ? QStringLiteral("句柄提权") : QStringLiteral("句柄降权"), ok, status);
}
}

void showProcessMenu(QWidget* parent, const ProcessRecord& record, const std::function<void()>& dumpRequested)
{
    QMenu menu(parent);
    QMenu* state = menu.addMenu(QStringLiteral("设置状态"));
    QAction* suspend = state->addAction(QStringLiteral("挂起"));
    QAction* resume = state->addAction(QStringLiteral("恢复"));
    QMenu* dump = menu.addMenu(QStringLiteral("转储进程内存"));
    QAction* dumpWindow = dump->addAction(QStringLiteral("打开转储窗口"));
    QMenu* ppl = menu.addMenu(QStringLiteral("设置进程 PPL"));
    QAction* pplNone = ppl->addAction(QStringLiteral("无"));
    QAction* pplAnti = ppl->addAction(QStringLiteral("PPL-Antimalware"));
    QAction* pplWindows = ppl->addAction(QStringLiteral("PPL-Windows"));
    QAction* pplTcbLight = ppl->addAction(QStringLiteral("PPL-WinTcb"));
    QAction* pplTcb = ppl->addAction(QStringLiteral("PP-WinTcb"));

    QAction* end = menu.addAction(QStringLiteral("结束进程"));
    QAction* kernelEnd = menu.addAction(QStringLiteral("内核结束进程"));
    QAction* forceEnd = menu.addAction(QStringLiteral("强制结束进程"));
    QAction* hide = menu.addAction(QStringLiteral("隐藏进程"));
    QAction* window = menu.addAction(QStringLiteral("窗口保护"));
    QMenu* handles = menu.addMenu(QStringLiteral("句柄保护"));
    QAction* handleDown = handles->addAction(QStringLiteral("降权"));
    QAction* handleUp = handles->addAction(QStringLiteral("提权"));
    QAction* handleStop = handles->addAction(QStringLiteral("停止"));
    QAction* inject = menu.addAction(QStringLiteral("注入 DLL"));
    QAction* location = menu.addAction(QStringLiteral("打开文件位置"));

    QAction* chosen = menu.exec(QCursor::pos());
    if (chosen == nullptr)
    {
        return;
    }

    const auto pid = static_cast<std::uint32_t>(record.pid);
    std::int32_t status = 0;
    if (chosen == end)
    {
        report(parent, QStringLiteral("结束进程"), endProcess(pid, &status), status);
    }
    else if (chosen == kernelEnd)
    {
        driverAction(parent, QStringLiteral("内核结束进程"), HACDBG_PROCESS_TERMINATE_KERNEL, pid, 0);
    }
    else if (chosen == forceEnd)
    {
        std::int32_t kernelStatus = 0;
        if (processDriverCall(HACDBG_PROCESS_TERMINATE_FORCE, pid, 0, 0, nullptr, &kernelStatus))
        {
            return;
        }
        report(parent, QStringLiteral("强制结束进程"), forceProcess(pid, &status), status == 0 ? kernelStatus : status);
    }
    else if (chosen == dumpWindow)
    {
        if (dumpRequested)
        {
            dumpRequested();
        }
    }
    else if (chosen == suspend || chosen == resume)
    {
        const QString title = chosen == suspend ? QStringLiteral("挂起") : QStringLiteral("恢复");
        std::int32_t kernelStatus = 0;
        const bool kernelOk = processDriverCall(chosen == suspend ? HACDBG_PROCESS_SUSPEND : HACDBG_PROCESS_RESUME, pid,
                                                0, 0, nullptr, &kernelStatus);
        if (kernelOk == false && suspendProcess(pid, chosen == resume, &status) == false)
        {
            report(parent, title, false, kernelStatus != 0 ? kernelStatus : status);
        }
    }
    else if (chosen == hide)
    {
        driverAction(parent, QStringLiteral("隐藏进程"), HACDBG_PROCESS_HIDE, pid, 0);
    }
    else if (chosen == window)
    {
        protectWindows(parent, pid);
    }
    else if (chosen == handleDown || chosen == handleUp)
    {
        handleAction(parent, record, chosen == handleUp);
    }
    else if (chosen == handleStop)
    {
        std::int32_t handleStatus = 0;
        const bool stopped = processDriverHandleCall(HACDBG_HANDLE_STOP, pid, nullptr, nullptr, &handleStatus);
        if (stopped)
        {
            QMessageBox::information(parent, QStringLiteral("句柄保护"), QStringLiteral("已停止。驱动仍保持加载。"));
        }
        else
        {
            report(parent, QStringLiteral("句柄保护"), false, handleStatus);
        }
    }
    else if (chosen == pplNone)
    {
        driverAction(parent, QStringLiteral("设置进程 PPL"), HACDBG_PROCESS_SET_PPL, pid, HACDBG_PPL_NONE);
    }
    else if (chosen == pplAnti)
    {
        driverAction(parent, QStringLiteral("设置进程 PPL"), HACDBG_PROCESS_SET_PPL, pid, HACDBG_PPL_ANTIMALWARE);
    }
    else if (chosen == pplWindows)
    {
        driverAction(parent, QStringLiteral("设置进程 PPL"), HACDBG_PROCESS_SET_PPL, pid, HACDBG_PPL_WINDOWS);
    }
    else if (chosen == pplTcbLight)
    {
        driverAction(parent, QStringLiteral("设置进程 PPL"), HACDBG_PROCESS_SET_PPL, pid, HACDBG_PPL_WINTCB_LIGHT);
    }
    else if (chosen == pplTcb)
    {
        driverAction(parent, QStringLiteral("设置进程 PPL"), HACDBG_PROCESS_SET_PPL, pid, HACDBG_PPL_WINTCB);
    }
    else if (chosen == inject)
    {
        injectDll(parent, record);
    }
    else if (chosen == location)
    {
        openFileLocation(parent, pid);
    }
}
