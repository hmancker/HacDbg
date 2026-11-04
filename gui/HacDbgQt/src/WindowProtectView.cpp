#include "WindowProtectView.h"

#include "window/WindowAffinity.h"
#include "window/WindowDriver.h"

#include "window_protect.h"

#include <QCheckBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QPushButton>
#include <QStandardItemModel>
#include <QTableView>
#include <QVBoxLayout>

#include <TlHelp32.h>
#include <unordered_map>
#include <vector>

#ifndef WDA_NONE
#define WDA_NONE 0x00000000
#endif
#ifndef WDA_MONITOR
#define WDA_MONITOR 0x00000001
#endif
#ifndef WDA_EXCLUDEFROMCAPTURE
#define WDA_EXCLUDEFROMCAPTURE 0x00000011
#endif

namespace
{
QString statusText(std::int32_t status)
{
    return QStringLiteral("0x%1").arg(static_cast<std::uint32_t>(status), 8, 16, QChar('0'));
}

void prepareTable(QTableView* table)
{
    QFont font(QStringLiteral("Cascadia Mono"));
    font.setStyleHint(QFont::Monospace);
    font.setPointSize(10);
    table->setFont(font);
    table->setShowGrid(false);
    table->setAlternatingRowColors(true);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setSelectionMode(QAbstractItemView::SingleSelection);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->verticalHeader()->hide();
    table->horizontalHeader()->setStretchLastSection(true);
    table->setWordWrap(false);
}

struct ListedWindow
{
    std::uintptr_t hwnd = 0;
    std::uint32_t pid = 0;
    unsigned long affinity = 0;
    bool affinityKnown = false;
    QString title;
    QString className;
    QString image;
};

struct EnumContext
{
    std::vector<ListedWindow>* rows = nullptr;
    std::unordered_map<std::uint32_t, QString>* images = nullptr;
};

BOOL CALLBACK collectWindow(HWND window, LPARAM parameter)
{
    auto* context = reinterpret_cast<EnumContext*>(parameter);
    DWORD pid = 0;
    wchar_t title[256] = {};
    wchar_t className[128] = {};
    ListedWindow item;

    if (IsWindowVisible(window) == FALSE)
    {
        return TRUE;
    }

    GetWindowThreadProcessId(window, &pid);
    GetWindowTextW(window, title, 256);
    GetClassNameW(window, className, 128);
    item.hwnd = reinterpret_cast<std::uintptr_t>(window);
    item.pid = pid;
    item.title = QString::fromWCharArray(title);
    item.className = QString::fromWCharArray(className);
    item.affinityKnown = queryWindowAffinity(window, &item.affinity);
    const auto image = context->images->find(pid);
    if (image != context->images->end())
    {
        item.image = image->second;
    }

    context->rows->push_back(item);
    return TRUE;
}

std::unordered_map<std::uint32_t, QString> imageNames()
{
    std::unordered_map<std::uint32_t, QString> names;
    const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W entry = {};

    if (snapshot == INVALID_HANDLE_VALUE)
    {
        return names;
    }

    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry) != FALSE)
    {
        do
        {
            names.emplace(entry.th32ProcessID, QString::fromWCharArray(entry.szExeFile));
        } while (Process32NextW(snapshot, &entry) != FALSE);
    }

    CloseHandle(snapshot);
    return names;
}

std::vector<ListedWindow> listWindows()
{
    std::unordered_map<std::uint32_t, QString> images = imageNames();
    std::vector<ListedWindow> rows;
    EnumContext context{&rows, &images};

    EnumWindows(collectWindow, reinterpret_cast<LPARAM>(&context));
    return rows;
}

int protectPidWindows(std::uint32_t pid)
{
    int changed = 0;
    const std::vector<ListedWindow> rows = listWindows();

    for (const ListedWindow& item : rows)
    {
        if (item.pid == pid && setWindowAntiCapture(reinterpret_cast<HWND>(item.hwnd), true))
        {
            changed++;
        }
    }

    return changed;
}
}

QString WindowProtectView::affinityText(unsigned long affinity)
{
    if (affinity == WDA_NONE)
    {
        return QStringLiteral("无");
    }
    if (affinity == WDA_MONITOR)
    {
        return QStringLiteral("WDA_MONITOR");
    }
    if (affinity == WDA_EXCLUDEFROMCAPTURE)
    {
        return QStringLiteral("排除截图");
    }

    return QStringLiteral("0x%1").arg(affinity, 0, 16);
}

WindowProtectView::WindowProtectView(QWidget* parent)
    : QWidget(parent)
{
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    auto* bar = new QHBoxLayout();
    bar->addWidget(new QLabel(QStringLiteral("过滤"), this));
    m_filter = new QLineEdit(this);
    m_filter->setPlaceholderText(QStringLiteral("HWND、PID、标题、类名或映像"));
    m_filter->setClearButtonEnabled(true);
    bar->addWidget(m_filter, 1);
    m_protectedOnly = new QCheckBox(QStringLiteral("只看已保护"), this);
    bar->addWidget(m_protectedOnly);
    auto* refreshButton = new QPushButton(QStringLiteral("刷新"), this);
    auto* protect = new QPushButton(QStringLiteral("保护选中"), this);
    auto* clear = new QPushButton(QStringLiteral("取消保护"), this);
    auto* self = new QPushButton(QStringLiteral("保护本进程"), this);
    m_hookButton = new QPushButton(QStringLiteral("安装自卫钩子"), this);
    auto* calibrate = new QPushButton(QStringLiteral("重新校准"), this);
    bar->addWidget(refreshButton);
    bar->addWidget(protect);
    bar->addWidget(clear);
    bar->addWidget(self);
    bar->addWidget(m_hookButton);
    bar->addWidget(calibrate);
    layout->addLayout(bar);

    m_table = new QTableView(this);
    prepareTable(m_table);
    m_model = new QStandardItemModel(this);
    m_model->setHorizontalHeaderLabels({QStringLiteral("HWND"), QStringLiteral("标题"), QStringLiteral("类名"),
                                        QStringLiteral("PID"), QStringLiteral("映像"), QStringLiteral("亲和性"),
                                        QStringLiteral("DWM")});
    m_table->setModel(m_model);
    m_table->setContextMenuPolicy(Qt::CustomContextMenu);
    layout->addWidget(m_table, 1);
    m_status = new QLabel(QStringLiteral("尚未刷新"), this);
    m_status->setWordWrap(true);
    layout->addWidget(m_status);

    connect(refreshButton, &QPushButton::clicked, this, &WindowProtectView::refresh);
    connect(m_filter, &QLineEdit::textChanged, this, &WindowProtectView::showRows);
    connect(m_protectedOnly, &QCheckBox::toggled, this, &WindowProtectView::showRows);
    connect(protect, &QPushButton::clicked, this, [this] { applySelected(true); });
    connect(clear, &QPushButton::clicked, this, [this] { applySelected(false); });
    connect(self, &QPushButton::clicked, this, [this] { protectProcess(GetCurrentProcessId()); });
    connect(m_hookButton, &QPushButton::clicked, this, &WindowProtectView::toggleHook);
    connect(calibrate, &QPushButton::clicked, this, [this] {
        m_recalibrate = true;
        refresh();
    });
    connect(m_table, &QWidget::customContextMenuRequested, this, [this](const QPoint& point) {
        const QModelIndex index = m_table->indexAt(point);
        if (index.isValid() == false)
        {
            return;
        }

        QMenu menu(this);
        QAction* protectRow = menu.addAction(QStringLiteral("保护"));
        QAction* clearRow = menu.addAction(QStringLiteral("取消保护"));
        QAction* chosen = menu.exec(m_table->viewport()->mapToGlobal(point));
        if (chosen == protectRow)
        {
            applySelected(true);
        }
        else if (chosen == clearRow)
        {
            applySelected(false);
        }
    });
}

void WindowProtectView::setStatus(const QString& text)
{
    m_status->setText(text);
}

bool WindowProtectView::matches(const WindowItem& item) const
{
    if (m_protectedOnly->isChecked() && item.affinity == WDA_NONE && item.dwmProtected == false)
    {
        return false;
    }

    const QString filter = m_filter->text().trimmed();
    if (filter.isEmpty())
    {
        return true;
    }

    if (item.title.contains(filter, Qt::CaseInsensitive) || item.className.contains(filter, Qt::CaseInsensitive) ||
        item.image.contains(filter, Qt::CaseInsensitive))
    {
        return true;
    }

    bool hex = false;
    QString text = filter;
    if (text.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
    {
        text = text.mid(2);
        hex = true;
    }

    bool ok = false;
    const std::uint64_t parsed = text.toULongLong(&ok, hex ? 16 : 10);
    return ok && (parsed == item.pid || parsed == item.hwnd);
}

void WindowProtectView::showRows()
{
    m_visible.clear();
    m_model->removeRows(0, m_model->rowCount());
    for (const WindowItem& item : m_rows)
    {
        if (matches(item) == false)
        {
            continue;
        }

        m_visible.push_back(item);
        const QString hwnd = QStringLiteral("0x%1").arg(static_cast<std::uint64_t>(item.hwnd), 0, 16);
        auto* hwndItem = new QStandardItem(hwnd);
        hwndItem->setData(static_cast<qulonglong>(item.hwnd), Qt::UserRole);
        m_model->appendRow({hwndItem, new QStandardItem(item.title), new QStandardItem(item.className),
                            new QStandardItem(QString::number(item.pid)), new QStandardItem(item.image),
                            new QStandardItem(item.affinityKnown ? affinityText(item.affinity) : QStringLiteral("—")),
                            new QStandardItem(item.dwmProtected ? QStringLiteral("已保护") : QStringLiteral("未保护"))});
    }
}

void WindowProtectView::reloadRows()
{
    m_rows.clear();
    for (const ListedWindow& listed : listWindows())
    {
        WindowItem item;
        item.hwnd = listed.hwnd;
        item.pid = listed.pid;
        item.affinity = listed.affinity;
        item.affinityKnown = listed.affinityKnown;
        item.title = listed.title;
        item.className = listed.className;
        item.image = listed.image;
        m_rows.push_back(item);
    }
}

void WindowProtectView::refresh()
{
    HACDBG_WINDOW_REQUEST request = {};
    QString scanNote;
    std::unordered_map<std::uint32_t, bool> protectedWindows;
    HWND sample = nullptr;
    unsigned long sampleAffinity = WDA_NONE;
    bool restoreSample = false;

    reloadRows();
    request.Operation = HACDBG_WINDOW_QUERY;
    m_driverPresent = windowDriverExecute(&request);
    if (m_driverPresent)
    {
        m_hookArmed = request.HookArmed != 0;
        m_ownerPid = request.OwnerPid;
        request = {};
        request.Operation = HACDBG_WINDOW_SCAN;
        request.DwmPid = dwmProcessId();
        request.Flags = m_recalibrate ? HACDBG_WINDOW_FLAG_RECALIBRATE : 0;
        m_recalibrate = false;
        for (const WindowItem& item : m_rows)
        {
            if (item.affinity == WDA_EXCLUDEFROMCAPTURE)
            {
                request.CalibrateHwnd = static_cast<unsigned int>(item.hwnd);
                request.CalibratePid = item.pid;
                break;
            }
        }

        if (request.CalibrateHwnd == 0)
        {
            QWidget* top = window();
            while (top != nullptr && top->parentWidget() != nullptr)
            {
                top = top->parentWidget();
            }

            if (top != nullptr)
            {
                sample = reinterpret_cast<HWND>(top->winId());
                queryWindowAffinity(sample, &sampleAffinity);
                if (sampleAffinity != WDA_EXCLUDEFROMCAPTURE && setWindowAntiCapture(sample, true))
                {
                    restoreSample = true;
                }
                request.CalibrateHwnd = static_cast<unsigned int>(reinterpret_cast<std::uintptr_t>(sample));
                request.CalibratePid = GetCurrentProcessId();
            }
        }

        Sleep(50);
        if (windowDriverExecute(&request) == false)
        {
            scanNote = QStringLiteral("DWM 扫描失败：%1").arg(statusText(request.Status));
        }
        else
        {
            for (unsigned int index = 0; index < request.RowCount && index < HACDBG_WINDOW_MAX_ROWS; ++index)
            {
                protectedWindows.emplace(request.Rows[index].Hwnd, true);
            }

            scanNote = QStringLiteral("DWM 已保护 %1").arg(request.RowCount);
            if (request.Truncated != 0)
            {
                scanNote += QStringLiteral("，扫描被截断");
            }
            if (request.Vtable != 0)
            {
                scanNote += QStringLiteral("，布局 flags+0x%1").arg(request.FlagsOffset, 0, 16);
            }
        }

        m_hookArmed = request.HookArmed != 0;
        m_ownerPid = request.OwnerPid;
    }
    else
    {
        scanNote = QStringLiteral("驱动未连接，只显示 SetWindowDisplayAffinity");
        m_hookArmed = false;
    }

    if (restoreSample && sample != nullptr)
    {
        setWindowAntiCapture(sample, false);
    }

    for (WindowItem& item : m_rows)
    {
        item.dwmProtected = protectedWindows.find(static_cast<std::uint32_t>(item.hwnd)) != protectedWindows.end();
        if (item.dwmProtected == false)
        {
            item.dwmProtected = protectedWindows.find(static_cast<std::uint32_t>(item.hwnd & 0xffffffffu)) !=
                                protectedWindows.end();
        }
    }

    m_hookButton->setText(m_hookArmed ? QStringLiteral("卸下自卫钩子") : QStringLiteral("安装自卫钩子"));
    QString hookNote = m_hookArmed ? QStringLiteral("自卫钩子已安装，其他进程不能调用 SetWindowDisplayAffinity")
                                   : QStringLiteral("自卫钩子未安装");
    if (m_hookArmed && m_ownerPid != 0)
    {
        hookNote += QStringLiteral("，允许进程 %1").arg(m_ownerPid);
    }

    setStatus(QStringLiteral("窗口 %1，%2。%3").arg(m_rows.size()).arg(scanNote, hookNote));
    showRows();
}

void WindowProtectView::applySelected(bool enable)
{
    const QModelIndex current = m_table->currentIndex();
    if (current.isValid() == false || current.row() < 0 || current.row() >= static_cast<int>(m_visible.size()))
    {
        QMessageBox::warning(this, QStringLiteral("窗口保护"), QStringLiteral("先选中一个窗口。"));
        return;
    }

    const WindowItem item = m_visible[static_cast<std::size_t>(current.row())];
    if (setWindowAntiCapture(reinterpret_cast<HWND>(item.hwnd), enable) == false)
    {
        const DWORD error = GetLastError();
        QMessageBox::warning(this, QStringLiteral("窗口保护"),
                             QStringLiteral("%1 0x%2")
                                 .arg(enable ? QStringLiteral("排除截图失败。") : QStringLiteral("取消保护失败。"))
                                 .arg(error, 8, 16, QChar('0')));
        return;
    }

    if (enable)
    {
        HACDBG_WINDOW_REQUEST request = {};
        std::int32_t status = 0;
        request.Operation = HACDBG_WINDOW_ARM;
        if (windowDriverExecute(&request) == false)
        {
            status = request.Status;
            QMessageBox::warning(this, QStringLiteral("窗口保护"),
                                 QStringLiteral("窗口已排除截图，自卫钩子没有安装：%1").arg(statusText(status)));
        }
    }

    refresh();
}

void WindowProtectView::toggleHook()
{
    HACDBG_WINDOW_REQUEST request = {};
    request.Operation = m_hookArmed ? HACDBG_WINDOW_DISARM : HACDBG_WINDOW_ARM;
    if (windowDriverExecute(&request) == false)
    {
        QMessageBox::warning(this, QStringLiteral("窗口保护"),
                             QStringLiteral("自卫钩子操作失败：%1").arg(statusText(request.Status)));
        return;
    }

    refresh();
}

void WindowProtectView::protectProcess(std::uint32_t pid)
{
    const int changed = protectPidWindows(pid);
    HACDBG_WINDOW_REQUEST request = {};
    request.Operation = HACDBG_WINDOW_ARM;
    if (windowDriverExecute(&request) == false)
    {
        QMessageBox::warning(this, QStringLiteral("窗口保护"),
                             QStringLiteral("自卫钩子没有安装：%1").arg(statusText(request.Status)));
    }

    m_filter->setText(QString::number(pid));
    refresh();
    if (changed == 0)
    {
        setStatus(m_status->text() + QStringLiteral(" 没有可排除截图的可见顶层窗口。"));
    }
}
