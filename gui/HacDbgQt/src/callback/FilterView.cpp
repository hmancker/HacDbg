#include "FilterView.h"

#include "FilterDriver.h"

#include <Windows.h>

#include <functional>

#include <QClipboard>
#include <QComboBox>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QGuiApplication>
#include <QDialog>
#include <QDialogButtonBox>
#include <QProcess>
#include <QHash>
#include <QPair>
#include <QHeaderView>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QPushButton>
#include <QShortcut>
#include <QStandardItemModel>
#include <QTreeView>
#include <QTextStream>
#include <QVBoxLayout>

#include <shellapi.h>
#include <shlobj.h>

namespace
{
QString dosPath(const wchar_t* kernelPath)
{
    const QString path = QString::fromWCharArray(kernelPath);
    if (path.startsWith(QStringLiteral("\\SystemRoot"), Qt::CaseInsensitive))
    {
        wchar_t windows[MAX_PATH] = {};
        const UINT chars = GetWindowsDirectoryW(windows, MAX_PATH);
        if (chars == 0 || chars >= MAX_PATH)
        {
            return path;
        }

        return QString::fromWCharArray(windows) + path.mid(static_cast<qsizetype>(QStringLiteral("\\SystemRoot").size()));
    }

    if (path.startsWith(QStringLiteral("\\??\\")))
    {
        return path.mid(4);
    }

    return path;
}

QString versionString(const void* block, const QString& key)
{
    void* value = nullptr;
    UINT bytes = 0;
    if (VerQueryValueW(block, reinterpret_cast<const wchar_t*>(key.utf16()), &value, &bytes) == FALSE || value == nullptr ||
        bytes < sizeof(wchar_t))
    {
        return {};
    }

    return QString::fromWCharArray(static_cast<const wchar_t*>(value));
}

void fileDetails(const QString& path, QString* company, QString* description)
{
    const DWORD bytes = GetFileVersionInfoSizeW(reinterpret_cast<const wchar_t*>(path.utf16()), nullptr);
    if (bytes == 0)
    {
        return;
    }

    std::vector<unsigned char> data(bytes);
    if (GetFileVersionInfoW(reinterpret_cast<const wchar_t*>(path.utf16()), 0, bytes, data.data()) == FALSE)
    {
        return;
    }

    struct Translation
    {
        WORD language;
        WORD codePage;
    }* translation = nullptr;
    UINT translationBytes = 0;
    if (VerQueryValueW(data.data(), L"\\VarFileInfo\\Translation", reinterpret_cast<void**>(&translation),
                       &translationBytes) == FALSE ||
        translation == nullptr || translationBytes < sizeof(Translation))
    {
        return;
    }

    const QString root = QStringLiteral("\\StringFileInfo\\%1%2\\")
                             .arg(translation->language, 4, 16, QChar('0'))
                             .arg(translation->codePage, 4, 16, QChar('0'));
    *company = versionString(data.data(), root + QStringLiteral("CompanyName"));
    *description = versionString(data.data(), root + QStringLiteral("FileDescription"));
}

QString hexText(unsigned long long value)
{
    if (value == 0)
    {
        return {};
    }

    return QStringLiteral("0x%1").arg(value, 16, 16, QChar('0')).toUpper().replace(QStringLiteral("0X"),
                                                                                    QStringLiteral("0x"));
}

QString defenderScanner()
{
    const QStringList roots = {qEnvironmentVariable("ProgramFiles"), qEnvironmentVariable("ProgramW6432")};
    for (const QString& root : roots)
    {
        if (root.isEmpty())
        {
            continue;
        }

        const QString path = root + QStringLiteral("\\Windows Defender\\MpCmdRun.exe");
        if (QFileInfo::exists(path))
        {
            return path;
        }
    }

    return {};
}

const char* dispatchName(unsigned int index)
{
    static const char* names[] = {
        "IRP_MJ_CREATE",
        "IRP_MJ_CREATE_NAMED_PIPE",
        "IRP_MJ_CLOSE",
        "IRP_MJ_READ",
        "IRP_MJ_WRITE",
        "IRP_MJ_QUERY_INFORMATION",
        "IRP_MJ_SET_INFORMATION",
        "IRP_MJ_QUERY_EA",
        "IRP_MJ_SET_EA",
        "IRP_MJ_FLUSH_BUFFERS",
        "IRP_MJ_QUERY_VOLUME_INFORMATION",
        "IRP_MJ_SET_VOLUME_INFORMATION",
        "IRP_MJ_DIRECTORY_CONTROL",
        "IRP_MJ_FILE_SYSTEM_CONTROL",
        "IRP_MJ_DEVICE_CONTROL",
        "IRP_MJ_INTERNAL_DEVICE_CONTROL",
        "IRP_MJ_SHUTDOWN",
        "IRP_MJ_LOCK_CONTROL",
        "IRP_MJ_CLEANUP",
        "IRP_MJ_CREATE_MAILSLOT",
        "IRP_MJ_QUERY_SECURITY",
        "IRP_MJ_SET_SECURITY",
        "IRP_MJ_POWER",
        "IRP_MJ_SYSTEM_CONTROL",
        "IRP_MJ_DEVICE_CHANGE",
        "IRP_MJ_QUERY_QUOTA",
        "IRP_MJ_SET_QUOTA",
        "IRP_MJ_PNP",
    };

    if (index >= sizeof(names) / sizeof(names[0]))
    {
        return "";
    }

    return names[index];
}

bool selectFile(const QString& path)
{
    PIDLIST_ABSOLUTE item = nullptr;
    const HRESULT parsed = SHParseDisplayName(reinterpret_cast<const wchar_t*>(path.utf16()), nullptr, &item, 0, nullptr);
    if (FAILED(parsed) || item == nullptr)
    {
        return false;
    }

    const HRESULT opened = SHOpenFolderAndSelectItems(item, 0, nullptr, 0);
    ILFree(item);
    return SUCCEEDED(opened);
}
}

FilterView::FilterView(QWidget* parent)
    : QWidget(parent)
{
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    auto* bar = new QHBoxLayout();
    bar->addWidget(new QLabel(QStringLiteral("类型"), this));
    m_type = new QComboBox(this);
    m_type->addItem(QStringLiteral("全部"));
    const struct
    {
        const char* label;
        unsigned int typeId;
    } types[] = {
        {"FILE", HACDBG_FILTER_FILE},       {"DISK", HACDBG_FILTER_DISK},   {"RAW", HACDBG_FILTER_RAW},
        {"VOLUME", HACDBG_FILTER_VOLUME},   {"KEYBOARD", HACDBG_FILTER_KEYBOARD},
        {"MOUSE", HACDBG_FILTER_MOUSE},     {"I8042PRT", HACDBG_FILTER_I8042},
        {"TCPIP", HACDBG_FILTER_TCPIP},     {"TDI", HACDBG_FILTER_TDI},
        {"NDIS", HACDBG_FILTER_NDIS},       {"PNP_MANAGER", HACDBG_FILTER_PNP},
    };
    for (const auto& type : types)
    {
        const int index = m_type->count();
        m_type->addItem(QString::fromLatin1(type.label));
        m_type->setItemData(index, type.typeId);
    }

    bar->addWidget(m_type);
    bar->addWidget(new QLabel(QStringLiteral("过滤"), this));
    m_filter = new QLineEdit(this);
    m_filter->setPlaceholderText(QStringLiteral("对象名、设备名、路径、公司或描述"));
    m_filter->setClearButtonEnabled(true);
    bar->addWidget(m_filter, 1);
    auto* refreshButton = new QPushButton(QStringLiteral("刷新"), this);
    bar->addWidget(refreshButton);
    layout->addLayout(bar);

    m_table = new QTreeView(this);
    m_model = new QStandardItemModel(this);
    m_model->setHorizontalHeaderLabels({QStringLiteral("对象名"), QStringLiteral("类型"), QStringLiteral("驱动路径"),
                                        QStringLiteral("驱动对象"), QStringLiteral("设备名"), QStringLiteral("设备对象"),
                                        QStringLiteral("HostDriverName"), QStringLiteral("HostDriverObject"),
                                        QStringLiteral("HostDeviceObject"), QStringLiteral("公司"), QStringLiteral("描述")});
    m_table->setModel(m_model);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setUniformRowHeights(true);
    m_table->setExpandsOnDoubleClick(true);
    m_table->header()->setStretchLastSection(true);
    m_table->header()->setSectionResizeMode(2, QHeaderView::Stretch);
    m_table->setContextMenuPolicy(Qt::CustomContextMenu);
    layout->addWidget(m_table, 1);

    m_status = new QLabel(QStringLiteral("尚未刷新"), this);
    m_status->setWordWrap(true);
    layout->addWidget(m_status);

    connect(refreshButton, &QPushButton::clicked, this, &FilterView::refresh);
    connect(m_type, &QComboBox::currentIndexChanged, this, [this](int) { showRows(); });
    connect(m_filter, &QLineEdit::textChanged, this, &FilterView::showRows);
    connect(m_table, &QWidget::customContextMenuRequested, this, &FilterView::showMenu);
    auto* refreshKey = new QShortcut(QKeySequence(Qt::Key_F5), this);
    connect(refreshKey, &QShortcut::activated, this, &FilterView::refresh);
}

bool FilterView::systemModule(const Row& row) const
{
    if (row.company.contains(QStringLiteral("Microsoft"), Qt::CaseInsensitive))
    {
        return true;
    }

    return row.path.contains(QStringLiteral("\\Windows\\"), Qt::CaseInsensitive);
}

bool FilterView::matches(std::size_t index) const
{
    const Row& row = m_rows[index];
    if (m_type->currentIndex() > 0 && row.typeId != m_type->currentData().toUInt())
    {
        return false;
    }

    bool nonSystemChild = false;
    if (m_hideSystem && systemModule(row))
    {
        for (std::size_t other = 0; other < m_rows.size(); ++other)
        {
            unsigned int parent = m_rows[other].parent;
            unsigned int guard = 0;
            while (parent != HACDBG_FILTER_NO_PARENT && parent < m_rows.size() && guard < 8)
            {
                if (parent == index && systemModule(m_rows[other]) == false)
                {
                    nonSystemChild = true;
                    break;
                }

                parent = m_rows[parent].parent;
                guard += 1;
            }

            if (nonSystemChild)
            {
                break;
            }
        }

        if (nonSystemChild == false)
        {
            return false;
        }
    }

    const QString filter = m_filter->text().trimmed();
    if (filter.isEmpty())
    {
        return true;
    }

    return row.driverName.contains(filter, Qt::CaseInsensitive) || row.type.contains(filter, Qt::CaseInsensitive) ||
           row.path.contains(filter, Qt::CaseInsensitive) || row.driverObject.contains(filter, Qt::CaseInsensitive) ||
           row.deviceName.contains(filter, Qt::CaseInsensitive) || row.deviceObject.contains(filter, Qt::CaseInsensitive) ||
           row.hostDriverName.contains(filter, Qt::CaseInsensitive) ||
           row.hostDriverObject.contains(filter, Qt::CaseInsensitive) ||
           row.hostDeviceObject.contains(filter, Qt::CaseInsensitive) ||
           row.company.contains(filter, Qt::CaseInsensitive) || row.description.contains(filter, Qt::CaseInsensitive);
}

void FilterView::refresh()
{
    auto* request = new HACDBG_FILTER_REQUEST();
    const bool ok = filterDriverQuery(request);
    m_rows.clear();
    m_scanned = false;
    m_truncated = false;
    if (ok)
    {
        QHash<QString, QPair<QString, QString>> details;
        for (unsigned int index = 0; index < request->Count && index < HACDBG_FILTER_MAX_ROWS; ++index)
        {
            const HACDBG_FILTER_ROW& source = request->Rows[index];
            Row row;
            row.typeId = source.Type;
            row.depth = source.Depth;
            row.parent = source.Parent;
            row.driverObjectValue = source.DriverObject;
            row.deviceObjectValue = source.DeviceObject;
            row.hostDeviceObjectValue = source.HostDeviceObject;
            row.driverName = QString::fromWCharArray(source.DriverName);
            row.type = QString::fromLatin1(HacDbgFilterTypeName(source.Type));
            row.path = dosPath(source.DriverPath);
            row.driverObject = hexText(source.DriverObject);
            row.deviceName = QString::fromWCharArray(source.DeviceName);
            row.deviceObject = hexText(source.DeviceObject);
            row.hostDriverName = QString::fromWCharArray(source.HostDriverName);
            row.hostDriverObject = hexText(source.HostDriverObject);
            row.hostDeviceObject = hexText(source.HostDeviceObject);
            if (details.contains(row.path))
            {
                row.company = details.value(row.path).first;
                row.description = details.value(row.path).second;
            }
            else
            {
                fileDetails(row.path, &row.company, &row.description);
                details.insert(row.path, {row.company, row.description});
            }

            m_rows.push_back(row);
        }

        m_scanned = true;
        m_truncated = request->Truncated != 0;
    }
    else
    {
        m_status->setText(QStringLiteral("驱动未连接：0x%1").arg(static_cast<unsigned int>(request->Status), 8, 16, QChar('0')));
    }

    delete request;
    showRows();
}

void FilterView::showRows()
{
    m_model->removeRows(0, m_model->rowCount());
    std::vector<QStandardItem*> nodes(m_rows.size(), nullptr);
    std::vector<unsigned char> direct(m_rows.size(), 0);
    std::vector<unsigned char> visible(m_rows.size(), 0);
    for (std::size_t index = 0; index < m_rows.size(); ++index)
    {
        direct[index] = matches(index) ? 1 : 0;
    }

    for (std::size_t index = 0; index < m_rows.size(); ++index)
    {
        if (direct[index] == 0)
        {
            continue;
        }

        visible[index] = 1;
        unsigned int parent = m_rows[index].parent;
        unsigned int guard = 0;
        while (parent != HACDBG_FILTER_NO_PARENT && parent < m_rows.size() && guard < 8)
        {
            visible[parent] = 1;
            parent = m_rows[parent].parent;
            guard += 1;
        }

        for (std::size_t child = 0; child < m_rows.size(); ++child)
        {
            unsigned int cursor = m_rows[child].parent;
            unsigned int depth = 0;
            while (cursor != HACDBG_FILTER_NO_PARENT && cursor < m_rows.size() && depth < 8)
            {
                if (cursor == index)
                {
                    visible[child] = 1;
                    break;
                }

                cursor = m_rows[cursor].parent;
                depth += 1;
            }
        }
    }

    int shown = 0;
    for (std::size_t index = 0; index < m_rows.size(); ++index)
    {
        if (visible[index] == 0)
        {
            continue;
        }

        const Row& row = m_rows[index];
        QList<QStandardItem*> cells;
        const QStringList text = {row.driverName,    row.type,         row.path,
                                  row.driverObject,  row.deviceName,   row.deviceObject,
                                  row.hostDriverName, row.hostDriverObject, row.hostDeviceObject,
                                  row.company,       row.description};
        for (const QString& cell : text)
        {
            cells.push_back(new QStandardItem(cell));
        }

        cells.first()->setData(static_cast<qulonglong>(index), Qt::UserRole);
        const unsigned int parent = row.parent;
        if (parent == HACDBG_FILTER_NO_PARENT || parent >= nodes.size() || nodes[parent] == nullptr)
        {
            m_model->appendRow(cells);
        }
        else
        {
            nodes[parent]->appendRow(cells);
        }

        nodes[index] = cells.first();
        shown += 1;
    }

    m_table->expandAll();
    if (m_scanned == false)
    {
        return;
    }

    QString text = QStringLiteral("过滤驱动 %1").arg(m_rows.size());
    if (m_truncated)
    {
        text += QStringLiteral("，列表被截断");
    }

    const bool narrowed = m_hideSystem || m_type->currentIndex() > 0 || m_filter->text().trimmed().isEmpty() == false;
    if (narrowed)
    {
        text += QStringLiteral("，显示 %1").arg(shown);
    }

    m_status->setText(text);
}

int FilterView::rowIndex(const QModelIndex& index) const
{
    if (index.isValid() == false)
    {
        return -1;
    }

    const QModelIndex first = index.sibling(index.row(), 0);
    const QVariant value = first.data(Qt::UserRole);
    if (value.isValid() == false)
    {
        return -1;
    }

    const qulonglong row = value.toULongLong();
    if (row >= m_rows.size())
    {
        return -1;
    }

    return static_cast<int>(row);
}

void FilterView::detachRow(const Row& row)
{
    quint64 host = row.hostDeviceObjectValue;
    if (host == 0)
    {
        for (const Row& other : m_rows)
        {
            if (other.deviceObjectValue == row.deviceObjectValue && other.hostDeviceObjectValue != 0)
            {
                host = other.hostDeviceObjectValue;
                break;
            }
        }
    }

    if (host == 0)
    {
        QMessageBox::information(this, QStringLiteral("删除过滤器"), QStringLiteral("这一行不是挂在别的设备上的过滤器。"));
        return;
    }

    if (QMessageBox::question(this, QStringLiteral("删除过滤器"),
                              QStringLiteral("从下层设备上摘掉 %1？").arg(row.driverName)) != QMessageBox::Yes)
    {
        return;
    }

    auto* request = new HACDBG_FILTER_REQUEST();
    int status = 0;
    const bool ok = filterDriverOperate(HACDBG_FILTER_OP_DETACH, row.driverObjectValue, row.deviceObjectValue, host, request,
                                        &status);
    delete request;
    if (ok == false)
    {
        m_status->setText(QStringLiteral("删除过滤器失败：0x%1").arg(static_cast<unsigned int>(status), 8, 16, QChar('0')));
        return;
    }

    refresh();
}

void FilterView::showDevices(const Row& row)
{
    auto* request = new HACDBG_FILTER_REQUEST();
    int status = 0;
    const bool ok =
        filterDriverOperate(HACDBG_FILTER_OP_DEVICES, row.driverObjectValue, 0, 0, request, &status);
    if (ok == false)
    {
        m_status->setText(QStringLiteral("查看设备列表失败：0x%1").arg(static_cast<unsigned int>(status), 8, 16, QChar('0')));
        delete request;
        return;
    }

    auto* dialog = new QDialog(this);
    dialog->setWindowTitle(QStringLiteral("设备列表 %1").arg(row.driverName));
    dialog->resize(760, 420);
    auto* layout = new QVBoxLayout(dialog);
    auto* model = new QStandardItemModel(dialog);
    model->setHorizontalHeaderLabels({QStringLiteral("设备名"), QStringLiteral("设备对象"), QStringLiteral("驱动路径")});
    for (unsigned int index = 0; index < request->Count && index < HACDBG_FILTER_MAX_ROWS; ++index)
    {
        const HACDBG_FILTER_ROW& source = request->Rows[index];
        model->appendRow({new QStandardItem(QString::fromWCharArray(source.DeviceName)),
                          new QStandardItem(hexText(source.DeviceObject)),
                          new QStandardItem(dosPath(source.DriverPath))});
    }

    delete request;
    auto* view = new QTreeView(dialog);
    view->setModel(model);
    view->setEditTriggers(QAbstractItemView::NoEditTriggers);
    view->setRootIsDecorated(false);
    view->header()->setStretchLastSection(true);
    layout->addWidget(view);
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close, dialog);
    connect(buttons, &QDialogButtonBox::rejected, dialog, &QDialog::close);
    layout->addWidget(buttons);
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->show();
}

void FilterView::showDispatch(const Row& row)
{
    auto* request = new HACDBG_FILTER_REQUEST();
    int status = 0;
    const bool ok =
        filterDriverOperate(HACDBG_FILTER_OP_DISPATCH, row.driverObjectValue, 0, 0, request, &status);
    if (ok == false)
    {
        m_status->setText(QStringLiteral("查看IO派遣函数失败：0x%1").arg(static_cast<unsigned int>(status), 8, 16, QChar('0')));
        delete request;
        return;
    }

    auto* dialog = new QDialog(this);
    dialog->setWindowTitle(QStringLiteral("IO派遣函数 %1").arg(row.driverName));
    dialog->resize(860, 520);
    auto* layout = new QVBoxLayout(dialog);
    auto* model = new QStandardItemModel(dialog);
    model->setHorizontalHeaderLabels({QStringLiteral("派遣函数"), QStringLiteral("地址"), QStringLiteral("路径")});
    for (unsigned int index = 0; index < request->Count && index < HACDBG_FILTER_MAX_ROWS; ++index)
    {
        const HACDBG_FILTER_ROW& source = request->Rows[index];
        auto* address = new QStandardItem(hexText(source.DeviceObject));
        address->setData(static_cast<qulonglong>(source.DeviceObject), Qt::UserRole);
        model->appendRow({new QStandardItem(QString::fromLatin1(dispatchName(source.Depth))), address,
                          new QStandardItem(dosPath(source.DriverPath))});
    }

    delete request;
    auto* view = new QTreeView(dialog);
    view->setModel(model);
    view->setEditTriggers(QAbstractItemView::NoEditTriggers);
    view->setRootIsDecorated(false);
    view->header()->setStretchLastSection(true);
    layout->addWidget(view);
    connect(view, &QTreeView::doubleClicked, this, [this](const QModelIndex& index) {
        const QModelIndex address = index.sibling(index.row(), 1);
        emit addressActivated(address.data(Qt::UserRole).toULongLong(), 0);
    });
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close, dialog);
    connect(buttons, &QDialogButtonBox::rejected, dialog, &QDialog::close);
    layout->addWidget(buttons);
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->show();
}

void FilterView::showMenu(const QPoint& point)
{
    const QModelIndex index = m_table->indexAt(point);
    if (index.isValid())
    {
        m_table->setCurrentIndex(index);
        m_table->selectionModel()->select(index, QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
    }

    const int rowNumber = rowIndex(index);
    const Row* row = rowNumber >= 0 ? &m_rows[static_cast<std::size_t>(rowNumber)] : nullptr;
    const bool havePath = row != nullptr && row->path.isEmpty() == false;
    QMenu menu(this);
    QAction* refreshAction = menu.addAction(QStringLiteral("刷新"));
    refreshAction->setShortcut(QKeySequence(Qt::Key_F5));
    refreshAction->setShortcutVisibleInContextMenu(true);
    QAction* detachAction = menu.addAction(QStringLiteral("删除过滤器"));
    QAction* devicesAction = menu.addAction(QStringLiteral("查看设备列表"));
    QAction* dispatchAction = menu.addAction(QStringLiteral("查看IO派遣函数"));
    QAction* scanAction = menu.addAction(QStringLiteral("扫描文件"));
    QAction* folderAction = menu.addAction(QStringLiteral("定位到文件管理"));
    QAction* explorerAction = menu.addAction(QStringLiteral("定位到资源管理器"));
    QMenu* copyMenu = menu.addMenu(QStringLiteral("复制"));
    QAction* copyCell = copyMenu->addAction(QStringLiteral("复制单元格"));
    QAction* copyRow = copyMenu->addAction(QStringLiteral("复制选行"));
    QAction* copyAll = copyMenu->addAction(QStringLiteral("复制全部数据"));
    QMenu* exportMenu = menu.addMenu(QStringLiteral("导出数据"));
    QAction* exportText = exportMenu->addAction(QStringLiteral("导出 TXT..."));
    QAction* exportJson = exportMenu->addAction(QStringLiteral("导出 JSON..."));
    QAction* exportHtml = exportMenu->addAction(QStringLiteral("导出 HTML..."));
    QAction* propertyAction = menu.addAction(QStringLiteral("属性..."));
    propertyAction->setShortcut(QKeySequence(Qt::Key_R));
    propertyAction->setShortcutVisibleInContextMenu(true);
    detachAction->setEnabled(row != nullptr);
    devicesAction->setEnabled(row != nullptr && row->driverObjectValue != 0);
    dispatchAction->setEnabled(row != nullptr && row->driverObjectValue != 0);
    scanAction->setEnabled(havePath);
    copyCell->setEnabled(row != nullptr && index.isValid());
    copyRow->setEnabled(row != nullptr);
    folderAction->setEnabled(havePath);
    explorerAction->setEnabled(havePath);
    propertyAction->setEnabled(havePath);

    QAction* chosen = menu.exec(m_table->viewport()->mapToGlobal(point));
    if (chosen == nullptr)
    {
        return;
    }

    if (chosen == refreshAction)
    {
        refresh();
    }
    else if (chosen == copyCell)
    {
        QGuiApplication::clipboard()->setText(index.data().toString());
    }
    else if (chosen == copyRow)
    {
        QStringList cells;
        for (int column = 0; column < m_model->columnCount(); ++column)
        {
            cells.push_back(index.sibling(index.row(), column).data().toString());
        }

        QGuiApplication::clipboard()->setText(cells.join(QLatin1Char('\t')));
    }
    else if (chosen == copyAll || chosen == exportText || chosen == exportJson)
    {
        if (chosen == copyAll)
        {
            QStringList lines;
            QStringList headers;
            for (int column = 0; column < m_model->columnCount(); ++column)
            {
                headers.push_back(m_model->headerData(column, Qt::Horizontal).toString());
            }

            lines.push_back(headers.join(QLatin1Char('\t')));
            const std::function<void(const QModelIndex&)> walk = [&](const QModelIndex& parent)
            {
                for (int modelRow = 0; modelRow < m_model->rowCount(parent); ++modelRow)
                {
                    QStringList cells;
                    for (int column = 0; column < m_model->columnCount(); ++column)
                    {
                        cells.push_back(m_model->index(modelRow, column, parent).data().toString());
                    }

                    lines.push_back(cells.join(QLatin1Char('\t')));
                    walk(m_model->index(modelRow, 0, parent));
                }
            };
            walk({});
            QGuiApplication::clipboard()->setText(lines.join(QLatin1Char('\n')));
        }
        else
        {
            exportShown(chosen == exportJson ? 1 : chosen == exportHtml ? 2 : 0);
        }
    }
    else if (row == nullptr)
    {
        return;
    }
    else if (chosen == detachAction)
    {
        detachRow(*row);
    }
    else if (chosen == devicesAction)
    {
        showDevices(*row);
    }
    else if (chosen == dispatchAction)
    {
        showDispatch(*row);
    }
    else if (chosen == scanAction)
    {
        const QString scanner = defenderScanner();
        if (scanner.isEmpty() ||
            QProcess::startDetached(scanner, {QStringLiteral("-Scan"), QStringLiteral("-ScanType"), QStringLiteral("3"),
                                               QStringLiteral("-File"), row->path}) == false)
        {
            QMessageBox::warning(this, QStringLiteral("扫描文件"), QStringLiteral("没有找到 Microsoft Defender，或无法启动扫描。"));
            return;
        }

        m_status->setText(QStringLiteral("已交给 Microsoft Defender 扫描 %1").arg(QFileInfo(row->path).fileName()));
    }
    else if (chosen == folderAction)
    {
        const QString folder = QFileInfo(row->path).absolutePath();
        ShellExecuteW(nullptr, L"explore", reinterpret_cast<const wchar_t*>(folder.utf16()), nullptr, nullptr, SW_SHOWNORMAL);
    }
    else if (chosen == explorerAction)
    {
        if (selectFile(row->path) == false)
        {
            QMessageBox::warning(this, QStringLiteral("定位到资源管理器"),
                                 QStringLiteral("无法在资源管理器中选中：%1").arg(row->path));
        }
    }
    else if (chosen == propertyAction)
    {
        const HWND owner = reinterpret_cast<HWND>(window()->winId());
        if (SHObjectProperties(owner, SHOP_FILEPATH, reinterpret_cast<const wchar_t*>(row->path.utf16()), nullptr) == FALSE)
        {
            QMessageBox::warning(this, QStringLiteral("属性"), QStringLiteral("打不开这个文件的属性。"));
        }
    }
}

void FilterView::exportShown(int kind)
{
    const bool json = kind == 1;
    const bool html = kind == 2;
    const QString path = QFileDialog::getSaveFileName(
        this, html ? QStringLiteral("导出 HTML") : json ? QStringLiteral("导出 JSON") : QStringLiteral("导出 TXT"),
        html ? QStringLiteral("HacDbg-filters.html")
             : json ? QStringLiteral("HacDbg-filters.json") : QStringLiteral("HacDbg-filters.txt"),
        html ? QStringLiteral("HTML (*.html)") : json ? QStringLiteral("JSON (*.json)") : QStringLiteral("文本 (*.txt)"));
    if (path.isEmpty())
    {
        return;
    }

    QFile file(path);
    if (file.open(QIODevice::WriteOnly | QIODevice::Truncate) == false)
    {
        QMessageBox::warning(this, QStringLiteral("导出"), QStringLiteral("写不了这个文件。"));
        return;
    }

    QStringList headers;
    for (int column = 0; column < m_model->columnCount(); ++column)
    {
        headers.push_back(m_model->headerData(column, Qt::Horizontal).toString());
    }

    int count = 0;
    if (json)
    {
        QJsonArray rows;
        const std::function<void(const QModelIndex&)> walk = [&](const QModelIndex& parent)
        {
            for (int modelRow = 0; modelRow < m_model->rowCount(parent); ++modelRow)
            {
                QJsonObject item;
                for (int column = 0; column < headers.size(); ++column)
                {
                    item.insert(headers.at(column), m_model->index(modelRow, column, parent).data().toString());
                }

                rows.append(item);
                count += 1;
                walk(m_model->index(modelRow, 0, parent));
            }
        };
        walk({});
        file.write(QJsonDocument(rows).toJson(QJsonDocument::Indented));
    }
    else if (html)
    {
        QTextStream out(&file);
        out.setEncoding(QStringConverter::Utf8);
        out << "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>过滤驱动</title></head><body><table border=\"1\">\n<tr>";
        for (const QString& header : headers)
        {
            out << "<th>" << header.toHtmlEscaped() << "</th>";
        }

        out << "</tr>\n";
        const std::function<void(const QModelIndex&)> walk = [&](const QModelIndex& parent)
        {
            for (int modelRow = 0; modelRow < m_model->rowCount(parent); ++modelRow)
            {
                out << "<tr>";
                for (int column = 0; column < headers.size(); ++column)
                {
                    out << "<td>" << m_model->index(modelRow, column, parent).data().toString().toHtmlEscaped() << "</td>";
                }

                out << "</tr>\n";
                count += 1;
                walk(m_model->index(modelRow, 0, parent));
            }
        };
        walk({});
        out << "</table></body></html>\n";
    }
    else
    {
        file.write("\xEF\xBB\xBF");
        QTextStream out(&file);
        out.setEncoding(QStringConverter::Utf8);
        out << headers.join(QLatin1Char('\t')) << "\n";
        const std::function<void(const QModelIndex&)> walk = [&](const QModelIndex& parent)
        {
            for (int modelRow = 0; modelRow < m_model->rowCount(parent); ++modelRow)
            {
                QStringList cells;
                for (int column = 0; column < headers.size(); ++column)
                {
                    QString cell = m_model->index(modelRow, column, parent).data().toString();
                    cell.replace(QLatin1Char('\t'), QLatin1Char(' '));
                    cells.push_back(cell);
                }

                out << cells.join(QLatin1Char('\t')) << "\n";
                count += 1;
                walk(m_model->index(modelRow, 0, parent));
            }
        };
        walk({});
    }

    file.close();
    m_status->setText(QStringLiteral("已导出 %1 行到 %2").arg(count).arg(QFileInfo(path).fileName()));
}
