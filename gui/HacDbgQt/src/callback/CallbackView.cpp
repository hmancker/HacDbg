#include "CallbackView.h"

#include "CallbackDriver.h"

#include <Windows.h>

#include <QClipboard>
#include <QComboBox>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QGuiApplication>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QHBoxLayout>
#include <algorithm>

#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QProcess>
#include <QPushButton>
#include <QShortcut>
#include <QStandardItemModel>
#include <QTableView>
#include <QTextStream>
#include <QVBoxLayout>

#include <shellapi.h>
#include <shlobj.h>

#include <vector>

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

void fileDetails(const QString& path, QString* company, QString* version, QString* description)
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
    *version = versionString(data.data(), root + QStringLiteral("FileVersion"));
    *description = versionString(data.data(), root + QStringLiteral("FileDescription"));
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

void showProperties(QWidget* parent, const QString& path)
{
    const HWND owner = reinterpret_cast<HWND>(parent->window()->winId());
    if (SHObjectProperties(owner, SHOP_FILEPATH, reinterpret_cast<const wchar_t*>(path.utf16()), nullptr) == FALSE)
    {
        QMessageBox::warning(parent, QStringLiteral("属性"), QStringLiteral("打不开这个文件的属性。"));
    }
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

QString stateName(unsigned int state)
{
    switch (state)
    {
    case HACDBG_CALLBACK_STATE_REMOVED:
        return QStringLiteral("移除");
    case HACDBG_CALLBACK_STATE_DISABLED:
        return QStringLiteral("禁用");
    case HACDBG_CALLBACK_STATE_ENABLED:
        return QStringLiteral("启用");
    default:
        return QStringLiteral("正常");
    }
}
}

CallbackView::CallbackView(QWidget* parent)
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
        unsigned int first;
        unsigned int last;
    } groups[] = {
        {"CreateProcess", HACDBG_CALLBACK_CREATE_PROCESS, HACDBG_CALLBACK_CREATE_PROCESS_EX2},
        {"CreateThread", HACDBG_CALLBACK_CREATE_THREAD, HACDBG_CALLBACK_CREATE_THREAD_EX},
        {"LoadImage", HACDBG_CALLBACK_LOAD_IMAGE, HACDBG_CALLBACK_LOAD_IMAGE_EX},
        {"ProcessObCallback", HACDBG_CALLBACK_PROCESS_OB_PRE, HACDBG_CALLBACK_PROCESS_OB_POST},
        {"ThreadObCallback", HACDBG_CALLBACK_THREAD_OB_PRE, HACDBG_CALLBACK_THREAD_OB_POST},
        {"DesktopObCallback", HACDBG_CALLBACK_DESKTOP_OB_PRE, HACDBG_CALLBACK_DESKTOP_OB_POST},
        {"ImageVerification", HACDBG_CALLBACK_IMAGE_VERIFICATION, HACDBG_CALLBACK_IMAGE_VERIFICATION},
        {"BugCheck", HACDBG_CALLBACK_BUGCHECK, HACDBG_CALLBACK_BUGCHECK_REASON},
        {"Shutdown", HACDBG_CALLBACK_SHUTDOWN, HACDBG_CALLBACK_LAST_CHANCE_SHUTDOWN},
        {"CmpCallback", HACDBG_CALLBACK_REGISTRY, HACDBG_CALLBACK_REGISTRY},
        {"FsNotifyChange", HACDBG_CALLBACK_FS_NOTIFY, HACDBG_CALLBACK_FS_NOTIFY},
        {"LogonSessionTerminated", HACDBG_CALLBACK_LOGON_TERMINATED, HACDBG_CALLBACK_LOGON_TERMINATED_EX},
        {"PowerSetting", HACDBG_CALLBACK_POWER_SETTING, HACDBG_CALLBACK_POWER_SETTING},
    };
    for (const auto& group : groups)
    {
        const int index = m_type->count();
        m_type->addItem(QString::fromLatin1(group.label));
        m_type->setItemData(index, group.first, Qt::UserRole);
        m_type->setItemData(index, group.last, Qt::UserRole + 1);
    }

    bar->addWidget(m_type);
    bar->addWidget(new QLabel(QStringLiteral("过滤"), this));
    m_filter = new QLineEdit(this);
    m_filter->setPlaceholderText(QStringLiteral("地址、类型、状态、路径、公司或描述"));
    m_filter->setClearButtonEnabled(true);
    bar->addWidget(m_filter, 1);
    auto* refreshButton = new QPushButton(QStringLiteral("刷新"), this);
    bar->addWidget(refreshButton);
    layout->addLayout(bar);

    m_table = new QTableView(this);
    m_model = new QStandardItemModel(this);
    m_model->setHorizontalHeaderLabels({QStringLiteral("回调入口"), QStringLiteral("类型"), QStringLiteral("状态"),
                                        QStringLiteral("路径"), QStringLiteral("公司"), QStringLiteral("版本"),
                                        QStringLiteral("Callback Extra"), QStringLiteral("描述")});
    m_table->setModel(m_model);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->horizontalHeader()->setStretchLastSection(true);
    m_table->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    m_table->verticalHeader()->setVisible(false);
    m_table->setWordWrap(false);
    m_table->setContextMenuPolicy(Qt::CustomContextMenu);
    layout->addWidget(m_table, 1);

    m_status = new QLabel(QStringLiteral("尚未刷新"), this);
    m_status->setWordWrap(true);
    layout->addWidget(m_status);

    connect(refreshButton, &QPushButton::clicked, this, &CallbackView::refresh);
    connect(m_type, &QComboBox::currentIndexChanged, this, [this](int) { showRows(); });
    connect(m_filter, &QLineEdit::textChanged, this, &CallbackView::showRows);
    connect(m_table, &QWidget::customContextMenuRequested, this, &CallbackView::showMenu);
    auto* refreshKey = new QShortcut(QKeySequence(Qt::Key_F5), this);
    connect(refreshKey, &QShortcut::activated, this, &CallbackView::refresh);
}

void CallbackView::refresh()
{
    auto* request = new HACDBG_CALLBACK_REQUEST();
    const bool ok = callbackDriverQuery(request);
    m_rows.clear();
    m_scanned = false;
    m_truncated = false;
    if (ok)
    {
        for (unsigned int index = 0; index < request->Count && index < HACDBG_CALLBACK_MAX_ROWS; ++index)
        {
            const HACDBG_CALLBACK_ROW& source = request->Rows[index];
            Row row;
            const QString path = dosPath(source.Path);
            row.typeId = source.Type;
            row.entryValue = source.Entry;
            row.extraValue = source.Extra;
            row.state = source.Reserved == HACDBG_CALLBACK_STATE_DISABLED ? HACDBG_CALLBACK_STATE_DISABLED
                                                                          : HACDBG_CALLBACK_STATE_NORMAL;
            for (const Row& mark : m_marks)
            {
                if (mark.typeId == row.typeId && mark.entryValue == row.entryValue && mark.extraValue == row.extraValue &&
                    (mark.state == HACDBG_CALLBACK_STATE_DISABLED || mark.state == HACDBG_CALLBACK_STATE_ENABLED))
                {
                    row.state = mark.state;
                    break;
                }
            }

            row.stateText = stateName(row.state);
            row.entry = QStringLiteral("0x%1").arg(source.Entry, 16, 16, QChar('0')).toUpper().replace("0X", "0x");
            row.type = QString::fromLatin1(HacDbgCallbackTypeName(source.Type));
            row.path = path;
            row.extra = QStringLiteral("0x%1").arg(source.Extra, 16, 16, QChar('0')).toUpper().replace("0X", "0x");
            fileDetails(path, &row.company, &row.version, &row.description);
            m_rows.push_back(row);
        }

        for (const Row& mark : m_marks)
        {
            if (mark.state != HACDBG_CALLBACK_STATE_REMOVED)
            {
                continue;
            }

            bool present = false;
            for (const Row& row : m_rows)
            {
                if (row.typeId == mark.typeId && row.entryValue == mark.entryValue && row.extraValue == mark.extraValue)
                {
                    present = true;
                    break;
                }
            }

            if (present == false)
            {
                m_rows.push_back(mark);
            }
        }

        std::stable_sort(m_rows.begin(), m_rows.end(), [](const Row& left, const Row& right) {
            if (left.typeId != right.typeId)
            {
                return left.typeId < right.typeId;
            }

            return left.entryValue < right.entryValue;
        });

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

bool CallbackView::systemModule(const Row& row) const
{
    if (row.company.contains(QStringLiteral("Microsoft"), Qt::CaseInsensitive))
    {
        return true;
    }

    return row.path.contains(QStringLiteral("\\Windows\\"), Qt::CaseInsensitive);
}

bool CallbackView::matches(const Row& row) const
{
    if (m_hideSystem && systemModule(row))
    {
        return false;
    }

    if (m_type->currentIndex() > 0)
    {
        const unsigned int first = m_type->currentData(Qt::UserRole).toUInt();
        const unsigned int last = m_type->currentData(Qt::UserRole + 1).toUInt();
        if (row.typeId < first || row.typeId > last)
        {
            return false;
        }
    }

    const QString filter = m_filter->text().trimmed();
    if (filter.isEmpty())
    {
        return true;
    }

    return row.entry.contains(filter, Qt::CaseInsensitive) || row.type.contains(filter, Qt::CaseInsensitive) ||
           row.stateText.contains(filter, Qt::CaseInsensitive) || row.path.contains(filter, Qt::CaseInsensitive) ||
           row.company.contains(filter, Qt::CaseInsensitive) || row.version.contains(filter, Qt::CaseInsensitive) ||
           row.extra.contains(filter, Qt::CaseInsensitive) || row.description.contains(filter, Qt::CaseInsensitive);
}

int CallbackView::shownIndex(const QModelIndex& index) const
{
    if (index.isValid() == false || index.row() < 0 || index.row() >= static_cast<int>(m_shown.size()))
    {
        return -1;
    }

    return index.row();
}

void CallbackView::editRow(const Row& row, unsigned int operation, const QString& title)
{
    const QString question = operation == HACDBG_CALLBACK_OP_REMOVE
                                 ? QStringLiteral("移除这条回调？回调表里的指针会被写成 0。")
                                 : QStringLiteral("禁用这条回调？入口影子页会直接返回，启用后卸掉影子页。");
    if (QMessageBox::question(this, title, question) != QMessageBox::Yes)
    {
        return;
    }

    int status = 0;
    if (callbackDriverEdit(operation, row.typeId, row.entryValue, row.extraValue, &status) == false)
    {
        m_status->setText(QStringLiteral("%1失败：0x%2").arg(title).arg(static_cast<unsigned int>(status), 8, 16, QChar('0')));
        return;
    }

    Row marked = row;
    marked.state = operation == HACDBG_CALLBACK_OP_REMOVE ? HACDBG_CALLBACK_STATE_REMOVED : HACDBG_CALLBACK_STATE_DISABLED;
    marked.stateText = stateName(marked.state);
    bool replaced = false;
    for (Row& mark : m_marks)
    {
        if (mark.typeId == marked.typeId && mark.entryValue == marked.entryValue && mark.extraValue == marked.extraValue)
        {
            mark = marked;
            replaced = true;
            break;
        }
    }

    if (replaced == false)
    {
        m_marks.push_back(marked);
    }

    refresh();
}

void CallbackView::showMenu(const QPoint& point)
{
    const QModelIndex index = m_table->indexAt(point);
    if (index.isValid())
    {
        m_table->setCurrentIndex(index);
        m_table->selectionModel()->select(index, QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
    }

    const int shown = shownIndex(index);
    const bool haveRow = shown >= 0;
    const Row* row = haveRow ? &m_rows[m_shown[static_cast<std::size_t>(shown)]] : nullptr;
    const bool havePath = row != nullptr && row->path.isEmpty() == false;

    QMenu menu(this);
    QAction* refreshAction = menu.addAction(QStringLiteral("刷新"));
    refreshAction->setShortcut(QKeySequence(Qt::Key_F5));
    refreshAction->setShortcutVisibleInContextMenu(true);
    QAction* removeAction = menu.addAction(QStringLiteral("移除回调"));
    QAction* disableAction = menu.addAction(QStringLiteral("禁用回调"));
    QAction* enableAction = menu.addAction(QStringLiteral("启用回调"));
    QAction* disassembleAction = menu.addAction(QStringLiteral("反汇编地址"));
    QAction* symbolAction = menu.addAction(QStringLiteral("加载符号"));
    QAction* hideAction = menu.addAction(QStringLiteral("不显示系统模块"));
    hideAction->setCheckable(true);
    hideAction->setChecked(m_hideSystem);
    QMenu* copyMenu = menu.addMenu(QStringLiteral("复制"));
    QAction* copyCell = copyMenu->addAction(QStringLiteral("复制单元格"));
    QAction* copyRow = copyMenu->addAction(QStringLiteral("复制选行"));
    QAction* copyAll = copyMenu->addAction(QStringLiteral("复制全部数据"));
    QAction* scanAction = menu.addAction(QStringLiteral("扫描文件"));
    QAction* folderAction = menu.addAction(QStringLiteral("定位到文件管理"));
    QAction* explorerAction = menu.addAction(QStringLiteral("定位到资源管理器"));
    QMenu* exportMenu = menu.addMenu(QStringLiteral("导出数据"));
    QAction* exportText = exportMenu->addAction(QStringLiteral("导出 TXT..."));
    QAction* exportJson = exportMenu->addAction(QStringLiteral("导出 JSON..."));
    QAction* exportHtml = exportMenu->addAction(QStringLiteral("导出 HTML..."));
    QAction* propertyAction = menu.addAction(QStringLiteral("属性..."));
    removeAction->setEnabled(haveRow);
    disableAction->setEnabled(haveRow);
    enableAction->setEnabled(haveRow);
    disassembleAction->setEnabled(haveRow && row->entryValue != 0);
    symbolAction->setEnabled(havePath);
    copyCell->setEnabled(haveRow && index.isValid());
    copyRow->setEnabled(haveRow);
    scanAction->setEnabled(havePath);
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
    else if (chosen == hideAction)
    {
        m_hideSystem = hideAction->isChecked();
        showRows();
    }
    else if (chosen == copyAll)
    {
        QStringList lines;
        QStringList headers;
        for (int column = 0; column < m_model->columnCount(); ++column)
        {
            headers.push_back(m_model->headerData(column, Qt::Horizontal).toString());
        }

        lines.push_back(headers.join(QLatin1Char('\t')));
        for (int modelRow = 0; modelRow < m_model->rowCount(); ++modelRow)
        {
            QStringList cells;
            for (int column = 0; column < m_model->columnCount(); ++column)
            {
                cells.push_back(m_model->index(modelRow, column).data().toString());
            }

            lines.push_back(cells.join(QLatin1Char('\t')));
        }

        QGuiApplication::clipboard()->setText(lines.join(QLatin1Char('\n')));
    }
    else if (chosen == exportText)
    {
        exportShown(0);
    }
    else if (chosen == exportJson)
    {
        exportShown(1);
    }
    else if (chosen == exportHtml)
    {
        exportShown(2);
    }
    else if (row == nullptr)
    {
        return;
    }
    else if (chosen == removeAction)
    {
        editRow(*row, HACDBG_CALLBACK_OP_REMOVE, QStringLiteral("移除回调"));
    }
    else if (chosen == disableAction)
    {
        editRow(*row, HACDBG_CALLBACK_OP_DISABLE, QStringLiteral("禁用回调"));
    }
    else if (chosen == enableAction)
    {
        int status = 0;
        if (callbackDriverEdit(HACDBG_CALLBACK_OP_ENABLE, row->typeId, row->entryValue, row->extraValue, &status) == false)
        {
            m_status->setText(QStringLiteral("启用回调失败：0x%1").arg(static_cast<unsigned int>(status), 8, 16, QChar('0')));
            return;
        }

        Row marked = *row;
        marked.state = HACDBG_CALLBACK_STATE_ENABLED;
        marked.stateText = stateName(marked.state);
        bool replaced = false;
        for (Row& mark : m_marks)
        {
            if (mark.typeId == marked.typeId && mark.entryValue == marked.entryValue && mark.extraValue == marked.extraValue)
            {
                mark = marked;
                replaced = true;
                break;
            }
        }

        if (replaced == false)
        {
            m_marks.push_back(marked);
        }

        refresh();
    }
    else if (chosen == disassembleAction)
    {
        emit addressActivated(row->entryValue, 0);
    }
    else if (chosen == symbolAction)
    {
        emit commandRequested(QStringLiteral(".reload /f %1").arg(QFileInfo(row->path).fileName()));
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
            cells.push_back(m_model->index(shown, column).data().toString());
        }

        QGuiApplication::clipboard()->setText(cells.join(QLatin1Char('\t')));
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
        showProperties(this, row->path);
    }
}

void CallbackView::exportShown(int kind)
{
    const QString title = kind == 1 ? QStringLiteral("导出 JSON") : kind == 2 ? QStringLiteral("导出 HTML") : QStringLiteral("导出 TXT");
    const QString suffix = kind == 1 ? QStringLiteral("json") : kind == 2 ? QStringLiteral("html") : QStringLiteral("txt");
    const QString filter = kind == 1 ? QStringLiteral("JSON (*.json)")
                                     : kind == 2 ? QStringLiteral("HTML (*.html)") : QStringLiteral("文本 (*.txt)");
    QString path = QFileDialog::getSaveFileName(this, title, QStringLiteral("HacDbg-callbacks.%1").arg(suffix), filter);
    if (path.isEmpty())
    {
        return;
    }

    if (path.endsWith(QStringLiteral(".") + suffix, Qt::CaseInsensitive) == false)
    {
        path += QStringLiteral(".") + suffix;
    }

    QStringList headers;
    for (int column = 0; column < m_model->columnCount(); ++column)
    {
        headers.push_back(m_model->headerData(column, Qt::Horizontal).toString());
    }

    QFile file(path);
    if (file.open(QIODevice::WriteOnly | QIODevice::Truncate) == false)
    {
        QMessageBox::warning(this, title, QStringLiteral("写不了这个文件。"));
        return;
    }

    if (kind == 1)
    {
        QJsonArray rows;
        for (int modelRow = 0; modelRow < m_model->rowCount(); ++modelRow)
        {
            QJsonObject item;
            for (int column = 0; column < headers.size(); ++column)
            {
                item.insert(headers.at(column), m_model->index(modelRow, column).data().toString());
            }

            rows.append(item);
        }

        file.write(QJsonDocument(rows).toJson(QJsonDocument::Indented));
    }
    else if (kind == 2)
    {
        auto escape = [](const QString& text)
        {
            QString safe = text;
            safe.replace(QLatin1Char('&'), QStringLiteral("&amp;"));
            safe.replace(QLatin1Char('<'), QStringLiteral("&lt;"));
            safe.replace(QLatin1Char('>'), QStringLiteral("&gt;"));
            safe.replace(QLatin1Char('"'), QStringLiteral("&quot;"));
            return safe;
        };

        QTextStream out(&file);
        out.setEncoding(QStringConverter::Utf8);
        out << "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>系统回调</title></head><body><table border=\"1\">\n<tr>";
        for (const QString& header : headers)
        {
            out << "<th>" << escape(header) << "</th>";
        }

        out << "</tr>\n";
        for (int modelRow = 0; modelRow < m_model->rowCount(); ++modelRow)
        {
            out << "<tr>";
            for (int column = 0; column < headers.size(); ++column)
            {
                out << "<td>" << escape(m_model->index(modelRow, column).data().toString()) << "</td>";
            }

            out << "</tr>\n";
        }

        out << "</table></body></html>\n";
    }
    else
    {
        auto cell = [](const QString& text)
        {
            QString safe = text;
            safe.replace(QLatin1Char('\t'), QLatin1Char(' '));
            safe.replace(QLatin1Char('\r'), QLatin1Char(' '));
            safe.replace(QLatin1Char('\n'), QLatin1Char(' '));
            return safe;
        };

        file.write("\xEF\xBB\xBF");
        QTextStream out(&file);
        out.setEncoding(QStringConverter::Utf8);
        QStringList headerCells;
        for (const QString& header : headers)
        {
            headerCells.push_back(cell(header));
        }

        out << headerCells.join(QLatin1Char('\t')) << "\n";
        for (int modelRow = 0; modelRow < m_model->rowCount(); ++modelRow)
        {
            QStringList cells;
            for (int column = 0; column < headers.size(); ++column)
            {
                cells.push_back(cell(m_model->index(modelRow, column).data().toString()));
            }

            out << cells.join(QLatin1Char('\t')) << "\n";
        }
    }

    file.close();
    m_status->setText(QStringLiteral("已导出 %1 行到 %2").arg(m_model->rowCount()).arg(QFileInfo(path).fileName()));
}

void CallbackView::showRows()
{
    m_model->removeRows(0, m_model->rowCount());
    m_shown.clear();
    int shown = 0;
    for (std::size_t index = 0; index < m_rows.size(); ++index)
    {
        const Row& row = m_rows[index];
        if (matches(row) == false)
        {
            continue;
        }

        m_shown.push_back(index);
        m_model->appendRow({new QStandardItem(row.entry), new QStandardItem(row.type), new QStandardItem(row.stateText),
                            new QStandardItem(row.path), new QStandardItem(row.company), new QStandardItem(row.version),
                            new QStandardItem(row.extra), new QStandardItem(row.description)});
        ++shown;
    }

    if (m_scanned == false)
    {
        return;
    }

    QString text = QStringLiteral("回调 %1").arg(m_rows.size());
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
