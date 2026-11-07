#include "MinifilterView.h"

#include "MinifilterDriver.h"

#include <Windows.h>

#include <functional>

#include <QClipboard>
#include <QPair>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QGuiApplication>
#include <QHash>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QProcess>
#include <QPushButton>
#include <QShortcut>
#include <QStandardItemModel>
#include <QTextStream>
#include <QTreeView>
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

MinifilterView::MinifilterView(QWidget* parent)
    : QWidget(parent)
{
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    auto* bar = new QHBoxLayout();
    bar->addWidget(new QLabel(QStringLiteral("过滤"), this));
    m_filter = new QLineEdit(this);
    m_filter->setPlaceholderText(QStringLiteral("名称、回调、路径、公司、Altitude 或描述"));
    m_filter->setClearButtonEnabled(true);
    bar->addWidget(m_filter, 1);
    auto* refreshButton = new QPushButton(QStringLiteral("刷新"), this);
    bar->addWidget(refreshButton);
    layout->addLayout(bar);

    m_table = new QTreeView(this);
    m_model = new QStandardItemModel(this);
    m_model->setHorizontalHeaderLabels({QStringLiteral("名称"), QStringLiteral("回调入口"), QStringLiteral("驱动路径"),
                                        QStringLiteral("公司"), QStringLiteral("描述"), QStringLiteral("FLT_FILTER"),
                                        QStringLiteral("Altitude")});
    m_table->setModel(m_model);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setUniformRowHeights(true);
    m_table->header()->setStretchLastSection(true);
    m_table->header()->setSectionResizeMode(2, QHeaderView::Stretch);
    m_table->setContextMenuPolicy(Qt::CustomContextMenu);
    layout->addWidget(m_table, 1);

    m_status = new QLabel(QStringLiteral("尚未刷新"), this);
    m_status->setWordWrap(true);
    layout->addWidget(m_status);

    connect(refreshButton, &QPushButton::clicked, this, &MinifilterView::refresh);
    connect(m_filter, &QLineEdit::textChanged, this, &MinifilterView::showRows);
    connect(m_table, &QWidget::customContextMenuRequested, this, &MinifilterView::showMenu);
    auto* refreshKey = new QShortcut(QKeySequence(Qt::Key_F5), this);
    connect(refreshKey, &QShortcut::activated, this, &MinifilterView::refresh);
}

bool MinifilterView::systemModule(const Row& row) const
{
    if (row.company.contains(QStringLiteral("Microsoft"), Qt::CaseInsensitive))
    {
        return true;
    }

    return row.path.contains(QStringLiteral("\\Windows\\"), Qt::CaseInsensitive);
}

void MinifilterView::refresh()
{
    auto* request = new HACDBG_MINIFILTER_REQUEST();
    const bool ok = minifilterDriverQuery(request);
    m_rows.clear();
    m_scanned = false;
    m_truncated = false;
    if (ok)
    {
        QHash<QString, QPair<QString, QString>> details;
        for (unsigned int index = 0; index < request->Count && index < HACDBG_MINIFILTER_MAX_ROWS; ++index)
        {
            const HACDBG_MINIFILTER_ROW& source = request->Rows[index];
            Row row;
            row.filterValue = source.Filter;
            row.callbackValue = source.Callback;
            row.parent = source.Parent;
            row.name = QString::fromWCharArray(source.Name);
            row.callback = hexText(source.Callback);
            row.path = dosPath(source.Path);
            row.filter = hexText(source.Filter);
            row.altitude = QString::fromWCharArray(source.Altitude);
            if (details.contains(row.path))
            {
                row.company = details.value(row.path).first;
                row.description = details.value(row.path).second;
            }
            else if (row.path.isEmpty() == false)
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

void MinifilterView::showRows()
{
    m_model->removeRows(0, m_model->rowCount());
    std::vector<QStandardItem*> nodes(m_rows.size(), nullptr);
    const QString filter = m_filter->text().trimmed();
    std::vector<unsigned char> direct(m_rows.size(), 0);
    std::vector<unsigned char> visible(m_rows.size(), 0);
    for (std::size_t index = 0; index < m_rows.size(); ++index)
    {
        const Row& row = m_rows[index];
        if (m_hideSystem && systemModule(row))
        {
            continue;
        }

        if (filter.isEmpty() || row.name.contains(filter, Qt::CaseInsensitive) ||
            row.callback.contains(filter, Qt::CaseInsensitive) || row.path.contains(filter, Qt::CaseInsensitive) ||
            row.company.contains(filter, Qt::CaseInsensitive) || row.description.contains(filter, Qt::CaseInsensitive) ||
            row.filter.contains(filter, Qt::CaseInsensitive) || row.altitude.contains(filter, Qt::CaseInsensitive))
        {
            direct[index] = 1;
        }
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
        while (parent != HACDBG_MINIFILTER_NO_PARENT && parent < m_rows.size() && guard < 4)
        {
            visible[parent] = 1;
            parent = m_rows[parent].parent;
            guard += 1;
        }

        for (std::size_t child = 0; child < m_rows.size(); ++child)
        {
            if (m_rows[child].parent == index)
            {
                visible[child] = 1;
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
        QList<QStandardItem*> cells = {new QStandardItem(row.name),     new QStandardItem(row.callback),
                                       new QStandardItem(row.path),     new QStandardItem(row.company),
                                       new QStandardItem(row.description), new QStandardItem(row.filter),
                                       new QStandardItem(row.altitude)};
        cells.first()->setData(static_cast<qulonglong>(index), Qt::UserRole);
        const unsigned int parent = row.parent;
        if (parent == HACDBG_MINIFILTER_NO_PARENT || parent >= nodes.size() || nodes[parent] == nullptr)
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

    m_table->collapseAll();
    if (m_scanned == false)
    {
        return;
    }

    QString text = QStringLiteral("微过滤 %1").arg(m_rows.size());
    if (m_truncated)
    {
        text += QStringLiteral("，列表被截断");
    }

    if (m_hideSystem || m_filter->text().trimmed().isEmpty() == false)
    {
        text += QStringLiteral("，显示 %1").arg(shown);
    }

    m_status->setText(text);
}

int MinifilterView::rowIndex(const QModelIndex& index) const
{
    if (index.isValid() == false)
    {
        return -1;
    }

    const QVariant value = index.sibling(index.row(), 0).data(Qt::UserRole);
    if (value.isValid() == false || value.toULongLong() >= m_rows.size())
    {
        return -1;
    }

    return static_cast<int>(value.toULongLong());
}

void MinifilterView::changeFilter(const Row& row, unsigned int operation, const QString& title)
{
    if (operation == HACDBG_MINIFILTER_OP_DISABLE &&
        QMessageBox::question(this, title, QStringLiteral("禁用 %1 的回调？入口会直接返回。").arg(row.name)) != QMessageBox::Yes)
    {
        return;
    }

    auto* request = new HACDBG_MINIFILTER_REQUEST();
    int status = 0;
    const bool ok = minifilterDriverOperate(operation, row.filterValue, request, &status);
    delete request;
    if (ok == false)
    {
        m_status->setText(QStringLiteral("%1失败：0x%2").arg(title).arg(static_cast<unsigned int>(status), 8, 16, QChar('0')));
        return;
    }

    refresh();
}

void MinifilterView::showMenu(const QPoint& point)
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
    const bool haveCallback = row != nullptr && row->callbackValue != 0;
    QMenu menu(this);
    QAction* refreshAction = menu.addAction(QStringLiteral("刷新"));
    refreshAction->setShortcut(QKeySequence(Qt::Key_F5));
    refreshAction->setShortcutVisibleInContextMenu(true);
    QAction* disableAction = menu.addAction(QStringLiteral("禁用过滤器"));
    QAction* enableAction = menu.addAction(QStringLiteral("启用过滤器"));
    QAction* disasmAction = menu.addAction(QStringLiteral("反汇编地址"));
    QAction* hideAction = menu.addAction(QStringLiteral("不显示系统模块"));
    hideAction->setCheckable(true);
    hideAction->setChecked(m_hideSystem);
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
    disableAction->setEnabled(row != nullptr && row->filterValue != 0);
    enableAction->setEnabled(row != nullptr && row->filterValue != 0);
    disasmAction->setEnabled(haveCallback);
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
        return;
    }

    if (chosen == hideAction)
    {
        m_hideSystem = hideAction->isChecked();
        showRows();
        return;
    }

    if (chosen == copyCell)
    {
        QGuiApplication::clipboard()->setText(index.data().toString());
        return;
    }

    if (chosen == copyRow && row != nullptr)
    {
        QStringList cells;
        for (int column = 0; column < m_model->columnCount(); ++column)
        {
            cells.push_back(index.sibling(index.row(), column).data().toString());
        }

        QGuiApplication::clipboard()->setText(cells.join(QLatin1Char('\t')));
        return;
    }

    if (chosen == copyAll || chosen == exportText || chosen == exportJson || chosen == exportHtml)
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

        return;
    }

    if (row == nullptr)
    {
        return;
    }

    if (chosen == disableAction)
    {
        changeFilter(*row, HACDBG_MINIFILTER_OP_DISABLE, QStringLiteral("禁用过滤器"));
    }
    else if (chosen == enableAction)
    {
        changeFilter(*row, HACDBG_MINIFILTER_OP_ENABLE, QStringLiteral("启用过滤器"));
    }
    else if (chosen == disasmAction)
    {
        emit addressActivated(row->callbackValue, 0);
    }
    else if (chosen == scanAction)
    {
        const QString scanner = defenderScanner();
        if (scanner.isEmpty() ||
            QProcess::startDetached(scanner, {QStringLiteral("-Scan"), QStringLiteral("-ScanType"), QStringLiteral("3"),
                                               QStringLiteral("-File"), row->path}) == false)
        {
            QMessageBox::warning(this, QStringLiteral("扫描文件"), QStringLiteral("没有找到 Microsoft Defender，或无法启动扫描。"));
        }
    }
    else if (chosen == folderAction)
    {
        ShellExecuteW(nullptr, L"explore", reinterpret_cast<const wchar_t*>(QFileInfo(row->path).absolutePath().utf16()),
                      nullptr, nullptr, SW_SHOWNORMAL);
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

void MinifilterView::exportShown(int kind)
{
    const bool json = kind == 1;
    const bool html = kind == 2;
    const QString path = QFileDialog::getSaveFileName(
        this, html ? QStringLiteral("导出 HTML") : json ? QStringLiteral("导出 JSON") : QStringLiteral("导出 TXT"),
        html ? QStringLiteral("HacDbg-minifilters.html")
             : json ? QStringLiteral("HacDbg-minifilters.json") : QStringLiteral("HacDbg-minifilters.txt"),
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
    else
    {
        if (html)
        {
            QTextStream out(&file);
            out.setEncoding(QStringConverter::Utf8);
            out << "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>微过滤</title></head><body><table border=\"1\"><tr>";
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
                        out << "<td>" << m_model->index(modelRow, column, parent).data().toString().toHtmlEscaped()
                            << "</td>";
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
                        cells.push_back(m_model->index(modelRow, column, parent).data().toString());
                    }

                    out << cells.join(QLatin1Char('\t')) << "\n";
                    count += 1;
                    walk(m_model->index(modelRow, 0, parent));
                }
            };
            walk({});
        }
    }

    file.close();
    m_status->setText(QStringLiteral("已导出 %1 行到 %2").arg(count).arg(QFileInfo(path).fileName()));
}
