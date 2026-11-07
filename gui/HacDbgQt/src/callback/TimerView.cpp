#include "TimerView.h"

#include "TimerDriver.h"

#include <Windows.h>

#include <functional>

#include <QCheckBox>
#include <QClipboard>
#include <QComboBox>
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
#include <QPair>
#include <QProcess>
#include <QRegularExpression>
#include <QShortcut>
#include <QStandardItemModel>
#include <QTableView>
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
        return QStringLiteral("-");
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

TimerView::TimerView(QWidget* parent)
    : QWidget(parent)
{
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    m_table = new QTableView(this);
    m_model = new QStandardItemModel(this);
    m_model->setHorizontalHeaderLabels({QStringLiteral("回调入口"), QStringLiteral("类型"), QStringLiteral("周期"),
                                        QStringLiteral("状态"), QStringLiteral("驱动路径"), QStringLiteral("DPC对象"),
                                        QStringLiteral("定时器对象"), QStringLiteral("公司"), QStringLiteral("描述")});
    m_table->setModel(m_model);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_table->setWordWrap(false);
    m_table->verticalHeader()->setVisible(false);
    m_table->horizontalHeader()->setStretchLastSection(true);
    m_table->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
    m_table->setContextMenuPolicy(Qt::CustomContextMenu);
    layout->addWidget(m_table, 1);

    auto* bar = new QHBoxLayout();
    m_type = new QComboBox(this);
    m_type->addItem(QStringLiteral("所有"));
    m_type->addItem(QStringLiteral("IO Timer"), HACDBG_TIMER_IO);
    m_type->addItem(QStringLiteral("DPC Timer"), HACDBG_TIMER_DPC);
    bar->addWidget(m_type);
    m_filter = new QLineEdit(this);
    m_filter->setPlaceholderText(QStringLiteral("输入要过滤的文本..."));
    m_filter->setClearButtonEnabled(true);
    bar->addWidget(m_filter, 1);
    m_regex = new QCheckBox(QStringLiteral("正则"), this);
    bar->addWidget(m_regex);
    m_count = new QLabel(QStringLiteral("数量: 0"), this);
    bar->addWidget(m_count);
    layout->addLayout(bar);

    m_status = new QLabel(QStringLiteral("尚未刷新"), this);
    layout->addWidget(m_status);

    connect(m_type, &QComboBox::currentIndexChanged, this, [this](int) { showRows(); });
    connect(m_filter, &QLineEdit::textChanged, this, &TimerView::showRows);
    connect(m_regex, &QCheckBox::toggled, this, &TimerView::showRows);
    connect(m_table, &QWidget::customContextMenuRequested, this, &TimerView::showMenu);
    auto* refreshKey = new QShortcut(QKeySequence(Qt::Key_F5), this);
    connect(refreshKey, &QShortcut::activated, this, &TimerView::refresh);
}

bool TimerView::systemModule(const Row& row) const
{
    if (row.company.contains(QStringLiteral("Microsoft"), Qt::CaseInsensitive))
    {
        return true;
    }

    return row.path.contains(QStringLiteral("\\Windows\\"), Qt::CaseInsensitive);
}

bool TimerView::matches(const Row& row) const
{
    if (m_type->currentIndex() > 0 && row.typeId != m_type->currentData().toUInt())
    {
        return false;
    }

    if (m_hideSystem && systemModule(row))
    {
        return false;
    }

    const QString filter = m_filter->text();
    if (filter.isEmpty())
    {
        return true;
    }

    const QStringList fields = {row.callback, row.type, row.periodText, row.state, row.path,
                                row.dpc,      row.timer, row.company,   row.description};
    if (m_regex->isChecked())
    {
        const QRegularExpression expression(filter);
        if (expression.isValid() == false)
        {
            return false;
        }

        for (const QString& field : fields)
        {
            if (expression.match(field).hasMatch())
            {
                return true;
            }
        }

        return false;
    }

    for (const QString& field : fields)
    {
        if (field.contains(filter, Qt::CaseInsensitive))
        {
            return true;
        }
    }

    return false;
}

void TimerView::refresh()
{
    auto* request = new HACDBG_TIMER_REQUEST();
    const bool ok = timerDriverQuery(request);
    m_rows.clear();
    m_scanned = false;
    m_truncated = false;
    if (ok)
    {
        QHash<QString, QPair<QString, QString>> details;
        for (unsigned int index = 0; index < request->Count && index < HACDBG_TIMER_MAX_ROWS; ++index)
        {
            const HACDBG_TIMER_ROW& source = request->Rows[index];
            Row row;
            row.typeId = source.Type;
            row.period = source.Period;
            row.running = source.Running;
            row.callbackValue = source.Callback;
            row.dpcValue = source.Dpc;
            row.timerValue = source.Timer;
            row.callback = hexText(source.Callback);
            row.type = source.Type == HACDBG_TIMER_IO ? QStringLiteral("IO Timer") : QStringLiteral("DPC Timer");
            row.periodText = QString::number(source.Period);
            row.state = source.Running != 0 ? QStringLiteral("运行中") : QStringLiteral("已停止");
            row.path = dosPath(source.Path);
            row.dpc = hexText(source.Dpc);
            row.timer = hexText(source.Timer);
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

void TimerView::showRows()
{
    m_model->removeRows(0, m_model->rowCount());
    int shown = 0;
    for (const Row& row : m_rows)
    {
        if (matches(row) == false)
        {
            continue;
        }

        const QStringList text = {row.callback, row.type, row.periodText, row.state, row.path,
                                  row.dpc,      row.timer, row.company,    row.description};
        QList<QStandardItem*> cells;
        for (const QString& cell : text)
        {
            cells.push_back(new QStandardItem(cell));
        }

        cells.first()->setData(static_cast<qulonglong>(&row - m_rows.data()), Qt::UserRole);
        m_model->appendRow(cells);
        shown += 1;
    }

    m_count->setText(QStringLiteral("数量: %1").arg(shown));
    if (m_scanned == false)
    {
        return;
    }

    QString text = QStringLiteral("定时器 %1").arg(m_rows.size());
    if (m_truncated)
    {
        text += QStringLiteral("，列表被截断");
    }

    m_status->setText(text);
}

int TimerView::rowIndex(const QModelIndex& index) const
{
    if (index.isValid() == false)
    {
        return -1;
    }

    const QVariant value = index.sibling(index.row(), 0).data(Qt::UserRole);
    if (value.isValid() == false)
    {
        return -1;
    }

    const auto row = static_cast<std::size_t>(value.toULongLong());
    if (row >= m_rows.size())
    {
        return -1;
    }

    return static_cast<int>(row);
}

void TimerView::showMenu(const QPoint& point)
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
    QAction* removeAction = menu.addAction(QStringLiteral("移除定时器"));
    QAction* disasmAction = menu.addAction(QStringLiteral("反汇编地址"));
    QAction* symbolAction = menu.addAction(QStringLiteral("加载符号"));
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
    removeAction->setEnabled(row != nullptr);
    disasmAction->setEnabled(row != nullptr && row->callbackValue != 0);
    symbolAction->setEnabled(havePath);
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
        if (chosen != copyAll)
        {
            exportShown(chosen == exportJson ? 1 : chosen == exportHtml ? 2 : 0);
            return;
        }

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
        return;
    }

    if (row == nullptr)
    {
        return;
    }

    if (chosen == removeAction)
    {
        if (QMessageBox::question(this, QStringLiteral("移除定时器"), QStringLiteral("移除这个定时器？")) != QMessageBox::Yes)
        {
            return;
        }

        int status = 0;
        if (timerDriverRemove(row->typeId, row->timerValue, &status) == false)
        {
            m_status->setText(QStringLiteral("移除定时器失败：0x%1").arg(static_cast<unsigned int>(status), 8, 16, QChar('0')));
            return;
        }

        refresh();
    }
    else if (chosen == disasmAction)
    {
        emit addressActivated(row->callbackValue, 0);
    }
    else if (chosen == symbolAction)
    {
        emit commandRequested(QStringLiteral(".reload /f %1").arg(QFileInfo(row->path).fileName()));
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

void TimerView::exportShown(int kind)
{
    const bool json = kind == 1;
    const bool html = kind == 2;
    const QString path = QFileDialog::getSaveFileName(
        this, html ? QStringLiteral("导出 HTML") : json ? QStringLiteral("导出 JSON") : QStringLiteral("导出 TXT"),
        html ? QStringLiteral("HacDbg-timers.html")
             : json ? QStringLiteral("HacDbg-timers.json") : QStringLiteral("HacDbg-timers.txt"),
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

    if (json)
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
    else if (html)
    {
        QTextStream out(&file);
        out.setEncoding(QStringConverter::Utf8);
        out << "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>定时器</title></head><body><table border=\"1\"><tr>";
        for (const QString& header : headers)
        {
            out << "<th>" << header.toHtmlEscaped() << "</th>";
        }

        out << "</tr>\n";
        for (int modelRow = 0; modelRow < m_model->rowCount(); ++modelRow)
        {
            out << "<tr>";
            for (int column = 0; column < headers.size(); ++column)
            {
                out << "<td>" << m_model->index(modelRow, column).data().toString().toHtmlEscaped() << "</td>";
            }

            out << "</tr>\n";
        }

        out << "</table></body></html>\n";
    }
    else
    {
        file.write("\xEF\xBB\xBF");
        QTextStream out(&file);
        out.setEncoding(QStringConverter::Utf8);
        out << headers.join(QLatin1Char('\t')) << "\n";
        for (int modelRow = 0; modelRow < m_model->rowCount(); ++modelRow)
        {
            QStringList cells;
            for (int column = 0; column < headers.size(); ++column)
            {
                cells.push_back(m_model->index(modelRow, column).data().toString());
            }

            out << cells.join(QLatin1Char('\t')) << "\n";
        }
    }

    file.close();
    m_status->setText(QStringLiteral("已导出 %1 行").arg(m_model->rowCount()));
}
