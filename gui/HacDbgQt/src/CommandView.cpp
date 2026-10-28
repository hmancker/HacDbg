#include "CommandView.h"

#include <QFrame>
#include <QHBoxLayout>
#include <QKeyEvent>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QPlainTextEdit>
#include <QResizeEvent>
#include <QScrollBar>
#include <QShortcut>
#include <QTextCursor>
#include <QTextDocument>
#include <QToolButton>
#include <QVBoxLayout>

namespace
{
constexpr int kMaximumBlocks = 20000;

QString commonPrefix(const std::vector<QString>& items)
{
    if (items.empty())
    {
        return {};
    }

    QString prefix = items.front();

    for (const QString& item : items)
    {
        while (prefix.isEmpty() == false && item.startsWith(prefix, Qt::CaseInsensitive) == false)
        {
            prefix.chop(1);
        }
    }

    return prefix;
}
}

CommandView::CommandView(QWidget* parent)
    : QWidget(parent)
{
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);

    m_output = new QPlainTextEdit(this);
    m_output->setReadOnly(true);
    m_output->setUndoRedoEnabled(false);
    m_output->setLineWrapMode(QPlainTextEdit::NoWrap);
    m_output->setMaximumBlockCount(kMaximumBlocks);
    m_output->setPlaceholderText(QStringLiteral("命令输出"));
    QFont font(QStringLiteral("Cascadia Mono"));
    font.setStyleHint(QFont::Monospace);
    font.setPointSize(10);
    m_output->setFont(font);

    m_inputRow = new QWidget(this);
    m_inputRow->setObjectName(QStringLiteral("commandBar"));
    m_inputRow->setFixedHeight(30);
    m_inputRow->setStyleSheet(QStringLiteral(
        "QWidget#commandBar { background: #f0f0f0; border-top: 1px solid #d0d0d0; }"));
    auto* inputLayout = new QHBoxLayout(m_inputRow);
    inputLayout->setContentsMargins(6, 2, 6, 2);
    inputLayout->setSpacing(6);
    auto* prompt = new QLabel(QStringLiteral("命令"), m_inputRow);
    prompt->setFont(font);
    m_input = new QLineEdit(m_inputRow);
    m_input->setFont(font);
    m_input->setEnabled(false);
    inputLayout->addWidget(prompt);
    inputLayout->addWidget(m_input, 1);

    m_findBar = new QFrame(this);
    m_findBar->setObjectName(QStringLiteral("findBar"));
    m_findBar->setStyleSheet(QStringLiteral(
        "QFrame#findBar { background: white; border: 1px solid #c8c8c8; }"));
    auto* findLayout = new QHBoxLayout(m_findBar);
    findLayout->setContentsMargins(4, 2, 4, 2);
    findLayout->setSpacing(4);
    m_findEdit = new QLineEdit(m_findBar);
    m_findEdit->setFixedWidth(180);
    m_findEdit->setFont(font);
    m_findStatus = new QLabel(m_findBar);
    m_findStatus->setMinimumWidth(64);
    auto* findCase = new QToolButton(m_findBar);
    findCase->setText(QStringLiteral("Aa"));
    findCase->setCheckable(true);
    findCase->setAutoRaise(true);
    findCase->setToolTip(QStringLiteral("区分大小写"));
    auto* findPrevious = new QToolButton(m_findBar);
    findPrevious->setText(QStringLiteral("←"));
    findPrevious->setAutoRaise(true);
    findPrevious->setToolTip(QStringLiteral("上一个"));
    auto* findNextButton = new QToolButton(m_findBar);
    findNextButton->setText(QStringLiteral("→"));
    findNextButton->setAutoRaise(true);
    findNextButton->setToolTip(QStringLiteral("下一个"));
    auto* findClose = new QToolButton(m_findBar);
    findClose->setText(QStringLiteral("×"));
    findClose->setAutoRaise(true);
    findClose->setToolTip(QStringLiteral("关闭"));
    findLayout->addWidget(m_findEdit);
    findLayout->addWidget(m_findStatus);
    findLayout->addWidget(findCase);
    findLayout->addWidget(findPrevious);
    findLayout->addWidget(findNextButton);
    findLayout->addWidget(findClose);
    m_findBar->hide();
    m_findBar->adjustSize();

    layout->addWidget(m_output, 1);

    auto* findShortcut = new QShortcut(QKeySequence::Find, this);
    findShortcut->setContext(Qt::WidgetWithChildrenShortcut);
    connect(findShortcut, &QShortcut::activated, this, &CommandView::openFind);
    auto* findBarShortcut = new QShortcut(QKeySequence::Find, m_inputRow);
    findBarShortcut->setContext(Qt::WidgetWithChildrenShortcut);
    connect(findBarShortcut, &QShortcut::activated, this, &CommandView::openFind);
    connect(m_findEdit, &QLineEdit::textChanged, this, [this](const QString&)
    {
        if (m_findEdit->text().isEmpty())
        {
            m_findStatus->clear();
            return;
        }

        QTextCursor cursor = m_output->textCursor();
        cursor.movePosition(QTextCursor::Start);
        m_output->setTextCursor(cursor);
        findNext(true);
    });
    connect(findCase, &QToolButton::toggled, this, [this](bool checked)
    {
        m_findCase = checked;

        if (m_findEdit->text().isEmpty() == false)
        {
            QTextCursor cursor = m_output->textCursor();
            cursor.movePosition(QTextCursor::Start);
            m_output->setTextCursor(cursor);
            findNext(true);
        }
    });
    connect(findPrevious, &QToolButton::clicked, this, [this] { findNext(false); });
    connect(findNextButton, &QToolButton::clicked, this, [this] { findNext(true); });
    connect(findClose, &QToolButton::clicked, this, &CommandView::hideFind);

    m_popup = new QWidget(nullptr, Qt::Tool | Qt::FramelessWindowHint);
    auto* popupLayout = new QVBoxLayout(m_popup);
    popupLayout->setContentsMargins(0, 0, 0, 0);
    m_list = new QListWidget(m_popup);
    m_list->setFont(font);
    popupLayout->addWidget(m_list);
    m_popup->hide();

    connect(m_input, &QLineEdit::returnPressed, this, &CommandView::submit);
    connect(m_list, &QListWidget::itemActivated, this, [this](QListWidgetItem*)
    {
        acceptCompletion();
    });
    m_input->installEventFilter(this);
    m_findEdit->installEventFilter(this);
}

QWidget* CommandView::commandBar() const
{
    return m_inputRow;
}

void CommandView::openFind()
{
    m_findBar->show();
    placeFindBar();
    m_findEdit->setFocus();
    m_findEdit->selectAll();

    if (m_findEdit->text().isEmpty() == false)
    {
        QTextCursor cursor = m_output->textCursor();
        cursor.movePosition(QTextCursor::Start);
        m_output->setTextCursor(cursor);
        findNext(true);
    }
}

void CommandView::hideFind()
{
    m_findBar->hide();
    m_output->setFocus();
}

void CommandView::placeFindBar()
{
    m_findBar->adjustSize();
    const QRect output = m_output->geometry();
    m_findBar->move(output.right() - m_findBar->width() - 8, output.top() + 6);
    m_findBar->raise();
}

void CommandView::resizeEvent(QResizeEvent* event)
{
    QWidget::resizeEvent(event);

    if (m_findBar->isVisible())
    {
        placeFindBar();
    }
}

void CommandView::findNext(bool forward)
{
    const QString needle = m_findEdit->text();

    if (needle.isEmpty())
    {
        m_findStatus->clear();
        return;
    }

    QTextDocument::FindFlags flags;

    if (forward == false)
    {
        flags |= QTextDocument::FindBackward;
    }

    if (m_findCase)
    {
        flags |= QTextDocument::FindCaseSensitively;
    }

    QTextCursor cursor = m_output->textCursor();

    if (cursor.hasSelection())
    {
        cursor.setPosition(forward ? cursor.selectionEnd() : cursor.selectionStart());
    }

    QTextCursor found = m_output->document()->find(needle, cursor, flags);

    if (found.isNull())
    {
        QTextCursor wrap(m_output->document());

        if (forward == false)
        {
            wrap.movePosition(QTextCursor::End);
        }

        found = m_output->document()->find(needle, wrap, flags);
    }

    int total = 0;
    int current = 0;
    QTextCursor scan(m_output->document());
    QTextDocument::FindFlags countFlags = flags;
    countFlags.setFlag(QTextDocument::FindBackward, false);

    while (total < 100000)
    {
        scan = m_output->document()->find(needle, scan, countFlags);

        if (scan.isNull())
        {
            break;
        }

        ++total;

        if (found.isNull() == false && scan.selectionStart() == found.selectionStart())
        {
            current = total;
        }
    }

    if (found.isNull())
    {
        m_findStatus->setText(QStringLiteral("无匹配"));
        return;
    }

    m_output->setTextCursor(found);
    m_output->ensureCursorVisible();
    m_findStatus->setText(total >= 100000 ? QStringLiteral("%1+").arg(current) : QStringLiteral("%1/%2").arg(current).arg(total));
}

void CommandView::setSession(CoreSession* session)
{
    m_session = session;
}

void CommandView::setInputEnabled(bool enabled)
{
    m_input->setEnabled(enabled);
}

void CommandView::focusInput()
{
    m_input->setFocus();
}

void CommandView::appendRecords(const std::vector<CoreSession::OutputRecord>& records)
{
    for (const CoreSession::OutputRecord& record : records)
    {
        switch (record.kind)
        {
        case HacDbgOutputClear:
            clearOutput();
            break;

        case HacDbgOutputQuit:
            emit quitRequested();
            break;

        case HacDbgOutputWarning:
            appendChunk(QStringLiteral("warn, ") + record.text +
                            (record.text.endsWith('\n') ? QString() : QStringLiteral("\n")),
                        QColor(0xB8, 0x86, 0x0B),
                        false);
            break;

        case HacDbgOutputError:
        {
            QString text = record.text;

            if (text.startsWith(QStringLiteral("err,"), Qt::CaseInsensitive) == false)
            {
                text.prepend(QStringLiteral("err, "));
            }

            if (text.endsWith('\n') == false)
            {
                text.append('\n');
            }

            appendChunk(text, QColor(0xB0, 0x00, 0x20), false);
            break;
        }

        case HacDbgOutputInfo:
            appendChunk(record.text.endsWith('\n') ? record.text : record.text + QStringLiteral("\n"),
                        palette().color(QPalette::Text),
                        true);
            break;

        default:
            appendChunk(record.text, palette().color(QPalette::Text), true);
            break;
        }
    }
}

void CommandView::appendEcho(const QString& command)
{
    appendChunk(QStringLiteral("kd> ") + command + QStringLiteral("\n"), palette().color(QPalette::Text), false);
}

void CommandView::appendLocalError(const QString& message)
{
    appendChunk(QStringLiteral("err, ") + message + QStringLiteral("\n"), QColor(0xB0, 0x00, 0x20), false);
}

void CommandView::appendLocalWarning(const QString& message)
{
    appendChunk(QStringLiteral("warn, ") + message + QStringLiteral("\n"), QColor(0xB8, 0x86, 0x0B), false);
}

void CommandView::clearOutput()
{
    m_output->clear();
}

void CommandView::pollCompletions(CoreSession* session)
{
    if (session == nullptr || m_completionRequestId == 0)
    {
        return;
    }

    HACDBG_CORE_COMPLETION_STATUS status = {};

    if (session->getCompletionStatus(&status) == false ||
        status.Pending != 0 ||
        status.CompletedRequestId != m_completionRequestId)
    {
        return;
    }

    const std::uint64_t requestId = m_completionRequestId;
    std::vector<QString> items;

    if (session->copyCompletions(requestId, &items) == false || currentToken() != m_completionToken)
    {
        return;
    }

    m_completionRequestId = 0;

    if (status.Failed != 0 || items.empty())
    {
        closeCompletion();
        return;
    }

    const QString prefix = commonPrefix(items);

    if (prefix.size() > m_completionToken.size())
    {
        replaceToken(prefix);
        m_completionToken = prefix;
    }

    showCompletions(items);
}

void CommandView::submit()
{
    const QString command = m_input->text().trimmed();

    if (command.isEmpty())
    {
        return;
    }

    if (m_history.empty() || m_history.back() != command)
    {
        m_history.push_back(command);
    }

    m_historyIndex = static_cast<int>(m_history.size());
    m_input->clear();
    closeCompletion();
    emit commandSubmitted(command);
}

void CommandView::requestCompletion(CoreSession* session)
{
    if (m_input->isEnabled() == false)
    {
        return;
    }

    const QString token = currentToken();

    if (token.contains('!'))
    {
        if (session == nullptr || session->isStarted() == false)
        {
            return;
        }

        const std::uint64_t requestId = session->requestCompletions(token);

        if (requestId == 0)
        {
            return;
        }

        m_completionRequestId = requestId;
        m_completionToken = token;
        return;
    }

    std::vector<QString> items;

    if (session == nullptr || session->completeCommands(token, &items) == false || items.empty())
    {
        return;
    }

    const QString prefix = commonPrefix(items);

    if (prefix.size() > token.size())
    {
        replaceToken(prefix);
    }

    showCompletions(items);
}

void CommandView::showCompletions(const std::vector<QString>& items)
{
    m_list->clear();

    for (const QString& item : items)
    {
        m_list->addItem(item);
    }

    if (m_list->count() == 0)
    {
        closeCompletion();
        return;
    }

    m_list->setCurrentRow(0);
    m_popup->resize(qMax(m_input->width(), 280), qMin(240, 8 + m_list->count() * 20));
    m_popup->move(m_input->mapToGlobal(QPoint(0, m_input->height())));
    m_popup->show();
}

void CommandView::acceptCompletion()
{
    QListWidgetItem* item = m_list->currentItem();

    if (item == nullptr)
    {
        return;
    }

    QString text = item->text();

    if (text.contains('!') == false && text.endsWith(' ') == false)
    {
        text.append(' ');
    }

    replaceToken(text);
    closeCompletion();
    m_input->setFocus();
}

void CommandView::moveCompletion(int delta)
{
    if (m_list->count() == 0)
    {
        return;
    }

    int row = m_list->currentRow() + delta;

    if (row < 0)
    {
        row = m_list->count() - 1;
    }
    else if (row >= m_list->count())
    {
        row = 0;
    }

    m_list->setCurrentRow(row);
}

void CommandView::closeCompletion()
{
    m_popup->hide();
    m_completionRequestId = 0;
}

QString CommandView::currentToken() const
{
    const QString text = m_input->text();
    const int space = text.lastIndexOf(' ');
    return space < 0 ? text : text.mid(space + 1);
}

void CommandView::replaceToken(const QString& replacement)
{
    m_applyingCompletion = true;
    QString text = m_input->text();
    const int space = text.lastIndexOf(' ');
    text = (space < 0 ? QString() : text.left(space + 1)) + replacement;
    m_input->setText(text);
    m_input->setCursorPosition(text.size());
    m_applyingCompletion = false;
}

void CommandView::appendChunk(const QString& text, const QColor& color, bool scanLines)
{
    if (text.isEmpty())
    {
        return;
    }

    const bool follow = nearEnd();
    const int saved = m_output->verticalScrollBar()->value();
    QTextCursor cursor(m_output->document());
    cursor.movePosition(QTextCursor::End);
    cursor.beginEditBlock();
    int start = 0;

    while (start <= text.size())
    {
        const int end = text.indexOf('\n', start);
        const int stop = end < 0 ? text.size() : end;
        const QString line = text.mid(start, stop - start);
        QTextCharFormat format;
        format.setForeground(scanLines ? colorFor(line) : color);
        cursor.setCharFormat(format);
        cursor.insertText(line);

        if (end < 0)
        {
            break;
        }

        cursor.insertText(QStringLiteral("\n"));
        start = end + 1;

        if (start == text.size())
        {
            break;
        }
    }

    cursor.endEditBlock();

    if (follow)
    {
        m_output->verticalScrollBar()->setValue(m_output->verticalScrollBar()->maximum());
    }
    else
    {
        m_output->verticalScrollBar()->setValue(saved);
    }
}

bool CommandView::nearEnd() const
{
    const QScrollBar* bar = m_output->verticalScrollBar();
    const int line = qMax(1, m_output->fontMetrics().lineSpacing());
    return bar->maximum() - bar->value() <= line * 2;
}

QColor CommandView::colorFor(const QString& line) const
{
    if (line.contains(QStringLiteral("err,"), Qt::CaseInsensitive) ||
        line.contains(QStringLiteral("[error]"), Qt::CaseInsensitive))
    {
        return QColor(0xB0, 0x00, 0x20);
    }

    if (line.contains(QStringLiteral("warn,"), Qt::CaseInsensitive) ||
        line.contains(QStringLiteral("[warning]"), Qt::CaseInsensitive))
    {
        return QColor(0xB8, 0x86, 0x0B);
    }

    return palette().color(QPalette::Text);
}

bool CommandView::eventFilter(QObject* watched, QEvent* event)
{
    if (watched == m_findEdit && event->type() == QEvent::KeyPress)
    {
        auto* key = static_cast<QKeyEvent*>(event);

        if (key->key() == Qt::Key_Escape)
        {
            hideFind();
            return true;
        }

        if (key->key() == Qt::Key_Return || key->key() == Qt::Key_Enter)
        {
            findNext(key->modifiers().testFlag(Qt::ShiftModifier) == false);
            return true;
        }

        return QWidget::eventFilter(watched, event);
    }

    if (watched != m_input || event->type() != QEvent::KeyPress || m_applyingCompletion)
    {
        return QWidget::eventFilter(watched, event);
    }

    auto* key = static_cast<QKeyEvent*>(event);
    const bool popup = m_popup->isVisible() && m_list->count() > 0;

    if (key->key() == Qt::Key_Tab)
    {
        if (popup)
        {
            moveCompletion(key->modifiers().testFlag(Qt::ShiftModifier) ? -1 : 1);
        }
        else
        {
            requestCompletion(m_session);
        }

        return true;
    }

    if (popup && (key->key() == Qt::Key_Up || key->key() == Qt::Key_Down))
    {
        moveCompletion(key->key() == Qt::Key_Up ? -1 : 1);
        return true;
    }

    if (popup && (key->key() == Qt::Key_Return || key->key() == Qt::Key_Enter))
    {
        acceptCompletion();
        return true;
    }

    if (popup && key->key() == Qt::Key_Escape)
    {
        closeCompletion();
        return true;
    }

    if (key->key() != Qt::Key_Up && key->key() != Qt::Key_Down)
    {
        return QWidget::eventFilter(watched, event);
    }

    if (m_history.empty())
    {
        return true;
    }

    if (key->key() == Qt::Key_Up)
    {
        if (m_historyIndex > 0)
        {
            --m_historyIndex;
        }
    }
    else if (m_historyIndex < static_cast<int>(m_history.size()))
    {
        ++m_historyIndex;
    }

    m_input->setText(m_historyIndex >= static_cast<int>(m_history.size()) ? QString() : m_history[static_cast<std::size_t>(m_historyIndex)]);
    return true;
}
