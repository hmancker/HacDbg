#pragma once

#include "CoreSession.h"

#include <QWidget>

#include <vector>

class QLabel;
class QLineEdit;
class QListWidget;
class QPlainTextEdit;
class QResizeEvent;

class CommandView : public QWidget
{
    Q_OBJECT

public:
    explicit CommandView(QWidget* parent = nullptr);

    void setSession(CoreSession* session);
    void setInputEnabled(bool enabled);
    void focusInput();
    QWidget* commandBar() const;
    void openFind();
    void appendRecords(const std::vector<CoreSession::OutputRecord>& records);
    void appendEcho(const QString& command);
    void appendLocalError(const QString& message);
    void appendLocalWarning(const QString& message);
    void clearOutput();
    void pollCompletions(CoreSession* session);

signals:
    void commandSubmitted(const QString& command);
    void interruptRequested();
    void quitRequested();

private:
    void submit();
    void hideFind();
    void findNext(bool forward);
    void requestCompletion(CoreSession* session);
    void showCompletions(const std::vector<QString>& items);
    void acceptCompletion();
    void moveCompletion(int delta);
    void closeCompletion();
    QString currentToken() const;
    void replaceToken(const QString& replacement);
    void appendChunk(const QString& text, const QColor& color, bool scanLines);
    bool nearEnd() const;
    QColor colorFor(const QString& line) const;
    void placeFindBar();
    void resizeEvent(QResizeEvent* event) override;
    bool eventFilter(QObject* watched, QEvent* event) override;

    CoreSession* m_session = nullptr;
    QPlainTextEdit* m_output = nullptr;
    QWidget* m_inputRow = nullptr;
    QLineEdit* m_input = nullptr;
    QWidget* m_findBar = nullptr;
    QLineEdit* m_findEdit = nullptr;
    QLabel* m_findStatus = nullptr;
    QWidget* m_popup = nullptr;
    QListWidget* m_list = nullptr;
    bool m_findCase = false;
    std::vector<QString> m_history;
    int m_historyIndex = 0;
    std::uint64_t m_completionRequestId = 0;
    QString m_completionToken;
    bool m_applyingCompletion = false;
};
