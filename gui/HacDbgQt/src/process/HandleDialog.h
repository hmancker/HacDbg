#pragma once

#include <QDialog>

class QLineEdit;
class QRadioButton;

class HandleDialog : public QDialog
{
    Q_OBJECT

public:
    explicit HandleDialog(bool upgrade, const QString& image, QWidget* parent = nullptr);

    QString actor() const;
    bool allProcesses() const;
    QString victim() const;

private:
    QLineEdit* m_actor = nullptr;
    QRadioButton* m_all = nullptr;
    QRadioButton* m_named = nullptr;
    QLineEdit* m_victim = nullptr;
};
