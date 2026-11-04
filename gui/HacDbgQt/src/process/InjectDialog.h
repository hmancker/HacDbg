#pragma once

#include <QDialog>

#include <cstdint>

class QCheckBox;
class QLineEdit;
class QRadioButton;

class InjectDialog : public QDialog
{
    Q_OBJECT

public:
    explicit InjectDialog(std::uint64_t pid, QWidget* parent = nullptr);

    bool pteMethod() const;
    bool poisonPage() const;
    QString dllPath() const;

private:
    QRadioButton* m_pte = nullptr;
    QRadioButton* m_apc = nullptr;
    QCheckBox* m_poison = nullptr;
    QLineEdit* m_path = nullptr;
};
