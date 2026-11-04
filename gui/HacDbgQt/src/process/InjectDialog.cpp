#include "InjectDialog.h"

#include <QCheckBox>
#include <QFileDialog>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QRadioButton>
#include <QVBoxLayout>

InjectDialog::InjectDialog(std::uint64_t pid, QWidget* parent)
    : QDialog(parent)
{
    setWindowTitle(QStringLiteral("注入 DLL → PID=%1").arg(pid));
    setModal(true);

    auto* layout = new QVBoxLayout(this);
    layout->addWidget(new QLabel(QStringLiteral("注入 DLL → PID=%1").arg(pid), this));
    m_pte = new QRadioButton(QStringLiteral("PTE 注入"), this);
    m_apc = new QRadioButton(QStringLiteral("APC 注入"), this);
    m_pte->setChecked(true);
    layout->addWidget(m_pte);
    layout->addWidget(m_apc);
    m_poison = new QCheckBox(QStringLiteral("页面中毒隐藏"), this);
    layout->addWidget(m_poison);

    auto* pathRow = new QHBoxLayout();
    m_path = new QLineEdit(this);
    m_path->setPlaceholderText(QStringLiteral("C:\\path\\to\\inject.dll"));
    auto* browse = new QPushButton(QStringLiteral("浏览..."), this);
    pathRow->addWidget(m_path, 1);
    pathRow->addWidget(browse);
    layout->addLayout(pathRow);

    auto* buttons = new QHBoxLayout();
    auto* inject = new QPushButton(QStringLiteral("注入"), this);
    auto* cancel = new QPushButton(QStringLiteral("取消"), this);
    buttons->addWidget(inject);
    buttons->addWidget(cancel);
    layout->addLayout(buttons);

    connect(browse, &QPushButton::clicked, this, [this]() {
        const QString file = QFileDialog::getOpenFileName(this, QStringLiteral("选择 DLL"), QString(),
                                                          QStringLiteral("DLL (*.dll)"));
        if (file.isEmpty() == false)
        {
            m_path->setText(file);
        }
    });
    connect(inject, &QPushButton::clicked, this, &QDialog::accept);
    connect(cancel, &QPushButton::clicked, this, &QDialog::reject);
}

bool InjectDialog::pteMethod() const
{
    return m_pte->isChecked();
}

bool InjectDialog::poisonPage() const
{
    return m_poison->isChecked();
}

QString InjectDialog::dllPath() const
{
    return m_path->text().trimmed();
}
