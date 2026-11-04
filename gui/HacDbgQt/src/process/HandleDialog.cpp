#include "HandleDialog.h"

#include <QFileInfo>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QRadioButton>
#include <QVBoxLayout>

HandleDialog::HandleDialog(bool upgrade, const QString& image, QWidget* parent)
    : QDialog(parent)
{
    const QString title = upgrade ? QStringLiteral("句柄提权") : QStringLiteral("句柄降权");
    QString actor = QFileInfo(image).fileName().trimmed();
    if (actor.isEmpty())
    {
        actor = QStringLiteral("cheatengine");
    }

    setWindowTitle(title);
    setModal(true);

    auto* layout = new QVBoxLayout(this);
    layout->addWidget(new QLabel(QStringLiteral("执行程序是持有句柄的程序。目标是句柄指向的进程。"), this));
    layout->addWidget(new QLabel(QStringLiteral("按映像名前 15 个字符匹配，可写成 cheatengine 或 x64dbg。"), this));
    layout->addWidget(new QLabel(QStringLiteral("设置后每 5 秒重复，直到点「停止」。"), this));

    layout->addWidget(new QLabel(QStringLiteral("执行程序"), this));
    m_actor = new QLineEdit(actor, this);
    m_actor->setMaxLength(63);
    m_actor->setPlaceholderText(QStringLiteral("cheatengine"));
    layout->addWidget(m_actor);

    m_all = new QRadioButton(QStringLiteral("其他全部进程"), this);
    m_named = new QRadioButton(QStringLiteral("指定进程"), this);
    m_all->setChecked(true);
    layout->addWidget(m_all);
    layout->addWidget(m_named);

    layout->addWidget(new QLabel(QStringLiteral("目标进程"), this));
    m_victim = new QLineEdit(this);
    m_victim->setMaxLength(63);
    m_victim->setEnabled(false);
    m_victim->setPlaceholderText(QStringLiteral("notepad"));
    layout->addWidget(m_victim);

    auto* buttons = new QHBoxLayout();
    auto* accept = new QPushButton(QStringLiteral("确定"), this);
    auto* cancel = new QPushButton(QStringLiteral("取消"), this);
    buttons->addWidget(accept);
    buttons->addWidget(cancel);
    layout->addLayout(buttons);

    connect(m_named, &QRadioButton::toggled, m_victim, &QLineEdit::setEnabled);
    connect(cancel, &QPushButton::clicked, this, &QDialog::reject);
    connect(accept, &QPushButton::clicked, this, [this]() {
        if (m_actor->text().trimmed().isEmpty())
        {
            QMessageBox::warning(this, windowTitle(), QStringLiteral("请输入执行程序。"));
            return;
        }

        if (m_named->isChecked() && m_victim->text().trimmed().isEmpty())
        {
            QMessageBox::warning(this, windowTitle(), QStringLiteral("请输入目标进程。"));
            return;
        }

        QDialog::accept();
    });
}

QString HandleDialog::actor() const
{
    return m_actor->text().trimmed();
}

bool HandleDialog::allProcesses() const
{
    return m_all->isChecked();
}

QString HandleDialog::victim() const
{
    return m_victim->text().trimmed();
}
