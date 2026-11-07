#include "KernelPage.h"

#include "CallbackView.h"
#include "FilterView.h"

#include <QTabWidget>
#include <QVBoxLayout>

KernelPage::KernelPage(QWidget* parent)
    : QWidget(parent)
{
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    m_tabs = new QTabWidget(this);
    m_callbacks = new CallbackView(m_tabs);
    m_filters = new FilterView(m_tabs);
    m_tabs->addTab(m_callbacks, QStringLiteral("Callbacks"));
    m_tabs->addTab(m_filters, QStringLiteral("Filters"));
    layout->addWidget(m_tabs);

    connect(m_callbacks, &CallbackView::addressActivated, this, &KernelPage::addressActivated);
    connect(m_callbacks, &CallbackView::commandRequested, this, &KernelPage::commandRequested);
    connect(m_filters, &FilterView::addressActivated, this, &KernelPage::addressActivated);
    connect(m_tabs, &QTabWidget::currentChanged, this, [this](int index) {
        if (index == 1 && m_filtersLoaded == false)
        {
            m_filtersLoaded = true;
            m_filters->refresh();
        }
    });
}

void KernelPage::refresh()
{
    if (m_tabs->currentIndex() == 0)
    {
        m_callbacks->refresh();
        return;
    }

    m_filtersLoaded = true;
    m_filters->refresh();
}
