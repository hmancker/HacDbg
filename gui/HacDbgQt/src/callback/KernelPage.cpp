#include "KernelPage.h"

#include "CallbackView.h"
#include "FilterView.h"
#include "MinifilterView.h"
#include "TimerView.h"

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
    m_minifilters = new MinifilterView(m_tabs);
    m_timers = new TimerView(m_tabs);
    m_tabs->addTab(m_callbacks, QStringLiteral("Callbacks"));
    m_tabs->addTab(m_filters, QStringLiteral("Filters"));
    m_tabs->addTab(m_minifilters, QStringLiteral("Minifilters"));
    m_tabs->addTab(m_timers, QStringLiteral("Timers"));
    layout->addWidget(m_tabs);

    connect(m_callbacks, &CallbackView::addressActivated, this, &KernelPage::addressActivated);
    connect(m_callbacks, &CallbackView::commandRequested, this, &KernelPage::commandRequested);
    connect(m_filters, &FilterView::addressActivated, this, &KernelPage::addressActivated);
    connect(m_minifilters, &MinifilterView::addressActivated, this, &KernelPage::addressActivated);
    connect(m_timers, &TimerView::addressActivated, this, &KernelPage::addressActivated);
    connect(m_timers, &TimerView::commandRequested, this, &KernelPage::commandRequested);
    connect(m_tabs, &QTabWidget::currentChanged, this, [this](int index) {
        if (index == 1 && m_filtersLoaded == false)
        {
            m_filtersLoaded = true;
            m_filters->refresh();
        }
        else if (index == 2 && m_minifiltersLoaded == false)
        {
            m_minifiltersLoaded = true;
            m_minifilters->refresh();
        }
        else if (index == 3 && m_timersLoaded == false)
        {
            m_timersLoaded = true;
            m_timers->refresh();
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

    if (m_tabs->currentIndex() == 1)
    {
        m_filtersLoaded = true;
        m_filters->refresh();
        return;
    }

    if (m_tabs->currentIndex() == 2)
    {
        m_minifiltersLoaded = true;
        m_minifilters->refresh();
        return;
    }

    m_timersLoaded = true;
    m_timers->refresh();
}
