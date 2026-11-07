#pragma once

#include <QWidget>

class CallbackView;
class FilterView;
class MinifilterView;
class TimerView;
class QTabWidget;

class KernelPage : public QWidget
{
    Q_OBJECT

public:
    explicit KernelPage(QWidget* parent = nullptr);

    void refresh();

signals:
    void addressActivated(quint64 address, quint64 cr3);
    void commandRequested(const QString& command);

private:
    QTabWidget* m_tabs = nullptr;
    CallbackView* m_callbacks = nullptr;
    FilterView* m_filters = nullptr;
    MinifilterView* m_minifilters = nullptr;
    TimerView* m_timers = nullptr;
    bool m_filtersLoaded = false;
    bool m_minifiltersLoaded = false;
    bool m_timersLoaded = false;
};
