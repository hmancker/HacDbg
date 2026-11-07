#pragma once

#include <QWidget>

#include <vector>

#include "kernel_timer.h"

class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QStandardItemModel;
class QTableView;

class TimerView : public QWidget
{
    Q_OBJECT

public:
    explicit TimerView(QWidget* parent = nullptr);

    void refresh();

signals:
    void addressActivated(quint64 address, quint64 cr3);
    void commandRequested(const QString& command);

private:
    struct Row
    {
        unsigned int typeId = 0;
        unsigned int period = 0;
        unsigned int running = 0;
        quint64 callbackValue = 0;
        quint64 dpcValue = 0;
        quint64 timerValue = 0;
        QString callback;
        QString type;
        QString periodText;
        QString state;
        QString path;
        QString dpc;
        QString timer;
        QString company;
        QString description;
    };

    void showRows();
    void showMenu(const QPoint& point);
    void exportShown(int kind);
    bool matches(const Row& row) const;
    bool systemModule(const Row& row) const;
    int rowIndex(const QModelIndex& index) const;

    QComboBox* m_type = nullptr;
    QLineEdit* m_filter = nullptr;
    QCheckBox* m_regex = nullptr;
    QLabel* m_count = nullptr;
    QLabel* m_status = nullptr;
    QTableView* m_table = nullptr;
    QStandardItemModel* m_model = nullptr;
    std::vector<Row> m_rows;
    bool m_scanned = false;
    bool m_truncated = false;
    bool m_hideSystem = false;
};
