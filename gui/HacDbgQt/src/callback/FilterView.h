#pragma once

#include <QWidget>

#include <cstdint>
#include <vector>

#include "kernel_filter.h"

class QComboBox;
class QLabel;
class QLineEdit;
class QStandardItem;
class QStandardItemModel;
class QTreeView;

class FilterView : public QWidget
{
    Q_OBJECT

public:
    explicit FilterView(QWidget* parent = nullptr);

    void refresh();

signals:
    void addressActivated(quint64 address, quint64 cr3);

private:
    struct Row
    {
        unsigned int typeId = 0;
        unsigned int depth = 0;
        unsigned int parent = HACDBG_FILTER_NO_PARENT;
        quint64 driverObjectValue = 0;
        quint64 deviceObjectValue = 0;
        quint64 hostDeviceObjectValue = 0;
        QString driverName;
        QString type;
        QString path;
        QString driverObject;
        QString deviceName;
        QString deviceObject;
        QString hostDriverName;
        QString hostDriverObject;
        QString hostDeviceObject;
        QString company;
        QString description;
    };

    void showRows();
    void showMenu(const QPoint& point);
    void detachRow(const Row& row);
    void showDevices(const Row& row);
    void showDispatch(const Row& row);
    void exportShown(int kind);
    bool matches(std::size_t index) const;
    bool systemModule(const Row& row) const;
    int rowIndex(const QModelIndex& index) const;

    QComboBox* m_type = nullptr;
    QLineEdit* m_filter = nullptr;
    QLabel* m_status = nullptr;
    QTreeView* m_table = nullptr;
    QStandardItemModel* m_model = nullptr;
    std::vector<Row> m_rows;
    bool m_scanned = false;
    bool m_truncated = false;
    bool m_hideSystem = false;
};
