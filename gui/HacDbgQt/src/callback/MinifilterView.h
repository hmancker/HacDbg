#pragma once

#include <QWidget>

#include <cstdint>
#include <vector>

#include "kernel_minifilter.h"

class QLabel;
class QLineEdit;
class QStandardItemModel;
class QTreeView;

class MinifilterView : public QWidget
{
    Q_OBJECT

public:
    explicit MinifilterView(QWidget* parent = nullptr);

    void refresh();

signals:
    void addressActivated(quint64 address, quint64 cr3);

private:
    struct Row
    {
        quint64 filterValue = 0;
        quint64 callbackValue = 0;
        unsigned int parent = HACDBG_MINIFILTER_NO_PARENT;
        QString name;
        QString callback;
        QString path;
        QString company;
        QString description;
        QString filter;
        QString altitude;
    };

    void showRows();
    void showMenu(const QPoint& point);
    void changeFilter(const Row& row, unsigned int operation, const QString& title);
    void exportShown(int kind);
    bool systemModule(const Row& row) const;
    int rowIndex(const QModelIndex& index) const;

    QLineEdit* m_filter = nullptr;
    QLabel* m_status = nullptr;
    QTreeView* m_table = nullptr;
    QStandardItemModel* m_model = nullptr;
    std::vector<Row> m_rows;
    bool m_scanned = false;
    bool m_truncated = false;
    bool m_hideSystem = false;
};
