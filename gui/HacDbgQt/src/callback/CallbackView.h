#pragma once

#include <QWidget>

#include <cstdint>
#include <vector>

#include "kernel_callback.h"

class QComboBox;
class QLabel;
class QLineEdit;
class QStandardItemModel;
class QTableView;

class CallbackView : public QWidget
{
    Q_OBJECT

public:
    explicit CallbackView(QWidget* parent = nullptr);

    void refresh();

signals:
    void addressActivated(quint64 address, quint64 cr3);
    void commandRequested(const QString& command);

private:
    struct Row
    {
        unsigned int typeId = 0;
        std::uint64_t entryValue = 0;
        std::uint64_t extraValue = 0;
        unsigned int state = 0;
        QString entry;
        QString type;
        QString stateText;
        QString path;
        QString company;
        QString version;
        QString extra;
        QString description;
    };

    void showRows();
    void showMenu(const QPoint& point);
    void exportShown(int kind);
    void editRow(const Row& row, unsigned int operation, const QString& title);
    bool matches(const Row& row) const;
    bool systemModule(const Row& row) const;
    int shownIndex(const QModelIndex& index) const;

    QComboBox* m_type = nullptr;
    QLineEdit* m_filter = nullptr;
    QLabel* m_status = nullptr;
    QTableView* m_table = nullptr;
    QStandardItemModel* m_model = nullptr;
    std::vector<Row> m_rows;
    std::vector<Row> m_marks;
    std::vector<std::size_t> m_shown;
    bool m_scanned = false;
    bool m_truncated = false;
    bool m_hideSystem = false;
};
