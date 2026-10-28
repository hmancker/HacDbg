#pragma once

#include <QTableView>

#include <hacdbg_core_api.h>

#include <cstdint>
#include <vector>

class QStandardItemModel;

class StackView : public QTableView
{
    Q_OBJECT

public:
    explicit StackView(QWidget* parent = nullptr);

    void setFrames(const HACDBG_CORE_STACK_FRAME* frames, std::uint32_t count);

signals:
    void addressActivated(std::uint64_t address);

private:
    QStandardItemModel* m_model = nullptr;
    std::vector<std::uint64_t> m_addresses;
};
