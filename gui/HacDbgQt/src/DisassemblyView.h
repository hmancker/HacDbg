#pragma once

#include <QAbstractScrollArea>

#include <cstdint>
#include <vector>

class DisassemblyView : public QAbstractScrollArea
{
    Q_OBJECT

public:
    struct Row
    {
        std::uint64_t address = 0;
        std::uint32_t length = 0;
        QString bytes;
        QString text;
        QString symbol;
        std::uint64_t jumpTarget = 0;
        bool hasJump = false;
    };

    explicit DisassemblyView(QWidget* parent = nullptr);

    void setRows(std::vector<Row> rows, std::uint64_t rip, const std::vector<std::uint64_t>& breakpoints);
    void setRip(std::uint64_t rip, const std::vector<std::uint64_t>& breakpoints);
    bool containsAddress(std::uint64_t address) const;
    const Row* rowForAddress(std::uint64_t address) const;
    const Row* selectedRow() const;
    std::uint64_t firstAddress() const;
    std::uint64_t lastEnd() const;

signals:
    void selectionChanged();

protected:
    void resizeEvent(QResizeEvent* event) override;
    void keyPressEvent(QKeyEvent* event) override;
    bool eventFilter(QObject* watched, QEvent* event) override;

private:
    int rowHeight() const;
    int visibleRows() const;
    void updateScroll();
    void scrollToRow(int row);
    int rowAt(int y) const;
    QColor mnemonicColor(const QString& text) const;

    std::vector<Row> m_rows;
    std::vector<std::uint64_t> m_breakpoints;
    std::uint64_t m_rip = 0;
    int m_selected = -1;
    int m_bytesWidth = 0;
};
