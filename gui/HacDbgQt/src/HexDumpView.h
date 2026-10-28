#pragma once

#include <QAbstractScrollArea>

#include <cstdint>
#include <vector>

class HexDumpView : public QAbstractScrollArea
{
    Q_OBJECT

public:
    explicit HexDumpView(QWidget* parent = nullptr);

    void setBytes(std::uint64_t base, std::uint64_t cursor, int cursorBytes, std::vector<std::uint8_t> bytes);

protected:
    void resizeEvent(QResizeEvent* event) override;
    bool eventFilter(QObject* watched, QEvent* event) override;

private:
    int rowHeight() const;
    void updateScroll();

    std::uint64_t m_base = 0;
    std::uint64_t m_cursor = 0;
    int m_cursorBytes = 1;
    std::vector<std::uint8_t> m_bytes;
};
