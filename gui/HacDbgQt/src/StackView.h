#pragma once

#include <QAbstractScrollArea>
#include <QString>

#include <hacdbg_core_api.h>

#include <cstdint>
#include <vector>

class QPainter;

class StackView : public QAbstractScrollArea
{
    Q_OBJECT

public:
    explicit StackView(QWidget* parent = nullptr);

    void setSnapshot(const HACDBG_CORE_STACK_FRAME* frames, std::uint32_t count, std::uint64_t base, std::uint64_t rsp,
                     const std::uint8_t* bytes, std::uint32_t byteCount);
    bool hasFrames() const;

signals:
    void addressActivated(std::uint64_t address);

protected:
    void resizeEvent(QResizeEvent* event) override;
    bool eventFilter(QObject* watched, QEvent* event) override;

private:
    struct Note
    {
        std::uint64_t slot = 0;
        QString text;
    };

    struct Span
    {
        std::uint64_t start = 0;
        std::uint64_t end = 0;
        bool kernel = false;
    };

    struct Row
    {
        std::uint64_t address = 0;
        std::uint64_t value = 0;
        QString comment;
        int bracket = 0;
        bool kernel = false;
        bool isReturn = false;
        bool rsp = false;
    };

    void addRow(std::uint64_t address, std::uint64_t value, std::uint64_t rsp, const std::vector<Note>& notes,
                const std::vector<Span>& spans);
    int rowHeight() const;
    int rowAt(int y) const;
    void updateScroll();
    void paintRows(QPainter& painter) const;

    std::vector<Row> m_rows;
    int m_selected = -1;
};
