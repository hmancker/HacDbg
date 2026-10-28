#pragma once

#include <QAbstractScrollArea>

#include <hacdbg_core_api.h>

#include <cstdint>

class RegisterView : public QAbstractScrollArea
{
    Q_OBJECT

public:
    explicit RegisterView(QWidget* parent = nullptr);

    void setRegisters(const HACDBG_CORE_REGISTERS& registers, bool paused);

signals:
    void ripActivated(std::uint64_t address);

protected:
    void resizeEvent(QResizeEvent* event) override;
    bool eventFilter(QObject* watched, QEvent* event) override;

private:
    struct Line
    {
        const char* name = "";
        std::uint64_t value = 0;
        bool known = false;
        bool changed = false;
    };

    int lineHeight() const;
    void updateScroll();

    Line m_lines[20] = {};
    bool m_flagKnown = false;
    bool m_flagChanged[9] = {};
    int m_flagValue[9] = {};
    bool m_havePrevious = false;
    bool m_previousPaused = false;
    std::uint64_t m_previous[20] = {};
    bool m_previousKnown[20] = {};
    std::uint64_t m_previousRflags = 0;
    bool m_previousRflagsKnown = false;
};
