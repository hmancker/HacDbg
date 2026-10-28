#pragma once

#include "CoreSession.h"

#include <QWidget>

#include <cstdint>
#include <vector>

class DisassemblyView;
class HexDumpView;
class QLabel;
class QLineEdit;
class QPushButton;
class QTimer;
class RegisterView;
class StackView;

class CpuView : public QWidget
{
    Q_OBJECT

public:
    explicit CpuView(QWidget* parent = nullptr);

    void setSession(CoreSession* session);
    void onState(const HACDBG_CORE_STATE& state);
    void poll();
    void openAt(std::uint64_t address, std::uint64_t cr3);

private:
    struct MemoryPage
    {
        std::uint64_t address = 0;
        std::uint64_t cr3 = 0;
        std::vector<std::uint8_t> bytes;
    };

    void showGoto();
    void hideGoto();
    void submitGoto(bool memory);
    void requestDisassembly(std::uint64_t address, std::uint64_t cr3, bool follow = false);
    void requestMemory(std::uint64_t address, std::uint64_t cr3, int highlightBytes);
    void scheduleFollow();
    void flushFollow();
    void showMemory(const MemoryPage& page);
    void noteSelection();
    bool takeCompleted(std::uint32_t view, std::uint64_t* requestId, HACDBG_CORE_VIEW_STATUS* status);
    void setDisassemblyStatus(const QString& text);
    void setMemoryStatus(const QString& text);

    CoreSession* m_session = nullptr;
    DisassemblyView* m_disassembly = nullptr;
    RegisterView* m_registers = nullptr;
    HexDumpView* m_dump = nullptr;
    StackView* m_stack = nullptr;
    QWidget* m_disasmGoto = nullptr;
    QWidget* m_memoryGoto = nullptr;
    QLineEdit* m_disasmAddress = nullptr;
    QLineEdit* m_disasmCr3 = nullptr;
    QLineEdit* m_memoryAddress = nullptr;
    QLineEdit* m_memoryCr3Edit = nullptr;
    QLabel* m_status = nullptr;
    QLabel* m_info = nullptr;
    QLabel* m_memoryStatus = nullptr;
    QLabel* m_stackStatus = nullptr;

    QTimer* m_followTimer = nullptr;
    std::uint64_t m_disassemblyRequest = 0;
    std::uint64_t m_memoryRequest = 0;
    std::uint64_t m_stackRequest = 0;
    std::uint64_t m_resolveRequest = 0;
    std::uint64_t m_resolveCr3 = 0;
    std::uint64_t m_disassemblyCr3 = 0;
    std::uint64_t m_pausedCr3 = 0;
    std::uint64_t m_lastRip = 0;
    std::uint64_t m_lastRsp = 0;
    std::uint64_t m_stackRsp = 0;
    std::uint64_t m_stackCr3 = 0;
    bool m_followRip = false;
    bool m_disassemblyStale = false;
    bool m_stackStale = false;
    std::uint64_t m_memoryCursor = 0;
    std::uint64_t m_memoryCr3 = 0;
    int m_memoryCursorBytes = 1;
    bool m_resolveForMemory = false;
    bool m_paused = false;
    bool m_suppressSelection = false;
    std::vector<MemoryPage> m_memoryCache;
    std::vector<std::uint64_t> m_breakpoints;
};
