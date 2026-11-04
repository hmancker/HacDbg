#pragma once

#include <QString>
#include <QWidget>

#include <cstdint>
#include <vector>

class QCheckBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QStandardItemModel;
class QTableView;

class WindowProtectView : public QWidget
{
    Q_OBJECT

public:
    explicit WindowProtectView(QWidget* parent = nullptr);

    void refresh();
    void protectProcess(std::uint32_t pid);

private:
    struct WindowItem
    {
        std::uintptr_t hwnd = 0;
        std::uint32_t pid = 0;
        unsigned long affinity = 0;
        bool affinityKnown = false;
        bool dwmProtected = false;
        QString title;
        QString className;
        QString image;
    };

    void reloadRows();
    void showRows();
    void applySelected(bool enable);
    void toggleHook();
    bool matches(const WindowItem& item) const;
    void setStatus(const QString& text);
    static QString affinityText(unsigned long affinity);

    QLineEdit* m_filter = nullptr;
    QCheckBox* m_protectedOnly = nullptr;
    QLabel* m_status = nullptr;
    QPushButton* m_hookButton = nullptr;
    QTableView* m_table = nullptr;
    QStandardItemModel* m_model = nullptr;
    std::vector<WindowItem> m_rows;
    std::vector<WindowItem> m_visible;
    bool m_hookArmed = false;
    bool m_driverPresent = false;
    bool m_recalibrate = false;
    std::uint32_t m_ownerPid = 0;
};
