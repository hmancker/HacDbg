#include "CoreSession.h"
#include "MainWindow.h"

#include <QApplication>
#include <QPalette>
#include <QStyleFactory>

#include <Windows.h>

namespace
{
bool hasArgument(int argc, char** argv, const char* name)
{
    for (int index = 1; index < argc; ++index)
    {
        if (QString::fromLocal8Bit(argv[index]).compare(QString::fromLatin1(name), Qt::CaseInsensitive) == 0)
        {
            return true;
        }
    }

    return false;
}

std::wstring executableDirectory()
{
    wchar_t path[MAX_PATH] = {};
    const DWORD length = GetModuleFileNameW(nullptr, path, MAX_PATH);
    std::wstring directory(path, length);
    const std::size_t slash = directory.find_last_of(L"\\/");

    if (slash != std::wstring::npos)
    {
        directory.resize(slash);
    }

    return directory;
}
}

int main(int argc, char** argv)
{
    if (hasArgument(argc, argv, "--abi-check"))
    {
        QString error;
        return CoreSession::checkAbi(executableDirectory().c_str(), &error);
    }

    QApplication application(argc, argv);
    application.setStyle(QStyleFactory::create(QStringLiteral("Fusion")));
    QPalette palette;
    palette.setColor(QPalette::Window, QColor(0xF3, 0xF3, 0xF3));
    palette.setColor(QPalette::WindowText, Qt::black);
    palette.setColor(QPalette::Base, Qt::white);
    palette.setColor(QPalette::AlternateBase, QColor(0xF7, 0xF7, 0xF7));
    palette.setColor(QPalette::Text, Qt::black);
    palette.setColor(QPalette::Button, QColor(0xF3, 0xF3, 0xF3));
    palette.setColor(QPalette::ButtonText, Qt::black);
    palette.setColor(QPalette::Highlight, QColor(0x1A, 0x5F, 0xB4));
    palette.setColor(QPalette::HighlightedText, Qt::white);
    application.setPalette(palette);

    MainWindow window(hasArgument(argc, argv, "--no-connect") == false);
    window.show();
    return application.exec();
}
