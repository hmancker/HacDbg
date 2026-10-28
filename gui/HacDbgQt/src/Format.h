#pragma once

#include <QString>

#include <cstdint>

inline QString fromField(const char* text, int capacity)
{
    int length = 0;

    if (text == nullptr || capacity <= 0)
    {
        return {};
    }

    while (length < capacity && text[length] != '\0')
    {
        ++length;
    }

    return QString::fromUtf8(text, length);
}

inline QString hex16(std::uint64_t value)
{
    return QStringLiteral("0x") +
           QStringLiteral("%1").arg(value, 16, 16, QLatin1Char('0')).toUpper();
}

inline bool parseHex(const QString& text, std::uint64_t* value, bool emptyIsZero)
{
    QString trimmed = text.trimmed();

    if (trimmed.isEmpty())
    {
        if (emptyIsZero == false || value == nullptr)
        {
            return false;
        }

        *value = 0;
        return true;
    }

    if (trimmed.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
    {
        trimmed = trimmed.mid(2);
    }

    bool ok = false;
    const std::uint64_t parsed = trimmed.toULongLong(&ok, 16);

    if (ok == false || value == nullptr)
    {
        return false;
    }

    *value = parsed;
    return true;
}
