#pragma once

#include <sstream>
#include <string>

void mapper_log_write(const std::string& text);

class KdmLogProxy
{
public:
	KdmLogProxy() = default;

	~KdmLogProxy()
	{
		std::wstring wide = m_ss.str();
		if (wide.empty())
		{
			return;
		}

		std::string text;
		text.reserve(wide.size());
		for (wchar_t ch : wide)
		{
			if (ch == L'\r')
			{
				continue;
			}

			if (ch == L'\n')
			{
				if (!text.empty())
				{
					emit(text);
					text.clear();
				}

				continue;
			}

			if (ch < 0x80)
			{
				text.push_back(static_cast<char>(ch));
			}
			else
			{
				text.push_back('?');
			}
		}

		if (!text.empty())
		{
			emit(text);
		}
	}

	KdmLogProxy& operator<<(const wchar_t* val)
	{
		if (val)
		{
			m_ss << val;
		}

		return *this;
	}

	KdmLogProxy& operator<<(const std::wstring& val)
	{
		m_ss << val;
		return *this;
	}

	KdmLogProxy& operator<<(const char* val)
	{
		if (val)
		{
			while (*val)
			{
				m_ss.put(static_cast<wchar_t>(static_cast<unsigned char>(*val++)));
			}
		}

		return *this;
	}

	KdmLogProxy& operator<<(const std::string& val)
	{
		for (unsigned char c : val)
		{
			m_ss.put(static_cast<wchar_t>(c));
		}

		return *this;
	}

	KdmLogProxy& operator<<(std::wostream& (*pf)(std::wostream&))
	{
		pf(m_ss);
		return *this;
	}

	KdmLogProxy& operator<<(std::ios_base& (*pf)(std::ios_base&))
	{
		pf(m_ss);
		return *this;
	}

	template<typename T>
	KdmLogProxy& operator<<(const T& val)
	{
		m_ss << val;
		return *this;
	}

private:
	static void emit(const std::string& text)
	{
		mapper_log_write(text);
	}

	std::wostringstream m_ss;
};

#if defined(DISABLE_OUTPUT)
#define kdmLog(content)
#else
#define kdmLog(content) do { KdmLogProxy() << content; } while (0)
#endif
