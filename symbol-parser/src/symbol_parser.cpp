#include "symbol_parser.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#define _NO_CVCONST_H
#include <dbghelp.h>
#include <winhttp.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <mutex>

#pragma comment(lib, "winhttp.lib")

#pragma comment(lib, "dbghelp.lib")

namespace
{
	std::mutex session_mutex = {};
	std::uint8_t (*interrupt_check)() = nullptr;
	std::string search_path_text = "SRV*C:\\Symbols*https://msdl.microsoft.com/download/symbols";
	std::uint8_t session_ready = 0;

	struct loaded_module_t
	{
		std::string name = {};
		std::string stem = {};
		std::uint64_t base = 0;
		std::uint32_t size = 0;
		std::string pdb_path = {};
	};

	std::vector<loaded_module_t> modules = {};

	struct codeview_rsds_t
	{
		std::uint32_t signature = 0;
		GUID guid = {};
		std::uint32_t age = 0;
		char pdb_name[1] = {};
	};

	std::string narrow(const std::wstring& text)
	{
		if (text.empty() == true)
		{
			return {};
		}

		const int size = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);

		if (size <= 0)
		{
			return {};
		}

		std::string result(static_cast<std::size_t>(size), '\0');
		WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), result.data(), size, nullptr, nullptr);

		return result;
	}

	std::wstring widen(const std::string& text)
	{
		if (text.empty() == true)
		{
			return {};
		}

		const int size = MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);

		if (size <= 0)
		{
			return {};
		}

		std::wstring result(static_cast<std::size_t>(size), L'\0');
		MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), result.data(), size);

		return result;
	}

	std::uint8_t same_text(const std::string_view left, const std::string_view right)
	{
		if (left.size() != right.size())
		{
			return 0;
		}

		for (std::size_t index = 0; index < left.size(); index++)
		{
			const auto lhs = static_cast<unsigned char>(left[index]);
			const auto rhs = static_cast<unsigned char>(right[index]);

			if (std::tolower(lhs) != std::tolower(rhs))
			{
				return 0;
			}
		}

		return 1;
	}

	std::string file_stem(const std::string_view name)
	{
		const std::size_t slash = name.find_last_of("\\/");
		const std::string_view file = slash == std::string_view::npos ? name : name.substr(slash + 1);
		const std::size_t dot = file.find_last_of('.');

		if (dot == std::string_view::npos)
		{
			return std::string(file);
		}

		return std::string(file.substr(0, dot));
	}

	std::string file_name_only(const std::string_view path)
	{
		const std::size_t slash = path.find_last_of("\\/");

		if (slash == std::string_view::npos)
		{
			return std::string(path);
		}

		return std::string(path.substr(slash + 1));
	}

	std::uint8_t is_kernel_alias(const std::string_view name)
	{
		const std::string stem = file_stem(name);

		return static_cast<std::uint8_t>(same_text(stem, "nt") == 1 || same_text(stem, "ntoskrnl") == 1 ||
			same_text(stem, "ntkrnlmp") == 1 || same_text(stem, "ntkrnlpa") == 1 || same_text(stem, "ntkrpamp") == 1);
	}

	std::uint8_t module_matches(const loaded_module_t& module, const std::string_view requested)
	{
		if (same_text(module.name, requested) == 1 || same_text(module.stem, requested) == 1 ||
			same_text(module.stem + ".exe", requested) == 1 || same_text(module.stem + ".sys", requested) == 1)
		{
			return 1;
		}

		return static_cast<std::uint8_t>(is_kernel_alias(requested) == 1 && is_kernel_alias(module.name) == 1);
	}

	std::uint8_t ensure_session()
	{
		if (session_ready == 1)
		{
			return 1;
		}

		const DWORD options = SYMOPT_UNDNAME | SYMOPT_AUTO_PUBLICS | SYMOPT_FAIL_CRITICAL_ERRORS | SYMOPT_CASE_INSENSITIVE |
			SYMOPT_NO_PROMPTS | SYMOPT_INCLUDE_32BIT_MODULES;

		SymSetOptions(options);

		const std::wstring path = widen(search_path_text);

		if (SymInitializeW(GetCurrentProcess(), path.empty() == true ? nullptr : path.c_str(), FALSE) == FALSE)
		{
			return 0;
		}

		session_ready = 1;

		return 1;
	}

	void apply_path_to_session()
	{
		if (session_ready == 0)
		{
			return;
		}

		const std::wstring path = widen(search_path_text);
		SymSetSearchPathW(GetCurrentProcess(), path.c_str());
	}

	std::uint8_t read_headers(const symbol_parser::image_read_t& read_image, std::vector<std::uint8_t>& headers)
	{
		headers.assign(0x1000, 0);

		if (read_image(0, headers.data(), headers.size()) == 0)
		{
			return 0;
		}

		const auto* const dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(headers.data());

		if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0)
		{
			return 0;
		}

		const std::uint64_t need = static_cast<std::uint64_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64);

		if (need > headers.size())
		{
			if (need > 0x2000)
			{
				return 0;
			}

			headers.resize(static_cast<std::size_t>(need));

			if (read_image(0, headers.data(), headers.size()) == 0)
			{
				return 0;
			}
		}

		const auto* const nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(headers.data() + dos->e_lfanew);

		return static_cast<std::uint8_t>(nt->Signature == IMAGE_NT_SIGNATURE &&
			nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
	}

	std::uint8_t parse_rsds(const std::uint8_t* data, std::size_t size, GUID& guid, std::uint32_t& age, std::string& pdb_name,
	                        std::string& pdb_hint);

	std::uint8_t read_codeview(const symbol_parser::image_read_t& read_image, const std::vector<std::uint8_t>& headers,
	                           GUID& guid, std::uint32_t& age, std::string& pdb_name, std::string& pdb_hint)
	{
		const auto* const dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(headers.data());
		const auto* const nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(headers.data() + dos->e_lfanew);
		const IMAGE_DATA_DIRECTORY& directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];

		if (directory.VirtualAddress == 0 || directory.Size < sizeof(IMAGE_DEBUG_DIRECTORY))
		{
			return 0;
		}

		std::vector<std::uint8_t> debug(directory.Size, 0);

		if (read_image(directory.VirtualAddress, debug.data(), debug.size()) == 0)
		{
			return 0;
		}

		const auto count = directory.Size / sizeof(IMAGE_DEBUG_DIRECTORY);
		const auto* const entries = reinterpret_cast<const IMAGE_DEBUG_DIRECTORY*>(debug.data());

		for (std::uint32_t index = 0; index < count; index++)
		{
			const IMAGE_DEBUG_DIRECTORY& entry = entries[index];

			const std::uint32_t data_size = entry.SizeOfData > 1024 ? 1024 : entry.SizeOfData;

			if (entry.Type != IMAGE_DEBUG_TYPE_CODEVIEW || entry.AddressOfRawData == 0 || data_size < 24)
			{
				continue;
			}

			std::vector<std::uint8_t> codeview(data_size, 0);

			if (read_image(entry.AddressOfRawData, codeview.data(), codeview.size()) == 0)
			{
				continue;
			}

			if (parse_rsds(codeview.data(), codeview.size(), guid, age, pdb_name, pdb_hint) == 1)
			{
				return 1;
			}
		}

		return 0;
	}

	std::uint8_t parse_rsds(const std::uint8_t* const data, const std::size_t size, GUID& guid, std::uint32_t& age,
	                        std::string& pdb_name, std::string& pdb_hint)
	{
		constexpr std::size_t header_size = sizeof(std::uint32_t) + sizeof(GUID) + sizeof(std::uint32_t);

		if (data == nullptr || size < header_size + 1)
		{
			return 0;
		}

		const auto* const rsds = reinterpret_cast<const codeview_rsds_t*>(data);

		if (rsds->signature != 0x53445352)
		{
			return 0;
		}

		guid = rsds->guid;
		age = rsds->age;
		const char* const name = reinterpret_cast<const char*>(data + header_size);
		const std::size_t length = strnlen(name, size - header_size);

		if (length == 0)
		{
			return 0;
		}

		pdb_hint = std::string(name, length);
		pdb_name = file_name_only(pdb_hint);

		if (pdb_hint.find('\\') == std::string::npos && pdb_hint.find('/') == std::string::npos)
		{
			pdb_hint.clear();
		}

		return static_cast<std::uint8_t>(pdb_name.empty() == false);
	}

	std::uint8_t read_file_bytes(const std::wstring& path, const std::uint64_t offset, void* const buffer, const std::uint32_t size)
	{
		if (path.empty() == true || buffer == nullptr || size == 0)
		{
			return 0;
		}

		const HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
		                                 OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

		if (file == INVALID_HANDLE_VALUE)
		{
			return 0;
		}

		LARGE_INTEGER position = {};
		position.QuadPart = static_cast<LONGLONG>(offset);
		const BOOL moved = SetFilePointerEx(file, position, nullptr, FILE_BEGIN);
		DWORD read = 0;
		const BOOL ok = moved == FALSE ? FALSE : ReadFile(file, buffer, size, &read, nullptr);
		CloseHandle(file);

		return static_cast<std::uint8_t>(ok != FALSE && read == size);
	}

	std::uint32_t rva_to_file_offset(const std::uint8_t* const image, const std::size_t image_size, const std::uint32_t rva)
	{
		if (image == nullptr || image_size < sizeof(IMAGE_DOS_HEADER) || rva == 0)
		{
			return 0;
		}

		const auto* const dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image);

		if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 ||
			static_cast<std::size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > image_size)
		{
			return 0;
		}

		const auto* const nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(image + dos->e_lfanew);

		if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		{
			return 0;
		}

		const std::size_t section_offset = static_cast<std::size_t>(dos->e_lfanew) + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
			nt->FileHeader.SizeOfOptionalHeader;

		for (std::uint16_t index = 0; index < nt->FileHeader.NumberOfSections; index++)
		{
			const std::size_t entry = section_offset + static_cast<std::size_t>(index) * sizeof(IMAGE_SECTION_HEADER);

			if (entry + sizeof(IMAGE_SECTION_HEADER) > image_size)
			{
				return 0;
			}

			const auto* const section = reinterpret_cast<const IMAGE_SECTION_HEADER*>(image + entry);
			const std::uint32_t span = section->Misc.VirtualSize > section->SizeOfRawData ? section->Misc.VirtualSize : section->SizeOfRawData;

			if (rva < section->VirtualAddress || rva >= section->VirtualAddress + span)
			{
				continue;
			}

			const std::uint32_t delta = rva - section->VirtualAddress;

			if (delta > section->SizeOfRawData || section->PointerToRawData == 0)
			{
				return 0;
			}

			return section->PointerToRawData + delta;
		}

		return 0;
	}

	std::wstring normalize_image_path(std::wstring path)
	{
		if (path.rfind(L"\\\\?\\", 0) == 0)
		{
			path.erase(0, 4);
		}

		if (path.rfind(L"\\??\\", 0) == 0)
		{
			path.erase(0, 4);
		}

		constexpr std::wstring_view system_root = L"\\systemroot";
		std::uint8_t rooted = static_cast<std::uint8_t>(path.size() >= system_root.size());

		for (std::size_t index = 0; rooted == 1 && index < system_root.size(); index++)
		{
			if (towlower(path[index]) != system_root[index])
			{
				rooted = 0;
			}
		}

		if (rooted == 1)
		{
			wchar_t windows[MAX_PATH] = {};
			const UINT windows_length = GetWindowsDirectoryW(windows, MAX_PATH);

			if (windows_length > 0 && windows_length < MAX_PATH)
			{
				path = std::wstring(windows, windows_length) + path.substr(system_root.size());
			}
		}

		return path;
	}

	std::uint8_t codeview_from_file(const std::wstring& path, const std::uint32_t timestamp, const std::uint32_t image_size,
	                                GUID& guid, std::uint32_t& age, std::string& pdb_name, std::string& pdb_hint)
	{
		std::vector<std::uint8_t> head(0x2000, 0);

		if (read_file_bytes(path, 0, head.data(), static_cast<std::uint32_t>(head.size())) == 0)
		{
			return 0;
		}

		const auto* const dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(head.data());

		if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 ||
			static_cast<std::size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > head.size())
		{
			return 0;
		}

		const auto* const nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(head.data() + dos->e_lfanew);

		if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
			nt->FileHeader.TimeDateStamp != timestamp || nt->OptionalHeader.SizeOfImage != image_size)
		{
			return 0;
		}

		const IMAGE_DATA_DIRECTORY& directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];

		if (directory.VirtualAddress == 0 || directory.Size < sizeof(IMAGE_DEBUG_DIRECTORY) || directory.Size > 0x1000)
		{
			return 0;
		}

		const std::uint32_t debug_offset = rva_to_file_offset(head.data(), head.size(), directory.VirtualAddress);

		if (debug_offset == 0)
		{
			return 0;
		}

		std::vector<std::uint8_t> debug(directory.Size, 0);

		if (read_file_bytes(path, debug_offset, debug.data(), static_cast<std::uint32_t>(debug.size())) == 0)
		{
			return 0;
		}

		const auto count = directory.Size / sizeof(IMAGE_DEBUG_DIRECTORY);
		const auto* const entries = reinterpret_cast<const IMAGE_DEBUG_DIRECTORY*>(debug.data());

		for (std::uint32_t index = 0; index < count; index++)
		{
			const IMAGE_DEBUG_DIRECTORY& entry = entries[index];
			const std::uint32_t data_size = entry.SizeOfData > 1024 ? 1024 : entry.SizeOfData;

			if (entry.Type != IMAGE_DEBUG_TYPE_CODEVIEW || data_size < 24)
			{
				continue;
			}

			std::uint32_t data_offset = entry.PointerToRawData;

			if (data_offset == 0)
			{
				data_offset = rva_to_file_offset(head.data(), head.size(), entry.AddressOfRawData);
			}

			if (data_offset == 0)
			{
				continue;
			}

			std::vector<std::uint8_t> codeview(data_size, 0);

			if (read_file_bytes(path, data_offset, codeview.data(), data_size) == 0)
			{
				continue;
			}

			if (parse_rsds(codeview.data(), codeview.size(), guid, age, pdb_name, pdb_hint) == 1)
			{
				return 1;
			}
		}

		return 0;
	}

	std::uint8_t codeview_from_disk(const std::string_view module_name, const std::string_view image_path,
	                                const std::vector<std::uint8_t>& headers, GUID& guid, std::uint32_t& age, std::string& pdb_name,
	                                std::string& pdb_hint)
	{
		if (headers.size() < sizeof(IMAGE_DOS_HEADER))
		{
			return 0;
		}

		const auto* const dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(headers.data());

		if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 ||
			static_cast<std::size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > headers.size())
		{
			return 0;
		}

		const auto* const nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(headers.data() + dos->e_lfanew);
		std::vector<std::wstring> candidates = {};

		if (image_path.empty() == false)
		{
			candidates.push_back(normalize_image_path(widen(std::string(image_path))));
		}

		wchar_t system[MAX_PATH] = {};
		const UINT system_length = GetSystemDirectoryW(system, MAX_PATH);

		if (system_length > 0 && system_length < MAX_PATH && module_name.empty() == false)
		{
			const std::wstring file_name = widen(std::string(module_name));
			candidates.push_back(std::wstring(system, system_length) + L"\\" + file_name);
			candidates.push_back(std::wstring(system, system_length) + L"\\drivers\\" + file_name);
		}

		for (const std::wstring& candidate : candidates)
		{
			if (codeview_from_file(candidate, nt->FileHeader.TimeDateStamp, nt->OptionalHeader.SizeOfImage, guid, age, pdb_name,
			                       pdb_hint) == 1)
			{
				return 1;
			}
		}

		return 0;
	}

	std::string guid_age_index(const GUID& guid, const std::uint32_t age)
	{
		char index[64] = {};

		std::snprintf(index, sizeof(index), "%08lX%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X%lX", guid.Data1, guid.Data2,
		              guid.Data3, guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3], guid.Data4[4], guid.Data4[5],
		              guid.Data4[6], guid.Data4[7], age);

		return index;
	}

	std::uint8_t file_is_pdb(const std::filesystem::path& path)
	{
		std::ifstream input(path, std::ios::binary);
		char magic[24] = {};

		input.read(magic, sizeof(magic));

		return static_cast<std::uint8_t>(input.gcount() == sizeof(magic) &&
			std::memcmp(magic, "Microsoft C/C++ MSF 7.00", sizeof(magic)) == 0);
	}

	struct symbol_store_t
	{
		std::string cache = {};
		std::string server = {};
	};

	std::vector<symbol_store_t> symbol_stores()
	{
		std::vector<symbol_store_t> stores = {};
		std::size_t cursor = 0;

		while (cursor < search_path_text.size())
		{
			const std::size_t separator = search_path_text.find(';', cursor);
			const std::string entry = search_path_text.substr(
				cursor, separator == std::string::npos ? std::string::npos : separator - cursor);
			cursor = separator == std::string::npos ? search_path_text.size() : separator + 1;

			if (entry.size() >= 4 && (entry[0] == 'S' || entry[0] == 's') && (entry[1] == 'R' || entry[1] == 'r') &&
				(entry[2] == 'V' || entry[2] == 'v') && entry[3] == '*')
			{
				std::vector<std::string> parts = {};
				std::size_t part_cursor = 0;

				while (part_cursor < entry.size())
				{
					const std::size_t star = entry.find('*', part_cursor);
					parts.push_back(entry.substr(part_cursor, star == std::string::npos ? std::string::npos : star - part_cursor));
					if (star == std::string::npos)
					{
						break;
					}

					part_cursor = star + 1;
				}

				symbol_store_t store = {};

				if (parts.size() >= 3)
				{
					store.cache = parts[1];
					store.server = parts[2];
				}
				else if (parts.size() == 2)
				{
					store.cache = "C:\\Symbols";
					store.server = parts[1];
				}

				if (store.cache.empty() == false)
				{
					stores.push_back(std::move(store));
				}

				continue;
			}

			if (entry.empty() == false)
			{
				stores.push_back({entry, {}});
			}
		}

		return stores;
	}

	std::uint8_t download_url(const std::wstring& url, std::vector<std::uint8_t>& body, std::string& detail)
	{
		URL_COMPONENTS components = {};
		wchar_t host[256] = {};
		wchar_t url_path[2048] = {};
		components.dwStructSize = sizeof(components);
		components.lpszHostName = host;
		components.dwHostNameLength = 256;
		components.lpszUrlPath = url_path;
		components.dwUrlPathLength = 2048;

		if (WinHttpCrackUrl(url.c_str(), 0, 0, &components) == FALSE)
		{
			detail = "invalid symbol server url";

			return 0;
		}

		HINTERNET session = WinHttpOpen(L"hyper-reV", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME,
		                                 WINHTTP_NO_PROXY_BYPASS, 0);

		if (session == nullptr)
		{
			detail = "WinHttpOpen failed " + std::to_string(GetLastError());

			return 0;
		}

		WinHttpSetTimeouts(session, 10000, 20000, 30000, 1000);
		HINTERNET connection = WinHttpConnect(session, host, components.nPort, 0);

		if (connection == nullptr)
		{
			detail = "WinHttpConnect failed " + std::to_string(GetLastError());
			WinHttpCloseHandle(session);

			return 0;
		}

		const DWORD request_flags = components.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0;
		HINTERNET request = WinHttpOpenRequest(connection, L"GET", url_path, nullptr, WINHTTP_NO_REFERER,
		                                        WINHTTP_DEFAULT_ACCEPT_TYPES, request_flags);

		if (request == nullptr)
		{
			detail = "WinHttpOpenRequest failed " + std::to_string(GetLastError());
			WinHttpCloseHandle(connection);
			WinHttpCloseHandle(session);

			return 0;
		}

		const DWORD redirect_policy = WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS;
		WinHttpSetOption(request, WINHTTP_OPTION_REDIRECT_POLICY, const_cast<DWORD*>(&redirect_policy), sizeof(redirect_policy));

		if (WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) == FALSE ||
			WinHttpReceiveResponse(request, nullptr) == FALSE)
		{
			detail = "download failed, winhttp " + std::to_string(GetLastError());
			WinHttpCloseHandle(request);
			WinHttpCloseHandle(connection);
			WinHttpCloseHandle(session);

			return 0;
		}

		DWORD status = 0;
		DWORD status_size = sizeof(status);
		WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &status,
		                    &status_size, WINHTTP_NO_HEADER_INDEX);

		if (status != 200)
		{
			detail = "symbol server returned HTTP " + std::to_string(status);
			WinHttpCloseHandle(request);
			WinHttpCloseHandle(connection);
			WinHttpCloseHandle(session);

			return 0;
		}

		while (true)
		{
			if (interrupt_check != nullptr && interrupt_check() == 1)
			{
				detail = "interrupted";
				WinHttpCloseHandle(request);
				WinHttpCloseHandle(connection);
				WinHttpCloseHandle(session);

				return 0;
			}

			DWORD available = 0;

			if (WinHttpQueryDataAvailable(request, &available) == FALSE)
			{
				detail = "download read failed, winhttp " + std::to_string(GetLastError());
				WinHttpCloseHandle(request);
				WinHttpCloseHandle(connection);
				WinHttpCloseHandle(session);

				return 0;
			}

			if (available == 0)
			{
				break;
			}

			const std::size_t offset = body.size();
			body.resize(offset + available);
			DWORD read = 0;

			if (WinHttpReadData(request, body.data() + offset, available, &read) == FALSE)
			{
				if (GetLastError() == ERROR_WINHTTP_TIMEOUT)
				{
					body.resize(offset);

					continue;
				}

				detail = "download read failed, winhttp " + std::to_string(GetLastError());
				WinHttpCloseHandle(request);
				WinHttpCloseHandle(connection);
				WinHttpCloseHandle(session);

				return 0;
			}

			body.resize(offset + read);
		}

		WinHttpCloseHandle(request);
		WinHttpCloseHandle(connection);
		WinHttpCloseHandle(session);

		return 1;
	}

	std::uint8_t body_is_pdb(const std::vector<std::uint8_t>& body)
	{
		return static_cast<std::uint8_t>(body.size() >= 24 &&
			std::memcmp(body.data(), "Microsoft C/C++ MSF 7.00", 24) == 0);
	}

	std::uint8_t find_pdb(const std::string& pdb_name, const GUID& guid, const std::uint32_t age, const std::uint8_t overwrite,
	                      std::wstring& path_out, std::string& detail)
	{
		const std::string index = guid_age_index(guid, age);
		const std::vector<symbol_store_t> stores = symbol_stores();
		std::string last_error = "symbol path has no SRV cache";

		for (const symbol_store_t& store : stores)
		{
			const std::filesystem::path cached = std::filesystem::path(store.cache) / pdb_name / index / pdb_name;

			if (overwrite == 0 && file_is_pdb(cached) == 1)
			{
				path_out = cached.wstring();

				return 1;
			}

			if (store.server.empty() == true)
			{
				last_error = "cached pdb was not found for " + pdb_name + " " + index;

				continue;
			}

			std::string server = store.server;

			while (server.empty() == false && server.back() == '/')
			{
				server.pop_back();
			}

			const std::string url = server + "/" + pdb_name + "/" + index + "/" + pdb_name;
			std::vector<std::uint8_t> body = {};
			std::string download_error = {};

			if (download_url(widen(url), body, download_error) == 0 || body_is_pdb(body) == 0)
			{
				last_error = pdb_name + " " + index + " from " + url + ": " +
					(download_error.empty() == true ? "response is not a pdb" : download_error);

				continue;
			}

			std::error_code error = {};
			std::filesystem::create_directories(cached.parent_path(), error);

			if (error)
			{
				detail = "failed to create " + cached.parent_path().string();

				return 0;
			}

			std::ofstream output(cached, std::ios::binary | std::ios::trunc);
			output.write(reinterpret_cast<const char*>(body.data()), static_cast<std::streamsize>(body.size()));

			if (output.good() == false)
			{
				detail = "failed to write " + cached.string();

				return 0;
			}

			output.close();
			path_out = cached.wstring();

			return 1;
		}

		detail = last_error;

		return 0;
	}

	loaded_module_t* find_loaded(const std::string_view name)
	{
		for (loaded_module_t& module : modules)
		{
			if (module_matches(module, name) == 1)
			{
				return &module;
			}
		}

		return nullptr;
	}

	constexpr DWORD symtag_data = 7;
	constexpr DWORD symtag_udt = 11;
	constexpr DWORD symtag_enum = 12;
	constexpr DWORD symtag_function_type = 13;
	constexpr DWORD symtag_pointer = 14;
	constexpr DWORD symtag_array = 15;
	constexpr DWORD symtag_base = 16;
	constexpr DWORD symtag_typedef = 17;
	constexpr DWORD symtag_base_class = 18;
	constexpr DWORD data_is_member = 7;
	constexpr DWORD basic_void = 1;
	constexpr DWORD basic_char = 2;
	constexpr DWORD basic_wchar = 3;
	constexpr DWORD basic_int = 6;
	constexpr DWORD basic_uint = 7;
	constexpr DWORD basic_float = 8;
	constexpr DWORD basic_bool = 10;
	constexpr DWORD basic_long = 13;
	constexpr DWORD basic_ulong = 14;
	constexpr DWORD basic_hresult = 31;

	std::uint8_t type_tag(const DWORD64 module_base, const ULONG type_id, DWORD& tag_out)
	{
		tag_out = 0;

		return static_cast<std::uint8_t>(SymGetTypeInfo(GetCurrentProcess(), module_base, type_id, TI_GET_SYMTAG, &tag_out) != FALSE);
	}

	ULONG skip_typedefs(const DWORD64 module_base, ULONG type_id)
	{
		for (std::uint32_t depth = 0; depth < 8; depth++)
		{
			DWORD tag = 0;

			if (type_tag(module_base, type_id, tag) == 0 || tag != symtag_typedef)
			{
				return type_id;
			}

			DWORD next = 0;

			if (SymGetTypeInfo(GetCurrentProcess(), module_base, type_id, TI_GET_TYPEID, &next) == FALSE || next == 0 || next == type_id)
			{
				return type_id;
			}

			type_id = next;
		}

		return type_id;
	}

	std::string symbol_type_name(const DWORD64 module_base, const ULONG type_id)
	{
		WCHAR* wide_name = nullptr;

		if (SymGetTypeInfo(GetCurrentProcess(), module_base, type_id, TI_GET_SYMNAME, &wide_name) == FALSE || wide_name == nullptr)
		{
			return {};
		}

		const std::string name = narrow(wide_name);
		LocalFree(wide_name);

		return name;
	}

	std::string base_type_name(const DWORD basic_type, const std::uint64_t size)
	{
		if (basic_type == basic_void)
		{
			return "Void";
		}

		if (basic_type == basic_bool)
		{
			return "Bool";
		}

		if (basic_type == basic_hresult)
		{
			return "HRESULT";
		}

		if (basic_type == basic_wchar)
		{
			return "Wchar";
		}

		if (basic_type == basic_float)
		{
			return size == 8 ? "Double" : "Float";
		}

		if (basic_type == basic_char)
		{
			return "Char";
		}

		const std::uint8_t unsigned_type = static_cast<std::uint8_t>(basic_type == basic_uint || basic_type == basic_ulong);

		if (basic_type == basic_int || basic_type == basic_uint || basic_type == basic_long || basic_type == basic_ulong)
		{
			if (size == 1)
			{
				return unsigned_type == 1 ? "UChar" : "Char";
			}

			if (size == 2)
			{
				return unsigned_type == 1 ? "Uint2B" : "Int2B";
			}

			if (size == 4)
			{
				return unsigned_type == 1 ? "Uint4B" : "Int4B";
			}

			if (size == 8)
			{
				return unsigned_type == 1 ? "Uint8B" : "Int8B";
			}
		}

		return "base";
	}

	std::string type_label(const DWORD64 module_base, const ULONG type_id, const std::uint32_t depth)
	{
		if (depth > 8 || type_id == 0)
		{
			return {};
		}

		const ULONG resolved = skip_typedefs(module_base, type_id);
		DWORD tag = 0;

		if (type_tag(module_base, resolved, tag) == 0)
		{
			return {};
		}

		ULONG64 length = 0;
		SymGetTypeInfo(GetCurrentProcess(), module_base, resolved, TI_GET_LENGTH, &length);

		if (tag == symtag_pointer)
		{
			DWORD next = 0;
			SymGetTypeInfo(GetCurrentProcess(), module_base, resolved, TI_GET_TYPEID, &next);
			const std::string inner = type_label(module_base, next, depth + 1);

			return (length == 4 ? "Ptr32 " : "Ptr64 ") + (inner.empty() == true ? "Void" : inner);
		}

		if (tag == symtag_array)
		{
			DWORD count = 0;
			DWORD next = 0;
			SymGetTypeInfo(GetCurrentProcess(), module_base, resolved, TI_GET_COUNT, &count);
			SymGetTypeInfo(GetCurrentProcess(), module_base, resolved, TI_GET_TYPEID, &next);
			const std::string inner = type_label(module_base, next, depth + 1);

			return (inner.empty() == true ? "char" : inner) + "[" + std::to_string(count) + "]";
		}

		if (tag == symtag_base)
		{
			DWORD basic = 0;
			SymGetTypeInfo(GetCurrentProcess(), module_base, resolved, TI_GET_BASETYPE, &basic);

			return base_type_name(basic, length);
		}

		if (tag == symtag_udt || tag == symtag_enum)
		{
			const std::string name = symbol_type_name(module_base, resolved);

			return name.empty() == true ? "struct" : name;
		}

		if (tag == symtag_function_type)
		{
			return "function";
		}

		const std::string name = symbol_type_name(module_base, resolved);

		return name.empty() == true ? "unknown" : name;
	}

	std::uint8_t fill_type_fields(const DWORD64 module_base, ULONG type_id, symbol_parser::type_info_t& info_out)
	{
		type_id = skip_typedefs(module_base, type_id);
		const std::string type_name = symbol_type_name(module_base, type_id);

		if (type_name.empty() == false)
		{
			info_out.name = type_name;
		}

		ULONG64 type_size = 0;

		if (SymGetTypeInfo(GetCurrentProcess(), module_base, type_id, TI_GET_LENGTH, &type_size) != FALSE)
		{
			info_out.size = type_size;
		}

		DWORD child_count = 0;

		if (SymGetTypeInfo(GetCurrentProcess(), module_base, type_id, TI_GET_CHILDRENCOUNT, &child_count) == FALSE || child_count == 0)
		{
			return 1;
		}

		if (child_count > 4096)
		{
			child_count = 4096;
		}

		std::vector<std::uint8_t> storage(sizeof(TI_FINDCHILDREN_PARAMS) + sizeof(ULONG) * (static_cast<std::size_t>(child_count) - 1));
		auto* const children = reinterpret_cast<TI_FINDCHILDREN_PARAMS*>(storage.data());
		children->Count = child_count;
		children->Start = 0;

		if (SymGetTypeInfo(GetCurrentProcess(), module_base, type_id, TI_FINDCHILDREN, children) == FALSE)
		{
			return 0;
		}

		info_out.fields.reserve(children->Count);

		for (ULONG index = 0; index < children->Count; index++)
		{
			const ULONG child = children->ChildId[index];
			DWORD tag = 0;

			if (type_tag(module_base, child, tag) == 0 || (tag != symtag_data && tag != symtag_base_class))
			{
				continue;
			}

			if (tag == symtag_data)
			{
				DWORD kind = 0;

				if (SymGetTypeInfo(GetCurrentProcess(), module_base, child, TI_GET_DATAKIND, &kind) == FALSE || kind != data_is_member)
				{
					continue;
				}
			}

			DWORD offset = 0;
			SymGetTypeInfo(GetCurrentProcess(), module_base, child, TI_GET_OFFSET, &offset);
			DWORD field_type = 0;
			SymGetTypeInfo(GetCurrentProcess(), module_base, child, TI_GET_TYPEID, &field_type);

			symbol_parser::type_field_t field = {};
			field.offset = offset;
			field.name = symbol_type_name(module_base, child);
			field.type_name = type_label(module_base, field_type, 0);

			if (field.name.empty() == true)
			{
				field.name = field.type_name.empty() == true ? "<unnamed>" : field.type_name;
			}

			const ULONG resolved = skip_typedefs(module_base, field_type);
			DWORD resolved_tag = 0;
			type_tag(module_base, resolved, resolved_tag);
			ULONG64 field_size = 0;
			SymGetTypeInfo(GetCurrentProcess(), module_base, resolved, TI_GET_LENGTH, &field_size);
			field.size = field_size;
			field.pointer = static_cast<std::uint8_t>(resolved_tag == symtag_pointer);
			field.integer = static_cast<std::uint8_t>(resolved_tag == symtag_base);

			DWORD bit_position = 0;

			if (SymGetTypeInfo(GetCurrentProcess(), module_base, child, TI_GET_BITPOSITION, &bit_position) != FALSE)
			{
				ULONG64 bit_length = 0;
				SymGetTypeInfo(GetCurrentProcess(), module_base, child, TI_GET_LENGTH, &bit_length);
				field.bitfield = 1;
				field.bit_position = bit_position;
				field.bit_length = static_cast<std::uint32_t>(bit_length);
				field.integer = 0;
				field.pointer = 0;
			}

			info_out.fields.push_back(std::move(field));
		}

		std::stable_sort(info_out.fields.begin(), info_out.fields.end(), [](const symbol_parser::type_field_t& left,
		                                                                     const symbol_parser::type_field_t& right)
		{
			return left.offset < right.offset;
		});

		return 1;
	}
}

namespace symbol_parser
{
	void set_interrupt_check(std::uint8_t (*const check)())
	{
		interrupt_check = check;
	}

	void set_search_path(std::string path)
	{
		const std::lock_guard<std::mutex> lock(session_mutex);

		search_path_text = std::move(path);
		apply_path_to_session();
	}

	void append_search_path(std::string path)
	{
		const std::lock_guard<std::mutex> lock(session_mutex);

		if (search_path_text.empty() == true)
		{
			search_path_text = std::move(path);
		}
		else if (path.empty() == false)
		{
			search_path_text += ";";
			search_path_text += path;
		}

		apply_path_to_session();
	}

	std::string search_path()
	{
		const std::lock_guard<std::mutex> lock(session_mutex);

		return search_path_text;
	}

	void use_microsoft_server(std::string cache_directory, const std::uint8_t append)
	{
		if (cache_directory.empty() == true)
		{
			cache_directory = "C:\\Symbols";
		}

		const std::string path = "SRV*" + cache_directory + "*https://msdl.microsoft.com/download/symbols";

		if (append == 1)
		{
			append_search_path(path);

			return;
		}

		set_search_path(path);
	}

	std::uint32_t options()
	{
		const std::lock_guard<std::mutex> lock(session_mutex);

		if (ensure_session() == 0)
		{
			return 0;
		}

		return SymGetOptions();
	}

	std::uint8_t load_module(const std::string_view name, const std::uint64_t base, const std::uint32_t size,
	                         const image_read_t& read_image, const std::string_view image_path, const std::uint8_t force,
	                         const std::uint8_t overwrite, std::string& detail)
	{
		const std::lock_guard<std::mutex> lock(session_mutex);

		if (read_image == nullptr || base == 0 || size == 0 || name.empty() == true)
		{
			detail = "invalid module";

			return 0;
		}

		if (search_path_text.empty() == true)
		{
			detail = "symbol path is not set";

			return 0;
		}

		if (ensure_session() == 0)
		{
			detail = "failed to initialize dbghelp";

			return 0;
		}

		for (std::size_t index = 0; index < modules.size(); index++)
		{
			loaded_module_t& existing = modules[index];

			if (same_text(existing.name, name) == 0)
			{
				continue;
			}

			if (force == 0 && existing.base == base && existing.size == size)
			{
				detail = existing.pdb_path;

				return 1;
			}

			SymUnloadModule64(GetCurrentProcess(), existing.base);
			modules.erase(modules.begin() + static_cast<std::ptrdiff_t>(index));

			break;
		}

		std::vector<std::uint8_t> headers = {};

		if (read_headers(read_image, headers) == 0)
		{
			detail = "failed to read the image headers";

			return 0;
		}

		GUID guid = {};
		std::uint32_t age = 0;
		std::string pdb_name = {};
		std::string pdb_hint = {};

		if (read_codeview(read_image, headers, guid, age, pdb_name, pdb_hint) == 0 &&
			codeview_from_disk(name, image_path, headers, guid, age, pdb_name, pdb_hint) == 0)
		{
			detail = "image has no RSDS pdb record";

			return 0;
		}

		std::wstring pdb_path = {};
		const std::wstring hinted_pdb = pdb_hint.empty() == true ? std::wstring() : normalize_image_path(widen(pdb_hint));

		if (hinted_pdb.empty() == false && file_is_pdb(hinted_pdb) == 1)
		{
			pdb_path = hinted_pdb;
		}
		else if (find_pdb(pdb_name, guid, age, overwrite, pdb_path, detail) == 0)
		{
			return 0;
		}

		const std::string stem = file_stem(name);
		const DWORD64 loaded = SymLoadModuleExW(GetCurrentProcess(), nullptr, pdb_path.c_str(), widen(stem).c_str(), base, size,
		                                         nullptr, 0);

		if (loaded == 0)
		{
			detail = "dbghelp did not accept the pdb";

			return 0;
		}

		loaded_module_t module = {};
		module.name = std::string(name);
		module.stem = stem;
		module.base = base;
		module.size = size;
		module.pdb_path = narrow(pdb_path);
		modules.push_back(std::move(module));
		detail = modules.back().pdb_path;

		return 1;
	}

	void unload_module(const std::uint64_t base)
	{
		const std::lock_guard<std::mutex> lock(session_mutex);

		for (std::size_t index = 0; index < modules.size(); index++)
		{
			if (modules[index].base != base)
			{
				continue;
			}

			if (session_ready == 1)
			{
				SymUnloadModule64(GetCurrentProcess(), modules[index].base);
			}

			modules.erase(modules.begin() + static_cast<std::ptrdiff_t>(index));

			return;
		}
	}

	void unload()
	{
		const std::lock_guard<std::mutex> lock(session_mutex);

		for (const loaded_module_t& module : modules)
		{
			SymUnloadModule64(GetCurrentProcess(), module.base);
		}

		modules.clear();

		if (session_ready == 1)
		{
			SymCleanup(GetCurrentProcess());
			session_ready = 0;
		}
	}

	std::vector<module_status_t> loaded_modules()
	{
		const std::lock_guard<std::mutex> lock(session_mutex);
		std::vector<module_status_t> result = {};
		result.reserve(modules.size());

		for (const loaded_module_t& module : modules)
		{
			module_status_t status = {};
			status.name = module.name;
			status.base = module.base;
			status.size = module.size;
			status.pdb_path = module.pdb_path;
			result.push_back(std::move(status));
		}

		return result;
	}

	std::uint8_t resolve(const std::string_view module, const std::string_view symbol, std::uint64_t& address_out)
	{
		const std::lock_guard<std::mutex> lock(session_mutex);

		if (session_ready == 0 || symbol.empty() == true)
		{
			return 0;
		}

		for (const loaded_module_t& loaded : modules)
		{
			if (module.empty() == false && module_matches(loaded, module) == 0)
			{
				continue;
			}

			const std::wstring query = widen(loaded.stem + "!" + std::string(symbol));
			alignas(SYMBOL_INFOW) unsigned char storage[sizeof(SYMBOL_INFOW) + (MAX_SYM_NAME * sizeof(wchar_t))] = {};
			auto* const info = reinterpret_cast<SYMBOL_INFOW*>(storage);
			info->SizeOfStruct = sizeof(SYMBOL_INFOW);
			info->MaxNameLen = MAX_SYM_NAME;

			if (SymFromNameW(GetCurrentProcess(), query.c_str(), info) == FALSE)
			{
				continue;
			}

			address_out = info->Address;

			return 1;
		}

		return 0;
	}

	std::uint8_t nearest(const std::uint64_t address, std::string& name_out, std::uint64_t& displacement_out)
	{
		const std::lock_guard<std::mutex> lock(session_mutex);

		if (session_ready == 0)
		{
			return 0;
		}

		alignas(SYMBOL_INFOW) unsigned char storage[sizeof(SYMBOL_INFOW) + (MAX_SYM_NAME * sizeof(wchar_t))] = {};
		auto* const info = reinterpret_cast<SYMBOL_INFOW*>(storage);
		info->SizeOfStruct = sizeof(SYMBOL_INFOW);
		info->MaxNameLen = MAX_SYM_NAME;
		DWORD64 displacement = 0;

		if (SymFromAddrW(GetCurrentProcess(), address, &displacement, info) == FALSE)
		{
			return 0;
		}

		IMAGEHLP_MODULEW64 module_info = {};
		module_info.SizeOfStruct = sizeof(module_info);
		std::string module_name = {};

		if (SymGetModuleInfoW64(GetCurrentProcess(), address, &module_info) != FALSE && module_info.ModuleName[0] != L'\0')
		{
			module_name = narrow(module_info.ModuleName);
		}

		const std::string symbol_name = narrow(info->Name);
		name_out = module_name.empty() == true ? symbol_name : module_name + "!" + symbol_name;
		displacement_out = displacement;

		return 1;
	}

	std::vector<symbol_match_t> enumerate(const std::string_view module, const std::string_view mask, const std::size_t limit)
	{
		const std::lock_guard<std::mutex> lock(session_mutex);
		std::vector<symbol_match_t> matches = {};

		if (session_ready == 0 || limit == 0)
		{
			return matches;
		}

		struct context_t
		{
			std::vector<symbol_match_t>* matches = nullptr;
			std::size_t limit = 0;
			std::string stem = {};
		};

		context_t context = {};
		context.matches = &matches;
		context.limit = limit;

		const auto callback = [](PSYMBOL_INFOW info, ULONG, PVOID user) -> BOOL
		{
			auto* const current = static_cast<context_t*>(user);

			if (current->matches->size() >= current->limit)
			{
				return FALSE;
			}

			const std::string symbol_name = narrow(info->Name);
			symbol_match_t match = {};
			match.name = current->stem.empty() == true ? symbol_name : current->stem + "!" + symbol_name;
			match.address = info->Address;
			current->matches->push_back(std::move(match));

			return TRUE;
		};

		for (const loaded_module_t& loaded : modules)
		{
			if (module.empty() == false && module_matches(loaded, module) == 0)
			{
				continue;
			}

			context.stem = loaded.stem;
			const std::wstring pattern = widen(mask.empty() == true ? loaded.stem + "!*" : loaded.stem + "!" + std::string(mask));
			SymEnumSymbolsW(GetCurrentProcess(), loaded.base, pattern.c_str(), callback, &context);

			if (matches.size() >= limit)
			{
				break;
			}
		}

		return matches;
	}

	std::uint8_t query_type(const std::string_view module, const std::string_view type_name, type_info_t& info_out, std::string& detail)
	{
		const std::lock_guard<std::mutex> lock(session_mutex);
		info_out = {};

		if (type_name.empty() == true)
		{
			detail = "syntax: dt <module>!<type>";

			return 0;
		}

		if (ensure_session() == 0)
		{
			detail = "failed to initialize dbghelp";

			return 0;
		}

		std::vector<const loaded_module_t*> candidates = {};

		for (const loaded_module_t& loaded : modules)
		{
			if (module.empty() == true || module_matches(loaded, module) == 1)
			{
				candidates.push_back(&loaded);
			}
		}

		if (candidates.empty() == true)
		{
			detail = "module symbols are not loaded";

			return 0;
		}

		const std::wstring wide_type = widen(std::string(type_name));

		for (const loaded_module_t* const loaded : candidates)
		{
			alignas(SYMBOL_INFOW) unsigned char storage[sizeof(SYMBOL_INFOW) + (MAX_SYM_NAME * sizeof(wchar_t))] = {};
			auto* const info = reinterpret_cast<SYMBOL_INFOW*>(storage);
			info->SizeOfStruct = sizeof(SYMBOL_INFOW);
			info->MaxNameLen = MAX_SYM_NAME;

			if (SymGetTypeFromNameW(GetCurrentProcess(), loaded->base, wide_type.c_str(), info) == FALSE || info->TypeIndex == 0)
			{
				continue;
			}

			info_out.module = is_kernel_alias(loaded->name) == 1 ? "nt" : loaded->stem;
			info_out.base = loaded->base;
			info_out.name = std::string(type_name);

			if (fill_type_fields(loaded->base, info->TypeIndex, info_out) == 0)
			{
				detail = "failed to read type fields";

				return 0;
			}

			if (info_out.name.empty() == true)
			{
				info_out.name = std::string(type_name);
			}

			detail.clear();

			return 1;
		}

		detail = "type not found";

		return 0;
	}
}
