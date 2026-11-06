#include "Search.h"
#include <ntimage.h>

#define SEARCH_POOL_TAG      'cSrS'
#define SEARCH_MODULE_SLACK  (64 * 1024)
#define SEARCH_MODULE_MAX    (8 * 1024 * 1024)
#define SEARCH_IMAGE_MAX     (128 * 1024 * 1024)
#define SEARCH_MAX_SECTIONS  96
#define SEARCH_MAX_PATTERNS  16

static BOOLEAN IsKernelAddress(ULONG_PTR address)
{
	return address >= (ULONG_PTR)MmSystemRangeStart;
}

static PVOID SearchAllocate(SIZE_T size)
{
#if (NTDDI_VERSION >= NTDDI_WIN10_VB)
	return ExAllocatePool2(POOL_FLAG_NON_PAGED, size, SEARCH_POOL_TAG);
#else
	PVOID memory;

#pragma warning(suppress: 4996)
	memory = ExAllocatePoolWithTag(NonPagedPool, size, SEARCH_POOL_TAG);
	if (memory != NULL)
	{
		RtlZeroMemory(memory, size);
	}
	return memory;
#endif
}

static VOID SearchFree(PVOID memory)
{
	if (memory != NULL)
	{
		ExFreePoolWithTag(memory, SEARCH_POOL_TAG);
	}
}

static BOOLEAN CopyKernelString(char* dest, SIZE_T destChars, const char* src, SIZE_T maxChars)
{
	SIZE_T limit;
	SIZE_T i;

	if (dest == NULL || destChars < 2 || src == NULL || maxChars == 0)
	{
		return FALSE;
	}

	dest[0] = '\0';
	if (!IsKernelAddress((ULONG_PTR)src))
	{
		return FALSE;
	}

	limit = destChars - 1;
	if (limit > maxChars)
	{
		limit = maxChars;
	}

	__try
	{
		for (i = 0; i < limit; i++)
		{
			dest[i] = src[i];
			if (dest[i] == '\0')
			{
				return TRUE;
			}
		}

		if (src[i] == '\0')
		{
			dest[i] = '\0';
			return TRUE;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		dest[0] = '\0';
		return FALSE;
	}

	dest[0] = '\0';
	return FALSE;
}

static VOID AsciiUpperInPlace(char* text)
{
	while (text != NULL && *text != '\0')
	{
		if (*text >= 'a' && *text <= 'z')
		{
			*text = (char)(*text - ('a' - 'A'));
		}
		text++;
	}
}

static BOOLEAN HexValue(UCHAR ch, UCHAR* value)
{
	if (ch >= '0' && ch <= '9')
	{
		*value = (UCHAR)(ch - '0');
		return TRUE;
	}
	if (ch >= 'A' && ch <= 'F')
	{
		*value = (UCHAR)(ch - 'A' + 10);
		return TRUE;
	}
	if (ch >= 'a' && ch <= 'f')
	{
		*value = (UCHAR)(ch - 'a' + 10);
		return TRUE;
	}
	return FALSE;
}

static BOOLEAN ReadInImage(
	PVOID dest,
	ULONG_PTR imageBase,
	ULONG_PTR imageSize,
	ULONG offset,
	SIZE_T bytes)
{
	if (dest == NULL || bytes == 0 || imageSize == 0)
	{
		return FALSE;
	}
	if ((ULONG_PTR)offset > imageSize || bytes > imageSize - offset)
	{
		return FALSE;
	}
	if (imageBase > (ULONG_PTR)-1 - offset)
	{
		return FALSE;
	}

	__try
	{
		RtlCopyMemory(dest, (PUCHAR)imageBase + offset, bytes);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return FALSE;
	}

	return TRUE;
}

static BOOLEAN AddressWithOffset(ULONG_PTR base, LONG offset, ULONG_PTR* out)
{
	if (out == NULL)
	{
		return FALSE;
	}

	if (offset >= 0)
	{
		if (base > (ULONG_PTR)-1 - (ULONG_PTR)offset)
		{
			return FALSE;
		}
		*out = base + (ULONG_PTR)offset;
		return TRUE;
	}

	if (base < (ULONG_PTR)(-(LONGLONG)offset))
	{
		return FALSE;
	}

	*out = base - (ULONG_PTR)(-(LONGLONG)offset);
	return TRUE;
}

static ULONG_PTR ApplyDelta(ULONG_PTR address, LONG delta)
{
	ULONG_PTR adjusted;

	if (!AddressWithOffset(address, delta, &adjusted))
	{
		return 0;
	}
	if (!IsKernelAddress(adjusted))
	{
		return 0;
	}
	return adjusted;
}

static BOOLEAN GetScanRange(
	ULONG_PTR imageBase,
	ULONG_PTR imageSize,
	const char* segmentName,
	ULONG_PTR* scanBase,
	ULONG_PTR* scanSize)
{
	IMAGE_DOS_HEADER dos;
	IMAGE_FILE_HEADER fileHeader;
	IMAGE_SECTION_HEADER section;
	ULONG eLfanew;
	ULONG signature;
	ULONG optOffset;
	ULONG sectionOffset;
	ULONG sizeOfImage;
	ULONG i;
	USHORT magic;
	BOOLEAN wantSection;

	if (scanBase == NULL || scanSize == NULL)
	{
		return FALSE;
	}

	*scanBase = 0;
	*scanSize = 0;

	if (!IsKernelAddress(imageBase) || imageSize < sizeof(IMAGE_DOS_HEADER) || imageSize > SEARCH_IMAGE_MAX)
	{
		return FALSE;
	}
	if (imageBase > (ULONG_PTR)-1 - imageSize)
	{
		return FALSE;
	}
	if (!ReadInImage(&dos, imageBase, imageSize, 0, sizeof(dos)))
	{
		return FALSE;
	}
	if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0)
	{
		return FALSE;
	}

	eLfanew = (ULONG)dos.e_lfanew;
	if (imageSize < sizeof(ULONG) + sizeof(IMAGE_FILE_HEADER) ||
		eLfanew > imageSize - sizeof(ULONG) - sizeof(IMAGE_FILE_HEADER))
	{
		return FALSE;
	}
	if (!ReadInImage(&signature, imageBase, imageSize, eLfanew, sizeof(signature)) ||
		signature != IMAGE_NT_SIGNATURE)
	{
		return FALSE;
	}
	if (!ReadInImage(&fileHeader, imageBase, imageSize, eLfanew + sizeof(ULONG), sizeof(fileHeader)))
	{
		return FALSE;
	}
	if (fileHeader.SizeOfOptionalHeader < 60 || fileHeader.SizeOfOptionalHeader > 1024)
	{
		return FALSE;
	}
	if (fileHeader.NumberOfSections > SEARCH_MAX_SECTIONS)
	{
		return FALSE;
	}

	optOffset = eLfanew + sizeof(ULONG) + sizeof(IMAGE_FILE_HEADER);
	if (optOffset > imageSize || fileHeader.SizeOfOptionalHeader > imageSize - optOffset)
	{
		return FALSE;
	}
	if (!ReadInImage(&magic, imageBase, imageSize, optOffset, sizeof(magic)))
	{
		return FALSE;
	}
	if (magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC && magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		return FALSE;
	}
	if (!ReadInImage(&sizeOfImage, imageBase, imageSize, optOffset + 56, sizeof(sizeOfImage)))
	{
		return FALSE;
	}
	if (sizeOfImage < sizeof(IMAGE_DOS_HEADER) || sizeOfImage > imageSize)
	{
		return FALSE;
	}

	if (fileHeader.SizeOfOptionalHeader > (ULONG)-1 - optOffset)
	{
		return FALSE;
	}
	sectionOffset = optOffset + fileHeader.SizeOfOptionalHeader;
	if (fileHeader.NumberOfSections > 0)
	{
		if (sectionOffset > imageSize ||
			(imageSize - sectionOffset) / sizeof(IMAGE_SECTION_HEADER) < fileHeader.NumberOfSections)
		{
			return FALSE;
		}
	}

	wantSection = (segmentName != NULL && segmentName[0] != '\0');
	if (!wantSection)
	{
		*scanBase = imageBase;
		*scanSize = sizeOfImage;
		return TRUE;
	}
	if (fileHeader.NumberOfSections == 0)
	{
		return FALSE;
	}

	for (i = 0; i < fileHeader.NumberOfSections; i++)
	{
		CHAR name[9];
		ULONG span;
		ULONG headerOffset;

		headerOffset = sectionOffset + (i * sizeof(IMAGE_SECTION_HEADER));
		if (!ReadInImage(&section, imageBase, imageSize, headerOffset, sizeof(section)))
		{
			return FALSE;
		}

		RtlCopyMemory(name, section.Name, 8);
		name[8] = '\0';
		if (_stricmp(name, segmentName) != 0)
		{
			continue;
		}

		if (section.VirtualAddress >= sizeOfImage)
		{
			return FALSE;
		}

		span = section.Misc.VirtualSize;
		if (span == 0)
		{
			span = section.SizeOfRawData;
		}
		if (span == 0 || span > sizeOfImage - section.VirtualAddress)
		{
			return FALSE;
		}
		if (imageBase > (ULONG_PTR)-1 - section.VirtualAddress)
		{
			return FALSE;
		}

		*scanBase = imageBase + section.VirtualAddress;
		*scanSize = span;
		return TRUE;
	}

	return FALSE;
}

static BOOLEAN ModuleListSane(const RTL_PROCESS_MODULES* modules, ULONG bytes)
{
	ULONG maxCount;

	if (modules == NULL || bytes < sizeof(RTL_PROCESS_MODULES))
	{
		return FALSE;
	}

	maxCount = (bytes - FIELD_OFFSET(RTL_PROCESS_MODULES, Modules)) / sizeof(RTL_PROCESS_MODULE_INFORMATION);
	return modules->NumberOfModules > 0 && modules->NumberOfModules <= maxCount;
}

static BOOLEAN QueryModuleList(RTL_PROCESS_MODULES** modules, ULONG* bytes)
{
	ULONG need;
	ULONG len;
	ULONG attempt;
	NTSTATUS status;
	RTL_PROCESS_MODULES* buffer;

	if (modules == NULL || bytes == NULL)
	{
		return FALSE;
	}

	*modules = NULL;
	*bytes = 0;
	need = 0;
	status = ZwQuerySystemInformation(SEARCH_SYSTEM_MODULE_INFORMATION, NULL, 0, &need);
	if (status != STATUS_INFO_LENGTH_MISMATCH && status != STATUS_BUFFER_TOO_SMALL)
	{
		return FALSE;
	}

	for (attempt = 0; attempt < 3; attempt++)
	{
		if (need < sizeof(RTL_PROCESS_MODULES) || need > SEARCH_MODULE_MAX || need > MAXULONG - SEARCH_MODULE_SLACK)
		{
			return FALSE;
		}

		len = need + SEARCH_MODULE_SLACK;
		buffer = (RTL_PROCESS_MODULES*)SearchAllocate(len);
		if (buffer == NULL)
		{
			return FALSE;
		}

		status = ZwQuerySystemInformation(SEARCH_SYSTEM_MODULE_INFORMATION, buffer, len, &need);
		if (NT_SUCCESS(status))
		{
			if (!ModuleListSane(buffer, len))
			{
				SearchFree(buffer);
				return FALSE;
			}

			*modules = buffer;
			*bytes = len;
			return TRUE;
		}

		SearchFree(buffer);
		if (status != STATUS_INFO_LENGTH_MISMATCH && status != STATUS_BUFFER_TOO_SMALL)
		{
			return FALSE;
		}
	}

	return FALSE;
}

static BOOLEAN MatchAt(
	ULONG_PTR beginAddr,
	ULONG_PTR endAddr,
	ULONG_PTR cursor,
	const FindCode* fc)
{
	UCHAR local[SEARCH_CODE_MAX];
	ULONG_PTR pos;
	ULONG k;

	if (fc == NULL || fc->len == 0 || fc->len > SEARCH_CODE_MAX)
	{
		return FALSE;
	}
	if (!AddressWithOffset(cursor, fc->offset, &pos))
	{
		return FALSE;
	}
	if (pos < beginAddr || pos >= endAddr || fc->len > endAddr - pos)
	{
		return FALSE;
	}

	RtlCopyMemory(local, (const UCHAR*)pos, fc->len);
	for (k = 0; k < fc->len; k++)
	{
		if (fc->mask[k] != 0 && local[k] != fc->code[k])
		{
			return FALSE;
		}
	}

	return TRUE;
}

BOOLEAN initFindCodeStruct(PFindCode findCode, PCHAR code, LONG offset, LONG lastAddrOffset)
{
	CHAR local[SEARCH_CODE_MAX * 2 + 1];
	PCHAR cursor;
	ULONG i;

	if (findCode == NULL)
	{
		return FALSE;
	}

	RtlZeroMemory(findCode, sizeof(*findCode));
	if (!CopyKernelString(local, sizeof(local), code, SEARCH_CODE_MAX * 2))
	{
		return FALSE;
	}

	i = 0;
	cursor = local;
	while (*cursor != '\0')
	{
		UCHAR high;
		UCHAR low;

		if (i >= SEARCH_CODE_MAX)
		{
			RtlZeroMemory(findCode, sizeof(*findCode));
			return FALSE;
		}

		if (*cursor == '*' || *cursor == '?')
		{
			findCode->code[i] = 0;
			findCode->mask[i] = 0;
			cursor++;
			i++;
			continue;
		}

		if (cursor[1] == '\0' ||
			!HexValue((UCHAR)cursor[0], &high) ||
			!HexValue((UCHAR)cursor[1], &low))
		{
			RtlZeroMemory(findCode, sizeof(*findCode));
			return FALSE;
		}

		findCode->code[i] = (UCHAR)((high << 4) | low);
		findCode->mask[i] = 1;
		cursor += 2;
		i++;
	}

	if (i == 0)
	{
		return FALSE;
	}

	findCode->len = i;
	findCode->offset = offset;
	findCode->lastAddressOffset = lastAddrOffset;
	return TRUE;
}

ULONG_PTR findAddressByCode(ULONG_PTR beginAddr, ULONG_PTR endAddr, PFindCode findCode, ULONG numbers)
{
	ULONG_PTR cursor;
	ULONG n;

	if (findCode == NULL || numbers == 0 || numbers > SEARCH_MAX_PATTERNS)
	{
		return 0;
	}
	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
	{
		return 0;
	}
	if (!IsKernelAddress(beginAddr) || endAddr <= beginAddr || endAddr - beginAddr > SEARCH_IMAGE_MAX)
	{
		return 0;
	}

	for (n = 0; n < numbers; n++)
	{
		if (findCode[n].len == 0 || findCode[n].len > SEARCH_CODE_MAX)
		{
			return 0;
		}
	}

	cursor = beginAddr;
	while (cursor < endAddr)
	{
		ULONG_PTR nextPage;
		ULONG_PTR pageEnd;

		nextPage = (cursor & ~((ULONG_PTR)PAGE_SIZE - 1)) + PAGE_SIZE;
		if (nextPage <= cursor)
		{
			break;
		}
		pageEnd = nextPage < endAddr ? nextPage : endAddr;

		__try
		{
			for (; cursor < pageEnd; cursor++)
			{
				BOOLEAN matched;

				matched = TRUE;
				for (n = 0; n < numbers; n++)
				{
					if (!MatchAt(beginAddr, endAddr, cursor, &findCode[n]))
					{
						matched = FALSE;
						break;
					}
				}

				if (matched)
				{
					return ApplyDelta(cursor, findCode[0].lastAddressOffset);
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			cursor = nextPage;
		}
	}

	return 0;
}

ULONG_PTR QuerySysModule(char* ModuleName, ULONG_PTR* module)
{
	RTL_PROCESS_MODULES* modules;
	CHAR wanted[256];
	ULONG bytes;
	ULONG i;
	ULONG_PTR imageBase;
	ULONG_PTR imageSize;
	BOOLEAN kernelAlias;

	if (module != NULL)
	{
		*module = 0;
	}
	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
	{
		return 0;
	}
	if (!CopyKernelString(wanted, sizeof(wanted), ModuleName, 255))
	{
		return 0;
	}

	AsciiUpperInPlace(wanted);
	if (wanted[0] == '\0')
	{
		return 0;
	}
	if (!QueryModuleList(&modules, &bytes) || bytes < sizeof(RTL_PROCESS_MODULES))
	{
		return 0;
	}

	imageBase = 0;
	imageSize = 0;
	kernelAlias = (strstr(wanted, "NTOSKRNL.EXE") != NULL || strstr(wanted, "NTKRNLPA.EXE") != NULL);
	if (kernelAlias)
	{
		imageBase = (ULONG_PTR)modules->Modules[0].ImageBase;
		imageSize = modules->Modules[0].ImageSize;
	}
	else
	{
		for (i = 0; i < modules->NumberOfModules; i++)
		{
			CHAR path[257];

			RtlCopyMemory(path, modules->Modules[i].FullPathName, 256);
			path[256] = '\0';
			AsciiUpperInPlace(path);
			if (strstr(path, wanted) != NULL)
			{
				imageBase = (ULONG_PTR)modules->Modules[i].ImageBase;
				imageSize = modules->Modules[i].ImageSize;
				break;
			}
		}
	}

	SearchFree(modules);

	if (!IsKernelAddress(imageBase) || imageSize == 0 || imageSize > SEARCH_IMAGE_MAX)
	{
		return 0;
	}
	if (module != NULL)
	{
		*module = imageBase;
	}
	return imageSize;
}

ULONG_PTR searchNtCode(char* code, int offset)
{
	return searchCode("ntoskrnl.exe", NULL, code, offset);
}

ULONG_PTR searchCode(char* moduleName, char* segmentName, char* code, int offset)
{
	FindCode pattern;
	CHAR section[9];
	const char* sectionArg;
	ULONG_PTR moduleBase;
	ULONG_PTR imageSize;
	ULONG_PTR scanBase;
	ULONG_PTR scanSize;

	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
	{
		return 0;
	}
	if (!initFindCodeStruct(&pattern, code, 0, offset))
	{
		return 0;
	}

	moduleBase = 0;
	imageSize = QuerySysModule(moduleName, &moduleBase);
	if (moduleBase == 0 || imageSize == 0)
	{
		return 0;
	}

	sectionArg = NULL;
	if (segmentName != NULL)
	{
		if (!CopyKernelString(section, sizeof(section), segmentName, 8))
		{
			return 0;
		}
		if (section[0] != '\0')
		{
			sectionArg = section;
		}
	}

	scanBase = 0;
	scanSize = 0;
	if (!GetScanRange(moduleBase, imageSize, sectionArg, &scanBase, &scanSize))
	{
		return 0;
	}
	if (scanBase > (ULONG_PTR)-1 - scanSize)
	{
		return 0;
	}

	return findAddressByCode(scanBase, scanBase + scanSize, &pattern, 1);
}
