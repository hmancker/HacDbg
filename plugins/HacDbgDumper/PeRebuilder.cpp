#include "PeRebuilder.h"
#include "log_defs.h"
#include <fstream>
#include <algorithm>
#include <numeric>

namespace {

uint32_t CalculateScyllaSectionDataSize(const uint8_t* buffer, uint64_t bufferSize, const IMAGE_SECTION_HEADER& section) {
	uint32_t normalSize = section.Misc.VirtualSize;
	if (normalSize == 0) {
		return 0;
	}

	uint64_t sectionOffset = section.VirtualAddress;
	if (sectionOffset >= bufferSize) {
		return 0;
	}

	uint32_t readableSize = normalSize;
	if (sectionOffset + readableSize > bufferSize) {
		readableSize = static_cast<uint32_t>(bufferSize - sectionOffset);
	}
	if (readableSize == 0) {
		return 0;
	}

	if (readableSize <= 100) {
		return readableSize;
	}

	for (int64_t index = static_cast<int64_t>(readableSize) - 1; index >= 0; --index) {
		if (buffer[sectionOffset + static_cast<uint64_t>(index)] != 0) {
			uint32_t dataSize = static_cast<uint32_t>(index) + 1 + sizeof(uint32_t);
			return min(dataSize, readableSize);
		}
	}

	return 0;
}

bool IsImmersiveSection(const IMAGE_SECTION_HEADER& section) {
	return strncmp(reinterpret_cast<const char*>(section.Name), ".imrsiv", 7) == 0;
}

}

PeRebuilder::PeRebuilder()
	: RawBuffer(nullptr), BufferSize(0), OriginalImageBase(0),
	  DosHeader(nullptr), NtHeaders(nullptr), SectionHeaders(nullptr) {}

bool PeRebuilder::LoadFromBuffer(uint8_t* Buffer, uint64_t Size, uint64_t ImageBase) {
	RawBuffer = Buffer; BufferSize = Size; OriginalImageBase = ImageBase;
	DosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(RawBuffer);
	if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE) { logging("Invalid DOS signature: 0x%X", DosHeader->e_magic); return false; }
	NtHeaders = reinterpret_cast<IMAGE_NT_HEADERS64*>(RawBuffer + DosHeader->e_lfanew);
	if (NtHeaders->Signature != IMAGE_NT_SIGNATURE) { logging("Invalid NT signature: 0x%X", NtHeaders->Signature); return false; }
	if (NtHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) { logging("Not a 64bit PE"); return false; }
	SectionHeaders = IMAGE_FIRST_SECTION(NtHeaders);
	SectionDataSizes.assign(NtHeaders->FileHeader.NumberOfSections, 0);
	logging("PE loaded: %d sections, ImageBase: 0x%llX, SizeOfImage: 0x%X",
		NtHeaders->FileHeader.NumberOfSections, NtHeaders->OptionalHeader.ImageBase, NtHeaders->OptionalHeader.SizeOfImage);
	return true;
}

bool PeRebuilder::FixHeaders() {
	NtHeaders->OptionalHeader.ImageBase = OriginalImageBase;
	if (NtHeaders->OptionalHeader.FileAlignment == 0) NtHeaders->OptionalHeader.FileAlignment = 0x200;

	// Clear IAT DataDirectory - IAT contains resolved runtime pointers
	auto& IatDir = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
	logging("Clearing IAT DataDirectory (was VA=0x%X, Size=0x%X)", IatDir.VirtualAddress, IatDir.Size);
	IatDir.VirtualAddress = 0;
	IatDir.Size = 0;

	auto& BoundImportDir = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT];
	BoundImportDir.VirtualAddress = 0;
	BoundImportDir.Size = 0;

	// NOTE: x64dbg/Scylla keeps Security and Debug DataDirectories, so we do not clear them.
	// Even though Security DD uses file offsets, x64dbg preserves it.

	logging("Headers fixed: ImageBase=0x%llX, FileAlignment=0x%X",
		OriginalImageBase, NtHeaders->OptionalHeader.FileAlignment);
	return true;
}

bool PeRebuilder::FixSectionHeaders() {
	uint16_t SectionCount = NtHeaders->FileHeader.NumberOfSections;
	uint32_t FileAlignment = NtHeaders->OptionalHeader.FileAlignment;
	if (FileAlignment == 0) FileAlignment = 0x200;
	uint32_t SectionAlignment = NtHeaders->OptionalHeader.SectionAlignment;
	if (SectionAlignment == 0) SectionAlignment = 0x1000;

	uint32_t FirstSectionOffset = AlignValue(
		DosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64) + (SectionCount * sizeof(IMAGE_SECTION_HEADER)),
		FileAlignment);
	NtHeaders->OptionalHeader.SizeOfHeaders = FirstSectionOffset;

	// Get IAT range for WRITE flag (before FixHeaders clears it)
	auto& IatDir = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
	uint32_t IatVA = IatDir.VirtualAddress;

	// Sort sections by their ORIGINAL PointerToRawData (preserves on-disk order)
	// The PE loader does NOT modify section headers in memory, so these are the
	// original values from the disk PE. x64dbg/Scylla preserves this ordering.
	std::vector<uint16_t> sortedIdx(SectionCount);
	std::iota(sortedIdx.begin(), sortedIdx.end(), 0);
	std::sort(sortedIdx.begin(), sortedIdx.end(), [&](uint16_t a, uint16_t b) {
		return SectionHeaders[a].PointerToRawData < SectionHeaders[b].PointerToRawData;
	});

	// First section starts right after headers
	uint32_t CurrentFileOffset = FirstSectionOffset;

	for (uint16_t order = 0; order < SectionCount; order++) {
		IMAGE_SECTION_HEADER& Section = SectionHeaders[sortedIdx[order]];
		const uint16_t SectionIndex = sortedIdx[order];
		const uint32_t OriginalVirtualSize = Section.Misc.VirtualSize;

		// Align VirtualSize to SectionAlignment (matches x64dbg/Scylla)
		Section.Misc.VirtualSize = AlignValue(OriginalVirtualSize, SectionAlignment);

		// If this section contains the IAT, add MEM_WRITE flag
		if (IatVA != 0 && IatVA >= Section.VirtualAddress &&
			IatVA < Section.VirtualAddress + Section.Misc.VirtualSize) {
			Section.Characteristics |= IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
			logging("Section %-8.8s: added MEM_READ|MEM_WRITE (contains IAT)", Section.Name);
		}

		uint32_t DataSize = CalculateScyllaSectionDataSize(RawBuffer, BufferSize, Section);
		if (DataSize == 0 && IsImmersiveSection(Section)) {
			DataSize = FileAlignment;
		}
		SectionDataSizes[SectionIndex] = DataSize;
		Section.SizeOfRawData = AlignValue(DataSize, FileAlignment);

		// Assign new contiguous PointerToRawData (compact file layout)
		Section.PointerToRawData = CurrentFileOffset;

		logging("Section %-8.8s | VA: 0x%08X | VSize: 0x%08X | RawPtr: 0x%08X | RawSize: 0x%08X",
			Section.Name, Section.VirtualAddress, Section.Misc.VirtualSize,
			Section.PointerToRawData, Section.SizeOfRawData);

		CurrentFileOffset += Section.SizeOfRawData;
	}
	return true;
}

bool PeRebuilder::FixImportDirectory() {
	auto& ImportDir = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (ImportDir.VirtualAddress == 0 || ImportDir.Size == 0) return true;
	uint64_t ImportOffset = RvaToOffset(ImportDir.VirtualAddress);
	if (ImportOffset == 0 || ImportOffset >= BufferSize) { logging("Import directory RVA points outside buffer"); return false; }
	auto* ImportDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(RawBuffer + ImportOffset);
	uint32_t ImportCount = 0;
	while (ImportDesc->Name != 0) {
		uint64_t NameOffset = RvaToOffset(ImportDesc->Name);
		if (NameOffset && NameOffset < BufferSize) {
			const char* DllName = reinterpret_cast<const char*>(RawBuffer + NameOffset);
			logging("Import: %s", DllName);
		}
		ImportDesc++; ImportCount++;
	}
	logging("Validated %d import descriptors", ImportCount);
	return true;
}

bool PeRebuilder::NullRelocations() {
	auto& RelocDir = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	RelocDir.VirtualAddress = 0; RelocDir.Size = 0;
	logging("Relocation directory nulled");
	return true;
}

bool PeRebuilder::SaveToDisk(const std::string& OutputPath) {
	std::ofstream File(OutputPath, std::ios::binary);
	if (!File.is_open()) { logging("Failed to create output file: %s", OutputPath.c_str()); return false; }

	uint16_t SectionCount = NtHeaders->FileHeader.NumberOfSections;
	uint32_t DosStubSize = 0;
	if (DosHeader->e_lfanew > sizeof(IMAGE_DOS_HEADER)) {
		DosStubSize = DosHeader->e_lfanew - sizeof(IMAGE_DOS_HEADER);
	}

	File.write(reinterpret_cast<const char*>(DosHeader), sizeof(IMAGE_DOS_HEADER));
	if (DosStubSize != 0) {
		File.write(reinterpret_cast<const char*>(RawBuffer + sizeof(IMAGE_DOS_HEADER)), DosStubSize);
	}
	File.write(reinterpret_cast<const char*>(NtHeaders), sizeof(IMAGE_NT_HEADERS64));
	for (uint16_t i = 0; i < SectionCount; i++) {
		File.write(reinterpret_cast<const char*>(&SectionHeaders[i]), sizeof(IMAGE_SECTION_HEADER));
	}

	std::vector<uint16_t> sortedIdx(SectionCount);
	std::iota(sortedIdx.begin(), sortedIdx.end(), 0);
	std::sort(sortedIdx.begin(), sortedIdx.end(), [&](uint16_t a, uint16_t b) {
		return SectionHeaders[a].PointerToRawData < SectionHeaders[b].PointerToRawData;
	});

	for (uint16_t order = 0; order < SectionCount; order++) {
		const uint16_t SectionIndex = sortedIdx[order];
		const IMAGE_SECTION_HEADER& Section = SectionHeaders[SectionIndex];

		// Pad file to PointerToRawData if needed
		uint64_t currentPos = (uint64_t)File.tellp();
		if (currentPos < Section.PointerToRawData) {
			uint64_t padSize = Section.PointerToRawData - currentPos;
			std::vector<uint8_t> padding(padSize, 0);
			File.write(reinterpret_cast<const char*>(padding.data()), padSize);
		}

		// Section data is at VirtualAddress offset in the memory buffer
		uint64_t srcOffset = Section.VirtualAddress;
		uint32_t dataSize = 0;
		if (SectionIndex < SectionDataSizes.size()) {
			dataSize = SectionDataSizes[SectionIndex];
		}
		uint32_t rawSize = Section.SizeOfRawData;

		// Clamp to buffer bounds
		if (srcOffset + dataSize > BufferSize) {
			if (srcOffset >= BufferSize) {
				dataSize = 0;
			} else {
				dataSize = static_cast<uint32_t>(BufferSize - srcOffset);
			}
		}

		if (dataSize != 0) {
			File.write(reinterpret_cast<const char*>(RawBuffer + srcOffset), dataSize);
		}

		if (dataSize < rawSize) {
			std::vector<uint8_t> zeros(rawSize - dataSize, 0);
			File.write(reinterpret_cast<const char*>(zeros.data()), zeros.size());
		}
	}

	File.close();
	uint64_t fileSize = std::filesystem::file_size(OutputPath);
	logging("Dump saved: %s (%llu bytes / 0x%llX)", OutputPath.c_str(), fileSize, fileSize);
	return true;
}

IMAGE_NT_HEADERS64* PeRebuilder::GetNtHeaders() const { return NtHeaders; }
uint32_t PeRebuilder::GetSectionCount() const { return NtHeaders ? NtHeaders->FileHeader.NumberOfSections : 0; }

uint64_t PeRebuilder::RvaToOffset(uint64_t Rva) {
	return Rva; // Memory layout: RVA == buffer offset
}

IMAGE_SECTION_HEADER* PeRebuilder::FindSectionByRva(uint64_t Rva) {
	uint16_t SectionCount = NtHeaders->FileHeader.NumberOfSections;
	for (uint16_t i = 0; i < SectionCount; i++) {
		uint64_t Start = SectionHeaders[i].VirtualAddress;
		uint64_t End = Start + SectionHeaders[i].Misc.VirtualSize;
		if (Rva >= Start && Rva < End) return &SectionHeaders[i];
	}
	return nullptr;
}

uint32_t PeRebuilder::AlignValue(uint32_t Value, uint32_t Alignment) {
	if (Alignment == 0) return Value;
	return (Value + Alignment - 1) & ~(Alignment - 1);
}
