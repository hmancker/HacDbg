#include "ProcessDumper.h"
#include <Psapi.h>
#include <fstream>

ProcessDumper::ProcessDumper()
	: ImageBase(0), ImageSize(0), Attached(false), DecryptionThreshold(1.0f) {}

ProcessDumper::~ProcessDumper() { Monitor.Stop(); }

bool ProcessDumper::Attach(DWORD TargetPid) {
	if (!process::attach_to_proc((uint64_t)TargetPid)) { logging("Failed to attach to PID %lu", TargetPid); return false; }
	{
		HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, TargetPid);
		if (hProc) {
			char Path[MAX_PATH] = {};
			DWORD PathSize = MAX_PATH;
			if (QueryFullProcessImageNameA(hProc, 0, Path, &PathSize)) {
				std::string FullPath(Path);
				size_t SlashPos = FullPath.find_last_of("\\/");
				ProcessName = (SlashPos != std::string::npos) ? FullPath.substr(SlashPos + 1) : FullPath;
			}
			CloseHandle(hProc);
		}
		if (ProcessName.empty()) { logging("Warning: Could not resolve process name from PID %lu", TargetPid); ProcessName = "unknown.exe"; }
	}
	logging("Attached to PID %lu (%s)", TargetPid, ProcessName.c_str());
	std::string ModuleName = ProcessName;
	size_t DotPos = ModuleName.find_last_of('.');
	if (DotPos == std::string::npos) ModuleName += ".exe";
	ImageBase = process::get_module_base(ModuleName);
	if (!ImageBase) { logging("Failed to get image base for %s", ModuleName.c_str()); return false; }
	ImageSize = process::get_module_size(ModuleName);
	if (!ImageSize) { logging("Failed to get image size for %s", ModuleName.c_str()); return false; }
	logging("Image: 0x%llX | Size: 0x%llX (%llu KB)", ImageBase, ImageSize, ImageSize / 1024);
	DumpBuffer.resize(ImageSize, 0);
	if (!ReadInitialImage()) logging("Warning: Initial image read incomplete, monitor will fill in the rest");
	Attached = true;
	return true;
}

bool ProcessDumper::StartMonitoring() {
	if (!Attached) { logging("Not attached"); return false; }
	if (!Monitor.Init(ImageBase, ImageSize)) { logging("Failed to init page monitor"); return false; }
	Monitor.SetCallback([this](const DecryptedRegion& Region) { OnPageDecrypted(Region); });
	Monitor.Start();
	logging("Monitor started - scanning pages via driver");
	return true;
}

bool ProcessDumper::DumpCurrent() { Monitor.Stop(); logging("Monitor stopped"); return true; }

bool ProcessDumper::Rebuild(const std::string& OutputPath) {
	std::lock_guard<std::mutex> Lock(DumpMutex);
	if (!Rebuilder.LoadFromBuffer(DumpBuffer.data(), DumpBuffer.size(), ImageBase)) { logging("Failed to parse dump buffer"); return false; }

	// Match x64dbg/Scylla approach: minimal header fixes only
	// NOTE: FixSectionHeaders FIRST (reads IAT VA for WRITE flag), then FixHeaders (clears IAT)
	Rebuilder.FixSectionHeaders();   // Compact layout + add WRITE to IAT section
	Rebuilder.FixHeaders();          // Set ImageBase, clear IAT DataDirectory

	if (!Rebuilder.SaveToDisk(OutputPath)) {
		return false;
	}

	AppendOverlayFromDisk(OutputPath);
	return true;
}

void ProcessDumper::SetDecryptionThreshold(float Threshold) {
	DecryptionThreshold = Threshold;
	if (DecryptionThreshold < 0.0f) DecryptionThreshold = 0.0f;
	if (DecryptionThreshold > 1.0f) DecryptionThreshold = 1.0f;
}

uint64_t ProcessDumper::GetImageBase() const { return ImageBase; }
uint64_t ProcessDumper::GetImageSize() const { return ImageSize; }
uint64_t ProcessDumper::GetDecryptedCount() const { return Monitor.GetDecryptedCount(); }
uint64_t ProcessDumper::GetTotalPages() const { return Monitor.GetTotalPages(); }
bool ProcessDumper::IsMonitoring() const { return Monitor.IsRunning(); }
float ProcessDumper::GetDecryptionProgress() const {
	uint64_t Total = Monitor.GetTotalPages();
	if (Total == 0) return 0.0f;
	return (float)Monitor.GetDecryptedCount() / (float)Total;
}

void ProcessDumper::OnPageDecrypted(const DecryptedRegion& Region) {
	std::lock_guard<std::mutex> Lock(DumpMutex);
	uint64_t Offset = Region.BaseAddress - ImageBase;
	if (Offset + Region.Size > DumpBuffer.size()) return;
	memcpy(DumpBuffer.data() + Offset, Region.Data.data(), Region.Size);
}

bool ProcessDumper::ReadInitialImage() {
	constexpr uint64_t ChunkSize = 0x1000;
	uint64_t PagesRead = 0;
	uint64_t TotalPages = ImageSize / ChunkSize;
	std::string DiskPath = GetTargetFilePath();
	std::ifstream DiskFile;
	std::vector<uint8_t> DiskBuffer;
	if (!DiskPath.empty()) {
		DiskFile.open(DiskPath, std::ios::binary);
		if (DiskFile.is_open()) {
			DiskFile.seekg(0, std::ios::end);
			auto FileSize = DiskFile.tellg();
			DiskFile.seekg(0, std::ios::beg);
			DiskBuffer.resize(FileSize);
			DiskFile.read(reinterpret_cast<char*>(DiskBuffer.data()), FileSize);
			DiskFile.close();
			logging("Loaded on-disk PE fallback: %s (%llu bytes)", DiskPath.c_str(), DiskBuffer.size());
		}
	}
	for (uint64_t Offset = 0; Offset < ImageSize; Offset += ChunkSize) {
		uint64_t ReadSize = min(ChunkSize, ImageSize - Offset);
		bool Ok = process::read_array(DumpBuffer.data() + Offset, (void*)(ImageBase + Offset), ReadSize);
		if (Ok) { PagesRead++; continue; }
		if (!DiskBuffer.empty() && Offset + ReadSize <= DiskBuffer.size()) {
			memcpy(DumpBuffer.data() + Offset, DiskBuffer.data() + Offset, ReadSize);
			PagesRead++;
		}
	}
	logging("Initial read: %llu / %llu pages", PagesRead, TotalPages);
	return PagesRead > 0;
}

bool ProcessDumper::ReadFromDisk(uint64_t Offset, uint64_t Size, uint8_t* Dest) {
	std::string Path = GetTargetFilePath();
	if (Path.empty()) return false;
	std::ifstream File(Path, std::ios::binary);
	if (!File.is_open()) return false;
	File.seekg(Offset);
	File.read(reinterpret_cast<char*>(Dest), Size);
	return File.good();
}

bool ProcessDumper::AppendOverlayFromDisk(const std::string& OutputPath) {
	std::string Path = GetTargetFilePath();
	if (Path.empty()) {
		return false;
	}

	uint64_t overlayOffset = 0;
	try {
		overlayOffset = std::filesystem::file_size(OutputPath);
	} catch (...) {
		logging("Overlay skipped: failed to get rebuilt output size for %s", OutputPath.c_str());
		return false;
	}

	std::ifstream Input(Path, std::ios::binary | std::ios::ate);
	if (!Input.is_open()) {
		logging("Overlay skipped: failed to open source file %s", Path.c_str());
		return false;
	}

	const uint64_t fileSize = static_cast<uint64_t>(Input.tellg());

	if (fileSize <= overlayOffset) {
		return true;
	}

	const uint64_t overlaySize = fileSize - overlayOffset;
	std::vector<char> overlayData(static_cast<size_t>(overlaySize));
	Input.seekg(static_cast<std::streamoff>(overlayOffset), std::ios::beg);
	Input.read(overlayData.data(), static_cast<std::streamsize>(overlaySize));
	if (!Input.good()) {
		logging("Overlay skipped: failed to read overlay from %s", Path.c_str());
		return false;
	}

	std::ofstream Output(OutputPath, std::ios::binary | std::ios::app);
	if (!Output.is_open()) {
		logging("Overlay skipped: failed to reopen output file %s", OutputPath.c_str());
		return false;
	}
	Output.write(overlayData.data(), static_cast<std::streamsize>(overlayData.size()));
	if (!Output.good()) {
		logging("Overlay skipped: failed to append overlay to %s", OutputPath.c_str());
		return false;
	}

	logging("Overlay appended: 0x%llX bytes from %s", overlaySize, Path.c_str());
	return true;
}

std::string ProcessDumper::GetTargetFilePath() {
	HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)process::target_pid);
	if (!hProc) return "";
	char Path[MAX_PATH] = {};
	DWORD PathSize = MAX_PATH;
	QueryFullProcessImageNameA(hProc, 0, Path, &PathSize);
	CloseHandle(hProc);
	return std::string(Path);
}
