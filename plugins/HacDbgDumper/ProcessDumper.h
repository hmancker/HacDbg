#pragma once
#include "PageMonitor.h"
#include "PeRebuilder.h"
#include <string>
#include <vector>
#include <mutex>

class ProcessDumper {
public:
	ProcessDumper();
	~ProcessDumper();
	bool Attach(DWORD TargetPid);
	bool StartMonitoring();
	bool DumpCurrent();
	bool Rebuild(const std::string& OutputPath);
	void SetDecryptionThreshold(float Threshold);
	uint64_t GetImageBase() const;
	uint64_t GetImageSize() const;
	uint64_t GetDecryptedCount() const;
	uint64_t GetTotalPages() const;
	bool IsMonitoring() const;
	float GetDecryptionProgress() const;
private:
	void OnPageDecrypted(const DecryptedRegion& Region);
	bool ReadInitialImage();
	bool ReadFromDisk(uint64_t Offset, uint64_t Size, uint8_t* Dest);
	bool AppendOverlayFromDisk(const std::string& OutputPath);
	std::string GetTargetFilePath();
	std::string ProcessName;
	uint64_t ImageBase;
	uint64_t ImageSize;
	float DecryptionThreshold;
	std::vector<uint8_t> DumpBuffer;
	std::mutex DumpMutex;
	PageMonitor Monitor;
	PeRebuilder Rebuilder;
	bool Attached;
};
