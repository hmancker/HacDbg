#include <ntddk.h>
#include <intrin.h>
#include "driver_shared.hpp"

#ifndef MAX_PATH
#define MAX_PATH 260
#endif

//
// x64 PEB.Ldr. The loader list walked below starts at this field.
//
#define PEB_LDR_OFFSET 0x18

//
// SystemProcessInformation. ZwQuerySystemInformation class 5.
//
#define SYSTEM_PROCESS_INFORMATION_CLASS 5

//
// KPROCESS.DirectoryTableBase. The debugger version table records this
// field at offset 0x28.
//
#define DIRECTORY_TABLE_BASE_OFFSET 0x28

typedef struct _KAPC_STATE {
	LIST_ENTRY ApcListHead[2];
	PKPROCESS Process;
	union {
		UCHAR InProgressFlags;
		struct {
			BOOLEAN KernelApcInProgress;
			BOOLEAN SpecialApcInProgress;
		};
	};
	BOOLEAN KernelApcPending;
	union {
		BOOLEAN UserApcPendingAll;
		struct {
			BOOLEAN SpecialUserApcPending;
			BOOLEAN UserApcPending;
		};
	};
} KAPC_STATE, *PKAPC_STATE;

extern "C" {
	NTSTATUS IoCreateDriver(PUNICODE_STRING DriverName, PDRIVER_INITIALIZE InitializationFunction);
	NTKERNELAPI NTSTATUS MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress,
		PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize,
		KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);
	NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(HANDLE ProcessId, PEPROCESS* Process);
	NTKERNELAPI PPEB PsGetProcessPeb(PEPROCESS Process);
	NTKERNELAPI VOID KeStackAttachProcess(PVOID Process, PKAPC_STATE ApcState);
	NTKERNELAPI VOID KeUnstackDetachProcess(PKAPC_STATE ApcState);
	NTKERNELAPI NTSTATUS PsSuspendProcess(PEPROCESS Process);
	NTKERNELAPI NTSTATUS PsResumeProcess(PEPROCESS Process);
	NTSTATUS ZwQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation,
		ULONG SystemInformationLength, PULONG ReturnLength);
}

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER Reserved[3];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR UniqueProcessKey;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

typedef struct _PEB_LDR_DATA_FULL {
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA_FULL, *PPEB_LDR_DATA_FULL;

typedef struct _LDR_DATA_TABLE_ENTRY_FULL {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY_FULL, *PLDR_DATA_TABLE_ENTRY_FULL;

namespace {
	constexpr ULONG kPoolTag = 'pmdP';
	constexpr uint64_t kMaxCopySize = 0x100000;
	PDEVICE_OBJECT g_device_object = nullptr;
	UNICODE_STRING g_symlink_name = {};

	char ascii_lower(char value) {
		if (value >= 'A' && value <= 'Z') {
			return static_cast<char>(value - 'A' + 'a');
		}
		return value;
	}

	bool name_equal(const char* left, const char* right) {
		if (left == nullptr || right == nullptr) {
			return false;
		}

		while (*left != '\0' && *right != '\0') {
			if (ascii_lower(*left) != ascii_lower(*right)) {
				return false;
			}
			++left;
			++right;
		}

		return *left == *right;
	}

	void unicode_to_ansi(UNICODE_STRING* src, char* dst, uint32_t max_len) {
		if (dst == nullptr || max_len == 0) {
			return;
		}

		dst[0] = '\0';
		if (src == nullptr || src->Buffer == nullptr || src->Length == 0) {
			return;
		}

		uint32_t len = src->Length / sizeof(WCHAR);
		if (len >= max_len) {
			len = max_len - 1;
		}

		for (uint32_t index = 0; index < len; ++index) {
			dst[index] = static_cast<char>(src->Buffer[index]);
		}

		dst[len] = '\0';
	}

	NTSTATUS find_pid_by_name(const char* target_name, uint64_t* out_pid) {
		if (target_name == nullptr || out_pid == nullptr) {
			return STATUS_INVALID_PARAMETER;
		}

		ULONG buffer_size = 0;
		ZwQuerySystemInformation(SYSTEM_PROCESS_INFORMATION_CLASS, nullptr, 0, &buffer_size);
		if (!buffer_size) {
			return STATUS_UNSUCCESSFUL;
		}

		buffer_size += 0x10000;
		void* buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, buffer_size, kPoolTag);
		if (!buffer) {
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		NTSTATUS status = ZwQuerySystemInformation(SYSTEM_PROCESS_INFORMATION_CLASS, buffer, buffer_size, nullptr);
		if (!NT_SUCCESS(status)) {
			ExFreePoolWithTag(buffer, kPoolTag);
			return status;
		}

		auto* entry = static_cast<PSYSTEM_PROCESS_INFORMATION>(buffer);
		while (true) {
			if (entry->ImageName.Buffer && entry->ImageName.Length > 0) {
				char ansi_name[MAX_PATH] = {};
				unicode_to_ansi(&entry->ImageName, ansi_name, MAX_PATH);
				if (name_equal(ansi_name, target_name)) {
					*out_pid = reinterpret_cast<uint64_t>(entry->UniqueProcessId);
					ExFreePoolWithTag(buffer, kPoolTag);
					return STATUS_SUCCESS;
				}
			}

			if (entry->NextEntryOffset == 0) {
				break;
			}

			entry = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(reinterpret_cast<uint8_t*>(entry) + entry->NextEntryOffset);
		}

		ExFreePoolWithTag(buffer, kPoolTag);
		return STATUS_NOT_FOUND;
	}

	NTSTATUS walk_process_modules(uint64_t pid, module_info_t* info_array, uint64_t capacity, uint64_t* out_count, bool count_only) {
		PEPROCESS process = nullptr;
		NTSTATUS status = PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(pid), &process);
		if (!NT_SUCCESS(status)) {
			return status;
		}

		KAPC_STATE apc_state = {};
		KeStackAttachProcess(reinterpret_cast<PRKPROCESS>(process), &apc_state);

		uint64_t module_count = 0;
		__try {
			PPEB peb = PsGetProcessPeb(process);
			if (!peb) {
				KeUnstackDetachProcess(&apc_state);
				ObDereferenceObject(process);
				return STATUS_UNSUCCESSFUL;
			}

			auto* ldr = *reinterpret_cast<PPEB_LDR_DATA_FULL*>(reinterpret_cast<uint8_t*>(peb) + PEB_LDR_OFFSET);
			if (!ldr || !ldr->Initialized) {
				KeUnstackDetachProcess(&apc_state);
				ObDereferenceObject(process);
				return STATUS_UNSUCCESSFUL;
			}

			PLIST_ENTRY head = &ldr->InLoadOrderModuleList;
			PLIST_ENTRY current = head->Flink;
			while (current != head) {
				auto* entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY_FULL, InLoadOrderLinks);

				if (!count_only && info_array) {
					if (module_count >= capacity) {
						break;
					}

					module_info_t info = {};
					if (entry->BaseDllName.Buffer && entry->BaseDllName.Length > 0) {
						unicode_to_ansi(&entry->BaseDllName, info.name, MAX_PATH);
					}
					info.base = reinterpret_cast<uint64_t>(entry->DllBase);
					info.size = static_cast<uint64_t>(entry->SizeOfImage);
					info_array[module_count] = info;
				}

				++module_count;
				current = current->Flink;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			KeUnstackDetachProcess(&apc_state);
			ObDereferenceObject(process);
			return STATUS_ACCESS_VIOLATION;
		}

		KeUnstackDetachProcess(&apc_state);
		ObDereferenceObject(process);

		if (out_count) {
			*out_count = module_count;
		}

		return STATUS_SUCCESS;
	}

	NTSTATUS copy_process_state_request(command_t* cmd, process_state_request_t* sub_cmd) {
		if (!cmd || !sub_cmd || !cmd->sub_command_ptr) {
			return STATUS_INVALID_PARAMETER;
		}

		__try {
			RtlCopyMemory(sub_cmd, cmd->sub_command_ptr, sizeof(*sub_cmd));
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return STATUS_ACCESS_VIOLATION;
		}

		if (!sub_cmd->pid) {
			return STATUS_INVALID_CID;
		}

		return STATUS_SUCCESS;
	}

	NTSTATUS suspend_process_by_pid(uint64_t pid) {
		PEPROCESS process = nullptr;
		NTSTATUS status = PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(pid), &process);
		if (!NT_SUCCESS(status)) {
			return status;
		}

		status = PsSuspendProcess(process);
		ObDereferenceObject(process);
		return status;
	}

	NTSTATUS resume_process_by_pid(uint64_t pid) {
		PEPROCESS process = nullptr;
		NTSTATUS status = PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(pid), &process);
		if (!NT_SUCCESS(status)) {
			return status;
		}

		status = PsResumeProcess(process);
		ObDereferenceObject(process);
		return status;
	}

	NTSTATUS handle_suspend_process_command(command_t* cmd) {
		process_state_request_t sub_cmd = {};
		NTSTATUS status = copy_process_state_request(cmd, &sub_cmd);
		if (!NT_SUCCESS(status)) {
			return status;
		}

		status = suspend_process_by_pid(sub_cmd.pid);
		if (!NT_SUCCESS(status)) {
			return status;
		}

		cmd->status = true;
		return STATUS_SUCCESS;
	}

	NTSTATUS handle_resume_process_command(command_t* cmd) {
		process_state_request_t sub_cmd = {};
		NTSTATUS status = copy_process_state_request(cmd, &sub_cmd);
		if (!NT_SUCCESS(status)) {
			return status;
		}

		status = resume_process_by_pid(sub_cmd.pid);
		if (!NT_SUCCESS(status)) {
			return status;
		}

		cmd->status = true;
		return STATUS_SUCCESS;
	}

	NTSTATUS handle_command(command_t* cmd) {
		if (!cmd->sub_command_ptr && cmd->call_type != cmd_ping_driver) {
			return STATUS_INVALID_PARAMETER;
		}

		switch (cmd->call_type) {
		case cmd_ping_driver:
			cmd->status = true;
			break;

		case cmd_get_pid_by_name: {
			get_pid_by_name_t sub_cmd = {};
			__try {
				RtlCopyMemory(&sub_cmd, cmd->sub_command_ptr, sizeof(sub_cmd));
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				return STATUS_ACCESS_VIOLATION;
			}

			uint64_t pid = 0;
			NTSTATUS status = find_pid_by_name(sub_cmd.name, &pid);
			if (!NT_SUCCESS(status)) {
				return status;
			}

			sub_cmd.pid = pid;
			__try {
				RtlCopyMemory(cmd->sub_command_ptr, &sub_cmd, sizeof(sub_cmd));
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				return STATUS_ACCESS_VIOLATION;
			}

			cmd->status = true;
		} break;

		case cmd_get_cr3: {
			get_cr3_t sub_cmd = {};
			__try {
				RtlCopyMemory(&sub_cmd, cmd->sub_command_ptr, sizeof(sub_cmd));
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				return STATUS_ACCESS_VIOLATION;
			}

			PEPROCESS process = nullptr;
			NTSTATUS status = PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(sub_cmd.pid), &process);
			if (!NT_SUCCESS(status)) {
				return status;
			}

			sub_cmd.cr3 = *reinterpret_cast<uint64_t*>(reinterpret_cast<uint8_t*>(process) + DIRECTORY_TABLE_BASE_OFFSET);
			ObDereferenceObject(process);

			if (!sub_cmd.cr3) {
				return STATUS_UNSUCCESSFUL;
			}

			__try {
				RtlCopyMemory(cmd->sub_command_ptr, &sub_cmd, sizeof(sub_cmd));
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				return STATUS_ACCESS_VIOLATION;
			}

			cmd->status = true;
		} break;

		case cmd_get_ldr_data_table_entry_count: {
			get_ldr_data_table_entry_count_t sub_cmd = {};
			__try {
				RtlCopyMemory(&sub_cmd, cmd->sub_command_ptr, sizeof(sub_cmd));
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				return STATUS_ACCESS_VIOLATION;
			}

			uint64_t count = 0;
			NTSTATUS status = walk_process_modules(sub_cmd.pid, nullptr, 0, &count, true);
			if (!NT_SUCCESS(status)) {
				return status;
			}

			sub_cmd.count = count;
			__try {
				RtlCopyMemory(cmd->sub_command_ptr, &sub_cmd, sizeof(sub_cmd));
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				return STATUS_ACCESS_VIOLATION;
			}

			cmd->status = true;
		} break;

		case cmd_get_data_table_entry_info: {
			cmd_get_data_table_entry_info_t sub_cmd = {};
			__try {
				RtlCopyMemory(&sub_cmd, cmd->sub_command_ptr, sizeof(sub_cmd));
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				return STATUS_ACCESS_VIOLATION;
			}

			if (!sub_cmd.info_array) {
				return STATUS_INVALID_PARAMETER;
			}

			uint64_t count = 0;
			NTSTATUS status = walk_process_modules(sub_cmd.pid, nullptr, 0, &count, true);
			if (!NT_SUCCESS(status) || count == 0) {
				return STATUS_UNSUCCESSFUL;
			}

			auto* temp = static_cast<module_info_t*>(ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(module_info_t) * count, kPoolTag));
			if (!temp) {
				return STATUS_INSUFFICIENT_RESOURCES;
			}

			status = walk_process_modules(sub_cmd.pid, temp, count, &count, false);
			if (!NT_SUCCESS(status)) {
				ExFreePoolWithTag(temp, kPoolTag);
				return status;
			}

			__try {
				RtlCopyMemory(sub_cmd.info_array, temp, sizeof(module_info_t) * count);
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				ExFreePoolWithTag(temp, kPoolTag);
				return STATUS_ACCESS_VIOLATION;
			}

			ExFreePoolWithTag(temp, kPoolTag);
			cmd->status = true;
		} break;

		case cmd_copy_virtual_memory: {
			copy_virtual_memory_t sub_cmd = {};
			__try {
				RtlCopyMemory(&sub_cmd, cmd->sub_command_ptr, sizeof(sub_cmd));
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				return STATUS_ACCESS_VIOLATION;
			}

			if (!sub_cmd.src || !sub_cmd.dst || !sub_cmd.size || sub_cmd.size > kMaxCopySize) {
				return STATUS_INVALID_PARAMETER;
			}

			PEPROCESS src_process = nullptr;
			PEPROCESS dst_process = nullptr;

			NTSTATUS status = PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(sub_cmd.src_pid), &src_process);
			if (!NT_SUCCESS(status)) {
				return status;
			}

			status = PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(sub_cmd.dst_pid), &dst_process);
			if (!NT_SUCCESS(status)) {
				ObDereferenceObject(src_process);
				return status;
			}

			SIZE_T bytes_copied = 0;
			status = MmCopyVirtualMemory(src_process, sub_cmd.src, dst_process, sub_cmd.dst, sub_cmd.size, KernelMode, &bytes_copied);

			ObDereferenceObject(src_process);
			ObDereferenceObject(dst_process);

			if (!NT_SUCCESS(status) || bytes_copied != sub_cmd.size) {
				return NT_SUCCESS(status) ? STATUS_PARTIAL_COPY : status;
			}

			cmd->status = true;
		} break;

		case cmd_suspend_process:
			return handle_suspend_process_command(cmd);

		case cmd_resume_process:
			return handle_resume_process_command(cmd);

		case cmd_remove_from_system_page_tables:
			return STATUS_NOT_SUPPORTED;

		default:
			return STATUS_INVALID_PARAMETER;
		}

		return STATUS_SUCCESS;
	}
}

NTSTATUS ioctl_dispatch(PDEVICE_OBJECT device, PIRP irp) {
	UNREFERENCED_PARAMETER(device);

	auto* stack = IoGetCurrentIrpStackLocation(irp);
	NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
	ULONG bytes_returned = 0;

	if (stack->Parameters.DeviceIoControl.IoControlCode == IOCTL_SEND_COMMAND) {
		if (stack->Parameters.DeviceIoControl.InputBufferLength >= sizeof(command_t) &&
			stack->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(command_t) &&
			irp->AssociatedIrp.SystemBuffer != nullptr) {
			auto* cmd = static_cast<command_t*>(irp->AssociatedIrp.SystemBuffer);
			cmd->status = false;
			status = handle_command(cmd);
			if (NT_SUCCESS(status)) {
				bytes_returned = sizeof(command_t);
			}
		}
	}

	irp->IoStatus.Status = status;
	irp->IoStatus.Information = bytes_returned;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS create_close_dispatch(PDEVICE_OBJECT device, PIRP irp) {
	UNREFERENCED_PARAMETER(device);
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS driver_initialize(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path) {
	UNREFERENCED_PARAMETER(registry_path);

	UNICODE_STRING device_name = {};
	RtlInitUnicodeString(&device_name, L"\\Device\\PdIoctl");
	RtlInitUnicodeString(&g_symlink_name, L"\\DosDevices\\PdIoctl");

	NTSTATUS status = IoCreateDevice(driver_object,
		0,
		&device_name,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&g_device_object);
	if (!NT_SUCCESS(status)) {
		g_symlink_name = {};
		return status;
	}

	driver_object->MajorFunction[IRP_MJ_CREATE] = create_close_dispatch;
	driver_object->MajorFunction[IRP_MJ_CLOSE] = create_close_dispatch;
	driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ioctl_dispatch;
	g_device_object->Flags |= DO_BUFFERED_IO;

	status = IoCreateSymbolicLink(&g_symlink_name, &device_name);
	if (!NT_SUCCESS(status)) {
		IoDeleteDevice(g_device_object);
		g_device_object = nullptr;
		g_symlink_name = {};
		return status;
	}

	g_device_object->Flags &= ~DO_DEVICE_INITIALIZING;
	return STATUS_SUCCESS;
}

extern "C" NTSTATUS driver_entry(void* driver_base, uint64_t driver_size) {
	UNREFERENCED_PARAMETER(driver_base);
	UNREFERENCED_PARAMETER(driver_size);

	return IoCreateDriver(nullptr, driver_initialize);
}
