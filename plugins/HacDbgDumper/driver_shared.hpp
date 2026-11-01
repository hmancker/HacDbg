#pragma once
#pragma optimize("", off)

#ifndef MAX_PATH
#define MAX_PATH 260
#endif

#define DEVICE_NAME "\\\\.\\PdIoctl"
#define IOCTL_SEND_COMMAND CTL_CODE(0x800, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)

#ifndef _UINT8_T_DEFINED
using uint8_t = unsigned char;
#endif
#ifndef _UINT16_T_DEFINED
using uint16_t = unsigned short;
#endif
#ifndef _UINT32_T_DEFINED
using uint32_t = unsigned int;
#endif
#ifndef _UINT64_T_DEFINED
using uint64_t = unsigned long long;
#endif

struct copy_virtual_memory_t {
	uint64_t src_pid;
	uint64_t dst_pid;
	void* src;
	void* dst;
	uint64_t size;
};

struct get_cr3_t {
	uint64_t pid;
	uint64_t cr3;
};

struct get_pid_by_name_t {
	char name[MAX_PATH];
	uint64_t pid;
};

struct get_ldr_data_table_entry_count_t {
	uint64_t pid;
	uint64_t count;
};

struct process_state_request_t {
	uint64_t pid;
};

struct module_info_t {
	char name[MAX_PATH];
	uint64_t base;
	uint64_t size;
};

struct cmd_get_data_table_entry_info_t {
	uint64_t pid;
	module_info_t* info_array;
};

enum call_types_t : uint32_t {
	cmd_get_pid_by_name,
	cmd_get_cr3,
	cmd_get_ldr_data_table_entry_count,
	cmd_get_data_table_entry_info,
	cmd_copy_virtual_memory,
	cmd_suspend_process,
	cmd_resume_process,
	cmd_remove_from_system_page_tables,
	cmd_ping_driver,
};

struct command_t {
	bool status;
	call_types_t call_type;
	void* sub_command_ptr;
};

static_assert(sizeof(bool) == 1, "command_t status width");
static_assert(sizeof(command_t) == 16, "command_t layout");

#pragma optimize("", on)
