#include "driver_um_lib.h"

namespace ioctl {

	static bool send_process_state_request(call_types_t call_type, uint64_t pid) {
		if (!inited || device_handle == INVALID_HANDLE_VALUE)
			return false;

		process_state_request_t request = { 0 };
		request.pid = pid;

		command_t cmd = { 0 };
		cmd.call_type = call_type;
		cmd.sub_command_ptr = &request;

		send_request(&cmd);
		return cmd.status;
	}

	__int64 send_request(void* cmd) {
		if (!inited || device_handle == INVALID_HANDLE_VALUE)
			return -1;

		DWORD bytes_returned = 0;
		BOOL result = DeviceIoControl(device_handle, IOCTL_SEND_COMMAND,
			cmd, sizeof(command_t), cmd, sizeof(command_t),
			&bytes_returned, nullptr);

		if (!result)
			return -1;

		return 0;
	}

	bool copy_virtual_memory(uint64_t src_pid, uint64_t dst_pid, void* src, void* dst, uint64_t size) {
		if (!inited || device_handle == INVALID_HANDLE_VALUE)
			return false;

		copy_virtual_memory_t copy_mem_cmd = { 0 };
		copy_mem_cmd.src_pid = src_pid;
		copy_mem_cmd.dst_pid = dst_pid;
		copy_mem_cmd.src = src;
		copy_mem_cmd.dst = dst;
		copy_mem_cmd.size = size;

		command_t cmd = { 0 };
		cmd.call_type = cmd_copy_virtual_memory;
		cmd.sub_command_ptr = &copy_mem_cmd;

		send_request(&cmd);

		return cmd.status;
	}

	uint64_t get_cr3(uint64_t pid) {
		if (!inited || device_handle == INVALID_HANDLE_VALUE)
			return 0;

		get_cr3_t get_cr3_cmd = { 0 };
		get_cr3_cmd.pid = pid;

		command_t cmd = { 0 };
		cmd.call_type = cmd_get_cr3;
		cmd.sub_command_ptr = &get_cr3_cmd;

		send_request(&cmd);

		return get_cr3_cmd.cr3;
	}

	uint64_t get_pid_by_name(const char* name) {
		if (!inited || device_handle == INVALID_HANDLE_VALUE || name == nullptr)
			return 0;

		get_pid_by_name_t get_pid_by_name_cmd = { 0 };
		strncpy_s(get_pid_by_name_cmd.name, name, _TRUNCATE);

		command_t cmd = { 0 };
		cmd.call_type = cmd_get_pid_by_name;
		cmd.sub_command_ptr = &get_pid_by_name_cmd;

		send_request(&cmd);

		return get_pid_by_name_cmd.pid;
	}

	uint64_t get_ldr_data_table_entry_count(uint64_t pid) {
		if (!inited || device_handle == INVALID_HANDLE_VALUE)
			return 0;

		get_ldr_data_table_entry_count_t get_ldr_data_table_entry = { 0 };
		get_ldr_data_table_entry.pid = pid;

		command_t cmd = { 0 };
		cmd.call_type = cmd_get_ldr_data_table_entry_count;
		cmd.sub_command_ptr = &get_ldr_data_table_entry;

		send_request(&cmd);

		return get_ldr_data_table_entry.count;
	}

	bool get_data_table_entry_info(uint64_t pid, module_info_t* info_array) {
		if (!inited || device_handle == INVALID_HANDLE_VALUE)
			return false;

		cmd_get_data_table_entry_info_t get_module_at_index = { 0 };
		get_module_at_index.pid = pid;
		get_module_at_index.info_array = info_array;

		command_t cmd = { 0 };
		cmd.call_type = cmd_get_data_table_entry_info;
		cmd.sub_command_ptr = &get_module_at_index;

		send_request(&cmd);

		return cmd.status;
	}

	bool suspend_process(uint64_t pid) {
		return send_process_state_request(cmd_suspend_process, pid);
	}

	bool resume_process(uint64_t pid) {
		return send_process_state_request(cmd_resume_process, pid);
	}

	bool ping_driver(void) {
		if (!inited || device_handle == INVALID_HANDLE_VALUE)
			return false;

		command_t cmd = { 0 };
		cmd.call_type = cmd_ping_driver;

		send_request(&cmd);

		return cmd.status;
	}
};
