#pragma once

#include <cstdint>
#include <span>

//
// Offsets of the kernel structures the debugger reads. One row covers a
// contiguous Windows build and ntoskrnl revision range. Lookup walks the
// table. UserDirectoryTableBase is zero when that build has no such field.
//
struct nt_offsets_t
{
	std::uint32_t build;
	std::uint32_t revision;
	std::uint16_t eprocess_directory_table_base;
	std::uint16_t eprocess_user_directory_table_base;
	std::uint16_t eprocess_unique_process_id;
	std::uint16_t eprocess_active_process_links;
	std::uint16_t eprocess_inherited_from_unique_process_id;
	std::uint16_t eprocess_peb;
	std::uint16_t eprocess_image_file_name;
	std::uint16_t eprocess_thread_list_head;
	std::uint16_t kthread_initial_stack;
	std::uint16_t kthread_stack_limit;
	std::uint16_t kthread_stack_base;
	std::uint16_t kthread_kernel_stack;
	std::uint16_t kthread_misc_flags;
	std::uint16_t kthread_system_thread_bit;
	std::uint16_t kthread_trap_frame;
	std::uint16_t kthread_priority;
	std::uint16_t kthread_teb;
	std::uint16_t kthread_context_switches;
	std::uint16_t kthread_state;
	std::uint16_t kthread_wait_mode;
	std::uint16_t kthread_wait_time;
	std::uint16_t kthread_win32_thread;
	std::uint16_t kthread_process;
	std::uint16_t kthread_wait_reason;
	std::uint16_t kthread_suspend_count;
	std::uint16_t ethread_cid;
	std::uint16_t ethread_win32_start_address;
	std::uint16_t ethread_thread_list_entry;
	std::uint16_t prcb_current_thread;
	std::uint16_t ktrap_rip;
	std::uint16_t ktrap_seg_cs;
};

const nt_offsets_t* nt_offsets_current();

std::uint8_t nt_offsets_select(std::uint32_t build, std::uint32_t revision, std::uint8_t revision_known);

std::uint8_t nt_offsets_select_from_image(std::span<const std::uint8_t> image);
