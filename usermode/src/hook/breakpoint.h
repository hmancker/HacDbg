#pragma once
#include <cstdint>
#include <string_view>
#include <vector>

#include <structures/trap_frame.h>

namespace breakpoint
{
	struct info_t
	{
		std::uint64_t id = 0;
		std::uint64_t address = 0;
		std::uint64_t cr3 = 0;
		std::uint8_t enabled = 0;
		std::uint8_t pauses_thread = 0;
	};

	// Guest state captured while a user breakpoint holds one thread in the pause stub.
	struct registers_t
	{
		std::uint64_t rax = 0;
		std::uint64_t rcx = 0;
		std::uint64_t rdx = 0;
		std::uint64_t rbx = 0;
		std::uint64_t rsp = 0;
		std::uint64_t rbp = 0;
		std::uint64_t rsi = 0;
		std::uint64_t rdi = 0;
		std::uint64_t r8 = 0;
		std::uint64_t r9 = 0;
		std::uint64_t r10 = 0;
		std::uint64_t r11 = 0;
		std::uint64_t r12 = 0;
		std::uint64_t r13 = 0;
		std::uint64_t r14 = 0;
		std::uint64_t r15 = 0;
		std::uint64_t rip = 0;
		std::uint64_t rflags = 0;
		std::uint64_t cr3 = 0;
		std::uint8_t rflags_known = 0;
	};

	std::uint64_t cr3_for_process(std::uint64_t process_id);
	std::uint8_t add(std::uint64_t address, std::uint64_t cr3, std::uint64_t& id_out);
	// Places a pause stub in caves near cave_hint. The thread is sent to the stub by the caller.
	// logical_rip is the address recorded in the pause log and the address g returns to.
	// cr3 translates the caves. The stub accepts whichever directory the thread returns with.
	std::uint8_t arm_direct_pause(std::uint64_t logical_rip, std::uint64_t cr3, std::uint64_t cave_hint, std::uint64_t& entry_out,
	                              std::uint64_t& id_out);
	// Installs a kernel pause at logical_rip and returns the stub the caller writes into the thread's resume RIP.
	// cr3 filters which directory stays in the spin. Zero accepts any directory.
	std::uint8_t arm_kernel_pause(std::uint64_t logical_rip, std::uint64_t cr3, std::uint64_t& entry_out, std::uint64_t& id_out);
	// Pause stub only. The caller overwrites one thread's saved resume address with entry_out.
	// logical_rip is not patched, so shared code such as KiSwapContext keeps running for every other thread.
	std::uint8_t arm_kernel_redirect(std::uint64_t logical_rip, std::uint64_t cr3, std::uint64_t& entry_out, std::uint64_t& id_out);
	std::uint8_t remove(std::uint64_t id);
	std::uint8_t remove_all();
	std::uint8_t set_enabled(std::uint64_t id, std::uint8_t enabled);
	std::uint8_t set_all_enabled(std::uint8_t enabled);
	std::vector<info_t> list();
	void clean_up();

	void observe_pause_logs(const trap_frame_log_t* logs, std::uint64_t count);

	// akh --monitor. log_rip is the address the stub asks the driver to
	// record. span is the stub length at address; a record whose rip falls
	// inside that stub still counts. Hits come from the log mailbox.
	struct monitor_site_t
	{
		std::uint64_t address = 0;
		std::uint64_t log_rip = 0;
		std::uint64_t span = 0;
		std::uint64_t hits = 0;
	};

	struct monitor_hit_t
	{
		std::uint64_t address = 0;
		std::uint64_t sequence = 0;
		trap_frame_log_t log = {};
	};

	std::uint8_t add_monitor(std::uint64_t address, std::uint64_t log_rip, std::uint64_t span);
	void remove_monitor(std::uint64_t address);
	void note_monitor_logs(const trap_frame_log_t* logs, std::uint64_t count);
	std::vector<monitor_site_t> monitor_sites();
	// Copies the oldest hits into Destination and drops them from the ring.
	// Newest is the capture count, including hits the ring has already overwritten.
	std::size_t copy_monitor_hits(monitor_hit_t* destination, std::size_t capacity, std::uint64_t* newest);
	// Copies new mailbox records into the monitor list. Does not take a pause.
	// Returns 1 when the mailbox still had a full chunk, so the caller should
	// drain again without waiting out an idle interval.
	std::uint8_t drain_monitor_mailbox();

	std::uint8_t capture_pause();
	std::uint8_t poll_new_pause();
	std::uint8_t has_paused_thread();
	std::uint64_t paused_breakpoint_id();
	std::vector<trap_frame_log_t> take_pending_logs();
	std::uint8_t paused_registers(registers_t& registers_out);
	std::uint8_t set_paused_register(std::string_view name, std::uint64_t value);
	std::uint8_t resume_paused();
	std::uint8_t read_paused_virtual(void* buffer, std::uint64_t address, std::uint64_t size);
	std::uint8_t write_paused_virtual(const void* buffer, std::uint64_t address, std::uint64_t size);
	std::uint64_t pause_entry_address();
	std::uint64_t step_cave_address(std::uint8_t index);
	std::uint64_t step_cave_capacity(std::uint8_t index);
	std::uint8_t write_step_cave(std::uint8_t index, const std::uint8_t* code, std::uint64_t size);
	std::uint8_t set_pause_site_patched(std::uint8_t patched);
	// logical_rip is what the next pause log records. go_target runs after registers are restored.
	// wait_ms == 0 returns as soon as the thread is released.
	std::uint8_t continue_paused_thread(std::uint64_t logical_rip, std::uint64_t go_target, std::uint64_t wait_ms);
}
