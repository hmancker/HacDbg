#pragma once
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace commands
{
	void process(const std::string& command);
	std::uint8_t read_command(std::string& command_out);
	std::uint8_t is_quit_command(const std::string& command);
	std::uint8_t poll_breakpoint();
	void cancel();
	void clear_cancel();
	std::uint8_t interrupt_requested();

	struct symbol_load_progress_t
	{
		std::uint32_t active = 0;
		std::uint32_t completed = 0;
		std::uint32_t total = 0;
	};

	symbol_load_progress_t symbol_load_progress();

	namespace views
	{
		struct module_t
		{
			std::string name = {};
			std::string symbol_path = {};
			std::uint64_t base = 0;
			std::uint64_t size = 0;
			std::uint64_t cr3 = 0;
			std::uint8_t kernel = 0;
			std::uint8_t symbols_loaded = 0;
		};

		struct process_t
		{
			std::string image = {};
			std::uint64_t eprocess = 0;
			std::uint64_t pid = 0;
			std::uint64_t parent_pid = 0;
			std::uint64_t peb = 0;
			std::uint64_t directory = 0;
			std::uint64_t user_cr3 = 0;
		};

		struct thread_t
		{
			std::string image = {};
			std::string state_name = {};
			std::string wait_reason_name = {};
			std::uint64_t ethread = 0;
			std::uint64_t eprocess = 0;
			std::uint64_t pid = 0;
			std::uint64_t tid = 0;
			std::uint64_t teb = 0;
			std::uint64_t trap = 0;
			std::uint64_t win32_start = 0;
			std::uint64_t stack_base = 0;
			std::uint64_t stack_limit = 0;
			std::uint64_t kernel_stack = 0;
			std::uint64_t instruction_pointer = 0;
			std::uint64_t cr3 = 0;
			std::uint32_t context_switches = 0;
			std::uint32_t wait_time = 0;
			std::uint32_t state = 0;
			std::int32_t priority = 0;
			std::int32_t suspend_count = 0;
			std::uint32_t wait_reason = 0;
			std::uint32_t wait_mode = 0;
			std::uint8_t system_thread = 0;
			std::uint8_t has_registers = 0;
			std::uint8_t kernel = 0;
		};

		struct stack_frame_t
		{
			std::string symbol = {};
			std::uint64_t child_sp = 0;
			std::uint64_t return_address = 0;
			std::uint64_t instruction_pointer = 0;
			std::uint64_t args[4] = {};
			std::uint32_t args_valid_mask = 0;
			std::uint8_t has_return = 0;
		};

		struct memory_t
		{
			std::vector<std::uint8_t> bytes = {};
			std::uint64_t address = 0;
			std::uint64_t cr3 = 0;
		};

		struct instruction_t
		{
			std::string bytes = {};
			std::string text = {};
			std::string symbol = {};
			std::uint64_t address = 0;
			std::uint64_t length = 0;
			std::uint8_t invalid = 0;
		};

		struct resolved_address_t
		{
			std::string symbol = {};
			std::uint64_t address = 0;
		};

		std::uint8_t modules(std::vector<module_t>& modules_out, std::string& error_out);
		std::uint8_t processes(std::vector<process_t>& processes_out, std::string& error_out);
		std::uint8_t threads(std::uint64_t eprocess, std::vector<thread_t>& threads_out,
		                     std::uint8_t& truncated_out, std::string& error_out);
		std::uint8_t stack(std::uint32_t frame_count, std::vector<stack_frame_t>& frames_out, std::string& error_out);
		std::uint8_t read_memory(std::uint64_t address, std::uint64_t cr3, std::uint32_t size, memory_t& memory_out,
		                         std::string& error_out);
		std::uint8_t disassemble(std::uint64_t address, std::uint64_t cr3, std::uint32_t instruction_count,
		                         std::vector<instruction_t>& instructions_out, std::uint64_t& next_address_out,
		                         std::string& error_out);
		std::uint8_t resolve(std::string_view text, resolved_address_t& address_out, std::string& error_out);
	}

	//
	// Fills matches for one whitespace-delimited token. A token without '!'
	// returns command names from the static table. A token with '!' returns
	// module!symbol names and may use the symbol parser; call that form only
	// from the core worker.
	//
	void collect_completions(const std::string& token, std::vector<std::string>& matches);
}
