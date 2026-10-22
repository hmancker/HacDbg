#include "commands.h"
#include <CLI/CLI.hpp>
#include <hypercall/hypercall_def.h>
#include "../hook/breakpoint.h"
#include "../hook/hook.h"
#include "../hook/hook_disassembly.h"
#include <symbol_parser.h>

#include <Windows.h>
#include "../hypercall/hypercall.h"
#include "../system/system.h"
#include "../logs/logs.h"

#include <version.h>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

#include <Zydis/Zydis.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <thread>
#include <ranges>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "../script/script.h"

constexpr std::uint64_t command_memory_size_limit = 0x1000000;

#define INVOKE_COMMAND_PROCESSOR(command) process_##command(command)
#define PROCESS_INITIAL_COMMAND(command) if (*command) INVOKE_COMMAND_PROCESSOR(command)
#define PROCESS_COMMAND(command) else if (*command) INVOKE_COMMAND_PROCESSOR(command)

template <class T>
static T get_command_option(const CLI::App* const app, const std::string& option_name)
{
	const auto* const option = app->get_option(option_name);

	return !option->empty() ? option->as<T>() : T{};
}

static CLI::Option* add_command_option(CLI::App* const app, const std::string& option_name)
{
	return app->add_option(option_name);
}

static CLI::Option* add_transformed_command_option(CLI::App* const app, const std::string& option_name,
                                                   const CLI::Transformer& transformer)
{
	auto* const option = add_command_option(app, option_name);

	return option->transform(transformer);
}

static std::uint8_t get_command_flag(const CLI::App* const app, const std::string& flag_name)
{
	const auto* const option = app->get_option(flag_name);

	return static_cast<std::uint8_t>(!option->empty());
}

static CLI::Option* add_command_flag(CLI::App* app, const std::string& flag_name)
{
	return app->add_flag(flag_name);
}

static CLI::Option* add_memory_size_option(CLI::App* const app)
{
	return add_command_option(app, "size")
		->check(CLI::Range(static_cast<std::uint64_t>(0), command_memory_size_limit))
		->required();
}

static std::uint8_t parse_u64(const std::string& text, std::uint64_t& value_out)
{
	if (text.empty() == true)
	{
		return 0;
	}

	try
	{
		std::size_t consumed = 0;

		value_out = std::stoull(text, &consumed, 0);

		return static_cast<std::uint8_t>(consumed == text.size());
	}
	catch (const std::exception&)
	{
		return 0;
	}
}

static std::uint8_t parse_hex_nibble(const char character, std::uint8_t& nibble_out)
{
	if (character >= '0' && character <= '9')
	{
		nibble_out = static_cast<std::uint8_t>(character - '0');

		return 1;
	}

	if (character >= 'a' && character <= 'f')
	{
		nibble_out = static_cast<std::uint8_t>(character - 'a' + 10);

		return 1;
	}

	if (character >= 'A' && character <= 'F')
	{
		nibble_out = static_cast<std::uint8_t>(character - 'A' + 10);

		return 1;
	}

	return 0;
}

static std::uint8_t fill_memory_write_buffer(std::vector<std::uint8_t>& buffer, const std::string& value_text)
{
	if (buffer.empty() == true)
	{
		return 1;
	}

	if (buffer.size() <= sizeof(std::uint64_t))
	{
		std::uint64_t value = 0;

		if (parse_u64(value_text, value) == 0)
		{
			return 0;
		}

		std::memcpy(buffer.data(), &value, buffer.size());

		return 1;
	}

	std::string_view hex = value_text;

	if (hex.size() >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X'))
	{
		hex.remove_prefix(2);
	}

	if (hex.size() != buffer.size() * 2)
	{
		return 0;
	}

	for (std::size_t index = 0; index < buffer.size(); index++)
	{
		std::uint8_t high = 0;
		std::uint8_t low = 0;

		if (parse_hex_nibble(hex[index * 2], high) == 0 || parse_hex_nibble(hex[index * 2 + 1], low) == 0)
		{
			return 0;
		}

		buffer[index] = static_cast<std::uint8_t>((high << 4) | low);
	}

	return 1;
}

static void log_read_memory(const std::uint8_t* const data, const std::uint64_t size)
{
	if (size <= sizeof(std::uint64_t))
	{
		std::uint64_t value = 0;

		if (size != 0)
		{
			std::memcpy(&value, data, static_cast<std::size_t>(size));
		}

		LOG_INFO("value: 0x{:x}", value);

		return;
	}

	LOG_INFO("read 0x{:x} bytes:", size);

	for (std::uint64_t offset = 0; offset < size; offset += 16)
	{
		std::string line = fmt::format("{:08x} ", offset);
		const std::uint64_t line_count = (size - offset) < 16 ? (size - offset) : 16;

		for (std::uint64_t index = 0; index < line_count; index++)
		{
			line += fmt::format("{:02X} ", data[offset + index]);
		}

		LOG_INFO("{}", line);
	}
}

static void log_rejected_write_value(const std::uint64_t size)
{
	if (size > sizeof(std::uint64_t))
	{
		LOG_ERR("value must be a {}-byte hex string", size);

		return;
	}

	LOG_ERR("failed to parse value");
}

static CLI::App* init_rgpm(CLI::App& app, const CLI::Transformer& aliases_transformer)
{
	CLI::App* rgpm = app.add_subcommand("rgpm", "reads memory from a given guest physical address")->ignore_case();

	add_transformed_command_option(rgpm, "physical_address", aliases_transformer)->required();
	add_memory_size_option(rgpm);

	return rgpm;
}

static void process_rgpm(const CLI::App* const rgpm)
{
	const auto guest_physical_address = get_command_option<std::uint64_t>(rgpm, "physical_address");
	const auto size = get_command_option<std::uint64_t>(rgpm, "size");

	std::vector<std::uint8_t> buffer(static_cast<std::size_t>(size));

	const std::uint64_t bytes_read = hypercall::read_guest_physical_memory(buffer.data(), guest_physical_address, size);

	if (bytes_read == size)
	{
		log_read_memory(buffer.data(), size);
	}
	else
	{
		LOG_ERR("failed to read");
	}
}

static CLI::App* init_wgpm(CLI::App& app, const CLI::Transformer& aliases_transformer)
{
	CLI::App* wgpm = app.add_subcommand("wgpm", "writes memory to a given guest physical address")->ignore_case();

	add_transformed_command_option(wgpm, "physical_address", aliases_transformer)->required();
	add_command_option(wgpm, "value")->required();
	add_memory_size_option(wgpm);

	return wgpm;
}

static void process_wgpm(const CLI::App* const wgpm)
{
	const auto guest_physical_address = get_command_option<std::uint64_t>(wgpm, "physical_address");
	const auto size = get_command_option<std::uint64_t>(wgpm, "size");
	const auto value_text = get_command_option<std::string>(wgpm, "value");

	std::vector<std::uint8_t> buffer(static_cast<std::size_t>(size));

	if (fill_memory_write_buffer(buffer, value_text) == 0)
	{
		log_rejected_write_value(size);

		return;
	}

	const std::uint64_t bytes_written = hypercall::write_guest_physical_memory(
		buffer.data(), guest_physical_address, size);

	if (bytes_written == size)
	{
		LOG_INFO("success in write");
	}
	else
	{
		LOG_ERR("failed to write");
	}
}

static CLI::App* init_cgpm(CLI::App& app, const CLI::Transformer& aliases_transformer)
{
	CLI::App* cgpm = app.add_subcommand(
		"cgpm", "copies memory from a given source to a destination (guest physical addresses)")->ignore_case();

	add_transformed_command_option(cgpm, "destination_physical_address", aliases_transformer)->required();
	add_transformed_command_option(cgpm, "source_physical_address", aliases_transformer)->required();
	add_memory_size_option(cgpm);

	return cgpm;
}

static void process_cgpm(const CLI::App* const cgpm)
{
	const auto guest_destination_physical_address = get_command_option<std::uint64_t>(
		cgpm, "destination_physical_address");
	const auto guest_source_physical_address = get_command_option<std::uint64_t>(cgpm, "source_physical_address");
	const auto size = get_command_option<std::uint64_t>(cgpm, "size");

	std::vector<std::uint8_t> buffer(size);

	const std::uint64_t bytes_read = hypercall::read_guest_physical_memory(
		buffer.data(), guest_source_physical_address, size);
	const std::uint64_t bytes_written = hypercall::write_guest_physical_memory(
		buffer.data(), guest_destination_physical_address, size);

	if (bytes_read == size && bytes_written == size)
	{
		LOG_INFO("success in copy");
	}
	else
	{
		LOG_ERR("failed to copy");
	}
}

static CLI::App* init_gvat(CLI::App& app, const CLI::Transformer& aliases_transformer)
{
	CLI::App* gvat = app.add_subcommand(
		                    "gvat",
		                    "translates a guest virtual address to its corresponding guest physical address, with the given guest cr3 value")
	                    ->ignore_case();

	add_transformed_command_option(gvat, "virtual_address", aliases_transformer)->required();
	add_transformed_command_option(gvat, "cr3", aliases_transformer)->required();

	return gvat;
}

static void process_gvat(const CLI::App* const gvat)
{
	const auto virtual_address = get_command_option<std::uint64_t>(gvat, "virtual_address");
	const auto cr3 = get_command_option<std::uint64_t>(gvat, "cr3");

	const std::uint64_t physical_address = hypercall::translate_guest_virtual_address(virtual_address, cr3);

	LOG_INFO("physical address: 0x{:x}", physical_address);
}

static CLI::App* init_rgvm(CLI::App& app, const CLI::Transformer& aliases_transformer)
{
	CLI::App* rgvm = app.add_subcommand(
		                    "rgvm",
		                    "reads memory from a given guest virtual address (when given the corresponding guest cr3 value)")
	                    ->
	                    ignore_case();

	add_transformed_command_option(rgvm, "virtual_address", aliases_transformer)->required();
	add_transformed_command_option(rgvm, "cr3", aliases_transformer)->required();
	add_memory_size_option(rgvm);

	return rgvm;
}

static void process_rgvm(const CLI::App* const rgvm)
{
	const auto guest_virtual_address = get_command_option<std::uint64_t>(rgvm, "virtual_address");
	const auto cr3 = get_command_option<std::uint64_t>(rgvm, "cr3");
	const auto size = get_command_option<std::uint64_t>(rgvm, "size");

	std::vector<std::uint8_t> buffer(static_cast<std::size_t>(size));

	const std::uint64_t bytes_read = hypercall::read_guest_virtual_memory(
		buffer.data(), guest_virtual_address, cr3, size);

	if (bytes_read == size)
	{
		log_read_memory(buffer.data(), size);
	}
	else
	{
		LOG_ERR("failed to read");
	}
}

static CLI::App* init_wgvm(CLI::App& app, const CLI::Transformer& aliases_transformer)
{
	CLI::App* wgvm = app.add_subcommand(
		                    "wgvm",
		                    "writes memory from a given guest virtual address (when given the corresponding guest cr3 value)")
	                    ->
	                    ignore_case();

	add_transformed_command_option(wgvm, "virtual_address", aliases_transformer)->required();
	add_transformed_command_option(wgvm, "cr3", aliases_transformer)->required();
	add_command_option(wgvm, "value")->required();
	add_memory_size_option(wgvm);

	return wgvm;
}

static void process_wgvm(const CLI::App* const wgvm)
{
	const auto guest_virtual_address = get_command_option<std::uint64_t>(wgvm, "virtual_address");
	const auto cr3 = get_command_option<std::uint64_t>(wgvm, "cr3");
	const auto size = get_command_option<std::uint64_t>(wgvm, "size");
	const auto value_text = get_command_option<std::string>(wgvm, "value");

	std::vector<std::uint8_t> buffer(static_cast<std::size_t>(size));

	if (fill_memory_write_buffer(buffer, value_text) == 0)
	{
		log_rejected_write_value(size);

		return;
	}

	const std::uint64_t bytes_written = hypercall::write_guest_virtual_memory(
		buffer.data(), guest_virtual_address, cr3, size);

	if (bytes_written == size)
	{
		LOG_INFO("success in write at given address");
	}
	else
	{
		LOG_ERR("failed to write at given address");
	}
}

static CLI::App* init_cgvm(CLI::App& app, const CLI::Transformer& aliases_transformer)
{
	CLI::App* cgvm = app.add_subcommand(
		                    "cgvm",
		                    "copies memory from a given source to a destination (guest virtual addresses) (when given the corresponding guest cr3 values)")
	                    ->ignore_case();

	add_transformed_command_option(cgvm, "destination_virtual_address", aliases_transformer)->required();
	add_transformed_command_option(cgvm, "destination_cr3", aliases_transformer)->required();
	add_transformed_command_option(cgvm, "source_virtual_address", aliases_transformer)->required();
	add_transformed_command_option(cgvm, "source_cr3", aliases_transformer)->required();
	add_memory_size_option(cgvm);

	return cgvm;
}

static void process_cgvm(const CLI::App* const wgvm)
{
	const auto guest_destination_virtual_address = get_command_option<std::uint64_t>(
		wgvm, "destination_virtual_address");
	const auto guest_destination_cr3 = get_command_option<std::uint64_t>(wgvm, "destination_cr3");

	const auto guest_source_virtual_address = get_command_option<std::uint64_t>(wgvm, "source_virtual_address");
	const auto guest_source_cr3 = get_command_option<std::uint64_t>(wgvm, "source_cr3");

	const auto size = get_command_option<std::uint64_t>(wgvm, "size");

	std::vector<std::uint8_t> buffer(size);

	const std::uint64_t bytes_read = hypercall::read_guest_virtual_memory(
		buffer.data(), guest_source_virtual_address, guest_source_cr3, size);
	const std::uint64_t bytes_written = hypercall::write_guest_virtual_memory(
		buffer.data(), guest_destination_virtual_address, guest_destination_cr3, size);

	if (bytes_read == size && bytes_written == size)
	{
		LOG_INFO("success in copy");
	}
	else
	{
		LOG_ERR("failed to copy");
	}
}

static CLI::App* init_akh(CLI::App& app, const CLI::Transformer& aliases_transformer)
{
	CLI::App* const akh = app.add_subcommand(
		                         "akh",
		                         "add a hook on specified kernel code (given the guest virtual address) (asmbytes in form: 0xE8 0x12 0x23 0x34 0x45)")
	                         ->ignore_case();

	add_transformed_command_option(akh, "virtual_address", aliases_transformer)->required();
	add_command_option(akh, "--script_text")->multi_option_policy(CLI::MultiOptionPolicy::TakeAll)->expected(-1);
	add_command_option(akh, "--script_file")->multi_option_policy(CLI::MultiOptionPolicy::TakeAll)->expected(-1);
	add_command_option(akh, "--asmbytes")->multi_option_policy(CLI::MultiOptionPolicy::TakeAll)->expected(-1);
	add_command_option(akh, "--post_original_asmbytes")->multi_option_policy(CLI::MultiOptionPolicy::TakeAll)->
	                                                     expected(-1);
	add_command_flag(akh, "--monitor");

	return akh;
}

static void process_akh(const CLI::App* const akh)
{
	const auto virtual_address = get_command_option<std::uint64_t>(akh, "virtual_address");

	auto asm_bytes = get_command_option<std::vector<uint8_t>>(akh, "--asmbytes");

	const auto script_contents = get_command_option<std::string>(akh, "--script_text");
	const auto script_file = get_command_option<std::string>(akh, "--script_file");

	if (!script_contents.empty())
	{
		const auto compiled_script_bytes = script::compile(script_contents);

		asm_bytes.insert_range(asm_bytes.end(), compiled_script_bytes);
	}
	else if (!script_file.empty())
	{
		const auto compiled_script_bytes = script::compile_from_path(script_file);

		asm_bytes.insert_range(asm_bytes.end(), compiled_script_bytes);
	}

	const auto post_original_asm_bytes = get_command_option<std::vector<uint8_t>>(akh, "--post_original_asmbytes");

	const std::uint8_t monitor = get_command_flag(akh, "--monitor");

	if (monitor == 1)
	{
		std::array<std::uint8_t, 9> monitor_bytes = {
			0x51, // push rcx
			0xB9, 0x00, 0x00, 0x00, 0x00, // mov ecx, 0
			0x0F, 0xA2, // cpuid
			0x59 // pop rcx
		};

		hypercall_info_t call_info = {};

		call_info.primary_key = hypercall_primary_key;
		call_info.secondary_key = hypercall_secondary_key;
		call_info.call_type = hypercall_type_t::log_current_state;

		*reinterpret_cast<std::uint32_t*>(&monitor_bytes[2]) = static_cast<std::uint32_t>(call_info.value);

		asm_bytes.insert(asm_bytes.end(), monitor_bytes.begin(), monitor_bytes.end());
	}

	const std::uint8_t hook_status = hook::add_kernel_hook(virtual_address, asm_bytes, post_original_asm_bytes);

	if (hook_status == 1)
	{
		LOG_INFO("success in hook");
	}
	else
	{
		LOG_ERR("failed to hook");
	}
}

static CLI::App* init_rkh(CLI::App& app, const CLI::Transformer& aliases_transformer)
{
	CLI::App* rkh = app.add_subcommand(
		                   "rkh",
		                   "remove a previously placed hook on specified kernel code (given the guest virtual address)")
	                   ->
	                   ignore_case();

	add_transformed_command_option(rkh, "virtual_address", aliases_transformer)->required();

	return rkh;
}

static void process_rkh(const CLI::App* const rkh)
{
	const auto virtual_address = get_command_option<std::uint64_t>(rkh, "virtual_address");

	const std::uint8_t hook_removal_status = hook::remove_kernel_hook(virtual_address, 1);

	if (hook_removal_status == 1)
	{
		LOG_INFO("success in hook removal");
	}
	else
	{
		LOG_ERR("failed to remove hook");
	}
}

static CLI::App* init_hgpp(CLI::App& app, const CLI::Transformer& aliases_transformer)
{
	CLI::App* hgpp = app.add_subcommand("hgpp", "hide a physical page's real contents from the guest")->ignore_case();

	add_transformed_command_option(hgpp, "physical_address", aliases_transformer)->required();

	return hgpp;
}

static void process_hgpp(const CLI::App* const hgpp)
{
	const auto physical_address = get_command_option<std::uint64_t>(hgpp, "physical_address");

	const std::uint64_t hide_status = hypercall::hide_guest_physical_page(physical_address);

	if (hide_status == 1)
	{
		LOG_INFO("success in hiding page");
	}
	else
	{
		LOG_ERR("failed to hide page");
	}
}

static CLI::App* init_fl(CLI::App& app)
{
	CLI::App* fl = app.add_subcommand("fl", "flush trap frame logs from hooks")->ignore_case();

	return fl;
}

static void process_fl([[maybe_unused]] const CLI::App* const fl)
{
	constexpr std::uint64_t log_count = 2840;
	constexpr std::uint64_t failed_log_count = -1;

	std::vector<trap_frame_log_t> logs(log_count);

	std::vector<trap_frame_log_t> pending = breakpoint::take_pending_logs();
	const std::uint64_t logs_flushed = hypercall::flush_logs(logs);

	if (logs_flushed != failed_log_count && logs_flushed > 0)
	{
		breakpoint::observe_pause_logs(logs.data(), logs_flushed);
	}

	std::uint64_t pending_count = 0;

	for (const trap_frame_log_t& log : pending)
	{
		if (log.rip == 0)
		{
			break;
		}

		pending_count++;
	}

	const std::uint64_t fresh_count = logs_flushed == failed_log_count ? 0 : logs_flushed;

	if (logs_flushed == failed_log_count && pending_count == 0)
	{
		LOG_ERR("failed to flush logs");
	}
	else if (pending_count == 0 && fresh_count == 0)
	{
		LOG_INFO("there are no logs to flush");
	}
	else
	{
		LOG_INFO("success in flushing logs ({}), outputting logs now:\n\n", pending_count + fresh_count);

		std::uint64_t printed = 0;

		for (std::uint64_t i = 0; i < pending_count; i++)
		{
			const trap_frame_log_t& log = pending[i];

			LOG_INFO(
				"{}. rip=0x{:X} rax=0x{:X} rcx=0x{:X}\nrdx=0x{:X} rbx=0x{:X} rsp=0x{:X} rbp=0x{:X}\nrsi=0x{:X} rdi=0x{:X} r8=0x{:X} r9=0x{:X}\nr10=0x{:X} r11=0x{:X} r12=0x{:X} r13=0x{:X} r14=0x{:X}\nr15=0x{:X} cr3=0x{:X}\n"
				, printed, log.rip, log.rax, log.rcx, log.rdx, log.rbx, log.rsp, log.rbp, log.rsi, log.rdi, log.r8, log.r9,
				log.r10, log.r11, log.r12, log.r13, log.r14, log.r15, log.cr3);

			LOG_INFO("stack data:");

			for (const std::uint64_t stack_value : log.stack_data)
			{
				LOG_INFO("  0x{:X}", stack_value);
			}

			printed++;
		}

		for (std::uint64_t i = 0; i < fresh_count; i++)
		{
			const trap_frame_log_t& log = logs[i];

			if (log.rip == 0)
			{
				break;
			}

			LOG_INFO(
				"{}. rip=0x{:X} rax=0x{:X} rcx=0x{:X}\nrdx=0x{:X} rbx=0x{:X} rsp=0x{:X} rbp=0x{:X}\nrsi=0x{:X} rdi=0x{:X} r8=0x{:X} r9=0x{:X}\nr10=0x{:X} r11=0x{:X} r12=0x{:X} r13=0x{:X} r14=0x{:X}\nr15=0x{:X} cr3=0x{:X}\n"
				, printed, log.rip, log.rax, log.rcx, log.rdx, log.rbx, log.rsp, log.rbp, log.rsi, log.rdi, log.r8, log.r9,
				log.r10, log.r11, log.r12, log.r13, log.r14, log.r15, log.cr3);

			LOG_INFO("stack data:");

			for (const std::uint64_t stack_value : log.stack_data)
			{
				LOG_INFO("  0x{:X}", stack_value);
			}

			printed++;
		}
	}
}

static CLI::App* init_hfpc(CLI::App& app)
{
	CLI::App* hfpc = app.add_subcommand("hfpc", "get hyperv-attachment's heap free page count")->ignore_case();

	return hfpc;
}

static void process_hfpc([[maybe_unused]] CLI::App* const hfpc)
{
	const std::uint64_t heap_free_page_count = hypercall::get_heap_free_page_count();

	LOG_INFO("heap free page count: {}", heap_free_page_count);
}

static CLI::App* init_lkm(CLI::App& app)
{
	CLI::App* lkm = app.add_subcommand("lkm", "print list of loaded kernel modules")->ignore_case();

	return lkm;
}

static void process_lkm([[maybe_unused]] CLI::App* const lkm)
{
	for (const auto& [module_name, module_info] : sys::kernel::modules_list)
	{
		LOG_INFO("'{}' has a base address of: 0x{:x}, and a size of: 0x{:X}", module_name, module_info.base_address,
		             module_info.size);
	}
}

static CLI::App* init_kme(CLI::App& app)
{
	CLI::App* kme = app.add_subcommand("kme", "list the exports of a loaded kernel module (when given the name)")->
	                    ignore_case();

	add_command_option(kme, "module_name")->required();

	return kme;
}

static void process_kme(const CLI::App* const kme)
{
	const auto module_name = get_command_option<std::string>(kme, "module_name");

	if (!sys::kernel::modules_list.contains(module_name))
	{
		LOG_ERR("module not found");

		return;
	}

	const sys::kernel_module_t module = sys::kernel::modules_list[module_name];

	for (const auto& [export_name, export_address] : module.exports)
	{
		LOG_INFO("{} = 0x{:X}", export_name, export_address);
	}
}

static CLI::App* init_dkm(CLI::App& app)
{
	CLI::App* dkm = app.add_subcommand("dkm", "dump kernel module to a file on disk")->ignore_case();

	add_command_option(dkm, "module_name")->required();
	add_command_option(dkm, "output_directory")->required();

	return dkm;
}

static void process_dkm(const CLI::App* const dkm)
{
	const auto module_name = get_command_option<std::string>(dkm, "module_name");

	if (!sys::kernel::modules_list.contains(module_name))
	{
		LOG_ERR("module not found");

		return;
	}

	const auto output_directory = get_command_option<std::string>(dkm, "output_directory");

	const std::uint8_t status = sys::kernel::dump_module_to_disk(module_name, output_directory);

	if (status == 1)
	{
		LOG_INFO("success in dumping module");
	}
	else
	{
		LOG_ERR("failed to dump module");
	}
}

static CLI::App* init_gva(CLI::App& app, const CLI::Transformer& aliases_transformer)
{
	CLI::App* gva = app.add_subcommand("gva", "get the numerical value of an alias")->ignore_case();

	add_transformed_command_option(gva, "alias_name", aliases_transformer)->required();

	return gva;
}

static void process_gva(const CLI::App* const gva)
{
	const auto alias_value = get_command_option<std::uint64_t>(gva, "alias_name");

	LOG_INFO("alias value: 0x{:X}", alias_value);
}

static std::uint64_t cr3_for_guest_address(std::uint64_t address);
static std::uint8_t take_command_token(std::string_view& text, std::string& token_out);

constexpr std::uint64_t unassemble_default_instruction_count = 8;
constexpr std::uint64_t unassemble_max_instruction_count = 0x1000;
constexpr std::uint64_t unassemble_max_range_bytes = 0x10000;

static std::uint64_t unassemble_next_address = 0;
static std::uint8_t unassemble_has_next_address = 0;

static std::uint8_t equals_ignore_case(const std::string_view left, const std::string_view right)
{
	if (left.size() != right.size())
	{
		return 0;
	}

	for (std::size_t index = 0; index < left.size(); index++)
	{
		const auto left_character = static_cast<unsigned char>(left[index]);
		const auto right_character = static_cast<unsigned char>(right[index]);

		if (std::tolower(left_character) != std::tolower(right_character))
		{
			return 0;
		}
	}

	return 1;
}

static std::string module_stem(const std::string_view module_name)
{
	const std::size_t dot = module_name.rfind('.');

	if (dot == std::string_view::npos)
	{
		return std::string(module_name);
	}

	return std::string(module_name.substr(0, dot));
}

static std::uint8_t is_ntoskrnl_module(const std::string_view module_name)
{
	const std::string stem = module_stem(module_name);

	return static_cast<std::uint8_t>(equals_ignore_case(stem, "ntoskrnl") == 1 || equals_ignore_case(stem, "ntkrnlmp") == 1
		|| equals_ignore_case(stem, "ntkrnlpa") == 1 || equals_ignore_case(stem, "ntkrpamp") == 1);
}

static std::uint8_t parse_windbg_number(const std::string_view text, std::uint64_t& value_out)
{
	std::string cleaned;
	cleaned.reserve(text.size());

	for (const char character : text)
	{
		if (character != '`')
		{
			cleaned.push_back(character);
		}
	}

	if (cleaned.empty() == true)
	{
		return 0;
	}

	int base = 16;
	std::string_view body = cleaned;

	if (body.size() >= 2 && body[0] == '0' && (body[1] == 'n' || body[1] == 'N'))
	{
		base = 10;
		body.remove_prefix(2);
	}
	else if (body.size() >= 2 && body[0] == '0' && (body[1] == 'x' || body[1] == 'X'))
	{
		body.remove_prefix(2);
	}

	if (body.empty() == true)
	{
		return 0;
	}

	try
	{
		std::size_t consumed = 0;
		const std::uint64_t value = std::stoull(std::string(body), &consumed, base);

		if (consumed != body.size())
		{
			return 0;
		}

		value_out = value;

		return 1;
	}
	catch (const std::exception&)
	{
		return 0;
	}
}

static std::uint8_t lookup_alias(const std::unordered_map<std::string, std::uint64_t>& aliases,
                                 const std::string_view name, std::uint64_t& address_out)
{
	for (const auto& [alias_name, alias_address] : aliases)
	{
		if (equals_ignore_case(alias_name, name) == 1)
		{
			address_out = alias_address;

			return 1;
		}
	}

	return 0;
}

static std::uint8_t lookup_module_symbol(const std::unordered_map<std::string, std::uint64_t>& aliases,
                                         const std::string_view module, const std::string_view symbol,
                                         std::uint64_t& address_out)
{
	if (symbol_parser::resolve(module, symbol, address_out) == 1)
	{
		return 1;
	}

	if (equals_ignore_case(module, "nt") == 1)
	{
		for (const auto& [module_name, module_info] : sys::kernel::modules_list)
		{
			if (is_ntoskrnl_module(module_name) == 0)
			{
				continue;
			}

			const std::string full_name = module_name + "!" + std::string(symbol);

			if (lookup_alias(aliases, full_name, address_out) == 1)
			{
				return 1;
			}

			(void)module_info;
		}
	}

	for (const auto& [module_name, module_info] : sys::kernel::modules_list)
	{
		const std::uint8_t stem_match = equals_ignore_case(module_stem(module_name), module);
		const std::uint8_t full_match = equals_ignore_case(module_name, module);

		if (stem_match == 0 && full_match == 0)
		{
			continue;
		}

		const std::string full_name = module_name + "!" + std::string(symbol);

		if (lookup_alias(aliases, full_name, address_out) == 1)
		{
			return 1;
		}

		(void)module_info;
	}

	return 0;
}

static std::uint8_t resolve_symbol(const std::unordered_map<std::string, std::uint64_t>& aliases,
                                   const std::string_view text, std::uint64_t& address_out)
{
	if (lookup_alias(aliases, text, address_out) == 1)
	{
		return 1;
	}

	const std::size_t bang = text.find('!');

	if (bang == std::string_view::npos || bang == 0 || bang + 1 >= text.size())
	{
		return 0;
	}

	return lookup_module_symbol(aliases, text.substr(0, bang), text.substr(bang + 1), address_out);
}

static std::uint8_t apply_displacement(const std::uint64_t base_address, const std::uint64_t displacement,
                                       const std::uint8_t subtract, std::uint64_t& address_out)
{
	if (subtract == 1)
	{
		if (displacement > base_address)
		{
			return 0;
		}

		address_out = base_address - displacement;

		return 1;
	}

	if (base_address + displacement < base_address)
	{
		return 0;
	}

	address_out = base_address + displacement;

	return 1;
}

static std::uint8_t resolve_windbg_address(const std::unordered_map<std::string, std::uint64_t>& aliases,
                                           const std::string_view text, std::uint64_t& address_out)
{
	const std::size_t plus = text.rfind('+');
	const std::size_t minus = text.rfind('-');
	std::size_t operand_index = std::string_view::npos;

	if (plus != std::string_view::npos && (minus == std::string_view::npos || plus > minus))
	{
		operand_index = plus;
	}
	else
	{
		operand_index = minus;
	}

	if (operand_index != std::string_view::npos && operand_index > 0 && operand_index + 1 < text.size())
	{
		std::uint64_t displacement = 0;

		if (parse_windbg_number(text.substr(operand_index + 1), displacement) == 1)
		{
			const std::string_view base_text = text.substr(0, operand_index);
			std::uint64_t base_address = 0;

			if (resolve_symbol(aliases, base_text, base_address) == 0 && parse_windbg_number(base_text, base_address) == 0)
			{
				return 0;
			}

			return apply_displacement(base_address, displacement, static_cast<std::uint8_t>(text[operand_index] == '-'),
			                          address_out);
		}
	}

	if (resolve_symbol(aliases, text, address_out) == 1)
	{
		return 1;
	}

	return parse_windbg_number(text, address_out);
}

static std::uint8_t parse_length_token(const std::string_view token, std::uint64_t& count_out)
{
	if (token.empty() == true || (token[0] != 'L' && token[0] != 'l'))
	{
		return 0;
	}

	if (token.size() == 1)
	{
		return 0;
	}

	return parse_windbg_number(token.substr(1), count_out);
}

struct windbg_range_request_t
{
	std::uint64_t start_address = 0;
	std::uint64_t count = 0;
	std::uint64_t end_address = 0;
	std::uint8_t is_range = 0;
};

struct unassemble_request_t
{
	std::uint64_t start_address = 0;
	std::uint64_t instruction_count = unassemble_default_instruction_count;
	std::uint64_t end_address = 0;
	std::uint8_t is_range = 0;
};

static std::uint8_t parse_windbg_range(const std::vector<std::string>& args,
                                       const std::unordered_map<std::string, std::uint64_t>& aliases,
                                       const std::uint64_t default_count, const std::uint64_t current_address,
                                       const std::uint8_t has_current_address, const char* const count_name,
                                       const char* const missing_address_text, windbg_range_request_t& request_out)
{
	request_out = {};
	request_out.count = default_count;

	const auto fail_address = [](const std::string& token)
	{
		LOG_ERR("invalid address: {}", token);

		return static_cast<std::uint8_t>(0);
	};

	if (args.empty() == true)
	{
		if (has_current_address == 0)
		{
			LOG_ERR("{}", missing_address_text);

			return 0;
		}

		request_out.start_address = current_address;

		return 1;
	}

	if (args.size() > 3)
	{
		LOG_ERR("invalid syntax");

		return 0;
	}

	std::size_t index = 0;
	std::uint8_t has_start = 0;

	if (parse_length_token(args[0], request_out.count) == 0 && args[0] != "L" && args[0] != "l")
	{
		if (resolve_windbg_address(aliases, args[0], request_out.start_address) == 0)
		{
			return fail_address(args[0]);
		}

		has_start = 1;
		index = 1;
	}

	if (has_start == 0)
	{
		if (has_current_address == 0)
		{
			LOG_ERR("{}", missing_address_text);

			return 0;
		}

		request_out.start_address = current_address;
	}

	if (index >= args.size())
	{
		return 1;
	}

	if (args[index] == "L" || args[index] == "l")
	{
		if (index + 1 >= args.size())
		{
			LOG_ERR("missing {}", count_name);

			return 0;
		}

		if (parse_windbg_number(args[index + 1], request_out.count) == 0)
		{
			LOG_ERR("invalid {}: {}", count_name, args[index + 1]);

			return 0;
		}

		if (index + 2 != args.size())
		{
			LOG_ERR("invalid syntax");

			return 0;
		}

		return 1;
	}

	if (parse_length_token(args[index], request_out.count) == 1)
	{
		if (index + 1 != args.size())
		{
			LOG_ERR("invalid syntax");

			return 0;
		}

		return 1;
	}

	if (index + 1 != args.size())
	{
		LOG_ERR("invalid syntax");

		return 0;
	}

	if (resolve_windbg_address(aliases, args[index], request_out.end_address) == 0)
	{
		return fail_address(args[index]);
	}

	request_out.is_range = 1;

	return 1;
}

static std::uint8_t parse_unassemble_request(const std::vector<std::string>& args,
                                             const std::unordered_map<std::string, std::uint64_t>& aliases,
                                             unassemble_request_t& request_out)
{
	windbg_range_request_t range = {};

	if (parse_windbg_range(args, aliases, unassemble_default_instruction_count, unassemble_next_address,
	                       unassemble_has_next_address, "instruction count", "no current disassembly address",
	                       range) == 0)
	{
		return 0;
	}

	request_out.start_address = range.start_address;
	request_out.instruction_count = range.count;
	request_out.end_address = range.end_address;
	request_out.is_range = range.is_range;

	return 1;
}

static std::unordered_map<std::uint64_t, std::string> make_symbol_index()
{
	std::unordered_map<std::uint64_t, std::string> symbols = {};

	for (const auto& [module_name, module_info] : sys::kernel::modules_list)
	{
		for (const auto& [export_name, export_address] : module_info.exports)
		{
			symbols.emplace(export_address, export_name);
		}

		symbols.emplace(module_info.base_address, module_name);
	}

	return symbols;
}

static void print_disassembly_line(const std::uint64_t address, const std::string_view bytes, const std::string_view text)
{
	fmt::print("{:08x}`{:08x} {:<30} {}\n", static_cast<std::uint32_t>(address >> 32),
	           static_cast<std::uint32_t>(address), bytes, text);
}

static void unassemble_guest_code(const unassemble_request_t& request)
{
	if (request.instruction_count == 0)
	{
		LOG_ERR("instruction count is zero");

		return;
	}

	if (request.is_range == 0 && request.instruction_count > unassemble_max_instruction_count)
	{
		LOG_ERR("instruction count is above 0x{:x}", unassemble_max_instruction_count);

		return;
	}

	std::uint64_t bytes_to_read = 0;

	if (request.is_range == 1)
	{
		if (request.end_address <= request.start_address)
		{
			LOG_ERR("empty range");

			return;
		}

		const std::uint64_t span = request.end_address - request.start_address;

		if (span > unassemble_max_range_bytes)
		{
			LOG_ERR("range is above 0x{:x} bytes", unassemble_max_range_bytes);

			return;
		}

		bytes_to_read = span + (ZYDIS_MAX_INSTRUCTION_LENGTH - 1);
	}
	else
	{
		bytes_to_read = request.instruction_count * ZYDIS_MAX_INSTRUCTION_LENGTH;
	}

	if (bytes_to_read != 0 && request.start_address + bytes_to_read < request.start_address)
	{
		LOG_ERR("address range wraps");

		return;
	}

	const std::uint64_t read_cr3 = cr3_for_guest_address(request.start_address);

	if (read_cr3 == 0)
	{
		LOG_ERR("current cr3 is not set");

		return;
	}

	std::vector<std::uint8_t> buffer(static_cast<std::size_t>(bytes_to_read));
	const std::uint64_t bytes_read = hypercall::read_guest_virtual_memory(
		buffer.data(), request.start_address, read_cr3, bytes_to_read);

	if (bytes_read == 0)
	{
		LOG_ERR("failed to read");

		return;
	}

	ZydisDecoder decoder = {};

	if (ZYAN_FAILED(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64)))
	{
		LOG_ERR("failed to set up decoder");

		return;
	}

	ZydisFormatter formatter = {};

	if (ZYAN_FAILED(ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL_MASM)))
	{
		if (ZYAN_FAILED(ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL)))
		{
			LOG_ERR("failed to set up formatter");

			return;
		}
	}

	const std::unordered_map<std::uint64_t, std::string> symbols = make_symbol_index();
	std::uint64_t offset = 0;
	std::uint64_t shown = 0;

	while (offset < bytes_read)
	{
		const std::uint64_t instruction_address = request.start_address + offset;

		if (request.is_range == 1)
		{
			if (instruction_address >= request.end_address)
			{
				break;
			}
		}
		else if (shown >= request.instruction_count)
		{
			break;
		}

		const auto symbol = symbols.find(instruction_address);

		if (symbol != symbols.end())
		{
			fmt::print("{}:\n", symbol->second);
		}
		else
		{
			std::string pdb_name = {};
			std::uint64_t pdb_displacement = 0;

			if (symbol_parser::nearest(instruction_address, pdb_name, pdb_displacement) == 1 && pdb_displacement == 0)
			{
				fmt::print("{}:\n", pdb_name);
			}
		}

		ZydisDecoderContext decoder_context = {};
		ZydisDecodedInstruction decoded_instruction = {};
		const ZyanStatus decode_status = ZydisDecoderDecodeInstruction(
			&decoder, &decoder_context, buffer.data() + offset, bytes_read - offset, &decoded_instruction);

		if (ZYAN_FAILED(decode_status))
		{
			if (decode_status == ZYDIS_STATUS_NO_MORE_DATA)
			{
				break;
			}

			print_disassembly_line(instruction_address, fmt::format("{:02x}", buffer[static_cast<std::size_t>(offset)]), "??");
			offset += 1;
			shown += 1;

			continue;
		}

		std::array<ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT> operands = {};
		const ZyanStatus operand_status = ZydisDecoderDecodeOperands(
			&decoder, &decoder_context, &decoded_instruction, operands.data(),
			static_cast<ZyanU8>(operands.size()));

		char formatted_instruction[256] = {};

		if (ZYAN_FAILED(operand_status) || ZYAN_FAILED(ZydisFormatterFormatInstruction(
			    &formatter, &decoded_instruction, operands.data(), decoded_instruction.operand_count,
			    formatted_instruction, sizeof(formatted_instruction), instruction_address, nullptr)))
		{
			print_disassembly_line(instruction_address, fmt::format("{:02x}", buffer[static_cast<std::size_t>(offset)]), "??");
			offset += 1;
			shown += 1;

			continue;
		}

		std::string bytes;
		bytes.reserve(decoded_instruction.length * 2);

		for (std::uint8_t byte_index = 0; byte_index < decoded_instruction.length; byte_index++)
		{
			bytes += fmt::format("{:02x}", buffer[static_cast<std::size_t>(offset) + byte_index]);
		}

		print_disassembly_line(instruction_address, bytes, formatted_instruction);
		offset += decoded_instruction.length;
		shown += 1;
	}

	if (offset == 0)
	{
		LOG_ERR("failed to read");

		return;
	}

	unassemble_next_address = request.start_address + offset;
	unassemble_has_next_address = 1;
	std::fflush(stdout);
}

static CLI::App* init_u(CLI::App& app)
{
	CLI::App* const unassemble = app.add_subcommand("u", "unassembles guest virtual instructions (WinDbg syntax)")->
	                                  ignore_case();

	unassemble->prefix_command();
	unassemble->fallthrough(false);
	unassemble->subcommand_fallthrough(false);

	return unassemble;
}

static void process_u(const CLI::App* const unassemble)
{
	const std::vector<std::string> args = unassemble->remaining();
	const std::unordered_map<std::string, std::uint64_t> aliases = sys::kernel::compile_symbol_list();
	unassemble_request_t request = {};

	if (args.empty() == true && unassemble_has_next_address == 0 && breakpoint::capture_pause() == 1)
	{
		breakpoint::registers_t paused = {};

		if (breakpoint::paused_registers(paused) == 1)
		{
			unassemble_next_address = paused.rip;
			unassemble_has_next_address = 1;
		}
	}

	if (parse_unassemble_request(args, aliases, request) == 0)
	{
		return;
	}

	unassemble_guest_code(request);
}

constexpr std::uint64_t display_default_bytes = 0x80;

enum class guest_display_t
{
	bytes,
	words,
	dwords,
	qwords,
	dwords_and_ascii,
	ascii_string,
	unicode_string
};

static std::uint64_t display_element_size(const guest_display_t kind)
{
	switch (kind)
	{
	case guest_display_t::words:
	case guest_display_t::unicode_string:
		return 2;
	case guest_display_t::dwords:
	case guest_display_t::dwords_and_ascii:
		return 4;
	case guest_display_t::qwords:
		return 8;
	default:
		return 1;
	}
}

static std::uint64_t display_default_count(const guest_display_t kind)
{
	return display_default_bytes / display_element_size(kind);
}

static std::uint8_t display_shows_ascii(const guest_display_t kind)
{
	return static_cast<std::uint8_t>(kind == guest_display_t::bytes || kind == guest_display_t::dwords_and_ascii);
}

static std::uint8_t display_is_string(const guest_display_t kind)
{
	return static_cast<std::uint8_t>(kind == guest_display_t::ascii_string || kind == guest_display_t::unicode_string);
}

static std::string format_windbg_address(const std::uint64_t address)
{
	return fmt::format("{:08x}`{:08x}", static_cast<std::uint32_t>(address >> 32), static_cast<std::uint32_t>(address));
}

static std::uint64_t read_little_endian(const std::uint8_t* const data, const std::uint64_t size)
{
	std::uint64_t value = 0;

	for (std::uint64_t index = 0; index < size; index++)
	{
		value |= static_cast<std::uint64_t>(data[index]) << (index * 8);
	}

	return value;
}

static char display_ascii_character(const std::uint8_t value)
{
	if (value >= 0x20 && value <= 0x7e)
	{
		return static_cast<char>(value);
	}

	return '.';
}

static std::string format_display_ascii(const std::uint8_t* const data, const std::uint64_t size)
{
	std::string text;
	text.reserve(static_cast<std::size_t>(size));

	for (std::uint64_t index = 0; index < size; index++)
	{
		text.push_back(display_ascii_character(data[index]));
	}

	return text;
}

static std::string format_hex_elements(const std::uint8_t* const data, const std::uint64_t element_count,
                                       const std::uint64_t element_size)
{
	std::string line;

	for (std::uint64_t index = 0; index < element_count; index++)
	{
		if (element_size == 1)
		{
			if (index != 0)
			{
				line += index == 8 ? "-" : " ";
			}

			line += fmt::format("{:02x}", data[index]);

			continue;
		}

		if (index != 0)
		{
			line += " ";
		}

		const std::uint64_t value = read_little_endian(data + index * element_size, element_size);

		if (element_size == 2)
		{
			line += fmt::format("{:04x}", static_cast<std::uint16_t>(value));
		}
		else if (element_size == 4)
		{
			line += fmt::format("{:08x}", static_cast<std::uint32_t>(value));
		}
		else
		{
			line += fmt::format("{:08x}`{:08x}", static_cast<std::uint32_t>(value >> 32),
			                    static_cast<std::uint32_t>(value));
		}
	}

	return line;
}

static void remember_display_address(const std::uint64_t address)
{
	unassemble_next_address = address;
	unassemble_has_next_address = 1;
}

static void display_guest_memory(const CLI::App* const command, const guest_display_t kind)
{
	const std::uint64_t element_size = display_element_size(kind);
	const std::unordered_map<std::string, std::uint64_t> aliases = sys::kernel::compile_symbol_list();
	windbg_range_request_t request = {};

	if (parse_windbg_range(command->remaining(), aliases, display_default_count(kind), unassemble_next_address,
	                       unassemble_has_next_address, "length", "no current address", request) == 0)
	{
		return;
	}

	std::uint64_t bytes_to_read = 0;

	if (request.is_range == 1)
	{
		if (request.end_address <= request.start_address)
		{
			LOG_ERR("empty range");

			return;
		}

		bytes_to_read = request.end_address - request.start_address;
	}
	else
	{
		if (request.count == 0)
		{
			LOG_ERR("length is zero");

			return;
		}

		if (request.count > unassemble_max_range_bytes / element_size)
		{
			LOG_ERR("length is above 0x{:x}", unassemble_max_range_bytes / element_size);

			return;
		}

		bytes_to_read = request.count * element_size;
	}

	if (bytes_to_read > unassemble_max_range_bytes)
	{
		LOG_ERR("range is above 0x{:x} bytes", unassemble_max_range_bytes);

		return;
	}

	if (request.start_address + bytes_to_read < request.start_address)
	{
		LOG_ERR("address range wraps");

		return;
	}

	const std::uint64_t read_cr3 = cr3_for_guest_address(request.start_address);

	if (read_cr3 == 0)
	{
		LOG_ERR("current cr3 is not set");

		return;
	}

	std::vector<std::uint8_t> buffer(static_cast<std::size_t>(bytes_to_read));
	const std::uint64_t bytes_read = hypercall::read_guest_virtual_memory(
		buffer.data(), request.start_address, read_cr3, bytes_to_read);

	if (bytes_read == 0)
	{
		LOG_ERR("failed to read");

		return;
	}

	const std::uint64_t available = bytes_read < bytes_to_read ? bytes_read : bytes_to_read;
	const std::uint8_t* const data = buffer.data();

	if (display_is_string(kind) == 1)
	{
		std::string text;
		std::uint64_t consumed = 0;
		std::uint8_t ended_on_null = 0;

		if (kind == guest_display_t::unicode_string)
		{
			while (consumed + 1 < available)
			{
				const std::uint16_t character = static_cast<std::uint16_t>(
					data[consumed] | (static_cast<std::uint16_t>(data[consumed + 1]) << 8));

				consumed += 2;

				if (character == 0)
				{
					ended_on_null = 1;

					break;
				}

				text.push_back(character <= 0x7e ? display_ascii_character(static_cast<std::uint8_t>(character)) : '.');
			}
		}
		else
		{
			while (consumed < available)
			{
				const std::uint8_t character = data[consumed];

				consumed += 1;

				if (character == 0)
				{
					ended_on_null = 1;

					break;
				}

				text.push_back(display_ascii_character(character));
			}
		}

		if (consumed == 0)
		{
			LOG_ERR("failed to read");

			return;
		}

		constexpr std::uint64_t characters_per_line = 64;

		if (text.empty() == true)
		{
			fmt::print("{}  \"\"\n", format_windbg_address(request.start_address));
		}

		for (std::uint64_t printed = 0; printed < text.size(); printed += characters_per_line)
		{
			const std::uint64_t line_count = text.size() - printed < characters_per_line
				                                 ? text.size() - printed
				                                 : characters_per_line;
			const std::uint64_t line_address = request.start_address + printed * element_size;

			fmt::print("{}  \"{}\"\n", format_windbg_address(line_address),
			           std::string_view(text.data() + printed, static_cast<std::size_t>(line_count)));
		}

		remember_display_address(request.start_address + consumed);

		if (ended_on_null == 0 && bytes_read < bytes_to_read)
		{
			LOG_ERR("failed to read");
		}

		std::fflush(stdout);

		return;
	}

	const std::uint64_t usable = available - (available % element_size);

	if (usable == 0)
	{
		LOG_ERR("failed to read");

		return;
	}

	const std::uint64_t elements_per_line = 16 / element_size;
	std::uint64_t offset = 0;

	while (offset < usable)
	{
		const std::uint64_t line_elements = (usable - offset) / element_size < elements_per_line
			                                    ? (usable - offset) / element_size
			                                    : elements_per_line;
		const std::uint64_t line_bytes = line_elements * element_size;

		fmt::print("{}  {}", format_windbg_address(request.start_address + offset),
		           format_hex_elements(data + offset, line_elements, element_size));

		if (display_shows_ascii(kind) == 1)
		{
			fmt::print("  {}", format_display_ascii(data + offset, line_bytes));
		}

		fmt::print("\n");
		offset += line_bytes;
	}

	remember_display_address(request.start_address + usable);

	if (bytes_read < bytes_to_read)
	{
		LOG_ERR("failed to read");
	}

	std::fflush(stdout);
}

static CLI::App* init_windbg_command(CLI::App& app, const char* const name, const char* const description)
{
	CLI::App* const command = app.add_subcommand(name, description)->ignore_case();

	command->prefix_command();
	command->fallthrough(false);
	command->subcommand_fallthrough(false);

	return command;
}

static void process_db(const CLI::App* const command)
{
	display_guest_memory(command, guest_display_t::bytes);
}

static void process_dw(const CLI::App* const command)
{
	display_guest_memory(command, guest_display_t::words);
}

static void process_dd(const CLI::App* const command)
{
	display_guest_memory(command, guest_display_t::dwords);
}

static void process_dq(const CLI::App* const command)
{
	display_guest_memory(command, guest_display_t::qwords);
}

static void process_dp(const CLI::App* const command)
{
	display_guest_memory(command, guest_display_t::qwords);
}

static void process_dc(const CLI::App* const command)
{
	display_guest_memory(command, guest_display_t::dwords_and_ascii);
}

static void process_da(const CLI::App* const command)
{
	display_guest_memory(command, guest_display_t::ascii_string);
}

static void process_du(const CLI::App* const command)
{
	display_guest_memory(command, guest_display_t::unicode_string);
}

static std::string windbg_command_line;

enum class guest_enter_t
{
	bytes,
	words,
	dwords,
	qwords,
	ascii_string,
	unicode_string,
	ascii_string_z,
	unicode_string_z
};

static std::uint64_t enter_element_size(const guest_enter_t kind)
{
	switch (kind)
	{
	case guest_enter_t::words:
		return 2;
	case guest_enter_t::dwords:
		return 4;
	case guest_enter_t::qwords:
		return 8;
	case guest_enter_t::unicode_string:
	case guest_enter_t::unicode_string_z:
		return 2;
	default:
		return 1;
	}
}

static std::uint8_t enter_is_string(const guest_enter_t kind)
{
	return static_cast<std::uint8_t>(kind == guest_enter_t::ascii_string || kind == guest_enter_t::unicode_string ||
		kind == guest_enter_t::ascii_string_z || kind == guest_enter_t::unicode_string_z);
}

static std::uint8_t enter_adds_null(const guest_enter_t kind)
{
	return static_cast<std::uint8_t>(kind == guest_enter_t::ascii_string_z || kind == guest_enter_t::unicode_string_z);
}

static std::string_view skip_whitespace(std::string_view text)
{
	while (text.empty() == false && std::isspace(static_cast<unsigned char>(text.front())) != 0)
	{
		text.remove_prefix(1);
	}

	return text;
}

enum class windbg_token_status_t : std::uint8_t
{
	end,
	token,
	error
};

struct windbg_token_t
{
	std::string text;
	std::uint8_t quoted = 0;
};

static windbg_token_status_t read_windbg_token(std::string_view& text, windbg_token_t& token_out)
{
	text = skip_whitespace(text);

	if (text.empty() == true)
	{
		return windbg_token_status_t::end;
	}

	if (text.front() == '\'' || text.front() == '"')
	{
		const char quote = text.front();

		text.remove_prefix(1);

		const std::size_t end = text.find(quote);

		if (end == std::string_view::npos)
		{
			LOG_ERR("unterminated quote");

			return windbg_token_status_t::error;
		}

		token_out.text = std::string(text.substr(0, end));
		token_out.quoted = 1;
		text.remove_prefix(end + 1);

		return windbg_token_status_t::token;
	}

	std::size_t length = 0;

	while (length < text.size() && std::isspace(static_cast<unsigned char>(text[length])) == 0)
	{
		length++;
	}

	token_out.text = std::string(text.substr(0, length));
	token_out.quoted = 0;
	text.remove_prefix(length);

	return windbg_token_status_t::token;
}

static std::uint8_t value_fits_element(const std::uint64_t value, const std::uint64_t element_size)
{
	if (element_size >= sizeof(std::uint64_t))
	{
		return 1;
	}

	const std::uint64_t limit = (1ull << (element_size * 8)) - 1;

	return static_cast<std::uint8_t>(value <= limit);
}

static std::uint8_t append_enter_element(std::vector<std::uint8_t>& bytes, const std::uint64_t value,
                                         const std::uint64_t element_size)
{
	if (element_size > unassemble_max_range_bytes ||
		bytes.size() + element_size > unassemble_max_range_bytes)
	{
		LOG_ERR("length is above 0x{:x} bytes", unassemble_max_range_bytes);

		return 0;
	}

	for (std::uint64_t index = 0; index < element_size; index++)
	{
		bytes.push_back(static_cast<std::uint8_t>(value >> (index * 8)));
	}

	return 1;
}

static std::uint8_t append_utf16_string(std::vector<std::uint8_t>& bytes, const std::string& text)
{
	if (text.empty() == true)
	{
		return 1;
	}

	const int wide_count = MultiByteToWideChar(CP_ACP, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);

	if (wide_count <= 0)
	{
		LOG_ERR("failed to encode string");

		return 0;
	}

	std::wstring wide(static_cast<std::size_t>(wide_count), L'\0');

	if (MultiByteToWideChar(CP_ACP, 0, text.data(), static_cast<int>(text.size()), wide.data(), wide_count) <= 0)
	{
		LOG_ERR("failed to encode string");

		return 0;
	}

	for (const wchar_t character : wide)
	{
		const auto unit = static_cast<std::uint16_t>(character);

		if (append_enter_element(bytes, unit, sizeof(std::uint16_t)) == 0)
		{
			return 0;
		}
	}

	return 1;
}

static std::uint8_t parse_enter_string(std::string_view text, std::string& string_out)
{
	text = skip_whitespace(text);

	if (text.empty() == true)
	{
		LOG_ERR("missing values");

		return 0;
	}

	if (text.front() == '\'' || text.front() == '"')
	{
		const char quote = text.front();

		text.remove_prefix(1);

		const std::size_t end = text.find(quote);

		if (end == std::string_view::npos)
		{
			LOG_ERR("unterminated quote");

			return 0;
		}

		string_out = std::string(text.substr(0, end));
		text.remove_prefix(end + 1);
		text = skip_whitespace(text);

		if (text.empty() == false)
		{
			LOG_ERR("invalid syntax");

			return 0;
		}

		return 1;
	}

	string_out = std::string(text);

	return 1;
}

static void enter_guest_memory(const guest_enter_t kind)
{
	const std::uint64_t element_size = enter_element_size(kind);
	std::string_view text = windbg_command_line;
	windbg_token_t token = {};
	const windbg_token_status_t command_status = read_windbg_token(text, token);

	if (command_status != windbg_token_status_t::token)
	{
		LOG_ERR("invalid syntax");

		return;
	}

	const windbg_token_status_t address_status = read_windbg_token(text, token);

	if (address_status == windbg_token_status_t::error)
	{
		return;
	}

	if (address_status != windbg_token_status_t::token)
	{
		LOG_ERR("missing address");

		return;
	}

	std::uint64_t address = 0;

	if (token.quoted == 0 && token.text == ".")
	{
		if (unassemble_has_next_address == 0)
		{
			LOG_ERR("no current address");

			return;
		}

		address = unassemble_next_address;
	}
	else
	{
		const std::unordered_map<std::string, std::uint64_t> aliases = sys::kernel::compile_symbol_list();

		if (resolve_windbg_address(aliases, token.text, address) == 0)
		{
			LOG_ERR("invalid address: {}", token.text);

			return;
		}
	}

	std::vector<std::uint8_t> bytes;

	if (enter_is_string(kind) == 1)
	{
		std::string value;

		if (parse_enter_string(text, value) == 0)
		{
			return;
		}

		if (kind == guest_enter_t::unicode_string || kind == guest_enter_t::unicode_string_z)
		{
			if (append_utf16_string(bytes, value) == 0)
			{
				return;
			}
		}
		else
		{
			for (const char character : value)
			{
				if (append_enter_element(bytes, static_cast<unsigned char>(character), 1) == 0)
				{
					return;
				}
			}
		}

		if (enter_adds_null(kind) == 1 && append_enter_element(bytes, 0, element_size) == 0)
		{
			return;
		}
	}
	else
	{
		std::uint8_t saw_value = 0;

		while (true)
		{
			const windbg_token_status_t value_status = read_windbg_token(text, token);

			if (value_status == windbg_token_status_t::error)
			{
				return;
			}

			if (value_status == windbg_token_status_t::end)
			{
				break;
			}

			saw_value = 1;

			if (token.quoted == 1)
			{
				for (const char character : token.text)
				{
					if (append_enter_element(bytes, static_cast<unsigned char>(character), element_size) == 0)
					{
						return;
					}
				}

				continue;
			}

			std::uint64_t value = 0;

			if (parse_windbg_number(token.text, value) == 0)
			{
				LOG_ERR("invalid value: {}", token.text);

				return;
			}

			if (value_fits_element(value, element_size) == 0)
			{
				LOG_ERR("value does not fit: {}", token.text);

				return;
			}

			if (append_enter_element(bytes, value, element_size) == 0)
			{
				return;
			}
		}

		if (saw_value == 0)
		{
			LOG_ERR("missing values");

			return;
		}
	}

	if (bytes.empty() == true)
	{
		LOG_INFO("wrote 0x0 bytes");

		return;
	}

	if (address + bytes.size() < address)
	{
		LOG_ERR("address range wraps");

		return;
	}

	const std::uint64_t write_cr3 = cr3_for_guest_address(address);

	if (write_cr3 == 0)
	{
		LOG_ERR("current cr3 is not set");

		return;
	}

	const std::uint64_t bytes_written = hypercall::write_guest_virtual_memory(
		bytes.data(), address, write_cr3, bytes.size());

	if (bytes_written == 0)
	{
		LOG_ERR("failed to write");

		return;
	}

	remember_display_address(address + bytes_written);

	if (bytes_written != bytes.size())
	{
		LOG_ERR("failed to write");

		return;
	}

	LOG_INFO("wrote 0x{:x} bytes at {}", bytes_written, format_windbg_address(address));
}

static void process_eb(const CLI::App* const command)
{
	(void)command;

	enter_guest_memory(guest_enter_t::bytes);
}

static void process_ew(const CLI::App* const command)
{
	(void)command;

	enter_guest_memory(guest_enter_t::words);
}

static void process_ed(const CLI::App* const command)
{
	(void)command;

	enter_guest_memory(guest_enter_t::dwords);
}

static void process_eq(const CLI::App* const command)
{
	(void)command;

	enter_guest_memory(guest_enter_t::qwords);
}

static void process_ep(const CLI::App* const command)
{
	(void)command;

	enter_guest_memory(guest_enter_t::qwords);
}

static void process_ea(const CLI::App* const command)
{
	(void)command;

	enter_guest_memory(guest_enter_t::ascii_string);
}

static void process_eu(const CLI::App* const command)
{
	(void)command;

	enter_guest_memory(guest_enter_t::unicode_string);
}

static void process_eza(const CLI::App* const command)
{
	(void)command;

	enter_guest_memory(guest_enter_t::ascii_string_z);
}

static void process_ezu(const CLI::App* const command)
{
	(void)command;

	enter_guest_memory(guest_enter_t::unicode_string_z);
}

static std::uint8_t resolve_breakpoint_address(const std::string& token,
                                               const std::unordered_map<std::string, std::uint64_t>& aliases,
                                               std::uint64_t& address_out)
{
	if (token == ".")
	{
		if (unassemble_has_next_address == 0)
		{
			LOG_ERR("no current address");

			return 0;
		}

		address_out = unassemble_next_address;

		return 1;
	}

	if (resolve_windbg_address(aliases, token, address_out) == 1)
	{
		return 1;
	}

	const char* const user_modules[] = {"user32.dll", "kernel32.dll", "kernelbase.dll", "ntdll.dll"};

	for (const char* const module_name : user_modules)
	{
		HMODULE module = GetModuleHandleA(module_name);

		if (module == nullptr)
		{
			module = LoadLibraryA(module_name);
		}

		if (module == nullptr)
		{
			continue;
		}

		const FARPROC export_address = GetProcAddress(module, token.c_str());

		if (export_address != nullptr)
		{
			address_out = reinterpret_cast<std::uint64_t>(export_address);

			return 1;
		}
	}

	LOG_ERR("invalid address: {}", token);

	return 0;
}

static std::string breakpoint_symbol_name(const std::uint64_t address)
{
	for (const auto& [module_name, module_info] : sys::kernel::modules_list)
	{
		if (module_info.base_address == address)
		{
			return module_name;
		}

		for (const auto& [export_name, export_address] : module_info.exports)
		{
			if (export_address == address)
			{
				return export_name;
			}
		}
	}

	return {};
}

static std::string format_eflags(const std::uint64_t flags)
{
	const auto bit = [flags](const std::uint64_t index) -> std::uint8_t
	{
		return static_cast<std::uint8_t>((flags >> index) & 1ull);
	};

	return fmt::format("{} {} {} {} {} {} {} {}", bit(11) == 1 ? "ov" : "nv", bit(10) == 1 ? "dn" : "up",
	                   bit(9) == 1 ? "ei" : "di", bit(7) == 1 ? "ng" : "pl", bit(6) == 1 ? "zr" : "nz",
	                   bit(4) == 1 ? "ac" : "na", bit(2) == 1 ? "pe" : "po", bit(0) == 1 ? "cy" : "nc");
}

static void print_paused_registers(const breakpoint::registers_t& registers)
{
	fmt::print("rax={:016x} rbx={:016x} rcx={:016x}\n", registers.rax, registers.rbx, registers.rcx);
	fmt::print("rdx={:016x} rsi={:016x} rdi={:016x}\n", registers.rdx, registers.rsi, registers.rdi);
	fmt::print("rip={} rsp={} rbp={:016x}\n", format_windbg_address(registers.rip), format_windbg_address(registers.rsp),
	           registers.rbp);
	fmt::print(" r8={:016x}  r9={:016x} r10={:016x}\n", registers.r8, registers.r9, registers.r10);
	fmt::print("r11={:016x} r12={:016x} r13={:016x}\n", registers.r11, registers.r12, registers.r13);
	fmt::print("r14={:016x} r15={:016x}\n", registers.r14, registers.r15);

	if (registers.rflags_known == 1)
	{
		fmt::print("efl={:08x} {}\n", static_cast<std::uint32_t>(registers.rflags), format_eflags(registers.rflags));
	}

	std::fflush(stdout);
}

static void print_instruction_buffer(const std::uint64_t address, const std::uint8_t* const buffer, const std::uint64_t size)
{
	if (buffer == nullptr || size == 0)
	{
		print_disassembly_line(address, {}, "??");

		return;
	}

	ZydisDecoder decoder = {};

	if (ZYAN_FAILED(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64)))
	{
		print_disassembly_line(address, {}, "??");

		return;
	}

	ZydisDecoderContext decoder_context = {};
	ZydisDecodedInstruction decoded_instruction = {};

	if (ZYAN_FAILED(ZydisDecoderDecodeInstruction(&decoder, &decoder_context, buffer, size, &decoded_instruction)))
	{
		print_disassembly_line(address, {}, "??");

		return;
	}

	std::array<ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT> operands = {};

	if (ZYAN_FAILED(ZydisDecoderDecodeOperands(&decoder, &decoder_context, &decoded_instruction, operands.data(),
	                                           static_cast<ZyanU8>(operands.size()))))
	{
		print_disassembly_line(address, {}, "??");

		return;
	}

	ZydisFormatter formatter = {};

	if (ZYAN_FAILED(ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL)))
	{
		print_disassembly_line(address, {}, "??");

		return;
	}

	char formatted_instruction[256] = {};

	if (ZYAN_FAILED(ZydisFormatterFormatInstruction(&formatter, &decoded_instruction, operands.data(),
	                                                decoded_instruction.operand_count, formatted_instruction,
	                                                sizeof(formatted_instruction), address, nullptr)))
	{
		print_disassembly_line(address, {}, "??");

		return;
	}

	print_disassembly_line(address, {}, formatted_instruction);
	unassemble_next_address = address;
	unassemble_has_next_address = 1;
}

static void print_paused_instruction(const std::uint64_t address)
{
	std::uint8_t buffer[15] = {};

	if (breakpoint::read_paused_virtual(buffer, address, sizeof(buffer)) == 0)
	{
		print_disassembly_line(address, {}, "??");

		return;
	}

	print_instruction_buffer(address, buffer, sizeof(buffer));
}

static void print_memory_instruction(const std::uint64_t address, const std::uint64_t cr3)
{
	std::uint8_t buffer[15] = {};

	if (cr3 == 0 || hypercall::read_guest_virtual_memory(buffer, address, cr3, sizeof(buffer)) != sizeof(buffer))
	{
		print_disassembly_line(address, {}, "??");

		return;
	}

	print_instruction_buffer(address, buffer, sizeof(buffer));
}

static void print_paused_state()
{
	breakpoint::registers_t registers = {};

	if (breakpoint::paused_registers(registers) == 0)
	{
		return;
	}

	print_paused_registers(registers);
	print_paused_instruction(registers.rip);
}

static std::uint8_t write_step_jump(std::uint8_t* const destination, const std::uint64_t site, const std::uint64_t target)
{
	const std::int64_t delta = static_cast<std::int64_t>(target) - static_cast<std::int64_t>(site + 5);

	if (delta < static_cast<std::int64_t>(INT32_MIN) || delta > static_cast<std::int64_t>(INT32_MAX))
	{
		return 0;
	}

	destination[0] = 0xE9;
	*reinterpret_cast<std::int32_t*>(destination + 1) = static_cast<std::int32_t>(delta);

	return 1;
}

static void write_step_absolute_jump(std::uint8_t* const destination, const std::uint64_t target)
{
	destination[0] = 0x68;
	*reinterpret_cast<std::uint32_t*>(destination + 1) = static_cast<std::uint32_t>(target);
	destination[5] = 0xC7;
	destination[6] = 0x44;
	destination[7] = 0x24;
	destination[8] = 0x04;
	*reinterpret_cast<std::uint32_t*>(destination + 9) = static_cast<std::uint32_t>(target >> 32);
	destination[13] = 0xC3;
}

static std::uint8_t paused_zydis_register(const ZydisRegister reg, const breakpoint::registers_t& registers,
                                          std::uint64_t& value_out)
{
	const ZydisRegister largest = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, reg);
	std::uint64_t value = 0;

	switch (largest)
	{
	case ZYDIS_REGISTER_RAX:
		value = registers.rax;
		break;
	case ZYDIS_REGISTER_RCX:
		value = registers.rcx;
		break;
	case ZYDIS_REGISTER_RDX:
		value = registers.rdx;
		break;
	case ZYDIS_REGISTER_RBX:
		value = registers.rbx;
		break;
	case ZYDIS_REGISTER_RSP:
		value = registers.rsp;
		break;
	case ZYDIS_REGISTER_RBP:
		value = registers.rbp;
		break;
	case ZYDIS_REGISTER_RSI:
		value = registers.rsi;
		break;
	case ZYDIS_REGISTER_RDI:
		value = registers.rdi;
		break;
	case ZYDIS_REGISTER_R8:
		value = registers.r8;
		break;
	case ZYDIS_REGISTER_R9:
		value = registers.r9;
		break;
	case ZYDIS_REGISTER_R10:
		value = registers.r10;
		break;
	case ZYDIS_REGISTER_R11:
		value = registers.r11;
		break;
	case ZYDIS_REGISTER_R12:
		value = registers.r12;
		break;
	case ZYDIS_REGISTER_R13:
		value = registers.r13;
		break;
	case ZYDIS_REGISTER_R14:
		value = registers.r14;
		break;
	case ZYDIS_REGISTER_R15:
		value = registers.r15;
		break;
	default:
		return 0;
	}

	if (reg == ZYDIS_REGISTER_AH || reg == ZYDIS_REGISTER_CH || reg == ZYDIS_REGISTER_DH || reg == ZYDIS_REGISTER_BH)
	{
		value_out = (value >> 8) & 0xFFull;

		return 1;
	}

	const ZyanU16 width = ZydisRegisterGetWidth(ZYDIS_MACHINE_MODE_LONG_64, reg);

	if (width >= 64)
	{
		value_out = value;
	}
	else
	{
		value_out = value & ((1ull << width) - 1ull);
	}

	return 1;
}

static std::uint8_t memory_operand_address(const ZydisDecodedOperand& operand, const std::uint64_t runtime,
                                           const std::uint64_t length, const breakpoint::registers_t& registers,
                                           std::uint64_t& address_out)
{
	if (operand.type != ZYDIS_OPERAND_TYPE_MEMORY)
	{
		return 0;
	}

	std::uint64_t address = 0;

	if (operand.mem.base == ZYDIS_REGISTER_RIP || operand.mem.base == ZYDIS_REGISTER_EIP)
	{
		address = runtime + length;
	}
	else if (operand.mem.base != ZYDIS_REGISTER_NONE)
	{
		std::uint64_t base = 0;

		if (paused_zydis_register(operand.mem.base, registers, base) == 0)
		{
			return 0;
		}

		address = base;
	}

	if (operand.mem.index != ZYDIS_REGISTER_NONE)
	{
		std::uint64_t index = 0;

		if (paused_zydis_register(operand.mem.index, registers, index) == 0)
		{
			return 0;
		}

		const std::uint64_t scale = operand.mem.scale == 0 ? 1 : operand.mem.scale;

		address += index * scale;
	}

	if (operand.mem.disp.has_displacement == 1)
	{
		address += static_cast<std::uint64_t>(operand.mem.disp.value);
	}

	address_out = address;

	return 1;
}

static std::uint8_t branch_target(const ZydisDecodedInstruction& instruction,
                                  const std::array<ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT>& operands,
                                  const std::uint64_t runtime, const breakpoint::registers_t& registers,
                                  std::uint64_t& target_out)
{
	for (std::uint8_t index = 0; index < instruction.operand_count_visible; index++)
	{
		const ZydisDecodedOperand& operand = operands[index];

		if (operand.type == ZYDIS_OPERAND_TYPE_POINTER)
		{
			return 0;
		}

		if (operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && operand.imm.is_relative == 1)
		{
			return ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instruction, &operand, runtime, &target_out)) == 1 ? 1 : 0;
		}

		if (operand.type == ZYDIS_OPERAND_TYPE_REGISTER)
		{
			return paused_zydis_register(operand.reg.value, registers, target_out);
		}

		if (operand.type == ZYDIS_OPERAND_TYPE_MEMORY)
		{
			std::uint64_t address = 0;

			if (memory_operand_address(operand, runtime, instruction.length, registers, address) == 0 ||
				breakpoint::read_paused_virtual(&target_out, address, sizeof(target_out)) == 0)
			{
				return 0;
			}

			return 1;
		}
	}

	return 0;
}

static std::uint8_t is_jcc(const ZydisMnemonic mnemonic)
{
	switch (mnemonic)
	{
	case ZYDIS_MNEMONIC_JB:
	case ZYDIS_MNEMONIC_JBE:
	case ZYDIS_MNEMONIC_JL:
	case ZYDIS_MNEMONIC_JLE:
	case ZYDIS_MNEMONIC_JNB:
	case ZYDIS_MNEMONIC_JNBE:
	case ZYDIS_MNEMONIC_JNL:
	case ZYDIS_MNEMONIC_JNLE:
	case ZYDIS_MNEMONIC_JNO:
	case ZYDIS_MNEMONIC_JNP:
	case ZYDIS_MNEMONIC_JNS:
	case ZYDIS_MNEMONIC_JNZ:
	case ZYDIS_MNEMONIC_JO:
	case ZYDIS_MNEMONIC_JP:
	case ZYDIS_MNEMONIC_JS:
	case ZYDIS_MNEMONIC_JZ:
	case ZYDIS_MNEMONIC_JCXZ:
	case ZYDIS_MNEMONIC_JECXZ:
	case ZYDIS_MNEMONIC_JRCXZ:
		return 1;
	default:
		return 0;
	}
}

static std::uint8_t jcc_taken(const ZydisMnemonic mnemonic, const breakpoint::registers_t& registers)
{
	const std::uint8_t overflow = static_cast<std::uint8_t>((registers.rflags >> 11) & 1ull);
	const std::uint8_t sign = static_cast<std::uint8_t>((registers.rflags >> 7) & 1ull);
	const std::uint8_t zero = static_cast<std::uint8_t>((registers.rflags >> 6) & 1ull);
	const std::uint8_t parity = static_cast<std::uint8_t>((registers.rflags >> 2) & 1ull);
	const std::uint8_t carry = static_cast<std::uint8_t>(registers.rflags & 1ull);

	switch (mnemonic)
	{
	case ZYDIS_MNEMONIC_JO:
		return overflow;
	case ZYDIS_MNEMONIC_JNO:
		return static_cast<std::uint8_t>(overflow == 0);
	case ZYDIS_MNEMONIC_JB:
		return carry;
	case ZYDIS_MNEMONIC_JNB:
		return static_cast<std::uint8_t>(carry == 0);
	case ZYDIS_MNEMONIC_JZ:
		return zero;
	case ZYDIS_MNEMONIC_JNZ:
		return static_cast<std::uint8_t>(zero == 0);
	case ZYDIS_MNEMONIC_JBE:
		return static_cast<std::uint8_t>(carry == 1 || zero == 1);
	case ZYDIS_MNEMONIC_JNBE:
		return static_cast<std::uint8_t>(carry == 0 && zero == 0);
	case ZYDIS_MNEMONIC_JS:
		return sign;
	case ZYDIS_MNEMONIC_JNS:
		return static_cast<std::uint8_t>(sign == 0);
	case ZYDIS_MNEMONIC_JP:
		return parity;
	case ZYDIS_MNEMONIC_JNP:
		return static_cast<std::uint8_t>(parity == 0);
	case ZYDIS_MNEMONIC_JL:
		return static_cast<std::uint8_t>(sign != overflow);
	case ZYDIS_MNEMONIC_JNL:
		return static_cast<std::uint8_t>(sign == overflow);
	case ZYDIS_MNEMONIC_JLE:
		return static_cast<std::uint8_t>(zero == 1 || sign != overflow);
	case ZYDIS_MNEMONIC_JNLE:
		return static_cast<std::uint8_t>(zero == 0 && sign == overflow);
	case ZYDIS_MNEMONIC_JRCXZ:
		return static_cast<std::uint8_t>(registers.rcx == 0);
	case ZYDIS_MNEMONIC_JECXZ:
		return static_cast<std::uint8_t>(static_cast<std::uint32_t>(registers.rcx) == 0);
	case ZYDIS_MNEMONIC_JCXZ:
		return static_cast<std::uint8_t>(static_cast<std::uint16_t>(registers.rcx) == 0);
	default:
		return 0;
	}
}

static std::uint8_t refuses_step(const ZydisMnemonic mnemonic)
{
	switch (mnemonic)
	{
	case ZYDIS_MNEMONIC_SYSCALL:
	case ZYDIS_MNEMONIC_SYSENTER:
	case ZYDIS_MNEMONIC_SYSRET:
	case ZYDIS_MNEMONIC_INT:
	case ZYDIS_MNEMONIC_INT1:
	case ZYDIS_MNEMONIC_INT3:
	case ZYDIS_MNEMONIC_IRET:
	case ZYDIS_MNEMONIC_IRETD:
	case ZYDIS_MNEMONIC_IRETQ:
	case ZYDIS_MNEMONIC_HLT:
		return 1;
	default:
		return 0;
	}
}

static std::uint8_t step_once(const std::uint8_t into)
{
	breakpoint::registers_t registers = {};

	if (breakpoint::paused_registers(registers) == 0)
	{
		LOG_ERR("no paused thread");

		return 0;
	}

	std::uint8_t buffer[15] = {};

	if (breakpoint::read_paused_virtual(buffer, registers.rip, sizeof(buffer)) == 0)
	{
		LOG_ERR("failed to read the instruction");

		return 0;
	}

	ZydisDecoder decoder = {};
	ZydisDecoderContext decoder_context = {};
	ZydisDecodedInstruction decoded_instruction = {};

	if (ZYAN_FAILED(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64)) ||
		ZYAN_FAILED(ZydisDecoderDecodeInstruction(&decoder, &decoder_context, buffer, sizeof(buffer), &decoded_instruction)))
	{
		LOG_ERR("failed to decode the instruction");

		return 0;
	}

	std::array<ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT> operands = {};

	if (ZYAN_FAILED(ZydisDecoderDecodeOperands(&decoder, &decoder_context, &decoded_instruction, operands.data(),
	                                           static_cast<ZyanU8>(operands.size()))))
	{
		LOG_ERR("failed to decode the instruction");

		return 0;
	}

	if (refuses_step(decoded_instruction.mnemonic) == 1)
	{
		LOG_ERR("cannot step this instruction");

		return 0;
	}

	const std::uint64_t fallthrough = registers.rip + decoded_instruction.length;
	const std::uint64_t entry = breakpoint::pause_entry_address();
	const std::uint64_t cave0 = breakpoint::step_cave_address(0);
	const std::uint64_t cave1 = breakpoint::step_cave_address(1);
	std::uint64_t logical_rip = fallthrough;
	std::uint64_t go_target = entry;
	std::uint8_t hide_site = 0;

	if (entry == 0 || cave0 == 0)
	{
		LOG_ERR("no paused thread");

		return 0;
	}

	if (decoded_instruction.mnemonic == ZYDIS_MNEMONIC_CALL)
	{
		std::uint64_t target = 0;

		if (branch_target(decoded_instruction, operands, registers.rip, registers, target) == 0)
		{
			LOG_ERR("cannot resolve this call");

			return 0;
		}

		if (into == 1)
		{
			std::uint8_t code[18] = {};

			code[0] = 0x68;
			*reinterpret_cast<std::uint32_t*>(code + 1) = static_cast<std::uint32_t>(fallthrough);
			code[5] = 0xC7;
			code[6] = 0x44;
			code[7] = 0x24;
			code[8] = 0x04;
			*reinterpret_cast<std::uint32_t*>(code + 9) = static_cast<std::uint32_t>(fallthrough >> 32);

			if (write_step_jump(code + 13, cave0 + 13, entry) == 0 ||
				breakpoint::write_step_cave(0, code, sizeof(code)) == 0)
			{
				return 0;
			}

			logical_rip = target;
			go_target = cave0;
		}
		else
		{
			const std::int64_t call_delta = static_cast<std::int64_t>(target) - static_cast<std::int64_t>(cave0 + 5);

			if (call_delta < static_cast<std::int64_t>(INT32_MIN) || call_delta > static_cast<std::int64_t>(INT32_MAX))
			{
				LOG_ERR("cannot step over this call");

				return 0;
			}

			// The call returns to the jmp that re-enters the pause stub. Both bytes live in the
			// cave that single-step already executes, so a second cave cannot land on int 3 padding.
			std::uint8_t code[10] = {0xE8};

			*reinterpret_cast<std::int32_t*>(code + 1) = static_cast<std::int32_t>(call_delta);

			if (write_step_jump(code + 5, cave0 + 5, entry) == 0 || breakpoint::write_step_cave(0, code, sizeof(code)) == 0)
			{
				return 0;
			}

			hide_site = 1;
			go_target = cave0;
		}
	}
	else if (decoded_instruction.mnemonic == ZYDIS_MNEMONIC_RET)
	{
		std::uint64_t return_address = 0;
		std::uint32_t adjust = 8;

		if (breakpoint::read_paused_virtual(&return_address, registers.rsp, sizeof(return_address)) == 0)
		{
			LOG_ERR("failed to read the return address");

			return 0;
		}

		if (decoded_instruction.operand_count_visible > 0 && operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
		{
			adjust += static_cast<std::uint32_t>(operands[0].imm.value.u);
		}

		std::uint8_t code[12] = {0x48, 0x81, 0xC4};

		*reinterpret_cast<std::uint32_t*>(code + 3) = adjust;

		if (write_step_jump(code + 7, cave0 + 7, entry) == 0 || breakpoint::write_step_cave(0, code, sizeof(code)) == 0)
		{
			return 0;
		}

		logical_rip = return_address;
		go_target = cave0;
	}
	else if (decoded_instruction.mnemonic == ZYDIS_MNEMONIC_JMP || is_jcc(decoded_instruction.mnemonic) == 1)
	{
		std::uint64_t target = 0;

		if (branch_target(decoded_instruction, operands, registers.rip, registers, target) == 0)
		{
			LOG_ERR("cannot resolve this branch");

			return 0;
		}

		if (is_jcc(decoded_instruction.mnemonic) == 1)
		{
			if (registers.rflags_known == 0)
			{
				LOG_ERR("flags are not available");

				return 0;
			}

			logical_rip = jcc_taken(decoded_instruction.mnemonic, registers) == 1 ? target : fallthrough;
		}
		else
		{
			logical_rip = target;
		}
	}
	else if (decoded_instruction.mnemonic == ZYDIS_MNEMONIC_LOOP || decoded_instruction.mnemonic == ZYDIS_MNEMONIC_LOOPE ||
		decoded_instruction.mnemonic == ZYDIS_MNEMONIC_LOOPNE)
	{
		std::uint64_t target = 0;

		if (branch_target(decoded_instruction, operands, registers.rip, registers, target) == 0)
		{
			LOG_ERR("cannot resolve this branch");

			return 0;
		}

		const std::uint64_t next_rcx = registers.rcx - 1;
		const std::uint8_t zero = static_cast<std::uint8_t>((registers.rflags >> 6) & 1ull);
		std::uint8_t taken = static_cast<std::uint8_t>(next_rcx != 0);

		if (decoded_instruction.mnemonic == ZYDIS_MNEMONIC_LOOPE)
		{
			taken = static_cast<std::uint8_t>(next_rcx != 0 && zero == 1);
		}
		else if (decoded_instruction.mnemonic == ZYDIS_MNEMONIC_LOOPNE)
		{
			taken = static_cast<std::uint8_t>(next_rcx != 0 && zero == 0);
		}

		if (breakpoint::set_paused_register("rcx", next_rcx) == 0)
		{
			return 0;
		}

		logical_rip = taken == 1 ? target : fallthrough;
	}
	else
	{
		const auto relocated = hook_disasm::get_routine_aligned_bytes(buffer, decoded_instruction.length, registers.rip);
		const std::uint8_t relative = static_cast<std::uint8_t>((decoded_instruction.attributes & ZYDIS_ATTRIB_IS_RELATIVE) != 0);

		if (relocated.second != decoded_instruction.length || relocated.first.empty() == true ||
			(relative == 1 && relocated.first.size() == decoded_instruction.length) ||
			relocated.first.size() + 5 > breakpoint::step_cave_capacity(0))
		{
			LOG_ERR("cannot step this instruction");

			return 0;
		}

		std::vector<std::uint8_t> code = relocated.first;

		code.resize(code.size() + 5);

		if (write_step_jump(code.data() + relocated.first.size(), cave0 + relocated.first.size(), entry) == 0 ||
			breakpoint::write_step_cave(0, code.data(), code.size()) == 0)
		{
			return 0;
		}

		go_target = cave0;
	}

	if (hide_site == 1)
	{
		breakpoint::set_pause_site_patched(0);
	}

	const std::uint8_t continued = breakpoint::continue_paused_thread(logical_rip, go_target, 30000);

	if (hide_site == 1)
	{
		breakpoint::set_pause_site_patched(1);
	}

	if (continued == 0)
	{
		return 0;
	}

	print_paused_instruction(logical_rip);

	return 1;
}

enum class step_stop_t : std::uint8_t
{
	none,
	call,
	ret,
	either
};

static std::uint8_t instruction_matches_stop(const step_stop_t stop)
{
	breakpoint::registers_t registers = {};
	std::uint8_t buffer[15] = {};
	ZydisDecoder decoder = {};
	ZydisDecoderContext decoder_context = {};
	ZydisDecodedInstruction decoded_instruction = {};

	if (stop == step_stop_t::none || breakpoint::paused_registers(registers) == 0 ||
		breakpoint::read_paused_virtual(buffer, registers.rip, sizeof(buffer)) == 0 ||
		ZYAN_FAILED(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64)) ||
		ZYAN_FAILED(ZydisDecoderDecodeInstruction(&decoder, &decoder_context, buffer, sizeof(buffer), &decoded_instruction)))
	{
		return 0;
	}

	const std::uint8_t call = static_cast<std::uint8_t>(decoded_instruction.mnemonic == ZYDIS_MNEMONIC_CALL);
	const std::uint8_t ret = static_cast<std::uint8_t>(decoded_instruction.mnemonic == ZYDIS_MNEMONIC_RET);

	if (stop == step_stop_t::call)
	{
		return call;
	}

	if (stop == step_stop_t::ret)
	{
		return ret;
	}

	return static_cast<std::uint8_t>(call == 1 || ret == 1);
}

static std::uint8_t parse_step_count(const std::vector<std::string>& args, std::uint64_t& count_out)
{
	if (args.empty() == true)
	{
		count_out = 1;

		return 1;
	}

	if (args.size() == 1 && parse_windbg_number(args[0], count_out) == 1 && count_out != 0 && count_out <= 100000)
	{
		return 1;
	}

	LOG_ERR("invalid syntax");

	return 0;
}

static void run_steps(const std::uint8_t into, const std::uint64_t count, const step_stop_t stop)
{
	if (breakpoint::capture_pause() == 0)
	{
		LOG_ERR("no paused thread");

		return;
	}

	if (stop == step_stop_t::none)
	{
		for (std::uint64_t index = 0; index < count; index++)
		{
			if (step_once(into) == 0)
			{
				return;
			}
		}
	}
	else
	{
		constexpr std::uint64_t step_limit = 100000;

		if (instruction_matches_stop(stop) == 1 && step_once(into) == 0)
		{
			return;
		}

		std::uint64_t hits = 0;
		std::uint64_t steps = 0;

		while (hits < count && steps < step_limit)
		{
			if (instruction_matches_stop(stop) == 1)
			{
				hits++;

				if (hits >= count)
				{
					break;
				}
			}

			if (step_once(into) == 0)
			{
				return;
			}

			steps++;
		}

		if (hits < count)
		{
			LOG_ERR("step limit reached");
		}
	}

	print_paused_state();
}

static void process_step_command(const CLI::App* const command, const std::uint8_t into, const step_stop_t stop)
{
	std::uint64_t count = 1;

	if (parse_step_count(command->remaining(), count) == 0)
	{
		return;
	}

	run_steps(into, count, stop);
}

static std::uint64_t* paused_register_field(breakpoint::registers_t& registers, const std::string_view name)
{
	const auto equals = [name](const char* const text) -> std::uint8_t
	{
		std::uint64_t index = 0;

		while (text[index] != '\0')
		{
			if (index >= name.size() ||
				std::tolower(static_cast<unsigned char>(name[index])) != text[index])
			{
				return 0;
			}

			index++;
		}

		return static_cast<std::uint8_t>(index == name.size());
	};

	if (equals("rax") == 1 || equals("eax") == 1)
	{
		return &registers.rax;
	}

	if (equals("rbx") == 1 || equals("ebx") == 1)
	{
		return &registers.rbx;
	}

	if (equals("rcx") == 1 || equals("ecx") == 1)
	{
		return &registers.rcx;
	}

	if (equals("rdx") == 1 || equals("edx") == 1)
	{
		return &registers.rdx;
	}

	if (equals("rsi") == 1 || equals("esi") == 1)
	{
		return &registers.rsi;
	}

	if (equals("rdi") == 1 || equals("edi") == 1)
	{
		return &registers.rdi;
	}

	if (equals("rbp") == 1 || equals("ebp") == 1)
	{
		return &registers.rbp;
	}

	if (equals("rsp") == 1 || equals("esp") == 1)
	{
		return &registers.rsp;
	}

	if (equals("r8") == 1 || equals("r8d") == 1)
	{
		return &registers.r8;
	}

	if (equals("r9") == 1 || equals("r9d") == 1)
	{
		return &registers.r9;
	}

	if (equals("r10") == 1 || equals("r10d") == 1)
	{
		return &registers.r10;
	}

	if (equals("r11") == 1 || equals("r11d") == 1)
	{
		return &registers.r11;
	}

	if (equals("r12") == 1 || equals("r12d") == 1)
	{
		return &registers.r12;
	}

	if (equals("r13") == 1 || equals("r13d") == 1)
	{
		return &registers.r13;
	}

	if (equals("r14") == 1 || equals("r14d") == 1)
	{
		return &registers.r14;
	}

	if (equals("r15") == 1 || equals("r15d") == 1)
	{
		return &registers.r15;
	}

	if (equals("rip") == 1 || equals("eip") == 1)
	{
		return &registers.rip;
	}

	if (equals("efl") == 1 || equals("rflags") == 1)
	{
		return &registers.rflags;
	}

	return nullptr;
}

static std::uint8_t show_implicit_register_context();
static std::uint8_t read_implicit_register(const std::string_view name, std::uint64_t& value_out);
static std::uint8_t write_implicit_register(const std::string_view name, const std::uint64_t value);
static std::uint8_t implicit_context_active();
static void clear_implicit_thread();

static void process_r(const CLI::App* const command)
{
	std::string text;

	for (const std::string& arg : command->remaining())
	{
		text += arg;
	}

	if (implicit_context_active() == 1)
	{
		if (text.empty() == true)
		{
			show_implicit_register_context();

			return;
		}

		const std::size_t separator = text.find('=');
		const std::string_view name = std::string_view(text).substr(0, separator);

		if (separator == std::string::npos)
		{
			std::uint64_t value = 0;

			if (read_implicit_register(name, value) == 0)
			{
				return;
			}

			fmt::print("{}={:016x}\n", std::string(name), value);
			std::fflush(stdout);

			return;
		}

		std::uint64_t value = 0;

		if (name.empty() == true || parse_windbg_number(std::string_view(text).substr(separator + 1), value) == 0)
		{
			LOG_ERR("invalid syntax");

			return;
		}

		if (write_implicit_register(name, value) == 0)
		{
			return;
		}

		fmt::print("{}={:016x}\n", std::string(name), value);
		fmt::print("context only; the guest thread was not changed\n");
		std::fflush(stdout);

		return;
	}

	if (breakpoint::capture_pause() == 0)
	{
		LOG_ERR("no paused thread");

		return;
	}

	if (text.empty() == true)
	{
		print_paused_state();

		return;
	}

	const std::size_t separator = text.find('=');
	const std::string_view name = std::string_view(text).substr(0, separator);

	if (separator == std::string::npos)
	{
		breakpoint::registers_t registers = {};

		if (breakpoint::paused_registers(registers) == 0)
		{
			LOG_ERR("no paused thread");

			return;
		}

		const std::uint64_t* const field = paused_register_field(registers, name);

		if (field == nullptr)
		{
			LOG_ERR("invalid register");

			return;
		}

		fmt::print("{}={:016x}\n", std::string(name), *field);
		std::fflush(stdout);

		return;
	}

	std::uint64_t value = 0;

	if (name.empty() == true || parse_windbg_number(std::string_view(text).substr(separator + 1), value) == 0)
	{
		LOG_ERR("invalid syntax");

		return;
	}

	if (breakpoint::set_paused_register(name, value) == 0)
	{
		return;
	}

	fmt::print("{}={:016x}\n", std::string(name), value);
	std::fflush(stdout);
}

static void process_t(const CLI::App* const command)
{
	process_step_command(command, 1, step_stop_t::none);
}

static void process_p(const CLI::App* const command)
{
	process_step_command(command, 0, step_stop_t::none);
}

static void process_tc(const CLI::App* const command)
{
	process_step_command(command, 1, step_stop_t::call);
}

static void process_tt(const CLI::App* const command)
{
	process_step_command(command, 1, step_stop_t::ret);
}

static void process_tct(const CLI::App* const command)
{
	process_step_command(command, 1, step_stop_t::either);
}

static void process_pc(const CLI::App* const command)
{
	process_step_command(command, 0, step_stop_t::call);
}

static void process_pt(const CLI::App* const command)
{
	process_step_command(command, 0, step_stop_t::ret);
}

static void process_pct(const CLI::App* const command)
{
	process_step_command(command, 0, step_stop_t::either);
}

static std::uint8_t resume_suspended_process();
static std::uint8_t read_kernel_memory(std::uint64_t address, void* buffer, std::uint64_t size);
static void release_suspended_process_for_pause(std::uint64_t cr3);
static void announce_breakpoint_hit();

static void process_g(const CLI::App* const command)
{
	if (command->remaining().empty() == false)
	{
		LOG_ERR("invalid syntax");

		return;
	}

	if (breakpoint::has_paused_thread() == 0)
	{
		if (resume_suspended_process() == 0)
		{
			LOG_ERR("no paused thread");
		}
		else
		{
			clear_implicit_thread();
		}

		return;
	}

	breakpoint::registers_t registers = {};
	const std::uint8_t had_pause = breakpoint::paused_registers(registers);

	if (breakpoint::resume_paused() == 0)
	{
		return;
	}

	LOG_INFO("go");
	clear_implicit_thread();

	if (had_pause == 1)
	{
		release_suspended_process_for_pause(registers.cr3);
	}
}

static void process_bp(const CLI::App* const command)
{
	const std::vector<std::string> args = command->remaining();

	if (args.size() > 2)
	{
		LOG_ERR("invalid syntax");

		return;
	}

	const std::unordered_map<std::string, std::uint64_t> aliases = sys::kernel::compile_symbol_list();
	std::uint64_t address = 0;
	std::uint64_t cr3 = 0;
	std::uint64_t selector = 0;

	if (args.empty() == true)
	{
		if (resolve_breakpoint_address(".", aliases, address) == 0)
		{
			return;
		}
	}
	else if (resolve_breakpoint_address(args[0], aliases, address) == 0)
	{
		return;
	}

	if (args.size() == 2)
	{
		if (resolve_windbg_address(aliases, args[1], selector) == 0)
		{
			LOG_ERR("invalid cr3: {}", args[1]);

			return;
		}

		if (selector <= 0xFFFFF)
		{
			cr3 = breakpoint::cr3_for_process(selector);

			if (cr3 == 0)
			{
				LOG_ERR("process {} was not found", selector);

				return;
			}
		}
		else
		{
			cr3 = selector;
		}
	}

	std::uint64_t id = 0;

	breakpoint::add(address, cr3, id);
}

static std::uint8_t parse_breakpoint_ids(const std::vector<std::string>& args, std::vector<std::uint64_t>& ids_out,
                                         std::uint8_t& all_out)
{
	all_out = 0;
	ids_out.clear();

	if (args.empty() == true)
	{
		LOG_ERR("missing breakpoint id");

		return 0;
	}

	if (args.size() == 1 && args[0] == "*")
	{
		all_out = 1;

		return 1;
	}

	for (const std::string& arg : args)
	{
		std::uint64_t id = 0;

		if (arg == "*" || parse_windbg_number(arg, id) == 0)
		{
			LOG_ERR("invalid breakpoint id: {}", arg);

			return 0;
		}

		ids_out.push_back(id);
	}

	return 1;
}

static void process_bl(const CLI::App* const command)
{
	if (command->remaining().empty() == false)
	{
		LOG_ERR("invalid syntax");

		return;
	}

	const std::vector<breakpoint::info_t> breakpoints = breakpoint::list();

	if (breakpoints.empty() == true)
	{
		LOG_INFO("no breakpoints");

		return;
	}

	for (const breakpoint::info_t& breakpoint : breakpoints)
	{
		const std::string symbol = breakpoint_symbol_name(breakpoint.address);

		fmt::print("{:<4} {} {}", breakpoint.id, breakpoint.enabled == 1 ? "e" : "d",
		           format_windbg_address(breakpoint.address));

		if (breakpoint.pauses_thread == 1)
		{
			fmt::print(" pause");
		}

		if (symbol.empty() == false)
		{
			fmt::print(" {}", symbol);
		}

		if (breakpoint.cr3 != 0)
		{
			fmt::print(" cr3 {}", format_windbg_address(breakpoint.cr3));
		}

		fmt::print("\n");
	}

	std::fflush(stdout);
}

static void process_bc(const CLI::App* const command)
{
	std::vector<std::uint64_t> ids = {};
	std::uint8_t all = 0;

	if (parse_breakpoint_ids(command->remaining(), ids, all) == 0)
	{
		return;
	}

	if (all == 1)
	{
		breakpoint::remove_all();

		return;
	}

	for (const std::uint64_t id : ids)
	{
		breakpoint::remove(id);
	}
}

static void process_bd(const CLI::App* const command)
{
	std::vector<std::uint64_t> ids = {};
	std::uint8_t all = 0;

	if (parse_breakpoint_ids(command->remaining(), ids, all) == 0)
	{
		return;
	}

	if (all == 1)
	{
		breakpoint::set_all_enabled(0);

		return;
	}

	for (const std::uint64_t id : ids)
	{
		breakpoint::set_enabled(id, 0);
	}
}

static void process_be(const CLI::App* const command)
{
	std::vector<std::uint64_t> ids = {};
	std::uint8_t all = 0;

	if (parse_breakpoint_ids(command->remaining(), ids, all) == 0)
	{
		return;
	}

	if (all == 1)
	{
		breakpoint::set_all_enabled(1);

		return;
	}

	for (const std::uint64_t id : ids)
	{
		breakpoint::set_enabled(id, 1);
	}
}

static std::string symbol_command_text(const std::string_view command_name)
{
	std::string_view text = skip_whitespace(windbg_command_line);

	if (text.size() >= command_name.size() && equals_ignore_case(text.substr(0, command_name.size()), command_name) == 1)
	{
		text.remove_prefix(command_name.size());
	}

	text = skip_whitespace(text);

	if (text.size() >= 2 && text.front() == '"' && text.back() == '"')
	{
		text.remove_prefix(1);
		text.remove_suffix(1);
	}

	return std::string(text);
}

static std::uint8_t read_guest_module_bytes(const std::uint64_t base, const std::uint64_t rva, const std::uint64_t cr3,
                                            void* const buffer, const std::uint64_t size)
{
	if (cr3 == 0 || buffer == nullptr || size == 0 || base + rva < base)
	{
		return 0;
	}

	return static_cast<std::uint8_t>(hypercall::read_guest_virtual_memory(buffer, base + rva, cr3, size) == size);
}

struct reload_module_t
{
	std::string name = {};
	std::string path = {};
	std::uint64_t base = 0;
	std::uint32_t size = 0;
	std::uint64_t cr3 = 0;
};

struct dot_progress_t
{
	std::atomic<std::uint8_t> running = 1;
	std::thread worker;

	dot_progress_t()
		: worker([this]
		{
			while (running.load() == 1)
			{
				fmt::print(".");
				std::fflush(stdout);
				Sleep(200);
			}
		})
	{
	}

	~dot_progress_t()
	{
		running.store(0);

		if (worker.joinable() == true)
		{
			worker.join();
		}
	}
};

static std::uint8_t console_interrupt_requested();
static void console_interrupt_clear();

static std::uint8_t load_image_symbols(const reload_module_t& module, const std::uint8_t force, const std::uint8_t overwrite)
{
	fmt::print("Loading symbols for {:08x}`{:08x} {} ", static_cast<std::uint32_t>(module.base >> 32),
	           static_cast<std::uint32_t>(module.base), module.name);
	std::fflush(stdout);

	std::string detail = {};
	std::uint8_t loaded = 0;

	{
		const dot_progress_t progress = {};
		const symbol_parser::image_read_t read = [base = module.base, cr3 = module.cr3](const std::uint64_t rva, void* const buffer,
		                                                                                const std::uint64_t size)
		{
			return read_guest_module_bytes(base, rva, cr3, buffer, size);
		};
		loaded = symbol_parser::load_module(module.name, module.base, module.size, read, module.path, force, overwrite, detail);
	}

	fmt::print("\n");

	if (loaded == 0)
	{
		if (detail != "interrupted")
		{
			LOG_ERR("{}: {}", module.name, detail);
		}

		return 0;
	}

	fmt::print("    {}\n", detail);

	return 1;
}

static std::uint8_t kernel_module_selected(const std::string_view module_name, const std::string_view filter)
{
	if (filter.empty() == true)
	{
		return 1;
	}

	if (equals_ignore_case(module_name, filter) == 1 || equals_ignore_case(module_stem(module_name), filter) == 1)
	{
		return 1;
	}

	const std::uint8_t filter_is_nt = static_cast<std::uint8_t>(equals_ignore_case(filter, "nt") == 1);
	const std::uint8_t module_is_nt = is_ntoskrnl_module(module_name);

	return static_cast<std::uint8_t>(filter_is_nt == 1 && module_is_nt == 1);
}

static void append_kernel_modules(std::vector<reload_module_t>& modules, const std::string_view filter)
{
	for (const auto& [module_name, module_info] : sys::kernel::modules_list)
	{
		if (kernel_module_selected(module_name, filter) == 0)
		{
			continue;
		}

		reload_module_t module = {};
		module.name = module_name;
		module.base = module_info.base_address;
		module.size = module_info.size;
		module.cr3 = sys::current_cr3;
		modules.push_back(std::move(module));
	}

	std::sort(modules.begin(), modules.end(), [](const reload_module_t& left, const reload_module_t& right)
	{
		const std::uint8_t left_nt = is_ntoskrnl_module(left.name);
		const std::uint8_t right_nt = is_ntoskrnl_module(right.name);

		if (left_nt != right_nt)
		{
			return left_nt > right_nt;
		}

		return _stricmp(left.name.c_str(), right.name.c_str()) < 0;
	});
}

static std::uint8_t same_directory(const std::uint64_t left, const std::uint64_t right)
{
	constexpr std::uint64_t cr3_mask = ~0xFFFull;

	return static_cast<std::uint8_t>(left != 0 && right != 0 && (left & cr3_mask) == (right & cr3_mask));
}

static std::uint64_t eprocess_for_cr3(const std::uint64_t cr3)
{
	constexpr std::uint64_t directory_table_base = 0x28;
	constexpr std::uint64_t user_directory_table_base = 0x158;
	constexpr std::uint64_t active_process_links = 0x1d8;
	const std::unordered_map<std::string, std::uint64_t> aliases = sys::kernel::compile_symbol_list();
	const auto system_process = aliases.find("ntoskrnl.exe!PsInitialSystemProcess");

	if (system_process == aliases.end() || sys::current_cr3 == 0)
	{
		return 0;
	}

	std::uint64_t eprocess = 0;

	if (hypercall::read_guest_virtual_memory(&eprocess, system_process->second, sys::current_cr3, sizeof(eprocess)) !=
			sizeof(eprocess) || eprocess == 0)
	{
		return 0;
	}

	const std::uint64_t first = eprocess;

	for (std::uint64_t count = 0; count < 4096 && eprocess != 0; count++)
	{
		std::uint64_t directory = 0;
		std::uint64_t user_directory = 0;
		hypercall::read_guest_virtual_memory(&directory, eprocess + directory_table_base, sys::current_cr3, sizeof(directory));
		hypercall::read_guest_virtual_memory(&user_directory, eprocess + user_directory_table_base, sys::current_cr3,
		                                     sizeof(user_directory));

		if (same_directory(directory, cr3) == 1 || same_directory(user_directory, cr3) == 1)
		{
			return eprocess;
		}

		std::uint64_t flink = 0;

		if (hypercall::read_guest_virtual_memory(&flink, eprocess + active_process_links, sys::current_cr3, sizeof(flink)) !=
				sizeof(flink) || flink == 0)
		{
			break;
		}

		eprocess = flink - active_process_links;

		if (eprocess == first)
		{
			break;
		}
	}

	return 0;
}

static std::uint8_t collect_user_modules(const std::uint64_t cr3, std::vector<reload_module_t>& modules_out)
{
	constexpr std::uint64_t eprocess_peb = 0x2e0;
	constexpr std::uint64_t peb_ldr = 0x18;
	constexpr std::uint64_t ldr_in_load_order = 0x10;
	constexpr std::uint64_t entry_dll_base = 0x30;
	constexpr std::uint64_t entry_size_of_image = 0x40;
	constexpr std::uint64_t entry_full_dll_name = 0x48;
	constexpr std::uint64_t entry_base_dll_name = 0x58;
	const std::uint64_t eprocess = eprocess_for_cr3(cr3);

	if (eprocess == 0)
	{
		return 0;
	}

	std::uint64_t peb = 0;

	if (hypercall::read_guest_virtual_memory(&peb, eprocess + eprocess_peb, sys::current_cr3, sizeof(peb)) != sizeof(peb) ||
		peb == 0)
	{
		return 0;
	}

	std::uint64_t ldr = 0;

	if (hypercall::read_guest_virtual_memory(&ldr, peb + peb_ldr, cr3, sizeof(ldr)) != sizeof(ldr) || ldr == 0)
	{
		return 0;
	}

	const std::uint64_t head = ldr + ldr_in_load_order;
	std::uint64_t entry = 0;

	if (hypercall::read_guest_virtual_memory(&entry, head, cr3, sizeof(entry)) != sizeof(entry) || entry == 0)
	{
		return 0;
	}

	for (std::uint64_t count = 0; count < 1024 && entry != head && entry != 0; count++)
	{
		std::uint64_t base = 0;
		std::uint32_t image_size = 0;
		std::uint16_t name_length = 0;
		std::uint64_t name_buffer = 0;
		std::uint16_t path_length = 0;
		std::uint64_t path_buffer = 0;
		hypercall::read_guest_virtual_memory(&base, entry + entry_dll_base, cr3, sizeof(base));
		hypercall::read_guest_virtual_memory(&image_size, entry + entry_size_of_image, cr3, sizeof(image_size));
		hypercall::read_guest_virtual_memory(&name_length, entry + entry_base_dll_name, cr3, sizeof(name_length));
		hypercall::read_guest_virtual_memory(&name_buffer, entry + entry_base_dll_name + 8, cr3, sizeof(name_buffer));
		hypercall::read_guest_virtual_memory(&path_length, entry + entry_full_dll_name, cr3, sizeof(path_length));
		hypercall::read_guest_virtual_memory(&path_buffer, entry + entry_full_dll_name + 8, cr3, sizeof(path_buffer));

		if (base != 0 && image_size != 0 && name_length != 0 && name_length < 1024 && name_buffer != 0)
		{
			std::wstring wide(name_length / 2, L'\0');

			if (hypercall::read_guest_virtual_memory(wide.data(), name_buffer, cr3, name_length) == name_length)
			{
				reload_module_t module = {};
				module.name = sys::user::to_string(wide);
				module.base = base;
				module.size = image_size;
				module.cr3 = cr3;

				if (path_length != 0 && path_length < 1024 && path_buffer != 0)
				{
					std::wstring path(path_length / 2, L'\0');

					if (hypercall::read_guest_virtual_memory(path.data(), path_buffer, cr3, path_length) == path_length)
					{
						module.path = sys::user::to_string(path);
					}
				}

				modules_out.push_back(std::move(module));
			}
		}

		std::uint64_t next = 0;

		if (hypercall::read_guest_virtual_memory(&next, entry, cr3, sizeof(next)) != sizeof(next))
		{
			break;
		}

		entry = next;
	}

	return static_cast<std::uint8_t>(modules_out.empty() == false);
}

struct live_context_t
{
	std::uint64_t rip = 0;
	std::uint64_t rip_cr3 = 0;
	std::uint8_t rip_is_user = 0;
	std::uint64_t user_cr3 = 0;
	std::uint64_t image_base = 0;
};

static std::uint8_t read_kernel_qword(const std::uint64_t address, std::uint64_t& value_out)
{
	if (sys::current_cr3 == 0)
	{
		return 0;
	}

	return static_cast<std::uint8_t>(hypercall::read_guest_virtual_memory(&value_out, address, sys::current_cr3, sizeof(value_out)) ==
		sizeof(value_out));
}

static std::uint64_t cr3_for_user_modules(const std::uint64_t eprocess)
{
	constexpr std::uint64_t directory_table_base = 0x28;
	constexpr std::uint64_t user_directory_table_base = 0x158;
	std::uint64_t user_directory = 0;
	std::uint64_t directory = 0;

	read_kernel_qword(eprocess + user_directory_table_base, user_directory);
	read_kernel_qword(eprocess + directory_table_base, directory);

	if (user_directory != 0)
	{
		return user_directory;
	}

	return directory;
}

static std::uint64_t processor_block_address()
{
	const std::unordered_map<std::string, std::uint64_t> aliases = sys::kernel::compile_symbol_list();
	const auto exported_block = aliases.find("ntoskrnl.exe!KiProcessorBlock");

	if (exported_block != aliases.end())
	{
		return exported_block->second;
	}

	const auto query_prcb = aliases.find("ntoskrnl.exe!KeQueryPrcbAddress");

	if (query_prcb == aliases.end())
	{
		return 0;
	}

	std::uint8_t code[32] = {};

	if (hypercall::read_guest_virtual_memory(code, query_prcb->second, sys::current_cr3, sizeof(code)) != sizeof(code))
	{
		return 0;
	}

	for (std::uint64_t index = 0; index + 7 <= sizeof(code); index++)
	{
		const std::uint8_t rex = code[index];
		const std::uint8_t opcode = code[index + 1];
		const std::uint8_t modrm = code[index + 2];

		if (rex != 0x48 || opcode != 0x8D || (modrm != 0x0D && modrm != 0x05 && modrm != 0x15))
		{
			continue;
		}

		std::int32_t displacement = 0;
		std::memcpy(&displacement, code + index + 3, sizeof(displacement));

		return query_prcb->second + index + 7 + static_cast<std::int64_t>(displacement);
	}

	return 0;
}

static std::uint8_t read_live_context(live_context_t& context_out)
{
	constexpr std::uint64_t prcb_current_thread = 0x8;
	constexpr std::uint64_t thread_trap_frame = 0x90;
	constexpr std::uint64_t thread_process = 0x220;
	constexpr std::uint64_t eprocess_peb = 0x2e0;
	constexpr std::uint64_t trap_rip = 0x168;
	constexpr std::uint64_t trap_seg_cs = 0x170;
	const std::uint64_t processor_block = processor_block_address();

	if (processor_block == 0)
	{
		return 0;
	}

	for (std::uint64_t cpu = 0; cpu < 64; cpu++)
	{
		std::uint64_t prcb = 0;

		if (read_kernel_qword(processor_block + cpu * 8, prcb) == 0 || prcb == 0)
		{
			break;
		}

		std::uint64_t thread = 0;

		if (read_kernel_qword(prcb + prcb_current_thread, thread) == 0 || thread == 0)
		{
			continue;
		}

		std::uint64_t process = 0;
		std::uint64_t trap = 0;
		read_kernel_qword(thread + thread_process, process);
		read_kernel_qword(thread + thread_trap_frame, trap);

		std::uint64_t peb = 0;

		if (process != 0)
		{
			read_kernel_qword(process + eprocess_peb, peb);
		}

		if (context_out.user_cr3 == 0 && peb != 0)
		{
			context_out.user_cr3 = cr3_for_user_modules(process);
			std::uint64_t image_base = 0;

			if (context_out.user_cr3 != 0 &&
				hypercall::read_guest_virtual_memory(&image_base, peb + 0x10, context_out.user_cr3, sizeof(image_base)) ==
					sizeof(image_base))
			{
				context_out.image_base = image_base;
			}
		}

		if (context_out.rip != 0 || trap == 0)
		{
			continue;
		}

		std::uint64_t rip = 0;
		std::uint16_t cs = 0;
		read_kernel_qword(trap + trap_rip, rip);
		hypercall::read_guest_virtual_memory(&cs, trap + trap_seg_cs, sys::current_cr3, sizeof(cs));

		if (rip == 0)
		{
			continue;
		}

		context_out.rip = rip;
		context_out.rip_is_user = static_cast<std::uint8_t>(cs == 0x33 || rip <= 0x00007FFFFFFFFFFFull);
		context_out.rip_cr3 = context_out.rip_is_user == 1 ? cr3_for_user_modules(process) : sys::current_cr3;
	}

	return static_cast<std::uint8_t>(context_out.rip != 0 || context_out.user_cr3 != 0);
}

static std::uint8_t current_instruction(std::uint64_t& address_out, std::uint64_t& cr3_out)
{
	breakpoint::registers_t registers = {};

	if (breakpoint::paused_registers(registers) == 1 && registers.rip != 0)
	{
		address_out = registers.rip;
		cr3_out = registers.cr3 != 0 ? registers.cr3 : sys::current_cr3;

		return 1;
	}

	if (unassemble_next_address != 0 && unassemble_next_address > 0x00007FFFFFFFFFFFull)
	{
		address_out = unassemble_next_address;
		cr3_out = sys::current_cr3;

		return 1;
	}

	live_context_t live = {};

	if (read_live_context(live) == 0 || (live.rip == 0 && live.image_base == 0))
	{
		return 0;
	}

	address_out = live.rip != 0 ? live.rip : live.image_base;
	cr3_out = live.rip != 0 && live.rip_cr3 != 0 ? live.rip_cr3 : live.user_cr3;
	if (cr3_out == 0)
	{
		cr3_out = sys::current_cr3;
	}
	fmt::print("Current instruction {:08x}`{:08x}\n", static_cast<std::uint32_t>(address_out >> 32),
	           static_cast<std::uint32_t>(address_out));

	return 1;
}

static std::uint64_t user_cr3_for_pid(const std::uint64_t process_id)
{
	constexpr std::uint64_t directory_table_base = 0x28;
	constexpr std::uint64_t user_directory_table_base = 0x158;
	constexpr std::uint64_t unique_process_id = 0x1d0;
	constexpr std::uint64_t active_process_links = 0x1d8;
	const std::unordered_map<std::string, std::uint64_t> aliases = sys::kernel::compile_symbol_list();
	const auto system_process = aliases.find("ntoskrnl.exe!PsInitialSystemProcess");

	if (process_id == 0 || system_process == aliases.end() || sys::current_cr3 == 0)
	{
		return 0;
	}

	std::uint64_t eprocess = 0;

	if (hypercall::read_guest_virtual_memory(&eprocess, system_process->second, sys::current_cr3, sizeof(eprocess)) !=
			sizeof(eprocess) || eprocess == 0)
	{
		return 0;
	}

	const std::uint64_t first = eprocess;

	for (std::uint64_t count = 0; count < 4096 && eprocess != 0; count++)
	{
		std::uint64_t pid = 0;

		if (hypercall::read_guest_virtual_memory(&pid, eprocess + unique_process_id, sys::current_cr3, sizeof(pid)) ==
				sizeof(pid) && pid == process_id)
		{
			std::uint64_t user_directory = 0;
			std::uint64_t directory = 0;
			hypercall::read_guest_virtual_memory(&user_directory, eprocess + user_directory_table_base, sys::current_cr3,
			                                     sizeof(user_directory));
			hypercall::read_guest_virtual_memory(&directory, eprocess + directory_table_base, sys::current_cr3, sizeof(directory));

			return user_directory != 0 ? user_directory : directory;
		}

		std::uint64_t flink = 0;

		if (hypercall::read_guest_virtual_memory(&flink, eprocess + active_process_links, sys::current_cr3, sizeof(flink)) !=
				sizeof(flink) || flink == 0)
		{
			break;
		}

		eprocess = flink - active_process_links;

		if (eprocess == first)
		{
			break;
		}
	}

	return 0;
}

struct guest_process_t
{
	std::uint64_t eprocess = 0;
	std::uint64_t pid = 0;
	std::uint64_t parent_pid = 0;
	std::uint64_t peb = 0;
	std::uint64_t directory = 0;
	std::uint64_t user_cr3 = 0;
	std::string image = {};
};

struct implicit_process_t
{
	std::uint8_t set = 0;
	std::uint8_t suspended = 0;
	guest_process_t process = {};
};

static implicit_process_t implicit_process = {};

static std::uint8_t read_guest_process(const std::uint64_t eprocess, guest_process_t& process_out)
{
	constexpr std::uint64_t directory_table_base = 0x28;
	constexpr std::uint64_t user_directory_table_base = 0x158;
	constexpr std::uint64_t unique_process_id = 0x1d0;
	constexpr std::uint64_t inherited_from = 0x2d0;
	constexpr std::uint64_t peb_offset = 0x2e0;
	constexpr std::uint64_t image_file_name = 0x338;

	if (eprocess == 0 || sys::current_cr3 == 0)
	{
		return 0;
	}

	process_out = {};
	process_out.eprocess = eprocess;
	hypercall::read_guest_virtual_memory(&process_out.pid, eprocess + unique_process_id, sys::current_cr3, sizeof(process_out.pid));
	hypercall::read_guest_virtual_memory(&process_out.parent_pid, eprocess + inherited_from, sys::current_cr3,
	                                     sizeof(process_out.parent_pid));
	hypercall::read_guest_virtual_memory(&process_out.peb, eprocess + peb_offset, sys::current_cr3, sizeof(process_out.peb));
	hypercall::read_guest_virtual_memory(&process_out.directory, eprocess + directory_table_base, sys::current_cr3,
	                                     sizeof(process_out.directory));
	hypercall::read_guest_virtual_memory(&process_out.user_cr3, eprocess + user_directory_table_base, sys::current_cr3,
	                                     sizeof(process_out.user_cr3));

	if (process_out.user_cr3 == 0)
	{
		process_out.user_cr3 = process_out.directory;
	}

	char image[16] = {};

	if (hypercall::read_guest_virtual_memory(image, eprocess + image_file_name, sys::current_cr3, 15) == 15)
	{
		image[15] = '\0';
		process_out.image = image;
	}

	return static_cast<std::uint8_t>(process_out.pid != 0 || process_out.image.empty() == false);
}

static std::vector<guest_process_t> list_guest_processes()
{
	constexpr std::uint64_t active_process_links = 0x1d8;
	std::vector<guest_process_t> processes = {};
	const std::unordered_map<std::string, std::uint64_t> aliases = sys::kernel::compile_symbol_list();
	const auto system_process = aliases.find("ntoskrnl.exe!PsInitialSystemProcess");

	if (system_process == aliases.end() || sys::current_cr3 == 0)
	{
		return processes;
	}

	std::uint64_t eprocess = 0;

	if (hypercall::read_guest_virtual_memory(&eprocess, system_process->second, sys::current_cr3, sizeof(eprocess)) !=
			sizeof(eprocess) || eprocess == 0)
	{
		return processes;
	}

	const std::uint64_t first = eprocess;

	for (std::uint64_t count = 0; count < 4096 && eprocess != 0; count++)
	{
		guest_process_t process = {};

		if (read_guest_process(eprocess, process) == 1)
		{
			processes.push_back(std::move(process));
		}

		std::uint64_t flink = 0;

		if (hypercall::read_guest_virtual_memory(&flink, eprocess + active_process_links, sys::current_cr3, sizeof(flink)) !=
				sizeof(flink) || flink == 0)
		{
			break;
		}

		eprocess = flink - active_process_links;

		if (eprocess == first)
		{
			break;
		}
	}

	return processes;
}

static std::uint8_t find_guest_process(const std::uint64_t selector, const std::uint8_t selector_is_pid, guest_process_t& process_out)
{
	for (const guest_process_t& process : list_guest_processes())
	{
		if ((selector_is_pid == 1 && process.pid == selector) || (selector_is_pid == 0 && process.eprocess == selector))
		{
			process_out = process;

			return 1;
		}
	}

	return 0;
}

static std::uint8_t process_is_critical(const guest_process_t& process)
{
	if (process.pid == 0 || process.pid == 4 || process.pid == GetCurrentProcessId())
	{
		return 1;
	}

	return static_cast<std::uint8_t>(equals_ignore_case(process.image, "System") == 1 ||
		equals_ignore_case(process.image, "smss.exe") == 1 || equals_ignore_case(process.image, "csrss.exe") == 1);
}

static LONG process_suspend_call(const std::uint64_t pid, const std::uint8_t resume)
{
	const char* const export_name = resume == 1 ? "NtResumeProcess" : "NtSuspendProcess";
	const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");

	if (ntdll == nullptr)
	{
		return static_cast<LONG>(0xC0000135);
	}

	const auto function = reinterpret_cast<LONG(NTAPI*)(HANDLE)>(GetProcAddress(ntdll, export_name));

	if (function == nullptr)
	{
		return static_cast<LONG>(0xC0000002);
	}

	const HANDLE process = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, static_cast<DWORD>(pid));

	if (process == nullptr)
	{
		return static_cast<LONG>(0xC0000022);
	}

	const LONG status = function(process);
	CloseHandle(process);

	return status;
}

static std::uint8_t process_has_suspend_count(const std::uint64_t eprocess)
{
	constexpr std::uint64_t thread_list_head = 0x370;
	constexpr std::uint64_t thread_list_entry = 0x578;
	constexpr std::uint64_t suspend_count = 0x284;
	const std::uint64_t head = eprocess + thread_list_head;
	std::uint64_t link = 0;

	if (eprocess == 0 || read_kernel_memory(head, &link, sizeof(link)) == 0 || link == 0)
	{
		return 0;
	}

	for (std::uint64_t count = 0; count < 4096 && link != head; count++)
	{
		std::uint8_t suspended = 0;

		if (read_kernel_memory(link - thread_list_entry + suspend_count, &suspended, sizeof(suspended)) == 1 && suspended != 0)
		{
			return 1;
		}

		if (read_kernel_memory(link, &link, sizeof(link)) == 0 || link == 0)
		{
			break;
		}
	}

	return 0;
}

static std::uint8_t resume_suspended_process()
{
	if (implicit_process.suspended == 0)
	{
		return 0;
	}

	std::uint8_t resumed = 0;

	for (std::uint32_t attempt = 0; attempt < 32; attempt++)
	{
		if (attempt != 0 && process_has_suspend_count(implicit_process.process.eprocess) == 0)
		{
			break;
		}

		const LONG status = process_suspend_call(implicit_process.process.pid, 1);

		if (status < 0)
		{
			LOG_ERR("resume process {} failed: {:08x}", implicit_process.process.pid, static_cast<std::uint32_t>(status));

			return 1;
		}

		resumed = 1;
	}

	implicit_process.suspended = 0;

	if (resumed == 1)
	{
		fmt::print("resumed process {} cid {:x}\n", implicit_process.process.image, implicit_process.process.pid);
		std::fflush(stdout);
	}

	return 1;
}

static void release_suspended_process_for_pause(const std::uint64_t cr3)
{
	(void)cr3;

	if (implicit_process.suspended == 0)
	{
		return;
	}

	resume_suspended_process();
}

static std::uint64_t kernel_context_cr3();

static std::uint64_t current_user_cr3()
{
	if (implicit_process.set == 1 && implicit_process.process.user_cr3 != 0)
	{
		return implicit_process.process.user_cr3;
	}

	breakpoint::registers_t registers = {};

	if (breakpoint::paused_registers(registers) == 1 && registers.cr3 != 0 && registers.rip <= 0x00007FFFFFFFFFFFull)
	{
		return registers.cr3;
	}

	return user_cr3_for_pid(GetCurrentProcessId());
}

static std::uint64_t cr3_for_guest_address(const std::uint64_t address)
{
	if (address <= 0x00007FFFFFFFFFFFull)
	{
		const std::uint64_t user_cr3 = current_user_cr3();

		if (user_cr3 != 0)
		{
			return user_cr3;
		}
	}

	const std::uint64_t context_cr3 = kernel_context_cr3();

	if (context_cr3 != 0)
	{
		return context_cr3;
	}

	breakpoint::registers_t paused = {};

	if (breakpoint::paused_registers(paused) == 1 && paused.rip > 0x00007FFFFFFFFFFFull && paused.cr3 != 0)
	{
		return paused.cr3;
	}

	return sys::current_cr3;
}

static std::uint8_t module_contains(const reload_module_t& module, const std::uint64_t address)
{
	return static_cast<std::uint8_t>(module.base != 0 && address >= module.base &&
		address < module.base + module.size);
}

static void process_sympath(const CLI::App* const command)
{
	(void)command;
	const std::string path = symbol_command_text(".sympath");

	if (path.empty() == true)
	{
		const std::string current = symbol_parser::search_path();

		if (current.empty() == true)
		{
			fmt::print("Symbol search path is empty. Use .sympath or .symfix\n");
		}
		else
		{
			fmt::print("Symbol search path is: {}\n", current);
		}

		return;
	}

	symbol_parser::set_search_path(path);
	fmt::print("Symbol search path is: {}\n", symbol_parser::search_path());
	fmt::print("Use .reload /f <module> to load pdb files\n");
}

static void process_sympath_add(const CLI::App* const command)
{
	(void)command;
	const std::string path = symbol_command_text(".sympath+");

	if (path.empty() == true)
	{
		LOG_ERR("syntax: .sympath+ <path>");

		return;
	}

	symbol_parser::append_search_path(path);
	fmt::print("Symbol search path is: {}\n", symbol_parser::search_path());
}

static void process_symfix(const CLI::App* const command)
{
	(void)command;
	symbol_parser::use_microsoft_server(symbol_command_text(".symfix"), 0);
	fmt::print("Symbol search path is: {}\n", symbol_parser::search_path());
	fmt::print("Use .reload /f <module> to load pdb files\n");
}

static void process_symfix_add(const CLI::App* const command)
{
	(void)command;
	symbol_parser::use_microsoft_server(symbol_command_text(".symfix+"), 1);
	fmt::print("Symbol search path is: {}\n", symbol_parser::search_path());
}

static void process_reload(const CLI::App* const command)
{
	(void)command;
	const std::string text = symbol_command_text(".reload");
	std::uint8_t force = 0;
	std::uint8_t user = 0;
	std::uint8_t unload = 0;
	std::uint8_t overwrite = 0;
	std::uint8_t current_module = 0;
	std::string filter = {};
	std::string_view remaining = text;

	while (remaining.empty() == false)
	{
		remaining = skip_whitespace(remaining);
		if (remaining.empty() == true)
		{
			break;
		}

		const std::size_t end = remaining.find_first_of(" \t");
		const std::string_view token = remaining.substr(0, end);

		if (equals_ignore_case(token, "/f") == 1)
		{
			force = 1;
		}
		else if (equals_ignore_case(token, "/user") == 1)
		{
			user = 1;
		}
		else if (equals_ignore_case(token, "/u") == 1 || equals_ignore_case(token, "/unl") == 1)
		{
			unload = 1;
		}
		else if (equals_ignore_case(token, "/o") == 1)
		{
			overwrite = 1;
			force = 1;
		}
		else if (equals_ignore_case(token, "/i") == 1)
		{
		}
		else if (token.empty() == false && token[0] == '/')
		{
			LOG_ERR("unsupported .reload option");

			return;
		}
		else if (token == ".")
		{
			current_module = 1;
		}
		else
		{
			filter = std::string(token);
		}

		if (end == std::string_view::npos)
		{
			break;
		}

		remaining.remove_prefix(end);
	}

	std::vector<reload_module_t> modules = {};
	std::uint8_t kernel_symbols = 0;

	if (current_module == 1 && user == 0)
	{
		kernel_symbols = 1;
		append_kernel_modules(modules, {});
	}
	else if (current_module == 1)
	{
		std::uint64_t address = 0;
		std::uint64_t cr3 = 0;

		if (current_instruction(address, cr3) == 0)
		{
			LOG_ERR("no current instruction");

			return;
		}

		const std::uint8_t address_is_user = static_cast<std::uint8_t>(address <= 0x00007FFFFFFFFFFFull);

		if (address_is_user == 1)
		{
			if (collect_user_modules(cr3, modules) == 0)
			{
				LOG_ERR("failed to read the current user module list");

				return;
			}
		}
		else
		{
			append_kernel_modules(modules, {});
		}

		std::vector<reload_module_t> matched = {};

		for (const reload_module_t& module : modules)
		{
			if (module_contains(module, address) == 1)
			{
				matched.push_back(module);
			}
		}

		modules = std::move(matched);
	}
	else if (user == 1)
	{
		const std::uint64_t user_cr3 = current_user_cr3();

		if (user_cr3 == 0)
		{
			LOG_ERR("no current user process");

			return;
		}

		if (collect_user_modules(user_cr3, modules) == 0)
		{
			LOG_ERR("failed to read the current user module list");

			return;
		}

		if (filter.empty() == false)
		{
			std::vector<reload_module_t> matched = {};

			for (const reload_module_t& module : modules)
			{
				if (kernel_module_selected(module.name, filter) == 1)
				{
					matched.push_back(module);
				}
			}

			modules = std::move(matched);
		}
	}
	else
	{
		append_kernel_modules(modules, filter);

		if (filter.empty() == true)
		{
			kernel_symbols = 1;
		}
	}

	if (modules.empty() == true)
	{
		LOG_ERR("no matching module");

		return;
	}

	if (force == 0 && unload == 0)
	{
		for (const reload_module_t& module : modules)
		{
			std::string pdb_name = {};
			std::uint64_t displacement = 0;
			const std::uint8_t has_pdb = symbol_parser::nearest(module.base, pdb_name, displacement);
			fmt::print("{:08x}`{:08x} {:08x} {} {}\n", static_cast<std::uint32_t>(module.base >> 32),
			           static_cast<std::uint32_t>(module.base), module.size, module.name, has_pdb == 1 ? "symbols" : "deferred");
		}

		return;
	}

	if (unload == 1 && force == 0)
	{
		for (const reload_module_t& module : modules)
		{
			symbol_parser::unload_module(module.base);
			fmt::print("Unloaded symbols for {}\n", module.name);
		}

		return;
	}

	if (kernel_symbols == 1)
	{
		fmt::print("Loading Kernel Symbols\n");
		std::fflush(stdout);
	}

	std::uint64_t loaded = 0;
	std::uint8_t stopped = 0;

	for (const reload_module_t& module : modules)
	{
		if (console_interrupt_requested() == 1)
		{
			stopped = 1;

			break;
		}

		loaded += load_image_symbols(module, force, overwrite);

		if (console_interrupt_requested() == 1)
		{
			stopped = 1;

			break;
		}
	}

	if (stopped == 1)
	{
		console_interrupt_clear();
		fmt::print("interrupted\n");

		return;
	}

	if (loaded == 0)
	{
		LOG_ERR("no symbols loaded");

		return;
	}

	if (kernel_symbols == 1)
	{
		fmt::print("Loaded symbols for {} module(s)\n", loaded);
	}
}

static std::string module_display_name(const std::string& module_name)
{
	if (is_ntoskrnl_module(module_name) == 1)
	{
		return "nt";
	}

	return module_stem(module_name);
}

static std::uint8_t wildcard_match(const std::string_view text, const std::string_view pattern)
{
	std::size_t text_index = 0;
	std::size_t pattern_index = 0;
	std::size_t star = std::string_view::npos;
	std::size_t matched = 0;

	while (text_index < text.size())
	{
		if (pattern_index < pattern.size() &&
			(pattern[pattern_index] == '?' ||
				std::tolower(static_cast<unsigned char>(pattern[pattern_index])) ==
					std::tolower(static_cast<unsigned char>(text[text_index]))))
		{
			text_index += 1;
			pattern_index += 1;

			continue;
		}

		if (pattern_index < pattern.size() && pattern[pattern_index] == '*')
		{
			star = pattern_index;
			pattern_index += 1;
			matched = text_index;

			continue;
		}

		if (star != std::string_view::npos)
		{
			pattern_index = star + 1;
			matched += 1;
			text_index = matched;

			continue;
		}

		return 0;
	}

	while (pattern_index < pattern.size() && pattern[pattern_index] == '*')
	{
		pattern_index += 1;
	}

	return static_cast<std::uint8_t>(pattern_index == pattern.size());
}

static std::uint8_t module_pattern_matches(const std::string& module_name, const std::string_view pattern)
{
	if (pattern.empty() == true || pattern == "*")
	{
		return 1;
	}

	const std::string display = module_display_name(module_name);
	const std::string stem = module_stem(module_name);
	const std::uint8_t wildcard = static_cast<std::uint8_t>(pattern.find_first_of("*?") != std::string_view::npos);

	if (wildcard == 0)
	{
		return static_cast<std::uint8_t>(equals_ignore_case(display, pattern) == 1 || equals_ignore_case(stem, pattern) == 1 ||
			equals_ignore_case(module_name, pattern) == 1);
	}

	return static_cast<std::uint8_t>(wildcard_match(display, pattern) == 1 || wildcard_match(stem, pattern) == 1 ||
		wildcard_match(module_name, pattern) == 1);
}

struct image_facts_t
{
	std::uint16_t machine = 0;
	std::uint32_t timestamp = 0;
	std::uint32_t checksum = 0;
	std::uint32_t size_of_image = 0;
	std::uint8_t valid = 0;
};

static std::uint8_t read_image_facts(const std::uint64_t base, const std::uint64_t cr3, image_facts_t& facts_out)
{
	facts_out = {};
	std::uint8_t dos[0x40] = {};

	if (cr3 == 0 || hypercall::read_guest_virtual_memory(dos, base, cr3, sizeof(dos)) != sizeof(dos) || dos[0] != 'M' || dos[1] != 'Z')
	{
		return 0;
	}

	std::uint32_t lfanew = 0;
	std::memcpy(&lfanew, dos + 0x3c, sizeof(lfanew));

	if (lfanew < sizeof(dos) || lfanew > 0x1000)
	{
		return 0;
	}

	std::uint8_t pe[0x200] = {};

	if (hypercall::read_guest_virtual_memory(pe, base + lfanew, cr3, sizeof(pe)) != sizeof(pe) || pe[0] != 'P' || pe[1] != 'E' ||
		pe[2] != 0 || pe[3] != 0)
	{
		return 0;
	}

	std::memcpy(&facts_out.machine, pe + 4, sizeof(facts_out.machine));
	std::memcpy(&facts_out.timestamp, pe + 8, sizeof(facts_out.timestamp));
	std::uint16_t magic = 0;
	std::memcpy(&magic, pe + 24, sizeof(magic));

	if (magic != 0x20b && magic != 0x10b)
	{
		return 0;
	}

	std::memcpy(&facts_out.size_of_image, pe + 24 + 56, sizeof(facts_out.size_of_image));
	std::memcpy(&facts_out.checksum, pe + 24 + 64, sizeof(facts_out.checksum));
	facts_out.valid = 1;

	return 1;
}

static std::string machine_name(const std::uint16_t machine)
{
	if (machine == 0x8664)
	{
		return "x64";
	}

	if (machine == 0x14c)
	{
		return "x86";
	}

	if (machine == 0xAA64)
	{
		return "arm64";
	}

	return "unknown";
}

static const symbol_parser::module_status_t* loaded_symbol_status(const std::vector<symbol_parser::module_status_t>& loaded,
                                                                  const reload_module_t& module)
{
	for (const symbol_parser::module_status_t& status : loaded)
	{
		if (status.base == module.base || equals_ignore_case(status.name, module.name) == 1)
		{
			return &status;
		}
	}

	return nullptr;
}

struct lm_options_t
{
	std::uint8_t kernel = 0;
	std::uint8_t user = 0;
	std::uint8_t verbose = 0;
	std::uint8_t loaded_only = 0;
	std::uint8_t has_address = 0;
	std::uint64_t address = 0;
	std::string pattern = {};
};

static std::uint8_t lm_flag_character(const char character)
{
	const char lower = static_cast<char>(std::tolower(static_cast<unsigned char>(character)));

	return static_cast<std::uint8_t>(lower == 'k' || lower == 'u' || lower == 'v' || lower == 'l' || lower == 'm' || lower == 'a');
}

static std::uint8_t parse_lm_options(const std::vector<std::string>& args, lm_options_t& options_out)
{
	options_out = {};
	std::uint8_t expect_pattern = 0;
	std::uint8_t expect_address = 0;
	const std::unordered_map<std::string, std::uint64_t> aliases = sys::kernel::compile_symbol_list();

	for (const std::string& token : args)
	{
		if (expect_pattern == 1)
		{
			options_out.pattern = token;
			expect_pattern = 0;

			continue;
		}

		if (expect_address == 1)
		{
			if (resolve_windbg_address(aliases, token, options_out.address) == 0)
			{
				LOG_ERR("invalid address: {}", token);

				return 0;
			}

			options_out.has_address = 1;
			expect_address = 0;

			continue;
		}

		std::uint8_t flags_only = static_cast<std::uint8_t>(token.empty() == false);

		for (const char character : token)
		{
			if (lm_flag_character(character) == 0)
			{
				flags_only = 0;

				break;
			}
		}

		if (flags_only == 0)
		{
			LOG_ERR("unsupported lm option: {}", token);

			return 0;
		}

		for (const char character : token)
		{
			const char lower = static_cast<char>(std::tolower(static_cast<unsigned char>(character)));

			if (lower == 'k')
			{
				options_out.kernel = 1;
			}
			else if (lower == 'u')
			{
				options_out.user = 1;
			}
			else if (lower == 'v')
			{
				options_out.verbose = 1;
			}
			else if (lower == 'l')
			{
				options_out.loaded_only = 1;
			}
			else if (lower == 'm')
			{
				expect_pattern = 1;
			}
			else if (lower == 'a')
			{
				expect_address = 1;
			}
		}
	}

	if (expect_pattern == 1)
	{
		LOG_ERR("syntax: lm m <pattern>");

		return 0;
	}

	if (expect_address == 1)
	{
		LOG_ERR("syntax: lm a <address>");

		return 0;
	}

	if (options_out.kernel == 0 && options_out.user == 0)
	{
		options_out.kernel = 1;
	}

	return 1;
}

static std::uint8_t lm_module_visible(const reload_module_t& module, const lm_options_t& options,
                                      const std::vector<symbol_parser::module_status_t>& loaded)
{
	if (module.base == 0 || module.size == 0)
	{
		return 0;
	}

	if (module_pattern_matches(module.name, options.pattern) == 0)
	{
		return 0;
	}

	if (options.has_address == 1 && module_contains(module, options.address) == 0)
	{
		return 0;
	}

	if (options.loaded_only == 1 && loaded_symbol_status(loaded, module) == nullptr)
	{
		return 0;
	}

	return 1;
}

static void print_lm_modules(const std::vector<reload_module_t>& modules, const lm_options_t& options,
                             const std::vector<symbol_parser::module_status_t>& loaded, std::uint64_t& shown_out)
{
	for (const reload_module_t& module : modules)
	{
		if (lm_module_visible(module, options, loaded) == 0)
		{
			continue;
		}

		const std::uint64_t end = module.base + module.size < module.base ? module.base : module.base + module.size;
		const symbol_parser::module_status_t* const status = loaded_symbol_status(loaded, module);
		fmt::print("{} {}   {:<14} {}", format_windbg_address(module.base), format_windbg_address(end),
		           module_display_name(module.name), status == nullptr ? "(deferred)" : "(pdb symbols)");

		if (status != nullptr && status->pdb_path.empty() == false)
		{
			fmt::print("          {}", status->pdb_path);
		}

		fmt::print("\n");
		shown_out += 1;

		if (options.verbose == 0)
		{
			continue;
		}

		fmt::print("    Image name: {}\n", module.name);
		fmt::print("    Image size: {:08x}\n", module.size);
		image_facts_t facts = {};

		if (read_image_facts(module.base, module.cr3, facts) == 1)
		{
			fmt::print("    Machine: {} ({:x})\n", machine_name(facts.machine), facts.machine);
			fmt::print("    Timestamp: {:08x}\n", facts.timestamp);
			fmt::print("    CheckSum: {:08x}\n", facts.checksum);
		}

		if (status != nullptr && status->pdb_path.empty() == false)
		{
			fmt::print("    Symbol file: {}\n", status->pdb_path);
		}
	}
}

static void process_lm(const CLI::App* const command)
{
	lm_options_t options = {};

	if (parse_lm_options(command->remaining(), options) == 0)
	{
		return;
	}

	const std::vector<symbol_parser::module_status_t> loaded = symbol_parser::loaded_modules();
	std::vector<reload_module_t> kernel_modules = {};
	std::vector<reload_module_t> user_modules = {};

	if (options.kernel == 1)
	{
		append_kernel_modules(kernel_modules, {});
	}

	if (options.user == 1)
	{
		const std::uint64_t user_cr3 = current_user_cr3();

		if (user_cr3 == 0)
		{
			LOG_ERR("no current user process");

			if (options.kernel == 0)
			{
				return;
			}
		}
		else if (collect_user_modules(user_cr3, user_modules) == 0 && options.kernel == 0)
		{
			LOG_ERR("failed to read the current user module list");

			return;
		}
	}

	fmt::print("start             end                 module name\n");
	std::uint64_t shown = 0;
	print_lm_modules(kernel_modules, options, loaded, shown);
	const std::uint64_t kernel_shown = shown;

	if (kernel_shown != 0 && user_modules.empty() == false)
	{
		fmt::print("\n");
	}

	print_lm_modules(user_modules, options, loaded, shown);

	if (shown == 0 && options.loaded_only == 1)
	{
		fmt::print("no module has symbols loaded\n");
	}
	else if (shown == 0)
	{
		fmt::print("no matching module\n");
	}
}

static std::uint8_t collect_named_modules(const std::string_view pattern, const std::uint8_t user_only,
                                          std::vector<reload_module_t>& modules_out, std::uint8_t& user_out)
{
	modules_out.clear();
	user_out = 0;

	if (user_only == 0)
	{
		std::vector<reload_module_t> kernel_modules = {};
		append_kernel_modules(kernel_modules, {});

		for (const reload_module_t& module : kernel_modules)
		{
			if (module_pattern_matches(module.name, pattern) == 1)
			{
				modules_out.push_back(module);
			}
		}

		if (modules_out.empty() == false)
		{
			return 1;
		}
	}

	const std::uint64_t user_cr3 = current_user_cr3();

	if (user_cr3 == 0)
	{
		if (user_only == 1)
		{
			LOG_ERR("no current user process");
		}
		else
		{
			LOG_ERR("no matching module");
		}

		return 0;
	}

	std::vector<reload_module_t> user_modules = {};

	if (collect_user_modules(user_cr3, user_modules) == 0)
	{
		LOG_ERR("failed to read the current user module list");

		return 0;
	}

	for (const reload_module_t& module : user_modules)
	{
		if (module_pattern_matches(module.name, pattern) == 1)
		{
			modules_out.push_back(module);
		}
	}

	if (modules_out.empty() == true)
	{
		LOG_ERR("no matching module");

		return 0;
	}

	user_out = 1;

	return 1;
}

static void force_load_listed_modules(const std::vector<reload_module_t>& modules, const std::uint8_t user_modules)
{
	if (modules.size() > 1)
	{
		if (user_modules == 1)
		{
			fmt::print("Loading User Symbols\n");
		}
		else
		{
			fmt::print("Loading Kernel Symbols\n");
		}

		std::fflush(stdout);
	}

	std::uint64_t loaded = 0;
	std::uint8_t stopped = 0;

	for (const reload_module_t& module : modules)
	{
		if (console_interrupt_requested() == 1)
		{
			stopped = 1;

			break;
		}

		loaded += load_image_symbols(module, 1, 0);

		if (console_interrupt_requested() == 1)
		{
			stopped = 1;

			break;
		}
	}

	if (stopped == 1)
	{
		console_interrupt_clear();
		fmt::print("interrupted\n");

		return;
	}

	if (loaded == 0)
	{
		LOG_ERR("no symbols loaded");

		return;
	}

	if (modules.size() > 1)
	{
		fmt::print("Loaded symbols for {} module(s)\n", loaded);
	}
}

static void print_guest_process(const guest_process_t& process)
{
	fmt::print("PROCESS {:08x}`{:08x}\n", static_cast<std::uint32_t>(process.eprocess >> 32),
	           static_cast<std::uint32_t>(process.eprocess));
	fmt::print("    Cid: {:x}    Peb: {:08x}`{:08x}  ParentCid: {:x}\n", process.pid,
	           static_cast<std::uint32_t>(process.peb >> 32), static_cast<std::uint32_t>(process.peb), process.parent_pid);
	fmt::print("    DirBase: {:08x}`{:08x}\n", static_cast<std::uint32_t>(process.directory >> 32),
	           static_cast<std::uint32_t>(process.directory));
	fmt::print("    Image: {}\n", process.image.empty() == true ? "?" : process.image);
}

static std::uint8_t effective_process(guest_process_t& process_out)
{
	if (implicit_process.set == 1)
	{
		process_out = implicit_process.process;

		return 1;
	}

	const std::uint64_t self = GetCurrentProcessId();

	return find_guest_process(self, 1, process_out);
}

static std::uint8_t read_kernel_memory(const std::uint64_t address, void* const buffer, const std::uint64_t size)
{
	if (address == 0 || buffer == nullptr || size == 0 || sys::current_cr3 == 0)
	{
		return 0;
	}

	return static_cast<std::uint8_t>(hypercall::read_guest_virtual_memory(buffer, address, sys::current_cr3, size) == size);
}

static std::uint8_t write_kernel_memory(const std::uint64_t address, const void* const buffer, const std::uint64_t size)
{
	if (address == 0 || buffer == nullptr || size == 0 || sys::current_cr3 == 0)
	{
		return 0;
	}

	return static_cast<std::uint8_t>(hypercall::write_guest_virtual_memory(buffer, address, sys::current_cr3, size) == size);
}

static std::uint64_t ntdll_cave_hint(const std::uint64_t user_cr3)
{
	const std::uint64_t local_ntdll = reinterpret_cast<std::uint64_t>(GetModuleHandleW(L"ntdll.dll"));

	if (local_ntdll == 0 || user_cr3 == 0)
	{
		return 0;
	}

	std::vector<reload_module_t> modules = {};

	if (collect_user_modules(user_cr3, modules) == 0)
	{
		return 0;
	}

	for (const reload_module_t& module : modules)
	{
		if (equals_ignore_case(module.name, "ntdll.dll") == 1)
		{
			return module.base == local_ntdll ? local_ntdll : 0;
		}
	}

	return 0;
}

struct user_thread_t
{
	std::uint64_t ethread = 0;
	std::uint64_t trap = 0;
	std::uint64_t rip = 0;
	std::uint64_t tid = 0;
};

static void collect_user_threads(const std::uint64_t eprocess, std::vector<user_thread_t>& threads_out)
{
	constexpr std::uint64_t thread_list_head = 0x370;
	constexpr std::uint64_t thread_list_entry = 0x578;
	constexpr std::uint64_t ethread_cid = 0x508;
	constexpr std::uint64_t trap_frame = 0x90;
	constexpr std::uint64_t trap_rip = 0x168;
	constexpr std::uint64_t trap_seg_cs = 0x170;
	const std::uint64_t head = eprocess + thread_list_head;
	std::uint64_t link = 0;

	threads_out.clear();

	if (read_kernel_memory(head, &link, sizeof(link)) == 0 || link == 0)
	{
		return;
	}

	for (std::uint64_t count = 0; count < 4096 && link != head && threads_out.size() < 32; count++)
	{
		const std::uint64_t ethread = link - thread_list_entry;
		std::uint64_t trap = 0;

		if (read_kernel_memory(ethread + trap_frame, &trap, sizeof(trap)) == 1 && trap != 0)
		{
			std::uint64_t rip = 0;
			std::uint16_t seg_cs = 0;

			if (read_kernel_memory(trap + trap_rip, &rip, sizeof(rip)) == 1 &&
				read_kernel_memory(trap + trap_seg_cs, &seg_cs, sizeof(seg_cs)) == 1 && (seg_cs & 0xFF) == 0x33 && rip != 0 &&
				rip <= 0x00007FFFFFFFFFFFull)
			{
				std::uint64_t tid = 0;

				if (read_kernel_memory(ethread + ethread_cid + sizeof(std::uint64_t), &tid, sizeof(tid)) == 1 && tid != 0 &&
					tid <= 0xFFFFFFFFull)
				{
					threads_out.push_back({ethread, trap, rip, tid});
				}
			}
		}

		if (read_kernel_memory(link, &link, sizeof(link)) == 0 || link == 0)
		{
			break;
		}
	}
}

static void collect_kernel_threads(const std::uint64_t eprocess, std::vector<user_thread_t>& threads_out)
{
	constexpr std::uint64_t thread_list_head = 0x370;
	constexpr std::uint64_t thread_list_entry = 0x578;
	constexpr std::uint64_t ethread_cid = 0x508;
	constexpr std::uint64_t trap_frame = 0x90;
	constexpr std::uint64_t thread_state = 0x184;
	constexpr std::uint64_t trap_rip = 0x168;
	constexpr std::uint64_t trap_seg_cs = 0x170;
	constexpr std::uint8_t running_state = 2;
	constexpr std::uint8_t terminated_state = 4;
	const std::uint64_t head = eprocess + thread_list_head;
	std::uint64_t link = 0;

	threads_out.clear();

	if (read_kernel_memory(head, &link, sizeof(link)) == 0 || link == 0)
	{
		return;
	}

	for (std::uint64_t count = 0; count < 4096 && link != head && threads_out.size() < 64; count++)
	{
		const std::uint64_t ethread = link - thread_list_entry;
		std::uint8_t state = 0;
		std::uint64_t trap = 0;

		if (read_kernel_memory(ethread + thread_state, &state, sizeof(state)) == 1 && state != running_state &&
			state != terminated_state && read_kernel_memory(ethread + trap_frame, &trap, sizeof(trap)) == 1 && trap != 0)
		{
			std::uint64_t rip = 0;
			std::uint16_t seg_cs = 0;

			if (read_kernel_memory(trap + trap_rip, &rip, sizeof(rip)) == 1 &&
				read_kernel_memory(trap + trap_seg_cs, &seg_cs, sizeof(seg_cs)) == 1 && (seg_cs & 0xFF) == 0x10 &&
				rip > 0x00007FFFFFFFFFFFull)
			{
				std::uint64_t tid = 0;

				if (read_kernel_memory(ethread + ethread_cid + sizeof(std::uint64_t), &tid, sizeof(tid)) == 1 && tid != 0 &&
					tid <= 0xFFFFFFFFull)
				{
					threads_out.push_back({ethread, trap, rip, tid});
				}
			}
		}

		if (read_kernel_memory(link, &link, sizeof(link)) == 0 || link == 0)
		{
			break;
		}
	}
}

static void collect_process_threads(const std::uint64_t eprocess, std::vector<user_thread_t>& threads_out)
{
	constexpr std::uint64_t thread_list_head = 0x370;
	constexpr std::uint64_t thread_list_entry = 0x578;
	constexpr std::uint64_t ethread_cid = 0x508;
	constexpr std::uint64_t trap_frame = 0x90;
	const std::uint64_t head = eprocess + thread_list_head;
	std::uint64_t link = 0;

	threads_out.clear();

	if (read_kernel_memory(head, &link, sizeof(link)) == 0 || link == 0)
	{
		return;
	}

	for (std::uint64_t count = 0; count < 4096 && link != head && threads_out.size() < 64; count++)
	{
		const std::uint64_t ethread = link - thread_list_entry;
		std::uint64_t trap = 0;
		std::uint64_t tid = 0;

		read_kernel_memory(ethread + trap_frame, &trap, sizeof(trap));

		if (read_kernel_memory(ethread + ethread_cid + sizeof(tid), &tid, sizeof(tid)) == 1 && tid != 0 && tid <= 0xFFFFFFFFull)
		{
			threads_out.push_back({ethread, trap, 0, tid});
		}

		if (read_kernel_memory(link, &link, sizeof(link)) == 0 || link == 0)
		{
			break;
		}
	}
}

static HANDLE open_user_thread(const std::uint64_t tid)
{
	return OpenThread(0x0004 | THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION,
	                  FALSE, static_cast<DWORD>(tid));
}

static std::uint8_t write_thread_rip(const HANDLE thread, const std::uint64_t trap, const std::uint64_t rip)
{
	std::uint8_t wrote = 0;

	if (thread != nullptr)
	{
		CONTEXT context = {};

		context.ContextFlags = CONTEXT_CONTROL;

		if (GetThreadContext(thread, &context) != FALSE)
		{
			context.ContextFlags = CONTEXT_CONTROL;
			context.Rip = rip;

			if (SetThreadContext(thread, &context) != FALSE)
			{
				wrote = 1;
			}
		}
	}

	constexpr std::uint64_t trap_rip = 0x168;

	if (trap != 0 && write_kernel_memory(trap + trap_rip, &rip, sizeof(rip)) == 1)
	{
		wrote = 1;
	}

	return wrote;
}

static void wake_user_thread(const HANDLE thread, const std::uint64_t tid)
{
	const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");

	if (ntdll == nullptr || thread == nullptr)
	{
		return;
	}

	const auto alert = reinterpret_cast<LONG(NTAPI*)(HANDLE)>(GetProcAddress(ntdll, "NtAlertThread"));

	if (alert != nullptr)
	{
		alert(thread);
	}

	const auto routine = reinterpret_cast<void*>(GetProcAddress(ntdll, "NtYieldExecution"));

	if (routine != nullptr)
	{
		const auto queue2 = reinterpret_cast<LONG(NTAPI*)(HANDLE, HANDLE, ULONG, void*, void*, void*, void*)>(
			GetProcAddress(ntdll, "NtQueueApcThreadEx2"));

		if (queue2 != nullptr)
		{
			queue2(thread, nullptr, 1, routine, nullptr, nullptr, nullptr);
		}
		else
		{
			const auto queue = reinterpret_cast<LONG(NTAPI*)(HANDLE, HANDLE, void*, void*, void*, void*)>(
				GetProcAddress(ntdll, "NtQueueApcThreadEx"));

			if (queue != nullptr)
			{
				queue(thread, reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(1)), routine, nullptr, nullptr, nullptr);
			}
		}
	}

	HMODULE user32 = GetModuleHandleW(L"user32.dll");

	if (user32 == nullptr)
	{
		user32 = LoadLibraryW(L"user32.dll");
	}

	if (user32 != nullptr)
	{
		const auto post = reinterpret_cast<BOOL(WINAPI*)(DWORD, UINT, WPARAM, LPARAM)>(GetProcAddress(user32, "PostThreadMessageW"));

		if (post != nullptr)
		{
			post(static_cast<DWORD>(tid), 0, 0, 0);
		}
	}
}

static std::uint8_t wait_for_direct_pause(const ULONGLONG deadline, const ULONGLONG slice_ms)
{
	const ULONGLONG slice_end = GetTickCount64() + slice_ms;

	while (GetTickCount64() < deadline && GetTickCount64() < slice_end)
	{
		if (breakpoint::poll_new_pause() == 1)
		{
			return 1;
		}

		fmt::print(".");
		std::fflush(stdout);
		Sleep(200);
	}

	return breakpoint::poll_new_pause();
}

static void undo_process_suspend()
{
	if (implicit_process.suspended == 0)
	{
		return;
	}

	const LONG status = process_suspend_call(implicit_process.process.pid, 1);

	if (status < 0)
	{
		LOG_ERR("resume process {} failed: {:08x}", implicit_process.process.pid, static_cast<std::uint32_t>(status));

		return;
	}

	implicit_process.suspended = 0;
}

static void report_process_break(const guest_process_t& process, const std::uint8_t reload)
{
	fmt::print("\nProcess suspended.\n");

	if (reload == 1)
	{
		std::vector<reload_module_t> modules = {};

		if (process.user_cr3 == 0 || collect_user_modules(process.user_cr3, modules) == 0)
		{
			LOG_ERR("failed to read the user module list");
		}
		else
		{
			force_load_listed_modules(modules, 1);
		}
	}

	announce_breakpoint_hit();
}

static std::uint8_t hijack_user_thread(const user_thread_t& user_thread, const std::uint64_t user_cr3, const std::uint64_t cave_hint,
                                       const ULONGLONG deadline)
{
	const HANDLE thread = open_user_thread(user_thread.tid);

	if (thread == nullptr)
	{
		return 0;
	}

	std::uint64_t entry = 0;
	std::uint64_t breakpoint_id = 0;

	if (breakpoint::arm_direct_pause(user_thread.rip, user_cr3, cave_hint, entry, breakpoint_id) == 0)
	{
		CloseHandle(thread);

		return 0;
	}

	fmt::print("\nthread {:x} ", user_thread.tid);
	std::fflush(stdout);

	if (write_thread_rip(thread, user_thread.trap, entry) == 0)
	{
		breakpoint::remove(breakpoint_id);
		CloseHandle(thread);

		return 0;
	}

	// A thread blocked in a system call still has a user trap frame. Resuming it continues that
	// wait. A special user APC, an alert, and a posted message give the wait a reason to return.
	wake_user_thread(thread, user_thread.tid);

	if (ResumeThread(thread) == static_cast<DWORD>(-1))
	{
		write_thread_rip(thread, user_thread.trap, user_thread.rip);
		breakpoint::remove(breakpoint_id);
		CloseHandle(thread);

		return 0;
	}

	if (wait_for_direct_pause(deadline, 2000) == 1 || breakpoint::poll_new_pause() == 1)
	{
		CloseHandle(thread);

		return 1;
	}

	SuspendThread(thread);

	if (breakpoint::poll_new_pause() == 1)
	{
		ResumeThread(thread);
		CloseHandle(thread);

		return 1;
	}

	write_thread_rip(thread, user_thread.trap, user_thread.rip);
	breakpoint::remove(breakpoint_id);
	CloseHandle(thread);

	return 0;
}

static std::uint8_t user_canonical(std::uint64_t value);
static std::uint8_t kernel_canonical(std::uint64_t value);
static std::uint8_t find_user_return_frame(std::uint64_t ethread, std::uint64_t trap_hint, std::uint64_t& trap_out,
                                           std::uint64_t& rip_out);

static std::uint8_t rip_in_kernel_image(const std::uint64_t rip)
{
	if (kernel_canonical(rip) == 0)
	{
		return 0;
	}

	for (const auto& [name, module] : sys::kernel::modules_list)
	{
		(void)name;

		if (module.base_address != 0 && rip >= module.base_address && rip < module.base_address + module.size)
		{
			return 1;
		}
	}

	return 0;
}

static std::uint8_t is_swap_context_resume(const std::uint64_t rip)
{
	// nt!KiSwapContext+0x76 on this Windows build: lea rcx, [rsp+100h].
	// Every waiting thread stores this as its switch-frame return. Diverting it
	// pauses the processor inside the context switch and freezes the machine.
	std::uint8_t bytes[8] = {};

	if (rip_in_kernel_image(rip) == 0 || read_kernel_memory(rip, bytes, sizeof(bytes)) == 0)
	{
		return 0;
	}

	constexpr std::uint8_t swap_resume[] = {0x48, 0x8D, 0x8C, 0x24, 0x00, 0x01, 0x00, 0x00};

	return static_cast<std::uint8_t>(std::memcmp(bytes, swap_resume, sizeof(swap_resume)) == 0);
}

static std::uint8_t trap_is_user_return(const std::uint64_t trap, std::uint64_t& rip_out)
{
	std::uint16_t cs = 0;
	std::uint64_t rip = 0;

	rip_out = 0;

	if (trap == 0 || read_kernel_memory(trap + 0x168, &rip, sizeof(rip)) == 0 || read_kernel_memory(trap + 0x170, &cs, sizeof(cs)) == 0)
	{
		return 0;
	}

	if ((cs & 0xFF) != 0x33 || user_canonical(rip) == 0 || is_swap_context_resume(rip) == 1)
	{
		return 0;
	}

	rip_out = rip;

	return 1;
}

static std::uint8_t release_process_freeze()
{
	if (implicit_process.suspended == 0)
	{
		return 1;
	}

	const LONG status = process_suspend_call(implicit_process.process.pid, 1);

	if (status < 0)
	{
		return 0;
	}

	implicit_process.suspended = 0;

	return 1;
}

static std::uint8_t freeze_process_again()
{
	if (implicit_process.suspended == 1)
	{
		return 1;
	}

	const LONG status = process_suspend_call(implicit_process.process.pid, 0);

	if (status < 0)
	{
		return 0;
	}

	implicit_process.suspended = 1;

	return 1;
}

static std::uint8_t resume_until_running(const HANDLE thread, std::uint32_t& resumes_out)
{
	resumes_out = 0;

	for (std::uint32_t attempt = 0; attempt < 8; attempt++)
	{
		const DWORD previous = ResumeThread(thread);

		if (previous == static_cast<DWORD>(-1))
		{
			return static_cast<std::uint8_t>(resumes_out != 0);
		}

		resumes_out++;

		if (previous <= 1)
		{
			return 1;
		}
	}

	return 1;
}

static void restore_suspend_count(const HANDLE thread, const std::uint32_t resumes)
{
	for (std::uint32_t count = 0; count < resumes; count++)
	{
		if (SuspendThread(thread) == static_cast<DWORD>(-1))
		{
			break;
		}
	}
}

static std::uint8_t wait_until_user_pause()
{
	while (console_interrupt_requested() == 0)
	{
		if (breakpoint::poll_new_pause() == 1)
		{
			return 1;
		}

		fmt::print(".");
		std::fflush(stdout);
		Sleep(200);
	}

	return breakpoint::poll_new_pause();
}

static std::uint8_t hook_next_and_run(const user_thread_t& thread, const guest_process_t& process, const std::uint64_t cave_hint)
{
	std::uint64_t rip = 0;
	std::uint64_t trap = 0;

	if (find_user_return_frame(thread.ethread, thread.trap, trap, rip) == 0)
	{
		return 0;
	}

	const HANDLE handle = open_user_thread(thread.tid);

	if (handle == nullptr)
	{
		return 0;
	}

	std::uint64_t entry = 0;
	std::uint64_t breakpoint_id = 0;

	if (breakpoint::arm_direct_pause(rip, process.user_cr3, cave_hint, entry, breakpoint_id) == 0)
	{
		CloseHandle(handle);

		return 0;
	}

	fmt::print("\nthread {:x} next {} ", thread.tid, format_windbg_address(rip));
	std::fflush(stdout);

	// Point only this frame at the stub. KiSwapContext is left unchanged.
	if (write_kernel_memory(trap + 0x168, &entry, sizeof(entry)) == 0)
	{
		breakpoint::remove(breakpoint_id);
		CloseHandle(handle);

		return 0;
	}

	// NtSuspendProcess freezes the process itself. ResumeThread clears the thread
	// count, but the scheduler still will not run it until NtResumeProcess.
	if (release_process_freeze() == 0)
	{
		write_kernel_memory(trap + 0x168, &rip, sizeof(rip));
		breakpoint::remove(breakpoint_id);
		CloseHandle(handle);

		return 0;
	}

	std::uint32_t resumes = 0;

	if (resume_until_running(handle, resumes) == 0)
	{
		write_kernel_memory(trap + 0x168, &rip, sizeof(rip));
		freeze_process_again();
		breakpoint::remove(breakpoint_id);
		CloseHandle(handle);

		return 0;
	}

	wake_user_thread(handle, thread.tid);

	if (wait_until_user_pause() == 1)
	{
		freeze_process_again();
		ResumeThread(handle);
		CloseHandle(handle);

		return 1;
	}

	write_kernel_memory(trap + 0x168, &rip, sizeof(rip));
	freeze_process_again();
	breakpoint::remove(breakpoint_id);
	CloseHandle(handle);
	fmt::print("\n");

	return 0;
}

static std::uint8_t hijack_kernel_thread(const user_thread_t& kernel_thread, const std::uint64_t kernel_cr3, const ULONGLONG deadline)
{
	const HANDLE thread = open_user_thread(kernel_thread.tid);

	if (thread == nullptr)
	{
		return 0;
	}

	std::uint64_t entry = 0;
	std::uint64_t breakpoint_id = 0;

	if (breakpoint::arm_kernel_pause(kernel_thread.rip, kernel_cr3, entry, breakpoint_id) == 0)
	{
		CloseHandle(thread);

		return 0;
	}

	fmt::print("\nkernel thread {:x} ", kernel_thread.tid);
	std::fflush(stdout);

	constexpr std::uint64_t trap_rip = 0x168;

	if (write_kernel_memory(kernel_thread.trap + trap_rip, &entry, sizeof(entry)) == 0)
	{
		breakpoint::remove(breakpoint_id);
		CloseHandle(thread);

		return 0;
	}

	// The process suspend count is still held. One resume lets only this thread
	// run into the kernel pause stub. The other threads stay suspended.
	if (ResumeThread(thread) == static_cast<DWORD>(-1))
	{
		write_kernel_memory(kernel_thread.trap + trap_rip, &kernel_thread.rip, sizeof(kernel_thread.rip));
		breakpoint::remove(breakpoint_id);
		CloseHandle(thread);

		return 0;
	}

	if (wait_for_direct_pause(deadline, 2000) == 1 || breakpoint::poll_new_pause() == 1)
	{
		CloseHandle(thread);

		return 1;
	}

	SuspendThread(thread);

	if (breakpoint::poll_new_pause() == 1)
	{
		ResumeThread(thread);
		CloseHandle(thread);

		return 1;
	}

	write_kernel_memory(kernel_thread.trap + trap_rip, &kernel_thread.rip, sizeof(kernel_thread.rip));
	breakpoint::remove(breakpoint_id);
	CloseHandle(thread);

	return 0;
}

static std::uint8_t suspend_implicit_process(const guest_process_t& process)
{
	if (implicit_process.suspended == 1)
	{
		return 1;
	}

	const LONG status = process_suspend_call(process.pid, 0);

	if (status < 0)
	{
		fmt::print("\n");
		LOG_ERR("suspend process {} failed: {:08x}", process.pid, static_cast<std::uint32_t>(status));

		return 0;
	}

	implicit_process.suspended = 1;

	return 1;
}

static void break_into_process(const guest_process_t& process, const std::uint8_t reload)
{
	if (breakpoint::has_paused_thread() == 1)
	{
		LOG_ERR("a thread is already paused");

		return;
	}

	if (process_is_critical(process) == 1)
	{
		LOG_ERR("refusing to suspend {}", process.image.empty() == true ? "this process" : process.image);

		return;
	}

	if (implicit_process.suspended == 1)
	{
		resume_suspended_process();
	}

	implicit_process.set = 1;
	implicit_process.suspended = 0;
	implicit_process.process = process;
	fmt::print("Implicit process: {} cid {:x}\n", process.image, process.pid);
	fmt::print("waiting for a user return");
	std::fflush(stdout);

	const std::uint64_t cave_hint = ntdll_cave_hint(process.user_cr3);

	if (cave_hint == 0)
	{
		fmt::print("\n");
		LOG_ERR("ntdll cave was not found");

		return;
	}

	while (console_interrupt_requested() == 0)
	{
		if (suspend_implicit_process(process) == 0)
		{
			return;
		}

		std::vector<user_thread_t> threads = {};

		collect_process_threads(process.eprocess, threads);
		std::uint8_t hooked = 0;

		for (const user_thread_t& thread : threads)
		{
			std::uint64_t trap = 0;
			std::uint64_t rip = 0;

			if (find_user_return_frame(thread.ethread, thread.trap, trap, rip) == 0)
			{
				continue;
			}

			fmt::print("\nhooking the next instruction");
			std::fflush(stdout);
			hooked = 1;

			if (hook_next_and_run(thread, process, cave_hint) == 1)
			{
				report_process_break(process, reload);

				return;
			}

			if (console_interrupt_requested() == 1)
			{
				break;
			}
		}

		if (console_interrupt_requested() == 1)
		{
			break;
		}

		if (hooked == 0)
		{
			fmt::print(".");
			std::fflush(stdout);
		}

		undo_process_suspend();
		Sleep(100);
	}

	fmt::print("\n");
	undo_process_suspend();
	console_interrupt_clear();
	fmt::print("interrupted\n");
}

static std::uint8_t set_implicit_process(const guest_process_t& process, const std::uint8_t suspend, const std::uint8_t reload)
{
	if (suspend == 1)
	{
		if (process_is_critical(process) == 1)
		{
			LOG_ERR("refusing to suspend {}", process.image.empty() == true ? "this process" : process.image);

			return 0;
		}

		if (implicit_process.suspended == 1 && implicit_process.process.pid != process.pid)
		{
			resume_suspended_process();
		}

		if (implicit_process.suspended == 0 || implicit_process.process.pid != process.pid)
		{
			const LONG status = process_suspend_call(process.pid, 0);

			if (status < 0)
			{
				LOG_ERR("suspend process {} failed: {:08x}", process.pid, static_cast<std::uint32_t>(status));

				return 0;
			}

			implicit_process.suspended = 1;
		}
	}

	implicit_process.set = 1;
	implicit_process.process = process;
	fmt::print("Implicit process: {} cid {:x}\n", process.image, process.pid);

	if (suspend == 1)
	{
		fmt::print("Process suspended. The guest thread was not switched.\n");
	}

	std::fflush(stdout);

	if (reload == 1)
	{
		std::vector<reload_module_t> modules = {};

		if (process.user_cr3 == 0 || collect_user_modules(process.user_cr3, modules) == 0)
		{
			LOG_ERR("failed to read the user module list");

			return 0;
		}

		force_load_listed_modules(modules, 1);
	}

	return 1;
}

static std::uint8_t image_name_matches(const std::string& image, const std::string& filter)
{
	if (filter.empty() == true)
	{
		return 1;
	}

	if (equals_ignore_case(image, filter) == 1)
	{
		return 1;
	}

	std::string lower_image = image;
	std::string lower_filter = filter;

	for (char& character : lower_image)
	{
		character = static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
	}

	for (char& character : lower_filter)
	{
		character = static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
	}

	return static_cast<std::uint8_t>(lower_image.find(lower_filter) != std::string::npos);
}

static void process_bang_process()
{
	const std::string text = symbol_command_text("process");
	std::string_view body = skip_whitespace(text);
	std::string first = {};
	std::string second = {};
	std::string third = {};
	take_command_token(body, first);
	take_command_token(body, second);
	take_command_token(body, third);

	if (first.empty() == true || first == "0")
	{
		std::string image_filter = {};
		std::uint64_t flags = 0;

		if (second.empty() == false && parse_windbg_number(second, flags) == 1)
		{
			if (flags != 0)
			{
				fmt::print("thread details are not shown\n");
			}

			image_filter = third;
		}
		else
		{
			image_filter = second;
		}

		const std::vector<guest_process_t> processes = list_guest_processes();

		if (processes.empty() == true)
		{
			LOG_ERR("failed to read the process list");

			return;
		}

		std::uint64_t shown = 0;

		for (const guest_process_t& process : processes)
		{
			if (image_name_matches(process.image, image_filter) == 0)
			{
				continue;
			}

			print_guest_process(process);
			shown += 1;
		}

		if (shown == 0)
		{
			LOG_ERR("process {} was not found", image_filter);
		}

		return;
	}

	std::uint64_t selector = 0;

	if (parse_windbg_number(first, selector) == 0)
	{
		LOG_ERR("invalid process: {}", first);

		return;
	}

	guest_process_t process = {};
	const std::uint8_t by_pid = static_cast<std::uint8_t>(selector <= 0xFFFFF);

	if (find_guest_process(selector, by_pid, process) == 0)
	{
		LOG_ERR("process {} was not found", first);

		return;
	}

	print_guest_process(process);
}

static void process_dot_detach()
{
	breakpoint::clean_up();
	hook::clean_up();

	if (implicit_process.suspended == 1)
	{
		resume_suspended_process();
	}

	fmt::print("shadow pages released\n");
	std::fflush(stdout);
}

static void process_dot_process()
{
	const std::string text = symbol_command_text(".process");
	std::string_view body = skip_whitespace(text);
	std::uint8_t suspend = 0;
	std::uint8_t reload = 0;
	std::string target = {};

	while (body.empty() == false)
	{
		std::string token = {};

		if (take_command_token(body, token) == 0)
		{
			break;
		}

		if (equals_ignore_case(token, "/i") == 1)
		{
			suspend = 1;
		}
		else if (equals_ignore_case(token, "/p") == 1)
		{
			continue;
		}
		else if (equals_ignore_case(token, "/r") == 1)
		{
			reload = 1;
		}
		else if (target.empty() == true)
		{
			target = token;
		}
		else
		{
			LOG_ERR("syntax: .process [/i] [/p] [/r] [pid]");

			return;
		}
	}

	if (target.empty() == true)
	{
		if (suspend == 1)
		{
			LOG_ERR("syntax: .process /i <pid>");

			return;
		}

		guest_process_t process = {};

		if (effective_process(process) == 0)
		{
			LOG_ERR("no current process");

			return;
		}

		print_guest_process(process);
		fmt::print("    Context: {}\n", implicit_process.set == 1 ? "explicit" : "current debugger");
		fmt::print("    Suspended: {}\n", implicit_process.suspended == 1 ? "yes" : "no");

		if (reload == 1)
		{
			set_implicit_process(process, 0, 1);
		}

		return;
	}

	std::uint64_t selector = 0;

	if (parse_windbg_number(target, selector) == 0)
	{
		LOG_ERR("invalid process: {}", target);

		return;
	}

	guest_process_t process = {};
	const std::uint8_t by_pid = static_cast<std::uint8_t>(selector <= 0xFFFFF);

	if (find_guest_process(selector, by_pid, process) == 0)
	{
		LOG_ERR("process {} was not found", target);

		return;
	}

	if (suspend == 1)
	{
		break_into_process(process, reload);

		return;
	}

	set_implicit_process(process, 0, reload);
}

struct guest_thread_t
{
	std::uint64_t ethread = 0;
	std::uint64_t eprocess = 0;
	std::uint64_t pid = 0;
	std::uint64_t tid = 0;
	std::uint64_t teb = 0;
	std::uint64_t trap = 0;
	std::uint64_t win32_start = 0;
	std::uint64_t win32_thread = 0;
	std::uint64_t stack_base = 0;
	std::uint64_t stack_limit = 0;
	std::uint64_t initial_stack = 0;
	std::uint64_t kernel_stack = 0;
	std::uint64_t user_cr3 = 0;
	std::uint64_t directory = 0;
	std::uint32_t context_switches = 0;
	std::uint32_t wait_time = 0;
	std::uint8_t state = 0;
	std::int8_t priority = 0;
	std::int8_t suspend_count = 0;
	std::uint8_t wait_reason = 0;
	std::uint8_t wait_mode = 0;
	std::uint8_t system_thread = 0;
	std::string image = {};
	breakpoint::registers_t registers = {};
	std::uint8_t has_registers = 0;
};

struct implicit_thread_t
{
	std::uint8_t set = 0;
	guest_thread_t thread = {};
};

static implicit_thread_t implicit_thread = {};

static std::uint64_t kernel_context_cr3()
{
	if (implicit_thread.set == 0 || implicit_thread.thread.has_registers == 0 ||
		implicit_thread.thread.registers.rip <= 0x00007FFFFFFFFFFFull || implicit_thread.thread.registers.cr3 == 0)
	{
		return 0;
	}

	return implicit_thread.thread.registers.cr3;
}

static const char* thread_state_name(const std::uint8_t state)
{
	switch (state)
	{
	case 0:
		return "Initialized";
	case 1:
		return "Ready";
	case 2:
		return "Running";
	case 3:
		return "Standby";
	case 4:
		return "Terminated";
	case 5:
		return "Waiting";
	case 6:
		return "Transition";
	case 7:
		return "DeferredReady";
	case 8:
		return "GateWait";
	default:
		return "Unknown";
	}
}

static const char* wait_reason_name(const std::uint8_t reason)
{
	static const char* const names[] = {
		"Executive", "FreePage", "PageIn", "PoolAllocation", "DelayExecution", "Suspended", "UserRequest", "WrExecutive",
		"WrFreePage", "WrPageIn", "WrPoolAllocation", "WrDelayExecution", "WrSuspended", "WrUserRequest", "WrEventPair", "WrQueue",
		"WrLpcReceive", "WrLpcReply", "WrVirtualMemory", "WrPageOut", "WrRendezvous", "WrKeyedEvent", "WrTerminated",
		"WrProcessInSwap", "WrCpuRateControl", "WrCalloutStack", "WrKernel", "WrResource", "WrPushLock", "WrMutex", "WrQuantumEnd",
		"WrDispatchInt", "WrPreempted", "WrYieldExecution", "WrFastMutex", "WrGuardedMutex", "WrRundown", "WrAlertByThreadId",
		"WrDeferredPreempt", "WrPhysicalFault"};

	if (reason >= sizeof(names) / sizeof(names[0]))
	{
		return "Unknown";
	}

	return names[reason];
}

static std::uint8_t read_trap_registers(const std::uint64_t trap, breakpoint::registers_t& registers_out)
{
	std::uint8_t frame[0x190] = {};

	if (trap == 0 || read_kernel_memory(trap, frame, sizeof(frame)) == 0)
	{
		return 0;
	}

	const auto qword = [&](const std::uint64_t offset) -> std::uint64_t
	{
		std::uint64_t value = 0;
		std::memcpy(&value, frame + offset, sizeof(value));

		return value;
	};

	registers_out = {};
	registers_out.rax = qword(0x30);
	registers_out.rcx = qword(0x38);
	registers_out.rdx = qword(0x40);
	registers_out.r8 = qword(0x48);
	registers_out.r9 = qword(0x50);
	registers_out.r10 = qword(0x58);
	registers_out.r11 = qword(0x60);
	registers_out.rbx = qword(0x140);
	registers_out.rdi = qword(0x148);
	registers_out.rsi = qword(0x150);
	registers_out.rbp = qword(0x158);
	registers_out.rip = qword(0x168);
	registers_out.rflags = qword(0x178) & 0xFFFFFFFFull;
	registers_out.rflags_known = 1;
	registers_out.rsp = qword(0x180);

	return 1;
}

static std::uint8_t user_canonical(const std::uint64_t value)
{
	return static_cast<std::uint8_t>(value != 0 && value <= 0x00007FFFFFFFFFFFull);
}

static std::uint8_t kernel_canonical(const std::uint64_t value)
{
	return static_cast<std::uint8_t>(value >= 0xFFFF800000000000ull);
}

static void assign_thread_context_cr3(guest_thread_t& thread)
{
	const std::uint64_t kernel_cr3 = thread.directory != 0 ? thread.directory : sys::current_cr3;

	thread.registers.cr3 = user_canonical(thread.registers.rip) == 1 && thread.user_cr3 != 0 ? thread.user_cr3 : kernel_cr3;
	thread.has_registers = static_cast<std::uint8_t>(thread.registers.rip != 0);
}

static std::uint8_t stack_trap_matches(const std::uint8_t* const frame, const std::uint8_t want_user)
{
	std::uint64_t rip = 0;
	std::uint64_t rsp = 0;
	std::uint64_t flags = 0;
	std::uint16_t cs = 0;

	std::memcpy(&rip, frame + 0x168, sizeof(rip));
	std::memcpy(&cs, frame + 0x170, sizeof(cs));
	std::memcpy(&flags, frame + 0x178, sizeof(flags));
	std::memcpy(&rsp, frame + 0x180, sizeof(rsp));

	if ((flags & 2) == 0)
	{
		return 0;
	}

	if (want_user == 1)
	{
		return static_cast<std::uint8_t>(cs == 0x33 && user_canonical(rip) == 1 && user_canonical(rsp) == 1);
	}

	return static_cast<std::uint8_t>(cs == 0x10 && kernel_canonical(rip) == 1 && kernel_canonical(rsp) == 1);
}

static std::uint8_t find_user_return_frame(const std::uint64_t ethread, const std::uint64_t trap_hint, std::uint64_t& trap_out,
                                           std::uint64_t& rip_out)
{
	trap_out = 0;
	rip_out = 0;

	if (trap_is_user_return(trap_hint, rip_out) == 1)
	{
		trap_out = trap_hint;

		return 1;
	}

	std::uint64_t kernel_stack = 0;
	std::uint64_t stack_base = 0;

	if (read_kernel_memory(ethread + 0x58, &kernel_stack, sizeof(kernel_stack)) == 0 || kernel_stack == 0 ||
		read_kernel_memory(ethread + 0x38, &stack_base, sizeof(stack_base)) == 0 || stack_base <= kernel_stack)
	{
		return 0;
	}

	std::uint64_t span = stack_base - kernel_stack;

	if (span > 0x4000)
	{
		span = 0x4000;
	}

	if (span < 0x190)
	{
		return 0;
	}

	std::vector<std::uint8_t> stack(static_cast<std::size_t>(span));
	std::uint64_t filled = 0;

	while (filled < span)
	{
		const std::uint64_t chunk = span - filled > 0x1000 ? 0x1000 : span - filled;

		if (read_kernel_memory(kernel_stack + filled, stack.data() + filled, chunk) == 0)
		{
			break;
		}

		filled += chunk;
	}

	for (std::uint64_t offset = 0; offset + 0x190 <= filled; offset += 8)
	{
		if (stack_trap_matches(stack.data() + offset, 1) == 0)
		{
			continue;
		}

		const std::uint64_t trap = kernel_stack + offset;
		std::uint64_t rip = 0;

		if (trap_is_user_return(trap, rip) == 0)
		{
			continue;
		}

		trap_out = trap;
		rip_out = rip;

		return 1;
	}

	return 0;
}

static std::uint8_t recover_saved_thread_context(guest_thread_t& thread)
{
	if (thread.kernel_stack == 0 || thread.stack_base <= thread.kernel_stack)
	{
		return 0;
	}

	std::uint64_t span = thread.stack_base - thread.kernel_stack;

	if (span > 0x4000)
	{
		span = 0x4000;
	}

	if (span < 0x190)
	{
		return 0;
	}

	std::vector<std::uint8_t> stack(static_cast<std::size_t>(span));
	std::uint64_t filled = 0;

	while (filled < span)
	{
		const std::uint64_t chunk = span - filled > page_size ? page_size : span - filled;

		if (read_kernel_memory(thread.kernel_stack + filled, stack.data() + filled, chunk) == 0)
		{
			break;
		}

		filled += chunk;
	}

	const auto adopt = [&](const std::uint64_t trap) -> std::uint8_t
	{
		if (read_trap_registers(trap, thread.registers) == 0 || thread.registers.rip == 0)
		{
			return 0;
		}

		thread.trap = trap;
		assign_thread_context_cr3(thread);

		return 1;
	};

	if (filled >= 0x190)
	{
		for (std::uint8_t pass = 0; pass < 2; pass++)
		{
			for (std::uint64_t offset = 0; offset + 0x190 <= filled; offset += 8)
			{
				if (stack_trap_matches(stack.data() + offset, pass == 0 ? 1 : 0) == 1 && adopt(thread.kernel_stack + offset) == 1)
				{
					return 1;
				}
			}
		}

		constexpr std::uint64_t switch_return_offsets[] = {0x38, 0x30, 0};

		for (const std::uint64_t offset : switch_return_offsets)
		{
			std::uint64_t rip = 0;

			if (offset + sizeof(rip) > filled)
			{
				continue;
			}

			std::memcpy(&rip, stack.data() + offset, sizeof(rip));

			if (kernel_canonical(rip) == 0)
			{
				continue;
			}

			thread.registers = {};
			thread.registers.rip = rip;
			assign_thread_context_cr3(thread);

			return 1;
		}
	}

	return 0;
}

static std::uint8_t read_guest_thread(const std::uint64_t ethread, guest_thread_t& thread_out)
{
	constexpr std::uint64_t initial_stack = 0x28;
	constexpr std::uint64_t stack_limit = 0x30;
	constexpr std::uint64_t stack_base = 0x38;
	constexpr std::uint64_t kernel_stack = 0x58;
	constexpr std::uint64_t misc_flags = 0x74;
	constexpr std::uint64_t trap_frame = 0x90;
	constexpr std::uint64_t priority = 0xc3;
	constexpr std::uint64_t teb = 0xf0;
	constexpr std::uint64_t context_switches = 0x154;
	constexpr std::uint64_t state = 0x184;
	constexpr std::uint64_t wait_mode = 0x187;
	constexpr std::uint64_t wait_time = 0x1b4;
	constexpr std::uint64_t win32_thread = 0x1c8;
	constexpr std::uint64_t thread_process = 0x220;
	constexpr std::uint64_t wait_reason = 0x283;
	constexpr std::uint64_t suspend_count = 0x284;
	constexpr std::uint64_t cid = 0x508;
	constexpr std::uint64_t win32_start = 0x560;

	thread_out = {};
	thread_out.ethread = ethread;

	if (ethread < 0xFFFF000000000000ull)
	{
		return 0;
	}

	std::uint64_t unique_process = 0;
	std::uint64_t unique_thread = 0;

	if (read_kernel_memory(ethread + cid, &unique_process, sizeof(unique_process)) == 0 ||
		read_kernel_memory(ethread + cid + sizeof(unique_thread), &unique_thread, sizeof(unique_thread)) == 0 || unique_thread == 0 ||
		unique_thread > 0xFFFFFFFFull)
	{
		return 0;
	}

	thread_out.pid = unique_process;
	thread_out.tid = unique_thread;
	read_kernel_qword(ethread + thread_process, thread_out.eprocess);
	read_kernel_qword(ethread + teb, thread_out.teb);
	read_kernel_qword(ethread + trap_frame, thread_out.trap);
	read_kernel_qword(ethread + win32_thread, thread_out.win32_thread);
	read_kernel_qword(ethread + win32_start, thread_out.win32_start);
	read_kernel_qword(ethread + initial_stack, thread_out.initial_stack);
	read_kernel_qword(ethread + stack_limit, thread_out.stack_limit);
	read_kernel_qword(ethread + stack_base, thread_out.stack_base);
	read_kernel_qword(ethread + kernel_stack, thread_out.kernel_stack);

	std::uint32_t switches = 0;
	std::uint32_t waited = 0;
	std::uint32_t flags = 0;
	std::uint8_t state_value = 0;
	std::uint8_t reason = 0;
	std::uint8_t mode = 0;
	std::uint8_t priority_value = 0;
	std::uint8_t suspended = 0;

	if (read_kernel_memory(ethread + context_switches, &switches, sizeof(switches)) == 1)
	{
		thread_out.context_switches = switches;
	}

	if (read_kernel_memory(ethread + wait_time, &waited, sizeof(waited)) == 1)
	{
		thread_out.wait_time = waited;
	}

	if (read_kernel_memory(ethread + misc_flags, &flags, sizeof(flags)) == 1)
	{
		thread_out.system_thread = static_cast<std::uint8_t>((flags & (1u << 10)) != 0);
	}

	if (read_kernel_memory(ethread + state, &state_value, sizeof(state_value)) == 1)
	{
		thread_out.state = state_value;
	}

	if (read_kernel_memory(ethread + wait_reason, &reason, sizeof(reason)) == 1)
	{
		thread_out.wait_reason = reason;
	}

	if (read_kernel_memory(ethread + wait_mode, &mode, sizeof(mode)) == 1)
	{
		thread_out.wait_mode = mode;
	}

	if (read_kernel_memory(ethread + priority, &priority_value, sizeof(priority_value)) == 1)
	{
		thread_out.priority = static_cast<std::int8_t>(priority_value);
	}

	if (read_kernel_memory(ethread + suspend_count, &suspended, sizeof(suspended)) == 1)
	{
		thread_out.suspend_count = static_cast<std::int8_t>(suspended);
	}

	if (thread_out.eprocess != 0)
	{
		guest_process_t owner = {};

		if (read_guest_process(thread_out.eprocess, owner) == 1)
		{
			thread_out.image = owner.image;
			thread_out.user_cr3 = owner.user_cr3;
			thread_out.directory = owner.directory;

			if (owner.pid != 0)
			{
				thread_out.pid = owner.pid;
			}
		}
	}

	if (thread_out.trap != 0 && read_trap_registers(thread_out.trap, thread_out.registers) == 1 && thread_out.registers.rip != 0)
	{
		assign_thread_context_cr3(thread_out);

		return 1;
	}

	// A waiting thread often has a null TrapFrame. The user or kernel frame is still
	// on the kernel stack, and the switch frame holds the kernel resume address.
	recover_saved_thread_context(thread_out);

	return 1;
}

static std::uint8_t find_guest_thread(const std::uint64_t selector, const std::uint8_t selector_is_tid, guest_thread_t& thread_out)
{
	constexpr std::uint64_t thread_list_head = 0x370;
	constexpr std::uint64_t thread_list_entry = 0x578;
	constexpr std::uint64_t ethread_cid = 0x508;

	if (selector_is_tid == 0)
	{
		return read_guest_thread(selector, thread_out);
	}

	for (const guest_process_t& process : list_guest_processes())
	{
		const std::uint64_t head = process.eprocess + thread_list_head;
		std::uint64_t link = 0;

		if (read_kernel_memory(head, &link, sizeof(link)) == 0 || link == 0)
		{
			continue;
		}

		for (std::uint64_t count = 0; count < 4096 && link != head; count++)
		{
			const std::uint64_t ethread = link - thread_list_entry;
			std::uint64_t tid = 0;

			if (read_kernel_memory(ethread + ethread_cid + sizeof(tid), &tid, sizeof(tid)) == 1 && tid == selector)
			{
				return read_guest_thread(ethread, thread_out);
			}

			if (read_kernel_memory(link, &link, sizeof(link)) == 0 || link == 0)
			{
				break;
			}
		}
	}

	return 0;
}

static std::uint8_t processor_current_thread(guest_thread_t& thread_out)
{
	constexpr std::uint64_t prcb_current_thread = 0x8;
	const std::uint64_t processor_block = processor_block_address();
	std::uint64_t prcb = 0;
	std::uint64_t thread = 0;

	if (processor_block == 0 || read_kernel_qword(processor_block, prcb) == 0 || prcb == 0 ||
		read_kernel_qword(prcb + prcb_current_thread, thread) == 0 || thread == 0)
	{
		return 0;
	}

	return read_guest_thread(thread, thread_out);
}

static void print_guest_thread(const guest_thread_t& thread, const std::uint8_t show_process)
{
	fmt::print("THREAD {}  Cid {:x}.{:x}  Teb: {}\n", format_windbg_address(thread.ethread), thread.pid, thread.tid,
	           format_windbg_address(thread.teb));
	fmt::print("    Owning Process {}       Image: {}\n", format_windbg_address(thread.eprocess),
	           thread.image.empty() == true ? "?" : thread.image);
	fmt::print("    Win32 Start Address {}\n", format_windbg_address(thread.win32_start));
	fmt::print("    Win32Thread {}\n", format_windbg_address(thread.win32_thread));
	fmt::print("    Stack Init {} Base {} Limit {}\n", format_windbg_address(thread.initial_stack),
	           format_windbg_address(thread.stack_base), format_windbg_address(thread.stack_limit));
	fmt::print("    Kernel stack {}\n", format_windbg_address(thread.kernel_stack));
	fmt::print("    Context Switch Count {}\n", thread.context_switches);
	fmt::print("    WaitTime {}\n", thread.wait_time);
	fmt::print("    State: {} ({})  WaitReason: {} ({})  WaitMode: {}\n", thread_state_name(thread.state), thread.state,
	           wait_reason_name(thread.wait_reason), thread.wait_reason, thread.wait_mode == 1 ? "User" : "Kernel");
	fmt::print("    Priority: {}  SuspendCount: {}  SystemThread: {}\n", static_cast<int>(thread.priority),
	           static_cast<int>(thread.suspend_count), thread.system_thread == 1 ? "yes" : "no");

	if (thread.trap == 0 || thread.has_registers == 0)
	{
		fmt::print("    Trap Frame: (none)\n");
	}
	else
	{
		fmt::print("    Trap Frame {}  rip={} rsp={}\n", format_windbg_address(thread.trap),
		           format_windbg_address(thread.registers.rip), format_windbg_address(thread.registers.rsp));
	}

	if (show_process == 1 && thread.eprocess != 0)
	{
		guest_process_t process = {};

		if (read_guest_process(thread.eprocess, process) == 1)
		{
			print_guest_process(process);
		}
	}

	std::fflush(stdout);
}

static std::uint8_t current_context_thread(guest_thread_t& thread_out)
{
	if (implicit_thread.set == 1)
	{
		thread_out = implicit_thread.thread;

		return 1;
	}

	if (find_guest_thread(GetCurrentThreadId(), 1, thread_out) == 1)
	{
		return 1;
	}

	return processor_current_thread(thread_out);
}

static std::uint8_t implicit_context_active()
{
	return implicit_thread.set;
}

static void clear_implicit_thread()
{
	implicit_thread = {};
}

static std::uint8_t show_implicit_register_context()
{
	if (implicit_thread.set == 0)
	{
		return 0;
	}

	if (implicit_thread.thread.has_registers == 0)
	{
		LOG_ERR("thread has no trap frame");

		return 1;
	}

	fmt::print("Last set context:\n");
	print_paused_registers(implicit_thread.thread.registers);
	fmt::print("r12-r15 are not stored in the trap frame\n");
	print_memory_instruction(implicit_thread.thread.registers.rip, implicit_thread.thread.registers.cr3);
	std::fflush(stdout);

	return 1;
}

static std::uint8_t read_implicit_register(const std::string_view name, std::uint64_t& value_out)
{
	if (implicit_thread.set == 0)
	{
		return 0;
	}

	if (implicit_thread.thread.has_registers == 0)
	{
		LOG_ERR("thread has no trap frame");

		return 0;
	}

	const std::uint64_t* const field = paused_register_field(implicit_thread.thread.registers, name);

	if (field == nullptr)
	{
		LOG_ERR("invalid register");

		return 0;
	}

	value_out = *field;

	return 1;
}

static std::uint8_t write_implicit_register(const std::string_view name, const std::uint64_t value)
{
	if (implicit_thread.set == 0)
	{
		return 0;
	}

	std::uint64_t* const field = paused_register_field(implicit_thread.thread.registers, name);

	if (field == nullptr)
	{
		LOG_ERR("invalid register");

		return 0;
	}

	*field = value;

	if (equals_ignore_case(name, "efl") == 1 || equals_ignore_case(name, "rflags") == 1)
	{
		implicit_thread.thread.registers.rflags_known = 1;
	}

	return 1;
}

static void use_thread_context(const guest_thread_t& thread, const std::uint8_t switch_process, const std::uint8_t reload)
{
	implicit_thread.set = 1;
	implicit_thread.thread = thread;
	fmt::print("Using context of thread {}\n", format_windbg_address(thread.ethread));
	std::fflush(stdout);

	if (switch_process == 0 && reload == 0)
	{
		return;
	}

	if (thread.eprocess == 0)
	{
		LOG_ERR("thread has no process");

		return;
	}

	guest_process_t process = {};

	if (read_guest_process(thread.eprocess, process) == 0)
	{
		LOG_ERR("process {} was not found", format_windbg_address(thread.eprocess));

		return;
	}

	set_implicit_process(process, 0, reload);
}

static void print_process_threads(const guest_process_t& process)
{
	constexpr std::uint64_t thread_list_head = 0x370;
	constexpr std::uint64_t thread_list_entry = 0x578;
	const std::uint64_t head = process.eprocess + thread_list_head;
	std::uint64_t link = 0;
	std::uint64_t shown = 0;

	fmt::print("Threads of {} cid {:x}:\n", process.image.empty() == true ? "?" : process.image, process.pid);

	if (read_kernel_memory(head, &link, sizeof(link)) == 0 || link == 0)
	{
		LOG_ERR("failed to read the thread list");

		return;
	}

	for (std::uint64_t count = 0; count < 4096 && link != head && shown < 128; count++)
	{
		const std::uint64_t ethread = link - thread_list_entry;
		guest_thread_t thread = {};

		if (read_guest_thread(ethread, thread) == 1)
		{
			const std::uint8_t kernel = static_cast<std::uint8_t>(thread.has_registers == 1 && thread.registers.rip > 0x00007FFFFFFFFFFFull);

			fmt::print("  {:x}.{:x} {} {} rip={}", thread.pid, thread.tid, format_windbg_address(thread.ethread),
			           kernel == 1 || thread.system_thread == 1 ? "kernel" : "user",
			           thread.has_registers == 1 ? format_windbg_address(thread.registers.rip) : "(none)");
			fmt::print(" {}\n", thread_state_name(thread.state));
			shown++;
		}

		if (read_kernel_memory(link, &link, sizeof(link)) == 0 || link == 0)
		{
			break;
		}
	}

	if (shown == 128)
	{
		fmt::print("  list truncated\n");
	}

	std::fflush(stdout);
}

static void process_dot_thread()
{
	const std::string text = symbol_command_text(".thread");
	std::string_view body = skip_whitespace(text);
	std::uint8_t switch_process = 0;
	std::uint8_t reload = 0;
	std::string target = {};

	while (body.empty() == false)
	{
		std::string token = {};

		if (take_command_token(body, token) == 0)
		{
			break;
		}

		if (equals_ignore_case(token, "/p") == 1 || equals_ignore_case(token, "/P") == 1)
		{
			switch_process = 1;
		}
		else if (equals_ignore_case(token, "/r") == 1)
		{
			switch_process = 1;
			reload = 1;
		}
		else if (equals_ignore_case(token, "/w") == 1)
		{
			LOG_ERR("wow64 context is not supported");

			return;
		}
		else if (target.empty() == true)
		{
			target = token;
		}
		else
		{
			LOG_ERR("syntax: .thread [/p] [/r] [thread]");

			return;
		}
	}

	if (target.empty() == true)
	{
		guest_thread_t thread = {};

		if (implicit_process.set == 1)
		{
			print_process_threads(implicit_process.process);
		}

		if (implicit_thread.set == 1)
		{
			print_guest_thread(implicit_thread.thread, 0);
			fmt::print("    Context: explicit\n");
			std::fflush(stdout);

			if (reload == 1)
			{
				use_thread_context(implicit_thread.thread, 1, 1);
			}

			return;
		}

		if (breakpoint::has_paused_thread() == 1)
		{
			breakpoint::registers_t registers = {};

			fmt::print("Implicit thread is not set. Register context is the paused thread.\n");

			if (breakpoint::paused_registers(registers) == 1)
			{
				fmt::print("rip={}\n", format_windbg_address(registers.rip));
			}

			std::fflush(stdout);

			return;
		}

		if (current_context_thread(thread) == 0)
		{
			LOG_ERR("no current thread");

			return;
		}

		print_guest_thread(thread, 0);
		fmt::print("    Context: current\n");
		std::fflush(stdout);

		return;
	}

	std::uint64_t selector = 0;

	if (parse_windbg_number(target, selector) == 0)
	{
		LOG_ERR("invalid thread: {}", target);

		return;
	}

	if (selector == 0)
	{
		clear_implicit_thread();
		fmt::print("Implicit thread cleared\n");
		std::fflush(stdout);

		return;
	}

	guest_thread_t thread = {};
	const std::uint8_t by_tid = static_cast<std::uint8_t>(selector <= 0xFFFFF);

	if (find_guest_thread(selector, by_tid, thread) == 0)
	{
		LOG_ERR("thread {} was not found", target);

		return;
	}

	use_thread_context(thread, switch_process, reload);
}

static void process_bang_thread()
{
	const std::string text = symbol_command_text("thread");
	std::string_view body = skip_whitespace(text);
	std::uint8_t show_process = 0;
	std::uint8_t by_tid = 0;
	std::string target = {};
	std::uint64_t flags = 0;
	std::uint8_t has_flags = 0;

	while (body.empty() == false)
	{
		std::string token = {};

		if (take_command_token(body, token) == 0)
		{
			break;
		}

		if (equals_ignore_case(token, "-p") == 1)
		{
			show_process = 1;

			continue;
		}

		if (equals_ignore_case(token, "-t") == 1)
		{
			by_tid = 1;

			continue;
		}

		if (target.empty() == true)
		{
			target = token;

			continue;
		}

		if (has_flags == 0 && parse_windbg_number(token, flags) == 1)
		{
			has_flags = 1;

			continue;
		}

		LOG_ERR("syntax: !thread [-p] [-t] [thread [flags]]");

		return;
	}

	guest_thread_t thread = {};

	if (target.empty() == true || target == "-1")
	{
		if (current_context_thread(thread) == 0)
		{
			LOG_ERR("no current thread");

			return;
		}
	}
	else
	{
		std::uint64_t selector = 0;

		if (parse_windbg_number(target, selector) == 0)
		{
			LOG_ERR("invalid thread: {}", target);

			return;
		}

		const std::uint8_t selector_is_tid = static_cast<std::uint8_t>(by_tid == 1 || selector <= 0xFFFFF);

		if (selector == 0 || find_guest_thread(selector, selector_is_tid, thread) == 0)
		{
			LOG_ERR("thread {} was not found", target);

			return;
		}
	}

	print_guest_thread(thread, show_process);

	if ((flags & 4) != 0)
	{
		fmt::print("    stack trace is not available\n");
		std::fflush(stdout);
	}
}

struct stack_module_t
{
	std::uint64_t base = 0;
	std::uint32_t size = 0;
	std::vector<std::uint32_t> functions = {};
};

struct stack_regs_t
{
	std::uint64_t r[16] = {};
	std::uint64_t rip = 0;
	std::uint64_t rsp = 0;
};

enum class stack_style_t
{
	plain,
	args3,
	dump,
	params,
	verbose
};

struct stack_frame_t
{
	std::uint64_t child_sp = 0;
	std::uint64_t ret = 0;
	std::uint64_t rip = 0;
	std::uint64_t args[4] = {};
	std::uint8_t has_ret = 0;
	std::uint8_t args_valid[4] = {};
};

static std::uint8_t read_paused_block(const std::uint64_t address, void* const buffer, const std::uint64_t size, const std::uint64_t extra_cr3)
{
	if (breakpoint::read_paused_virtual(buffer, address, size) == 1)
	{
		return 1;
	}

	if (extra_cr3 != 0 && hypercall::read_guest_virtual_memory(buffer, address, extra_cr3, size) == size)
	{
		return 1;
	}

	if (address > 0x00007FFFFFFFFFFFull && sys::current_cr3 != 0 &&
		hypercall::read_guest_virtual_memory(buffer, address, sys::current_cr3, size) == size)
	{
		return 1;
	}

	return 0;
}

static std::uint8_t canonical_code_address(const std::uint64_t address)
{
	const std::uint64_t sign = address >> 47;

	return static_cast<std::uint8_t>(address != 0 && (sign == 0 || sign == 0x1FFFFull));
}

static std::uint8_t gpr_index(const ZydisRegister reg, std::uint8_t& index_out)
{
	const ZydisRegister largest = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, reg);

	if (largest < ZYDIS_REGISTER_RAX || largest > ZYDIS_REGISTER_R15)
	{
		return 0;
	}

	index_out = static_cast<std::uint8_t>(largest - ZYDIS_REGISTER_RAX);

	return 1;
}

static void load_stack_regs(const breakpoint::registers_t& registers, stack_regs_t& regs_out)
{
	regs_out = {};
	regs_out.r[0] = registers.rax;
	regs_out.r[1] = registers.rcx;
	regs_out.r[2] = registers.rdx;
	regs_out.r[3] = registers.rbx;
	regs_out.r[4] = registers.rsp;
	regs_out.r[5] = registers.rbp;
	regs_out.r[6] = registers.rsi;
	regs_out.r[7] = registers.rdi;
	regs_out.r[8] = registers.r8;
	regs_out.r[9] = registers.r9;
	regs_out.r[10] = registers.r10;
	regs_out.r[11] = registers.r11;
	regs_out.r[12] = registers.r12;
	regs_out.r[13] = registers.r13;
	regs_out.r[14] = registers.r14;
	regs_out.r[15] = registers.r15;
	regs_out.rip = registers.rip;
	regs_out.rsp = registers.rsp;
}

static std::uint8_t module_bounds(const std::vector<stack_module_t>& modules, const std::uint64_t address, std::uint64_t& base_out,
                                  std::uint32_t& size_out)
{
	for (const stack_module_t& module : modules)
	{
		if (module.base != 0 && address >= module.base && address - module.base < module.size)
		{
			base_out = module.base;
			size_out = module.size;

			return 1;
		}
	}

	return 0;
}

static std::uint8_t load_function_table(stack_module_t& module, const std::uint64_t extra_cr3)
{
	if (module.functions.empty() == false)
	{
		return 1;
	}

	std::uint8_t dos[64] = {};

	if (read_paused_block(module.base, dos, sizeof(dos), extra_cr3) == 0 || dos[0] != 'M' || dos[1] != 'Z')
	{
		return 0;
	}

	std::uint32_t e_lfanew = 0;
	std::memcpy(&e_lfanew, dos + 0x3c, sizeof(e_lfanew));

	if (e_lfanew < sizeof(dos) || e_lfanew > 0x1000)
	{
		return 0;
	}

	std::uint8_t pe[264] = {};

	if (read_paused_block(module.base + e_lfanew, pe, sizeof(pe), extra_cr3) == 0 || pe[0] != 'P' || pe[1] != 'E')
	{
		return 0;
	}

	std::uint16_t magic = 0;
	std::memcpy(&magic, pe + 24, sizeof(magic));

	if (magic != 0x20b)
	{
		return 0;
	}

	std::uint32_t exception_rva = 0;
	std::uint32_t exception_size = 0;
	std::memcpy(&exception_rva, pe + 24 + 112 + 3 * 8, sizeof(exception_rva));
	std::memcpy(&exception_size, pe + 24 + 116 + 3 * 8, sizeof(exception_size));

	if (exception_rva == 0 || exception_size < 12 || exception_size > 0x200000)
	{
		return 0;
	}

	module.functions.resize(static_cast<std::size_t>(exception_size / 4));
	std::uint8_t* const raw = reinterpret_cast<std::uint8_t*>(module.functions.data());
	std::uint64_t done = 0;

	while (done < exception_size)
	{
		const std::uint64_t chunk = exception_size - done > 0x1000 ? 0x1000 : exception_size - done;

		if (read_paused_block(module.base + exception_rva + done, raw + done, chunk, extra_cr3) == 0)
		{
			module.functions.clear();

			return 0;
		}

		done += chunk;
	}

	return 1;
}

static std::uint8_t find_runtime_function(stack_module_t& module, const std::uint64_t extra_cr3, const std::uint32_t rva,
                                          std::uint32_t& begin_out, std::uint32_t& end_out, std::uint32_t& unwind_out)
{
	if (load_function_table(module, extra_cr3) == 0)
	{
		return 0;
	}

	const std::uint64_t count = module.functions.size() / 3;
	std::uint64_t low = 0;
	std::uint64_t high = count;

	while (low < high)
	{
		const std::uint64_t mid = low + (high - low) / 2;
		const std::uint32_t begin = module.functions[mid * 3];
		const std::uint32_t end = module.functions[mid * 3 + 1];

		if (rva < begin)
		{
			high = mid;
		}
		else if (rva >= end)
		{
			low = mid + 1;
		}
		else
		{
			begin_out = begin;
			end_out = end;
			unwind_out = module.functions[mid * 3 + 2];

			return 1;
		}
	}

	return 0;
}

static std::uint8_t emulate_epilog(stack_regs_t& regs, const std::uint64_t extra_cr3, std::uint64_t& child_sp_out, std::uint64_t& ret_out)
{
	std::uint64_t rip = regs.rip;
	stack_regs_t local = regs;

	for (std::uint32_t step = 0; step < 16; step++)
	{
		std::uint8_t bytes[15] = {};

		if (read_paused_block(rip, bytes, sizeof(bytes), extra_cr3) == 0)
		{
			return 0;
		}

		ZydisDecoder decoder = {};
		ZydisDecoderContext decoder_context = {};
		ZydisDecodedInstruction instruction = {};

		if (ZYAN_FAILED(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64)) ||
			ZYAN_FAILED(ZydisDecoderDecodeInstruction(&decoder, &decoder_context, bytes, sizeof(bytes), &instruction)))
		{
			return 0;
		}

		std::array<ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT> operands = {};

		if (ZYAN_FAILED(ZydisDecoderDecodeOperands(&decoder, &decoder_context, &instruction, operands.data(),
		                                           static_cast<ZyanU8>(operands.size()))))
		{
			return 0;
		}

		if (instruction.mnemonic == ZYDIS_MNEMONIC_RET)
		{
			std::uint64_t ret = 0;

			if (read_paused_block(local.rsp, &ret, sizeof(ret), extra_cr3) == 0)
			{
				return 0;
			}

			child_sp_out = local.rsp;
			ret_out = ret;
			local.rsp += 8;

			if (instruction.operand_count_visible > 0 && operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
			{
				local.rsp += operands[0].imm.value.u;
			}

			local.rip = ret;
			regs = local;

			return 1;
		}

		std::uint8_t rsp_index = 0;

		if (gpr_index(ZYDIS_REGISTER_RSP, rsp_index) == 0)
		{
			return 0;
		}

		if (instruction.mnemonic == ZYDIS_MNEMONIC_ADD && instruction.operand_count_visible >= 2 &&
			operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
		{
			std::uint8_t index = 0;

			if (gpr_index(operands[0].reg.value, index) == 0 || index != rsp_index)
			{
				return 0;
			}

			local.rsp += static_cast<std::uint64_t>(operands[1].imm.value.s);
		}
		else if (instruction.mnemonic == ZYDIS_MNEMONIC_LEA && instruction.operand_count_visible >= 2 &&
			operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
		{
			std::uint8_t index = 0;
			std::uint8_t base = 0;

			if (gpr_index(operands[0].reg.value, index) == 0 || index != rsp_index ||
				gpr_index(operands[1].mem.base, base) == 0)
			{
				return 0;
			}

			local.rsp = local.r[base] + static_cast<std::uint64_t>(operands[1].mem.disp.value);
		}
		else if (instruction.mnemonic == ZYDIS_MNEMONIC_POP && instruction.operand_count_visible >= 1 &&
			operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
		{
			std::uint8_t index = 0;
			std::uint64_t value = 0;

			if (gpr_index(operands[0].reg.value, index) == 0 ||
				read_paused_block(local.rsp, &value, sizeof(value), extra_cr3) == 0)
			{
				return 0;
			}

			local.r[index] = value;
			local.rsp += 8;
		}
		else
		{
			return 0;
		}

		rip += instruction.length;
	}

	return 0;
}

static std::uint8_t apply_unwind_codes(stack_regs_t& regs, const std::uint8_t* const info, const std::uint64_t info_size,
                                      const std::uint64_t extra_cr3, const std::uint8_t in_prolog, const std::uint32_t prolog_offset,
                                      std::uint8_t& machine_out, std::uint64_t& child_sp_out, std::uint64_t& ret_out, std::uint32_t& unwind_rva_out)
{
	const std::uint8_t version = info[0] & 7;
	const std::uint8_t flags = info[0] >> 3;
	const std::uint8_t count = info[2];
	const std::uint8_t frame_register = info[3] & 0xF;
	const std::uint8_t frame_offset = info[3] >> 4;

	machine_out = 0;
	unwind_rva_out = 0;

	if ((version != 1 && version != 2) || info_size < 4)
	{
		return 0;
	}

	std::uint32_t slot = 0;

	while (slot < count)
	{
		if (4 + slot * 2 + 1 >= info_size)
		{
			return 0;
		}

		const std::uint8_t code_offset = info[4 + slot * 2];
		const std::uint8_t op = info[5 + slot * 2] & 0xF;
		const std::uint8_t op_info = info[5 + slot * 2] >> 4;
		std::uint32_t extra = 0;
		std::uint32_t consumed = 1;

		if (op == 1 && op_info == 0)
		{
			consumed = 2;
		}
		else if (op == 1 || op == 5 || op == 9)
		{
			consumed = 3;
		}
		else if (op == 4 || op == 8)
		{
			consumed = 2;
		}

		if (slot + consumed > count || 4 + (slot + consumed) * 2 > info_size)
		{
			return 0;
		}

		if (consumed == 2)
		{
			std::memcpy(&extra, info + 4 + (slot + 1) * 2, sizeof(std::uint16_t));
		}
		else if (consumed == 3)
		{
			std::memcpy(&extra, info + 4 + (slot + 1) * 2, sizeof(extra));
		}

		slot += consumed;

		// Codes are stored from the end of the prolog. An op past the current
		// instruction has not executed yet.
		if (in_prolog == 1 && code_offset > prolog_offset)
		{
			continue;
		}

		if (op == 0)
		{
			std::uint64_t value = 0;

			if (op_info >= 16 || read_paused_block(regs.rsp, &value, sizeof(value), extra_cr3) == 0)
			{
				return 0;
			}

			regs.r[op_info] = value;
			regs.rsp += 8;
		}
		else if (op == 1 && op_info == 0)
		{
			regs.rsp += static_cast<std::uint64_t>(extra) * 8;
		}
		else if (op == 1 && op_info == 1)
		{
			regs.rsp += extra;
		}
		else if (op == 2)
		{
			regs.rsp += static_cast<std::uint64_t>(op_info) * 8 + 8;
		}
		else if (op == 3)
		{
			if (frame_register >= 16)
			{
				return 0;
			}

			regs.rsp = regs.r[frame_register] - static_cast<std::uint64_t>(frame_offset) * 16;
		}
		else if (op == 4)
		{
			std::uint64_t value = 0;

			if (op_info >= 16 || read_paused_block(regs.rsp + static_cast<std::uint64_t>(extra) * 8, &value, sizeof(value), extra_cr3) == 0)
			{
				return 0;
			}

			regs.r[op_info] = value;
		}
		else if (op == 5)
		{
			std::uint64_t value = 0;

			if (op_info >= 16 || read_paused_block(regs.rsp + extra, &value, sizeof(value), extra_cr3) == 0)
			{
				return 0;
			}

			regs.r[op_info] = value;
		}
		else if (op == 8 || op == 9)
		{
			continue;
		}
		else if (op == 10)
		{
			const std::uint64_t rip_slot = regs.rsp + (op_info == 0 ? 0 : 8);
			const std::uint64_t rsp_slot = regs.rsp + (op_info == 0 ? 24 : 32);
			std::uint64_t machine_rip = 0;
			std::uint64_t machine_rsp = 0;

			if (read_paused_block(rip_slot, &machine_rip, sizeof(machine_rip), extra_cr3) == 0 ||
				read_paused_block(rsp_slot, &machine_rsp, sizeof(machine_rsp), extra_cr3) == 0)
			{
				return 0;
			}

			child_sp_out = regs.rsp;
			ret_out = machine_rip;
			regs.rip = machine_rip;
			regs.rsp = machine_rsp;
			machine_out = 1;

			return 1;
		}
		else
		{
			return 0;
		}
	}

	if ((flags & 4) != 0)
	{
		const std::uint32_t aligned = (static_cast<std::uint32_t>(count) + 1u) & ~1u;

		if (4 + aligned * 2 + 12 > info_size)
		{
			return 0;
		}

		std::memcpy(&unwind_rva_out, info + 4 + aligned * 2 + 8, sizeof(unwind_rva_out));
	}

	return 1;
}

static std::uint8_t unwind_with_pdata(std::vector<stack_module_t>& modules, stack_regs_t& regs, const std::uint64_t extra_cr3,
                                      std::uint64_t& child_sp_out, std::uint64_t& ret_out)
{
	std::uint64_t base = 0;
	std::uint32_t image_size = 0;

	if (emulate_epilog(regs, extra_cr3, child_sp_out, ret_out) == 1)
	{
		return 1;
	}

	const stack_regs_t saved = regs;

	if (module_bounds(modules, regs.rip, base, image_size) == 0 || regs.rip < base)
	{
		return 0;
	}

	stack_module_t* module = nullptr;

	for (stack_module_t& candidate : modules)
	{
		if (candidate.base == base)
		{
			module = &candidate;

			break;
		}
	}

	if (module == nullptr)
	{
		return 0;
	}

	const std::uint32_t rva = static_cast<std::uint32_t>(regs.rip - base);
	std::uint32_t begin = 0;
	std::uint32_t end = 0;
	std::uint32_t unwind = 0;

	if (find_runtime_function(*module, extra_cr3, rva, begin, end, unwind) == 0 || unwind == 0)
	{
		regs = saved;

		return 0;
	}

	for (std::uint32_t chain = 0; chain < 4; chain++)
	{
		std::uint8_t info[512] = {};

		if (read_paused_block(base + unwind, info, sizeof(info), extra_cr3) == 0)
		{
			regs = saved;

			return 0;
		}

		const std::uint8_t in_prolog = static_cast<std::uint8_t>(chain == 0 && rva >= begin && rva - begin < info[1]);
		const std::uint32_t prolog_offset = rva >= begin ? rva - begin : 0;
		std::uint8_t machine = 0;
		std::uint32_t next_unwind = 0;

		if (apply_unwind_codes(regs, info, sizeof(info), extra_cr3, in_prolog, prolog_offset, machine, child_sp_out, ret_out, next_unwind) == 0)
		{
			regs = saved;

			return 0;
		}

		if (machine == 1)
		{
			return 1;
		}

		if (next_unwind == 0)
		{
			break;
		}

		unwind = next_unwind;
	}

	std::uint64_t ret = 0;

	if ((regs.rsp & 7) != 0 || read_paused_block(regs.rsp, &ret, sizeof(ret), extra_cr3) == 0)
	{
		regs = saved;

		return 0;
	}

	child_sp_out = regs.rsp;
	ret_out = ret;
	regs.rsp += 8;
	regs.rip = ret;

	return 1;
}

static std::uint8_t leaf_unwind(stack_regs_t& regs, const std::uint64_t extra_cr3, std::uint64_t& child_sp_out, std::uint64_t& ret_out)
{
	std::uint64_t ret = 0;

	if ((regs.rsp & 7) != 0 || read_paused_block(regs.rsp, &ret, sizeof(ret), extra_cr3) == 0 || canonical_code_address(ret) == 0)
	{
		return 0;
	}

	child_sp_out = regs.rsp;
	ret_out = ret;
	regs.rsp += 8;
	regs.rip = ret;

	return 1;
}

static void collect_stack_modules(const std::uint64_t cr3, std::vector<stack_module_t>& modules_out, std::uint64_t& extra_cr3_out)
{
	modules_out.clear();
	extra_cr3_out = 0;
	std::vector<reload_module_t> user_modules = {};

	if (collect_user_modules(cr3, user_modules) == 0)
	{
		const std::uint64_t eprocess = eprocess_for_cr3(cr3);
		const std::uint64_t user_cr3 = cr3_for_user_modules(eprocess);

		if (user_cr3 != 0)
		{
			extra_cr3_out = user_cr3;
			collect_user_modules(user_cr3, user_modules);
		}
	}

	for (const reload_module_t& module : user_modules)
	{
		stack_module_t entry = {};
		entry.base = module.base;
		entry.size = module.size;
		modules_out.push_back(std::move(entry));
	}

	for (const auto& [module_name, module_info] : sys::kernel::modules_list)
	{
		(void)module_name;
		stack_module_t entry = {};
		entry.base = module_info.base_address;
		entry.size = module_info.size;
		modules_out.push_back(std::move(entry));
	}
}

static std::string stack_call_site(const std::uint64_t address)
{
	std::string name = {};
	std::uint64_t displacement = 0;

	if (address == 0)
	{
		return "00000000`00000000";
	}

	if (symbol_parser::nearest(address, name, displacement) == 1 && name.empty() == false)
	{
		if (displacement == 0)
		{
			return name;
		}

		return fmt::format("{}+0x{:x}", name, displacement);
	}

	return format_windbg_address(address);
}

static std::string stack_qword(const std::uint8_t valid, const std::uint64_t value)
{
	if (valid == 0)
	{
		return "????????`????????";
	}

	return format_windbg_address(value);
}

static void read_frame_args(stack_frame_t& frame, const std::uint64_t extra_cr3, const std::uint32_t count)
{
	for (std::uint32_t index = 0; index < count && index < 4; index++)
	{
		const std::uint64_t address = frame.child_sp + 8 + static_cast<std::uint64_t>(index) * 8;
		frame.args_valid[index] = read_paused_block(address, &frame.args[index], sizeof(frame.args[index]), extra_cr3);
	}
}

static std::uint8_t build_stack_frames(const breakpoint::registers_t& registers, const std::uint64_t frame_count, std::vector<stack_frame_t>& frames_out)
{
	std::vector<stack_module_t> modules = {};
	std::uint64_t extra_cr3 = 0;
	stack_regs_t regs = {};

	frames_out.clear();
	collect_stack_modules(registers.cr3, modules, extra_cr3);
	load_stack_regs(registers, regs);

	if (regs.rsp == 0 || canonical_code_address(regs.rip) == 0)
	{
		return 0;
	}

	for (std::uint64_t index = 0; index < frame_count; index++)
	{
		stack_frame_t frame = {};
		frame.rip = regs.rip;
		std::uint64_t child_sp = 0;
		std::uint64_t ret = 0;
		const std::uint64_t previous_rsp = regs.rsp;

		if (unwind_with_pdata(modules, regs, extra_cr3, child_sp, ret) == 0 && leaf_unwind(regs, extra_cr3, child_sp, ret) == 0)
		{
			frame.child_sp = previous_rsp;
			frames_out.push_back(frame);

			break;
		}

		frame.child_sp = child_sp;
		frame.ret = ret;
		frame.has_ret = 1;
		read_frame_args(frame, extra_cr3, 4);
		frames_out.push_back(frame);

		if (ret == 0 || canonical_code_address(regs.rip) == 0 || regs.rsp <= previous_rsp)
		{
			break;
		}
	}

	return static_cast<std::uint8_t>(frames_out.empty() == false);
}

static void print_stack_frames(const std::vector<stack_frame_t>& frames, const stack_style_t style, const std::uint8_t show_size)
{
	if (style == stack_style_t::verbose)
	{
		fmt::print(" # Child-SP          RetAddr               : Args to Child                                                           : Call Site\n");
	}
	else if (style == stack_style_t::args3)
	{
		fmt::print(" # Child-SP          RetAddr               : Args to Child                                      : Call Site\n");
	}
	else if (style == stack_style_t::dump)
	{
		fmt::print(" # Child-SP          RetAddr               Memory\n");
	}
	else if (style == stack_style_t::params)
	{
		fmt::print(" # Call Site\n");
	}
	else
	{
		fmt::print(" # Child-SP          RetAddr               Call Site\n");
	}

	for (std::uint64_t index = 0; index < frames.size(); index++)
	{
		const stack_frame_t& frame = frames[index];
		const std::string site = stack_call_site(frame.rip);
		const std::string ret = frame.has_ret == 1 ? format_windbg_address(frame.ret) : std::string("????????`????????");
		std::string size_text = {};

		if (show_size == 1 && index > 0 && frame.child_sp > frames[index - 1].child_sp)
		{
			size_text = fmt::format("{:x}", frame.child_sp - frames[index - 1].child_sp);
		}

		if (style == stack_style_t::params)
		{
			fmt::print("{:02x} {}{}\n", index, size_text.empty() == true ? "" : "[" + size_text + "] ", site);

			for (std::uint32_t arg = 0; arg < 4; arg++)
			{
				fmt::print("            Parameter[{}] = {}\n", arg, stack_qword(frame.args_valid[arg], frame.args[arg]));
			}

			continue;
		}

		fmt::print("{:02x} {} {} ", index, format_windbg_address(frame.child_sp), ret);

		if (style == stack_style_t::args3 || style == stack_style_t::verbose)
		{
			const std::uint32_t arg_count = style == stack_style_t::args3 ? 3 : 4;
			fmt::print(": ");

			for (std::uint32_t arg = 0; arg < arg_count; arg++)
			{
				fmt::print("{}{}", stack_qword(frame.args_valid[arg], frame.args[arg]), arg + 1 == arg_count ? "" : " ");
			}

			fmt::print(" : {}", site);
		}
		else if (style == stack_style_t::dump)
		{
			fmt::print("{} {} {}", ret, stack_qword(frame.args_valid[0], frame.args[0]), stack_qword(frame.args_valid[1], frame.args[1]));
			fmt::print(" {}", site);
		}
		else
		{
			fmt::print("{}", site);
		}

		if (show_size == 1 && size_text.empty() == false)
		{
			fmt::print(" ({})", size_text);
		}

		fmt::print("\n");
	}

	std::fflush(stdout);
}

static std::uint8_t stack_style_letter(const std::string_view text, stack_style_t& style_out)
{
	if (equals_ignore_case(text, "b") == 1)
	{
		style_out = stack_style_t::args3;

		return 1;
	}

	if (equals_ignore_case(text, "d") == 1)
	{
		style_out = stack_style_t::dump;

		return 1;
	}

	if (equals_ignore_case(text, "p") == 1 || equals_ignore_case(text, "v") == 1)
	{
		style_out = equals_ignore_case(text, "v") == 1 ? stack_style_t::verbose : stack_style_t::params;

		return 1;
	}

	return 0;
}

static void process_k(const CLI::App* const command)
{
	stack_style_t style = stack_style_t::plain;
	std::uint8_t show_size = 0;
	std::uint64_t frame_count = 20;

	for (const std::string& arg : command->remaining())
	{
		if (equals_ignore_case(arg, "n") == 1)
		{
			continue;
		}

		if (equals_ignore_case(arg, "f") == 1)
		{
			show_size = 1;

			continue;
		}

		stack_style_t parsed = stack_style_t::plain;

		if (stack_style_letter(arg, parsed) == 1)
		{
			style = parsed;

			continue;
		}

		if (parse_windbg_number(arg, frame_count) == 0 || frame_count == 0 || frame_count > 128)
		{
			LOG_ERR("syntax: k[b|d|p|v] [n] [f] [frame count]");

			return;
		}
	}

	if (breakpoint::has_paused_thread() == 0)
	{
		LOG_ERR("no paused thread");

		return;
	}

	breakpoint::registers_t registers = {};

	if (breakpoint::paused_registers(registers) == 0)
	{
		LOG_ERR("no paused thread");

		return;
	}

	std::vector<stack_frame_t> frames = {};

	if (build_stack_frames(registers, frame_count, frames) == 0)
	{
		LOG_ERR("failed to read the stack");

		return;
	}

	print_stack_frames(frames, style, show_size);
}

static std::uint8_t rewrite_stack_command(const std::string_view token, std::string& rewritten_out)
{
	if (token.empty() == true || (token[0] != 'k' && token[0] != 'K'))
	{
		return 0;
	}

	std::uint8_t seen_style = 0;
	std::uint8_t seen_n = 0;
	std::uint8_t seen_f = 0;
	std::string style = {};

	for (std::size_t index = 1; index < token.size(); index++)
	{
		const char character = static_cast<char>(std::tolower(static_cast<unsigned char>(token[index])));

		if ((character == 'b' || character == 'd' || character == 'p' || character == 'v') && seen_style == 0)
		{
			seen_style = 1;
			style = character;

			continue;
		}

		if (character == 'n' && seen_n == 0)
		{
			seen_n = 1;

			continue;
		}

		if (character == 'f' && seen_f == 0)
		{
			seen_f = 1;

			continue;
		}

		return 0;
	}

	rewritten_out = "k";

	if (style.empty() == false)
	{
		rewritten_out.push_back(' ');
		rewritten_out += style;
	}

	if (seen_n == 1)
	{
		rewritten_out += " n";
	}

	if (seen_f == 1)
	{
		rewritten_out += " f";
	}

	return 1;
}

static void process_lmi(const CLI::App* const command)
{
	const std::vector<std::string> args = command->remaining();

	if (args.size() != 1)
	{
		LOG_ERR("syntax: lmi <module>");

		return;
	}

	std::vector<reload_module_t> modules = {};
	std::uint8_t user_modules = 0;

	if (collect_named_modules(args[0], 0, modules, user_modules) == 0)
	{
		return;
	}

	lm_options_t options = {};
	options.verbose = 1;
	const std::vector<symbol_parser::module_status_t> loaded = symbol_parser::loaded_modules();

	for (const reload_module_t& module : modules)
	{
		fmt::print("Loaded Module Info: [{}]\n", module_display_name(module.name));
		std::uint64_t shown = 0;
		std::vector<reload_module_t> one = { module };
		print_lm_modules(one, options, loaded, shown);
	}
}

static void process_ld(const CLI::App* const command)
{
	const std::vector<std::string> args = command->remaining();
	std::uint8_t user_only = 0;
	std::string pattern = {};

	for (const std::string& token : args)
	{
		if (equals_ignore_case(token, "/user") == 1)
		{
			user_only = 1;

			continue;
		}

		if (pattern.empty() == false)
		{
			LOG_ERR("syntax: ld <module>");

			return;
		}

		pattern = token;
	}

	if (pattern.empty() == true)
	{
		LOG_ERR("syntax: ld <module>");

		return;
	}

	if (pattern == "." || pattern == "*")
	{
		pattern = "*";
	}

	std::vector<reload_module_t> modules = {};
	std::uint8_t user_modules = 0;

	if (collect_named_modules(pattern, user_only, modules, user_modules) == 0)
	{
		return;
	}

	force_load_listed_modules(modules, user_modules);
}

static std::string format_nearest_symbol(const std::uint64_t address)
{
	if (address == 0)
	{
		return {};
	}

	std::string name = {};
	std::uint64_t displacement = 0;

	if (symbol_parser::nearest(address, name, displacement) == 0 || name.empty() == true)
	{
		return {};
	}

	if (displacement == 0)
	{
		return name;
	}

	return fmt::format("{}+0x{:x}", name, displacement);
}

static void display_symbolized_memory(const CLI::App* const command, const std::uint64_t element_size)
{
	const std::unordered_map<std::string, std::uint64_t> aliases = sys::kernel::compile_symbol_list();
	windbg_range_request_t request = {};

	if (parse_windbg_range(command->remaining(), aliases, display_default_bytes / element_size, unassemble_next_address,
	                       unassemble_has_next_address, "length", "no current address", request) == 0)
	{
		return;
	}

	std::uint64_t count = request.count;

	if (request.is_range == 1)
	{
		if (request.end_address <= request.start_address)
		{
			LOG_ERR("empty range");

			return;
		}

		count = (request.end_address - request.start_address) / element_size;
	}

	if (count == 0)
	{
		LOG_ERR("length is zero");

		return;
	}

	if (count > unassemble_max_range_bytes / element_size)
	{
		LOG_ERR("length is above 0x{:x}", unassemble_max_range_bytes / element_size);

		return;
	}

	const std::uint64_t bytes_to_read = count * element_size;

	if (request.start_address + bytes_to_read < request.start_address)
	{
		LOG_ERR("address range wraps");

		return;
	}

	const std::uint64_t read_cr3 = cr3_for_guest_address(request.start_address);

	if (read_cr3 == 0)
	{
		LOG_ERR("current cr3 is not set");

		return;
	}

	std::vector<std::uint8_t> buffer(static_cast<std::size_t>(bytes_to_read));
	const std::uint64_t bytes_read = hypercall::read_guest_virtual_memory(
		buffer.data(), request.start_address, read_cr3, bytes_to_read);

	if (bytes_read < element_size)
	{
		LOG_ERR("failed to read");

		return;
	}

	const std::uint64_t available = bytes_read - (bytes_read % element_size);

	for (std::uint64_t offset = 0; offset < available; offset += element_size)
	{
		const std::uint64_t value = read_little_endian(buffer.data() + offset, element_size);
		const std::uint64_t address = request.start_address + offset;
		const std::string symbol = format_nearest_symbol(value);

		if (element_size == 8)
		{
			fmt::print("{}  {}", format_windbg_address(address), format_windbg_address(value));
		}
		else
		{
			fmt::print("{}  {:08x}", format_windbg_address(address), static_cast<std::uint32_t>(value));
		}

		if (symbol.empty() == false)
		{
			fmt::print(" {}", symbol);
		}

		fmt::print("\n");
	}

	remember_display_address(request.start_address + available);

	if (bytes_read < bytes_to_read)
	{
		LOG_ERR("failed to read");
	}
}

static void process_dps(const CLI::App* const command)
{
	display_symbolized_memory(command, 8);
}

static void process_dqs(const CLI::App* const command)
{
	display_symbolized_memory(command, 8);
}

static void process_dds(const CLI::App* const command)
{
	display_symbolized_memory(command, 4);
}

static std::string format_type_value(const symbol_parser::type_field_t& field, const std::uint64_t raw)
{
	if (field.pointer == 1 || field.size == 8)
	{
		std::string text = format_windbg_address(raw);
		const std::string symbol = format_nearest_symbol(raw);

		if (symbol.empty() == false)
		{
			text += " ";
			text += symbol;
		}

		return text;
	}

	if (field.size == 4)
	{
		return fmt::format("{:08x}", static_cast<std::uint32_t>(raw));
	}

	if (field.size == 2)
	{
		return fmt::format("{:04x}", static_cast<std::uint16_t>(raw));
	}

	return fmt::format("{:02x}", static_cast<std::uint8_t>(raw));
}

static void process_dt(const CLI::App* const command)
{
	const std::vector<std::string> args = command->remaining();

	if (args.empty() == true)
	{
		LOG_ERR("syntax: dt <module>!<type> [address] [field]");

		return;
	}

	const std::string& spec = args[0];
	std::string module = {};
	std::string type_name = spec;
	const std::size_t bang = spec.find('!');

	if (bang != std::string::npos)
	{
		module = spec.substr(0, bang);
		type_name = spec.substr(bang + 1);
	}

	if (type_name.empty() == true)
	{
		LOG_ERR("syntax: dt <module>!<type> [address] [field]");

		return;
	}

	symbol_parser::type_info_t info = {};
	std::string detail = {};

	if (symbol_parser::query_type(module, type_name, info, detail) == 0)
	{
		LOG_ERR("{}", detail);

		return;
	}

	const std::unordered_map<std::string, std::uint64_t> aliases = sys::kernel::compile_symbol_list();
	std::uint64_t address = 0;
	std::uint8_t has_address = 0;
	std::vector<std::string> field_filters = {};

	for (std::size_t index = 1; index < args.size(); index++)
	{
		std::uint8_t field_match = 0;

		for (const symbol_parser::type_field_t& field : info.fields)
		{
			if (equals_ignore_case(field.name, args[index]) == 1)
			{
				field_match = 1;

				break;
			}
		}

		if (field_match == 1)
		{
			field_filters.push_back(args[index]);

			continue;
		}

		std::uint64_t value = 0;

		if (has_address == 0 && resolve_windbg_address(aliases, args[index], value) == 1)
		{
			address = value;
			has_address = 1;

			continue;
		}

		LOG_ERR("invalid dt argument: {}", args[index]);

		return;
	}

	std::size_t width = 8;

	for (const symbol_parser::type_field_t& field : info.fields)
	{
		if (field.name.size() > width && field.name.size() <= 40)
		{
			width = field.name.size();
		}
	}

	fmt::print("{}!{}\n", info.module, info.name);
	std::uint64_t shown = 0;
	const std::uint64_t read_cr3 = has_address == 1 ? cr3_for_guest_address(address) : sys::current_cr3;

	for (const symbol_parser::type_field_t& field : info.fields)
	{
		if (field_filters.empty() == false)
		{
			std::uint8_t selected = 0;

			for (const std::string& filter : field_filters)
			{
				if (equals_ignore_case(field.name, filter) == 1)
				{
					selected = 1;

					break;
				}
			}

			if (selected == 0)
			{
				continue;
			}
		}

		shown += 1;

		if (field.bitfield == 1)
		{
			fmt::print("   +0x{:03x} {:<{}} : Pos {}, {} Bit\n", field.offset, field.name, width, field.bit_position, field.bit_length);

			continue;
		}

		std::string value_text = {};

		if (has_address == 1 && read_cr3 != 0 && (field.integer == 1 || field.pointer == 1) && field.size >= 1 && field.size <= 8 &&
			address + field.offset >= address)
		{
			std::uint64_t raw = 0;

			if (hypercall::read_guest_virtual_memory(&raw, address + field.offset, read_cr3, field.size) == field.size)
			{
				value_text = format_type_value(field, raw);
			}
		}

		if (value_text.empty() == true)
		{
			fmt::print("   +0x{:03x} {:<{}} : {}\n", field.offset, field.name, width, field.type_name);
		}
		else
		{
			fmt::print("   +0x{:03x} {:<{}} : {} {}\n", field.offset, field.name, width, value_text, field.type_name);
		}
	}

	if (shown == 0)
	{
		LOG_ERR("field not found");
	}
}

static void process_symopt(const CLI::App* const command)
{
	(void)command;
	fmt::print("Symbol options are: 0x{:x}\n", symbol_parser::options());
	fmt::print("Symbol search path is: {}\n", symbol_parser::search_path().empty() == true ? "(empty)" : symbol_parser::search_path());
}

static void process_examine(const CLI::App* const command)
{
	(void)command;
	const std::string mask = symbol_command_text("x");
	const std::size_t bang = mask.find('!');

	if (mask.empty() == true || bang == std::string::npos || bang == 0 || bang + 1 >= mask.size())
	{
		LOG_ERR("syntax: x <module>!<symbol>");

		return;
	}

	const std::string module = mask.substr(0, bang);
	const std::string symbol = mask.substr(bang + 1);
	const std::uint8_t wildcard = static_cast<std::uint8_t>(symbol.find_first_of("*?") != std::string::npos);
	constexpr std::size_t match_limit = 128;

	const std::unordered_map<std::string, std::uint64_t> aliases = sys::kernel::compile_symbol_list();

	if (wildcard == 0)
	{
		std::uint64_t address = 0;

		if (lookup_module_symbol(aliases, module, symbol, address) == 0)
		{
			LOG_ERR("symbol not found");

			return;
		}

		fmt::print("{:016x} {}!{}\n", address, module, symbol);

		return;
	}

	std::vector<symbol_parser::symbol_match_t> matches = symbol_parser::enumerate(module, symbol, match_limit + 1);

	if (matches.empty() == true)
	{
		for (const auto& [full_name, address] : aliases)
		{
			const std::size_t export_bang = full_name.find('!');

			if (export_bang == std::string::npos || export_bang == 0 || export_bang + 1 >= full_name.size())
			{
				continue;
			}

			const std::string_view export_module(full_name.data(), export_bang);
			const std::string_view export_symbol(full_name.data() + export_bang + 1, full_name.size() - export_bang - 1);
			const std::uint8_t module_match = static_cast<std::uint8_t>(
				equals_ignore_case(export_module, module) == 1 || equals_ignore_case(module_stem(export_module), module) == 1 ||
				(equals_ignore_case(module, "nt") == 1 && is_ntoskrnl_module(export_module) == 1));

			if (module_match == 0 || wildcard_match(export_symbol, symbol) == 0)
			{
				continue;
			}

			symbol_parser::symbol_match_t match = {};
			match.name = std::string(module) + "!" + std::string(export_symbol);
			match.address = address;
			matches.push_back(std::move(match));

			if (matches.size() > match_limit)
			{
				break;
			}
		}
	}

	if (matches.empty() == true)
	{
		LOG_ERR("no matching symbols");

		return;
	}

	const std::size_t shown = matches.size() > match_limit ? match_limit : matches.size();

	for (std::size_t index = 0; index < shown; index++)
	{
		fmt::print("{:016x} {}\n", matches[index].address, matches[index].name);
	}

	if (matches.size() > match_limit)
	{
		fmt::print("output truncated at {} matches\n", match_limit);
	}
}

static void process_nearest(const CLI::App* const command)
{
	(void)command;
	const std::string text = symbol_command_text("ln");
	std::uint64_t address = 0;

	if (text.empty() == true)
	{
		breakpoint::registers_t registers = {};

		if (breakpoint::paused_registers(registers) == 0)
		{
			LOG_ERR("syntax: ln <address>");

			return;
		}

		address = registers.rip;
	}
	else
	{
		const std::unordered_map<std::string, std::uint64_t> aliases = sys::kernel::compile_symbol_list();

		if (resolve_windbg_address(aliases, text, address) == 0)
		{
			LOG_ERR("invalid address");

			return;
		}
	}

	std::string name = {};
	std::uint64_t displacement = 0;

	if (symbol_parser::nearest(address, name, displacement) == 0)
	{
		LOG_ERR("no symbol found");

		return;
	}

	if (displacement == 0)
	{
		fmt::print("{:016x} {}\n", address, name);
	}
	else
	{
		fmt::print("{:016x} {}+{:x}\n", address, name, displacement);
	}
}

static void clear_console_screen()
{
	const HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
	CONSOLE_SCREEN_BUFFER_INFO info = {};

	if (GetConsoleScreenBufferInfo(output, &info) == 0)
	{
		fmt::print("\n");

		return;
	}

	const DWORD cells = static_cast<DWORD>(info.dwSize.X) * static_cast<DWORD>(info.dwSize.Y);
	DWORD written = 0;
	const COORD origin = { 0, 0 };
	FillConsoleOutputCharacterA(output, ' ', cells, origin, &written);
	FillConsoleOutputAttribute(output, info.wAttributes, cells, origin, &written);
	SetConsoleCursorPosition(output, origin);
}

static void process_cls(const CLI::App* const)
{
	clear_console_screen();
}

static void process_echo(const CLI::App* const)
{
	fmt::print("{}\n", symbol_command_text(".echo"));
	std::fflush(stdout);
}

static std::uint8_t take_command_token(std::string_view& text, std::string& token_out)
{
	text = skip_whitespace(text);

	if (text.empty() == true)
	{
		return 0;
	}

	if (text.front() == '"')
	{
		text.remove_prefix(1);
		token_out.clear();

		while (text.empty() == false && text.front() != '"')
		{
			token_out.push_back(text.front());
			text.remove_prefix(1);
		}

		if (text.empty() == false && text.front() == '"')
		{
			text.remove_prefix(1);
		}

		text = skip_whitespace(text);

		if (text.empty() == false && text.front() == ',')
		{
			text.remove_prefix(1);
		}

		return 1;
	}

	std::size_t length = 0;

	while (length < text.size() && text[length] != ' ' && text[length] != '\t' && text[length] != ',')
	{
		length += 1;
	}

	token_out = std::string(text.substr(0, length));
	text.remove_prefix(length);
	text = skip_whitespace(text);

	if (text.empty() == false && text.front() == ',')
	{
		text.remove_prefix(1);
	}

	return 1;
}

static void print_format_text(const std::string_view format, std::string_view arguments)
{
	const std::unordered_map<std::string, std::uint64_t> aliases = sys::kernel::compile_symbol_list();

	for (std::size_t index = 0; index < format.size(); index++)
	{
		const char character = format[index];

		if (character == '\\' && index + 1 < format.size())
		{
			const char escaped = format[index + 1];
			index += 1;

			if (escaped == 'n')
			{
				fmt::print("\n");
			}
			else if (escaped == 't')
			{
				fmt::print("\t");
			}
			else if (escaped == 'r')
			{
				fmt::print("\r");
			}
			else
			{
				fmt::print("{}", escaped);
			}

			continue;
		}

		if (character != '%' || index + 1 >= format.size())
		{
			fmt::print("{}", character);

			continue;
		}

		const char specifier = format[index + 1];
		index += 1;

		if (specifier == '%')
		{
			fmt::print("%");

			continue;
		}

		std::string token = {};

		if (take_command_token(arguments, token) == 0)
		{
			LOG_ERR("missing argument for %{}", specifier);

			return;
		}

		if (specifier == 's')
		{
			fmt::print("{}", token);

			continue;
		}

		std::uint64_t value = 0;

		if (resolve_windbg_address(aliases, token, value) == 0)
		{
			LOG_ERR("invalid expression: {}", token);

			return;
		}

		if (specifier == 'd' || specifier == 'i')
		{
			fmt::print("{}", static_cast<std::int64_t>(value));
		}
		else if (specifier == 'u')
		{
			fmt::print("{}", value);
		}
		else if (specifier == 'x' || specifier == 'X' || specifier == 'p')
		{
			fmt::print("{:x}", value);
		}
		else
		{
			LOG_ERR("unsupported format specifier %{}", specifier);

			return;
		}
	}

	std::fflush(stdout);
}

static void process_printf(const CLI::App* const)
{
	const std::string remainder = symbol_command_text(".printf");
	std::string_view text = skip_whitespace(remainder);

	if (text.empty() == true)
	{
		LOG_ERR("syntax: .printf \"format\" [argument]");

		return;
	}

	std::string format = {};

	if (text.front() == '"')
	{
		if (take_command_token(text, format) == 0)
		{
			LOG_ERR("syntax: .printf \"format\" [argument]");

			return;
		}
	}
	else
	{
		format = std::string(text);
		text = {};
	}

	print_format_text(format, text);
}

static void print_expression_formats(const std::uint64_t value)
{
	fmt::print("Evaluate expression: {:08x}`{:08x} = {}\n", static_cast<std::uint32_t>(value >> 32),
	           static_cast<std::uint32_t>(value), value);
	fmt::print("Hex:     {:016x}\n", value);
	fmt::print("Decimal: {}\n", value);
	fmt::print("Octal:   {:o}\n", value);
	fmt::print("Binary:  ");

	for (int shift = 63; shift >= 0; shift--)
	{
		fmt::print("{}", (value >> shift) & 1);

		if (shift % 8 == 0 && shift != 0)
		{
			fmt::print(" ");
		}
	}

	fmt::print("\nChars:   ");

	for (int shift = 0; shift < 64; shift += 8)
	{
		const unsigned char character = static_cast<unsigned char>((value >> shift) & 0xff);
		fmt::print("{}", character >= 0x20 && character < 0x7f ? static_cast<char>(character) : '.');
	}

	fmt::print("\n");
	std::fflush(stdout);
}

static void process_formats(const CLI::App* const)
{
	const std::string text = symbol_command_text(".formats");

	if (text.empty() == true)
	{
		LOG_ERR("syntax: .formats <expression>");

		return;
	}

	const std::unordered_map<std::string, std::uint64_t> aliases = sys::kernel::compile_symbol_list();
	std::uint64_t value = 0;

	if (resolve_windbg_address(aliases, text, value) == 0)
	{
		LOG_ERR("invalid expression: {}", text);

		return;
	}

	print_expression_formats(value);
}

static void process_time(const CLI::App* const)
{
	SYSTEMTIME time = {};
	GetLocalTime(&time);
	fmt::print("Debugger time: {:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}\n", time.wYear, time.wMonth, time.wDay, time.wHour,
	           time.wMinute, time.wSecond, time.wMilliseconds);
	std::fflush(stdout);
}

static void process_version(const CLI::App* const)
{
	std::uint32_t driver_major = 0;
	std::uint32_t driver_minor = 0;
	std::uint32_t driver_patch = 0;
	std::uint32_t driver_abi = 0;
	std::string driver_version;

	fmt::print("HacDbg usermode: {}\n", HACDBG_VERSION_STRING);

	if (hypercall::query_driver_version(driver_major, driver_minor, driver_patch, driver_abi,
	                                    driver_version) == 1)
	{
		fmt::print("HacDbg hypervisor: {}\n", driver_version);

		if (driver_version != HACDBG_VERSION_STRING)
		{
			fmt::print("Version mismatch: usermode {} hypervisor {}\n", HACDBG_VERSION_STRING,
			           driver_version);
		}
	}
	else
	{
		fmt::print("HacDbg hypervisor: unavailable\n");
	}

	const std::string path = symbol_parser::search_path();
	fmt::print("Symbol search path: {}\n", path.empty() == true ? "(empty)" : path);
	std::fflush(stdout);
}

static void process_help(const CLI::App* const)
{
	fmt::print("Display:    db dw dd dq dp dc da du dds dps dqs\n");
	fmt::print("Enter:      eb ew ed eq ep ea eu eza ezu\n");
	fmt::print("Unassemble: u\n");
	fmt::print("Breakpoint: bp bl bc bd be\n");
	fmt::print("Execute:    g t p tc tt tct pc pt pct\n");
	fmt::print("Stack:      k kb kd kp kv\n");
	fmt::print("Register:   r .thread\n");
	fmt::print("Symbol:     .sympath .sympath+ .symfix .symfix+ .reload .symopt lm lmi ld x ln dt\n");
	fmt::print("Process:    !process .process .detach !thread\n");
	fmt::print("Misc:       .cls .echo .printf .formats ? .time version .help q\n");
	fmt::print("Guest:      rgpm wgpm cgpm gvat rgvm wgvm cgvm gva\n");
	fmt::print("Hook:       akh rkh hgpp fl hfpc lkm kme dkm\n");
	std::fflush(stdout);
}

static std::string normalize_symbol_command(const std::string& command)
{
	const std::string_view trimmed = skip_whitespace(command);
	std::string_view text = trimmed;

	if (text.empty() == false && text.front() == '!')
	{
		text.remove_prefix(1);
		text = skip_whitespace(text);
	}

	if (text.empty() == false && text.front() == '?')
	{
		return std::string(".formats") + std::string(text.substr(1));
	}

	const std::size_t end = text.find_first_of(" \t");
	const std::string_view token = text.substr(0, end);
	const std::string_view rest = end == std::string_view::npos ? std::string_view() : text.substr(end);

	if (token.size() > 2 && equals_ignore_case(token.substr(0, 2), "lm") == 1 && equals_ignore_case(token, "lmi") == 0)
	{
		const std::string_view flags = token.substr(2);
		std::uint8_t flags_only = 1;

		for (const char character : flags)
		{
			if (lm_flag_character(character) == 0)
			{
				flags_only = 0;

				break;
			}
		}

		if (flags_only == 1)
		{
			std::string rewritten = "lm";

			for (const char character : flags)
			{
				rewritten.push_back(' ');
				rewritten.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(character))));
			}

			rewritten.append(rest);

			return rewritten;
		}
	}

	std::string stack_command = {};

	if (rewrite_stack_command(token, stack_command) == 1)
	{
		stack_command.append(rest);

		return stack_command;
	}

	return std::string(text);
}

std::uint8_t commands::is_quit_command(const std::string& command)
{
	std::string_view text = skip_whitespace(command);

	while (text.empty() == false && (text.back() == ' ' || text.back() == '\t'))
	{
		text.remove_suffix(1);
	}

	return static_cast<std::uint8_t>(equals_ignore_case(text, "exit") == 1 || equals_ignore_case(text, "q") == 1 ||
		equals_ignore_case(text, "qq") == 1 || equals_ignore_case(text, ".quit") == 1);
}

void commands::process(const std::string& command)
{
	if (command.empty())
	{
		return;
	}

	const std::string parsed_command = normalize_symbol_command(command);
	windbg_command_line = parsed_command;

	CLI::App app;
	app.require_subcommand(1);

	sys::kernel::parse_modules();

	const std::unordered_map<std::string, std::uint64_t> aliases = sys::kernel::compile_symbol_list();

	const auto aliases_transformer = CLI::Transformer(aliases, CLI::ignore_case);

	const CLI::App* const rgpm = init_rgpm(app, aliases_transformer);
	const CLI::App* const wgpm = init_wgpm(app, aliases_transformer);
	const CLI::App* const cgpm = init_cgpm(app, aliases_transformer);
	const CLI::App* const gvat = init_gvat(app, aliases_transformer);
	const CLI::App* const rgvm = init_rgvm(app, aliases_transformer);
	const CLI::App* const wgvm = init_wgvm(app, aliases_transformer);
	const CLI::App* const cgvm = init_cgvm(app, aliases_transformer);
	const CLI::App* const akh = init_akh(app, aliases_transformer);
	const CLI::App* const rkh = init_rkh(app, aliases_transformer);
	const CLI::App* const gva = init_gva(app, aliases_transformer);
	const CLI::App* const hgpp = init_hgpp(app, aliases_transformer);
	const CLI::App* const fl = init_fl(app);
	CLI::App* const hfpc = init_hfpc(app);
	CLI::App* const lkm = init_lkm(app);
	const CLI::App* const kme = init_kme(app);
	const CLI::App* const dkm = init_dkm(app);
	const CLI::App* const u = init_u(app);
	const CLI::App* const db = init_windbg_command(app, "db", "displays guest bytes and ASCII (WinDbg syntax)");
	const CLI::App* const dw = init_windbg_command(app, "dw", "displays guest words (WinDbg syntax)");
	const CLI::App* const dd = init_windbg_command(app, "dd", "displays guest double-words (WinDbg syntax)");
	const CLI::App* const dq = init_windbg_command(app, "dq", "displays guest quad-words (WinDbg syntax)");
	const CLI::App* const dp = init_windbg_command(app, "dp", "displays guest pointer-sized values (WinDbg syntax)");
	const CLI::App* const dc = init_windbg_command(app, "dc", "displays guest double-words and ASCII (WinDbg syntax)");
	const CLI::App* const da = init_windbg_command(app, "da", "displays a guest ASCII string (WinDbg syntax)");
	const CLI::App* const du = init_windbg_command(app, "du", "displays a guest Unicode string (WinDbg syntax)");
	const CLI::App* const eb = init_windbg_command(app, "eb", "enters guest bytes (WinDbg syntax)");
	const CLI::App* const ew = init_windbg_command(app, "ew", "enters guest words (WinDbg syntax)");
	const CLI::App* const ed = init_windbg_command(app, "ed", "enters guest double-words (WinDbg syntax)");
	const CLI::App* const eq = init_windbg_command(app, "eq", "enters guest quad-words (WinDbg syntax)");
	const CLI::App* const ep = init_windbg_command(app, "ep", "enters guest pointer-sized values (WinDbg syntax)");
	const CLI::App* const ea = init_windbg_command(app, "ea", "enters a guest ASCII string (WinDbg syntax)");
	const CLI::App* const eu = init_windbg_command(app, "eu", "enters a guest Unicode string (WinDbg syntax)");
	const CLI::App* const eza = init_windbg_command(app, "eza", "enters a guest ASCII string and a null (WinDbg syntax)");
	const CLI::App* const ezu = init_windbg_command(app, "ezu", "enters a guest Unicode string and a null (WinDbg syntax)");
	const CLI::App* const bp = init_windbg_command(app, "bp", "sets an execution breakpoint (WinDbg syntax)");
	const CLI::App* const g = init_windbg_command(app, "g", "resumes a paused user breakpoint");
	const CLI::App* const k = init_windbg_command(app, "k", "displays the paused thread stack (WinDbg syntax)");
	const CLI::App* const r = init_windbg_command(app, "r", "displays or sets the paused thread registers (WinDbg syntax)");
	const CLI::App* const t = init_windbg_command(app, "t", "traces one instruction into calls (WinDbg syntax)");
	const CLI::App* const p = init_windbg_command(app, "p", "steps one instruction over calls (WinDbg syntax)");
	const CLI::App* const tc = init_windbg_command(app, "tc", "traces to the next call (WinDbg syntax)");
	const CLI::App* const tt = init_windbg_command(app, "tt", "traces to the next return (WinDbg syntax)");
	const CLI::App* const tct = init_windbg_command(app, "tct", "traces to the next call or return (WinDbg syntax)");
	const CLI::App* const pc = init_windbg_command(app, "pc", "steps to the next call (WinDbg syntax)");
	const CLI::App* const pt = init_windbg_command(app, "pt", "steps to the next return (WinDbg syntax)");
	const CLI::App* const pct = init_windbg_command(app, "pct", "steps to the next call or return (WinDbg syntax)");
	const CLI::App* const bl = init_windbg_command(app, "bl", "lists execution breakpoints (WinDbg syntax)");
	const CLI::App* const bc = init_windbg_command(app, "bc", "clears execution breakpoints (WinDbg syntax)");
	const CLI::App* const bd = init_windbg_command(app, "bd", "disables execution breakpoints (WinDbg syntax)");
	const CLI::App* const be = init_windbg_command(app, "be", "enables execution breakpoints (WinDbg syntax)");
	const CLI::App* const sympath = init_windbg_command(app, ".sympath", "shows or sets the symbol path (WinDbg syntax)");
	const CLI::App* const sympath_add = init_windbg_command(app, ".sympath+", "appends to the symbol path (WinDbg syntax)");
	const CLI::App* const symfix = init_windbg_command(app, ".symfix", "sets the Microsoft symbol server (WinDbg syntax)");
	const CLI::App* const symfix_add = init_windbg_command(app, ".symfix+", "appends the Microsoft symbol server (WinDbg syntax)");
	const CLI::App* const reload = init_windbg_command(app, ".reload", "reloads module symbols (WinDbg syntax)");
	const CLI::App* const symopt = init_windbg_command(app, ".symopt", "shows dbghelp symbol options");
	const CLI::App* const examine = init_windbg_command(app, "x", "examines loaded symbols (WinDbg syntax)");
	const CLI::App* const nearest = init_windbg_command(app, "ln", "shows the nearest loaded symbol (WinDbg syntax)");
	const CLI::App* const lm = init_windbg_command(app, "lm", "lists modules and symbol status (WinDbg syntax)");
	const CLI::App* const lmi = init_windbg_command(app, "lmi", "shows loaded module information (WinDbg syntax)");
	const CLI::App* const ld = init_windbg_command(app, "ld", "loads symbols for a module (WinDbg syntax)");
	const CLI::App* const dps = init_windbg_command(app, "dps", "displays pointer-sized values and symbols (WinDbg syntax)");
	const CLI::App* const dqs = init_windbg_command(app, "dqs", "displays quad-words and symbols (WinDbg syntax)");
	const CLI::App* const dds = init_windbg_command(app, "dds", "displays double-words and symbols (WinDbg syntax)");
	const CLI::App* const dt = init_windbg_command(app, "dt", "displays a structure from pdb type information (WinDbg syntax)");
	const CLI::App* const cls = init_windbg_command(app, ".cls", "clears the screen (WinDbg syntax)");
	const CLI::App* const cls_alias = init_windbg_command(app, "cls", "clears the screen");
	const CLI::App* const echo = init_windbg_command(app, ".echo", "prints a line (WinDbg syntax)");
	const CLI::App* const printf_cmd = init_windbg_command(app, ".printf", "prints formatted text (WinDbg syntax)");
	const CLI::App* const formats = init_windbg_command(app, ".formats", "evaluates an expression (WinDbg syntax)");
	const CLI::App* const time_cmd = init_windbg_command(app, ".time", "prints the debugger time (WinDbg syntax)");
	const CLI::App* const help_cmd = init_windbg_command(app, ".help", "lists command groups");
	const CLI::App* const version_cmd = init_windbg_command(app, "version", "prints debugger version information");
	const CLI::App* const process_cmd = init_windbg_command(app, "process", "lists processes (WinDbg !process syntax)");
	const CLI::App* const dot_process = init_windbg_command(app, ".process", "sets the implicit process (WinDbg syntax)");
	const CLI::App* const dot_detach = init_windbg_command(app, ".detach", "releases every SLAT shadow page and resumes a frozen process");
	const CLI::App* const thread_cmd = init_windbg_command(app, "thread", "shows a thread (WinDbg !thread syntax)");
	const CLI::App* const dot_thread = init_windbg_command(app, ".thread", "sets the register context (WinDbg syntax)");

	try
	{
		app.parse(parsed_command);

		PROCESS_INITIAL_COMMAND(rgpm);
		PROCESS_COMMAND(wgpm);
		PROCESS_COMMAND(cgpm);
		PROCESS_COMMAND(gvat);
		PROCESS_COMMAND(rgvm);
		PROCESS_COMMAND(wgvm);
		PROCESS_COMMAND(cgvm);
		PROCESS_COMMAND(akh);
		PROCESS_COMMAND(rkh);
		PROCESS_COMMAND(gva);
		PROCESS_COMMAND(hgpp);
		PROCESS_COMMAND(fl);
		PROCESS_COMMAND(hfpc);
		PROCESS_COMMAND(lkm);
		PROCESS_COMMAND(kme);
		PROCESS_COMMAND(dkm);
		PROCESS_COMMAND(u);
		PROCESS_COMMAND(db);
		PROCESS_COMMAND(dw);
		PROCESS_COMMAND(dd);
		PROCESS_COMMAND(dq);
		PROCESS_COMMAND(dp);
		PROCESS_COMMAND(dc);
		PROCESS_COMMAND(da);
		PROCESS_COMMAND(du);
		PROCESS_COMMAND(eb);
		PROCESS_COMMAND(ew);
		PROCESS_COMMAND(ed);
		PROCESS_COMMAND(eq);
		PROCESS_COMMAND(ep);
		PROCESS_COMMAND(ea);
		PROCESS_COMMAND(eu);
		PROCESS_COMMAND(eza);
		PROCESS_COMMAND(ezu);
		PROCESS_COMMAND(bp);
		PROCESS_COMMAND(g);
		PROCESS_COMMAND(k);
		PROCESS_COMMAND(r);
		PROCESS_COMMAND(t);
		PROCESS_COMMAND(tc);
		PROCESS_COMMAND(tt);
		PROCESS_COMMAND(tct);
		PROCESS_COMMAND(p);
		PROCESS_COMMAND(pc);
		PROCESS_COMMAND(pt);
		PROCESS_COMMAND(pct);
		PROCESS_COMMAND(bl);
		PROCESS_COMMAND(bc);
		PROCESS_COMMAND(bd);
		PROCESS_COMMAND(be);
		PROCESS_COMMAND(sympath);
		PROCESS_COMMAND(sympath_add);
		PROCESS_COMMAND(symfix);
		PROCESS_COMMAND(symfix_add);
		PROCESS_COMMAND(reload);
		PROCESS_COMMAND(symopt);
		PROCESS_COMMAND(examine);
		PROCESS_COMMAND(nearest);
		PROCESS_COMMAND(lm);
		PROCESS_COMMAND(lmi);
		PROCESS_COMMAND(ld);
		PROCESS_COMMAND(dps);
		PROCESS_COMMAND(dqs);
		PROCESS_COMMAND(dds);
		PROCESS_COMMAND(dt);
		else if (*cls || *cls_alias)
		{
			process_cls(nullptr);
		}
		else if (*echo)
		{
			process_echo(nullptr);
		}
		else if (*printf_cmd)
		{
			process_printf(nullptr);
		}
		else if (*formats)
		{
			process_formats(nullptr);
		}
		else if (*time_cmd)
		{
			process_time(nullptr);
		}
		else if (*help_cmd)
		{
			process_help(nullptr);
		}
		else if (*version_cmd)
		{
			process_version(nullptr);
		}
		else if (*process_cmd)
		{
			process_bang_process();
		}
		else if (*dot_process)
		{
			process_dot_process();
		}
		else if (*dot_detach)
		{
			process_dot_detach();
		}
		else if (*thread_cmd)
		{
			process_bang_thread();
		}
		else if (*dot_thread)
		{
			process_dot_thread();
		}
	}
	catch (const CLI::ParseError& error)
	{
		app.exit(error);
	}
}

static void print_debugger_prompt()
{
	fmt::print("{}", breakpoint::has_paused_thread() == 1 ? "0: kd> " : "kd> ");
	std::fflush(stdout);
}

static void announce_breakpoint_hit()
{
	breakpoint::registers_t registers = {};

	if (breakpoint::paused_registers(registers) == 0)
	{
		return;
	}

	clear_implicit_thread();
	fmt::print("Breakpoint {} hit\n", breakpoint::paused_breakpoint_id());
	print_paused_instruction(registers.rip);
	std::fflush(stdout);
}

static std::atomic<std::uint8_t> console_cancel = 0;
static std::atomic<std::uint8_t> f11_step = 0;
static HHOOK keyboard_hook = nullptr;
static std::vector<std::string> console_history = {};

static std::uint8_t debugger_window_is_focused()
{
	const HWND foreground = GetForegroundWindow();

	if (foreground == nullptr)
	{
		return 0;
	}

	const HWND console = GetConsoleWindow();

	if (console != nullptr && (foreground == console || IsChild(foreground, console) != FALSE ||
		GetAncestor(foreground, GA_ROOT) == GetAncestor(console, GA_ROOT)))
	{
		return 1;
	}

	wchar_t console_title[512] = {};
	wchar_t foreground_title[512] = {};

	if (GetConsoleTitleW(console_title, 512) == 0 || console_title[0] == L'\0' ||
		GetWindowTextW(foreground, foreground_title, 512) == 0)
	{
		return 0;
	}

	return static_cast<std::uint8_t>(_wcsicmp(console_title, foreground_title) == 0);
}

static LRESULT CALLBACK low_level_keyboard(const int code, const WPARAM wparam, const LPARAM lparam)
{
	if (code == HC_ACTION && (wparam == WM_KEYDOWN || wparam == WM_SYSKEYDOWN))
	{
		const auto* const info = reinterpret_cast<KBDLLHOOKSTRUCT*>(lparam);

		if (info->vkCode == VK_F11 && (info->flags & LLKHF_UP) == 0 && debugger_window_is_focused() == 1)
		{
			f11_step.store(1);

			return 1;
		}
	}

	return CallNextHookEx(keyboard_hook, code, wparam, lparam);
}

static std::uint8_t console_interrupt_requested()
{
	return console_cancel.load();
}

static void console_interrupt_clear()
{
	console_cancel.store(0);
}

static BOOL WINAPI console_ctrl_handler(const DWORD type)
{
	if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT)
	{
		console_cancel.store(1);

		return TRUE;
	}

	return FALSE;
}

static std::string debugger_prompt_text()
{
	return breakpoint::has_paused_thread() == 1 ? "0: kd> " : "kd> ";
}

static void scroll_console_to_cursor();

static void ensure_console_scrollback()
{
	const HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
	CONSOLE_SCREEN_BUFFER_INFO info = {};

	if (GetConsoleScreenBufferInfo(output, &info) == 0 || info.dwSize.Y >= 9000)
	{
		return;
	}

	const COORD size = { info.dwSize.X, 9000 };
	SetConsoleScreenBufferSize(output, size);
	scroll_console_to_cursor();
}

static void move_console_window(CONSOLE_SCREEN_BUFFER_INFO info, int top)
{
	const int height = info.srWindow.Bottom - info.srWindow.Top + 1;
	const int width = info.srWindow.Right - info.srWindow.Left + 1;
	const int max_top = info.dwSize.Y - height;

	if (top < 0)
	{
		top = 0;
	}

	if (top > max_top)
	{
		top = max_top;
	}

	SMALL_RECT window = info.srWindow;
	window.Top = static_cast<SHORT>(top);
	window.Bottom = static_cast<SHORT>(top + height - 1);
	window.Right = static_cast<SHORT>(window.Left + width - 1);

	if (window.Top == info.srWindow.Top && window.Bottom == info.srWindow.Bottom && window.Left == info.srWindow.Left &&
		window.Right == info.srWindow.Right)
	{
		return;
	}

	SetConsoleWindowInfo(GetStdHandle(STD_OUTPUT_HANDLE), TRUE, &window);
}

static void scroll_console_pages(const int pages)
{
	const HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
	CONSOLE_SCREEN_BUFFER_INFO info = {};

	if (GetConsoleScreenBufferInfo(output, &info) == 0)
	{
		return;
	}

	const int height = info.srWindow.Bottom - info.srWindow.Top + 1;
	const int step = height > 1 ? height - 1 : 1;
	move_console_window(info, info.srWindow.Top + pages * step);
}

static void scroll_console_to_top()
{
	const HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
	CONSOLE_SCREEN_BUFFER_INFO info = {};

	if (GetConsoleScreenBufferInfo(output, &info) == 0)
	{
		return;
	}

	move_console_window(info, 0);
}

static void scroll_console_to_cursor()
{
	const HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
	CONSOLE_SCREEN_BUFFER_INFO info = {};

	if (GetConsoleScreenBufferInfo(output, &info) == 0)
	{
		return;
	}

	const int height = info.srWindow.Bottom - info.srWindow.Top + 1;
	const int cursor_row = info.dwCursorPosition.Y;
	move_console_window(info, cursor_row - height + 1);
}

static COORD input_origin = {};
static std::uint8_t input_origin_valid = 0;
static std::size_t input_drawn_cells = 0;

static void capture_input_origin()
{
	const HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
	CONSOLE_SCREEN_BUFFER_INFO info = {};

	input_drawn_cells = 0;

	if (GetConsoleScreenBufferInfo(output, &info) == 0)
	{
		input_origin_valid = 0;

		return;
	}

	input_origin = info.dwCursorPosition;
	input_origin_valid = 1;
}

static COORD input_cell(const COORD origin, const int width, const std::size_t offset)
{
	const int linear = static_cast<int>(origin.X) + static_cast<int>(offset);
	COORD cell = {};
	cell.X = static_cast<SHORT>(linear % width);
	cell.Y = static_cast<SHORT>(origin.Y + linear / width);

	return cell;
}

static void write_input_cells(const HANDLE output, const COORD origin, const int width, const SHORT buffer_height, const std::string& text)
{
	std::size_t offset = 0;

	while (offset < text.size())
	{
		const COORD cell = input_cell(origin, width, offset);

		if (cell.Y >= buffer_height)
		{
			return;
		}

		const int room = width - cell.X;
		std::size_t chunk = text.size() - offset;

		if (chunk > static_cast<std::size_t>(room))
		{
			chunk = static_cast<std::size_t>(room);
		}

		DWORD written = 0;
		WriteConsoleOutputCharacterA(output, text.data() + offset, static_cast<DWORD>(chunk), cell, &written);
		offset += chunk;
	}
}

static void paint_input_line(const std::string& prompt, const std::string& text, const std::size_t cursor, std::size_t& drawn)
{
	const HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
	CONSOLE_SCREEN_BUFFER_INFO info = {};

	if (GetConsoleScreenBufferInfo(output, &info) == 0 || info.dwSize.X <= 0)
	{
		fmt::print("\r{}{}", prompt, text);
		std::fflush(stdout);
		drawn = text.size();

		return;
	}

	if (input_origin_valid == 0)
	{
		input_origin = info.dwCursorPosition;
		input_origin.X = 0;
		input_origin_valid = 1;
	}

	const int width = info.dwSize.X;
	const std::string visible = prompt + text;
	const std::size_t clamped = cursor > text.size() ? text.size() : cursor;
	const std::size_t caret_cells = prompt.size() + clamped;
	const std::size_t clear_cells = input_drawn_cells > visible.size() ? input_drawn_cells : visible.size();
	std::string painted = visible;

	if (clear_cells > visible.size())
	{
		painted.append(clear_cells - visible.size(), ' ');
	}

	CONSOLE_CURSOR_INFO saved_cursor = {};
	const BOOL cursor_known = GetConsoleCursorInfo(output, &saved_cursor);
	CONSOLE_CURSOR_INFO hidden_cursor = saved_cursor;
	hidden_cursor.bVisible = FALSE;

	if (cursor_known != FALSE)
	{
		SetConsoleCursorInfo(output, &hidden_cursor);
	}

	write_input_cells(output, input_origin, width, info.dwSize.Y, painted);

	const COORD caret = input_cell(input_origin, width, caret_cells);

	if (caret.Y < info.dwSize.Y)
	{
		SetConsoleCursorPosition(output, caret);
	}

	input_drawn_cells = visible.size();
	drawn = text.size();
	CONSOLE_CURSOR_INFO shown_cursor = saved_cursor;
	shown_cursor.dwSize = shown_cursor.dwSize == 0 ? 25 : shown_cursor.dwSize;
	shown_cursor.bVisible = TRUE;
	SetConsoleCursorInfo(output, &shown_cursor);
	scroll_console_to_cursor();
}

static std::uint8_t starts_with_ignore_case(const std::string_view text, const std::string_view prefix)
{
	if (text.size() < prefix.size())
	{
		return 0;
	}

	for (std::size_t index = 0; index < prefix.size(); index++)
	{
		if (std::tolower(static_cast<unsigned char>(text[index])) != std::tolower(static_cast<unsigned char>(prefix[index])))
		{
			return 0;
		}
	}

	return 1;
}

static const char* debugger_command_names[] = {
	".cls", ".detach", ".echo", ".formats", ".help", ".printf", ".process", ".quit", ".reload", ".symfix", ".symfix+", ".sympath", ".sympath+",
	".thread",
	".symopt", ".time", "akh", "bc", "bd", "be", "bl", "bp", "cgpm", "cgvm", "cls",
	"da", "db", "dc", "dd", "dds", "dkm", "dp", "dps", "dq", "dqs", "dt", "du", "dw", "ea", "eb", "ed", "ep", "eq", "eu", "ew",
	"exit", "eza", "ezu", "fl", "g", "gva", "gvat", "hfpc", "hgpp", "k", "kb", "kd", "kme", "kp", "kv", "ld", "lkm", "lm", "lmi", "ln", "p", "pc", "pct", "pt", "process", "q",
	"thread",
	"r", "rgpm", "rgvm", "rkh", "t", "tc", "tct", "tt", "u", "version", "wgpm", "wgvm", "x",
};

static void collect_completions(const std::string& token, std::vector<std::string>& matches)
{
	matches.clear();
	const std::size_t bang = token.find('!');

	if (bang == std::string::npos)
	{
		for (const char* const name : debugger_command_names)
		{
			if (starts_with_ignore_case(name, token) == 1)
			{
				matches.emplace_back(name);
			}
		}

		return;
	}

	if (bang + 1 >= token.size())
	{
		return;
	}

	const std::string module = token.substr(0, bang);
	const std::string prefix = token.substr(bang + 1);
	std::vector<std::string> plain = {};
	std::vector<std::string> decorated = {};

	const auto add_symbol = [&](const std::string& symbol)
	{
		const std::string completion = module + "!" + symbol;
		std::vector<std::string>& bucket = symbol.find('$') == std::string::npos ? plain : decorated;

		for (const std::string& existing : bucket)
		{
			if (equals_ignore_case(existing, completion) == 1)
			{
				return;
			}
		}

		bucket.push_back(completion);
	};

	const std::unordered_map<std::string, std::uint64_t> aliases = sys::kernel::compile_symbol_list();

	for (const auto& [full_name, address] : aliases)
	{
		(void)address;
		const std::size_t export_bang = full_name.find('!');

		if (export_bang == std::string::npos || export_bang == 0 || export_bang + 1 >= full_name.size())
		{
			continue;
		}

		const std::string_view export_module(full_name.data(), export_bang);
		const std::string_view export_symbol(full_name.data() + export_bang + 1, full_name.size() - export_bang - 1);
		const std::uint8_t module_match = static_cast<std::uint8_t>(
			equals_ignore_case(export_module, module) == 1 || equals_ignore_case(module_stem(export_module), module) == 1 ||
			(equals_ignore_case(module, "nt") == 1 && is_ntoskrnl_module(export_module) == 1));

		if (module_match == 0 || starts_with_ignore_case(export_symbol, prefix) == 0)
		{
			continue;
		}

		add_symbol(std::string(export_symbol));
	}

	for (const symbol_parser::symbol_match_t& match : symbol_parser::enumerate(module, prefix + "*", 1024))
	{
		const std::size_t match_bang = match.name.rfind('!');
		const std::string symbol = match_bang == std::string::npos ? match.name : match.name.substr(match_bang + 1);

		if (starts_with_ignore_case(symbol, prefix) == 0)
		{
			continue;
		}

		add_symbol(symbol);
	}

	if (prefix.find('$') == std::string::npos && plain.empty() == false)
	{
		matches = std::move(plain);
	}
	else
	{
		matches = std::move(plain);
		matches.insert(matches.end(), decorated.begin(), decorated.end());
	}

	std::sort(matches.begin(), matches.end(), [](const std::string& left, const std::string& right)
	{
		return _stricmp(left.c_str(), right.c_str()) < 0;
	});
}

static std::uint8_t apply_completion(std::string& line, std::size_t& cursor)
{
	const std::size_t before = cursor == 0 ? 0 : line.rfind(' ', cursor - 1);
	const std::size_t token_begin = before == std::string::npos ? 0 : before + 1;
	const std::size_t token_end = line.find(' ', cursor);
	const std::size_t token_stop = token_end == std::string::npos ? line.size() : token_end;
	const std::string token = line.substr(token_begin, token_stop - token_begin);
	std::vector<std::string> matches = {};
	collect_completions(token, matches);

	if (matches.empty() == true)
	{
		return 0;
	}

	std::string common = matches.front();

	for (const std::string& match : matches)
	{
		std::size_t length = 0;

		while (length < common.size() && length < match.size() &&
			std::tolower(static_cast<unsigned char>(common[length])) == std::tolower(static_cast<unsigned char>(match[length])))
		{
			length += 1;
		}

		common.resize(length);
	}

	if (matches.size() == 1)
	{
		common = matches.front();

		if (common.find('!') == std::string::npos)
		{
			common.push_back(' ');
		}
	}

	if (common.size() > token.size())
	{
		line.replace(token_begin, token_stop - token_begin, common);
		cursor = token_begin + common.size();

		return 1;
	}

	const HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
	CONSOLE_SCREEN_BUFFER_INFO screen = {};
	const WORD previous_color = GetConsoleScreenBufferInfo(output, &screen) == 0
		                            ? static_cast<WORD>(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE)
		                            : screen.wAttributes;

	std::fflush(stdout);
	SetConsoleTextAttribute(output, static_cast<WORD>(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY));
	fmt::print("\n");
	constexpr std::size_t show_limit = 48;
	const std::size_t shown = matches.size() > show_limit ? show_limit : matches.size();

	for (std::size_t index = 0; index < shown; index++)
	{
		fmt::print("{}\n", matches[index]);
	}

	if (matches.size() > shown)
	{
		fmt::print("... {} matches\n", matches.size());
	}

	std::fflush(stdout);
	SetConsoleTextAttribute(output, previous_color);

	return 2;
}

static void remember_command(const std::string& command)
{
	if (command.empty() == true)
	{
		return;
	}

	if (console_history.empty() == false && console_history.back() == command)
	{
		return;
	}

	console_history.push_back(command);

	if (console_history.size() > 200)
	{
		console_history.erase(console_history.begin());
	}
}

static std::uint8_t read_console_command(std::string& command_out)
{
	static std::uint8_t handler_ready = 0;

	if (handler_ready == 0)
	{
		SetConsoleCtrlHandler(console_ctrl_handler, TRUE);
		symbol_parser::set_interrupt_check(console_interrupt_requested);
		keyboard_hook = SetWindowsHookExW(WH_KEYBOARD_LL, low_level_keyboard, GetModuleHandleW(nullptr), 0);
		handler_ready = 1;
	}

	const HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
	DWORD previous_mode = 0;

	if (GetConsoleMode(input, &previous_mode) == 0)
	{
		return 0;
	}

	ensure_console_scrollback();
	SetConsoleMode(input, ENABLE_PROCESSED_INPUT | ENABLE_EXTENDED_FLAGS | ENABLE_QUICK_EDIT_MODE);

	std::string line;
	std::size_t cursor = 0;
	std::size_t drawn = 0;
	std::size_t history_pos = console_history.size();
	std::string history_draft;
	std::string prompt = debugger_prompt_text();
	capture_input_origin();
	paint_input_line(prompt, line, cursor, drawn);

	while (true)
	{
		const DWORD waited = MsgWaitForMultipleObjects(1, &input, FALSE, 100, QS_ALLINPUT);
		MSG message = {};

		while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE) != FALSE)
		{
			TranslateMessage(&message);
			DispatchMessageW(&message);
		}

		if (f11_step.exchange(0) == 1)
		{
			scroll_console_to_cursor();

			if (line.empty() == false)
			{
				continue;
			}

			if (breakpoint::has_paused_thread() == 0)
			{
				fmt::print("\nno paused thread\n");
				std::fflush(stdout);
				capture_input_origin();
				paint_input_line(prompt, line, cursor, drawn);

				continue;
			}

			line = "t";
			fmt::print("{}\n", line);
			std::fflush(stdout);
			remember_command(line);
			SetConsoleMode(input, previous_mode);
			command_out = line;

			return 1;
		}

		if (console_cancel.load() == 1)
		{
			console_cancel.store(0);
			line.clear();
			cursor = 0;
			fmt::print("^C\n");
			std::fflush(stdout);
			capture_input_origin();
			paint_input_line(prompt, line, cursor, drawn);
		}

		if (waited == WAIT_OBJECT_0)
		{
			INPUT_RECORD records[16] = {};
			DWORD read = 0;

			if (ReadConsoleInputA(input, records, 16, &read) != 0)
			{
				std::uint8_t finished = 0;

				for (DWORD index = 0; index < read && finished == 0; index++)
				{
					if (records[index].EventType != KEY_EVENT || records[index].Event.KeyEvent.bKeyDown == 0)
					{
						continue;
					}

					const KEY_EVENT_RECORD& key_event = records[index].Event.KeyEvent;
					const WORD key = key_event.wVirtualKeyCode;
					const WORD repeat = key_event.wRepeatCount == 0 ? 1 : key_event.wRepeatCount;
					const std::uint8_t control = static_cast<std::uint8_t>(
						(key_event.dwControlKeyState & (LEFT_CTRL_PRESSED | RIGHT_CTRL_PRESSED)) != 0);

					if (key == VK_PRIOR || key == VK_NEXT)
					{
						scroll_console_pages(key == VK_PRIOR ? -static_cast<int>(repeat) : static_cast<int>(repeat));

						continue;
					}

					if (control == 1 && key == VK_HOME)
					{
						scroll_console_to_top();

						continue;
					}

					if (control == 1 && key == VK_END)
					{
						scroll_console_to_cursor();

						continue;
					}

					if (key == VK_LEFT || key == VK_RIGHT || key == VK_HOME || key == VK_END || key == VK_BACK || key == VK_DELETE ||
						key == VK_UP || key == VK_DOWN || key == VK_TAB || key == VK_RETURN || key == VK_F5 || key == VK_F10 || key == VK_F11)
					{
						scroll_console_to_cursor();
					}

					if (key == VK_RETURN)
					{
						if (line.empty() == true && console_history.empty() == false)
						{
							line = console_history.back();
							fmt::print("{}\n", line);
						}
						else
						{
							fmt::print("\n");
						}

						std::fflush(stdout);
						remember_command(line);
						SetConsoleMode(input, previous_mode);
						command_out = line;
						finished = 1;

						continue;
					}

					if (key == VK_F5 || key == VK_F10 || key == VK_F11)
					{
						if (line.empty() == false)
						{
							continue;
						}

						if (breakpoint::has_paused_thread() == 0)
						{
							fmt::print("\nno paused thread\n");
							std::fflush(stdout);
							capture_input_origin();
							paint_input_line(prompt, line, cursor, drawn);

							continue;
						}

						line = key == VK_F5 ? "g" : key == VK_F10 ? "p" : "t";
						fmt::print("{}\n", line);
						std::fflush(stdout);
						remember_command(line);
						SetConsoleMode(input, previous_mode);
						command_out = line;
						finished = 1;

						continue;
					}

					if (key == VK_UP || key == VK_DOWN)
					{
						if (console_history.empty() == true)
						{
							continue;
						}

						if (key == VK_UP)
						{
							if (history_pos == console_history.size())
							{
								history_draft = line;
							}

							if (history_pos > 0)
							{
								history_pos -= 1;
							}
						}
						else if (history_pos < console_history.size())
						{
							history_pos += 1;
						}

						line = history_pos == console_history.size() ? history_draft : console_history[history_pos];
						cursor = line.size();
						paint_input_line(prompt, line, cursor, drawn);

						continue;
					}

					if (key == VK_LEFT)
					{
						for (WORD count = 0; count < repeat && cursor > 0; count++)
						{
							cursor -= 1;
						}

						paint_input_line(prompt, line, cursor, drawn);

						continue;
					}

					if (key == VK_RIGHT)
					{
						for (WORD count = 0; count < repeat && cursor < line.size(); count++)
						{
							cursor += 1;
						}

						paint_input_line(prompt, line, cursor, drawn);

						continue;
					}

					if (key == VK_HOME)
					{
						cursor = 0;
						paint_input_line(prompt, line, cursor, drawn);

						continue;
					}

					if (key == VK_END)
					{
						cursor = line.size();
						paint_input_line(prompt, line, cursor, drawn);

						continue;
					}

					if (key == VK_BACK)
					{
						for (WORD count = 0; count < repeat && cursor > 0; count++)
						{
							line.erase(cursor - 1, 1);
							cursor -= 1;
						}

						paint_input_line(prompt, line, cursor, drawn);

						continue;
					}

					if (key == VK_DELETE)
					{
						for (WORD count = 0; count < repeat && cursor < line.size(); count++)
						{
							line.erase(cursor, 1);
						}

						paint_input_line(prompt, line, cursor, drawn);

						continue;
					}

					if (key == VK_TAB)
					{
						const std::uint8_t completed = apply_completion(line, cursor);

						if (completed == 2)
						{
							capture_input_origin();
						}

						if (completed != 0)
						{
							paint_input_line(prompt, line, cursor, drawn);
						}

						continue;
					}

					const char character = key_event.uChar.AsciiChar;

					if (character < 0x20 || character == 0x7f)
					{
						continue;
					}

					line.insert(cursor, repeat, character);
					cursor += repeat;
					paint_input_line(prompt, line, cursor, drawn);
				}

				if (finished == 1)
				{
					return 1;
				}
			}
		}

		if (breakpoint::poll_new_pause() == 1)
		{
			fmt::print("\n");
			announce_breakpoint_hit();
			prompt = debugger_prompt_text();
			std::fflush(stdout);
			capture_input_origin();
			paint_input_line(prompt, line, cursor, drawn);
		}
	}
}

std::uint8_t commands::read_command(std::string& command_out)
{
	const HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
	DWORD console_mode = 0;

	if (GetConsoleMode(input, &console_mode) != 0)
	{
		return read_console_command(command_out);
	}

	print_debugger_prompt();

	if (std::getline(std::cin, command_out).fail() == true)
	{
		return 0;
	}

	return 1;
}
