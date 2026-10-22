#include "nt_offsets.h"

#include "../hypercall/hypercall.h"
#include "../logs/logs.h"
#include "system.h"

#include <Windows.h>

#include <cstring>
#include <cwchar>

namespace
{
	struct nt_offset_span_t
	{
		std::uint32_t build_min;
		std::uint32_t build_max;
		std::uint32_t revision_min;
		std::uint32_t revision_max;
		std::uint16_t user_directory_table_base;
		std::uint16_t unique_process_id;
		std::uint16_t active_process_links;
		std::uint16_t inherited_from_unique_process_id;
		std::uint16_t peb;
		std::uint16_t image_file_name;
		std::uint16_t thread_list_head;
		std::uint16_t ethread_cid;
		std::uint16_t ethread_win32_start_address;
		std::uint16_t ethread_thread_list_entry;
	};

	//
	// Rows are the x64 layouts read from ntoskrnl PDBs for each Windows 10
	// and Windows 11 kernel branch. A revision split exists only where
	// UserDirectoryTableBase was added inside one build. The other listed
	// fields stayed put from the first PDB of that branch through the last
	// one that was checked. Enablement-package builds (18363, 19042-19045,
	// 22631, 26200) share the base kernel layout and sit inside the same row.
	//
	constexpr nt_offset_span_t g_NtOffsetSpans[] = {
		{10240, 10240, 0, 17737, 0, 0x2E8, 0x2F0, 0x3E0, 0x3F8, 0x448, 0x480, 0x628, 0x680, 0x690},
		{10240, 10240, 17738, 0xFFFFFFFFu, 0x278, 0x2E8, 0x2F0, 0x3E0, 0x3F8, 0x448, 0x480, 0x628, 0x680, 0x690},
		{10586, 10586, 0, 0xFFFFFFFFu, 0, 0x2E8, 0x2F0, 0x3E0, 0x3F8, 0x450, 0x488, 0x628, 0x680, 0x690},
		{14393, 14393, 0, 2006, 0, 0x2E8, 0x2F0, 0x3E0, 0x3F8, 0x450, 0x488, 0x630, 0x688, 0x698},
		{14393, 14393, 2007, 0xFFFFFFFFu, 0x2C0, 0x2E8, 0x2F0, 0x3E0, 0x3F8, 0x450, 0x488, 0x630, 0x688, 0x698},
		{15063, 15063, 0, 849, 0, 0x2E0, 0x2E8, 0x3E0, 0x3F8, 0x450, 0x488, 0x638, 0x690, 0x6A0},
		{15063, 15063, 850, 0xFFFFFFFFu, 0x278, 0x2E0, 0x2E8, 0x3E0, 0x3F8, 0x450, 0x488, 0x638, 0x690, 0x6A0},
		{16299, 16299, 0, 191, 0, 0x2E0, 0x2E8, 0x3E0, 0x3F8, 0x450, 0x488, 0x638, 0x690, 0x6A8},
		{16299, 16299, 192, 0xFFFFFFFFu, 0x278, 0x2E0, 0x2E8, 0x3E0, 0x3F8, 0x450, 0x488, 0x638, 0x690, 0x6A8},
		{17134, 17763, 0, 0xFFFFFFFFu, 0x278, 0x2E0, 0x2E8, 0x3E0, 0x3F8, 0x450, 0x488, 0x638, 0x690, 0x6A8},
		{18362, 18363, 0, 0xFFFFFFFFu, 0x280, 0x2E8, 0x2F0, 0x3E8, 0x3F8, 0x450, 0x488, 0x648, 0x6A0, 0x6B8},
		{19041, 19045, 0, 0xFFFFFFFFu, 0x388, 0x440, 0x448, 0x540, 0x550, 0x5A8, 0x5E0, 0x478, 0x4D0, 0x4E8},
		{22000, 22631, 0, 0xFFFFFFFFu, 0x388, 0x440, 0x448, 0x540, 0x550, 0x5A8, 0x5E0, 0x4C8, 0x520, 0x538},
		// 24H2 is 26100. 25H2 is 26200. 26H2 is 26300, including experimental
		// builds such as 26340. 25H2 and 26H2 are enablement packages: the
		// ntoskrnl file version stays 10.0.26100.<revision> while
		// NtBuildNumber becomes 26200 or 26300. Field offsets were checked
		// on 10.0.26100.9711, the kernel shared with 26200.9711 and 26300.9711.
		{26100, 27999, 0, 0xFFFFFFFFu, 0x158, 0x1D0, 0x1D8, 0x2D0, 0x2E0, 0x338, 0x370, 0x508, 0x560, 0x578},
		// 26H1 is 28000. Checked through 10.0.28000.3231. The fields above
		// match 26100, so later builds keep this row until a new layout appears.
		{28000, 0xFFFFFFFFu, 0, 0xFFFFFFFFu, 0x158, 0x1D0, 0x1D8, 0x2D0, 0x2E0, 0x338, 0x370, 0x508, 0x560, 0x578},
	};

	nt_offsets_t g_CurrentOffsets = {};
	std::uint8_t g_OffsetsSelected = 0;

	constexpr std::uint64_t kuser_shared_data = 0xFFFFF78000000000ull;
	constexpr std::uint32_t kuser_nt_build_number = 0x260;
	constexpr std::uint32_t fixed_file_info_signature = 0xFEEF04BDu;

	std::uint8_t span_contains_build(const nt_offset_span_t& span, const std::uint32_t build)
	{
		return static_cast<std::uint8_t>(build >= span.build_min && build <= span.build_max);
	}

	std::uint8_t span_contains_revision(const nt_offset_span_t& span, const std::uint32_t revision)
	{
		return static_cast<std::uint8_t>(revision >= span.revision_min && revision <= span.revision_max);
	}

	const nt_offset_span_t* find_span(const std::uint32_t build, const std::uint32_t revision, const std::uint8_t revision_known)
	{
		const nt_offset_span_t* chosen = nullptr;

		for (const nt_offset_span_t& span : g_NtOffsetSpans)
		{
			if (span_contains_build(span, build) == 0)
			{
				continue;
			}

			if (revision_known == 0)
			{
				if (chosen == nullptr || span.revision_min >= chosen->revision_min)
				{
					chosen = &span;
				}

				continue;
			}

			if (span_contains_revision(span, revision) == 1)
			{
				return &span;
			}
		}

		return chosen;
	}

	void publish_span(const nt_offset_span_t& span, const std::uint32_t build, const std::uint32_t revision)
	{
		nt_offsets_t row = {};

		row.build = build;
		row.revision = revision;
		row.eprocess_directory_table_base = 0x28;
		row.eprocess_user_directory_table_base = span.user_directory_table_base;
		row.eprocess_unique_process_id = span.unique_process_id;
		row.eprocess_active_process_links = span.active_process_links;
		row.eprocess_inherited_from_unique_process_id = span.inherited_from_unique_process_id;
		row.eprocess_peb = span.peb;
		row.eprocess_image_file_name = span.image_file_name;
		row.eprocess_thread_list_head = span.thread_list_head;
		row.kthread_initial_stack = 0x28;
		row.kthread_stack_limit = 0x30;
		row.kthread_stack_base = 0x38;
		row.kthread_kernel_stack = 0x58;
		row.kthread_misc_flags = 0x74;
		row.kthread_system_thread_bit = 10;
		row.kthread_trap_frame = 0x90;
		row.kthread_priority = 0xC3;
		row.kthread_teb = 0xF0;
		row.kthread_context_switches = 0x154;
		row.kthread_state = 0x184;
		row.kthread_wait_mode = 0x187;
		row.kthread_wait_time = 0x1B4;
		row.kthread_win32_thread = 0x1C8;
		row.kthread_process = 0x220;
		row.kthread_wait_reason = 0x283;
		row.kthread_suspend_count = 0x284;
		row.ethread_cid = span.ethread_cid;
		row.ethread_win32_start_address = span.ethread_win32_start_address;
		row.ethread_thread_list_entry = span.ethread_thread_list_entry;
		row.prcb_current_thread = 0x8;
		row.ktrap_rip = 0x168;
		row.ktrap_seg_cs = 0x170;

		g_CurrentOffsets = row;
		g_OffsetsSelected = 1;
	}

	std::uint8_t file_version_from_image(const std::span<const std::uint8_t> image, std::uint32_t& build_out, std::uint32_t& revision_out)
	{
		std::uint32_t fallback_build = 0;
		std::uint32_t fallback_revision = 0;
		std::uint8_t saw_fallback = 0;

		for (std::size_t index = 0; index + 16 <= image.size(); index++)
		{
			std::uint32_t signature = 0;
			std::uint32_t file_version_ms = 0;
			std::uint32_t file_version_ls = 0;

			std::memcpy(&signature, image.data() + index, sizeof(signature));

			if (signature != fixed_file_info_signature)
			{
				continue;
			}

			std::memcpy(&file_version_ms, image.data() + index + 8, sizeof(file_version_ms));
			std::memcpy(&file_version_ls, image.data() + index + 12, sizeof(file_version_ls));

			const std::uint32_t major = file_version_ms >> 16;
			const std::uint32_t build = file_version_ls >> 16;
			const std::uint32_t revision = file_version_ls & 0xFFFFu;

			if (major != 10 || build < 10240)
			{
				continue;
			}

			if (find_span(build, revision, 1) != nullptr)
			{
				build_out = build;
				revision_out = revision;

				return 1;
			}

			if (saw_fallback == 0)
			{
				fallback_build = build;
				fallback_revision = revision;
				saw_fallback = 1;
			}
		}

		if (saw_fallback == 0)
		{
			return 0;
		}

		build_out = fallback_build;
		revision_out = fallback_revision;

		return 1;
	}

	std::uint8_t build_from_registry(std::uint32_t& build_out, std::uint32_t& revision_out)
	{
		wchar_t build_text[32] = {};
		DWORD text_size = sizeof(build_text);
		const LSTATUS build_status = RegGetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
		                                           L"CurrentBuildNumber", RRF_RT_REG_SZ, nullptr, build_text, &text_size);

		if (build_status != ERROR_SUCCESS || build_text[0] == L'\0')
		{
			return 0;
		}

		build_out = static_cast<std::uint32_t>(wcstoul(build_text, nullptr, 10));

		DWORD revision = 0;
		DWORD revision_size = sizeof(revision);
		const LSTATUS revision_status = RegGetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"UBR",
		                                              RRF_RT_REG_DWORD, nullptr, &revision, &revision_size);

		revision_out = revision_status == ERROR_SUCCESS ? revision : 0;

		return static_cast<std::uint8_t>(build_out != 0);
	}

	std::uint8_t build_from_shared_user_data(std::uint32_t& build_out)
	{
		std::uint32_t build = 0;

		if (sys::current_cr3 == 0 ||
			hypercall::read_guest_virtual_memory(&build, kuser_shared_data + kuser_nt_build_number, sys::current_cr3, sizeof(build)) !=
				sizeof(build))
		{
			return 0;
		}

		build &= 0x0FFFFFFFu;
		build_out = build;

		return static_cast<std::uint8_t>(build >= 10240);
	}
}

const nt_offsets_t* nt_offsets_current()
{
	if (g_OffsetsSelected == 0)
	{
		return nullptr;
	}

	return &g_CurrentOffsets;
}

std::uint8_t nt_offsets_select(const std::uint32_t build, const std::uint32_t revision, const std::uint8_t revision_known)
{
	const nt_offset_span_t* const span = find_span(build, revision, revision_known);

	if (span == nullptr)
	{
		g_OffsetsSelected = 0;
		LOG_ERR("unsupported windows build {}", build);

		return 0;
	}

	publish_span(*span, build, revision_known == 1 ? revision : span->revision_min);

	if (revision_known == 1)
	{
		LOG_INFO("guest kernel offsets: build {} revision {}", build, revision);
	}
	else
	{
		LOG_INFO("guest kernel offsets: build {} revision unknown, using layout from revision {}", build, span->revision_min);
	}

	return 1;
}

std::uint8_t nt_offsets_select_from_image(const std::span<const std::uint8_t> image)
{
	std::uint32_t build = 0;
	std::uint32_t revision = 0;

	if (file_version_from_image(image, build, revision) == 1)
	{
		return nt_offsets_select(build, revision, 1);
	}

	if (build_from_registry(build, revision) == 1)
	{
		return nt_offsets_select(build, revision, 1);
	}

	if (build_from_shared_user_data(build) == 1)
	{
		return nt_offsets_select(build, 0, 0);
	}

	LOG_ERR("unable to read the guest windows build");

	return 0;
}
