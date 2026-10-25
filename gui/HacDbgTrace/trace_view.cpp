/**
 * @file trace_view.cpp
 * @brief Dear ImGui dashboard for bounded VM-exit trace snapshots.
 *
 * @author HacDbg
 */

#include "trace_view.h"

#include <imgui.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdio>
#include <cstring>

namespace
{
	constexpr const char* reason_names[HACDBG_TRACE_REASON_COUNT] = {
		"other",
		"cpuid",
		"msr",
		"nested page fault",
		"i/o",
		"exception",
		"halt",
		"shutdown",
		"interrupt window",
		"external interrupt",
		"preemption timer",
		"vmx instruction",
		"svm instruction",
		"xsetbv",
		"invd",
		"monitor trap"
	};

	constexpr uint32_t reason_colors[HACDBG_TRACE_REASON_COUNT] = {
		0xFF8B98A5,
		0xFF4CC2FF,
		0xFF7DD3A7,
		0xFFFFA657,
		0xFFD2A8FF,
		0xFFFF7B72,
		0xFFE3B341,
		0xFFFF8FA3,
		0xFF8AB4F8,
		0xFF67D8EF,
		0xFFF6C177,
		0xFFC792EA,
		0xFFA5D6A7,
		0xFFB39DDB,
		0xFFFFB86C,
		0xFF64B5F6
	};

	float color_channel(const uint32_t color, const uint32_t shift)
	{
		return static_cast<float>((color >> shift) & 0xFFu) / 255.0f;
	}

	ImVec4 to_vec4(const uint32_t color, const float alpha = 1.0f)
	{
		return ImVec4(
			color_channel(color, 16),
			color_channel(color, 8),
			color_channel(color, 0),
			alpha);
	}

	ImU32 to_u32(const uint32_t color, const float alpha = 1.0f)
	{
		ImVec4 value = to_vec4(color, alpha);
		return ImGui::ColorConvertFloat4ToU32(value);
	}

	void format_count(const uint64_t value, char* const buffer, const std::size_t size)
	{
		if (value >= 1000000000ull)
		{
			std::snprintf(buffer, size, "%.2fG", static_cast<double>(value) / 1000000000.0);
		}
		else if (value >= 1000000ull)
		{
			std::snprintf(buffer, size, "%.2fM", static_cast<double>(value) / 1000000.0);
		}
		else if (value >= 1000ull)
		{
			std::snprintf(buffer, size, "%.1fK", static_cast<double>(value) / 1000.0);
		}
		else
		{
			std::snprintf(buffer, size, "%llu", static_cast<unsigned long long>(value));
		}
	}

	void format_rate(const float value, char* const buffer, const std::size_t size)
	{
		if (value >= 1000000.0f)
		{
			std::snprintf(buffer, size, "%.2fM/s", static_cast<double>(value) / 1000000.0);
		}
		else if (value >= 1000.0f)
		{
			std::snprintf(buffer, size, "%.1fK/s", static_cast<double>(value) / 1000.0);
		}
		else
		{
			std::snprintf(buffer, size, "%.0f/s", static_cast<double>(value));
		}
	}

	const char* mode_name(const uint32_t flags)
	{
		if ((flags & HACDBG_TRACE_FLAG_EVENTS_ENABLED) != 0)
		{
			return "EVENTS";
		}

		if ((flags & HACDBG_TRACE_FLAG_COUNTERS_ENABLED) != 0)
		{
			return "COUNTERS";
		}

		return "DISABLED";
	}
}

trace_view::trace_view(const HACDBG_TRACE_THEME& theme)
	: theme_(theme)
{
}

void trace_view::set_theme(const HACDBG_TRACE_THEME& theme)
{
	if (std::memcmp(&theme_, &theme, sizeof(theme)) == 0)
	{
		return;
	}

	theme_ = theme;
	style_dirty_ = true;
}

void trace_view::set_dpi(const uint32_t dpi)
{
	const uint32_t next_dpi = (std::max)(dpi, 48u);

	if (next_dpi == dpi_)
	{
		return;
	}

	dpi_ = next_dpi;
	style_dirty_ = true;
}

bool trace_view::display_paused() const
{
	return paused_;
}

uint64_t trace_view::generation() const
{
	return seen_generation_;
}

void trace_view::reset_metrics()
{
	total_rate_ = 0.0f;
	cpu_rate_.fill(0.0f);
	reason_rate_.fill(0.0f);
	reason_total_.fill(0);
	cpu_present_.fill(false);
	max_cpu_rate_ = 0.0f;
	timeline_.fill(0.0f);
	timeline_head_ = 0;
	timeline_count_ = 0;
}

void trace_view::reset_view()
{
	current_ = {};
	previous_ = {};
	has_snapshot_ = false;
	has_previous_ = false;
	paused_ = false;
	last_ingest_seconds_ = 0.0;
	reset_metrics();
}

void trace_view::push_rate(const float rate)
{
	timeline_[timeline_head_] = rate;
	timeline_head_ = (timeline_head_ + 1) % timeline_capacity;

	if (timeline_count_ < timeline_capacity)
	{
		timeline_count_ += 1;
	}
}

void trace_view::ingest(const HACDBG_TRACE_SNAPSHOT& snapshot, const uint64_t generation,
                        const double now_seconds)
{
	if (paused_ || generation == seen_generation_)
	{
		return;
	}

	if (has_snapshot_ && snapshot.TotalExits < current_.TotalExits)
	{
		reset_metrics();
		has_previous_ = false;
	}
	else
	{
		previous_ = current_;
		has_previous_ = has_snapshot_;
	}

	current_ = snapshot;
	has_snapshot_ = true;
	seen_generation_ = generation;

	reason_total_.fill(0);
	cpu_present_.fill(false);

	std::array<uint64_t, HACDBG_TRACE_MAX_CPUS> previous_cpu_totals = {};
	std::array<uint64_t, HACDBG_TRACE_REASON_COUNT> previous_reason_totals = {};

	if (has_previous_ != false)
	{
		for (uint32_t index = 0; index < previous_.CpuCount && index < HACDBG_TRACE_MAX_CPUS; index++)
		{
			const HACDBG_TRACE_CPU& cpu = previous_.Cpu[index];

			if (cpu.CpuIndex < HACDBG_TRACE_MAX_CPUS)
			{
				previous_cpu_totals[cpu.CpuIndex] = cpu.TotalExits;

				for (uint32_t reason = 0; reason < HACDBG_TRACE_REASON_COUNT; reason++)
				{
					previous_reason_totals[reason] += cpu.ReasonCounts[reason];
				}
			}
		}
	}

	for (uint32_t index = 0; index < current_.CpuCount && index < HACDBG_TRACE_MAX_CPUS; index++)
	{
		const HACDBG_TRACE_CPU& cpu = current_.Cpu[index];

		if (cpu.CpuIndex >= HACDBG_TRACE_MAX_CPUS)
		{
			continue;
		}

		cpu_present_[cpu.CpuIndex] = true;

		for (uint32_t reason = 0; reason < HACDBG_TRACE_REASON_COUNT; reason++)
		{
			reason_total_[reason] += cpu.ReasonCounts[reason];
		}
	}

	const double elapsed = now_seconds - last_ingest_seconds_;
	const bool counters_enabled = (current_.Flags & HACDBG_TRACE_FLAG_COUNTERS_ENABLED) != 0;
	const bool can_measure = has_previous_ && counters_enabled && elapsed > 0.005 && elapsed < 2.0;
	const float smoothing = 0.35f;

	if (can_measure != false)
	{
		const uint64_t total_delta = current_.TotalExits >= previous_.TotalExits
		                                 ? current_.TotalExits - previous_.TotalExits
		                                 : 0;
		const float raw_total = static_cast<float>(static_cast<double>(total_delta) / elapsed);
		total_rate_ = total_rate_ * (1.0f - smoothing) + raw_total * smoothing;

		for (uint32_t index = 0; index < current_.CpuCount && index < HACDBG_TRACE_MAX_CPUS; index++)
		{
			const HACDBG_TRACE_CPU& cpu = current_.Cpu[index];

			if (cpu.CpuIndex >= HACDBG_TRACE_MAX_CPUS)
			{
				continue;
			}

			const uint64_t previous_total = previous_cpu_totals[cpu.CpuIndex];
			const uint64_t delta = cpu.TotalExits >= previous_total ? cpu.TotalExits - previous_total : 0;
			const float raw = static_cast<float>(static_cast<double>(delta) / elapsed);

			cpu_rate_[cpu.CpuIndex] = cpu_rate_[cpu.CpuIndex] * (1.0f - smoothing) + raw * smoothing;
		}

		for (uint32_t reason = 0; reason < HACDBG_TRACE_REASON_COUNT; reason++)
		{
			const uint64_t previous_total = previous_reason_totals[reason];
			const uint64_t total = reason_total_[reason];
			const uint64_t delta = total >= previous_total ? total - previous_total : 0;
			const float raw = static_cast<float>(static_cast<double>(delta) / elapsed);

			reason_rate_[reason] = reason_rate_[reason] * (1.0f - smoothing) + raw * smoothing;
		}
	}
	else
	{
		total_rate_ *= (1.0f - smoothing);
		max_cpu_rate_ = 0.0f;

		for (float& rate : cpu_rate_)
		{
			rate *= (1.0f - smoothing);
		}

		for (float& rate : reason_rate_)
		{
			rate *= (1.0f - smoothing);
		}
	}

	if (counters_enabled == false)
	{
		total_rate_ = 0.0f;
		cpu_rate_.fill(0.0f);
		reason_rate_.fill(0.0f);
	}

	max_cpu_rate_ = 0.0f;

	for (const float rate : cpu_rate_)
	{
		max_cpu_rate_ = (std::max)(max_cpu_rate_, rate);
	}

	push_rate(total_rate_);
	last_ingest_seconds_ = now_seconds;
}

void trace_view::apply_style()
{
	const float scale = static_cast<float>(dpi_) / 96.0f;
	ImGuiStyle style = ImGuiStyle();

	style.WindowPadding = ImVec2(12.0f, 10.0f);
	style.FramePadding = ImVec2(9.0f, 5.0f);
	style.CellPadding = ImVec2(8.0f, 5.0f);
	style.ItemSpacing = ImVec2(8.0f, 7.0f);
	style.ItemInnerSpacing = ImVec2(6.0f, 5.0f);
	style.ScrollbarSize = 13.0f;
	style.WindowRounding = 0.0f;
	style.ChildRounding = 6.0f;
	style.FrameRounding = 4.0f;
	style.PopupRounding = 5.0f;
	style.ScrollbarRounding = 6.0f;
	style.GrabRounding = 4.0f;
	style.TabRounding = 4.0f;
	style.WindowBorderSize = 0.0f;
	style.ChildBorderSize = 1.0f;
	style.FrameBorderSize = 1.0f;
	style.PopupBorderSize = 1.0f;
	style.FontSizeBase = 15.0f;

	style.ScaleAllSizes(scale);
	style.FontScaleDpi = scale;

	style.Colors[ImGuiCol_Text] = to_vec4(theme_.Text);
	style.Colors[ImGuiCol_TextDisabled] = to_vec4(theme_.Muted);
	style.Colors[ImGuiCol_WindowBg] = to_vec4(theme_.Background);
	style.Colors[ImGuiCol_ChildBg] = to_vec4(theme_.Surface);
	style.Colors[ImGuiCol_PopupBg] = to_vec4(theme_.SurfaceRaised, 0.98f);
	style.Colors[ImGuiCol_Border] = to_vec4(theme_.Border);
	style.Colors[ImGuiCol_FrameBg] = to_vec4(theme_.SurfaceRaised);
	style.Colors[ImGuiCol_FrameBgHovered] = to_vec4(theme_.Border);
	style.Colors[ImGuiCol_FrameBgActive] = to_vec4(theme_.Border);
	style.Colors[ImGuiCol_TitleBg] = to_vec4(theme_.Surface);
	style.Colors[ImGuiCol_TitleBgActive] = to_vec4(theme_.Surface);
	style.Colors[ImGuiCol_MenuBarBg] = to_vec4(theme_.Surface);
	style.Colors[ImGuiCol_ScrollbarBg] = to_vec4(theme_.Background);
	style.Colors[ImGuiCol_ScrollbarGrab] = to_vec4(theme_.Border);
	style.Colors[ImGuiCol_ScrollbarGrabHovered] = to_vec4(theme_.Muted);
	style.Colors[ImGuiCol_ScrollbarGrabActive] = to_vec4(theme_.Accent);
	style.Colors[ImGuiCol_CheckMark] = to_vec4(theme_.Accent);
	style.Colors[ImGuiCol_SliderGrab] = to_vec4(theme_.Accent);
	style.Colors[ImGuiCol_SliderGrabActive] = to_vec4(theme_.Accent);
	style.Colors[ImGuiCol_Button] = to_vec4(theme_.SurfaceRaised);
	style.Colors[ImGuiCol_ButtonHovered] = to_vec4(theme_.Border);
	style.Colors[ImGuiCol_ButtonActive] = to_vec4(theme_.Accent, 0.8f);
	style.Colors[ImGuiCol_Header] = to_vec4(theme_.SurfaceRaised);
	style.Colors[ImGuiCol_HeaderHovered] = to_vec4(theme_.Border);
	style.Colors[ImGuiCol_HeaderActive] = to_vec4(theme_.Border);
	style.Colors[ImGuiCol_Separator] = to_vec4(theme_.Border);
	style.Colors[ImGuiCol_Tab] = to_vec4(theme_.Surface);
	style.Colors[ImGuiCol_TabHovered] = to_vec4(theme_.Border);
	style.Colors[ImGuiCol_TabSelected] = to_vec4(theme_.SurfaceRaised);
	style.Colors[ImGuiCol_TabSelectedOverline] = to_vec4(theme_.Accent);
	style.Colors[ImGuiCol_TabDimmed] = to_vec4(theme_.Background);
	style.Colors[ImGuiCol_TabDimmedSelected] = to_vec4(theme_.Surface);
	style.Colors[ImGuiCol_TabDimmedSelectedOverline] = to_vec4(theme_.Accent, 0.5f);
	style.Colors[ImGuiCol_TableHeaderBg] = to_vec4(theme_.SurfaceRaised);
	style.Colors[ImGuiCol_TableBorderStrong] = to_vec4(theme_.Border);
	style.Colors[ImGuiCol_TableBorderLight] = to_vec4(theme_.Border, 0.55f);
	style.Colors[ImGuiCol_TableRowBg] = ImVec4(0.0f, 0.0f, 0.0f, 0.0f);
	style.Colors[ImGuiCol_TableRowBgAlt] = to_vec4(theme_.SurfaceRaised, 0.45f);
	style.Colors[ImGuiCol_TextSelectedBg] = to_vec4(theme_.Accent, 0.35f);
	style.Colors[ImGuiCol_NavHighlight] = to_vec4(theme_.Accent, 0.7f);

	ImGui::GetStyle() = style;
	style_dirty_ = false;
}

void trace_view::draw()
{
	if (style_dirty_ != false)
	{
		apply_style();
	}

	const ImGuiViewport* const viewport = ImGui::GetMainViewport();
	ImGui::SetNextWindowPos(viewport->WorkPos);
	ImGui::SetNextWindowSize(viewport->WorkSize);

	const ImGuiWindowFlags window_flags =
		ImGuiWindowFlags_NoTitleBar |
		ImGuiWindowFlags_NoResize |
		ImGuiWindowFlags_NoMove |
		ImGuiWindowFlags_NoCollapse |
		ImGuiWindowFlags_NoSavedSettings |
		ImGuiWindowFlags_NoBringToFrontOnFocus |
		ImGuiWindowFlags_NoNavFocus;

	if (ImGui::Begin("##HacDbgTraceDashboard", nullptr, window_flags) != false)
	{
		draw_header();

		if (has_snapshot_ == false)
		{
			draw_empty_state();
		}
		else
		{
			draw_summary();
			draw_filters();
			draw_timeline();
			draw_detail_tabs();

			char captured_buffer[32] = {};
			std::snprintf(captured_buffer, sizeof(captured_buffer), "0x%016llX",
			              static_cast<unsigned long long>(current_.CapturedTsc));

			ImGui::TextDisabled(
				"Snapshot v%u  |  %u CPUs  |  %u events  |  captured TSC %s  |  duration sampling unavailable",
				current_.Version,
				current_.CpuCount,
				current_.EventCount,
				captured_buffer);
		}
	}

	ImGui::End();
}

void trace_view::draw_header()
{
	ImGui::PushStyleColor(ImGuiCol_Text, to_vec4(theme_.Accent));
	ImGui::TextUnformatted("VM-EXIT TRACE");
	ImGui::PopStyleColor();

	ImGui::SameLine();
	ImGui::TextDisabled("live hypervisor telemetry");

	const char* const mode = has_snapshot_ ? mode_name(current_.Flags) : "WAITING";
	const ImU32 mode_color = has_snapshot_
	                             ? ((current_.Flags & HACDBG_TRACE_FLAG_COUNTERS_ENABLED) != 0
	                                    ? to_u32(theme_.Accent)
	                                    : to_u32(theme_.Muted))
	                             : to_u32(theme_.Warning);

	const float badge_width = ImGui::CalcTextSize(mode).x + 18.0f;
	ImGui::SameLine();
	ImGui::SetCursorPosX((std::max)(ImGui::GetCursorPosX(),
	                               ImGui::GetWindowContentRegionMax().x - badge_width));

	ImGui::PushStyleColor(ImGuiCol_Text, mode_color);
	ImGui::TextUnformatted(mode);
	ImGui::PopStyleColor();
	ImGui::Separator();
}

void trace_view::draw_summary()
{
	if (ImGui::BeginTable("##trace_summary", 4,
	                      ImGuiTableFlags_SizingStretchSame |
	                      ImGuiTableFlags_BordersInnerV |
	                      ImGuiTableFlags_NoSavedSettings) == false)
	{
		return;
	}

	char total_buffer[32] = {};
	char rate_buffer[32] = {};
	char dropped_buffer[32] = {};
	char event_buffer[32] = {};

	format_count(current_.TotalExits, total_buffer, sizeof(total_buffer));
	format_rate(total_rate_, rate_buffer, sizeof(rate_buffer));
	format_count(current_.DroppedEvents, dropped_buffer, sizeof(dropped_buffer));
	std::snprintf(event_buffer, sizeof(event_buffer), "%u / %u", current_.EventCount,
	              HACDBG_TRACE_MAX_EVENTS);

	const char* labels[4] = {"TOTAL EXITS", "EXIT RATE", "DROPPED", "EVENT WINDOW"};
	const char* values[4] = {total_buffer, rate_buffer, dropped_buffer, event_buffer};

	ImGui::TableNextRow();

	for (int column = 0; column < 4; column++)
	{
		ImGui::TableNextColumn();
		ImGui::TextDisabled("%s", labels[column]);
		ImGui::PushFont(nullptr, ImGui::GetStyle().FontSizeBase * 1.55f);
		ImGui::PushStyleColor(ImGuiCol_Text,
		                      column == 2 && current_.DroppedEvents != 0
		                          ? to_vec4(theme_.Warning)
		                          : to_vec4(theme_.Text));
		ImGui::TextUnformatted(values[column]);
		ImGui::PopStyleColor();
		ImGui::PopFont();
	}

	ImGui::EndTable();
}

void trace_view::draw_filters()
{
	const float scale = static_cast<float>(dpi_) / 96.0f;
	const float toolbar_height = ImGui::GetFrameHeight() + ImGui::GetStyle().WindowPadding.y * 2.0f;

	if (ImGui::BeginChild("##trace_filters", ImVec2(0.0f, toolbar_height), ImGuiChildFlags_Borders,
	                      ImGuiWindowFlags_NoScrollbar) == false)
	{
		ImGui::EndChild();
		return;
	}

	ImGui::TextDisabled("Event filters");
	ImGui::SameLine();

	char cpu_preview[32] = {};

	if (cpu_filter_ < 0)
	{
		std::snprintf(cpu_preview, sizeof(cpu_preview), "All CPUs");
	}
	else
	{
		std::snprintf(cpu_preview, sizeof(cpu_preview), "CPU %d", cpu_filter_);
	}

	ImGui::SetNextItemWidth(110.0f * scale);
	if (ImGui::BeginCombo("##cpu_filter", cpu_preview) != false)
	{
		if (ImGui::Selectable("All CPUs", cpu_filter_ < 0))
		{
			cpu_filter_ = -1;
		}

		for (uint32_t index = 0; index < current_.CpuCount && index < HACDBG_TRACE_MAX_CPUS; index++)
		{
			const uint32_t cpu_index = current_.Cpu[index].CpuIndex;
			char label[32] = {};
			std::snprintf(label, sizeof(label), "CPU %u", cpu_index);
			ImGui::PushID(static_cast<int>(cpu_index));

			if (ImGui::Selectable(label, cpu_filter_ == static_cast<int>(cpu_index)))
			{
				cpu_filter_ = static_cast<int>(cpu_index);
			}

			ImGui::PopID();
		}

		ImGui::EndCombo();
	}

	ImGui::SameLine();

	uint32_t selected_reasons = 0;
	for (uint32_t reason = 0; reason < HACDBG_TRACE_REASON_COUNT; reason++)
	{
		if ((reason_filter_ & (1u << reason)) != 0)
		{
			selected_reasons += 1;
		}
	}

	char reason_preview[48] = {};
	if (selected_reasons == HACDBG_TRACE_REASON_COUNT)
	{
		std::snprintf(reason_preview, sizeof(reason_preview), "All reasons");
	}
	else
	{
		std::snprintf(reason_preview, sizeof(reason_preview), "Reasons (%u)", selected_reasons);
	}

	ImGui::SetNextItemWidth(145.0f * scale);
	if (ImGui::BeginCombo("##reason_filter", reason_preview) != false)
	{
		if (ImGui::Selectable("All reasons", reason_filter_ == HACDBG_TRACE_EVENT_MASK_ALL))
		{
			reason_filter_ = HACDBG_TRACE_EVENT_MASK_ALL;
		}

		if (ImGui::Selectable("No reasons", reason_filter_ == 0))
		{
			reason_filter_ = 0;
		}

		ImGui::Separator();

		for (uint32_t reason = 0; reason < HACDBG_TRACE_REASON_COUNT; reason++)
		{
			bool enabled = (reason_filter_ & (1u << reason)) != 0;
			ImGui::PushID(static_cast<int>(reason));
			ImGui::PushStyleColor(ImGuiCol_Text, to_vec4(reason_colors[reason]));

			if (ImGui::MenuItem(reason_names[reason], nullptr, &enabled))
			{
				if (enabled != false)
				{
					reason_filter_ |= 1u << reason;
				}
				else
				{
					reason_filter_ &= ~(1u << reason);
				}
			}

			ImGui::PopStyleColor();
			ImGui::PopID();
		}

		ImGui::EndCombo();
	}

	ImGui::SameLine();
	ImGui::Checkbox("Pause display", &paused_);
	ImGui::SameLine();

	if (ImGui::Button("Reset view") != false)
	{
		reset_view();
	}

	ImGui::EndChild();
}

void trace_view::draw_timeline()
{
	const float height = 118.0f * static_cast<float>(dpi_) / 96.0f;

	if (ImGui::BeginChild("##trace_timeline", ImVec2(0.0f, height), ImGuiChildFlags_Borders,
	                      ImGuiWindowFlags_NoScrollbar) == false)
	{
		ImGui::EndChild();
		return;
	}

	char rate_buffer[32] = {};
	format_rate(total_rate_, rate_buffer, sizeof(rate_buffer));

	ImGui::TextDisabled("Exit rate timeline");
	ImGui::SameLine();
	ImGui::TextColored(to_vec4(theme_.Accent), "%s", rate_buffer);
	ImGui::SameLine();
	ImGui::TextDisabled("last 6 seconds");

	const ImVec2 origin = ImGui::GetCursorScreenPos();
	const ImVec2 available = ImGui::GetContentRegionAvail();
	const ImVec2 size((std::max)(available.x, 20.0f), (std::max)(available.y, 20.0f));

	ImGui::Dummy(size);

	ImDrawList* const draw_list = ImGui::GetWindowDrawList();
	const ImVec2 max_point(origin.x + size.x, origin.y + size.y);
	const ImU32 background = to_u32(theme_.SurfaceRaised, 0.55f);
	const ImU32 grid = to_u32(theme_.Border, 0.8f);
	const ImU32 accent = to_u32(theme_.Accent);

	draw_list->AddRectFilled(origin, max_point, background, 5.0f);
	draw_list->AddRect(origin, max_point, grid, 5.0f);

	float maximum = 1.0f;
	for (std::size_t index = 0; index < timeline_count_; index++)
	{
		maximum = (std::max)(maximum, timeline_[index]);
	}
	maximum *= 1.15f;

	const float left = origin.x + 9.0f;
	const float right = origin.x + size.x - 9.0f;
	const float top = origin.y + 9.0f;
	const float bottom = origin.y + size.y - 9.0f;

	for (int line = 1; line <= 3; line++)
	{
		const float y = top + (bottom - top) * static_cast<float>(line) / 4.0f;
		draw_list->AddLine(ImVec2(left, y), ImVec2(right, y), grid, 1.0f);
	}

	std::array<ImVec2, timeline_capacity> points = {};
	std::size_t point_count = 0;

	if (timeline_count_ > 0)
	{
		const std::size_t first = timeline_count_ < timeline_capacity ? 0 : timeline_head_;

		for (std::size_t index = 0; index < timeline_count_; index++)
		{
			const std::size_t source = (first + index) % timeline_capacity;
			const float x = timeline_count_ <= 1
				? right
				: left + (right - left) * static_cast<float>(index) /
				          static_cast<float>(timeline_count_ - 1);
			const float y = bottom - (bottom - top) * (timeline_[source] / maximum);
			points[point_count] = ImVec2(x, y);
			point_count += 1;
		}

		if (point_count >= 2)
		{
			draw_list->AddPolyline(points.data(), static_cast<int>(point_count), accent, ImDrawFlags_None,
			                       2.0f);
		}
	}

	char maximum_buffer[32] = {};
	format_rate(maximum, maximum_buffer, sizeof(maximum_buffer));
	draw_list->AddText(ImVec2(left + 4.0f, top + 2.0f), to_u32(theme_.Muted), maximum_buffer);

	ImGui::EndChild();
}

void trace_view::draw_detail_tabs()
{
	if (ImGui::BeginTabBar("##trace_detail_tabs", ImGuiTabBarFlags_NoCloseWithMiddleMouseButton) == false)
	{
		ImGui::EndTabBar();
		return;
	}

	if (ImGui::BeginTabItem("Recent events") != false)
	{
		draw_events();
		ImGui::EndTabItem();
	}

	if (ImGui::BeginTabItem("CPU rates") != false)
	{
		draw_cpu_heatmap();
		ImGui::EndTabItem();
	}

	if (ImGui::BeginTabItem("Exit reasons") != false)
	{
		draw_reason_distribution();
		ImGui::EndTabItem();
	}

	ImGui::EndTabBar();
}

void trace_view::draw_cpu_heatmap()
{
	const float scale = static_cast<float>(dpi_) / 96.0f;
	const float height = (std::max)(
		ImGui::GetContentRegionAvail().y - ImGui::GetTextLineHeightWithSpacing(),
		140.0f * scale);

	if (ImGui::BeginChild("##trace_cpu_heatmap", ImVec2(0.0f, height), ImGuiChildFlags_Borders) == false)
	{
		ImGui::EndChild();
		return;
	}

	ImGui::TextDisabled("Per-CPU exit rate");

	const ImGuiTableFlags flags =
		ImGuiTableFlags_SizingStretchSame |
		ImGuiTableFlags_PadOuterX |
		ImGuiTableFlags_NoSavedSettings;

	if (ImGui::BeginTable("##cpu_table", 4, flags) == false)
	{
		ImGui::EndChild();
		return;
	}

	const float bar_height = 5.0f * scale;
	const float maximum = (std::max)(max_cpu_rate_, 1.0f);

	ImGui::TableNextRow();

	for (uint32_t index = 0; index < current_.CpuCount && index < HACDBG_TRACE_MAX_CPUS; index++)
	{
		const uint32_t cpu_index = current_.Cpu[index].CpuIndex;

		if (cpu_index >= HACDBG_TRACE_MAX_CPUS)
		{
			continue;
		}

		ImGui::TableNextColumn();
		ImGui::PushID(static_cast<int>(cpu_index));
		ImGui::TextDisabled("CPU %u", cpu_index);

		char rate_buffer[24] = {};
		format_rate(cpu_rate_[cpu_index], rate_buffer, sizeof(rate_buffer));
		ImGui::TextUnformatted(rate_buffer);

		const ImVec2 bar_origin = ImGui::GetCursorScreenPos();
		const float bar_width = (std::max)(ImGui::GetContentRegionAvail().x, 8.0f);
		const float fraction = (std::min)(cpu_rate_[cpu_index] / maximum, 1.0f);
		ImDrawList* const draw_list = ImGui::GetWindowDrawList();

		draw_list->AddRectFilled(bar_origin,
		                         ImVec2(bar_origin.x + bar_width, bar_origin.y + bar_height),
		                         to_u32(theme_.Border), bar_height * 0.5f);
		draw_list->AddRectFilled(bar_origin,
		                         ImVec2(bar_origin.x + bar_width * fraction, bar_origin.y + bar_height),
		                         to_u32(theme_.Accent), bar_height * 0.5f);
		ImGui::Dummy(ImVec2(bar_width, bar_height + 3.0f * scale));
		ImGui::PopID();
	}

	ImGui::EndTable();
	ImGui::EndChild();
}

void trace_view::draw_reason_distribution()
{
	const float scale = static_cast<float>(dpi_) / 96.0f;
	const float height = (std::max)(
		ImGui::GetContentRegionAvail().y - ImGui::GetTextLineHeightWithSpacing(),
		140.0f * scale);

	if (ImGui::BeginChild("##trace_reasons", ImVec2(0.0f, height), ImGuiChildFlags_Borders) == false)
	{
		ImGui::EndChild();
		return;
	}

	ImGui::TextDisabled("Exit reason distribution");

	const ImGuiTableFlags flags =
		ImGuiTableFlags_RowBg |
		ImGuiTableFlags_BordersInnerH |
		ImGuiTableFlags_SizingStretchProp |
		ImGuiTableFlags_NoSavedSettings;

	if (ImGui::BeginTable("##reason_table", 3, flags) == false)
	{
		ImGui::EndChild();
		return;
	}

	ImGui::TableSetupColumn("reason", ImGuiTableColumnFlags_WidthStretch, 1.4f);
	ImGui::TableSetupColumn("rate", ImGuiTableColumnFlags_WidthStretch, 0.75f);
	ImGui::TableSetupColumn("total", ImGuiTableColumnFlags_WidthStretch, 0.85f);
	ImGui::TableHeadersRow();

	bool any_reason = false;

	for (uint32_t reason = 0; reason < HACDBG_TRACE_REASON_COUNT; reason++)
	{
		if (reason_total_[reason] == 0 && reason_rate_[reason] < 0.5f)
		{
			continue;
		}

		any_reason = true;
		char rate_buffer[24] = {};
		char total_buffer[24] = {};
		format_rate(reason_rate_[reason], rate_buffer, sizeof(rate_buffer));
		format_count(reason_total_[reason], total_buffer, sizeof(total_buffer));

		ImGui::TableNextRow();
		ImGui::TableNextColumn();
		ImGui::TextColored(to_vec4(reason_colors[reason]), "%s", reason_names[reason]);
		ImGui::TableNextColumn();
		ImGui::TextUnformatted(rate_buffer);
		ImGui::TableNextColumn();
		ImGui::TextUnformatted(total_buffer);
	}

	if (any_reason == false)
	{
		ImGui::TableNextRow();
		ImGui::TableNextColumn();
		ImGui::TextDisabled("No exits recorded");
	}

	ImGui::EndTable();
	ImGui::EndChild();
}

void trace_view::draw_events()
{
	const float scale = static_cast<float>(dpi_) / 96.0f;
	const float height = (std::max)(
		ImGui::GetContentRegionAvail().y - ImGui::GetTextLineHeightWithSpacing(),
		150.0f * scale);

	if (ImGui::BeginChild("##trace_events", ImVec2(0.0f, height), ImGuiChildFlags_Borders) == false)
	{
		ImGui::EndChild();
		return;
	}

	std::array<event_ref, HACDBG_TRACE_MAX_EVENTS> events = {};
	std::size_t visible_events = 0;

	for (uint32_t index = 0; index < current_.EventCount && index < HACDBG_TRACE_MAX_EVENTS; index++)
	{
		const HACDBG_TRACE_EVENT& event = current_.Events[index];
		const bool cpu_matches = cpu_filter_ < 0 || event.CpuIndex == static_cast<uint32_t>(cpu_filter_);
		const bool reason_matches = event.Reason < HACDBG_TRACE_REASON_COUNT &&
		                            (reason_filter_ & (1u << event.Reason)) != 0;

		if (cpu_matches != false && reason_matches != false)
		{
			events[visible_events].tsc = event.Tsc;
			events[visible_events].index = index;
			visible_events += 1;
		}
	}

	std::sort(events.begin(), events.begin() + static_cast<std::ptrdiff_t>(visible_events),
	          [](const event_ref& left, const event_ref& right)
	{
		return left.tsc > right.tsc;
	});

	ImGui::TextDisabled("Recent events");
	ImGui::SameLine();
	ImGui::TextDisabled("%zu shown / %u in snapshot", visible_events, current_.EventCount);
	ImGui::SameLine();
	ImGui::TextDisabled("duration n/a");

	if ((current_.Flags & HACDBG_TRACE_FLAG_EVENTS_ENABLED) == 0)
	{
		ImGui::TextDisabled("Event capture is off. Enable event mode in the WPF toolbar.");
		ImGui::EndChild();
		return;
	}

	if (visible_events == 0)
	{
		ImGui::TextDisabled("No matching events. Lower the sample interval or wait for exits.");
		ImGui::EndChild();
		return;
	}

	const ImGuiTableFlags flags =
		ImGuiTableFlags_RowBg |
		ImGuiTableFlags_Borders |
		ImGuiTableFlags_ScrollX |
		ImGuiTableFlags_ScrollY |
		ImGuiTableFlags_SizingFixedFit |
		ImGuiTableFlags_NoSavedSettings;

	if (ImGui::BeginTable("##events_table", 7, flags, ImVec2(0.0f, 0.0f)) == false)
	{
		ImGui::EndChild();
		return;
	}

	ImGui::TableSetupScrollFreeze(0, 1);
	ImGui::TableSetupColumn("cpu", ImGuiTableColumnFlags_WidthFixed, 48.0f * scale);
	ImGui::TableSetupColumn("reason", ImGuiTableColumnFlags_WidthFixed, 140.0f * scale);
	ImGui::TableSetupColumn("rip", ImGuiTableColumnFlags_WidthFixed, 150.0f * scale);
	ImGui::TableSetupColumn("cr3", ImGuiTableColumnFlags_WidthFixed, 150.0f * scale);
	ImGui::TableSetupColumn("tsc", ImGuiTableColumnFlags_WidthFixed, 150.0f * scale);
	ImGui::TableSetupColumn("info1", ImGuiTableColumnFlags_WidthFixed, 150.0f * scale);
	ImGui::TableSetupColumn("info2", ImGuiTableColumnFlags_WidthFixed, 150.0f * scale);
	ImGui::TableHeadersRow();

	for (std::size_t visible = 0; visible < visible_events; visible++)
	{
		const HACDBG_TRACE_EVENT& event = current_.Events[events[visible].index];
		const uint32_t reason = event.Reason < HACDBG_TRACE_REASON_COUNT
		                          ? event.Reason
		                          : HACDBG_TRACE_REASON_OTHER;

		ImGui::TableNextRow();
		ImGui::TableNextColumn();
		ImGui::Text("%u", event.CpuIndex);
		ImGui::TableNextColumn();
		ImGui::TextColored(to_vec4(reason_colors[reason]), "%s", reason_names[reason]);
		ImGui::TableNextColumn();
		ImGui::Text("0x%016llX", static_cast<unsigned long long>(event.Rip));
		ImGui::TableNextColumn();
		ImGui::Text("0x%016llX", static_cast<unsigned long long>(event.Cr3));
		ImGui::TableNextColumn();
		ImGui::Text("0x%016llX", static_cast<unsigned long long>(event.Tsc));
		ImGui::TableNextColumn();
		ImGui::Text("0x%llX", static_cast<unsigned long long>(event.ExitInfo1));
		ImGui::TableNextColumn();
		ImGui::Text("0x%llX", static_cast<unsigned long long>(event.ExitInfo2));
	}

	ImGui::EndTable();
	ImGui::EndChild();
}

void trace_view::draw_empty_state()
{
	ImGui::Dummy(ImVec2(0.0f, 24.0f));

	const char* const title = "Waiting for the first trace snapshot";
	const char* const detail = "Enable counters or event mode in the WPF trace toolbar.";
	const float title_width = ImGui::CalcTextSize(title).x;
	const float detail_width = ImGui::CalcTextSize(detail).x;
	const float content_width = ImGui::GetContentRegionAvail().x;

	ImGui::SetCursorPosX((std::max)((content_width - title_width) * 0.5f, 0.0f));
	ImGui::TextColored(to_vec4(theme_.Accent), "%s", title);
	ImGui::SetCursorPosX((std::max)((content_width - detail_width) * 0.5f, 0.0f));
	ImGui::TextDisabled("%s", detail);
}
