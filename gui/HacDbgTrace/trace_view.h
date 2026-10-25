#pragma once

#include "hacdbg_trace_api.h"

#include <array>
#include <cstddef>
#include <cstdint>

class trace_view
{
public:
	static constexpr std::size_t timeline_capacity = 180;

	explicit trace_view(const HACDBG_TRACE_THEME& theme);

	void set_theme(const HACDBG_TRACE_THEME& theme);
	void set_dpi(uint32_t dpi);
	void ingest(const HACDBG_TRACE_SNAPSHOT& snapshot, uint64_t generation, double now_seconds);
	void draw();
	void reset_view();
	bool display_paused() const;
	uint64_t generation() const;

private:
	struct event_ref
	{
		uint64_t tsc = 0;
		uint32_t index = 0;
	};

	void apply_style();
	void reset_metrics();
	void push_rate(float rate);
	void draw_header();
	void draw_summary();
	void draw_filters();
	void draw_timeline();
	void draw_detail_tabs();
	void draw_cpu_heatmap();
	void draw_reason_distribution();
	void draw_events();
	void draw_empty_state();

	HACDBG_TRACE_THEME theme_ = {};
	uint32_t dpi_ = 96;
	bool style_dirty_ = true;

	HACDBG_TRACE_SNAPSHOT current_ = {};
	HACDBG_TRACE_SNAPSHOT previous_ = {};
	bool has_snapshot_ = false;
	bool has_previous_ = false;
	bool paused_ = false;
	uint64_t seen_generation_ = 0;
	double last_ingest_seconds_ = 0.0;

	float total_rate_ = 0.0f;
	std::array<float, HACDBG_TRACE_MAX_CPUS> cpu_rate_ = {};
	std::array<float, HACDBG_TRACE_REASON_COUNT> reason_rate_ = {};
	std::array<uint64_t, HACDBG_TRACE_REASON_COUNT> reason_total_ = {};
	std::array<bool, HACDBG_TRACE_MAX_CPUS> cpu_present_ = {};
	float max_cpu_rate_ = 0.0f;

	std::array<float, timeline_capacity> timeline_ = {};
	std::size_t timeline_head_ = 0;
	std::size_t timeline_count_ = 0;

	int cpu_filter_ = -1;
	uint32_t reason_filter_ = HACDBG_TRACE_EVENT_MASK_ALL;
};
