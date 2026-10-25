#include <Windows.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>

#include "hypercall.h"

namespace
{
	const char* const reason_names[HACDBG_TRACE_REASON_COUNT] = {
		"other",
		"cpuid",
		"msr",
		"nested-page-fault",
		"io",
		"exception",
		"halt",
		"shutdown",
		"interrupt-window",
		"external-interrupt",
		"preemption-timer",
		"vmx-instruction",
		"svm-instruction",
		"xsetbv",
		"invd",
		"monitor-trap"
	};

	void print_usage()
	{
		std::printf(
			"HacDbgTraceProbe --enable-counters | --enable-events | --disable\n"
			"                 [--reset] [--sample N] [--mask HEX]\n"
			"                 [--wait MS] [--read [--cpu N] [--events N]]\n"
			"\n"
			"Control flags may be combined. --reset disables capture before clearing,\n"
			"so include --enable-counters or --enable-events to start again immediately.\n"
			"--events limits how many events are printed; it does not enable capture.\n"
			"trace_control and trace_read hypercalls are excluded from the counters.\n");
	}

	bool parse_u64(const char* const text, std::uint64_t& value_out)
	{
		char* end = nullptr;

		value_out = std::strtoull(text, &end, 0);
		return end != text && *end == '\0';
	}

	const char* mode_name(const std::uint32_t flags)
	{
		if ((flags & HACDBG_TRACE_FLAG_EVENTS_ENABLED) != 0)
		{
			return "events";
		}

		if ((flags & HACDBG_TRACE_FLAG_COUNTERS_ENABLED) != 0)
		{
			return "counters";
		}

		return "disabled";
	}
}

int
main(const int argc, char** const argv)
{
	std::uint64_t control_flags = 0;
	std::uint64_t sample_rate = 0;
	std::uint64_t event_mask = 0;
	std::uint64_t wait_ms = 0;
	std::uint64_t cpu_filter = HACDBG_TRACE_ALL_CPUS;
	std::uint32_t event_limit = 16;
	bool control = false;
	bool read = false;

	for (int index = 1; index < argc; index++)
	{
		const char* const argument = argv[index];

		if (std::strcmp(argument, "--help") == 0 || std::strcmp(argument, "-h") == 0)
		{
			print_usage();
			return 0;
		}

		if (std::strcmp(argument, "--enable-counters") == 0)
		{
			control_flags |= HACDBG_TRACE_CONTROL_ENABLE_COUNTERS;
			control = true;
		}
		else if (std::strcmp(argument, "--enable-events") == 0)
		{
			control_flags |= HACDBG_TRACE_CONTROL_ENABLE_COUNTERS |
			                 HACDBG_TRACE_CONTROL_ENABLE_EVENTS;
			control = true;
		}
		else if (std::strcmp(argument, "--disable") == 0)
		{
			control_flags |= HACDBG_TRACE_CONTROL_DISABLE;
			control = true;
		}
		else if (std::strcmp(argument, "--reset") == 0)
		{
			control_flags |= HACDBG_TRACE_CONTROL_RESET;
			control = true;
		}
		else if (std::strcmp(argument, "--read") == 0)
		{
			read = true;
		}
		else if (std::strcmp(argument, "--sample") == 0)
		{
			if (index + 1 >= argc || parse_u64(argv[++index], sample_rate) == false ||
			    sample_rate > UINT32_MAX)
			{
				std::fprintf(stderr, "err, invalid sample rate\n");
				return 2;
			}

			control_flags |= HACDBG_TRACE_CONTROL_SET_SAMPLE_RATE;
			control = true;
		}
		else if (std::strcmp(argument, "--mask") == 0)
		{
			if (index + 1 >= argc || parse_u64(argv[++index], event_mask) == false ||
			    event_mask > HACDBG_TRACE_EVENT_MASK_ALL)
			{
				std::fprintf(stderr, "err, invalid event mask\n");
				return 2;
			}

			control_flags |= HACDBG_TRACE_CONTROL_SET_EVENT_MASK;
			control = true;
		}
		else if (std::strcmp(argument, "--wait") == 0)
		{
			if (index + 1 >= argc || parse_u64(argv[++index], wait_ms) == false ||
			    wait_ms > 600000)
			{
				std::fprintf(stderr, "err, invalid wait time\n");
				return 2;
			}
		}
		else if (std::strcmp(argument, "--cpu") == 0)
		{
			if (index + 1 >= argc || parse_u64(argv[++index], cpu_filter) == false ||
			    cpu_filter > UINT32_MAX)
			{
				std::fprintf(stderr, "err, invalid CPU index\n");
				return 2;
			}
		}
		else if (std::strcmp(argument, "--events") == 0)
		{
			std::uint64_t limit = 0;

			if (index + 1 >= argc || parse_u64(argv[++index], limit) == false ||
			    limit > HACDBG_TRACE_MAX_EVENTS)
			{
				std::fprintf(stderr, "err, invalid event count\n");
				return 2;
			}

			event_limit = static_cast<std::uint32_t>(limit);
		}
		else
		{
			std::fprintf(stderr, "err, unknown argument: %s\n", argument);
			print_usage();
			return 2;
		}
	}

	if (control == false && read == false)
	{
		print_usage();
		return 2;
	}

	std::uint32_t major = 0;
	std::uint32_t minor = 0;
	std::uint32_t patch = 0;
	std::uint32_t abi = 0;
	std::string version;

	if (hypercall::query_driver_version(major, minor, patch, abi, version) == 0)
	{
		std::fprintf(stderr, "err, hypervisor version query failed\n");
		return 1;
	}

	std::printf("hypervisor: %s (hypercall abi %u)\n", version.c_str(), abi);

	if (control != false)
	{
		const std::uint64_t result = hypercall::trace_control(
			control_flags, static_cast<std::uint32_t>(sample_rate),
			static_cast<std::uint32_t>(event_mask));

		std::printf("trace_control: %s\n", result != 0 ? "ok" : "failed");

		if (result == 0)
		{
			return 1;
		}
	}

	if (wait_ms != 0)
	{
		Sleep(static_cast<DWORD>(wait_ms));
	}

	if (read == false)
	{
		return 0;
	}

	std::unique_ptr<HACDBG_TRACE_SNAPSHOT> snapshot(new HACDBG_TRACE_SNAPSHOT());
	const std::uint64_t copied = hypercall::trace_read(
		*snapshot, static_cast<std::uint32_t>(cpu_filter));

	if (copied != sizeof(*snapshot))
	{
		std::fprintf(stderr, "err, trace_read returned %I64u of %Iu bytes\n", copied,
		             sizeof(*snapshot));
		return 1;
	}

	std::printf("snapshot: version=%u mode=%s cpus=%u events=%u total=%I64u dropped=%I64u "
	            "tsc=0x%I64x\n",
	            snapshot->Version, mode_name(snapshot->Flags), snapshot->CpuCount,
	            snapshot->EventCount, snapshot->TotalExits, snapshot->DroppedEvents,
	            snapshot->CapturedTsc);

	if (event_limit != 0 && (snapshot->Flags & HACDBG_TRACE_FLAG_EVENTS_ENABLED) == 0)
	{
		std::fprintf(stderr,
		             "warn, event capture is disabled; use --enable-events instead of "
		             "--enable-counters to record events\n");
	}
	else if ((snapshot->Flags & HACDBG_TRACE_FLAG_EVENTS_ENABLED) != 0 &&
	         snapshot->EventCount == 0)
	{
		std::fprintf(stderr,
		             "warn, no event reached the sampling interval; retry with "
		             "--sample 1 to verify the ring\n");
	}

	std::uint64_t reason_totals[HACDBG_TRACE_REASON_COUNT] = {};
	for (std::uint32_t cpu = 0; cpu < snapshot->CpuCount; cpu++)
	{
		const HACDBG_TRACE_CPU& counters = snapshot->Cpu[cpu];

		if (counters.TotalExits != 0 || counters.DroppedEvents != 0)
		{
			std::printf("cpu %u: total=%I64u dropped=%u\n", counters.CpuIndex,
			            counters.TotalExits, counters.DroppedEvents);
		}

		for (std::uint32_t reason = 0; reason < HACDBG_TRACE_REASON_COUNT; reason++)
		{
			reason_totals[reason] += counters.ReasonCounts[reason];
		}
	}

	for (std::uint32_t reason = 0; reason < HACDBG_TRACE_REASON_COUNT; reason++)
	{
		if (reason_totals[reason] != 0)
		{
			std::printf("reason %-20s %I64u\n", reason_names[reason], reason_totals[reason]);
		}
	}

	const std::uint32_t shown = snapshot->EventCount < event_limit
	                                ? snapshot->EventCount
	                                : event_limit;

	for (std::uint32_t index = 0; index < shown; index++)
	{
		const HACDBG_TRACE_EVENT& event = snapshot->Events[index];
		const char* const reason = event.Reason < HACDBG_TRACE_REASON_COUNT
		                               ? reason_names[event.Reason]
		                               : "invalid";

		std::printf("event %u: cpu=%u reason=%-20s rip=0x%I64x cr3=0x%I64x "
		            "info1=0x%I64x info2=0x%I64x tsc=0x%I64x flags=0x%x\n",
		            index, event.CpuIndex, reason, event.Rip, event.Cr3,
		            event.ExitInfo1, event.ExitInfo2, event.Tsc, event.Flags);
	}

	return 0;
}
