#include "logs.h"

#include <memory>

#include <spdlog/sinks/sink.h>

namespace
{
	class output_sink_t final : public spdlog::sinks::sink
	{
	public:
		void log(const spdlog::details::log_msg& message) override
		{
			output::kind_t kind = output::kind_t::info;

			if (message.level == spdlog::level::warn)
			{
				kind = output::kind_t::warning;
			}
			else if (message.level == spdlog::level::err || message.level == spdlog::level::critical)
			{
				kind = output::kind_t::error;
			}

			output::write(kind, std::string_view(message.payload.data(), message.payload.size()));
		}

		void flush() override
		{
			output::flush();
		}

		void set_pattern(const std::string&) override
		{
		}

		void set_formatter(std::unique_ptr<spdlog::formatter>) override
		{
		}
	};
}

void logs::set_up()
{
	auto sink = std::make_shared<output_sink_t>();
	auto logger = std::make_shared<spdlog::logger>("HacDbg", sink);

	logger->set_level(spdlog::level::trace);
	spdlog::set_default_logger(std::move(logger));
}
