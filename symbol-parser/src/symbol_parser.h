#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace symbol_parser
{
	struct module_status_t
	{
		std::string name = {};
		std::uint64_t base = 0;
		std::uint32_t size = 0;
		std::string pdb_path = {};
	};

	struct symbol_match_t
	{
		std::string name = {};
		std::uint64_t address = 0;
	};

	struct type_field_t
	{
		std::uint32_t offset = 0;
		std::uint32_t bit_position = 0;
		std::uint32_t bit_length = 0;
		std::uint64_t size = 0;
		std::uint8_t bitfield = 0;
		std::uint8_t integer = 0;
		std::uint8_t pointer = 0;
		std::string name = {};
		std::string type_name = {};
	};

	struct type_info_t
	{
		std::string module = {};
		std::uint64_t base = 0;
		std::string name = {};
		std::uint64_t size = 0;
		std::vector<type_field_t> fields = {};
	};

	using image_read_t = std::function<std::uint8_t(std::uint64_t rva, void* buffer, std::uint64_t size)>;

	void set_interrupt_check(std::uint8_t (*check)());
	void set_search_path(std::string path);
	void append_search_path(std::string path);
	std::string search_path();
	void use_microsoft_server(std::string cache_directory, std::uint8_t append);
	std::uint32_t options();

	std::uint8_t load_module(std::string_view name, std::uint64_t base, std::uint32_t size, const image_read_t& read_image,
	                         std::string_view image_path, std::uint8_t force, std::uint8_t overwrite, std::string& detail);
	void unload_module(std::uint64_t base);
	void unload();
	std::vector<module_status_t> loaded_modules();

	std::uint8_t resolve(std::string_view module, std::string_view symbol, std::uint64_t& address_out);
	std::uint8_t nearest(std::uint64_t address, std::string& name_out, std::uint64_t& displacement_out);
	std::uint8_t nearest_span(std::uint64_t address, std::string& name_out, std::uint64_t& displacement_out,
	                          std::uint64_t& size_out);
	std::vector<symbol_match_t> enumerate(std::string_view module, std::string_view mask, std::size_t limit);
	std::uint8_t query_type(std::string_view module, std::string_view type_name, type_info_t& info_out, std::string& detail);
}
