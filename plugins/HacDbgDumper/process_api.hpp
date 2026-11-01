#pragma once
#include "driver_um_lib.h"
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <string>

namespace process {

    inline bool inited = false;
    inline uint64_t owner_pid = 0;
    inline uint64_t owner_cr3 = 0;
    inline std::string target_process_name;
    inline uint64_t target_pid = 0;
    inline uint64_t target_cr3 = 0;
    inline uint64_t target_module_count = 0;
    inline module_info_t* target_modules = 0;

    inline void release_target_modules() {
        free(target_modules);
        target_modules = nullptr;
        target_module_count = 0;
        inited = false;
    }

    inline bool init_process(std::string process_name) {
        release_target_modules();
        target_process_name = process_name;
        if (!ioctl::init_roseware_lib()) return false;
        if (!ioctl::is_lib_inited()) { logging("Can't init process if the rose instance is not initialized"); return false; }

        owner_pid = GetCurrentProcessId();
        if (!owner_pid) { logging("Failed to get pid of owner process"); return false; }

        owner_cr3 = ioctl::get_cr3(owner_pid);
        if (!owner_cr3) { logging("Failed to get cr3 of owner process"); return false; }

        target_pid = ioctl::get_pid_by_name(process_name.c_str());
        if (!target_pid) { logging("Failed to get pid of target process: %s", process_name.c_str()); return false; }

        target_cr3 = ioctl::get_cr3(target_pid);
        if (!target_cr3) { logging("Failed to get initial CR3 for target process"); return false; }

        target_module_count = ioctl::get_ldr_data_table_entry_count(target_pid);
        if (!target_module_count) { logging("Failed get target module count"); return false; }

        target_modules = (module_info_t*)malloc(sizeof(module_info_t) * target_module_count);
        if (!target_modules) { logging("Failed to alloc memory for modules"); target_module_count = 0; return false; }

        memset(target_modules, 0, sizeof(module_info_t) * target_module_count);
        if (!ioctl::get_data_table_entry_info(target_pid, target_modules)) {
            logging("Failed getting data table entry info");
            release_target_modules();
            return false;
        }

        inited = true;
        return true;
    }

    inline bool attach_to_proc(std::string process_name) {
        return init_process(process_name);
    }

    inline bool init_process_by_pid(uint64_t pid) {
        release_target_modules();
        if (!ioctl::init_roseware_lib()) return false;
        if (!ioctl::is_lib_inited()) { logging("Can't init process if the rose instance is not initialized"); return false; }

        owner_pid = GetCurrentProcessId();
        if (!owner_pid) { logging("Failed to get pid of owner process"); return false; }

        owner_cr3 = ioctl::get_cr3(owner_pid);
        if (!owner_cr3) { logging("Failed to get cr3 of owner process"); return false; }

        target_pid = pid;

        target_cr3 = ioctl::get_cr3(target_pid);
        if (!target_cr3) { logging("Failed to get initial CR3 for target process"); return false; }

        target_module_count = ioctl::get_ldr_data_table_entry_count(target_pid);
        if (!target_module_count) { logging("Failed get target module count"); return false; }

        target_modules = (module_info_t*)malloc(sizeof(module_info_t) * target_module_count);
        if (!target_modules) { logging("Failed to alloc memory for modules"); target_module_count = 0; return false; }

        memset(target_modules, 0, sizeof(module_info_t) * target_module_count);
        if (!ioctl::get_data_table_entry_info(target_pid, target_modules)) {
            logging("Failed getting data table entry info");
            release_target_modules();
            return false;
        }

        inited = true;
        return true;
    }

    inline bool attach_to_proc(uint64_t pid) {
        return init_process_by_pid(pid);
    }

    template <typename t>
    inline t read(void* src, uint64_t size = sizeof(t)) {
        t buffer{};
        if (!ioctl::copy_virtual_memory(target_pid, owner_pid, src, &buffer, size))
            return {};
        return buffer;
    }

    inline bool write(void* dest, void* src, uint64_t size) {
        if (!ioctl::copy_virtual_memory(owner_pid, target_pid, src, dest, size))
            return false;
        return true;
    }

    inline bool read_array(void* dest, void* src, uint64_t size) {
        if (!ioctl::copy_virtual_memory(target_pid, owner_pid, src, dest, size))
            return false;
        return true;
    }

    inline bool write_array(void* dest, void* src, uint64_t size) {
        if (!ioctl::copy_virtual_memory(owner_pid, target_pid, src, dest, size))
            return false;
        return true;
    }

    inline module_info_t get_module(std::string module_name) {
        if (target_modules == nullptr || target_module_count == 0) {
            return { 0 };
        }

        for (uint64_t i = 0; i < target_module_count; i++) {
            if (_stricmp(module_name.c_str(), target_modules[i].name) == 0)
                return target_modules[i];
        }
        for (uint64_t i = 0; i < target_module_count; i++) {
            std::string storedName(target_modules[i].name);
            std::string searchName(module_name);
            std::transform(storedName.begin(), storedName.end(), storedName.begin(), [](unsigned char ch) {
                return static_cast<char>(std::tolower(ch));
            });
            std::transform(searchName.begin(), searchName.end(), searchName.begin(), [](unsigned char ch) {
                return static_cast<char>(std::tolower(ch));
            });
            if (storedName.find(searchName) != std::string::npos || searchName.find(storedName) != std::string::npos)
                return target_modules[i];
        }
        return { 0 };
    }

    inline uint64_t get_module_base(std::string module_name) {
        module_info_t module = get_module(module_name);
        return module.base;
    }

    inline uint64_t get_module_size(std::string module_name) {
        module_info_t module = get_module(module_name);
        return module.size;
    }

    inline void logging_modules(void) {
        if (target_modules == nullptr) {
            return;
        }
        for (uint64_t i = 0; i < target_module_count; i++)
            logging("%s", target_modules[i].name);
    }

    inline uint64_t get_pid(std::string process_name) {
        return ioctl::get_pid_by_name(process_name.c_str());
    }
};
