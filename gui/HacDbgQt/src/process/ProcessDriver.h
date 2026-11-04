#pragma once

#include <cstdint>

bool processDriverCall(std::uint32_t operation, std::uint32_t pid, std::uint32_t parameter, std::uint32_t flags,
                       const wchar_t* path, std::int32_t* status);

bool processDriverImagePath(std::uint32_t pid, wchar_t* path, std::uint32_t pathChars, std::int32_t* status);

bool processDriverHandleCall(std::uint32_t parameter, std::uint32_t pid, const wchar_t* actor, const wchar_t* victim,
                             std::int32_t* status);
