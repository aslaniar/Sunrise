#include <Windows.h>

#include <array>
#include <cstdint>
#include <cstring>

#include "../../../core/filesystem/path.h"
#include "internal.h"

namespace sunrise::state::build_data::cache {

/** Cache file name relative to the owned artifact directory (server_main's constant). */
constexpr std::wstring_view kCacheFileSuffix = L"\\Sunrise\\cache\\build_data.bin";

/**
 * Re-stamps the cache header's configured-equipment hash after a persisted equipment
 * mutation. The image timestamp and size stay (the executable did not change mid-session),
 * and the payload checksum is untouched (it covers constants and domains, never the
 * identity fields). The write goes through a same-directory temporary file and an atomic
 * rename, so a torn header can never be observed.
 * @param hash Configured-equipment hash of the post-mutation account.
 * @return True when the file is on disk under its final name with the new hash.
 */
bool restamp_equipment_hash(std::uint64_t hash) noexcept {
    core::path::Buffer directory{};
    if (!core::path::artifact_directory(GetModuleHandleW(nullptr), directory)) {
        return false;
    }
    core::path::Buffer path = directory;
    if (!core::path::append(path, kCacheFileSuffix)) {
        return false;
    }
    const HANDLE file = CreateFileW(path.chars.data(),
                                    GENERIC_READ,
                                    FILE_SHARE_READ,
                                    nullptr,
                                    OPEN_EXISTING,
                                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                                    nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }
    std::array<std::byte, 96> header{};
    DWORD readBytes = 0;
    const bool headerOk = ReadFile(file, header.data(), static_cast<DWORD>(header.size()),
                                   &readBytes, nullptr) != FALSE
                          && readBytes == header.size();
    (void)CloseHandle(file);
    if (!headerOk) {
        return false;
    }
    std::memcpy(header.data() + 20, &hash, sizeof hash);

    core::path::Buffer temporary = path;
    if (!core::path::append(temporary, L".stamp")) {
        return false;
    }
    const HANDLE output = CreateFileW(temporary.chars.data(),
                                      GENERIC_WRITE,
                                      0,
                                      nullptr,
                                      CREATE_ALWAYS,
                                      FILE_ATTRIBUTE_NORMAL,
                                      nullptr);
    if (output == INVALID_HANDLE_VALUE) {
        return false;
    }
    DWORD writtenBytes = 0;
    const bool written = WriteFile(output, header.data(), static_cast<DWORD>(header.size()),
                                   &writtenBytes, nullptr) != FALSE
                         && writtenBytes == header.size();
    (void)CloseHandle(output);
    if (!written) {
        (void)DeleteFileW(temporary.chars.data());
        return false;
    }
    if (MoveFileExW(temporary.chars.data(),
                    path.chars.data(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)
        == FALSE) {
        (void)DeleteFileW(temporary.chars.data());
        return false;
    }
    return true;
}

} // namespace sunrise::state::build_data::cache
