#include <Windows.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include "../../../core/filesystem/path.h"
#include "internal.h"

namespace sunrise::state::build_data::cache {

/** Cache file name relative to the module directory (server_main's constant). */
constexpr std::wstring_view kCacheFileSuffix = L"\\Sunrise\\cache\\build_data.bin";
/** The largest cache file the stamp rewrites; anything bigger is never a valid cache. */
constexpr std::uint64_t kMaximumPatchSize = 16U * 1024U * 1024U;

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
    core::path::Buffer path{};
    if (!core::path::module_directory(GetModuleHandleW(nullptr), path)) {
        return false;
    }
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
    LARGE_INTEGER size{};
    if (GetFileSizeEx(file, &size) == FALSE || size.QuadPart <= 96
        || static_cast<std::uint64_t>(size.QuadPart) > kMaximumPatchSize) {
        (void)CloseHandle(file);
        return false;
    }
    // The WHOLE file is read and rewritten (the payload rides along untouched): the temp
    // file that replaces the final name must carry the full cache, never just the header.
    std::vector<std::byte> body(static_cast<std::size_t>(size.QuadPart));
    DWORD readBytes = 0;
    const bool headerOk = ReadFile(file, body.data(), static_cast<DWORD>(body.size()),
                                   &readBytes, nullptr) != FALSE
                          && readBytes == body.size();
    (void)CloseHandle(file);
    if (!headerOk) {
        return false;
    }
    std::memcpy(body.data() + 20, &hash, sizeof hash);

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
    const bool written = WriteFile(output, body.data(), static_cast<DWORD>(body.size()),
                                   &writtenBytes, nullptr) != FALSE
                         && writtenBytes == body.size();
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
