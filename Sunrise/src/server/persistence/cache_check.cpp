#include "cache_check.h"

#include <Windows.h>

#include <array>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string_view>

#include "../../core/logging/log.h"
#include "../../state/build_data/socket_entry_lists/definition.h"
#include "../../state/build_data/cache/records/format.h"

namespace sunrise::server::persistence {
namespace {

void report(const char* format, ...) noexcept {
    std::array<char, 256> line{};
    va_list args;
    va_start(args, format);
    const int written = std::vsnprintf(line.data(), line.size(), format, args);
    va_end(args);
    if (written <= 0) {
        return;
    }
    std::fputs(line.data(), stdout);
    std::fputc('\n', stdout);
    std::fflush(stdout);
}

/** @return The reader's checksum over the disk bytes at [offset, offset+size). */
std::uint64_t extend(std::uint64_t checksum, const std::byte* data, std::size_t size) noexcept {
    for (std::size_t i = 0; i < size; ++i) {
        checksum ^= std::to_integer<std::uint8_t>(data[i]);
        checksum *= state::build_data::cache::records::kChecksumPrime;
    }
    return checksum;
}

} // namespace

/** Verifies the deployed cache against the reader's exact model + prints every check. */
int run_cache_check(void* module) noexcept {
    using namespace state::build_data::cache;
    (void)module;
    const HANDLE file = CreateFileW(L"Sunrise\\cache\\build_data.bin",
                                    GENERIC_READ,
                                    FILE_SHARE_READ,
                                    nullptr,
                                    OPEN_EXISTING,
                                    FILE_ATTRIBUTE_NORMAL,
                                    nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        report("ev=cache_check stage=open result=fail error=%lu", GetLastError());
        return 1;
    }
    LARGE_INTEGER size{};
    GetFileSizeEx(file, &size);
    report("ev=cache_check stage=size result=ok bytes=%lld", size.QuadPart);

    records::Header header{};
    DWORD read = 0;
    const bool headerOk = ReadFile(file, &header, sizeof header, &read, nullptr) != FALSE
                          && read == sizeof header;
    report("ev=cache_check stage=header result=%s sizeof=%zu magic=%s version=%u",
           headerOk ? "ok" : "fail",
           sizeof(records::Header),
           header.magic.data(),
           header.version);
    report("ev=cache_check stage=identity ts=0x%08X size=0x%X eq=0x%016llX",
           header.imageTimestamp,
           header.imageSize,
           static_cast<unsigned long long>(header.configuredEquipmentHash));
    report("ev=cache_check stage=counts n=%u i=%u d=%u b=%u s=%u t=%u a=%u p=%u sc=%u r=%u "
           "st=%u nh=%u sp=%u hn=%u",
           header.namedCount,
           header.itemCount,
           header.itemDetailCount,
           header.inventoryBucketCount,
           header.socketEntryListCount,
           header.socketEntryTableCount,
           header.abilityBucketCount,
           header.progressionCount,
           header.scenarioCount,
           header.rosterGroupCount,
           header.spawnStemCount,
           header.spawnNameHashCount,
           header.spawnPointCount,
           header.hashNameCount);
    report("ev=cache_check stage=stored_checksum value=0x%016llX",
           static_cast<unsigned long long>(header.payloadChecksum));

    // the reader's expected checksum, over the file's bytes from the header's end
    SetFilePointer(file, 0, nullptr, FILE_BEGIN);
    std::uint64_t checksum = records::kChecksumOffsetBasis;
    checksum = extend(checksum,
                      reinterpret_cast<const std::byte*>(&header.constants),
                      sizeof(records::InvestmentConstants));
    std::array<std::byte, 64 * 1024> buffer{};
    DWORD remaining = 0;
    SetFilePointer(file, static_cast<LONG>(sizeof header), nullptr, FILE_BEGIN);
    while (ReadFile(file, buffer.data(), static_cast<DWORD>(buffer.size()), &remaining, nullptr)
           && remaining != 0) {
        checksum = extend(checksum, buffer.data(), remaining);
    }
    report("ev=cache_check stage=computed_checksum value=0x%016llX match=%s",
           static_cast<unsigned long long>(checksum),
           checksum == header.payloadChecksum ? "yes" : "NO");
    CloseHandle(file);
    return checksum == header.payloadChecksum ? 0 : 1;
}

} // namespace sunrise::server::persistence
