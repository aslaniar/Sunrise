#pragma once
#include <Windows.h>
#include <array>
#include <cstdio>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace sunrise::server::http::presence {

/** One peer's presence keys, keyed by its little-endian xuid string as published. */
inline constexpr std::size_t kMaxPeers = 8;
inline constexpr std::size_t kMaxKeyBytes = 96;
inline constexpr std::size_t kMaxValueBytes = 160;

struct Entry {
    std::uint64_t xuid{};
    char key[kMaxKeyBytes]{};
    char value[kMaxValueBytes]{};
};

/** Stores one key for one xuid. Overwrites same key. @return True when stored. */
bool store(std::uint64_t xuid, std::string_view key, std::string_view value) noexcept;

/** Copies every stored entry flattened as lines "xuid key value\n" into output. */
std::size_t snapshot(char* output, std::size_t capacity) noexcept;

}
