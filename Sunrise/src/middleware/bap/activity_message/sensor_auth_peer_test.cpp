#include "sensor_auth_peer_test.h"

#include <array>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <span>

#include "sensor_auth_update.h"

namespace sunrise::middleware::bap::activity_message::sensor_auth_update {
namespace {

/**
 * The frozen fixture. Its shape mirrors what a Tower roster push carries: one group whose
 * first slots are two participation slots and a lifetime slot, a region, a spawn override.
 * The expected bodies were produced by the pre-peer encoder (git HEAD) for the off case and
 * are asserted BYTE-EXACT below - that is the whole point of the off-path assertion.
 */
constexpr std::uint8_t kSlotTypes[] = {13, 13, 17, 8};
constexpr std::uint8_t kSlotFlags[] = {3, 3, 1, 0};
constexpr std::uint64_t kLocalKey = 0x1111111122222222ULL;
constexpr std::uint64_t kPeerKey = 0x3333333344444444ULL;
/** The 64-bit key is written MSB-first, so its bit position is asserted, not its byte copy. */
constexpr std::size_t kLocalKeyBit = 765;
/** One full object block later: 88 header bits + reset + auth-present + 224 body + sense. */
constexpr std::size_t kPeerKeyBit = 1080;

/** @param c Hex character of one nibble. @return Its unsigned value. */
[[nodiscard]] constexpr unsigned hex_nibble(const char c) noexcept {
    return static_cast<unsigned>(c <= '9' ? c - '0' : c - 'A' + 10);
}

/** @return The frozen bytes the pre-peer encoder produced for the fixture with no peer. */
[[nodiscard]] constexpr std::array<std::byte, 147> expected_off_body() noexcept {
    constexpr std::array<const char*, 5> hex = {
        "00000000000000000A000000000000000B0000000000000000780468ACF13600",
        "0000020000000000000000000000000000000000000000000000000000000100",
        "C0A3456789A000000011A2B3C4D1D0000000001C7E00000015C5000000000108",
        "88888889111111100300080404000000023456789A3A00040000000E468ACF13",
        "49400100000000A3456789A26000C000000000"};
    std::array<std::byte, 147> out{};
    for (std::size_t index = 0; index < out.size(); ++index) {
        const std::size_t position = index * 2;
        const char high = hex[position / 64][position % 64];
        const char low = hex[(position + 1) / 64][(position + 1) % 64];
        out[index] = static_cast<std::byte>(hex_nibble(high) * 16U + hex_nibble(low));
    }
    return out;
}

/** @return The frozen bytes the peer-aware encoder must produce for the fixture with a peer. */
[[nodiscard]] constexpr std::array<std::byte, 175> expected_peer_body() noexcept {
    constexpr std::array<const char*, 6> hex = {
        "00000000000000000A000000000000000B0000000000000000780468ACF13600",
        "0000020000000000000000000000000000000000000000000000000000000100",
        "C0A3456789A000000011A2B3C4D1D0000000001C7E00000015C5000000000108",
        "88888889111111100300080404000000023456789A3A00040000038FC0000003",
        "B8A000000000213333333344444444006001008080000000468ACF1349400100",
        "000000A3456789A26000C000000000"};
    std::array<std::byte, 175> out{};
    for (std::size_t index = 0; index < out.size(); ++index) {
        const std::size_t position = index * 2;
        const char high = hex[position / 64][position % 64];
        const char low = hex[(position + 1) / 64][(position + 1) % 64];
        out[index] = static_cast<std::byte>(hex_nibble(high) * 16U + hex_nibble(low));
    }
    return out;
}

/** Builds the fixture snapshot. @param withPeer When set, the peer binding is staged. */
[[nodiscard]] Snapshot fixture(const bool withPeer) noexcept {
    Snapshot snapshot{};
    snapshot.patchEpoch = {0xA, 0xB};
    snapshot.roster.groupCount = 1;
    snapshot.roster.groups[0].key = 0x1A2B3C4DU;
    snapshot.roster.groups[0].slotTypes = std::span<const std::uint8_t>(kSlotTypes, 4);
    snapshot.roster.groups[0].slotFlags = std::span<const std::uint8_t>(kSlotFlags, 4);
    snapshot.roster.playerKeyGroup = 0x1A2B3C4DU;
    snapshot.playerKey = kLocalKey;
    snapshot.region = 5;
    snapshot.hasRegion = true;
    snapshot.lifetime = 3;
    snapshot.spawnSliceSet = 48;
    snapshot.spawnSetHash = 0xDEADBEEFU;
    snapshot.hasSpawnOverride = true;
    snapshot.stateSequence = 1;
    if (withPeer) {
        snapshot.peer.playerKey = kPeerKey;
        snapshot.peer.region = 7;
        snapshot.peer.hasRegion = true;
        snapshot.peer.hasPeer = true;
    }
    return snapshot;
}

/** @return The zero-based bit at @p index of the body, MSB-first within each byte. */
[[nodiscard]] bool body_bit(const std::span<const std::byte> body,
                            const std::size_t index) noexcept {
    const std::size_t byte = index / 8;
    const unsigned offset = static_cast<unsigned>(index % 8);
    return (std::to_integer<unsigned>(body[byte]) >> (7U - offset)) & 1U;
}

/** @return The 64-bit MSB-first value at @p bit. */
[[nodiscard]] std::uint64_t body_key(const std::span<const std::byte> body,
                                     const std::size_t bit) noexcept {
    std::uint64_t value = 0;
    for (std::size_t offset = 0; offset < 64; ++offset) {
        value = (value << 1U) | (body_bit(body, bit + offset) ? 1ULL : 0ULL);
    }
    return value;
}

/** Reports one failure and counts it. */
bool fail(int& failures, const char* what) noexcept {
    std::printf("sensor_auth_peer_test FAIL: %s\n", what);
    ++failures;
    return false;
}

} // namespace

int run_sensor_auth_peer_test() noexcept {
    int failures = 0;
    std::byte output[4096]{};
    std::size_t written = 0;

    // OFF PATH: byte-identical to the pre-peer encoder. This is the inertness guarantee.
    if (!encode_sensor_auth_update(fixture(false), output, written)) {
        fail(failures, "off-path encode refused");
        return failures == 0 ? 0 : 1;
    }
    constexpr auto expected = expected_off_body();
    if (written != expected.size()) {
        fail(failures, "off-path size changed");
    } else if (std::memcmp(output, expected.data(), expected.size()) != 0) {
        fail(failures, "off-path body is not bit-identical to the pre-peer encoder");
    }

    // ON PATH: byte-identical to the frozen peer-aware body.
    if (!encode_sensor_auth_update(fixture(true), output, written)) {
        fail(failures, "peer-path encode refused");
        return failures == 0 ? 0 : 1;
    }
    constexpr auto expectedPeer = expected_peer_body();
    if (written != expectedPeer.size()) {
        fail(failures, "peer-path size changed");
    } else if (std::memcmp(output, expectedPeer.data(), expectedPeer.size()) != 0) {
        fail(failures, "peer-path body does not match the frozen expectation");
    }

    // Structural reads, stated so a failure names itself: local key stays where it always was,
    // the peer key sits exactly one whole object block later.
    const std::span<const std::byte> body(output, written);
    if (const std::uint64_t local = body_key(body, kLocalKeyBit); local != kLocalKey) {
        std::printf("sensor_auth_peer_test FAIL: local key at bit %zu is %llX\n",
                    kLocalKeyBit,
                    static_cast<unsigned long long>(local));
        ++failures;
    }
    if (const std::uint64_t peer = body_key(body, kPeerKeyBit); peer != kPeerKey) {
        std::printf("sensor_auth_peer_test FAIL: peer key at bit %zu is %llX\n",
                    kPeerKeyBit,
                    static_cast<unsigned long long>(peer));
        ++failures;
    }

    // NEGATIVE: a staged peer without an identity is refused, not encoded with a zero key.
    Snapshot bad = fixture(true);
    bad.peer.playerKey = 0;
    if (encode_sensor_auth_update(bad, output, written)) {
        fail(failures, "zero peer key was accepted");
    }

    if (failures == 0) {
        std::printf("sensor_auth_peer_test PASS (off bit-identical, peer block 315 bits)\n");
    }
    return failures == 0 ? 0 : 1;
}

} // namespace sunrise::middleware::bap::activity_message::sensor_auth_update
