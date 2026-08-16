#include "activity_world_population_push.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdio>
#include <cstdint>

#include "../../../../../core/logging/log.h"
#include "../../../../../core/settings/settings.h"
#include "../../../../../middleware/bap/activity_message/activity_entity_baseline.h"
#include "../../../../../middleware/bap/activity_message/activity_patch_epoch_parser.h"
#include "../../../../../middleware/secure_channel/runtime.h"
#include "activity_notification_frame.h"

namespace sunrise::server::bap::encrypted::push::activity {
namespace {

namespace service = middleware::bap::activity_message;

/** Patch-epoch bump uses activity message type 52. */
constexpr std::uint32_t kPatchEpochMessageType = service::patch_epoch::kMessageType;
/** The fixed epoch payload is two big-endian 64-bit fields. */
constexpr std::size_t kPatchEpochSize = service::patch_epoch::kEncodedSize;

/**
 * The RESOLVED entity carrier (claims/sobject-carrier.md): the sim-event type 7
 * sobject_message record rides the queue-event envelope. The client's router
 * FUN_1416E6ED0 dispatches svc-9 activity message type 17 (0x11) to FUN_1416F0F60
 * ("simulation_queue_bap_message_queue_event_apply"), which parses
 * {u32 a, u32 sessionIndex, u32 eventType, u32 size, payload[size], tail[136 B]}
 * (lane_sobject_ghidra2.txt lines 63-72), then applies per eventType -- 7 =
 * _simulation_event_type_sobject_message. The settings knob worldPopulationCarrier names
 * the sim-event type (default 7); the svc-9 envelope type is fixed at 17.
 */
constexpr std::uint32_t kQueueEventMessageType = 17;
/** Sim-event type 7 = sobject_message (the 22-entry name array @ 0x1420377A0). */
constexpr std::uint32_t kSobjectMessageEventType = 7;
/** The queue-event header is 4 x u32. */
constexpr std::size_t kQueueEventHeaderSize = 4 * sizeof(std::uint32_t);
/** The queue-event tail is a fixed 136-byte field (0x440 bits, FUN_1416F0F60). */
constexpr std::size_t kQueueEventTailSize = 136;
/** Whole queue-event body: header + 0x89 record + tail. */
constexpr std::size_t kQueueEventBodySize =
    kQueueEventHeaderSize + service::entity_baseline::kSobjectMessageSize
    + kQueueEventTailSize;
/**
 * Session index in the queue-event header. The client indexes its session records
 * (stride 0x81e8, gate session + 0x90 == 1) by this value; the Tower boot has one
 * activity session, so 0 is the probe value (the apply no-ops safely when it misses).
 */
constexpr std::uint32_t kProbeSessionIndex = 0;

/**
 * Entity slot the v0 baseline claims: the top of the lease mask (O1, spec 3.3). The join
 * still grants the whole 8192-bit mask today, so this slot's lease bit is set; whether
 * the client renders it without simulating it is the O1 observation the boot makes.
 */
constexpr std::uint16_t kWorldPopulationSlot = 8191;
/** Local entity registry index for the header's 8-bit field (1 = not the player). */
constexpr std::uint8_t kWorldPopulationLocalIndex = 1;

/**
 * THE VENDOR-FIRST BASELINE: Commander Zavala (vendor_definitions_full.json
 * definitionHash 0x04243655, tag 0x8131908E) at his Tower spot. The placement point:
 * spawn set 0x80ED3B2D (w64_city_tower_d2_0369_6.pkg), point 18 -- position
 * [53.69, 65.9, 18.03], rotation quat [0, 0, -1, -0.003], nameHash 0x5B9195B4
 * (RE_output/content/spawn_sets_full.json; the set's label row covers bubbles
 * [0,1,3,4,7] and the cin_300_vnd / cin_320_rev vendor scenarios -- the courtyard).
 * The name hash is the point's own FNV-1 hash: the internal vendor-point name is not
 * corpus-resolvable, and the position matters most for the first gate.
 */
constexpr std::array<float, 3> kVendorPosition{53.69F, 65.90F, 18.03F};
constexpr std::uint32_t kVendorPointNameHash = 0x5B9195B4U;

/** Wipes the part of one scratch buffer that may hold written bytes. */
void clear_prefix(std::span<std::byte> buffer, std::size_t size) noexcept {
    SecureZeroMemory(buffer.data(), (std::min)(buffer.size(), size));
}

/** Writes one u32 big-endian (the queue-event header's wire order). */
void write_u32_be(std::span<std::byte> output, std::size_t offset, std::uint32_t value) noexcept {
    for (std::size_t index = 0; index < 4; ++index) {
        output[offset + index] = static_cast<std::byte>(
            (value >> (8U * (3U - static_cast<unsigned int>(index)))) & 0xFFU);
    }
}

/** Writes one u64 big-endian, the patch-epoch wire order. */
void write_u64_be(std::span<std::byte> output, std::size_t offset, std::uint64_t value) noexcept {
    for (std::size_t index = 0; index < 8; ++index) {
        output[offset + index] = static_cast<std::byte>(
            (value >> (8U * (7U - static_cast<unsigned int>(index)))) & 0xFFU);
    }
}

/**
 * Reports one world-population stage line.
 * @param stage Stage name (push or epoch).
 * @param messageType Activity message type staged.
 * @param bodySize Typed message body bytes, zero for the epoch.
 * @param ok True when the frame staged.
 */
void report(const char* stage, std::uint32_t messageType, std::size_t bodySize, bool ok) noexcept {
    std::array<char, core::log::kLineCapacity> line{};
    const int written = std::snprintf(line.data(),
                                      line.size(),
                                      "ev=world_population stage=%s result=%s type=%u body=%zu",
                                      stage,
                                      ok ? "ok" : "fail",
                                      messageType,
                                      bodySize);
    if (written > 0) {
        core::log::write(core::log::Channel::server,
                         ok ? core::log::Level::debug : core::log::Level::warn,
                         {line.data(), static_cast<std::size_t>(written)});
    }
}

} // namespace

/** Appends the one-vendor type-7 push and the patch-epoch bump, or nothing when the
 *  feature is off. Every staged notification advances the local nonce exactly once. */
bool append_world_population_notifications(
    Scratch& scratch,
    std::uint64_t sessionId,
    std::span<const std::byte, state::kAesKeySize> key,
    std::array<std::byte, state::kBapNonceSize>& nonce,
    std::span<std::byte> response,
    std::size_t& written) noexcept {
    const core::settings::server::Settings& serverSettings = core::settings::get().server;
    if (!serverSettings.worldPopulation) {
        return true;
    }
    if (written > response.size()) {
        return false;
    }
    const std::size_t initialWritten = written;
    auto initialNonce = nonce;

    // 1. The type-7 sobject_message record (kind 2 + the entity stream).
    service::entity_baseline::Baseline baseline{};
    baseline.schemaHash = serverSettings.worldPopulationSchemaHash;
    baseline.globalSlot = kWorldPopulationSlot;
    baseline.localIndex = kWorldPopulationLocalIndex;
    baseline.codecType = 0;
    baseline.streamByte = 0;
    baseline.nameHash = kVendorPointNameHash;
    baseline.position = kVendorPosition;
    baseline.facingRadians = 0.0F;
    baseline.bodyVitality = 1.0F;
    baseline.shieldVitality = 1.0F;
    std::size_t recordSize = 0;
    bool staged = service::entity_baseline::encode_entity_baseline(
                      baseline, scratch.responseBody, recordSize)
                  && recordSize == service::entity_baseline::kSobjectMessageSize;
    if (staged) {
        // 2. The queue-event envelope (svc-9 type 17): 4 x u32 BE header, the 0x89
        //    record, then the fixed 136-byte tail (zero probe).
        if (scratch.responsePayload.size() >= kQueueEventBodySize) {
            write_u32_be(scratch.responsePayload, 0, 0);
            write_u32_be(scratch.responsePayload, 4, kProbeSessionIndex);
            write_u32_be(scratch.responsePayload, 8, kSobjectMessageEventType);
            write_u32_be(scratch.responsePayload, 12,
                         static_cast<std::uint32_t>(
                             service::entity_baseline::kSobjectMessageSize));
            std::copy(scratch.responseBody.begin(),
                      scratch.responseBody.begin()
                          + static_cast<std::ptrdiff_t>(recordSize),
                      scratch.responsePayload.begin()
                          + static_cast<std::ptrdiff_t>(kQueueEventHeaderSize));
            std::fill(scratch.responsePayload.begin()
                          + static_cast<std::ptrdiff_t>(kQueueEventHeaderSize + recordSize),
                      scratch.responsePayload.begin()
                          + static_cast<std::ptrdiff_t>(kQueueEventBodySize),
                      std::byte{0});
            staged = append_notification_frame(
                scratch,
                sessionId,
                kQueueEventMessageType,
                std::span(scratch.responsePayload).first(kQueueEventBodySize),
                key,
                nonce,
                response,
                written);
        } else {
            staged = false;
        }
    }
    SecureZeroMemory(scratch.responseBody.data(),
                     (std::min)(scratch.responseBody.size(), recordSize));
    SecureZeroMemory(scratch.responsePayload.data(),
                     (std::min)(scratch.responsePayload.size(), kQueueEventBodySize));
    if (!staged) {
        report("push", serverSettings.worldPopulationCarrier, recordSize, false);
        clear_prefix(response.subspan(initialWritten), written - initialWritten);
        written = initialWritten;
        nonce = initialNonce;
        return false;
    }
    middleware::secure_channel::advance_nonce(nonce);
    report("push", serverSettings.worldPopulationCarrier, recordSize, true);

    // 3. The epoch bump (type 52, 16 bytes, 2 x u64 BE). The value pair is the v0 probe
    //    first-guess: first = 1 (a new epoch), second = 0 (no sub-epoch).
    std::array<std::byte, kPatchEpochSize> epoch{};
    write_u64_be(epoch, 0, 1);
    write_u64_be(epoch, 8, 0);
    staged = append_notification_frame(scratch,
                                       sessionId,
                                       kPatchEpochMessageType,
                                       epoch,
                                       key,
                                       nonce,
                                       response,
                                       written);
    SecureZeroMemory(epoch.data(), epoch.size());
    if (!staged) {
        report("epoch", kPatchEpochMessageType, kPatchEpochSize, false);
        clear_prefix(response.subspan(initialWritten), written - initialWritten);
        written = initialWritten;
        nonce = initialNonce;
        return false;
    }
    middleware::secure_channel::advance_nonce(nonce);
    report("epoch", kPatchEpochMessageType, kPatchEpochSize, true);
    SecureZeroMemory(&initialNonce, sizeof initialNonce);
    return true;
}

} // namespace sunrise::server::bap::encrypted::push::activity
