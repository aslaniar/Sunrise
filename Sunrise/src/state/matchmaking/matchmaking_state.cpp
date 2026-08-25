#include "matchmaking_state.h"

#include <Windows.h>
#include "../../core/logging/log.h"
#include <cstdio>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>

#include "../runtime/storage/internal.h"
#include "transactions/internal.h"

namespace sunrise::state::matchmaking {

/** Acquires the first available generation-checked logical context. */
bool acquire_context(ContextHandle& context) noexcept {
    context = {};
    AcquireSRWLockExclusive(&runtime::storage::g_stateLock);
    MatchmakingState& state = runtime::storage::g_states[core::settings::kLegacyAccount].matchmaking;
    if (state.allocatorRevision == kInvalidRevision) {
        ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);
        return false;
    }
    for (std::size_t index = 0; index < state.contexts.size(); ++index) {
        ContextSlot& slot = state.contexts[index];
        if (slot.active || slot.generation == (std::numeric_limits<std::uint32_t>::max)()) {
            continue;
        }
        // Advance before erasure so a released handle cannot become valid again.
        std::uint32_t generation = slot.generation;
        ++generation;
        SecureZeroMemory(&slot, sizeof slot);
        slot.active = true;
        slot.generation = generation;
        slot.data.revision = kInitialContextRevision;
        slot.data.latestSlot = kInvalidVariantSlot;
        context = {index, generation};
        ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);
        return true;
    }
    ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);
    return false;
}

/** Releases a context and securely erases every descriptor it owns. */
bool release_context(ContextHandle context) noexcept {
    AcquireSRWLockExclusive(&runtime::storage::g_stateLock);
    ContextSlot* slot = transactions::resolve(runtime::storage::g_states[core::settings::kLegacyAccount].matchmaking, context);
    if (slot == nullptr) {
        ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);
        return false;
    }
    // Keep only the generation needed to reject handles from this acquisition.
    const std::uint32_t generation = slot->generation;
    SecureZeroMemory(slot, sizeof *slot);
    slot->generation = generation;
    ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);
    return true;
}

/** Copies the latest advertisement under the State lock. */
bool latest_snapshot(ContextHandle context, LatestSnapshot& snapshot) noexcept {
    SecureZeroMemory(&snapshot, sizeof snapshot);
    AcquireSRWLockShared(&runtime::storage::g_stateLock);
    MatchmakingState& state = runtime::storage::g_states[core::settings::kLegacyAccount].matchmaking;
    ContextSlot* slot = transactions::resolve(state, context);
    if (slot == nullptr) {
        ReleaseSRWLockShared(&runtime::storage::g_stateLock);
        return false;
    }
    LatestSnapshot prepared{};
    // A kept variant wins once it replaces the standalone latest id.
    if (slot->data.latestSlot < kVariantCapacity) {
        const VariantRecord& latest = slot->data.variants[slot->data.latestSlot];
        if (!latest.occupied || latest.advertisementId == kAbsentAdvertisementId) {
            ReleaseSRWLockShared(&runtime::storage::g_stateLock);
            return false;
        }
        prepared.advertisementId = latest.advertisementId;
        prepared.hasDescriptor = latest.hasDescriptor;
        if (latest.hasDescriptor) {
            std::memcpy(prepared.descriptor.data(), latest.descriptor.data(), kDescriptorSize);
        }
    } else if (slot->data.latestSlot == kInvalidVariantSlot
               && slot->data.standaloneLatestId != kAbsentAdvertisementId) {
        prepared.advertisementId = slot->data.standaloneLatestId;
    } else {
        ReleaseSRWLockShared(&runtime::storage::g_stateLock);
        return false;
    }
    ReleaseSRWLockShared(&runtime::storage::g_stateLock);
    snapshot = prepared;
    // Keep the descriptor in State and the caller output, not an extra stack lifetime.
    SecureZeroMemory(&prepared, sizeof prepared);
    return true;
}

/** Securely erases a transient latest-advertisement snapshot. */
void erase_snapshot(LatestSnapshot& snapshot) noexcept {
    SecureZeroMemory(&snapshot, sizeof snapshot);
}


/** Copies one advertisement published by a context other than the caller's. */
bool foreign_advertisement(ContextHandle exclude, LatestSnapshot& snapshot) noexcept {
    SecureZeroMemory(&snapshot, sizeof snapshot);
    AcquireSRWLockShared(&runtime::storage::g_stateLock);
    MatchmakingState& state = runtime::storage::g_states[core::settings::kLegacyAccount].matchmaking;

    // The caller's OWN advertised descriptor, if it has one. Excluding only its context slot is
    // not enough: each BAP connection acquires its own matchmaking context, and one client holds
    // several connections - so a searcher was being handed its own session back from its sibling
    // link, which is nothing it can join (FINDINGS 20.37). Identity here is the descriptor
    // itself, which is the thing a peer would actually connect to.
    std::array<std::byte, kDescriptorSize> own{};
    bool hasOwn = false;
    if (const ContextSlot* mine = transactions::resolve(state, exclude);
        mine != nullptr && mine->data.latestSlot < kVariantCapacity) {
        const VariantRecord& record = mine->data.variants[mine->data.latestSlot];
        if (record.occupied && record.hasDescriptor) {
            std::memcpy(own.data(), record.descriptor.data(), kDescriptorSize);
            hasOwn = true;
        }
    }

    LatestSnapshot prepared{};
    bool found = false;
    std::size_t skippedSelf = 0;
    std::size_t skippedSibling = 0;
    for (std::size_t index = 0; index < state.contexts.size() && !found; ++index) {
        if (index == exclude.slot) {
            ++skippedSelf;
            continue;
        }
        const ContextSlot& slot = state.contexts[index];
        if (!slot.active || slot.data.latestSlot >= kVariantCapacity) {
            continue;
        }
        const VariantRecord& latest = slot.data.variants[slot.data.latestSlot];
        if (!latest.occupied || latest.advertisementId == kAbsentAdvertisementId
            || !latest.hasDescriptor) {
            continue;
        }
        // Same descriptor means the same session, whichever connection published it.
        if (hasOwn
            && std::memcmp(own.data(), latest.descriptor.data(), kDescriptorSize) == 0) {
            ++skippedSibling;
            continue;
        }
        prepared.advertisementId = latest.advertisementId;
        prepared.hasDescriptor = true;
        std::memcpy(prepared.descriptor.data(), latest.descriptor.data(), kDescriptorSize);
        found = true;
    }
    ReleaseSRWLockShared(&runtime::storage::g_stateLock);
    if (found) {
        snapshot = prepared;
    }
    SecureZeroMemory(&prepared, sizeof prepared);
    SecureZeroMemory(own.data(), own.size());
    std::array<char, 128> line{};
    const int count = std::snprintf(line.data(), line.size(),
                                    "ev=matchmaking stage=foreign result=%s self=%zu sibling=%zu",
                                    found ? "found" : "none", skippedSelf, skippedSibling);
    if (count > 0) {
        core::log::write(core::log::Channel::server, core::log::Level::info,
                         {line.data(), static_cast<std::size_t>(count)});
    }
    return found;
}

} // namespace sunrise::state::matchmaking
