#include "activity_identity_store.h"

#include <algorithm>
#include <array>

#include <Windows.h>

namespace sunrise::server::bap::encrypted::activity_message::activity_identity {
namespace {

struct Slot {
    std::uint64_t key{};
    bool valid{};
    std::array<std::byte, kIdentityBytes> identity{};
};

/** One identity per named key; the captures overwrite per boot. */
std::array<Slot, 8> g_identities{};
SRWLOCK g_lock{};

} // namespace

bool store(std::uint64_t key,
           std::span<const std::byte, kIdentityBytes> identity) noexcept {
    if (key == 0) {
        // Zero is the sentinel for "no key" on both planes; never store under it.
        return false;
    }
    AcquireSRWLockExclusive(&g_lock);
    Slot* target = nullptr;
    for (Slot& slot : g_identities) {
        if (slot.valid && slot.key == key) {
            target = &slot;
            break;
        }
        if (target == nullptr && !slot.valid) {
            target = &slot;
        }
    }
    if (target == nullptr) {
        ReleaseSRWLockExclusive(&g_lock);
        return false;
    }
    target->key = key;
    target->valid = true;
    std::copy_n(identity.begin(), kIdentityBytes, target->identity.begin());
    ReleaseSRWLockExclusive(&g_lock);
    return true;
}

bool load(std::uint64_t key, std::span<std::byte, kIdentityBytes> output) noexcept {
    if (key == 0) {
        return false;
    }
    AcquireSRWLockShared(&g_lock);
    for (const Slot& slot : g_identities) {
        if (slot.valid && slot.key == key) {
            std::copy_n(slot.identity.begin(), kIdentityBytes, output.begin());
            ReleaseSRWLockShared(&g_lock);
            return true;
        }
    }
    ReleaseSRWLockShared(&g_lock);
    return false;
}

} // namespace sunrise::server::bap::encrypted::activity_message::activity_identity