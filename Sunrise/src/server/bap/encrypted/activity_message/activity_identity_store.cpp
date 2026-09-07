#include "activity_identity_store.h"

#include <algorithm>
#include <array>

#include <Windows.h>

namespace sunrise::server::bap::encrypted::activity_message::activity_identity {
namespace {

struct Slot {
    core::settings::AccountKey account{};
    bool valid{};
    std::array<std::byte, kIdentityBytes> identity{};
};

/** One identity per provisioned account; the captures overwrite per boot. */
std::array<Slot, 8> g_identities{};
SRWLOCK g_lock{};

} // namespace

bool store(core::settings::AccountKey account,
           std::span<const std::byte, kIdentityBytes> identity) noexcept {
    AcquireSRWLockExclusive(&g_lock);
    Slot* target = nullptr;
    for (Slot& slot : g_identities) {
        if (slot.valid && slot.account == account) {
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
    target->account = account;
    target->valid = true;
    std::copy_n(identity.begin(), kIdentityBytes, target->identity.begin());
    ReleaseSRWLockExclusive(&g_lock);
    return true;
}

bool load(core::settings::AccountKey account,
          std::span<std::byte, kIdentityBytes> output) noexcept {
    AcquireSRWLockShared(&g_lock);
    for (const Slot& slot : g_identities) {
        if (slot.valid && slot.account == account) {
            std::copy_n(slot.identity.begin(), kIdentityBytes, output.begin());
            ReleaseSRWLockShared(&g_lock);
            return true;
        }
    }
    ReleaseSRWLockShared(&g_lock);
    return false;
}

} // namespace sunrise::server::bap::encrypted::activity_message::activity_identity
