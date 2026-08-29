#include "admission_observer.h"

#include <Windows.h>

#include <intrin.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>

#include "../../../core/logging/log.h"
#include "../../../core/settings/settings.h"
#include "../../diagnostics/module_range.h"
#include "../../hooking/detour.h"

namespace sunrise::client::hooks::admission {
namespace {

/** Image RVA of the peer-adoption function; RCX = netmgr (`lea r15,[rcx+0x860]`). */
constexpr std::uintptr_t kAdoptionRva = 0x1769A50;

/**
 * Image RVA of the PEER-SLOT CREATOR (FINDINGS 20.159). One function serving what two
 * lanes named separately: it derives the 0xb8-stride slot array, a 0x38-stride array and
 * the peer states (+0x1758, stride 0x120) from a single base, and writes the slot's
 * machine id at +0xc8. Five callers - and TWO of them sit inside fn 0x141781800, the
 * message-30 membership apply, i.e. the handler for the bodies THIS SERVER PUBLISHES,
 * both passing kind 0xa. Which caller actually fires decides the whole road: if the apply
 * reaches it for a peer, the fix is server-side in a body we already send; if only the
 * join gate ever does, the DLL injection is the road and must create the slot itself.
 * The caller RVA is therefore the point of this observer, not the arguments.
 */
constexpr std::uintptr_t kSlotCreateRva = 0x17692E0;

/** Every array below is indexed off this one base inside netmgr. */
constexpr std::uintptr_t kArenaOffset = 0x860;
/** Peer slots: machine id, member count, member-index list. */
constexpr std::uintptr_t kPeerSlotStride = 0xb8;
constexpr std::uintptr_t kPeerMachineOffset = 0xc8;
constexpr std::uintptr_t kPeerMemberCountOffset = 0xe8;
constexpr std::uintptr_t kPeerMemberListOffset = 0xf0;
/** Peer connection states live on their own stride, and the adoption arm wants != 3. */
constexpr std::uintptr_t kPeerStateStride = 0x120;
constexpr std::uintptr_t kPeerStateOffset = 0x1758;
/** Member records: the three fields the adoption path actually reads. */
constexpr std::uintptr_t kMemberStride = 0x1a8;
constexpr std::uintptr_t kMemberAddressOffset = 0x3c00;
constexpr std::uintptr_t kMemberFlagsOffset = 0x3c30;
constexpr std::uintptr_t kMemberMembershipOffset = 0x3b78;
/** ADMIT sets flags bits 0,2,3,4 (0x1D); bit 4 is the one the adoption path reads. */
constexpr std::uint16_t kAdmitFlagBits = 0x1D;

/** Peers to walk. The real bound is unknown, so the census stays deliberately small. */
constexpr std::size_t kPeerScan = 8;
/** Member indices to report per peer. */
constexpr std::size_t kMemberScan = 8;
/** Hard line cap - this sits on a session tick. */
constexpr unsigned kLineCap = 48;
constexpr std::size_t kLineCapacity = 256;

/**
 * Verified ABI of the slot creator, read off its two call sites in the message-30 apply:
 * RCX = the arena object, EDX = slot index, R8D = kind (0xa at both apply sites), R9D = a
 * flag, then FOUR stack arguments. The observer mirrors all eight so every one passes
 * through untouched.
 */
using SlotCreate = std::uint64_t(__fastcall*)(void*,
                                              std::uint32_t,
                                              std::uint32_t,
                                              std::uint32_t,
                                              void*,
                                              void*,
                                              void*,
                                              void*) noexcept;

hooking::detour::Handle g_slotCreate{};
std::atomic<unsigned> g_slotLines{};

/** @return Machine id currently in a slot, or 0 when unreadable. */
[[nodiscard]] std::uint64_t slot_machine(std::uint8_t* arena, std::uint32_t index) noexcept {
    if (arena == nullptr) {
        return 0;
    }
    __try {
        return *reinterpret_cast<const std::uint64_t*>(arena + index * kPeerSlotStride
                                                       + kPeerMachineOffset);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

/**
 * Observes one slot creation. Logs the CALLER RVA (which names the path), the arguments,
 * and the slot's machine id before and after - so a create, a no-op and an overwrite are
 * all distinguishable. Slot creation is not a per-tick event, so every call is logged up
 * to the cap rather than only changes.
 */
std::uint64_t __fastcall observe_slot_create(void* arena,
                                             std::uint32_t index,
                                             std::uint32_t kind,
                                             std::uint32_t flag,
                                             void* a5,
                                             void* a6,
                                             void* a7,
                                             void* a8) noexcept {
    const void* const caller = _ReturnAddress();
    auto* const bytes = static_cast<std::uint8_t*>(arena);
    const std::uint64_t before = slot_machine(bytes, index);
    const auto original = reinterpret_cast<SlotCreate>(g_slotCreate.original);
    const std::uint64_t result = original(arena, index, kind, flag, a5, a6, a7, a8);
    if (g_slotLines.load(std::memory_order_relaxed) >= kLineCap) {
        return result;
    }
    g_slotLines.fetch_add(1, std::memory_order_relaxed);
    const std::uint64_t after = slot_machine(bytes, index);
    std::uintptr_t callerRva = 0;
    HMODULE module{};
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
                               | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           static_cast<LPCSTR>(caller),
                           &module)
        != 0) {
        callerRva = reinterpret_cast<std::uintptr_t>(caller)
                    - reinterpret_cast<std::uintptr_t>(module);
    }
    std::array<char, kLineCapacity> text{};
    const int written = std::snprintf(text.data(),
                                      text.size(),
                                      "ev=admission stage=slot_create caller=0x%llX idx=%u "
                                      "kind=%u flag=%u machine_before=0x%llX "
                                      "machine_after=0x%llX",
                                      static_cast<unsigned long long>(callerRva),
                                      index,
                                      kind,
                                      flag,
                                      static_cast<unsigned long long>(before),
                                      static_cast<unsigned long long>(after));
    if (written > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         {text.data(), static_cast<std::size_t>(written)});
    }
    return result;
}

/** Verified ABI: RCX = netmgr. Remaining integer registers pass through untouched. */
using Adoption = std::uint64_t(__fastcall*)(void*, void*, void*, void*) noexcept;

hooking::detour::Handle g_handle{};
std::atomic<std::uint64_t> g_lastKey{~0ULL};
std::atomic<unsigned> g_lines{};
std::atomic<bool> g_injected{};

/** @return Byte pointer to netmgr's shared array arena, or null. */
[[nodiscard]] std::uint8_t* arena_of(void* netmgr) noexcept {
    return netmgr == nullptr ? nullptr : static_cast<std::uint8_t*>(netmgr) + kArenaOffset;
}

/** One peer slot's readable state. `ok` false means the read faulted. */
struct PeerView {
    std::uint64_t machineId{};
    std::int32_t state{};
    std::int32_t memberCount{};
    std::int32_t firstMemberIndex{-1};
    std::uint64_t firstMemberXuid{};
    std::uint16_t firstMemberFlags{};
    bool ok{};
};

/** Reads one peer slot and, when it names members, its first member record. */
[[nodiscard]] PeerView read_peer(std::uint8_t* arena, std::size_t index) noexcept {
    PeerView view{};
    __try {
        std::uint8_t* const slot = arena + index * kPeerSlotStride;
        view.machineId = *reinterpret_cast<const std::uint64_t*>(slot + kPeerMachineOffset);
        view.memberCount = *reinterpret_cast<const std::int32_t*>(slot + kPeerMemberCountOffset);
        view.state = *reinterpret_cast<const std::int32_t*>(arena + index * kPeerStateStride
                                                            + kPeerStateOffset);
        if (view.memberCount > 0 && static_cast<std::size_t>(view.memberCount) <= kMemberScan) {
            const std::int32_t member =
                *reinterpret_cast<const std::int32_t*>(slot + kPeerMemberListOffset);
            view.firstMemberIndex = member;
            if (member >= 0) {
                std::uint8_t* const record = arena + static_cast<std::uintptr_t>(member)
                                                         * kMemberStride;
                view.firstMemberXuid =
                    *reinterpret_cast<const std::uint64_t*>(record + kMemberAddressOffset);
                view.firstMemberFlags =
                    *reinterpret_cast<const std::uint16_t*>(record + kMemberFlagsOffset);
            }
        }
        view.ok = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        view.ok = false;
    }
    return view;
}

/** Writes one census line. */
void report_peer(std::size_t index, const PeerView& view) noexcept {
    std::array<char, kLineCapacity> text{};
    const int written =
        std::snprintf(text.data(),
                      text.size(),
                      "ev=admission stage=census peer=%zu ok=%u state=%d machine=0x%llX "
                      "members=%d first_idx=%d first_xuid=0x%llX first_flags=0x%04X",
                      index,
                      view.ok ? 1U : 0U,
                      view.state,
                      static_cast<unsigned long long>(view.machineId),
                      view.memberCount,
                      view.firstMemberIndex,
                      static_cast<unsigned long long>(view.firstMemberXuid),
                      static_cast<unsigned>(view.firstMemberFlags));
    if (written > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         {text.data(), static_cast<std::size_t>(written)});
    }
}

/**
 * Writes the three fields the adoption path reads, and links the record into the peer's
 * member list. This is what ADMIT would have produced for a peer that joined us.
 *
 * DELIBERATELY NARROW. ADMIT also writes +0x3c10/+0x3c20 (the rest of the 48-byte address
 * block), +0x3c32 and +0x3c68; none of them are read by the adoption path, so none are
 * forged here. Writing only what is consumed keeps a wrong guess inert instead of
 * corrupting a record the game later reads for another purpose.
 *
 * @param arena netmgr's array arena.
 * @param peerIndex Peer slot to attach the record to.
 * @param memberIndex Record index to populate. MUST be one the census showed unused.
 * @param xuid Peer identity to publish into the address-block head.
 * @return True when every write landed.
 */
[[nodiscard]] bool inject_member(std::uint8_t* arena,
                                 std::size_t peerIndex,
                                 std::int32_t memberIndex,
                                 std::uint64_t xuid) noexcept {
    __try {
        std::uint8_t* const record =
            arena + static_cast<std::uintptr_t>(memberIndex) * kMemberStride;
        // Refuse a record that is already in use: a live address-block head or any flag
        // bit means the game owns this index, and overwriting it is the p2(62) failure.
        if (*reinterpret_cast<const std::uint64_t*>(record + kMemberAddressOffset) != 0
            || *reinterpret_cast<const std::uint16_t*>(record + kMemberFlagsOffset) != 0) {
            return false;
        }
        *reinterpret_cast<std::uint64_t*>(record + kMemberAddressOffset) = xuid;
        *reinterpret_cast<std::uint16_t*>(record + kMemberFlagsOffset) = kAdmitFlagBits;
        // flagsA is `membership byte == 0`, so leaving it zero publishes the peer as a
        // full member - the same value an admitted peer carries before it is marked.
        *reinterpret_cast<std::uint8_t*>(record + kMemberMembershipOffset) = 0;

        std::uint8_t* const slot = arena + peerIndex * kPeerSlotStride;
        *reinterpret_cast<std::int32_t*>(slot + kPeerMemberListOffset) = memberIndex;
        *reinterpret_cast<std::int32_t*>(slot + kPeerMemberCountOffset) = 1;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return true;
}

/** The observer. Censuses at entry, optionally injects, then runs the original. */
std::uint64_t __fastcall observe(void* netmgr, void* second, void* third, void* fourth) noexcept {
    std::uint8_t* const arena = arena_of(netmgr);
    const auto& client = core::settings::get().client;
    if (arena != nullptr && g_lines.load(std::memory_order_relaxed) < kLineCap) {
        std::array<PeerView, kPeerScan> views{};
        std::uint64_t key = 0;
        for (std::size_t index = 0; index < kPeerScan; ++index) {
            views[index] = read_peer(arena, index);
            key = key * 31 + static_cast<std::uint64_t>(views[index].state)
                  + (views[index].machineId != 0 ? 1ULL : 0ULL) * 7
                  + static_cast<std::uint64_t>(views[index].memberCount) * 131;
        }
        // Same discipline as the phase probe: this sits on a tick, so only a CHANGED
        // picture is worth a line.
        if (client.admissionCensus && g_lastKey.exchange(key, std::memory_order_relaxed) != key) {
            for (std::size_t index = 0; index < kPeerScan; ++index) {
                if (views[index].machineId != 0 || views[index].state != 0) {
                    g_lines.fetch_add(1, std::memory_order_relaxed);
                    report_peer(index, views[index]);
                }
            }
        }
        // ONE injection per process. A peer that names a machine id but holds no members
        // is exactly the shape ADMIT would have resolved.
        if (client.admissionInject && !g_injected.load(std::memory_order_relaxed)) {
            for (std::size_t index = 0; index < kPeerScan; ++index) {
                const PeerView& view = views[index];
                if (!view.ok || view.machineId == 0 || view.memberCount != 0) {
                    continue;
                }
                const std::int32_t memberIndex =
                    static_cast<std::int32_t>(client.admissionMemberIndex);
                const std::uint64_t xuid = client.admissionXuid;
                if (memberIndex < 0 || xuid == 0) {
                    break;
                }
                const bool done = inject_member(arena, index, memberIndex, xuid);
                g_injected.store(true, std::memory_order_relaxed);
                std::array<char, kLineCapacity> text{};
                const int written =
                    std::snprintf(text.data(),
                                  text.size(),
                                  "ev=admission stage=inject result=%s peer=%zu idx=%d "
                                  "xuid=0x%llX",
                                  done ? "written" : "refused",
                                  index,
                                  memberIndex,
                                  static_cast<unsigned long long>(xuid));
                if (written > 0) {
                    core::log::write(core::log::Channel::client,
                                     core::log::Level::info,
                                     {text.data(), static_cast<std::size_t>(written)});
                }
                break;
            }
        }
    }
    const auto original = reinterpret_cast<Adoption>(g_handle.original);
    return original(netmgr, second, third, fourth);
}

bool fail_install(const char* reason) noexcept {
    std::array<char, 96> text{};
    const int written = std::snprintf(
        text.data(), text.size(), "ev=admission stage=install result=fail why=%s", reason);
    if (written > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::warn,
                         {text.data(), static_cast<std::size_t>(written)});
    }
    return false;
}

} // namespace

bool install() noexcept {
    if (g_handle.attached) {
        return true;
    }
    std::byte* const base = reinterpret_cast<std::byte*>(GetModuleHandleW(nullptr));
    if (base == nullptr) {
        return fail_install("base");
    }
    const std::uintptr_t baseValue = reinterpret_cast<std::uintptr_t>(base);
    diagnostics::ModuleRange range{};
    if (!diagnostics::module_range(reinterpret_cast<HMODULE>(base), range)
        || !diagnostics::contains(range, baseValue + kAdoptionRva)) {
        return fail_install("range");
    }
    if (!diagnostics::contains(range, baseValue + kSlotCreateRva)) {
        return fail_install("range_slot");
    }
    const hooking::detour::Spec spec{reinterpret_cast<void*>(baseValue + kAdoptionRva),
                                     reinterpret_cast<void*>(&observe)};
    if (!hooking::detour::install(spec, g_handle)) {
        return fail_install("attach");
    }
    const hooking::detour::Spec slotSpec{reinterpret_cast<void*>(baseValue + kSlotCreateRva),
                                         reinterpret_cast<void*>(&observe_slot_create)};
    if (!hooking::detour::install(slotSpec, g_slotCreate)) {
        return fail_install("attach_slot");
    }
    const auto& client = core::settings::get().client;
    std::array<char, 160> text{};
    const int written = std::snprintf(text.data(),
                                      text.size(),
                                      "ev=admission stage=install result=ok rva=0x%llX slot=0x%llX "
                                      "census=%u inject=%u idx=%d xuid=0x%llX",
                                      static_cast<unsigned long long>(kAdoptionRva),
                                      static_cast<unsigned long long>(kSlotCreateRva),
                                      client.admissionCensus ? 1U : 0U,
                                      client.admissionInject ? 1U : 0U,
                                      static_cast<int>(client.admissionMemberIndex),
                                      static_cast<unsigned long long>(client.admissionXuid));
    if (written > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         {text.data(), static_cast<std::size_t>(written)});
    }
    return true;
}

bool uninstall() noexcept {
    bool ok = true;
    if (g_slotCreate.attached) {
        ok = hooking::detour::uninstall(g_slotCreate) && ok;
    }
    if (g_handle.attached) {
        ok = hooking::detour::uninstall(g_handle) && ok;
    }
    return ok;
}

bool is_installed() noexcept {
    return g_handle.attached || g_slotCreate.attached;
}

} // namespace sunrise::client::hooks::admission
