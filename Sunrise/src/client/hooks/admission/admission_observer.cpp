#include "admission_observer.h"

#include <Windows.h>

#include <intrin.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string_view>

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
/** Slot the injection targets: measured free on both machines (p2(97)/p2(98)). */
constexpr std::uint32_t kInjectSlot = 1;
/** The kind the one CREATING call carries. kind=10 creates nothing (20.160). */
constexpr std::uint32_t kCreateKind = 5;
/** Capacities of the captured a5 string and a6 block. */
constexpr std::size_t kIdentityCapacity = 0x50;
constexpr std::size_t kBlockCapacity = 0x40;

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
/** The kind=5 argument dump is worth exactly one occurrence. */
std::atomic<bool> g_argsDumped{};
/**
 * Template captured from the REAL kind=5 call (20.162). The injection substitutes into
 * this rather than synthesising, confining fabrication to the fields we mean to fabricate.
 */
std::array<char, kIdentityCapacity> g_identityTemplate{};
std::array<std::uint8_t, kBlockCapacity> g_blockTemplate{};
std::uint32_t g_capturedFlag{};
std::atomic<bool> g_templateReady{};
std::atomic<bool> g_injectDone{};

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

/** Bytes shown per hexdump line. 64 renders to 128 chars, inside kLineCapacity. */
constexpr std::size_t kDumpBytes = 64;

/**
 * Hex-dumps borrowed memory into one log line, or reports it unreadable.
 * @param tag Field name for the line.
 * @param address Borrowed pointer; may be null or bad.
 * @param count Bytes to render, capped at kDumpBytes.
 */
void dump_hex(const char* tag, const void* address, std::size_t count) noexcept {
    std::array<char, kLineCapacity> text{};
    if (address == nullptr) {
        const int empty = std::snprintf(
            text.data(), text.size(), "ev=admission stage=arg tag=%s ptr=null", tag);
        if (empty > 0) {
            core::log::write(core::log::Channel::client,
                             core::log::Level::info,
                             {text.data(), static_cast<std::size_t>(empty)});
        }
        return;
    }
    std::array<std::uint8_t, kDumpBytes> copy{};
    const std::size_t take = count < kDumpBytes ? count : kDumpBytes;
    bool ok = true;
    __try {
        const auto* const source = static_cast<const std::uint8_t*>(address);
        for (std::size_t i = 0; i < take; ++i) {
            copy[i] = source[i];
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ok = false;
    }
    int written = std::snprintf(
        text.data(),
        text.size(),
        "ev=admission stage=arg tag=%s ptr=0x%llX ok=%u hex=",
        tag,
        static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(address)),
        ok ? 1U : 0U);
    if (written <= 0) {
        return;
    }
    if (ok) {
        for (std::size_t i = 0; i < take && written + 2 < static_cast<int>(text.size()); ++i) {
            written += std::snprintf(text.data() + written,
                                     text.size() - static_cast<std::size_t>(written),
                                     "%02X",
                                     copy[i]);
        }
    }
    core::log::write(core::log::Channel::client,
                     core::log::Level::info,
                     {text.data(), static_cast<std::size_t>(written)});
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
    // ARGUMENT CAPTURE (FINDINGS 20.160). Only the kind=5 call creates a slot, so only
    // that one is dumped, and only once. The four stack arguments are pointers the join
    // gate built: whether they are PEER-SPECIFIC or session-generic decides whether an
    // injection can replay them with a substituted index and machine id, or must
    // synthesise them. The created slot is dumped too - its 0x50-byte blob at +0x50 is
    // the one field a hand-written injection currently cannot reproduce.
    if (kind == 5 && after != 0 && !g_argsDumped.exchange(true, std::memory_order_relaxed)) {
        // ONLY a5 AND a6 ARE POINTERS. Read off the call site that actually fires -
        // the join gate at 0x141772A99 - a5 is `lea rax,[rbp+0x1b0]` and a6 is the
        // return of 0x1402ffd20, while a7 is a bare `rbx` and a8 is the return of the
        // TIMESTAMP function 0x1402fe650. Dereferencing those two crashed the client at
        // character selection in p2(99): the earlier version took its ABI from the two
        // call sites inside the message-30 apply, which p2(98) had just proven never
        // execute. A call site that does not run cannot tell you the shape of one that
        // does. a7/a8 are now logged as VALUES and never dereferenced.
        dump_hex("a5", a5, kDumpBytes);
        dump_hex("a6", a6, kDumpBytes);
        __try {
            const auto* const id = static_cast<const char*>(a5);
            for (std::size_t i = 0; i < kIdentityCapacity; ++i) {
                g_identityTemplate[i] = id[i];
            }
            const auto* const blk = static_cast<const std::uint8_t*>(a6);
            for (std::size_t i = 0; i < kBlockCapacity; ++i) {
                g_blockTemplate[i] = blk[i];
            }
            g_capturedFlag = flag;
            g_templateReady.store(true, std::memory_order_release);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            g_templateReady.store(false, std::memory_order_release);
        }
        std::array<char, kLineCapacity> raw{};
        const int rawWritten =
            std::snprintf(raw.data(),
                          raw.size(),
                          "ev=admission stage=arg tag=a7a8 a7=0x%llX a8=0x%llX (values, "
                          "not dereferenced)",
                          static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(a7)),
                          static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(a8)));
        if (rawWritten > 0) {
            core::log::write(core::log::Channel::client,
                             core::log::Level::info,
                             {raw.data(), static_cast<std::size_t>(rawWritten)});
        }
        if (bytes != nullptr) {
            std::uint8_t* const slot = bytes + index * kPeerSlotStride;
            dump_hex("slot48", slot + 0x48, kDumpBytes);
            dump_hex("slot88", slot + 0x88, kDumpBytes);
        }
    }
    return result;
}

/** Verified ABI: RCX = netmgr. Remaining integer registers pass through untouched. */
using Adoption = std::uint64_t(__fastcall*)(void*, void*, void*, void*) noexcept;

hooking::detour::Handle g_handle{};
std::atomic<std::uint64_t> g_lastKey{~0ULL};
std::atomic<unsigned> g_lines{};
std::atomic<bool> g_injected{};

/**
 * Rewrites the decimal steam id inside a captured identity string.
 * Shape is "steamid:<digits>#<16 hex>" (20.162); only the digits change, so the hex
 * suffix and everything around it stay exactly as the game wrote them.
 * @param identity Captured template, edited in place on success.
 * @param steamId Replacement decimal id.
 * @return True when the template had the expected shape and the result fits.
 */
[[nodiscard]] bool substitute_steam_id(std::array<char, kIdentityCapacity>& identity,
                                       std::uint64_t steamId) noexcept {
    if (std::strncmp(identity.data(), "steamid:", 8) != 0) {
        return false;
    }
    const void* const hash = std::memchr(identity.data(), '#', identity.size());
    if (hash == nullptr) {
        return false;
    }
    std::array<char, kIdentityCapacity> out{};
    const int written = std::snprintf(out.data(),
                                      out.size(),
                                      "steamid:%llu%s",
                                      static_cast<unsigned long long>(steamId),
                                      static_cast<const char*>(hash));
    if (written <= 0 || static_cast<std::size_t>(written) >= out.size()) {
        return false;
    }
    identity = out;
    return true;
}

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
        // THE INJECTION (FINDINGS 20.162). Calls the game's OWN slot creator rather than
        // hand-forging the slot, so every field it writes is correct by construction -
        // including the flags bit 5 that ADMIT's recorded stores never explained (20.158).
        // a5/a6 are the template captured from the REAL kind=5 call with only the identity
        // substituted, so every byte we do not understand stays byte-faithful. a7 is
        // FABRICATED, and testing whether that suffices is the whole point (p2(63)).
        if (client.admissionInject && g_templateReady.load(std::memory_order_acquire)
            && !g_injectDone.load(std::memory_order_relaxed)
            && client.admissionPeerSteamId != 0 && client.admissionPeerMachine != 0
            && client.admissionA7 != 0 && g_slotCreate.original != nullptr) {
            const PeerView target = read_peer(arena, kInjectSlot);
            // Only into a genuinely free slot. p2(97)/p2(98) measured slot 1 as
            // probed-and-empty on both machines; refuse anything else.
            if (target.ok && target.machineId == 0) {
                g_injectDone.store(true, std::memory_order_relaxed);
                std::array<char, kIdentityCapacity> identity = g_identityTemplate;
                const bool built = substitute_steam_id(identity, client.admissionPeerSteamId);
                std::array<std::uint8_t, kBlockCapacity> block = g_blockTemplate;
                const std::uint64_t head = client.admissionPeerMachine;
                for (std::size_t i = 0; i < sizeof head; ++i) {
                    block[i] = static_cast<std::uint8_t>((head >> (i * 8)) & 0xFF);
                }
                std::uint64_t created = 0;
                if (built) {
                    const auto creator = reinterpret_cast<SlotCreate>(g_slotCreate.original);
                    created = creator(arena,
                                      kInjectSlot,
                                      kCreateKind,
                                      g_capturedFlag,
                                      identity.data(),
                                      block.data(),
                                      reinterpret_cast<void*>(client.admissionA7),
                                      reinterpret_cast<void*>(GetTickCount64()));
                }
                const PeerView after = read_peer(arena, kInjectSlot);
                std::array<char, kLineCapacity> text{};
                const int written =
                    std::snprintf(text.data(),
                                  text.size(),
                                  "ev=admission stage=inject result=%s slot=%u ret=%llu "
                                  "machine_now=0x%llX id=%.44s",
                                  built ? "called" : "id_build_failed",
                                  static_cast<unsigned>(kInjectSlot),
                                  static_cast<unsigned long long>(created),
                                  static_cast<unsigned long long>(after.machineId),
                                  identity.data());
                if (written > 0) {
                    core::log::write(core::log::Channel::client,
                                     core::log::Level::info,
                                     {text.data(), static_cast<std::size_t>(written)});
                }
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
