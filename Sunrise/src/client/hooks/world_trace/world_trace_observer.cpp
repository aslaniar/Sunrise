#include "world_trace_observer.h"

#include <Windows.h>
#include <intrin.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "../../../core/logging/log.h"
#include "../../../core/settings/settings.h"
#include "../../diagnostics/module_range.h"
#include "../../hooking/detour.h"

namespace sunrise::client::hooks::world_trace {
namespace {

/**
 * Image RVAs. The two hook targets are .pdata function STARTs
 * (verify_hook_rvas.py gates every boot on this):
 *   emitter      0x1417607B0 -> 0x17607B0  (0x1417607B0..0x1417607E0)
 *   entity read  0x141718080 -> 0x1718080  (0x141718080..0x1417183B2)
 * The remaining three are DATA addresses the dump reads; .pdata does not cover
 * them and the gate lists them NOT-CODE for review - that is expected.
 */
constexpr std::uintptr_t kEmitterRva = 0x17607B0;
constexpr std::uintptr_t kEntityCreateRva = 0x1718080;
/** DAT_141F91300: the entity-index global the entity reader's context shares. */
constexpr std::uintptr_t kEntityIndexRva = 0x1F91300;
/** *DAT_142439C70: the runtime schema-table root (heap once the registrar ran). */
constexpr std::uintptr_t kSchemaRootRva = 0x2439C70;
/** *(int32*)(*(void**)0x14209ED00): the live chunk-8 (power) schema id. */
constexpr std::uintptr_t kChunk8IdPtrRva = 0x209ED00;

/** The client's own player archetype - the world_population emission's schema. */
constexpr std::uint32_t kPlayerArchetypeKey = 0x80806AC0U;

/** Distinct reports per stream; counters keep the rate visible past each cap. */
constexpr unsigned kEmitCap = 8;
constexpr unsigned kEntityCap = 16;
/** Entry rows dumped per schema node before truncating (the count stays in the header). */
constexpr std::size_t kMaxEntriesDumped = 16;

/** Verified pass-through shapes: 4 register args + 6 stack slots, forwarded bit-exact. */
using EmitterFn = std::uint64_t(__fastcall*)(const void*, void*, const void*, const void*,
                                             void*, void*, void*, void*, void*, void*) noexcept;
using EntityFn = std::uint64_t(__fastcall*)(void*, void*, void*, void*, void*,
                                            void*, void*, void*, void*, void*) noexcept;

hooking::detour::Handle g_emitter{};
hooking::detour::Handle g_entity{};
std::atomic<unsigned> g_emitCalls{};
std::atomic<unsigned> g_emitReported{};
std::atomic<unsigned> g_entityCalls{};
std::atomic<unsigned> g_entityReported{};
/** One-shot gate for the schema dump (first emitter call = tables live). */
std::atomic<bool> g_schemaDumped{};
std::atomic<bool> g_installed{};
std::uintptr_t g_base{};

/** Caller RVA of the current detour invocation, for call-graph work without boots. */
std::uint64_t caller_rva() noexcept {
    const auto ret = reinterpret_cast<std::uintptr_t>(_ReturnAddress());
    return g_base != 0 && ret > g_base ? static_cast<unsigned long long>(ret - g_base) : 0ULL;
}

/** Log helper: one formatted client line, best effort. */
void line(const char* text, int written) noexcept {
    if (written > 0) {
        core::log::write(core::log::Channel::client, core::log::Level::info,
                         {text, static_cast<std::size_t>(written)});
    }
}

/** Hexdump of `bytes` at `address` (SEH-guarded); one client line. Faults log `fault=1`. */
void dump_hex(const char* stage, std::uintptr_t address, std::size_t bytes) noexcept {
    std::array<char, core::log::kLineCapacity> text{};
    int written = std::snprintf(text.data(), text.size(),
                                "ev=wtrace stage=%s addr=0x%llX bytes=%zu hex=",
                                stage, static_cast<unsigned long long>(address), bytes);
    bool ok = true;
    std::uint8_t value = 0;
    for (std::size_t i = 0; i < bytes && written > 0; ++i) {
        __try {
            value = *(reinterpret_cast<const std::uint8_t*>(address) + i);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            ok = false;
            break;
        }
        written += std::snprintf(text.data() + written,
                                 text.size() - static_cast<std::size_t>(written),
                                 "%02X", value);
        if (written > static_cast<int>(text.size()) - 8) {
            break;
        }
    }
    if (!ok) {
        written += std::snprintf(text.data() + written,
                                 text.size() - static_cast<std::size_t>(written), " <fault>");
    }
    line(text.data(), written);
}

/** Reads one dword through a pointer, SEH-guarded; `fallback` on any fault. */
std::uint32_t read_dword_at(std::uintptr_t address, std::uint32_t fallback) noexcept {
    if (address == 0) {
        return fallback;
    }
    __try {
        return *reinterpret_cast<const std::uint32_t*>(address);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return fallback;
    }
}

/**
 * Resolves one schema key and dumps the raw row / slot / node / entries.
 * Resolver arithmetic per character-record-mapping.md CLAIM 2 (dialect A) -
 * INFERRED traversal, VERIFIED raw bytes beside it. Whole body SEH-guarded.
 */
void dump_tree(const char* name, std::uint32_t key) noexcept {
    std::array<char, 192> text{};
    const std::uintptr_t root = *reinterpret_cast<const std::uintptr_t*>(g_base + kSchemaRootRva);
    int written = std::snprintf(text.data(), text.size(),
                                "ev=wtrace stage=schema tree=%s key=0x%08X root=0x%llX",
                                name, static_cast<unsigned>(key),
                                static_cast<unsigned long long>(root));
    line(text.data(), written);
    if (root == 0) {
        return;
    }
    bool ok = true;
    std::uintptr_t row = 0;
    std::uintptr_t slot = 0;
    std::uintptr_t node = 0;
    std::uint64_t bound = 0;
    std::uint32_t headerCount = 0;
    std::int32_t count = 0;
    __try {
        const std::uint64_t hi = static_cast<std::uint64_t>(key) >> 13;
        const std::uint64_t index =
            ((hi | 0xFFC0000ULL) >> 0x12) & (hi & 0xFFFFULL);
        row = root + index * 0x40;
        const std::uint32_t stride = *reinterpret_cast<const std::uint32_t*>(row + 0x30);
        const std::uint32_t mask = *reinterpret_cast<const std::uint32_t*>(row + 0x34);
        const std::uint64_t base = *reinterpret_cast<const std::uint64_t*>(row + 0x08);
        slot = static_cast<std::uintptr_t>(
            static_cast<std::uint64_t>(key & 0x1FFFU) * stride + base);
        slot -= static_cast<std::uintptr_t>(
            mask & *reinterpret_cast<const std::uint64_t*>(slot + 8));
        const std::uint64_t nodeOffset = *reinterpret_cast<const std::uint64_t*>(slot + 0x48);
        node = nodeOffset != 0 ? slot + 0x48 + nodeOffset : 0;
        if (node != 0) {
            bound = *reinterpret_cast<const std::uint64_t*>(node);
            headerCount = *reinterpret_cast<const std::uint32_t*>(node + 0x14);
            count = *reinterpret_cast<const std::int32_t*>(node + 0x18);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ok = false;
    }
    if (!ok) {
        written = std::snprintf(text.data(), text.size(),
                                "ev=wtrace stage=schema tree=%s result=fault", name);
        line(text.data(), written);
        return;
    }
    if (node == 0) {
        written = std::snprintf(text.data(), text.size(),
                                "ev=wtrace stage=schema tree=%s result=no_node", name);
        line(text.data(), written);
        // The raw row/slot are still the evidence of what the live tables hold.
        dump_hex("schema_row", row, 0x40);
        dump_hex("schema_slot", slot, 0x80);
        return;
    }
    written = std::snprintf(text.data(), text.size(),
                            "ev=wtrace stage=schema tree=%s result=ok node=0x%llX bound=%llu "
                            "hdr_count=%u count=%d",
                            name, static_cast<unsigned long long>(node),
                            static_cast<unsigned long long>(bound),
                            static_cast<unsigned>(headerCount), static_cast<int>(count));
    line(text.data(), written);
    dump_hex("schema_row", row, 0x40);
    dump_hex("schema_slot", slot, 0x80);
    dump_hex("schema_node", node, 0x28);
    const std::size_t entries =
        bound < kMaxEntriesDumped ? static_cast<std::size_t>(bound) : kMaxEntriesDumped;
    for (std::size_t i = 0; i < entries; ++i) {
        const std::uintptr_t entry = node + i * 0x28;
        std::array<char, core::log::kLineCapacity> row{};
        int rw = std::snprintf(row.data(), row.size(),
                               "ev=wtrace stage=schema_entry tree=%s i=%zu hex=",
                               name, i);
        bool entryOk = true;
        __try {
            for (std::size_t b = 0; b < 0x28; ++b) {
                rw += std::snprintf(row.data() + rw, row.size() - static_cast<std::size_t>(rw),
                                    "%02X",
                                    *reinterpret_cast<const std::uint8_t*>(entry + b));
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            entryOk = false;
        }
        if (!entryOk) {
            rw += std::snprintf(row.data() + rw, row.size() - static_cast<std::size_t>(rw),
                                " <fault>");
        }
        line(row.data(), rw);
        if (!entryOk) {
            return;
        }
    }
    if (bound > kMaxEntriesDumped) {
        written = std::snprintf(text.data(), text.size(),
                                "ev=wtrace stage=schema tree=%s entries_truncated total=%llu "
                                "dumped=%zu",
                                name, static_cast<unsigned long long>(bound), entries);
        line(text.data(), written);
    }
}

/** One-shot: the chunk-8 power key + both schema trees the boot exists to capture. */
void dump_schemas_once() noexcept {
    if (g_schemaDumped.exchange(true, std::memory_order_relaxed)) {
        return;
    }
    std::array<char, 160> text{};
    // The chunk-8 schema id: *(int32*)(*(void**)base+0x209ED00), read live.
    const std::uintptr_t idPtr =
        *reinterpret_cast<const std::uintptr_t*>(g_base + kChunk8IdPtrRva);
    const std::uint32_t chunk8Key = read_dword_at(idPtr, 0);
    int written = std::snprintf(text.data(), text.size(),
                                "ev=wtrace stage=schema_id ptr=0x%llX chunk8_key=0x%08X",
                                static_cast<unsigned long long>(idPtr),
                                static_cast<unsigned>(chunk8Key));
    line(text.data(), written);
    dump_tree("chunk8_power", chunk8Key);
    dump_tree("player_archetype", kPlayerArchetypeKey);
}

/**
 * Manifest emitter (0x1417607B0): rcx = &eventid, edx = count, r8 = records (48B),
 * r9 = flags. Logs the identity column the client assembles, then the one-shot
 * schema dump on the first call.
 */
std::uint64_t __fastcall observe_emitter(const void* rcx, void* rdx, const void* r8,
                                         const void* r9, void* a5, void* a6, void* a7,
                                         void* a8, void* a9, void* a10) noexcept {
    const unsigned call = g_emitCalls.fetch_add(1, std::memory_order_relaxed) + 1U;
    if (g_emitReported.load(std::memory_order_relaxed) < kEmitCap) {
        g_emitReported.fetch_add(1, std::memory_order_relaxed);
        const std::uint32_t eventid = read_dword_at(
            reinterpret_cast<std::uintptr_t>(rcx), 0xFFFFFFFFU);
        const std::uint32_t count =
            static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(rdx));
        std::array<char, 384> text{};
        int written = std::snprintf(text.data(), text.size(),
                                    "ev=wtrace stage=emit call=%u caller_rva=0x%llX "
                                    "eventid=%u count=%u",
                                    call, caller_rva(), static_cast<unsigned>(eventid),
                                    static_cast<unsigned>(count));
        // Records: count x 48B (0x30) at r8; the identity is the first 8 bytes. Up to 4.
        // Flags: count dwords at r9. Both SEH-guarded reads.
        for (std::uint32_t i = 0; i < count && i < 4U; ++i) {
            std::uint32_t lo = 0;
            std::uint32_t hi = 0;
            std::uint32_t flag = 0;
            __try {
                const auto* const base =
                    reinterpret_cast<const std::uint8_t*>(r8) + i * 0x30U;
                lo = *reinterpret_cast<const std::uint32_t*>(base);
                hi = *reinterpret_cast<const std::uint32_t*>(base + 4);
                flag = r9 != nullptr ? *reinterpret_cast<const std::uint32_t*>(
                                           reinterpret_cast<const std::uint8_t*>(r9) + i * 4U)
                                     : 0U;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                lo = 0xDEADBEEFU;
                hi = 0xDEADBEEFU;
                flag = 0xFFFFFFFFU;
            }
            written += std::snprintf(text.data() + written,
                                     text.size() - static_cast<std::size_t>(written),
                                     " rec%u=%08X%08X f%u=%u", i,
                                     static_cast<unsigned>(hi), static_cast<unsigned>(lo),
                                     i, static_cast<unsigned>(flag));
            if (written > static_cast<int>(text.size()) - 48) {
                break;
            }
        }
        line(text.data(), written);
    }
    if (call == 1U) {
        dump_schemas_once();
    }
    const auto original = reinterpret_cast<EmitterFn>(g_emitter.original);
    return original(rcx, rdx, r8, r9, a5, a6, a7, a8, a9, a10);
}

/**
 * Entity create/decode (0x141718080). Its RETURN VALUE is the decode verdict:
 * 0 = success, 1/2 = codec-body decode failed, 3 = update-mask walker failure.
 * Logs the record's fields before and after the original runs.
 */
std::uint64_t __fastcall observe_entity(void* rcx, void* rdx, void* record, void* r9,
                                        void* param5, void* a6, void* a7, void* a8,
                                        void* a9, void* a10) noexcept {
    const unsigned call = g_entityCalls.fetch_add(1, std::memory_order_relaxed) + 1U;
    const std::uintptr_t recordAddr = reinterpret_cast<std::uintptr_t>(record);
    const std::uint32_t entityIndex =
        read_dword_at(g_base + kEntityIndexRva, 0xFFFFFFFFU);
    if (g_entityReported.load(std::memory_order_relaxed) < kEntityCap) {
        g_entityReported.fetch_add(1, std::memory_order_relaxed);
        std::array<char, 288> text{};
        const std::uint32_t flagsByte = read_dword_at(recordAddr + 0x40U, 0xFFFFFFFFU);
        const std::uint32_t localIndex = read_dword_at(recordAddr + 0x02U, 0xFFFFFFFFU);
        int written = std::snprintf(text.data(), text.size(),
                                    "ev=wtrace stage=entity call=%u caller_rva=0x%llX "
                                    "entity_index=%u flags=0x%02X local_index=%u param5=%d",
                                    call, caller_rva(),
                                    static_cast<unsigned>(entityIndex),
                                    static_cast<unsigned>(flagsByte & 0xFFU),
                                    static_cast<unsigned>(localIndex & 0xFFFFU),
                                    static_cast<int>(reinterpret_cast<std::intptr_t>(param5)));
        line(text.data(), written);
    }
    const auto original = reinterpret_cast<EntityFn>(g_entity.original);
    const std::uint64_t result =
        original(rcx, rdx, record, r9, param5, a6, a7, a8, a9, a10);
    if (g_entityReported.load(std::memory_order_relaxed) < kEntityCap) {
        g_entityReported.fetch_add(1, std::memory_order_relaxed);
        const std::uint32_t codecType = read_dword_at(recordAddr, 0xFFFFFFFFU);
        const std::uint32_t sizeWord = read_dword_at(recordAddr + 0x2cU, 0xFFFFFFFFU);
        const std::uint32_t streamByte = read_dword_at(recordAddr + 0x44U, 0xFFFFFFFFU);
        const std::uintptr_t body =
            *reinterpret_cast<const std::uintptr_t*>(recordAddr + 0x30U);
        std::array<char, 384> text{};
        int written = std::snprintf(text.data(), text.size(),
                                    "ev=wtrace stage=entity_done call=%u ret=%llu verdict=%s "
                                    "codec_type=%u codec_size=%u stream_byte=%u body=0x%llX",
                                    call, static_cast<unsigned long long>(result),
                                    result == 0 ? "ok"
                                                : (result == 3 ? "mask_fail" : "decode_fail"),
                                    static_cast<unsigned>(codecType & 0xFFU),
                                    static_cast<unsigned>(sizeWord & 0xFFFFU),
                                    static_cast<unsigned>(streamByte & 0xFFU),
                                    static_cast<unsigned long long>(body));
        line(text.data(), written);
        // The decoded body head: what the client actually built from our record.
        if (body != 0 && (sizeWord & 0xFFFFU) > 0) {
            dump_hex("entity_body", body, (sizeWord & 0xFFFFU) < 24U ? (sizeWord & 0xFFFFU) : 24U);
        }
    }
    return result;
}

bool fail_install(const char* reason) noexcept {
    std::array<char, 112> text{};
    const int written = std::snprintf(
        text.data(), text.size(), "ev=wtrace stage=install result=fail why=%s", reason);
    line(text.data(), written);
    return false;
}

} // namespace

bool install() noexcept {
    if (!core::settings::get().client.worldTrace) {
        core::log::write(core::log::Channel::client, core::log::Level::info,
                         "ev=wtrace stage=install result=skipped why=disarmed");
        return true;
    }
    if (g_installed.exchange(true, std::memory_order_relaxed)) {
        return true;
    }
    std::byte* const base = reinterpret_cast<std::byte*>(GetModuleHandleW(nullptr));
    if (base == nullptr) {
        return fail_install("base");
    }
    g_base = reinterpret_cast<std::uintptr_t>(base);
    diagnostics::ModuleRange range{};
    if (!diagnostics::module_range(reinterpret_cast<HMODULE>(base), range)
        || !diagnostics::contains(range, g_base + kEmitterRva)
        || !diagnostics::contains(range, g_base + kEntityCreateRva)) {
        return fail_install("range");
    }
    const hooking::detour::Spec emitterSpec{reinterpret_cast<void*>(g_base + kEmitterRva),
                                            reinterpret_cast<void*>(&observe_emitter)};
    if (!hooking::detour::install(emitterSpec, g_emitter)) {
        return fail_install("emitter");
    }
    const hooking::detour::Spec entitySpec{reinterpret_cast<void*>(g_base + kEntityCreateRva),
                                           reinterpret_cast<void*>(&observe_entity)};
    if (!hooking::detour::install(entitySpec, g_entity)) {
        hooking::detour::uninstall(g_emitter);
        return fail_install("entity");
    }
    std::array<char, 192> text{};
    const int written = std::snprintf(text.data(), text.size(),
                                      "ev=wtrace stage=install result=ok emitter=0x%llX "
                                      "entity=0x%llX schema_root=0x%llX chunk8_id_ptr=0x%llX",
                                      static_cast<unsigned long long>(kEmitterRva),
                                      static_cast<unsigned long long>(kEntityCreateRva),
                                      static_cast<unsigned long long>(kSchemaRootRva),
                                      static_cast<unsigned long long>(kChunk8IdPtrRva));
    line(text.data(), written);
    return true;
}

bool uninstall() noexcept {
    if (!g_emitter.attached && !g_entity.attached) {
        return true;
    }
    const bool ok = hooking::detour::uninstall(g_emitter)
                    && hooking::detour::uninstall(g_entity);
    g_installed.store(false, std::memory_order_relaxed);
    return ok;
}

bool is_installed() noexcept {
    return g_emitter.attached && g_entity.attached;
}

} // namespace sunrise::client::hooks::world_trace
