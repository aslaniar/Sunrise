/**
 * Sword skate. A sword's air attack throws the player forward, and a glide started while that
 * throw is still carrying them keeps the speed for about a second. The client refuses to start a
 * glide while the throw is active, so the speed decays instead and the chain cannot be continued.
 *
 * The refusal is one bit of a movement-state field on the player's physics component. It is set
 * when the air attack starts and cleared when it ends, and the glide reads it before anything
 * else. Clearing it on the tick the jump is pressed lets the client start its own glide, with its
 * own lift, drift and air control; nothing here moves the player.
 *
 * The bit was found by comparing two builds through the same injected inputs at the same timings:
 * one where the glide starts after a sword throw and one where it is refused. The throw itself is
 * identical on both, reaching the same speed, and a glide the client accepts on its own decays at
 * the same rate on both, so neither the throw nor the glide was changed. Only the refusal was.
 */

#include "sword_skate.h"

#include <Windows.h>

#include <cstddef>
#include <cstdint>

#include "../../../core/ui/runtime/ui_visibility_runtime.h"
#include "../../sword_skate/sword_skate_settings_store.h"
#include "../teleport/runtime.h"

namespace sunrise::client::hooks::sword_skate {
namespace {

/** Movement-state flags on the player's physics component. */
constexpr std::size_t kMovementStateOffset = 15492;
/**
 * Set while a sword's air attack is carrying the player, and read by the glide before it starts.
 * The field carries other bits that the attack also sets; only this one refuses the glide, and
 * clearing only it leaves the rest of the attack's state alone.
 */
constexpr std::uint32_t kGlideRefusedBit = 0x00000800U;
/** The high bit of a polled key state marks it held. */
constexpr SHORT kKeyHeldBit = static_cast<SHORT>(0x8000);

/** Jump held on the previous tick, so the flag is only cleared on the press and not on the hold. */
bool g_jumpHeld{false};

/**
 * Reads one value out of game memory without faulting on a torn pointer.
 * @param address Source address.
 * @param value Receives the value.
 * @return True when Windows copied the whole value.
 */
[[nodiscard]] bool read_at(const std::byte* address, std::uint32_t& value) noexcept {
    SIZE_T read = 0;
    return ReadProcessMemory(GetCurrentProcess(), address, &value, sizeof value, &read) != FALSE
           && read == sizeof value;
}

/**
 * Writes one value into game memory. The call applies page protection itself.
 * @param address Destination address.
 * @param value Value to store.
 * @return True when Windows copied the whole value.
 */
[[nodiscard]] bool write_at(std::byte* address, std::uint32_t value) noexcept {
    SIZE_T written = 0;
    return WriteProcessMemory(GetCurrentProcess(), address, &value, sizeof value, &written) != FALSE
           && written == sizeof value;
}

} // namespace

/** Clears the glide refusal for one physics tick of the local player. */
void apply(void* component) noexcept {
    const client::sword_skate::Settings settings = client::sword_skate::get();
    // An open interface owns the keyboard, so a press meant for it must not reach this either.
    const bool usable = settings.enabled && settings.jumpKey != client::sword_skate::kNoKey
                        && !core::ui::runtime::snapshot().visible;
    if (!usable) {
        // Cleared rather than left as it was, or the first press after the feature comes back is
        // read as a hold and skipped.
        g_jumpHeld = false;
        return;
    }
    // Ownership is tested before the key is read, because this runs for every component the sync
    // touches and the held flag must only ever advance on the player's own tick. Advancing it on
    // any other component lets that component consume the press, and the player's tick then sees
    // no edge at all.
    if (component == nullptr || !teleport::owns_local_player(component)) {
        return;
    }
    const bool held = (GetAsyncKeyState(static_cast<int>(settings.jumpKey)) & kKeyHeldBit) != 0;
    const bool wasHeld = g_jumpHeld;
    g_jumpHeld = held;
    // Only the press matters. Clearing the flag for as long as the key is down would keep it clear
    // through the whole attack, which is a different change to make and not this one.
    if (!held || wasHeld) {
        return;
    }
    auto* const bytes = static_cast<std::byte*>(component);
    std::uint32_t state = 0;
    if (!read_at(bytes + kMovementStateOffset, state) || (state & kGlideRefusedBit) == 0) {
        return;
    }
    (void)write_at(bytes + kMovementStateOffset, state & ~kGlideRefusedBit);
}

} // namespace sunrise::client::hooks::sword_skate
