/**
 * The sword-skate module's interface. Every control writes the configuration straight to disk, so
 * a change made here survives the next launch without a settings edit.
 */

#include "sword_skate_panel.h"

#include <Windows.h>

#include <array>
#include <cstdio>
#include <imgui.h>

#include "../../../core/ui/components/toggle/ui_toggle_component.h"
#include "../../sword_skate/sword_skate_settings_store.h"

namespace sunrise::client::ui::sword_skate {
namespace {

/** Lowest and highest virtual keys the picker scans. Zero is not a key. */
constexpr int kFirstVirtualKey = 1;
constexpr int kLastVirtualKey = 254;
/** Mouse buttons are skipped so a click on the picker cannot bind itself. */
constexpr int kLastMouseKey = 6;
/** Longest key name Windows returns, plus the null. */
constexpr std::size_t kKeyNameCapacity = 64;

bool g_capturing{};

/**
 * Names one virtual key for display.
 * @param virtualKey Key to name, or zero for no binding.
 * @param output Receives the name.
 */
void key_name(std::uint32_t virtualKey, std::array<char, kKeyNameCapacity>& output) noexcept {
    if (virtualKey == client::sword_skate::kNoKey) {
        (void)std::snprintf(output.data(), output.size(), "None");
        return;
    }
    const UINT scanCode = MapVirtualKeyW(virtualKey, MAPVK_VK_TO_VSC);
    std::array<wchar_t, kKeyNameCapacity> wide{};
    const int written = scanCode != 0 ? GetKeyNameTextW(static_cast<LONG>(scanCode << 16),
                                                        wide.data(),
                                                        static_cast<int>(wide.size()))
                                      : 0;
    if (written <= 0
        || WideCharToMultiByte(CP_UTF8,
                               0,
                               wide.data(),
                               written,
                               output.data(),
                               static_cast<int>(output.size() - 1),
                               nullptr,
                               nullptr)
               <= 0) {
        (void)std::snprintf(
            output.data(), output.size(), "Key 0x%02X", static_cast<unsigned>(virtualKey));
    }
}

/**
 * Takes the first key held while the picker is armed.
 * @param picked Receives the key, or zero when Escape clears the binding.
 * @return True when this frame ended the capture.
 */
[[nodiscard]] bool capture_key(std::uint32_t& picked) noexcept {
    if ((GetAsyncKeyState(VK_ESCAPE) & 0x8000) != 0) {
        picked = client::sword_skate::kNoKey;
        return true;
    }
    for (int key = kFirstVirtualKey; key <= kLastVirtualKey; ++key) {
        if (key <= kLastMouseKey) {
            continue;
        }
        if ((GetAsyncKeyState(key) & 0x8000) != 0) {
            picked = static_cast<std::uint32_t>(key);
            return true;
        }
    }
    return false;
}

} // namespace

/** Draws the sword-skate module inside the active Core UI frame. */
void draw() noexcept {
    client::sword_skate::Settings settings = client::sword_skate::get();
    bool changed = false;

    ImGui::TextUnformatted("Sword Skate");
    ImGui::Separator();
    ImGui::TextWrapped("A sword's air attack throws you forward, and a glide started while that "
                       "throw is still carrying you keeps the speed. The client refuses to start "
                       "a glide during the throw; this clears that refusal on the tick you press "
                       "jump, and the client's own glide runs from there.");
    ImGui::Spacing();

    changed = core::ui::components::toggle::control("Enabled", settings.enabled) || changed;

    ImGui::Spacing();
    // One label column and one control column, so the key button spans both edges.
    const float labelWidth =
        ImGui::CalcTextSize("Jump key").x + ImGui::GetStyle().ItemSpacing.x * 2;
    const float controlWidth = ImGui::GetContentRegionAvail().x - labelWidth;

    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted("Jump key");
    ImGui::SameLine(labelWidth);
    if (g_capturing) {
        if (ImGui::Button("...", ImVec2(controlWidth, 0.0F))) {
            g_capturing = false;
        }
        std::uint32_t picked = client::sword_skate::kNoKey;
        if (capture_key(picked)) {
            settings.jumpKey = picked;
            g_capturing = false;
            changed = true;
        }
    } else {
        std::array<char, kKeyNameCapacity> name{};
        key_name(settings.jumpKey, name);
        if (ImGui::Button(name.data(), ImVec2(controlWidth, 0.0F))) {
            g_capturing = true;
        }
    }
    ImGui::TextWrapped("Must match the key the game jumps on. Nothing happens on any other key.");

    if (changed && !client::sword_skate::publish(settings)) {
        ImGui::Spacing();
        ImGui::TextUnformatted("value out of range, not saved");
    }
}

} // namespace sunrise::client::ui::sword_skate
