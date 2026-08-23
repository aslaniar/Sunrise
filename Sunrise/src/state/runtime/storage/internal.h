#pragma once

#include <Windows.h>

#include "../../../core/settings/provisioning.h"
#include "../state.h"

namespace sunrise::state::runtime::storage {

/** One root process-local State per provisioned account; slot 0 is the legacy slot. */
extern std::array<State, core::settings::kAccountCapacity> g_states;
/** How many slots are live (>= 1 after any successful initialize). */
extern std::size_t g_accountCount;
/** Windows reader-writer lock protecting mutable root State fields. */
extern SRWLOCK g_stateLock;

} // namespace sunrise::state::runtime::storage
