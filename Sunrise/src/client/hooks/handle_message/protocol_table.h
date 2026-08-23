#pragma once
/**
 * BAP service registry and activity-message kinds, as DATA with handbook
 * page cites. GENERATED FILE - do not edit by hand.
 *
 * Source: RE_scripts/generate_protocol_table.py parses the page-marked
 * handbook dump (RE_output/dumps/bungie_bullshit_guide.txt) and cross-
 * checks the number sets against src/middleware/bap/frame.h enums.
 * Rerun the generator after any handbook or frame.h revision.
 *
 * Registry: Internet's guide to bungie's bullshit.pdf, sections 10.2
 * (request services, pp15-16), 10.3 (response services, pp16-17), 10.4
 * (server notifications, p17). Kinds: sections 21.2/21.3 (pp46-47).
 *
 * The tape looks names up here; no registry text lives in the observer.
 */

#include <array>
#include <cstdint>
#include <string_view>

namespace sunrise::client::hooks::handle_message::protocol {

/** One BAP service registry entry (handbook sections 10.2-10.4). */
struct ServiceEntry {
    std::uint16_t number;
    std::string_view name;
    std::string_view role;   // request | response | notification
    std::string_view page;   // handbook page cite
};

/** One activity-message kind inside the svc-9 envelope (21.2/21.3). */
struct KindEntry {
    std::uint8_t number;
    std::string_view name;   // compact tape name
    std::string_view desc;   // handbook phrasing
    std::string_view page;   // handbook page cite
};

/** request services; handbook p15-p16. */
inline constexpr std::array<ServiceEntry, 27> kRequestServices{{
    {6, "activity_host_manager", "request", "p15"}, // 6: activity-host manager
    {8, "activity_message", "request", "p15"}, // 8: activity message
    {10, "web_service", "request", "p15"}, // 10: web service
    {110, "server_role_web_service", "request", "p15"}, // 110: server-role web service
    {12, "subscribe_family", "request", "p15"}, // 12: subscribe family
    {14, "unsubscribe_family", "request", "p15"}, // 14: unsubscribe family
    {16, "activity_host", "request", "p15"}, // 16: activity host
    {18, "client_configuration", "request", "p15"}, // 18: client configuration
    {21, "purchased_offers", "request", "p15"}, // 21: purchased offers
    {23, "account_translation", "request", "p15"}, // 23: account translation
    {25, "server_hello", "request", "p16"}, // 25: server hello
    {29, "one_way_notification", "request", "p16"}, // 29: one-way notification
    {30, "start", "request", "p16"}, // 30: start
    {32, "user_message", "request", "p16"}, // 32: user message
    {34, "skill", "request", "p16"}, // 34: skill
    {36, "unnamed_request", "request", "p16"}, // 36: unnamed request
    {38, "unnamed_request", "request", "p16"}, // 38: unnamed request
    {40, "unnamed_request", "request", "p16"}, // 40: unnamed request
    {42, "matchmaking", "request", "p16"}, // 42: matchmaking
    {44, "clan", "request", "p16"}, // 44: clan
    {48, "unnamed_request", "request", "p16"}, // 48: unnamed request
    {121, "register_subscriber", "request", "p16"}, // 121: register subscriber
    {171, "large_one_way_notification", "request", "p16"}, // 171: large one-way notification
    {250, "echo", "request", "p16"}, // 250: echo
    {302, "relay_registration", "request", "p16"}, // 302: relay registration
    {304, "steam_certificate_signing", "request", "p16"}, // 304: Steam certificate signing
    {306, "account_from_membership", "request", "p16"}, // 306: account from membership
}};

/** response services; handbook p16-p17. */
inline constexpr std::array<ServiceEntry, 24> kResponseServices{{
    {7, "activity_host_manager", "response", "p16"}, // 7: activity-host manager
    {11, "web_service", "response", "p16"}, // 11: web service
    {112, "server_role_web_service", "response", "p16"}, // 112: server-role web service
    {13, "subscribe_family", "response", "p16"}, // 13: subscribe family
    {15, "unsubscribe_family", "response", "p16"}, // 15: unsubscribe family
    {17, "activity_host", "response", "p16"}, // 17: activity host
    {19, "client_configuration", "response", "p16"}, // 19: client configuration
    {22, "purchased_offers", "response", "p16"}, // 22: purchased offers
    {24, "account_translation", "response", "p16"}, // 24: account translation
    {26, "server_hello", "response", "p16"}, // 26: server hello
    {31, "start", "response", "p16"}, // 31: start
    {33, "user_message", "response", "p16"}, // 33: user message
    {35, "skill", "response", "p16"}, // 35: skill
    {37, "response_to_service_36", "response", "p16"}, // 37: response to service 36
    {39, "response_to_service_38", "response", "p16"}, // 39: response to service 38
    {41, "response_to_service_40", "response", "p16"}, // 41: response to service 40
    {43, "matchmaking", "response", "p16"}, // 43: matchmaking
    {45, "clan", "response", "p17"}, // 45: clan
    {49, "response_to_service_48", "response", "p17"}, // 49: response to service 48
    {122, "subscriber_registration", "response", "p17"}, // 122: subscriber registration
    {251, "echo", "response", "p17"}, // 251: echo
    {303, "relay_registration", "response", "p17"}, // 303: relay registration
    {305, "steam_certificate_signing", "response", "p17"}, // 305: Steam certificate signing
    {307, "account_from_membership", "response", "p17"}, // 307: account from membership
}};

/** notification services; handbook p17-p17. */
inline constexpr std::array<ServiceEntry, 2> kNotificationServices{{
    {9, "activity_message", "notification", "p17"}, // 9: activity message
    {123, "queue_update", "notification", "p17"}, // 123: queue update
}};

/** activity-message kinds; handbook p46-p47. */
inline constexpr std::array<KindEntry, 37> kMessageKinds{{
    {0, "entity_slot_notification", "entity-slot notification", "p46"},
    {1, "global_activity_state", "global activity state", "p46"},
    {3, "join_request", "join request", "p46"},
    {4, "join_result", "join result or pending-join notification", "p46"},
    {5, "auth_sense", "auth and sense update", "p46"},
    {6, "sense_update", "sense update", "p46"},
    {8, "request_activity_host", "request activity host", "p46"},
    {11, "start_new_activity", "start new activity", "p46"},
    {12, "membership_replication", "membership replication", "p46"},
    {13, "request_peer_reservation", "request peer reservation", "p47"},
    {14, "release_peer_reservation", "release peer reservation", "p47"},
    {15, "peer_leave", "peer leave request", "p47"},
    {16, "keepalive", "client keepalive", "p47"},
    {18, "state_refresh", "state refresh", "p47"},
    {19, "incident_report", "incident report", "p47"},
    {20, "slot_grant_request", "entity-slot grant request", "p47"},
    {21, "slot_return", "entity-slot return", "p47"},
    {22, "client_authoritative_data", "client authoritative data", "p47"},
    {23, "client_identity", "client identity", "p47"},
    {26, "abandon_authority", "abandon authority", "p47"},
    {27, "purge", "purge request", "p47"},
    {29, "reset_ack", "reset acknowledgement", "p47"},
    {31, "query_answer", "per-bubble query answer", "p47"},
    {32, "query_answer", "whole-activity query answer", "p47"},
    {33, "abdicate", "abdicate authority", "p47"},
    {34, "debug", "debug command", "p47"},
    {37, "connectivity_failure", "connectivity failure report", "p47"},
    {38, "membership_ack", "membership acknowledgement", "p47"},
    {39, "heartbeat", "client heartbeat", "p47"},
    {43, "bug_claw", "bug-claw report", "p47"},
    {46, "lag_switch", "lag-switch report", "p47"},
    {47, "connection_quality", "connection-quality report", "p47"},
    {48, "speculative_migration", "speculative migration report", "p47"},
    {49, "high_water", "high-water report", "p47"},
    {50, "inspirations_refresh", "inspirations refresh", "p47"},
    {52, "patch_epoch", "patch epoch", "p47"},
    {54, "bubble_host_table", "bubble-host table", "p46"},
}};

/** @return Handbook name for one BAP service number, or "" when unknown. */
[[nodiscard]] inline const char* service_name(std::uint16_t number) noexcept {
    for (const ServiceEntry& entry : kRequestServices) {
        if (entry.number == number) return entry.name.data();
    }
    for (const ServiceEntry& entry : kResponseServices) {
        if (entry.number == number) return entry.name.data();
    }
    for (const ServiceEntry& entry : kNotificationServices) {
        if (entry.number == number) return entry.name.data();
    }
    return "";
}

/** @return Tape name for one activity-message kind, or "" when unknown. */
[[nodiscard]] inline const char* kind_name(std::uint8_t number) noexcept {
    for (const KindEntry& entry : kMessageKinds) {
        if (entry.number == number) return entry.name.data();
    }
    return "";
}

} // namespace sunrise::client::hooks::handle_message::protocol
