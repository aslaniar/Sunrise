#include "egress_dns_replacements.h"

#include <intrin.h>
#include <string_view>

#include "../resolver/redirect.h"
#include "../internal.h"
#include "../policy/policy.h"

namespace sunrise::client::hooks::egress::dns {
namespace {

/**
 * The numeric host every redirected operation reaches. Substituting THIS name for
 * non-numeric lookups keeps the local-table contract while answering with the
 * configured server address: a plain "localhost" substitution hangs the caller's
 * NAT-discovery phase under Wine, where `DnsQuery localhost` + cache-only options
 * returns no records (FINDINGS 20.73 addendum 2 - the mac's stun never started).
 */
const char* substitute_host_a() noexcept {
    return egress::resolver::redirect_host_a();
}

const wchar_t* substitute_host_w() noexcept {
    return egress::resolver::redirect_host_w();
}

/** DNS refusal is the SDK status for a resolver that rejects the request. */
constexpr DNS_STATUS kBlockedDnsStatus = DNS_ERROR_RCODE_REFUSED;
/**
 * A numeric literal never passes through the resolver as a name, so the local-table and
 * cache-only restrictions that guarded the localhost substitution are unnecessary here -
 * and dropping them avoids the Wine-side option clashes that made "localhost" hang.
 */
constexpr DWORD kNumericQueryOptions = 0;
/**
 * An address literal needs no lookup and cannot name a remote host, so it is passed on
 * untouched. Replacing it is what produced the rejected query.
 * @return True when the caller already asked for a numeric address.
 */
template <typename Character> [[nodiscard]] bool is_numeric(const Character* name) noexcept {
    return name != nullptr && ((name[0] >= '0' && name[0] <= '9') || name[0] == ':');
}

/** @return A view of the name, or an empty view when it is null. */
template <typename Character>
[[nodiscard]] std::basic_string_view<Character> view(const Character* name) noexcept {
    return name != nullptr ? std::basic_string_view<Character>(name)
                           : std::basic_string_view<Character>{};
}

/** @return The refusal status after recording one denied resolver query. */
template <typename Character>
[[nodiscard]] DNS_STATUS deny_query(const Character* name, WORD type, const void* caller) noexcept {
    policy::log_name_decision(policy::NameOperation::dns, false, view(name), type, 0, caller);
    return kBlockedDnsStatus;
}

/** @return The resolver's own status, after recording one substituted query. */
template <typename Character>
[[nodiscard]] DNS_STATUS
allow_query(DNS_STATUS status, const Character* name, WORD type, const void* caller) noexcept {
    policy::log_name_decision(
        policy::NameOperation::dns, true, view(name), type, static_cast<unsigned>(status), caller);
    return status;
}

/** Clears pointer outputs before returning the local DNS refusal. */
void clear_query_outputs(PDNS_RECORD* results, PVOID* reserved) noexcept {
    if (results != nullptr) {
        *results = nullptr;
    }
    if (reserved != nullptr) {
        *reserved = nullptr;
    }
}

} // namespace

/** Answers one narrow-character query from the local loopback name. */
DNS_STATUS WINAPI query_a(PCSTR name,
                          WORD type,
                          DWORD options,
                          PIP4_ARRAY extra,
                          PDNS_RECORD* results,
                          PVOID* reserved) noexcept {
    const void* const caller = _ReturnAddress();
    clear_query_outputs(results, reserved);
    const auto call = original<decltype(&::DnsQuery_A)>(HookSlot::dnsQueryA);
    if (name == nullptr || name[0] == '\0' || results == nullptr || call == nullptr) {
        return deny_query(name, type, caller);
    }
    if (is_numeric(name)) {
        return allow_query(call(name, type, options, extra, results, reserved), name, type, caller);
    }
    return allow_query(
        call(substitute_host_a(), type, kNumericQueryOptions, extra, results, reserved),
        name,
        type,
        caller);
}

/** Answers one wide-character query from the local loopback name. */
DNS_STATUS WINAPI query_w(PCWSTR name,
                          WORD type,
                          DWORD options,
                          PIP4_ARRAY extra,
                          PDNS_RECORD* results,
                          PVOID* reserved) noexcept {
    const void* const caller = _ReturnAddress();
    clear_query_outputs(results, reserved);
    const auto call = original<decltype(&::DnsQuery_W)>(HookSlot::dnsQueryW);
    if (name == nullptr || name[0] == L'\0' || results == nullptr || call == nullptr) {
        return deny_query(name, type, caller);
    }
    if (is_numeric(name)) {
        return allow_query(call(name, type, options, extra, results, reserved), name, type, caller);
    }
    return allow_query(
        call(substitute_host_w(), type, kNumericQueryOptions, extra, results, reserved),
        name,
        type,
        caller);
}

/** Answers one UTF-8 query from the local loopback name. */
DNS_STATUS WINAPI query_utf8(PCSTR name,
                             WORD type,
                             DWORD options,
                             PIP4_ARRAY extra,
                             PDNS_RECORD* results,
                             PVOID* reserved) noexcept {
    const void* const caller = _ReturnAddress();
    clear_query_outputs(results, reserved);
    const auto call = original<decltype(&::DnsQuery_UTF8)>(HookSlot::dnsQueryUtf8);
    if (name == nullptr || name[0] == '\0' || results == nullptr || call == nullptr) {
        return deny_query(name, type, caller);
    }
    if (is_numeric(name)) {
        return allow_query(call(name, type, options, extra, results, reserved), name, type, caller);
    }
    return allow_query(
        call(substitute_host_a(), type, kNumericQueryOptions, extra, results, reserved),
        name,
        type,
        caller);
}

/** Answers one structured query from the local loopback name. */
DNS_STATUS WINAPI query_ex(PDNS_QUERY_REQUEST request,
                           PDNS_QUERY_RESULT results,
                           PDNS_QUERY_CANCEL cancel) noexcept {
    const void* const caller = _ReturnAddress();
    const auto call = original<decltype(&::DnsQueryEx)>(HookSlot::dnsQueryEx);
    if (request == nullptr || request->QueryName == nullptr || call == nullptr) {
        if (results != nullptr) {
            results->QueryStatus = kBlockedDnsStatus;
            results->QueryOptions = 0;
            results->pQueryRecords = nullptr;
            results->Reserved = nullptr;
        }
        if (cancel != nullptr) {
            *cancel = {};
        }
        return deny_query(request != nullptr ? request->QueryName : nullptr,
                          request != nullptr ? request->QueryType : 0,
                          caller);
    }
    DNS_QUERY_REQUEST forwarded = *request;
    if (!is_numeric(request->QueryName)) {
        forwarded.QueryName = substitute_host_w();
        forwarded.QueryOptions = kNumericQueryOptions;
    }
    return allow_query(
        call(&forwarded, results, cancel), request->QueryName, request->QueryType, caller);
}

/** Rejects one raw DNS query without scheduling its completion callback. */
DNS_STATUS WINAPI query_raw(DNS_QUERY_RAW_REQUEST* request, DNS_QUERY_RAW_CANCEL* cancel) noexcept {
    (void)request;
    if (cancel != nullptr) {
        *cancel = {};
    }
    return deny_query<char>(nullptr, 0, _ReturnAddress());
}

} // namespace sunrise::client::hooks::egress::dns
