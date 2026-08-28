#include <string_view>

#include "../internal.h"
#include "../policy/policy.h"
#include "redirect.h"
#include "replacements.h"

#include "self_address.h"

namespace sunrise::client::hooks::egress::resolver {
namespace {

/** @return Family answered for one requested address-info family. */
[[nodiscard]] int redirect_family(int family) noexcept {
    return family == AF_INET6 ? AF_INET6 : AF_INET;
}

/**
 * Builds numeric IPv4 constraints without caller-owned output pointers.
 * @tparam AddressInfo ANSI or wide Windows address-info layout.
 * @param hints Caller socket constraints.
 * @param family Address family the system resolver must answer.
 * @return Constraints for the system resolver.
 */
template <typename AddressInfo>
[[nodiscard]] AddressInfo redirect_hints(const AddressInfo* hints, int family) noexcept {
    AddressInfo forwarded{};
    forwarded.ai_flags = AI_NUMERICHOST;
    forwarded.ai_family = family;
    if (hints != nullptr) {
        forwarded.ai_flags |= hints->ai_flags;
        forwarded.ai_socktype = hints->ai_socktype;
        forwarded.ai_protocol = hints->ai_protocol;
    }
    return forwarded;
}

} // namespace

/** Maps a synchronous ANSI lookup to the numeric redirect target of its requested family. */
INT WSAAPI address_info_a(PCSTR node,
                          PCSTR service,
                          const ADDRINFOA* hints,
                          PADDRINFOA* result) noexcept {
    if (result != nullptr) {
        *result = nullptr;
    }
    const int family = redirect_family(hints != nullptr ? hints->ai_family : AF_UNSPEC);
    const auto call = original<decltype(&::getaddrinfo)>(HookSlot::getAddrInfoA);
    if (node == nullptr || node[0] == '\0' || result == nullptr || call == nullptr) {
        return deny_resolution(policy::NameOperation::resolve, node, family);
    }
    policy::log_name_decision(policy::NameOperation::resolve, true, node, family);
    // FINDINGS 20.125 step 1: the machine's own name answers with its own LAN address, not
    // with the server's (the rig joined believing it lived at the host it was dialing).
    char selfHost[16]{};
    in_addr selfAddress{};
    const char* forwardedNode = redirect_host_a();
    if (self_address::is_self_name(node)
        && self_address::self_address(selfHost, sizeof(selfHost), selfAddress)) {
        self_address::log_self(node, selfHost);
        forwardedNode = selfHost;
    }
    const ADDRINFOA forwarded = redirect_hints(hints, family);
    return call(family == AF_INET6 ? kLoopbackHost6A : forwardedNode, service, &forwarded, result);
}

/** Maps a synchronous wide lookup to the numeric redirect target of its requested family. */
INT WSAAPI address_info_w(PCWSTR node,
                          PCWSTR service,
                          const ADDRINFOW* hints,
                          PADDRINFOW* result) noexcept {
    if (result != nullptr) {
        *result = nullptr;
    }
    const int family = redirect_family(hints != nullptr ? hints->ai_family : AF_UNSPEC);
    const auto call = original<decltype(&::GetAddrInfoW)>(HookSlot::getAddrInfoW);
    if (node == nullptr || node[0] == L'\0' || result == nullptr || call == nullptr) {
        return deny_resolution(policy::NameOperation::resolve, node, family);
    }
    policy::log_name_decision(policy::NameOperation::resolve, true, node, family);
    char selfHost[16]{};
    wchar_t selfHostWide[16]{};
    in_addr selfAddress{};
    const wchar_t* forwardedNode = redirect_host_w();
    if (self_address::is_self_name(node)
        && self_address::self_address(selfHost, sizeof(selfHost), selfAddress)) {
        self_address::log_self(selfHost, selfHost);
        for (std::size_t index = 0; index + 1 < sizeof(selfHostWide) / sizeof(selfHostWide[0]);
             ++index) {
            selfHostWide[index] = static_cast<wchar_t>(selfHost[index]);
            if (selfHost[index] == '\0') {
                break;
            }
        }
        forwardedNode = selfHostWide;
    }
    const ADDRINFOW forwarded = redirect_hints(hints, family);
    return call(family == AF_INET6 ? kLoopbackHost6W : forwardedNode, service, &forwarded, result);
}

/** Maps one extended narrow-character lookup to the numeric redirect target. */
INT WSAAPI address_info_ex_a(PCSTR name,
                             PCSTR service,
                             DWORD nameSpace,
                             LPGUID provider,
                             const ADDRINFOEXA* hints,
                             PADDRINFOEXA* result,
                             timeval* timeout,
                             LPOVERLAPPED overlapped,
                             LPLOOKUPSERVICE_COMPLETION_ROUTINE completion,
                             LPHANDLE nameHandle) noexcept {
    if (result != nullptr) {
        *result = nullptr;
    }
    if (nameHandle != nullptr) {
        *nameHandle = nullptr;
    }
    const auto call = original<decltype(&::GetAddrInfoExA)>(HookSlot::getAddrInfoExA);
    if (name == nullptr || name[0] == 0 || result == nullptr || call == nullptr) {
        return deny_resolution(policy::NameOperation::resolve, name, 0);
    }
    policy::log_name_decision(policy::NameOperation::resolve, true, name, 0);
    char selfHost[16]{};
    in_addr selfAddress{};
    const char* forwardedNode = redirect_host_a();
    if (self_address::is_self_name(name)
        && self_address::self_address(selfHost, sizeof(selfHost), selfAddress)) {
        self_address::log_self(name, selfHost);
        forwardedNode = selfHost;
    }
    return call(forwardedNode,
                service,
                nameSpace,
                provider,
                hints,
                result,
                timeout,
                overlapped,
                completion,
                nameHandle);
}

/** Maps one extended wide-character lookup to the numeric redirect target. */
INT WSAAPI address_info_ex_w(PCWSTR name,
                             PCWSTR service,
                             DWORD nameSpace,
                             LPGUID provider,
                             const ADDRINFOEXW* hints,
                             PADDRINFOEXW* result,
                             timeval* timeout,
                             LPOVERLAPPED overlapped,
                             LPLOOKUPSERVICE_COMPLETION_ROUTINE completion,
                             LPHANDLE nameHandle) noexcept {
    if (result != nullptr) {
        *result = nullptr;
    }
    if (nameHandle != nullptr) {
        *nameHandle = nullptr;
    }
    const auto call = original<decltype(&::GetAddrInfoExW)>(HookSlot::getAddrInfoExW);
    if (name == nullptr || name[0] == 0 || result == nullptr || call == nullptr) {
        return deny_resolution(policy::NameOperation::resolve, name, 0);
    }
    policy::log_name_decision(policy::NameOperation::resolve, true, name, 0);
    char selfHostN[16]{};
    wchar_t selfHost[16]{};
    in_addr selfAddress{};
    const wchar_t* forwardedNode = redirect_host_w();
    if (self_address::is_self_name(name)
        && self_address::self_address(selfHostN, sizeof(selfHostN), selfAddress)) {
        self_address::log_self(selfHostN, selfHostN);
        for (std::size_t index = 0; index + 1 < sizeof(selfHost) / sizeof(selfHost[0]);
             ++index) {
            selfHost[index] = static_cast<wchar_t>(selfHostN[index]);
            if (selfHostN[index] == '\0') {
                break;
            }
        }
        forwardedNode = selfHost;
    }
    return call(forwardedNode,
                service,
                nameSpace,
                provider,
                hints,
                result,
                timeout,
                overlapped,
                completion,
                nameHandle);
}

/** Answers a legacy forward lookup from fixed storage without a resolver call. */
hostent* WSAAPI host_by_name(const char* name) noexcept {
    if (name == nullptr || name[0] == '\0') {
        // A null name must not reach the string_view parameter: its implicit conversion runs
        // strlen. Same guard as deny_resolution.
        policy::log_name_decision(policy::NameOperation::resolve,
                                  false,
                                  name != nullptr ? std::string_view(name) : std::string_view{},
                                  AF_INET);
        WSASetLastError(kBlockedHostError);
        return nullptr;
    }
    // Winsock keeps its own result in per-thread storage and callers read it before their
    // next lookup, so fixed thread-local storage matches the documented lifetime.
    thread_local in_addr address{};
    thread_local char* addressList[2]{};
    thread_local char* aliases[1]{};
    thread_local hostent entry{};
    char selfHost[16]{};
    in_addr selfAddress{};
    if (self_address::is_self_name(name)
        && self_address::self_address(selfHost, sizeof(selfHost), selfAddress)) {
        self_address::log_self(name, selfHost);
        address = selfAddress;
    } else {
        address = redirect_address();
    }
    addressList[0] = reinterpret_cast<char*>(&address);
    addressList[1] = nullptr;
    aliases[0] = nullptr;
    entry.h_name = const_cast<char*>(name);
    entry.h_aliases = aliases;
    entry.h_addrtype = AF_INET;
    entry.h_length = static_cast<short>(sizeof(address));
    entry.h_addr_list = addressList;
    policy::log_name_decision(policy::NameOperation::resolve, true, name, AF_INET);
    return &entry;
}

} // namespace sunrise::client::hooks::egress::resolver
