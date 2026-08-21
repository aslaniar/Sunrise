#include "server_runtime.h"

#include "../../client/network/consumer.h"
#include "../../core/logging/log.h"
#include "../bap/runtime.h"
#include "../gameplay/gameplay_runtime.h"
#include "../http/server_http.h"
#include "../transport/bap_listener.h"
#if !defined(SUNRISE_STANDALONE_SERVER)
#include "../../client/hooks/external_server/route.h"
#include "../ui/runtime/server_ui_module_runtime.h"
#endif

namespace sunrise::server {

/** Registers Server consumers with the Client networking boundary. */
bool initialize() noexcept {
#if defined(SUNRISE_STANDALONE_SERVER)
    // The standalone process owns the socket directly: there is no Client consumer registry to
    // register with and no UI page to attach, so the transport is the entire server surface.
    if (!transport::initialize()) {
        core::log::write(core::log::Channel::server,
                         core::log::Level::warn,
                         "ev=transport stage=listen result=fail");
        return false;
    }
    return true;
#else
    if (!client::network::register_http_consumer(&http::consume)) {
        return false;
    }
    if (client::network::register_bap_consumer(&bap::consume)) {
        // External mode: the standalone server already owns BAP/gameplay on these ports.
        // A second local bind does not reliably fail the way "HTTP and UI remain useful when
        // the port is already owned" above assumed - observed instead: it silently succeeds,
        // and the Client's own loopback connect steals the local listener instead of reaching
        // the external server. The switch gates the bind itself rather than relying on that.
        const bool hostLocally = !external_server::enabled();
        if (hostLocally && !transport::initialize()) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::warn,
                             "ev=transport stage=listen result=fail");
        }
        // The gameplay endpoint must bind before any descriptor advertises it.
        if (hostLocally && !gameplay::initialize()) {
            core::log::write(core::log::Channel::server,
                             core::log::Level::warn,
                             "ev=gameplay stage=init result=fail");
        }
        if (ui::runtime::initialize()) {
            return true;
        }
        if (hostLocally) {
            gameplay::shutdown();
            transport::shutdown();
        }
        client::network::unregister_bap_consumer(&bap::consume);
    }
    // BAP registration failure rolls back the earlier HTTP registration.
    client::network::unregister_http_consumer(&http::consume);
    return false;
#endif
}

/** Runs one bounded server service slice. @param now Monotonic tick count. */
void service(std::uint64_t now) noexcept {
    transport::service(now);
    gameplay::service(now);
}

/** Unregisters Server consumers in reverse registration order. */
void shutdown() noexcept {
#if defined(SUNRISE_STANDALONE_SERVER)
    transport::shutdown();
    bap::shutdown();
#else
    ui::runtime::shutdown();
    if (!external_server::enabled()) {
        gameplay::shutdown();
        transport::shutdown();
    }
    client::network::unregister_bap_consumer(&bap::consume);
    client::network::unregister_http_consumer(&http::consume);
    bap::shutdown();
#endif
}

} // namespace sunrise::server
