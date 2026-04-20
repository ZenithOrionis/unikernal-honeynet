#include "config.h"

const DecoyProfile *get_router_profile(void) {
    static const DecoyProfile profile = {
        "router",
        "EdgeRouter X",
        "Core Gateway Console",
        "WAN routing node",
        "Gateway Authentication",
        "Administrative functions are restricted to trusted subnets.",
        "Configuration export is disabled while the uplink is in service mode.",
        "WAN uplink stable. DHCP leases refreshed 11 seconds ago."
    };

    return &profile;
}

