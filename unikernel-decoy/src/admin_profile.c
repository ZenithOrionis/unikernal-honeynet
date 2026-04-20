#include "config.h"

const DecoyProfile *get_admin_profile(void) {
    static const DecoyProfile profile = {
        "admin",
        "Internal Control Panel",
        "Restricted Operations Panel",
        "Enterprise operations portal",
        "Operations Authentication",
        "Administrative access has been denied for this origin.",
        "Configuration payloads are unavailable outside maintenance windows.",
        "Control plane nominal. Patch baseline verified 3 minutes ago."
    };

    return &profile;
}

