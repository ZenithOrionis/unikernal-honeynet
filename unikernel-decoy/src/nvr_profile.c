#include "config.h"

const DecoyProfile *get_nvr_profile(void) {
    static const DecoyProfile profile = {
        "nvr",
        "SecureVision NVR",
        "Camera Management Portal",
        "CCTV storage controller",
        "Recorder Sign-In",
        "Video archive controls require elevated recorder privileges.",
        "Remote export is disabled while camera indexing is in progress.",
        "All channels online. Motion archive backlog: 02 clips."
    };

    return &profile;
}

