#ifndef CONFIG_H
#define CONFIG_H

#include <stddef.h>

#define DEFAULT_LISTEN_PORT 80
#define DEFAULT_COLLECTOR_URL "http://10.0.2.2:5000/event"
#define DEFAULT_PROFILE "router"
#define DEFAULT_DECOY_ID "gw-core-01"
#define DEFAULT_TITLE "EdgeRouter X"
#define DEFAULT_HOSTNAME "gw-core-01"
#define DEFAULT_LABEL "WAN routing node"
#define DEFAULT_ASSET_DIR "/app/assets"

#define MAX_METHOD_LENGTH 8
#define MAX_PATH_LENGTH 256
#define MAX_USER_AGENT_LENGTH 256
#define MAX_BODY_LENGTH 2048
#define MAX_FIELD_LENGTH 128
#define MAX_PROFILE_LENGTH 32
#define MAX_TITLE_LENGTH 128
#define MAX_HOSTNAME_LENGTH 64
#define MAX_LABEL_LENGTH 128
#define MAX_URL_LENGTH 256
#define MAX_ASSET_DIR_LENGTH 256
#define MAX_TAG_COUNT 12
#define MAX_TAG_LENGTH 64

typedef struct {
    char method[MAX_METHOD_LENGTH];
    char path[MAX_PATH_LENGTH];
    char user_agent[MAX_USER_AGENT_LENGTH];
    char body[MAX_BODY_LENGTH];
    char username[MAX_FIELD_LENGTH];
    char password[MAX_FIELD_LENGTH];
    size_t body_length;
    int suspicious;
    char tags[MAX_TAG_COUNT][MAX_TAG_LENGTH];
    int tag_count;
} HttpRequest;

typedef struct {
    char profile[MAX_PROFILE_LENGTH];
    char decoy_id[MAX_HOSTNAME_LENGTH];
    char title[MAX_TITLE_LENGTH];
    char hostname[MAX_HOSTNAME_LENGTH];
    char label[MAX_LABEL_LENGTH];
    char collector_url[MAX_URL_LENGTH];
    char asset_dir[MAX_ASSET_DIR_LENGTH];
    int listen_port;
} DecoyConfig;

typedef struct {
    const char *name;
    const char *default_title;
    const char *banner;
    const char *service_label;
    const char *login_heading;
    const char *admin_message;
    const char *config_message;
    const char *status_message;
} DecoyProfile;

const DecoyProfile *get_router_profile(void);
const DecoyProfile *get_nvr_profile(void);
const DecoyProfile *get_admin_profile(void);

int parse_http_request(const char *raw_request, HttpRequest *request);
size_t build_http_response(
    const DecoyConfig *config,
    const HttpRequest *request,
    char *response,
    size_t response_capacity
);
int send_event_to_collector(
    const DecoyConfig *config,
    const HttpRequest *request,
    const char *source_ip
);

#endif

