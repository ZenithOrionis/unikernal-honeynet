#define _POSIX_C_SOURCE 200112L

#include "config.h"

#include <errno.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>


typedef struct {
    char host[128];
    int port;
    char path[128];
} CollectorUrl;


static unsigned long event_counter = 0;


static void safe_copy(char *destination, size_t capacity, const char *source) {
    if (capacity == 0) {
        return;
    }

    if (source == NULL) {
        destination[0] = '\0';
        return;
    }

    snprintf(destination, capacity, "%s", source);
}


static void append_text(char *buffer, size_t capacity, size_t *length, const char *text) {
    int written;

    if (*length >= capacity || text == NULL) {
        return;
    }

    written = snprintf(buffer + *length, capacity - *length, "%s", text);
    if (written < 0) {
        return;
    }

    *length += (size_t) written;
}


static void current_timestamp(char *buffer, size_t capacity) {
    time_t now = time(NULL);
    struct tm timestamp_parts;

    gmtime_r(&now, &timestamp_parts);
    strftime(buffer, capacity, "%Y-%m-%dT%H:%M:%SZ", &timestamp_parts);
}


static void build_event_id(char *buffer, size_t capacity, const char *prefix) {
    struct timeval now;

    gettimeofday(&now, NULL);
    event_counter += 1;
    snprintf(
        buffer,
        capacity,
        "%s-%ld-%ld-%lu",
        prefix,
        (long) now.tv_sec,
        (long) now.tv_usec,
        event_counter
    );
}


static void escape_json(const char *input, char *output, size_t capacity) {
    size_t index = 0;

    if (capacity == 0) {
        return;
    }

    while (input != NULL && *input != '\0' && index + 2 < capacity) {
        switch (*input) {
            case '\\':
            case '"':
                output[index++] = '\\';
                output[index++] = *input;
                break;
            case '\n':
                output[index++] = '\\';
                output[index++] = 'n';
                break;
            case '\r':
                output[index++] = '\\';
                output[index++] = 'r';
                break;
            case '\t':
                output[index++] = '\\';
                output[index++] = 't';
                break;
            default:
                output[index++] = *input;
                break;
        }
        input++;
    }

    output[index] = '\0';
}


static void build_headers_subset_json(const HttpRequest *request, char *buffer, size_t capacity) {
    char escaped_host[MAX_HOSTNAME_LENGTH * 2];
    char escaped_accept[256];

    escape_json(request->host, escaped_host, sizeof(escaped_host));
    escape_json(request->accept, escaped_accept, sizeof(escaped_accept));

    snprintf(
        buffer,
        capacity,
        "{"
        "\"host\":\"%s\","
        "\"accept\":\"%s\""
        "}",
        escaped_host,
        escaped_accept
    );
}


static void build_tags_json(const HttpRequest *request, char *buffer, size_t capacity) {
    int i;
    size_t length = 0;

    buffer[0] = '\0';
    append_text(buffer, capacity, &length, "[");

    for (i = 0; i < request->tag_count; i++) {
        char escaped_tag[MAX_TAG_LENGTH * 2];

        if (i > 0) {
            append_text(buffer, capacity, &length, ",");
        }

        escape_json(request->tags[i], escaped_tag, sizeof(escaped_tag));
        append_text(buffer, capacity, &length, "\"");
        append_text(buffer, capacity, &length, escaped_tag);
        append_text(buffer, capacity, &length, "\"");
    }

    append_text(buffer, capacity, &length, "]");
}


static const char *event_class_from_request(const HttpRequest *request) {
    int index;

    for (index = 0; index < request->tag_count; index++) {
        if (strcmp(request->tags[index], "credential_bruteforce") == 0) {
            return "credential";
        }
        if (strcmp(request->tags[index], "path_traversal_probe") == 0 ||
            strcmp(request->tags[index], "xss_probe") == 0 ||
            strcmp(request->tags[index], "sqli_probe") == 0) {
            return "probe";
        }
        if (strcmp(request->tags[index], "admin_panel_enumeration") == 0 ||
            strcmp(request->tags[index], "sensitive_path_discovery") == 0) {
            return "recon";
        }
    }

    return request->suspicious ? "scan" : "probe";
}


static void build_request_fingerprint(const HttpRequest *request, char *buffer, size_t capacity) {
    uint32_t hash = 2166136261u;
    const char *parts[] = {request->method, request->path, request->user_agent};
    int part_index;

    for (part_index = 0; part_index < 3; part_index++) {
        const unsigned char *cursor = (const unsigned char *) parts[part_index];
        while (cursor != NULL && *cursor != '\0') {
            hash ^= (uint32_t) *cursor++;
            hash *= 16777619u;
        }
        hash ^= (uint32_t) '|';
        hash *= 16777619u;
    }

    snprintf(buffer, capacity, "fp-%08x", hash);
}


static int parse_collector_url(const char *raw_url, CollectorUrl *collector_url) {
    const char *url = raw_url;
    const char *host_start;
    const char *path_start;
    const char *port_start;
    size_t host_length;

    if (url == NULL || url[0] == '\0') {
        url = DEFAULT_COLLECTOR_URL;
    }

    if (strncmp(url, "http://", 7) != 0) {
        return -1;
    }

    host_start = url + 7;
    path_start = strchr(host_start, '/');
    if (path_start == NULL) {
        path_start = url + strlen(url);
    }

    port_start = strchr(host_start, ':');
    if (port_start != NULL && port_start < path_start) {
        host_length = (size_t) (port_start - host_start);
        snprintf(collector_url->host, sizeof(collector_url->host), "%.*s", (int) host_length, host_start);
        collector_url->port = atoi(port_start + 1);
    } else {
        host_length = (size_t) (path_start - host_start);
        snprintf(collector_url->host, sizeof(collector_url->host), "%.*s", (int) host_length, host_start);
        collector_url->port = 80;
    }

    if (*path_start == '\0') {
        safe_copy(collector_url->path, sizeof(collector_url->path), "/event");
    } else {
        safe_copy(collector_url->path, sizeof(collector_url->path), path_start);
    }

    if (collector_url->host[0] == '\0' || collector_url->port <= 0) {
        return -1;
    }

    return 0;
}


static int open_connection(const CollectorUrl *collector_url) {
    char port_string[16];
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    struct addrinfo *entry;
    int socket_fd = -1;
    struct timeval timeout;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    snprintf(port_string, sizeof(port_string), "%d", collector_url->port);
    if (getaddrinfo(collector_url->host, port_string, &hints, &result) != 0) {
        return -1;
    }

    for (entry = result; entry != NULL; entry = entry->ai_next) {
        socket_fd = socket(entry->ai_family, entry->ai_socktype, entry->ai_protocol);
        if (socket_fd < 0) {
            continue;
        }

        timeout.tv_sec = 2;
        timeout.tv_usec = 0;
        setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

        if (connect(socket_fd, entry->ai_addr, entry->ai_addrlen) == 0) {
            break;
        }

        close(socket_fd);
        socket_fd = -1;
    }

    freeaddrinfo(result);
    return socket_fd;
}


static int send_all(int socket_fd, const char *buffer, size_t length) {
    size_t total_sent = 0;

    while (total_sent < length) {
        ssize_t sent = send(socket_fd, buffer + total_sent, length - total_sent, 0);
        if (sent <= 0) {
            return -1;
        }
        total_sent += (size_t) sent;
    }

    return 0;
}


static int dispatch_payload(const DecoyConfig *config, const char *path_override, const char *payload, int payload_length) {
    CollectorUrl collector_url;
    char ingest_header[256];
    char http_request[8192];
    char response_buffer[256];
    int socket_fd = -1;
    int request_length;
    int attempt;

    if (parse_collector_url(config->collector_url, &collector_url) != 0) {
        fprintf(stderr, "collector url is invalid: %s\n", config->collector_url);
        return -1;
    }

    if (path_override != NULL && path_override[0] != '\0') {
        safe_copy(collector_url.path, sizeof(collector_url.path), path_override);
    }

    ingest_header[0] = '\0';
    if (config->collector_token[0] != '\0') {
        snprintf(ingest_header, sizeof(ingest_header), "X-Ingest-Key: %s\r\n", config->collector_token);
    }

    request_length = snprintf(
        http_request,
        sizeof(http_request),
        "POST %s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "User-Agent: unikernel-decoy/%s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "%s"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        collector_url.path,
        collector_url.host,
        collector_url.port,
        config->decoy_version,
        payload_length,
        ingest_header,
        payload
    );

    if (request_length < 0 || (size_t) request_length >= sizeof(http_request)) {
        fprintf(stderr, "collector request was truncated\n");
        return -1;
    }

    for (attempt = 1; attempt <= 3; attempt++) {
        socket_fd = open_connection(&collector_url);
        if (socket_fd < 0) {
            fprintf(stderr, "failed to connect to collector at %s (attempt %d)\n", config->collector_url, attempt);
        } else if (send_all(socket_fd, http_request, (size_t) request_length) == 0) {
            recv(socket_fd, response_buffer, sizeof(response_buffer) - 1, 0);
            close(socket_fd);
            return 0;
        } else {
            fprintf(stderr, "failed to send payload to collector (attempt %d)\n", attempt);
            close(socket_fd);
        }

        {
            struct timespec pause;
            pause.tv_sec = 0;
            pause.tv_nsec = (long) attempt * 200000000L;
            nanosleep(&pause, NULL);
        }
    }

    return -1;
}


int send_event_to_collector(
    const DecoyConfig *config,
    const HttpRequest *request,
    const char *source_ip,
    int response_status_code,
    int latency_ms
) {
    char event_id[96];
    char timestamp[32];
    char request_fingerprint[64];
    char escaped_decoy_id[MAX_HOSTNAME_LENGTH * 2];
    char escaped_profile[MAX_PROFILE_LENGTH * 2];
    char escaped_source_ip[MAX_HOSTNAME_LENGTH * 2];
    char escaped_method[MAX_METHOD_LENGTH * 2];
    char escaped_path[MAX_PATH_LENGTH * 2];
    char escaped_user_agent[MAX_USER_AGENT_LENGTH * 2];
    char escaped_username[MAX_FIELD_LENGTH * 2];
    char escaped_password[MAX_FIELD_LENGTH * 2];
    char escaped_edge_node_id[MAX_HOSTNAME_LENGTH * 2];
    char escaped_decoy_version[MAX_PROFILE_LENGTH * 2];
    char escaped_public_endpoint[MAX_ENDPOINT_LENGTH * 2];
    char escaped_site[MAX_HOSTNAME_LENGTH * 2];
    char escaped_environment[MAX_ENVIRONMENT_LENGTH * 2];
    char escaped_coverage_role[MAX_LABEL_LENGTH * 2];
    char tags_json[1024];
    char headers_subset_json[512];
    char payload[6144];
    int payload_length;

    build_event_id(event_id, sizeof(event_id), "evt");
    current_timestamp(timestamp, sizeof(timestamp));
    build_request_fingerprint(request, request_fingerprint, sizeof(request_fingerprint));
    escape_json(config->decoy_id, escaped_decoy_id, sizeof(escaped_decoy_id));
    escape_json(config->profile, escaped_profile, sizeof(escaped_profile));
    escape_json(source_ip != NULL ? source_ip : "unknown", escaped_source_ip, sizeof(escaped_source_ip));
    escape_json(request->method, escaped_method, sizeof(escaped_method));
    escape_json(request->path, escaped_path, sizeof(escaped_path));
    escape_json(request->user_agent, escaped_user_agent, sizeof(escaped_user_agent));
    escape_json(request->username, escaped_username, sizeof(escaped_username));
    escape_json(request->password, escaped_password, sizeof(escaped_password));
    escape_json(config->edge_node_id, escaped_edge_node_id, sizeof(escaped_edge_node_id));
    escape_json(config->decoy_version, escaped_decoy_version, sizeof(escaped_decoy_version));
    escape_json(config->public_endpoint, escaped_public_endpoint, sizeof(escaped_public_endpoint));
    escape_json(config->site, escaped_site, sizeof(escaped_site));
    escape_json(config->environment, escaped_environment, sizeof(escaped_environment));
    escape_json(config->coverage_role, escaped_coverage_role, sizeof(escaped_coverage_role));
    build_tags_json(request, tags_json, sizeof(tags_json));
    build_headers_subset_json(request, headers_subset_json, sizeof(headers_subset_json));

    payload_length = snprintf(
        payload,
        sizeof(payload),
        "{"
        "\"event_id\":\"%s\","
        "\"ts\":\"%s\","
        "\"decoy_id\":\"%s\","
        "\"profile\":\"%s\","
        "\"src_ip\":\"%s\","
        "\"method\":\"%s\","
        "\"path\":\"%s\","
        "\"user_agent\":\"%s\","
        "\"username\":\"%s\","
        "\"password\":\"%s\","
        "\"suspicious\":%s,"
        "\"tags\":%s,"
        "\"normalized_tags\":%s,"
        "\"collector_version\":\"%s\","
        "\"edge_node_id\":\"%s\","
        "\"decoy_version\":\"%s\","
        "\"status_code\":%d,"
        "\"latency_ms\":%d,"
        "\"headers_subset\":%s,"
        "\"public_endpoint\":\"%s\","
        "\"request_fingerprint\":\"%s\","
        "\"event_class\":\"%s\","
        "\"site\":\"%s\","
        "\"environment\":\"%s\","
        "\"coverage_role\":\"%s\""
        "}",
        event_id,
        timestamp,
        escaped_decoy_id,
        escaped_profile,
        escaped_source_ip,
        escaped_method,
        escaped_path,
        escaped_user_agent,
        escaped_username,
        escaped_password,
        request->suspicious ? "true" : "false",
        tags_json,
        tags_json,
        "decoy-runtime/0.2.0",
        escaped_edge_node_id,
        escaped_decoy_version,
        response_status_code,
        latency_ms,
        headers_subset_json,
        escaped_public_endpoint,
        request_fingerprint,
        event_class_from_request(request),
        escaped_site,
        escaped_environment,
        escaped_coverage_role
    );

    if (payload_length < 0 || (size_t) payload_length >= sizeof(payload)) {
        fprintf(stderr, "event payload was truncated\n");
        return -1;
    }

    return dispatch_payload(config, NULL, payload, payload_length);
}


int send_heartbeat_to_collector(
    const DecoyConfig *config,
    long uptime_seconds,
    int relay_queue_backlog
) {
    char timestamp[32];
    char escaped_decoy_id[MAX_HOSTNAME_LENGTH * 2];
    char escaped_edge_node_id[MAX_HOSTNAME_LENGTH * 2];
    char escaped_decoy_version[MAX_PROFILE_LENGTH * 2];
    char escaped_public_endpoint[MAX_ENDPOINT_LENGTH * 2];
    char escaped_profile[MAX_PROFILE_LENGTH * 2];
    char escaped_site[MAX_HOSTNAME_LENGTH * 2];
    char escaped_environment[MAX_ENVIRONMENT_LENGTH * 2];
    char escaped_coverage_role[MAX_LABEL_LENGTH * 2];
    char payload[2048];
    int payload_length;

    current_timestamp(timestamp, sizeof(timestamp));
    escape_json(config->decoy_id, escaped_decoy_id, sizeof(escaped_decoy_id));
    escape_json(config->edge_node_id, escaped_edge_node_id, sizeof(escaped_edge_node_id));
    escape_json(config->decoy_version, escaped_decoy_version, sizeof(escaped_decoy_version));
    escape_json(config->public_endpoint, escaped_public_endpoint, sizeof(escaped_public_endpoint));
    escape_json(config->profile, escaped_profile, sizeof(escaped_profile));
    escape_json(config->site, escaped_site, sizeof(escaped_site));
    escape_json(config->environment, escaped_environment, sizeof(escaped_environment));
    escape_json(config->coverage_role, escaped_coverage_role, sizeof(escaped_coverage_role));

    payload_length = snprintf(
        payload,
        sizeof(payload),
        "{"
        "\"ts\":\"%s\","
        "\"decoy_id\":\"%s\","
        "\"edge_node_id\":\"%s\","
        "\"decoy_version\":\"%s\","
        "\"public_endpoint\":\"%s\","
        "\"profile\":\"%s\","
        "\"uptime_seconds\":%ld,"
        "\"listen_port\":%d,"
        "\"site\":\"%s\","
        "\"environment\":\"%s\","
        "\"coverage_role\":\"%s\","
        "\"runtime_state\":\"running\","
        "\"relay_queue_backlog\":%d,"
        "\"relay_health\":\"healthy\""
        "}",
        timestamp,
        escaped_decoy_id,
        escaped_edge_node_id,
        escaped_decoy_version,
        escaped_public_endpoint,
        escaped_profile,
        uptime_seconds,
        config->listen_port,
        escaped_site,
        escaped_environment,
        escaped_coverage_role,
        relay_queue_backlog
    );

    if (payload_length < 0 || (size_t) payload_length >= sizeof(payload)) {
        fprintf(stderr, "heartbeat payload was truncated\n");
        return -1;
    }

    return dispatch_payload(config, "/heartbeat", payload, payload_length);
}
