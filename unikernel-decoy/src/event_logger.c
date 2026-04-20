#define _POSIX_C_SOURCE 200112L

#include "config.h"

#include <errno.h>
#include <netdb.h>
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


int send_event_to_collector(
    const DecoyConfig *config,
    const HttpRequest *request,
    const char *source_ip
) {
    CollectorUrl collector_url;
    char timestamp[32];
    char escaped_decoy_id[MAX_HOSTNAME_LENGTH * 2];
    char escaped_profile[MAX_PROFILE_LENGTH * 2];
    char escaped_source_ip[MAX_HOSTNAME_LENGTH * 2];
    char escaped_method[MAX_METHOD_LENGTH * 2];
    char escaped_path[MAX_PATH_LENGTH * 2];
    char escaped_user_agent[MAX_USER_AGENT_LENGTH * 2];
    char escaped_username[MAX_FIELD_LENGTH * 2];
    char escaped_password[MAX_FIELD_LENGTH * 2];
    char tags_json[1024];
    char payload[4096];
    char http_request[6144];
    char response_buffer[256];
    int socket_fd;
    int payload_length;
    int request_length;

    if (parse_collector_url(config->collector_url, &collector_url) != 0) {
        fprintf(stderr, "collector url is invalid: %s\n", config->collector_url);
        return -1;
    }

    current_timestamp(timestamp, sizeof(timestamp));
    escape_json(config->decoy_id, escaped_decoy_id, sizeof(escaped_decoy_id));
    escape_json(config->profile, escaped_profile, sizeof(escaped_profile));
    escape_json(source_ip != NULL ? source_ip : "unknown", escaped_source_ip, sizeof(escaped_source_ip));
    escape_json(request->method, escaped_method, sizeof(escaped_method));
    escape_json(request->path, escaped_path, sizeof(escaped_path));
    escape_json(request->user_agent, escaped_user_agent, sizeof(escaped_user_agent));
    escape_json(request->username, escaped_username, sizeof(escaped_username));
    escape_json(request->password, escaped_password, sizeof(escaped_password));
    build_tags_json(request, tags_json, sizeof(tags_json));

    payload_length = snprintf(
        payload,
        sizeof(payload),
        "{"
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
        "\"tags\":%s"
        "}",
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
        tags_json
    );

    if (payload_length < 0 || (size_t) payload_length >= sizeof(payload)) {
        fprintf(stderr, "event payload was truncated\n");
        return -1;
    }

    request_length = snprintf(
        http_request,
        sizeof(http_request),
        "POST %s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "User-Agent: unikernel-decoy/1.0\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        collector_url.path,
        collector_url.host,
        collector_url.port,
        payload_length,
        payload
    );

    if (request_length < 0 || (size_t) request_length >= sizeof(http_request)) {
        fprintf(stderr, "collector request was truncated\n");
        return -1;
    }

    socket_fd = open_connection(&collector_url);
    if (socket_fd < 0) {
        fprintf(stderr, "failed to connect to collector at %s\n", config->collector_url);
        return -1;
    }

    if (send_all(socket_fd, http_request, (size_t) request_length) != 0) {
        fprintf(stderr, "failed to send event to collector\n");
        close(socket_fd);
        return -1;
    }

    recv(socket_fd, response_buffer, sizeof(response_buffer) - 1, 0);
    close(socket_fd);

    return 0;
}

