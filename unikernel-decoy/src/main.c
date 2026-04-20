#define _POSIX_C_SOURCE 200112L

#include "config.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>


static volatile sig_atomic_t keep_running = 1;


static void handle_signal(int signal_number) {
    (void) signal_number;
    keep_running = 0;
}


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


static const DecoyProfile *default_profile_for_name(const char *profile_name) {
    if (strcmp(profile_name, "nvr") == 0) {
        return get_nvr_profile();
    }

    if (strcmp(profile_name, "admin") == 0) {
        return get_admin_profile();
    }

    return get_router_profile();
}


static void load_runtime_config(DecoyConfig *config) {
    const char *value;
    const DecoyProfile *profile;

    safe_copy(config->profile, sizeof(config->profile), DEFAULT_PROFILE);
    value = getenv("DECOY_PROFILE");
    if (value != NULL && value[0] != '\0') {
        safe_copy(config->profile, sizeof(config->profile), value);
    }

    profile = default_profile_for_name(config->profile);

    safe_copy(config->decoy_id, sizeof(config->decoy_id), DEFAULT_DECOY_ID);
    value = getenv("DECOY_ID");
    if (value != NULL && value[0] != '\0') {
        safe_copy(config->decoy_id, sizeof(config->decoy_id), value);
    }

    safe_copy(config->title, sizeof(config->title), profile->default_title);
    value = getenv("DECOY_TITLE");
    if (value != NULL && value[0] != '\0') {
        safe_copy(config->title, sizeof(config->title), value);
    }

    safe_copy(config->hostname, sizeof(config->hostname), DEFAULT_HOSTNAME);
    value = getenv("DECOY_HOSTNAME");
    if (value != NULL && value[0] != '\0') {
        safe_copy(config->hostname, sizeof(config->hostname), value);
    }

    safe_copy(config->label, sizeof(config->label), profile->service_label);
    value = getenv("DECOY_LABEL");
    if (value != NULL && value[0] != '\0') {
        safe_copy(config->label, sizeof(config->label), value);
    }

    safe_copy(config->collector_url, sizeof(config->collector_url), DEFAULT_COLLECTOR_URL);
    value = getenv("COLLECTOR_URL");
    if (value != NULL && value[0] != '\0') {
        safe_copy(config->collector_url, sizeof(config->collector_url), value);
    }

    safe_copy(config->asset_dir, sizeof(config->asset_dir), DEFAULT_ASSET_DIR);
    value = getenv("ASSET_DIR");
    if (value != NULL && value[0] != '\0') {
        safe_copy(config->asset_dir, sizeof(config->asset_dir), value);
    }

    config->listen_port = DEFAULT_LISTEN_PORT;
    value = getenv("HTTP_PORT");
    if (value != NULL && value[0] != '\0') {
        config->listen_port = atoi(value);
    }
    if (config->listen_port <= 0) {
        config->listen_port = DEFAULT_LISTEN_PORT;
    }
}


static int starts_with_case_insensitive(const char *text, const char *prefix) {
    while (*text != '\0' && *prefix != '\0') {
        if (tolower((unsigned char) *text) != tolower((unsigned char) *prefix)) {
            return 0;
        }
        text++;
        prefix++;
    }

    return *prefix == '\0';
}


static size_t content_length_from_headers(const char *request_buffer) {
    const char *cursor = request_buffer;

    while (*cursor != '\0') {
        const char *line_end = strstr(cursor, "\r\n");
        if (line_end == NULL || line_end == cursor) {
            break;
        }

        if (starts_with_case_insensitive(cursor, "Content-Length:")) {
            const char *value = cursor + strlen("Content-Length:");
            while (*value == ' ') {
                value++;
            }
            return (size_t) strtoul(value, NULL, 10);
        }

        cursor = line_end + 2;
    }

    return 0;
}


static ssize_t read_http_request(int client_fd, char *buffer, size_t capacity) {
    size_t total = 0;

    while (total + 1 < capacity) {
        ssize_t received = recv(client_fd, buffer + total, capacity - total - 1, 0);
        const char *header_end;

        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }

        if (received == 0) {
            break;
        }

        total += (size_t) received;
        buffer[total] = '\0';

        header_end = strstr(buffer, "\r\n\r\n");
        if (header_end != NULL) {
            size_t header_length = (size_t) ((header_end + 4) - buffer);
            size_t content_length = content_length_from_headers(buffer);
            if (total >= header_length + content_length) {
                break;
            }
        }
    }

    return (ssize_t) total;
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


static void handle_client(int client_fd, const struct sockaddr_in *client_address, const DecoyConfig *config) {
    char raw_request[8192];
    char response[16384];
    char source_ip[INET_ADDRSTRLEN];
    HttpRequest request;
    ssize_t request_length;
    size_t response_length;

    request_length = read_http_request(client_fd, raw_request, sizeof(raw_request));
    if (request_length <= 0) {
        return;
    }

    if (parse_http_request(raw_request, &request) != 0) {
        const char *bad_request =
            "HTTP/1.1 400 Bad Request\r\n"
            "Content-Length: 11\r\n"
            "Connection: close\r\n"
            "\r\n"
            "bad request";
        send_all(client_fd, bad_request, strlen(bad_request));
        return;
    }

    if (inet_ntop(AF_INET, &(client_address->sin_addr), source_ip, sizeof(source_ip)) == NULL) {
        safe_copy(source_ip, sizeof(source_ip), "unknown");
    }

    response_length = build_http_response(config, &request, response, sizeof(response));
    send_all(client_fd, response, response_length);
    send_event_to_collector(config, &request, source_ip);

    printf("[%s] %s %s from %s\n", config->hostname, request.method, request.path, source_ip);
    fflush(stdout);
}


int main(void) {
    DecoyConfig config;
    int server_fd;
    int reuse_address = 1;
    struct sockaddr_in server_address;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    signal(SIGPIPE, SIG_IGN);

    load_runtime_config(&config);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return 1;
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse_address, sizeof(reuse_address)) != 0) {
        perror("setsockopt");
        close(server_fd);
        return 1;
    }

    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);
    server_address.sin_port = htons((unsigned short) config.listen_port);

    if (bind(server_fd, (struct sockaddr *) &server_address, sizeof(server_address)) != 0) {
        perror("bind");
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 32) != 0) {
        perror("listen");
        close(server_fd);
        return 1;
    }

    printf(
        "decoy started: profile=%s id=%s title=%s port=%d collector=%s\n",
        config.profile,
        config.decoy_id,
        config.title,
        config.listen_port,
        config.collector_url
    );
    fflush(stdout);

    while (keep_running) {
        struct sockaddr_in client_address;
        socklen_t client_length = sizeof(client_address);
        int client_fd = accept(server_fd, (struct sockaddr *) &client_address, &client_length);

        if (client_fd < 0) {
            if (errno == EINTR) {
                continue;
            }

            perror("accept");
            break;
        }

        handle_client(client_fd, &client_address, &config);
        close(client_fd);
    }

    close(server_fd);
    return 0;
}

