#define _POSIX_C_SOURCE 200112L

#include "config.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


typedef struct {
    const char *needle;
    const char *tag;
} SuspiciousRule;


static const SuspiciousRule SUSPICIOUS_RULES[] = {
    {"union select", "sqli_probe"},
    {"<script>", "xss_probe"},
    {"../", "path_traversal_probe"},
    {"wget", "internet_recon"},
    {"curl", "internet_recon"},
    {"cmd=", "internet_recon"},
    {".env", "sensitive_path_discovery"},
    {"phpmyadmin", "admin_panel_enumeration"},
};


static void zero_request(HttpRequest *request) {
    memset(request, 0, sizeof(*request));
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


static int contains_case_insensitive(const char *haystack, const char *needle) {
    size_t haystack_length;
    size_t needle_length;
    size_t i;
    size_t j;

    if (haystack == NULL || needle == NULL) {
        return 0;
    }

    haystack_length = strlen(haystack);
    needle_length = strlen(needle);
    if (needle_length == 0 || haystack_length < needle_length) {
        return 0;
    }

    for (i = 0; i + needle_length <= haystack_length; i++) {
        for (j = 0; j < needle_length; j++) {
            if (tolower((unsigned char) haystack[i + j]) !=
                tolower((unsigned char) needle[j])) {
                break;
            }
        }

        if (j == needle_length) {
            return 1;
        }
    }

    return 0;
}


static void add_tag(HttpRequest *request, const char *tag) {
    int i;

    if (tag == NULL || tag[0] == '\0') {
        return;
    }

    for (i = 0; i < request->tag_count; i++) {
        if (strcmp(request->tags[i], tag) == 0) {
            return;
        }
    }

    if (request->tag_count >= MAX_TAG_COUNT) {
        return;
    }

    safe_copy(request->tags[request->tag_count], MAX_TAG_LENGTH, tag);
    request->tag_count += 1;
}


static void trim_query_string(char *path) {
    char *question = strchr(path, '?');
    if (question != NULL) {
        *question = '\0';
    }
}


static void extract_header_value(
    const char *raw_request,
    const char *header_name,
    char *destination,
    size_t capacity
) {
    const char *cursor = raw_request;
    size_t header_name_length = strlen(header_name);

    destination[0] = '\0';

    while (*cursor != '\0') {
        const char *line_end = strstr(cursor, "\r\n");
        size_t line_length;
        size_t i;
        int match = 1;

        if (line_end == NULL || line_end == cursor) {
            break;
        }

        line_length = (size_t) (line_end - cursor);
        if (line_length > header_name_length + 1) {
            for (i = 0; i < header_name_length; i++) {
                if (tolower((unsigned char) cursor[i]) !=
                    tolower((unsigned char) header_name[i])) {
                    match = 0;
                    break;
                }
            }

            if (match && cursor[header_name_length] == ':') {
                const char *value = cursor + header_name_length + 1;
                while (*value == ' ') {
                    value++;
                }

                snprintf(destination, capacity, "%.*s", (int) (line_end - value), value);
                return;
            }
        }

        cursor = line_end + 2;
    }
}


static char from_hex(char value) {
    if (value >= '0' && value <= '9') {
        return (char) (value - '0');
    }
    if (value >= 'a' && value <= 'f') {
        return (char) (value - 'a' + 10);
    }
    if (value >= 'A' && value <= 'F') {
        return (char) (value - 'A' + 10);
    }
    return 0;
}


static void url_decode_into(char *destination, size_t capacity, const char *source) {
    size_t out_index = 0;

    if (capacity == 0) {
        return;
    }

    while (*source != '\0' && out_index + 1 < capacity) {
        if (*source == '+' ) {
            destination[out_index++] = ' ';
            source++;
            continue;
        }

        if (*source == '%' &&
            isxdigit((unsigned char) source[1]) &&
            isxdigit((unsigned char) source[2])) {
            destination[out_index++] = (char)
                ((from_hex(source[1]) << 4) | from_hex(source[2]));
            source += 3;
            continue;
        }

        destination[out_index++] = *source;
        source++;
    }

    destination[out_index] = '\0';
}


static void extract_form_field(
    const char *body,
    const char *field_name,
    char *destination,
    size_t capacity
) {
    char pattern[64];
    const char *field;
    const char *end;
    char encoded[MAX_FIELD_LENGTH * 3];

    snprintf(pattern, sizeof(pattern), "%s=", field_name);
    field = strstr(body, pattern);
    if (field == NULL) {
        destination[0] = '\0';
        return;
    }

    field += strlen(pattern);
    end = strchr(field, '&');
    if (end == NULL) {
        end = field + strlen(field);
    }

    snprintf(encoded, sizeof(encoded), "%.*s", (int) (end - field), field);
    url_decode_into(destination, capacity, encoded);
}


static int is_known_path(const char *path) {
    return strcmp(path, "/") == 0 ||
        strcmp(path, "/login") == 0 ||
        strcmp(path, "/admin") == 0 ||
        strcmp(path, "/config") == 0 ||
        strcmp(path, "/status") == 0;
}


static void analyze_request(HttpRequest *request) {
    size_t i;

    if (strcmp(request->method, "POST") == 0 && strcmp(request->path, "/login") == 0) {
        add_tag(request, "credential_bruteforce");
        if (request->username[0] != '\0' || request->password[0] != '\0') {
            add_tag(request, "credential_attempt");
        }
    }

    if (strcmp(request->path, "/admin") == 0 ||
        strcmp(request->path, "/config") == 0 ||
        strcmp(request->path, "/status") == 0) {
        add_tag(request, "admin_panel_enumeration");
        add_tag(request, "sensitive_path_discovery");
    }

    if (!is_known_path(request->path)) {
        request->suspicious = 1;
        add_tag(request, "internet_recon");
    }

    for (i = 0; i < sizeof(SUSPICIOUS_RULES) / sizeof(SUSPICIOUS_RULES[0]); i++) {
        if (contains_case_insensitive(request->path, SUSPICIOUS_RULES[i].needle) ||
            contains_case_insensitive(request->body, SUSPICIOUS_RULES[i].needle) ||
            contains_case_insensitive(request->username, SUSPICIOUS_RULES[i].needle) ||
            contains_case_insensitive(request->password, SUSPICIOUS_RULES[i].needle)) {
            request->suspicious = 1;
            add_tag(request, SUSPICIOUS_RULES[i].tag);
        }
    }
}


int parse_http_request(const char *raw_request, HttpRequest *request) {
    const char *line_end;
    const char *body_start;
    char request_line[512];

    if (raw_request == NULL || request == NULL) {
        return -1;
    }

    zero_request(request);

    line_end = strstr(raw_request, "\r\n");
    if (line_end == NULL) {
        return -1;
    }

    snprintf(request_line, sizeof(request_line), "%.*s", (int) (line_end - raw_request), raw_request);
    if (sscanf(request_line, "%7s %255s", request->method, request->path) != 2) {
        return -1;
    }

    trim_query_string(request->path);
    extract_header_value(raw_request, "User-Agent", request->user_agent, sizeof(request->user_agent));
    extract_header_value(raw_request, "Host", request->host, sizeof(request->host));
    extract_header_value(raw_request, "Accept", request->accept, sizeof(request->accept));

    body_start = strstr(raw_request, "\r\n\r\n");
    if (body_start != NULL) {
        body_start += 4;
        safe_copy(request->body, sizeof(request->body), body_start);
        request->body_length = strlen(request->body);
    }

    if (strcmp(request->method, "POST") == 0) {
        extract_form_field(request->body, "username", request->username, sizeof(request->username));
        extract_form_field(request->body, "password", request->password, sizeof(request->password));
    }

    analyze_request(request);
    return 0;
}
