#define _POSIX_C_SOURCE 200112L

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


static const char *status_text(int status_code) {
    switch (status_code) {
        case 200:
            return "OK";
        case 401:
            return "Unauthorized";
        case 403:
            return "Forbidden";
        case 404:
            return "Not Found";
        case 405:
            return "Method Not Allowed";
        default:
            return "OK";
    }
}


static const DecoyProfile *resolve_profile(const DecoyConfig *config) {
    if (strcmp(config->profile, "nvr") == 0) {
        return get_nvr_profile();
    }

    if (strcmp(config->profile, "admin") == 0) {
        return get_admin_profile();
    }

    return get_router_profile();
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


static int load_template_file(const char *path, char *buffer, size_t capacity) {
    FILE *file;
    size_t bytes_read;

    file = fopen(path, "rb");
    if (file == NULL) {
        return -1;
    }

    bytes_read = fread(buffer, 1, capacity - 1, file);
    fclose(file);

    buffer[bytes_read] = '\0';
    return 0;
}


static void render_with_placeholders(
    const char *template_text,
    const DecoyConfig *config,
    const DecoyProfile *profile,
    const char *notice,
    char *buffer,
    size_t capacity
) {
    const char *cursor = template_text;
    size_t length = 0;

    buffer[0] = '\0';

    while (*cursor != '\0' && length + 1 < capacity) {
        if (strncmp(cursor, "{{TITLE}}", 9) == 0) {
            append_text(buffer, capacity, &length, config->title);
            cursor += 9;
            continue;
        }

        if (strncmp(cursor, "{{HOSTNAME}}", 12) == 0) {
            append_text(buffer, capacity, &length, config->hostname);
            cursor += 12;
            continue;
        }

        if (strncmp(cursor, "{{BANNER}}", 10) == 0) {
            append_text(buffer, capacity, &length, profile->banner);
            cursor += 10;
            continue;
        }

        if (strncmp(cursor, "{{SERVICE_LABEL}}", 17) == 0) {
            append_text(buffer, capacity, &length, config->label);
            cursor += 17;
            continue;
        }

        if (strncmp(cursor, "{{NOTICE}}", 10) == 0) {
            append_text(buffer, capacity, &length, notice);
            cursor += 10;
            continue;
        }

        buffer[length++] = *cursor++;
        buffer[length] = '\0';
    }
}


static const char *login_template_name(const DecoyConfig *config) {
    if (strcmp(config->profile, "nvr") == 0) {
        return "nvr_login.html";
    }

    if (strcmp(config->profile, "admin") == 0) {
        return "admin_login.html";
    }

    return "router_login.html";
}


static void build_login_page(
    const DecoyConfig *config,
    const DecoyProfile *profile,
    const char *notice,
    char *body,
    size_t body_capacity
) {
    char template_path[512];
    char template_text[8192];
    const char *fallback =
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<title>{{TITLE}}</title></head><body><main><h1>{{BANNER}}</h1>"
        "{{NOTICE}}<p>{{SERVICE_LABEL}} :: {{HOSTNAME}}</p>"
        "<form method='post' action='/login'>"
        "<label>Username <input name='username' type='text'></label><br><br>"
        "<label>Password <input name='password' type='password'></label><br><br>"
        "<button type='submit'>Sign in</button></form></main></body></html>";

    snprintf(
        template_path,
        sizeof(template_path),
        "%s/%s",
        config->asset_dir,
        login_template_name(config)
    );

    if (load_template_file(template_path, template_text, sizeof(template_text)) != 0) {
        snprintf(template_text, sizeof(template_text), "%s", fallback);
    }

    render_with_placeholders(template_text, config, profile, notice, body, body_capacity);
}


static void build_shell_page(
    const DecoyConfig *config,
    const DecoyProfile *profile,
    const char *page_title,
    const char *heading,
    const char *body_html,
    char *body,
    size_t body_capacity
) {
    snprintf(
        body,
        body_capacity,
        "<!doctype html>"
        "<html lang='en'>"
        "<head>"
        "<meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<title>%s</title>"
        "<style>"
        "body{margin:0;font-family:Arial,sans-serif;background:linear-gradient(180deg,#eef3f1,#dce6e2);color:#17221c;}"
        "main{max-width:560px;margin:48px auto;background:#ffffff;border:1px solid #ced8d2;border-radius:18px;padding:28px;"
        "box-shadow:0 12px 28px rgba(23,34,28,0.08);}"
        ".meta{color:#5b6b62;font-size:0.95rem;margin-bottom:8px;}"
        "a{color:#0c6f5a;}"
        "</style>"
        "</head>"
        "<body><main><div class='meta'>%s :: %s</div><h1>%s</h1>%s</main></body></html>",
        page_title,
        profile->name,
        config->hostname,
        heading,
        body_html
    );
}


size_t build_http_response(
    const DecoyConfig *config,
    const HttpRequest *request,
    char *response,
    size_t response_capacity,
    int *status_code_out
) {
    const DecoyProfile *profile = resolve_profile(config);
    char body[12288];
    int status_code = 200;
    int body_length;
    const char *notice = "";

    if (strcmp(request->path, "/") == 0 && strcmp(request->method, "GET") == 0) {
        char content[4096];
        snprintf(
            content,
            sizeof(content),
            "<p>%s is online as <strong>%s</strong>.</p>"
            "<p>%s</p>"
            "<p><a href='/login'>Open login portal</a></p>",
            config->title,
            config->hostname,
            profile->status_message
        );
        build_shell_page(config, profile, config->title, profile->banner, content, body, sizeof(body));
    } else if (strcmp(request->path, "/login") == 0 && strcmp(request->method, "GET") == 0) {
        build_login_page(config, profile, notice, body, sizeof(body));
    } else if (strcmp(request->path, "/login") == 0 && strcmp(request->method, "POST") == 0) {
        status_code = 401;
        notice = "<p style='color:#8c2f1d;'><strong>Authentication failed.</strong> Audit trail has been updated.</p>";
        build_login_page(config, profile, notice, body, sizeof(body));
    } else if (strcmp(request->path, "/admin") == 0 && strcmp(request->method, "GET") == 0) {
        status_code = 403;
        build_shell_page(
            config,
            profile,
            "Administrative Console",
            "Administrative Console",
            profile->admin_message,
            body,
            sizeof(body)
        );
    } else if (strcmp(request->path, "/config") == 0 && strcmp(request->method, "GET") == 0) {
        status_code = 403;
        build_shell_page(
            config,
            profile,
            "Configuration Export",
            "Configuration Export",
            profile->config_message,
            body,
            sizeof(body)
        );
    } else if (strcmp(request->path, "/status") == 0 && strcmp(request->method, "GET") == 0) {
        build_shell_page(
            config,
            profile,
            "System Status",
            "System Status",
            profile->status_message,
            body,
            sizeof(body)
        );
    } else if (strcmp(request->method, "GET") != 0 && strcmp(request->method, "POST") != 0) {
        status_code = 405;
        build_shell_page(
            config,
            profile,
            "Method Not Allowed",
            "Request Rejected",
            "<p>The requested method is not available on this service.</p>",
            body,
            sizeof(body)
        );
    } else {
        status_code = 404;
        build_shell_page(
            config,
            profile,
            "Not Found",
            "Resource Not Found",
            "<p>The requested resource does not exist on this node.</p>",
            body,
            sizeof(body)
        );
    }

    body_length = (int) strlen(body);
    if (status_code_out != NULL) {
        *status_code_out = status_code;
    }
    {
        int written = snprintf(
        response,
        response_capacity,
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        status_code,
        status_text(status_code),
        body_length,
        body
        );

        if (written < 0) {
            return 0;
        }

        if ((size_t) written >= response_capacity) {
            return response_capacity > 0 ? response_capacity - 1 : 0;
        }

        return (size_t) written;
    }
}
