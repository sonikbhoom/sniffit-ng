#include "sniffit_ng/config.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#define CONFIG_LINE_CAPACITY 512U

static void set_error(char *buffer, size_t capacity, const char *message, size_t line)
{
    if (buffer != NULL && capacity > 0U) {
        if (line > 0U) {
            (void)snprintf(buffer, capacity, "line %zu: %s", line, message);
        } else {
            (void)snprintf(buffer, capacity, "%s", message);
        }
    }
}

static char *trim(char *text)
{
    char *end;

    while (isspace((unsigned char)*text)) {
        ++text;
    }
    end = text + strlen(text);
    while (end > text && isspace((unsigned char)end[-1])) {
        --end;
    }
    *end = '\0';
    return text;
}

void sn_config_init(struct sn_app_config *config)
{
    if (config != NULL) {
        *config = (struct sn_app_config){0};
    }
}

bool sn_config_validate_payload_inspection(
    const struct sn_app_config *config,
    char *error_buffer,
    size_t error_buffer_size)
{
    if (config == NULL) {
        set_error(error_buffer, error_buffer_size, "missing configuration", 0U);
        return false;
    }
    if (config->inspect_payloads && !config->payload_display_acknowledged) {
        set_error(error_buffer, error_buffer_size,
                  "inspect_payloads requires the active ethical acknowledgment comment", 0U);
        return false;
    }
    if (error_buffer != NULL && error_buffer_size > 0U) {
        error_buffer[0] = '\0';
    }
    return true;
}

bool sn_config_load_file(const char *path,
                         struct sn_app_config *config,
                         char *error_buffer,
                         size_t error_buffer_size)
{
    FILE *stream;
    char line[CONFIG_LINE_CAPACITY];
    size_t line_number = 0U;
    bool inspect_setting_seen = false;
    bool external_address_setting_seen = false;

    if (path == NULL || path[0] == '\0' || config == NULL) {
        set_error(error_buffer, error_buffer_size, "invalid config path or output", 0U);
        return false;
    }
    stream = fopen(path, "r");
    if (stream == NULL) {
        set_error(error_buffer, error_buffer_size, "could not open config file", 0U);
        return false;
    }

    sn_config_init(config);
    while (fgets(line, sizeof(line), stream) != NULL) {
        char *text;
        char *equals;
        size_t length;
        ++line_number;
        length = strlen(line);
        if (length > 0U && line[length - 1U] != '\n' && !feof(stream)) {
            fclose(stream);
            set_error(error_buffer, error_buffer_size, "line exceeds 511 characters", line_number);
            return false;
        }
        text = trim(line);
        if (text[0] == '\0') {
            continue;
        }
        if (strcmp(text, SN_CONFIG_PAYLOAD_ACK_COMMENT) == 0) {
            config->payload_display_acknowledged = true;
            continue;
        }
        if (text[0] == '#') {
            continue;
        }
        equals = strchr(text, '=');
        if (equals == NULL) {
            fclose(stream);
            set_error(error_buffer, error_buffer_size, "expected key = value", line_number);
            return false;
        }
        *equals = '\0';
        {
            char *key = trim(text);
            char *value = trim(equals + 1);
            if (strcmp(key, "inspect_payloads") == 0 && !inspect_setting_seen) {
                inspect_setting_seen = true;
                if (strcmp(value, "true") == 0) {
                    config->inspect_payloads = true;
                } else if (strcmp(value, "false") == 0) {
                    config->inspect_payloads = false;
                } else {
                    fclose(stream);
                    set_error(error_buffer, error_buffer_size,
                              "inspect_payloads must be true or false", line_number);
                    return false;
                }
            } else if (strcmp(key, "resolve_external_addr") == 0 &&
                       !external_address_setting_seen) {
                external_address_setting_seen = true;
                if (strcmp(value, "true") == 0) {
                    config->resolve_external_addr = true;
                } else if (strcmp(value, "false") == 0) {
                    config->resolve_external_addr = false;
                } else {
                    fclose(stream);
                    set_error(error_buffer, error_buffer_size,
                              "resolve_external_addr must be true or false", line_number);
                    return false;
                }
            } else {
                fclose(stream);
                set_error(error_buffer, error_buffer_size,
                          "unknown or duplicate configuration key", line_number);
                return false;
            }
        }
    }
    if (ferror(stream)) {
        fclose(stream);
        set_error(error_buffer, error_buffer_size, "error reading config file", line_number);
        return false;
    }
    fclose(stream);
    return sn_config_validate_payload_inspection(config, error_buffer, error_buffer_size);
}
