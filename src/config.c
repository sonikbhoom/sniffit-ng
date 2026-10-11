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

static bool parse_port_number(const char *text, uint16_t *port)
{
    unsigned int value = 0U;

    if (text == NULL || text[0] == '\0' || port == NULL) {
        return false;
    }
    for (const char *digit = text; *digit != '\0'; ++digit) {
        if (!isdigit((unsigned char)*digit)) {
            return false;
        }
        value = value * 10U + (unsigned int)(*digit - '0');
        if (value > UINT16_MAX) {
            return false;
        }
    }
    if (value == 0U) {
        return false;
    }
    *port = (uint16_t)value;
    return true;
}

static bool parse_ui_priority(char *value, struct sn_app_config *config)
{
    char *entry = value;

    config->ui_priority_count = 0U;
    if (entry[0] == '\0') {
        return true;
    }
    for (;;) {
        char *comma = strchr(entry, ',');
        char *token;
        char *separator;
        struct sn_ui_priority_port priority = {0};

        if (comma != NULL) {
            *comma = '\0';
        }
        token = trim(entry);
        separator = strchr(token, '/');
        if (separator == NULL || strchr(separator + 1, '/') != NULL) {
            return false;
        }
        *separator = '\0';
        if (!parse_port_number(trim(token), &priority.port)) {
            return false;
        }
        {
            char *protocol = trim(separator + 1);
            if (strcmp(protocol, "tcp") == 0) {
                priority.protocol = 6U;
            } else if (strcmp(protocol, "udp") == 0) {
                priority.protocol = 17U;
            } else {
                return false;
            }
        }
        if (config->ui_priority_count >= SN_CONFIG_UI_PRIORITY_CAPACITY) {
            return false;
        }
        for (size_t index = 0U; index < config->ui_priority_count; ++index) {
            if (config->ui_priority_ports[index].protocol == priority.protocol &&
                config->ui_priority_ports[index].port == priority.port) {
                return false;
            }
        }
        config->ui_priority_ports[config->ui_priority_count++] = priority;
        if (comma == NULL) {
            return true;
        }
        entry = comma + 1;
    }
}

void sn_config_init(struct sn_app_config *config)
{
    if (config != NULL) {
        *config = (struct sn_app_config){0};
        config->ui_priority_ports[0] =
            (struct sn_ui_priority_port){.protocol = 6U, .port = 22U};
        config->ui_priority_ports[1] =
            (struct sn_ui_priority_port){.protocol = 6U, .port = 23U};
        config->ui_priority_count = 2U;
    }
}

bool sn_config_validate_inspection_options(
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
    if (config->full_decode && !config->full_decode_acknowledged) {
        set_error(error_buffer, error_buffer_size,
                  "full_decode requires the active sensitive-data acknowledgment comment",
                  0U);
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
    bool full_decode_setting_seen = false;
    bool external_address_setting_seen = false;
    bool raw_flows_setting_seen = false;
    bool tainted_extensions_setting_seen = false;
    bool ui_priority_setting_seen = false;
    bool decoder_setting_seen[SN_DECODER_MODULE_COUNT] = {false};

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
        if (strcmp(text, SN_CONFIG_FULL_DECODE_ACK_COMMENT) == 0) {
            config->full_decode_acknowledged = true;
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
            } else if (strcmp(key, "full_decode") == 0 &&
                       !full_decode_setting_seen) {
                full_decode_setting_seen = true;
                if (strcmp(value, "true") == 0) {
                    config->full_decode = true;
                } else if (strcmp(value, "false") == 0) {
                    config->full_decode = false;
                } else {
                    fclose(stream);
                    set_error(error_buffer, error_buffer_size,
                              "full_decode must be true or false", line_number);
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
            } else if (strcmp(key, "show_raw_flows") == 0 &&
                       !raw_flows_setting_seen) {
                raw_flows_setting_seen = true;
                if (strcmp(value, "true") == 0) {
                    config->show_raw_flows = true;
                } else if (strcmp(value, "false") == 0) {
                    config->show_raw_flows = false;
                } else {
                    fclose(stream);
                    set_error(error_buffer, error_buffer_size,
                              "show_raw_flows must be true or false", line_number);
                    return false;
                }
            } else if (strcmp(key, "tainted_extensions") == 0 &&
                       !tainted_extensions_setting_seen) {
                tainted_extensions_setting_seen = true;
                if (strcmp(value, "true") == 0) {
                    config->tainted_extensions = true;
                } else if (strcmp(value, "false") == 0) {
                    config->tainted_extensions = false;
                } else {
                    fclose(stream);
                    set_error(error_buffer, error_buffer_size,
                              "tainted_extensions must be true or false", line_number);
                    return false;
                }
            } else if (strcmp(key, "ui_priority") == 0 &&
                       !ui_priority_setting_seen) {
                ui_priority_setting_seen = true;
                if (!parse_ui_priority(value, config)) {
                    fclose(stream);
                    set_error(error_buffer, error_buffer_size,
                              "ui_priority must contain unique PORT/tcp or PORT/udp entries",
                              line_number);
                    return false;
                }
            } else {
                enum sn_decoder_module module;

                if (sn_decoder_module_from_name(key, &module)) {
                    if (decoder_setting_seen[module]) {
                        fclose(stream);
                        set_error(error_buffer, error_buffer_size,
                                  "unknown or duplicate configuration key", line_number);
                        return false;
                    }
                    decoder_setting_seen[module] = true;
                    if (strcmp(value, "raw") == 0) {
                        config->decoder_modes[module] = SN_DECODER_RAW;
                    } else if (strcmp(value, "simplified") == 0) {
                        config->decoder_modes[module] = SN_DECODER_SIMPLIFIED;
                    } else {
                        fclose(stream);
                        set_error(error_buffer, error_buffer_size,
                                  "decoder mode must be raw or simplified", line_number);
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
    }
    if (ferror(stream)) {
        fclose(stream);
        set_error(error_buffer, error_buffer_size, "error reading config file", line_number);
        return false;
    }
    fclose(stream);
    return sn_config_validate_inspection_options(config, error_buffer,
                                                 error_buffer_size);
}
