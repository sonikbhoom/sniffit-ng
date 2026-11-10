#include "sniffit_ng/arp_config.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum setting_type {
    SETTING_DIRECTORY, SETTING_BOOL, SETTING_NUMBER, SETTING_CIDR, SETTING_IP_LIST
};

struct setting {
    const char *name;
    enum setting_type type;
    size_t offset;
};

#define ROTATION_OFFSET(field) \
    (offsetof(struct sn_arp_config, rotation) + offsetof(struct sn_arp_rotation_config, field))
#define ANALYSIS_OFFSET(field) \
    (offsetof(struct sn_arp_config, analysis) + offsetof(struct sn_arp_analysis_config, field))

static const struct setting settings[] = {
    {"log_directory", SETTING_DIRECTORY, offsetof(struct sn_arp_config, log_directory)},
    {"packet_logging", SETTING_BOOL, ROTATION_OFFSET(packet_logging)},
    {"address_logging", SETTING_BOOL, ROTATION_OFFSET(address_logging)},
    {"packet_segment_bytes", SETTING_NUMBER, ROTATION_OFFSET(packet_segment_bytes)},
    {"address_segment_bytes", SETTING_NUMBER, ROTATION_OFFSET(address_segment_bytes)},
    {"rotate_daily", SETTING_BOOL, ROTATION_OFFSET(rotate_daily)},
    {"idle_seconds", SETTING_NUMBER, ROTATION_OFFSET(idle_seconds)},
    {"maximum_age_seconds", SETTING_NUMBER, ROTATION_OFFSET(maximum_age_seconds)},
    {"maximum_total_bytes", SETTING_NUMBER, ROTATION_OFFSET(maximum_total_bytes)},
    {"delete_old_segments", SETTING_BOOL, ROTATION_OFFSET(delete_old_segments)},
    {"local_network", SETTING_CIDR, ANALYSIS_OFFSET(local_known)},
    {"baseline_ips", SETTING_IP_LIST, ANALYSIS_OFFSET(baseline_ips)},
    {"talkative_requests_per_minute", SETTING_NUMBER, ANALYSIS_OFFSET(talkative_requests_per_minute)},
    {"sweep_targets", SETTING_NUMBER, ANALYSIS_OFFSET(sweep_targets)},
    {"sweep_window_seconds", SETTING_NUMBER, ANALYSIS_OFFSET(sweep_window_seconds)},
    {"range_poll_repeat", SETTING_NUMBER, ANALYSIS_OFFSET(range_poll_repeat)},
    {"range_poll_min_targets", SETTING_NUMBER, ANALYSIS_OFFSET(range_poll_min_targets)},
    {"off_link_min_requests", SETTING_NUMBER, ANALYSIS_OFFSET(off_link_min_requests)}
};

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

void sn_arp_config_init(struct sn_arp_config *config)
{
    if (config != NULL) {
        *config = (struct sn_arp_config){0};
        sn_arp_rotation_config_init(&config->rotation);
        sn_arp_analysis_config_init(&config->analysis);
    }
}

static bool parse_cidr(const char *value, struct sn_arp_analysis_config *analysis)
{
    char address[INET_ADDRSTRLEN + 1U];
    const char *slash = strchr(value, '/');
    char *end;
    unsigned long prefix;
    size_t length;

    if (value[0] == '\0') {
        analysis->local_known = false;
        return true;
    }
    if (slash == NULL || slash == value || !isdigit((unsigned char)slash[1])) {
        return false;
    }
    length = (size_t)(slash - value);
    if (length >= sizeof(address)) {
        return false;
    }
    memcpy(address, value, length);
    address[length] = '\0';
    prefix = strtoul(slash + 1, &end, 10);
    if (*end != '\0' || prefix > 32UL ||
        inet_pton(AF_INET, address, analysis->local_network) != 1) {
        return false;
    }
    analysis->local_prefix = (uint8_t)prefix;
    analysis->local_known = true;
    return true;
}

static bool parse_ip_list(char *value, struct sn_arp_analysis_config *analysis)
{
    char *entry = value;

    analysis->baseline_count = 0U;
    if (value[0] == '\0') {
        return true;
    }
    for (;;) {
        char *comma = strchr(entry, ',');
        char *token;

        if (comma != NULL) {
            *comma = '\0';
        }
        token = trim(entry);
        if (analysis->baseline_count >= SN_ARP_BASELINE_CAPACITY ||
            inet_pton(AF_INET, token, analysis->baseline_ips[analysis->baseline_count]) != 1) {
            return false;
        }
        ++analysis->baseline_count;
        if (comma == NULL) {
            return true;
        }
        entry = comma + 1;
    }
}

static bool assign_setting(struct sn_arp_config *config, const struct setting *setting,
                           char *value)
{
    unsigned char *field = (unsigned char *)config + setting->offset;

    if (setting->type == SETTING_CIDR) {
        return parse_cidr(value, &config->analysis);
    }
    if (setting->type == SETTING_IP_LIST) {
        return parse_ip_list(value, &config->analysis);
    }
    if (setting->type == SETTING_DIRECTORY) {
        if (value[0] != '/' || strlen(value) >= SN_ARP_LOG_DIRECTORY_CAPACITY) {
            return false;
        }
        (void)snprintf((char *)field, SN_ARP_LOG_DIRECTORY_CAPACITY, "%s", value);
        return true;
    }
    if (setting->type == SETTING_BOOL) {
        if (strcmp(value, "true") == 0) {
            *(bool *)field = true;
            return true;
        }
        if (strcmp(value, "false") == 0) {
            *(bool *)field = false;
            return true;
        }
        return false;
    }
    if (value[0] == '\0') {
        return false;
    }
    for (const char *digit = value; *digit != '\0'; ++digit) {
        if (!isdigit((unsigned char)*digit)) {
            return false;
        }
    }
    {
        char *end;
        unsigned long long parsed;

        errno = 0;
        parsed = strtoull(value, &end, 10);
        if (errno == ERANGE || *end != '\0' || parsed > UINT64_MAX) {
            return false;
        }
        *(uint64_t *)field = (uint64_t)parsed;
    }
    return true;
}

bool sn_arp_config_load(const char *path, struct sn_arp_config *config,
                        char *error_buffer, size_t error_capacity)
{
    char line[1024];
    bool seen[sizeof(settings) / sizeof(settings[0])] = {false};
    size_t line_number = 0U;
    FILE *stream;

    if (path == NULL || config == NULL || (stream = fopen(path, "r")) == NULL) {
        set_error(error_buffer, error_capacity, "cannot open configuration", 0U);
        return false;
    }
    sn_arp_config_init(config);
    while (fgets(line, sizeof(line), stream) != NULL) {
        char *key;
        char *value;
        char *equals;
        size_t index;
        size_t length = strlen(line);

        ++line_number;
        if (length > 0U && line[length - 1U] != '\n' && !feof(stream)) {
            set_error(error_buffer, error_capacity, "line is too long", line_number);
            (void)fclose(stream);
            return false;
        }
        key = trim(line);
        if (key[0] == '\0' || key[0] == '#') {
            continue;
        }
        equals = strchr(key, '=');
        if (equals == NULL) {
            set_error(error_buffer, error_capacity, "expected key = value", line_number);
            (void)fclose(stream);
            return false;
        }
        *equals = '\0';
        key = trim(key);
        value = trim(equals + 1);
        for (index = 0U; index < sizeof(settings) / sizeof(settings[0]); ++index) {
            if (strcmp(key, settings[index].name) == 0) {
                break;
            }
        }
        if (index == sizeof(settings) / sizeof(settings[0]) || seen[index] ||
            !assign_setting(config, &settings[index], value)) {
            set_error(error_buffer, error_capacity, "unknown, duplicate or invalid setting", line_number);
            (void)fclose(stream);
            return false;
        }
        seen[index] = true;
    }
    if (ferror(stream)) {
        (void)fclose(stream);
        set_error(error_buffer, error_capacity, "error reading configuration", line_number);
        return false;
    }
    if (fclose(stream) != 0) {
        set_error(error_buffer, error_capacity, "error reading configuration", line_number);
        return false;
    }
    if ((config->rotation.packet_logging || config->rotation.address_logging) &&
        config->log_directory[0] == '\0') {
        set_error(error_buffer, error_capacity, "log_directory is required when logging is enabled", 0U);
        return false;
    }
    if ((config->rotation.packet_segment_bytes > 0U && config->rotation.packet_segment_bytes < 40U) ||
        (config->rotation.address_segment_bytes > 0U && config->rotation.address_segment_bytes < 512U)) {
        set_error(error_buffer, error_capacity, "segment size is too small", 0U);
        return false;
    }
    if (config->analysis.sweep_targets > SN_ARP_WINDOW_TARGET_CAPACITY ||
        (config->analysis.sweep_targets > 0U && config->analysis.sweep_window_seconds == 0U)) {
        set_error(error_buffer, error_capacity,
                  "sweep_targets must be 0-512 and needs a nonzero sweep_window_seconds", 0U);
        return false;
    }
    set_error(error_buffer, error_capacity, "", 0U);
    return true;
}