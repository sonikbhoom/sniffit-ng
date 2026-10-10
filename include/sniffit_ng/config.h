#ifndef SNIFFIT_NG_CONFIG_H
#define SNIFFIT_NG_CONFIG_H

#include <stdbool.h>
#include <stddef.h>

#define SN_CONFIG_PAYLOAD_ACK_COMMENT \
    "## User has acknowledged to behave ethically and inspect only authorized traffic."

struct sn_app_config {
    bool inspect_payloads;
    bool payload_display_acknowledged;
};

void sn_config_init(struct sn_app_config *config);

bool sn_config_load_file(const char *path,
                         struct sn_app_config *config,
                         char *error_buffer,
                         size_t error_buffer_size);

bool sn_config_validate_payload_inspection(
    const struct sn_app_config *config,
    char *error_buffer,
    size_t error_buffer_size);

#endif
