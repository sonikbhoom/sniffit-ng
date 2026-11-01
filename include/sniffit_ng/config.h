#ifndef SNIFFIT_NG_CONFIG_H
#define SNIFFIT_NG_CONFIG_H

#include "sniffit_ng/decoder_modes.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SN_CONFIG_UI_PRIORITY_CAPACITY 32U
#define SN_CONFIG_HIDE_PROTOCOL_CAPACITY 5U
#define SN_PRIORITY_LOG_DEFAULT_MAX_BYTES (10UL * 1024UL * 1024UL)
#define SN_PRIORITY_LOG_DEFAULT_KEEP 7U
#define SN_PRIORITY_LOG_PATH_CAPACITY 512U

struct sn_ui_priority_port {
    uint8_t protocol;
    uint16_t port;
};

#define SN_CONFIG_PAYLOAD_ACK_COMMENT \
    "## User has acknowledged to behave ethically and inspect only authorized traffic."
#define SN_CONFIG_FULL_DECODE_ACK_COMMENT \
    "## User acknowledges Telnet hex display can expose credentials and private traffic."

struct sn_app_config {
    bool inspect_payloads;
    bool payload_display_acknowledged;
    bool full_decode;
    bool full_decode_acknowledged;
    bool resolve_external_addr;
    bool show_raw_flows;
    bool tainted_extensions;
    struct sn_ui_priority_port ui_priority_ports[SN_CONFIG_UI_PRIORITY_CAPACITY];
    size_t ui_priority_count;
    uint8_t hide_protocols[SN_CONFIG_HIDE_PROTOCOL_CAPACITY];
    size_t hide_protocol_count;
    char priority_log_path[SN_PRIORITY_LOG_PATH_CAPACITY];
    unsigned long priority_log_max_bytes;
    unsigned int priority_log_keep;
    enum sn_decoder_mode decoder_modes[SN_DECODER_MODULE_COUNT];
};

/* Case-insensitive lookup of the IP protocols the UI can list: tcp, udp, icmp, igmp, vrrp. */
bool sn_config_protocol_from_name(const char *name, uint8_t *protocol);

void sn_config_init(struct sn_app_config *config);

bool sn_config_load_file(const char *path,
                         struct sn_app_config *config,
                         char *error_buffer,
                         size_t error_buffer_size);

bool sn_config_validate_inspection_options(
    const struct sn_app_config *config,
    char *error_buffer,
    size_t error_buffer_size);

#endif
