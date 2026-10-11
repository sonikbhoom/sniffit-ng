#ifndef SNIFFIT_NG_UI_WINDOW_H
#define SNIFFIT_NG_UI_WINDOW_H

#include "sniffit_ng/flow.h"

#include <stdbool.h>
#include <stddef.h>

struct sn_ui_flow_filter {
    bool source_ip_enabled;
    bool destination_ip_enabled;
    bool source_port_enabled;
    bool destination_port_enabled;
    bool protocol_enabled;
    uint8_t source_ip[4];
    uint8_t destination_ip[4];
    uint16_t source_port;
    uint16_t destination_port;
    uint8_t protocol;
};

size_t sn_ui_window_start(size_t item_count,
                          size_t selected,
                          size_t visible_count,
                          size_t current_start);

void sn_ui_sort_flows(const struct sn_flow **flows, size_t flow_count);
bool sn_ui_flow_is_ssh_telnet(const struct sn_flow *flow);
void sn_ui_sort_flows_by_priority(const struct sn_flow **flows,
                                  size_t flow_count);
const char *sn_ui_port_service_name(uint8_t protocol, uint16_t port);
bool sn_ui_flow_matches(const struct sn_flow *flow,
                        const struct sn_ui_flow_filter *filter);
int sn_ui_detail_navigation_direction(int key, int up_key, int down_key);
bool sn_ui_detail_should_dismiss(int key, int timeout_key, int resize_key);

#endif
