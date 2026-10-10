#ifndef SNIFFIT_NG_UI_WINDOW_H
#define SNIFFIT_NG_UI_WINDOW_H

#include "sniffit_ng/flow.h"

#include <stdbool.h>
#include <stddef.h>

size_t sn_ui_window_start(size_t item_count,
                          size_t selected,
                          size_t visible_count,
                          size_t current_start);

void sn_ui_sort_flows(const struct sn_flow **flows, size_t flow_count);
const char *sn_ui_port_service_name(uint8_t protocol, uint16_t port);
int sn_ui_detail_navigation_direction(int key, int up_key, int down_key);
bool sn_ui_detail_should_dismiss(int key, int timeout_key, int resize_key);

#endif
