#include "sniffit_ng/ui_window.h"

#include <stdlib.h>
#include <string.h>

size_t sn_ui_window_start(size_t item_count,
                          size_t selected,
                          size_t visible_count,
                          size_t current_start)
{
    size_t maximum_start;

    if (item_count == 0U || visible_count == 0U) {
        return 0U;
    }
    if (selected >= item_count) {
        selected = item_count - 1U;
    }
    maximum_start = item_count > visible_count ? item_count - visible_count : 0U;
    if (current_start > maximum_start) {
        current_start = maximum_start;
    }
    if (selected < current_start) {
        current_start = selected;
    } else if (selected - current_start >= visible_count) {
        current_start = selected - visible_count + 1U;
    }
    return current_start;
}

static int compare_endpoint(const struct sn_flow_endpoint *left,
                            const struct sn_flow_endpoint *right)
{
    int address_order = memcmp(left->ipv4, right->ipv4, sizeof(left->ipv4));

    if (address_order != 0) {
        return address_order;
    }
    if (left->port < right->port) {
        return -1;
    }
    if (left->port > right->port) {
        return 1;
    }
    return 0;
}

static int compare_flows(const struct sn_flow *left, const struct sn_flow *right)
{
    if (left->protocol != right->protocol) {
        return left->protocol < right->protocol ? -1 : 1;
    }

    int endpoint_order = compare_endpoint(&left->endpoints[0], &right->endpoints[0]);
    if (endpoint_order != 0) {
        return endpoint_order;
    }
    return compare_endpoint(&left->endpoints[1], &right->endpoints[1]);
}

static int compare_flow_pointers(const void *left, const void *right)
{
    const struct sn_flow *const *left_flow = left;
    const struct sn_flow *const *right_flow = right;

    return compare_flows(*left_flow, *right_flow);
}

void sn_ui_sort_flows(const struct sn_flow **flows, size_t flow_count)
{
    if (flows != NULL && flow_count > 1U) {
        qsort(flows, flow_count, sizeof(*flows), compare_flow_pointers);
    }
}

const char *sn_ui_port_service_name(uint8_t protocol, uint16_t port)
{
    if (protocol == 6U) {
        switch (port) {
        case 20U: return "FTP-data";
        case 21U: return "FTP";
        case 22U: return "SSH";
        case 23U: return "Telnet";
        case 25U: return "SMTP";
        case 53U: return "DNS";
        case 80U: return "HTTP";
        case 110U: return "POP3";
        case 143U: return "IMAP";
        case 443U: return "HTTPS";
        case 587U: return "Submission";
        case 993U: return "IMAPS";
        case 995U: return "POP3S";
        case 8080U: return "HTTP-alt";
        default: return NULL;
        }
    }
    if (protocol == 17U) {
        switch (port) {
        case 53U: return "DNS";
        case 67U: return "DHCP-server";
        case 68U: return "DHCP-client";
        case 69U: return "TFTP";
        case 123U: return "NTP";
        case 161U: return "SNMP";
        case 443U: return "QUIC";
        case 5353U: return "mDNS";
        default: return NULL;
        }
    }
    return NULL;
}

static bool endpoint_matches(const struct sn_flow_endpoint *endpoint,
                             bool ip_enabled,
                             const uint8_t ip[4],
                             bool port_enabled,
                             uint16_t port)
{
    return (!ip_enabled || (ip != NULL && memcmp(endpoint->ipv4, ip, 4U) == 0)) &&
           (!port_enabled || endpoint->port == port);
}

bool sn_ui_flow_matches(const struct sn_flow *flow,
                        const struct sn_ui_flow_filter *filter)
{
    if (flow == NULL || filter == NULL) {
        return false;
    }
    for (size_t source = 0U; source < 2U; ++source) {
        size_t destination = 1U - source;
        if (endpoint_matches(&flow->endpoints[source],
                             filter->source_ip_enabled, filter->source_ip,
                             filter->source_port_enabled, filter->source_port) &&
            endpoint_matches(&flow->endpoints[destination],
                             filter->destination_ip_enabled, filter->destination_ip,
                             filter->destination_port_enabled, filter->destination_port)) {
            return true;
        }
    }
    return false;
}

int sn_ui_detail_navigation_direction(int key, int up_key, int down_key)
{
    if (key == up_key || key == 'k' || key == 'K') {
        return -1;
    }
    if (key == down_key || key == 'j' || key == 'J') {
        return 1;
    }
    return 0;
}

bool sn_ui_detail_should_dismiss(int key, int timeout_key, int resize_key)
{
    return key != timeout_key && key != resize_key;
}
