#include "sniffit_ng/packet.h"

#include <string.h>

#define ETHERNET_HEADER_LENGTH 14U
#define IPV4_MIN_HEADER_LENGTH 20U
#define TCP_MIN_HEADER_LENGTH 20U
#define UDP_HEADER_LENGTH 8U
#define ICMP_MIN_HEADER_LENGTH 4U
#define IPV4_ETHERTYPE 0x0800U
#define VLAN_ETHERTYPE 0x8100U
#define QINQ_ETHERTYPE 0x88a8U
#define PROVIDER_VLAN_ETHERTYPE 0x9100U

static uint16_t read_be16(const uint8_t *bytes)
{
    return (uint16_t)(((uint16_t)bytes[0] << 8) | (uint16_t)bytes[1]);
}

static bool is_vlan_ethertype(uint16_t ethertype)
{
    return ethertype == VLAN_ETHERTYPE ||
           ethertype == QINQ_ETHERTYPE ||
           ethertype == PROVIDER_VLAN_ETHERTYPE;
}

static bool ipv4_checksum_valid(const uint8_t *header, size_t header_length)
{
    uint32_t sum = 0;

    for (size_t offset = 0; offset < header_length; offset += 2) {
        sum += ((uint32_t)header[offset] << 8) | (uint32_t)header[offset + 1];
    }

    while ((sum >> 16) != 0U) {
        sum = (sum & 0xffffU) + (sum >> 16);
    }

    return sum == 0xffffU;
}

enum sn_packet_result sn_packet_parse_ethernet_ipv4(
    const uint8_t *captured,
    size_t captured_length,
    struct sn_packet_view *view)
{
    size_t network_offset = ETHERNET_HEADER_LENGTH;
    uint16_t ethertype;
    const uint8_t *ip;
    size_t ip_header_length;
    size_t ip_total_length;
    size_t ip_payload_length;
    uint16_t fragment_field;

    if (view == NULL) {
        return SN_PACKET_MALFORMED;
    }
    *view = (struct sn_packet_view){0};
    if (captured == NULL) {
        return SN_PACKET_MALFORMED;
    }
    if (captured_length < ETHERNET_HEADER_LENGTH) {
        return SN_PACKET_TRUNCATED;
    }

    ethertype = read_be16(captured + 12);
    for (size_t vlan_depth = 0; is_vlan_ethertype(ethertype); ++vlan_depth) {
        if (vlan_depth == 2U) {
            return SN_PACKET_MALFORMED;
        }
        if (captured_length - network_offset < 4U) {
            return SN_PACKET_TRUNCATED;
        }
        ethertype = read_be16(captured + network_offset + 2U);
        network_offset += 4U;
    }
    if (ethertype != IPV4_ETHERTYPE) {
        return SN_PACKET_UNSUPPORTED;
    }
    if (captured_length - network_offset < IPV4_MIN_HEADER_LENGTH) {
        return SN_PACKET_TRUNCATED;
    }

    ip = captured + network_offset;
    if ((ip[0] >> 4) != 4U) {
        return SN_PACKET_MALFORMED;
    }
    ip_header_length = (size_t)(ip[0] & 0x0fU) * 4U;
    if (ip_header_length < IPV4_MIN_HEADER_LENGTH) {
        return SN_PACKET_MALFORMED;
    }
    if (captured_length - network_offset < ip_header_length) {
        return SN_PACKET_TRUNCATED;
    }

    ip_total_length = read_be16(ip + 2U);
    if (ip_total_length < ip_header_length) {
        return SN_PACKET_MALFORMED;
    }
    if (ip_total_length > captured_length - network_offset) {
        return SN_PACKET_TRUNCATED;
    }

    memcpy(view->source_ipv4, ip + 12U, sizeof(view->source_ipv4));
    memcpy(view->destination_ipv4, ip + 16U, sizeof(view->destination_ipv4));
    view->protocol = ip[9];
    view->ipv4_header_length = ip_header_length;
    view->ipv4_total_length = ip_total_length;
    view->ipv4_checksum_valid = ipv4_checksum_valid(ip, ip_header_length);

    fragment_field = read_be16(ip + 6U);
    view->fragment_offset = (uint16_t)(fragment_field & 0x1fffU);
    view->more_fragments = (fragment_field & 0x2000U) != 0U;

    ip_payload_length = ip_total_length - ip_header_length;
    view->transport = ip + ip_header_length;
    view->transport_length = ip_payload_length;
    view->payload = view->transport;
    view->payload_length = ip_payload_length;

    if (view->fragment_offset != 0U) {
        return SN_PACKET_OK;
    }

    switch (view->protocol) {
    case 6U: {
        size_t tcp_header_length;

        if (ip_payload_length < TCP_MIN_HEADER_LENGTH) {
            return SN_PACKET_MALFORMED;
        }
        tcp_header_length = (size_t)(view->transport[12] >> 4) * 4U;
        if (tcp_header_length < TCP_MIN_HEADER_LENGTH ||
            tcp_header_length > ip_payload_length) {
            return SN_PACKET_MALFORMED;
        }
        view->payload = view->transport + tcp_header_length;
        view->payload_length = ip_payload_length - tcp_header_length;
        view->transport_header_present = true;
        return SN_PACKET_OK;
    }
    case 17U: {
        size_t udp_length;

        if (ip_payload_length < UDP_HEADER_LENGTH) {
            return SN_PACKET_MALFORMED;
        }
        udp_length = read_be16(view->transport + 4U);
        if (udp_length < UDP_HEADER_LENGTH || udp_length > ip_payload_length) {
            return SN_PACKET_MALFORMED;
        }
        view->transport_length = udp_length;
        view->payload = view->transport + UDP_HEADER_LENGTH;
        view->payload_length = udp_length - UDP_HEADER_LENGTH;
        view->transport_header_present = true;
        return SN_PACKET_OK;
    }
    case 1U:
        if (ip_payload_length < ICMP_MIN_HEADER_LENGTH) {
            return SN_PACKET_MALFORMED;
        }
        view->payload = view->transport + ICMP_MIN_HEADER_LENGTH;
        view->payload_length = ip_payload_length - ICMP_MIN_HEADER_LENGTH;
        view->transport_header_present = true;
        return SN_PACKET_OK;
    default:
        return SN_PACKET_UNSUPPORTED;
    }
}
