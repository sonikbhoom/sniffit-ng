#ifndef SNIFFIT_NG_ARP_H
#define SNIFFIT_NG_ARP_H

#include "sniffit_ng/packet.h"

struct sn_arp_packet {
    uint16_t operation;
    uint8_t sender_mac[6];
    uint8_t sender_ipv4[4];
    uint8_t target_mac[6];
    uint8_t target_ipv4[4];
};

enum sn_packet_result sn_arp_parse(const uint8_t *bytes, size_t length,
                                   struct sn_arp_packet *packet);
enum sn_packet_result sn_arp_locate_link(const uint8_t *bytes, size_t length,
                                         enum sn_packet_link_type link_type,
                                         size_t *payload_offset);
enum sn_packet_result sn_arp_parse_link(const uint8_t *bytes, size_t length,
                                        enum sn_packet_link_type link_type,
                                        struct sn_arp_packet *packet);

#endif