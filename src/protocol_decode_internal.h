#ifndef SNIFFIT_NG_PROTOCOL_DECODE_INTERNAL_H
#define SNIFFIT_NG_PROTOCOL_DECODE_INTERNAL_H

#include "sniffit_ng/packet.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

static inline bool sn_decode_result_fits(int formatted_length, size_t output_capacity)
{
    return formatted_length >= 0 && (size_t)formatted_length < output_capacity;
}

bool sn_decode_icmp(const struct sn_packet_view *packet,
                    char *output,
                    size_t output_capacity);
bool sn_decode_tcp(const struct sn_packet_view *packet,
                   char *output,
                   size_t output_capacity,
                   bool tainted_extensions);
bool sn_decode_telnet(const uint8_t *bytes,
                      size_t length,
                      char *output,
                      size_t output_capacity);
bool sn_decode_http(const uint8_t *bytes,
                    size_t length,
                    char *output,
                    size_t output_capacity,
                    bool tainted_extensions);
bool sn_decode_udp(const struct sn_packet_view *packet,
                   char *output,
                   size_t output_capacity);
bool sn_decode_igmp(const struct sn_packet_view *packet,
                    char *output,
                    size_t output_capacity);
bool sn_decode_vrrp(const struct sn_packet_view *packet,
                    char *output,
                    size_t output_capacity);
bool sn_decode_snmp(const uint8_t *bytes,
                    size_t length,
                    char *output,
                    size_t output_capacity);
bool sn_decode_ntp(const uint8_t *bytes,
                   size_t length,
                   char *output,
                   size_t output_capacity);
bool sn_decode_quic(const uint8_t *bytes,
                    size_t length,
                    char *output,
                    size_t output_capacity);
bool sn_decode_rtp(const uint8_t *bytes,
                   size_t length,
                   char *output,
                   size_t output_capacity);
bool sn_decode_rtcp(const uint8_t *bytes,
                    size_t length,
                    char *output,
                    size_t output_capacity);
bool sn_decode_syslog(const uint8_t *bytes,
                      size_t length,
                      char *output,
                      size_t output_capacity);
bool sn_decode_radius(const uint8_t *bytes,
                      size_t length,
                      char *output,
                      size_t output_capacity);
bool sn_decode_tacacs(const uint8_t *bytes,
                      size_t length,
                      char *output,
                      size_t output_capacity);
bool sn_decode_dns(const uint8_t *bytes,
                   size_t length,
                   char *output,
                   size_t output_capacity);
bool sn_decode_dns_tcp(const uint8_t *bytes,
                       size_t length,
                       char *output,
                       size_t output_capacity);
bool sn_decode_tls(const uint8_t *bytes,
                   size_t length,
                   char *output,
                   size_t output_capacity);
bool sn_decode_dhcp4(const uint8_t *bytes,
                     size_t length,
                     char *output,
                     size_t output_capacity);

#endif