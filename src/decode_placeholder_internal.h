#ifndef SNIFFIT_NG_DECODE_PLACEHOLDER_INTERNAL_H
#define SNIFFIT_NG_DECODE_PLACEHOLDER_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

static inline bool sn_decode_placeholder(const uint8_t *bytes,
                                         size_t length,
                                         char *output,
                                         size_t output_capacity)
{
    (void)bytes;
    (void)length;
    if (output == NULL || output_capacity == 0U) {
        return false;
    }
    output[0] = '\0';
    return false;
}

bool sn_decode_icmpv6(const uint8_t *bytes, size_t length, char *output, size_t output_capacity);
bool sn_decode_ndp(const uint8_t *bytes, size_t length, char *output, size_t output_capacity);
bool sn_decode_dhcp6(const uint8_t *bytes, size_t length, char *output, size_t output_capacity);
bool sn_decode_ospf3(const uint8_t *bytes, size_t length, char *output, size_t output_capacity);
bool sn_decode_ripng(const uint8_t *bytes, size_t length, char *output, size_t output_capacity);
bool sn_decode_arp(const uint8_t *bytes, size_t length, char *output, size_t output_capacity);
bool sn_decode_lldp(const uint8_t *bytes, size_t length, char *output, size_t output_capacity);
bool sn_decode_cdp(const uint8_t *bytes, size_t length, char *output, size_t output_capacity);
bool sn_decode_stp(const uint8_t *bytes, size_t length, char *output, size_t output_capacity);
bool sn_decode_rstp(const uint8_t *bytes, size_t length, char *output, size_t output_capacity);
bool sn_decode_lacp(const uint8_t *bytes, size_t length, char *output, size_t output_capacity);
bool sn_decode_bgp(const uint8_t *bytes, size_t length, char *output, size_t output_capacity);
bool sn_decode_ospf2(const uint8_t *bytes, size_t length, char *output, size_t output_capacity);
bool sn_decode_isis(const uint8_t *bytes, size_t length, char *output, size_t output_capacity);
bool sn_decode_rip(const uint8_t *bytes, size_t length, char *output, size_t output_capacity);
bool sn_decode_hsrp(const uint8_t *bytes, size_t length, char *output, size_t output_capacity);
bool sn_decode_glbp(const uint8_t *bytes, size_t length, char *output, size_t output_capacity);
bool sn_decode_mpls(const uint8_t *bytes, size_t length, char *output, size_t output_capacity);
bool sn_decode_gre(const uint8_t *bytes, size_t length, char *output, size_t output_capacity);
bool sn_decode_ipip(const uint8_t *bytes, size_t length, char *output, size_t output_capacity);
bool sn_decode_vxlan(const uint8_t *bytes, size_t length, char *output, size_t output_capacity);
bool sn_decode_geneve(const uint8_t *bytes, size_t length, char *output, size_t output_capacity);

#endif