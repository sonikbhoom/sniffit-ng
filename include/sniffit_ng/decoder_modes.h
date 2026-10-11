#ifndef SNIFFIT_NG_DECODER_MODES_H
#define SNIFFIT_NG_DECODER_MODES_H

#include <stdbool.h>

enum sn_decoder_module {
    SN_DECODER_ICMP,
    SN_DECODER_IGMP,
    SN_DECODER_TCP,
    SN_DECODER_HTTP,
    SN_DECODER_DNS,
    SN_DECODER_TLS,
    SN_DECODER_TACACS,
    SN_DECODER_SYSLOG,
    SN_DECODER_UDP,
    SN_DECODER_DHCP4,
    SN_DECODER_SNMP,
    SN_DECODER_NTP,
    SN_DECODER_QUIC,
    SN_DECODER_RTP,
    SN_DECODER_RTCP,
    SN_DECODER_RADIUS,
    SN_DECODER_VRRP,
    SN_DECODER_TELNET,
    SN_DECODER_MODULE_COUNT
};

enum sn_decoder_mode {
    SN_DECODER_SIMPLIFIED,
    SN_DECODER_RAW
};

const char *sn_decoder_module_name(enum sn_decoder_module module);

bool sn_decoder_module_from_name(const char *name,
                                 enum sn_decoder_module *module);

#endif