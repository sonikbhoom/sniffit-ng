#include "sniffit_ng/decoder_modes.h"

#include <string.h>

static const char *const module_names[SN_DECODER_MODULE_COUNT] = {
    "icmp", "igmp", "tcp", "http", "dns", "tls", "tacacs", "syslog",
    "udp", "dhcp4", "snmp", "ntp", "quic", "rtp", "rtcp", "radius",
    "vrrp", "telnet"
};

const char *sn_decoder_module_name(enum sn_decoder_module module)
{
    if (module < 0 || module >= SN_DECODER_MODULE_COUNT) {
        return NULL;
    }
    return module_names[module];
}

bool sn_decoder_module_from_name(const char *name,
                                 enum sn_decoder_module *module)
{
    if (name == NULL || module == NULL) {
        return false;
    }
    for (int index = 0; index < SN_DECODER_MODULE_COUNT; ++index) {
        if (strcmp(name, module_names[index]) == 0) {
            *module = (enum sn_decoder_module)index;
            return true;
        }
    }
    return false;
}