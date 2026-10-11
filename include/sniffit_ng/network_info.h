#ifndef SNIFFIT_NG_NETWORK_INFO_H
#define SNIFFIT_NG_NETWORK_INFO_H

#include <stdbool.h>

#define SN_NETWORK_INTERFACE_NAME_CAPACITY 64U
#define SN_NETWORK_IPV4_TEXT_CAPACITY 16U

struct sn_network_info {
    char interface_name[SN_NETWORK_INTERFACE_NAME_CAPACITY];
    char local_ipv4[SN_NETWORK_IPV4_TEXT_CAPACITY];
    char external_ipv4[SN_NETWORK_IPV4_TEXT_CAPACITY];
};

void sn_network_info_init(struct sn_network_info *info, const char *interface_name);

bool sn_network_info_find_local_ipv4(struct sn_network_info *info);

bool sn_ipv4_is_rfc1918(const char *address_text);

bool sn_network_info_resolve_external_ipv4(struct sn_network_info *info);

#endif