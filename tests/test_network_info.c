#include "sniffit_ng/network_info.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    struct sn_network_info info;

    sn_network_info_init(&info, "lo");
    assert(strcmp(info.interface_name, "lo") == 0);
    assert(sn_network_info_find_local_ipv4(&info));
    assert(strcmp(info.local_ipv4, "127.0.0.1") == 0);

    sn_network_info_init(&info, "sniffit-no-such-interface");
    assert(!sn_network_info_find_local_ipv4(&info));
    assert(info.local_ipv4[0] == '\0');
    assert(sn_ipv4_is_rfc1918("10.1.2.3"));
    assert(sn_ipv4_is_rfc1918("172.16.0.1"));
    assert(sn_ipv4_is_rfc1918("172.31.255.254"));
    assert(sn_ipv4_is_rfc1918("192.168.1.1"));
    assert(!sn_ipv4_is_rfc1918("172.32.0.1"));
    assert(!sn_ipv4_is_rfc1918("8.8.8.8"));
    assert(!sn_ipv4_is_rfc1918("not-an-ip"));
    sn_network_info_init(&info, "eth0");
    (void)snprintf(info.local_ipv4, sizeof(info.local_ipv4), "8.8.8.8");
    assert(!sn_network_info_resolve_external_ipv4(&info));
    assert(info.external_ipv4[0] == '\0');
    return 0;
}