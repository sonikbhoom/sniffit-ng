#include "sniffit_ng/protocol_decode.h"
#include "sniffit_ng/http_decode_extension.h"
#include "decode_placeholder_internal.h"
#include "protocol_decode_internal.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_tcp_and_udp_metadata(void)
{
    uint8_t tcp[25] = {0};
    uint8_t udp[11] = {0};
    struct sn_packet_view packet = {0};
    char output[SN_PACKET_DECODE_TEXT_CAPACITY];

    tcp[0] = 0x04U;
    tcp[1] = 0xd2U;
    tcp[2] = 0x01U;
    tcp[3] = 0xbbU;
    tcp[4] = 0x01U;
    tcp[7] = 0x02U;
    tcp[12] = 0x50U;
    tcp[13] = 0x12U;
    tcp[14] = 0x20U;
    packet.protocol = 6U;
    packet.transport = tcp;
    packet.transport_length = sizeof(tcp);
    packet.transport_header_present = true;
    packet.payload_length = 5U;
    assert(sn_protocol_decode(&packet, output, sizeof(output)));
    assert(strstr(output, "TCP 1234->443") != NULL);
    assert(strstr(output, "flags=0x12") != NULL);
    assert(strstr(output, "payload=5") != NULL);

    udp[0] = 0x30U;
    udp[1] = 0x39U;
    udp[2] = 0x00U;
    udp[3] = 0x35U;
    udp[4] = 0x00U;
    udp[5] = 0x0bU;
    packet.protocol = 17U;
    packet.transport = udp;
    packet.transport_length = sizeof(udp);
    packet.payload = (const uint8_t *)"abc";
    packet.payload_length = 3U;
    assert(sn_protocol_decode(&packet, output, sizeof(output)));
    assert(strstr(output, "UDP 12345->53") != NULL);
    assert(strstr(output, "payload=3") != NULL);
    assert(strstr(output, "abc") == NULL);
}

static void test_http_summaries_hide_paths_and_sensitive_headers(void)
{
    static const uint8_t request[] =
        "GET /private/path?token=secret HTTP/1.1\r\n"
        "Host: 152.2.23.104\r\n"
        "Authorization: Bearer private-token\r\n"
        "Cookie: session=private-cookie\r\n\r\n";
    static const uint8_t response[] =
        "HTTP/1.1 200 OK\r\n"
        "Server: nginx/1.24.0\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 125\r\n"
        "Set-Cookie: private-cookie\r\n\r\n";
    static const uint8_t partial[] = "GET / HTTP/1.1";
    uint8_t tcp[20] = {0};
    struct sn_packet_view packet = {0};
    char output[SN_PACKET_DECODE_TEXT_CAPACITY];

    tcp[0] = 0xbbU;
    tcp[1] = 0x8cU;
    tcp[2] = 0U;
    tcp[3] = 80U;
    tcp[12] = 0x50U;
    packet.protocol = 6U;
    packet.transport = tcp;
    packet.transport_length = sizeof(tcp) + sizeof(request) - 1U;
    packet.transport_header_present = true;
    packet.payload = request;
    packet.payload_length = sizeof(request) - 1U;
    assert(sn_protocol_decode(&packet, output, sizeof(output)));
    assert(strstr(output, "HTTP request method=GET version=HTTP/1.1 host=152.2.23.104") != NULL);
    assert(strstr(output, "/private/path") == NULL);
    assert(strstr(output, "secret") == NULL);
    assert(strstr(output, "private-token") == NULL);
    assert(strstr(output, "private-cookie") == NULL);

    tcp[0] = 0U;
    tcp[1] = 80U;
    tcp[2] = 0xbbU;
    tcp[3] = 0x8cU;
    packet.transport_length = sizeof(tcp) + sizeof(response) - 1U;
    packet.payload = response;
    packet.payload_length = sizeof(response) - 1U;
    assert(sn_protocol_decode(&packet, output, sizeof(output)));
    assert(strstr(output, "HTTP response version=HTTP/1.1 status=200") != NULL);
    assert(strstr(output, "server=nginx/1.24.0") != NULL);
    assert(strstr(output, "type=text/html") != NULL);
    assert(strstr(output, "bytes=125") != NULL);
    assert(strstr(output, "private-cookie") == NULL);

    tcp[0] = 0x01U;
    tcp[1] = 0xbbU;
    tcp[2] = 0xbbU;
    tcp[3] = 0x8cU;
    assert(sn_protocol_decode(&packet, output, sizeof(output)));
    assert(strstr(output, "HTTP response") == NULL);

    tcp[1] = 80U;
    packet.payload = partial;
    packet.payload_length = sizeof(partial) - 1U;
    packet.transport_length = sizeof(tcp) + sizeof(partial) - 1U;
    assert(sn_protocol_decode(&packet, output, sizeof(output)));
    assert(strstr(output, "HTTP") == NULL);
}

static void test_http_extension_is_disabled_by_default(void)
{
    static const uint8_t payload[] = "GET /secret HTTP/1.1\r\nHost: example.test\r\n\r\n";
    char output[SN_HTTP_EXTENSION_OUTPUT_CAPACITY] = "not empty";

    assert(!sn_http_decode_extension(payload, sizeof(payload) - 1U,
                                     output, sizeof(output)));
    assert(output[0] == '\0');
}

static void test_ntp_metadata_and_validation(void)
{
    uint8_t ntp[48] = {0};
    uint8_t udp[56] = {0U, 123U, 0x9cU, 0x40U, 0U, 56U, 0U, 0U};
    struct sn_packet_view packet = {0};
    char output[SN_PACKET_DECODE_TEXT_CAPACITY];

    ntp[0] = 0x24U;
    ntp[1] = 2U;
    ntp[2] = 6U;
    ntp[3] = 236U;
    ntp[12] = 'G';
    ntp[13] = 'P';
    ntp[14] = 'S';

    packet.protocol = 17U;
    packet.transport = udp;
    packet.transport_length = sizeof(udp);
    packet.transport_header_present = true;
    packet.payload = ntp;
    packet.payload_length = sizeof(ntp);
    assert(sn_protocol_decode(&packet, output, sizeof(output)));
    assert(strstr(output, "UDP 123->40000") != NULL);
    assert(strstr(output, "NTP v4 server LI=0 stratum=2 poll=6 precision=-20") != NULL);
    assert(strstr(output, "refid=47505300") != NULL);
    assert(strstr(output, "timestamp") == NULL);

    packet.payload_length = sizeof(ntp) - 1U;
    udp[5] = 55U;
    packet.transport_length = 55U;
    assert(sn_protocol_decode(&packet, output, sizeof(output)));
    assert(strstr(output, "UDP 123->40000") != NULL);
    assert(strstr(output, "NTP") == NULL);

    packet.payload_length = sizeof(ntp);
    udp[5] = 56U;
    packet.transport_length = sizeof(udp);
    ntp[0] = 0x27U;
    assert(sn_protocol_decode(&packet, output, sizeof(output)));
    assert(strstr(output, "UDP 123->40000") != NULL);
    assert(strstr(output, "NTP") == NULL);

    char tiny_output[1] = {'x'};
    assert(!sn_decode_ntp(ntp, sizeof(ntp), tiny_output, sizeof(tiny_output)));
    assert(tiny_output[0] == '\0');
}

static void test_snmp_metadata_and_malformed_ber(void)
{
    static const uint8_t message[] = {
        0x30U, 0x26U,
        0x02U, 0x01U, 0x01U,
        0x04U, 0x06U, 'p', 'u', 'b', 'l', 'i', 'c',
        0xa0U, 0x19U,
        0x02U, 0x04U, 0x12U, 0x34U, 0x56U, 0x78U,
        0x02U, 0x01U, 0x00U,
        0x02U, 0x01U, 0x00U,
        0x30U, 0x0bU,
        0x30U, 0x09U,
        0x06U, 0x05U, 0x2bU, 0x06U, 0x01U, 0x02U, 0x01U,
        0x05U, 0x00U
    };
    static const uint8_t v3_message[] = {
        0x30U, 0x09U, 0x02U, 0x01U, 0x03U, 0x30U, 0x00U,
        0x04U, 0x00U, 0x04U, 0x00U
    };
    uint8_t udp[48] = {0U, 1U, 0U, 161U, 0U, 48U, 0U, 0U};
    struct sn_packet_view packet = {0};
    char output[SN_PACKET_DECODE_TEXT_CAPACITY];

    packet.protocol = 17U;
    packet.transport = udp;
    packet.transport_length = sizeof(udp);
    packet.transport_header_present = true;
    packet.payload = message;
    packet.payload_length = sizeof(message);
    assert(sn_protocol_decode(&packet, output, sizeof(output)));
    assert(strstr(output, "SNMPv2c GetRequest id=305419896 vars=1") != NULL);
    assert(strstr(output, "public") == NULL);

    packet.payload_length = sizeof(message) - 1U;
    udp[5] = 47U;
    packet.transport_length = 47U;
    assert(sn_protocol_decode(&packet, output, sizeof(output)));
    assert(strstr(output, "UDP 1->161") != NULL);
    assert(strstr(output, "SNMP") == NULL);

    udp[5] = 19U;
    packet.transport_length = 19U;
    packet.payload = v3_message;
    packet.payload_length = sizeof(v3_message);
    assert(sn_protocol_decode(&packet, output, sizeof(output)));
    assert(strstr(output, "SNMPv3 message") != NULL);

    packet.payload_length = sizeof(v3_message) - 1U;
    udp[5] = 18U;
    packet.transport_length = 18U;
    assert(sn_protocol_decode(&packet, output, sizeof(output)));
    assert(strstr(output, "SNMP") == NULL);
}

static void test_igmp_vrrp_and_icmp(void)
{
    uint8_t igmp[8] = {0x16U, 0U, 0U, 0U, 239U, 1U, 2U, 3U};
    uint8_t vrrp[12] = {0x21U, 7U, 100U, 1U, 0U, 1U, 0U, 0U,
                        192U, 0U, 2U, 1U};
    uint8_t icmp[8] = {8U, 0U, 0U, 0U, 0x12U, 0x34U, 0U, 7U};
    struct sn_packet_view packet = {0};
    char output[SN_PACKET_DECODE_TEXT_CAPACITY];

    packet.protocol = 2U;
    packet.transport = igmp;
    packet.transport_length = sizeof(igmp);
    packet.transport_header_present = true;
    assert(sn_protocol_decode(&packet, output, sizeof(output)));
    assert(strstr(output, "IGMP v2 report") != NULL);
    assert(strstr(output, "239.1.2.3") != NULL);

    packet.protocol = 112U;
    packet.transport = vrrp;
    packet.transport_length = sizeof(vrrp);
    assert(sn_protocol_decode(&packet, output, sizeof(output)));
    assert(strstr(output, "VRRPv2 advert vrid=7 priority=100 addresses=1") != NULL);
    vrrp[3] = 2U;
    assert(!sn_protocol_decode(&packet, output, sizeof(output)));

    packet.protocol = 1U;
    packet.transport = icmp;
    packet.transport_length = sizeof(icmp);
    packet.icmp_type = 8U;
    packet.icmp_code = 0U;
    packet.icmp_identifier = 0x1234U;
    packet.icmp_sequence = 7U;
    assert(sn_protocol_decode(&packet, output, sizeof(output)));
    assert(strstr(output, "ICMP Echo request") != NULL);
}

static void test_invalid_decoder_arguments(void)
{
    struct sn_packet_view packet = {0};
    char output[8] = "dirty";
    char tiny_output[1] = {'x'};

    assert(!sn_protocol_decode(&packet, output, sizeof(output)));
    assert(output[0] == '\0');
    assert(!sn_protocol_decode(NULL, output, sizeof(output)));
    assert(!sn_protocol_decode(&packet, NULL, 0U));

    packet.protocol = 1U;
    packet.transport_header_present = true;
    packet.transport_length = 8U;
    packet.icmp_type = 8U;
    assert(!sn_protocol_decode(&packet, tiny_output, sizeof(tiny_output)));
    assert(tiny_output[0] == '\0');
}

static void test_protocol_placeholders_are_inert(void)
{
    typedef bool (*placeholder_decoder)(const uint8_t *, size_t, char *, size_t);
    static const placeholder_decoder decoders[] = {
        sn_decode_dns, sn_decode_dhcp4, sn_decode_tls,
        sn_decode_quic, sn_decode_rtp, sn_decode_rtcp, sn_decode_syslog,
        sn_decode_radius, sn_decode_tacacs, sn_decode_icmpv6, sn_decode_ndp,
        sn_decode_dhcp6, sn_decode_ospf3, sn_decode_ripng, sn_decode_arp,
        sn_decode_lldp, sn_decode_cdp, sn_decode_stp, sn_decode_rstp,
        sn_decode_lacp, sn_decode_bgp, sn_decode_ospf2, sn_decode_isis,
        sn_decode_rip, sn_decode_hsrp, sn_decode_glbp, sn_decode_mpls,
        sn_decode_gre, sn_decode_ipip, sn_decode_vxlan, sn_decode_geneve
    };
    uint8_t bytes[4] = {0U, 1U, 2U, 3U};
    char output[16];

    for (size_t index = 0U; index < sizeof(decoders) / sizeof(decoders[0]); ++index) {
        memset(output, 'x', sizeof(output));
        assert(!decoders[index](bytes, sizeof(bytes), output, sizeof(output)));
        assert(output[0] == '\0');
    }
}

int main(void)
{
    test_tcp_and_udp_metadata();
    test_http_summaries_hide_paths_and_sensitive_headers();
    test_http_extension_is_disabled_by_default();
    test_ntp_metadata_and_validation();
    test_snmp_metadata_and_malformed_ber();
    test_igmp_vrrp_and_icmp();
    test_invalid_decoder_arguments();
    test_protocol_placeholders_are_inert();
    puts("protocol decoder tests passed");
    return 0;
}