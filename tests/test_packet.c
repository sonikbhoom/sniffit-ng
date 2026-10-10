#include "sniffit_ng/packet.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ETHERNET_HEADER_LENGTH 14U
#define IPV4_HEADER_LENGTH 20U
#define FRAME_CAPACITY 256U

static void write_be16(uint8_t *bytes, uint16_t value)
{
    bytes[0] = (uint8_t)(value >> 8);
    bytes[1] = (uint8_t)(value & 0xffU);
}

static uint16_t ipv4_checksum(const uint8_t *header, size_t header_length)
{
    uint32_t sum = 0;

    for (size_t offset = 0; offset < header_length; offset += 2U) {
        sum += ((uint32_t)header[offset] << 8) | (uint32_t)header[offset + 1U];
    }
    while ((sum >> 16) != 0U) {
        sum = (sum & 0xffffU) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

static size_t make_ipv4_frame(uint8_t *frame, uint8_t protocol, size_t transport_length)
{
    uint8_t *ip = frame + ETHERNET_HEADER_LENGTH;
    size_t frame_length = ETHERNET_HEADER_LENGTH + IPV4_HEADER_LENGTH + transport_length;

    memset(frame, 0, FRAME_CAPACITY);
    write_be16(frame + 12U, 0x0800U);
    ip[0] = 0x45U;
    write_be16(ip + 2U, (uint16_t)(IPV4_HEADER_LENGTH + transport_length));
    ip[8] = 64U;
    ip[9] = protocol;
    ip[12] = 192U;
    ip[13] = 0U;
    ip[14] = 2U;
    ip[15] = 1U;
    ip[16] = 198U;
    ip[17] = 51U;
    ip[18] = 100U;
    ip[19] = 2U;
    write_be16(ip + 10U, ipv4_checksum(ip, IPV4_HEADER_LENGTH));
    return frame_length;
}

static void test_valid_tcp_and_checksum(void)
{
    uint8_t frame[FRAME_CAPACITY];
    struct sn_packet_view view;
    size_t frame_length = make_ipv4_frame(frame, 6U, 23U);
    uint8_t *tcp = frame + ETHERNET_HEADER_LENGTH + IPV4_HEADER_LENGTH;

    tcp[12] = 0x50U;
    memcpy(tcp + 20U, "abc", 3U);
    memset(frame + ETHERNET_HEADER_LENGTH + 10U, 0, 2U);
    write_be16(frame + ETHERNET_HEADER_LENGTH + 10U,
               ipv4_checksum(frame + ETHERNET_HEADER_LENGTH, IPV4_HEADER_LENGTH));

    assert(sn_packet_parse_ethernet_ipv4(frame, frame_length, &view) == SN_PACKET_OK);
    assert(view.transport_header_present);
    assert(view.protocol == 6U);
    assert(view.ipv4_checksum_valid);
    assert(view.payload_length == 3U);
    assert(memcmp(view.payload, "abc", 3U) == 0);
    assert(view.source_ipv4[0] == 192U && view.destination_ipv4[0] == 198U);
}

static void test_truncated_frames(void)
{
    uint8_t frame[FRAME_CAPACITY];
    struct sn_packet_view view;
    size_t frame_length = make_ipv4_frame(frame, 1U, 4U);

    assert(sn_packet_parse_ethernet_ipv4(frame, 13U, &view) == SN_PACKET_TRUNCATED);
    assert(sn_packet_parse_ethernet_ipv4(frame, ETHERNET_HEADER_LENGTH + 19U,
                                         &view) == SN_PACKET_TRUNCATED);
    assert(sn_packet_parse_ethernet_ipv4(frame, frame_length - 1U,
                                         &view) == SN_PACKET_TRUNCATED);
}

static void test_malformed_ipv4_headers(void)
{
    uint8_t frame[FRAME_CAPACITY];
    struct sn_packet_view view;
    uint8_t *ip;
    size_t frame_length = make_ipv4_frame(frame, 1U, 4U);

    ip = frame + ETHERNET_HEADER_LENGTH;
    ip[0] = 0x65U;
    assert(sn_packet_parse_ethernet_ipv4(frame, frame_length, &view) == SN_PACKET_MALFORMED);

    ip[0] = 0x44U;
    assert(sn_packet_parse_ethernet_ipv4(frame, frame_length, &view) == SN_PACKET_MALFORMED);

    ip[0] = 0x45U;
    write_be16(ip + 2U, 19U);
    assert(sn_packet_parse_ethernet_ipv4(frame, frame_length, &view) == SN_PACKET_MALFORMED);
}

static void test_valid_udp(void)
{
    uint8_t frame[FRAME_CAPACITY];
    struct sn_packet_view view;
    size_t frame_length = make_ipv4_frame(frame, 17U, 11U);
    uint8_t *udp = frame + ETHERNET_HEADER_LENGTH + IPV4_HEADER_LENGTH;

    write_be16(udp + 4U, 11U);
    assert(sn_packet_parse_ethernet_ipv4(frame, frame_length, &view) == SN_PACKET_OK);
    assert(view.transport_header_present);
    assert(view.payload_length == 3U);
}

static void test_icmp_echo_metadata_and_payload_boundary(void)
{
    uint8_t frame[FRAME_CAPACITY];
    struct sn_packet_view view;
    size_t frame_length = make_ipv4_frame(frame, 1U, 13U);
    uint8_t *icmp = frame + ETHERNET_HEADER_LENGTH + IPV4_HEADER_LENGTH;

    icmp[0] = 8U;
    icmp[1] = 0U;
    write_be16(icmp + 4U, 0x1234U);
    write_be16(icmp + 6U, 7U);
    memcpy(icmp + 8U, "hello", 5U);

    assert(sn_packet_parse_ethernet_ipv4(frame, frame_length, &view) == SN_PACKET_OK);
    assert(view.icmp_type == 8U);
    assert(view.icmp_code == 0U);
    assert(view.icmp_identifier == 0x1234U);
    assert(view.icmp_sequence == 7U);
    assert(view.payload_length == 5U);
    assert(memcmp(view.payload, "hello", 5U) == 0);

    frame_length = make_ipv4_frame(frame, 1U, 7U);
    icmp = frame + ETHERNET_HEADER_LENGTH + IPV4_HEADER_LENGTH;
    icmp[0] = 0U;
    assert(sn_packet_parse_ethernet_ipv4(frame, frame_length, &view) == SN_PACKET_MALFORMED);
}

static void test_igmp_and_vrrp_headers(void)
{
    uint8_t frame[FRAME_CAPACITY];
    struct sn_packet_view view;
    size_t frame_length = make_ipv4_frame(frame, 2U, 8U);
    uint8_t *igmp = frame + ETHERNET_HEADER_LENGTH + IPV4_HEADER_LENGTH;

    igmp[0] = 0x16U;
    igmp[4] = 239U;
    igmp[5] = 1U;
    igmp[6] = 2U;
    igmp[7] = 3U;
    assert(sn_packet_parse_ethernet_ipv4(frame, frame_length, &view) == SN_PACKET_OK);
    assert(view.protocol == 2U && view.transport_header_present);
    assert(view.payload_length == 0U);

    frame_length = make_ipv4_frame(frame, 112U, 12U);
    uint8_t *vrrp = frame + ETHERNET_HEADER_LENGTH + IPV4_HEADER_LENGTH;
    vrrp[0] = 0x21U;
    vrrp[1] = 7U;
    vrrp[2] = 100U;
    vrrp[3] = 1U;
    vrrp[8] = 192U;
    vrrp[9] = 0U;
    vrrp[10] = 2U;
    vrrp[11] = 1U;
    assert(sn_packet_parse_ethernet_ipv4(frame, frame_length, &view) == SN_PACKET_OK);
    assert(view.protocol == 112U && view.transport_header_present);

    vrrp[3] = 2U;
    assert(sn_packet_parse_ethernet_ipv4(frame, frame_length, &view) == SN_PACKET_MALFORMED);
}

static void test_malformed_transport_headers(void)
{
    uint8_t frame[FRAME_CAPACITY];
    struct sn_packet_view view;
    size_t frame_length = make_ipv4_frame(frame, 6U, 20U);
    uint8_t *tcp = frame + ETHERNET_HEADER_LENGTH + IPV4_HEADER_LENGTH;

    tcp[12] = 0x40U;
    assert(sn_packet_parse_ethernet_ipv4(frame, frame_length, &view) == SN_PACKET_MALFORMED);
    tcp[12] = 0xf0U;
    assert(sn_packet_parse_ethernet_ipv4(frame, frame_length, &view) == SN_PACKET_MALFORMED);

    frame_length = make_ipv4_frame(frame, 17U, 8U);
    write_be16(frame + ETHERNET_HEADER_LENGTH + IPV4_HEADER_LENGTH + 4U, 7U);
    assert(sn_packet_parse_ethernet_ipv4(frame, frame_length, &view) == SN_PACKET_MALFORMED);

    write_be16(frame + ETHERNET_HEADER_LENGTH + IPV4_HEADER_LENGTH + 4U, 9U);
    assert(sn_packet_parse_ethernet_ipv4(frame, frame_length, &view) == SN_PACKET_MALFORMED);
}

static void test_fragment_and_vlan(void)
{
    uint8_t frame[FRAME_CAPACITY];
    struct sn_packet_view view;
    size_t frame_length = make_ipv4_frame(frame, 6U, 20U);
    uint8_t *ip = frame + ETHERNET_HEADER_LENGTH;
    uint8_t *tcp = ip + IPV4_HEADER_LENGTH;

    tcp[12] = 0x50U;
    write_be16(ip + 6U, 1U);
    assert(sn_packet_parse_ethernet_ipv4(frame, frame_length, &view) == SN_PACKET_OK);
    assert(view.fragment_offset == 1U);
    assert(!view.transport_header_present);

    write_be16(ip + 6U, 0U);
    memmove(frame + ETHERNET_HEADER_LENGTH + 4U, ip,
            frame_length - ETHERNET_HEADER_LENGTH);
    write_be16(frame + 12U, 0x8100U);
    write_be16(frame + 14U, 1U);
    write_be16(frame + 16U, 0x0800U);
    frame_length += 4U;

    assert(sn_packet_parse_ethernet_ipv4(frame, frame_length, &view) == SN_PACKET_OK);
    assert(view.transport_header_present);
}

static void test_linux_cooked_sll_ipv4(void)
{
    uint8_t ethernet_frame[FRAME_CAPACITY];
    uint8_t sll_frame[FRAME_CAPACITY] = {0};
    struct sn_packet_view view;
    size_t ethernet_length = make_ipv4_frame(ethernet_frame, 17U, 8U);
    size_t sll_length = ethernet_length - ETHERNET_HEADER_LENGTH + 16U;

    write_be16(ethernet_frame + ETHERNET_HEADER_LENGTH + IPV4_HEADER_LENGTH + 4U, 8U);
    write_be16(sll_frame + 14U, 0x0800U);
    memcpy(sll_frame + 16U, ethernet_frame + ETHERNET_HEADER_LENGTH,
           ethernet_length - ETHERNET_HEADER_LENGTH);

    assert(sn_packet_parse_link_ipv4(sll_frame, sll_length,
                                     SN_PACKET_LINK_LINUX_SLL, &view) == SN_PACKET_OK);
    assert(view.protocol == 17U);
    assert(view.transport_header_present);
    assert(view.source_ipv4[3] == 1U && view.destination_ipv4[3] == 2U);
    assert(sn_packet_parse_link_ipv4(sll_frame, 15U,
                                     SN_PACKET_LINK_LINUX_SLL, &view) ==
           SN_PACKET_TRUNCATED);

    write_be16(sll_frame + 14U, 0x0806U);
    assert(sn_packet_parse_link_ipv4(sll_frame, sll_length,
                                     SN_PACKET_LINK_LINUX_SLL, &view) ==
           SN_PACKET_UNSUPPORTED);
}

static void test_unsupported_and_invalid_arguments(void)
{
    uint8_t frame[FRAME_CAPACITY];
    struct sn_packet_view view;
    size_t frame_length = make_ipv4_frame(frame, 1U, 4U);

    write_be16(frame + 12U, 0x0806U);
    assert(sn_packet_parse_ethernet_ipv4(frame, frame_length, &view) == SN_PACKET_UNSUPPORTED);
    assert(sn_packet_parse_ethernet_ipv4(NULL, 0U, &view) == SN_PACKET_MALFORMED);
    assert(sn_packet_parse_ethernet_ipv4(frame, frame_length, NULL) == SN_PACKET_MALFORMED);
}

int main(void)
{
    test_valid_tcp_and_checksum();
    test_truncated_frames();
    test_malformed_ipv4_headers();
    test_valid_udp();
    test_icmp_echo_metadata_and_payload_boundary();
    test_igmp_and_vrrp_headers();
    test_malformed_transport_headers();
    test_fragment_and_vlan();
    test_linux_cooked_sll_ipv4();
    test_unsupported_and_invalid_arguments();
    puts("packet parser tests passed");
    return 0;
}
