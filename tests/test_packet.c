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
    test_malformed_transport_headers();
    test_fragment_and_vlan();
    test_unsupported_and_invalid_arguments();
    puts("packet parser tests passed");
    return 0;
}
