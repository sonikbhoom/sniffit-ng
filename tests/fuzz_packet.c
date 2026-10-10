#include "sniffit_ng/packet.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define FUZZ_FRAME_CAPACITY 512U
#define IPV4_HEADER_LENGTH 20U
#define ETHERNET_HEADER_LENGTH 14U
#define SLL_HEADER_LENGTH 16U

static void write_be16(uint8_t *bytes, uint16_t value)
{
    bytes[0] = (uint8_t)(value >> 8);
    bytes[1] = (uint8_t)value;
}

static void fuzz_structured_frame(const uint8_t *input,
                                  size_t input_size,
                                  enum sn_packet_link_type link_type,
                                  uint8_t protocol)
{
    uint8_t frame[FUZZ_FRAME_CAPACITY] = {0};
    struct sn_packet_view view;
    size_t link_header_length = link_type == SN_PACKET_LINK_ETHERNET ?
        ETHERNET_HEADER_LENGTH : SLL_HEADER_LENGTH;
    size_t network_offset = link_header_length;
    size_t transport_length;
    size_t frame_length;
    uint8_t *ip = frame + network_offset;
    uint8_t *transport = ip + IPV4_HEADER_LENGTH;

    if (protocol == 6U) {
        transport_length = 20U + (input_size % 64U);
    } else if (protocol == 1U || protocol == 2U || protocol == 112U) {
        transport_length = 8U + (input_size % 48U);
    } else {
        transport_length = 8U + (input_size % 128U);
    }
    frame_length = link_header_length + IPV4_HEADER_LENGTH + transport_length;
    if (frame_length > sizeof(frame)) {
        return;
    }

    if (link_type == SN_PACKET_LINK_ETHERNET) {
        write_be16(frame + 12U, 0x0800U);
    } else {
        write_be16(frame + 14U, 0x0800U);
    }
    ip[0] = 0x45U;
    write_be16(ip + 2U, (uint16_t)(IPV4_HEADER_LENGTH + transport_length));
    ip[8] = 64U;
    ip[9] = protocol;
    if (input_size > 0U) {
        ip[12] = input[0];
    }
    if (input_size > 1U) {
        ip[15] = input[1];
    }
    if (input_size > 2U) {
        ip[19] = input[2];
    }
    if (input_size > 0U) {
        size_t copy_length = input_size;
        if (copy_length > transport_length) {
            copy_length = transport_length;
        }
        memcpy(transport, input, copy_length);
    }

    if (protocol == 6U) {
        transport[12] = 0x50U;
    } else if (protocol == 17U) {
        write_be16(transport + 4U, (uint16_t)transport_length);
    } else if (protocol == 1U) {
        transport[0] = input_size > 3U && (input[3] & 1U) != 0U ? 8U : 0U;
    } else if (protocol == 112U) {
        transport[0] = 0x21U;
        transport[3] = 0U;
    }

    (void)sn_packet_parse_link_ipv4(frame, frame_length, link_type, &view);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct sn_packet_view view;
    static const uint8_t protocols[] = {6U, 17U, 1U, 2U, 112U, 47U};

    (void)sn_packet_parse_link_ipv4(data, size, SN_PACKET_LINK_ETHERNET, &view);
    (void)sn_packet_parse_link_ipv4(data, size, SN_PACKET_LINK_LINUX_SLL, &view);
    for (size_t index = 0U; index < sizeof(protocols); ++index) {
        fuzz_structured_frame(data, size, SN_PACKET_LINK_ETHERNET, protocols[index]);
        fuzz_structured_frame(data, size, SN_PACKET_LINK_LINUX_SLL, protocols[index]);
    }
    return 0;
}
