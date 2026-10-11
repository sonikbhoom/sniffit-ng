#include "sniffit_ng/packet_inspect.h"

#include <arpa/inet.h>
#include <stdio.h>

#define ETHERNET_MIN_LENGTH 14U
#define LINUX_SLL_LENGTH 16U
#define IPV4_MIN_HEADER_LENGTH 20U
#define IPV4_MAX_HEADER_LENGTH 60U
#define TCP_MIN_HEADER_LENGTH 20U
#define TCP_MAX_HEADER_LENGTH 60U

static uint16_t read_be16(const uint8_t *bytes)
{
    return (uint16_t)(((uint16_t)bytes[0] << 8) | (uint16_t)bytes[1]);
}

static uint32_t read_be32(const uint8_t *bytes)
{
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) | (uint32_t)bytes[3];
}

static void print_hex(FILE *output, const uint8_t *bytes, size_t length)
{
    for (size_t index = 0U; index < length; ++index) {
        (void)fprintf(output, "%02x", bytes[index]);
    }
}

static const char *parse_result_name(enum sn_packet_result result)
{
    switch (result) {
    case SN_PACKET_OK: return "ok";
    case SN_PACKET_UNSUPPORTED: return "unsupported";
    case SN_PACKET_TRUNCATED: return "truncated";
    case SN_PACKET_MALFORMED: return "malformed";
    default: return "unknown";
    }
}

static const char *sll_packet_type_name(uint16_t packet_type)
{
    switch (packet_type) {
    case 0U: return "host";
    case 1U: return "broadcast";
    case 2U: return "multicast";
    case 3U: return "other-host";
    case 4U: return "outgoing";
    default: return "unknown";
    }
}

static void print_link_header(FILE *output,
                              const struct sn_capture_packet *packet)
{
    if (packet->link_type == SN_PACKET_LINK_ETHERNET) {
        if (packet->captured_length < ETHERNET_MIN_LENGTH) {
            (void)fprintf(output, "  Ethernet header=truncated\n");
            return;
        }
        (void)fprintf(output,
                      "  Ethernet observed_src=%02x:%02x:%02x:%02x:%02x:%02x"
                      " observed_dst=%02x:%02x:%02x:%02x:%02x:%02x\n",
                      packet->data[6], packet->data[7], packet->data[8],
                      packet->data[9], packet->data[10], packet->data[11],
                      packet->data[0], packet->data[1], packet->data[2],
                      packet->data[3], packet->data[4], packet->data[5]);
        return;
    }

    if (packet->link_type == SN_PACKET_LINK_LINUX_SLL) {
        if (packet->captured_length < LINUX_SLL_LENGTH) {
            (void)fprintf(output, "  Linux-SLL header=truncated\n");
            return;
        }
        {
            uint16_t packet_type = read_be16(packet->data);
            uint16_t hardware_type = read_be16(packet->data + 2U);
            size_t address_length = read_be16(packet->data + 4U);
            size_t displayed_length = address_length > 8U ? 8U : address_length;

            (void)fprintf(output, "  Linux-SLL packet_type=%s(%u) hardware_type=%u",
                          sll_packet_type_name(packet_type), packet_type,
                          hardware_type);
            if (address_length > 8U) {
                (void)fprintf(output, " observed_src=invalid-length(%zu)",
                              address_length);
            } else {
                (void)fprintf(output, " observed_src=");
                print_hex(output, packet->data + 6U, displayed_length);
                (void)fprintf(output, " address_length=%zu", address_length);
            }
            (void)fputc('\n', output);
        }
        return;
    }

    (void)fprintf(output, "  link=unsupported\n");
}

static void print_ipv4_header(FILE *output, const struct sn_packet_view *view)
{
    const uint8_t *ip = view->ipv4_packet;
    char source[INET_ADDRSTRLEN] = "?";
    char destination[INET_ADDRSTRLEN] = "?";
    uint16_t fragment_field = read_be16(ip + 6U);
    uint16_t ipv4_flags = (uint16_t)(fragment_field >> 13);

    (void)inet_ntop(AF_INET, view->source_ipv4, source, sizeof(source));
    (void)inet_ntop(AF_INET, view->destination_ipv4, destination,
                    sizeof(destination));
    (void)fprintf(output,
                  "  IPv4 claimed_src=%s claimed_dst=%s protocol=%u ttl=%u"
                  " ihl=%zu total=%zu id=0x%04x flags=0x%x offset=%u"
                  " checksum=%s\n",
                  source, destination, view->protocol, ip[8],
                  view->ipv4_header_length, view->ipv4_total_length,
                  read_be16(ip + 4U), ipv4_flags, view->fragment_offset,
                  view->ipv4_checksum_valid ? "valid" : "invalid");
    (void)fprintf(output, "  IPv4 header_hex=");
    print_hex(output, ip, view->ipv4_header_length);
    (void)fputc('\n', output);
}

static void print_tcp_header(FILE *output, const struct sn_packet_view *view)
{
    static const struct {
        uint8_t mask;
        const char *name;
    } flag_names[] = {
        {0x80U, "CWR"}, {0x40U, "ECE"}, {0x20U, "URG"},
        {0x10U, "ACK"}, {0x08U, "PSH"}, {0x04U, "RST"},
        {0x02U, "SYN"}, {0x01U, "FIN"}
    };
    const uint8_t *tcp = view->transport;
    uint8_t flags = tcp[13];
    size_t claimed_header_length = (size_t)(tcp[12] >> 4) * 4U;
    size_t raw_header_length = TCP_MIN_HEADER_LENGTH;
    bool has_valid_tcp_header = claimed_header_length >= TCP_MIN_HEADER_LENGTH &&
        claimed_header_length <= TCP_MAX_HEADER_LENGTH &&
        claimed_header_length <= view->transport_length;
    bool has_flag = false;

    if (has_valid_tcp_header) {
        raw_header_length = claimed_header_length;
    }
    (void)fprintf(output,
                  "  TCP claimed_src_port=%u claimed_dst_port=%u seq=%u ack=%u"
                  " data_offset=%zu window=%u checksum=0x%04x urgent=%u"
                  " flags=0x%02x [",
                  read_be16(tcp), read_be16(tcp + 2U), read_be32(tcp + 4U),
                  read_be32(tcp + 8U), claimed_header_length,
                  read_be16(tcp + 14U), read_be16(tcp + 16U),
                  read_be16(tcp + 18U), flags);
    for (size_t index = 0U; index < sizeof(flag_names) / sizeof(flag_names[0]);
         ++index) {
        if ((flags & flag_names[index].mask) != 0U) {
            (void)fprintf(output, "%s%s", has_flag ? "|" : "",
                          flag_names[index].name);
            has_flag = true;
        }
    }
    if (!has_flag) {
        (void)fprintf(output, "none");
    }
    (void)fprintf(output, "] ns=%u", tcp[12] & 0x01U);
    if (has_valid_tcp_header) {
        (void)fprintf(output, " payload_bytes=%zu",
                      view->payload_length);
    } else {
        (void)fprintf(output, " header=malformed");
    }
    (void)fputc('\n', output);
    (void)fprintf(output, "  TCP header_hex=");
    print_hex(output, tcp, raw_header_length);
    (void)fputc('\n', output);
}

bool sn_packet_inspect(FILE *output,
                       const struct sn_capture_packet *packet,
                       size_t packet_number)
{
    struct sn_packet_view view;
    enum sn_packet_result parse_result;

    if (output == NULL || packet == NULL ||
        (packet->captured_length > 0U && packet->data == NULL)) {
        return false;
    }
    (void)fprintf(output,
                  "packet=%zu time=%lld.%06ld caplen=%zu wirelen=%zu link=%s\n",
                  packet_number, (long long)packet->timestamp.tv_sec,
                  (long)packet->timestamp.tv_usec, packet->captured_length,
                  packet->wire_length,
                  packet->link_type == SN_PACKET_LINK_ETHERNET ?
                      "Ethernet" : "Linux-SLL");
    print_link_header(output, packet);

    parse_result = sn_packet_parse_link_ipv4(packet->data,
                                              packet->captured_length,
                                              packet->link_type, &view);
    (void)fprintf(output, "  parse=%s\n", parse_result_name(parse_result));
    if (view.ipv4_packet != NULL &&
        view.ipv4_header_length >= IPV4_MIN_HEADER_LENGTH &&
        view.ipv4_header_length <= IPV4_MAX_HEADER_LENGTH) {
        print_ipv4_header(output, &view);
        if (view.protocol == 6U && view.transport != NULL &&
            view.transport_length >= TCP_MIN_HEADER_LENGTH) {
            print_tcp_header(output, &view);
        }
    }
    return ferror(output) == 0;
}