#include "sniffit_ng/protocol_decode.h"

#include "protocol_decode_internal.h"
#include "sniffit_ng/protocol_decode_extension.h"

#include <stdio.h>
#include <string.h>

static uint16_t read_be16(const uint8_t *bytes)
{
    return (uint16_t)(((uint16_t)bytes[0] << 8) | bytes[1]);
}

static bool copy_extension_output(const char *extension,
                                  char *output,
                                  size_t output_capacity)
{
    char sanitized[SN_PACKET_DECODE_TEXT_CAPACITY];
    size_t length = 0U;

    while (length < SN_PACKET_DECODE_TEXT_CAPACITY && extension[length] != '\0') {
        unsigned char character = (unsigned char)extension[length];
        sanitized[length] = character < 0x20U || character > 0x7eU ?
            '.' : extension[length];
        ++length;
    }
    if (length == 0U || length == SN_PACKET_DECODE_TEXT_CAPACITY ||
        length >= output_capacity) {
        output[0] = '\0';
        return false;
    }
    sanitized[length] = '\0';
    memcpy(output, sanitized, length + 1U);
    return true;
}

bool sn_protocol_decode(const struct sn_packet_view *packet,
                        char *output,
                        size_t output_capacity)
{
    return sn_protocol_decode_with_modes(packet, output, output_capacity,
                                         false, false, NULL);
}

bool sn_protocol_decode_with_extension(const struct sn_packet_view *packet,
                                       char *output,
                                       size_t output_capacity,
                                       bool tainted_extensions)
{
    return sn_protocol_decode_with_options(packet, output, output_capacity,
                                           false, tainted_extensions);
}

static bool decode_raw_ipv4(const struct sn_packet_view *packet,
                            char *output,
                            size_t output_capacity)
{
    int formatted_length;

    if (packet == NULL || output == NULL || output_capacity == 0U ||
        packet->ipv4_total_length == 0U || packet->ipv4_packet == NULL ||
        packet->ipv4_packet_length != packet->ipv4_total_length) {
        return false;
    }
    formatted_length = snprintf(output, output_capacity,
                                "IPv4 protocol=%u length=%zu fragment=%u more=%s checksum=%s",
                                packet->protocol, packet->ipv4_total_length,
                                packet->fragment_offset,
                                packet->more_fragments ? "yes" : "no",
                                packet->ipv4_checksum_valid ? "valid" : "invalid");
    return sn_decode_result_fits(formatted_length, output_capacity);
}

static bool port_is(uint16_t port, uint16_t first, uint16_t second)
{
    return port == first || port == second;
}

static bool tls_port(uint16_t port)
{
    return port == 443U || port == 853U || port == 465U || port == 636U ||
           port == 993U || port == 995U || port == 8443U;
}

static bool media_port(uint16_t port)
{
    return port == 5004U || port == 5005U ||
           (port >= 16384U && port <= 32767U);
}

static bool snmp_v1_or_v2c(const struct sn_packet_view *packet)
{
    size_t cursor = 1U;
    size_t sequence_length;
    uint8_t length_byte;

    if (packet->payload == NULL || packet->payload_length < 5U ||
        packet->payload[0] != 0x30U) {
        return false;
    }
    length_byte = packet->payload[cursor++];
    if ((length_byte & 0x80U) == 0U) {
        sequence_length = length_byte;
    } else {
        size_t length_octets = (size_t)(length_byte & 0x7fU);

        if (length_octets == 0U || length_octets > sizeof(size_t) ||
            length_octets > packet->payload_length - cursor) {
            return false;
        }
        sequence_length = 0U;
        for (size_t index = 0U; index < length_octets; ++index) {
            if (sequence_length > (SIZE_MAX >> 8)) {
                return false;
            }
            sequence_length = (sequence_length << 8) | packet->payload[cursor++];
        }
    }
    if (sequence_length > packet->payload_length - cursor ||
        sequence_length < 3U || packet->payload_length - cursor < 3U ||
        packet->payload[cursor] != 0x02U || packet->payload[cursor + 1U] != 1U) {
        return false;
    }
    return packet->payload[cursor + 2U] <= 1U;
}

static bool is_legacy_cleartext_tcp_port(uint16_t port)
{
    return port == 20U || port == 21U || port == 23U || port == 25U ||
           port == 110U || port == 143U || port == 389U || port == 513U ||
           port == 587U || port == 2525U;
}

static bool is_cleartext_udp_port(uint16_t port)
{
    return port == 69U || port == 520U || port == 1900U || port == 5353U;
}

static const char *security_note(const struct sn_packet_view *packet,
                                 enum sn_decoder_module module)
{
    uint16_t source_port = 0U;
    uint16_t destination_port = 0U;

    if (packet->transport != NULL && packet->transport_length >= 4U) {
        source_port = read_be16(packet->transport);
        destination_port = read_be16(packet->transport + 2U);
    }
    switch (module) {
    case SN_DECODER_ICMP:
        return " | SECURITY: unencrypted and unauthenticated diagnostic traffic";
    case SN_DECODER_IGMP:
        return " | SECURITY: unencrypted network-control traffic";
    case SN_DECODER_HTTP:
        return " | SECURITY: WEAK; HTTP is unencrypted, use HTTPS";
    case SN_DECODER_DNS:
        return " | SECURITY: WEAK; DNS on port 53 is usually cleartext";
    case SN_DECODER_SYSLOG:
        return " | SECURITY: syslog is unencrypted unless protected in transit";
    case SN_DECODER_DHCP4:
        return " | SECURITY: DHCPv4 is unauthenticated local-network configuration";
    case SN_DECODER_NTP:
        return " | SECURITY: WEAK; NTP is unauthenticated plaintext, use NTS";
    case SN_DECODER_SNMP:
        if (snmp_v1_or_v2c(packet)) {
            return " | SECURITY: WEAK; SNMPv1/v2c community strings are cleartext, use SNMPv3 authPriv";
        }
        return "";
    case SN_DECODER_RADIUS:
        return " | SECURITY: RADIUS attributes are not encrypted; protect the transport or use RadSec";
    case SN_DECODER_TELNET:
        return " | SECURITY: WEAK; Telnet exposes credentials and sessions, use SSH";
    case SN_DECODER_TCP:
        if (is_legacy_cleartext_tcp_port(source_port) ||
            is_legacy_cleartext_tcp_port(destination_port)) {
            return " | SECURITY: WEAK; legacy TCP service may expose credentials/data without TLS";
        }
        return "";
    case SN_DECODER_UDP:
        if (is_cleartext_udp_port(source_port) ||
            is_cleartext_udp_port(destination_port)) {
            return " | SECURITY: unencrypted legacy UDP service; use a protected alternative where available";
        }
        return "";
    default:
        return "";
    }
}

static bool append_security_note(const struct sn_packet_view *packet,
                                 enum sn_decoder_module module,
                                 char *output,
                                 size_t output_capacity)
{
    const char *note = security_note(packet, module);
    size_t output_length = strlen(output);
    size_t note_length = strlen(note);

    if (note[0] == '\0') {
        return true;
    }
    if (note_length + 1U >= output_capacity) {
        output[0] = '\0';
        return false;
    }
    if (output_length + note_length + 1U >= output_capacity) {
        size_t retained_length;

        if (output_capacity < note_length + 4U) {
            output[0] = '\0';
            return false;
        }
        retained_length = output_capacity - note_length - 4U;
        output[retained_length] = '.';
        output[retained_length + 1U] = '.';
        output[retained_length + 2U] = '.';
        memcpy(output + retained_length + 3U, note, note_length + 1U);
        return true;
    }
    memcpy(output + output_length, note, note_length + 1U);
    return true;
}

static enum sn_decoder_module decoder_module_for_packet(
    const struct sn_packet_view *packet)
{
    uint16_t source_port = 0U;
    uint16_t destination_port = 0U;

    switch (packet->protocol) {
    case 1U: return SN_DECODER_ICMP;
    case 2U: return SN_DECODER_IGMP;
    case 112U: return SN_DECODER_VRRP;
    case 6U:
    case 17U:
        if (packet->transport != NULL && packet->transport_length >= 4U) {
            source_port = read_be16(packet->transport);
            destination_port = read_be16(packet->transport + 2U);
        }
        break;
    default:
        return SN_DECODER_MODULE_COUNT;
    }

    if (packet->protocol == 6U) {
        if (source_port == 23U || destination_port == 23U) {
            return SN_DECODER_TELNET;
        }
        if (port_is(source_port, 80U, 8080U) ||
            port_is(destination_port, 80U, 8080U) ||
            source_port == 8000U || destination_port == 8000U) {
            return SN_DECODER_HTTP;
        }
        if (source_port == 53U || destination_port == 53U) {
            return SN_DECODER_DNS;
        }
        if (tls_port(source_port) || tls_port(destination_port)) {
            return SN_DECODER_TLS;
        }
        if (source_port == 49U || destination_port == 49U) {
            return SN_DECODER_TACACS;
        }
        if (source_port == 514U || destination_port == 514U) {
            return SN_DECODER_SYSLOG;
        }
        return SN_DECODER_TCP;
    }

    if (port_is(source_port, 67U, 68U) || port_is(destination_port, 67U, 68U)) {
        return SN_DECODER_DHCP4;
    }
    if (source_port == 53U || destination_port == 53U) {
        return SN_DECODER_DNS;
    }
    if (port_is(source_port, 161U, 162U) ||
        port_is(destination_port, 161U, 162U)) {
        return SN_DECODER_SNMP;
    }
    if (source_port == 123U || destination_port == 123U) {
        return SN_DECODER_NTP;
    }
    if (source_port == 443U || destination_port == 443U) {
        return SN_DECODER_QUIC;
    }
    if (source_port == 514U || destination_port == 514U) {
        return SN_DECODER_SYSLOG;
    }
    if (source_port == 1812U || source_port == 1813U ||
        source_port == 1645U || source_port == 1646U ||
        destination_port == 1812U || destination_port == 1813U ||
        destination_port == 1645U || destination_port == 1646U) {
        return SN_DECODER_RADIUS;
    }
    if (media_port(source_port) || media_port(destination_port)) {
        if (packet->payload != NULL && packet->payload_length >= 2U &&
            packet->payload[1] >= 192U && packet->payload[1] <= 223U) {
            return SN_DECODER_RTCP;
        }
        return SN_DECODER_RTP;
    }
    return SN_DECODER_UDP;
}

static bool decode_with_policy(
    const struct sn_packet_view *packet,
    char *output,
    size_t output_capacity,
    bool show_raw_flows,
    bool tainted_extensions,
    const enum sn_decoder_mode modes[SN_DECODER_MODULE_COUNT],
    bool extension_for_all)
{
    bool decoded = false;
    enum sn_decoder_module module;
    bool raw_mode;

    if (output == NULL || output_capacity == 0U) {
        return false;
    }
    output[0] = '\0';
    if (packet == NULL) {
        return false;
    }
    module = decoder_module_for_packet(packet);
    raw_mode = modes != NULL && module < SN_DECODER_MODULE_COUNT &&
               modes[module] == SN_DECODER_RAW;
    if (module == SN_DECODER_MODULE_COUNT &&
        (show_raw_flows || tainted_extensions)) {
        raw_mode = true;
    }
    if (tainted_extensions && (extension_for_all || raw_mode) &&
        packet->ipv4_packet != NULL &&
        packet->ipv4_packet_length == packet->ipv4_total_length &&
        packet->ipv4_packet_length >= packet->ipv4_header_length) {
        char extension_output[SN_PACKET_DECODE_TEXT_CAPACITY] = {0};
        if (sn_protocol_decode_extension(packet, extension_output,
                                         sizeof(extension_output)) &&
            copy_extension_output(extension_output, output, output_capacity)) {
            if (append_security_note(packet, module, output, output_capacity)) {
                return true;
            }
            output[0] = '\0';
            return false;
        }
        output[0] = '\0';
    }
    if (raw_mode) {
        decoded = decode_raw_ipv4(packet, output, output_capacity);
        if (decoded) {
            decoded = append_security_note(packet, module, output, output_capacity);
        }
        if (!decoded) {
            output[0] = '\0';
        }
        return decoded;
    }

    switch (packet->protocol) {
    case 1U:
        decoded = sn_decode_icmp(packet, output, output_capacity);
        break;
    case 2U:
        decoded = sn_decode_igmp(packet, output, output_capacity);
        break;
    case 6U:
        decoded = sn_decode_tcp(packet, output, output_capacity,
                                tainted_extensions);
        break;
    case 17U:
        decoded = sn_decode_udp(packet, output, output_capacity);
        break;
    case 112U:
        decoded = sn_decode_vrrp(packet, output, output_capacity);
        break;
    default:
        break;
    }
    if (!decoded && show_raw_flows) {
        decoded = decode_raw_ipv4(packet, output, output_capacity);
    }
    if (decoded) {
        decoded = append_security_note(packet, module, output, output_capacity);
    }
    if (!decoded) {
        output[0] = '\0';
    }
    return decoded;
}

bool sn_protocol_decode_with_options(const struct sn_packet_view *packet,
                                     char *output,
                                     size_t output_capacity,
                                     bool show_raw_flows,
                                     bool tainted_extensions)
{
    return decode_with_policy(packet, output, output_capacity, show_raw_flows,
                              tainted_extensions, NULL, true);
}

bool sn_protocol_decode_with_modes(
    const struct sn_packet_view *packet,
    char *output,
    size_t output_capacity,
    bool show_raw_flows,
    bool tainted_extensions,
    const enum sn_decoder_mode modes[SN_DECODER_MODULE_COUNT])
{
    return decode_with_policy(packet, output, output_capacity, show_raw_flows,
                              tainted_extensions, modes, false);
}