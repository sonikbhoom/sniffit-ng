#include "sniffit_ng/protocol_decode.h"
#include "sniffit_ng/http_decode_extension.h"
#include "sniffit_ng/protocol_decode_extension.h"
#include "decode_placeholder_internal.h"
#include "protocol_decode_internal.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static unsigned int protocol_extension_calls;
static unsigned int http_extension_calls;

bool sn_http_decode_extension(const uint8_t *payload,
                              size_t payload_length,
                              char *output,
                              size_t output_capacity)
{
    static const char extension_text[] = "researcher";

    ++http_extension_calls;
    if (payload == NULL || payload_length == 0U || output == NULL ||
        output_capacity < sizeof(extension_text)) {
        return false;
    }
    memcpy(output, extension_text, sizeof(extension_text));
    return true;
}

bool sn_protocol_decode_extension(const struct sn_packet_view *packet,
                                  char *output,
                                  size_t output_capacity)
{
    static const char extension_text[] = "researcher\001summary";
    bool test_protocol = packet != NULL && packet->protocol == 253U;
    bool dns_protocol = packet != NULL && packet->protocol == 17U &&
                        packet->transport != NULL &&
                        packet->transport_length >= 4U &&
                        ((packet->transport[0] == 0U && packet->transport[1] == 53U) ||
                         (packet->transport[2] == 0U && packet->transport[3] == 53U));
    bool telnet_protocol = packet != NULL && packet->protocol == 6U &&
                           packet->transport != NULL &&
                           packet->transport_length >= 4U &&
                           (packet->transport[1] == 23U ||
                            packet->transport[3] == 23U);
    bool tls_protocol = packet != NULL && packet->protocol == 6U &&
                        packet->transport != NULL &&
                        packet->transport_length >= 4U &&
                        ((((uint16_t)packet->transport[0] << 8) |
                         packet->transport[1]) == 443U ||
                        (((uint16_t)packet->transport[2] << 8) |
                         packet->transport[3]) == 443U);
        bool icmp_protocol = packet != NULL && packet->protocol == 1U;
        bool ftp_protocol = packet != NULL && packet->protocol == 6U &&
                        packet->transport != NULL &&
                        packet->transport_length >= 4U &&
                        (((uint16_t)packet->transport[0] << 8) |
                        packet->transport[1]) == 21U;
        bool radius_protocol = packet != NULL && packet->protocol == 17U &&
                          packet->transport != NULL &&
                          packet->transport_length >= 4U &&
                          packet->transport[3] == 0x14U &&
                          (packet->transport[2] == 0x07U ||
                           packet->transport[2] == 0x06U);
        bool snmp_protocol = packet != NULL && packet->protocol == 17U &&
                        packet->transport != NULL &&
                        packet->transport_length >= 4U &&
                        packet->transport[3] == 161U &&
                        packet->payload != NULL && packet->payload_length >= 5U &&
                        packet->payload[0] == 0x30U &&
                        packet->payload[2] == 0x02U &&
                        packet->payload[3] == 1U &&
                        packet->payload[4] <= 1U;

    ++protocol_extension_calls;
        if ((!test_protocol && !dns_protocol && !telnet_protocol && !tls_protocol &&
            !icmp_protocol && !ftp_protocol && !snmp_protocol && !radius_protocol) ||
        output == NULL ||
        output_capacity < sizeof(extension_text)) {
        return false;
    }
    memcpy(output, extension_text, sizeof(extension_text));
    return true;
}

static void test_tainted_extension_gate_and_output_sanitizing(void)
{
    uint8_t ipv4_packet[20] = {0};
    struct sn_packet_view packet = {0};
    char output[SN_PACKET_DECODE_TEXT_CAPACITY];

    packet.protocol = 253U;
    packet.ipv4_packet = ipv4_packet;
    packet.ipv4_packet_length = sizeof(ipv4_packet);
    packet.ipv4_total_length = sizeof(ipv4_packet);
    packet.ipv4_header_length = sizeof(ipv4_packet);

    protocol_extension_calls = 0U;
    assert(!sn_protocol_decode_with_extension(&packet, output, sizeof(output), false));
    assert(protocol_extension_calls == 0U);

    assert(sn_protocol_decode_with_extension(&packet, output, sizeof(output), true));
    assert(protocol_extension_calls == 1U);
    assert(strcmp(output, "researcher.summary") == 0);

    output[0] = 'x';
    assert(!sn_protocol_decode_with_extension(&packet, output, 4U, true));
    assert(output[0] == '\0');
}

static void test_protocol_mode_selects_extension_or_simplified_decoder(void)
{
    uint8_t ipv4_packet[40] = {0};
    uint8_t udp[8] = {0U, 53U, 0x14U, 0xe9U, 0U, 8U, 0U, 0U};
    struct sn_packet_view packet = {0};
    enum sn_decoder_mode modes[SN_DECODER_MODULE_COUNT] = {0};
    char output[SN_PACKET_DECODE_TEXT_CAPACITY];

    packet.protocol = 17U;
    packet.transport = udp;
    packet.transport_length = sizeof(udp);
    packet.transport_header_present = true;
    packet.ipv4_packet = ipv4_packet;
    packet.ipv4_packet_length = sizeof(ipv4_packet);
    packet.ipv4_total_length = sizeof(ipv4_packet);
    packet.ipv4_header_length = 20U;
    modes[SN_DECODER_DNS] = SN_DECODER_RAW;

    protocol_extension_calls = 0U;
    assert(sn_protocol_decode_with_modes(&packet, output, sizeof(output),
                                         false, false, modes));
    assert(protocol_extension_calls == 0U);
    assert(strstr(output, "IPv4 protocol=17") != NULL);
    assert(strstr(output, "researcher.summary") == NULL);
    assert(strstr(output, "SECURITY:") == NULL);
    assert(strcmp(sn_protocol_security_advisory(&packet),
                  "SECURITY: WEAK; DNS on port 53 is usually cleartext") == 0);

    protocol_extension_calls = 0U;
    assert(sn_protocol_decode_with_modes(&packet, output, sizeof(output),
                                         false, true, modes));
    assert(protocol_extension_calls == 1U);
    assert(strstr(output, "researcher.summary") != NULL);
    assert(strstr(output, "SECURITY:") == NULL);

    modes[SN_DECODER_DNS] = SN_DECODER_SIMPLIFIED;
    protocol_extension_calls = 0U;
    assert(sn_protocol_decode_with_modes(&packet, output, sizeof(output),
                                         false, true, modes));
    assert(protocol_extension_calls == 0U);
    assert(strstr(output, "UDP 53->5353") != NULL);

    packet.protocol = 6U;
    packet.transport = NULL;
    packet.transport_length = 0U;
    packet.transport_header_present = false;
    assert(sn_protocol_decode_with_modes(&packet, output, sizeof(output),
                                         true, false, modes));
    assert(strstr(output, "IPv4 protocol=6") != NULL);

    uint8_t tcp[20] = {0};
    tcp[1] = 23U;
    tcp[12] = 0x50U;
    packet.protocol = 6U;
    packet.transport = tcp;
    packet.transport_length = sizeof(tcp);
    packet.transport_header_present = true;
    packet.ipv4_packet_length = 40U;
    packet.ipv4_total_length = 40U;
    modes[SN_DECODER_TELNET] = SN_DECODER_SIMPLIFIED;
    assert(sn_protocol_decode_with_modes(&packet, output, sizeof(output),
                                         false, false, modes));
    assert(strstr(output, "SECURITY:") == NULL);
    assert(strcmp(sn_protocol_security_advisory(&packet),
                  "SECURITY: WEAK; Telnet exposes credentials and sessions, use SSH") == 0);

    modes[SN_DECODER_TELNET] = SN_DECODER_RAW;
    protocol_extension_calls = 0U;
    assert(sn_protocol_decode_with_modes(&packet, output, sizeof(output),
                                         false, false, modes));
    assert(protocol_extension_calls == 0U);
    assert(strstr(output, "IPv4 protocol=6") != NULL);
    assert(strstr(output, "SECURITY:") == NULL);
    assert(sn_protocol_decode_with_modes(&packet, output, sizeof(output),
                                         false, true, modes));
    assert(protocol_extension_calls == 1U);
    assert(strstr(output, "researcher.summary") != NULL);

    tcp[0] = 1U;
    tcp[1] = 187U;
    modes[SN_DECODER_TLS] = SN_DECODER_RAW;
    protocol_extension_calls = 0U;
    assert(sn_protocol_decode_with_modes(&packet, output, sizeof(output),
                                         false, false, modes));
    assert(protocol_extension_calls == 0U);
    assert(strstr(output, "IPv4 protocol=6") != NULL);
    assert(sn_protocol_decode_with_modes(&packet, output, sizeof(output),
                                         false, true, modes));
    assert(protocol_extension_calls == 1U);

    uint8_t icmp[8] = {8U, 0U, 0U, 0U};
    packet.protocol = 1U;
    packet.transport = icmp;
    packet.transport_length = sizeof(icmp);
    packet.transport_header_present = true;
    packet.icmp_type = 8U;
    modes[SN_DECODER_ICMP] = SN_DECODER_RAW;
    protocol_extension_calls = 0U;
    assert(sn_protocol_decode_with_modes(&packet, output, sizeof(output),
                                         false, false, modes));
    assert(protocol_extension_calls == 0U);
    assert(strstr(output, "IPv4 protocol=1") != NULL);
    assert(strstr(output, "SECURITY:") == NULL);
    assert(strcmp(sn_protocol_security_advisory(&packet),
                  "SECURITY: unencrypted and unauthenticated diagnostic traffic") == 0);
    assert(sn_protocol_decode_with_modes(&packet, output, sizeof(output),
                                         false, true, modes));
    assert(protocol_extension_calls == 1U);

    tcp[0] = 0U;
    tcp[1] = 21U;
    modes[SN_DECODER_TCP] = SN_DECODER_RAW;
    packet.protocol = 6U;
    packet.transport = tcp;
    packet.transport_length = sizeof(tcp);
    protocol_extension_calls = 0U;
    assert(sn_protocol_decode_with_modes(&packet, output, sizeof(output),
                                         false, false, modes));
    assert(protocol_extension_calls == 0U);
    assert(strstr(output, "IPv4 protocol=6") != NULL);
    assert(strstr(output, "SECURITY:") == NULL);
    assert(strcmp(sn_protocol_security_advisory(&packet),
                  "SECURITY: WEAK; legacy TCP service may expose credentials/data without TLS") == 0);
    assert(sn_protocol_decode_with_modes(&packet, output, sizeof(output),
                                         false, true, modes));
    assert(protocol_extension_calls == 1U);

    uint8_t snmp_udp[8] = {0U, 161U, 0U, 0U, 0U, 8U, 0U, 0U};
    uint8_t snmp[5] = {0x30U, 3U, 0x02U, 1U, 1U};
    packet.protocol = 17U;
    packet.transport = snmp_udp;
    packet.transport_length = sizeof(snmp_udp);
    packet.payload = snmp;
    packet.payload_length = sizeof(snmp);
    packet.ipv4_packet_length = 33U;
    packet.ipv4_total_length = 33U;
    modes[SN_DECODER_SNMP] = SN_DECODER_RAW;
    protocol_extension_calls = 0U;
    assert(sn_protocol_decode_with_modes(&packet, output, sizeof(output),
                                         false, false, modes));
    assert(protocol_extension_calls == 0U);
    assert(strstr(output, "IPv4 protocol=17") != NULL);
    assert(strstr(output, "SECURITY:") == NULL);
    assert(strstr(sn_protocol_security_advisory(&packet),
                  "SNMPv1/v2c community strings are cleartext") != NULL);
    assert(sn_protocol_decode_with_modes(&packet, output, sizeof(output),
                                         false, true, modes));
    assert(protocol_extension_calls == 1U);
    assert(strstr(output, "SECURITY:") == NULL);

    snmp[4] = 3U;
    protocol_extension_calls = 0U;
    assert(sn_protocol_decode_with_modes(&packet, output, sizeof(output),
                                         false, false, modes));
    assert(protocol_extension_calls == 0U);

    snmp_udp[0] = 0x9cU;
    snmp_udp[1] = 0x40U;
    snmp_udp[2] = 0x07U;
    snmp_udp[3] = 0x14U;
    modes[SN_DECODER_RADIUS] = SN_DECODER_RAW;
    protocol_extension_calls = 0U;
    assert(sn_protocol_decode_with_modes(&packet, output, sizeof(output),
                                         false, false, modes));
    assert(protocol_extension_calls == 0U);
    assert(strstr(output, "SECURITY:") == NULL);
    assert(strstr(sn_protocol_security_advisory(&packet),
                  "RADIUS attributes are not encrypted") != NULL);
    assert(sn_protocol_decode_with_modes(&packet, output, sizeof(output),
                                         false, true, modes));
    assert(protocol_extension_calls == 1U);
    assert(strstr(output, "SECURITY:") == NULL);
}

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

static void test_telnet_negotiation_is_decoded_without_payload_text(void)
{
    static const uint8_t telnet_payload[] = {
        'l', 'o', 'g', 'i', 'n', ':', ' ', 'u', 's', 'e', 'r',
        255U, 253U, 24U,
        255U, 251U, 1U,
        255U, 250U, 24U, 0U, 'x', 't', 'e', 'r', 'm', 255U, 240U,
        255U, 255U
    };
    uint8_t tcp[20] = {0};
    struct sn_packet_view packet = {0};
    char output[SN_PACKET_DECODE_TEXT_CAPACITY];

    tcp[0] = 0xc3U;
    tcp[1] = 0x50U;
    tcp[2] = 0U;
    tcp[3] = 23U;
    tcp[12] = 0x50U;
    packet.protocol = 6U;
    packet.transport = tcp;
    packet.transport_length = sizeof(tcp) + sizeof(telnet_payload);
    packet.transport_header_present = true;
    packet.payload = telnet_payload;
    packet.payload_length = sizeof(telnet_payload);

    assert(sn_protocol_decode(&packet, output, sizeof(output)));
    assert(strstr(output, "TELNET payload=") != NULL);
    assert(strstr(output, "DO TERMINAL-TYPE(24)") != NULL);
    assert(strstr(output, "WILL ECHO(1)") != NULL);
    assert(strstr(output, "SB TERMINAL-TYPE(24) bytes=6") != NULL);
    assert(strstr(output, "data=12") != NULL);
    assert(strstr(output, "login") == NULL);
    assert(strstr(output, "user") == NULL);
    assert(strstr(output, "xterm") == NULL);

    char tiny_output[1] = {'x'};
    assert(!sn_protocol_decode(&packet, tiny_output, sizeof(tiny_output)));
    assert(tiny_output[0] == '\0');
}

static void test_telnet_commands_and_truncated_sequences(void)
{
    static const uint8_t commands[] = {
        255U, 241U, 255U, 246U, 255U, 252U, 3U, 255U, 255U, 255U, 200U
    };
    static const uint8_t unknown_command[] = {255U, 200U};
    static const uint8_t truncated_iac[] = {255U};
    static const uint8_t truncated_negotiation[] = {255U, 253U};
    static const uint8_t truncated_subnegotiation[] = {
        255U, 250U, 24U, 'x', 255U
    };
    static const uint8_t malformed_subnegotiation[] = {
        255U, 250U, 24U, 'x', 255U, 251U, 255U, 241U
    };
    uint8_t tcp[20] = {0};
    struct sn_packet_view packet = {0};
    char output[SN_PACKET_DECODE_TEXT_CAPACITY];

    tcp[0] = 0xc3U;
    tcp[1] = 0x50U;
    tcp[2] = 0U;
    tcp[3] = 23U;
    tcp[12] = 0x50U;
    packet.protocol = 6U;
    packet.transport = tcp;
    packet.transport_length = sizeof(tcp) + sizeof(commands);
    packet.transport_header_present = true;
    packet.payload = commands;
    packet.payload_length = sizeof(commands);
    assert(sn_protocol_decode(&packet, output, sizeof(output)));
    assert(strstr(output, "NOP") != NULL);
    assert(strstr(output, "AYT") != NULL);
    assert(strstr(output, "WONT SUPPRESS-GO-AHEAD(3)") != NULL);
    assert(strstr(output, "IAC") != NULL);
    assert(strstr(output, "+1 controls") != NULL);

    packet.payload = unknown_command;
    packet.payload_length = sizeof(unknown_command);
    packet.transport_length = sizeof(tcp) + packet.payload_length;
    assert(sn_protocol_decode(&packet, output, sizeof(output)));
    assert(strstr(output, "CMD(200)") != NULL);

    packet.payload = truncated_iac;
    packet.payload_length = sizeof(truncated_iac);
    packet.transport_length = sizeof(tcp) + packet.payload_length;
    assert(sn_protocol_decode(&packet, output, sizeof(output)));
    assert(strstr(output, "IAC incomplete") != NULL);

    packet.payload = truncated_negotiation;
    packet.payload_length = sizeof(truncated_negotiation);
    packet.transport_length = sizeof(tcp) + packet.payload_length;
    assert(sn_protocol_decode(&packet, output, sizeof(output)));
    assert(strstr(output, "DO incomplete") != NULL);

    packet.payload = truncated_subnegotiation;
    packet.payload_length = sizeof(truncated_subnegotiation);
    packet.transport_length = sizeof(tcp) + packet.payload_length;
    assert(sn_protocol_decode(&packet, output, sizeof(output)));
    assert(strstr(output, "SB TERMINAL-TYPE(24) bytes=1 incomplete") != NULL);
    assert(strstr(output, "SB TERMINAL-TYPE(24) bytes=1 x") == NULL);

    packet.payload = malformed_subnegotiation;
    packet.payload_length = sizeof(malformed_subnegotiation);
    packet.transport_length = sizeof(tcp) + packet.payload_length;
    assert(sn_protocol_decode(&packet, output, sizeof(output)));
    assert(strstr(output, "SB TERMINAL-TYPE(24) bytes=1 malformed") != NULL);
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
    assert(http_extension_calls == 0U);

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
    assert(http_extension_calls == 0U);

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

    enum sn_decoder_mode modes[SN_DECODER_MODULE_COUNT] = {0};
    modes[SN_DECODER_HTTP] = SN_DECODER_SIMPLIFIED;
    tcp[0] = 0x9cU;
    tcp[1] = 0x40U;
    tcp[2] = 0U;
    tcp[3] = 80U;
    tcp[12] = 0x50U;
    packet.payload = request;
    packet.payload_length = sizeof(request) - 1U;
    packet.transport_length = sizeof(tcp) + sizeof(request) - 1U;
    http_extension_calls = 0U;
    assert(sn_protocol_decode_with_modes(&packet, output, sizeof(output),
                                         false, false, modes));
    assert(http_extension_calls == 0U);
    assert(strstr(output, "custom=") == NULL);
    assert(sn_protocol_decode_with_modes(&packet, output, sizeof(output),
                                         false, true, modes));
    assert(http_extension_calls == 1U);
    assert(strstr(output, "custom=researcher") != NULL);
}

static void test_http_extension_output_contract(void)
{
    static const uint8_t payload[] = "GET /secret HTTP/1.1\r\nHost: example.test\r\n\r\n";
    char output[SN_HTTP_EXTENSION_OUTPUT_CAPACITY] = "not empty";

    assert(sn_http_decode_extension(payload, sizeof(payload) - 1U,
                                    output, sizeof(output)));
    assert(strcmp(output, "researcher") == 0);
}

static void test_dns_udp_tcp_and_compression_bounds(void)
{
    static const uint8_t query[] = {
        0x12U, 0x34U, 0x01U, 0x00U, 0x00U, 0x01U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U,
        0x03U, 'w', 'w', 'w', 0x07U, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03U, 'c', 'o', 'm', 0x00U, 0x00U, 0x01U, 0x00U, 0x01U
    };
    uint8_t response[49] = {0};
    uint8_t udp[8] = {0x30U, 0x39U, 0x00U, 0x35U, 0U, 0U, 0U, 0U};
    uint8_t tcp[20] = {0};
    uint8_t tcp_payload[2U + sizeof(query)] = {0};
    uint8_t malformed[18] = {0};
    struct sn_packet_view packet = {0};
    char output[SN_PACKET_DECODE_TEXT_CAPACITY];

    packet.protocol = 17U;
    packet.transport = udp;
    packet.transport_length = sizeof(udp) + sizeof(query);
    packet.transport_header_present = true;
    packet.payload = query;
    packet.payload_length = sizeof(query);
    udp[4] = 0U;
    udp[5] = (uint8_t)packet.transport_length;
    assert(sn_protocol_decode(&packet, output, sizeof(output)));
    assert(strstr(output, "DNS REQUEST id=0x1234 opcode=QUERY RD=1") != NULL);
    assert(strstr(output, "Question: www.example.com A/IN") != NULL);
    assert(strcmp(sn_protocol_security_advisory(&packet),
                  "SECURITY: WEAK; DNS on port 53 is usually cleartext") == 0);

    memcpy(response, query, sizeof(query));
    response[2] = 0x81U;
    response[3] = 0x80U;
    response[7] = 0x01U;
    response[sizeof(query)] = 0xc0U;
    response[sizeof(query) + 1U] = 0x0cU;
    response[sizeof(query) + 3U] = 0x01U;
    response[sizeof(query) + 5U] = 0x01U;
    response[sizeof(query) + 9U] = 60U;
    response[sizeof(query) + 11U] = 4U;
    response[sizeof(query) + 12U] = 203U;
    response[sizeof(query) + 13U] = 0U;
    response[sizeof(query) + 14U] = 113U;
    response[sizeof(query) + 15U] = 9U;
    packet.transport_length = sizeof(udp) + sizeof(response);
    udp[5] = (uint8_t)packet.transport_length;
    packet.payload = response;
    packet.payload_length = sizeof(response);
    assert(sn_protocol_decode(&packet, output, sizeof(output)));
    assert(strstr(output, "DNS RESPONSE id=0x1234 status=NOERROR opcode=QUERY") != NULL);
    assert(strstr(output, "Question: www.example.com A/IN") != NULL);
    assert(strstr(output, "Answer: A=203.0.113.9 ttl=60") != NULL);
    assert(strstr(output, "Counts: answers=1 authority=0 additional=0") != NULL);

    malformed[5] = 0U;
    malformed[5] = 1U;
    malformed[12] = 0xc0U;
    malformed[13] = 0x0cU;
    malformed[15] = 1U;
    malformed[17] = 1U;
    udp[5] = (uint8_t)(sizeof(udp) + sizeof(malformed));
    packet.transport_length = sizeof(udp) + sizeof(malformed);
    packet.payload = malformed;
    packet.payload_length = sizeof(malformed);
    assert(sn_protocol_decode(&packet, output, sizeof(output)));
    assert(strstr(output, "UDP 12345->53") != NULL);
    assert(strstr(output, "DNS REQUEST") == NULL);
    assert(strstr(output, "Question:") == NULL);
    assert(strcmp(sn_protocol_security_advisory(&packet),
                  "SECURITY: WEAK; DNS on port 53 is usually cleartext") == 0);

    tcp[0] = 0x30U;
    tcp[1] = 0x39U;
    tcp[2] = 0U;
    tcp[3] = 53U;
    tcp[12] = 0x50U;
    tcp_payload[1] = (uint8_t)sizeof(query);
    memcpy(tcp_payload + 2U, query, sizeof(query));
    packet.protocol = 6U;
    packet.transport = tcp;
    packet.transport_length = sizeof(tcp) + sizeof(tcp_payload);
    packet.payload = tcp_payload;
    packet.payload_length = sizeof(tcp_payload);
    assert(sn_protocol_decode(&packet, output, sizeof(output)));
    assert(strstr(output, "DNS REQUEST id=0x1234 opcode=QUERY RD=1") != NULL);
}

static void test_dns_txt_content_stays_hidden(void)
{
    static const uint8_t response[] = {
        0x12U, 0x35U, 0x81U, 0x80U, 0x00U, 0x01U, 0x00U, 0x01U,
        0x00U, 0x00U, 0x00U, 0x00U,
        0x01U, 'x', 0x03U, 'c', 'o', 'm', 0x00U, 0x00U, 0x10U, 0x00U, 0x01U,
        0xc0U, 0x0cU, 0x00U, 0x10U, 0x00U, 0x01U, 0x00U, 0x00U, 0x00U, 0x3cU,
        0x00U, 0x07U, 0x06U, 's', 'e', 'c', 'r', 'e', 't'
    };
    uint8_t udp[8] = {0U, 53U, 0x30U, 0x39U, 0U, 0U, 0U, 0U};
    struct sn_packet_view packet = {0};
    char output[SN_PACKET_DECODE_TEXT_CAPACITY];

    udp[4] = 0U;
    udp[5] = (uint8_t)(sizeof(udp) + sizeof(response));
    packet.protocol = 17U;
    packet.transport = udp;
    packet.transport_length = sizeof(udp) + sizeof(response);
    packet.transport_header_present = true;
    packet.payload = response;
    packet.payload_length = sizeof(response);
    assert(sn_protocol_decode(&packet, output, sizeof(output)));
    assert(strstr(output, "TXT strings=1 bytes=7 content=hidden ttl=60") != NULL);
    assert(strstr(output, "secret") == NULL);
}

static void test_dns_maximum_wire_name_is_bounded_in_output(void)
{
    const uint8_t label_lengths[] = {63U, 63U, 63U, 61U};
    uint8_t query[12U + 255U + 4U] = {0};
    uint8_t udp[8] = {0x30U, 0x39U, 0U, 53U, 0U, 0U, 0U, 0U};
    struct sn_packet_view packet = {0};
    char output[SN_PACKET_DECODE_TEXT_CAPACITY];
    size_t cursor = 12U;
    uint16_t udp_length = (uint16_t)(sizeof(udp) + sizeof(query));

    query[0] = 0x56U;
    query[1] = 0x79U;
    query[2] = 0x01U;
    query[5] = 0x01U;
    for (size_t index = 0U; index < sizeof(label_lengths); ++index) {
        query[cursor++] = label_lengths[index];
        memset(query + cursor, 'a', label_lengths[index]);
        cursor += label_lengths[index];
    }
    query[cursor++] = 0U;
    query[cursor++] = 0U;
    query[cursor++] = 1U;
    query[cursor++] = 0U;
    query[cursor++] = 1U;
    assert(cursor == sizeof(query));

    udp[4] = (uint8_t)(udp_length >> 8);
    udp[5] = (uint8_t)(udp_length & 0xffU);
    packet.protocol = 17U;
    packet.transport = udp;
    packet.transport_length = sizeof(udp) + sizeof(query);
    packet.transport_header_present = true;
    packet.payload = query;
    packet.payload_length = sizeof(query);
    assert(sn_protocol_decode(&packet, output, sizeof(output)));
    assert(strstr(output, "DNS REQUEST id=0x5679") != NULL);
    assert(strstr(output, "...") != NULL);
    assert(strstr(output, "SECURITY:") == NULL);
    assert(strcmp(sn_protocol_security_advisory(&packet),
                  "SECURITY: WEAK; DNS on port 53 is usually cleartext") == 0);
    assert(output[sizeof(output) - 1U] == '\0');
}

static void test_dhcp4_discover_offer_and_malformed_options(void)
{
    uint8_t message[250] = {0};
    uint8_t udp[8] = {0U, 68U, 0U, 67U, 1U, 0U, 0U, 0U};
    struct sn_packet_view packet = {0};
    char output[SN_PACKET_DECODE_TEXT_CAPACITY];

    message[0] = 1U;
    message[1] = 1U;
    message[2] = 6U;
    message[4] = 0x39U;
    message[5] = 0x03U;
    message[6] = 0xf3U;
    message[7] = 0x26U;
    memcpy(message + 28U, "\x00\x11\x22\x33\x44\x55", 6U);
    message[236] = 99U;
    message[237] = 130U;
    message[238] = 83U;
    message[239] = 99U;
    message[240] = 53U;
    message[241] = 1U;
    message[242] = 1U;
    message[243] = 55U;
    message[244] = 2U;
    message[245] = 1U;
    message[246] = 3U;
    message[247] = 255U;

    packet.protocol = 17U;
    packet.transport = udp;
    packet.transport_length = sizeof(udp) + 248U;
    packet.transport_header_present = true;
    packet.payload = message;
    packet.payload_length = 248U;
    assert(sn_protocol_decode(&packet, output, sizeof(output)));
    assert(strstr(output, "DHCPv4 Discover xid=0x3903f326 htype=1 chaddr=00:11:22:33:44:55") != NULL);
    assert(strstr(output, "lease=0 options=2") != NULL);

    message[242] = 2U;
    message[243] = 51U;
    message[244] = 4U;
    message[245] = 0U;
    message[246] = 0U;
    message[247] = 14U;
    message[248] = 16U;
    message[249] = 255U;
    packet.payload_length = sizeof(message);
    packet.transport_length = sizeof(udp) + sizeof(message);
    udp[5] = 2U;
    assert(sn_protocol_decode(&packet, output, sizeof(output)));
    assert(strstr(output, "DHCPv4 Offer") != NULL);
    assert(strstr(output, "lease=3600 options=2") != NULL);

    message[244] = 10U;
    assert(sn_protocol_decode(&packet, output, sizeof(output)));
    assert(strstr(output, "UDP 68->67") != NULL);
    assert(strstr(output, "DHCPv4 Discover") == NULL);
    assert(strstr(output, "DHCPv4 Offer") == NULL);

    packet.payload_length = 236U;
    packet.transport_length = sizeof(udp) + packet.payload_length;
    udp[4] = 0U;
    udp[5] = 244U;
    assert(sn_protocol_decode(&packet, output, sizeof(output)));
    assert(strstr(output, "BOOTP request xid=0x3903f326") != NULL);
}

static void test_tls_record_metadata_on_tcp(void)
{
    uint8_t tcp[20] = {0U, 0U, 1U, 0xbbU};
    uint8_t handshake[9] = {22U, 3U, 3U, 0U, 4U, 1U, 0U, 0U, 0U};
    uint8_t application_data[8] = {23U, 3U, 3U, 0U, 3U, 's', 'e', 'c'};
    struct sn_packet_view packet = {0};
    char output[SN_PACKET_DECODE_TEXT_CAPACITY];

    tcp[12] = 0x50U;
    packet.protocol = 6U;
    packet.transport = tcp;
    packet.transport_header_present = true;
    packet.payload = handshake;
    packet.payload_length = sizeof(handshake);
    packet.transport_length = sizeof(tcp) + sizeof(handshake);
    assert(sn_protocol_decode(&packet, output, sizeof(output)));
    assert(strstr(output, "TLS record=handshake version=0x0303 record-bytes=4") != NULL);
    assert(strstr(output, "handshake=ClientHello") != NULL);
    assert(strstr(output, "secret") == NULL);

    packet.payload = application_data;
    packet.payload_length = sizeof(application_data);
    packet.transport_length = sizeof(tcp) + sizeof(application_data);
    assert(sn_protocol_decode(&packet, output, sizeof(output)));
    assert(strstr(output, "TLS record=application-data version=0x0303 record-bytes=3") != NULL);
    assert(strstr(output, "sec") == NULL);

    handshake[8] = 1U;
    packet.payload = handshake;
    packet.payload_length = sizeof(handshake);
    packet.transport_length = sizeof(tcp) + sizeof(handshake);
    assert(sn_protocol_decode(&packet, output, sizeof(output)));
    assert(strstr(output, "TLS record=") == NULL);
}

static void test_rtp_rtcp_metadata_over_udp(void)
{
    uint8_t udp[8] = {0x4eU, 0x20U, 0x4eU, 0x21U, 0U, 0U, 0U, 0U};
    uint8_t rtp[13] = {0x80U, 0xe0U, 0U, 5U, 0U, 0U, 0U, 9U,
                       0x12U, 0x34U, 0x56U, 0x78U, 0xaaU};
    uint8_t rtcp[8] = {0x81U, 200U, 0U, 1U, 0x12U, 0x34U, 0x56U, 0x78U};
    struct sn_packet_view packet = {0};
    char output[SN_PACKET_DECODE_TEXT_CAPACITY];

    packet.protocol = 17U;
    packet.transport = udp;
    packet.transport_header_present = true;
    packet.payload = rtp;
    packet.payload_length = sizeof(rtp);
    packet.transport_length = sizeof(udp) + sizeof(rtp);
    udp[5] = (uint8_t)packet.transport_length;
    assert(sn_protocol_decode(&packet, output, sizeof(output)));
    assert(strstr(output, "RTP v2 pt=96 marker=1 seq=5 timestamp=9 ssrc=12345678 csrc=0 payload=1") != NULL);
    assert(strstr(output, "aa") == NULL);

    packet.payload = rtcp;
    packet.payload_length = sizeof(rtcp);
    packet.transport_length = sizeof(udp) + sizeof(rtcp);
    udp[5] = (uint8_t)packet.transport_length;
    assert(sn_protocol_decode(&packet, output, sizeof(output)));
    assert(strstr(output, "RTCP SR count=1 bytes=8") != NULL);

    rtp[0] = 0x8fU;
    packet.payload = rtp;
    packet.payload_length = 12U;
    packet.transport_length = sizeof(udp) + packet.payload_length;
    udp[5] = (uint8_t)packet.transport_length;
    assert(sn_protocol_decode(&packet, output, sizeof(output)));
    assert(strstr(output, "UDP 20000->20001") != NULL);
    assert(strstr(output, "RTP v2") == NULL);
}

static void test_quic_invariant_header_on_udp(void)
{
    uint8_t udp[8] = {0x30U, 0x39U, 0x01U, 0xbbU, 0U, 18U, 0U, 0U};
    uint8_t quic[10] = {0xc0U, 0U, 0U, 0U, 1U, 2U, 0xaaU, 0xbbU, 1U, 0xccU};
    struct sn_packet_view packet = {0};
    char output[SN_PACKET_DECODE_TEXT_CAPACITY];

    packet.protocol = 17U;
    packet.transport = udp;
    packet.transport_length = sizeof(udp) + sizeof(quic);
    packet.transport_header_present = true;
    packet.payload = quic;
    packet.payload_length = sizeof(quic);
    assert(sn_protocol_decode(&packet, output, sizeof(output)));
    assert(strstr(output, "QUIC v1 long-header type=0 version=0x00000001 dcid-len=2 scid-len=1") != NULL);
    assert(strstr(output, "aabb") == NULL);

    quic[5] = 20U;
    assert(sn_protocol_decode(&packet, output, sizeof(output)));
    assert(strstr(output, "UDP 12345->443") != NULL);
    assert(strstr(output, "QUIC") == NULL);

    quic[0] = 0x40U;
    packet.payload_length = 8U;
    udp[5] = 16U;
    packet.transport_length = sizeof(udp) + packet.payload_length;
    assert(sn_protocol_decode(&packet, output, sizeof(output)));
    assert(strstr(output, "QUIC short-header payload=7") != NULL);
}

static void test_syslog_radius_tacacs_metadata(void)
{
    static const uint8_t syslog[] = "<34>Oct 11 22:14:15 host app: private message";
    uint8_t radius[25] = {1U, 7U, 0U, 25U};
    uint8_t udp[8] = {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U};
    uint8_t tcp[20] = {0U, 20000U >> 8, (uint8_t)20000U, 0U, 0U, 0U, 0U, 0U,
                       0U, 0U, 0U, 0U, 0x50U};
    uint8_t tacacs[16] = {0xc0U, 1U, 1U, 0x80U, 0x12U, 0x34U, 0x56U, 0x78U,
                          0U, 0U, 0U, 4U, 's', 'e', 'c', 'r'};
    struct sn_packet_view packet = {0};
    char output[SN_PACKET_DECODE_TEXT_CAPACITY];

    packet.protocol = 17U;
    packet.transport = udp;
    packet.transport_header_present = true;
    packet.payload = syslog;
    packet.payload_length = sizeof(syslog) - 1U;
    packet.transport_length = sizeof(udp) + packet.payload_length;
    udp[0] = 0x30U;
    udp[1] = 0x39U;
    udp[2] = 2U;
    udp[3] = 2U;
    udp[5] = (uint8_t)packet.transport_length;
    assert(sn_protocol_decode(&packet, output, sizeof(output)));
    assert(strstr(output, "Syslog PRI=34 facility=4 severity=2") != NULL);
    assert(strstr(output, "private message") == NULL);

    packet.payload = radius;
    packet.payload_length = sizeof(radius);
    packet.transport_length = sizeof(udp) + sizeof(radius);
    udp[0] = (uint8_t)(1812U >> 8);
    udp[1] = (uint8_t)1812U;
    udp[2] = 0xc3U;
    udp[3] = 0x50U;
    udp[5] = (uint8_t)packet.transport_length;
    radius[20] = 1U;
    radius[21] = 5U;
    radius[22] = 'p';
    radius[23] = 'w';
    assert(sn_protocol_decode(&packet, output, sizeof(output)));
    assert(strstr(output, "RADIUS Access-Request id=7 bytes=25 attributes=1") != NULL);
    assert(strstr(output, "pw") == NULL);

    radius[21] = 9U;
    assert(sn_protocol_decode(&packet, output, sizeof(output)));
    assert(strstr(output, "UDP 1812->50000") != NULL);
    assert(strstr(output, "RADIUS Access-") == NULL);

    packet.protocol = 6U;
    packet.transport = tcp;
    packet.transport_length = sizeof(tcp) + sizeof(tacacs);
    packet.payload = tacacs;
    packet.payload_length = sizeof(tacacs);
    tcp[2] = 0U;
    tcp[3] = 49U;
    assert(sn_protocol_decode(&packet, output, sizeof(output)));
    assert(strstr(output, "TACACS+ authentication version=0xc0 seq=1") != NULL);
    assert(strstr(output, "secret") == NULL);
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
    assert(strstr(output, "NTP SERVER RESPONSE v4") != NULL);
    assert(strcmp(sn_protocol_security_advisory(&packet),
                  "SECURITY: WEAK; NTP is unauthenticated plaintext, use NTS") == 0);
    assert(strstr(output, "Status: leap=no-warning stratum=2 (secondary)") != NULL);
    assert(strstr(output, "Parameters: poll=6 precision=-20") != NULL);
    assert(strstr(output, "refid=47505300") != NULL);
    assert(strstr(output, "timestamp") == NULL);
    assert(strstr(output, "UDP 123->40000") == NULL);

    ntp[0] = 0x23U;
    ntp[1] = 0U;
    assert(sn_protocol_decode(&packet, output, sizeof(output)));
    assert(strstr(output, "NTP CLIENT REQUEST v4") != NULL);
    assert(strstr(output, "stratum=0 (unspecified/KoD)") != NULL);

    packet.payload_length = sizeof(ntp) - 1U;
    udp[5] = 55U;
    packet.transport_length = 55U;
    assert(sn_protocol_decode(&packet, output, sizeof(output)));
    assert(strstr(output, "UDP 123->40000") != NULL);
    assert(strstr(output, "NTP SERVER RESPONSE") == NULL);
    assert(strcmp(sn_protocol_security_advisory(&packet),
                  "SECURITY: WEAK; NTP is unauthenticated plaintext, use NTS") == 0);

    packet.payload_length = sizeof(ntp);
    udp[5] = 56U;
    packet.transport_length = sizeof(udp);
    ntp[0] = 0x27U;
    assert(sn_protocol_decode(&packet, output, sizeof(output)));
    assert(strstr(output, "UDP 123->40000") != NULL);
    assert(strstr(output, "NTP SERVER RESPONSE") == NULL);
    assert(strcmp(sn_protocol_security_advisory(&packet),
                  "SECURITY: WEAK; NTP is unauthenticated plaintext, use NTS") == 0);

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
    assert(strstr(output, "SECURITY:") == NULL);
    assert(strcmp(sn_protocol_security_advisory(&packet),
                  "SECURITY: unencrypted and unauthenticated diagnostic traffic") == 0);
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
        sn_decode_icmpv6, sn_decode_ndp,
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
    test_tainted_extension_gate_and_output_sanitizing();
    test_protocol_mode_selects_extension_or_simplified_decoder();
    test_tcp_and_udp_metadata();
    test_telnet_negotiation_is_decoded_without_payload_text();
    test_telnet_commands_and_truncated_sequences();
    test_http_summaries_hide_paths_and_sensitive_headers();
    test_http_extension_output_contract();
    test_dns_udp_tcp_and_compression_bounds();
    test_dns_txt_content_stays_hidden();
    test_dns_maximum_wire_name_is_bounded_in_output();
    test_dhcp4_discover_offer_and_malformed_options();
    test_tls_record_metadata_on_tcp();
    test_rtp_rtcp_metadata_over_udp();
    test_quic_invariant_header_on_udp();
    test_syslog_radius_tacacs_metadata();
    test_ntp_metadata_and_validation();
    test_snmp_metadata_and_malformed_ber();
    test_igmp_vrrp_and_icmp();
    test_invalid_decoder_arguments();
    test_protocol_placeholders_are_inert();
    puts("protocol decoder tests passed");
    return 0;
}