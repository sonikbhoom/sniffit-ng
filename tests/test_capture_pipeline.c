#define _POSIX_C_SOURCE 200809L

#include "sniffit_ng/capture.h"
#include "sniffit_ng/monitor.h"

#include <assert.h>
#include <pcap/pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ETHERNET_LENGTH 14U
#define IPV4_LENGTH 20U
#define TCP_LENGTH 20U
#define UDP_LENGTH 8U
#define FRAME_LENGTH (ETHERNET_LENGTH + IPV4_LENGTH + TCP_LENGTH)
#define DNS_MESSAGE_CAPACITY 64U
#define DNS_FRAME_CAPACITY \
    (ETHERNET_LENGTH + IPV4_LENGTH + UDP_LENGTH + DNS_MESSAGE_CAPACITY)

static const uint8_t dns_query[] = {
    0x12U, 0x34U, 0x01U, 0x00U, 0x00U, 0x01U, 0x00U, 0x00U,
    0x00U, 0x00U, 0x00U, 0x00U,
    0x03U, 'w', 'w', 'w', 0x07U, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    0x03U, 'c', 'o', 'm', 0x00U, 0x00U, 0x01U, 0x00U, 0x01U
};

static void write_be16(uint8_t *bytes, uint16_t value)
{
    bytes[0] = (uint8_t)(value >> 8);
    bytes[1] = (uint8_t)(value & 0xffU);
}

static void make_tcp_frame(uint8_t *frame)
{
    uint8_t *ip = frame + ETHERNET_LENGTH;
    uint8_t *tcp = ip + IPV4_LENGTH;

    memset(frame, 0, FRAME_LENGTH);
    write_be16(frame + 12U, 0x0800U);
    ip[0] = 0x45U;
    write_be16(ip + 2U, IPV4_LENGTH + TCP_LENGTH);
    ip[8] = 64U;
    ip[9] = 6U;
    ip[12] = 192U;
    ip[14] = 2U;
    ip[15] = 1U;
    ip[16] = 192U;
    ip[18] = 2U;
    ip[19] = 2U;
    write_be16(tcp, 12345U);
    write_be16(tcp + 2U, 443U);
    tcp[12] = 0x50U;
}

static size_t make_dns_frame(uint8_t *frame,
                             const uint8_t *message,
                             size_t message_length,
                             bool response,
                             uint16_t source_port,
                             uint16_t destination_port)
{
    uint8_t *ip = frame + ETHERNET_LENGTH;
    uint8_t *udp = ip + IPV4_LENGTH;

    memset(frame, 0, DNS_FRAME_CAPACITY);
    write_be16(frame + 12U, 0x0800U);
    ip[0] = 0x45U;
    write_be16(ip + 2U, (uint16_t)(IPV4_LENGTH + UDP_LENGTH + message_length));
    ip[8] = 64U;
    ip[9] = 17U;
    if (response) {
        ip[12] = 198U;
        ip[14] = 51U;
        ip[15] = 53U;
        ip[16] = 192U;
        ip[19] = 10U;
    } else {
        ip[12] = 192U;
        ip[15] = 10U;
        ip[16] = 198U;
        ip[18] = 51U;
        ip[19] = 53U;
    }
    write_be16(udp, source_port);
    write_be16(udp + 2U, destination_port);
    write_be16(udp + 4U, (uint16_t)(UDP_LENGTH + message_length));
    memcpy(udp + UDP_LENGTH, message, message_length);
    return ETHERNET_LENGTH + IPV4_LENGTH + UDP_LENGTH + message_length;
}

static void dump_packet(pcap_dumper_t *dumper,
                        const uint8_t *bytes,
                        uint32_t captured_length,
                        uint32_t wire_length,
                        long seconds)
{
    struct pcap_pkthdr header = {0};

    header.ts.tv_sec = seconds;
    header.ts.tv_usec = 250000;
    header.caplen = captured_length;
    header.len = wire_length;
    pcap_dump((u_char *)dumper, &header, bytes);
}

static void create_capture(char *path, size_t path_capacity)
{
    char path_template[] = "/tmp/sniffit-ng-pipeline-XXXXXX";
    uint8_t frame[DNS_FRAME_CAPACITY];
    uint8_t response[sizeof(dns_query) + 16U];
    uint8_t malformed_dns[18] = {
        0x56U, 0x78U, 0x01U, 0x00U, 0x00U, 0x01U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0xc0U, 0x0cU,
        0x00U, 0x01U, 0x00U, 0x01U
    };
    size_t dns_frame_length;
    pcap_t *dead_capture;
    pcap_dumper_t *dumper;
    int descriptor = mkstemp(path_template);

    assert(descriptor >= 0);
    assert(close(descriptor) == 0);
    assert(snprintf(path, path_capacity, "%s", path_template) > 0);
    dead_capture = pcap_open_dead(DLT_EN10MB, 256);
    assert(dead_capture != NULL);
    dumper = pcap_dump_open(dead_capture, path);
    assert(dumper != NULL);

    make_tcp_frame(frame);
    dump_packet(dumper, frame, FRAME_LENGTH, FRAME_LENGTH, 1L);
    dump_packet(dumper, frame, ETHERNET_LENGTH - 1U, FRAME_LENGTH, 2L);
    write_be16(frame + ETHERNET_LENGTH + 2U, IPV4_LENGTH - 1U);
    dump_packet(dumper, frame, FRAME_LENGTH, FRAME_LENGTH, 3L);

    memcpy(response, dns_query, sizeof(dns_query));
    response[2] = 0x81U;
    response[3] = 0x80U;
    response[7] = 0x01U;
    response[33] = 0xc0U;
    response[34] = 0x0cU;
    response[35] = 0U;
    response[36] = 1U;
    response[37] = 0U;
    response[38] = 1U;
    response[42] = 60U;
    response[44] = 4U;
    response[45] = 203U;
    response[46] = 0U;
    response[47] = 113U;
    response[48] = 9U;
    dns_frame_length = make_dns_frame(frame, response, sizeof(response), true,
                                      53U, 12345U);
    dump_packet(dumper, frame, (uint32_t)dns_frame_length,
                (uint32_t)dns_frame_length, 4L);

    dns_frame_length = make_dns_frame(frame, dns_query, sizeof(dns_query), false,
                                       12345U, 53U);
    dump_packet(dumper, frame, (uint32_t)(dns_frame_length - 1U),
                (uint32_t)dns_frame_length, 5L);

    dns_frame_length = make_dns_frame(frame, malformed_dns, sizeof(malformed_dns),
                                       false, 12345U, 53U);
    dump_packet(dumper, frame, (uint32_t)dns_frame_length,
                (uint32_t)dns_frame_length, 6L);
    assert(pcap_dump_flush(dumper) == 0);
    pcap_dump_close(dumper);
    pcap_close(dead_capture);
}

int main(void)
{
    char path[80];
    char error[256] = {0};
    struct sn_capture *capture;
    struct sn_capture_packet packet;
    struct sn_monitor monitor;
    enum sn_capture_result capture_result;
    enum sn_monitor_result monitor_result;
    const struct sn_flow *dns_flow = NULL;
    size_t packet_index = 0U;

    create_capture(path, sizeof(path));
    capture = sn_capture_open_offline(path, error, sizeof(error));
    assert(capture != NULL);
    sn_monitor_init(&monitor, 10000000000ULL);

    while ((capture_result = sn_capture_next(capture, &packet,
                                              error, sizeof(error))) == SN_CAPTURE_PACKET) {
        monitor_result = sn_monitor_process(&monitor, &packet);
        switch (packet_index) {
        case 0U:
            assert(packet.captured_length == FRAME_LENGTH);
            assert(packet.wire_length == FRAME_LENGTH);
            assert(monitor_result == SN_MONITOR_PROCESSED);
            break;
        case 1U:
            assert(packet.captured_length == ETHERNET_LENGTH - 1U);
            assert(packet.wire_length == FRAME_LENGTH);
            assert(monitor_result == SN_MONITOR_TRUNCATED);
            break;
        case 2U:
            assert(monitor_result == SN_MONITOR_MALFORMED);
            break;
        case 3U:
        case 5U:
            assert(monitor_result == SN_MONITOR_PROCESSED);
            break;
        case 4U:
            assert(monitor_result == SN_MONITOR_TRUNCATED);
            break;
        default:
            assert(false);
        }
        ++packet_index;
    }

    assert(capture_result == SN_CAPTURE_EOF);
    assert(packet_index == 6U);
    assert(monitor.stats.captured_packets == 6U);
    assert(monitor.stats.tcp_packets == 1U);
    assert(monitor.stats.truncated_packets == 2U);
    assert(monitor.stats.malformed_packets == 1U);
    assert(sn_flow_table_count(&monitor.flows) == 2U);
    for (size_t index = 0U; index < SN_FLOW_TABLE_CAPACITY; ++index) {
        const struct sn_flow *flow = &monitor.flows.entries[index];
        if (flow->active && flow->protocol == 17U &&
            (flow->endpoints[0].port == 53U || flow->endpoints[1].port == 53U)) {
            dns_flow = flow;
            break;
        }
    }
    assert(dns_flow != NULL);
    assert(dns_flow->decode_history_count == 2U);
    assert(strstr(sn_flow_decode_history_at(dns_flow, 0U)->text,
                  "DNS RESPONSE id=0x1234 status=NOERROR") != NULL);
    assert(strstr(sn_flow_decode_history_at(dns_flow, 0U)->text,
                  "Answer: A=203.0.113.9 ttl=60") != NULL);
    assert(strstr(sn_flow_decode_history_at(dns_flow, 1U)->text,
                  "UDP 12345->53") != NULL);

    sn_capture_close(capture);
    assert(unlink(path) == 0);
    puts("capture pipeline tests passed");
    return 0;
}
