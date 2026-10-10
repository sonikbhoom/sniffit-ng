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
#define FRAME_LENGTH (ETHERNET_LENGTH + IPV4_LENGTH + TCP_LENGTH)

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
    uint8_t frame[FRAME_LENGTH];
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
    size_t packet_index = 0U;

    create_capture(path, sizeof(path));
    capture = sn_capture_open_offline(path, error, sizeof(error));
    assert(capture != NULL);
    sn_monitor_init(&monitor, 10000000000ULL);

    while ((capture_result = sn_capture_next(capture, &packet,
                                              error, sizeof(error))) == SN_CAPTURE_PACKET) {
        monitor_result = sn_monitor_process(&monitor, &packet);
        if (packet_index == 0U) {
            assert(packet.captured_length == FRAME_LENGTH);
            assert(packet.wire_length == FRAME_LENGTH);
            assert(monitor_result == SN_MONITOR_PROCESSED);
        } else if (packet_index == 1U) {
            assert(packet.captured_length == ETHERNET_LENGTH - 1U);
            assert(packet.wire_length == FRAME_LENGTH);
            assert(monitor_result == SN_MONITOR_TRUNCATED);
        } else {
            assert(packet_index == 2U);
            assert(monitor_result == SN_MONITOR_MALFORMED);
        }
        ++packet_index;
    }

    assert(capture_result == SN_CAPTURE_EOF);
    assert(packet_index == 3U);
    assert(monitor.stats.captured_packets == 3U);
    assert(monitor.stats.ipv4_packets == 1U);
    assert(monitor.stats.tcp_packets == 1U);
    assert(monitor.stats.truncated_packets == 1U);
    assert(monitor.stats.malformed_packets == 1U);
    assert(sn_flow_table_count(&monitor.flows) == 1U);

    sn_capture_close(capture);
    assert(unlink(path) == 0);
    puts("capture pipeline tests passed");
    return 0;
}
