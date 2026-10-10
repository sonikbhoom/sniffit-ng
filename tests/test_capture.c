#define _POSIX_C_SOURCE 200809L

#include "sniffit_ng/capture.h"

#include <assert.h>
#include <pcap/pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void write_be16(uint8_t *bytes, uint16_t value)
{
    bytes[0] = (uint8_t)(value >> 8);
    bytes[1] = (uint8_t)(value & 0xffU);
}

static void create_test_pcap(char *path, size_t path_capacity, int link_type)
{
    char path_template[] = "/tmp/sniffit-ng-capture-XXXXXX";
    uint8_t frame[14] = {0};
    struct pcap_pkthdr header = {0};
    pcap_t *dead_capture;
    pcap_dumper_t *dumper;
    int fd = mkstemp(path_template);

    assert(fd >= 0);
    assert(close(fd) == 0);
    assert(snprintf(path, path_capacity, "%s", path_template) > 0);

    dead_capture = pcap_open_dead(link_type, 256);
    assert(dead_capture != NULL);
    dumper = pcap_dump_open(dead_capture, path);
    assert(dumper != NULL);

    write_be16(frame + 12U, 0x0800U);
    header.ts.tv_sec = 123;
    header.ts.tv_usec = 456789;
    header.caplen = sizeof(frame);
    header.len = sizeof(frame) + 4U;
    pcap_dump((u_char *)dumper, &header, frame);
    assert(pcap_dump_flush(dumper) == 0);

    pcap_dump_close(dumper);
    pcap_close(dead_capture);
}

static void test_offline_packet_lifetime_and_eof(void)
{
    char path[64];
    char error[256] = {0};
    struct sn_capture_packet packet;
    struct sn_capture *capture;

    create_test_pcap(path, sizeof(path), DLT_EN10MB);
    capture = sn_capture_open_offline(path, error, sizeof(error));
    assert(capture != NULL);
    assert(sn_capture_next(capture, &packet, error, sizeof(error)) == SN_CAPTURE_PACKET);
    assert(packet.data != NULL);
    assert(packet.captured_length == 14U);
    assert(packet.wire_length == 18U);
    assert(packet.timestamp.tv_sec == 123);
    assert(packet.timestamp.tv_usec == 456789);
    assert(sn_capture_next(capture, &packet, error, sizeof(error)) == SN_CAPTURE_EOF);
    assert(packet.data == NULL);
    sn_capture_close(capture);
    assert(unlink(path) == 0);
}

static void test_unsupported_link_type_is_rejected(void)
{
    char path[64];
    char error[256] = {0};

    create_test_pcap(path, sizeof(path), DLT_RAW);
    assert(sn_capture_open_offline(path, error, sizeof(error)) == NULL);
    assert(strstr(error, "unsupported link type") != NULL);
    assert(unlink(path) == 0);
}

static void test_invalid_sources_and_arguments(void)
{
    char error[256] = {0};
    struct sn_capture_packet packet;

    assert(sn_capture_open_offline(NULL, error, sizeof(error)) == NULL);
    assert(sn_capture_open_offline("", error, sizeof(error)) == NULL);
    assert(sn_capture_open_live("", 65535, false, 1000, error, sizeof(error)) == NULL);
    assert(sn_capture_open_live("eth0", 0, false, 1000, error, sizeof(error)) == NULL);
    assert(sn_capture_next(NULL, &packet, error, sizeof(error)) == SN_CAPTURE_ERROR);
}

int main(void)
{
    test_offline_packet_lifetime_and_eof();
    test_unsupported_link_type_is_rejected();
    test_invalid_sources_and_arguments();
    puts("capture tests passed");
    return 0;
}
