#define _POSIX_C_SOURCE 200809L

#include "sniffit_ng/capture.h"
#include "sniffit_ng/pcap_writer.h"

#include <assert.h>
#include <pcap/pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void make_temporary_path(char *path, size_t capacity)
{
    char template[] = "/tmp/sniffit-ng-write-pcap-XXXXXX";
    int descriptor = mkstemp(template);

    assert(descriptor >= 0);
    assert(close(descriptor) == 0);
    assert(unlink(template) == 0);
    assert(snprintf(path, capacity, "%s", template) > 0);
}

static void test_round_trip_link_type(enum sn_packet_link_type link_type,
                                      size_t captured_length)
{
    uint8_t bytes[24];
    char path[64];
    char error[256] = {0};
    struct sn_capture_packet packet = {0};
    struct sn_capture_packet read_packet;
    struct sn_pcap_writer *writer;
    struct sn_capture *capture;
    struct stat metadata;

    for (size_t index = 0U; index < sizeof(bytes); ++index) {
        bytes[index] = (uint8_t)(index + 1U);
    }
    make_temporary_path(path, sizeof(path));
    writer = sn_pcap_writer_open(path, link_type, error, sizeof(error));
    assert(writer != NULL);
    packet.data = bytes;
    packet.captured_length = captured_length;
    packet.wire_length = captured_length + 5U;
    packet.link_type = link_type;
    packet.timestamp.tv_sec = 1234;
    packet.timestamp.tv_usec = 567890;
    assert(sn_pcap_writer_write(writer, &packet));
    assert(sn_pcap_writer_close(writer));

    assert(stat(path, &metadata) == 0);
    assert((metadata.st_mode & 0777U) == 0600U);
    assert(sn_pcap_writer_open(path, link_type, error, sizeof(error)) == NULL);

    capture = sn_capture_open_offline(path, error, sizeof(error));
    assert(capture != NULL);
    assert(sn_capture_next(capture, &read_packet, error, sizeof(error)) == SN_CAPTURE_PACKET);
    assert(read_packet.link_type == link_type);
    assert(read_packet.captured_length == captured_length);
    assert(read_packet.wire_length == captured_length + 5U);
    assert(read_packet.timestamp.tv_sec == 1234);
    assert(read_packet.timestamp.tv_usec == 567890);
    assert(memcmp(read_packet.data, bytes, captured_length) == 0);
    sn_capture_close(capture);
    assert(unlink(path) == 0);
}

static void test_invalid_writer_inputs(void)
{
    uint8_t bytes[1] = {0U};
    char path[64];
    char error[256] = {0};
    struct sn_pcap_writer *writer;
    struct sn_capture_packet packet = {0};

    make_temporary_path(path, sizeof(path));
    writer = sn_pcap_writer_open(path, SN_PACKET_LINK_ETHERNET,
                                 error, sizeof(error));
    assert(writer != NULL);
    packet.data = bytes;
    packet.captured_length = sizeof(bytes);
    packet.wire_length = sizeof(bytes);
    packet.link_type = SN_PACKET_LINK_LINUX_SLL;
    packet.timestamp.tv_usec = 0;
    assert(!sn_pcap_writer_write(writer, &packet));
    packet.link_type = SN_PACKET_LINK_ETHERNET;
    packet.timestamp.tv_usec = 1000000;
    assert(!sn_pcap_writer_write(writer, &packet));
    assert(sn_pcap_writer_close(writer));
    assert(unlink(path) == 0);
}

int main(void)
{
    test_round_trip_link_type(SN_PACKET_LINK_ETHERNET, 24U);
    test_round_trip_link_type(SN_PACKET_LINK_LINUX_SLL, 16U);
    test_invalid_writer_inputs();
    puts("pcap writer tests passed");
    return 0;
}
