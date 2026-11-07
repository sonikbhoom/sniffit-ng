#define _POSIX_C_SOURCE 200809L

#include "sniffit_ng/capture.h"
#include "sniffit_ng/arp_state.h"
#include "sniffit_ng/arp_replay.h"
#include "sniffit_ng/monitor.h"
#include "sniffit_ng/packet_inspect.h"

#include <assert.h>
#include <dirent.h>
#include <pcap/pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
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

static void make_telnet_probe_frame(uint8_t *frame)
{
    uint8_t *ip = frame + ETHERNET_LENGTH;
    uint8_t *tcp = ip + IPV4_LENGTH;

    memset(frame, 0, FRAME_LENGTH);
    frame[6] = 0x02U;
    frame[11] = 0x01U;
    write_be16(frame + 12U, 0x0800U);
    ip[0] = 0x45U;
    write_be16(ip + 2U, IPV4_LENGTH + TCP_LENGTH);
    ip[8] = 51U;
    ip[9] = 6U;
    ip[12] = 221U;
    ip[13] = 156U;
    ip[14] = 241U;
    ip[15] = 83U;
    ip[16] = 174U;
    ip[17] = 88U;
    ip[18] = 220U;
    ip[19] = 62U;
    write_be16(tcp, 60255U);
    write_be16(tcp + 2U, 23U);
    tcp[4] = 0x12U;
    tcp[5] = 0x34U;
    tcp[12] = 0x50U;
    tcp[13] = 0x02U;
    write_be16(tcp + 14U, 64240U);
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

static char *inspect_packet(const struct sn_capture_packet *packet,
                            size_t packet_number)
{
    char *inspection = NULL;
    size_t inspection_length = 0U;
    FILE *stream = open_memstream(&inspection, &inspection_length);

    assert(stream != NULL);
    assert(sn_packet_inspect(stream, packet, packet_number));
    assert(fclose(stream) == 0);
    assert(inspection_length == strlen(inspection));
    return inspection;
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

    make_telnet_probe_frame(frame);
    dump_packet(dumper, frame, FRAME_LENGTH, FRAME_LENGTH, 4L);
    dump_packet(dumper, frame, FRAME_LENGTH - 1U, FRAME_LENGTH, 5L);
    frame[ETHERNET_LENGTH + IPV4_LENGTH + 12U] = 0x40U;
    dump_packet(dumper, frame, FRAME_LENGTH, FRAME_LENGTH, 6L);

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
                (uint32_t)dns_frame_length, 7L);

    dns_frame_length = make_dns_frame(frame, dns_query, sizeof(dns_query), false,
                                       12345U, 53U);
    dump_packet(dumper, frame, (uint32_t)(dns_frame_length - 1U),
                (uint32_t)dns_frame_length, 8L);

    dns_frame_length = make_dns_frame(frame, malformed_dns, sizeof(malformed_dns),
                                       false, 12345U, 53U);
    dump_packet(dumper, frame, (uint32_t)dns_frame_length,
                (uint32_t)dns_frame_length, 9L);
    assert(pcap_dump_flush(dumper) == 0);
    pcap_dump_close(dumper);
    pcap_close(dead_capture);
}

#ifdef DLT_LINUX_SLL
static void verify_arp_sll_pipeline(void)
{
    char input_path[] = "/tmp/sniffit-ng-arp-sll-XXXXXX";
    char directory[] = "/tmp/sniffit-ng-arp-sll-log-XXXXXX";
    char output_path[256];
    char error[256] = {0};
    uint8_t frame[48] = {
        [14] = 0x81U, [15] = 0x00U, [18] = 0x08U, [19] = 0x06U,
        [21] = 1U, [22] = 0x08U, [24] = 6U, [25] = 4U, [27] = 1U,
        [28] = 0x02U, [33] = 1U, [34] = 192U, [37] = 1U, [44] = 192U, [47] = 2U
    };
    struct sn_arp_config config;
    struct sn_arp_replay_stats stats;
    struct sn_capture *capture;
    struct sn_capture_packet packet;
    pcap_t *dead_capture;
    pcap_dumper_t *dumper;
    DIR *stream;
    struct dirent *entry;
    unsigned int archives = 0U;
    int descriptor = mkstemp(input_path);

    assert(descriptor >= 0 && close(descriptor) == 0);
    assert(mkdtemp(directory) != NULL);
    dead_capture = pcap_open_dead(DLT_LINUX_SLL, 256);
    assert(dead_capture != NULL);
    dumper = pcap_dump_open(dead_capture, input_path);
    assert(dumper != NULL);
    dump_packet(dumper, frame, sizeof(frame), sizeof(frame), 1L);
    assert(pcap_dump_flush(dumper) == 0);
    pcap_dump_close(dumper);
    pcap_close(dead_capture);
    sn_arp_config_init(&config);
    config.rotation.address_logging = false;
    assert(snprintf(config.log_directory, sizeof(config.log_directory), "%s", directory) > 0);
    assert(sn_arp_replay_file(input_path, &config, &stats, error, sizeof(error)));
    assert(stats.state.decoded == 1U && stats.state.history_count == 1U);
    assert(sn_arp_state_at(&stats.state, 0U)->link_type == SN_PACKET_LINK_LINUX_SLL);
    stream = opendir(directory);
    assert(stream != NULL);
    while ((entry = readdir(stream)) != NULL) {
        if (entry->d_name[0] == '.') {
            continue;
        }
        assert(snprintf(output_path, sizeof(output_path), "%s/%s", directory, entry->d_name) > 0);
        if (strstr(entry->d_name, ".pcap") != NULL && strstr(entry->d_name, ".owner") == NULL) {
            ++archives;
            capture = sn_capture_open_offline(output_path, error, sizeof(error));
            assert(capture != NULL);
            assert(sn_capture_next(capture, &packet, error, sizeof(error)) == SN_CAPTURE_PACKET);
            assert(packet.link_type == SN_PACKET_LINK_LINUX_SLL);
            assert(packet.captured_length == sizeof(frame) && memcmp(packet.data, frame, sizeof(frame)) == 0);
            assert(sn_capture_next(capture, &packet, error, sizeof(error)) == SN_CAPTURE_EOF);
            sn_capture_close(capture);
        }
        assert(unlink(output_path) == 0);
    }
    assert(closedir(stream) == 0 && archives == 1U);
    assert(rmdir(directory) == 0 && unlink(input_path) == 0);
}

static void verify_sll_inspection(void)
{
    char path_template[] = "/tmp/sniffit-ng-sll-inspect-XXXXXX";
    uint8_t frame[16U + IPV4_LENGTH + TCP_LENGTH] = {0};
    uint8_t *ip = frame + 16U;
    uint8_t *tcp = ip + IPV4_LENGTH;
    char error[256] = {0};
    char *inspection = NULL;
    size_t inspection_length = 0U;
    struct sn_capture_packet packet;
    struct sn_capture *capture;
    pcap_t *dead_capture;
    pcap_dumper_t *dumper;
    FILE *stream;
    int descriptor = mkstemp(path_template);

    assert(descriptor >= 0);
    assert(close(descriptor) == 0);
    frame[1] = 4U;
    frame[3] = 1U;
    frame[5] = 6U;
    frame[6] = 0x02U;
    frame[7] = 0xaaU;
    frame[8] = 0xbbU;
    frame[9] = 0xccU;
    frame[10] = 0xddU;
    frame[11] = 0xeeU;
    write_be16(frame + 14U, 0x0800U);
    ip[0] = 0x45U;
    write_be16(ip + 2U, IPV4_LENGTH + TCP_LENGTH);
    ip[8] = 64U;
    ip[9] = 6U;
    ip[12] = 203U;
    ip[13] = 0U;
    ip[14] = 113U;
    ip[15] = 7U;
    ip[16] = 192U;
    ip[17] = 0U;
    ip[18] = 2U;
    ip[19] = 10U;
    write_be16(tcp, 60255U);
    write_be16(tcp + 2U, 23U);
    tcp[12] = 0x50U;
    tcp[13] = 0x12U;

    dead_capture = pcap_open_dead(DLT_LINUX_SLL, (int)sizeof(frame));
    assert(dead_capture != NULL);
    dumper = pcap_dump_open(dead_capture, path_template);
    assert(dumper != NULL);
    dump_packet(dumper, frame, sizeof(frame), sizeof(frame), 10L);
    assert(pcap_dump_flush(dumper) == 0);
    pcap_dump_close(dumper);
    pcap_close(dead_capture);

    capture = sn_capture_open_offline(path_template, error, sizeof(error));
    assert(capture != NULL);
    assert(sn_capture_next(capture, &packet, error, sizeof(error)) ==
           SN_CAPTURE_PACKET);
    assert(packet.link_type == SN_PACKET_LINK_LINUX_SLL);
    stream = open_memstream(&inspection, &inspection_length);
    assert(stream != NULL);
    assert(sn_packet_inspect(stream, &packet, 1U));
    assert(fclose(stream) == 0);
    assert(strstr(inspection, "Linux-SLL packet_type=outgoing(4)") != NULL);
    assert(strstr(inspection, "observed_src=02aabbccddee") != NULL);
    assert(strstr(inspection, "flags=0x12 [ACK|SYN]") != NULL);
    free(inspection);
    assert(sn_capture_next(capture, &packet, error, sizeof(error)) == SN_CAPTURE_EOF);
    sn_capture_close(capture);
    assert(unlink(path_template) == 0);
}
#endif

static void verify_arp_pipeline(void)
{
    char path[] = "/tmp/sniffit-ng-arp-pipeline-XXXXXX";
    char error[256] = {0};
    uint8_t frame[42] = {
        [12] = 0x08U, [13] = 0x06U,
        [15] = 1U, [16] = 0x08U, [18] = 6U, [19] = 4U, [21] = 1U,
        [22] = 0x02U, [27] = 1U, [28] = 192U, [30] = 2U, [31] = 1U,
        [38] = 192U, [40] = 2U, [41] = 2U
    };
    struct sn_arp_state state;
    struct sn_capture_packet packet;
    struct sn_capture *capture;
    pcap_t *dead_capture;
    pcap_dumper_t *dumper;
    int descriptor = mkstemp(path);

    assert(descriptor >= 0);
    assert(close(descriptor) == 0);
    dead_capture = pcap_open_dead(DLT_EN10MB, 256);
    assert(dead_capture != NULL);
    dumper = pcap_dump_open(dead_capture, path);
    assert(dumper != NULL);
    dump_packet(dumper, frame, sizeof(frame), sizeof(frame), 1L);
    frame[21] = 2U;
    dump_packet(dumper, frame, sizeof(frame), sizeof(frame), 2L);
    dump_packet(dumper, frame, sizeof(frame) - 1U, sizeof(frame), 3L);
    frame[18] = 0U;
    dump_packet(dumper, frame, sizeof(frame), sizeof(frame), 4L);
    frame[13] = 0U;
    dump_packet(dumper, frame, sizeof(frame), sizeof(frame), 5L);
    dump_packet(dumper, frame, 13U, sizeof(frame), 6L);
    frame[13] = 0x06U;
    frame[18] = 6U;
    frame[21] = 3U;
    dump_packet(dumper, frame, sizeof(frame), sizeof(frame), 7L);
    assert(pcap_dump_flush(dumper) == 0);
    pcap_dump_close(dumper);
    pcap_close(dead_capture);

    capture = sn_capture_open_offline(path, error, sizeof(error));
    assert(capture != NULL);
    sn_arp_state_init(&state);
    assert(sn_capture_next(capture, &packet, error, sizeof(error)) == SN_CAPTURE_PACKET);
    assert(sn_arp_state_process(&state, &packet) == SN_PACKET_OK);
    assert(sn_capture_next(capture, &packet, error, sizeof(error)) == SN_CAPTURE_PACKET);
    assert(sn_arp_state_process(&state, &packet) == SN_PACKET_OK);
    assert(sn_capture_next(capture, &packet, error, sizeof(error)) == SN_CAPTURE_PACKET);
    assert(sn_arp_state_process(&state, &packet) == SN_PACKET_TRUNCATED);
    assert(sn_capture_next(capture, &packet, error, sizeof(error)) == SN_CAPTURE_PACKET);
    assert(sn_arp_state_process(&state, &packet) == SN_PACKET_MALFORMED);
    assert(sn_capture_next(capture, &packet, error, sizeof(error)) == SN_CAPTURE_PACKET);
    assert(sn_arp_state_process(&state, &packet) == SN_PACKET_UNSUPPORTED);
    assert(sn_capture_next(capture, &packet, error, sizeof(error)) == SN_CAPTURE_PACKET);
    assert(sn_arp_state_process(&state, &packet) == SN_PACKET_TRUNCATED);
    assert(sn_capture_next(capture, &packet, error, sizeof(error)) == SN_CAPTURE_PACKET);
    assert(sn_arp_state_process(&state, &packet) == SN_PACKET_UNSUPPORTED);
    assert(sn_capture_next(capture, &packet, error, sizeof(error)) == SN_CAPTURE_EOF);
    assert(state.captured == 7U && state.decoded == 2U && state.truncated == 2U);
    assert(state.malformed == 1U && state.unsupported == 2U && state.history_count == 2U);
    assert(sn_arp_state_at(&state, 0U)->packet.operation == 1U);
    assert(sn_arp_state_at(&state, 0U)->packet.sender_ipv4[3] == 1U);
    assert(sn_arp_state_at(&state, 1U)->packet.operation == 2U);
    assert(sn_arp_state_at(&state, 1U)->timestamp.tv_sec == 2L);
    assert(sn_arp_state_at(&state, 2U) == NULL);
    sn_capture_close(capture);
    {
        char directory[] = "/tmp/sniffit-ng-arp-replay-XXXXXX";
        char output_path[256];
        struct sn_arp_config config;
        struct sn_arp_replay_stats stats;
        DIR *stream;
        struct dirent *entry;
        unsigned int pcap_count = 0U;
        unsigned int address_count = 0U;

        assert(mkdtemp(directory) != NULL);
        sn_arp_config_init(&config);
        assert(snprintf(config.log_directory, sizeof(config.log_directory), "%s", directory) > 0);
        assert(sn_arp_replay_file(path, &config, &stats, error, sizeof(error)));
        assert(stats.state.captured == 5U && stats.state.decoded == 2U && stats.state.unsupported == 1U);
        assert(stats.state.truncated == 1U && stats.state.malformed == 1U && stats.non_arp == 1U);
        assert(stats.unclassified == 1U);
        stream = opendir(directory);
        assert(stream != NULL);
        while ((entry = readdir(stream)) != NULL) {
            if (entry->d_name[0] == '.') {
                continue;
            }
            assert(snprintf(output_path, sizeof(output_path), "%s/%s", directory, entry->d_name) > 0);
            if (strstr(entry->d_name, ".pcap") != NULL && strstr(entry->d_name, ".owner") == NULL) {
                unsigned int records = 0U;
                enum sn_capture_result result;
                ++pcap_count;
                capture = sn_capture_open_offline(output_path, error, sizeof(error));
                assert(capture != NULL);
                while ((result = sn_capture_next(capture, &packet, error, sizeof(error))) == SN_CAPTURE_PACKET) {
                    ++records;
                    assert(packet.timestamp.tv_sec == (time_t)(records == 5U ? 7U : records));
                    assert(packet.wire_length == sizeof(frame));
                    assert(packet.captured_length == sizeof(frame) - (records == 3U ? 1U : 0U));
                    assert(packet.data[18] == (records == 4U ? 0U : 6U));
                }
                assert(records == 5U && result == SN_CAPTURE_EOF);
                sn_capture_close(capture);
            } else if (strstr(entry->d_name, ".jsonl") != NULL &&
                       strstr(entry->d_name, ".owner") == NULL) {
                char line[512];
                FILE *addresses = fopen(output_path, "r");
                ++address_count;
                assert(addresses != NULL && fgets(line, sizeof(line), addresses) != NULL);
                assert(fgets(line, sizeof(line), addresses) != NULL);
                assert(fgets(line, sizeof(line), addresses) == NULL);
                assert(fclose(addresses) == 0);
            }
            assert(unlink(output_path) == 0);
        }
        assert(closedir(stream) == 0 && pcap_count == 1U && address_count == 1U);
        assert(rmdir(directory) == 0);
    }
    {
        char config_path[] = "/tmp/sniffit-ng-arp-cli-XXXXXX";
        int config_fd = mkstemp(config_path);
        FILE *config_file;
        pid_t child;
        int status;

        assert(config_fd >= 0);
        config_file = fdopen(config_fd, "w");
        assert(config_file != NULL);
        assert(fputs("packet_logging = false\naddress_logging = false\n", config_file) >= 0);
        assert(fclose(config_file) == 0);
        child = fork();
        assert(child >= 0);
        if (child == 0) {
            assert(freopen("/dev/null", "w", stdout) != NULL);
            execl(ARP_CLI_PATH, ARP_CLI_PATH, "--read-pcap", path, "--config", config_path,
                  (char *)NULL);
            _exit(127);
        }
        assert(waitpid(child, &status, 0) == child);
        assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
        {
            char directory[] = "/tmp/sniffit-ng-arp-cli-log-XXXXXX";
            char output_path[256];
            DIR *stream;
            struct dirent *entry;
            unsigned int files = 0U;

            assert(mkdtemp(directory) != NULL);
            config_file = fopen(config_path, "w");
            assert(config_file != NULL && fprintf(config_file, "log_directory = %s\n", directory) > 0);
            assert(fclose(config_file) == 0);
            child = fork();
            assert(child >= 0);
            if (child == 0) {
                assert(freopen("/dev/null", "w", stdout) != NULL);
                execl(ARP_CLI_PATH, ARP_CLI_PATH, "--read-pcap", path, "--config", config_path,
                      (char *)NULL);
                _exit(127);
            }
            assert(waitpid(child, &status, 0) == child);
            assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
            stream = opendir(directory);
            assert(stream != NULL);
            while ((entry = readdir(stream)) != NULL) {
                if (entry->d_name[0] == '.') {
                    continue;
                }
                ++files;
                assert(snprintf(output_path, sizeof(output_path), "%s/%s", directory, entry->d_name) > 0);
                assert(unlink(output_path) == 0);
            }
            assert(closedir(stream) == 0 && files == 4U);
            assert(rmdir(directory) == 0);
        }
        assert(unlink(config_path) == 0);
    }
    assert(unlink(path) == 0);

    frame[13] = 0x06U;
    frame[18] = 6U;
    frame[21] = 1U;
    packet = (struct sn_capture_packet){
        .data = frame, .captured_length = sizeof(frame), .wire_length = sizeof(frame),
        .link_type = SN_PACKET_LINK_ETHERNET
    };
    sn_arp_state_init(&state);
    for (size_t index = 0U; index < SN_ARP_HISTORY_CAPACITY + 2U; ++index) {
        packet.timestamp.tv_sec = (time_t)index;
        assert(sn_arp_state_process(&state, &packet) == SN_PACKET_OK);
    }
    assert(state.history_count == SN_ARP_HISTORY_CAPACITY);
    assert(sn_arp_state_at(&state, 0U)->timestamp.tv_sec == 2L);
    assert(sn_arp_state_at(&state, SN_ARP_HISTORY_CAPACITY - 1U)->timestamp.tv_sec ==
           (time_t)(SN_ARP_HISTORY_CAPACITY + 1U));
}

static void verify_ssh_header_pipeline(void)
{
    char path_template[] = "/tmp/sniffit-ng-ssh-pipeline-XXXXXX";
    uint8_t frame[FRAME_LENGTH + 4U] = {0};
    uint8_t *ip = frame + ETHERNET_LENGTH;
    uint8_t *tcp = ip + IPV4_LENGTH;
    char error[256] = {0};
    enum sn_decoder_mode modes[SN_DECODER_MODULE_COUNT] = {0};
    struct sn_capture_packet packet;
    struct sn_capture *capture;
    struct sn_monitor *monitor = calloc(1U, sizeof(*monitor));
    pcap_t *dead_capture;
    pcap_dumper_t *dumper;
    int descriptor = mkstemp(path_template);

    assert(monitor != NULL);
    assert(descriptor >= 0);
    assert(close(descriptor) == 0);
    write_be16(frame + 12U, 0x0800U);
    ip[0] = 0x45U;
    write_be16(ip + 2U, IPV4_LENGTH + TCP_LENGTH + 4U);
    ip[8] = 64U;
    ip[9] = 6U;
    ip[12] = 192U;
    ip[15] = 1U;
    ip[16] = 192U;
    ip[19] = 2U;
    write_be16(tcp, 40000U);
    write_be16(tcp + 2U, 22U);
    tcp[12] = 0x50U;
    frame[FRAME_LENGTH] = 0xdeU;
    frame[FRAME_LENGTH + 1U] = 0xadU;
    frame[FRAME_LENGTH + 2U] = 0xbeU;
    frame[FRAME_LENGTH + 3U] = 0xefU;

    dead_capture = pcap_open_dead(DLT_EN10MB, (int)sizeof(frame));
    assert(dead_capture != NULL);
    dumper = pcap_dump_open(dead_capture, path_template);
    assert(dumper != NULL);
    dump_packet(dumper, frame, sizeof(frame), sizeof(frame), 20L);
    dump_packet(dumper, frame, FRAME_LENGTH - 1U, sizeof(frame), 21L);
    tcp[12] = 0x40U;
    dump_packet(dumper, frame, sizeof(frame), sizeof(frame), 22L);
    tcp[12] = 0x50U;
    assert(pcap_dump_flush(dumper) == 0);
    pcap_dump_close(dumper);
    pcap_close(dead_capture);

    capture = sn_capture_open_offline(path_template, error, sizeof(error));
    assert(capture != NULL);
    sn_monitor_init(monitor, 10000000000ULL);
    modes[SN_DECODER_SSH] = SN_DECODER_RAW;
    sn_monitor_set_decode_options(monitor, false, false, modes);
    assert(monitor->ssh_header_view_enabled);
    assert(sn_capture_next(capture, &packet, error, sizeof(error)) ==
           SN_CAPTURE_PACKET);
    assert(sn_monitor_process(monitor, &packet) == SN_MONITOR_PROCESSED);
    assert(sn_monitor_ssh_header_count(monitor) == 1U);
    {
        const struct sn_ssh_header_record *record =
            sn_monitor_ssh_header_at(monitor, 0U);

        assert(record != NULL && record->active);
        assert(record->sequence == 1U);
        assert(record->timestamp.tv_sec == 20L);
        assert(record->link_type == SN_PACKET_LINK_ETHERNET);
        assert(record->captured_length == sizeof(frame));
        assert(record->wire_length == sizeof(frame));
        assert(record->stored_length == FRAME_LENGTH);
        assert(memcmp(record->bytes, frame, FRAME_LENGTH) == 0);
    }
    assert(sn_capture_next(capture, &packet, error, sizeof(error)) ==
           SN_CAPTURE_PACKET);
    assert(sn_monitor_process(monitor, &packet) == SN_MONITOR_TRUNCATED);
    assert(sn_monitor_ssh_header_count(monitor) == 1U);
    assert(sn_capture_next(capture, &packet, error, sizeof(error)) ==
           SN_CAPTURE_PACKET);
    assert(sn_monitor_process(monitor, &packet) == SN_MONITOR_MALFORMED);
    assert(sn_monitor_ssh_header_count(monitor) == 1U);
    assert(sn_flow_table_count(&monitor->flows) == 1U);
    assert(sn_capture_next(capture, &packet, error, sizeof(error)) == SN_CAPTURE_EOF);

    sn_monitor_destroy(monitor);
    free(monitor);
    sn_capture_close(capture);
    assert(unlink(path_template) == 0);
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
    const struct sn_flow *telnet_flow = NULL;
    const struct sn_flow *dns_flow = NULL;
    size_t packet_index = 0U;

    create_capture(path, sizeof(path));
    capture = sn_capture_open_offline(path, error, sizeof(error));
    assert(capture != NULL);
    sn_monitor_init(&monitor, 10000000000ULL);
    assert(!monitor.full_decode_enabled);
    assert(sn_monitor_full_decode_count(&monitor) == 0U);

    while ((capture_result = sn_capture_next(capture, &packet,
                                              error, sizeof(error))) == SN_CAPTURE_PACKET) {
        if (packet_index == 3U) {
            assert(sn_monitor_set_full_decode(&monitor, true));
        }
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
        {
            char *inspection;

            assert(monitor_result == SN_MONITOR_PROCESSED);
            inspection = inspect_packet(&packet, packet_index + 1U);
            assert(strstr(inspection,
                          "claimed_src=221.156.241.83 claimed_dst=174.88.220.62") != NULL);
            assert(strstr(inspection, "claimed_src_port=60255 claimed_dst_port=23") != NULL);
            assert(strstr(inspection, "flags=0x02 [SYN] ns=0 payload_bytes=0") != NULL);
            assert(strstr(inspection,
                          "TCP header_hex=eb5f001712340000000000005002faf000000000") != NULL);
            free(inspection);
            break;
        }
        case 4U:
        {
            char *inspection;

            assert(packet.captured_length == FRAME_LENGTH - 1U);
            assert(packet.wire_length == FRAME_LENGTH);
            assert(monitor_result == SN_MONITOR_TRUNCATED);
            inspection = inspect_packet(&packet, packet_index + 1U);
            assert(strstr(inspection, "parse=truncated") != NULL);
            free(inspection);
            break;
        }
        case 5U:
        {
            char *inspection;

            assert(monitor_result == SN_MONITOR_MALFORMED);
            inspection = inspect_packet(&packet, packet_index + 1U);
            assert(strstr(inspection, "parse=malformed") != NULL);
            assert(strstr(inspection, "flags=0x02 [SYN]") != NULL);
            free(inspection);
            break;
        }
        case 6U:
        case 8U:
            assert(monitor_result == SN_MONITOR_PROCESSED);
            break;
        case 7U:
            assert(monitor_result == SN_MONITOR_TRUNCATED);
            break;
        default:
            assert(false);
        }
        ++packet_index;
    }

    assert(capture_result == SN_CAPTURE_EOF);
    assert(packet_index == 9U);
    assert(monitor.stats.captured_packets == 9U);
    assert(monitor.stats.tcp_packets == 2U);
    assert(monitor.stats.truncated_packets == 3U);
    assert(monitor.stats.malformed_packets == 2U);
    assert(sn_flow_table_count(&monitor.flows) == 3U);
    for (size_t index = 0U; index < SN_FLOW_TABLE_CAPACITY; ++index) {
        const struct sn_flow *flow = &monitor.flows.entries[index];
        if (flow->active) {
            if (flow->protocol == 6U &&
                (flow->endpoints[0].port == 23U || flow->endpoints[1].port == 23U)) {
                telnet_flow = flow;
            }
            if (flow->protocol == 17U &&
                (flow->endpoints[0].port == 53U || flow->endpoints[1].port == 53U)) {
                dns_flow = flow;
            }
        }
    }
    assert(telnet_flow != NULL);
    assert(telnet_flow->packets[0] == 0U);
    assert(telnet_flow->packets[1] == 1U);
    assert(telnet_flow->decode_history_count == 1U);
    assert(strstr(sn_flow_decode_history_at(telnet_flow, 0U)->text,
                  "TCP 60255->23 flags=0x02") != NULL);
    assert(strstr(sn_flow_decode_history_at(telnet_flow, 0U)->text,
                  "TELNET payload=0") != NULL);
    assert(sn_monitor_full_decode_count(&monitor) == 1U);
    {
        const struct sn_full_decode_record *record =
            sn_monitor_full_decode_at(&monitor, 0U);
        assert(record != NULL);
        assert(record->active);
        assert(record->captured_length == FRAME_LENGTH);
        assert(record->wire_length == FRAME_LENGTH);
        assert(record->stored_length == FRAME_LENGTH);
        assert(record->bytes[12] == 0x08U);
        assert(record->bytes[ETHERNET_LENGTH + IPV4_LENGTH + 13U] == 0x02U);
    }
    {
        uint8_t telnet_frame[FRAME_LENGTH];
        struct sn_capture_packet telnet_packet = {
            .data = telnet_frame,
            .captured_length = FRAME_LENGTH,
            .wire_length = FRAME_LENGTH,
            .link_type = SN_PACKET_LINK_ETHERNET
        };

        make_telnet_probe_frame(telnet_frame);
        for (size_t index = 0U; index < 10U; ++index) {
            telnet_packet.timestamp.tv_sec = (time_t)(10U + index);
            assert(sn_monitor_process(&monitor, &telnet_packet) ==
                   SN_MONITOR_PROCESSED);
        }
        assert(sn_monitor_full_decode_count(&monitor) ==
               SN_MONITOR_FULL_DECODE_HISTORY_CAPACITY);
        assert(sn_monitor_full_decode_at(&monitor, 0U)->sequence == 4U);
        assert(sn_monitor_full_decode_at(
                   &monitor, SN_MONITOR_FULL_DECODE_HISTORY_CAPACITY - 1U)->sequence ==
               11U);
    }
    assert(sn_monitor_set_full_decode(&monitor, false));
    assert(sn_monitor_full_decode_count(&monitor) == 0U);
    sn_monitor_destroy(&monitor);
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
#ifdef DLT_LINUX_SLL
    verify_sll_inspection();
    verify_arp_sll_pipeline();
#endif
    verify_ssh_header_pipeline();
    verify_arp_pipeline();
    puts("capture pipeline tests passed");
    return 0;
}
