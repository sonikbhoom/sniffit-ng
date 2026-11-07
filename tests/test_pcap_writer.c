#define _POSIX_C_SOURCE 200809L

#include "sniffit_ng/capture.h"
#include "sniffit_ng/arp_log.h"
#include "sniffit_ng/arp_config.h"
#include "sniffit_ng/arp_rotation.h"
#include "sniffit_ng/pcap_writer.h"

#include <assert.h>
#include <dirent.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/wait.h>
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

static void test_arp_logs(void)
{
    uint8_t bytes[42] = {
        [12] = 8U, [13] = 6U, [15] = 1U, [16] = 8U,
        [18] = 6U, [19] = 4U, [21] = 1U,
        [22] = 2U, [27] = 1U, [28] = 192U, [30] = 2U, [31] = 1U,
        [38] = 192U, [40] = 2U, [41] = 2U
    };
    char pcap_path[64];
    char address_path[64];
    char error[256] = {0};
    char line[512];
    struct sn_capture_packet packet = {
        .data = bytes, .captured_length = sizeof(bytes), .wire_length = sizeof(bytes),
        .link_type = SN_PACKET_LINK_ETHERNET, .timestamp = {.tv_sec = 1234, .tv_usec = 7}
    };
    struct sn_capture_packet read_packet;
    struct sn_arp_log *log;
    struct sn_capture *capture;
    struct stat metadata;
    FILE *stream;

    make_temporary_path(pcap_path, sizeof(pcap_path));
    make_temporary_path(address_path, sizeof(address_path));
    log = sn_arp_log_open(pcap_path, address_path, packet.link_type, error, sizeof(error));
    assert(log != NULL);
    assert(sn_arp_log_write(log, &packet));
    packet.captured_length--;
    assert(sn_arp_log_write(log, &packet));
    assert(sn_arp_log_close(log));
    assert(stat(pcap_path, &metadata) == 0 && (metadata.st_mode & 0777U) == 0600U);
    assert(stat(address_path, &metadata) == 0 && (metadata.st_mode & 0777U) == 0600U);

    capture = sn_capture_open_offline(pcap_path, error, sizeof(error));
    assert(capture != NULL);
    assert(sn_capture_next(capture, &read_packet, error, sizeof(error)) == SN_CAPTURE_PACKET);
    assert(read_packet.captured_length == sizeof(bytes) && read_packet.wire_length == sizeof(bytes));
    assert(read_packet.timestamp.tv_sec == 1234 && read_packet.timestamp.tv_usec == 7);
    assert(memcmp(read_packet.data, bytes, sizeof(bytes)) == 0);
    assert(sn_capture_next(capture, &read_packet, error, sizeof(error)) == SN_CAPTURE_PACKET);
    assert(read_packet.captured_length == sizeof(bytes) - 1U && read_packet.wire_length == sizeof(bytes));
    assert(sn_capture_next(capture, &read_packet, error, sizeof(error)) == SN_CAPTURE_EOF);
    sn_capture_close(capture);
    stream = fopen(address_path, "r");
    assert(stream != NULL && fgets(line, sizeof(line), stream) != NULL);
    assert(strstr(line, "\"sender_ipv4\":\"192.0.2.1\"") != NULL);
    assert(strstr(line, "\"target_ipv4\":\"192.0.2.2\"") != NULL);
    assert(fgets(line, sizeof(line), stream) == NULL);
    assert(fclose(stream) == 0);
    assert(sn_arp_log_open(pcap_path, address_path, packet.link_type, error, sizeof(error)) == NULL);
    assert(unlink(pcap_path) == 0 && unlink(address_path) == 0);
    log = sn_arp_log_open(NULL, NULL, packet.link_type, error, sizeof(error));
    assert(log != NULL && sn_arp_log_write(log, &packet) && sn_arp_log_close(log));
    assert(sn_arp_log_open("relative", NULL, packet.link_type, error, sizeof(error)) == NULL);

    log = sn_arp_log_open(NULL, address_path, packet.link_type, error, sizeof(error));
    assert(log != NULL);
    packet.captured_length = sizeof(bytes);
    assert(sn_arp_log_write(log, &packet));
    packet.wire_length = sizeof(bytes) - 1U;
    assert(!sn_arp_log_write(log, &packet));
    packet.wire_length = sizeof(bytes);
    assert(!sn_arp_log_write(log, &packet));
    assert(!sn_arp_log_close(log));
    log = sn_arp_log_open(pcap_path, address_path, packet.link_type, error, sizeof(error));
    assert(log == NULL);
    assert(access(pcap_path, F_OK) != 0);
    assert(unlink(address_path) == 0);
}

static void test_arp_rotation(void)
{
    char directory[] = "/tmp/sniffit-ng-arp-rotation-XXXXXX";
    char error[256];
    char path[256];
    uint8_t bytes[42] = {
        [12] = 8U, [13] = 6U, [15] = 1U, [16] = 8U,
        [18] = 6U, [19] = 4U, [21] = 1U,
        [22] = 2U, [27] = 1U, [28] = 192U, [31] = 1U, [38] = 192U, [41] = 2U
    };
    struct sn_capture_packet packet = {
        .data = bytes, .captured_length = sizeof(bytes), .wire_length = sizeof(bytes),
        .link_type = SN_PACKET_LINK_ETHERNET, .timestamp = {.tv_sec = 100}
    };
    struct sn_arp_rotation_config config;
    struct sn_arp_rotation *rotation;
    DIR *stream;
    struct dirent *entry;
    unsigned int packets = 0U;
    unsigned int addresses = 0U;
    struct stat info;

    assert(mkdtemp(directory) != NULL);
    sn_arp_rotation_config_init(&config);
    config.packet_segment_bytes = 140U;
    config.address_segment_bytes = 512U;
    rotation = sn_arp_rotation_open(directory, &config, error, sizeof(error));
    assert(rotation != NULL);
    assert(sn_arp_rotation_open(directory, &config, error, sizeof(error)) == NULL);
    assert(sn_arp_rotation_write(rotation, &packet, 100));
    assert(sn_arp_rotation_write(rotation, &packet, 101));
    assert(sn_arp_rotation_write(rotation, &packet, 102));
    assert(sn_arp_rotation_write(rotation, &packet, 86401));
    assert(sn_arp_rotation_close(rotation));
    stream = opendir(directory);
    assert(stream != NULL);
    while ((entry = readdir(stream)) != NULL) {
        if (entry->d_name[0] == '.') {
            continue;
        }
        assert(snprintf(path, sizeof(path), "%s/%s", directory, entry->d_name) > 0);
        assert(stat(path, &info) == 0 && (info.st_mode & 0777U) == 0600U);
        if (strstr(entry->d_name, ".owner") != NULL) {
            assert(unlink(path) == 0);
            continue;
        }
        if (strstr(entry->d_name, "arpwatch-packets-") == entry->d_name) {
            ++packets;
            assert(info.st_size <= 140);
        } else {
            assert(strstr(entry->d_name, "arpwatch-addresses-") == entry->d_name);
            ++addresses;
            assert(info.st_size <= 512);
        }
        assert(unlink(path) == 0);
    }
    assert(closedir(stream) == 0);
    assert(packets == 3U && addresses == 4U);
    assert(rmdir(directory) == 0);
}

static void test_arp_retention(void)
{
    char directory[] = "/tmp/sniffit-ng-arp-retention-XXXXXX";
    char error[256];
    char path[256];
    uint8_t bytes[42] = {
        [12] = 8U, [13] = 6U, [15] = 1U, [16] = 8U,
        [18] = 6U, [19] = 4U, [21] = 1U
    };
    struct sn_capture_packet packet = {
        .data = bytes, .captured_length = sizeof(bytes), .wire_length = sizeof(bytes),
        .link_type = SN_PACKET_LINK_ETHERNET, .timestamp = {.tv_sec = 100}
    };
    struct sn_arp_rotation_config config;
    struct sn_arp_rotation *rotation;
    DIR *stream;
    struct dirent *entry;
    unsigned int packets = 0U;
    FILE *unrelated;

    assert(mkdtemp(directory) != NULL);
    assert(snprintf(path, sizeof(path), "%s/keep.txt", directory) > 0);
    unrelated = fopen(path, "w");
    assert(unrelated != NULL && fclose(unrelated) == 0);
    assert(snprintf(path, sizeof(path), "%s/arpwatch-packets-00000000000000000090-000003.pcap",
                    directory) > 0);
    unrelated = fopen(path, "w");
    assert(unrelated != NULL && fputs("unrelated", unrelated) >= 0 && fclose(unrelated) == 0);
    sn_arp_rotation_config_init(&config);
    config.address_logging = false;
    config.packet_segment_bytes = 82U;
    config.maximum_total_bytes = 164U;
    config.maximum_age_seconds = 0U;
    rotation = sn_arp_rotation_open(directory, &config, error, sizeof(error));
    assert(rotation != NULL);
    assert(sn_arp_rotation_write(rotation, &packet, 100));
    assert(sn_arp_rotation_write(rotation, &packet, 101));
    assert(sn_arp_rotation_write(rotation, &packet, 102));
    assert(sn_arp_rotation_deleted(rotation) == 1U);
    assert(sn_arp_rotation_close(rotation));
    assert(access(path, F_OK) == 0);

    config.delete_old_segments = false;
    rotation = sn_arp_rotation_open(directory, &config, error, sizeof(error));
    assert(rotation != NULL);
    assert(!sn_arp_rotation_write(rotation, &packet, 103));
    assert(!sn_arp_rotation_close(rotation));
    config.delete_old_segments = true;
    config.maximum_total_bytes = 0U;
    config.maximum_age_seconds = 5U;
    rotation = sn_arp_rotation_open(directory, &config, error, sizeof(error));
    assert(rotation != NULL);
    assert(sn_arp_rotation_write(rotation, &packet, 110));
    assert(sn_arp_rotation_deleted(rotation) == 2U);
    assert(sn_arp_rotation_close(rotation));

    stream = opendir(directory);
    assert(stream != NULL);
    while ((entry = readdir(stream)) != NULL) {
        if (entry->d_name[0] == '.') {
            continue;
        }
        if (strstr(entry->d_name, "arpwatch-packets-") == entry->d_name &&
            strstr(entry->d_name, ".owner") == NULL && strstr(entry->d_name, "000003.pcap") == NULL) {
            ++packets;
        }
        assert(snprintf(path, sizeof(path), "%s/%s", directory, entry->d_name) > 0);
        assert(unlink(path) == 0);
    }
    assert(closedir(stream) == 0 && packets == 1U);
    assert(rmdir(directory) == 0);
}

static void test_arp_marker_collision(void)
{
    char directory[] = "/tmp/sniffit-ng-arp-marker-XXXXXX";
    char marker[256];
    char pcap_path[256];
    char error[256];
    uint8_t bytes[42] = {
        [12] = 8U, [13] = 6U, [15] = 1U, [16] = 8U,
        [18] = 6U, [19] = 4U, [21] = 1U
    };
    struct sn_capture_packet packet = {
        .data = bytes, .captured_length = sizeof(bytes), .wire_length = sizeof(bytes),
        .link_type = SN_PACKET_LINK_ETHERNET, .timestamp = {.tv_sec = 100}
    };
    struct sn_arp_rotation_config config;
    struct sn_arp_rotation *rotation;
    FILE *stream;

    assert(mkdtemp(directory) != NULL);
    assert(snprintf(pcap_path, sizeof(pcap_path),
                    "%s/arpwatch-packets-00000000000000000100-000000.pcap", directory) > 0);
    assert(snprintf(marker, sizeof(marker), "%s.owner", pcap_path) > 0);
    stream = fopen(marker, "w");
    assert(stream != NULL && fputs("unrelated", stream) >= 0 && fclose(stream) == 0);
    sn_arp_rotation_config_init(&config);
    config.address_logging = false;
    rotation = sn_arp_rotation_open(directory, &config, error, sizeof(error));
    assert(rotation != NULL && !sn_arp_rotation_write(rotation, &packet, 100));
    assert(!sn_arp_rotation_close(rotation));
    assert(access(pcap_path, F_OK) != 0 && access(marker, F_OK) == 0);
    assert(unlink(marker) == 0 && rmdir(directory) == 0);
}

static void test_arp_idle_and_shared_limit(void)
{
    char directory[] = "/tmp/sniffit-ng-arp-idle-XXXXXX";
    char path[256];
    char error[256];
    uint8_t bytes[42] = {
        [12] = 8U, [13] = 6U, [15] = 1U, [16] = 8U,
        [18] = 6U, [19] = 4U, [21] = 1U
    };
    struct sn_capture_packet packet = {
        .data = bytes, .captured_length = sizeof(bytes), .wire_length = sizeof(bytes),
        .link_type = SN_PACKET_LINK_ETHERNET, .timestamp = {.tv_sec = 100}
    };
    struct sn_arp_rotation_config config;
    struct sn_arp_rotation *rotation;
    DIR *stream;
    struct dirent *entry;
    unsigned int segments = 0U;
    uint64_t total = 0U;
    struct stat info;

    assert(mkdtemp(directory) != NULL);
    sn_arp_rotation_config_init(&config);
    config.address_logging = false;
    config.packet_segment_bytes = 0U;
    config.rotate_daily = false;
    config.idle_seconds = 10U;
    rotation = sn_arp_rotation_open(directory, &config, error, sizeof(error));
    assert(rotation != NULL);
    assert(sn_arp_rotation_write(rotation, &packet, 100));
    assert(sn_arp_rotation_write(rotation, &packet, 109));
    assert(sn_arp_rotation_write(rotation, &packet, 119));
    assert(sn_arp_rotation_close(rotation));
    stream = opendir(directory);
    assert(stream != NULL);
    while ((entry = readdir(stream)) != NULL) {
        if (entry->d_name[0] == '.') {
            continue;
        }
        if (strstr(entry->d_name, ".owner") == NULL) {
            ++segments;
        }
        assert(snprintf(path, sizeof(path), "%s/%s", directory, entry->d_name) > 0);
        assert(unlink(path) == 0);
    }
    assert(closedir(stream) == 0 && segments == 2U);

    sn_arp_rotation_config_init(&config);
    config.packet_segment_bytes = 82U;
    config.address_segment_bytes = 512U;
    config.maximum_total_bytes = 800U;
    rotation = sn_arp_rotation_open(directory, &config, error, sizeof(error));
    assert(rotation != NULL);
    assert(sn_arp_rotation_write(rotation, &packet, 100));
    assert(sn_arp_rotation_write(rotation, &packet, 100));
    assert(sn_arp_rotation_deleted(rotation) == 1U);
    assert(sn_arp_rotation_close(rotation));
    assert(snprintf(path, sizeof(path),
                    "%s/arpwatch-packets-00000000000000000100-000000.pcap", directory) > 0);
    assert(access(path, F_OK) != 0);
    assert(snprintf(path, sizeof(path),
                    "%s/arpwatch-addresses-00000000000000000100-000001.jsonl", directory) > 0);
    assert(access(path, F_OK) == 0);
    stream = opendir(directory);
    assert(stream != NULL);
    while ((entry = readdir(stream)) != NULL) {
        if (entry->d_name[0] == '.') {
            continue;
        }
        assert(snprintf(path, sizeof(path), "%s/%s", directory, entry->d_name) > 0);
        if (strstr(entry->d_name, ".owner") == NULL) {
            assert(stat(path, &info) == 0 && info.st_size >= 0);
            total += (uint64_t)info.st_size;
        }
        assert(unlink(path) == 0);
    }
    assert(closedir(stream) == 0 && total <= 800U);
    assert(rmdir(directory) == 0);
}

static void test_arp_log_write_failure(void)
{
    char path[64];
    pid_t child;
    int status;

    make_temporary_path(path, sizeof(path));
    child = fork();
    assert(child >= 0);
    if (child == 0) {
        struct rlimit limit = {.rlim_cur = 24, .rlim_max = 24};
        uint8_t bytes[42] = {0};
        char error[256];
        struct sn_capture_packet packet = {
            .data = bytes, .captured_length = sizeof(bytes), .wire_length = sizeof(bytes),
            .link_type = SN_PACKET_LINK_ETHERNET
        };
        struct sn_arp_log *log;

        assert(signal(SIGXFSZ, SIG_IGN) != SIG_ERR);
        assert(setrlimit(RLIMIT_FSIZE, &limit) == 0);
        log = sn_arp_log_open(path, NULL, packet.link_type, error, sizeof(error));
        assert(log != NULL);
        assert(!sn_arp_log_write(log, &packet));
        assert(!sn_arp_log_close(log));
        _exit(0);
    }
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    assert(unlink(path) == 0);
}

static void test_arp_config(void)
{
    char path[64];
    char error[256];
    struct sn_arp_config config;
    FILE *stream;

    make_temporary_path(path, sizeof(path));
    stream = fopen(path, "w");
    assert(stream != NULL);
    assert(fputs("log_directory = /tmp/arpwatch\npacket_segment_bytes = 4096\n"
                 "address_logging = false\nmaximum_age_seconds = 0\n"
                 "delete_old_segments = false\n", stream) >= 0);
    assert(fclose(stream) == 0);
    assert(sn_arp_config_load(path, &config, error, sizeof(error)));
    assert(strcmp(config.log_directory, "/tmp/arpwatch") == 0);
    assert(config.rotation.packet_logging && !config.rotation.address_logging);
    assert(config.rotation.packet_segment_bytes == 4096U);
    assert(config.rotation.maximum_age_seconds == 0U && !config.rotation.delete_old_segments);
    assert(config.rotation.maximum_total_bytes == UINT64_C(1073741824));
    stream = fopen(path, "w");
    assert(stream != NULL && fputs("packet_logging = false\npacket_logging = true\n", stream) >= 0);
    assert(fclose(stream) == 0);
    assert(!sn_arp_config_load(path, &config, error, sizeof(error)));
    stream = fopen(path, "w");
    assert(stream != NULL && fputs("log_directory = /tmp/arpwatch\nmaximum_total_bytes = -1\n", stream) >= 0);
    assert(fclose(stream) == 0);
    assert(!sn_arp_config_load(path, &config, error, sizeof(error)));
    stream = fopen(path, "w");
    assert(stream != NULL && fputs("packet_logging = false\naddress_logging = false\n", stream) >= 0);
    assert(fclose(stream) == 0);
    assert(sn_arp_config_load(path, &config, error, sizeof(error)));
    assert(unlink(path) == 0);
}

int main(void)
{
    test_round_trip_link_type(SN_PACKET_LINK_ETHERNET, 24U);
    test_round_trip_link_type(SN_PACKET_LINK_LINUX_SLL, 16U);
    test_invalid_writer_inputs();
    test_arp_logs();
    test_arp_rotation();
    test_arp_retention();
    test_arp_marker_collision();
    test_arp_idle_and_shared_limit();
    test_arp_log_write_failure();
    test_arp_config();
    puts("pcap writer tests passed");
    return 0;
}
