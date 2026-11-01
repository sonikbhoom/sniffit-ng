#define _POSIX_C_SOURCE 200809L

#include "sniffit_ng/priority_log.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void be16(uint8_t *out, uint16_t value)
{
    out[0] = (uint8_t)(value >> 8U);
    out[1] = (uint8_t)value;
}

static struct sn_capture_packet make_packet(uint8_t *frame,
                                            size_t capacity,
                                            uint8_t protocol,
                                            const uint8_t source[4],
                                            const uint8_t destination[4],
                                            uint16_t source_port,
                                            uint16_t destination_port,
                                            uint8_t tcp_flags,
                                            long seconds,
                                            long microseconds)
{
    uint8_t *ip = frame + 14U;
    uint8_t *transport = ip + 20U;
    size_t transport_length = protocol == 6U ? 20U : 8U;
    struct sn_capture_packet packet = {0};

    assert(capacity >= 14U + 20U + transport_length);
    memset(frame, 0, capacity);
    be16(frame + 12U, 0x0800U);
    ip[0] = 0x45U;
    be16(ip + 2U, (uint16_t)(20U + transport_length));
    ip[8] = 64U;
    ip[9] = protocol;
    memcpy(ip + 12U, source, 4U);
    memcpy(ip + 16U, destination, 4U);
    be16(transport, source_port);
    be16(transport + 2U, destination_port);
    if (protocol == 6U) {
        transport[12] = 0x50U;
        transport[13] = tcp_flags;
    } else {
        be16(transport + 4U, 8U);
    }
    packet.data = frame;
    packet.captured_length = 14U + 20U + transport_length;
    packet.wire_length = packet.captured_length;
    packet.link_type = SN_PACKET_LINK_ETHERNET;
    packet.timestamp.tv_sec = seconds;
    packet.timestamp.tv_usec = microseconds;
    return packet;
}

static char *read_file(const char *path)
{
    static char buffer[4096];
    FILE *stream = fopen(path, "r");
    size_t length;

    assert(stream != NULL);
    length = fread(buffer, 1U, sizeof(buffer) - 1U, stream);
    buffer[length] = '\0';
    fclose(stream);
    return buffer;
}

int main(void)
{
    static const uint8_t local[4] = {192U, 0U, 2U, 10U};
    static const uint8_t remote[4] = {203U, 0U, 113U, 9U};
    static const uint8_t other[4] = {192U, 0U, 2U, 99U};
    const struct sn_ui_priority_port ports[] = {
        {.protocol = 6U, .port = 22U},
        {.protocol = 17U, .port = 53U}
    };
    char directory[] = "/tmp/sniffit-priority-log-XXXXXX";
    char path[128];
    char link[128];
    char error[256];
    uint8_t frame[128];
    struct sn_capture_packet packet;
    struct sn_priority_log *log;
    struct stat info;
    char *contents;

    assert(mkdtemp(directory) != NULL);
    (void)snprintf(path, sizeof(path), "%s/priority.jsonl", directory);
    (void)snprintf(link, sizeof(link), "%s/link.jsonl", directory);

    assert(sn_priority_log_open("relative.jsonl", ports, 2U, NULL,
                                error, sizeof(error)) == NULL);
    assert(sn_priority_log_open(path, ports, 0U, NULL, error, sizeof(error)) == NULL);

    log = sn_priority_log_open(path, ports, 2U, "192.0.2.10", error, sizeof(error));
    assert(log != NULL);
    assert(stat(path, &info) == 0 && (info.st_mode & 0777U) == 0600U);

    /* 2026-11-01T21:12:05.959Z */
    packet = make_packet(frame, sizeof(frame), 6U, remote, local, 40000U, 22U,
                         0x02U, 1793567525L, 959000L);
    assert(sn_priority_log_observe(log, &packet));
    packet = make_packet(frame, sizeof(frame), 6U, remote, local, 40001U, 80U,
                         0x02U, 1793567526L, 0L);
    assert(sn_priority_log_observe(log, &packet));
    packet = make_packet(frame, sizeof(frame), 6U, local, remote, 22U, 40000U,
                         0x12U, 1793567527L, 0L);
    assert(sn_priority_log_observe(log, &packet));
    packet = make_packet(frame, sizeof(frame), 6U, remote, other, 40002U, 22U,
                         0x02U, 1793567528L, 0L);
    assert(sn_priority_log_observe(log, &packet));
    packet = make_packet(frame, sizeof(frame), 17U, remote, local, 5000U, 53U,
                         0U, 1793567529L, 5000L);
    assert(sn_priority_log_observe(log, &packet));
    packet = make_packet(frame, sizeof(frame), 17U, remote, local, 5000U, 22U,
                         0U, 1793567530L, 0L);
    assert(sn_priority_log_observe(log, &packet));
    assert(sn_priority_log_close(log));

    contents = read_file(path);
    assert(strstr(contents,
                  "{\"ts\":\"2026-11-01T21:12:05.959Z\",\"proto\":\"tcp\","
                  "\"src\":\"203.0.113.9\",\"sport\":40000,\"dst\":\"192.0.2.10\","
                  "\"dport\":22,\"flags\":\"S\",\"len\":40}\n") == contents);
    assert(strstr(contents, "\"proto\":\"udp\",\"src\":\"203.0.113.9\",\"sport\":5000,"
                            "\"dst\":\"192.0.2.10\",\"dport\":53,\"flags\":\"\"") != NULL);
    assert(strstr(contents, "\"dport\":80") == NULL);
    assert(strstr(contents, "\"src\":\"192.0.2.10\"") == NULL);
    assert(strstr(contents, "192.0.2.99") == NULL);
    assert(strstr(contents, "\"dport\":22,\"flags\":\"\"") == NULL);
    {
        size_t lines = 0U;
        for (const char *cursor = contents; *cursor != '\0'; ++cursor) {
            lines += *cursor == '\n' ? 1U : 0U;
        }
        assert(lines == 2U);
    }

    /* Reopening appends; without a known local address every destination matches. */
    log = sn_priority_log_open(path, ports, 2U, NULL, error, sizeof(error));
    assert(log != NULL);
    packet = make_packet(frame, sizeof(frame), 6U, remote, other, 40002U, 22U,
                         0x12U, 1793567528L, 1000L);
    assert(sn_priority_log_observe(log, &packet));
    assert(sn_priority_log_close(log));
    contents = read_file(path);
    assert(strstr(contents, "\"dst\":\"192.0.2.99\",\"dport\":22,\"flags\":\"AS\"") != NULL);

    assert(symlink(path, link) == 0);
    assert(sn_priority_log_open(link, ports, 2U, NULL, error, sizeof(error)) == NULL);
    assert(chmod(path, 0644) == 0);
    assert(sn_priority_log_open(path, ports, 2U, NULL, error, sizeof(error)) == NULL);

    assert(unlink(link) == 0);
    assert(unlink(path) == 0);
    assert(rmdir(directory) == 0);
    puts("priority log tests passed");
    return 0;
}
