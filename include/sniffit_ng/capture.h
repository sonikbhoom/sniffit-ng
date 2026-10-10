#ifndef SNIFFIT_NG_CAPTURE_H
#define SNIFFIT_NG_CAPTURE_H

#include "sniffit_ng/packet.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/time.h>

enum sn_capture_result {
    SN_CAPTURE_PACKET,
    SN_CAPTURE_TIMEOUT,
    SN_CAPTURE_EOF,
    SN_CAPTURE_ERROR
};

struct sn_capture;

struct sn_capture_packet {
    const uint8_t *data;
    size_t captured_length;
    size_t wire_length;
    enum sn_packet_link_type link_type;
    struct timeval timestamp;
};

struct sn_capture *sn_capture_open_offline(
    const char *path,
    char *error_buffer,
    size_t error_buffer_size);

struct sn_capture *sn_capture_open_live(
    const char *device,
    int snapshot_length,
    bool promiscuous,
    int timeout_ms,
    char *error_buffer,
    size_t error_buffer_size);

bool sn_capture_set_nonblocking(
    struct sn_capture *capture,
    char *error_buffer,
    size_t error_buffer_size);

int sn_capture_selectable_fd(const struct sn_capture *capture);

/* Packet bytes are borrowed from libpcap until the next read or close. */
enum sn_capture_result sn_capture_next(
    struct sn_capture *capture,
    struct sn_capture_packet *packet,
    char *error_buffer,
    size_t error_buffer_size);

void sn_capture_close(struct sn_capture *capture);

#endif
