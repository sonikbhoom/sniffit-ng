#include "sniffit_ng/capture.h"

#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct sn_capture {
    pcap_t *handle;
    bool live;
    enum sn_packet_link_type link_type;
};

static void copy_error(char *destination, size_t capacity, const char *message)
{
    if (destination != NULL && capacity > 0U) {
        (void)snprintf(destination, capacity, "%s", message != NULL ? message : "");
    }
}

static struct sn_capture *wrap_handle(
    pcap_t *handle,
    bool live,
    char *error_buffer,
    size_t error_buffer_size)
{
    struct sn_capture *capture;
    enum sn_packet_link_type link_type;
    int pcap_link_type;

    if (handle == NULL) {
        return NULL;
    }
    pcap_link_type = pcap_datalink(handle);
    if (pcap_link_type == DLT_EN10MB) {
        link_type = SN_PACKET_LINK_ETHERNET;
#ifdef DLT_LINUX_SLL
    } else if (pcap_link_type == DLT_LINUX_SLL) {
        link_type = SN_PACKET_LINK_LINUX_SLL;
#endif
    } else {
        char message[128];
        (void)snprintf(message, sizeof(message),
                       "unsupported link type: Sniffit NG does not support DLT %d",
                       pcap_link_type);
        copy_error(error_buffer, error_buffer_size, message);
        pcap_close(handle);
        return NULL;
    }

    capture = calloc(1U, sizeof(*capture));
    if (capture == NULL) {
        copy_error(error_buffer, error_buffer_size, "out of memory opening capture source");
        pcap_close(handle);
        return NULL;
    }
    capture->handle = handle;
    capture->live = live;
    capture->link_type = link_type;
    copy_error(error_buffer, error_buffer_size, "");
    return capture;
}

struct sn_capture *sn_capture_open_offline(
    const char *path,
    char *error_buffer,
    size_t error_buffer_size)
{
    char pcap_error[PCAP_ERRBUF_SIZE] = {0};
    pcap_t *handle;

    if (path == NULL || path[0] == '\0') {
        copy_error(error_buffer, error_buffer_size, "pcap path must not be empty");
        return NULL;
    }
    handle = pcap_open_offline(path, pcap_error);
    if (handle == NULL) {
        copy_error(error_buffer, error_buffer_size, pcap_error);
        return NULL;
    }
    return wrap_handle(handle, false, error_buffer, error_buffer_size);
}

struct sn_capture *sn_capture_open_live(
    const char *device,
    int snapshot_length,
    bool promiscuous,
    int timeout_ms,
    char *error_buffer,
    size_t error_buffer_size)
{
    char pcap_error[PCAP_ERRBUF_SIZE] = {0};
    pcap_t *handle;

    if (device == NULL || device[0] == '\0' || snapshot_length <= 0 ||
        snapshot_length > 1048576 || timeout_ms < 0 || timeout_ms > 60000) {
        copy_error(error_buffer, error_buffer_size, "invalid live capture parameters");
        return NULL;
    }
    handle = pcap_open_live(device, snapshot_length, promiscuous ? 1 : 0,
                            timeout_ms, pcap_error);
    if (handle == NULL) {
        copy_error(error_buffer, error_buffer_size, pcap_error);
        return NULL;
    }
    return wrap_handle(handle, true, error_buffer, error_buffer_size);
}

bool sn_capture_set_nonblocking(
    struct sn_capture *capture,
    char *error_buffer,
    size_t error_buffer_size)
{
    char pcap_error[PCAP_ERRBUF_SIZE] = {0};

    if (capture == NULL || capture->handle == NULL || !capture->live) {
        copy_error(error_buffer, error_buffer_size,
                   "nonblocking mode is only available for live capture handles");
        return false;
    }
    if (pcap_setnonblock(capture->handle, 1, pcap_error) != 0) {
        copy_error(error_buffer, error_buffer_size, pcap_error);
        return false;
    }
    copy_error(error_buffer, error_buffer_size, "");
    return true;
}

int sn_capture_selectable_fd(const struct sn_capture *capture)
{
    if (capture == NULL || capture->handle == NULL) {
        return -1;
    }
    return pcap_get_selectable_fd(capture->handle);
}

enum sn_capture_result sn_capture_next(
    struct sn_capture *capture,
    struct sn_capture_packet *packet,
    char *error_buffer,
    size_t error_buffer_size)
{
    struct pcap_pkthdr *header = NULL;
    const u_char *bytes = NULL;
    int result;

    if (packet != NULL) {
        *packet = (struct sn_capture_packet){0};
    }
    if (capture == NULL || capture->handle == NULL || packet == NULL) {
        copy_error(error_buffer, error_buffer_size, "invalid capture read arguments");
        return SN_CAPTURE_ERROR;
    }

    result = pcap_next_ex(capture->handle, &header, &bytes);
    if (result == 1) {
        if (header == NULL || bytes == NULL) {
            copy_error(error_buffer, error_buffer_size, "libpcap returned an invalid packet");
            return SN_CAPTURE_ERROR;
        }
        packet->data = bytes;
        packet->captured_length = header->caplen;
        packet->wire_length = header->len;
        packet->link_type = capture->link_type;
        packet->timestamp = header->ts;
        copy_error(error_buffer, error_buffer_size, "");
        return SN_CAPTURE_PACKET;
    }
    if (result == 0) {
        return SN_CAPTURE_TIMEOUT;
    }
    if (result == -2) {
        return SN_CAPTURE_EOF;
    }
    copy_error(error_buffer, error_buffer_size, pcap_geterr(capture->handle));
    return SN_CAPTURE_ERROR;
}

void sn_capture_close(struct sn_capture *capture)
{
    if (capture == NULL) {
        return;
    }
    if (capture->handle != NULL) {
        pcap_close(capture->handle);
    }
    free(capture);
}
