#define _POSIX_C_SOURCE 200809L

#include "sniffit_ng/capture.h"
#include "sniffit_ng/packet.h"
#include "sniffit_ng/privilege.h"

#include <arpa/inet.h>
#include <errno.h>
#include <pcap/pcap.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static const uint8_t probe[] = "sniffit-ng-loopback-probe";

static int capture_unavailable(const char *error)
{
    return strstr(error, "Permission denied") != NULL ||
           strstr(error, "Operation not permitted") != NULL ||
           strstr(error, "permission") != NULL ||
           strstr(error, "unsupported link type") != NULL;
}

int main(void)
{
    char error[256] = {0};
    struct sn_capture *capture;
    struct sn_capture_packet packet;
    struct sn_packet_view view;
    struct sockaddr_in destination = {0};
    int socket_fd;
    ssize_t sent;
    bool found = false;
    struct pollfd capture_poll;

    if (!sn_enable_capture_capability(error, sizeof(error))) {
        if (strstr(error, "CAP_NET_RAW is not permitted") != NULL) {
            fprintf(stderr, "SKIP live loopback capture: %s\n", error);
            return 77;
        }
        fprintf(stderr, "live loopback capability setup failed: %s\n", error);
        return 1;
    }
    capture = sn_capture_open_live("lo", 65535, false, 100, error, sizeof(error));
    if (capture == NULL) {
        if (capture_unavailable(error)) {
            fprintf(stderr, "SKIP live loopback capture: %s\n", error);
            return 77;
        }
        fprintf(stderr, "live loopback capture setup failed: %s\n", error);
        return 1;
    }
    if (!sn_capture_set_nonblocking(capture, error, sizeof(error))) {
        fprintf(stderr, "live loopback nonblocking setup failed: %s\n", error);
        sn_capture_close(capture);
        return 1;
    }
    if (!sn_drop_privileges_to_real_user(error, sizeof(error))) {
        fprintf(stderr, "live loopback privilege drop failed: %s\n", error);
        sn_capture_close(capture);
        return 1;
    }
    capture_poll.fd = sn_capture_selectable_fd(capture);
    capture_poll.events = POLLIN;
    capture_poll.revents = 0;
    if (capture_poll.fd < 0) {
        fprintf(stderr, "SKIP live loopback capture: libpcap source has no selectable fd\n");
        sn_capture_close(capture);
        return 77;
    }

    socket_fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (socket_fd < 0) {
        perror("socket");
        sn_capture_close(capture);
        return 1;
    }
    destination.sin_family = AF_INET;
    destination.sin_port = htons(9U);
    destination.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sent = sendto(socket_fd, probe, sizeof(probe) - 1U, 0,
                  (struct sockaddr *)&destination, sizeof(destination));
    close(socket_fd);
    if (sent != (ssize_t)(sizeof(probe) - 1U)) {
        perror("sendto");
        sn_capture_close(capture);
        return 1;
    }

    for (unsigned int attempt = 0U; attempt < 20U; ++attempt) {
        enum sn_capture_result result = sn_capture_next(
            capture, &packet, error, sizeof(error));
        if (result == SN_CAPTURE_TIMEOUT) {
            int ready;
            capture_poll.revents = 0;
            ready = poll(&capture_poll, 1U, 100);
            if (ready < 0 && errno != EINTR) {
                perror("poll");
                sn_capture_close(capture);
                return 1;
            }
            continue;
        }
        if (result != SN_CAPTURE_PACKET) {
            fprintf(stderr, "live loopback read failed: %s\n", error);
            sn_capture_close(capture);
            return 1;
        }
        if (sn_packet_parse_ethernet_ipv4(packet.data,
                                          packet.captured_length,
                                          &view) == SN_PACKET_OK &&
            view.protocol == 17U && view.payload_length == sizeof(probe) - 1U &&
            memcmp(view.payload, probe, sizeof(probe) - 1U) == 0) {
            found = true;
            break;
        }
    }

    sn_capture_close(capture);
    if (!found) {
        fprintf(stderr, "did not observe the self-generated loopback UDP probe\n");
        return 1;
    }
    puts("live loopback capture test passed");
    return 0;
}
