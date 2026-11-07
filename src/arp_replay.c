#include "sniffit_ng/arp_replay.h"

#include <stdio.h>
#include <time.h>

static void copy_error(char *buffer, size_t capacity, const char *message)
{
    if (buffer != NULL && capacity > 0U) {
        (void)snprintf(buffer, capacity, "%s", message);
    }
}

bool sn_arp_replay_file(const char *path, const struct sn_arp_config *config,
                        struct sn_arp_replay_stats *stats,
                        char *error_buffer, size_t error_capacity)
{
    struct sn_capture *capture;
    struct sn_arp_rotation *rotation = NULL;
    struct sn_capture_packet packet;
    enum sn_capture_result capture_result;
    bool success = true;

    if (path == NULL || config == NULL || stats == NULL) {
        copy_error(error_buffer, error_capacity, "invalid ARP replay arguments");
        return false;
    }
    *stats = (struct sn_arp_replay_stats){0};
    capture = sn_capture_open_offline(path, error_buffer, error_capacity);
    if (capture == NULL) {
        return false;
    }
    if (config->rotation.packet_logging || config->rotation.address_logging) {
        rotation = sn_arp_rotation_open(config->log_directory, &config->rotation,
                                         error_buffer, error_capacity);
        if (rotation == NULL) {
            sn_capture_close(capture);
            return false;
        }
    }
    while ((capture_result = sn_capture_next(capture, &packet, error_buffer, error_capacity)) ==
           SN_CAPTURE_PACKET) {
        size_t offset;
        enum sn_packet_result classification = sn_arp_locate_link(
            packet.data, packet.captured_length, packet.link_type, &offset);

        if (classification == SN_PACKET_UNSUPPORTED) {
            if (stats->non_arp < UINT64_MAX) {
                ++stats->non_arp;
            }
            continue;
        }
        if (classification != SN_PACKET_OK) {
            if (stats->unclassified < UINT64_MAX) {
                ++stats->unclassified;
            }
            continue;
        }
        if (rotation != NULL) {
            time_t now = time(NULL);
            if (now == (time_t)-1 || !sn_arp_rotation_write(rotation, &packet, now)) {
                copy_error(error_buffer, error_capacity, "ARP log write or retention failed");
                success = false;
                break;
            }
        }
        (void)sn_arp_state_process(&stats->state, &packet);
    }
    if (success && capture_result != SN_CAPTURE_EOF) {
        success = false;
    }
    if (rotation != NULL) {
        stats->deleted_segments = sn_arp_rotation_deleted(rotation);
        if (!sn_arp_rotation_close(rotation)) {
            if (success) {
                copy_error(error_buffer, error_capacity, "ARP log close or sync failed");
            }
            success = false;
        }
    }
    sn_capture_close(capture);
    return success;
}