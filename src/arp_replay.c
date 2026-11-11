#include "sniffit_ng/arp_replay.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct sn_arp_capture_session {
    struct sn_arp_replay_stats stats;
    struct sn_arp_rotation *rotation;
};

static void copy_error(char *buffer, size_t capacity, const char *message)
{
    if (buffer != NULL && capacity > 0U) {
        (void)snprintf(buffer, capacity, "%s", message);
    }
}

void sn_arp_replay_stats_release(struct sn_arp_replay_stats *stats)
{
    if (stats != NULL) {
        free(stats->analysis);
        stats->analysis = NULL;
    }
}

struct sn_arp_capture_session *sn_arp_capture_session_open(
    const struct sn_arp_config *config, char *error_buffer, size_t error_capacity)
{
    struct sn_arp_capture_session *session;

    if (config == NULL) {
        copy_error(error_buffer, error_capacity, "invalid ARP capture session config");
        return NULL;
    }
    session = calloc(1U, sizeof(*session));
    if (session == NULL) {
        copy_error(error_buffer, error_capacity, "out of memory for ARP capture session");
        return NULL;
    }
    session->stats.analysis = calloc(1U, sizeof(*session->stats.analysis));
    if (session->stats.analysis == NULL) {
        copy_error(error_buffer, error_capacity, "out of memory for ARP analysis");
        free(session);
        return NULL;
    }
    sn_arp_analysis_init(session->stats.analysis, &config->analysis);
    if (config->rotation.packet_logging || config->rotation.address_logging) {
        session->rotation = sn_arp_rotation_open(config->log_directory, &config->rotation,
                                                  error_buffer, error_capacity);
        if (session->rotation == NULL) {
            free(session->stats.analysis);
            free(session);
            return NULL;
        }
    }
    copy_error(error_buffer, error_capacity, "");
    return session;
}

bool sn_arp_capture_session_process(struct sn_arp_capture_session *session,
                                    const struct sn_capture_packet *packet, time_t now,
                                    char *error_buffer, size_t error_capacity)
{
    size_t offset;
    enum sn_packet_result classification;

    if (session == NULL || packet == NULL) {
        copy_error(error_buffer, error_capacity, "invalid ARP capture session packet");
        return false;
    }
    classification = sn_arp_locate_link(packet->data, packet->captured_length,
                                         packet->link_type, &offset);
    if (classification == SN_PACKET_UNSUPPORTED) {
        if (session->stats.non_arp < UINT64_MAX) {
            ++session->stats.non_arp;
        }
        return true;
    }
    if (classification != SN_PACKET_OK) {
        if (session->stats.unclassified < UINT64_MAX) {
            ++session->stats.unclassified;
        }
        return true;
    }
    if (session->rotation != NULL &&
        !sn_arp_rotation_write(session->rotation, packet, now)) {
        copy_error(error_buffer, error_capacity, "ARP log write or retention failed");
        return false;
    }
    if (sn_arp_state_process(&session->stats.state, packet) == SN_PACKET_OK) {
        sn_arp_analysis_observe(session->stats.analysis, sn_arp_state_at(
            &session->stats.state, session->stats.state.history_count - 1U));
    }
    return true;
}

struct sn_arp_replay_stats *sn_arp_capture_session_stats(
    struct sn_arp_capture_session *session)
{
    return session != NULL ? &session->stats : NULL;
}

bool sn_arp_capture_session_finish(struct sn_arp_capture_session *session,
                                   char *error_buffer, size_t error_capacity)
{
    bool success;

    if (session == NULL || session->rotation == NULL) {
        return true;
    }
    session->stats.deleted_segments = sn_arp_rotation_deleted(session->rotation);
    success = sn_arp_rotation_close(session->rotation);
    session->rotation = NULL;
    if (!success) {
        copy_error(error_buffer, error_capacity, "ARP log close or sync failed");
    }
    return success;
}

void sn_arp_capture_session_release(struct sn_arp_capture_session *session)
{
    if (session != NULL) {
        if (session->rotation != NULL) {
            (void)sn_arp_rotation_close(session->rotation);
        }
        free(session->stats.analysis);
        free(session);
    }
}

bool sn_arp_capture_process(struct sn_capture *capture,
                            const struct sn_arp_config *config,
                            struct sn_arp_replay_stats *stats,
                            const volatile sig_atomic_t *stop_requested,
                            char *error_buffer, size_t error_capacity)
{
    struct sn_arp_capture_session *session;
    struct sn_capture_packet packet;
    enum sn_capture_result capture_result = SN_CAPTURE_TIMEOUT;
    bool success = true;

    if (capture == NULL || config == NULL || stats == NULL) {
        copy_error(error_buffer, error_capacity, "invalid ARP capture arguments");
        return false;
    }
    *stats = (struct sn_arp_replay_stats){0};
    session = sn_arp_capture_session_open(config, error_buffer, error_capacity);
    if (session == NULL) {
        return false;
    }
    while (stop_requested == NULL || *stop_requested == 0) {
        capture_result = sn_capture_next(capture, &packet, error_buffer, error_capacity);
        if (capture_result == SN_CAPTURE_TIMEOUT) {
            int descriptor = sn_capture_selectable_fd(capture);
            struct pollfd poll_descriptor = {.fd = descriptor, .events = POLLIN};
            int poll_result = poll(descriptor >= 0 ? &poll_descriptor : NULL,
                                   descriptor >= 0 ? 1U : 0U, 100);

            if (poll_result < 0 && errno != EINTR) {
                char message[256];

                (void)snprintf(message, sizeof(message), "capture wait failed: %s",
                               strerror(errno));
                copy_error(error_buffer, error_capacity, message);
                success = false;
                break;
            }
            continue;
        }
        if (capture_result != SN_CAPTURE_PACKET) {
            break;
        }
        time_t now = time(NULL);
        if (now == (time_t)-1 ||
            !sn_arp_capture_session_process(session, &packet, now,
                                            error_buffer, error_capacity)) {
            if (now == (time_t)-1) {
                copy_error(error_buffer, error_capacity, "cannot read wall clock for ARP logging");
            }
            success = false;
            break;
        }
    }
    if (success && (stop_requested == NULL || *stop_requested == 0) &&
        capture_result != SN_CAPTURE_EOF) {
        success = false;
    }
    if (!sn_arp_capture_session_finish(session, error_buffer, error_capacity)) {
        success = false;
    }
    *stats = *sn_arp_capture_session_stats(session);
    session->stats.analysis = NULL;
    sn_arp_capture_session_release(session);
    return success;
}

bool sn_arp_replay_file(const char *path, const struct sn_arp_config *config,
                        struct sn_arp_replay_stats *stats,
                        char *error_buffer, size_t error_capacity)
{
    struct sn_capture *capture;
    bool success;

    if (path == NULL || config == NULL || stats == NULL) {
        copy_error(error_buffer, error_capacity, "invalid ARP replay arguments");
        return false;
    }
    *stats = (struct sn_arp_replay_stats){0};
    capture = sn_capture_open_offline(path, error_buffer, error_capacity);
    if (capture == NULL) {
        return false;
    }
    success = sn_arp_capture_process(capture, config, stats, NULL,
                                     error_buffer, error_capacity);
    sn_capture_close(capture);
    return success;
}