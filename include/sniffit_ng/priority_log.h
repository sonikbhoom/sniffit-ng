#ifndef SNIFFIT_NG_PRIORITY_LOG_H
#define SNIFFIT_NG_PRIORITY_LOG_H

#include "sniffit_ng/capture.h"
#include "sniffit_ng/config.h"

#include <stdbool.h>
#include <stddef.h>

struct sn_priority_log;

/*
 * The log is rotated when it reaches max_bytes or when the UTC day of the
 * newest record changes. Rotated files are PATH.1 (newest) to PATH.keep;
 * older ones are deleted.
 */
struct sn_priority_log_limits {
    unsigned long max_bytes;
    unsigned int keep;
};

/*
 * Opens an append-only JSON Lines log of packets addressed to a UI priority
 * port. The file is created with owner-only permissions; symlinks, non-regular
 * files, foreign owners and group/other-accessible files are rejected.
 * local_ipv4 (dotted text, may be NULL or empty) restricts records to packets
 * sent to that address by another host. limits may be NULL for the defaults.
 */
struct sn_priority_log *sn_priority_log_open(
    const char *path,
    const struct sn_ui_priority_port *ports,
    size_t port_count,
    const char *local_ipv4,
    const struct sn_priority_log_limits *limits,
    char *error_buffer,
    size_t error_buffer_size);

/* Returns false only when a matching record could not be written. */
bool sn_priority_log_observe(struct sn_priority_log *log,
                             const struct sn_capture_packet *packet);

bool sn_priority_log_close(struct sn_priority_log *log);

#endif
