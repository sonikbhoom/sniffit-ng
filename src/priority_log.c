#include "sniffit_ng/priority_log.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

struct sn_priority_log {
    FILE *stream;
    char path[SN_PRIORITY_LOG_PATH_CAPACITY];
    struct sn_priority_log_limits limits;
    unsigned long size;
    long day;
    struct sn_ui_priority_port ports[SN_CONFIG_UI_PRIORITY_CAPACITY];
    size_t port_count;
    bool local_known;
    uint8_t local_ipv4[4];
};

static long utc_day(time_t seconds)
{
    return (long)(seconds / 86400);
}

static void copy_error(char *destination, size_t capacity, const char *message)
{
    if (destination != NULL && capacity > 0U) {
        (void)snprintf(destination, capacity, "%s", message != NULL ? message : "");
    }
}

struct sn_priority_log *sn_priority_log_open(
    const char *path,
    const struct sn_ui_priority_port *ports,
    size_t port_count,
    const char *local_ipv4,
    const struct sn_priority_log_limits *limits,
    char *error_buffer,
    size_t error_buffer_size)
{
    struct sn_priority_log *log;
    struct stat info;
    int descriptor;

    if (path == NULL || path[0] != '/') {
        copy_error(error_buffer, error_buffer_size,
                   "priority log path must be absolute");
        return NULL;
    }
    if (strlen(path) >= sizeof(log->path) - 16U) {
        copy_error(error_buffer, error_buffer_size, "priority log path is too long");
        return NULL;
    }
    if (ports == NULL || port_count == 0U ||
        port_count > SN_CONFIG_UI_PRIORITY_CAPACITY) {
        copy_error(error_buffer, error_buffer_size, "no priority ports to log");
        return NULL;
    }
    descriptor = open(path, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW | O_CLOEXEC,
                      S_IRUSR | S_IWUSR);
    if (descriptor < 0) {
        copy_error(error_buffer, error_buffer_size, strerror(errno));
        return NULL;
    }
    if (fstat(descriptor, &info) != 0 || !S_ISREG(info.st_mode) ||
        info.st_uid != geteuid() || (info.st_mode & (S_IRWXG | S_IRWXO)) != 0U) {
        close(descriptor);
        copy_error(error_buffer, error_buffer_size,
                   "priority log must be a regular file owned by you with no group/other access");
        return NULL;
    }
    log = calloc(1U, sizeof(*log));
    if (log == NULL) {
        close(descriptor);
        copy_error(error_buffer, error_buffer_size, "out of memory opening priority log");
        return NULL;
    }
    log->stream = fdopen(descriptor, "a");
    if (log->stream == NULL) {
        int saved_errno = errno;
        close(descriptor);
        free(log);
        copy_error(error_buffer, error_buffer_size, strerror(saved_errno));
        return NULL;
    }
    snprintf(log->path, sizeof(log->path), "%s", path);
    log->limits.max_bytes = limits != NULL && limits->max_bytes > 0UL ?
        limits->max_bytes : SN_PRIORITY_LOG_DEFAULT_MAX_BYTES;
    log->limits.keep = limits != NULL && limits->keep > 0U ?
        limits->keep : SN_PRIORITY_LOG_DEFAULT_KEEP;
    log->size = (unsigned long)info.st_size;
    log->day = info.st_size > 0 ? utc_day(info.st_mtime) : -1;
    memcpy(log->ports, ports, port_count * sizeof(log->ports[0]));
    log->port_count = port_count;
    if (local_ipv4 != NULL && local_ipv4[0] != '\0') {
        log->local_known = inet_pton(AF_INET, local_ipv4, log->local_ipv4) == 1;
    }
    copy_error(error_buffer, error_buffer_size, "");
    return log;
}

static bool rotate(struct sn_priority_log *log)
{
    char from[SN_PRIORITY_LOG_PATH_CAPACITY + 16U];
    char to[SN_PRIORITY_LOG_PATH_CAPACITY + 16U];
    int descriptor;

    if (fclose(log->stream) != 0) {
        log->stream = NULL;
        return false;
    }
    log->stream = NULL;
    snprintf(to, sizeof(to), "%s.%u", log->path, log->limits.keep);
    if (unlink(to) != 0 && errno != ENOENT) {
        return false;
    }
    for (unsigned int index = log->limits.keep; index > 1U; --index) {
        snprintf(from, sizeof(from), "%s.%u", log->path, index - 1U);
        snprintf(to, sizeof(to), "%s.%u", log->path, index);
        if (rename(from, to) != 0 && errno != ENOENT) {
            return false;
        }
    }
    snprintf(to, sizeof(to), "%s.1", log->path);
    if (rename(log->path, to) != 0) {
        return false;
    }
    descriptor = open(log->path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                      S_IRUSR | S_IWUSR);
    if (descriptor < 0) {
        return false;
    }
    log->stream = fdopen(descriptor, "a");
    if (log->stream == NULL) {
        close(descriptor);
        return false;
    }
    log->size = 0UL;
    log->day = -1;
    return true;
}

static bool port_is_priority(const struct sn_priority_log *log,
                             uint8_t protocol,
                             uint16_t port)
{
    for (size_t index = 0U; index < log->port_count; ++index) {
        if (log->ports[index].protocol == protocol && log->ports[index].port == port) {
            return true;
        }
    }
    return false;
}

static uint16_t read_be16(const uint8_t *bytes)
{
    return (uint16_t)(((unsigned int)bytes[0] << 8U) | bytes[1]);
}

bool sn_priority_log_observe(struct sn_priority_log *log,
                             const struct sn_capture_packet *packet)
{
    struct sn_packet_view view;
    char source[INET_ADDRSTRLEN];
    char destination[INET_ADDRSTRLEN];
    char stamp[32];
    char flags[9] = "";
    struct tm utc;
    time_t seconds;
    uint16_t source_port;
    uint16_t destination_port;
    int written;

    if (log == NULL || packet == NULL || packet->data == NULL ||
        packet->timestamp.tv_sec < 0 || packet->timestamp.tv_usec < 0 ||
        packet->timestamp.tv_usec > 999999) {
        return true;
    }
    if (sn_packet_parse_link_ipv4(packet->data, packet->captured_length,
                                  packet->link_type, &view) != SN_PACKET_OK ||
        (view.protocol != 6U && view.protocol != 17U) ||
        view.fragment_offset != 0U || !view.transport_header_present ||
        view.transport_length < 4U) {
        return true;
    }
    source_port = read_be16(view.transport);
    destination_port = read_be16(view.transport + 2U);
    if (!port_is_priority(log, view.protocol, destination_port)) {
        return true;
    }
    if (log->local_known &&
        (memcmp(view.destination_ipv4, log->local_ipv4, 4U) != 0 ||
         memcmp(view.source_ipv4, log->local_ipv4, 4U) == 0)) {
        return true;
    }
    seconds = (time_t)packet->timestamp.tv_sec;
    if (gmtime_r(&seconds, &utc) == NULL ||
        inet_ntop(AF_INET, view.source_ipv4, source, sizeof(source)) == NULL ||
        inet_ntop(AF_INET, view.destination_ipv4, destination,
                  sizeof(destination)) == NULL) {
        return true;
    }
    written = snprintf(stamp, sizeof(stamp), "%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ",
                       utc.tm_year + 1900, utc.tm_mon + 1, utc.tm_mday,
                       utc.tm_hour, utc.tm_min, utc.tm_sec,
                       (long)(packet->timestamp.tv_usec / 1000));
    if (written < 0 || (size_t)written >= sizeof(stamp)) {
        return true;
    }
    if (view.protocol == 6U && view.transport_length >= 14U) {
        static const char letters[] = "CEUAPRSF";
        size_t used = 0U;

        for (unsigned int bit = 0U; bit < 8U; ++bit) {
            if ((view.transport[13] & (0x80U >> bit)) != 0U) {
                flags[used++] = letters[bit];
            }
        }
        flags[used] = '\0';
    }
    if (log->stream == NULL) {
        return false;
    }
    if (log->size > 0UL &&
        (log->size >= log->limits.max_bytes ||
         (log->day >= 0 && log->day != utc_day(seconds))) &&
        !rotate(log)) {
        return false;
    }
    written = fprintf(log->stream,
                "{\"ts\":\"%s\",\"proto\":\"%s\",\"src\":\"%s\",\"sport\":%u,"
                "\"dst\":\"%s\",\"dport\":%u,\"flags\":\"%s\",\"len\":%zu}\n",
                stamp, view.protocol == 6U ? "tcp" : "udp", source,
                (unsigned int)source_port, destination,
                (unsigned int)destination_port, flags,
                view.ipv4_total_length);
    if (written < 0) {
        return false;
    }
    log->size += (unsigned long)written;
    log->day = utc_day(seconds);
    return fflush(log->stream) == 0;
}

bool sn_priority_log_close(struct sn_priority_log *log)
{
    bool ok = true;

    if (log != NULL) {
        ok = log->stream == NULL || fclose(log->stream) == 0;
        free(log);
    }
    return ok;
}
