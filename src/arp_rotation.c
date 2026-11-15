#define _GNU_SOURCE

#include "sniffit_ng/arp_rotation.h"
#include "sniffit_ng/arp.h"
#include "sniffit_ng/arp_log.h"

#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#define ARP_DIRECTORY_CAPACITY 512U
#define ARP_SEGMENT_PATH_CAPACITY (ARP_DIRECTORY_CAPACITY + 96U)
#define ARP_ADDRESS_RECORD_MAX 512U

struct sn_arp_segment {
    struct sn_arp_log *log;
    char path[ARP_SEGMENT_PATH_CAPACITY];
    uint64_t size;
    time_t opened;
    time_t last_write;
    enum sn_packet_link_type link_type;
};

struct sn_arp_rotation {
    char directory[ARP_DIRECTORY_CAPACITY];
    int directory_fd;
    struct sn_arp_rotation_config config;
    struct sn_arp_segment packets;
    struct sn_arp_segment addresses;
    unsigned int sequence;
    uint64_t deleted;
    uint64_t retained_bytes;
    time_t retention_scan_time;
    bool retention_scan_valid;
    bool retention_age_expired;
    bool failed;
};

static void copy_error(char *buffer, size_t capacity, const char *message)
{
    if (buffer != NULL && capacity > 0U) {
        (void)snprintf(buffer, capacity, "%s", message);
    }
}

void sn_arp_rotation_config_init(struct sn_arp_rotation_config *config)
{
    if (config != NULL) {
        *config = (struct sn_arp_rotation_config){
            .packet_logging = true,
            .address_logging = true,
            .packet_segment_bytes = UINT64_C(64) * 1024U * 1024U,
            .address_segment_bytes = UINT64_C(16) * 1024U * 1024U,
            .rotate_daily = true,
            .maximum_age_seconds = UINT64_C(30) * 86400U,
            .maximum_total_bytes = UINT64_C(1024) * 1024U * 1024U,
            .delete_old_segments = true
        };
    }
}

struct sn_arp_rotation *sn_arp_rotation_open(const char *directory,
                                             const struct sn_arp_rotation_config *config,
                                             char *error_buffer, size_t error_capacity)
{
    struct sn_arp_rotation *rotation;
    struct stat info;
    int descriptor;

    if (directory == NULL || directory[0] != '/' || strlen(directory) >= ARP_DIRECTORY_CAPACITY ||
        config == NULL || (config->packet_segment_bytes > 0U && config->packet_segment_bytes < 40U) ||
        (config->address_segment_bytes > 0U && config->address_segment_bytes < ARP_ADDRESS_RECORD_MAX)) {
        copy_error(error_buffer, error_capacity, "invalid log directory or segment limits");
        return NULL;
    }
    descriptor = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (descriptor < 0) {
        copy_error(error_buffer, error_capacity, strerror(errno));
        return NULL;
    }
    if (fstat(descriptor, &info) != 0 || !S_ISDIR(info.st_mode) ||
        info.st_uid != geteuid() || (info.st_mode & (S_IRWXG | S_IRWXO)) != 0U) {
        close(descriptor);
        copy_error(error_buffer, error_capacity, "log directory must be owner-only and owned by you");
        return NULL;
    }
    if (flock(descriptor, LOCK_EX | LOCK_NB) != 0) {
        copy_error(error_buffer, error_capacity, "log directory is already in use");
        close(descriptor);
        return NULL;
    }
    rotation = calloc(1U, sizeof(*rotation));
    if (rotation == NULL) {
        close(descriptor);
        copy_error(error_buffer, error_capacity, "out of memory opening ARP rotation");
        return NULL;
    }
    (void)snprintf(rotation->directory, sizeof(rotation->directory), "%s", directory);
    rotation->directory_fd = descriptor;
    rotation->config = *config;
    copy_error(error_buffer, error_capacity, "");
    return rotation;
}

static bool close_segment(struct sn_arp_segment *segment)
{
    bool success = sn_arp_log_close(segment->log);
    *segment = (struct sn_arp_segment){0};
    return success;
}

static bool needs_rotation(const struct sn_arp_rotation *rotation,
                           const struct sn_arp_segment *segment, uint64_t extra,
                           uint64_t limit, time_t now, enum sn_packet_link_type link_type,
                           bool packets)
{
    if (segment->log == NULL) {
        return false;
    }
    return (limit > 0U && (segment->size > limit || extra > limit - segment->size)) ||
           (rotation->config.rotate_daily && now / 86400 != segment->opened / 86400) ||
           (rotation->config.maximum_age_seconds > 0U && now >= segment->opened &&
            (uint64_t)(now - segment->opened) >= rotation->config.maximum_age_seconds) ||
           (rotation->config.idle_seconds > 0U && now >= segment->last_write &&
            (uint64_t)(now - segment->last_write) >= rotation->config.idle_seconds) ||
           (packets && segment->link_type != link_type);
}

static bool create_marker(struct sn_arp_rotation *rotation, const char *path)
{
    const char *name = strrchr(path, '/') + 1;
    char marker[NAME_MAX + 1U];
    struct stat info;
    int descriptor;
    int written;
    bool success;

    written = snprintf(marker, sizeof(marker), "%s.owner", name);
    if (written < 0 || (size_t)written >= sizeof(marker) ||
        fstatat(rotation->directory_fd, name, &info, AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISREG(info.st_mode) || info.st_uid != geteuid() || info.st_nlink != 1) {
        return false;
    }
    descriptor = openat(rotation->directory_fd, marker,
                        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                        S_IRUSR | S_IWUSR);
    if (descriptor < 0) {
        return false;
    }
    success = fchmod(descriptor, S_IRUSR | S_IWUSR) == 0 &&
              dprintf(descriptor, "%ju %ju\n", (uintmax_t)info.st_dev,
                      (uintmax_t)info.st_ino) > 0 && fsync(descriptor) == 0;
    if (close(descriptor) != 0) {
        success = false;
    }
    if (!success) {
        (void)unlinkat(rotation->directory_fd, marker, 0);
        return false;
    }
    if (fsync(rotation->directory_fd) != 0) {
        (void)unlinkat(rotation->directory_fd, marker, 0);
        return false;
    }
    return true;
}

static int marker_matches(struct sn_arp_rotation *rotation, const char *name,
                          const struct stat *info)
{
    char marker[NAME_MAX + 1U];
    char contents[128];
    struct stat marker_info;
    uintmax_t device;
    uintmax_t inode;
    char extra;
    ssize_t length;
    int descriptor;
    int written = snprintf(marker, sizeof(marker), "%s.owner", name);

    if (written < 0 || (size_t)written >= sizeof(marker)) {
        return -1;
    }
    descriptor = openat(rotation->directory_fd, marker, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (descriptor < 0) {
        return errno == ENOENT ? 0 : -1;
    }
    if (fstat(descriptor, &marker_info) != 0 || !S_ISREG(marker_info.st_mode) ||
        marker_info.st_uid != geteuid() || marker_info.st_nlink != 1 ||
        (marker_info.st_mode & (S_IRWXG | S_IRWXO)) != 0U || marker_info.st_size < 0 ||
        (uintmax_t)marker_info.st_size >= sizeof(contents)) {
        close(descriptor);
        return -1;
    }
    length = read(descriptor, contents, sizeof(contents) - 1U);
    if (close(descriptor) != 0 || length < 0 || length != marker_info.st_size) {
        return -1;
    }
    contents[length] = '\0';
    if (sscanf(contents, "%ju %ju %c", &device, &inode, &extra) != 2 ||
        device != (uintmax_t)info->st_dev || inode != (uintmax_t)info->st_ino) {
        return -1;
    }
    return 1;
}

static bool open_segment(struct sn_arp_rotation *rotation, struct sn_arp_segment *segment,
                         bool packets, enum sn_packet_link_type link_type, time_t now)
{
    char error[256];
    struct stat info;

    for (unsigned int attempt = 0U; attempt < 1000000U; ++attempt) {
        int written = snprintf(segment->path, sizeof(segment->path), "%s/arpwatch-%s-%020lld-%06u.%s",
                               rotation->directory, packets ? "packets" : "addresses",
                               (long long)now, rotation->sequence++ % 1000000U,
                               packets ? "pcap" : "jsonl");
        if (written < 0 || (size_t)written >= sizeof(segment->path)) {
            return false;
        }
        if (lstat(segment->path, &info) == 0) {
            continue;
        }
        if (errno != ENOENT) {
            return false;
        }
        segment->log = sn_arp_log_open(packets ? segment->path : NULL,
                                        packets ? NULL : segment->path,
                                        link_type, error, sizeof(error));
        if (segment->log == NULL) {
            return false;
        }
        if (!create_marker(rotation, segment->path)) {
            char name[NAME_MAX + 1U];

            (void)snprintf(name, sizeof(name), "%s", strrchr(segment->path, '/') + 1);
            (void)close_segment(segment);
            (void)unlinkat(rotation->directory_fd, name, 0);
            return false;
        }
        segment->size = packets ? 24U : 0U;
        segment->opened = now;
        segment->last_write = now;
        segment->link_type = link_type;
        return true;
    }
    return false;
}

static bool managed_name(const char *name, uint64_t *created, unsigned int *sequence)
{
    const char *digits;
    const char *suffix;
    uint64_t value = 0U;
    unsigned int ordinal = 0U;

    if (strncmp(name, "arpwatch-packets-", 17U) == 0) {
        digits = name + 17U;
        suffix = ".pcap";
    } else if (strncmp(name, "arpwatch-addresses-", 19U) == 0) {
        digits = name + 19U;
        suffix = ".jsonl";
    } else {
        return false;
    }
    if (strlen(digits) != 27U + strlen(suffix) || digits[20] != '-') {
        return false;
    }
    for (size_t index = 0U; index < 20U; ++index) {
        unsigned int digit;
        if (digits[index] < '0' || digits[index] > '9') {
            return false;
        }
        digit = (unsigned int)(digits[index] - '0');
        if (value > (UINT64_MAX - digit) / 10U) {
            return false;
        }
        value = value * 10U + digit;
    }
    for (size_t index = 21U; index < 27U; ++index) {
        if (digits[index] < '0' || digits[index] > '9') {
            return false;
        }
        ordinal = ordinal * 10U + (unsigned int)(digits[index] - '0');
    }
    if (strcmp(digits + 27U, suffix) != 0) {
        return false;
    }
    *created = value;
    *sequence = ordinal;
    return true;
}

static bool enforce_retention(struct sn_arp_rotation *rotation, time_t now, uint64_t incoming)
{
    if (rotation->retention_scan_valid && rotation->retention_scan_time == now &&
        !rotation->retention_age_expired &&
        (rotation->config.maximum_total_bytes == 0U ||
         (rotation->retained_bytes <= rotation->config.maximum_total_bytes &&
          incoming <= rotation->config.maximum_total_bytes - rotation->retained_bytes))) {
        return true;
    }
    for (;;) {
        int descriptor = openat(rotation->directory_fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        DIR *directory;
        struct dirent *entry;
        char oldest[NAME_MAX + 1U] = "";
        uint64_t oldest_created = UINT64_MAX;
        unsigned int oldest_sequence = UINT_MAX;
        uint64_t total = 0U;
        bool expired = false;
        bool scan_error = false;

        if (descriptor < 0) {
            return false;
        }
        directory = fdopendir(descriptor);
        if (directory == NULL) {
            close(descriptor);
            return false;
        }
        errno = 0;
        while ((entry = readdir(directory)) != NULL) {
            struct stat info;
            uint64_t created;
            unsigned int sequence;
            bool active;
            int marked;

            if (!managed_name(entry->d_name, &created, &sequence)) {
                continue;
            }
            if (fstatat(rotation->directory_fd, entry->d_name, &info, AT_SYMLINK_NOFOLLOW) != 0) {
                scan_error = true;
                break;
            }
            marked = marker_matches(rotation, entry->d_name, &info);
            if (marked == 0) {
                errno = 0;
                continue;
            }
            if (marked < 0) {
                scan_error = true;
                break;
            }
            if (!S_ISREG(info.st_mode) || info.st_uid != geteuid() || info.st_nlink != 1 ||
                (info.st_mode & (S_IRWXG | S_IRWXO)) != 0U || info.st_size < 0 ||
                UINT64_MAX - total < (uint64_t)info.st_size) {
                scan_error = true;
                break;
            }
            total += (uint64_t)info.st_size;
            active = (rotation->packets.log != NULL &&
                      strcmp(strrchr(rotation->packets.path, '/') + 1, entry->d_name) == 0) ||
                     (rotation->addresses.log != NULL &&
                      strcmp(strrchr(rotation->addresses.path, '/') + 1, entry->d_name) == 0);
            if (!active && (oldest[0] == '\0' || created < oldest_created ||
                            (created == oldest_created && sequence < oldest_sequence) ||
                            (created == oldest_created && sequence == oldest_sequence &&
                             strcmp(entry->d_name, oldest) < 0))) {
                oldest_created = created;
                oldest_sequence = sequence;
                (void)snprintf(oldest, sizeof(oldest), "%s", entry->d_name);
            }
            errno = 0;
        }
        if (errno != 0) {
            scan_error = true;
        }
        if (closedir(directory) != 0 || scan_error) {
            return false;
        }
        if (oldest[0] != '\0' && rotation->config.maximum_age_seconds > 0U &&
            (uint64_t)now >= oldest_created &&
            (uint64_t)now - oldest_created >= rotation->config.maximum_age_seconds) {
            expired = true;
        }
        if (!expired && (rotation->config.maximum_total_bytes == 0U ||
            (total <= rotation->config.maximum_total_bytes &&
             incoming <= rotation->config.maximum_total_bytes - total))) {
            rotation->retained_bytes = total;
            rotation->retention_scan_time = now;
            rotation->retention_scan_valid = true;
            rotation->retention_age_expired = false;
            return true;
        }
        if (!rotation->config.delete_old_segments || oldest[0] == '\0') {
            rotation->retained_bytes = total;
            rotation->retention_scan_time = now;
            rotation->retention_scan_valid = true;
            rotation->retention_age_expired = expired;
            return false;
        }
        {
            char marker[NAME_MAX + 1U];
            int written = snprintf(marker, sizeof(marker), "%s.owner", oldest);

            if (written < 0 || (size_t)written >= sizeof(marker) ||
                unlinkat(rotation->directory_fd, oldest, 0) != 0 ||
                unlinkat(rotation->directory_fd, marker, 0) != 0 ||
                fsync(rotation->directory_fd) != 0) {
                return false;
            }
        }
        if (rotation->deleted < UINT64_MAX) {
            ++rotation->deleted;
        }
    }
}

static bool write_segment(struct sn_arp_rotation *rotation, struct sn_arp_segment *segment,
                          const struct sn_capture_packet *packet, time_t now, bool packets)
{
    uint64_t extra = packets ? 16U + (uint64_t)packet->captured_length : ARP_ADDRESS_RECORD_MAX;
    uint64_t limit = packets ? rotation->config.packet_segment_bytes :
                               rotation->config.address_segment_bytes;
    uint64_t previous_size;
    struct stat info;

    if (limit > 0U && (extra > limit || (packets && extra > limit - 24U))) {
        return false;
    }
    if (needs_rotation(rotation, segment, extra, limit, now, packet->link_type, packets) &&
        !close_segment(segment)) {
        return false;
    }
    previous_size = segment->log != NULL ? segment->size : 0U;
    if (!enforce_retention(rotation, now, extra + (segment->log == NULL && packets ? 24U : 0U))) {
        return false;
    }
    if (segment->log == NULL && !open_segment(rotation, segment, packets, packet->link_type, now)) {
        return false;
    }
    if (!sn_arp_log_write(segment->log, packet) || lstat(segment->path, &info) != 0 ||
        !S_ISREG(info.st_mode) || info.st_size < 0) {
        return false;
    }
    segment->size = (uint64_t)info.st_size;
    if (rotation->retention_scan_valid) {
        if (segment->size < previous_size ||
            UINT64_MAX - rotation->retained_bytes < segment->size - previous_size) {
            return false;
        }
        rotation->retained_bytes += segment->size - previous_size;
    }
    segment->last_write = now;
    return true;
}

bool sn_arp_rotation_write(struct sn_arp_rotation *rotation,
                           const struct sn_capture_packet *packet, time_t now)
{
    struct sn_arp_packet decoded;

    if (rotation == NULL || rotation->failed || packet == NULL || now < 0 ||
        packet->data == NULL || packet->captured_length > packet->wire_length ||
        packet->captured_length > 65535U || packet->timestamp.tv_sec < 0 ||
        packet->timestamp.tv_usec < 0 || packet->timestamp.tv_usec >= 1000000) {
        if (rotation != NULL) {
            rotation->failed = true;
        }
        return false;
    }
    if (rotation->config.packet_logging &&
        !write_segment(rotation, &rotation->packets, packet, now, true)) {
        rotation->failed = true;
        return false;
    }
    if (rotation->config.address_logging &&
        sn_arp_parse_link(packet->data, packet->captured_length, packet->link_type, &decoded) ==
            SN_PACKET_OK &&
        !write_segment(rotation, &rotation->addresses, packet, now, false)) {
        rotation->failed = true;
        return false;
    }
    return true;
}

uint64_t sn_arp_rotation_deleted(const struct sn_arp_rotation *rotation)
{
    return rotation == NULL ? 0U : rotation->deleted;
}

bool sn_arp_rotation_close(struct sn_arp_rotation *rotation)
{
    bool success;

    if (rotation == NULL) {
        return true;
    }
    success = !rotation->failed;
    if (!close_segment(&rotation->packets)) {
        success = false;
    }
    if (!close_segment(&rotation->addresses)) {
        success = false;
    }
    if (close(rotation->directory_fd) != 0) {
        success = false;
    }
    free(rotation);
    return success;
}