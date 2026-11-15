#define _POSIX_C_SOURCE 200809L

#include "sniffit_ng/arp_log.h"
#include "sniffit_ng/arp.h"
#include "sniffit_ng/pcap_writer.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct sn_arp_log {
    struct sn_pcap_writer *pcap;
    FILE *addresses;
    bool failed;
};

static void copy_error(char *buffer, size_t capacity, const char *message)
{
    if (buffer != NULL && capacity > 0U) {
        (void)snprintf(buffer, capacity, "%s", message);
    }
}

struct sn_arp_log *sn_arp_log_open(const char *pcap_path,
                                    const char *address_path,
                                    enum sn_packet_link_type link_type,
                                    char *error_buffer, size_t error_capacity)
{
    struct sn_arp_log *log;
    int descriptor;

    if ((pcap_path != NULL && pcap_path[0] != '/') ||
        (address_path != NULL && address_path[0] != '/') ||
        (pcap_path != NULL && address_path != NULL && strcmp(pcap_path, address_path) == 0)) {
        copy_error(error_buffer, error_capacity, "log paths must be distinct and absolute");
        return NULL;
    }
    log = calloc(1U, sizeof(*log));
    if (log == NULL) {
        copy_error(error_buffer, error_capacity, "out of memory opening ARP logs");
        return NULL;
    }
    if (pcap_path != NULL) {
        log->pcap = sn_pcap_writer_open(pcap_path, link_type, error_buffer, error_capacity);
        if (log->pcap == NULL) {
            free(log);
            return NULL;
        }
    }
    if (address_path != NULL) {
        descriptor = open(address_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                          S_IRUSR | S_IWUSR);
        if (descriptor < 0) {
            copy_error(error_buffer, error_capacity, strerror(errno));
            if (log->pcap != NULL) {
                (void)sn_pcap_writer_close(log->pcap);
                (void)unlink(pcap_path);
            }
            free(log);
            return NULL;
        }
        if (fchmod(descriptor, S_IRUSR | S_IWUSR) != 0) {
            copy_error(error_buffer, error_capacity, strerror(errno));
            close(descriptor);
            (void)unlink(address_path);
            if (log->pcap != NULL) {
                (void)sn_pcap_writer_close(log->pcap);
                (void)unlink(pcap_path);
            }
            free(log);
            return NULL;
        }
        log->addresses = fdopen(descriptor, "w");
        if (log->addresses == NULL) {
            copy_error(error_buffer, error_capacity, strerror(errno));
            close(descriptor);
            (void)unlink(address_path);
            if (log->pcap != NULL) {
                (void)sn_pcap_writer_close(log->pcap);
                (void)unlink(pcap_path);
            }
            free(log);
            return NULL;
        }
    }
    copy_error(error_buffer, error_capacity, "");
    return log;
}

bool sn_arp_log_write(struct sn_arp_log *log, const struct sn_capture_packet *packet)
{
    struct sn_arp_packet arp;
    int written;

    if (log == NULL || log->failed || packet == NULL || packet->data == NULL ||
        packet->captured_length > packet->wire_length || packet->captured_length > 65535U ||
        packet->timestamp.tv_sec < 0 || packet->timestamp.tv_usec < 0 ||
        packet->timestamp.tv_usec >= 1000000) {
        if (log != NULL) {
            log->failed = true;
        }
        return false;
    }
    if (log->pcap != NULL && !sn_pcap_writer_write(log->pcap, packet)) {
        log->failed = true;
        return false;
    }
    if (log->addresses == NULL ||
        sn_arp_parse_link(packet->data, packet->captured_length, packet->link_type, &arp) !=
            SN_PACKET_OK) {
        return true;
    }
    written = fprintf(log->addresses,
        "{\"seconds\":%lld,\"microseconds\":%ld,\"operation\":%u,"
        "\"sender_mac\":\"%02x:%02x:%02x:%02x:%02x:%02x\","
        "\"sender_ipv4\":\"%u.%u.%u.%u\","
        "\"target_mac\":\"%02x:%02x:%02x:%02x:%02x:%02x\","
        "\"target_ipv4\":\"%u.%u.%u.%u\"}\n",
        (long long)packet->timestamp.tv_sec, (long)packet->timestamp.tv_usec,
        (unsigned int)arp.operation,
        arp.sender_mac[0], arp.sender_mac[1], arp.sender_mac[2],
        arp.sender_mac[3], arp.sender_mac[4], arp.sender_mac[5],
        arp.sender_ipv4[0], arp.sender_ipv4[1], arp.sender_ipv4[2], arp.sender_ipv4[3],
        arp.target_mac[0], arp.target_mac[1], arp.target_mac[2],
        arp.target_mac[3], arp.target_mac[4], arp.target_mac[5],
        arp.target_ipv4[0], arp.target_ipv4[1], arp.target_ipv4[2], arp.target_ipv4[3]);
    if (written < 0 || fflush(log->addresses) != 0) {
        log->failed = true;
        return false;
    }
    return true;
}

bool sn_arp_log_close(struct sn_arp_log *log)
{
    bool success;

    if (log == NULL) {
        return true;
    }
    success = !log->failed;
    if (log->addresses != NULL) {
        if (fflush(log->addresses) != 0 || fsync(fileno(log->addresses)) != 0) {
            success = false;
        }
        if (fclose(log->addresses) != 0) {
            success = false;
        }
    }
    if (!sn_pcap_writer_close(log->pcap)) {
        success = false;
    }
    free(log);
    return success;
}