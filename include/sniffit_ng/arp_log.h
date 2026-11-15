#ifndef SNIFFIT_NG_ARP_LOG_H
#define SNIFFIT_NG_ARP_LOG_H

#include "sniffit_ng/capture.h"

struct sn_arp_log;

struct sn_arp_log *sn_arp_log_open(const char *pcap_path,
                                    const char *address_path,
                                    enum sn_packet_link_type link_type,
                                    char *error_buffer, size_t error_capacity);
bool sn_arp_log_write(struct sn_arp_log *log, const struct sn_capture_packet *packet);
bool sn_arp_log_close(struct sn_arp_log *log);

#endif