#include "sniffit_ng/network_info.h"

#include <arpa/inet.h>
#include <curl/curl.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct ipv4_response {
    char text[SN_NETWORK_IPV4_TEXT_CAPACITY + 1U];
    size_t length;
};

static size_t capture_ipv4_response(char *data,
                                    size_t size,
                                    size_t count,
                                    void *context)
{
    struct ipv4_response *response = context;
    size_t bytes;

    if (size != 0U && count > SIZE_MAX / size) {
        return 0U;
    }
    bytes = size * count;
    if (bytes > sizeof(response->text) - 1U - response->length) {
        return 0U;
    }
    memcpy(response->text + response->length, data, bytes);
    response->length += bytes;
    response->text[response->length] = '\0';
    return bytes;
}

void sn_network_info_init(struct sn_network_info *info, const char *interface_name)
{
    if (info == NULL) {
        return;
    }
    *info = (struct sn_network_info){0};
    if (interface_name != NULL) {
        (void)snprintf(info->interface_name, sizeof(info->interface_name), "%s",
                       interface_name);
    }
}

bool sn_network_info_find_local_ipv4(struct sn_network_info *info)
{
    struct ifaddrs *addresses = NULL;
    bool found = false;

    if (info == NULL || info->interface_name[0] == '\0') {
        return false;
    }
    info->local_ipv4[0] = '\0';
    if (getifaddrs(&addresses) != 0) {
        return false;
    }
    for (const struct ifaddrs *entry = addresses; entry != NULL; entry = entry->ifa_next) {
        if (entry->ifa_name == NULL || entry->ifa_addr == NULL ||
            entry->ifa_addr->sa_family != AF_INET ||
            strcmp(entry->ifa_name, info->interface_name) != 0) {
            continue;
        }
        const struct sockaddr_in *address = (const struct sockaddr_in *)entry->ifa_addr;
        if (inet_ntop(AF_INET, &address->sin_addr, info->local_ipv4,
                      sizeof(info->local_ipv4)) != NULL) {
            found = true;
            break;
        }
    }
    freeifaddrs(addresses);
    return found;
}

bool sn_ipv4_is_rfc1918(const char *address_text)
{
    struct in_addr address;
    uint32_t host_address;

    if (address_text == NULL || inet_pton(AF_INET, address_text, &address) != 1) {
        return false;
    }
    host_address = ntohl(address.s_addr);
    return (host_address & 0xff000000U) == 0x0a000000U ||
           (host_address & 0xfff00000U) == 0xac100000U ||
           (host_address & 0xffff0000U) == 0xc0a80000U;
}

bool sn_network_info_resolve_external_ipv4(struct sn_network_info *info)
{
    struct ipv4_response response = {0};
    struct in_addr external_address;
    CURL *handle;
    CURLcode result;
    bool resolved = false;

    if (info == NULL || !sn_ipv4_is_rfc1918(info->local_ipv4)) {
        return false;
    }
    info->external_ipv4[0] = '\0';
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        return false;
    }
    handle = curl_easy_init();
    if (handle == NULL) {
        curl_global_cleanup();
        return false;
    }
    (void)curl_easy_setopt(handle, CURLOPT_URL, "https://ifconfig.io/ip");
    (void)curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 0L);
    (void)curl_easy_setopt(handle, CURLOPT_FAILONERROR, 1L);
    (void)curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT_MS, 1500L);
    (void)curl_easy_setopt(handle, CURLOPT_TIMEOUT_MS, 3000L);
    (void)curl_easy_setopt(handle, CURLOPT_NOSIGNAL, 1L);
    (void)curl_easy_setopt(handle, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
    (void)curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 1L);
    (void)curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 2L);
    (void)curl_easy_setopt(handle, CURLOPT_MAXFILESIZE_LARGE,
                           (curl_off_t)SN_NETWORK_IPV4_TEXT_CAPACITY);
    (void)curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, capture_ipv4_response);
    (void)curl_easy_setopt(handle, CURLOPT_WRITEDATA, &response);
    result = curl_easy_perform(handle);
    curl_easy_cleanup(handle);
    curl_global_cleanup();
    if (result != CURLE_OK) {
        return false;
    }

    while (response.length > 0U &&
           (response.text[response.length - 1U] == '\n' ||
            response.text[response.length - 1U] == '\r')) {
        response.text[--response.length] = '\0';
    }
    if (inet_pton(AF_INET, response.text, &external_address) == 1 &&
        inet_ntop(AF_INET, &external_address, info->external_ipv4,
                  sizeof(info->external_ipv4)) != NULL) {
        resolved = true;
    }
    return resolved;
}