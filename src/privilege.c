#define _GNU_SOURCE

#include "sniffit_ng/privilege.h"

#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#if defined(__linux__)
#include <grp.h>
#include <linux/capability.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#endif

static void copy_error(char *destination, size_t capacity, const char *message)
{
    if (destination != NULL && capacity > 0U) {
        (void)snprintf(destination, capacity, "%s", message != NULL ? message : "");
    }
}

static bool report_errno(char *error_buffer, size_t error_buffer_size,
                         const char *operation)
{
    char message[256];

    (void)snprintf(message, sizeof(message), "%s: %s", operation, strerror(errno));
    copy_error(error_buffer, error_buffer_size, message);
    return false;
}

static bool parse_nonroot_id(const char *text, unsigned long *value)
{
    char *end = NULL;
    unsigned long parsed;

    if (text == NULL || text[0] == '\0' || value == NULL) {
        return false;
    }
    errno = 0;
    parsed = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || parsed == 0UL) {
        return false;
    }
    *value = parsed;
    return true;
}

bool sn_drop_privileges_to_real_user(char *error_buffer, size_t error_buffer_size)
{
#if defined(__linux__)
    uid_t user_id = getuid();
    gid_t group_id = getgid();
    uid_t effective_user_id = geteuid();
    gid_t effective_group_id = getegid();
    struct __user_cap_header_struct capability_header = {
        .version = _LINUX_CAPABILITY_VERSION_3,
        .pid = 0
    };
    struct __user_cap_data_struct empty_capabilities[2] = {{0}};

    if (user_id == 0U || group_id == 0U) {
        unsigned long sudo_uid;
        unsigned long sudo_gid;
        const char *uid_text = getenv("SUDO_UID");
        const char *gid_text = getenv("SUDO_GID");

        if (!parse_nonroot_id(uid_text, &sudo_uid) ||
            !parse_nonroot_id(gid_text, &sudo_gid) ||
            (unsigned long)(uid_t)sudo_uid != sudo_uid ||
            (unsigned long)(gid_t)sudo_gid != sudo_gid) {
            copy_error(error_buffer, error_buffer_size,
                       "no valid non-root invoking user; run under sudo from a regular user account");
            return false;
        }
        user_id = (uid_t)sudo_uid;
        group_id = (gid_t)sudo_gid;
    }

    if (user_id == 0U || group_id == 0U) {
        copy_error(error_buffer, error_buffer_size,
                   "refusing live capture when no non-root real user is available");
        return false;
    }

    if (effective_user_id == 0U) {
        if (setgroups(0U, NULL) != 0) {
            return report_errno(error_buffer, error_buffer_size, "setgroups");
        }
    }
    if (effective_group_id != group_id) {
        if (setresgid(group_id, group_id, group_id) != 0) {
            return report_errno(error_buffer, error_buffer_size, "setresgid");
        }
    }
    if (effective_user_id != user_id) {
        if (setresuid(user_id, user_id, user_id) != 0) {
            return report_errno(error_buffer, error_buffer_size, "setresuid");
        }
    }

    if (syscall(SYS_capset, &capability_header, empty_capabilities) != 0) {
        return report_errno(error_buffer, error_buffer_size, "capset");
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        return report_errno(error_buffer, error_buffer_size, "PR_SET_NO_NEW_PRIVS");
    }

    copy_error(error_buffer, error_buffer_size, "");
    return true;
#else
    (void)error_buffer;
    (void)error_buffer_size;
    copy_error(error_buffer, error_buffer_size,
               "live capture privilege reduction is implemented on Linux only");
    return false;
#endif
}
bool sn_enable_capture_capability(char *error_buffer, size_t error_buffer_size)
{
#if defined(__linux__)
    struct __user_cap_header_struct header = {
        .version = _LINUX_CAPABILITY_VERSION_3,
        .pid = 0
    };
    struct __user_cap_data_struct capabilities[2] = {{0}};
    unsigned int index = (unsigned int)CAP_NET_RAW / 32U;
    uint32_t mask = UINT32_C(1) << ((unsigned int)CAP_NET_RAW % 32U);

    if (syscall(SYS_capget, &header, capabilities) != 0) {
        return report_errno(error_buffer, error_buffer_size, "capget");
    }
    if ((capabilities[index].permitted & mask) == 0U) {
        copy_error(error_buffer, error_buffer_size,
                   "CAP_NET_RAW is not permitted; use setcap cap_net_raw+p or an authorized sudo invocation");
        return false;
    }
    if ((capabilities[index].effective & mask) == 0U) {
        capabilities[index].effective |= mask;
        if (syscall(SYS_capset, &header, capabilities) != 0) {
            return report_errno(error_buffer, error_buffer_size, "enable CAP_NET_RAW");
        }
    }
    copy_error(error_buffer, error_buffer_size, "");
    return true;
#else
    copy_error(error_buffer, error_buffer_size,
               "live capture capability management is implemented on Linux only");
    return false;
#endif
}

