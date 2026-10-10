#define _GNU_SOURCE

#include "sniffit_ng/privilege.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void)
{
    char error[256] = {0};
    uid_t expected_uid = getuid();
    gid_t expected_gid = getgid();
    bool started_as_root = geteuid() == 0U;
    pid_t child;
    int status;

    if (expected_uid == 0U || expected_gid == 0U) {
        const char *sudo_uid = getenv("SUDO_UID");
        const char *sudo_gid = getenv("SUDO_GID");
        if (sudo_uid == NULL || sudo_gid == NULL) {
            fputs("SKIP privilege-drop test without a non-root invoking user\n", stderr);
            return 77;
        }
        expected_uid = (uid_t)strtoul(sudo_uid, NULL, 10);
        expected_gid = (gid_t)strtoul(sudo_gid, NULL, 10);
        if (expected_uid == 0U || expected_gid == 0U) {
            fputs("SKIP privilege-drop test without a non-root invoking user\n", stderr);
            return 77;
        }
    }

    child = fork();
    assert(child >= 0);
    if (child == 0) {
        uid_t real_uid;
        uid_t effective_uid;
        uid_t saved_uid;
        gid_t real_gid;
        gid_t effective_gid;
        gid_t saved_gid;

        if (!sn_drop_privileges_to_real_user(error, sizeof(error))) {
            dprintf(STDERR_FILENO, "privilege drop failed: %s\n", error);
            _exit(1);
        }
        if (getresuid(&real_uid, &effective_uid, &saved_uid) != 0 ||
            getresgid(&real_gid, &effective_gid, &saved_gid) != 0 ||
            real_uid != expected_uid || effective_uid != real_uid || saved_uid != real_uid ||
            real_gid != expected_gid || effective_gid != real_gid || saved_gid != real_gid ||
            (started_as_root && getgroups(0, NULL) != 0) ||
            prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1) {
            _exit(2);
        }
        _exit(0);
    }

    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status));
    assert(WEXITSTATUS(status) == 0);
    puts("privilege drop test passed");
    return 0;
}
