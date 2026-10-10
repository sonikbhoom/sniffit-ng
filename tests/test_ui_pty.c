#include "sniffit_ng/ui.h"

#include <assert.h>
#include <pty.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static void seed_flows(struct sn_monitor *monitor)
{
    struct sn_flow *first = &monitor->flows.entries[0];
    struct sn_flow *second = &monitor->flows.entries[1];

    first->active = true;
    first->protocol = 6U;
    first->endpoints[0].ipv4[0] = 192U;
    first->endpoints[0].ipv4[3] = 1U;
    first->endpoints[0].port = 40000U;
    first->endpoints[1].ipv4[0] = 152U;
    first->endpoints[1].ipv4[1] = 2U;
    first->endpoints[1].ipv4[2] = 23U;
    first->endpoints[1].ipv4[3] = 104U;
    first->endpoints[1].port = 80U;
    first->packets[0] = 1U;

    second->active = true;
    second->protocol = 17U;
    second->endpoints[0].ipv4[0] = 192U;
    second->endpoints[0].ipv4[3] = 1U;
    second->endpoints[0].port = 40001U;
    second->endpoints[1].ipv4[0] = 192U;
    second->endpoints[1].ipv4[1] = 0U;
    second->endpoints[1].ipv4[2] = 2U;
    second->endpoints[1].ipv4[3] = 1U;
    second->endpoints[1].port = 53U;
    second->packets[0] = 1U;
}

int main(void)
{
    struct winsize terminal_size = {0};
    int master_fd;
    pid_t child;
    int child_status;
    const char keys[] = "\njqq";

    terminal_size.ws_row = 30U;
    terminal_size.ws_col = 120U;
    child = forkpty(&master_fd, NULL, NULL, &terminal_size);
    assert(child >= 0);
    if (child == 0) {
        struct sn_monitor monitor;

        (void)setenv("TERM", "xterm", 1);
        sn_monitor_init(&monitor, UINT64_MAX);
        seed_flows(&monitor);
        _exit(sn_ui_run(&monitor, false, false, NULL, NULL));
    }

    assert(write(master_fd, keys, sizeof(keys) - 1U) == (ssize_t)(sizeof(keys) - 1U));
    assert(waitpid(child, &child_status, 0) == child);
    assert(WIFEXITED(child_status));
    assert(WEXITSTATUS(child_status) == 0);
    assert(close(master_fd) == 0);
    puts("curses pty interaction test passed");
    return 0;
}
