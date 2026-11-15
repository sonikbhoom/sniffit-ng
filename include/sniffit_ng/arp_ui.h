#ifndef SNIFFIT_NG_ARP_UI_H
#define SNIFFIT_NG_ARP_UI_H

#include "sniffit_ng/arp_analysis.h"
#include "sniffit_ng/arp_replay.h"
#include "sniffit_ng/arp_view.h"

#include <stddef.h>

enum sn_arp_ui_poll_result {
    SN_ARP_UI_POLL_IDLE,
    SN_ARP_UI_POLL_UPDATED,
    SN_ARP_UI_POLL_STOPPED,
    SN_ARP_UI_POLL_FAILED
};

typedef enum sn_arp_ui_poll_result (*sn_arp_ui_poll_callback)(
    void *context, char *error_buffer, size_t error_capacity);

/* Interactive viewer over completed analysis. Returns 0 on a normal exit. */
int sn_arp_ui_run(const struct sn_arp_analysis *analysis, const struct sn_arp_state *state,
                  const struct sn_arp_view_totals *totals);

/* Live viewer calls poll at a bounded interval; the callback owns capture interaction. */
int sn_arp_ui_run_live(struct sn_arp_replay_stats *stats,
                       struct sn_arp_view_totals *totals,
                       sn_arp_ui_poll_callback poll_callback, void *poll_context,
                       char *error_buffer, size_t error_capacity);

#endif
