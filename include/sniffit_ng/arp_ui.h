#ifndef SNIFFIT_NG_ARP_UI_H
#define SNIFFIT_NG_ARP_UI_H

#include "sniffit_ng/arp_analysis.h"
#include "sniffit_ng/arp_view.h"

/* Interactive viewer over completed analysis. Returns 0 on a normal exit. */
int sn_arp_ui_run(const struct sn_arp_analysis *analysis, const struct sn_arp_state *state,
                  const struct sn_arp_view_totals *totals);

#endif
