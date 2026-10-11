#ifndef SNIFFIT_NG_UI_H
#define SNIFFIT_NG_UI_H

#include "sniffit_ng/monitor.h"
#include "sniffit_ng/network_info.h"
#include "sniffit_ng/ui_window.h"

#include <stdbool.h>

enum sn_ui_poll_result {
    SN_UI_POLL_IDLE,
    SN_UI_POLL_UPDATED,
    SN_UI_POLL_STOPPED
};

typedef enum sn_ui_poll_result (*sn_ui_poll_callback)(void *context,
							      const char **status);

int sn_ui_run(struct sn_monitor *monitor,
		const struct sn_network_info *network_info,
		bool recording_active,
		bool payload_inspection_active,
		const struct sn_ui_priority_port *priority_ports,
		size_t priority_count,
		sn_ui_poll_callback poll_capture,
		void *poll_context);

#endif
