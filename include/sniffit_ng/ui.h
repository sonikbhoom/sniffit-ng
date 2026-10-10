#ifndef SNIFFIT_NG_UI_H
#define SNIFFIT_NG_UI_H

#include "sniffit_ng/monitor.h"

#include <stdbool.h>

typedef const char *(*sn_ui_poll_callback)(void *context);

int sn_ui_run(struct sn_monitor *monitor,
			  bool payload_logging_active,
			  sn_ui_poll_callback poll_capture,
			  void *poll_context);

#endif
