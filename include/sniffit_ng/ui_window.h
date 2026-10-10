#ifndef SNIFFIT_NG_UI_WINDOW_H
#define SNIFFIT_NG_UI_WINDOW_H

#include <stdbool.h>
#include <stddef.h>

size_t sn_ui_window_start(size_t item_count,
                          size_t selected,
                          size_t visible_count,
                          size_t current_start);

bool sn_ui_detail_should_dismiss(int key, int timeout_key, int resize_key);

#endif
