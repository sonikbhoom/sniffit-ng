#include "sniffit_ng/ui_window.h"

size_t sn_ui_window_start(size_t item_count,
                          size_t selected,
                          size_t visible_count,
                          size_t current_start)
{
    size_t maximum_start;

    if (item_count == 0U || visible_count == 0U) {
        return 0U;
    }
    if (selected >= item_count) {
        selected = item_count - 1U;
    }
    maximum_start = item_count > visible_count ? item_count - visible_count : 0U;
    if (current_start > maximum_start) {
        current_start = maximum_start;
    }
    if (selected < current_start) {
        current_start = selected;
    } else if (selected - current_start >= visible_count) {
        current_start = selected - visible_count + 1U;
    }
    return current_start;
}

bool sn_ui_detail_should_dismiss(int key)
{
    return key == 27;
}
