#include "sniffit_ng/ui_window.h"

#include <assert.h>
#include <stdio.h>

static void test_selection_scrolls_down_and_up(void)
{
    assert(sn_ui_window_start(100U, 0U, 10U, 0U) == 0U);
    assert(sn_ui_window_start(100U, 9U, 10U, 0U) == 0U);
    assert(sn_ui_window_start(100U, 10U, 10U, 0U) == 1U);
    assert(sn_ui_window_start(100U, 35U, 10U, 26U) == 26U);
    assert(sn_ui_window_start(100U, 25U, 10U, 26U) == 25U);
    assert(sn_ui_window_start(100U, 99U, 10U, 90U) == 90U);
}

static void test_resize_clamps_window(void)
{
    assert(sn_ui_window_start(6U, 5U, 10U, 0U) == 0U);
    assert(sn_ui_window_start(100U, 75U, 20U, 60U) == 60U);
    assert(sn_ui_window_start(100U, 75U, 5U, 60U) == 71U);
    assert(sn_ui_window_start(4U, 3U, 2U, 50U) == 2U);
}

static void test_empty_and_out_of_range_inputs(void)
{
    assert(sn_ui_window_start(0U, 0U, 10U, 4U) == 0U);
    assert(sn_ui_window_start(10U, 2U, 0U, 4U) == 0U);
    assert(sn_ui_window_start(10U, 100U, 3U, 0U) == 7U);
}

static void test_detail_closes_only_on_escape(void)
{
    assert(!sn_ui_detail_should_dismiss(-1, -1, -2));
    assert(!sn_ui_detail_should_dismiss(-2, -1, -2));
    assert(sn_ui_detail_should_dismiss(27, -1, -2));
    assert(sn_ui_detail_should_dismiss('q', -1, -2));
    assert(sn_ui_detail_should_dismiss('\n', -1, -2));
    assert(sn_ui_detail_should_dismiss(' ', -1, -2));
}

int main(void)
{
    test_selection_scrolls_down_and_up();
    test_resize_clamps_window();
    test_empty_and_out_of_range_inputs();
    test_detail_closes_only_on_escape();
    puts("ui window tests passed");
    return 0;
}
