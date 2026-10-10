#include "sniffit_ng/ui_window.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

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

static void test_flow_order_is_deterministic(void)
{
    struct sn_flow first = {0};
    struct sn_flow second = {0};
    struct sn_flow third = {0};
    struct sn_flow fourth = {0};
    const struct sn_flow *flows[4];

    first.protocol = 6U;
    first.endpoints[0].ipv4[0] = 10U;
    first.endpoints[0].port = 80U;
    first.endpoints[1].ipv4[0] = 10U;
    first.endpoints[1].ipv4[3] = 2U;

    second = first;
    second.endpoints[0].ipv4[0] = 11U;
    third = first;
    third.protocol = 17U;
    fourth = first;
    fourth.endpoints[0].port = 81U;

    flows[0] = &third;
    flows[1] = &second;
    flows[2] = &fourth;
    flows[3] = &first;
    sn_ui_sort_flows(flows, 4U);

    assert(flows[0] == &first);
    assert(flows[1] == &fourth);
    assert(flows[2] == &second);
    assert(flows[3] == &third);
}

static void test_service_hints_are_protocol_specific(void)
{
    assert(strcmp(sn_ui_port_service_name(6U, 22U), "SSH") == 0);
    assert(strcmp(sn_ui_port_service_name(17U, 53U), "DNS") == 0);
    assert(sn_ui_port_service_name(17U, 22U) == NULL);
    assert(sn_ui_port_service_name(1U, 80U) == NULL);
}

static void test_flow_filter_direction_semantics(void)
{
    struct sn_flow flow = {0};
    struct sn_ui_flow_filter filter = {0};

    flow.protocol = 6U;
    flow.endpoints[0].ipv4[0] = 10U;
    flow.endpoints[0].ipv4[3] = 1U;
    flow.endpoints[0].port = 1234U;
    flow.endpoints[1].ipv4[0] = 10U;
    flow.endpoints[1].ipv4[3] = 2U;
    flow.endpoints[1].port = 443U;

    assert(sn_ui_flow_matches(&flow, &filter));

    filter.source_ip_enabled = true;
    memcpy(filter.source_ip, flow.endpoints[0].ipv4, sizeof(filter.source_ip));
    assert(sn_ui_flow_matches(&flow, &filter));

    filter.destination_port_enabled = true;
    filter.destination_port = 443U;
    assert(sn_ui_flow_matches(&flow, &filter));

    memcpy(filter.source_ip, flow.endpoints[1].ipv4, sizeof(filter.source_ip));
    memcpy(filter.destination_ip, flow.endpoints[0].ipv4, sizeof(filter.destination_ip));
    filter.destination_ip_enabled = true;
    filter.source_port_enabled = true;
    filter.source_port = 443U;
    filter.destination_port = 1234U;
    assert(sn_ui_flow_matches(&flow, &filter));

    filter.destination_ip[3] = 3U;
    assert(!sn_ui_flow_matches(&flow, &filter));
    assert(!sn_ui_flow_matches(NULL, &filter));
    assert(!sn_ui_flow_matches(&flow, NULL));
}

static void test_detail_navigation_and_dismissal(void)
{
    assert(sn_ui_detail_navigation_direction(259, 259, 258) == -1);
    assert(sn_ui_detail_navigation_direction(258, 259, 258) == 1);
    assert(sn_ui_detail_navigation_direction('k', 259, 258) == -1);
    assert(sn_ui_detail_navigation_direction('J', 259, 258) == 1);
    assert(sn_ui_detail_navigation_direction('x', 259, 258) == 0);
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
    test_flow_order_is_deterministic();
    test_service_hints_are_protocol_specific();
    test_flow_filter_direction_semantics();
    test_detail_navigation_and_dismissal();
    puts("ui window tests passed");
    return 0;
}
