# Session Checkpoint

Date: 2026-10-10
Project: `/home/sonik/src/sniffit-ng`
Branch: `main`
Remote: `https://github.com/sonikbhoom/sniffit-ng.git`

## Current State

- Successor repository is independent of `/home/sonik/src/sniffit`; do not edit the legacy tree as part of successor work.
- Ethernet and Linux cooked v1 (SLL) IPv4 capture/parsing are supported. Other link types are rejected until implemented and tested.
- The live NTP check on `ppp0` was confirmed in the curses monitor: one request/reply flow, NTPv4 client/server metadata, stratum 2, server precision -25, and reference ID `84f60be9`. `ntpdate -4 -q time.nrc.ca` also succeeded without adjusting the system clock.
- Active bounded metadata decoders: TCP, packet-local HTTP/1.x, DNS over UDP/TCP, DHCPv4/BOOTP, generic UDP, NTP, SNMP, TLS record metadata, QUIC header metadata, RTP/RTCP, Syslog, RADIUS, TACACS+, ICMP, IGMP, and VRRP.
- HTTP built-in summaries omit paths, cookies, authorization, and bodies. A build-time `SNIFFIT_NG_CUSTOM_HTTP_DECODER_SOURCE` hook exists; its default is a no-op. No built-in full packet/body dump is enabled.
- ICMP Echo payload bytes remain separately gated by the exact config acknowledgment and bounded in-memory history. Persistent payload logs and pcap recording require interactive authorization; outputs are exclusive mode 0600.
- Pcap recording via `--write-pcap FILE` preserves link type, caplen/wire length, and timestamps for Ethernet/SLL; existing paths and symlinks are rejected.
- Remaining protocol source files are inert placeholders, not active decoders or runtime plugins. See the protocol backlog in `PLAN.md`.

## Validation

- Full sanitizer CTest suite: 17 passed; live-loopback test skipped because the test runner lacks `CAP_NET_RAW`.
- Non-sanitized `build/live/sniffit-ng` rebuilt successfully.
- Pcap writer tests round-trip Ethernet and SLL frames and verify permissions/no-overwrite behavior.
- Clang/libFuzzer parser target ran 20,000 ASan/UBSan-instrumented mutations over raw and structured Ethernet/SLL IPv4 paths without a fault.
- Linux PTY curses interaction test passes.
- Live NTP traffic was observed on `ppp0` with tcpdump and decoded by Sniffit NG after adding SLL support.

## Next Work

1. Legacy CLI/config compatibility subset, with explicit mapping and validation.
2. Summary/dump output modes that preserve the payload recording policy.
3. Sustained corpus-backed fuzzing, broader malformed pcaps, cross-environment capability tests, and broader PTY coverage.
4. IPv6, additional link-layer/routing support, and the remaining decoder placeholders in dependency order.
5. CPack RPM/DEB packaging, validate installation/removal, and avoid shipping file capabilities.
6. Decide licensing before inviting reuse/contributions.

## Recovery Files

- `SESSION_TRANSCRIPT_2026-10-10.jsonl` is a local copy of the Copilot chat transcript and is excluded from Git because it may include private conversation and machine/network details.
- Do not stage or publish the raw transcript without explicit review and consent.
