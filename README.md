# Sniffit NG

Sniffit NG is a security-focused C successor to the legacy Sniffit monitor, developed in a separate source tree. It supports bounded Ethernet and Linux cooked v1 (SLL) IPv4 parsing, offline pcap replay, privilege-reduced live capture, bidirectional flow summaries, and an ncurses monitor. Other libpcap link types are rejected unless explicitly implemented and tested.

This repository currently has no license. Public visibility does not itself grant permission to reuse, modify, or redistribute the code.

## Monitor and Protocol Decoding

In the live curses view, select a flow and press Enter to open the inspection pane on the right. The flow list remains visible on the left (about 40% of the terminal); the detail pane uses the remaining width. New records append to a bounded scrolling history instead of replacing the pane. Use arrow keys or `j`/`k` to switch the inspected flow without closing it; other keys close the pane.

Packet decoding is protocol-wide, not limited to ICMP. Active metadata summaries currently include TCP, packet-local HTTP/1.x, TLS record metadata, DNS over UDP/TCP, DHCPv4/BOOTP, generic UDP, NTP, SNMP, Syslog, RADIUS, TACACS+, QUIC, RTP/RTCP, ICMP, IGMP, and VRRP. Each flow retains at most 16 recent metadata records. Fixed service hints are derived only from protocol and port, never packet content.

HTTP summaries include request method and a validated Host, or response status plus allowlisted Server, Content-Type, and numeric Content-Length fields. Paths, query strings, cookies, Set-Cookie, authorization headers, and bodies are omitted. TCP stream reassembly is not implemented, so HTTP fields split across packets may not be recognized. HTTPS is not decoded as plaintext HTTP.

DNS summaries include query/response, opcode/rcode, section counts, and the first safely decoded question name/type/class. Compression pointers are bounded and checked for loops; answer data and TXT values are not displayed. TCP DNS is decoded from complete length-prefixed messages in one packet; stream reassembly is not implemented.

TLS summaries include record version/type and packet-local handshake type/length. SNI, certificates, and record contents are not decoded; split TLS records may be missed because stream reassembly is not implemented.

QUIC summaries expose invariant-header version/type and connection-ID lengths, or only packet length for short headers; connection IDs and protected bytes are not shown. RTP/RTCP summaries report validated sequence/header identifiers, packet type/counts, and lengths without media data. Syslog shows only PRI/facility/severity and message length. RADIUS and TACACS+ show packet-level identifiers/type/counts while omitting attribute values and authentication data.

DHCPv4/BOOTP summaries include the operation or message type, transaction ID, client hardware type/address, lease duration, and option count. DHCP options are length-checked; values other than the explicitly summarized fields are omitted.

NTP summaries include version, mode, leap indicator, stratum, poll/precision, and a hexadecimal reference ID; NTP timestamps are omitted. SNMP summaries include version, PDU type, request ID, and varbind count; community strings and varbind values are never displayed.

**Planned modules:** Source files also exist for ICMPv6/Neighbor Discovery, DHCPv6, OSPFv3/RIPng, ARP, LLDP/CDP, STP/RSTP, LACP, BGP, OSPFv2, IS-IS, RIP, HSRP/GLBP, MPLS, GRE, IP-in-IP, VXLAN, and Geneve. These are inert placeholders, not plugins or supported decoders: they are compiled but are not connected to the dispatcher and always report “not decoded.” They require their listed parser prerequisites and tests before activation.

HTTP analysts can supply an optional compile-time metadata extension source with `-DSNIFFIT_NG_CUSTOM_HTTP_DECODER_SOURCE=/path/to/http_extension.c`. Implement `sn_http_decode_extension` as declared in [`include/sniffit_ng/http_decode_extension.h`](include/sniffit_ng/http_decode_extension.h). The hook receives one bounded TCP payload span and may add a short printable summary. Its default implementation is inert. This is a trusted source-code customization point, not a runtime full-disclosure switch or a built-in raw dump.

ICMP Echo payload samples are a separate, opt-in feature controlled by the acknowledged inspection setting below. Other protocol payload contents are not retained by built-in decoders.

Flow masks affect which connections are shown, not which packets are captured or counted. Source and destination host/port masks are optional and combine as endpoint pairs; because each flow is bidirectional, either traffic direction can satisfy the pair. Setting a host mask to `all` or a port mask to `0` clears that individual mask. Flows are listed deterministically by protocol and endpoints.

## Build and test

Requirements: C17 compiler, CMake 3.16 or newer, pkg-config, libpcap, and ncursesw development files.

```sh
cmake -S . -B build -DSNIFFIT_NG_ENABLE_SANITIZERS=ON
cmake --build build
ctest --test-dir build --output-on-failure
./build/sniffit-ng --help
./build/sniffit-ng --read-pcap capture.pcap
sudo ./build/sniffit-ng --interface lo
```

To record packets from an offline replay or live interface to a new pcap file, use `--write-pcap FILE`. Since a pcap retains complete packet contents, recording requires the interactive privacy/authorization acknowledgment. The file is created exclusively with owner-only permissions; existing files and symlinks are rejected. Live output is opened only after capture privileges are dropped.

```sh
./build/sniffit-ng --read-pcap input.pcap --write-pcap output.pcap
sudo ./build/sniffit-ng --interface lo --write-pcap loopback.pcap
```

### Packet Parser Fuzzing

With Clang/libFuzzer installed, build the optional Ethernet/SLL parser fuzzer and run a short smoke pass:

```sh
cmake -S . -B build/fuzz -DCMAKE_C_COMPILER=clang \
	-DSNIFFIT_NG_BUILD_PACKET_FUZZER=ON -DBUILD_TESTING=OFF
cmake --build build/fuzz --target fuzz_packet
./build/fuzz/fuzz_packet -runs=5000 -max_len=1024
```

The harness tries raw inputs and structured IPv4 frames over Ethernet/SLL, including TCP, UDP, ICMP, IGMP, and VRRP. Use a persistent corpus and longer runs for sustained fuzzing.

The viewer supports offline pcap replay and live capture with `--interface DEVICE` on Ethernet and Linux cooked v1 (SLL) links. Live mode defaults to non-promiscuous capture; `--promiscuous` must be explicitly requested. On Linux, install a protected, root-owned copy with `CAP_NET_RAW` in its permitted set to avoid running the full application through `sudo`:

```sh
sudo setcap cap_net_raw+p /usr/local/bin/sniffit-ng
getcap /usr/local/bin/sniffit-ng
/usr/local/bin/sniffit-ng --interface lo
```

The application makes only `CAP_NET_RAW` effective while opening pcap, then clears capabilities and sets `no_new_privs` before parsing packets, writing logs, or entering curses. A sudo invocation from a regular user is also supported when `SUDO_UID` and `SUDO_GID` are available. Do not set file capabilities on a developer-writable build artifact: any user able to execute that binary can capture traffic available to the process. Promiscuous mode may require additional privilege and is not granted by `CAP_NET_RAW` alone. The parser borrows pointers into the caller's capture buffer; those views are valid only until the next read from the source.

Persistent payload logging is disabled by default. To enable it for one offline replay, run `./build/sniffit-ng --read-pcap capture.pcap --payload-logging`; the program requires an interactive acknowledgment before opening the capture. It creates `sniffit-ng-payload.log` exclusively with owner-only permissions and writes validated payload bytes as hex. Use `--payload-log PATH` with `--payload-logging` to choose another new path; existing files and symlinks are not followed. Review the warning, confirm authorization and consent, protect the output, and delete it according to your retention policy. Without a controlling terminal, logging fails closed.

## ICMP Echo Payload Inspection

Flow summaries and protocol metadata work without payload inspection. `--inspect-payloads` enables the Enter detail view to display sanitized ICMP Echo payload records. At most 16 recent records per flow are kept in memory, each with at most 64 payload bytes; new records append to the open scrolling pane. This feature does not write payload bytes to disk. To avoid repeating the ethical acknowledgment, place this exact active comment in the config file:

```ini
inspect_payloads = true
## User has acknowledged to behave ethically and inspect only authorized traffic.
```

By default, the config is read from `$XDG_CONFIG_HOME/sniffit-ng/config`, or `~/.config/sniffit-ng/config` when `XDG_CONFIG_HOME` is unset. Pass `--config FILE` to use another file. The `--inspect-payloads` switch can enable inspection for one run, but an acknowledgment in the loaded config is still required. If inspection is enabled in config, it is active for that run without the switch. The program prints a reminder that inspection must be authorized and handled ethically. Missing acknowledgment fails closed. The shipped [`sniffit-ng.conf.example`](sniffit-ng.conf.example) keeps inspection disabled and its acknowledgment line commented out.

This persisted acknowledgment applies only to in-memory ICMP Echo display. Persistent payload logging remains a separate feature and still requires the interactive per-run acknowledgment described above.
