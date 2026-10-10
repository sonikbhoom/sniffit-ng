# Legacy Feature Parity

This checklist records documented legacy behavior and the intended Sniffit NG disposition. It is based on `man/sniffit.8`, `man/sniffit.5`, and the reviewed source, not assumptions about undocumented behavior.

| Legacy behavior | Sniffit NG disposition | Status |
| --- | --- | --- |
| `-i` curses live monitor | Preserve the connection-list-first workflow and familiar keyboard navigation. | Initial offline/live viewer implemented; additional parity interactions remain |
| `-I` extended connection descriptions | Preserve useful protocol/port descriptions with bounded, sanitized text. | Planned |
| Arrow keys / `j` / `k` selection | Preserve. | Implemented with scroll-window handling and resize clamping; window helper unit-tested |
| F1/F2 or `1`/`2` source/destination host masks | Preserve with validated IPv4 input and clear reset state. | Implemented in offline viewer |
| F3/F4 or `3`/`4` source/destination port masks | Preserve with strict numeric range validation. | Implemented in offline viewer |
| Enter to inspect/log a selected connection | Preserve flow details. Bounded ICMP Echo payload display is in-memory and config-acknowledged; persistent payload recording is a separate per-run acknowledged option. | ICMP Echo request/reply ID, sequence, and sanitized 64-byte sample implemented; config acknowledgment and opt-out behavior tested |
| `n` packet-rate panel sampled every three seconds | Preserve, including IP/TCP/ICMP/UDP counters, with timer updates on the UI event loop. | Three-second live packet/byte sampler implemented, unit-tested, and visually confirmed by the user |
| `r` reset and `q` quit/stop logging | Preserve with predictable state transitions and graceful shutdown. | Reset and quit implemented; logging state pending |
| Live capture and interface selection | Preserve; determine link type from capture metadata and validate supported framing. | Capture/privilege implementation and post-drop loopback probe passed; user confirmed live curses rendering |
| Offline pcap input (`-r`) | Preserve and infer link type from the pcap instead of requiring a manually forced device. | Ethernet offline replay implemented |
| TCP/UDP/ICMP/IP filtering and summaries | Preserve protocol selection and bounded packet summaries. | Bounded flow summaries and protocol counters implemented |
| `-d`, `-a`, `-x` terminal dump modes | Provide equivalent output modes if useful after core capture/UI parity. | Planned |
| `-L` application-protocol logging | Replace automatic credential detection/extraction. Only explicit, acknowledged payload logging may persist payload bytes. | Deliberate change |
| `-M` native in-process plugins | Do not load arbitrary native plugins into the privileged process. Prefer bounded built-in decoders; evaluate isolation only for a concrete extension need. | Deliberate change |
| F5-F8 execute current-directory helper programs | Do not preserve implicit arbitrary execution. Consider a documented, configured, allowlisted action interface only if required. | Deliberate change |
| `g` packet generation | Keep disabled by default; if retained, require a separate runtime option and explicit authorization acknowledgment. | Planned, gated |
| Legacy config syntax | Support a validated migration subset; reject malformed input instead of silently continuing or overrunning buffers. | Planned |
| Sniffit NG config | Store opt-in payload inspection and its ethical acknowledgment comment; reject malformed/unknown options. | Implemented for `inspect_payloads` with exact `##` acknowledgment marker |
| Legacy interface-wide root execution | Replace with least-privilege capture setup and privilege drop before packet processing/UI work. | Deliberate change |

## Initial Keys

`j`/`k` and arrow keys navigate; F1-F4 or `1`-`4` set host/port masks; Enter opens selected-flow details; `n` toggles packet statistics; `r` resets current flow state; `q` exits or closes the selected detail/log view. Exact bindings may be refined after a usable curses prototype.
