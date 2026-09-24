# XDP Firewall

A kernel-level packet filter for Linux built with **eBPF and XDP**. Rules are enforced in-kernel at the network driver layer — before the kernel builds a socket buffer for the packet — and are hot-reloaded from a JSON rules file with no restart required.

## Why XDP

Most simple firewalls hook into the network stack via netfilter (`iptables`-style) or a userspace queue like `libnetfilter_queue`, which means every packet crosses the kernel/userspace boundary for a filtering decision. XDP (eXpress Data Path) runs the filtering logic directly in the kernel at the earliest point traffic reaches the driver — closer to how high-throughput production systems (e.g. Cloudflare's L4Drop, Meta's Katran) handle filtering and load balancing at scale. The trade-off is a more constrained programming model: the in-kernel program runs inside the eBPF verifier's sandbox, so it can't use arbitrary loops, dynamic memory, or unbounded recursion.

## Architecture

- **`firewall.bpf.c`** — the in-kernel XDP program. Parses each incoming packet's Ethernet, IP, and TCP/UDP headers with explicit, verifier-required bounds checks, then applies rules in this order: reject IP fragments outright, reject malformed/truncated headers, check the source IP against `ip_blacklist` (applies to every protocol, including ICMP — not just TCP/UDP), then check source/destination port against `port_blacklist` for TCP/UDP traffic specifically.
- **`firewall.c`** — the userspace loader and control plane. Loads and attaches the compiled BPF object via a libbpf skeleton, parses `rules.json` into the kernel-side blacklist maps, and watches the rules file's containing directory via `inotify` so edits — including atomic rename-based edits (`mv newfile.json rules.json`) — are picked up live. On every reload, both maps are fully cleared and repopulated from the current file, so removing a rule genuinely un-blocks it rather than only ever accumulating entries.
- **`map_loader.c/h`** — pure validation and BPF map I/O, kept separate from `main()` specifically so it can be linked into unit tests without pulling in the daemon's entry point.
- **`rules_parser.c/h`** — reads and parses `rules.json` (via cJSON).
- **`rules_notify.c/h`** — wraps `inotify`, watching the rules file's directory and filtering events to the specific filename.
- **`config.h`** — shared constants (file paths, JSON key names, buffer sizes).

## Features

- **In-kernel packet filtering** at the XDP hook — no userspace round-trip per packet.
- **Source IP blacklisting**, enforced regardless of protocol (ICMP, TCP, UDP, or anything else IP-encapsulated).
- **Source and destination port blacklisting** for TCP/UDP traffic.
- **Fail-closed on malformed input** — a packet that claims to be IPv4/TCP/UDP but whose headers don't actually fit the buffer is dropped, not passed through; the same applies to any IP fragment, since a fragment other than the first doesn't carry the port information needed to filter it.
- **Live rule reload** that correctly handles both in-place edits and atomic rename-based edits, and correctly removes stale entries on every reload — not just an accumulating allow/deny list.
- **Clean lifecycle** — SIGINT/SIGTERM detach the XDP program and free resources before exit, rather than leaving an orphaned program attached to the interface.

## Requirements

- Linux kernel with XDP/BPF support (5.x+ recommended)
- `clang`, `gcc`, `bpftool`, `libbpf`, `libelf`, `zlib`
- Root privileges (or `CAP_NET_ADMIN` / `CAP_BPF`) to attach an XDP program to an interface

## Build

```bash
make
```

## Usage

```bash
sudo ./firewall <interface>
```

Attaches the XDP filter, loads the initial rules from `rules.json`, and watches for changes to that file — editing and saving it (including via a temp-file-and-rename pattern) applies the new rules live. `Ctrl+C` detaches cleanly.

## Rules format

`rules.json`:

```json
{
    "ip_blacklist": ["190.190.190.190"],
    "port_blacklist": ["9999"],
    "dst_port_blacklist": ["22"]
}
```

## Testing

This project is validated across three distinct layers, each catching a different class of bug:

- **Unit tests** (`make run_parser_test`, `make run_inotify_test`) — pure parsing/validation logic and the inotify file-watching mechanism, tested in isolation from BPF with no root privileges required.
- **In-kernel program verification** (`make run_xdp_test`) — the compiled XDP program run for real inside the kernel's BPF verifier via `BPF_PROG_TEST_RUN`, against hand- and scapy-crafted packets covering blacklist matches, malformed headers, and fragmentation. Requires root.
- **Network-namespace integration tests** (`tests/test_integration.sh`) — the full daemon attached to a real interface inside an isolated network namespace, exercised with real traffic (`ping`, `nc`, `hping3`, raw scapy frames), covering attach/detach lifecycle, signal handling, live rule reload (including the remove-a-rule case), and resource behavior over repeated reload cycles. Requires root.

## Known limitations

- **No connection state tracking.** Every packet is evaluated independently — there's no notion of an established connection, so this doesn't distinguish return traffic on an allowed connection from unsolicited traffic. This is the natural next step (see Future work).
- **IPv4 only.** IPv6 traffic is currently passed through unfiltered.
- **Blacklist, not allowlist.** Default-allow with explicit blocks is simpler to reason about for a portfolio project, but is the less secure default posture compared to default-deny.
- **No CIDR range support.** Rules match individual IPs; blocking a subnet requires listing every address in it.

## Future work

- Connection-state tracking (stateful filtering)
- CIDR range and rule-priority support
- IPv6 support
- Packet/drop counters exposed via a BPF map for basic observability
