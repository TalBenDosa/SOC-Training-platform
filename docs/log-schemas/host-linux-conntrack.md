# Linux netfilter connection tracking: `conntrack` and its sysctls

Category: Network / stateful firewall internals (Linux host or Linux-based firewall) · Vendor: netfilter project (conntrack-tools), Linux kernel · Card version: 2026-11-15

Command-line output from a root shell on the firewall. No registry entry; a builder checks terminal output against this card.

## 1. Official sources

| Source | What it confirmed |
|---|---|
| conntrack-tools user manual: https://conntrack-tools.netfilter.org/manual.html (checked 2026-11-15) | `conntrack -L` lines, e.g. `tcp      6 431982 ESTABLISHED src=192.168.2.100 dst=123.59.27.117 sport=34846 dport=993 packets=169 bytes=14322 src=123.59.27.117 dst=192.168.2.100 sport=993 dport=34846 packets=113 bytes=34787 [ASSURED] mark=0 use=1`; `conntrack -E` event lines `[NEW] tcp      6 120 SYN_SENT src=… dst=… sport=… dport=… [UNREPLIED] src=… dst=… sport=… dport=…`, `[UPDATE] tcp      6 432000 ESTABLISHED … [ASSURED]`; `[ASSURED]` = traffic seen in both directions |
| `conntrack(8)` man page: https://manpages.debian.org/bookworm/conntrack/conntrack.8.en.html | `-L` list, `-E` event log, `-C` table counter, `-S` statistics, `-D` delete, `-p` protocol, `-s` / `-d` original-direction source / destination, `--dport`, `--state` (`NONE, SYN_SENT, SYN_RECV, ESTABLISHED, FIN_WAIT, CLOSE_WAIT, LAST_ACK, TIME_WAIT, CLOSE, LISTEN`), `-o extended|timestamp|ktimestamp` |
| Linux kernel docs, `nf_conntrack` sysctl: https://docs.kernel.org/networking/nf_conntrack-sysctl.html (checked 2026-11-15) | Defaults: `nf_conntrack_tcp_timeout_established` 432000 s (5 days), `…_syn_sent` 120, `…_syn_recv` 60, `…_time_wait` 120, `…_close_wait` 60, `…_fin_wait` 120, `nf_conntrack_udp_timeout` 30, `…_udp_timeout_stream` 120; `nf_conntrack_max` defaults to `nf_conntrack_buckets`, which is computed from RAM (memory / 16384, clamped 1024 to 262144); `nf_conntrack_count` = entries now; `nf_conntrack_acct` 0 (packet/byte counters off by default) |

## 2. Native format and delivery

Read live on the box (`conntrack -L`, `conntrack -E`, `sysctl`, `/proc/sys/net/netfilter/`), or shipped as text by `conntrackd` / `ulogd`. One entry per line:

```text
<proto name> <proto number> <seconds left> [<TCP state>] <original tuple> [UNREPLIED] <reply tuple> [ASSURED] mark=<n> [secctx=…] use=<n>
```

The **original** tuple is the direction of the first packet; the **reply** tuple is what the answer must look like (with NAT, its addresses show the translation). The number after the protocol number is the entry's remaining lifetime in seconds, reset by each packet. `packets=` / `bytes=` appear only when `nf_conntrack_acct=1`. `conntrack -L` prints a summary line `conntrack v1.4.x (conntrack-tools): N flow entries have been shown.` to stderr.

## 3. Core field reference

| Token | Meaning |
|---|---|
| `tcp 6` / `udp 17` / `icmp 1` | Protocol name and number |
| `117` | Seconds before the entry expires if nothing more is seen |
| `SYN_SENT`, `SYN_RECV`, `ESTABLISHED`, `FIN_WAIT`, `CLOSE_WAIT`, `LAST_ACK`, `TIME_WAIT`, `CLOSE` | TCP state as tracked by netfilter |
| `src= dst= sport= dport=` (first set) | Original direction |
| `[UNREPLIED]` | No packet seen in the reply direction yet |
| `src= dst= sport= dport=` (second set) | Expected reply |
| `[ASSURED]` | Seen both ways; not dropped first when the table is full |
| `mark=`, `use=` | Connection mark; reference count |
| `[NEW]`, `[UPDATE]`, `[DESTROY]` | Event type, in `-E` output only |

## 4. Samples

```text
root@gf-fw-a:~# conntrack -C
18342
root@gf-fw-a:~# sysctl net.netfilter.nf_conntrack_max net.netfilter.nf_conntrack_tcp_timeout_established
net.netfilter.nf_conntrack_max = 262144
net.netfilter.nf_conntrack_tcp_timeout_established = 432000
root@gf-fw-a:~# conntrack -L -p tcp --state SYN_SENT 2>/dev/null | head -2
tcp      6 117 SYN_SENT src=198.51.100.150 dst=10.30.9.20 sport=40112 dport=5432 [UNREPLIED] src=10.30.9.20 dst=198.51.100.150 sport=5432 dport=40112 mark=0 use=1
tcp      6 116 SYN_SENT src=198.51.100.151 dst=10.30.9.20 sport=40977 dport=5432 [UNREPLIED] src=10.30.9.20 dst=198.51.100.151 sport=5432 dport=40977 mark=0 use=1
root@gf-fw-a:~# conntrack -E -p tcp
[NEW] tcp      6 120 SYN_SENT src=10.30.6.44 dst=198.51.100.20 sport=51022 dport=443 [UNREPLIED] src=198.51.100.20 dst=203.0.113.10 sport=443 dport=51022
[UPDATE] tcp      6 432000 ESTABLISHED src=10.30.6.44 dst=198.51.100.20 sport=51022 dport=443 src=198.51.100.20 dst=203.0.113.10 sport=443 dport=51022 [ASSURED]
```

In the `-E` sample the reply destination `203.0.113.10` is the firewall's public address: source NAT, visible only in the reply tuple.

## 5. Investigation notes

- **Half-open flood:** many `SYN_SENT` entries with `[UNREPLIED]` (the SYN was seen, no answer came back) to one destination port, each living 120 s (`syn_sent` default): count them with `conntrack -L -p tcp --state SYN_SENT | wc -l` and group by `dport`. Mitigation: SYN cookies on the server, per-source limits (`connlimit`, `hashlimit`).
- **Table full:** `nf_conntrack_count` near `nf_conntrack_max` and kernel messages `nf_conntrack: table full, dropping packet` (wording UNVERIFIED) mean new connections are being dropped for everyone.
- **Stale entries:** an idle `ESTABLISHED` flow stays for up to 432000 s (5 days) by default; a client that left without FIN keeps its slot and its permission. Lower the timeout or delete the entry (`conntrack -D -s <ip>`).
- **What the table does not know:** no payload, no application, no user. A stateful filter allows whatever rides inside an allowed flow; that is what application-aware firewalls add.
- `conntrack -L -s <ip>` lists everything an address has open; the countdown number tells you how fresh each entry is.

## 6. Common mistakes

- Reading the third number as elapsed time: it is time **left**.
- Expecting byte counters by default (`nf_conntrack_acct` is 0).
- `[UNREPLIED]` before the original tuple, or `[ASSURED]` on a `SYN_SENT` entry.
- Treating conntrack as a log: `-L` is a snapshot; only `-E` (or conntrackd/ulogd) produces a stream, and nothing is kept after an entry expires.
- Upper-case keys or `src_ip=`: the tokens are `src=`, `dst=`, `sport=`, `dport=`.

## 7. UNVERIFIED

- The exact kernel message text when the table is full.
