/**
 * Learning Rooms — Batch 17 (Room 1)
 *
 * "TCP/IP Internals for Analysts" (tcpip-deep-dive)
 *
 * Advanced deep dive into TCP/IP mechanics for SOC analysts who already know
 * what a port and an IP address are: the TCP flag/state machine, RST vs FIN
 * semantics, scan signatures (SYN/FIN/NULL/XMAS/ACK), fragmentation, TTL and
 * window-size OS fingerprinting, and reading flow records vs full packets.
 */

import type { TelemetryEvent } from "@/lib/sim/types";
import { KQL_PRIMER } from "@/data/kqlPrimer";

// ── Log analysis event 1: SYN scan sweep captured as a NIDS flow record ────
const synScanEvent: TelemetryEvent = {
  id: "evt-tcpip-la1-001",
  ts: "2026-02-11T03:41:07.000Z",
  source: "ids",
  vendor: "Corelight (Zeek)",
  event_type: "net_connection",
  severity: "high",
  hostname: "WKS-ENG14.solvix.local",
  src_ip: "10.40.6.114",
  dst_ip: "10.40.2.30",
  dst_port: 3389,
  protocol: "tcp",
  description:
    "Internal host WKS-ENG14 opened 1,024 short-lived TCP connection attempts to distinct destination ports on SRV-CORE02 within 38 seconds; the representative connection shown below is one of that set and never advanced past the initial packet",
  raw: {
    "id.orig_h": "10.40.6.114",
    "id.orig_p": 51882,
    "id.resp_h": "10.40.2.30",
    "id.resp_p": 3389,
    proto: "tcp",
    service: "-",
    duration: 0.000412,
    orig_bytes: 0,
    resp_bytes: 0,
    conn_state: "S0",
    history: "S",
    orig_pkts: 1,
    orig_ip_bytes: 44,
    resp_pkts: 0,
    resp_ip_bytes: 0,
    missed_bytes: 0,
    local_orig: true,
    local_resp: true,
  },
};

// ── Log analysis event 2: TTL-based OS-fingerprint mismatch on a trusted src ─
const ttlMismatchEvent: TelemetryEvent = {
  id: "evt-tcpip-la2-001",
  ts: "2026-02-14T22:07:51.000Z",
  source: "ids",
  vendor: "Corelight (Zeek)",
  event_type: "net_connection",
  severity: "medium",
  hostname: "SRV-FIN03.solvix.local",
  src_ip: "10.40.1.9",
  dst_ip: "10.40.3.55",
  dst_port: 22,
  protocol: "tcp",
  description:
    "Interactive SSH session from BASTION-01 (10.40.1.9) to the finance file server SRV-FIN03, lasting 41 minutes",
  raw: {
    "id.orig_h": "10.40.1.9",
    "id.orig_p": 58211,
    "id.resp_h": "10.40.3.55",
    "id.resp_p": 22,
    proto: "tcp",
    service: "ssh",
    duration: 2460.7,
    orig_bytes: 51244,
    resp_bytes: 118902,
    conn_state: "SF",
    history: "ShAdDaFf",
    orig_pkts: 588,
    resp_pkts: 640,
    orig_ttl: 125,
    resp_ttl: 61,
    window_size_orig: 64240,
  },
};

const tcpipDeepDiveRoom = {
  id: "tcpip-deep-dive",
  title: "TCP/IP Internals for Analysts",
  description:
    "Go beyond 'TCP uses a three-way handshake' into the internals a working SOC analyst actually reads: flag combinations and the full connection state machine, RST vs FIN semantics, retransmissions, fragmentation, TTL and window-size OS fingerprinting, the exact signatures of SYN/FIN/NULL/XMAS/ACK scans, and how to tell what a flow record can and cannot show you compared to a full packet capture.",
  difficulty: "advanced" as const,
  category: "Network Security" as const,
  estimatedMinutes: 65,
  xp: 400,
  icon: "🔬",
  prerequisites: ["networking-fundamentals", "firewall-network-security"],
  tasks: [
    // ── Reading 1: TCP header + handshake state machine ─────────────────────
    {
      type: "reading" as const,
      id: "tcpip-r1",
      heading: "The TCP Header, Its Flags, and the Full Connection State Machine",
      content:
        `Every beginner learns "TCP does a three-way handshake: SYN, SYN-ACK, ACK." That sentence is true but useless during an investigation, because an investigation is never about the happy path — it's about the packet that broke the pattern. To read that packet, you need to know what's actually inside a TCP header and what state a connection is in at every point of its life.\n\n` +
        `**The TCP header, field by field**\n\n` +
        `Beyond source port and destination port, a TCP segment carries: a 32-bit **sequence number** (which byte of the stream this segment starts at), a 32-bit **acknowledgment number** (the next byte the sender expects to receive, valid only when the ACK flag is set), a **window size** (how many bytes the sender is willing to receive before requiring another acknowledgment — used for flow control, and, as you'll see later, for OS fingerprinting), and six single-bit **control flags**: URG, ACK, PSH, RST, SYN, and FIN. Two more flags, ECE and CWR, exist for Explicit Congestion Notification and are rarely relevant to security work. Every TCP segment you will ever look at in a SIEM, a flow log, or a packet capture is defined by which of these flags are set.\n\n` +
        `**What each flag actually means**\n\n` +
        `- **SYN** — "I want to synchronize sequence numbers with you," i.e. open a new connection.\n` +
        `- **ACK** — "I am acknowledging data or a control flag you sent me." Set on almost every segment after the handshake.\n` +
        `- **PSH** — "Don't buffer this, push it to the application immediately." Common on interactive traffic (SSH keystrokes) and rare on bulk transfers.\n` +
        `- **URG** — "Some of this data is urgent," rarely used in modern traffic; unexpected URG traffic is itself worth a second look.\n` +
        `- **RST** — "Abort this connection immediately, right now, no negotiation." Covered in depth in the next reading.\n` +
        `- **FIN** — "I have no more data to send, let's close this gracefully." Also covered next.\n\n` +
        `**The TCP state machine**\n\n` +
        `A TCP connection is not just "open" or "closed" — it moves through a defined sequence of states, and both the client and server independently track their own side: CLOSED -> LISTEN (server waiting) -> SYN_SENT (client sent SYN) -> SYN_RECEIVED (server got SYN, sent SYN-ACK) -> ESTABLISHED (three-way handshake complete, data can flow) -> FIN_WAIT_1 / CLOSE_WAIT (one side initiated close) -> FIN_WAIT_2 / LAST_ACK -> TIME_WAIT -> CLOSED. TIME_WAIT deserves a specific mention: after a connection closes, the side that sent the final ACK holds the connection in TIME_WAIT for a period (commonly 2 minutes) purely so that any stray, delayed duplicate packets from the old connection are recognized and discarded rather than confused with a brand-new connection reusing the same port pair. A host with an enormous number of connections stuck in TIME_WAIT is either extremely busy or the target of a connection-exhaustion attack.\n\n` +
        `**Why this matters for detection**\n\n` +
        `Nearly every network-based attack technique — port scanning, session hijacking, evasion via crafted flags, firewall/IDS fingerprinting — works by deliberately sending flag combinations or sequence numbers that a normal TCP stack would never produce on its own. You cannot recognize an abnormal flag combination if you don't have the normal state machine memorized cold first.`,
      codeExample:
        "TCP HEADER FLAGS -- THE SIX YOU MUST KNOW\n" +
        "=======================================================\n" +
        "Bit   Flag   Meaning\n" +
        "-------------------------------------------------------\n" +
        "1     URG    Urgent pointer field is significant\n" +
        "1     ACK    Acknowledgment field is significant\n" +
        "1     PSH    Push buffered data to the application now\n" +
        "1     RST    Abort the connection immediately\n" +
        "1     SYN    Synchronize sequence numbers (open conn)\n" +
        "1     FIN    No more data from sender (graceful close)\n" +
        "=======================================================\n\n" +
        "NORMAL THREE-WAY HANDSHAKE (FLAGS SET ON EACH SEGMENT)\n" +
        "=======================================================\n" +
        "Client -> Server   [SYN]                seq=x\n" +
        "Server -> Client   [SYN, ACK]            seq=y ack=x+1\n" +
        "Client -> Server   [ACK]                 seq=x+1 ack=y+1\n" +
        "  ... connection is now ESTABLISHED, data flows ...\n" +
        "=======================================================\n\n" +
        "TCP CONNECTION STATE MACHINE (SIMPLIFIED)\n" +
        "=======================================================\n" +
        "CLOSED -> LISTEN (server) / SYN_SENT (client)\n" +
        "        -> SYN_RECEIVED -> ESTABLISHED\n" +
        "        -> FIN_WAIT_1 / CLOSE_WAIT\n" +
        "        -> FIN_WAIT_2 / LAST_ACK\n" +
        "        -> TIME_WAIT -> CLOSED\n" +
        "=======================================================",
      checkpoint: {
        question:
          "According to the reading, why does a TCP connection hold in the TIME_WAIT state after closing?",
        options: [
          "So that the operating system's audit subsystem has time to permanently log the connection's start and end timestamps for compliance before the socket is released",
          "So that any stray, delayed duplicate packets from the old connection are recognized and discarded rather than confused with a new connection reusing the same port pair",
          "Because the SYN flag carries a mandatory cooldown timer enforced by the TCP/IP stack, preventing the same initial sequence number from being reused by a new connection",
          "To wait for the destination host to send one final SYN-ACK acknowledging that all previously transmitted data segments were received intact",
        ],
        answer: 1,
        explanation:
          "TIME_WAIT exists purely so any late-arriving duplicate packets from the just-closed connection are recognized as stale rather than misinterpreted by a brand-new connection reusing the same port pair. It commonly lasts around 2 minutes. It has nothing to do with audit logging, a SYN-reuse cooldown timer (no such mechanism exists), or waiting on a further SYN-ACK — the connection is already fully closed by this point.",
      },
    },

    // ── Reading 2: RST vs FIN semantics ─────────────────────────────────────
    {
      type: "reading" as const,
      id: "tcpip-r2",
      heading: "RST vs FIN: Graceful Close, Abrupt Abort, and Injected Resets",
      content:
        `RST and FIN both end a TCP connection, but they mean fundamentally different things, and confusing them will lead you to misread a firewall block as an application error, or worse, miss an active hijack attempt.\n\n` +
        `**FIN — the polite goodbye**\n\n` +
        `FIN means "I have no more data to send." A graceful close is a four-step exchange: the initiating side sends FIN, the other side ACKs it and (usually shortly after) sends its own FIN, which is then ACKed in turn. Both sides get to finish sending whatever data they still had queued before the connection fully closes. This is what you see at the end of a normal HTTP session, an SSH logout, or a completed file transfer. In a flow log, a connection that ends this way typically shows both sides' byte counters non-zero and a clean four-packet teardown.\n\n` +
        `**RST — the abrupt slam**\n\n` +
        `RST means "something is wrong, abandon this connection immediately, no negotiation, no guarantee of delivering any remaining data." There is no acknowledgment expected for an RST beyond the immediate teardown. RST appears in several very different situations, and telling them apart is a core analyst skill:\n\n` +
        `1. **Port closed, nothing listening.** When a SYN arrives at a port with no service bound to it, the OS's TCP/IP stack immediately replies with RST,ACK. This is the normal, completely benign response to a probe against a closed port — and it's also the exact signal a SYN scan uses to map which ports are closed.\n` +
        `2. **Firewall/IPS reject action.** Many firewalls, when configured to REJECT rather than silently DROP, spoof an RST back to the sender on the firewall's behalf, making a blocked connection look identical, to the sender, to a closed port. The visible difference to an analyst is usually only in the firewall's own logs (an explicit deny/reject rule match) versus what the destination host itself would have generated.\n` +
        `3. **Application-level refusal.** A service can be up and listening but still send RST — for example, a web server hitting a connection limit, or a security control (IPS, WAF) injecting a spoofed RST mid-session to kill a connection it has decided is malicious, without ever touching the actual client or server.\n` +
        `4. **Mid-session RST as evidence of tampering.** A connection that was ESTABLISHED, exchanged real data for some time, and then received an unexpected RST is a very different finding than a RST that arrives one packet after the initial SYN. A mid-session RST can mean a crashed application, a timeout, an IPS actively terminating a session it flagged as malicious mid-stream, or — in TCP hijacking / session-reset attacks — a spoofed RST injected by an on-path or blind attacker trying to disrupt an active connection (this is exactly what a "RST attack" against long-lived BGP or VPN sessions historically abused).\n\n` +
        `**Reading Zeek's conn_state field: the shortcut that encodes all of this**\n\n` +
        `Zeek (and Corelight sensors built on it) summarize exactly this kind of nuance into a single conn_state code so you don't have to reconstruct it packet by packet: SF (normal establishment and termination), S0 (connection attempt, no reply — the closed-port-or-filtered signature), REJ (connection attempt rejected, i.e. RST received in response to the SYN), RSTO (connection established, then originator sent an RST), RSTR (responder sent the RST), RSTOS0 (originator sent a SYN followed by an RST, without ever getting a SYN-ACK — one of the classic half-open scan artefacts), S1 (connection established, not terminated), OTH (a partial connection, mid-stream, neither a full open nor a full close was observed by the sensor). Memorizing this table turns a wall of flow records into an instantly readable summary of exactly what happened to each connection.`,
      codeExample:
        "ZEEK / CORELIGHT conn_state VALUES -- THE ANALYST CHEAT SHEET\n" +
        "=======================================================\n" +
        "Code     Meaning\n" +
        "-------------------------------------------------------\n" +
        "S0       Connection attempt, no reply seen (filtered or\n" +
        "         silently dropped -- classic scan-against-a-\n" +
        "         firewalled-port signature)\n" +
        "S1       Connection established, not terminated\n" +
        "SF       Normal establishment and termination (SYN,\n" +
        "         SYN-ACK, ACK ... FIN, ACK, FIN, ACK)\n" +
        "REJ      Connection attempt rejected (SYN answered\n" +
        "         with RST,ACK -- port is closed)\n" +
        "RSTO     Originator sent an RST after the connection\n" +
        "         was established\n" +
        "RSTR     Responder sent an RST after the connection\n" +
        "         was established\n" +
        "RSTOS0   Originator sent SYN then RST, never got a\n" +
        "         SYN-ACK back (half-open scan artefact)\n" +
        "RSTRH    Responder sent SYN-ACK then RST, without ever\n" +
        "         seeing a SYN from the originator (spoofed\n" +
        "         source, or scanner tooling artefact)\n" +
        "OTH      No SYN seen; a partial/mid-stream connection\n" +
        "=======================================================\n\n" +
        "FIN (graceful) vs RST (abrupt) -- WHAT EACH LOOKS LIKE\n" +
        "=======================================================\n" +
        "FIN close:  [FIN,ACK] -> [ACK] -> [FIN,ACK] -> [ACK]\n" +
        "            Both byte counters non-zero, clean teardown\n" +
        "RST abort:  [RST] or [RST,ACK], single packet, no\n" +
        "            negotiation, remaining queued data is lost\n" +
        "=======================================================",
      checkpoint: {
        question:
          "According to the reading, what does the Zeek conn_state value 'REJ' indicate?",
        options: [
          "The connection was established, then the originator sent an RST",
          "A connection attempt was rejected — the SYN was answered with RST,ACK, meaning the port is closed",
          "The connection completed a normal handshake and graceful teardown",
          "No SYN was ever observed by the sensor",
        ],
        answer: 1,
        explanation:
          "REJ specifically means the SYN was answered with RST,ACK — the port is closed. This differs from S0 (no reply at all, i.e. filtered/dropped) and from RSTO/RSTR (RST after the connection was already established).",
      },
    },

    // ── Reading 3: scan signatures ───────────────────────────────────────────
    {
      type: "reading" as const,
      id: "tcpip-r3",
      heading: "Scan Signatures: SYN, FIN, NULL, XMAS, ACK, and Full-Connect Scans",
      content:
        `Port scanning tools like nmap deliberately craft nonstandard flag combinations specifically because different combinations produce different, revealing responses from an open vs. closed port. Recognizing the flag pattern of the probe itself, not just the fact that "many ports were touched," lets you identify exactly which scan technique and often which tool was used.\n\n` +
        `**SYN scan (a.k.a. half-open scan, nmap -sS)**\n\n` +
        `The attacker sends only a SYN and never completes the handshake. An open port replies SYN-ACK (the scanner then sends RST instead of ACK, aborting before a full session is ever logged by the application); a closed port replies RST,ACK; a filtered port produces no reply at all, or an ICMP "destination unreachable / administratively prohibited" message. This is the default and most common nmap scan precisely because it is fast and, historically, was less likely to be logged by the target application (though modern NIDS/flow logging catches it easily — that's exactly what conn_state S0/REJ/RSTOS0 records reveal).\n\n` +
        `**FIN, NULL, and XMAS scans — abusing an RFC 793 quirk**\n\n` +
        `These three scans all exploit the same obscure rule in the original TCP specification: if a segment arrives at a **closed** port with no SYN flag set, the correct behavior is to reply with RST. If the same segment arrives at an **open** port, compliant stacks are supposed to silently drop it with no reply at all. This produces a counter-intuitive result: silence means "probably open," a response means "closed."\n` +
        `- **NULL scan** — no flags set at all.\n` +
        `- **FIN scan** — only the FIN flag set (a "close" for a connection that was never opened).\n` +
        `- **XMAS scan** — FIN, PSH, and URG all set together (the packet "lights up like a Christmas tree").\n` +
        `All three exist mainly to slip past older, simpler firewalls that only filter on the SYN flag, and all three are highly unreliable against modern Windows stacks, which frequently reply RST regardless of the state — but they remain extremely recognizable in a flow log precisely because a segment with FIN, NULL, or XMAS flags and **no prior SYN in the same connection** should never occur in legitimate traffic. There is no legitimate reason for any real application to open a "connection" by sending a bare FIN.\n\n` +
        `**ACK scan**\n\n` +
        `An ACK scan sends only an ACK flag with no preceding SYN. It cannot determine open vs. closed at all (a stateless packet filter will let it through to both), but it is specifically designed to map firewall rule sets: if the target replies with RST, the ACK reached the destination unfiltered; if there's no reply, a stateful firewall silently dropped it because it didn't match any established connection in the firewall's own state table. This is a firewall-mapping technique, not a port-discovery technique.\n\n` +
        `**Full connect scan (nmap -sT)**\n\n` +
        `The scanner completes the entire three-way handshake normally, then immediately closes the connection. It is the slowest and the "loudest" (application-level logging on the target will usually see a fully-formed, if extremely brief, connection), but it requires no special raw-socket privileges to run and works identically to a real client connecting, which is precisely why it's what unprivileged scanning tools and scripts default to when they can't craft raw packets.\n\n` +
        `**The single most useful pattern-recognition rule**\n\n` +
        `Any single flag combination is a weak signal on its own — a bare RST or a bare ACK happens constantly in normal traffic. What makes a scan unmistakable is the **breadth**: the same source touching many distinct destination ports (or many distinct destination hosts on the same port) in a short window, each attempt using an identical, nonstandard flag pattern. One NULL-flag packet is noise. A thousand NULL-flag packets from one source to a thousand consecutive ports in forty seconds is a NULL scan.`,
      codeExample:
        "SCAN TYPE -> FLAGS SENT -> RESPONSE FROM OPEN vs CLOSED PORT\n" +
        "=======================================================\n" +
        "Scan       Flags Sent      Open Port Reply   Closed Port Reply\n" +
        "-------------------------------------------------------\n" +
        "SYN        SYN             SYN,ACK            RST,ACK\n" +
        "FULL       SYN->ACK->FIN   full handshake      RST,ACK\n" +
        "           (nmap -sT)      then close\n" +
        "NULL       (none)          no reply            RST\n" +
        "FIN        FIN             no reply            RST\n" +
        "XMAS       FIN,PSH,URG     no reply            RST\n" +
        "ACK        ACK             RST (if unfiltered) RST (if unfiltered)\n" +
        "           (maps firewall  no reply if a stateful firewall\n" +
        "           rules, not      silently dropped it (no matching\n" +
        "           port state)     session in the state table)\n" +
        "=======================================================\n\n" +
        "THE TELL-TALE PATTERN IN A FLOW LOG\n" +
        "=======================================================\n" +
        "One source IP -> hundreds/thousands of destination ports\n" +
        "(or destination IPs) -> short time window -> identical,\n" +
        "nonstandard flag pattern on every attempt -> near-zero\n" +
        "bytes transferred on each -> this is a scan, and the flag\n" +
        "pattern tells you which scan technique was used.\n" +
        "=======================================================",
    },

    // ── Reading 4: fragmentation, TTL, window-size fingerprinting ───────────
    {
      type: "reading" as const,
      id: "tcpip-r4",
      heading: "Fragmentation, TTL, and Window Size: Fingerprinting the OS Behind an IP",
      content:
        `Two hosts can send TCP traffic that looks identical at the port/protocol level, yet be running completely different operating systems — and that OS fingerprint is often the detail that tells you a connection did not come from the device its IP address suggests it did.\n\n` +
        `**IP fragmentation, briefly**\n\n` +
        `Every network link has a Maximum Transmission Unit (MTU) — the largest packet it can carry, typically 1500 bytes on Ethernet. If an IP packet is larger than the MTU of a link it must cross, a router along the path splits it into multiple **fragments**, each carrying a fragment offset (where this piece belongs in the original packet) and a "More Fragments" (MF) flag (set on all fragments except the last). The receiving host reassembles them using those offsets before handing the data up to TCP. Attackers abuse fragmentation deliberately: a tool like fragroute can split a malicious payload across multiple tiny fragments specifically so that an inspection engine which does not fully reassemble traffic before pattern-matching never sees the complete, recognizable payload in any single fragment — the payload only becomes visible again after the target host reassembles it. This is why any modern IDS/IPS must reassemble fragmented streams before running signature matching, and why unusually small, deliberately fragmented packets to a security-sensitive service is itself worth flagging, independent of payload content.\n\n` +
        `**TTL: a free, passive OS hint on every single packet**\n\n` +
        `The IP Time-To-Live (TTL) field is decremented by one at every router hop and exists to prevent packets from looping forever. Different operating systems set a different **initial** TTL when they originate a packet, and while intermediate routers only ever decrement it, they never increase it or reset it back to the OS default. This means the TTL you observe on an inbound packet equals (initial TTL of the sending OS) minus (number of hops it crossed to reach you) — and because initial TTLs cluster around a small set of well-known values, you can work backwards: an observed TTL of 118-125 almost certainly started at 128 (the Windows default) and crossed 3-10 hops; an observed TTL around 54-64 almost certainly started at 64 (the default for Linux and most BSD/macOS systems); a TTL near 245-255 started at 255 (common on Cisco IOS and Solaris). This single field, present on every packet with zero extra logging configuration required, is one of the cheapest and most reliable passive OS-fingerprinting signals available — and it is exactly the kind of detail that flags a mismatch between "the device this IP is supposed to be" and "the device that actually sent this traffic."\n\n` +
        `**Window size and other passive fingerprint features**\n\n` +
        `The initial TCP window size (advertised in the SYN packet), along with details like the set of TCP options offered, their order, and the IP "Don't Fragment" (DF) flag behavior, together form a fingerprint precise enough to distinguish not just Windows-vs-Linux but often specific OS versions — this is exactly what tools like p0f do, passively, from flow metadata alone, with no active probing required. A Windows host's SYN typically advertises a window size of 64240 or 65535 with a specific, ordered set of TCP options; a Linux host's default window and option ordering look different again. None of these signals are individually proof of anything — NAT, load balancers, VPNs, and legitimately reconfigured TCP stacks can all shift these values — but taken together, and especially when they contradict what you expect from a known, baselined asset, they are strong corroborating evidence that deserves a second look before you either dismiss or escalate a finding.`,
      codeExample:
        "INITIAL TTL BY OPERATING SYSTEM (BEFORE HOPS ARE SUBTRACTED)\n" +
        "=======================================================\n" +
        "OS / Platform             Initial TTL   Typical Observed Range\n" +
        "-------------------------------------------------------\n" +
        "Linux / most BSD / macOS  64            54-64  (few hops)\n" +
        "Windows (all modern)      128           110-128\n" +
        "Cisco IOS / Solaris       255           240-255\n" +
        "=======================================================\n" +
        "Rule of thumb: round the observed TTL UP to the nearest\n" +
        "of {64, 128, 255} -- the difference is the hop count.\n" +
        "=======================================================\n\n" +
        "PASSIVE FINGERPRINT FIELDS WORTH BASELINING PER ASSET\n" +
        "=======================================================\n" +
        "Field               What it hints at\n" +
        "-------------------------------------------------------\n" +
        "Initial TTL          Sending OS family + hop count\n" +
        "SYN window size      OS family / version (64240, 65535,\n" +
        "                     5840, 29200 are common defaults)\n" +
        "TCP options + order  OS TCP stack fingerprint (p0f-style)\n" +
        "DF flag behavior     OS-specific path-MTU-discovery habit\n" +
        "=======================================================",
      checkpoint: {
        question:
          "According to the reading, an observed initial TTL of about 118-125 on an inbound packet most likely indicates the sending host's OS started at which initial TTL value?",
        options: [
          "64 (Linux/BSD/macOS default)",
          "128 (Windows default)",
          "255 (Cisco IOS/Solaris default)",
          "32 (a legacy embedded-device default)",
        ],
        answer: 1,
        explanation:
          "TTL 118-125 sits just below 128, the standard Windows initial TTL, after 3-10 hops of decrementing. 64 is the Linux/BSD/macOS default, and 255 is common on Cisco IOS/Solaris.",
      },
    },

    // ── Reading 5: flow records vs full packets ──────────────────────────────
    {
      type: "reading" as const,
      id: "tcpip-r5",
      heading: "Reading Flow Records vs. Full Packet Captures",
      content:
        `Most day-to-day network investigation happens in **flow records** — NetFlow, IPFIX, or Zeek/Corelight conn.log entries — not full packet captures (PCAP). Knowing exactly what a flow record can and cannot tell you is what lets you decide, quickly, whether you need to escalate to pulling a full PCAP at all.\n\n` +
        `**What a flow record gives you**\n\n` +
        `A flow record is metadata about a conversation: the 5-tuple (source IP, source port, destination IP, destination port, protocol), start and end time, packet counts, byte counts in each direction, and — in Zeek's case — the conn_state and history summary you learned earlier. This is enough to answer the vast majority of triage questions: is this connection expected for this asset, is the volume unusual, did it complete normally or get reset, is this a scan pattern, is the timing suspicious. Flow data is compact (a single flow record is a few hundred bytes regardless of whether the underlying conversation carried 10 bytes or 10 gigabytes), which is exactly why it can be retained for months when full PCAP cannot.\n\n` +
        `**What a flow record cannot give you**\n\n` +
        `No payload. You cannot see the HTTP request path, the file that was downloaded, the exact command sent over a shell, or the content of a DNS query from a NetFlow record alone (Zeek is a partial exception — because it does protocol-aware parsing at capture time, it also produces application-layer logs like http.log, dns.log, and ssl.log alongside conn.log, which do carry meaningful application metadata even without a full PCAP; but that's Zeek doing extra work at the moment of capture, not something you can extract from a NetFlow export after the fact). If you need the literal bytes exchanged — to extract a downloaded malware sample, prove exact data exfiltrated, or examine an exploit payload — only a full packet capture will do, and by definition, that capture has to have already been running before or during the incident; you cannot retroactively conjure packet contents from flow metadata.\n\n` +
        `**Zeek's history field — the density of a full packet trace, compressed into a string**\n\n` +
        `Zeek's history field packs an extraordinary amount of detail into a short string: each letter represents an event, uppercase from the originator, lowercase from the responder — S (SYN), h (SYN-ACK), A (pure ACK), D (data sent), F (FIN), R (RST), C (a state-changing packet with a bad checksum), and several more. A history of "ShAdDaFf" reads as: originator sent SYN, responder sent SYN-ACK, originator ACKed, both sides sent data (D then d), originator sent FIN, responder sent FIN back — a completely normal, clean connection close. A history of just "S" (as in this room's first scan example) means exactly one thing happened: a lone SYN, and nothing else — no reply was ever seen by the sensor.\n\n` +
        `**When to escalate from flow to PCAP**\n\n` +
        `Pull a full packet capture (or, if one wasn't already running, deploy one going forward and treat the gap as a limitation of your finding) when: you need to prove or recover exact data content (exfiltrated file contents, exact malicious payload), you're investigating a protocol-level anomaly that flow metadata alone can't explain (a connection classified OTH with unclear byte patterns), or you need packet-level timing/fragmentation detail (evasion techniques, TTL/window fingerprint verification down to individual packets) that a flow record's summary numbers smooth over. For the overwhelming majority of triage — "is this normal, is this a scan, is this beaconing, is this exfil-shaped" — flow records are not just sufficient, they are usually faster to work with because there is far less data to sift through.`,
      codeExample:
        "FLOW RECORD (NetFlow/IPFIX/Zeek conn.log) FIELDS\n" +
        "=======================================================\n" +
        "ts            ts=2026-02-11T03:41:07.000Z\n" +
        "uid           unique connection identifier\n" +
        "id.orig_h/p   source IP / port\n" +
        "id.resp_h/p   destination IP / port\n" +
        "proto         tcp / udp / icmp\n" +
        "service       zeek-detected app protocol (ssh, http, ...)\n" +
        "duration      connection length in seconds\n" +
        "orig_bytes    payload bytes sent by originator\n" +
        "resp_bytes    payload bytes sent by responder\n" +
        "conn_state    S0/SF/REJ/RSTO/RSTR/... (see Reading 2)\n" +
        "history       packet-by-packet summary string\n" +
        "orig_pkts/resp_pkts   packet counts each direction\n" +
        "=======================================================\n\n" +
        "ZEEK history FIELD -- LETTER MEANINGS\n" +
        "=======================================================\n" +
        "Uppercase = originator side   Lowercase = responder side\n" +
        "S  SYN            h  SYN-ACK (lowercase h, responder)\n" +
        "A  pure ACK       D  a packet with payload (data)\n" +
        "F  FIN            R  RST\n" +
        "C  bad checksum   I  inconsistent packet\n" +
        "-------------------------------------------------------\n" +
        "\"ShAdDaFf\"  = normal handshake, data both ways, clean FIN close\n" +
        "\"S\"         = one lone SYN, no reply seen at all (scan artefact)\n" +
        "\"ShR\"       = SYN, SYN-ACK, then originator RST (aborted early)\n" +
        "=======================================================",
    },

    // ── Reading 6: retransmissions, dup ACKs, blackholed connections ────────
    {
      type: "reading" as const,
      id: "tcpip-r6",
      heading: "Retransmissions, Duplicate ACKs, and Spotting Blocked or Beaconing Traffic at Scale",
      content:
        `The last piece of the puzzle is putting flags, state, and byte counts together to answer the question analysts ask constantly: is this connection behaving like normal application traffic, like a scan, or like something checking in on a schedule?\n\n` +
        `**Retransmissions: a signal about the path, not just the endpoint**\n\n` +
        `TCP guarantees delivery by requiring acknowledgment of every segment; if the sender doesn't get an ACK within its retransmission timeout, it resends the segment. A small, occasional retransmission rate is completely normal on any real network (a little packet loss is expected). A **high, sustained** retransmission rate to one specific destination, though, is a meaningful signal: it can mean genuine network congestion or a flaky path, but it can equally mean a firewall or IPS is silently dropping some, but not all, packets of a connection it's suspicious of (rather than cleanly resetting it), or that an attacker's C2 infrastructure sits behind an unstable or heavily rate-limited hop. Either way, "this destination has an abnormal retransmission rate compared to this host's other traffic" is worth pulling into your triage.\n\n` +
        `**Duplicate ACKs and fast retransmit**\n\n` +
        `When a receiver gets segments out of order (one segment was lost, but later ones arrived), it re-sends an ACK for the last byte it received correctly, once for every out-of-order segment it gets — these are duplicate ACKs. Three duplicate ACKs in a row conventionally triggers "fast retransmit," where the sender resends the missing segment without waiting for a full timeout. A burst of duplicate ACKs in a flow log is a fingerprint of packet loss or reordering on that specific path — useful context when you're trying to distinguish "this connection looks weird because of a bad network link" from "this connection looks weird because something is actively interfering with it."\n\n` +
        `**Asymmetric byte counts: reading the shape of a conversation**\n\n` +
        `A normal web browsing session is asymmetric in a predictable way: a small request (orig_bytes, a few hundred bytes) produces a much larger response (resp_bytes, tens of kilobytes of HTML/images/scripts). A connection with the opposite shape — large orig_bytes, tiny resp_bytes, especially over a long duration — is the shape of an upload, and on an unexpected destination or at an unexpected hour, is exactly the shape you'd expect from data being pushed out during exfiltration. A connection with both directions carrying small, remarkably **consistent** byte counts, repeating at regular intervals against the same destination, is the shape of a heartbeat or check-in — legitimate software does this constantly (update checkers, telemetry, license validation) but so does C2 beaconing, which is why byte-count shape alone is never proof, only a prioritization signal.\n\n` +
        `**Putting it together — the analyst's flow-record triage pass**\n\n` +
        `Given any single suspicious flow record, ask in order: (1) What does conn_state/history tell me about how this connection started and ended? (2) Is the flag pattern one that legitimate traffic would ever produce (a bare SYN, a bare FIN/NULL/XMAS with no prior SYN, is inherently abnormal; a full SF close is not)? (3) Is the byte-count shape consistent with the stated protocol/service, and is it symmetric (browsing-like), upload-shaped, or beacon-shaped? (4) Does the initial TTL/window size match what I'd expect from the claimed source asset's known OS? (5) Is this one flow, or one of many identical flows repeating across ports, hosts, or time — and if repeating over time, at what interval? Answering these five questions, in this order, is usually enough to triage a raw flow record into "benign," "needs a second look," or "escalate," before you ever need to touch a full packet capture.`,
      codeExample:
        "THE FIVE-QUESTION FLOW-RECORD TRIAGE PASS\n" +
        "=======================================================\n" +
        "1. conn_state/history -- how did it start and end?\n" +
        "2. Flag pattern -- could legitimate traffic ever look\n" +
        "   like this (bare SYN/FIN/NULL/XMAS = red flag)?\n" +
        "3. Byte-count shape -- symmetric (browsing), upload-\n" +
        "   shaped (large orig, tiny resp), or beacon-shaped\n" +
        "   (small + consistent + repeating)?\n" +
        "4. TTL / window size -- matches the claimed source\n" +
        "   asset's known OS baseline?\n" +
        "5. Repetition -- one-off, or one of many identical\n" +
        "   flows across ports/hosts/time -- and at what interval?\n" +
        "=======================================================\n\n" +
        "EXAMPLE: CONTRASTING THREE FLOW SHAPES\n" +
        "=======================================================\n" +
        "Normal browsing:  orig_bytes=612   resp_bytes=48221\n" +
        "                  conn_state=SF    single connection\n" +
        "\n" +
        "Scan attempt:     orig_bytes=0     resp_bytes=0\n" +
        "                  conn_state=S0    history=S\n" +
        "                  x1,024 across sequential dst ports\n" +
        "\n" +
        "Beacon-shaped:    orig_bytes=214   resp_bytes=198\n" +
        "                  (nearly identical every time)\n" +
        "                  conn_state=SF, repeats every ~60s\n" +
        "=======================================================",
      checkpoint: {
        question:
          "According to the reading, what byte-count shape is typical of C2 beaconing or a legitimate check-in/heartbeat, as opposed to a normal browsing session or a data-exfiltration upload?",
        options: [
          "Small request followed by a much larger response, occurring once as a single, non-repeating connection — the shape of ordinary web browsing, not a beacon",
          "Large orig_bytes paired with a comparatively tiny resp_bytes sustained over one long-lived connection — the asymmetric shape the reading associates with an outbound data upload, not a periodic check-in",
          "Small, remarkably consistent byte counts in both directions, repeating at regular intervals against the same destination",
          "Zero bytes transferred in both directions, with the connection stuck in conn_state S0 because no reply was ever observed — the signature of a failed scan attempt, not an active, established beacon",
        ],
        answer: 2,
        explanation:
          "The reading describes beacon/heartbeat-shaped traffic as small, consistent byte counts repeating at regular intervals against the same destination — distinct from browsing (small request/large response, one-off), from exfiltration-shaped uploads (large orig_bytes, tiny resp_bytes), and from a failed scan attempt (zero bytes, S0, no reply at all — no connection ever completed, so there's nothing to beacon with).",
      },
    },

    // ── Reading 7: Wireshark hands-on ────────────────────────────────────────
    {
      type: "reading" as const,
      id: "tcpip-r7",
      heading: "Reading a Packet Capture in Wireshark",
      content:
        `Everything in the last two readings — flags, conn_state, byte-count shape, retransmissions — is what you reconstruct from *metadata*. The moment you've escalated to a full PCAP, you're looking at the actual bytes, and the tool almost every analyst reaches for to do that is Wireshark. Knowing your way around its interface well enough to move fast under pressure is a distinct skill from understanding TCP theory, and it's the one this reading covers.\n\n` +
        `**The three panes**\n\n` +
        `Wireshark's main window is split into three stacked panes, and learning to move between them fluidly is most of what "reading a PCAP efficiently" actually means. The **packet list** (top) shows one row per captured packet, with columns for No. (capture order), Time (offset from capture start, by default), Source and Destination (IP addresses, or MAC/hostname depending on settings), Protocol (the highest-layer protocol Wireshark identified — TCP, HTTP, DNS, TLS, etc.), and Info (a one-line, protocol-aware summary — for a TCP packet this shows the flags set, sequence/ack numbers, and window size right there, without opening the packet at all). The **packet details** pane (middle) shows the fully decoded protocol stack of whichever single packet is selected in the list, as a set of collapsible layers — Frame, Ethernet, IP, TCP, and then whatever application-layer protocol sits on top — each expandable to see every individual field Wireshark parsed out. The **packet bytes** pane (bottom) shows the same packet as raw hex on the left and its ASCII representation on the right; clicking any field in the details pane highlights the exact bytes it came from in both panes simultaneously, which is the fastest way to confirm you're reading the field you think you're reading rather than trusting a label.\n\n` +
        `**Capture filters vs. display filters — a distinction that trips up beginners constantly**\n\n` +
        `These are two different mechanisms, applied at two different times, using two different syntaxes, and mixing them up wastes real time during an investigation. A **capture filter** is applied before or during capture and decides what gets written to the capture file in the first place — anything that doesn't match is discarded permanently and is never recoverable from that capture. Capture filters use Berkeley Packet Filter (BPF) syntax, the same syntax tcpdump uses — e.g. \`tcp port 445\` or \`host 10.0.0.5 and tcp port 3389\`. Because a capture filter throws data away at capture time, you set it once, before you start capturing, based on what you already know you need — and if it turns out you needed something it excluded, there is no way to get it back; you have to recapture. A **display filter**, by contrast, is applied after the fact to a capture that already exists in full — it never deletes anything, it only controls which rows the packet list currently shows you. Display filters use Wireshark's own syntax (not BPF), typically field-based comparisons like \`tcp.port == 445 && ip.addr == 10.0.0.5\`, or \`http.request.method == "POST"\`, or \`tcp.flags.syn == 1 && tcp.flags.ack == 0\` to isolate bare SYNs. Because nothing underlying is discarded, you can type a display filter, clear it, and type a completely different one, as many times as you like, without ever losing data — which is exactly why, in practice, the standard workflow is to capture broadly (or with only a light capture filter) and do all your actual narrowing with display filters afterward.\n\n` +
        `**Follow TCP Stream — the single most useful feature for understanding a session**\n\n` +
        `Reading a multi-packet conversation one packet at a time is slow and error-prone — you'd be manually stitching together dozens or hundreds of individual segments in your head. Right-click any packet belonging to the conversation you care about, choose Follow, then TCP Stream (the equivalent exists for UDP and HTTP streams too), and Wireshark reassembles the entire conversation, both directions, into one continuous, human-readable view — shown as text by default, with the two directions colored differently, and with a dropdown to switch to hex, C-array, or other renderings. This is how you actually read what a session contained — an HTTP request and its response, a plaintext protocol exchange, the commands sent over an unencrypted shell — without hand-assembling it from the packet list. It also auto-generates the matching display filter (e.g. \`tcp.stream eq 4\`) so you can jump straight back to just those packets in the main view afterward.\n\n` +
        `**File > Export Objects — pulling transferred files back out of a capture**\n\n` +
        `If a session captured in the PCAP actually transferred a file — a download over HTTP, a file copied over SMB, an attachment over SMTP — Wireshark can reassemble and extract that file straight out of the capture, without needing the file from anywhere else. File > Export Objects lists the relevant protocol (HTTP, SMB, DICOM, IMF for email, TFTP, and a few others), shows every object Wireshark identified inside the capture with its filename, content type, and size, and lets you save any of them to disk individually or all at once. This is exactly how an analyst recovers a malware payload that was downloaded during an intrusion directly from network evidence — confirming precisely what file left the wire, byte for byte, even if the file no longer exists anywhere else by the time you're investigating.\n\n` +
        `**A worked example: spotting beaconing by eye in the packet list**\n\n` +
        `You don't always need Follow TCP Stream or a display filter to notice beaconing — sometimes it's visible just from scrolling the packet list. Sort or scan by Time and Destination: if the same destination IP:port keeps reappearing at a near-constant interval — say, every ~60 seconds, packet after packet, hour after hour — that rhythm is exactly the visual signature of a scheduled check-in. Combined with what you already know from flow analysis (small, consistent byte counts each time), seeing that same pattern confirmed directly in the packet list, with the actual timestamps in front of you, is often the final piece of evidence that turns "I suspect this is a beacon" into "I can show you the exact interval." From there, a display filter like \`ip.addr == <destination> && tcp.flags.syn == 1\` isolates just the connection attempts to that host, making the interval trivially easy to measure packet-by-packet with the Time column.`,
      codeExample:
        "WIRESHARK -- CAPTURE FILTER vs. DISPLAY FILTER\n" +
        "=======================================================\n" +
        "                CAPTURE FILTER        DISPLAY FILTER\n" +
        "-------------------------------------------------------\n" +
        "When applied    Before/during capture  After capture, any time\n" +
        "Syntax          BPF (tcpdump-style)    Wireshark's own syntax\n" +
        "Effect          Discards non-matching  Only hides/shows rows;\n" +
        "                packets permanently -- nothing underlying is\n" +
        "                cannot be undone       ever deleted\n" +
        "Example         tcp port 445           tcp.port == 445 &&\n" +
        "                                        ip.addr == 10.0.0.5\n" +
        "Can change      No -- must recapture    Yes -- as many times\n" +
        "after the fact  to get anything missed  as you want, freely\n" +
        "=======================================================\n\n" +
        "COMMON DISPLAY FILTER EXAMPLES\n" +
        "=======================================================\n" +
        "tcp.port == 445 && ip.addr == 10.0.0.5\n" +
        "http.request.method == \"POST\"\n" +
        "tcp.flags.syn == 1 && tcp.flags.ack == 0    (bare SYNs)\n" +
        "dns.qry.name contains \"evil\"\n" +
        "=======================================================\n\n" +
        "WORKFLOW: RIGHT-CLICK PACKET -> FOLLOW -> TCP STREAM\n" +
        "=======================================================\n" +
        "Reassembles the full two-way conversation as readable\n" +
        "text/hex -- generates a matching filter, e.g.:\n" +
        "    tcp.stream eq 4\n" +
        "=======================================================\n\n" +
        "WORKFLOW: FILE > EXPORT OBJECTS > HTTP / SMB / IMF ...\n" +
        "=======================================================\n" +
        "Lists every file transferred inside the capture with\n" +
        "filename, content type, and size -- save any one, or\n" +
        "all, straight to disk.\n" +
        "=======================================================",
      checkpoint: {
        question:
          "An analyst has a full packet capture already saved from earlier in the day. They want to narrow the view down to just one suspicious host's traffic, then a few minutes later narrow it differently to look at a different protocol instead — without losing any of the originally captured data. Which filter type should they use, and why?",
        options: [
          "A capture filter, because BPF syntax like tcp port 445 is more precise than Wireshark's own filter syntax and will isolate the suspicious host's traffic more reliably",
          "A display filter, because it only controls which already-captured rows are currently shown, never discards anything, and can be typed, cleared, and retyped as many times as needed after the fact",
          "A capture filter, because it can be reapplied at any time after capture has finished, exactly like a display filter, so either one works equally well here",
          "Neither — once a capture is saved, Wireshark's filtering options are locked to whatever filter, if any, was set at the moment the capture was started",
        ],
        answer: 1,
        explanation:
          "Because the capture already exists and the analyst wants to change what they're looking at repeatedly without losing data, a display filter is the right tool: it only hides/shows rows in an already-recorded capture and can be changed freely, any number of times. A capture filter only applies before or during capture and permanently discards anything that doesn't match — it cannot be applied retroactively to a capture that's already finished, which rules out both capture-filter options. Wireshark's filtering is not locked after capture either; display filters remain fully available on a saved file indefinitely.",
      },
    },

    // ── Question 1 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "tcpip-q1",
      question:
        "A firewall log shows a connection where the client sent only a SYN, and the server replied RST,ACK. The connection never advanced further. What does this most likely indicate?",
      options: [
        "A successful, completed connection to an open port — RST,ACK is simply an unusual but valid way for a server to acknowledge a completed handshake, similar to a normal SYN-ACK response, and the connection would now be ready to carry application data",
        "The destination port is closed on the target host (or a device on the path spoofed a reject on the target's behalf) — this is the standard response to a probe against a closed port, and is exactly the signal a SYN scan relies on",
        "The client's operating system crashed mid-handshake, and the RST,ACK is an automatic recovery signal generated by the client's own kernel after the crash, before the server had any chance to reply at all",
        "This is a graceful connection teardown equivalent to a FIN close — RST,ACK and FIN,ACK are two different bit patterns the TCP specification allows either endpoint to use interchangeably to signal a normal, orderly end of session once all data has been exchanged",
      ],
      answer: 1,
      explanation:
        "RST,ACK in direct response to a bare SYN (with no prior SYN-ACK) is the standard TCP behavior when a SYN arrives at a port with nothing listening — or a firewall configured to REJECT (rather than silently DROP) spoofing that same response. This exact reply is what lets a SYN scanner distinguish a closed port (RST,ACK) from an open one (SYN,ACK) or a filtered one (no reply at all). A FIN close requires an established connection to already exist first, which never happened here — and RST is never interchangeable with FIN: RST is an abrupt abort with no negotiation, while FIN is a graceful, four-step close. Nothing in this exchange indicates a client-side crash either; the RST,ACK came from the server side.",
      xp: 20,
    },

    // ── Question 2 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "tcpip-q2",
      question:
        "You're reviewing Zeek conn.log entries and see hundreds of records from one internal host, all with conn_state RSTOS0, spread across sequential destination ports on one target within seconds. What does RSTOS0 specifically tell you, beyond just 'this is a scan'?",
      options: [
        "The connections all completed normally with a graceful FIN close — RSTOS0 is simply Zeek's label for a standard handshake-then-teardown sequence where both sides exchanged FIN,ACK segments in the usual order",
        "The originator sent a SYN and then sent an RST itself, without ever receiving a SYN-ACK back — a signature consistent with scanner tooling that aborts half-open attempts on its own rather than waiting",
        "The responder actively refused every connection with an explicit application-level error message returned in the payload, rather than at the TCP layer, meaning the scanned service itself is running and rejecting the client by design",
        "RSTOS0 only ever appears on UDP traffic, so this must be a UDP-based scan — conn_state values like S0, SF, and RSTO are all Zeek codes reserved exclusively for connectionless UDP flows, never for TCP",
      ],
      answer: 1,
      explanation:
        "RSTOS0 decodes as: the Originator sent a SYN, and an RST was seen, but the responder's SYN-ACK (the 'S0' portion) was never observed — meaning the originator itself tore the attempt down rather than completing or waiting for a normal handshake outcome. This is a recognizable artefact of certain scanning tool behavior and is a stronger, more specific signal than just 'many ports touched' — it tells you something about how the scanning client itself is built, which can help fingerprint the tool in use. It is not a graceful close (no FIN was ever exchanged), it doesn't indicate an application-level refusal (the responder's SYN-ACK was never even seen), and Zeek's conn_state codes describe TCP connections specifically, not UDP flows.",
      xp: 25,
    },

    // ── Question 3 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "tcpip-q3",
      question:
        "An analyst sees a NULL scan (all flags cleared) hitting closed ports on a Windows Server target, but the technique's designers built it to be silent on open ports based on RFC 793 behavior. Why is a NULL/FIN/XMAS scan considered unreliable against modern Windows hosts specifically?",
      options: [
        "Windows firewalls block all incoming TCP traffic by default, making every scan type — SYN, FIN, NULL, XMAS, and full connect alike — equally useless against any Windows host regardless of its specific TCP/IP stack behavior",
        "Modern Windows TCP/IP stacks frequently reply with RST regardless of port state for these nonstandard flag combinations, rather than following the RFC 793 'silence means open' behavior — breaking the open/closed signal the scan relies on",
        "NULL, FIN, and XMAS scans only ever function over UDP because the flag-based logic they depend on is a UDP-only feature, and Windows does not implement UDP flag handling at all",
        "Windows requires a valid SYN flag before processing any TCP segment at the kernel level, so these scans are silently dropped by the network driver before ever reaching the TCP/IP stack's connection-state logic at all",
      ],
      answer: 1,
      explanation:
        "The RFC 793 behavior these scans depend on (silence on open ports, RST on closed ports for segments without SYN) is followed inconsistently across real-world TCP/IP stack implementations. Windows in particular is well known for replying RST to malformed/flagless segments regardless of the underlying port's actual state, which collapses the open-vs-closed signal the scan is trying to extract. This is exactly why nmap documentation flags these scan types as unreliable against Windows targets specifically, while they remain more useful against many Unix-like TCP/IP stacks that follow the older behavior more faithfully. It isn't a firewall blocking traffic outright (the scan still gets a reply, just not the RFC 793-predicted one), it has nothing to do with UDP, and Windows processes flagless TCP segments perfectly well — it just answers them with RST.",
      xp: 25,
    },

    // ── Log Analysis 1: SYN scan sweep ───────────────────────────────────────
    {
      type: "log_analysis" as const,
      id: "tcpip-la1",
      heading: "Investigating a Rapid Port Sweep Against an Internal Server",
      context:
        "You're triaging a NIDS alert. SRV-CORE02 (10.40.2.30) is a domain-joined print/file server that normally only receives connections on ports 445, 139, and 3389 from a small set of known IT hosts. The sensor captured 1,024 separate connection records from WKS-ENG14 (10.40.6.114) against SRV-CORE02 in a 38-second window: 1,017 ended S0 (no reply), 6 ended RSTR (destination reset), and 1 reached SF (full handshake). The record below is one representative sample from that set.",
      event: synScanEvent,
      questions: [
        {
          question:
            "The record shows conn_state: 'S0' and history: 'S', with orig_bytes and resp_bytes both 0. What does this single flow record tell you happened on the wire?",
          options: [
            "A full TCP session was established and connected normally, with the server replying SYN,ACK before the handshake completed and 0 bytes of application data simply happened to be exchanged in either direction that time",
            "The originator (WKS-ENG14) sent a lone SYN and the sensor never observed any reply at all — the connection never progressed past the very first packet",
            "The destination actively refused the connection with an RST — the same RST,ACK behavior you'd see whenever a stateful firewall or the destination's own OS deliberately rejects an unwanted incoming request",
            "This was a UDP connection, so no TCP three-way handshake was ever expected in the first place, and the S0 label here simply reflects Zeek's default state for any non-TCP protocol flow",
          ],
          answer: 1,
          explanation:
            "history 'S' means literally one event was observed: a SYN from the originator. conn_state S0 confirms no reply was seen — not a SYN-ACK (open) and not an RST (closed/rejected). Zero bytes in both directions confirms no data ever flowed. This is the signature of either a filtered destination port or a scanner that fires SYNs faster than it waits for replies. Nothing here indicates a completed handshake, an RST reply (that would show as REJ, not S0), or UDP traffic — the record's own proto field reads 'tcp'.",
          xp: 25,
        },
        {
          question:
            "The task's opening context states this sample is one of 1,024 connections in 38 seconds, of which 1,017 got the same S0 (no reply) outcome, 6 got RSTR, and 1 got SF (full handshake). How should that aggregate change your read of the single sample record above?",
          options: [
            "It shouldn't — every connection attempt should be scored purely on its own individual flag pattern and byte count, since aggregating separate flow records together only introduces noise and cannot itself reveal a coordinated reconnaissance pattern",
            "It confirms this sample record is one of a systematic sweep across essentially the entire well-known port range from a single internal source against a single target in under a minute — individually ambiguous flow records become an unambiguous scan pattern in aggregate",
            "It proves SRV-CORE02 itself has been compromised and is now the one actively scanning other internal hosts across the network, rather than being the passive target the connections were aimed at",
            "It indicates the sensor mis-attributed all 1,024 connection attempts to a single source address by mistake, when in reality they were generated by 1,024 separate internal hosts acting independently",
          ],
          answer: 1,
          explanation:
            "One S0 record in isolation could plausibly be an application retry against a temporarily unavailable service. 1,024 attempts across that many distinct destination ports, from one source, against one target, inside 38 seconds — with the overwhelming majority landing S0 and a handful getting RSTR (a handful of ports did reply RST, meaning closed-but-reachable) and exactly one SF (one port, likely one of the three normally-open services, completed a real handshake) — is not something any legitimate application does. This is the textbook aggregate shape of a SYN/port sweep, and it's the aggregate view, not any single record, that turns ambiguous into conclusive. Aggregation is exactly what reveals the pattern (not noise), SRV-CORE02 is the target here, not the source (10.40.6.114/WKS-ENG14 is), and the context is explicit that this is one source's 1,024 attempts, not 1,024 distinct sources.",
          xp: 30,
        },
        {
          question:
            "Given WKS-ENG14 is a regular engineering workstation with no business reason to be scanning SRV-CORE02, what is the correct next investigative step?",
          options: [
            "Close the alert — since only one of the 1,024 attempted ports (RDP, 3389) actually completed a handshake and the rest all failed with S0, the sweep clearly didn't succeed at anything, and a failed reconnaissance attempt carries no investigative value worth an analyst's time (unlike a successful lateral-movement hop, which would justify escalation)",
            "Treat WKS-ENG14 itself as the priority to investigate — pull its EDR/process telemetry for the scan time window to identify what process initiated the sweep (attacker tooling, or a compromised legitimate app), and check whether this is an isolated event or one host of several exhibiting the same pattern (lateral-movement reconnaissance often sweeps multiple internal targets from a freshly compromised host)",
            "Block SRV-CORE02's IP address at the perimeter firewall, since it is the target being scanned — this stops nothing, because the sweep originates entirely from inside the network at WKS-ENG14, and a perimeter firewall rule has no effect whatsoever on internal, east-west traffic between two hosts on the same LAN",
            "Reset WKS-ENG14's DNS cache, since port scans are typically caused by stale or corrupted DNS entries pointing the resolver to the wrong destination host, and clearing the cache will force the workstation to re-resolve SRV-CORE02's address correctly and stop the scanning behavior",
          ],
          answer: 1,
          explanation:
            "A port sweep originating from an internal workstation against an internal server is a strong internal-reconnaissance signal — commonly seen right after a workstation is compromised, as an attacker (or automated worm/tooling) maps out what's reachable and what's listening before attempting lateral movement. The priority is understanding what's running on WKS-ENG14 that initiated the sweep (via EDR process ancestry, not just the network layer), and checking whether other internal hosts show the same pattern against the same or other targets in the same window, which would indicate a broader compromise rather than an isolated event.",
          xp: 30,
        },
      ],
    },

    // ── Log Analysis 2: TTL OS-fingerprint mismatch ─────────────────────────
    {
      type: "log_analysis" as const,
      id: "tcpip-la2",
      heading: "A TTL Value That Doesn't Match the Expected Source",
      context:
        "BASTION-01 (10.40.1.9) is a hardened Ubuntu Linux jump host that IT uses for administrative SSH access into sensitive segments. Across the last 40 recorded sessions from this host, the observed initial TTL has consistently landed between 58 and 61 — consistent with a Linux host (initial TTL 64) crossing 3-6 hops to reach the sensor. Review the session below, captured tonight against the finance file server SRV-FIN03.",
      event: ttlMismatchEvent,
      questions: [
        {
          question:
            "This session's orig_ttl is 125, well outside BASTION-01's established 58-61 baseline. Based on typical initial TTL values by OS family, what does 125 most likely indicate about the traffic's true origin?",
          options: [
            "125 is well within the normal variance a Linux TTL can show across different network paths and routing conditions, so this single session requires no further analyst attention beyond noting it in the routine log",
            "An initial TTL of 125 rounds up to 128 (the standard Windows default) minus roughly 3 hops — meaning these packets most likely did not originate from BASTION-01's known Linux TCP/IP stack at all",
            "TTL values above 100 always indicate the packet was fragmented somewhere along its path, since fragmentation itself is what causes the field to jump upward from a host's normal baseline value",
            "The TTL field is randomized per-connection by design as an anti-fingerprinting measure in modern operating systems, so it carries no forensic meaning and cannot be used to infer anything about a packet's true origin",
          ],
          answer: 1,
          explanation:
            "Observed TTLs cluster just below their sending OS's initial value, decremented once per hop. 125 sits just below 128 (Windows' standard initial TTL), not anywhere near 64 (Linux/BSD/macOS). Combined with BASTION-01's own established 58-61 baseline over 40 prior sessions, this single session stands out as inconsistent with the same source device having generated it — a strong passive indicator that this traffic did not originate from BASTION-01's actual, known Linux stack. TTL is not randomized (it's a deterministic hop counter), and a high TTL is not evidence of fragmentation — those are two unrelated IP header fields entirely.",
          xp: 25,
        },
        {
          question:
            "Which explanations, taken together, should the analyst consider BEFORE concluding this is definitely a spoofed or hijacked source — recognizing that TTL is a corroborating signal, not standalone proof?",
          options: [
            "There is no other explanation worth considering — a TTL mismatch this large, by itself and without any further corroborating telemetry from EDR or the change log, is already conclusive, courtroom-grade proof that the source IP address has been spoofed by an external attacker",
            "Legitimate explanations to rule out first include: BASTION-01 was re-imaged or its OS was legitimately changed, the session was routed through a different, unexpected network path with a different hop count, or the source IP is now NAT'd/shared with a different physical device — alongside the malicious explanation that another host is spoofing or otherwise using BASTION-01's expected source address",
            "TTL fields cannot be observed at all on already-established connections, only on the very first SYN packet of a session, so any finding based on this session's TTL value must be dismissed as an artifact of incomplete logging rather than investigated further",
            "Since the destination is a finance server, this must automatically be escalated and processed purely as a regulatory compliance violation rather than as a security incident, and the technical TTL evidence itself becomes irrelevant to a compliance-driven case",
          ],
          answer: 1,
          explanation:
            "A single passive fingerprinting signal is corroborating evidence, not a verdict. Before escalating this as spoofing or compromise, a careful analyst rules out mundane explanations: was BASTION-01 recently reimaged or migrated to a different OS as part of an approved change, did the routing path between BASTION-01 and the sensor change (altering hop count enough to explain a shift, though a shift from ~60 to ~125 is far too large to be hop-count noise alone), or is there a NAT/infrastructure change sharing that IP. Ruling these out first is what turns a hunch into a defensible finding either way.",
          xp: 25,
        },
        {
          question:
            "After checking the change log and confirming BASTION-01 was NOT re-imaged, no routing changes occurred, and no NAT change was made, what is the correct next step?",
          options: [
            "Dismiss the finding entirely, since a TTL value is 'only metadata' with no forensic weight of its own, and metadata-only findings should never be escalated or correlated against other telemetry sources regardless of how unusual the value looks",
            "Escalate for further investigation: correlate BASTION-01's own endpoint telemetry (EDR/host logs) for signs of compromise or unauthorized use, check whether other sessions from 10.40.1.9 around the same time also show the anomalous TTL, and treat the finding as evidence the source address may not correspond to the expected physical device until proven otherwise",
            "Immediately terminate all SSH access company-wide, since any single TTL mismatch on any host is a reliable enough indicator, on its own, to declare an active worm outbreak spreading across the entire environment",
            "Change SRV-FIN03's IP address to resolve the discrepancy, since reassigning the destination server a new address will force BASTION-01's real TCP/IP stack to renegotiate its TTL baseline on the next connection",
          ],
          answer: 1,
          explanation:
            "With the mundane explanations ruled out, this now warrants deeper investigation rather than dismissal or an overreaction: pull BASTION-01's own host-level telemetry to check for signs of tampering or unauthorized access, check whether the TTL anomaly is isolated to this one session or appears across others from the same source IP in the same period, and treat the address-to-device mapping as unverified until the discrepancy is explained. This is exactly the kind of finding that starts as a single flow-record anomaly and, through careful follow-up, either resolves into a benign explanation or into evidence of a genuine device impersonation or spoofing incident.",
          xp: 30,
        },
      ],
    },

    // ── Analyst Choice: normal load-balancer health-check RSTs ─────────────
    {
      type: "analyst_choice" as const,
      id: "tcpip-ac1",
      heading: "Verdict: Repeated RST Bursts Against a Web Server Farm",
      scenario:
        "A correlation rule fired because 10.40.9.5 sent TCP connections to all six web servers in the DMZ web farm, hitting port 443 on each, roughly every 15 seconds around the clock, with every single connection completing a normal SYN/SYN-ACK/ACK handshake, exchanging a small fixed amount of data, and then being torn down cleanly with an RST from the client side rather than a FIN. The rule flagged the RST-based teardown pattern repeated at a fixed short interval across multiple hosts as scan-like.",
      event: {
        id: "evt-tcpip-ac1-001",
        ts: "2026-02-12T09:00:00.000Z",
        source: "ids",
        vendor: "Corelight (Zeek)",
        event_type: "net_connection",
        severity: "low",
        hostname: "LB-HEALTHCHECK",
        src_ip: "10.40.9.5",
        dst_ip: "10.40.5.21",
        dst_port: 443,
        protocol: "tcp",
        description:
          "10.40.9.5 completes a full TLS-capable TCP handshake against port 443 on each of six DMZ web servers every ~15 seconds, exchanges a small fixed payload each time, and closes with a client-side RST rather than a FIN",
        raw: {
          "id.orig_h": "10.40.9.5",
          "id.orig_p": 41102,
          "id.resp_h": "10.40.5.21",
          "id.resp_p": 443,
          proto: "tcp",
          service: "ssl",
          duration: 0.041,
          orig_bytes: 187,
          resp_bytes: 612,
          conn_state: "RSTO",
          history: "ShADadR",
          orig_pkts: 6,
          resp_pkts: 5,
          recurrence_interval_seconds_avg: 15.02,
          distinct_dst_hosts_touched: 6,
        },
      },
      correct_verdict: "false_positive",
      explanation:
        "This pattern is characteristic of an application load balancer's active health-check probe, not a scan. Every session completes a genuine, full three-way handshake and a real (if small) TLS-capable data exchange with each backend web server before closing — a scanner does not bother completing a real TLS-capable exchange with every target it touches. The RST-based teardown (conn_state RSTO) instead of a FIN is simply the load balancer's health-check client choosing to abort quickly after collecting the response it needed, rather than performing a full graceful close — a common, deliberate optimization in load-balancer health-check implementations, not a sign of malicious tooling. The fixed ~15-second recurrence across exactly the six known backend servers in the web farm (not a broad, expanding, or random set of hosts) is exactly the fingerprint of scheduled infrastructure monitoring.",
      fp_trap:
        "It's tempting to treat 'repeated RST-based connection teardowns at a fixed interval, hitting multiple hosts' as inherently scan-like or beacon-like, because both scans and beacons also produce repeating, small, regular connections. The differentiator here is that a scan or a beacon typically does NOT complete a full, real TLS-capable data exchange on every single attempt — it either never completes the handshake (scan) or repeats an identical tiny payload against ONE external destination (beacon). A source hitting a small, fixed, known set of internal backend servers, completing genuine full sessions with real (if small) application data every time, is the signature of legitimate infrastructure monitoring, not reconnaissance or C2. Escalating this indiscriminately just because of the RST-based close and fixed timing produces exactly the kind of alert fatigue that causes real anomalies to get lost in the noise.",
      xp: 30,
    },

    // ── Matching: scan technique <-> flags/signature ─────────────────────────
    {
      type: "matching" as const,
      id: "tcpip-m1",
      heading: "Match Each Scan Technique to Its Flag Pattern and Signature",
      instructions: "Match each scan/probe technique to the flags it sends and what makes it recognizable in a flow log.",
      pairs: [
        {
          id: "syn",
          left: "SYN scan (nmap -sS, half-open)",
          right: "Sends only SYN, never completes the handshake; open replies SYN-ACK, closed replies RST,ACK, filtered gets no reply at all",
        },
        {
          id: "null",
          left: "NULL scan",
          right: "Sends a segment with no flags set at all; relies on the RFC 793 quirk where an open port stays silent and a closed port replies RST",
        },
        {
          id: "fin",
          left: "FIN scan",
          right: "Sends only the FIN flag with no prior SYN — a 'close' for a connection that was never opened; same silence-vs-RST logic as NULL",
        },
        {
          id: "xmas",
          left: "XMAS scan",
          right: "Sends FIN, PSH, and URG together ('lit up like a Christmas tree'); same underlying RFC 793 quirk as NULL and FIN scans",
        },
        {
          id: "ack",
          left: "ACK scan",
          right: "Sends only ACK with no prior SYN; cannot determine open vs. closed, but maps which ports a stateful firewall's rules actually let through",
        },
        {
          id: "connect",
          left: "Full connect scan (nmap -sT)",
          right: "Completes the entire real three-way handshake before closing; slower and more visible at the application layer, but needs no raw-socket privileges to run",
        },
      ],
      explanation:
        "Every scan technique is defined by the specific flag combination it sends and what that combination is designed to reveal. SYN scans exploit the handshake itself; NULL/FIN/XMAS scans all exploit the same RFC 793 silence-on-open-port rule (and are all similarly unreliable against modern Windows stacks that don't follow it faithfully); ACK scans don't probe port state at all, they probe firewall rule sets; and full connect scans trade stealth for reliability by completing a real connection. Recognizing which flag pattern you're looking at tells you not just 'this is a scan' but which technique and often which tooling produced it.",
      xp: 40,
    },

    // ── Ordering: TCP handshake + teardown sequence ─────────────────────────
    {
      type: "ordering" as const,
      id: "tcpip-o1",
      heading: "Order a Complete TCP Session: Handshake, Data, and Graceful Teardown",
      instructions: "Arrange these events into the correct chronological order for one complete, normal TCP session.",
      items: [
        { id: "syn", text: "Client sends SYN (seq=x)" },
        { id: "synack", text: "Server replies SYN-ACK (seq=y, ack=x+1)" },
        { id: "ack", text: "Client sends ACK (ack=y+1) — connection is now ESTABLISHED" },
        { id: "data", text: "Both sides exchange application data (PSH/ACK segments)" },
        { id: "finclient", text: "Client sends FIN,ACK — client has no more data to send" },
        { id: "ackserver1", text: "Server ACKs the client's FIN" },
        { id: "finserver", text: "Server sends its own FIN,ACK once it has finished sending" },
        { id: "ackclient2", text: "Client ACKs the server's FIN — client enters TIME_WAIT" },
      ],
      correct_order: ["syn", "synack", "ack", "data", "finclient", "ackserver1", "finserver", "ackclient2"],
      explanation:
        "A complete TCP session is the three-way handshake (SYN, SYN-ACK, ACK), followed by whatever application data is exchanged while ESTABLISHED, followed by a four-step graceful teardown: each side independently signals it has no more data (FIN) and the other side acknowledges. The side that sends the final ACK holds the connection in TIME_WAIT briefly to catch any stray delayed packets from the now-closed connection before fully releasing it. Any deviation from this sequence — a FIN or RST appearing before ESTABLISHED, data appearing before the handshake completes — is exactly the kind of anomaly that scan and evasion techniques deliberately produce.",
      xp: 35,
    },

    // ── Query Fill: KQL for detecting a port-sweep pattern ──────────────────
    {
      type: "query_fill" as const,
      id: "tcpip-qf1",
      heading: "Write It Yourself: Detect a Port Sweep in KQL",
      language: "kql",
      context: KQL_PRIMER +
        "Using the pattern from Log Analysis 1 (one source touching many destination ports on one target, mostly ending in S0/no reply, within a short window), write the KQL that would surface this pattern across your whole network flow table, the way a detection engineer would before shipping it as a scheduled analytics rule.",
      template:
        "NetworkFlowEvents\n| where ConnectionState in ({{states}})\n| summarize DistinctPorts = dcount(DestinationPort) by SourceIp, DestinationIp, bin(TimeGenerated, {{window}})\n| where DistinctPorts > {{threshold}}",
      blanks: [
        { id: "states", answers: ["\"S0\"", "'S0'", "\"S0\", \"RSTOS0\"", "'S0', 'RSTOS0'"], placeholder: "conn_state values indicating no completed handshake" },
        { id: "window", answers: ["1m", "60s", "1min"], placeholder: "aggregation time window" },
        { id: "threshold", answers: ["100", "50"], placeholder: "distinct-port count threshold" },
      ],
      explanation:
        "The core detection logic mirrors what you read directly off the flow record in Log Analysis 1: filter to connection states that mean 'no completed handshake' (S0 at minimum, optionally RSTOS0), group by the source-to-destination pair within a short rolling window (one minute is tight enough to catch a fast sweep like the 38-second one you investigated), count the DISTINCT destination ports touched, and alert when that count crosses a threshold no legitimate application would ever produce in that time frame. A real deployment would also exclude known, approved scanners (vulnerability management tools) by source IP to avoid constant false positives from authorized scanning.",
      xp: 35,
    },

    // ── Flag ──────────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "tcpip-f1",
      prompt:
        "Look at the TTL-mismatch investigation (Log Analysis 2). What is the exact orig_ttl value recorded in the raw log for the suspicious BASTION-01 session? Enter the number only.",
      answer: "125",
      hint: "Look for the orig_ttl field in the raw block of the SRV-FIN03 SSH session event.",
      xp: 25,
    },
  ],
};

export default [tcpipDeepDiveRoom];
