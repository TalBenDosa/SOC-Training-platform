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
  dst_port: 8080,
  protocol: "tcp",
  description:
    "Internal host WKS-ENG14 opened 1,024 short-lived TCP connection attempts to distinct destination ports on SRV-CORE02 within 38 seconds; the representative connection shown below is one of that set and never advanced past the initial packet",
  raw: {
    "id.orig_h": "10.40.6.114",
    "id.orig_p": 51882,
    "id.resp_h": "10.40.2.30",
    "id.resp_p": 8080,
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
        `Every beginner learns "TCP does a three-way handshake: SYN, SYN-ACK, ACK." That sentence is true but useless during an investigation, because an investigation is never about the happy path. It's about the packet that broke the pattern. To read that packet, you need to know what's actually inside a TCP header and what state a connection is in at every point of its life.\n\n` +
        `**The TCP header, field by field**\n\n` +
        `Beyond source port and destination port, a TCP segment carries: a 32-bit **sequence number** (which byte of the stream this segment starts at), a 32-bit **acknowledgment number** (the next byte the sender expects to receive, valid only when the ACK flag is set), a **window size** (how many bytes the sender is willing to receive before requiring another acknowledgment. Used for flow control, and, as you'll see later, for OS fingerprinting), and six single-bit **control flags**: URG, ACK, PSH, RST, SYN, and FIN. Two more flags, ECE and CWR, exist for Explicit Congestion Notification and are rarely relevant to security work. Every TCP segment you will ever look at in a SIEM, a flow log, or a packet capture is defined by which of these flags are set.\n\n` +
        `**What each flag actually means**\n\n` +
        `- **SYN**: "I want to synchronize sequence numbers with you," i.e. open a new connection.\n` +
        `- **ACK**: "I am acknowledging data or a control flag you sent me." Set on almost every segment after the handshake.\n` +
        `- **PSH**: "Don't buffer this, push it to the application immediately." Common on interactive traffic (SSH keystrokes) and rare on bulk transfers.\n` +
        `- **URG**: "Some of this data is urgent," rarely used in modern traffic; unexpected URG traffic is itself worth a second look.\n` +
        `- **RST**: "Abort this connection immediately, right now, no negotiation." Covered in depth in the next reading.\n` +
        `- **FIN**: "I have no more data to send, let's close this gracefully." Also covered next.\n\n` +
        `**The TCP state machine**\n\n` +
        `A TCP connection is not just "open" or "closed". It moves through a defined sequence of states, and both the client and server independently track their own side: CLOSED -> LISTEN (server waiting) -> SYN_SENT (client sent SYN) -> SYN_RECEIVED (server got SYN, sent SYN-ACK) -> ESTABLISHED (three-way handshake complete, data can flow) -> FIN_WAIT_1 / CLOSE_WAIT (one side initiated close) -> FIN_WAIT_2 / LAST_ACK -> TIME_WAIT -> CLOSED. TIME_WAIT deserves a specific mention: after a connection closes, the side that sent the final ACK holds the connection in TIME_WAIT for a period (commonly 2 minutes) purely so that any stray, delayed duplicate packets from the old connection are recognized and discarded rather than confused with a brand-new connection reusing the same port pair. A host with an enormous number of connections stuck in TIME_WAIT is either extremely busy or the target of a connection-exhaustion attack.\n\n` +
        `**Why this matters for detection**\n\n` +
        `Nearly every network-based attack technique (port scanning, session hijacking, evasion via crafted flags, firewall/IDS fingerprinting) works by deliberately sending flag combinations or sequence numbers that a normal TCP stack would never produce on its own. You cannot recognize an abnormal flag combination if you don't have the normal state machine memorized cold first.`,
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
          "To wait for the peer's own FIN, because the connection isn't closed until both sides have sent one",
          "So delayed duplicate packets from the old connection are discarded, not mistaken for a new one on the same port pair",
          "To keep the port pair reserved so a connection-exhaustion attack can't immediately reuse it",
          "To give the peer time to retransmit any data segments that were still in flight when the close began",
        ],
        answer: 1,
        explanation:
          "The reading gives TIME_WAIT one job: hold the closed connection (commonly about 2 minutes) so late, duplicate packets from it are recognised as stale instead of being read as part of a new connection on the same port pair. “To wait for the peer's own FIN” describes FIN_WAIT_2, an earlier state, by TIME_WAIT both FINs have already been exchanged. “Keep the port pair reserved” against exhaustion gets it backwards: the reading says huge TIME_WAIT counts are a SYMPTOM of exhaustion attacks or heavy load. “Retransmit any data segments” is wrong because all data was sent and acknowledged before the FIN exchange finished.",
      },
    },

    // ── Reading 2: RST vs FIN semantics ─────────────────────────────────────
    {
      type: "reading" as const,
      id: "tcpip-r2",
      heading: "RST vs FIN: Graceful Close, Abrupt Abort, and Injected Resets",
      content:
        `RST and FIN both end a TCP connection, but they mean fundamentally different things, and confusing them will lead you to misread a firewall block as an application error, or worse, miss an active hijack attempt.\n\n` +
        `**FIN: the polite goodbye**\n\n` +
        `FIN means "I have no more data to send." A graceful close is a four-step exchange: the initiating side sends FIN, the other side ACKs it and (usually shortly after) sends its own FIN, which is then ACKed in turn. Both sides get to finish sending whatever data they still had queued before the connection fully closes. This is what you see at the end of a normal HTTP session, an SSH logout, or a completed file transfer. In a flow log, a connection that ends this way typically shows both sides' byte counters non-zero and a clean four-packet teardown.\n\n` +
        `**RST: the abrupt slam**\n\n` +
        `RST means "something is wrong, abandon this connection immediately, no negotiation, no guarantee of delivering any remaining data." There is no acknowledgment expected for an RST beyond the immediate teardown. RST appears in several very different situations, and telling them apart is a core analyst skill:\n\n` +
        `1. **Port closed, nothing listening.** When a SYN arrives at a port with no service bound to it, the OS's TCP/IP stack immediately replies with RST,ACK. This is the normal, completely benign response to a probe against a closed port, and it's also the exact signal a SYN scan uses to map which ports are closed.\n` +
        `2. **Firewall/IPS reject action.** Many firewalls, when configured to REJECT rather than silently DROP, spoof an RST back to the sender on the firewall's behalf, making a blocked connection look identical, to the sender, to a closed port. The visible difference to an analyst is usually only in the firewall's own logs (an explicit deny/reject rule match) versus what the destination host itself would have generated.\n` +
        `3. **Application-level refusal.** A service can be up and listening but still send RST, for example, a web server hitting a connection limit, or a security control (IPS, WAF) injecting a spoofed RST mid-session to kill a connection it has decided is malicious, without ever touching the actual client or server.\n` +
        `4. **Mid-session RST as evidence of tampering.** A connection that was ESTABLISHED, exchanged real data for some time, and then received an unexpected RST is a very different finding than a RST that arrives one packet after the initial SYN. A mid-session RST can mean a crashed application, a timeout, an IPS actively terminating a session it flagged as malicious mid-stream, or (in TCP hijacking / session-reset attacks) a spoofed RST injected by an on-path or blind attacker trying to disrupt an active connection (this is exactly what a "RST attack" against long-lived BGP or VPN sessions historically abused).\n\n` +
        `**Reading Zeek's conn_state field: the shortcut that encodes all of this**\n\n` +
        `Zeek (and Corelight sensors built on it) summarize exactly this kind of nuance into a single conn_state code so you don't have to reconstruct it packet by packet: SF (normal establishment and termination), S0 (connection attempt, no reply, the closed-port-or-filtered signature), REJ (connection attempt rejected, i.e. RST received in response to the SYN), RSTO (connection established, then originator sent an RST), RSTR (responder sent the RST), RSTOS0 (originator sent a SYN followed by an RST, without ever getting a SYN-ACK: one of the classic half-open scan artefacts), S1 (connection established, not terminated), OTH (a partial connection, mid-stream, neither a full open nor a full close was observed by the sensor). Memorizing this table turns a wall of flow records into an instantly readable summary of exactly what happened to each connection.`,
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
          "The connection was established, and then the originator sent an RST",
          "The attempt was rejected: the SYN was answered with RST,ACK (closed port)",
          "The attempt got no reply at all, so the SYN was dropped or filtered",
          "The originator sent a SYN, then its own RST, with no SYN-ACK seen",
        ],
        answer: 1,
        explanation:
          "REJ means the SYN was answered with RST,ACK: the port is closed but the host is reachable. “Established, and then the originator sent an RST” is RSTO. “No reply at all” is S0, the filtered/dropped signature. “A SYN, then its own RST, with no SYN-ACK seen” is RSTOS0, the half-open scan artefact.",
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
        `The attacker sends only a SYN and never completes the handshake. An open port replies SYN-ACK (the scanner then sends RST instead of ACK, aborting before a full session is ever logged by the application); a closed port replies RST,ACK; a filtered port produces no reply at all, or an ICMP "destination unreachable / administratively prohibited" message. This is the default and most common nmap scan precisely because it is fast and, historically, was less likely to be logged by the target application (though modern NIDS/flow logging catches it easily. That's exactly what conn_state S0/REJ/RSTOS0 records reveal).\n\n` +
        `**FIN, NULL, and XMAS scans, abusing an RFC 793 quirk**\n\n` +
        `These three scans all exploit the same obscure rule in the original TCP specification: if a segment arrives at a **closed** port with no SYN flag set, the correct behavior is to reply with RST. If the same segment arrives at an **open** port, compliant stacks are supposed to silently drop it with no reply at all. This produces a counter-intuitive result: silence means "probably open," a response means "closed."\n` +
        `- **NULL scan**: no flags set at all.\n` +
        `- **FIN scan**: only the FIN flag set (a "close" for a connection that was never opened).\n` +
        `- **XMAS scan**: FIN, PSH, and URG all set together (the packet "lights up like a Christmas tree").\n` +
        `All three exist mainly to slip past older, simpler firewalls that only filter on the SYN flag, and all three are highly unreliable against modern Windows stacks, which frequently reply RST regardless of the state, but they remain extremely recognizable in a flow log precisely because a segment with FIN, NULL, or XMAS flags and **no prior SYN in the same connection** should never occur in legitimate traffic. There is no legitimate reason for any real application to open a "connection" by sending a bare FIN.\n\n` +
        `**ACK scan**\n\n` +
        `An ACK scan sends only an ACK flag with no preceding SYN. It cannot determine open vs. closed at all (a stateless packet filter will let it through to both), but it is specifically designed to map firewall rule sets: if the target replies with RST, the ACK reached the destination unfiltered; if there's no reply, a stateful firewall silently dropped it because it didn't match any established connection in the firewall's own state table. This is a firewall-mapping technique, not a port-discovery technique.\n\n` +
        `**Full connect scan (nmap -sT)**\n\n` +
        `The scanner completes the entire three-way handshake normally, then immediately closes the connection. It is the slowest and the "loudest" (application-level logging on the target will usually see a fully-formed, if extremely brief, connection), but it requires no special raw-socket privileges to run and works identically to a real client connecting, which is precisely why it's what unprivileged scanning tools and scripts default to when they can't craft raw packets.\n\n` +
        `**The single most useful pattern-recognition rule**\n\n` +
        `Any single flag combination is a weak signal on its own: a bare RST or a bare ACK happens constantly in normal traffic. What makes a scan unmistakable is the **breadth**: the same source touching many distinct destination ports (or many distinct destination hosts on the same port) in a short window, each attempt using an identical, nonstandard flag pattern. One NULL-flag packet is noise. A thousand NULL-flag packets from one source to a thousand consecutive ports in forty seconds is a NULL scan.`,
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
        `Two hosts can send TCP traffic that looks identical at the port/protocol level, yet be running completely different operating systems, and that OS fingerprint is often the detail that tells you a connection did not come from the device its IP address suggests it did.\n\n` +
        `**IP fragmentation, briefly**\n\n` +
        `Every network link has a Maximum Transmission Unit (MTU): the largest packet it can carry, typically 1500 bytes on Ethernet. If an IP packet is larger than the MTU of a link it must cross, a router along the path splits it into multiple **fragments**, each carrying a fragment offset (where this piece belongs in the original packet) and a "More Fragments" (MF) flag (set on all fragments except the last). The receiving host reassembles them using those offsets before handing the data up to TCP. Attackers abuse fragmentation deliberately: a tool like fragroute can split a malicious payload across multiple tiny fragments specifically so that an inspection engine which does not fully reassemble traffic before pattern-matching never sees the complete, recognizable payload in any single fragment, the payload only becomes visible again after the target host reassembles it. This is why any modern IDS/IPS must reassemble fragmented streams before running signature matching, and why unusually small, deliberately fragmented packets to a security-sensitive service is itself worth flagging, independent of payload content.\n\n` +
        `**TTL: a free, passive OS hint on every single packet**\n\n` +
        `The IP Time-To-Live (TTL) field is decremented by one at every router hop and exists to prevent packets from looping forever. Different operating systems set a different **initial** TTL when they originate a packet, and while intermediate routers only ever decrement it, they never increase it or reset it back to the OS default. This means the TTL you observe on an inbound packet equals (initial TTL of the sending OS) minus (number of hops it crossed to reach you), and because initial TTLs cluster around a small set of well-known values, you can work backwards: an observed TTL of 118-125 almost certainly started at 128 (the Windows default) and crossed 3-10 hops; an observed TTL around 54-64 almost certainly started at 64 (the default for Linux and most BSD/macOS systems); a TTL near 245-255 started at 255 (common on Cisco IOS and Solaris). This single field, present on every packet with zero extra logging configuration required, is one of the cheapest and most reliable passive OS-fingerprinting signals available, and it is exactly the kind of detail that flags a mismatch between "the device this IP is supposed to be" and "the device that actually sent this traffic."\n\n` +
        `**Window size and other passive fingerprint features**\n\n` +
        `The initial TCP window size (advertised in the SYN packet), along with details like the set of TCP options offered, their order, and the IP "Don't Fragment" (DF) flag behavior, together form a fingerprint precise enough to distinguish not just Windows-vs-Linux but often specific OS versions. This is exactly what tools like p0f do, passively, from flow metadata alone, with no active probing required. A Windows host's SYN typically advertises a window size of 64240 or 65535 with a specific, ordered set of TCP options; a Linux host's default window and option ordering look different again. None of these signals are individually proof of anything. NAT, load balancers, VPNs, and legitimately reconfigured TCP stacks can all shift these values, but taken together, and especially when they contradict what you expect from a known, baselined asset, they are strong corroborating evidence that deserves a second look before you either dismiss or escalate a finding.\n\n` +
        `A practical note on where these fields come from, because it trips people up: stock Zeek conn.log and a plain NetFlow/IPFIX export do NOT record per-packet TTL or the advertised TCP window, those are packet-level details, not standard flow fields. You see them when a sensor is explicitly configured to enrich its flow records with them (a Corelight sensor can surface orig_ttl / resp_ttl and the SYN window size alongside the usual conn fields. That is exactly what the enriched Corelight log-analysis event in this room shows), from a passive-fingerprinting tool like p0f reading the packets directly, or from a full PCAP. If all you have is a vanilla NetFlow export, TTL- and window-based fingerprinting simply isn't available, and confirming an OS mismatch means pulling a capture.`,
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
          "Your team only has a stock NetFlow/IPFIX export from the core switches. A colleague wants to run this reading's TTL and window-size OS check against it. According to the reading, what should you tell them?",
        options: [
          "It works: TTL is in every IP header, so every flow export records it for each flow by default",
          "It won't work: plain flow exports don't keep TTL or SYN window; you need an enriched sensor, p0f or a PCAP",
          "It works for TTL only: NetFlow stores the first packet of each flow, so its TTL can be read from there",
          "It won't work: routers rewrite TTL to a fixed value at each hop, so it carries no OS information",
        ],
        answer: 1,
        explanation:
          "The reading's practical note: stock Zeek conn.log and plain NetFlow/IPFIX do not record per-packet TTL or the SYN window. Those come from a sensor enriched to add them, from p0f reading packets, or from a full capture. “TTL is in every IP header, so every flow export records it” mixes the packet with the flow summary: being in the header doesn't mean the exporter keeps it. “NetFlow stores the first packet of each flow” is false: a flow record is counters and the 5-tuple, not stored packets. “Routers rewrite TTL to a fixed value” contradicts the reading: routers only decrement it, which is why it fingerprints the sender at all.",
      },
    },

    // ── Reading 5: flow records vs full packets ──────────────────────────────
    {
      type: "reading" as const,
      id: "tcpip-r5",
      heading: "Reading Flow Records vs. Full Packet Captures",
      content:
        `Most day-to-day network investigation happens in **flow records**: NetFlow, IPFIX, or Zeek/Corelight conn.log entries, not full packet captures (PCAP). Knowing exactly what a flow record can and cannot tell you is what lets you decide, quickly, whether you need to escalate to pulling a full PCAP at all.\n\n` +
        `**What a flow record gives you**\n\n` +
        `A flow record is metadata about a conversation: the 5-tuple (source IP, source port, destination IP, destination port, protocol), start and end time, packet counts, byte counts in each direction, and, in Zeek's case, the conn_state and history summary you learned earlier. This is enough to answer the vast majority of triage questions: is this connection expected for this asset, is the volume unusual, did it complete normally or get reset, is this a scan pattern, is the timing suspicious. Flow data is compact (a single flow record is a few hundred bytes regardless of whether the underlying conversation carried 10 bytes or 10 gigabytes), which is exactly why it can be retained for months when full PCAP cannot.\n\n` +
        `**What a flow record cannot give you**\n\n` +
        `No payload. You cannot see the HTTP request path, the file that was downloaded, the exact command sent over a shell, or the content of a DNS query from a NetFlow record alone (Zeek is a partial exception, because it does protocol-aware parsing at capture time, it also produces application-layer logs like http.log, dns.log, and ssl.log alongside conn.log, which do carry meaningful application metadata even without a full PCAP; but that's Zeek doing extra work at the moment of capture, not something you can extract from a NetFlow export after the fact). If you need the literal bytes exchanged, to extract a downloaded malware sample, prove exact data exfiltrated, or examine an exploit payload, only a full packet capture will do, and by definition, that capture has to have already been running before or during the incident; you cannot retroactively conjure packet contents from flow metadata.\n\n` +
        `**Zeek's history field: the density of a full packet trace, compressed into a string**\n\n` +
        `Zeek's history field packs an extraordinary amount of detail into a short string: each letter represents an event, uppercase from the originator, lowercase from the responder. S (SYN), h (SYN-ACK), A (pure ACK), D (data sent), F (FIN), R (RST), C (a state-changing packet with a bad checksum), and several more. A history of "ShAdDaFf" reads as: originator sent SYN, responder sent SYN-ACK, originator ACKed, both sides sent data (D then d), originator sent FIN, responder sent FIN back, a completely normal, clean connection close. A history of just "S" (as in this room's first scan example) means exactly one thing happened: a lone SYN, and nothing else, no reply was ever seen by the sensor.\n\n` +
        `**When to escalate from flow to PCAP**\n\n` +
        `Pull a full packet capture (or, if one wasn't already running, deploy one going forward and treat the gap as a limitation of your finding) when: you need to prove or recover exact data content (exfiltrated file contents, exact malicious payload), you're investigating a protocol-level anomaly that flow metadata alone can't explain (a connection classified OTH with unclear byte patterns), or you need packet-level timing/fragmentation detail (evasion techniques, TTL/window fingerprint verification down to individual packets) that a flow record's summary numbers smooth over. For the overwhelming majority of triage ("is this normal, is this a scan, is this beaconing, is this exfil-shaped") flow records are not just sufficient, they are usually faster to work with because there is far less data to sift through.`,
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
        `When a receiver gets segments out of order (one segment was lost, but later ones arrived), it re-sends an ACK for the last byte it received correctly, once for every out-of-order segment it gets: these are duplicate ACKs. Three duplicate ACKs in a row conventionally triggers "fast retransmit," where the sender resends the missing segment without waiting for a full timeout. A burst of duplicate ACKs in a flow log is a fingerprint of packet loss or reordering on that specific path. Useful context when you're trying to distinguish "this connection looks weird because of a bad network link" from "this connection looks weird because something is actively interfering with it."\n\n` +
        `**Asymmetric byte counts: reading the shape of a conversation**\n\n` +
        `A normal web browsing session is asymmetric in a predictable way: a small request (orig_bytes, a few hundred bytes) produces a much larger response (resp_bytes, tens of kilobytes of HTML/images/scripts). A connection with the opposite shape (large orig_bytes, tiny resp_bytes, especially over a long duration) is the shape of an upload, and on an unexpected destination or at an unexpected hour, is exactly the shape you'd expect from data being pushed out during exfiltration. A connection with both directions carrying small, remarkably **consistent** byte counts, repeating at regular intervals against the same destination, is the shape of a heartbeat or check-in. Legitimate software does this constantly (update checkers, telemetry, license validation) but so does C2 beaconing, which is why byte-count shape alone is never proof, only a prioritization signal. Infrastructure monitoring has the same rhythm: a load balancer's health checker connects to every server in its backend pool every few seconds, fetches a small status response, and often closes with an RST rather than a FIN to free the socket quickly, the difference from a beacon is who and where (a known infrastructure source, internal to internal, hitting exactly the pool it fronts), not the shape.\n\n` +
        `**Putting it together: the analyst's flow-record triage pass**\n\n` +
        `Given any single suspicious flow record, ask in order: (1) What does conn_state/history tell me about how this connection started and ended? (2) Is the flag pattern one that legitimate traffic would ever produce (a bare SYN, a bare FIN/NULL/XMAS with no prior SYN, is inherently abnormal; a full SF close is not)? (3) Is the byte-count shape consistent with the stated protocol/service, and is it symmetric (browsing-like), upload-shaped, or beacon-shaped? (4) Does the initial TTL/window size match what I'd expect from the claimed source asset's known OS? (5) Is this one flow, or one of many identical flows repeating across ports, hosts, or time, and if repeating over time, at what interval? Answering these five questions, in this order, is usually enough to triage a raw flow record into "benign," "needs a second look," or "escalate," before you ever need to touch a full packet capture.`,
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
          "A small request and a much larger response, seen once as a single connection to the destination",
          "Large orig_bytes with a tiny resp_bytes, sustained over one long-lived connection to the destination",
          "Small, consistent byte counts in both directions, repeating at regular intervals to one destination",
          "Zero bytes both ways with conn_state S0, repeated quickly across many ports on the same destination",
        ],
        answer: 2,
        explanation:
          "The reading describes beacon/heartbeat-shaped traffic as small, consistent byte counts repeating at regular intervals against the same destination. Distinct from browsing (small request/large response, one-off), from exfiltration-shaped uploads (large orig_bytes, tiny resp_bytes), and from a failed scan attempt (zero bytes, S0, no reply at all: no connection ever completed, so there's nothing to beacon with).",
      },
    },

    // ── Reading 7: Wireshark hands-on ────────────────────────────────────────
    {
      type: "reading" as const,
      id: "tcpip-r7",
      heading: "Reading a Packet Capture in Wireshark",
      content:
        `Everything in the last two readings (flags, conn_state, byte-count shape, retransmissions) is what you reconstruct from *metadata*. The moment you've escalated to a full PCAP, you're looking at the actual bytes, and the tool almost every analyst reaches for to do that is Wireshark. Knowing your way around its interface well enough to move fast under pressure is a distinct skill from understanding TCP theory, and it's the one this reading covers.\n\n` +
        `**The three panes**\n\n` +
        `Wireshark's main window is split into three stacked panes, and learning to move between them fluidly is most of what "reading a PCAP efficiently" actually means. The **packet list** (top) shows one row per captured packet, with columns for No. (capture order), Time (offset from capture start, by default), Source and Destination (IP addresses, or MAC/hostname depending on settings), Protocol (the highest-layer protocol Wireshark identified. TCP, HTTP, DNS, TLS, etc.), and Info (a one-line, protocol-aware summary, for a TCP packet this shows the flags set, sequence/ack numbers, and window size right there, without opening the packet at all). The **packet details** pane (middle) shows the fully decoded protocol stack of whichever single packet is selected in the list, as a set of collapsible layers (Frame, Ethernet, IP, TCP, and then whatever application-layer protocol sits on top) each expandable to see every individual field Wireshark parsed out. The **packet bytes** pane (bottom) shows the same packet as raw hex on the left and its ASCII representation on the right; clicking any field in the details pane highlights the exact bytes it came from in both panes simultaneously, which is the fastest way to confirm you're reading the field you think you're reading rather than trusting a label.\n\n` +
        `**Capture filters vs. display filters: a distinction that trips up beginners constantly**\n\n` +
        `These are two different mechanisms, applied at two different times, using two different syntaxes, and mixing them up wastes real time during an investigation. A **capture filter** is applied before or during capture and decides what gets written to the capture file in the first place, anything that doesn't match is discarded permanently and is never recoverable from that capture. Capture filters use Berkeley Packet Filter (BPF) syntax, the same syntax tcpdump uses: e.g. \`tcp port 445\` or \`host 10.0.0.5 and tcp port 3389\`. Because a capture filter throws data away at capture time, you set it once, before you start capturing, based on what you already know you need, and if it turns out you needed something it excluded, there is no way to get it back; you have to recapture. A **display filter**, by contrast, is applied after the fact to a capture that already exists in full. It never deletes anything, it only controls which rows the packet list currently shows you. Display filters use Wireshark's own syntax (not BPF), typically field-based comparisons like \`tcp.port == 445 && ip.addr == 10.0.0.5\`, or \`http.request.method == "POST"\`, or \`tcp.flags.syn == 1 && tcp.flags.ack == 0\` to isolate bare SYNs. Because nothing underlying is discarded, you can type a display filter, clear it, and type a completely different one, as many times as you like, without ever losing data, which is exactly why, in practice, the standard workflow is to capture broadly (or with only a light capture filter) and do all your actual narrowing with display filters afterward.\n\n` +
        `**Follow TCP Stream: the single most useful feature for understanding a session**\n\n` +
        `Reading a multi-packet conversation one packet at a time is slow and error-prone. You'd be manually stitching together dozens or hundreds of individual segments in your head. Right-click any packet belonging to the conversation you care about, choose Follow, then TCP Stream (the equivalent exists for UDP and HTTP streams too), and Wireshark reassembles the entire conversation, both directions, into one continuous, human-readable view. Shown as text by default, with the two directions colored differently, and with a dropdown to switch to hex, C-array, or other renderings. This is how you actually read what a session contained: an HTTP request and its response, a plaintext protocol exchange, the commands sent over an unencrypted shell, without hand-assembling it from the packet list. It also auto-generates the matching display filter (e.g. \`tcp.stream eq 4\`) so you can jump straight back to just those packets in the main view afterward.\n\n` +
        `**File > Export Objects, pulling transferred files back out of a capture**\n\n` +
        `If a session captured in the PCAP actually transferred a file (a download over HTTP, a file copied over SMB, an attachment over SMTP) Wireshark can reassemble and extract that file straight out of the capture, without needing the file from anywhere else. File > Export Objects lists the relevant protocol (HTTP, SMB, DICOM, IMF for email, TFTP, and a few others), shows every object Wireshark identified inside the capture with its filename, content type, and size, and lets you save any of them to disk individually or all at once. This is exactly how an analyst recovers a malware payload that was downloaded during an intrusion directly from network evidence, confirming precisely what file left the wire, byte for byte, even if the file no longer exists anywhere else by the time you're investigating.\n\n` +
        `**A worked example: spotting beaconing by eye in the packet list**\n\n` +
        `You don't always need Follow TCP Stream or a display filter to notice beaconing, sometimes it's visible just from scrolling the packet list. Sort or scan by Time and Destination: if the same destination IP:port keeps reappearing at a near-constant interval (say, every ~60 seconds, packet after packet, hour after hour) that rhythm is exactly the visual signature of a scheduled check-in. Combined with what you already know from flow analysis (small, consistent byte counts each time), seeing that same pattern confirmed directly in the packet list, with the actual timestamps in front of you, is often the final piece of evidence that turns "I suspect this is a beacon" into "I can show you the exact interval." From there, a display filter like \`ip.addr == <destination> && tcp.flags.syn == 1\` isolates just the connection attempts to that host, making the interval trivially easy to measure packet-by-packet with the Time column.`,
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
          "An analyst has a full packet capture already saved from earlier in the day. They want to narrow the view down to just one suspicious host's traffic, then a few minutes later narrow it differently to look at a different protocol instead, without losing any of the originally captured data. Which filter type should they use, and why?",
        options: [
          "A capture filter, since BPF expressions like host 10.0.0.5 isolate one host more precisely",
          "A display filter, since it only changes which captured packets are shown and can be changed freely",
          "A capture filter, since it can be run against the saved file to keep only the matching packets",
          "A display filter, but saved to a new file each time, since clearing one drops the hidden packets",
        ],
        answer: 1,
        explanation:
          "The capture already exists and the analyst wants to re-narrow it repeatedly, so a display filter is right: it only hides or shows rows and never deletes anything. “Since BPF expressions ... isolate one host more precisely” is not the deciding factor: both syntaxes can isolate a host, and capture filters only act while capturing. “Run against the saved file” is the core misconception: a capture filter works before or during capture and cannot be applied retroactively. “Saved to a new file each time, since clearing one drops the hidden packets” gets the tool right but the reason wrong, clearing a display filter brings every packet back.",
      },
    },

    // ── Question 1 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "tcpip-q1",
      question:
        "A firewall log shows a connection where the client sent only a SYN, and the server replied RST,ACK. The connection never advanced further. What does this most likely indicate?",
      options: [
        "The server accepted the probe on an open port but reset the session at once because its listen backlog was full, so the service is up and busy",
        "The destination port is closed on the target (or a device on the path rejected on its behalf), the standard reply to a SYN probe of a closed port",
        "A stateful firewall in the path silently dropped the SYN, and the RST,ACK is the client's own stack cleaning up after its handshake timer expired",
        "A graceful teardown: RST,ACK and FIN,ACK are interchangeable ways for the server to close a session after a short exchange of data",
      ],
      answer: 1,
      explanation:
        "RST,ACK in direct response to a bare SYN (with no prior SYN-ACK) is the standard TCP behavior when a SYN arrives at a port with nothing listening, or a firewall configured to REJECT (rather than silently DROP) spoofing that same response. This exact reply is what lets a SYN scanner distinguish a closed port (RST,ACK) from an open one (SYN,ACK) or a filtered one (no reply at all). “A graceful teardown” is wrong twice: a FIN close needs an established connection, which never existed here, and RST is an abrupt abort, never interchangeable with FIN. “Accepted the probe on an open port” would first produce a SYN-ACK, which the log does not show. “A stateful firewall ... silently dropped the SYN” would leave no reply at all, and here the RST,ACK came from the server side, not from the client's own stack.",
      xp: 20,
    },

    // ── Question 2 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "tcpip-q2",
      question:
        "You're reviewing Zeek conn.log entries and see hundreds of records from one internal host, all with conn_state RSTOS0, spread across sequential destination ports on one target within seconds. What does RSTOS0 specifically tell you, beyond just 'this is a scan'?",
      options: [
        "The responder answered each SYN with an RST, so every port was reachable but closed; RSTOS0 is Zeek's label for a rejected connection attempt",
        "The originator sent a SYN and then its own RST without ever seeing a SYN-ACK, consistent with scanner tooling that aborts half-open attempts itself",
        "The originator completed the handshake and then reset the session before sending data, a pattern typical of banner-grabbing tools probing open ports",
        "The connections were established and the responder reset them after a protocol error, so the scanned services are running and rejecting the client",
      ],
      answer: 1,
      explanation:
        "RSTOS0 decodes as: the Originator sent a SYN, and an RST was seen, but the responder's SYN-ACK (the 'S0' portion) was never observed, meaning the originator itself tore the attempt down rather than completing or waiting for a normal handshake outcome. This is a recognizable artefact of certain scanning tool behavior and is a stronger, more specific signal than just 'many ports touched'. It tells you something about how the scanning client itself is built, which can help fingerprint the tool in use. “The responder answered each SYN with an RST” describes REJ, a different code. “Completed the handshake and then reset the session” would be RSTO, with a SYN-ACK in the history. “The responder reset them after a protocol error” would be RSTR: both require an established connection, which the S0 part of RSTOS0 rules out.",
      xp: 25,
    },

    // ── Question 3 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "tcpip-q3",
      question:
        "An analyst sees a NULL scan (all flags cleared) hitting closed ports on a Windows Server target, but the technique's designers built it to be silent on open ports based on RFC 793 behavior. Why is a NULL/FIN/XMAS scan considered unreliable against modern Windows hosts specifically?",
      options: [
        "Windows Defender Firewall drops all unsolicited inbound TCP by default, so every scan type returns silence and open ports cannot be told from closed ones",
        "Windows stacks typically answer these odd flag combinations with an RST whatever the port state, instead of RFC 793's silence on open ports, destroying the signal",
        "Windows rate-limits RST replies per source, so after the first few probes closed ports also go silent and read as open ports to the scanner",
        "Windows requires a SYN flag before processing any TCP segment, so these probes are discarded by the network driver and never reach the connection-state logic",
      ],
      answer: 1,
      explanation:
        "The RFC 793 behavior these scans depend on (silence on open ports, RST on closed ports for segments without SYN) is followed inconsistently across real-world TCP/IP stack implementations. Windows in particular is well known for replying RST to malformed/flagless segments regardless of the underlying port's actual state, which collapses the open-vs-closed signal the scan is trying to extract. This is exactly why nmap documentation flags these scan types as unreliable against Windows targets specifically, while they remain more useful against many Unix-like TCP/IP stacks that follow the older behavior more faithfully. “Windows Defender Firewall drops all unsolicited inbound TCP” would leave every probe unanswered, but the reading's point is that Windows stacks DO reply, with RST. “Windows rate-limits RST replies” is not the reason the reading gives: the problem is RST on open ports too, not missing RSTs on closed ones. “Windows requires a SYN flag before processing any TCP segment” fails for the same reason: Windows does process flagless segments. It just answers them with RST.",
      xp: 25,
    },

    // ── Log Analysis 1: SYN scan sweep ───────────────────────────────────────
    {
      type: "log_analysis" as const,
      id: "tcpip-la1",
      heading: "Investigating a Rapid Port Sweep Against an Internal Server",
      context:
        "You're triaging a NIDS alert. SRV-CORE02 (10.40.2.30) is a domain-joined print/file server that normally only receives connections on ports 445, 139, and 3389 from a small set of known IT hosts. The sensor captured 1,024 separate connection records from WKS-ENG14 (10.40.6.114) against SRV-CORE02 in a 38-second window: 1,017 ended S0 (no reply), 6 ended REJ (SYN answered with RST, closed port), and 1 reached SF (full handshake). The record below is one representative sample from that set.",
      event: synScanEvent,
      questions: [
        {
          question:
            "The record shows conn_state: 'S0' and history: 'S', with orig_bytes and resp_bytes both 0. What does this single flow record tell you happened on the wire?",
          options: [
            "A full handshake completed, but neither side sent any application data before the connection closed",
            "WKS-ENG14 sent a lone SYN and the sensor saw no reply of any kind: no SYN-ACK and no RST",
            "SRV-CORE02 refused the connection with RST,ACK, the normal reply from a port with nothing listening",
            "SRV-CORE02 replied SYN-ACK, but WKS-ENG14 never sent the final ACK, leaving the connection half-open",
          ],
          answer: 1,
          explanation:
            "history 'S' means exactly one event was observed: a SYN from the originator, and conn_state S0 confirms no reply was seen. That is the signature of a filtered port or a scanner that does not wait for replies. “A full handshake completed” would show an h and A in the history and a state like SF, not a lone S. “Refused the connection with RST,ACK” would be REJ, with an r in the history. “Replied SYN-ACK, but ... never sent the final ACK” would put the responder's h in the history string, and there is none.",
          xp: 25,
        },
        {
          question:
            "Now weigh the sample against the aggregate counts given in the task context. How should that aggregate change your read of the single record?",
          options: [
            "It shouldn't: score each record on its own, since combining separate flows adds noise, not evidence",
            "One source hitting 1,024 ports on one target in 38s turns an ambiguous record into a clear port sweep",
            "The single SF shows the sweep found an open service, so SRV-CORE02 is now the likely compromised host",
            "The 6 REJ results show a firewall stopped the sweep, so it failed and needs no further follow-up",
          ],
          answer: 1,
          explanation:
            "One S0 record alone could be an application retry against a busy service. 1,024 distinct ports from one source to one target in 38 seconds is the breadth the reading calls unmistakable: the aggregate, not any single record, makes it a scan. “Score each record on its own” throws away the breadth signal that defines a scan. “SRV-CORE02 is now the likely compromised host” mixes up roles: the server is the target; an SF only means one normally-open service answered. “A firewall stopped the sweep” misreads REJ: a REJ is the target host answering RST,ACK from a closed port, and a reconnaissance sweep matters whether or not it found much.",
          xp: 30,
        },
        {
          question:
            "Given WKS-ENG14 is a regular engineering workstation with no business reason to be scanning SRV-CORE02, what is the correct next investigative step?",
          options: [
            "Close it: only one port completed a handshake, so the reconnaissance gained the attacker almost nothing",
            "Investigate WKS-ENG14: find the process behind the sweep in EDR and check other hosts for the same pattern",
            "Investigate SRV-CORE02 first, since the one completed handshake means the target may already be breached",
            "Block WKS-ENG14 at the perimeter firewall, so the sweep is cut off before it reaches any more servers",
          ],
          answer: 1,
          explanation:
            "An internal workstation sweeping an internal server is classic post-compromise reconnaissance before lateral movement. The source is where the attacker is, so find the process behind the sweep (EDR process ancestry) and check whether other hosts show the same pattern. “Close it” ignores that reconnaissance is the warning before the next step: the attacker now knows which services answer. “Investigate SRV-CORE02 first” misreads the SF: one normally-open service answering a SYN is not a breach of the target. “Block WKS-ENG14 at the perimeter firewall” cannot work: the sweep is east-west traffic inside the LAN and never crosses the perimeter.",
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
        "BASTION-01 (10.40.1.9) is a hardened Ubuntu Linux jump host that IT uses for administrative SSH access into sensitive segments. Across the last 40 recorded sessions from this host, the observed initial TTL has consistently landed between 58 and 61. Consistent with a Linux host (initial TTL 64) crossing 3-6 hops to reach the sensor. Review the session below, captured tonight against the finance file server SRV-FIN03.",
      event: ttlMismatchEvent,
      questions: [
        {
          question:
            "Compare the originator TTL recorded for this session with BASTION-01's established baseline. Based on typical initial TTL values by OS family, what does it most likely indicate about the traffic's true origin?",
          options: [
            "Normal path variation: a Linux host's observed TTL can drift that far when routing changes between sessions",
            "The sender's stack most likely starts at 128 (Windows), not 64, so it is unlikely to be BASTION-01's Linux stack",
            "Fragmentation on the path, since reassembling fragmented packets resets their TTL to a higher value",
            "The SSH server's settings, since each session negotiates the TTL that both sides then use for its packets",
          ],
          answer: 1,
          explanation:
            "Observed TTLs sit just below the sender's initial value, minus one per hop. This session's orig_ttl rounds up to 128, the Windows default, not 64 like BASTION-01's 40 baseline sessions. “Normal path variation” is impossible in this direction: routers only decrement TTL, so a host that starts at 64 can never be seen above 64. “Fragmentation” is a separate IP mechanism and never raises TTL. “Negotiates the TTL” is wrong: each side sets its own initial TTL, which is exactly why orig_ttl and resp_ttl differ in this record.",
          xp: 25,
        },
        {
          question:
            "Which explanations, taken together, should the analyst consider BEFORE concluding this is definitely a spoofed or hijacked source, recognizing that TTL is a corroborating signal, not standalone proof?",
          options: [
            "None: a TTL mismatch this large is proof on its own that an outside attacker spoofed the source address",
            "A re-image or approved OS change on BASTION-01, or a NAT change sharing its IP, as well as spoofing or misuse",
            "A longer routing path tonight, which can push the observed TTL above the host's usual baseline range",
            "A sensor enrichment fault, since stock Zeek conn.log never records TTL, so the field can't be trusted here",
          ],
          answer: 1,
          explanation:
            "A passive fingerprint is corroborating evidence, not a verdict, so first rule out mundane causes: a re-image or approved OS change on BASTION-01, or a NAT/infrastructure change that puts a different device behind its IP, while keeping spoofing or misuse on the table. “Proof on its own” over-reads a single signal. “A longer routing path” cannot raise TTL; every hop only decrements it, so a path change could lower 64 but never lift it to 125. “A sensor enrichment fault” misapplies the reading: stock conn.log lacks TTL, but this is an enriched Corelight record, which is exactly where the reading says TTL appears.",
          xp: 25,
        },
        {
          question:
            "After checking the change log and confirming BASTION-01 was NOT re-imaged, no routing changes occurred, and no NAT change was made, what is the correct next step?",
          options: [
            "Dismiss it: TTL is only metadata, so with no change found, the value is most likely a one-off sensor glitch",
            "Escalate: check BASTION-01's EDR/host logs and other sessions from 10.40.1.9 for the same anomalous TTL",
            "Declare a breach and block 10.40.1.9 everywhere, since the mismatch now proves the bastion is compromised",
            "Ask the sensor team to recalibrate TTL enrichment, then re-check the next session BASTION-01 makes",
          ],
          answer: 1,
          explanation:
            "With the benign causes ruled out, the address-to-device mapping is unverified, so escalate: look at BASTION-01's own host telemetry for tampering or unauthorised use, and check whether other sessions from 10.40.1.9 in the same period carry the same anomaly. “Dismiss it ... sensor glitch” is an assumption with no evidence; the enrichment matched 40 previous sessions. “Declare a breach and block 10.40.1.9 everywhere” overreacts to one corroborating signal and cuts IT's admin path before anything is confirmed. “Recalibrate TTL enrichment” and waiting for the next session loses time while a 41-minute session into the finance server stays unexplained.",
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
        "This pattern is characteristic of an application load balancer's active health-check probe, not a scan. Every session completes a genuine, full three-way handshake and a real (if small) TLS-capable data exchange with each backend web server before closing: a scanner does not bother completing a real TLS-capable exchange with every target it touches. The RST-based teardown (conn_state RSTO) instead of a FIN is simply the load balancer's health-check client choosing to abort quickly after collecting the response it needed, rather than performing a full graceful close: a common, deliberate optimization in load-balancer health-check implementations, not a sign of malicious tooling. The fixed ~15-second recurrence across exactly the six known backend servers in the web farm (not a broad, expanding, or random set of hosts) is exactly the fingerprint of scheduled infrastructure monitoring.",
      fp_trap:
        "It's tempting to treat 'repeated RST-based connection teardowns at a fixed interval, hitting multiple hosts' as inherently scan-like or beacon-like, because both scans and beacons also produce repeating, small, regular connections. Session completeness alone does not separate them: a scan usually never completes the handshake, but an HTTPS C2 beacon DOES complete a full TLS session on every check-in, with the same small, regular shape seen here. The real discriminators are direction and destinations: a beacon calls OUT from an internal host to an external server, while here the source is the load balancer's health-check host (LB-HEALTHCHECK), the traffic is internal-to-internal, and the destinations are exactly the six known backend servers of the web farm it fronts. A known infrastructure source polling exactly its own backend pool on a fixed schedule is the signature of legitimate infrastructure monitoring, not reconnaissance or C2. Escalating this indiscriminately just because of the RST-based close and fixed timing produces exactly the kind of alert fatigue that causes real anomalies to get lost in the noise.",
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
          right: "Sends only the FIN flag with no prior SYN: a 'close' for a connection that was never opened; same silence-vs-RST logic as NULL",
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
        { id: "ack", text: "Client sends ACK (ack=y+1): connection is now ESTABLISHED" },
        { id: "data", text: "Both sides exchange application data (PSH/ACK segments)" },
        { id: "finclient", text: "Client sends FIN,ACK, client has no more data to send" },
        { id: "ackserver1", text: "Server ACKs the client's FIN" },
        { id: "finserver", text: "Server sends its own FIN,ACK once it has finished sending" },
        { id: "ackclient2", text: "Client ACKs the server's FIN: client enters TIME_WAIT" },
      ],
      correct_order: ["syn", "synack", "ack", "data", "finclient", "ackserver1", "finserver", "ackclient2"],
      explanation:
        "A complete TCP session is the three-way handshake (SYN, SYN-ACK, ACK), followed by whatever application data is exchanged while ESTABLISHED, followed by a four-step graceful teardown: each side independently signals it has no more data (FIN) and the other side acknowledges. The side that sends the final ACK holds the connection in TIME_WAIT briefly to catch any stray delayed packets from the now-closed connection before fully releasing it. Any deviation from this sequence (a FIN or RST appearing before ESTABLISHED, data appearing before the handshake completes) is exactly the kind of anomaly that scan and evasion techniques deliberately produce.",
      xp: 35,
    },

    // ── Query Fill: KQL for detecting a port-sweep pattern ──────────────────
    {
      type: "query_fill" as const,
      id: "tcpip-qf1",
      heading: "Write It Yourself: Detect a Port Sweep in KQL",
      language: "kql",
      context: KQL_PRIMER +
        "Using the pattern from Log Analysis 1 (one source touching many destination ports on one target, mostly ending in S0/no reply, within a short window), write the KQL that would surface this pattern across your whole network flow table, the way a detection engineer would before shipping it as a scheduled analytics rule. List the conn_state value(s) that mean the handshake never completed (S0 must be included; REJ and RSTOS0 are optional extras), pick a short time window (30 seconds to 10 minutes), and set a distinct-port threshold between 20 and 500, rounded to a multiple of 5.",
      template:
        "NetworkFlowEvents\n| where ConnectionState in ({{states}})\n| summarize DistinctPorts = dcount(DestinationPort) by SourceIp, DestinationIp, bin(TimeGenerated, {{window}})\n| where DistinctPorts > {{threshold}}",
      blanks: [
        { id: "states", answers: ["\"S0\"","'S0'","\"S0\", \"REJ\"","\"S0\",\"REJ\"","'S0', 'REJ'","'S0','REJ'","\"REJ\", \"S0\"","\"REJ\",\"S0\"","'REJ', 'S0'","'REJ','S0'","\"S0\", \"RSTOS0\"","\"S0\",\"RSTOS0\"","'S0', 'RSTOS0'","'S0','RSTOS0'","\"RSTOS0\", \"S0\"","\"RSTOS0\",\"S0\"","'RSTOS0', 'S0'","'RSTOS0','S0'","\"S0\", \"REJ\", \"RSTOS0\"","\"S0\",\"REJ\",\"RSTOS0\"","'S0', 'REJ', 'RSTOS0'","'S0','REJ','RSTOS0'","\"S0\", \"RSTOS0\", \"REJ\"","\"S0\",\"RSTOS0\",\"REJ\"","'S0', 'RSTOS0', 'REJ'","'S0','RSTOS0','REJ'","\"REJ\", \"S0\", \"RSTOS0\"","\"REJ\",\"S0\",\"RSTOS0\"","'REJ', 'S0', 'RSTOS0'","'REJ','S0','RSTOS0'","\"REJ\", \"RSTOS0\", \"S0\"","\"REJ\",\"RSTOS0\",\"S0\"","'REJ', 'RSTOS0', 'S0'","'REJ','RSTOS0','S0'","\"RSTOS0\", \"S0\", \"REJ\"","\"RSTOS0\",\"S0\",\"REJ\"","'RSTOS0', 'S0', 'REJ'","'RSTOS0','S0','REJ'","\"RSTOS0\", \"REJ\", \"S0\"","\"RSTOS0\",\"REJ\",\"S0\"","'RSTOS0', 'REJ', 'S0'","'RSTOS0','REJ','S0'"], placeholder: "conn_state values indicating no completed handshake" },
        { id: "window", answers: ["30s", "45s", "60s", "90s", "120s", "180s", "300s", "600s", "1m", "2m", "3m", "5m", "10m", "1min", "2min", "3min", "5min", "10min"], placeholder: "aggregation time window" },
        { id: "threshold", answers: ["20","25","30","35","40","45","50","55","60","65","70","75","80","85","90","95","100","105","110","115","120","125","130","135","140","145","150","155","160","165","170","175","180","185","190","195","200","205","210","215","220","225","230","235","240","245","250","255","260","265","270","275","280","285","290","295","300","305","310","315","320","325","330","335","340","345","350","355","360","365","370","375","380","385","390","395","400","405","410","415","420","425","430","435","440","445","450","455","460","465","470","475","480","485","490","495","500"], placeholder: "distinct-port count threshold" },
      ],
      explanation:
        "The core detection logic mirrors what you read directly off the flow record in Log Analysis 1: filter to connection states that mean 'no completed handshake' (S0 at minimum; REJ, closed ports answering RST, and RSTOS0 are also scan evidence), group by the source-to-destination pair within a short window (one minute is tight enough to catch a fast sweep like the 38-second one you investigated; a few minutes also works but catches slower sweeps at the cost of more noise), count the DISTINCT destination ports touched, and alert when that count crosses a threshold no legitimate application would reach in that time frame. Lower thresholds catch slower or narrower sweeps but fire more often; higher ones are quieter but miss small scans. A real deployment would also exclude known, approved scanners (vulnerability management tools) by source IP to avoid constant false positives from authorized scanning.",
      xp: 35,
    },

    // ── Flag ──────────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "tcpip-f1",
      prompt:
        "In the TTL-mismatch session against SRV-FIN03, assume the originator's initial TTL was its OS family's default. Using the fingerprinting reading's rule of thumb, how many router hops did that traffic cross before reaching the sensor? Enter the number only.",
      answer: "3",
      hint: "Round the observed originator TTL up to the nearest of 64, 128 or 255. The difference between the two is the hop count.",
      xp: 25,
    },
  ],
};

export default [tcpipDeepDiveRoom];
