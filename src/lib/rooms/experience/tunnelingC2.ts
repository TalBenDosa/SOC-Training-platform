import type { RoomExperience } from "./types";

// Experience for "tunneling-c2-channels" (rooms-batch-17-r6.ts).
//
// The 3D world is a NETWORK: relay nodes joined by beams, with the learner
// clearing the route one hop at a time toward the attacker's C2 core. Stations
// read as hops ("Hop 1: The Beacon", ..., "C2 Core").
//
// Every briefing lab uses example data that differs from the room's graded
// tasks, so a lab never hands over a graded answer. The graded cases live at
// Solvix (SRV-APP12 / SRV-DB07 / WKS-DEV27, plink -R 3389 over port 443 to
// 45.83.219.11, an ngrok beacon at 61.2 s / 6.8 s, a 90 s / 30% jitter beacon).
// The labs use a different fictional network (Harbor Logistics), different
// hosts, ports, intervals and tools, and a documentation IP range
// (198.51.100.0/24, RFC 5737), so nothing here overlaps a graded answer.
export const TUNNELING_C2: RoomExperience = {
  roomId: "tunneling-c2-channels",
  codename: "Operation Quiet Wire",
  theme: "c2",
  scene: "network",
  layout: "stage",
  handler: { name: "Dana Reyes", role: "SOC Lead, Night Shift" },
  briefing: [
    "23:40. A packet-capture box flagged one quiet, steady link that never closes.",
    "Something inside Solvix is talking to the outside on its own schedule.",
    "Learn how these channels are built, then trace this one hop by hop.",
    "Follow the beams to the core, confirm the channel, then cut it and write it up.",
  ],
  mission: "A covert channel is carrying traffic out of Solvix. Learn how tunnels and C2 work, trace the route hop by hop to the attacker's core, then confirm it, contain it, and close the case.",
  estimate: "~85 min",
  look: { primary: "#34d399", secondary: "#22d3ee", warn: "#fbbf24" },
  stations: [
    {
      id: "hop1-beacon",
      label: "Hop 1: The Beacon",
      tagline: "Where the link begins: SSH forwarding, SOCKS pivots and reverse shells",
      building: "archive",
      taskIds: ["tunnel-r1", "tunnel-r2", "tunnel-q1"],
    },
    {
      id: "hop2-carrier",
      label: "Hop 2: The Carrier",
      tagline: "What the channel hides inside: ICMP, DNS, and the math behind a beacon",
      building: "lab",
      taskIds: ["tunnel-r3", "tunnel-r4", "tunnel-q2"],
    },
    {
      id: "hop3-disguise",
      label: "Hop 3: The Disguise",
      tagline: "Why it looks legitimate: ngrok, Chisel and plink, and reading context",
      building: "factory",
      taskIds: ["tunnel-r5", "tunnel-q3", "tunnel-m1"],
    },
    {
      id: "hop4-hunt",
      label: "Hop 4: First Evidence",
      tagline: "The playbook, then a real SSH client launched where it should not be",
      building: "office",
      taskIds: ["tunnel-r6", "tunnel-la1", "tunnel-f1"],
    },
    {
      id: "hop5-pivot",
      label: "Hop 5: The Pivot",
      tagline: "A database server beaconing out: score it, hunt it, write the query, call it",
      building: "control",
      taskIds: ["tunnel-la2", "tunnel-o1", "tunnel-qf1", "tunnel-ac1"],
    },
    {
      id: "c2-core",
      label: "C2 Core",
      tagline: "Cut the channel in the right order, then close the case",
      building: "vault",
      taskIds: ["tunnel-o2", "tunnel-wr1"],
      boss: true,
    },
  ],
  personas: {
    "tunnel-ac1": {
      name: "J. Okafor",
      role: "Software Engineer · Platform",
      line: "That's my laptop. I run a tunnel for the sprint demo so stakeholders can hit my branch. There's an exception on file for it.",
    },
  },
  briefings: {
    // ── Reading 1: SSH port forwarding (-L / -R / -D) ───────────────────────
    "tunnel-r1": [
      {
        kind: "inspect",
        title: "Read the forwarding command",
        prompt: "An SSH client launched on a Harbor Logistics host with this command. Open each part: what does it set up, and which part is the dangerous one?",
        artifact: "Process command line (native ssh.exe)",
        items: [
          { id: "ssh", text: "ssh", tag: "The client", tone: "info",
            note: "Windows ships this as C:\\Windows\\System32\\OpenSSH\\ssh.exe, so the same syntax turns up in a native binary, not only in plink." },
          { id: "r", text: "-R 8080:127.0.0.1:445", tag: "Remote forward · the dangerous direction", tone: "warn",
            note: "Opens a listener on the REMOTE server's port 8080 that tunnels back IN to this host's own 127.0.0.1:445 (SMB). Whoever reaches that remote listener reaches this host's file sharing, over a link that was only ever an OUTBOUND connection." },
          { id: "p", text: "-p 2222", tag: "SSH server port", tone: "info",
            note: "The port the SSH session itself connects to on the server. It is separate from the forwarded ports. Here the session runs on 2222, not the default 22." },
          { id: "dest", text: "ops@198.51.100.77", tag: "The remote server", tone: "warn",
            note: "The machine the outbound SSH connection goes to, and the machine that owns the new inbound listener. In an intrusion this is attacker-controlled." },
        ],
      },
      {
        kind: "match",
        title: "Three forwarding modes",
        prompt: "Match each SSH forwarding flag to exactly what it opens.",
        pairs: [
          { id: "l", left: "-L 5432:db-internal:5432 jump", right: "A listener on THIS machine that tunnels OUT to a service reachable from the jump host", why: "Local forward: you reach a remote service from here. The target host:port is fixed in the syntax." },
          { id: "r", left: "-R 8080:127.0.0.1:445 server", right: "A listener on the REMOTE server that tunnels back IN to a service on this machine", why: "Remote forward: the firewall-bypassing direction. An outbound link hands someone inbound reach." },
          { id: "d", left: "-D 9050 jump", right: "A SOCKS proxy on THIS machine that reaches any TCP destination the jump host can", why: "Dynamic forward: no fixed target. Point any tool at the SOCKS port and pivot anywhere the jump host reaches." },
        ],
      },
      {
        kind: "sort",
        title: "Which way does the reach go?",
        prompt: "For each command, does it let the operator reach OUT from the initiating host, or does it hand someone reach IN to it?",
        buckets: [
          { id: "out", label: "Operator reaches OUT" },
          { id: "in", label: "Someone reaches IN" },
        ],
        items: [
          { id: "c1", text: "ssh -L 3307:mysql:3306 jump", bucket: "out", why: "Local forward: the initiating host reaches the internal MySQL through the jump host." },
          { id: "c2", text: "ssh -R 7001:127.0.0.1:5985 server", bucket: "in", why: "Remote forward: the remote server's listener reaches back in to this host's WinRM." },
          { id: "c3", text: "ssh -D 1081 jump", bucket: "out", why: "Dynamic SOCKS proxy on the local host: the operator reaches out, anywhere the jump host can." },
          { id: "c4", text: "ssh -R 1080 server", bucket: "in", why: "Reverse SOCKS (a port-only -R): a proxy on the remote server whose traffic exits from this host, so the operator pivots in through it." },
        ],
      },
    ],

    // ── Reading 2: SOCKS proxies and reverse shells ─────────────────────────
    "tunnel-r2": [
      {
        kind: "simulate",
        title: "Bind shell or reverse shell?",
        prompt: "A Harbor Logistics web server sits behind a firewall that blocks unsolicited inbound traffic and allows most outbound. Watch which shell reaches the operator.",
        checks: [
          { name: "Needs inbound?", question: "Does the firewall have to allow a new connection TO the victim?" },
          { name: "Needs outbound?", question: "Does the victim just have to connect OUT?" },
        ],
        scenarios: [
          {
            id: "bind", label: "Bind shell on port 9001",
            detail: "The web server opens a listener on 9001 and waits for the operator to connect in.",
            results: ["fail", "pass"],
            why: ["The firewall blocks the unsolicited inbound connection to 9001.", "No outbound connection is attempted, so that permissive rule never helps."],
            verdict: "Blocked. A bind shell needs inbound reach, which a reasonably configured firewall denies.",
          },
          {
            id: "reverse", label: "Reverse shell to operator:9001",
            detail: "The web server connects OUT to the operator, who hands back a shell over that link.",
            results: ["pass", "pass"],
            why: ["No inbound rule is needed: the victim starts the connection.", "The permissive outbound rule carries it straight out."],
            verdict: "Connected. Outbound is trusted more than inbound, so the reverse shell wins. The same asymmetry makes SSH -R work.",
          },
        ],
      },
      {
        kind: "match",
        title: "Name the pivoting piece",
        prompt: "Match each term to what it actually does.",
        pairs: [
          { id: "socks", left: "SOCKS proxy", right: "Relays raw TCP (or SOCKS5 UDP) to a requested host and port, with no idea what protocol is inside", why: "Protocol-agnostic: that is exactly why it is so useful for pivoting any tool." },
          { id: "pc", left: "proxychains", right: "Pushes an existing tool's traffic through a SOCKS proxy even though the tool has no proxy support", why: "It wraps the tool, so a scanner or browser pivots without being proxy-aware." },
          { id: "multi", left: "Multi-hop SOCKS chain", right: "Compromise A, pivot through A to reach and take B, stand up a second proxy on B, and so on", why: "Each hop only sees its neighbours, so the true origin gets harder to trace." },
          { id: "rev", left: "Reverse shell", right: "The victim connects OUT to the operator, who returns an interactive shell over that link", why: "Flips the direction so only an outbound connection is needed." },
        ],
      },
      {
        kind: "sort",
        title: "Raw shell or blended-in?",
        prompt: "Sort each observed connection by whether it looks like a raw interactive shell or like something deliberately dressed up as normal traffic.",
        buckets: [
          { id: "raw", label: "Raw / interactive shape" },
          { id: "blend", label: "Dressed up to blend in" },
        ],
        items: [
          { id: "s1", text: "Outbound TCP to port 1337, irregular bursts matching typed commands and their output", bucket: "raw", why: "Bursty, interactive timing on an unusual port is the classic raw reverse-shell shape." },
          { id: "s2", text: "Long-lived TLS on 443 to a cloud host, small regular check-ins", bucket: "blend", why: "Wrapped in HTTPS to look ordinary; now timing and destination context, not raw protocol, give it away." },
          { id: "s3", text: "A plain TCP stream on port 9001 that never negotiates HTTP, TLS or SSH", bucket: "raw", why: "No protocol handshake at all is the netcat-style raw shell." },
        ],
      },
    ],

    // ── Reading 3: ICMP and DNS tunneling mechanics ─────────────────────────
    "tunnel-r3": [
      {
        kind: "inspect",
        title: "Read the ping payloads",
        prompt: "Three echo requests to the same external host. Open each payload: which look like a real ping, and which is carrying data?",
        artifact: "ICMP echo request · data payload",
        items: [
          { id: "win", text: "32 bytes: abcdefghijklmnopqrstuvwabcdefghi", tag: "Standard Windows ping", tone: "trust",
            note: "A fixed, repeating alphabetic filler. No real application reads it; it is just padding." },
          { id: "lin", text: "56 bytes: [8-byte timestamp] then 08 09 0a 0b ... 37", tag: "Standard Linux ping", tone: "trust",
            note: "Only the leading 8-byte timestamp changes between packets; the rest is a predictable incrementing pattern." },
          { id: "tun", text: "variable size: changes meaningfully every packet, arbitrary bytes", tag: "Does not match either OS pattern", tone: "warn",
            note: "Payloads that vary in size and content packet to packet, and match neither standard filler, are data riding inside ICMP (icmpsh, ptunnel). Pair that with a high rate to one host and it is a tunnel." },
        ],
      },
      {
        kind: "sort",
        title: "Does DNS tunneling fit?",
        prompt: "DNS tunneling moves tens to a few hundred usable bytes per round trip, so at best tens of megabytes an hour. Sort each task by whether DNS tunneling is a plausible mechanical fit.",
        buckets: [
          { id: "fits", label: "Fits DNS tunneling" },
          { id: "nope", label: "Wrong tool for this" },
        ],
        items: [
          { id: "d1", text: "Carry small C2 commands and small replies, patiently, for weeks", bucket: "fits", why: "Low volume over a long time is DNS tunneling's comfort zone." },
          { id: "d2", text: "Exfiltrate a 4 GB database dump before the backup window closes", bucket: "nope", why: "Far too slow. Look instead for an upload-shaped TCP flow or a fast HTTPS POST." },
          { id: "d3", text: "Drip a stolen 20 KB credentials file out over a day", bucket: "fits", why: "Small and slow: well within a DNS channel's throughput." },
          { id: "d4", text: "Stream a live screen-share of the victim's desktop", bucket: "nope", why: "Needs steady high bandwidth and low latency, the opposite of a DNS channel." },
        ],
      },
      {
        kind: "match",
        title: "Which signal catches which tunnel?",
        prompt: "Match each observation to the tunnel it points at.",
        pairs: [
          { id: "icmpsize", left: "Large, inconsistent ICMP payloads to one host, with the standard filler bytes missing", right: "ICMP tunneling", why: "Real diagnostic pings keep a fixed filler pattern even when large; varying content is data." },
          { id: "icmprate", left: "Hundreds of echo requests a minute to a single external IP", right: "ICMP tunneling", why: "Far beyond any troubleshooting session: a volume signal, like DNS tunneling's query-rate signal." },
          { id: "dnsrate", left: "A flood of long, high-entropy subdomain lookups under one domain", right: "DNS tunneling", why: "The encoded data rides in the query names; volume and entropy give it away." },
        ],
      },
    ],

    // ── Reading 4: HTTP(S) beaconing math ───────────────────────────────────
    "tunnel-r4": [
      {
        kind: "simulate",
        title: "Work out the jitter band",
        prompt: "A beacon sleeps 120 seconds with 25% jitter, applied symmetrically. The band runs from 120 minus 30 to 120 plus 30, so 90 to 150 seconds. Check each observed gap.",
        checks: [
          { name: "In band?", question: "Is the gap between 90 and 150 seconds?" },
        ],
        scenarios: [
          { id: "g1", label: "Gap of 96 s", detail: "One measured inter-arrival delta.", results: ["pass"], why: ["96 is inside 90 to 150."], verdict: "Fits the beacon profile." },
          { id: "g2", label: "Gap of 148 s", detail: "One measured inter-arrival delta.", results: ["pass"], why: ["148 is just inside the 150 ceiling."], verdict: "Fits, near the top edge." },
          { id: "g3", label: "Gap of 72 s", detail: "One measured inter-arrival delta.", results: ["fail"], why: ["72 is below the 90 floor."], verdict: "Outside the band: a different cause, or a different beacon config than assumed." },
        ],
      },
      {
        kind: "sort",
        title: "Beacon or just regular?",
        prompt: "A beacon with interval 45 s and 20% jitter lands every gap between 36 and 54 seconds, indefinitely. Sort each delta series by whether it matches that signature.",
        buckets: [
          { id: "beacon", label: "Matches the beacon band" },
          { id: "human", label: "Not this beacon" },
        ],
        items: [
          { id: "a", text: "41, 48, 37, 52, 39, 50, 44 (seconds), holding for hours", bucket: "beacon", why: "Every gap sits in 36 to 54 and the band never drifts: tight, bounded, sustained." },
          { id: "b", text: "8, 240, 35, 1100, 60, 19 (seconds)", bucket: "human", why: "Gaps from seconds to many minutes: the unbounded spread of real human activity." },
          { id: "c", text: "46, 39, 53, 42, 49 for five samples, then nothing for the rest of the day", bucket: "human", why: "A short burst is not a sustained beacon; the pattern has to persist across a long window." },
        ],
      },
      {
        kind: "match",
        title: "What raises a beacon score?",
        prompt: "Match each factor to how it affects confidence that a link is a beacon.",
        pairs: [
          { id: "var", left: "Gaps cluster tightly around the mean (low spread)", right: "Raises the score", why: "Tight clustering is the core beacon signal." },
          { id: "reps", left: "Hundreds of check-ins observed over many hours", right: "Raises the score", why: "More repetitions turn coincidence into confidence." },
          { id: "dest", left: "Destination is widely used across the whole company", right: "Lowers the score", why: "A common, long-trusted destination is a weak suspect; rarity raises suspicion, not popularity." },
          { id: "bytes", left: "Nearly identical bytes sent per check-in", right: "Raises the score", why: "Consistent payload size fits an automated beacon, not human browsing." },
        ],
      },
    ],

    // ── Reading 5: dual-use tunneling tools ─────────────────────────────────
    "tunnel-r5": [
      {
        kind: "match",
        title: "Tool to fingerprint",
        prompt: "Match each dual-use tool to the trace that gives it away.",
        pairs: [
          { id: "ngrok", left: "ngrok agent", right: "Outbound TLS to ngrok's own cloud; SNI under *.ngrok.io or *.ngrok-free.app from a host with no reason to tunnel", why: "The traffic is genuine SaaS; the host's lack of any business reason is the anomaly." },
          { id: "chisel", left: "Chisel", right: "A single dropped binary that tunnels over HTTP, with a WebSocket upgrade whose subprotocol carries a version string, SSH inside", why: "Portable, no install, often a SOCKS pivot; operators customize the handshake, so behavior beats static signatures." },
          { id: "plink", left: "plink.exe", right: "A signed PuTTY binary scripting -L/-R/-D forwards, often trusted by EDR by default", why: "Old, signed and widely used, so detection rests on where it ran and in what context." },
          { id: "netsh", left: "netsh interface portproxy", right: "A built-in Windows command that forwards a port with no download at all", why: "A true living-off-the-land option: the OS already ships it." },
        ],
      },
      {
        kind: "sort",
        title: "Does context clear it?",
        prompt: "The tool alone never settles it. Sort each sighting by whether the context clears it or keeps it suspicious.",
        buckets: [
          { id: "clear", label: "Context clears it" },
          { id: "susp", label: "Stays suspicious" },
        ],
        items: [
          { id: "x1", text: "plink.exe run from the documented admin toolkit path, matched to an open change ticket", bucket: "clear", why: "Known location plus a documented approval is a verifiable business explanation." },
          { id: "x2", text: "ngrok agent on a point-of-sale terminal, no ticket, running overnight", bucket: "susp", why: "A POS terminal has no reason to run a developer tunnel, and nothing documents it." },
          { id: "x3", text: "Chisel dropped into a Downloads folder on a jump box, long-lived SOCKS-shaped link, no change record", bucket: "susp", why: "Unfamiliar binary, odd location, pivot-shaped traffic, no explanation." },
          { id: "x4", text: "A build agent reaching a tunnel SaaS, listed in the CI platform's documented integrations", bucket: "clear", why: "A documented, expected integration is the business reason that clears it." },
        ],
      },
      {
        kind: "sequence",
        title: "Three questions, in order",
        prompt: "A dual-use tool is sighted. Tap the three detection questions in the order the reading asks them.",
        items: [
          { id: "q1", text: "Does this host or account have any business reason to run this tool at all?", note: "Start with reason to exist." },
          { id: "q2", text: "Is the location it ran from normal, or anomalous (Temp, Downloads, a user profile)?", note: "Then where it ran from." },
          { id: "q3", text: "Does the connection behave normally, or is it long-lived, beacon-shaped, to an unexpected place?", note: "Then how the link behaves." },
        ],
        order: ["q1", "q2", "q3"],
        doneNote: "Business reason, then location, then behavior: context, not the tool's mere presence, decides.",
      },
    ],

    // ── Reading 6: investigation playbook and containment ───────────────────
    "tunnel-r6": [
      {
        kind: "sequence",
        title: "Work the alert-led playbook",
        prompt: "An endpoint alert already names the process behind a suspicious long-lived link. Tap the investigation steps in the order the reading runs them.",
        items: [
          { id: "proc", text: "Read the process ancestry and full command line", note: "Fastest way to see -L/-R/-D and the exact args; network-only data cannot show it." },
          { id: "rep", text: "Check the destination's reputation and rarity", note: "First-seen in the whole environment, or used routinely for months?" },
          { id: "dur", text: "Look at connection duration and byte pattern", note: "Short and transactional, long-lived interactive, or beacon-shaped?" },
          { id: "meta", text: "Read the DNS and TLS metadata (SNI, JA4/JA4S, preceding DNS)", note: "The SNI or fingerprint, and whether the DNS itself is the channel." },
          { id: "corr", text: "Correlate with everything else on that host and account", note: "A phishing click, an odd auth, a dropped file in the same window." },
          { id: "verify", text: "Check for a documented legitimate explanation before escalating", note: "A change ticket or owner confirmation: confirmed, or escalate." },
        ],
        order: ["proc", "rep", "dur", "meta", "corr", "verify"],
        doneNote: "When the alert already names the process, you start at the endpoint; verifying with the owner is the last gate before you call it.",
      },
      {
        kind: "simulate",
        title: "Confirmed or escalate?",
        prompt: "You reach the verification step. Watch what each outcome means for the finding.",
        checks: [
          { name: "Documented reason?", question: "Is there a change ticket, approved deployment or owner confirmation?" },
        ],
        scenarios: [
          { id: "conf", label: "it_verify_result: confirmed", detail: "An owner confirms a documented, approved reason for the activity.", results: ["pass"], why: ["A legitimate explanation exists and is verifiable."], verdict: "Very likely a benign true positive: the rule caught real use, and the use is authorized. Not a false positive, since nothing misfired." },
          { id: "unv", label: "it_verify_result: unverified (no ticket)", detail: "No owner, ticket or approval can be found.", results: ["fail"], why: ["Nothing documents or authorizes the activity."], verdict: "Escalate and investigate as a real possibility. Do not dismiss it just because the tool is sometimes used legitimately." },
        ],
      },
      {
        kind: "sort",
        title: "First move on a confirmed channel",
        prompt: "A channel is confirmed malicious, with no active data loss right now. Sort each action by whether it belongs in the FIRST step or must wait.",
        buckets: [
          { id: "first", label: "Do first (preserve)" },
          { id: "later", label: "Comes later" },
        ],
        items: [
          { id: "mem", text: "Capture the host's memory and its live process and connection lists", bucket: "first", why: "Volatile evidence vanishes on a restart, so grab it while the implant still runs." },
          { id: "reboot", text: "Reboot or reimage the host to clear the implant", bucket: "later", why: "That destroys the in-memory evidence you need; eradication comes after preserve, scope and contain." },
          { id: "block", text: "Block the destination at the proxy, firewall and DNS", bucket: "later", why: "Part of containment, done together with isolating every confirmed host, not before preserving evidence." },
          { id: "notes", text: "Write the final incident record", bucket: "later", why: "Documentation is the last step, once the timeline and actions are complete." },
        ],
      },
    ],
  },
};
