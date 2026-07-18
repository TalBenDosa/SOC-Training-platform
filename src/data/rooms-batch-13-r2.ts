import type { TelemetryEvent } from "@/lib/sim/types";

const fwC2Event: TelemetryEvent = {
  id: "evt-fw-c2-001",
  ts: "2024-08-05T03:14:07.000Z",
  source: "firewall",
  vendor: "FortiGate 600F",
  event_type: "net_connection",
  severity: "high",
  hostname: "FGT-CORE-01",
  src_ip: "10.0.3.88",
  dst_ip: "185.220.101.47",
  dst_port: 443,
  protocol: "TCP",
  description:
    "Suspicious outbound HTTPS to Tor exit node - 60-second beacon interval, 15 consecutive connections",
  mitre_technique: "T1071.001",
  mitre_tactic: "Command and Control",
  raw: {
    "data.type": "traffic",
    "data.subtype": "forward",
    "data.logid": "0000000013",
    "data.level": "warning",
    "data.action": "accept",
    "data.srcip": "10.0.3.88",
    "data.srcport": "51247",
    "data.dstip": "185.220.101.47",
    "data.dstport": "443",
    "data.proto": "6",
    "data.app": "HTTPS",
    "data.duration": "7",
    "data.sentbyte": "1024",
    "data.rcvdbyte": "512",
    "data.sessionid": "2847391",
    "data.srccountry": "Reserved",
    "data.dstcountry": "Netherlands",
    "data.policyid": "15",
    "data.policyname": "outbound-web-allow",
    "data.logdesc": "Forward traffic accepted",
  },
};

const firewallMasterclass = {
  id: "firewall-masterclass",
  title: "Firewalls: From Packet Filter to NGFW",
  description:
    "Master firewalls from the ground up — stateless ACLs, stateful inspection, deep packet inspection, NGFW App-ID and User-ID, SSL inspection, rule-base design, and reading real FortiGate logs in your SIEM.",
  difficulty: "intermediate" as const,
  category: "Network Security",
  estimatedMinutes: 70,
  xp: 650,
  icon: "🔥",
  prerequisites: ["networking-protocols", "firewall-network-security"],
  tasks: [
    // ── Reading 1 ─────────────────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "fw-r1",
      heading: "What Is a Firewall? History and Purpose",
      content:
        `Think of a firewall as the bouncer standing at the entrance to an exclusive venue. The bouncer does not let everyone in — they check each person against a list of rules: "Are you on the guest list? Are you old enough? Are you carrying anything prohibited?" Anyone who passes all checks enters. Anyone who fails is turned away. A firewall does exactly this for network traffic: every packet that attempts to cross from one network segment to another is checked against a policy, and the firewall decides in milliseconds whether to allow, deny, or drop it.\n\n` +
        `**Why firewalls exist**\n\n` +
        `Before firewalls, networks were open by design. The early internet was built for academic research — trust was assumed, not enforced. When organizations began connecting to the internet in the late 1980s and early 1990s, attackers quickly discovered they could reach internal systems directly. There was nothing in the middle to stop them. A tool was needed to act as the controlled checkpoint between a trusted internal network and the untrusted outside world.\n\n` +
        `**The evolution through generations**\n\n` +
        `Firewall technology has evolved through four major generations, each driven by a new type of attack that the previous generation could not stop.\n\n` +
        `The first generation — packet filtering — appeared in 1988 when engineers at DEC (Digital Equipment Corporation) built the first packet-filter firewall. It inspected IP and TCP/UDP headers only: source IP, destination IP, source port, destination port, and protocol. Simple and fast, but it had no awareness of whether a packet belonged to a legitimate conversation.\n\n` +
        `The second generation — stateful inspection — arrived in 1993 when Check Point Software launched FireWall-1, the world's first commercially available stateful firewall. Instead of treating each packet in isolation, it tracked the state of every connection. A packet was only allowed through if it belonged to an established, legitimate session. This blocked a whole class of spoofing and session-hijacking attacks that had plagued packet filters.\n\n` +
        `The third generation — Unified Threat Management (UTM) — emerged in the early 2000s. Vendors began combining firewall capabilities with antivirus, intrusion prevention (IPS), VPN, and web filtering into a single appliance. UTM devices were popular in small to mid-size businesses because one box did many jobs, but performance suffered and application visibility was still limited.\n\n` +
        `The fourth generation — Next-Generation Firewalls (NGFW) — was pioneered by Palo Alto Networks in 2007. Nir Zuk, one of the inventors of stateful inspection at Check Point, founded Palo Alto with the explicit goal of building a firewall that could identify applications, users, and content regardless of port, protocol, or encryption. An NGFW can tell the difference between Facebook and Facebook Messenger and apply different policies to each — even though both travel over port 443.\n\n` +
        `Today, cloud-native NGFWs delivered as Software-as-a-Service extend these capabilities to hybrid and multi-cloud environments, inspecting traffic between cloud workloads the same way a physical appliance inspects traffic at a corporate perimeter.\n\n` +
        `**The fundamental principle that has never changed**\n\n` +
        `Despite four generations of evolution, every firewall in history operates on the same core principle: default deny. Traffic is blocked unless explicitly permitted. The bouncer does not ask "why should I turn you away?" — they ask "why should I let you in?" This principle, combined with the principle of least privilege (only allow what is strictly necessary), forms the bedrock of network security.`,
      codeExample:
        `FIREWALL GENERATION TIMELINE\n` +
        `════════════════════════════════════════════════════════════════\n` +
        `\n` +
        ` 1988          1993           2004            2007           2020+\n` +
        `  │              │              │               │              │\n` +
        `  ▼              ▼              ▼               ▼              ▼\n` +
        `┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐\n` +
        `│  PACKET  │  │STATEFUL  │  │   UTM    │  │  NGFW    │  │  CLOUD   │\n` +
        `│  FILTER  │─▶│INSPECTION│─▶│(Unified  │─▶│(Next-Gen │─▶│  NGFW   │\n` +
        `│  (DEC)   │  │(Check    │  │ Threat   │  │Firewall) │  │ (FWaaS) │\n` +
        `│          │  │ Point    │  │ Mgmt)    │  │(Palo     │  │         │\n` +
        `│          │  │FireWall-1│  │          │  │ Alto)    │  │         │\n` +
        `└──────────┘  └──────────┘  └──────────┘  └──────────┘  └──────────┘\n` +
        `\n` +
        ` Inspects:     Inspects:      Inspects:      Inspects:      Inspects:\n` +
        ` IP headers    Connection     L3/L4 +        L3/L4/L7       All above\n` +
        ` only          state          AV/IPS/VPN     App/User/      + east-west\n` +
        `               (5-tuple)      in one box     Content        cloud traffic\n` +
        `\n` +
        ` Blocked by:   Blocked by:    Blocked by:    Blocked by:    Blocked by:\n` +
        ` IP spoofing   App-layer      App tunneling  Certificate    API misuse\n` +
        ` Port tricks   attacks        over HTTP      pinning        in cloud\n` +
        `════════════════════════════════════════════════════════════════`,
    },

    // ── Reading 2 ─────────────────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "fw-r2",
      heading: "Generation 1: Stateless Packet Filtering and Access Control Lists",
      content:
        `Picture a nightclub with a bouncer who checks only a single rule printed on a laminated card: "Anyone over 18 from ZIP code 90210 can enter." The bouncer checks your ID — age and address — and lets you in or turns you away. They do not remember you from last time, they do not care what you did inside last week, and they certainly do not check what you are carrying. Each person is evaluated in complete isolation every time they approach the door.\n\n` +
        `This is exactly how a stateless packet filter works. It inspects each packet independently, looking only at the IP header fields: source IP address, destination IP address, IP protocol number (TCP=6, UDP=17, ICMP=1), source port, and destination port. Based on these fields alone, it applies a numbered list of rules called an Access Control List (ACL) and either permits or denies the packet.\n\n` +
        `**How ACL rules are evaluated**\n\n` +
        `ACL rules are evaluated top-to-bottom. The first rule that matches the packet wins — processing stops immediately and the action is taken. This is called first-match semantics. At the bottom of every ACL sits an implicit deny-all rule: any packet that matches no explicit rule is dropped. Rule order is therefore critical. A permit-all rule placed at the top of an ACL would render every rule below it irrelevant.\n\n` +
        `**What stateless filtering can and cannot see**\n\n` +
        `A packet filter CAN see: source and destination IP, source and destination port, protocol number, TCP flags (SYN, ACK, FIN, RST) in a basic sense. It CANNOT see: whether a packet belongs to an established connection, the application running over the connection, or anything in the payload (the actual data being transmitted).\n\n` +
        `**Why stateless filtering is still used today**\n\n` +
        `Despite its limitations, stateless packet filtering survives in modern networks for a simple reason: speed. ACL processing is extremely fast and can be offloaded to dedicated hardware (ASICs) on routers and switches. Edge routers frequently use ACLs to perform coarse-grained filtering — blocking obviously malicious IP ranges, restricting management access to specific source IPs, or rate-limiting ICMP — before traffic even reaches the firewall. This reduces load on more sophisticated (and more expensive) inspection engines downstream.\n\n` +
        `**Classic bypass techniques**\n\n` +
        `Because stateless filters trust only the header fields, attackers can abuse them in several ways. IP spoofing involves crafting packets with a forged source IP address. If a rule says "allow any traffic from 192.168.1.0/24," an attacker can set their source IP to 192.168.1.100 and the filter will pass the packet. Port manipulation is equally effective: many organizations configure ACLs to allow outbound traffic on port 53 (DNS) from any host. An attacker can configure their malware to send C2 traffic using source port 53, causing the filter to classify it as DNS and permit it. These weaknesses drove the development of stateful inspection.\n\n` +
        `**Reading ACL rules**\n\n` +
        `Cisco IOS syntax, still the most widely recognized format, follows the pattern: action, protocol, source, source-wildcard, destination, destination-wildcard, operator, port. Understanding this syntax lets you instantly evaluate whether a rule permits or blocks a given traffic flow — a skill tested regularly in incident investigations when you need to determine why a connection was allowed or denied.`,
      codeExample:
        `EXAMPLE CISCO IOS ACCESS CONTROL LIST (ACL)\n` +
        `════════════════════════════════════════════════════════════════\n` +
        `\n` +
        `ip access-list extended OUTBOUND-POLICY\n` +
        ` ! Rule 10: Allow DNS queries from internal subnet to any DNS server\n` +
        ` 10  permit udp 10.0.0.0 0.255.255.255 any eq 53\n` +
        `\n` +
        ` ! Rule 20: Allow HTTP from internal subnet to any web server\n` +
        ` 20  permit tcp 10.0.0.0 0.255.255.255 any eq 80\n` +
        `\n` +
        ` ! Rule 30: Allow HTTPS from internal subnet to any web server\n` +
        ` 30  permit tcp 10.0.0.0 0.255.255.255 any eq 443\n` +
        `\n` +
        ` ! Rule 40: Allow SMTP outbound from mail server only\n` +
        ` 40  permit tcp host 10.0.1.25 any eq 25\n` +
        `\n` +
        ` ! Rule 50: Block RFC1918 private IPs arriving on external interface\n` +
        ` 50  deny   ip 192.168.0.0 0.0.255.255 any\n` +
        ` 60  deny   ip 172.16.0.0  0.15.255.255 any\n` +
        ` 70  deny   ip 10.0.0.0    0.255.255.255 any\n` +
        `\n` +
        ` ! Rule 80: Block ICMP flooding (rate-limit not shown)\n` +
        ` 80  deny   icmp any any\n` +
        `\n` +
        ` ! Implicit: deny ip any any  <-- this exists even if not written!\n` +
        `\n` +
        `════════════════════════════════════════════════════════════════\n` +
        `BYPASS EXAMPLES AGAINST THIS ACL:\n` +
        `\n` +
        `  Attack: C2 malware sets source port = 53\n` +
        `  Packet: src=10.0.3.88:53 dst=185.220.101.47:4444 proto=UDP\n` +
        `  Result: Rule 10 MATCHES (udp from 10.x.x.x, source port=53)\n` +
        `  ---> PERMITTED  (stateless filter cannot distinguish real DNS)\n` +
        `\n` +
        `  Attack: Attacker spoofs IP 10.0.1.25 to relay through SMTP rule\n` +
        `  Packet: src=10.0.1.25 dst=attacker:25 proto=TCP\n` +
        `  Result: Rule 40 MATCHES (src host 10.0.1.25, dest port 25)\n` +
        `  ---> PERMITTED  (no way to verify the source IP is genuine)\n` +
        `════════════════════════════════════════════════════════════════`,
    },

    // ── Reading 3 ─────────────────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "fw-r3",
      heading: "Generation 2: Stateful Inspection and the Connection Tracking Revolution",
      content:
        `Imagine the same nightclub bouncer, but now they carry a clipboard. Every time someone enters, the bouncer writes down their name, the time they arrived, and the door they used. When someone tries to leave, the bouncer checks the clipboard: "Did this person actually come in earlier?" If the answer is no — if someone tries to walk out through the entrance without ever having checked in — they are stopped.\n\n` +
        `This is stateful inspection: the firewall maintains a memory of every active network connection and uses that memory to evaluate whether each incoming packet belongs to a legitimate conversation.\n\n` +
        `**The connection state table (also called conntrack)**\n\n` +
        `A stateful firewall maintains a connection state table in memory. Every active connection is tracked by its 5-tuple: source IP, destination IP, source port, destination port, and protocol. When a new connection attempt arrives (a TCP SYN packet), the firewall evaluates it against the policy rules. If it is permitted, an entry is created in the state table. All subsequent packets in that connection are matched against the state table — if they match an established entry, they are forwarded without re-evaluating the full rule base. This is faster than re-checking all rules for every packet, and far more secure.\n\n` +
        `**TCP state machine tracking**\n\n` +
        `For TCP connections, the stateful firewall tracks the full TCP handshake and connection lifecycle. A legitimate TCP connection progresses: SYN (client initiates) → SYN-ACK (server responds) → ACK (client confirms, connection ESTABLISHED) → data exchange → FIN/ACK exchange (graceful close). The firewall tracks which state each connection is in.\n\n` +
        `If an attacker sends a crafted SYN-ACK or RST packet to an internal host without a prior SYN having been recorded, the stateful firewall drops it immediately — there is no matching entry in the state table. This blocks SYN-ACK flooding, session hijacking attempts, and many port scanning techniques that rely on receiving packets that were never requested.\n\n` +
        `**Why stateful inspection was a revolution**\n\n` +
        `Before stateful inspection, administrators had to write explicit return-traffic rules in their ACLs. To allow internal users to browse the web, you needed a rule permitting outbound port 80 AND a second rule permitting inbound traffic on high ports (1024-65535) for the return traffic. This second rule was a gaping hole — any external attacker could send packets to internal high ports and the ACL would allow them. Stateful inspection eliminated this problem entirely. Return traffic is automatically permitted because it matches an existing state table entry. External-initiated traffic to internal hosts is blocked because there is no matching entry.\n\n` +
        `**What stateful inspection still cannot see**\n\n` +
        `The state table tells the firewall that a connection is legitimate. It does not tell the firewall what the connection is carrying. A stateful firewall cannot distinguish between a legitimate HTTPS session to a bank website and an HTTPS session carrying malware over port 443. It knows the connection was properly established via the TCP handshake and matches an allow rule — but the payload is opaque. This limitation drove the development of Deep Packet Inspection and the NGFW.`,
      codeExample:
        `CONNECTION STATE TABLE — EXAMPLE SNAPSHOT\n` +
        `════════════════════════════════════════════════════════════════\n` +
        `\n` +
        ` Proto  Src IP          Src Port  Dst IP          Dst Port  State\n` +
        ` ─────  ──────────────  ────────  ──────────────  ────────  ────────────\n` +
        ` TCP    10.0.1.55       54221     142.250.74.14   443       ESTABLISHED\n` +
        ` TCP    10.0.2.31       49103     52.96.67.21     443       ESTABLISHED\n` +
        ` TCP    10.0.1.25       58831     74.125.24.26    25        SYN_SENT\n` +
        ` UDP    10.0.3.88       51247     8.8.8.8         53        UNREPLIED\n` +
        ` TCP    10.0.4.12       60021     185.220.101.47  443       ESTABLISHED\n` +
        ` TCP    10.0.1.77       50801     10.0.5.10       3389      ESTABLISHED\n` +
        `\n` +
        `════════════════════════════════════════════════════════════════\n` +
        `HOW STATEFUL INSPECTION BLOCKS ATTACKS:\n` +
        `\n` +
        ` Scenario A — Unsolicited SYN-ACK from internet:\n` +
        `   Packet arrives: SYN-ACK from 203.0.113.55:80 to 10.0.1.99:51001\n` +
        `   State table lookup: No entry for 10.0.1.99:51001 <-> 203.0.113.55:80\n` +
        `   Action: DROP (no matching session — likely port scan or spoof)\n` +
        `\n` +
        ` Scenario B — RST injection attack:\n` +
        `   Packet arrives: RST from 203.0.113.55 targeting 10.0.1.55:54221\n` +
        `   State table lookup: Entry EXISTS but sequence number out of window\n` +
        `   Action: DROP (sequence number validation failed)\n` +
        `\n` +
        ` Scenario C — Legitimate return traffic:\n` +
        `   Packet arrives: ACK+data from 142.250.74.14:443 to 10.0.1.55:54221\n` +
        `   State table lookup: Entry EXISTS, state=ESTABLISHED, seq number OK\n` +
        `   Action: FORWARD (matched existing session, no rule re-evaluation)\n` +
        `════════════════════════════════════════════════════════════════`,
    },

    // ── Reading 4 ─────────────────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "fw-r4",
      heading: "Generation 3: Deep Packet Inspection and Application Awareness",
      content:
        `A stateful firewall is like a postal inspector who checks that every envelope has a valid return address and was properly stamped, but never opens the envelope to look inside. Deep Packet Inspection (DPI) is the postal inspector who opens the envelope, reads the letter, and decides based on the content whether it should be delivered or confiscated.\n\n` +
        `**What DPI inspects**\n\n` +
        `DPI does not stop at the IP and TCP/UDP headers (Layer 3 and Layer 4). It continues into the application layer (Layer 7) and parses the actual payload of the packet. This means a DPI engine can read HTTP headers and identify the URL being requested, parse DNS responses and detect malicious domain names in the answer section, identify Skype, BitTorrent, or custom protocols regardless of which port they use, and detect command-and-control traffic patterns embedded inside what appears to be normal web traffic.\n\n` +
        `**Why port-based policies are insufficient**\n\n` +
        `Modern malware and evasion tools routinely operate on unexpected ports or tunnel inside legitimate protocols. Skype once tunneled over port 443 (HTTPS) to evade corporate firewalls. BitTorrent clients dynamically select any available port. Remote access tools like TeamViewer and AnyDesk use port 443 to evade port-based blocking. Without DPI, a firewall that "allows port 443" is functionally allowing all of these applications. DPI can distinguish between genuine HTTPS web traffic and applications masquerading as HTTPS.\n\n` +
        `**Protocol anomaly detection**\n\n` +
        `DPI can also detect when a protocol is being misused. The HTTP specification defines a very specific format for requests and responses. Malware communicating over port 80 often does not perfectly conform to the HTTP specification — the user-agent string may be absent or malformed, request timing patterns may be robotic, or the content-type header may claim HTML but the body contains binary data. DPI engines compare observed protocol behavior against known-good protocol specifications and flag anomalies.\n\n` +
        `**Application firewall vs proxy firewall**\n\n` +
        `These terms are sometimes confused. An application-layer firewall (like an NGFW performing DPI) inspects traffic inline — it sits in the path and inspects every packet before forwarding. A proxy firewall acts as a full relay: the client connects to the proxy, the proxy establishes a separate connection to the server, and all traffic flows through the proxy as a man-in-the-middle. Proxy firewalls provide the deepest inspection but introduce latency and may break applications that do not support proxy configuration.\n\n` +
        `**The encryption problem**\n\n` +
        `DPI's biggest limitation is encryption. When traffic is encrypted with TLS (HTTPS), a DPI engine cannot read the payload without first decrypting it. Over 60% of internet traffic today is TLS-encrypted, and malware authors know to route their traffic over HTTPS specifically to evade DPI. This drove the development of SSL/TLS inspection, covered in detail in R8. Without SSL inspection, a DPI-capable NGFW is still partially blind to a large fraction of modern traffic.`,
      codeExample:
        `DPI INSPECTION STACK — WHAT GETS INSPECTED AT EACH LAYER\n` +
        `════════════════════════════════════════════════════════════════\n` +
        `\n` +
        ` Incoming Packet\n` +
        `       │\n` +
        `       ▼\n` +
        ` ┌─────────────────────────────────────────────────────────┐\n` +
        ` │  LAYER 3 — IP Header Inspection                        │\n` +
        ` │  Check: src IP, dst IP, TTL, IP options                │\n` +
        ` │  Detect: IP spoofing, fragmentation attacks            │\n` +
        ` └─────────────────────────┬───────────────────────────────┘\n` +
        `                           │\n` +
        `                           ▼\n` +
        ` ┌─────────────────────────────────────────────────────────┐\n` +
        ` │  LAYER 4 — TCP/UDP Header Inspection                   │\n` +
        ` │  Check: ports, flags, sequence numbers, state          │\n` +
        ` │  Detect: port scans, SYN floods, invalid flag combos   │\n` +
        ` └─────────────────────────┬───────────────────────────────┘\n` +
        `                           │\n` +
        `                           ▼\n` +
        ` ┌─────────────────────────────────────────────────────────┐\n` +
        ` │  LAYER 7 — Application Payload Inspection (DPI)        │\n` +
        ` │  Check: HTTP headers, URL, DNS query/response,         │\n` +
        ` │         TLS SNI, protocol conformance, signatures       │\n` +
        ` │  Detect: malware C2, tunneling, policy violations,     │\n` +
        ` │          protocol anomalies, known attack patterns      │\n` +
        ` └─────────────────────────┬───────────────────────────────┘\n` +
        `                           │\n` +
        `                           ▼\n` +
        ` ┌─────────────────────────────────────────────────────────┐\n` +
        ` │  CONTENT INSPECTION (IPS / AV / Sandbox)               │\n` +
        ` │  Check: file types, byte patterns, heuristics          │\n` +
        ` │  Detect: exploits, malware payloads, zero-days         │\n` +
        ` └─────────────────────────┬───────────────────────────────┘\n` +
        `                           │\n` +
        `                           ▼\n` +
        `                     PERMIT / DENY\n` +
        `\n` +
        `════════════════════════════════════════════════════════════════\n` +
        `EXAMPLE: DETECTING SKYPE TUNNELED OVER HTTPS\n` +
        `\n` +
        `  Stateless/Stateful sees:  TCP dst_port=443 --> PERMIT (HTTPS allowed)\n` +
        `  DPI additionally sees:\n` +
        `    - TLS SNI = lyncqosdiagnostics.skype.com\n` +
        `    - Certificate issuer = Microsoft (Skype)\n` +
        `    - Traffic signature matches Skype protocol\n` +
        `    - Application identified = Skype\n` +
        `  Policy action: DENY (Skype blocked per corporate policy)\n` +
        `════════════════════════════════════════════════════════════════`,
    },

    // ── Reading 5 ─────────────────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "fw-r5",
      heading: "Next-Generation Firewalls: What NGFW Actually Means",
      content:
        `In 2007, Palo Alto Networks published a research paper and began selling what they called the "next-generation firewall." The term was more than marketing — it described a fundamentally different philosophy: instead of asking "what port is this traffic on?" an NGFW asks "what application is this, who is the user running it, and what content does it contain?" This shift from port-based to identity-based policy is the defining characteristic of a true NGFW.\n\n` +
        `**App-ID: Application identification regardless of port**\n\n` +
        `App-ID is Palo Alto's term for deep application identification. It uses a combination of application signatures, behavioral analysis, and protocol decoding to identify what application is running — regardless of which port or protocol it uses. The practical implication is enormous: a traditional firewall that "allows port 443" permits all HTTPS traffic. An NGFW using App-ID can distinguish between Google Workspace, Salesforce, Dropbox, a corporate VPN over HTTPS, and a malware C2 framework all running over the same port 443. You can write a policy that says "allow Google Workspace, block Dropbox, inspect and allow the VPN, and block everything else on port 443 that cannot be identified."\n\n` +
        `**User-ID: Tying traffic to identities, not just IP addresses**\n\n` +
        `IP addresses are assigned to machines, not people. In a dynamic environment with DHCP, VDI (Virtual Desktop Infrastructure), and shared workstations, the same IP address may be used by different employees throughout the day. User-ID solves this by integrating with Active Directory or other identity providers to map each IP address to the logged-in user in real time. This enables user-based policy: "Allow the Finance department to access Bloomberg, block P2P applications for everyone except the IT team, restrict social media during business hours for all users in the Sales group." Policies follow the person, not the machine.\n\n` +
        `**Content-ID: Inspecting what is inside the traffic**\n\n` +
        `Content-ID is the umbrella term for multiple inspection engines operating on traffic after the application has been identified. It includes: an Intrusion Prevention System (IPS) that detects and blocks exploit attempts against known CVEs; an antivirus engine that scans files in transit for malware signatures; URL filtering that categorizes and blocks web destinations by category (malware, phishing, adult content, gambling); file type control that can block specific file types (e.g., block .exe and .bat downloads); and data pattern matching that can detect sensitive data like credit card numbers or social security numbers leaving the organization.\n\n` +
        `**Additional NGFW capabilities**\n\n` +
        `Modern NGFWs from leading vendors include SSL/TLS inspection (the firewall decrypts, inspects, and re-encrypts HTTPS traffic), cloud-based sandboxing that detonates suspicious files in an isolated environment before permitting them through, and machine-learning threat intelligence that receives updated threat indicators every few minutes from the vendor's global sensor network. Palo Alto's WildFire, Fortinet's FortiSandbox, and Check Point's SandBlast are the major commercial implementations.\n\n` +
        `**The SOC analyst's perspective**\n\n` +
        `From a SOC standpoint, an NGFW dramatically enriches the logs available for investigation. Instead of seeing "TCP from 10.0.3.88 to 185.220.101.47 on port 443 — ALLOW," you see "Application: ssl-tunnel, User: mike.jones@corp.com, Category: unknown, Threat: Malware C2, Action: BLOCK." This contextual richness is what enables the correlation queries and behavioral detections that distinguish a mature SOC from one simply watching port numbers.`,
      codeExample:
        `FEATURE COMPARISON: TRADITIONAL FW vs UTM vs NGFW\n` +
        `════════════════════════════════════════════════════════════════\n` +
        `\n` +
        ` Feature                      │ Traditional FW │   UTM    │   NGFW   │\n` +
        ` ─────────────────────────────┼────────────────┼──────────┼──────────┤\n` +
        ` Stateful inspection          │      YES       │   YES    │   YES    │\n` +
        ` Port/protocol policy         │      YES       │   YES    │   YES    │\n` +
        ` Application identification   │       NO       │ PARTIAL  │   YES    │\n` +
        ` User-based policy            │       NO       │    NO    │   YES    │\n` +
        ` Built-in IPS                 │       NO       │   YES    │   YES    │\n` +
        ` Built-in AV (gateway)        │       NO       │   YES    │   YES    │\n` +
        ` URL filtering                │       NO       │   YES    │   YES    │\n` +
        ` SSL/TLS inspection           │       NO       │ PARTIAL  │   YES    │\n` +
        ` Cloud sandbox integration    │       NO       │    NO    │   YES    │\n` +
        ` ML threat intelligence       │       NO       │    NO    │   YES    │\n` +
        ` Single-pass architecture     │       NO       │    NO    │   YES    │\n` +
        ` App-level granularity        │       NO       │    NO    │   YES    │\n` +
        `                              │                │          │          │\n` +
        ` Can distinguish:             │                │          │          │\n` +
        `  Facebook vs FB Messenger    │       NO       │    NO    │   YES    │\n` +
        `  Google Drive vs Box.com     │       NO       │ PARTIAL  │   YES    │\n` +
        `  YouTube vs Netflix          │       NO       │ PARTIAL  │   YES    │\n` +
        `  Legitimate SSL vs C2 HTTPS  │       NO       │    NO    │   YES*   │\n` +
        `                              │                │          │ (*+SSL   │\n` +
        `                              │                │          │ inspect) │\n` +
        `════════════════════════════════════════════════════════════════\n` +
        `\n` +
        `PALO ALTO App-ID EXAMPLE POLICY:\n` +
        `\n` +
        `  Rule: "Allow-Office365-Block-Dropbox"\n` +
        `  From: Trust    To: Untrust\n` +
        `  Application: office365, google-workspace    Action: ALLOW\n` +
        `  Application: dropbox, box, onedrive-personal Action: BLOCK\n` +
        `  Application: ssl, web-browsing (unidentified) Action: INSPECT\n` +
        `\n` +
        `  All three rules match traffic on port 443.\n` +
        `  Traditional FW would allow all of them with one "permit tcp any eq 443".\n` +
        `════════════════════════════════════════════════════════════════`,
    },

    // ── Reading 6 ─────────────────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "fw-r6",
      heading: "How Firewall Rules Work: Building and Reading a Rule Base",
      content:
        `Every firewall is only as good as its rule base. A misconfigured rule base is more dangerous than having no firewall at all, because it creates a false sense of security while leaving real gaps. Understanding how to read, write, and audit firewall rules is one of the most practically valuable skills in network security.\n\n` +
        `**Anatomy of a firewall rule**\n\n` +
        `Every rule in a modern NGFW policy consists of: Name (human-readable identifier), Source Zone (where the traffic originates), Destination Zone (where the traffic is headed), Source Address (individual IP, subnet, or address group), Destination Address, Application (for NGFW) or Service/Port (for traditional FW), Action (allow, deny, drop, or inspect), and Log setting (log all, log at session start, log at session end, no log).\n\n` +
        `The distinction between deny and drop is important. Deny sends a TCP RST or ICMP Unreachable back to the sender — the client knows the connection was refused. Drop silently discards the packet with no response. Drop is generally preferred for inbound traffic from untrusted sources because it provides no information to attackers performing reconnaissance.\n\n` +
        `**First-match wins — order is everything**\n\n` +
        `Rules are evaluated top-to-bottom. The moment a packet matches a rule, the action is taken and evaluation stops — no further rules are checked. This means the most specific rules must come before the most general ones. A common mistake is placing a broad "allow all" rule above more specific deny rules, effectively making those deny rules unreachable. This is called a shadow rule — a rule that can never be triggered because an earlier rule always matches first.\n\n` +
        `**The implicit deny-all**\n\n` +
        `At the bottom of every firewall rule base is an invisible implicit deny rule: "deny all from any to any." Any traffic that does not match an explicit permit rule is silently dropped. This is the fundamental default-deny posture of every firewall. Many organizations make this rule explicit and log it — the implicit-deny log is valuable for detecting scanning activity, misconfigured applications, and policy gaps.\n\n` +
        `**Best practices for rule base hygiene**\n\n` +
        `A well-maintained rule base follows several principles. Most specific rules come first: a rule allowing one specific host takes precedence over a rule allowing a whole subnet. Rules should have justification comments or ticket numbers explaining why they exist. Every rule should log at minimum at session end, with critical deny rules logging immediately. Unused rules should be audited and removed quarterly — firewall rules accumulate over years and become security debt. Overly broad rules like "allow TCP any any" should be replaced with specific application or port restrictions. Rules referencing decommissioned servers or expired projects are particularly dangerous because they may create unexpected access paths that no one monitors.\n\n` +
        `**Reading a rule in an investigation**\n\n` +
        `As a SOC analyst, you will frequently need to look up why a connection was allowed or denied. Find the policyname or rule_name field in the firewall log. Pull the policy configuration and read the rule. Ask: Is this rule intentionally broad? Is the destination address group maintained? Is the application or port restriction appropriate? Does this rule have logging enabled? The answers to these questions frequently reveal either a misconfiguration or a legitimate business need you were not aware of.`,
      codeExample:
        `REALISTIC 10-RULE FORTIGATE POLICY WITH ANALYSIS\n` +
        `════════════════════════════════════════════════════════════════\n` +
        `\n` +
        ` #   Name                    From      To        Src         Dst           App/Svc      Action  Log\n` +
        ` ─── ─────────────────────── ──────── ──────── ─────────── ───────────── ─────────── ─────── ────\n` +
        ` 1   MGMT-ADMIN-ACCESS       MGMT     CORE     10.1.1.0/24 Firewalls     SSH,HTTPS   ALLOW   YES\n` +
        ` 2   DC-REPLICATION          TRUST    TRUST    DomainCtrl  DomainCtrl    LDAP,DNS    ALLOW   YES\n` +
        ` 3   OUTBOUND-O365           TRUST    UNTRUST  10.0.0.0/8  Office365-IPs HTTPS,SMTP  ALLOW   YES\n` +
        ` 4   OUTBOUND-WEB            TRUST    UNTRUST  10.0.0.0/8  any           HTTPS,HTTP  ALLOW   YES\n` +
        ` 5   OUTBOUND-DNS            TRUST    UNTRUST  10.0.0.0/8  8.8.8.8       DNS         ALLOW   YES\n` +
        ` 6   DMZ-TO-DB               DMZ      TRUST    WebServers  DB-Servers    MySQL,MSSQL ALLOW   YES\n` +
        ` 7   INBOUND-WEB-PUBLIC      UNTRUST  DMZ      any         DMZ-VIP       HTTPS,HTTP  ALLOW   YES\n` +
        ` 8   BLOCK-TOR-IPS           any      any      TOR-Exit-IPs any          any         DENY    YES\n` +
        ` 9   BLOCK-KNOWN-BAD         any      any      Threat-Intel-Feed any     any         DENY    YES\n` +
        ` 10  IMPLICIT-DENY-LOG       any      any      any         any           any         DENY    YES\n` +
        `\n` +
        `ANALYSIS:\n` +
        `  Rule 1 before Rule 4: Admin SSH is more specific than outbound web.\n` +
        `  Rule 3 before Rule 4: O365 allowed broadly; Rule 4 is the catch-all HTTPS.\n` +
        `  Rules 8+9 are SHADOW risks if placed AFTER Rule 4 -- Rule 4 would match first!\n` +
        `  CORRECT ORDER: Block rules (8,9) should be ABOVE broad allow rules (4)!\n` +
        `\n` +
        `  SHADOW RULE EXAMPLE (BUG):\n` +
        `    Rule 4 "allow any to any HTTPS" placed above Rule 8 "deny TOR-Exit-IPs"\n` +
        `    --> All TOR traffic PASSES via Rule 4, Rule 8 is never evaluated!\n` +
        `    --> Fix: Move deny rules to top, or use threat intel as address objects\n` +
        `       in the destination of Rule 4 with negation.\n` +
        `════════════════════════════════════════════════════════════════`,
    },

    // ── Reading 7 ─────────────────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "fw-r7",
      heading: "Network Zones and DMZ Architecture",
      content:
        `Think of a modern hospital. There are clearly different areas with different access levels: the public waiting room anyone can enter, the clinical offices where only credentialed staff are admitted, and the operating theaters that require both credentials and explicit scheduling. The hospital does not rely on a single door to separate all of these areas — it uses a layered architecture of access controls. Network security zones work on the same principle.\n\n` +
        `**What is a security zone?**\n\n` +
        `A security zone is a logical grouping of network interfaces, VLANs, or subnets that share the same trust level and are subject to the same security policy. Instead of writing rules between every pair of individual IP addresses, you write rules between zones. All hosts inside the Trust zone can communicate with each other freely; any traffic crossing a zone boundary is inspected and subject to policy.\n\n` +
        `**Common zone types**\n\n` +
        `The Untrust zone represents the internet — completely untrusted, assumed hostile. No traffic from Untrust to Trust is ever permitted without explicit rules. The Trust zone is the internal corporate network — employees, servers, printers, all infrastructure that the organization owns and controls. The management zone (also called the MGMT zone) isolates firewall management interfaces so that administrative access to the firewall itself is only possible from a dedicated management network, not from the general corporate network. The guest zone isolates visitor Wi-Fi from the corporate network. The DMZ — Demilitarized Zone — deserves its own discussion.\n\n` +
        `**The DMZ: Why it exists**\n\n` +
        `Some servers must be reachable from the internet. A public web server, an externally accessible email server, a partner-facing API gateway — these all require inbound connections from untrusted sources. You cannot put them in the Trust zone because then a compromised web server would have unfettered internal network access. You cannot put them in the Untrust zone because they need to communicate with internal databases and directory services. The DMZ is the answer: a semi-trusted zone between Untrust and Trust.\n\n` +
        `The DMZ zone policy follows a strict traffic matrix. Untrust to DMZ: allow only the specific ports needed for the service (HTTP, HTTPS, port 25 for SMTP). DMZ to Trust: allow only the minimum necessary internal access (the web server needs port 3306 to reach the database — allow only that, from only the web server IP, to only the database server IP). DMZ to Untrust: allow only outbound connections explicitly needed (software updates, license checks). Trust to DMZ: allow administrative access for maintenance. Any violation of this matrix — such as the web server initiating arbitrary outbound connections to the internet — is a red flag indicating compromise.\n\n` +
        `**Dual-firewall DMZ**\n\n` +
        `For higher-security environments, a dual-firewall DMZ places two separate firewall appliances (ideally from different vendors) in series, with the DMZ sitting between them. The external firewall (internet-facing) handles Untrust-to-DMZ traffic. The internal firewall handles DMZ-to-Trust traffic. Even if an attacker fully compromises the external firewall and pivots through the DMZ, they face a completely separate security control before reaching the Trust zone. The dual-vendor approach ensures that a zero-day vulnerability in one firewall platform does not render both ineffective simultaneously.`,
      codeExample:
        `NETWORK ZONE TOPOLOGY — ASCII DIAGRAM\n` +
        `════════════════════════════════════════════════════════════════\n` +
        `\n` +
        `   INTERNET (UNTRUST)\n` +
        `        │\n` +
        `        │  Any inbound traffic\n` +
        `        ▼\n` +
        ` ┌─────────────────┐\n` +
        ` │  EXTERNAL FW    │  (e.g., Palo Alto PA-5450)\n` +
        ` │  Untrust ──► DMZ│  Policy: allow HTTP/HTTPS to web servers\n` +
        ` └────────┬────────┘         allow SMTP to mail server\n` +
        `          │                  deny everything else\n` +
        `          ▼\n` +
        ` ╔═══════════════════════════════════════════════╗\n` +
        ` ║              DMZ ZONE                        ║\n` +
        ` ║  ┌──────────┐  ┌──────────┐  ┌──────────┐  ║\n` +
        ` ║  │ Web      │  │  Mail    │  │   API    │  ║\n` +
        ` ║  │ Server   │  │  Server  │  │ Gateway  │  ║\n` +
        ` ║  │10.200.1.1│  │10.200.1.2│  │10.200.1.3│  ║\n` +
        ` ║  └──────────┘  └──────────┘  └──────────┘  ║\n` +
        ` ╚═══════════════════════════════════════════════╝\n` +
        `          │\n` +
        ` ┌────────┴────────┐\n` +
        ` │  INTERNAL FW    │  (e.g., FortiGate 600F — different vendor!)\n` +
        ` │  DMZ ──► Trust  │  Policy: allow MySQL 3306 from 10.200.1.1\n` +
        ` └────────┬────────┘           to DB server 10.0.5.10 ONLY\n` +
        `          │                  deny all other DMZ-to-Trust traffic\n` +
        `          ▼\n` +
        ` ╔═══════════════════════════════════════════════╗\n` +
        ` ║           TRUST ZONE (Internal)              ║\n` +
        ` ║  ┌──────────┐  ┌──────────┐  ┌──────────┐  ║\n` +
        ` ║  │ DB       │  │  Corp AD │  │  Finance │  ║\n` +
        ` ║  │ Server   │  │  DC01    │  │  Servers │  ║\n` +
        ` ║  │10.0.5.10 │  │10.0.1.10 │  │10.0.2.0/2│  ║\n` +
        ` ║  └──────────┘  └──────────┘  └──────────┘  ║\n` +
        ` ╚═══════════════════════════════════════════════╝\n` +
        `\n` +
        `INTER-ZONE TRAFFIC MATRIX:\n` +
        ` Source Zone    → Dest Zone   │ Permitted Traffic\n` +
        ` ───────────────────────────────────────────────────\n` +
        ` UNTRUST        → DMZ         │ TCP 80, 443, 25 (to specific IPs)\n` +
        ` DMZ            → TRUST       │ TCP 3306 (web→db ONLY), TCP 389 (mail→AD)\n` +
        ` TRUST          → UNTRUST     │ HTTP, HTTPS, DNS outbound\n` +
        ` TRUST          → DMZ         │ SSH/RDP (admin access, restricted IPs)\n` +
        ` DMZ            → UNTRUST     │ HTTPS for updates (specific IPs)\n` +
        ` UNTRUST        → TRUST       │ DENY ALL (blocked at external FW)\n` +
        `════════════════════════════════════════════════════════════════`,
    },

    // ── Reading 8 ─────────────────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "fw-r8",
      heading: "SSL/TLS Inspection: Breaking Encryption to See Inside",
      content:
        `Imagine you are a customs inspector at a border crossing. Your job is to check every package for contraband. But suddenly, half of all packages arrive inside locked metal boxes — legally locked, with valid seals. Without the ability to open those boxes, you are effectively blind to whatever they contain. SSL/TLS inspection (also called SSL decryption, HTTPS inspection, or TLS interception) is the mechanism that gives the firewall the ability to open those locked boxes.\n\n` +
        `**Why SSL inspection matters today**\n\n` +
        `In 2010, roughly 20% of web traffic was encrypted. In 2025, the figure exceeds 85%. Malware authors know this. Modern malware almost universally communicates with C2 infrastructure over HTTPS specifically to evade inspection. Without SSL inspection, a firewall's IPS, AV, URL filtering, and DLP engines are entirely blind to the majority of network traffic. An NGFW without SSL inspection enabled is, in practice, a very expensive stateful firewall for most internet traffic.\n\n` +
        `**How SSL inspection works**\n\n` +
        `SSL inspection works by placing the firewall as a trusted man-in-the-middle. When an internal client initiates an HTTPS connection to, say, a web server, the firewall intercepts it and establishes two separate TLS sessions: one between the client and the firewall, and one between the firewall and the actual server. The firewall decrypts the traffic from the server, inspects the plaintext payload with all its security engines, then re-encrypts it and sends it to the client.\n\n` +
        `For the client to trust the firewall's certificate, the organization must deploy a corporate Certificate Authority (CA) certificate to all managed endpoints. This is typically done via Group Policy Object (GPO) for Windows environments. Endpoints configured with the corporate CA certificate will trust the firewall-issued certificates without generating browser warnings. Unmanaged devices (personal phones, contractor laptops) will see certificate warnings because they do not have the corporate CA installed.\n\n` +
        `**What the firewall can now see**\n\n` +
        `With SSL inspection enabled, all security engines have full visibility into previously encrypted traffic. The IPS can detect exploit code in encrypted downloads. The AV engine can scan files transferred via HTTPS. The URL filter can see the exact URL (not just the domain). DLP policies can match credit card numbers or intellectual property in data uploads. C2 traffic that hides inside HTTPS is fully visible and can be identified by content signatures, behavioral patterns, or threat intelligence matches.\n\n` +
        `**What bypasses SSL inspection: Certificate pinning**\n\n` +
        `Some applications embed a specific certificate fingerprint in their code and refuse to connect if they receive any other certificate — including the firewall's substitute certificate. This is called certificate pinning, and it is used by applications like WhatsApp, many banking apps, and Microsoft applications like Teams and Outlook (which use a specific bypass mechanism). When SSL inspection is enabled, these applications will fail to connect. Administrators must create SSL inspection bypass rules for pinned applications, which means those applications' traffic remains uninspected. Attackers who can get their C2 client to use certificate pinning can potentially bypass SSL inspection at organizations that have not anticipated this.\n\n` +
        `**Privacy and legal considerations**\n\n` +
        `SSL inspection means the firewall decrypts employees' personal HTTPS traffic — banking sessions, medical portals, personal email. This creates legal and ethical obligations. Most organizations implement SSL bypass categories: traffic to banking, healthcare, legal, and personal categories is exempted from SSL inspection. Employees must be informed via acceptable use policies that work traffic may be inspected. Some jurisdictions have specific legal requirements around SSL inspection disclosure.`,
      codeExample:
        `SSL INSPECTION — MAN-IN-THE-MIDDLE FLOW\n` +
        `════════════════════════════════════════════════════════════════\n` +
        `\n` +
        ` WITHOUT SSL INSPECTION:\n` +
        ` Client ─────[encrypted TLS]───────────────────► Server\n` +
        `                                Firewall can only see:\n` +
        `                                - TLS SNI (server name)\n` +
        `                                - Destination IP and port\n` +
        `                                - Certificate subject (sometimes)\n` +
        `                                - Traffic volume and timing\n` +
        `\n` +
        ` WITH SSL INSPECTION:\n` +
        `\n` +
        `  Step 1: Client sends TLS ClientHello to firewall\n` +
        `  Step 2: Firewall connects to real server, establishes Session A\n` +
        `  Step 3: Firewall issues its own certificate signed by Corp CA\n` +
        `  Step 4: Client completes TLS handshake with firewall (Session B)\n` +
        `  Step 5: Firewall decrypts Session B, re-encrypts for Session A\n` +
        `\n` +
        ` Client ──[TLS Session B]──► FIREWALL ──[TLS Session A]──► Server\n` +
        `                                │\n` +
        `                                │ DECRYPTED PLAINTEXT\n` +
        `                                ▼\n` +
        `                         ┌─────────────┐\n` +
        `                         │  IPS Engine │ ◄─ Detects exploits\n` +
        `                         │  AV Engine  │ ◄─ Scans files\n` +
        `                         │  URL Filter │ ◄─ Checks full URL\n` +
        `                         │  DLP Engine │ ◄─ Matches data patterns\n` +
        `                         │  C2 Detect  │ ◄─ Identifies C2 traffic\n` +
        `                         └─────────────┘\n` +
        `\n` +
        `════════════════════════════════════════════════════════════════\n` +
        `CERTIFICATE PINNING BYPASS (APPLICATIONS THAT BREAK SSL INSPECT):\n` +
        `\n` +
        ` Application         Pinning   SSL Inspect Action\n` +
        ` ──────────────────  ────────  ───────────────────────────────\n` +
        ` Google Chrome       NO        Inspected normally\n` +
        ` Microsoft Edge      NO        Inspected normally\n` +
        ` WhatsApp            YES       Must be bypassed (fails to connect)\n` +
        ` Banking apps        YES       Must be bypassed (compliance risk)\n` +
        ` MS Teams            PARTIAL   Bypass via MS-specific URL categories\n` +
        ` Zoom                NO        Can be inspected\n` +
        ` Most malware C2     NO        Inspected and blocked\n` +
        ` Advanced C2 (rare)  YES       May bypass inspection\n` +
        `\n` +
        `BYPASS CATEGORIES (configure in SSL inspection profile):\n` +
        ` - Financial Services (banking, trading platforms)\n` +
        ` - Health & Medicine (medical portals)\n` +
        ` - Certificate-pinned applications (whitelist by CN or fingerprint)\n` +
        `════════════════════════════════════════════════════════════════`,
    },

    // ── Reading 9 ─────────────────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "fw-r9",
      heading: "Palo Alto vs FortiGate vs Check Point: Market Leaders Compared",
      content:
        `The enterprise firewall market is dominated by three vendors: Palo Alto Networks, Fortinet (FortiGate), and Check Point. Each has a distinct philosophy, a distinct target customer, and distinct strengths and weaknesses. As a SOC analyst, you will encounter all three — understanding their architectures helps you interpret their logs, understand their detection capabilities, and advise on security posture gaps.\n\n` +
        `**Palo Alto Networks**\n\n` +
        `Palo Alto invented the NGFW category in 2007 and has spent the years since building the industry's most mature application and user identification capabilities. Their flagship product line runs PAN-OS, which introduces a single-pass parallel processing architecture: traffic is only scanned once for all engines simultaneously, avoiding the performance penalty of chaining multiple inspection modules in sequence. App-ID and User-ID remain the most granular in the market. WildFire is their cloud sandbox, analyzing suspicious files in seconds. ML-Powered NGFW (introduced in PAN-OS 10.0) uses machine learning to identify new applications and novel threats without requiring signature updates. Panorama provides centralized management for multi-firewall deployments. Palo Alto's primary weakness is cost: they are among the most expensive firewalls in both purchase and annual subscription fees.\n\n` +
        `**Fortinet FortiGate**\n\n` +
        `Fortinet's philosophy is the Security Fabric: a tightly integrated ecosystem of Fortinet products (FortiGate, FortiAnalyzer, FortiManager, FortiEDR, FortiSIEM, FortiClient) that all share threat intelligence and management planes. FortiGate's primary differentiator is performance. Fortinet designs its own custom ASICs (SPU — Security Processing Unit chips) that offload firewall and VPN processing from the general-purpose CPU, delivering throughputs measured in hundreds of gigabits per second even with full inspection enabled. This makes FortiGate attractive for environments where performance at scale is critical — large campuses, data centers, service providers. FortiOS is extremely feature-rich and is updated aggressively. FortiGate is also the best price-to-performance option in the market, spanning from very small offices (FortiGate 40F) to the hyperscale FortiGate 7000 series. The main criticism is that the breadth of features can make configuration complex, and the tight integration with Fortinet's ecosystem makes it less attractive if you already standardize on a competitor's endpoint or SIEM solution.\n\n` +
        `**Check Point Software Technologies**\n\n` +
        `Check Point is the oldest player in the commercial firewall market, having invented stateful inspection in 1993 with FireWall-1. Their current platform (R81.20 as of 2024) runs on the Gaia operating system. Check Point's hallmarks are a mature, stable GUI (SmartConsole), robust high-availability clustering (ClusterXL), and a policy architecture that scales to thousands of rules in complex enterprise environments. Check Point's Software Blade architecture lets customers license individual capabilities (IPS, AV, URL filtering, sandboxing) as needed. Their primary weakness is that innovation pace has been slower than Palo Alto and Fortinet, and the learning curve for SmartConsole can be steep for administrators new to the platform.\n\n` +
        `**Cisco**\n\n` +
        `Cisco's firewall line merged legacy ASA (stateful firewall, acquired from network router heritage) with SourceFire (best-in-class IPS, acquired in 2013) to create Firepower Threat Defense (FTD). The integration has been historically uneven — ASA and SourceFire were architecturally different products combined administratively but not always elegantly. Cisco is a strong choice in environments heavily standardized on Cisco networking, where the integration with Cisco ISE (identity services) and Cisco Umbrella (DNS security) is seamless.`,
      codeExample:
        `MARKET LEADER COMPARISON TABLE\n` +
        `════════════════════════════════════════════════════════════════\n` +
        `\n` +
        ` Vendor        │ Best For            │ Key Feature        │ Management     │ Weakness\n` +
        ` ──────────────┼─────────────────────┼────────────────────┼────────────────┼──────────────────\n` +
        ` Palo Alto     │ Enterprise requiring│ App-ID + User-ID   │ Panorama       │ High cost;\n` +
        ` Networks      │ best-in-class app   │ (most granular     │ (centralized,  │ expensive\n` +
        `               │ identification and  │ app/user policy)   │ GUI + API)     │ subscription\n` +
        `               │ threat intelligence │ WildFire sandbox   │                │ model\n` +
        `               │                     │ ML-Powered NGFW    │                │\n` +
        ` ──────────────┼─────────────────────┼────────────────────┼────────────────┼──────────────────\n` +
        ` Fortinet      │ Performance-         │ Custom ASIC chips  │ FortiManager + │ Complex config;\n` +
        ` FortiGate     │ sensitive networks; │ (SPU) for maximum  │ FortiAnalyzer  │ best within\n` +
        `               │ best price/perf;    │ throughput at full │ (SIEM + log)   │ Fortinet fabric;\n` +
        `               │ SMB to enterprise   │ inspection;        │                │ less ecosystem\n` +
        `               │                     │ Security Fabric     │                │ neutral\n` +
        ` ──────────────┼─────────────────────┼────────────────────┼────────────────┼──────────────────\n` +
        ` Check Point   │ Large complex       │ ClusterXL HA;      │ SmartConsole   │ Slower\n` +
        ` Software      │ enterprise with     │ Software Blade     │ (mature GUI)   │ innovation;\n` +
        `               │ mature policy and   │ architecture;      │                │ steep learning\n` +
        `               │ stability needs     │ deep rule-base mgmt│                │ curve\n` +
        ` ──────────────┼─────────────────────┼────────────────────┼────────────────┼──────────────────\n` +
        ` Cisco         │ Cisco-standardized  │ SourceFire IPS     │ Firepower      │ Historically\n` +
        ` Firepower     │ environments; ISE   │ integration; Cisco │ Management     │ uneven ASA+FTD\n` +
        `               │ + Umbrella users    │ ecosystem synergy  │ Center (FMC)   │ integration\n` +
        `\n` +
        `════════════════════════════════════════════════════════════════\n` +
        `LOG FORMAT IDENTIFIER — how to tell which firewall generated a log:\n` +
        `\n` +
        ` FortiGate:    data.type="traffic"  data.subtype="forward"  data.logid="0000000013"\n` +
        ` Palo Alto:    pan.app="ssl"  pan.rule="outbound-https"  pan.action="allow"\n` +
        ` Check Point:  cp.blade="Firewall"  inzone="Internal"  outzone="External"\n` +
        ` Cisco ASA:    %ASA-6-302013: Built inbound TCP connection\n` +
        `════════════════════════════════════════════════════════════════`,
    },

    // ── Reading 10 ────────────────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "fw-r10",
      heading: "Reading Firewall Logs in Your SIEM: Field-by-Field Analysis",
      content:
        `A firewall log is the most fundamental data source in network security. Every connection that crosses a firewall boundary generates a log record. Knowing how to read these records field by field — and knowing what patterns to look for — is a foundational SOC skill. Different vendors structure their logs differently, but the underlying information is consistent.\n\n` +
        `**FortiGate log fields — the most commonly encountered format**\n\n` +
        `FortiGate logs arrive in your SIEM with fields prefixed by "data." to indicate they are native FortiGate log fields. The most important are: data.type (the log category — "traffic" for connection logs, "threat" for IPS/AV detections, "event" for administrative events), data.subtype (for traffic logs: "forward" for transit traffic, "local" for traffic destined to the firewall itself), data.action (the firewall decision: "accept" means the traffic was permitted, "deny" means it was blocked by policy, "drop" means it was silently discarded), data.srcip and data.dstip (the source and destination IP addresses), data.dstport (destination port number), data.proto (IP protocol number: 6=TCP, 17=UDP, 1=ICMP), data.app (the identified application, such as "HTTPS", "DNS", "SMB"), data.sentbyte (bytes sent by the source, i.e., the client), data.rcvdbyte (bytes received by the source, i.e., sent by the server back to the client), data.duration (connection duration in seconds), data.policyname (the name of the matching firewall rule), and data.dstcountry (the geographic location of the destination IP, useful for identifying unusual destinations).\n\n` +
        `**Palo Alto Networks log fields**\n\n` +
        `Palo Alto logs use a pan. prefix for proprietary fields. Pan.app identifies the application (e.g., "web-browsing", "ssl", "smtp"), pan.rule is the matching rule name, pan.action is the enforcement action, and pan.bytes_sent and pan.bytes_received are traffic volume fields. Palo Alto also includes the URL category and threat name when applicable.\n\n` +
        `**What to hunt for in firewall logs**\n\n` +
        `High bytes sent to an external IP: large data.sentbyte values to unfamiliar destinations suggest data exfiltration. A 500MB upload to an IP in an unexpected country warrants immediate investigation. Periodic connections at fixed intervals: connections from the same internal IP to the same external IP at consistent time intervals (e.g., every 60 seconds) with small, consistent byte counts are textbook C2 beaconing. The interval regularity is the key indicator — real user behavior does not produce machine-precise connection timing. Internal-to-internal unusual ports: lateral movement often manifests as unexpected connections between internal hosts on ports like 445 (SMB), 135 (WMI/RPC), or 3389 (RDP). A workstation connecting to another workstation over RDP is unusual in most environments. Connections to Tor exit nodes or threat-intel-flagged IPs: even if the firewall allowed it (because the rule was broad), the data.dstcountry and destination IP are correlatable against threat intelligence feeds. Allowed connections that should have been blocked indicate a policy gap.\n\n` +
        `**SIEM correlation: combining firewall + DNS + EDR**\n\n` +
        `A single firewall log tells you that a connection happened. Correlating it with DNS logs (which domain was resolved immediately before the connection?) and EDR logs (which process on the endpoint initiated the connection?) transforms a network event into a full behavioral story. A connection to 185.220.101.47 is interesting. That same IP preceded by a DNS query to "update-svc.cdn-delivery-net.com" and initiated by a process called "svchost.exe" running from the user's Temp directory is a high-confidence threat requiring immediate response.`,
      codeExample:
        `FORTIGATE LOG FIELD REFERENCE — KEY FIELDS FOR SOC\n` +
        `════════════════════════════════════════════════════════════════\n` +
        `\n` +
        ` Field             │ Values              │ SOC Significance\n` +
        ` ──────────────────┼─────────────────────┼────────────────────────────────\n` +
        ` data.type         │ traffic/threat/event │ Filter: use "traffic" for conn\n` +
        ` data.subtype      │ forward/local        │ "local" = traffic TO firewall\n` +
        ` data.action       │ accept/deny/drop     │ "accept" = permitted through\n` +
        ` data.proto        │ 6/17/1               │ 6=TCP, 17=UDP, 1=ICMP\n` +
        ` data.sentbyte     │ integer (bytes)      │ High = possible exfil\n` +
        ` data.rcvdbyte     │ integer (bytes)      │ High = large download\n` +
        ` data.duration     │ integer (seconds)    │ Very short = scan; very long = persistent conn\n` +
        ` data.dstcountry   │ "Netherlands"/etc    │ Unexpected country = flag\n` +
        ` data.srccountry   │ "Reserved" for RFC1918│ RFC1918 always shows Reserved\n` +
        ` data.policyname   │ rule name string     │ Identifies which rule matched\n` +
        ` data.app          │ HTTPS/DNS/SSL/etc    │ Application-level identification\n` +
        `\n` +
        `════════════════════════════════════════════════════════════════\n` +
        `SIEM CORRELATION: FIREWALL + DNS + EDR (C2 DETECTION)\n` +
        `\n` +
        ` TIME     │ SOURCE  │ EVENT\n` +
        ` ─────────┼─────────┼──────────────────────────────────────────────────\n` +
        ` 03:13:59 │ Sysmon  │ Event 22: DNS query "update-svc.cdn-net.com"\n` +
        `          │ (EDR)   │ Process: svchost.exe (C:\\Users\\bob\\AppData\\Temp)\n` +
        `          │         │ Result: 185.220.101.47\n` +
        ` ─────────┼─────────┼──────────────────────────────────────────────────\n` +
        ` 03:14:07 │FortiGate│ data.srcip=10.0.3.88 data.dstip=185.220.101.47\n` +
        `          │         │ data.dstport=443 data.action=accept\n` +
        `          │         │ data.sentbyte=1024 data.rcvdbyte=512\n` +
        `          │         │ data.policyname=outbound-web-allow\n` +
        ` ─────────┼─────────┼──────────────────────────────────────────────────\n` +
        ` 03:14:07 │CrowdStr │ ProcessRollup2: svchost.exe PID=4892\n` +
        `          │ (EDR)   │ Parent: WINWORD.EXE PID=3211\n` +
        `          │         │ Path: C:\\Users\\bob\\AppData\\Local\\Temp\\svchost.exe\n` +
        `          │         │ SHA256: de96a6e6b7f82ab14...  Signed: false\n` +
        ` ─────────┼─────────┼──────────────────────────────────────────────────\n` +
        ` VERDICT:  Malware svchost.exe (fake, in Temp folder, spawned by Word,\n` +
        `           unsigned) is beaconing to Tor exit node via allowed HTTPS rule.\n` +
        `           MITRE: T1071.001 (Web Protocols C2) + T1036.005 (Masquerading)\n` +
        `════════════════════════════════════════════════════════════════`,
    },

    // ── Question 1 ────────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "fw-q1",
      question:
        "A firewall rule says: permit tcp 10.0.0.0/8 any eq 443. What does this rule do?",
      options: [
        "Blocks all HTTPS traffic from the internal network",
        "Allows HTTPS traffic (port 443) from any internal 10.x.x.x host to any destination",
        "Blocks TCP traffic to port 443 for the 10.0.0.0/8 network",
        "Only allows traffic from a specific internal host to port 443",
      ],
      answer: 1,
      explanation:
        "The rule 'permit tcp 10.0.0.0/8 any eq 443' breaks down as: ACTION=permit, PROTOCOL=tcp, SOURCE=10.0.0.0/8 (any address starting with 10.), DESTINATION=any, DESTINATION PORT=443 (HTTPS). It allows any internal 10.x.x.x host to reach any destination on TCP port 443. This is typical outbound HTTPS access for all internal users.",
      xp: 20,
    },

    // ── Question 2 ────────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "fw-q2",
      question:
        "What is the main advantage of STATEFUL inspection over STATELESS packet filtering?",
      options: [
        "Stateful inspection is faster because it processes fewer rules",
        "Stateful inspection tracks connection state, allowing it to block traffic that does not belong to an established session (e.g., unsolicited SYN-ACK packets)",
        "Stateful inspection can read encrypted HTTPS traffic",
        "Stateful inspection works at Layer 7 and can identify specific applications",
      ],
      answer: 1,
      explanation:
        "Stateful inspection maintains a connection state table. It knows whether a packet is part of a legitimate established connection. An unsolicited ACK or SYN-ACK with no matching SYN entry is blocked, because it does not belong to a real connection. Stateless filters cannot detect this. Stateful inspection still operates at L3/L4 — it does not inspect application content (that is NGFW/DPI).",
      xp: 25,
    },

    // ── Question 3 ────────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "fw-q3",
      question:
        "You see 15 outbound HTTPS connections in firewall logs from the same internal IP (10.0.3.88) to the same external IP (185.220.101.47) at almost exactly 60-second intervals, with 1024 bytes sent and 512 bytes received each time. What is the most likely explanation?",
      options: [
        "A user streaming video — regular buffering intervals are common for media apps",
        "A scheduled Windows Update check — Microsoft servers respond on this cadence",
        "C2 (Command and Control) beaconing — malware checking in with its server at regular intervals",
        "A web browser caching DNS responses — the 60-second interval matches DNS TTL",
      ],
      answer: 2,
      explanation:
        "Periodic connections at fixed intervals with small, consistent payloads is the textbook signature of malware C2 beaconing. The beacon checks in with the attacker's server at regular intervals (often 30-120 seconds) to receive commands or report status. Streaming video would have much larger byte counts and vary. Windows Update does not connect at 60-second intervals. The 185.220.101.47 destination is a known Tor exit node.",
      xp: 25,
    },

    // ── Log Analysis ──────────────────────────────────────────────────────────
    {
      type: "log_analysis" as const,
      id: "fw-la1",
      heading: "Investigating a C2 Beacon in Firewall Logs",
      context:
        "You are a SOC analyst at NexaCorp. A SIEM correlation rule fired: '15 connections from the same internal host to the same external IP within 15 minutes, with nearly identical byte counts.' The alert links to a sequence of FortiGate NGFW logs. The displayed event is a representative sample from the sequence. The source IP 10.0.3.88 belongs to a developer workstation (WS-DEV-09). The destination IP 185.220.101.47 is a known Tor network exit node (Abuseipdb reputation: MALICIOUS).",
      event: fwC2Event,
      questions: [
        {
          question:
            "Looking at the sentbyte (1024) and rcvdbyte (512) fields — the attacker's server sends back HALF of what the client sends. In the context of C2 beaconing, what does this asymmetric byte pattern indicate?",
          options: [
            "Normal HTTPS traffic — servers typically send less data than clients",
            "The server is rejecting the connection — hence the smaller response",
            "The malware sends a beacon check-in (1024 bytes including host info), and the server sends back a short acknowledgement or command (512 bytes) — consistent with a C2 keep-alive pattern",
            "The connection is being rate-limited by the FortiGate policy",
          ],
          answer: 2,
          explanation:
            "In C2 beaconing, the infected host (client) typically sends more data than it receives per session. The client sends a beacon containing system status, hostname, and potentially exfiltrated data. The server's small reply (512 bytes) is a command or simple acknowledgement ('stay alive, wait for next instruction'). This 2:1 ratio is common in RAT (Remote Access Trojan) and C2 frameworks like Cobalt Strike, Metasploit, and Sliver.",
          xp: 25,
        },
        {
          question:
            "The firewall action field shows 'accept' — meaning the FortiGate ALLOWED this connection. If the connection was to a known-malicious Tor exit node, why did the firewall allow it?",
          options: [
            "FortiGate does not have threat intelligence feeds and cannot identify Tor exit nodes",
            "The outbound-web-allow policy (policyname field) is a broad rule permitting all outbound HTTPS — the firewall had no rule specifically blocking this IP",
            "The Tor exit node was added to an allowlist by a previous administrator",
            "The connection used a corporate SSL certificate, so the firewall trusted it",
          ],
          answer: 1,
          explanation:
            "The policyname 'outbound-web-allow' is a broad allow rule for outbound HTTPS. Unless the firewall has a URL filtering policy or threat intelligence feed blocking this specific IP, it passes through. Threat intel integration (blocking known-bad IPs from services like PAN's MineMeld, Fortinet FortiGuard, or commercial IP reputation feeds) is essential but must be configured. This is a common gap: firewall rules allow port 443 broadly, trusting that HTTPS means legitimate web traffic.",
          xp: 20,
        },
        {
          question:
            "What TWO firewall capabilities, if enabled, would most likely have BLOCKED or DETECTED this C2 traffic?",
          options: [
            "Stateless packet filtering + MAC address filtering",
            "Threat Intelligence feed blocking known Tor IPs + SSL inspection to see inside the encrypted HTTPS session",
            "DNS filtering + VLAN segmentation",
            "Rate limiting outbound connections + geo-blocking Netherlands traffic",
          ],
          answer: 1,
          explanation:
            "Two complementary controls: (1) Threat Intelligence IP blocklist — 185.220.101.47 appears in multiple Tor exit node feeds. If the FortiGate's FortiGuard IP Reputation was enabled with this category blocked, the connection would be denied before it established. (2) SSL inspection — even if the IP was not in a feed, decrypting the HTTPS session would reveal the C2 traffic pattern (unusual user-agent, beaconing structure, no legitimate web content). Both together create defence in depth for encrypted C2.",
          xp: 25,
        },
      ],
    },

    // ── Flag Task ─────────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "fw-f1",
      prompt:
        "In the firewall log above, what is the value of the data.sessionid field? This session ID uniquely identifies this connection in the FortiGate logs.",
      answer: "2847391",
      hint: "Look in the raw field of the firewall event for data.sessionid.",
      xp: 30,
    },
  ],
};

export default [firewallMasterclass];
