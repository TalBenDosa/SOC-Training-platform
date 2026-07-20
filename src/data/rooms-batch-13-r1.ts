import type { TelemetryEvent } from "@/lib/sim/types";

const dnsExfilEvent: TelemetryEvent = {
  id: "evt-dns-exfil-001",
  ts: "2024-07-12T14:33:08.000Z",
  source: "sysmon",
  vendor: "Microsoft Sysmon",
  event_type: "dns_query",
  severity: "high",
  hostname: "WS-FINANCE-011",
  user_email: "m.cohen@nexacorp.com",
  description: "Abnormally long DNS query from finance workstation - possible DNS tunneling exfiltration",
  mitre_technique: "T1048.003",
  mitre_tactic: "Exfiltration",
  process: { name: "cmd.exe", pid: 7412, path: "C:\\Windows\\System32\\cmd.exe", parent_name: "explorer.exe", parent_pid: 3888, user: "NEXACORP\\m.cohen" },
  dns: { query: "aGVsbG8td29ybGQtdGhpcy1pcy10ZXN0LWRhdGEtZXhmaWx0cmF0aW9u.evil-c2.net", query_type: "A", response: "NXDOMAIN", rcode: "NXDOMAIN" },
  raw: {
    "event.code": "22",
    "winlog.provider_name": "Microsoft-Windows-Sysmon",
    "winlog.event_data.Image": "C:\\Windows\\System32\\cmd.exe",
    "winlog.event_data.QueryName": "aGVsbG8td29ybGQtdGhpcy1pcy10ZXN0LWRhdGEtZXhmaWx0cmF0aW9u.evil-c2.net",
    "winlog.event_data.QueryResults": "NXDOMAIN",
    "winlog.event_data.QueryStatus": "NXDOMAIN",
    "winlog.event_data.User": "NEXACORP\\m.cohen",
    "winlog.event_data.ProcessId": "7412",
    "winlog.event_data.UtcTime": "2024-07-12 14:33:08.441"
  }
};

const protocolsMasterclass = {
  id: "protocols-masterclass",
  title: "Network Protocols Deep Dive",
  description:
    "Master the protocols that every SOC analyst must know — TCP/IP, DNS, HTTP/S, TLS — from how they work to how attackers abuse them and how to detect anomalies in your SIEM.",
  difficulty: "intermediate" as const,
  category: "Network Security",
  estimatedMinutes: 75,
  xp: 165,
  icon: "📡",
  prerequisites: ["networking-fundamentals"],
  tasks: [
    // ── Reading 1 ─────────────────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "proto-r1",
      heading: "The OSI Model and TCP/IP: How Network Communication Is Organized",
      content:
        `Every network conversation that happens in your organization — a user loading a webpage, an attacker exfiltrating data, a workstation querying Active Directory — follows a set of rules that organize how information travels from one machine to another. Those rules are captured in two related models: the OSI model and the TCP/IP model.\n\n` +
        `**The OSI Model (Open Systems Interconnection)**\n\n` +
        `The OSI model divides networking into seven distinct layers, each responsible for a specific job. Think of it like a postal system: when you send a letter, it goes through packaging, addressing, sorting, transport, and delivery — each step handled by a different part of the system. The OSI layers work the same way.\n\n` +
        `**Layer 7 — Application**: This is where end-user protocols live. HTTP, HTTPS, DNS, FTP, SMTP, RDP. When a user types a URL into a browser, the Application layer is where that request is formed. This is the layer most visible to SOC analysts — web logs, email logs, and DNS query logs all live here.\n\n` +
        `**Layer 6 — Presentation**: Handles data formatting, encryption, and compression. TLS/SSL encryption is conceptually at this layer — it transforms the data before it travels. In practice, most modern SIEM tools don't produce separate Layer 6 logs; TLS is usually captured at the firewall or proxy level.\n\n` +
        `**Layer 5 — Session**: Manages the establishment, maintenance, and termination of sessions between applications. SMB (Server Message Block, used for Windows file sharing) has session-layer concepts. Rarely logged separately — most session data is embedded in higher-layer logs.\n\n` +
        `**Layer 4 — Transport**: TCP and UDP live here. This layer handles whether data delivery is guaranteed (TCP) or best-effort (UDP), and it introduces the concept of port numbers — the mechanism that tells the receiving computer which application should handle the incoming data. Firewall logs and IDS logs routinely capture Layer 4 data: source port, destination port, TCP flags.\n\n` +
        `**Layer 3 — Network**: IP (Internet Protocol) lives here. This layer handles logical addressing (IP addresses) and routing — deciding which path packets take across networks. Every firewall log that shows a source IP, destination IP, and whether the packet was allowed or blocked is operating at Layer 3.\n\n` +
        `**Layer 2 — Data Link**: MAC (Media Access Control) addresses and Ethernet frames live here. ARP (Address Resolution Protocol) operates at this layer to map IP addresses to MAC addresses. Layer 2 attacks like ARP poisoning and MAC spoofing are detected by NAC (Network Access Control) tools and switch logs, not by standard firewalls.\n\n` +
        `**Layer 1 — Physical**: The actual cables, fiber, radio signals, and hardware ports. No security logging happens here in a meaningful sense — you detect physical tampering through physical security systems, not SIEMs.\n\n` +
        `**The TCP/IP Model**\n\n` +
        `In practice, the networking world uses a simpler 4-layer model called TCP/IP (also called the Internet model). It collapses the OSI model's seven layers into four: Network Access (OSI Layers 1-2), Internet (OSI Layer 3), Transport (OSI Layer 4), and Application (OSI Layers 5-7).\n\n` +
        `**Why does this matter for a SOC analyst?**\n\n` +
        `The layer at which an attack occurs determines which tool can detect it. An ARP poisoning attack at Layer 2 will not appear in your firewall logs (Layer 3-4) — you need switch logs or NAC telemetry. A SQL injection attack at Layer 7 will not be caught by a firewall that only inspects Layer 3-4 headers — you need a WAF or proxy. A port scan at Layer 4 shows up in firewall logs as many connection attempts. A DNS exfiltration attack at Layer 7 may pass right through a firewall that allows DNS traffic — you need DNS query logging.\n\n` +
        `Understanding layers lets you instantly answer the question: "Which tool in my stack would capture this attack?" That question determines where you hunt and what log sources you query.`,
      codeExample:
        "OSI MODEL vs TCP/IP MODEL\n" +
        "============================================================\n" +
        "OSI Layer    Name           TCP/IP Layer   Example Protocols\n" +
        "------------------------------------------------------------\n" +
        "Layer 7      Application    Application    HTTP, HTTPS, DNS,\n" +
        "                                           FTP, SMTP, RDP,\n" +
        "                                           SSH, Telnet\n" +
        "Layer 6      Presentation   Application    TLS/SSL, JPEG,\n" +
        "                                           MPEG, ASCII\n" +
        "Layer 5      Session        Application    NetBIOS, SMB,\n" +
        "                                           RPC, SIP\n" +
        "------------------------------------------------------------\n" +
        "Layer 4      Transport      Transport      TCP, UDP, SCTP\n" +
        "------------------------------------------------------------\n" +
        "Layer 3      Network        Internet       IPv4, IPv6,\n" +
        "                                           ICMP, ARP*\n" +
        "------------------------------------------------------------\n" +
        "Layer 2      Data Link      Network        Ethernet, Wi-Fi\n" +
        "                           Access         (802.11), ARP,\n" +
        "                                           MAC addressing\n" +
        "Layer 1      Physical       Network        Cables, fiber,\n" +
        "                           Access         radio, hardware\n" +
        "============================================================\n\n" +
        "ATTACK-TO-LAYER-TO-TOOL MAPPING\n" +
        "============================================================\n" +
        "Attack               Layer   Detection Tool\n" +
        "------------------------------------------------------------\n" +
        "ARP Poisoning        L2      NAC / Switch port security\n" +
        "IP Spoofing          L3      Firewall (anti-spoof rules)\n" +
        "SYN Flood / DDoS     L4      Firewall / IDS\n" +
        "Port Scan            L4      Firewall / IDS\n" +
        "SQL Injection        L7      WAF / Proxy\n" +
        "DNS Tunneling        L7      DNS query logging / SIEM\n" +
        "HTTP C2 Beaconing    L7      Proxy / Next-gen Firewall\n" +
        "Phishing Email       L7      Email Gateway / SIEM\n" +
        "============================================================",
    },
    // ── Reading 2 ─────────────────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "proto-r2",
      heading: "IP Addressing: How Computers Find Each Other on a Network",
      content:
        `Every device on a network needs an address — just like every house on a street needs a number. In networking, that address is the IP address. Understanding IP addressing is foundational for SOC analysts because every log entry involving network traffic contains IP addresses, and correctly interpreting those addresses tells you whether you are looking at internal activity, external communication, or something suspicious.\n\n` +
        `**IPv4 Address Structure**\n\n` +
        `An IPv4 address is a 32-bit number written as four groups of decimal digits separated by dots — for example, 192.168.1.100. Each group (called an octet) represents 8 bits and can range from 0 to 255. The full address therefore represents 2^32 = approximately 4.3 billion possible addresses.\n\n` +
        `**Private vs Public IP Ranges**\n\n` +
        `Not all IP addresses are equal. Three ranges are reserved for use inside private networks and are never routed on the public internet. These are called RFC1918 ranges after the standards document that defines them:\n\n` +
        `- 10.0.0.0 to 10.255.255.255 (written as 10.0.0.0/8) — used by large enterprise networks. Provides 16.7 million addresses.\n` +
        `- 172.16.0.0 to 172.31.255.255 (written as 172.16.0.0/12) — used by medium-sized networks. Provides 1 million addresses.\n` +
        `- 192.168.0.0 to 192.168.255.255 (written as 192.168.0.0/16) — used by small networks and home routers. Provides 65,536 addresses.\n\n` +
        `Any IP address that falls outside these three ranges is a public IP address, routable on the internet, and assigned to a specific organization or internet service provider.\n\n` +
        `**CIDR Notation**\n\n` +
        `CIDR (Classless Inter-Domain Routing) notation expresses a range of addresses compactly using a slash followed by a number. The number after the slash indicates how many bits are fixed (the network portion). A /24 means the first 24 bits are fixed, leaving 8 bits variable — giving you 256 addresses (254 usable, since the first is the network address and the last is the broadcast address). A /16 gives you 65,536 addresses. A /8 gives you 16.7 million.\n\n` +
        `**NAT: Why Your Laptop IP Is 192.168.x.x**\n\n` +
        `Network Address Translation (NAT) is the technology that allows thousands of internal devices with private IP addresses to share a single public IP address. Your laptop has a private address like 192.168.1.50. When you connect to a website, your router replaces the source IP in your packet with the router's public IP (say, 203.0.113.22) before sending it out. The website sees 203.0.113.22, not your laptop's address. When the response comes back, the router translates it back and delivers it to your laptop.\n\n` +
        `**SOC Relevance: Reading IP Addresses in Logs**\n\n` +
        `When you read a log and see a private RFC1918 source IP, you know the connection originated inside your network. When you see a public IP, it came from outside. This matters enormously for alert triage: a connection from 10.10.5.42 to a database server is probably internal — but the same connection from 185.220.101.50 (a known Tor exit node) is alarming.\n\n` +
        `A red flag pattern: an inbound connection with a source IP in the RFC1918 range arriving at your perimeter firewall from the internet. This is a spoofed packet — attackers sometimes forge private IPs as the source of traffic to confuse logging or bypass poorly configured ACLs. A well-configured firewall should drop these at the edge (this is called anti-spoofing).\n\n` +
        `**IPv6**\n\n` +
        `IPv6 uses 128-bit addresses written as eight groups of four hexadecimal digits, such as 2001:0db8:85a3:0000:0000:8a2e:0370:7334. The loopback address (equivalent to IPv4's 127.0.0.1) is ::1. Link-local addresses (used only within a single network segment, not routed) start with fe80::. SOC analysts need to check for IPv6 traffic as a potential blind spot — organizations that log IPv4 extensively sometimes miss IPv6 tunneling attacks.`,
      codeExample:
        "SUBNET REFERENCE TABLE\n" +
        "=======================================================\n" +
        "CIDR    Subnet Mask       Addresses    Usable Hosts\n" +
        "-------------------------------------------------------\n" +
        "/8      255.0.0.0         16,777,216   16,777,214\n" +
        "/16     255.255.0.0       65,536       65,534\n" +
        "/24     255.255.255.0     256          254\n" +
        "/25     255.255.255.128   128          126\n" +
        "/26     255.255.255.192   64           62\n" +
        "/27     255.255.255.224   32           30\n" +
        "/28     255.255.255.240   16           14\n" +
        "/30     255.255.255.252   4            2\n" +
        "/32     255.255.255.255   1            1 (host route)\n" +
        "=======================================================\n\n" +
        "RFC1918 PRIVATE RANGES\n" +
        "=======================================================\n" +
        "Range              CIDR           Common Use\n" +
        "-------------------------------------------------------\n" +
        "10.0.0.0 - 10.255.255.255    /8   Large enterprise\n" +
        "172.16.0.0 - 172.31.255.255  /12  Medium networks\n" +
        "192.168.0.0 - 192.168.255.255/16  Small/home networks\n" +
        "127.0.0.0 - 127.255.255.255  /8   Loopback (localhost)\n" +
        "169.254.0.0 - 169.254.255.255/16  APIPA (no DHCP)\n" +
        "=======================================================\n\n" +
        "SPECIAL IPv6 ADDRESSES\n" +
        "=======================================================\n" +
        "::1                 Loopback (equivalent to 127.0.0.1)\n" +
        "fe80::/10           Link-local (not routed)\n" +
        "fc00::/7            Unique local (like RFC1918)\n" +
        "2001:db8::/32       Documentation examples only\n" +
        "=======================================================",
    },
    // ── Reading 3 ─────────────────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "proto-r3",
      heading: "TCP: The Protocol That Guarantees Delivery",
      content:
        `When you send an important document by courier, you might request a signature on delivery — confirmation that it arrived intact. TCP (Transmission Control Protocol) is the networking equivalent of that signed delivery. It is a connection-oriented, reliable protocol that guarantees data will arrive at the destination in the correct order, without duplication, and without corruption.\n\n` +
        `**The Three-Way Handshake**\n\n` +
        `Before any TCP data is exchanged, two computers must establish a connection through the three-way handshake:\n\n` +
        `1. SYN (Synchronize): The client sends a packet with the SYN flag set. This announces: "I want to start a conversation, and I am starting my sequence numbers at X."\n` +
        `2. SYN-ACK (Synchronize-Acknowledge): The server responds with both SYN and ACK flags set. This says: "I received your SYN, I acknowledge it (ACK), and here are my own starting sequence numbers."\n` +
        `3. ACK (Acknowledge): The client sends a final ACK. The connection is now established and data can flow.\n\n` +
        `This handshake is the foundation for many attack techniques. A SYN flood attack sends thousands of SYN packets but never completes the handshake — the server allocates memory for each half-open connection until it runs out of resources and crashes. Tools like Nmap perform SYN scans (also called half-open scans) by sending SYN packets and analyzing the response without completing the handshake.\n\n` +
        `**TCP Flags**\n\n` +
        `Each TCP packet carries flags — single-bit markers that indicate the purpose of the packet. The six primary flags are:\n\n` +
        `- SYN: Initiate a connection or synchronize sequence numbers\n` +
        `- ACK: Acknowledge receipt of data\n` +
        `- FIN: Signal that the sender has finished sending data (graceful termination)\n` +
        `- RST: Reset the connection immediately (abrupt termination — used to reject connections or inject session resets)\n` +
        `- PSH: Push data to the application immediately, don't buffer\n` +
        `- URG: Mark data as urgent (rarely used in practice)\n\n` +
        `**Sequence and Acknowledgement Numbers**\n\n` +
        `TCP tracks the order of data using sequence numbers. Each byte of data has a sequence number. The ACK number in each packet tells the sender which byte the receiver is expecting next. This mechanism enables TCP to detect lost packets, request retransmission, and reassemble data in the correct order even if packets arrive out of sequence.\n\n` +
        `**Four-Way Termination**\n\n` +
        `Ending a TCP connection properly requires four packets: FIN from one side, ACK from the other, then FIN from the second side, and a final ACK. This is the graceful close. RST bypasses this — it immediately terminates the connection without waiting for the other side to finish. An RST injection attack exploits this: an attacker who can forge a RST packet with the correct sequence number can force-terminate a legitimate TCP session.\n\n` +
        `**Connection States**\n\n` +
        `TCP connections go through multiple states: LISTEN (waiting for connections), SYN_SENT (SYN sent, awaiting SYN-ACK), ESTABLISHED (active connection), FIN_WAIT_1 and FIN_WAIT_2 (closing), TIME_WAIT (waiting to ensure the remote end received the final ACK), and CLOSED.\n\n` +
        `SOC analysts encounter these states in network flow data and firewall logs. A large number of connections stuck in SYN_SENT with no corresponding SYN-ACK can indicate a SYN flood or a scan of a non-listening service. Many connections in TIME_WAIT can indicate a high-volume application or a connection exhaustion attack.`,
      codeExample:
        "TCP THREE-WAY HANDSHAKE\n" +
        "=======================================================\n" +
        "CLIENT (10.10.1.50:52341)      SERVER (10.10.5.10:443)\n" +
        "-------------------------------------------------------\n" +
        "  |                                      |\n" +
        "  |  [SYN]                               |\n" +
        "  |  Seq=1000, Ack=0                     |\n" +
        "  |  Flags: SYN                          |\n" +
        "  |------------------------------------->|\n" +
        "  |                                      |\n" +
        "  |  [SYN-ACK]                           |\n" +
        "  |  Seq=5000, Ack=1001                  |\n" +
        "  |  Flags: SYN ACK                      |\n" +
        "  |<-------------------------------------|\n" +
        "  |                                      |\n" +
        "  |  [ACK]                               |\n" +
        "  |  Seq=1001, Ack=5001                  |\n" +
        "  |  Flags: ACK                          |\n" +
        "  |------------------------------------->|\n" +
        "  |  === CONNECTION ESTABLISHED ===      |\n" +
        "  |  Data can now flow in both           |\n" +
        "  |  directions                          |\n" +
        "=======================================================\n\n" +
        "TCP FLAG REFERENCE\n" +
        "=======================================================\n" +
        "Flag   Hex     Meaning\n" +
        "-------------------------------------------------------\n" +
        "SYN    0x02    Initiate connection\n" +
        "ACK    0x10    Acknowledge data received\n" +
        "FIN    0x01    Graceful close (no more data)\n" +
        "RST    0x04    Abort connection immediately\n" +
        "PSH    0x08    Push data to application now\n" +
        "URG    0x20    Urgent pointer field is valid\n" +
        "-------------------------------------------------------\n" +
        "Common attack flag combinations:\n" +
        "SYN only          = Port scan (Nmap -sS) or SYN flood\n" +
        "RST               = Session hijacking or injection\n" +
        "SYN+FIN           = Malformed / OS fingerprinting\n" +
        "No flags (NULL)   = Firewall evasion scan\n" +
        "All flags (XMAS)  = Firewall evasion scan\n" +
        "=======================================================",
    },
    // ── Reading 4 ─────────────────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "proto-r4",
      heading: "UDP: Speed Without Guarantees",
      content:
        `If TCP is the signed-delivery courier, then UDP (User Datagram Protocol) is a postcard tossed in the mailbox — fast, lightweight, and no confirmation of receipt. UDP is connectionless: there is no handshake, no acknowledgement, no retransmission, and no guaranteed ordering. A packet either arrives or it does not, and UDP does not know the difference.\n\n` +
        `**Why Does UDP Exist?**\n\n` +
        `For many applications, the overhead of TCP — the handshake, the acknowledgements, the retransmissions — costs more than the benefit is worth. Consider a VoIP call. If a voice packet is 200 milliseconds late, retransmitting it is useless — by the time it arrives, the conversation has moved on. Better to just drop it and keep going. UDP is ideal for latency-sensitive applications where occasional data loss is acceptable.\n\n` +
        `**UDP Header: Extreme Minimalism**\n\n` +
        `The UDP header is only 8 bytes: source port (2 bytes), destination port (2 bytes), length (2 bytes), and checksum (2 bytes). Compare this to TCP's minimum 20-byte header plus options. The simplicity means UDP can process traffic much faster than TCP — critical for high-volume, low-latency applications.\n\n` +
        `**Common UDP Applications**\n\n` +
        `DNS uses UDP port 53 for standard queries — a query and response fits in a single packet exchange, making the three-way handshake unnecessary overhead. DHCP (Dynamic Host Configuration Protocol) uses UDP ports 67 and 68 to assign IP addresses — again, a simple request-response pattern. VoIP (voice calls over IP) uses UDP because real-time audio cannot tolerate TCP's retransmission delays. TFTP (Trivial File Transfer Protocol, port 69) is used for simple file transfers like PXE booting. NTP (Network Time Protocol, port 123) synchronizes clocks. SNMP (port 161) monitors network devices. Video streaming and multiplayer games almost universally use UDP.\n\n` +
        `**SOC Relevance: Why Attackers Love UDP**\n\n` +
        `UDP presents three advantages for attackers. First, many firewalls and IDS systems perform stateful inspection on TCP connections but apply less rigorous analysis to UDP traffic, creating potential blind spots. Second, UDP-based DDoS amplification attacks are highly effective: an attacker sends a small UDP request to a server (like a DNS resolver or NTP server) with the victim's IP spoofed as the source, and the server sends a much larger response to the victim. DNS amplification can produce a 50x amplification factor; NTP's MONLIST command was historically capable of 4,000x amplification. Third, ICMP and UDP floods can saturate network links with minimal attacker infrastructure because no connection state needs to be maintained.\n\n` +
        `Malware increasingly tunnels C2 traffic over UDP to evade detection. Tools like DNScat2 and similar DNS tunneling utilities use UDP port 53 (DNS) to carry C2 communications because DNS traffic is almost universally permitted outbound. Some advanced RATs (Remote Access Trojans) use custom UDP protocols that mimic legitimate traffic patterns.\n\n` +
        `From a detection standpoint, volumetric analysis is key for UDP threats. A workstation that suddenly sends 10,000 UDP packets per second to a single external IP is almost certainly participating in a DDoS attack or executing a data exfiltration tool. Baseline your environment's normal UDP patterns and alert on deviations.`,
      codeExample:
        "TCP vs UDP HEADER COMPARISON\n" +
        "=======================================================\n" +
        "TCP HEADER (minimum 20 bytes)\n" +
        "-------------------------------------------------------\n" +
        "| Source Port (16 bits)   | Dest Port (16 bits)      |\n" +
        "| Sequence Number (32 bits)                          |\n" +
        "| Acknowledgement Number (32 bits)                   |\n" +
        "| Data   | Rsvd | Flags  | Window Size (16 bits)    |\n" +
        "| Offset |      | UAPRSF |                          |\n" +
        "| Checksum (16 bits)      | Urgent Pointer (16 bits) |\n" +
        "| Options (variable)...                              |\n" +
        "=======================================================\n\n" +
        "UDP HEADER (always exactly 8 bytes)\n" +
        "-------------------------------------------------------\n" +
        "| Source Port (16 bits)   | Dest Port (16 bits)      |\n" +
        "| Length (16 bits)        | Checksum (16 bits)       |\n" +
        "=======================================================\n\n" +
        "TCP vs UDP USE CASE COMPARISON\n" +
        "=======================================================\n" +
        "Feature          TCP               UDP\n" +
        "-------------------------------------------------------\n" +
        "Connection       Required (3-way)  None\n" +
        "Reliability      Guaranteed        Best-effort\n" +
        "Ordering         Maintained        Not maintained\n" +
        "Header size      20+ bytes         8 bytes\n" +
        "Speed            Slower            Faster\n" +
        "Use cases        HTTP, HTTPS,      DNS, DHCP,\n" +
        "                 SSH, SMTP,        VoIP, NTP,\n" +
        "                 FTP, RDP          video, gaming\n" +
        "-------------------------------------------------------\n" +
        "Attack uses      SYN flood,        UDP flood,\n" +
        "                 session hijack,   DNS amplification,\n" +
        "                 RST injection     DNS tunneling\n" +
        "=======================================================",
    },
    // ── Reading 5 ─────────────────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "proto-r5",
      heading: "DNS: The Internet's Phone Book — How Names Become IP Addresses",
      content:
        `Humans remember names. Computers communicate with numbers. DNS (Domain Name System) is the global translation service that bridges this gap. When you type www.example.com into a browser, DNS converts that name into an IP address like 93.184.216.34 so your computer knows where to send the packets.\n\n` +
        `**The Full DNS Resolution Flow**\n\n` +
        `A DNS query that appears instantaneous to the user actually involves a surprisingly complex chain of lookups:\n\n` +
        `1. Your browser checks its local cache. If it has recently resolved www.example.com and the record hasn't expired, it uses the cached answer without asking anyone.\n` +
        `2. If not cached, your operating system's stub resolver sends the query to your configured recursive resolver (typically your ISP's DNS server or a public resolver like 8.8.8.8 or 1.1.1.1).\n` +
        `3. The recursive resolver checks its own cache. If it has the answer, it returns it immediately.\n` +
        `4. If not cached, the recursive resolver starts from the top. It queries one of the 13 root nameserver clusters (labeled a.root-servers.net through m.root-servers.net), asking: "Who handles .com domains?"\n` +
        `5. The root nameserver responds with the address of the .com TLD (Top-Level Domain) nameserver.\n` +
        `6. The recursive resolver queries the .com TLD nameserver, asking: "Who is authoritative for example.com?"\n` +
        `7. The TLD nameserver returns the address of example.com's authoritative nameserver.\n` +
        `8. The recursive resolver queries the authoritative nameserver: "What is the A record for www.example.com?"\n` +
        `9. The authoritative nameserver returns the IP address. The recursive resolver caches it according to the TTL value and returns the answer to your stub resolver, which passes it to your browser.\n\n` +
        `**DNS Record Types**\n\n` +
        `- A: Maps a hostname to an IPv4 address. The most common record type.\n` +
        `- AAAA: Maps a hostname to an IPv6 address.\n` +
        `- MX: Identifies the mail servers responsible for accepting email for a domain.\n` +
        `- CNAME: Creates an alias pointing one hostname to another (e.g., www.example.com is a CNAME for example.com).\n` +
        `- TXT: Stores arbitrary text. Used for SPF (email sender verification), DKIM (email signing), DMARC (email policy), and domain ownership verification.\n` +
        `- PTR: Reverse DNS lookup — maps an IP address back to a hostname.\n` +
        `- NS: Identifies the authoritative nameservers for a domain.\n` +
        `- SOA: Start of Authority — metadata about the domain (primary nameserver, admin email, serial number, refresh intervals).\n\n` +
        `**TTL and Caching**\n\n` +
        `Every DNS record has a Time To Live (TTL) measured in seconds. Caches honor this TTL — a record with TTL=3600 will be cached for one hour before being re-queried. Attackers use very short TTLs (fast-flux DNS) to rapidly change the IPs behind a domain, making blocklisting ineffective.\n\n` +
        `**DNS over HTTPS (DoH)**\n\n` +
        `Traditional DNS sends queries in plaintext over UDP port 53 — visible to anyone monitoring the network. DNS over HTTPS (DoH) encrypts DNS queries by sending them as HTTPS requests to port 443, hiding them from network inspection. While this improves user privacy, it is a significant problem for SOC analysts: it bypasses corporate DNS resolvers, prevents DNS-based content filtering, and makes DNS-based C2 and tunneling invisible to traditional DNS logging.\n\n` +
        `**SOC Relevance: Why DNS Is the Most Abused Protocol**\n\n` +
        `DNS is permitted outbound by nearly every firewall. Blocking port 53 breaks the internet. Attackers know this and abuse DNS in multiple ways: C2 channels that poll a DNS server for instructions, data exfiltration via DNS tunneling (encoding data in subdomain labels), and domain generation algorithms (DGAs) that generate hundreds of random-looking domain names and try each one until the C2 server responds. Detecting DNS abuse requires query logging at scale and behavioral analysis — not just blocklists.`,
      codeExample:
        "DNS RESOLUTION FLOW\n" +
        "=======================================================\n" +
        "User types: www.example.com\n\n" +
        "  [Browser]                    [Stub Resolver]\n" +
        "     | query: www.example.com?       |\n" +
        "     |------------------------------->|\n" +
        "     |                               | (check local cache: miss)\n" +
        "     |                               |\n" +
        "     |                    [Recursive Resolver: 8.8.8.8]\n" +
        "     |                               | (check cache: miss)\n" +
        "     |                               |\n" +
        "     |                    [Root Nameserver]\n" +
        "     |                               |---> Who handles .com?\n" +
        "     |                               |<--- a.gtld-servers.net\n" +
        "     |                               |\n" +
        "     |                    [.com TLD Nameserver]\n" +
        "     |                               |---> Who handles example.com?\n" +
        "     |                               |<--- ns1.example.com\n" +
        "     |                               |\n" +
        "     |                    [Authoritative NS: ns1.example.com]\n" +
        "     |                               |---> A record for www?\n" +
        "     |                               |<--- 93.184.216.34 (TTL 3600)\n" +
        "     |                               |\n" +
        "     |<- 93.184.216.34 (cached) -----|  \n" +
        "     |                               |\n" +
        "=======================================================\n\n" +
        "DNS RECORD TYPES QUICK REFERENCE\n" +
        "=======================================================\n" +
        "Type    Purpose                    Example\n" +
        "-------------------------------------------------------\n" +
        "A       IPv4 address               93.184.216.34\n" +
        "AAAA    IPv6 address               2606:2800:220:1:...\n" +
        "MX      Mail server                mail.example.com (pri 10)\n" +
        "CNAME   Alias to another name      www -> example.com\n" +
        "TXT     Arbitrary text             v=spf1 include:...\n" +
        "PTR     Reverse lookup (IP->name)  34.216.184.93.in-addr.arpa\n" +
        "NS      Authoritative nameserver   ns1.example.com\n" +
        "SOA     Zone metadata              primary NS, serial, TTL\n" +
        "=======================================================",
    },
    // ── Reading 6 ─────────────────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "proto-r6",
      heading: "HTTP and HTTPS: The Protocol of the Web",
      content:
        `HTTP (HyperText Transfer Protocol) is the language that web browsers and web servers use to communicate. Every time you visit a website, your browser sends HTTP requests and receives HTTP responses. Understanding HTTP structure is essential for SOC analysts — web-based attacks (SQL injection, XSS, path traversal, C2 beaconing) all live in HTTP traffic.\n\n` +
        `**HTTP Methods**\n\n` +
        `HTTP defines a set of methods that tell the server what action the client wants to perform:\n\n` +
        `- GET: Retrieve a resource. The most common method. Parameters are sent in the URL. GET requests should never change server state.\n` +
        `- POST: Send data to the server, typically to submit a form, upload a file, or trigger an action. Parameters are sent in the request body.\n` +
        `- PUT: Replace or create a resource at a specific URL. Used in REST APIs.\n` +
        `- DELETE: Remove a resource. Used in REST APIs.\n` +
        `- HEAD: Like GET, but the server returns only the headers, not the body. Used to check if a resource exists or get its size.\n` +
        `- OPTIONS: Ask the server what methods it supports for a given URL. Commonly used by browsers in CORS preflight requests. Attackers sometimes use OPTIONS to fingerprint web servers.\n` +
        `- PATCH: Partially update a resource.\n\n` +
        `**HTTP Status Codes**\n\n` +
        `The server responds to every request with a three-digit status code:\n\n` +
        `- 1xx (Informational): Request received, processing continues. Rarely logged meaningfully.\n` +
        `- 2xx (Success): 200 OK (standard success), 201 Created (new resource created), 204 No Content (success but no body).\n` +
        `- 3xx (Redirection): 301 Moved Permanently (domain changed forever), 302 Found (temporary redirect — commonly abused in phishing to chain redirects).\n` +
        `- 4xx (Client Error): 400 Bad Request, 401 Unauthorized (authentication required), 403 Forbidden (authenticated but not permitted), 404 Not Found, 429 Too Many Requests (rate limited).\n` +
        `- 5xx (Server Error): 500 Internal Server Error, 502 Bad Gateway, 503 Service Unavailable.\n\n` +
        `**HTTP Request Structure**\n\n` +
        `An HTTP request has three parts: a request line (method + URL + HTTP version), headers (key-value pairs providing metadata — User-Agent, Host, Content-Type, Authorization, Cookie), and an optional body (present in POST and PUT).\n\n` +
        `**HTTP Response Structure**\n\n` +
        `An HTTP response has a status line (HTTP version + status code + reason phrase), headers, and an optional body containing the returned content.\n\n` +
        `**HTTPS: Adding Encryption**\n\n` +
        `HTTPS is HTTP transported inside a TLS (Transport Layer Security) tunnel. The TLS layer encrypts the content so that network observers can see the source IP, destination IP, destination port (443), and the SNI (Server Name Indication — the hostname sent during TLS negotiation) but cannot read the actual HTTP request or response.\n\n` +
        `**SOC Relevance: What HTTP Logs Reveal**\n\n` +
        `Proxy logs and web gateway logs capture HTTP metadata that is invaluable for threat detection. The User-Agent header identifies the client software — attackers often use custom or generic User-Agents (like "python-requests/2.28.0" or "curl/7.68.0") that stand out from normal browser traffic. The Referer header shows where the user came from. The URL contains query parameters that may show SQL injection attempts, path traversal strings, or C2 command parameters. A high rate of 403 or 404 responses from a single IP to a web server is a strong indicator of web scanning or exploitation attempts.`,
      codeExample:
        "RAW HTTP GET REQUEST\n" +
        "=======================================================\n" +
        "GET /api/users?id=1 HTTP/1.1\n" +
        "Host: app.example.com\n" +
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\n" +
        "             AppleWebKit/537.36 Chrome/120.0.0.0\n" +
        "Accept: application/json\n" +
        "Accept-Language: en-US,en;q=0.9\n" +
        "Cookie: session=abc123def456\n" +
        "Connection: keep-alive\n" +
        "-------------------------------------------------------\n" +
        "[empty line signals end of headers, no body for GET]\n" +
        "=======================================================\n\n" +
        "RAW HTTP RESPONSE (200 OK)\n" +
        "=======================================================\n" +
        "HTTP/1.1 200 OK\n" +
        "Content-Type: application/json\n" +
        "Content-Length: 89\n" +
        "Cache-Control: no-store\n" +
        "Date: Thu, 25 Jun 2026 12:00:00 GMT\n" +
        "Server: nginx/1.24.0\n" +
        "\n" +
        "{\"id\": 1, \"name\": \"John Smith\", \"email\": \"j.smith@corp.com\"}\n" +
        "=======================================================\n\n" +
        "SUSPICIOUS HTTP PATTERNS IN PROXY LOGS\n" +
        "=======================================================\n" +
        "Pattern                          Likely Threat\n" +
        "-------------------------------------------------------\n" +
        "User-Agent: python-requests/2.x  Automated/scripted tool\n" +
        "URL: /../../../etc/passwd        Path traversal (LFI)\n" +
        "URL: ?id=1' OR '1'='1            SQL injection attempt\n" +
        "Many 404s from single IP         Web scanning / enumeration\n" +
        "Many 403s from single IP         Unauthorized access attempts\n" +
        "POST to /cmd.php                 Webshell interaction\n" +
        "=======================================================",
    },
    // ── Reading 7 ─────────────────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "proto-r7",
      heading: "TLS/SSL: How Encryption Protects Data in Transit",
      content:
        `Before TLS existed, all web traffic was readable by anyone on the same network — a coffee shop, an ISP, or a nation-state could intercept and read every username and password sent over HTTP. TLS (Transport Layer Security) solved this by encrypting data in transit and authenticating the server's identity.\n\n` +
        `**TLS 1.2 vs TLS 1.3**\n\n` +
        `TLS 1.2 (introduced in 2008) is still widely deployed but has known weaknesses. TLS 1.3 (finalized in 2018) removes all the weak algorithms (RC4, DES, 3DES, RSA key exchange, SHA-1), simplifies the handshake to reduce latency, and enforces forward secrecy by default. SOC analysts should flag traffic negotiating TLS 1.0 or 1.1 — these versions are deprecated and may indicate an old, unpatched client or server, or a downgrade attack.\n\n` +
        `**The TLS Handshake (TLS 1.2)**\n\n` +
        `1. ClientHello: The client announces the TLS versions it supports, a list of cipher suites it can use, and a random value.\n` +
        `2. ServerHello: The server selects the TLS version and cipher suite, sends its own random value, and sends its digital certificate.\n` +
        `3. Certificate Verification: The client verifies the server's certificate against the trusted Certificate Authority (CA) store.\n` +
        `4. Key Exchange: Client and server exchange key material (using the algorithm from the chosen cipher suite) to derive a shared session key. Neither side transmits the key directly — they each independently compute the same key.\n` +
        `5. Finished: Both sides send a Finished message encrypted with the new session key, confirming the handshake succeeded.\n\n` +
        `**Certificate Chains**\n\n` +
        `Trust in TLS flows through a chain: your operating system and browser include a list of trusted Root Certificate Authorities (e.g., DigiCert, Let's Encrypt, Sectigo). Root CAs sign Intermediate CA certificates. Intermediate CAs sign Server certificates. When your browser sees a server certificate, it walks up the chain checking signatures until it reaches a trusted root.\n\n` +
        `A server certificate contains the Subject (CN = Common Name, SAN = Subject Alternative Names listing all valid hostnames), validity dates (Not Before, Not After), the public key, and the issuer.\n\n` +
        `**Cipher Suites**\n\n` +
        `A cipher suite is a named combination of algorithms, for example: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384. Breaking this down: ECDHE is the key exchange algorithm (Elliptic Curve Diffie-Hellman Ephemeral — provides forward secrecy), RSA is the authentication algorithm (used to verify the server certificate), AES_256_GCM is the symmetric encryption algorithm (encrypts the actual data), and SHA384 is the MAC algorithm (verifies data integrity).\n\n` +
        `**JA3 Fingerprinting**\n\n` +
        `Even though TLS encrypts the payload, the ClientHello packet is sent in plaintext. JA3 is a technique that hashes specific fields from the ClientHello (TLS version, cipher suites offered, extensions, elliptic curves, elliptic curve point formats) into a 32-character MD5 fingerprint. Different clients produce different JA3 hashes. Cobalt Strike's default Beacon has a well-known JA3 hash (51c64c77e60f3980eea90869b68c58a8). SOC analysts can query proxy or firewall logs for known-malicious JA3 hashes to identify C2 tools even when the payload is encrypted.\n\n` +
        `**SOC Relevance: TLS in the Kill Chain**\n\n` +
        `Attackers increasingly use TLS for C2 to blend in with legitimate HTTPS traffic. Detection techniques include: flagging self-signed certificates (issuer equals subject — legitimate services use CA-signed certs), checking for short-lived certificates (malware C2 infrastructure rotates certificates frequently), monitoring JA3 hashes against threat intelligence feeds, and looking for TLS traffic to IP addresses rather than domain names (legitimate sites don't usually do this).`,
      codeExample:
        "TLS 1.2 HANDSHAKE DIAGRAM\n" +
        "=======================================================\n" +
        "CLIENT                              SERVER\n" +
        "-------------------------------------------------------\n" +
        "  |                                      |\n" +
        "  |  ClientHello                         |\n" +
        "  |  - TLS versions: 1.2, 1.1, 1.0      |\n" +
        "  |  - Cipher suites: [list]             |\n" +
        "  |  - Client random: 32 bytes           |\n" +
        "  |  - Extensions: SNI, ALPN, etc.       |\n" +
        "  |------------------------------------->|\n" +
        "  |                                      |\n" +
        "  |  ServerHello + Certificate           |\n" +
        "  |  - Chosen cipher: ECDHE-RSA-AES256   |\n" +
        "  |  - Server random: 32 bytes           |\n" +
        "  |  - Certificate chain (X.509)         |\n" +
        "  |<-------------------------------------|\n" +
        "  |  [Client verifies cert chain]        |\n" +
        "  |                                      |\n" +
        "  |  ClientKeyExchange + ChangeCipherSpec|\n" +
        "  |  Finished (encrypted)                |\n" +
        "  |------------------------------------->|\n" +
        "  |                                      |\n" +
        "  |  ChangeCipherSpec + Finished         |\n" +
        "  |<-------------------------------------|\n" +
        "  |  === ENCRYPTED CHANNEL ACTIVE ===   |\n" +
        "=======================================================\n\n" +
        "SELF-SIGNED CERT vs CA-SIGNED CERT (IOC EXAMPLE)\n" +
        "=======================================================\n" +
        "LEGITIMATE (CA-signed):\n" +
        "  Subject:  CN=www.microsoft.com\n" +
        "  Issuer:   CN=Microsoft Azure TLS Issuing CA 05\n" +
        "  Valid:    2025-01-15 to 2026-01-15\n" +
        "\n" +
        "MALICIOUS C2 (self-signed -- red flag):\n" +
        "  Subject:  CN=update-svc.cdn-delivery-net.com\n" +
        "  Issuer:   CN=update-svc.cdn-delivery-net.com  <-- SAME!\n" +
        "  Valid:    2026-06-01 to 2026-08-01  (short TTL)\n" +
        "=======================================================\n\n" +
        "CIPHER SUITE BREAKDOWN\n" +
        "=======================================================\n" +
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\n" +
        "     |      |          |         |\n" +
        "     |      |          |         SHA384 = integrity check\n" +
        "     |      |          AES-256-GCM = data encryption\n" +
        "     |      RSA = server cert authentication\n" +
        "     ECDHE = key exchange (forward secrecy)\n" +
        "=======================================================",
    },
    // ── Reading 8 ─────────────────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "proto-r8",
      heading: "ICMP, ARP, and Other Essential Protocols",
      content:
        `Not all network protocols carry application data. Some exist purely to manage and troubleshoot the network itself. Three of the most important — ICMP, ARP, and DHCP — are also frequently abused by attackers, making them a must-know for SOC analysts.\n\n` +
        `**ICMP: Internet Control Message Protocol**\n\n` +
        `ICMP is an IP-layer protocol used for network diagnostics and error reporting. It carries no application data — its job is to communicate conditions about the network itself. Key ICMP message types:\n\n` +
        `- Type 8, Code 0: Echo Request (the "ping" sent by the source)\n` +
        `- Type 0, Code 0: Echo Reply (the response to a ping)\n` +
        `- Type 3, various codes: Destination Unreachable (host down, port closed, protocol unreachable, fragmentation needed)\n` +
        `- Type 11, Code 0: Time Exceeded (TTL expired in transit — what traceroute uses)\n` +
        `- Type 5: Redirect (tells a host to use a different route — abused to redirect traffic)\n\n` +
        `Ping works by sending ICMP Echo Requests and waiting for Echo Replies — the round-trip time is the measured latency. Traceroute sends packets with incrementally increasing TTL values (starting at 1). Each router that decrements the TTL to zero discards the packet and sends back an ICMP Time Exceeded message, revealing that router's IP address. By incrementing TTL from 1 upward, traceroute maps the entire path.\n\n` +
        `ICMP tunneling uses the data payload of ICMP Echo Request and Reply packets to carry arbitrary data. Because many firewalls permit ICMP pings (for diagnostic purposes), covert channels can be established through ICMP even when other protocols are blocked. Tools like ptunnel can tunnel TCP connections over ICMP.\n\n` +
        `**ARP: Address Resolution Protocol**\n\n` +
        `IP addresses are logical — they exist in software. Ethernet networks use MAC (Media Access Control) addresses — 48-bit hardware identifiers burned into network interface cards. ARP is the protocol that bridges between them: given an IP address, ARP finds the corresponding MAC address.\n\n` +
        `The ARP process: Computer A wants to send a packet to 192.168.1.1. It broadcasts "Who has 192.168.1.1? Tell 192.168.1.50." The device with that IP address (typically the default gateway/router) replies: "192.168.1.1 is at MAC address 00:1A:2B:3C:4D:5E." Computer A caches this mapping in its ARP table.\n\n` +
        `ARP Poisoning (also called ARP Spoofing): An attacker sends unsolicited ARP replies (gratuitous ARP packets) claiming that the default gateway's IP address is at the attacker's MAC address. Victim machines update their ARP cache with the false mapping. Now all traffic destined for the gateway goes to the attacker instead — a man-in-the-middle position. The attacker can read, modify, or drop the traffic. Detection requires monitoring for unexpected ARP table changes or for ARP replies that nobody requested.\n\n` +
        `**DHCP: Dynamic Host Configuration Protocol**\n\n` +
        `DHCP automates IP address assignment. The DORA process: Discover (client broadcasts "I need an IP address"), Offer (server responds "Here is 192.168.1.100, valid for 24 hours"), Request (client accepts "I'll take 192.168.1.100"), Acknowledge (server confirms "It's yours").\n\n` +
        `A rogue DHCP server attack: an attacker sets up an unauthorized DHCP server on the network. When clients send DHCP Discover broadcasts, the rogue server responds faster than the legitimate one and assigns IP addresses — including a gateway and DNS server pointing to attacker-controlled infrastructure. This gives the attacker a man-in-the-middle position over all newly-joining clients. Detection requires network access control (NAC) systems that enforce DHCP server authorization and alert on unexpected DHCP Offer packets.`,
      codeExample:
        "ARP REQUEST AND REPLY\n" +
        "=======================================================\n" +
        "ARP REQUEST (broadcast):\n" +
        "  Sender IP:  192.168.1.50  (Computer A)\n" +
        "  Sender MAC: AA:BB:CC:DD:EE:01\n" +
        "  Target IP:  192.168.1.1   (gateway)\n" +
        "  Target MAC: 00:00:00:00:00:00 (unknown)\n" +
        "  Destination: FF:FF:FF:FF:FF:FF (broadcast)\n\n" +
        "ARP REPLY (unicast):\n" +
        "  Sender IP:  192.168.1.1   (gateway)\n" +
        "  Sender MAC: 00:1A:2B:3C:4D:5E  <-- real MAC\n" +
        "  Target IP:  192.168.1.50\n" +
        "  Target MAC: AA:BB:CC:DD:EE:01\n" +
        "=======================================================\n\n" +
        "ARP POISONING ATTACK SCENARIO\n" +
        "=======================================================\n" +
        "Normal ARP table on victim (192.168.1.50):\n" +
        "  192.168.1.1  =>  00:1A:2B:3C:4D:5E  (legitimate gateway)\n\n" +
        "Attacker sends gratuitous ARP:\n" +
        "  'Who has 192.168.1.1? I have it at AA:BB:CC:11:22:33'\n\n" +
        "Poisoned ARP table on victim:\n" +
        "  192.168.1.1  =>  AA:BB:CC:11:22:33  (ATTACKER MAC)\n\n" +
        "Result: All victim traffic now flows through attacker.\n" +
        "=======================================================\n\n" +
        "ICMP TYPE REFERENCE FOR SOC\n" +
        "=======================================================\n" +
        "Type  Code  Meaning               SOC Relevance\n" +
        "-------------------------------------------------------\n" +
        "8     0     Echo Request (ping)   Recon / ICMP tunnel\n" +
        "0     0     Echo Reply            ICMP tunnel response\n" +
        "3     1     Host Unreachable      Scan result analysis\n" +
        "3     3     Port Unreachable      Closed port indicator\n" +
        "11    0     TTL Exceeded          Traceroute mapping\n" +
        "5     1     Host Redirect         Route poisoning attack\n" +
        "=======================================================",
    },
    // ── Reading 9 ─────────────────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "proto-r9",
      heading: "The SOC Analyst Port Reference: 50 Ports You Must Know",
      content:
        `Port numbers are how TCP and UDP identify which application on a server should handle incoming traffic. Ports 0-1023 are well-known ports assigned by IANA (Internet Assigned Numbers Authority) to specific protocols. Ports 1024-49151 are registered ports. Ports 49152-65535 are dynamic/ephemeral ports used as source ports by clients.\n\n` +
        `For a SOC analyst, knowing what normally runs on a port — and what absolutely should not — is a foundational skill. Unexpected traffic on a well-known port often indicates an attack or a misconfiguration. Traffic on unusual high-numbered ports can indicate malware C2.\n\n` +
        `**Remote Access and Administration Ports**\n\n` +
        `Port 22 (SSH): Secure Shell — encrypted remote terminal access. Legitimate on servers, concerning on workstations. Brute-force attacks against SSH are extremely common on internet-exposed servers. External connections to internal SSH should be rare and authenticated with keys, not passwords.\n\n` +
        `Port 23 (Telnet): Unencrypted remote terminal — transmits everything in plaintext including credentials. Should never be seen in a modern environment. Its presence indicates an extremely old or misconfigured device and is a critical finding.\n\n` +
        `Port 3389 (RDP): Remote Desktop Protocol. Legitimate for remote administration, but exposure to the internet makes it a prime target for brute force and exploitation (BlueKeep CVE-2019-0708). Should be behind a VPN, not directly internet-facing. Alert on inbound connections to 3389 from non-VPN external IPs.\n\n` +
        `Port 5985/5986 (WinRM): Windows Remote Management, used by PowerShell Remoting. Lateral movement via WinRM is very common in enterprise attacks — it is quieter than RDP and harder to detect. Alert on workstation-to-workstation WinRM connections.\n\n` +
        `**File Transfer and Sharing Ports**\n\n` +
        `Port 21 (FTP): File Transfer Protocol — cleartext. Never acceptable for transferring sensitive data. SFTP (port 22) or FTPS (port 990) should replace it. FTP traffic from internal workstations to external IPs is suspicious.\n\n` +
        `Port 445 (SMB): Server Message Block — Windows file sharing and printer sharing. One of the most attacked ports in history (EternalBlue, WannaCry, NotPetya all used SMB). Should be blocked at the perimeter. Internal workstation-to-workstation SMB is how ransomware spreads laterally. Port 139 (NetBIOS) is the legacy predecessor to SMB 445.\n\n` +
        `**Email Ports**\n\n` +
        `Port 25 (SMTP): Email transfer between servers. Outbound SMTP from workstations (rather than from the mail server) is a sign of spam bot activity or malware. Port 110 (POP3) and 143 (IMAP) are email retrieval protocols. Port 587 is the authenticated submission port for clients sending email.\n\n` +
        `**Directory and Identity Ports**\n\n` +
        `Port 389 (LDAP) and 636 (LDAPS — encrypted LDAP): Active Directory queries. Tools like BloodHound generate massive LDAP query volumes against domain controllers. Alert on workstations making unusually high volumes of LDAP queries.\n\n` +
        `**Database Ports**\n\n` +
        `Port 1433 (Microsoft SQL Server), 1521 (Oracle), 3306 (MySQL/MariaDB), 5432 (PostgreSQL): Database ports should never be directly reachable from workstations or the internet. Any traffic to these ports from non-application servers is a critical red flag — it may indicate SQL injection exploitation, lateral movement to a database server, or direct data exfiltration.\n\n` +
        `**Known Attacker Ports**\n\n` +
        `Port 4444 is the default listener port for Metasploit's Meterpreter shells. Port 31337 (spelled "elite" in leet speak) has been used by BackOrifice and many other tools. Any traffic to or from these ports is almost certainly malicious.`,
      codeExample:
        "PORT REFERENCE TABLE -- ORGANIZED BY RISK LEVEL\n" +
        "=======================================================\n" +
        "CRITICAL RISK (block at perimeter + alert internally)\n" +
        "-------------------------------------------------------\n" +
        "23    Telnet      Cleartext remote shell -- should not exist\n" +
        "445   SMB         EternalBlue, ransomware spread, NTLM relay\n" +
        "4444  Metasploit  Default Meterpreter listener\n" +
        "31337 Backdoor    Legacy malware default (BackOrifice, etc.)\n" +
        "3389  RDP         Brute force, BlueKeep if internet-facing\n" +
        "=======================================================\n" +
        "HIGH RISK (restrict and monitor closely)\n" +
        "-------------------------------------------------------\n" +
        "21    FTP         Cleartext file transfer -- use SFTP instead\n" +
        "22    SSH         Brute force target, lateral movement\n" +
        "135   RPC         DCOM/WMI lateral movement\n" +
        "139   NetBIOS     Legacy SMB, attack surface\n" +
        "5985  WinRM/HTTP  PowerShell remoting lateral movement\n" +
        "5986  WinRM/HTTPS PowerShell remoting lateral movement\n" +
        "=======================================================\n" +
        "MEDIUM RISK (monitor for anomalies)\n" +
        "-------------------------------------------------------\n" +
        "25    SMTP        Outbound from workstations = malware/spam\n" +
        "53    DNS         Tunneling, C2, DGA domains\n" +
        "389   LDAP        BloodHound enumeration, AD recon\n" +
        "636   LDAPS       Same as LDAP but encrypted\n" +
        "1433  MSSQL       DB access from non-app servers = red flag\n" +
        "1521  Oracle DB   DB access from non-app servers = red flag\n" +
        "3306  MySQL       DB access from non-app servers = red flag\n" +
        "5432  PostgreSQL  DB access from non-app servers = red flag\n" +
        "=======================================================\n" +
        "STANDARD (baseline and monitor for deviations)\n" +
        "-------------------------------------------------------\n" +
        "80    HTTP        Unencrypted web\n" +
        "110   POP3        Email retrieval (legacy)\n" +
        "143   IMAP        Email retrieval\n" +
        "443   HTTPS       Encrypted web (also C2 beacon channel)\n" +
        "8080  HTTP-alt    Dev servers, proxies -- check if expected\n" +
        "8443  HTTPS-alt   Dev servers, proxies -- check if expected\n" +
        "=======================================================",
    },
    // ── Reading 10 ────────────────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "proto-r10",
      heading: "How Attackers Abuse Protocols: C2, DNS Tunneling, and Protocol Attacks",
      content:
        `Understanding how protocols work is only half the picture. The other half is understanding how attackers exploit those same protocols to hide their activities. Advanced attackers don't announce themselves — they blend into normal traffic, using protocols that are permitted, expected, and difficult to inspect.\n\n` +
        `**DNS Tunneling (MITRE T1048.003)**\n\n` +
        `DNS tunneling exploits the fact that DNS queries are almost universally permitted outbound — blocking DNS breaks the internet. Attackers install a DNS tunneling tool (iodine, dnscat2, dns2tcp) on the compromised host and control a domain whose authoritative nameserver is also attacker-controlled. Data to exfiltrate is encoded (typically base64) and sent as DNS subdomain labels: encoded-data-chunk.attacker-domain.com. The attacker's nameserver decodes the subdomain, extracts the data, and can send commands back in DNS responses (TXT records or encoded A records).\n\n` +
        `IOCs for DNS tunneling: subdomain strings that are 30+ characters long and appear to be random or base64, high volume of queries to a single domain in a short time, large number of unique subdomains under one parent domain, uncommon query types (TXT, NULL, MX used for data, not just A records), NXDOMAIN responses at high rates, and queries from processes that should not be making DNS queries (cmd.exe, PowerShell).\n\n` +
        `**HTTP/S C2 Beaconing (MITRE T1071.001)**\n\n` +
        `Many malware families communicate with their C2 servers over HTTP or HTTPS to blend in with legitimate web traffic. The key behavioral signature is beaconing: the malware connects to the C2 server at regular intervals (every 30 seconds, every 60 seconds, every 5 minutes) to check for commands. Detection clues: regular timing intervals between connections (low standard deviation in inter-connection times), consistent small request and response sizes, unusual User-Agent strings (or a repeating user-agent that differs from the host's actual browser), base64 or encoded data in URL parameters or POST bodies, and connections to domains registered recently or with no reputation.\n\n` +
        `**HTTPS C2 and JA3 Detection**\n\n` +
        `When C2 uses HTTPS, the payload is encrypted. However, the TLS ClientHello is visible. JA3 fingerprinting hashes the TLS parameters (cipher suites offered, extensions, elliptic curves) to identify the TLS client implementation. Cobalt Strike Beacon has a well-documented JA3 hash (51c64c77e60f3980eea90869b68c58a8). Security researchers publish JA3 blocklists for known malware families — any proxy or firewall that logs JA3 hashes can be cross-referenced against these feeds.\n\n` +
        `**SMB Lateral Movement (MITRE T1021.002)**\n\n` +
        `SMB (port 445) is how Windows systems share files and printers. It is also how ransomware spreads internally. EternalBlue (CVE-2017-0144) exploited an SMBv1 vulnerability to achieve unauthenticated remote code execution — it powered WannaCry and NotPetya. Even without exploits, authenticated SMB (using stolen credentials) enables lateral movement via PsExec, WMI, or direct file copy to ADMIN$ and C$ shares. Detection: workstation-to-workstation SMB connections (not workstation-to-file-server), Windows Event 4624 LogonType 3 (network logon) on servers receiving connections from unexpected sources.\n\n` +
        `**RDP Brute Force (MITRE T1110.001)**\n\n` +
        `Port 3389 (RDP) exposed to the internet receives constant brute-force attempts. Detection: Windows Event 4625 (logon failure) with LogonType 10 (RemoteInteractive) at high volume from a single external IP. Once credentials are found, a successful 4624 event with LogonType 10 follows. Alert immediately on successful RDP logins from external IPs to any non-jump-server host.\n\n` +
        `**ICMP Tunneling**\n\n` +
        `ICMP Echo Request (ping) packets can carry a data payload. Tools like ptunnel hide TCP traffic inside ICMP packets. IOCs: ICMP packets with unusually large payloads (normal pings carry 32-56 bytes; tunneled ICMP may carry hundreds or thousands), high-frequency ICMP traffic between two specific hosts, and ICMP traffic to external IPs from servers that have no reason to ping the internet.`,
      codeExample:
        "DNS TUNNELING QUERY CHAIN EXAMPLE\n" +
        "=======================================================\n" +
        "Normal DNS query:                     [2 chars subdomain]\n" +
        "  www.google.com  A  =>  142.250.74.100\n\n" +
        "DNS tunneling queries:                [50+ chars, base64]\n" +
        "  dGhpcyBpcyBzZWNyZXQgZGF0YSBjaHVuayAxAA==.c2.evil.net\n" +
        "  aW50ZXJuYWwgZG9jdW1lbnQgY29uZmlkZW50aWFs.c2.evil.net\n" +
        "  cGF5cm9sbC1kYXRhLXEyLTIwMjYueGxzeAAAAAA=.c2.evil.net\n" +
        "  ZW1wbG95ZWUtc3NuLWxpc3QudHh0AAAAAAAAAA==.c2.evil.net\n\n" +
        "Each subdomain decodes to a chunk of exfiltrated data.\n" +
        "The authoritative NS for evil.net is attacker-controlled\n" +
        "and reassembles the data. Response may be NXDOMAIN to\n" +
        "avoid caching, or contain encoded C2 commands in TXT.\n" +
        "=======================================================\n\n" +
        "C2 BEACONING PATTERN vs NORMAL TRAFFIC\n" +
        "=======================================================\n" +
        "NORMAL BROWSING (irregular pattern):\n" +
        "  14:01:03 GET /news  443 200 12KB\n" +
        "  14:01:07 GET /image 443 200 450KB\n" +
        "  14:03:44 GET /video 443 200 2MB\n" +
        "  [gap of 8 minutes]\n" +
        "  14:11:22 GET /login 443 200 8KB\n\n" +
        "MALWARE BEACON (perfectly regular -- red flag):\n" +
        "  14:00:00 POST /update  443 200 256B  <- check-in\n" +
        "  14:01:00 POST /update  443 200 256B  <- check-in\n" +
        "  14:02:00 POST /update  443 200 256B  <- check-in\n" +
        "  14:03:00 POST /update  443 200 256B  <- check-in\n" +
        "  [exactly 60 seconds between each connection]\n" +
        "=======================================================",
    },
    // ── Question 1 ────────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "proto-q1",
      question:
        "During a TCP connection, which flag is sent FIRST by the client to initiate the connection?",
      options: [
        "ACK",
        "SYN",
        "FIN",
        "RST",
      ],
      answer: 1,
      explanation:
        "TCP connections begin with a SYN (synchronise) packet from the client. The server responds with SYN-ACK, and the client confirms with ACK. This 3-way handshake establishes the connection. SYN scans (used by Nmap and attackers) send SYN but never complete the handshake — the server's response (SYN-ACK meaning port open, RST meaning port closed) reveals the state of each port without fully establishing a connection.",
      xp: 20,
    },
    // ── Question 2 ────────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "proto-q2",
      question:
        "A SOC analyst sees hundreds of DNS queries from a single workstation, all going to subdomains of the same domain, with subdomain strings that are 50+ characters long and look like random base64 text. What is the most likely explanation?",
      options: [
        "Normal web browsing activity — CDN providers use long subdomain names",
        "DNS tunneling — the workstation is exfiltrating data by encoding it in DNS subdomain queries",
        "The DNS resolver is having trouble and retrying queries",
        "The user installed a new application that uses DNS for licence verification",
      ],
      answer: 1,
      explanation:
        "Long, random-looking subdomains sent at high frequency to a single domain is the classic signature of DNS tunneling. Legitimate CDN subdomains are short and predictable. The base64-like appearance confirms data is being encoded into the subdomain labels. This is MITRE technique T1048.003 — Exfiltration Over Alternative Protocol: DNS. The analyst should pull the full DNS query history for this host, decode sample subdomains to confirm exfiltrated content, isolate the workstation, and search for the same domain across all other hosts.",
      xp: 25,
    },
    // ── Question 3 ────────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "proto-q3",
      question:
        "Port 445 is blocked on your perimeter firewall. An attacker has already gained access to a workstation inside the network. What risk does port 445 STILL pose INTERNALLY?",
      options: [
        "No risk — if it is blocked at the perimeter the attacker cannot exploit it",
        "Internal SMB traffic on port 445 can enable lateral movement between workstations, spreading ransomware and enabling credential relay attacks",
        "Port 445 is only used for printing and poses minimal security risk",
        "The attacker would need to open port 445 on the perimeter firewall before it becomes a risk",
      ],
      answer: 1,
      explanation:
        "Blocking port 445 at the perimeter only prevents EXTERNAL attacks. Once an attacker is inside the network, internal port 445 (SMB) traffic is often unrestricted, enabling lateral movement between workstations, ransomware propagation, and NTLM relay attacks. WannaCry and NotPetya spread entirely over internal networks using SMB — perimeter blocks did nothing to stop internal propagation. Network segmentation (blocking workstation-to-workstation SMB with firewall rules or host-based firewalls) is required to limit this risk.",
      xp: 20,
    },
    // ── Log Analysis ──────────────────────────────────────────────────────────
    {
      type: "log_analysis" as const,
      id: "proto-la1",
      heading: "Investigating a DNS Tunneling Alert",
      context:
        "You are a Tier-1 SOC analyst at NexaCorp. A SIEM rule fired on an unusually long DNS query originating from a finance department workstation. The workstation belongs to m.cohen@nexacorp.com. DNS tunneling is a technique where attackers exfiltrate data by encoding it in DNS subdomain query strings — the encoded data is sent as a DNS query to an attacker-controlled domain. Review the Sysmon Event ID 22 log below.",
      event: dnsExfilEvent,
      questions: [
        {
          question:
            "The QueryName field shows 'aGVsbG8td29ybGQtdGhpcy1pcy10ZXN0LWRhdGEtZXhmaWx0cmF0aW9u.evil-c2.net'. The long prefix before the dot is a base64-encoded string. What does this confirm about the nature of this DNS query?",
          options: [
            "This is a normal CDN subdomain — base64 characters are commonly used in CDN URLs",
            "The subdomain contains encoded data, strongly suggesting DNS tunneling to exfiltrate information to an attacker-controlled domain",
            "The query failed because the domain does not exist (NXDOMAIN), proving it is safe",
            "The process cmd.exe automatically generates long DNS queries as part of Windows network stack",
          ],
          answer: 1,
          explanation:
            "Base64-encoded data in DNS subdomain labels is the textbook signature of DNS tunneling. The subdomain 'aGVsbG8td29ybGQtdGhpcy1pcy10ZXN0LWRhdGEtZXhmaWx0cmF0aW9u' decodes to 'hello-world-this-is-test-data-exfiltration' — a clear indicator of deliberate exfiltration. The NXDOMAIN response does NOT mean the domain is safe — it means the attacker's authoritative nameserver received the query (which contained the data) and returned NXDOMAIN to avoid leaving a real DNS record in caches. The exfiltration succeeded at the DNS layer before NXDOMAIN was returned.",
          xp: 25,
        },
        {
          question:
            "The log shows the query was made by cmd.exe (winlog.event_data.Image = C:\\Windows\\System32\\cmd.exe). Why is cmd.exe making DNS queries suspicious?",
          options: [
            "cmd.exe is a legitimate system process that makes DNS queries as part of normal Windows operation",
            "cmd.exe should never query DNS directly under normal operations — only browsers and dedicated apps do. This suggests a script or tool running in the command prompt is performing the exfiltration",
            "The DNS query is suspicious because cmd.exe is located in System32, which is an attacker-controlled folder",
            "The parent process explorer.exe is the real threat — cmd.exe is just passing through",
          ],
          answer: 1,
          explanation:
            "Under normal operations, cmd.exe (the Windows command prompt) does not initiate DNS queries directly. DNS queries typically originate from browsers, system services (like svchost.exe), or dedicated applications. When cmd.exe appears as the process making DNS queries in Sysmon Event 22, it strongly suggests a script, batch file, or tool like iodine or dnscat2 is being executed from the command line to perform tunneling. The parent process explorer.exe is normal — the user likely launched a malicious file from their desktop. The malicious activity is in what cmd.exe is executing.",
          xp: 20,
        },
        {
          question:
            "What should be the analyst's NEXT step after identifying this alert as likely DNS tunneling?",
          options: [
            "Close the alert as a false positive because NXDOMAIN means the domain does not exist and no data was transferred",
            "Immediately isolate the workstation WS-FINANCE-011 via EDR containment, query the SIEM for all DNS queries from this host in the past 30 days, and check other hosts for similar queries to evil-c2.net",
            "Send an email to m.cohen asking if they were running any DNS tools",
            "Mark as medium priority and investigate next week during scheduled review",
          ],
          answer: 1,
          explanation:
            "DNS tunneling is an active exfiltration event — the analyst should contain first, then investigate. Isolate WS-FINANCE-011 via EDR network containment to stop the exfiltration channel immediately. Pull all DNS query history from this host to estimate when this started and how much data was sent. Search across all hosts for queries to evil-c2.net to determine whether this is an isolated compromise or part of a wider campaign. NXDOMAIN absolutely does not mean no data was transferred — the query itself carries the data in the subdomain label, and NXDOMAIN is simply the attacker's chosen response to avoid DNS caching.",
          xp: 25,
        },
      ],
    },
    // ── Flag ──────────────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "proto-f1",
      prompt:
        "Look at the DNS log event above. The MITRE ATT&CK technique field identifies the exact exfiltration technique. What is the technique ID? Enter exactly as shown (e.g. T1234.567).",
      answer: "T1048.003",
      hint: "Look at the mitre_technique field of the event. It describes exfiltration over an alternative protocol using a specific sub-technique number.",
      xp: 30,
    },
  ],
};

export default [protocolsMasterclass];
