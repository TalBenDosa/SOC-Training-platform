// ─── Quiz Data: Protocols & Ports for Analysts ─────────────────────────────
// A beginner quiz on the protocols and ports a SOC analyst meets daily — what
// runs where, and why each matters for detection (SMB/445 lateral movement,
// RDP/3389, Kerberos/88, DNS/53 tunnelling, SSH/22, LDAP/389, SMTP/25, WinRM).
// Options are length-balanced so the answer can't be guessed by shape. Same
// contract as ./data.ts.

import type { Quiz } from "./data";

export const QUIZZES_PROTOCOLS_PORTS: Quiz[] = [
  {
    slug: "protocols-and-ports",
    title: "Protocols & Ports for Analysts",
    description: "The protocols and ports every analyst must recognise on sight — SMB, RDP, Kerberos, DNS, SSH, LDAP, SMTP — and why each one shows up in attacks.",
    difficulty: "Beginner",
    category: "Network",
    icon: "🔌",
    estimatedMinutes: 13,
    questions: [
      {
        id: "pp_01",
        question: "Port 445 is one of the most abused ports in enterprise attacks. Which protocol runs on it, and why?",
        options: [
          "RDP — remote desktop access, abused to log in interactively to a target host.",
          "SMB — Windows file sharing, abused for lateral movement, PsExec, and ransomware spread.",
          "DNS — name resolution, abused to tunnel command-and-control traffic out of the network.",
          "LDAP — directory queries, abused to enumerate users and groups in Active Directory.",
        ],
        answer: 1,
        explanation: "Port 445 carries SMB (Server Message Block), Windows file sharing. Attackers use it for lateral movement (PsExec, admin shares), NTLM relay, worm propagation (WannaCry/EternalBlue), and ransomware deployment. Workstation-to-workstation SMB should almost always be blocked.",
        xp: 10,
      },
      {
        id: "pp_02",
        question: "An analyst sees a spike of inbound connections to port 3389 from an external IP. Which service is this, and what's the concern?",
        options: [
          "SSH — someone is brute-forcing remote shell access to a Linux server on the estate.",
          "SMTP — a spam bot is relaying mail through an open corporate mail server.",
          "RDP — remote desktop is exposed to the internet and is being brute-forced or scanned.",
          "Kerberos — an attacker is requesting tickets to move laterally inside the domain.",
        ],
        answer: 2,
        explanation: "Port 3389 is RDP (Remote Desktop Protocol). Internet-exposed RDP is a top ransomware entry vector — attackers scan for it and brute-force credentials. RDP should sit behind a VPN or gateway, never be open to the internet, and should require MFA.",
        xp: 10,
      },
      {
        id: "pp_03",
        question: "Which protocol uses TCP/UDP port 88, and where would you expect to see that traffic?",
        options: [
          "Kerberos — authentication traffic to and from Active Directory domain controllers.",
          "NTP — time-synchronisation requests between servers and the network time source.",
          "LDAP — directory lookups that resolve user and group objects in the domain.",
          "DNS — hostname-to-IP resolution requests handled by the internal resolvers.",
        ],
        answer: 0,
        explanation: "Port 88 is Kerberos, the authentication protocol for Active Directory. Normal port-88 traffic flows to domain controllers. Spikes of AS-REQ (Event 4768) or TGS-REQ (4769) — especially for service accounts — can indicate Kerberoasting or AS-REP Roasting.",
        xp: 10,
      },
      {
        id: "pp_04",
        question: "Why is DNS (port 53) a favourite channel for data exfiltration and command-and-control?",
        options: [
          "Because DNS traffic is always encrypted, so its contents can never be inspected by defenders.",
          "Because DNS runs only over TCP, which guarantees the delivery of large exfiltrated files.",
          "Because DNS is rarely blocked and its queries can smuggle encoded data in the subdomains.",
          "Because DNS servers store the queried data permanently, letting attackers retrieve it later.",
        ],
        answer: 2,
        explanation: "DNS is allowed out of almost every network, so attackers tunnel data through it — encoding payloads into long, high-entropy subdomain labels and TXT-record responses. Thousands of unique random subdomains to one domain is the classic DNS-tunnelling tell.",
        xp: 15,
      },
      {
        id: "pp_05",
        question: "What is the difference between HTTP (port 80) and HTTPS (port 443)?",
        options: [
          "HTTP is used only by browsers, while HTTPS is used only by mobile applications.",
          "HTTP carries traffic in plaintext, while HTTPS wraps the same traffic in TLS encryption.",
          "HTTP supports file downloads, while HTTPS is limited to loading web pages and forms.",
          "HTTP is a newer, faster replacement that is gradually deprecating the older HTTPS standard.",
        ],
        answer: 1,
        explanation: "Both carry web traffic; the difference is TLS. HTTP (80) is plaintext, so anyone on the path can read it. HTTPS (443) encrypts the session with TLS. Most C2 today hides in HTTPS to blend in — so analysts pivot on domain age, certificate, and beaconing rather than payload content.",
        xp: 10,
      },
      {
        id: "pp_06",
        question: "Port 22 appears in a Linux server's auth logs with thousands of failed logins from one IP. Which service is this?",
        options: [
          "Telnet — an unencrypted remote login service that transmits credentials in cleartext.",
          "FTP — a file-transfer service whose control channel is being probed for anonymous access.",
          "SMTP — a mail-submission service being tested as an open relay for spam.",
          "SSH — the encrypted remote-shell service, here under a credential brute-force attempt.",
        ],
        answer: 3,
        explanation: "Port 22 is SSH (Secure Shell), the standard encrypted remote login for Linux/Unix. A flood of failed SSH logins from one source is a brute-force attempt. Defences: key-based auth, disable password login, fail2ban, and restrict source IPs.",
        xp: 10,
      },
      {
        id: "pp_07",
        question: "What runs on port 389, and what is the encrypted version's port?",
        options: [
          "LDAP on 389, with LDAPS (LDAP over TLS) on port 636.",
          "RADIUS on 389, with its accounting counterpart on port 1813.",
          "SMB on 389, with its encrypted signing variant on port 445.",
          "Kerberos on 389, with its password-change service on port 464.",
        ],
        answer: 0,
        explanation: "Port 389 is LDAP (Lightweight Directory Access Protocol), used to query directories like Active Directory. LDAPS — LDAP wrapped in TLS — runs on 636. Heavy LDAP querying from a workstation can indicate AD reconnaissance (e.g. BloodHound enumeration).",
        xp: 10,
      },
      {
        id: "pp_08",
        question: "Which port/protocol is used to SEND email between mail servers, and why do analysts watch it?",
        options: [
          "IMAP (143) — clients sync mailboxes with it, and mass syncs can indicate account takeover.",
          "SMTP (25) — servers relay mail with it, and abuse shows up as spam or exfiltration by email.",
          "POP3 (110) — clients download mail with it, and bulk downloads can indicate data theft.",
          "HTTPS (443) — webmail rides on it, so all mail abuse is visible only in web proxy logs.",
        ],
        answer: 1,
        explanation: "SMTP (port 25) is server-to-server mail transport. Analysts watch it for spam relay from compromised hosts, and for exfiltration over email (T1048.003). IMAP (143) and POP3 (110) are client retrieval protocols; they matter too, but the sending path is SMTP.",
        xp: 10,
      },
      {
        id: "pp_09",
        question: "What is the practical difference between TCP and UDP?",
        options: [
          "TCP is only for internal traffic, while UDP is only for traffic that leaves the network.",
          "TCP encrypts every packet by default, while UDP always sends its data in the clear.",
          "TCP is connection-oriented and reliable, while UDP is connectionless and best-effort.",
          "TCP is limited to web traffic, while UDP is limited to voice and video streaming only.",
        ],
        answer: 2,
        explanation: "TCP sets up a connection (the SYN, SYN-ACK, ACK handshake) and guarantees ordered, retransmitted delivery — used by HTTP, SMB, RDP. UDP is fire-and-forget with no handshake — used by DNS, NTP, and streaming, where speed beats guaranteed delivery. Neither is defined by encryption or direction.",
        xp: 10,
      },
      {
        id: "pp_10",
        question: "A firewall log shows one source IP hitting ports 21, 22, 23, 25, 80, 443, 445 on a host in quick succession. What is this?",
        options: [
          "A legitimate backup job connecting to each of the host's services in turn.",
          "A port scan — reconnaissance probing which services on the host are open.",
          "A DDoS attack aimed at exhausting the host's total connection capacity.",
          "A software update client retrying a single failed connection many times.",
        ],
        answer: 1,
        explanation: "Sequential connections across many well-known ports from one source is a textbook port scan (nmap's default behaviour) — reconnaissance to map open services before an attack. From an external IP or an unexpected internal host, it warrants investigation; an authorised vulnerability scanner is the benign explanation to rule out.",
        xp: 15,
      },
      {
        id: "pp_11",
        question: "Which ports carry WinRM (used by PowerShell Remoting), a common lateral-movement channel?",
        options: [
          "5985 for HTTP and 5986 for HTTPS.",
          "1433 for the default and 1434 for the browser.",
          "3306 for the primary and 33060 for the X protocol.",
          "8080 for the proxy and 8443 for its TLS listener.",
        ],
        answer: 0,
        explanation: "WinRM (Windows Remote Management) listens on 5985 (HTTP) and 5986 (HTTPS). PowerShell Remoting (Enter-PSSession, Invoke-Command) rides on WinRM and is a favourite living-off-the-land lateral-movement technique — watch for unexpected 5985/5986 traffic between workstations. (1433/1434 is SQL Server, 3306 is MySQL, 8080/8443 are alternate HTTP ports.)",
        xp: 15,
      },
      {
        id: "pp_12",
        question: "You see internal workstation-to-workstation traffic on port 445 at 02:00. Why is this worth investigating?",
        options: [
          "Because port 445 is reserved for domain controllers, so no workstation should ever use it.",
          "Because ordinary workstations rarely share files with each other over SMB — this pattern fits lateral movement.",
          "Because all traffic at 02:00 is automatically malicious and should be blocked on sight.",
          "Because port 445 only works over the internet, so internal use of it is always a misconfiguration.",
        ],
        answer: 1,
        explanation: "Users get files from servers, not from each other's machines, so workstation-to-workstation SMB (445) is abnormal and is exactly how PsExec-style lateral movement and ransomware spread look. The time of day adds suspicion but isn't proof by itself; the peer-to-peer SMB pattern is the real signal.",
        xp: 10,
      },
    ],
  },
];
