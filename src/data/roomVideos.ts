import type { VideoRef } from "@/lib/media/videos";

// Curated explainer videos (feedback FB-008). Every entry was verified against
// YouTube's oEmbed endpoint (HTTP 200 => exists + embeddable); title/channel are
// copied verbatim from its title/author_name, minutes from the watch page length.
// Reputable educational channels only; prefer < 15 min. Verified 2026-09-28.
// Integrity (valid ids, keys exist in ROOMS_META / LESSON_PATHS) is checked by
// src/data/videos.test.ts.

/** Explainer videos per room (room overview). Keyed by room id. */
export const ROOM_VIDEOS: Record<string, VideoRef[]> = {
  "intro-cybersecurity": [
    { youtubeId: "-BbPHZOE398", title: "Cybersecurity Explained in 3 Acronyms: CIA, PDR, & PPT", channel: "IBM Technology", minutes: 6 },
  ],
  "soc-structure": [
    { youtubeId: "OHkWXFheSKM", title: "Security Operations Center (SOC) Explained", channel: "IBM Technology", minutes: 6 },
  ],
  "networking-fundamentals": [
    { youtubeId: "owDh6FNJUog", title: "Understanding the OSI Model - N10-008 CompTIA Network+ : 1.1", channel: "Professor Messer", minutes: 12 },
  ],
  "networking-protocols": [
    { youtubeId: "g2fT-g9PX9o", title: "Network Ports Explained", channel: "PowerCert Animated Videos", minutes: 11 },
  ],
  "firewall-network-security": [
    { youtubeId: "kDEX1HXybrU", title: "What is a Firewall?", channel: "PowerCert Animated Videos", minutes: 6 },
  ],
  "firewall-masterclass": [
    { youtubeId: "rL4-vbsN35w", title: "Stateful vs Stateless Firewalls - You NEED to know the difference", channel: "LearnCantrill", minutes: 14 },
  ],
  "nac-masterclass": [
    { youtubeId: "yn6CPQ9RioA", title: "Zero Trust Explained in 4 mins", channel: "IBM Technology", minutes: 4 },
  ],
  "dns-deep-dive": [
    { youtubeId: "uOfonONtIuk", title: "How DNS Works - Computerphile", channel: "Computerphile", minutes: 8 },
  ],
  "tls-encrypted-traffic": [
    { youtubeId: "j9QmMEWmcfo", title: "SSL, TLS, HTTPS Explained", channel: "ByteByteGo", minutes: 6 },
  ],
  "email-protocols-forensics": [
    { youtubeId: "nK5QpGSBR8c", title: "Email Header Analysis and Forensic Investigation", channel: "13Cubed", minutes: 23 },
  ],
  "linux-fundamentals": [
    { youtubeId: "VbEx7B_PTOE", title: "Linux for Hackers // EP 1 (FREE Linux course for beginners)", channel: "NetworkChuck", minutes: 12 },
  ],
  "windows-event-logs": [
    { youtubeId: "OfTDtT11g2M", title: "Where SOC Analysts Should Start With Windows Event Logs", channel: "MyDFIR", minutes: 7 },
  ],
  "endpoint-security-fundamentals": [
    { youtubeId: "55GaIolVVqI", title: "What is Endpoint Detection and Response (EDR)?", channel: "IBM Technology", minutes: 6 },
  ],
  "av-vs-edr-masterclass": [
    { youtubeId: "8ZlHOZlNIKk", title: "EDR vs. EPP vs. NGAV", channel: "IBM Technology", minutes: 4 },
  ],
  "cyber-kill-chain": [
    { youtubeId: "II91fiUax2g", title: "Breaking The Kill-Chain: A Defensive Approach", channel: "The CISO Perspective", minutes: 13 },
  ],
  "mitre-attack": [
    { youtubeId: "Yxv1suJYMI8", title: "MITRE ATT&CK® Framework", channel: "mitrecorp (The MITRE Corporation)", minutes: 4 },
  ],
  "siem-fundamentals": [
    { youtubeId: "9RfsRn7m7OE", title: "What Is SIEM?", channel: "IBM Technology", minutes: 4 },
  ],
  "log-management": [
    { youtubeId: "tkg2Lw5ijIg", title: "Log Management - SY0-601 CompTIA Security+ : 4.3", channel: "Professor Messer", minutes: 10 },
  ],
  "soar-automation": [
    { youtubeId: "k7ju95jDxFA", title: "What is SOAR (Security, Orchestration, Automation & Response)", channel: "IBM Technology", minutes: 7 },
  ],
  "alert-triage": [
    { youtubeId: "k9c1PBynVpA", title: "SOC Alert Triage Explained: What Most Beginners Get Wrong", channel: "MyDFIR", minutes: 5 },
  ],
  "phishing-analysis": [
    { youtubeId: "gWGhUdHItto", title: "What is Phishing", channel: "IBM Technology", minutes: 8 },
  ],
  "active-directory": [
    { youtubeId: "mH48U0PlLKI", title: "What is Active Directory?", channel: "CBT Nuggets", minutes: 9 },
  ],
  "kerberos-authentication": [
    { youtubeId: "qW361k3-BtU", title: "Taming Kerberos - Computerphile", channel: "Computerphile", minutes: 16 },
  ],
  "identity-basics": [
    { youtubeId: "aNj36g7fSsU", title: "Identity & Access Management (IAM)", channel: "IBM Technology", minutes: 4 },
  ],
  "incident-response-methodology": [
    { youtubeId: "X2UiMLxRdhE", title: "Incident Response - CompTIA Security+ SY0-701 - 4.8", channel: "Professor Messer", minutes: 9 },
  ],
  "digital-forensics-basics": [
    { youtubeId: "UtDWApdO8Zk", title: "Digital Forensics - CompTIA Security+ SY0-701 - 4.8", channel: "Professor Messer", minutes: 10 },
  ],
  "memory-disk-forensics": [
    { youtubeId: "1PAGcPJFwbE", title: "Introduction to Memory Forensics", channel: "13Cubed", minutes: 23 },
  ],
  "threat-hunting-fundamentals": [
    { youtubeId: "VNp35Uw_bSM", title: "Cybersecurity Threat Hunting Explained", channel: "IBM Technology", minutes: 7 },
  ],
  "threat-intelligence": [
    { youtubeId: "86fruE9jkKk", title: "Threat Intelligence - CompTIA Security+ SY0-701 - 4.3", channel: "Professor Messer", minutes: 5 },
  ],
  "ioc-analysis": [
    { youtubeId: "x72hG9GvkaQ", title: "Indicators of Compromise - CompTIA Security+ SY0-701 - 2.4", channel: "Professor Messer", minutes: 11 },
  ],
  "osint-fundamentals": [
    { youtubeId: "Sa5LbKqCmFI", title: "OSINT Introduction: What is Open Source Intelligence?", channel: "OSINT Dojo", minutes: 8 },
  ],
  "malware-types": [
    { youtubeId: "-eZs8wjjGGE", title: "An Overview of Malware - CompTIA Security+ SY0-701 - 2.4", channel: "Professor Messer", minutes: 6 },
  ],
  "ransomware-full-lifecycle": [
    { youtubeId: "lIsWpCMBxHQ", title: "What is Ransomware?", channel: "IBM Technology", minutes: 4 },
  ],
  "encoding-encryption-hashing": [
    { youtubeId: "-bAnBzvMLig", title: "Encoding, Encryption and Hashing -- What's the Difference?", channel: "Auth0", minutes: 12 },
  ],
  "risk-fundamentals": [
    { youtubeId: "8zSoyAmHHc4", title: "Threats Vulnerabilities and Exploits", channel: "IBM Technology", minutes: 6 },
  ],
};

/** Explainer video for one specific long reading task. Keyed by "roomId:taskId". */
export const ROOM_TASK_VIDEOS: Record<string, VideoRef> = {
  "intro-cybersecurity:intro-cyber-r2":
    { youtubeId: "kPPFNrlN3zo", title: "What is the CIA Triad", channel: "IBM Technology", minutes: 4 },
  "networking-fundamentals:net-fund-r2":
    { youtubeId: "xMtP5ZB3wSk", title: "TCP - Three-way handshake in details", channel: "Sunny Classroom", minutes: 4 },
  "dns-deep-dive:dns-r2":
    { youtubeId: "BoxeL5ybOXI", title: "DNS Attacks - CompTIA Security+ SY0-701 - 2.4", channel: "Professor Messer", minutes: 9 },
  "tls-encrypted-traffic:tls-r1":
    { youtubeId: "LJDsdSh1CYM", title: "TLS / SSL - The complete sequence - Practical TLS", channel: "Practical Networking", minutes: 6 },
  "windows-fundamentals:win-fund-r2":
    { youtubeId: "E6ROLfd8RFo", title: "Windows Registry As Fast As Possible", channel: "Techquickie", minutes: 6 },
  "windows-event-logs:win-evtlogs-r2":
    { youtubeId: "EXsKJ9kIc6s", title: "Where's the 4624? - Logon Events vs. Account Logons", channel: "13Cubed", minutes: 7 },
  "active-directory:ad-r2":
    { youtubeId: "kp5d8Yv3-0c", title: "MicroNugget: How Kerberos Works in Windows Active Directory | CBT Nuggets", channel: "CBT Nuggets", minutes: 7 },
  "identity-basics:idbasics-r6":
    { youtubeId: "L3alw3iXaio", title: "What is Multi-Factor Authentication", channel: "IBM Technology", minutes: 3 },
};
