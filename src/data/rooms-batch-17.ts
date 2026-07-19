/**
 * Rooms Batch 17 — Network Communications & Protocols Deep Dive Series
 *
 * 6 advanced rooms taking the student from the beginner networking rooms
 * (networking-fundamentals, networking-protocols, firewall-network-security)
 * into protocol-internals-level SOC analysis:
 * - tcpip-deep-dive           — TCP flags/state machine, RST/FIN, scans, TTL/window fingerprinting, flow vs PCAP
 * - dns-deep-dive             — resolution path, DoH/DoT blind spots, DNS tunneling, DGA vs CDN, fast-flux, sinkholes
 * - tls-encrypted-traffic     — TLS handshake, SNI, cert chains, JA3/JA3S/JARM, detecting C2 in TLS, interception limits
 * - windows-protocols-lateral — SMB signing/admin shares, Kerberos ticket fields, Kerberoasting/AS-REP/PtT, NTLM, LDAP recon, DCERPC
 * - email-protocols-forensics — SMTP conversation, envelope vs header From, Received chain, SPF/DKIM/DMARC, ARC, header forensics
 * - tunneling-c2-channels     — SSH port forwarding, SOCKS, reverse shells, ICMP/DNS tunneling, beacon math, ngrok/Chisel/plink
 */

import r1 from "@/data/rooms-batch-17-r1";
import r2 from "@/data/rooms-batch-17-r2";
import r3 from "@/data/rooms-batch-17-r3";
import r4 from "@/data/rooms-batch-17-r4";
import r5 from "@/data/rooms-batch-17-r5";
import r6 from "@/data/rooms-batch-17-r6";

export default [...r1, ...r2, ...r3, ...r4, ...r5, ...r6];
