// ─── Quiz Data: Security Tools & the Defensive Stack ───────────────────────
// A beginner "know your toolstack" quiz: WHAT each defensive component is, what
// it protects, and how they differ from one another (Firewall, IDS/IPS, AV vs
// EDR, SIEM, SOAR, WAF, DLP, VPN, web proxy, NAC, XDR, honeypot). Complements
// the existing deep-dive quizzes (endpoint-security-edr, network-security,
// web-application-security, data-loss-prevention) with the foundational
// vocabulary a new analyst needs before those. Same contract as ./data.ts.
// Options are kept length-balanced so the answer can't be guessed by shape.

import type { Quiz } from "./data";

export const QUIZZES_SECURITY_TOOLS: Quiz[] = [
  {
    slug: "security-tools-defensive-stack",
    title: "Security Tools & the Defensive Stack",
    description: "Know your toolbox: what a Firewall, IDS/IPS, AV, EDR, SIEM, SOAR, WAF, DLP, VPN, proxy, and NAC each do — and how they differ. The vocabulary every SOC analyst needs.",
    difficulty: "Beginner",
    category: "SOC Fundamentals",
    icon: "🛡️",
    estimatedMinutes: 13,
    questions: [
      {
        id: "st_01",
        question: "What is the primary job of a network firewall (FW)?",
        options: [
          "It scans the files on each endpoint for known malware signatures and quarantines the bad ones.",
          "It controls traffic between networks, allowing or blocking connections based on a set of rules.",
          "It collects logs from across the estate and correlates them to raise alerts for analysts.",
          "It encrypts the traffic between a remote worker and the corporate network over the internet.",
        ],
        answer: 1,
        explanation: "A firewall sits between networks (e.g. the internet and the corporate LAN) and enforces a rule set — allow or deny — based on source/destination IP, port, and protocol. The other options describe antivirus (endpoint file scanning), a SIEM (log correlation), and a VPN (encrypted remote tunnel).",
        xp: 10,
      },
      {
        id: "st_02",
        question: "What is the key difference between an IDS and an IPS?",
        options: [
          "An IDS inspects only encrypted traffic, while an IPS inspects only plaintext traffic.",
          "An IDS runs on the endpoint, while an IPS can only run at the network perimeter.",
          "An IDS detects and alerts on malicious traffic, while an IPS sits inline and can also block it.",
          "An IDS is always a cloud service, while an IPS is always an on-premises hardware appliance.",
        ],
        answer: 2,
        explanation: "An IDS (Intrusion Detection System) watches traffic and raises an alert — it's a passive tap. An IPS (Intrusion Prevention System) sits inline in the traffic path, so besides alerting it can drop or reset the malicious connection. Detection vs. prevention is the distinction; neither is defined by encryption, location, or cloud-vs-appliance.",
        xp: 15,
      },
      {
        id: "st_03",
        question: "How does an EDR platform go beyond traditional antivirus (AV)?",
        options: [
          "EDR only scans inbound email attachments, whereas AV scans every file written to the disk.",
          "EDR blocks network ports at the firewall, whereas AV inspects the content of individual packets.",
          "EDR encrypts the endpoint's local disk, whereas AV is responsible for managing the decryption keys.",
          "EDR records process, file, and network activity so analysts can investigate and respond — not just block known signatures.",
        ],
        answer: 3,
        explanation: "Classic AV matches files against a signature database and blocks known-bad ones. EDR (Endpoint Detection and Response) continuously records endpoint telemetry — the process tree, file writes, network connections, registry changes — so an analyst can hunt, investigate a live incident, and respond (isolate the host, kill a process) even when there's no known signature.",
        xp: 15,
      },
      {
        id: "st_04",
        question: "What is the core function of a SIEM?",
        options: [
          "It centralises logs from many sources and correlates them to surface security alerts for analysts.",
          "It isolates a single compromised endpoint from the rest of the network on demand.",
          "It filters which websites employees are allowed to browse to from the office network.",
          "It stores encrypted backups of critical servers so they can be restored after an outage.",
        ],
        answer: 0,
        explanation: "A SIEM (Security Information and Event Management) ingests logs from firewalls, endpoints, cloud, identity providers and more, normalises them, and runs correlation rules to raise alerts a human can triage. It is the SOC's central nervous system. Endpoint isolation is EDR, web filtering is a proxy, and backups are a DR function.",
        xp: 10,
      },
      {
        id: "st_05",
        question: "A SOC adopts a SOAR platform primarily to…",
        options: [
          "…replace its human analysts entirely with a fully autonomous decision-making engine.",
          "…store external threat-intelligence feeds and share indicators with other organisations.",
          "…automate and orchestrate repetitive response steps across its tools using playbooks.",
          "…provide a perimeter appliance that inspects and filters traffic at the network edge.",
        ],
        answer: 2,
        explanation: "SOAR (Security Orchestration, Automation and Response) runs playbooks that stitch tools together — e.g. on a phishing alert, automatically detonate the URL, pull the sender's other emails, block the domain, and open a ticket. It speeds up and standardises response; it augments analysts rather than replacing them.",
        xp: 15,
      },
      {
        id: "st_06",
        question: "What does a Web Application Firewall (WAF) protect against?",
        options: [
          "It stops malware from executing on the web server's underlying operating system.",
          "It inspects HTTP/HTTPS requests to a web app and blocks attacks like SQL injection and XSS.",
          "It encrypts the connection between the user's browser and the server using a TLS certificate.",
          "It spreads incoming requests evenly across several backend web servers to balance load.",
        ],
        answer: 1,
        explanation: "A WAF sits in front of a web application and inspects the actual HTTP requests, blocking application-layer attacks — SQL injection, cross-site scripting (XSS), path traversal, and similar. A regular network firewall works at IP/port level and wouldn't see these. TLS termination and load balancing are separate functions.",
        xp: 10,
      },
      {
        id: "st_07",
        question: "What is the goal of a Data Loss Prevention (DLP) system?",
        options: [
          "To recover files after a ransomware attack has already encrypted them on the network.",
          "To detect and remove malware that is hidden inside documents and spreadsheets.",
          "To back up sensitive databases to an offsite location on a nightly schedule.",
          "To detect and block sensitive data — like ID numbers or card data — from leaving the organisation.",
        ],
        answer: 3,
        explanation: "DLP inspects data in motion (email, web uploads, USB) and at rest for sensitive patterns — PII, payment card numbers, source code — and blocks or alerts when it would leave the organisation. It's about exfiltration and accidental leakage, not recovery, malware removal, or backups.",
        xp: 10,
      },
      {
        id: "st_08",
        question: "What is the main purpose of a corporate VPN?",
        options: [
          "To create an encrypted tunnel so a remote worker can reach internal resources safely over the internet.",
          "To scan every file an employee downloads against a database of known malware signatures.",
          "To correlate authentication logs and flag impossible-travel sign-ins across regions.",
          "To filter spam and phishing messages out before they ever reach the user's inbox.",
        ],
        answer: 0,
        explanation: "A VPN (Virtual Private Network) builds an encrypted tunnel between the user's device and the corporate network, so traffic crossing the public internet is protected and the remote worker appears to be 'inside'. The distractors describe antivirus, UEBA/identity analytics, and an email security gateway.",
        xp: 10,
      },
      {
        id: "st_09",
        question: "A Secure Web Gateway (web proxy) is mainly used to…",
        options: [
          "…authenticate users against Active Directory using Kerberos tickets.",
          "…detect lateral movement between servers inside the data centre.",
          "…inspect and filter users' outbound web traffic, blocking malicious or disallowed sites.",
          "…encrypt the data stored at rest on employee laptops and mobile phones.",
        ],
        answer: 2,
        explanation: "A Secure Web Gateway (forward proxy) sits between users and the internet, inspecting outbound web requests to enforce policy — block known-bad domains, malware downloads, and disallowed categories, and log where users went. It's outbound web control, distinct from a WAF, which protects an inbound web application.",
        xp: 10,
      },
      {
        id: "st_10",
        question: "What does Network Access Control (NAC) decide?",
        options: [
          "Which files on a shared server a given user is allowed to open or to edit.",
          "Whether a device may join the network at all, based on its identity and compliance posture.",
          "Which firewall rule should apply to a packet leaving the corporate perimeter.",
          "How long the collected security logs are retained before they are deleted.",
        ],
        answer: 1,
        explanation: "NAC controls admission to the network: when a device connects (via 802.1X, for example) it checks the device's identity and posture — is it managed, patched, running AV? — and grants, quarantines, or denies access accordingly. It keeps rogue and non-compliant devices off the network, a key zero-trust control.",
        xp: 10,
      },
      {
        id: "st_11",
        question: "What does XDR add compared with EDR on its own?",
        options: [
          "It restricts protection to cloud workloads only and stops covering on-premises endpoints.",
          "It replaces the SIEM entirely by storing raw logs for long-term compliance retention.",
          "It is simply a new marketing name for antivirus, with no additional data sources.",
          "It correlates detections across endpoint, email, network, and cloud into a single incident.",
        ],
        answer: 3,
        explanation: "EDR sees the endpoint. XDR (Extended Detection and Response) stitches endpoint telemetry together with email, network, identity, and cloud signals so one attack showing up in several places becomes a single correlated incident instead of scattered alerts. It broadens visibility; it isn't cloud-only, a SIEM replacement, or rebranded AV.",
        xp: 15,
      },
      {
        id: "st_12",
        question: "An analyst needs to walk the full process tree and network connections on a compromised laptop to investigate it. Which tool is built for that?",
        options: [
          "EDR — it records endpoint process, file, and network activity for investigation and response.",
          "WAF — it inspects inbound HTTP requests aimed at a public web application.",
          "DLP — it detects and blocks sensitive data from leaving the organisation.",
          "NAC — it decides whether a device is allowed to join the network.",
        ],
        answer: 0,
        explanation: "The endpoint's own execution detail — process ancestry, command lines, network connections, file writes — is exactly what EDR captures, which is why an investigation of a compromised host starts there. A WAF, DLP, and NAC each solve a different problem and don't give you the host's process story.",
        xp: 10,
      },
      {
        id: "st_13",
        question: "What is a honeypot used for?",
        options: [
          "To cache frequently visited websites so that they load faster for employees.",
          "To store the passwords of privileged accounts inside an encrypted vault.",
          "To act as a decoy system that lures attackers so their activity can be detected and studied.",
          "To distribute software patches and updates to endpoints across the enterprise.",
        ],
        answer: 2,
        explanation: "A honeypot is a deliberately exposed decoy system with no legitimate business use — so any interaction with it is inherently suspicious. It draws attackers in to detect them early and learn their tools and techniques, with very few false positives. The distractors describe a web cache, a password vault (PAM), and a patch-management system.",
        xp: 10,
      },
    ],
  },
];
