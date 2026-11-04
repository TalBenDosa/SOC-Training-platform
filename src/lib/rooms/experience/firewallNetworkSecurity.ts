import type { RoomExperience } from "./types";

// "Operation Zone Wall" for the "firewall-network-security" room.
// Script: docs/campaign/16-firewall-network-security.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Meridale Clinics (fictional). Lab data differs from the graded tasks: the
// PAN-OS rulebase is not the reading's 10.0.1.50 example and asks which rule
// matches, not how stateful inspection works (q2); the zone and WAF labs never
// walk a DMZ breach to the database (q1); the segmentation drill is an IoT
// camera on another matrix, not q3's workstation SMB worm; the Suricata drill
// is a blocked MSSQL probe, not la1's Nmap SYN scan of 203.0.113.10; and the
// log queue avoids the reading's port-4444 example.
export const FIREWALL_NETWORK_SECURITY: RoomExperience = {
  roomId: "firewall-network-security",
  codename: "Operation Zone Wall",
  theme: "netsec",
  handler: { name: "Mateo Vidal", role: "Network Security Engineer, Meridale Clinics" },
  briefing: [
    "Meridale Clinics. Thirty-one clinics, one patient portal, and a network built in zones like a hospital is built in wards.",
    "Every packet that crosses a zone line meets a rule. Every rule leaves a log.",
    "Mateo Vidal runs the firewalls. He wants an analyst who can tell which rule fired, which zone holds, and which 'allow' should never have happened.",
    "Test the rules, walk the zones, and read the wire.",
  ],
  mission: "Test packets against a real PAN-OS rulebase, place every system in its zone, read a WAF block, check whether segmentation contains a compromised device, decode a Suricata alert, and triage a queue of firewall logs where 'allowed' does not mean 'safe'.",
  estimate: "~40 min",
  look: { primary: "#f97316", secondary: "#22d3ee", warn: "#f43f5e" },
  scene: "zonewall",
  layout: "stage",
  stations: [
    {
      id: "rules",
      label: "Rules of the Door",
      topic: "Packet filter, stateful, NGFW · rules read top to bottom, first match wins",
      tagline: "Ask the firewall which rule a packet would hit",
      building: "control",
      taskIds: ["fw-r1", "fw-q2"],
    },
    {
      id: "zones",
      label: "Zones and Sensors",
      topic: "IDS vs IPS · DMZ · VLAN segmentation · WAF",
      tagline: "Put every system in its zone, then read a WAF block",
      building: "lab",
      taskIds: ["fw-r2"],
    },
    {
      id: "contain",
      label: "Hold the Line",
      topic: "What a DMZ and inter-VLAN rules do when something is already compromised",
      tagline: "Check whether the zones contain a breach",
      building: "vault",
      taskIds: ["fw-q1", "fw-q3"],
    },
    {
      id: "wire",
      label: "Read the Wire",
      topic: "Firewall log fields · allow is not safe · IDS alerts and scan types",
      tagline: "Triage firewall logs, then decode a scan alert",
      building: "ticket",
      taskIds: ["fw-r3", "fw-la1", "fw-f1"],
      boss: true,
    },
  ],
  personas: {
    "fw-q1": { name: "Mateo Vidal", role: "Network Security Engineer", line: "Say the portal server in the DMZ falls. What still stands between the attacker and the patient database?" },
    "fw-q2": { name: "Mateo Vidal", role: "Network Security Engineer", line: "Quick one before you touch the rulebase: stateful versus stateless." },
    "fw-q3": { name: "Mateo Vidal", role: "Network Security Engineer", line: "Ransomware on a workstation, SMB everywhere. How far does it get?" },
  },
  briefings: {
    // ── Reading 1: firewall types and rule order ──
    "fw-r1": [
      {
        kind: "terminal",
        title: "Which Rule Fires?",
        prompt: "Meridale's Palo Alto firewall can tell you which rule a packet would match before you send it. Read the rulebase, then test four packets.",
        shell: "bash",
        host: "admin@PA-3220-HQ>",
        commands: [
          { match: "show\\s+running\\s+security-policy", help: "show running security-policy                       the rulebase, top to bottom",
            output: "\"DNS-Out; index: 1\" {\n        from trust; source [ 10.1.0.0/16 ];\n        to untrust; destination any;\n        application/service [ dns/udp/any/53 ];\n        action allow;\n}\n\"Block-Tor; index: 2\" {\n        from trust; source any;\n        to untrust; destination any;\n        application/service [ tor/tcp/any/any ];\n        action deny;\n}\n\"Web-Out; index: 3\" {\n        from trust; source any;\n        to untrust; destination any;\n        application/service [ web-browsing/tcp/any/80 ssl/tcp/any/443 ];\n        action allow;\n}\n\"SSH-Admins; index: 4\" {\n        from trust; source [ 10.1.9.0/24 ];\n        to dmz; destination [ 172.16.10.0/24 ];\n        application/service [ ssh/tcp/any/22 ];\n        action allow;\n}\n\"Deny-Trust-to-DMZ; index: 5\" {\n        from trust; source any;\n        to dmz; destination any;\n        application/service any/any/any/any;\n        action deny;\n}\n(then the built-in interzone-default: deny)" },
          { match: "test\\s+security-policy-match\\s+.*source\\s+10\\.1\\.5\\.20\\s+.*destination\\s+203\\.0\\.113\\.80\\s+.*", help: "test security-policy-match from trust to untrust source 10.1.5.20 destination 203.0.113.80 protocol 6 destination-port 443",
            output: "\"Web-Out; index: 3\" {\n        from trust;\n        source any;\n        to untrust;\n        destination any;\n        application/service [ web-browsing/tcp/any/80 ssl/tcp/any/443 ];\n        action allow;\n        terminal yes;\n}" },
          { match: "test\\s+security-policy-match\\s+.*source\\s+10\\.1\\.5\\.20\\s+.*destination\\s+172\\.16\\.10\\.5\\s+.*", help: "test security-policy-match from trust to dmz source 10.1.5.20 destination 172.16.10.5 protocol 6 destination-port 22",
            output: "\"Deny-Trust-to-DMZ; index: 5\" {\n        from trust;\n        source any;\n        to dmz;\n        destination any;\n        application/service any/any/any/any;\n        action deny;\n        terminal yes;\n}" },
          { match: "test\\s+security-policy-match\\s+.*source\\s+10\\.1\\.9\\.14\\s+.*destination\\s+172\\.16\\.10\\.5\\s+.*", help: "test security-policy-match from trust to dmz source 10.1.9.14 destination 172.16.10.5 protocol 6 destination-port 22",
            output: "\"SSH-Admins; index: 4\" {\n        from trust;\n        source 10.1.9.0/24;\n        to dmz;\n        destination 172.16.10.0/24;\n        application/service [ ssh/tcp/any/22 ];\n        action allow;\n        terminal yes;\n}" },
          { match: "test\\s+security-policy-match\\s+.*source\\s+10\\.1\\.5\\.20\\s+.*destination\\s+198\\.51\\.100\\.9\\s+.*", help: "test security-policy-match from trust to untrust source 10.1.5.20 destination 198.51.100.9 protocol 6 destination-port 3389",
            output: "\"interzone-default\" {\n        from any;\n        source any;\n        to any;\n        destination any;\n        action deny;\n}\n(no configured rule matched TCP 3389 to the internet)" },
        ],
        objectives: [
          { id: "web", task: "A clinic PC (10.1.5.20) opens HTTPS to 203.0.113.80. Which rule fires?", hint: "test security-policy-match from trust to untrust source 10.1.5.20 destination 203.0.113.80 protocol 6 destination-port 443", answer: ["Web-Out", "3"], why: "Rules 1 and 2 don't match ssl on 443, so the first match is rule 3." },
          { id: "ssh1", task: "The same PC tries SSH to a DMZ server (172.16.10.5). Which rule fires?", hint: "test security-policy-match from trust to dmz source 10.1.5.20 destination 172.16.10.5 protocol 6 destination-port 22", answer: ["Deny-Trust-to-DMZ", "5"], why: "SSH-Admins only allows 10.1.9.0/24. This PC is outside it, so the first match is the deny below." },
          { id: "ssh2", task: "An admin laptop (10.1.9.14) makes the same SSH connection. Which rule fires now?", hint: "test security-policy-match from trust to dmz source 10.1.9.14 destination 172.16.10.5 protocol 6 destination-port 22", answer: ["SSH-Admins", "4"], why: "Same destination, different source: rule 4 matches first, so the deny under it never gets a say. Order is the policy." },
          { id: "rdp", task: "The PC tries RDP (3389) to an internet address. What decides it?", hint: "test security-policy-match from trust to untrust source 10.1.5.20 destination 198.51.100.9 protocol 6 destination-port 3389", answer: ["interzone-default", "default deny", "the default deny", "interzone default"], why: "Nothing in the rulebase matches, so the built-in default deny drops it. Default-deny is what makes a rulebase an allow-list." },
        ],
      },
    ],
    // ── Reading 2: IDS/IPS, DMZ, VLANs, WAF ──
    "fw-r2": [
      {
        kind: "sort",
        title: "Which Zone?",
        prompt: "Meridale's network is being rebuilt in zones. Place each system where it belongs.",
        buckets: [
          { id: "dmz", label: "DMZ: reachable from the internet" },
          { id: "srv", label: "Server VLAN" },
          { id: "ws", label: "Workstation VLAN" },
          { id: "iot", label: "IoT VLAN" },
          { id: "guest", label: "Guest Wi-Fi" },
        ],
        items: [
          { id: "a", text: "Patient portal reverse proxy", bucket: "dmz", why: "Patients reach it from the internet, so it sits in the buffer zone, not next to the records." },
          { id: "b", text: "Electronic health records database", bucket: "srv", why: "The crown jewels: reachable only from approved systems inside." },
          { id: "c", text: "Reception desk PCs", bucket: "ws", why: "Staff endpoints: they browse, open email, and are phished first." },
          { id: "d", text: "Waiting-room smart TVs and door-badge readers", bucket: "iot", why: "Devices that rarely get patched: keep them away from servers." },
          { id: "e", text: "Patients' phones on clinic Wi-Fi", bucket: "guest", why: "Unknown devices: internet only, isolated from everything." },
          { id: "f", text: "Inbound mail gateway", bucket: "dmz", why: "It receives mail from the internet before passing it inward." },
          { id: "g", text: "Domain controllers", bucket: "srv", why: "Production infrastructure, never exposed directly." },
        ],
      },
      {
        kind: "anatomy",
        title: "Anatomy of a WAF Block",
        prompt: "The patient portal sits behind AWS WAF. Here's one blocked request, field by field.",
        source: "AWS WAF · web ACL log · meridale-portal-acl",
        fields: [
          { key: "timestamp", value: "1793866215000", label: "When", note: "Epoch milliseconds: 13 digits." },
          { key: "action", value: "BLOCK", label: "Outcome", note: "Inline, so it could stop the request, not just report it." },
          { key: "terminatingRuleId", value: "AWS-AWSManagedRulesSQLiRuleSet", label: "Which rule", note: "AWS's managed SQL injection rule group." },
          { key: "terminatingRuleMatchDetails", value: "SQL_INJECTION in QUERY_STRING", label: "What matched" },
          { key: "httpRequest.clientIp", value: "198.51.100.66", label: "From where" },
          { key: "httpRequest.httpMethod", value: "GET" },
          { key: "httpRequest.uri", value: "/appointments/search", label: "Target" },
          { key: "httpRequest.args", value: "clinic=7' OR 1=1--", label: "The payload", note: "A quote to break out of the SQL string, an always-true condition, and -- to comment out the rest." },
          { key: "httpRequest.country", value: "NL" },
        ],
        summary: "A network firewall saw an ordinary HTTPS request to an allowed port. Only a Layer 7 control that reads the request could see the injection inside it.",
      },
    ],
    // Drill before q3: segmentation, tested on a different device and matrix.
    "fw-q3": [
      {
        kind: "worksheet",
        title: "Does the Wall Hold?",
        prompt: "A waiting-room camera on the IoT VLAN was compromised and is probing the network. Read the inter-VLAN policy and decide what it can reach.",
        caption: "Meridale inter-VLAN policy · source IoT VLAN 50",
        columns: ["destination", "allowed services from VLAN 50", "everything else"],
        rows: [
          ["VLAN 20 Servers: NVR-01 (video recorder)", "RTSP tcp/554", "deny"],
          ["VLAN 20 Servers: FS-01 (file server)", "none", "deny"],
          ["VLAN 10 Workstations", "none", "deny"],
          ["Internet", "NTP udp/123 to time.meridale.example", "deny"],
        ],
        questions: [
          { id: "fs", q: "The camera tries SMB (tcp/445) to FS-01. Allowed? (yes/no)", hint: "Look at FS-01's row.", answer: ["no"], why: "Nothing from VLAN 50 is allowed to FS-01. The infection stays on its island." },
          { id: "nvr", q: "Which single service can it still use toward the servers?", hint: "The only allow in the server rows.", answer: ["RTSP", "554", "tcp/554", "rtsp tcp/554"], why: "Least privilege: the camera can stream to its recorder and nothing else. Watch NVR-01; it's the one path left." },
          { id: "c2", q: "Could it call out to an attacker's server on tcp/443? (yes/no)", hint: "Internet row.", answer: ["no"], why: "Egress filtering: only NTP to one internal time source. No path out for command and control." },
        ],
      },
    ],
    // ── Reading 3: reading firewall logs ──
    "fw-r3": [
      {
        kind: "queue",
        title: "Allowed Is Not Safe",
        prompt: "Overnight firewall logs from the HQ edge. Some denies are just noise; some allows are the real story.",
        console: "Firewall log review · PA-3220-HQ · 00:00-06:00",
        actions: [
          { id: "esc", label: "Escalate", tone: "escalate" },
          { id: "ok", label: "Expected, close", tone: "close" },
        ],
        alerts: [
          { id: "ssh", time: "01:12", severity: "Low", rule: "deny · inbound tcp/22", entity: "198.51.100.140 > 172.16.10.5",
            fields: [{ k: "action", v: "drop" }, { k: "rule", v: "interzone-default" }, { k: "bytes_received", v: "0" }, { k: "count (1h)", v: "3" }],
            context: "An internet address knocking on SSH, dropped by the default deny.", answer: "ok", why: "Background internet noise, correctly dropped. Worth a blocklist only if it becomes a flood." },
          { id: "smbout", time: "02:40", severity: "Medium", rule: "allow · outbound tcp/445", entity: "10.1.5.33 > 203.0.113.212",
            fields: [{ k: "action", v: "allow" }, { k: "rule", v: "Legacy-Any-Out" }, { k: "app", v: "ms-ds-smb" }, { k: "bytes_sent", v: "18,422" }],
            context: "A reception PC talking SMB to an internet address, allowed by an old catch-all rule.", answer: "esc", why: "SMB never needs to leave the network; it can leak NTLM hashes to an attacker's server. And Legacy-Any-Out shouldn't exist." },
          { id: "dns", time: "03:00", severity: "Low", rule: "allow · outbound udp/53", entity: "10.1.0.53 > 9.9.9.9",
            fields: [{ k: "action", v: "allow" }, { k: "rule", v: "DNS-Out" }, { k: "source", v: "internal resolver" }, { k: "bytes", v: "steady" }],
            context: "The internal DNS resolver forwarding queries upstream.", answer: "ok", why: "Exactly the job the rule was written for." },
          { id: "upload", time: "04:17", severity: "Low", rule: "allow · outbound tcp/443", entity: "10.1.20.8 > 198.51.100.200",
            fields: [{ k: "action", v: "allow" }, { k: "rule", v: "Web-Out" }, { k: "host", v: "EHR-DB-02" }, { k: "bytes_sent", v: "2.1 GB" }, { k: "duration", v: "3,940 s" }],
            context: "The health-records database server uploaded 2.1 GB over HTTPS to an unknown address at 4 a.m.", answer: "esc", why: "A server that never browses, sending gigabytes out: possible exfiltration. bytes_sent is the field that tells you." },
        ],
      },
    ],
    // Drill before the graded IDS alert: a Suricata alert from an inline sensor.
    "fw-la1": [
      {
        kind: "anatomy",
        title: "Anatomy of a Suricata Alert",
        prompt: "Before the graded alert: one from Meridale's inline Suricata sensor, in its native eve.json format.",
        source: "Suricata · eve.json · event_type alert · sensor ids-edge-01",
        fields: [
          { key: "timestamp", value: "2026-11-04T01:58:20.114+0000", label: "When" },
          { key: "event_type", value: "alert" },
          { key: "src_ip", value: "203.0.113.150", label: "From" },
          { key: "dest_ip", value: "172.16.10.21", label: "To", note: "A DMZ address." },
          { key: "dest_port", value: "1433", label: "Service", note: "Microsoft SQL Server: never meant to face the internet." },
          { key: "proto", value: "TCP" },
          { key: "alert.signature", value: "ET SCAN Suspicious inbound to MSSQL port 1433", label: "What it matched", note: "An Emerging Threats signature." },
          { key: "alert.signature_id", value: "2010935" },
          { key: "alert.category", value: "Potentially Bad Traffic" },
          { key: "alert.action", value: "blocked", label: "What the sensor did", note: "This sensor runs inline, so it dropped the probe. Read this field on every alert: it tells you whether the attack was stopped or only seen." },
        ],
        summary: "Signature, target and verdict in one record. Now read the graded alert and check its action field the same way.",
      },
    ],
  },
};
