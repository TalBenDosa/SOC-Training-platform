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
        kind: "intercept",
        title: "First Match Wins",
        prompt: "Mateo pastes tonight's rulebase, top to bottom. 1: deny 10.1.77.0/24 (waiting-room kiosks) to anywhere. 2: allow trust to the internet on web-browsing and ssl (80, 443). 3: allow 10.1.9.0/24 to the DMZ 172.16.10.0/24 on ssh (22). 4: deny trust to DMZ, any service. 5: allow 10.1.0.53 to the internet on dns (udp/53). Nothing else is written, so the default deny catches the rest. Block what the firewall would deny, let through what it would allow.",
        protect: "the PA-3220 edge",
        blockLabel: "Deny",
        passLabel: "Allow",
        seconds: 11,
        items: [
          { id: "kiosk", text: "10.1.77.12 to 203.0.113.9 tcp/443", sub: "waiting-room kiosk browsing out", bad: true, why: "Rule 2 would allow web, but rule 1 matches first and denies the whole kiosk range. First match wins, so rule 2 never sees it." },
          { id: "pcweb", text: "10.1.5.20 to 203.0.113.80 tcp/443", sub: "clinic PC, HTTPS", bad: false, why: "Rule 1 does not match this source, rule 2 matches ssl on 443 and allows. The first match decides." },
          { id: "admin", text: "10.1.9.14 to 172.16.10.5 tcp/22", sub: "admin laptop, SSH to the DMZ", bad: false, why: "The source is inside 10.1.9.0/24 and the service is ssh, so rule 3 allows it before the DMZ deny in rule 4 is reached." },
          { id: "pcssh", text: "10.1.5.20 to 172.16.10.5 tcp/22", sub: "clinic PC, SSH to the DMZ", bad: true, why: "Same destination as the admin, wrong source. Rule 3 needs 10.1.9.0/24, so the first match is the DMZ deny in rule 4." },
          { id: "adminrdp", text: "10.1.9.14 to 172.16.10.5 tcp/3389", sub: "the same admin laptop, RDP", bad: true, why: "Being an admin is not enough: rule 3 allows ssh only. RDP falls through to rule 4, the trust to DMZ deny." },
          { id: "resolver", text: "10.1.0.53 to 198.51.100.53 udp/53", sub: "internal resolver forwarding", bad: false, why: "Exactly what rule 5 was written for: the resolver's source address and dns." },
          { id: "rdpout", text: "10.1.5.20 to 198.51.100.9 tcp/3389", sub: "clinic PC, RDP to the internet", bad: true, why: "No rule mentions RDP to the internet, so the built-in default deny drops it. Default deny is what turns a rulebase into an allow-list." },
          { id: "dnspc", text: "10.1.5.31 to 203.0.113.44 udp/53", sub: "a PC asking an outside DNS directly", bad: true, why: "Rule 5 allows DNS only from the resolver 10.1.0.53. This PC's source misses it, no other rule matches, and the default deny applies." },
          { id: "admin2", text: "10.1.9.30 to 172.16.10.9 tcp/22", sub: "another admin, another DMZ host", bad: false, why: "Source in 10.1.9.0/24, destination in 172.16.10.0/24, service ssh: rule 3 matches exactly." },
          { id: "pcweb80", text: "10.1.5.20 to 203.0.113.80 tcp/80", sub: "clinic PC, plain HTTP", bad: false, why: "web-browsing on 80 is in rule 2 beside ssl on 443, so it is allowed. Whether HTTP should be allowed is a policy question, not a matching one." },
        ],
        lesson: "Read top to bottom and stop at the first match: a broad deny above a specific allow wins, a near-match on source or service falls to the next rule, and silence means default deny.",
      },
    ],
    // ── Reading 2: IDS/IPS, DMZ, VLANs, WAF ──
    "fw-r2": [
      {
        kind: "pathway",
        title: "Through the Zones",
        prompt: "A patient checks an appointment on the portal. Mateo wants you to carry that request from the internet to the application server and name every control it meets, so you learn which zone each system really belongs in.",
        goal: "Carry the patient's appointment lookup from the internet to the appointment API on the server VLAN.",
        nodes: [
          { id: "inet", label: "Patient browser", sub: "internet", x: 10, y: 50 },
          { id: "waf", label: "Cloud WAF", sub: "Layer 7 web ACL", x: 28, y: 22 },
          { id: "guest", label: "Clinic guest Wi-Fi", sub: "internet only", x: 28, y: 78 },
          { id: "edge", label: "Edge NGFW", sub: "untrust to DMZ", x: 46, y: 50 },
          { id: "ids", label: "IDS sensor", sub: "SPAN port copy", x: 58, y: 18 },
          { id: "dmz", label: "Portal reverse proxy", sub: "DMZ", x: 62, y: 82 },
          { id: "inner", label: "Inner firewall", sub: "DMZ to servers", x: 76, y: 50 },
          { id: "ws", label: "Reception PCs", sub: "workstation VLAN 10", x: 90, y: 20 },
          { id: "api", label: "Appointment API", sub: "server VLAN 20", x: 90, y: 80 },
        ],
        edges: [["inet", "waf"], ["inet", "guest"], ["waf", "edge"], ["guest", "edge"], ["edge", "ids"], ["edge", "dmz"], ["dmz", "inner"], ["inner", "ws"], ["inner", "api"]],
        route: ["inet", "waf", "edge", "dmz", "inner", "api"],
        notes: {
          inet: "A patient is an unknown device on the internet. Whatever they send must be treated as untrusted from the first byte.",
          waf: "The only control here that reads the request itself. A network firewall sees an allowed HTTPS port, the WAF sees a SQL quote in the query string.",
          edge: "The edge firewall lets the internet reach only the DMZ and only on the published service. It is the line between untrust and the buffer zone.",
          dmz: "The reverse proxy answers the patient, so it must be reachable from the internet and so it lives in the buffer zone, never next to the records.",
          inner: "A second firewall with a narrow rule: the proxy may call the API on one port and nothing else. If the DMZ falls, this is what still stands.",
          api: "The server VLAN is reachable only from approved systems. The patient never speaks to it directly: the proxy asks on their behalf.",
        },
        traps: {
          guest: "Guest Wi-Fi is also an internet-facing network, but it is for patients' phones to reach the internet. It is isolated and has no path to the portal or to any server.",
          ids: "The IDS watches a mirrored copy of traffic and raises alerts. Traffic does not flow through it, so it cannot be a hop. Only an inline IPS sits in the path.",
          ws: "Reception PCs are on the workstation VLAN and are phished first, so no server path leads through them. The inner firewall has no rule from the DMZ to this VLAN.",
        },
        lesson: "Each zone has one job: the WAF reads the request, the edge limits who reaches the DMZ, the DMZ faces the internet, the inner firewall narrows the next step, and servers are never reached directly.",
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
