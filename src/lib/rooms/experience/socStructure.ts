import type { RoomExperience } from "./types";

// "Operation Night Desk" for the "soc-structure" room (rooms-batch-01.ts).
// Script: docs/campaign/03-soc-structure.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// GlobalBank (fictional), the SOC night shift. Lab data differs from the
// graded tasks: the metrics worksheet works hours, not the industry ~200-day
// figure (q2); the queue has no multi-host ransomware outbreak (q3); the SOAR
// screen disables an account rather than quarantining a device (q4); the
// drill decodes a successful 4624 logon, not the graded 4625 failures (la1).
export const SOC_STRUCTURE: RoomExperience = {
  roomId: "soc-structure",
  codename: "Operation Night Desk",
  theme: "soc",
  handler: { name: "Priya Nair", role: "SOC Manager, GlobalBank" },
  briefing: [
    "22:00. GlobalBank Security Operations Center.",
    "Twelve desks, one video wall, five tools, and a night that has only just started.",
    "Priya Nair runs this floor. Tonight she is walking you through it.",
    "By 03:47 you will be sitting at a Tier 1 desk, and an alert will be yours.",
  ],
  mission: "Learn how a SOC really runs: what it does and how it is measured, who sits at which tier, which tool does what, and then work a real night-shift alert from a Tier 1 desk.",
  estimate: "~40 min",
  look: { primary: "#22d3ee", secondary: "#a78bfa", warn: "#fb7185" },
  scene: "socfloor",
  layout: "stage",
  story: {
    intro: { title: "The Floor at 22:00", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/soc-structure/night-desk-intro-0499435e.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/soc-structure/night-desk-intro-be7411cc.jpg" },
    afterStation: {
      tiers: { title: "The Ladder", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/soc-structure/night-desk-ch2-54a5700f.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/soc-structure/night-desk-ch2-71b58802.jpg" },
      tools: { title: "The Stack", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/soc-structure/night-desk-ch3-cbf0d781.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/soc-structure/night-desk-ch3-4376b2f1.jpg" },
      night: { title: "03:47", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/soc-structure/night-desk-finale-027ea530.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/soc-structure/night-desk-finale-45d23dfc.jpg" },
    },
  },
  stations: [
    {
      id: "floor",
      label: "The Floor",
      topic: "What a SOC does · SOC models · MTTD and MTTR · who the SOC works with",
      tagline: "Walk the floor: the SOC's six jobs, how it is built, how it is measured",
      building: "control",
      taskIds: ["soc-struct-r1", "soc-struct-q2"],
    },
    {
      id: "tiers",
      label: "The Tier Ladder",
      topic: "Tier 1, 2 and 3 · other SOC roles · triage · escalation · shift handover",
      tagline: "Sit at a Tier 1 desk, clear a live queue, and hand the shift over properly",
      building: "office",
      taskIds: ["soc-struct-r2", "soc-struct-q1", "soc-struct-q3"],
    },
    {
      id: "tools",
      label: "The Tool Stack",
      topic: "SIEM · EDR · SOAR · TIP · ticketing, and how they work together",
      tagline: "Recognise every tool by its screen, then follow one alert through all of them",
      building: "lab",
      taskIds: ["soc-struct-r3", "soc-struct-m1", "soc-struct-q4"],
    },
    {
      id: "night",
      label: "03:47 at GlobalBank",
      topic: "Triage a real authentication alert from a Tier 1 desk",
      tagline: "The SIEM fires. You are the first analyst to see it",
      building: "ticket",
      taskIds: ["soc-struct-la1"],
      boss: true,
    },
  ],
  personas: {
    "soc-struct-q2": {
      name: "Priya Nair",
      role: "SOC Manager",
      line: "The board will ask me this number on Monday. Tell me what the industry usually sees.",
    },
    "soc-struct-q1": {
      name: "Priya Nair",
      role: "SOC Manager",
      line: "Five hundred alerts overnight, and you are on the front line. What is your job on each one?",
    },
    "soc-struct-q3": {
      name: "Tom Becker",
      role: "Tier 2 Lead",
      line: "Something big is spreading on the network. Who should be driving this?",
    },
    "soc-struct-q4": {
      name: "Tom Becker",
      role: "Tier 2 Lead",
      line: "I am tired of clicking the same ten steps for every bad IP. Which tool fixes that?",
    },
  },
  briefings: {
    // ── Reading 1: what a SOC is ──
    "soc-struct-r1": [
      {
        kind: "sequence",
        title: "One Incident, Six Jobs",
        prompt: "Last month a payment server leaked data. Priya shows you what the SOC did. Put its actions in the order they happened.",
        items: [
          { id: "contain", text: "Block the destination IP at the firewall and disable the service account", note: "Contain: stop it spreading or leaking further." },
          { id: "report", text: "Write the incident report for Legal and the CISO", note: "Report: document everything that happened and was done." },
          { id: "monitor", text: "A wall tile shows an outbound traffic spike from PAY-SRV-03", note: "Monitor: someone, or something, has to notice first." },
          { id: "remediate", text: "Reset the credentials and patch the exposed service", note: "Remediate: remove the cause so it cannot happen again." },
          { id: "triage", text: "The analyst checks: is data really leaving, or is it a backup job?", note: "Triage: real threat or false alarm?" },
          { id: "investigate", text: "Who, what, when: a service account copying files since 01:12", note: "Investigate: build the full picture." },
        ],
        order: ["monitor", "triage", "investigate", "contain", "remediate", "report"],
        doneNote: "Monitor, triage, investigate, contain, remediate, report: the six jobs of every SOC, in the order an incident moves through them.",
      },
      {
        kind: "match",
        title: "Which SOC Model?",
        prompt: "Four organisations, four ways to run security monitoring. Match each one to its SOC model.",
        pairs: [
          { id: "inhouse", left: "A national bank employs its own 40 analysts on site, 24/7", right: "In-house SOC", why: "Full control, highest cost: common in banks, government and healthcare." },
          { id: "mssp", left: "A 60-person law firm pays a specialist company to watch its alerts", right: "MSSP", why: "A Managed Security Service Provider monitors many clients at once, so it is cheaper." },
          { id: "vsoc", left: "Analysts in four countries log in to shared cloud tools; there is no SOC room", right: "Virtual SOC", why: "No physical location: the tools are central, the people are remote." },
          { id: "hybrid", left: "A retailer watches its own payment systems and outsources the night shift", right: "Hybrid SOC", why: "Critical work in-house, overflow or specialist work outsourced." },
        ],
      },
      {
        kind: "worksheet",
        title: "The Metrics Board",
        prompt: "Every SOC is judged on two numbers. Work them out from last month's four incidents.",
        caption: "GlobalBank SOC · incidents, October",
        columns: ["incident", "attack started", "detected", "contained"],
        rows: [
          ["INC-101", "Oct 02 08:00", "Oct 02 14:00", "Oct 02 15:00"],
          ["INC-102", "Oct 05 22:00", "Oct 06 02:00", "Oct 06 04:00"],
          ["INC-103", "Oct 09 09:00", "Oct 10 09:00", "Oct 10 12:00"],
          ["INC-104", "Oct 14 13:00", "Oct 14 15:00", "Oct 14 17:00"],
        ],
        questions: [
          { id: "ttd103", q: "How many hours passed between the start of INC-103 and its detection?", hint: "Time to detect = detected minus attack started. Oct 09 09:00 to Oct 10 09:00.", answer: ["24", "24h", "24 hours", "24 hrs"], why: "A full day. For that whole day an attacker was inside and nobody knew." },
          { id: "mttd", q: "What is the Mean Time to Detect (MTTD) for the month, in hours?", hint: "Times to detect: 6, 4, 24 and 2 hours. Add them and divide by 4.", answer: ["9", "9h", "9 hours", "9 hrs"], why: "(6 + 4 + 24 + 2) / 4 = 9 hours. A healthy number for a SOC: the shorter the time to detect, the less an attacker can do." },
          { id: "mttr", q: "What is the Mean Time to Respond (MTTR), detection to containment, in hours?", hint: "Times to respond: 1, 2, 3 and 2 hours. Add them and divide by 4.", answer: ["2", "2h", "2 hours", "2 hrs"], why: "(1 + 2 + 3 + 2) / 4 = 2 hours. MTTR measures how fast the team acts once it knows." },
          { id: "worst", q: "Which single incident pulls the MTTD up the most?", hint: "Which incident has the longest time to detect?", answer: ["INC-103", "inc103", "103", "inc 103"], why: "One slow detection doubles the average. That is why SOCs tune detection rules and hunt: to shorten the worst cases." },
        ],
      },
      {
        kind: "sort",
        title: "Who Do You Call?",
        prompt: "The SOC never works alone. For each situation, pick the team the SOC brings in.",
        buckets: [
          { id: "it", label: "IT" },
          { id: "legal", label: "Legal & Compliance" },
          { id: "hr", label: "HR" },
          { id: "exec", label: "Executives" },
          { id: "police", label: "Law enforcement" },
        ],
        items: [
          { id: "patch", text: "A server needs a patch and a reboot to close the hole", bucket: "it", why: "IT owns and fixes the systems; the SOC tells them what and why." },
          { id: "notify", text: "Customer card data may have left: must the regulator be told, and by when?", bucket: "legal", why: "Breach notification deadlines are a legal question." },
          { id: "insider", text: "An employee is suspected of copying client files before resigning", bucket: "hr", why: "Insider cases involve HR from the start." },
          { id: "ceo", text: "The CEO needs a three-line status before the press calls", bucket: "exec", why: "Leadership is briefed during major incidents." },
          { id: "extort", text: "A criminal group demands payment to not publish stolen data", bucket: "police", why: "Extortion is a crime: law enforcement is brought in." },
          { id: "rule", text: "A firewall rule must change to block the attacker's range", bucket: "it", why: "Network changes go through the teams that run the network." },
        ],
      },
    ],
    // ── Reading 2: the tier model ──
    "soc-struct-r2": [
      {
        kind: "queue",
        title: "Night Queue",
        prompt: "You have the Tier 1 desk. Five alerts are waiting. For each one: close it as a false positive, or escalate it to Tier 2.",
        console: "SIEM · Incident queue · GlobalBank SOC",
        actions: [
          { id: "close", label: "Close: false positive", tone: "close" },
          { id: "escalate", label: "Escalate to Tier 2", tone: "escalate" },
        ],
        alerts: [
          {
            id: "scan", time: "02:04", severity: "Medium", rule: "Port scan from internal host", entity: "VULN-SCAN-01",
            fields: [{ k: "src_ip", v: "10.40.1.5 (VULN-SCAN-01)" }, { k: "targets", v: "1,024 hosts, TCP 1-1024" }, { k: "schedule", v: "Weekly vulnerability scan, Tue 02:00" }, { k: "change", v: "CHG-4471 approved" }],
            context: "The source is the bank's own vulnerability scanner, running at its scheduled time under an approved change.",
            answer: "close", why: "Authorised activity on schedule with a change ticket: a false positive for this rule. Note the change ID in the ticket and close it.",
          },
          {
            id: "macro", time: "02:17", severity: "High", rule: "Office application spawned PowerShell", entity: "WS-FIN-118 · m.cole",
            fields: [{ k: "parent", v: "WINWORD.EXE" }, { k: "child", v: "powershell.exe -nop -w hidden -enc SQBFAFgA..." }, { k: "network", v: "203.0.113.61:443 shortly after" }, { k: "user", v: "m.cole (Finance)" }],
            context: "Word started a hidden, encoded PowerShell command, and the machine then reached an unknown external server.",
            answer: "escalate", why: "Word has no business launching hidden encoded PowerShell. This is a likely compromise: open a ticket with these facts and escalate to Tier 2 now.",
          },
          {
            id: "travel", time: "02:31", severity: "Low", rule: "Impossible travel", entity: "a.khan",
            fields: [{ k: "sign-in 1", v: "Tel Aviv, 01:50" }, { k: "sign-in 2", v: "Frankfurt, 02:30" }, { k: "network", v: "Company VPN egress, Frankfurt" }, { k: "MFA", v: "Approved on registered phone" }],
            context: "The second sign-in comes from the bank's own VPN exit in Frankfurt, and the user approved MFA on their usual device.",
            answer: "close", why: "The 'travel' is the VPN, not a person flying. Known egress plus MFA on the registered device: false positive. Suggest excluding the VPN egress from this rule.",
          },
          {
            id: "lockouts", time: "02:44", severity: "High", rule: "Many accounts locked out from one host", entity: "SRV-APP-07",
            fields: [{ k: "accounts", v: "23 different users" }, { k: "source", v: "10.40.8.20 (SRV-APP-07)" }, { k: "window", v: "6 minutes" }, { k: "maintenance", v: "None scheduled" }],
            context: "An application server that never signs users in is failing logons for 23 different accounts in six minutes.",
            answer: "escalate", why: "One host trying many accounts looks like password spraying from a compromised server. Scope and containment are Tier 2 work: escalate.",
          },
          {
            id: "eicar", time: "03:02", severity: "Medium", rule: "Antivirus detection", entity: "WS-IT-004",
            fields: [{ k: "file", v: "eicar.com" }, { k: "threat", v: "EICAR test file" }, { k: "user", v: "it.admin2" }, { k: "change", v: "CHG-4480: AV agent test" }],
            context: "IT is testing the new antivirus agent with the industry-standard harmless test file, under a change ticket.",
            answer: "close", why: "EICAR is a harmless test string every antivirus detects on purpose. With the change ticket, close it as expected activity.",
          },
        ],
      },
      {
        kind: "sort",
        title: "Hand Over the Shift",
        prompt: "06:00. You are handing over to the morning shift. Bad handovers have let attackers slip through the gap. What goes in the note?",
        buckets: [
          { id: "in", label: "Goes in the handover" },
          { id: "out", label: "Leave it out" },
        ],
        items: [
          { id: "open", text: "INC-2231 on WS-FIN-118: Tier 2 is still containing it", bucket: "in", why: "Open incidents in progress always go first." },
          { id: "waiting", text: "The SRV-APP-07 escalation is waiting for the app owner's reply", bucket: "in", why: "Escalated tickets awaiting action must not be forgotten." },
          { id: "intel", text: "New intel: a phishing campaign is targeting banks this week", bucket: "in", why: "Changes in the threat landscape tell the next shift what to watch for." },
          { id: "watch", text: "Tom asked to be called if WS-FIN-118 talks to the internet again", bucket: "in", why: "A standing instruction for the next shift: write it down." },
          { id: "closed", text: "A false positive closed nine hours ago, with nothing pending", bucket: "out", why: "Closed with no follow-up: it lives in the ticket system, not the handover." },
          { id: "coffee", text: "The coffee machine on floor 3 is broken", bucket: "out", why: "True, sad, and not security." },
        ],
      },
      {
        kind: "match",
        title: "Who Owns It?",
        prompt: "Beyond the three tiers, other roles keep the SOC running. Match each job to its owner.",
        pairs: [
          { id: "mgr", left: "Plans the shift rota and reports MTTD to the board", right: "SOC Manager", why: "Accountable for the team and its metrics." },
          { id: "ti", left: "Tracks the groups that target banks and briefs the team", right: "Threat Intelligence Analyst", why: "Studies attackers, not individual alerts." },
          { id: "ir", left: "Preserves forensic evidence after a major breach", right: "Incident Response Specialist", why: "Forensics and evidence handling for serious incidents." },
          { id: "mal", left: "Takes a dropped program apart to see what it does", right: "Malware Analyst", why: "Reverse engineering and detection advice." },
          { id: "t3", left: "Hunts for attackers that no alert has caught yet", right: "Tier 3 Threat Hunter", why: "Proactive hunting and new detection rules." },
        ],
      },
    ],
    // ── Reading 3: the tool stack ──
    "soc-struct-r3": [
      {
        kind: "evidence",
        title: "Name the Tool",
        prompt: "You will live inside these screens. Look at each one and say which tool you are in.",
        choices: [
          { id: "siem", label: "SIEM" },
          { id: "edr", label: "EDR" },
          { id: "soar", label: "SOAR" },
          { id: "tip", label: "TIP" },
          { id: "ticket", label: "Ticketing" },
        ],
        items: [
          {
            id: "siem", caption: "Search · last 24 hours",
            screen: {
              type: "siem", product: "SIEM · log search",
              query: "SigninLogs | where ResultType != 0 | summarize failures=count() by UserPrincipalName, IPAddress | where failures > 20",
              rule: "Many failed sign-ins from one IP",
              header: ["UserPrincipalName", "IPAddress", "failures"],
              rows: [["r.ibrahim@globalbank.example", "198.51.100.77", "64"], ["d.osei@globalbank.example", "198.51.100.77", "41"], ["svc_reports@globalbank.example", "10.40.2.19", "22"]],
            },
            answer: "siem",
            callouts: [
              { at: "query", text: "A search over logs collected from many sources: here, the sign-in logs." },
              { at: "results", text: "Thousands of single events summarised into a pattern: one IP failing against many users." },
              { at: "rule", text: "Correlation: the SIEM turns the pattern into an alert. That is its core job." },
            ],
          },
          {
            id: "edr", caption: "Endpoint · WS-FIN-118",
            screen: {
              type: "edrtree", host: "WS-FIN-118", verdict: "Behaviour: Office application launched a script interpreter (blocked)",
              nodes: [
                { depth: 0, name: "explorer.exe", detail: "user m.cole" },
                { depth: 1, name: "WINWORD.EXE", detail: "Invoice_Oct.docm" },
                { depth: 2, name: "powershell.exe", detail: "-nop -w hidden -enc SQBFAFgA...", bad: true },
                { depth: 3, name: "rundll32.exe", detail: "C:\\Users\\Public\\upd.dll,Start", bad: true },
              ],
            },
            answer: "edr",
            callouts: [
              { at: "tree", text: "Every process on one machine, parent to child: only an agent on the endpoint can see this." },
              { at: "verdict", text: "Judged by behaviour, not by a known signature. That is the difference between EDR and plain antivirus." },
            ],
          },
          {
            id: "soar", caption: "Automation · run #8812",
            screen: {
              type: "soarrun", playbook: "Suspicious sign-in response", trigger: "SIEM alert: Many failed sign-ins from one IP",
              steps: [
                { name: "Enrich IP", result: "198.51.100.77: known proxy service (TIP)", ok: true },
                { name: "Check user history", result: "Never signed in from this IP before", ok: true },
                { name: "Disable account", result: "r.ibrahim disabled in the identity provider", ok: true },
                { name: "Revoke sessions", result: "3 active sessions revoked", ok: true },
                { name: "Open ticket", result: "INC-2240 created, assigned to Tier 1", ok: true },
                { name: "Notify", result: "Message posted to #soc-alerts", ok: true },
              ],
            },
            answer: "soar",
            callouts: [
              { at: "trigger", text: "Started automatically by an alert, with no analyst clicking." },
              { at: "steps", text: "A playbook: lookups and responses an analyst would do by hand, done in seconds." },
            ],
          },
          {
            id: "tip", caption: "Indicator lookup",
            screen: {
              type: "tip", indicator: "invoice-portal-secure.top", kind: "domain", score: "Malicious 92/100",
              tags: ["phishing", "credential harvesting", "banking sector"],
              sightings: ["First seen 6 days ago", "Reported by 14 sharing partners", "Linked to a campaign against European banks"],
            },
            answer: "tip",
            callouts: [
              { at: "indicator", text: "One indicator looked up: a domain, an IP or a file hash." },
              { at: "score", text: "Its reputation, collected from many intelligence sources." },
              { at: "sightings", text: "Who else has seen it and in which campaign: context no single log can give you." },
            ],
          },
        ],
      },
      {
        kind: "sequence",
        title: "One Alert, Every Tool",
        prompt: "A stolen password is used against GlobalBank. Follow it through the stack: tap the steps in order.",
        items: [
          { id: "soar", text: "SOAR looks the IP up in the TIP: a known proxy service", note: "Automation starts with enrichment." },
          { id: "idp", text: "The identity provider logs dozens of failed sign-ins, then one success", note: "Every system writes logs; this is where the story starts." },
          { id: "t1", text: "A Tier 1 analyst reviews the ticket and escalates to Tier 2", note: "A human confirms what the machines did." },
          { id: "siem", text: "The SIEM correlates the failures and the success into one alert", note: "Correlation turns events into an alert." },
          { id: "edr", text: "EDR on the user's laptop is checked: no malware, the password was phished", note: "The endpoint view rules out a local infection." },
          { id: "act", text: "SOAR disables the account and opens a ticket", note: "Response in seconds, not minutes." },
        ],
        order: ["idp", "siem", "soar", "act", "edr", "t1"],
        doneNote: "Logs feed the SIEM, the SIEM alerts, SOAR enriches with the TIP and acts, EDR adds the endpoint view, and the ticket carries it to people. No single tool sees it all.",
      },
    ],
    // Drill before the graded alert: a successful logon, decoded.
    "soc-struct-la1": [
      {
        kind: "anatomy",
        title: "Anatomy of a Windows Logon Event",
        prompt: "Your alert will be built from Windows Security events. Before 03:47, Priya shows you a different one: a successful network logon on the domain controller.",
        source: "Windows Security log · DC01.globalbank.local",
        fields: [
          { key: "EventID", value: "4624", label: "What happened", note: "4624 is a successful logon. Its partner, 4625, is a failed one. The ID alone tells you which story you are reading." },
          { key: "TimeCreated", value: "2025-11-14T01:12:40.512Z" },
          { key: "Computer", value: "DC01.globalbank.local", label: "Where it was logged", note: "The domain controller, which checks the password, so it logs logons for the whole domain." },
          { key: "TargetUserName", value: "svc_backup", label: "Which account", note: "The account that logged on. 'svc_' marks a service account: it should behave the same way every night." },
          { key: "TargetDomainName", value: "GLOBALBANK" },
          { key: "LogonType", value: "3", label: "How", note: "3 is a network logon (a file share, for example). 2 is someone at the keyboard, 10 is Remote Desktop. The type changes what 'normal' looks like." },
          { key: "IpAddress", value: "10.40.8.20", label: "From where", note: "The address the logon came from: here an internal server. From the internet or a Tor exit, the same event means something very different." },
          { key: "WorkstationName", value: "SRV-APP-07", label: "From which machine", note: "The name of the source computer, when Windows knows it." },
          { key: "LogonProcessName", value: "NtLmSsp" },
          { key: "AuthenticationPackageName", value: "NTLM", label: "Which protocol", note: "NTLM rather than Kerberos. In a modern domain, a lot of NTLM from one host is worth a second look." },
          { key: "IpPort", value: "51822" },
        ],
        summary: "At 01:12 the svc_backup service account logged on over the network to the domain controller from SRV-APP-07, using NTLM. One event is one logon: whether this is normal depends on what this account usually does, which only a SIEM comparing many events can tell you.",
      },
    ],
  },
};
