import type { RoomExperience } from "./types";

// "Operation Clear Sky" for the "sentinel-fundamentals" room.
// Script: docs/campaign/36-sentinel-fundamentals.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Ashgrove Pharmacy (fictional), not the graded tasks' CORP. Lab data differs
// from the graded tasks: the table sort never places a Windows logon (la1);
// the KQL console queries SigninLogs and never counts 4625s or ranks failed
// logins (q1, q3, queryfill-1); the incident sheet never picks a rule type
// (q2); the anatomy is a SigninLogs row, never a 4625 or its SubStatus,
// LogonType or IpAddress column (la1, flag1); and nothing judges a spray (ac1).
export const SENTINEL_FUNDAMENTALS: RoomExperience = {
  roomId: "sentinel-fundamentals",
  codename: "Operation Clear Sky",
  theme: "sentinel",
  handler: { name: "Malik Haddad", role: "Sentinel Architect, Ashgrove Pharmacy" },
  briefing: [
    "Ashgrove Pharmacy. 310 shops, a prescription system that must never go down, and everything already living in Microsoft 365 and Azure.",
    "Last month Ashgrove moved its SIEM to Microsoft Sentinel. The logs are flowing. Most of the team can't read them yet.",
    "Malik Haddad designed the workspace. He wants analysts who know which table to open, can write the query themselves, and can tell an incident from noise.",
    "Learn the workspace and its tables, KQL, analytics rules and incidents, then read the raw event behind an alert.",
  ],
  mission: "Put each kind of event in its Sentinel table, write KQL step by step against Ashgrove's sign-ins, walk an incident from alerts to entities to playbook, and read a sign-in row field by field.",
  estimate: "~45 min",
  look: { primary: "#0ea5e9", secondary: "#c084fc", warn: "#f43f5e" },
  scene: "skyquery",
  layout: "stage",
  stations: [
    {
      id: "tables",
      label: "Workspace and Tables",
      topic: "Log Analytics workspace · data connectors · SigninLogs, SecurityEvent, OfficeActivity and more",
      tagline: "Know which table to open",
      building: "control",
      taskIds: ["sentinel-r1"],
    },
    {
      id: "kql",
      label: "Speak KQL",
      topic: "where, project, summarize, ago(), sort, top",
      tagline: "Ask the logs a precise question",
      building: "lab",
      taskIds: ["sentinel-r2", "sentinel-q1"],
    },
    {
      id: "incidents",
      label: "Rules to Incidents",
      topic: "Scheduled, NRT, Fusion and anomaly rules · incidents · playbooks · workbooks",
      tagline: "From a rule to a case",
      building: "office",
      taskIds: ["sentinel-r3"],
    },
    {
      id: "event",
      label: "Inside the Event",
      topic: "Reading the raw row behind an incident",
      tagline: "Drill down to the evidence",
      building: "vault",
      taskIds: ["sentinel-la1", "sentinel-flag1"],
    },
    {
      id: "boss",
      label: "Write It, Call It",
      topic: "Choosing a rule type · ranking queries · writing KQL · a verdict",
      tagline: "Query, build, decide",
      building: "ticket",
      taskIds: ["sentinel-q2", "sentinel-q3", "sentinel-queryfill-1", "sentinel-ac1"],
      boss: true,
    },
  ],
  personas: {
    "sentinel-q1": { name: "Malik Haddad", role: "Sentinel Architect", line: "Failed Windows logons, last six hours. Which query is right?" },
    "sentinel-la1": { name: "Malik Haddad", role: "Sentinel Architect", line: "You've drilled into one failed logon. Read it like evidence." },
    "sentinel-q2": { name: "Malik Haddad", role: "Sentinel Architect", line: "Impossible travel, our own thresholds, every five minutes. Which rule type?" },
    "sentinel-ac1": { name: "Malik Haddad", role: "Sentinel Architect", line: "Many accounts, one source, all failing. Your verdict." },
  },
  briefings: {
    // ── Reading 1: workspace and tables ──
    "sentinel-r1": [
      {
        kind: "sort",
        title: "Which Table?",
        prompt: "Six things that happened at Ashgrove this morning. Which Sentinel table would you open to find each one?",
        buckets: [
          { id: "signin", label: "SigninLogs" },
          { id: "office", label: "OfficeActivity" },
          { id: "cef", label: "CommonSecurityLog" },
          { id: "syslog", label: "Syslog" },
          { id: "azure", label: "AzureActivity" },
        ],
        items: [
          { id: "entra", text: "A pharmacist's Entra ID sign-in to the prescription portal from a new device", bucket: "signin", why: "Cloud sign-ins to Entra ID land in SigninLogs." },
          { id: "rule", text: "An inbox rule created in a store manager's Exchange Online mailbox", bucket: "office", why: "Exchange, SharePoint and Teams audit events go to OfficeActivity." },
          { id: "fw", text: "The shop firewall's deny for an outbound connection, sent as CEF", bucket: "cef", why: "CEF from firewalls and proxies lands in CommonSecurityLog." },
          { id: "ssh", text: "An sshd login on the Linux label-printer gateway", bucket: "syslog", why: "Linux daemons forwarded by the agent go to Syslog." },
          { id: "vm", text: "A virtual machine deleted in the Azure subscription", bucket: "azure", why: "Azure control-plane operations are in AzureActivity." },
          { id: "mfa", text: "An MFA prompt denied by a regional manager", bucket: "signin", why: "MFA results are part of the sign-in record." },
        ],
      },
    ],
    // ── Reading 2: KQL ──
    "sentinel-r2": [
      {
        kind: "terminal",
        title: "Build the Query",
        prompt: "Logs blade, Ashgrove workspace. Build one query in steps: table, filter, columns, aggregate. Malik wants to know who signed in from the most countries this week.",
        shell: "bash",
        host: "Logs > ",
        commands: [
          { match: "^signinlogs\\s*\\|\\s*where\\s+timegenerated\\s*>\\s*ago\\(7d\\)\\s*\\|\\s*where\\s+resulttype\\s*==\\s*\"?0\"?\\s*\\|\\s*summarize\\s+.*dcount\\(location\\).*", help: "SigninLogs | where TimeGenerated > ago(7d) | where ResultType == \"0\" | summarize Countries = dcount(Location) by UserPrincipalName | sort by Countries desc",
            output: "UserPrincipalName                    Countries\n-----------------                    ---------\nd.okafor@ashgrove.example            4\nm.lindqvist@ashgrove.example         2\nt.ramos@ashgrove.example             1\n... (1,204 more rows, all 1)" },
          { match: "^signinlogs\\s*\\|\\s*where\\s+timegenerated\\s*>\\s*ago\\(7d\\)\\s*\\|\\s*where\\s+resulttype\\s*==\\s*\"?0\"?\\s*\\|\\s*project\\s+.*", help: "SigninLogs | where TimeGenerated > ago(7d) | where ResultType == \"0\" | project TimeGenerated, UserPrincipalName, Location, AppDisplayName",
            output: "TimeGenerated          UserPrincipalName              Location  AppDisplayName\n-------------          -----------------              --------  --------------\n2026-11-04 07:58:12    t.ramos@ashgrove.example       GB        Ashgrove Rx Portal\n2026-11-04 07:58:40    m.lindqvist@ashgrove.example   GB        Microsoft Teams\n... (8,912 rows)" },
          { match: "^signinlogs\\s*\\|\\s*where\\s+timegenerated\\s*>\\s*ago\\(7d\\)\\s*\\|\\s*where\\s+resulttype\\s*==\\s*\"?0\"?\\s*$", help: "SigninLogs | where TimeGenerated > ago(7d) | where ResultType == \"0\"   successful sign-ins only",
            output: "(8,912 rows: add project or summarize to make it readable)" },
          { match: "^signinlogs\\s*\\|\\s*where\\s+userprincipalname\\s*==\\s*\"d\\.okafor@ashgrove\\.example\".*", help: "SigninLogs | where UserPrincipalName == \"d.okafor@ashgrove.example\" | where ResultType == \"0\" | project TimeGenerated, Location, IPAddress, AppDisplayName",
            output: "TimeGenerated          Location  IPAddress        AppDisplayName\n-------------          --------  ---------        --------------\n2026-10-29 08:12:03    GB        198.51.100.14      Ashgrove Rx Portal\n2026-10-31 14:40:51    ES        198.51.100.14      Ashgrove Rx Portal\n2026-11-02 09:05:17    PT        198.51.100.61    Microsoft Teams\n2026-11-03 23:41:09    NG        203.0.113.88     Office 365 Exchange Online" },
        ],
        objectives: [
          { id: "count", task: "How many successful sign-ins in the last 7 days?", hint: "SigninLogs | where TimeGenerated > ago(7d) | where ResultType == \"0\"", answer: ["8912", "8,912"], why: "where narrows the table before anything else touches it. Always filter on time first: it's the cheapest filter you have." },
          { id: "who", task: "Who signed in from the most countries?", hint: "... | summarize Countries = dcount(Location) by UserPrincipalName | sort by Countries desc", answer: ["d.okafor", "d.okafor@ashgrove.example"], why: "summarize turns 8,912 rows into one number per user. dcount counts distinct values: four countries in a week." },
          { id: "odd", task: "Pivot on that user. Which country's sign-in, to mail, looks wrong?", hint: "where UserPrincipalName == \"d.okafor@ashgrove.example\" ... project", answer: ["ng", "nigeria"], why: "GB, then Spain on the same home IP (a VPN exit), then Portugal, then Nigeria at 23:41 to Exchange from a new address. One query found it, a second explained it." },
        ],
      },
    ],
    // ── Reading 3: rules, incidents, playbooks ──
    "sentinel-r3": [
      {
        kind: "sequence",
        title: "How Incident 4412 Came Together",
        prompt: "Incident 4412 was opened overnight on d.okafor. Tap the moments in the order they happened, from the first alert to the analyst's first move.",
        items: [
          { id: "group", text: "Sentinel groups three alerts on the shared entity d.okafor into Incident 4412" },
          { id: "dl", text: "Alert: 642 files downloaded from the Formulary SharePoint site (23:58)" },
          { id: "signin", text: "Alert: sign-in from a country d.okafor has never used (23:41)" },
          { id: "scope", text: "The analyst opens 4412 and scopes the forwarding rule and the downloaded files" },
          { id: "fwd", text: "Alert: an inbox rule forwarding mail to an outside address (23:47)" },
          { id: "pb", text: "A playbook revokes d.okafor's sessions and pages the on-call analyst (23:59)" },
        ],
        order: ["signin", "fwd", "dl", "group", "pb", "scope"],
        doneNote: "Three alerts, one entity, one incident. Automation bought time at 23:59; the analyst's job starts with scoping what already left.",
      },
    ],
    // Drill before the graded raw event: a SigninLogs row, field by field.
    "sentinel-la1": [
      {
        kind: "anatomy",
        title: "Anatomy of a SigninLogs Row",
        prompt: "Before the graded Windows event: the cloud sign-in behind incident 4412, field by field.",
        source: "Microsoft Sentinel · SigninLogs · Ashgrove workspace",
        fields: [
          { key: "TimeGenerated", value: "2026-11-03T23:41:09Z", label: "When" },
          { key: "UserPrincipalName", value: "d.okafor@ashgrove.example", label: "Who" },
          { key: "AppDisplayName", value: "Office 365 Exchange Online", label: "Into what" },
          { key: "ResultType", value: "0", label: "Outcome", note: "0 is success. Any other value is an Entra error code: 50126 is a bad password, 50074 is MFA required." },
          { key: "IPAddress", value: "203.0.113.88", label: "From where", note: "The pivot for every other sign-in from the same place." },
          { key: "Location", value: "NG", label: "Country" },
          { key: "ClientAppUsed", value: "Browser" },
          { key: "AuthenticationRequirement", value: "singleFactorAuthentication", label: "MFA?", note: "A trusted-location exception skipped MFA. That gap is a finding in itself." },
          { key: "RiskLevelDuringSignIn", value: "medium" },
          { key: "ConditionalAccessStatus", value: "notApplied", label: "Policy", note: "No Conditional Access policy applied to this sign-in." },
        ],
        summary: "Who, into what, outcome, from where, and how strongly they proved it. The graded event is a Windows 4625 in another table: read its outcome, logon type and source the same way.",
      },
    ],
  },
};
