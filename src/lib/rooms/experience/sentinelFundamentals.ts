import type { RoomExperience } from "./types";
import { SENTINEL_INCIDENT_LAB } from "./consoleLabs";

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
  story: {
    intro: { title: "The Logs Are Flowing", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/sentinel-fundamentals/clearsky-intro-e05c83eb.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/sentinel-fundamentals/clearsky-intro-17f65a10.jpg" },
    afterStation: {
      kql: { title: "Four Countries in a Week", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/sentinel-fundamentals/clearsky-ch2-5b2d7cdf.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/sentinel-fundamentals/clearsky-ch2-efcff862.jpg" },
      incidents: { title: "Incident 4412", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/sentinel-fundamentals/clearsky-ch3-885af19d.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/sentinel-fundamentals/clearsky-ch3-5fe5acb8.jpg" },
      boss: { title: "Query, Build, Decide", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/sentinel-fundamentals/clearsky-finale-d1757c53.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/sentinel-fundamentals/clearsky-finale-9d7d0a45.jpg" },
    },
  },
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
        kind: "tune",
        title: "The Travel Rule",
        prompt: "Malik is turning a hunting query into a scheduled analytics rule: SigninLogs, last 7 days, summarize dcount(Location) by UserPrincipalName, plus the share of those sign-ins that used a single factor. Set both thresholds, deploy, and see which users the rule would raise as incidents. The KQL behind it reads: SigninLogs | where TimeGenerated > ago(7d) | summarize countries = dcount(Location) by UserPrincipalName | top 5 by countries | project UserPrincipalName, countries. Here where keeps only the rows that match, ago(7d) is a relative time window (1h, 30m, 7d), summarize ... by groups the rows and computes an aggregate, top 5 by countries keeps the five highest by that column, and project keeps just the columns you name.",
        eventColumn: "user and week",
        dials: [
          { id: "countries", label: "Distinct countries in 7 days (dcount of Location)", short: "countries", min: 1, max: 8, step: 1, start: 1 },
          { id: "single", label: "Share of sign-ins with single-factor authentication", short: "single-factor", unit: "%", min: 0, max: 100, step: 5, start: 0 },
        ],
        events: [
          { id: "a1", label: "k.mensah: 4 countries, 90% single-factor via legacy IMAP", bad: true, values: { countries: 4, single: 90 } },
          { id: "a2", label: "t.ramos: 3 countries, 70% single-factor via legacy POP", bad: true, values: { countries: 3, single: 70 } },
          { id: "a3", label: "f.nowak: 5 countries, 55% single-factor", bad: true, values: { countries: 5, single: 55 } },
          { id: "a4", label: "l.adeyemi: 3 countries, 40% single-factor", bad: true, values: { countries: 3, single: 40 } },
          { id: "a5", label: "svc-rxsync: 2 countries, 100% single-factor, app credential", bad: true, values: { countries: 2, single: 100 } },
          { id: "n1", label: "supplier buyer: 4 countries on a trade trip, 10% single-factor", bad: false, values: { countries: 4, single: 10 } },
          { id: "n2", label: "regional manager: 6 countries through VPN exits, 25% single-factor", bad: false, values: { countries: 6, single: 25 } },
          { id: "n3", label: "shop kiosk login: 1 country, 100% single-factor by policy", bad: false, values: { countries: 1, single: 100 } },
          { id: "n4", label: "shift pharmacist: 1 country, 60% single-factor", bad: false, values: { countries: 1, single: 60 } },
          { id: "n5", label: "auditor on site: 2 countries, 35% single-factor", bad: false, values: { countries: 2, single: 35 } },
          { id: "n6", label: "executive travelling: 3 countries, 20% single-factor", bad: false, values: { countries: 3, single: 20 } },
          { id: "n7", label: "contractor: 2 countries, 50% single-factor", bad: false, values: { countries: 2, single: 50 } },
        ],
        goal: { catch: 4, maxFalse: 0 },
        lesson: "Both conditions have to hold: at least 3 countries AND a single-factor share between about 30% and 40%. Countries alone flags the buyer and the VPN-hopping manager; single-factor alone flags kiosks and shift staff. Four of the five bad users fall out of the overlap, and the service account with 2 countries and 100% single-factor does not: it is a non-interactive sign-in and needs its own rule on the service-principal table. A scheduled rule is this query on a timer, so every dial you set is a trade between incidents you read and incidents you never see.",
      },
    ],
    // ── Reading 3: rules, incidents, playbooks ──
    "sentinel-r3": [
      {
        kind: "deduce",
        title: "What Ties the Alerts Together?",
        prompt: "Three separate analytics rules fired within half an hour. Sentinel grouped them into one incident because they share an entity, and the playbook needs to act on exactly that entity. Read each alert's mapped entities as it arrives and strike out suspects until one is in all three.",
        nameColumn: "Entity",
        columns: ["Entity type", "Mapped from column"],
        suspects: [
          { id: "acct", name: "p.vasquez@ashgrove.example", cells: ["Account", "UserPrincipalName"] },
          { id: "ip1", name: "203.0.113.140", cells: ["IP address", "IPAddress"] },
          { id: "ip2", name: "198.51.100.230", cells: ["IP address", "CallerIpAddress"] },
          { id: "host", name: "ASH-LT-0233", cells: ["Host", "DeviceName"] },
          { id: "site", name: "Dispensing SharePoint site", cells: ["URL", "SiteUrl"] },
          { id: "app", name: "Office 365 Exchange Online", cells: ["Cloud application", "AppDisplayName"] },
        ],
        clues: [
          "Alert 1, 22:10, sign-in from an anonymous proxy. Entities mapped: p.vasquez@ashgrove.example, 203.0.113.140, Office 365 Exchange Online. The sign-in carries no device ID.",
          "Alert 2, 22:19, 410 files downloaded from the Dispensing SharePoint site. Entities mapped: p.vasquez@ashgrove.example, 203.0.113.140, the SharePoint site URL.",
          "Alert 3, 22:26, inbox rule forwarding to an outside address. Entities mapped: p.vasquez@ashgrove.example, 198.51.100.230, Office 365 Exchange Online.",
        ],
        culprit: "acct",
        why: "Only the account appears in all three alerts. The sign-in IP changed by alert 3, the app and site are different services, and the laptop never appeared because the first sign-in was a browser session with no device. Group and respond on the account: revoke its sessions and review the forwarding rule, rather than blocking one IP the attacker has already left.",
      },
      SENTINEL_INCIDENT_LAB,
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
        summary: "Who, into what, outcome, from where, and how strongly they proved it. The graded event is a Windows 4625 in another table: read its outcome, logon type and source the same way. In a 4625 the outcome is the SubStatus: 0xC0000064 means the username does not exist and 0xC0000072 means the account is disabled; other SubStatus codes name other reasons. LogonType says how the attempt arrived: 2 at the keyboard, 3 over the network, 5 a service, 10 remote desktop, 11 cached credentials.",
      },
    ],
  },
};
