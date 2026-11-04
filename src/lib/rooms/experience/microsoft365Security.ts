import type { RoomExperience } from "./types";

// "Operation Inbox Zero" for the "microsoft-365-security" room.
// Script: docs/campaign/38-microsoft-365-security.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Fairhaven College (fictional), not the graded tasks' corp.com. Lab data
// differs from the graded tasks: the product sort never ranks Secure Score
// actions (q5); the inbound-mail sheet is about impersonation and spoofing,
// never attachment sandboxing (q2); the audit console never shows an inbox
// rule (q1, la1, flag1), MailItemsAccessed (q3) or an OAuth consent (q4).
export const MICROSOFT_365_SECURITY: RoomExperience = {
  roomId: "microsoft-365-security",
  codename: "Operation Inbox Zero",
  theme: "m365",
  handler: { name: "Saoirse Doyle", role: "Microsoft 365 Security Lead, Fairhaven College" },
  briefing: [
    "Fairhaven College. 14,000 students, 2,100 staff, and every lecture, grade and payroll run living in one Microsoft 365 tenant.",
    "In September the bursar's office paid a fake invoice for £86,000. The mail came from inside the tenant, from an account that had been quietly taken over.",
    "Saoirse Doyle runs Microsoft 365 security. She wants analysts who know which Defender product sees what, and who can read the audit log like a confession.",
    "Learn the Defender family and Secure Score, how Defender for Office 365 judges a sender, the audit operations that matter, then work a business email compromise.",
  ],
  mission: "Put each signal on the Defender product that sees it, judge four inbound mails for impersonation and spoofing, search the unified audit log for forwarding, role changes and bulk downloads, then work the graded inbox-rule alert.",
  estimate: "~40 min",
  look: { primary: "#38bdf8", secondary: "#a3e635", warn: "#fb923c" },
  scene: "tenantcloud",
  layout: "stage",
  stations: [
    {
      id: "family",
      label: "The Defender Family",
      topic: "MDO, MDE, MDI, MDCA, Entra, Purview, Sentinel · Secure Score · the Defender portal",
      tagline: "Who sees what in the tenant",
      building: "control",
      taskIds: ["m365-sec-r1"],
    },
    {
      id: "mail",
      label: "Guarding the Inbox",
      topic: "Defender for Office 365 plans · Safe Links and Safe Attachments · impersonation and spoof intelligence",
      tagline: "Judge the sender, not the subject line",
      building: "lab",
      taskIds: ["m365-sec-r2", "m365-sec-q2"],
    },
    {
      id: "audit",
      label: "The Audit Trail",
      topic: "Unified audit log · retention · the six operations to watch",
      tagline: "Read the tenant's confession",
      building: "vault",
      taskIds: ["m365-sec-r3", "m365-sec-q1", "m365-sec-q3"],
    },
    {
      id: "rule",
      label: "The Hidden Rule",
      topic: "A forwarding inbox rule, field by field",
      tagline: "Find where the mail is going",
      building: "office",
      taskIds: ["m365-sec-la1", "m365-sec-flag1"],
    },
    {
      id: "boss",
      label: "Close the Tenant",
      topic: "Consent phishing · what to fix first",
      tagline: "Shut the doors that stay open",
      building: "ticket",
      taskIds: ["m365-sec-q4", "m365-sec-q5"],
      boss: true,
    },
  ],
  personas: {
    "m365-sec-q1": { name: "Saoirse Doyle", role: "M365 Security Lead", line: "A finance manager's account is taken, and the first move is an inbox rule. Why?" },
    "m365-sec-q3": { name: "Saoirse Doyle", role: "M365 Security Lead", line: "Did they read thousands of mails? Which operation tells me?" },
    "m365-sec-la1": { name: "Saoirse Doyle", role: "M365 Security Lead", line: "Sentinel caught a forwarding rule to an outside domain. Read it." },
    "m365-sec-q5": { name: "Saoirse Doyle", role: "M365 Security Lead", line: "Secure Score 35 out of 100. What do we fix first?" },
  },
  briefings: {
    // ── Reading 1: the family ──
    "m365-sec-r1": [
      {
        kind: "sort",
        title: "Who Sees It?",
        prompt: "Six signals from Fairhaven this week. Which Microsoft product is placed to see each one first?",
        buckets: [
          { id: "mdo", label: "Defender for Office 365" },
          { id: "mde", label: "Defender for Endpoint" },
          { id: "mdi", label: "Defender for Identity" },
          { id: "mdca", label: "Defender for Cloud Apps" },
        ],
        items: [
          { id: "lure", text: "A lecturer receives a mail with a link to a fake Moodle login", bucket: "mdo", why: "Mail flow and links in mail are Defender for Office 365's ground." },
          { id: "macro", text: "A library PC runs a macro that starts PowerShell", bucket: "mde", why: "A process on a device: the endpoint sensor sees it." },
          { id: "roast", text: "A burst of RC4 service-ticket requests against FH-DC01", bucket: "mdi", why: "Defender for Identity watches the domain controllers." },
          { id: "dropbox", text: "A staff account uploads 3 GB of exam papers to a personal Dropbox", bucket: "mdca", why: "Cloud app usage and SaaS uploads: the CASB." },
          { id: "lsass", text: "A tool on a lab workstation reads LSASS memory", bucket: "mde", why: "Credential theft on the device itself: endpoint." },
          { id: "share", text: "An 'anyone with the link' share created on a SharePoint grades library from an unsanctioned app", bucket: "mdca", why: "Cloud app activity and risky sharing are Cloud Apps territory." },
        ],
      },
    ],
    // ── Reading 2: Defender for Office 365 ──
    "m365-sec-r2": [
      {
        kind: "worksheet",
        title: "Four Senders",
        prompt: "Four mails that reached the bursar's office this morning, with what Defender for Office 365 recorded about each sender. Protected users include the Principal, Dr Helen Ward.",
        caption: "Explorer · Email · fairhaven.ac.example · bursar@",
        columns: ["display name", "sender address", "SPF / DKIM / DMARC", "MDO detection"],
        rows: [
          ["Dr Helen Ward", "h.ward.principal@outlook.example", "pass / pass / none", "User impersonation"],
          ["Fairhaven Payroll", "payroll@fairhaven-ac.example", "pass / pass / pass", "Domain impersonation"],
          ["Fairhaven Payroll", "payroll@fairhaven.ac.example via mail.payrollco.example", "pass / pass / pass", "Allowed by spoof intelligence (known sender)"],
          ["IT Helpdesk", "helpdesk@fairhaven.ac.example", "fail / none / fail", "Spoof: blocked"],
        ],
        questions: [
          { id: "typo", q: "Which sender address is a lookalike of the college's own domain?", hint: "Compare each domain with fairhaven.ac.example letter by letter.", answer: ["payroll@fairhaven-ac.example", "fairhaven-ac.example"], why: "A hyphen where the dot should be. It passes SPF and DKIM because the attacker owns that domain: authentication proves who sent it, not that it's ours." },
          { id: "name", q: "Which mail borrows a protected person's name from an outside address?", hint: "Protected users list.", answer: ["dr helen ward", "helen ward", "h.ward.principal@outlook.example"], why: "The Principal's display name on a consumer mailbox: user impersonation." },
          { id: "spoof", q: "Which row claims our own domain but fails every check?", hint: "fail / none / fail", answer: ["it helpdesk", "helpdesk@fairhaven.ac.example", "helpdesk"], why: "Our domain in the From line, sent from a server we never authorised. Spoof intelligence let the payroll vendor through and stopped this one." },
        ],
      },
    ],
    // ── Reading 3: the audit log ──
    "m365-sec-r3": [
      {
        kind: "terminal",
        title: "Search the Audit Log",
        prompt: "Exchange Online PowerShell, connected to Fairhaven's tenant. The account p.okoro in the estates office is behaving oddly. Search what it and its admins did yesterday.",
        shell: "powershell",
        host: "PS C:\\> ",
        commands: [
          { match: "search-unifiedauditlog\\s+.*-operations\\s+\"?set-mailbox\"?.*", help: "Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-1) -EndDate (Get-Date) -Operations Set-Mailbox | Format-List",
            output: "CreationDate : 11/3/2026 22:14:51\nUserIds      : svc-o365admin@fairhaven.ac.example\nOperation    : Set-Mailbox\nObjectId     : p.okoro\nClientIP     : 198.51.100.31\nParameters   :\n  ForwardingSmtpAddress      = smtp:estates.archive@mailbox.example\n  DeliverToMailboxAndForward = True" },
          { match: "search-unifiedauditlog\\s+.*-operations\\s+\"?add member to role\"?.*", help: "Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-1) -EndDate (Get-Date) -Operations \"Add member to role\"",
            output: "CreationDate : 11/3/2026 22:09:30\nUserIds      : p.okoro@fairhaven.ac.example\nOperation    : Add member to role.\nObjectId     : svc-o365admin@fairhaven.ac.example\nRole         : Exchange Administrator\nResultStatus : Success" },
          { match: "search-unifiedauditlog\\s+.*-operations\\s+\"?filedownloaded\"?.*", help: "Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-1) -EndDate (Get-Date) -Operations FileDownloaded -UserIds p.okoro@fairhaven.ac.example -ResultSize 5000 | Measure-Object",
            output: "Count    : 642\nAverage  :\nSum      :\nProperty :\n\n(first: 11/3/2026 22:31:02 · last: 11/3/2026 22:39:47 · site: /sites/Estates-BuildingPlans)" },
        ],
        objectives: [
          { id: "role", task: "Which admin role was granted, and to which account?", hint: "-Operations \"Add member to role\"", answer: ["exchange administrator", "exchange administrator to svc-o365admin", "svc-o365admin"], why: "p.okoro gave a service account Exchange Administrator at 22:09. Five minutes later that account changed a mailbox." },
          { id: "fwd", task: "Where is p.okoro's mail now being copied to?", hint: "-Operations Set-Mailbox: ForwardingSmtpAddress", answer: ["estates.archive@mailbox.example"], why: "Server-side forwarding, set by an admin account, not an inbox rule: the user never sees it in Outlook." },
          { id: "files", task: "How many files did p.okoro download from SharePoint in under ten minutes?", hint: "-Operations FileDownloaded ... | Measure-Object", answer: ["642"], why: "642 building plans in nine minutes. Role, forwarding, then bulk download: one story told by three operations." },
        ],
      },
    ],
  },
};
