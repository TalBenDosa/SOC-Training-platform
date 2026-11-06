import type { BriefingLab, RoomExperience } from "./types";

// "Operation Who Goes There" for the "auth-identity-monitoring" room.
// Script: docs/campaign/62-auth-identity-monitoring.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// New task order, because the stored order puts all three readings first:
// auth-r1, auth-q3 | auth-r2, auth-q1, auth-q2 | auth-r3, auth-o1 | auth-la1, auth-flag1.
//
// Silverpine Credit Union (fictional), not the graded tasks' corp.internal records.
// Signature: read the pattern, not the row. An Entra-style portal where three identical
// failure rows turn out to be three different stories once they are grouped by source, then a
// tune lab on real burst shapes (spray, slow spray, stuffing, a person who forgot a password).
// Game mix: defuse + portal + tune.
// Lab data differs from the graded tasks: the anatomy is a mistyped NAME on RDP (Type 10, not
// the NTLM Type 3 wrong-password sample in la1); the Type 5 row is a service account doing its
// job, never a Domain Admin (r1 checkpoint); the 4648 pair is an admin's own second account
// and an old teller-PC case, never a user with a service account (q3); the spray in the portal
// has 41 accounts and no success, and the source that got in is a stuffing run (q1, la1); the
// travel pairs start in Tacoma, never London to Sydney (q2); the ordering lab uses log events
// from a closed case, never the stage names (o1); no address is shared with flag1.

type Portal = Extract<BriefingLab, { kind: "portal" }>;

const SIGNIN_TABS = [{ id: "basic", label: "Basic info" }, { id: "loc", label: "Location" }, { id: "auth", label: "Authentication Details" }, { id: "capol", label: "Conditional Access" }];

const SHAPE_LAB: Portal = {
  kind: "portal",
  skin: "entra",
  title: "Same Error, Three Stories",
  prompt: "Monday, 08:30, Silverpine. The failed sign-ins tile is red and the helpdesk has just cleared a locked-out teller. Tove Ramirez slides you the keyboard: work out what these failures really are, then find out whether anyone got in.",
  product: "Identity admin center",
  resource: "Silverpine Credit Union",
  tenant: "silverpinecu.example",
  home: "overview",
  menu: [
    { items: [{ id: "overview", label: "Overview" }, { id: "users", label: "Users" }] },
    { group: "Protection", items: [{ id: "ca", label: "Conditional Access" }] },
    { group: "Monitoring & health", items: [{ id: "signins", label: "Sign-in logs" }, { id: "shape", label: "Workbooks" }] },
    { group: "Hybrid identity", items: [{ id: "onprem", label: "On-premises logons" }] },
  ],
  pages: {
    overview: {
      heading: "Overview",
      tiles: [{ label: "Users", value: "312" }, { label: "Failed sign-ins today", value: "89" }, { label: "Lockouts today", value: "1" }],
      note: "Primary domain silverpinecu.example. Directory synced from on-premises Active Directory.",
    },
    users: {
      heading: "Users",
      table: {
        columns: ["Display name", "User principal name", "Job title", "Account enabled"],
        rows: [
          { id: "u-ja", cells: ["Jo Avery", "j.avery@silverpinecu.example", "Teller, Branch 4", "Yes"], record: "u-ja" },
          { id: "u-km", cells: ["Kit Marsh", "k.marsh@silverpinecu.example", "Loan Processor", "Yes"], record: "u-km" },
          { id: "u-rs", cells: ["Remy Sanz", "r.sanz@silverpinecu.example", "Member Services", "Yes"], record: "u-rs" },
        ],
      },
    },
    ca: {
      heading: "Conditional Access | Policies",
      table: {
        columns: ["Policy name", "State", "Excluded", "Modified date"],
        rows: [
          { id: "c1", cells: ["Require MFA for all staff", "On", "Staff VPN (old RADIUS client)", "2024-05-02"] },
          { id: "c2", cells: ["Block legacy authentication", "On", "None", "2024-05-02"] },
        ],
      },
    },
    signins: {
      heading: "Sign-in events",
      filters: ["Date: Today", "Sample of the day's events", "Show dates as: Local"],
      note: "Closest Windows twins: 50126 is SubStatus 0xC000006A, 50034 is 0xC0000064, 50053 is 0xC0000234. Error code 0 is a success.",
      table: {
        columns: ["Date", "User", "Application", "Status", "Sign-in error code", "IP address", "Location"],
        rows: [
          { id: "s-a1", cells: ["06:03:12", "r.sanz", "Staff Portal", "Failure", "50126", "203.0.113.62", "Bucharest, RO"], record: "s-a1" },
          { id: "s-a2", cells: ["06:03:32", "t.abara", "Staff Portal", "Failure", "50126", "203.0.113.62", "Bucharest, RO"] },
          { id: "s-a3", cells: ["06:03:51", "v.hale", "Staff Portal", "Failure", "50126", "203.0.113.62", "Bucharest, RO"] },
          { id: "s-h1", cells: ["07:21:04", "k.marsh", "Office 365", "Success", "0", "203.0.113.20", "Tacoma, US"], record: "s-h1" },
          { id: "s-b1", cells: ["07:43:02", "b.oyelaran", "Staff VPN", "Failure", "50126", "198.51.100.34", "Sao Paulo, BR"] },
          { id: "s-b2", cells: ["07:43:19", "cmoreno77", "Staff VPN", "Failure", "50034", "198.51.100.34", "Sao Paulo, BR"] },
          { id: "s-b3", cells: ["07:47:26", "k.marsh", "Staff VPN", "Success", "0", "198.51.100.34", "Sao Paulo, BR"], record: "s-b3" },
          { id: "s-b4", cells: ["07:49:10", "f.lowe", "Staff VPN", "Failure", "50126", "198.51.100.34", "Sao Paulo, BR"] },
          { id: "s-b5", cells: ["07:51:55", "e.strand", "Staff VPN", "Success", "0", "198.51.100.34", "Sao Paulo, BR"], record: "s-b5" },
          { id: "s-j1", cells: ["07:58:41", "j.avery", "Windows Sign In", "Failure", "50126", "203.0.113.10", "Tacoma, US"], record: "s-j1" },
          { id: "s-j2", cells: ["07:59:58", "j.avery", "Windows Sign In", "Failure", "50126", "203.0.113.10", "Tacoma, US"] },
          { id: "s-j3", cells: ["08:00:31", "j.avery", "Windows Sign In", "Failure", "50053", "203.0.113.10", "Tacoma, US"] },
          { id: "s-j4", cells: ["08:11:52", "j.avery", "Windows Sign In", "Success", "0", "203.0.113.10", "Tacoma, US"] },
        ],
      },
    },
    shape: {
      heading: "Workbooks | Sign-in failure analysis",
      filters: ["Group by: IP address", "Date: Today"],
      note: "The same log, summarised by source. Nothing here is new data, only a different way of reading it.",
      table: {
        columns: ["IP address", "Location", "Failures", "Accounts", "Most tries on one account", "Not in directory (50034)", "Successes", "First", "Last"],
        rows: [
          { id: "g-hq", cells: ["203.0.113.20", "Tacoma, US", "9", "7", "2", "0", "186", "07:02", "08:24"] },
          { id: "g-spray", cells: ["203.0.113.62", "Bucharest, RO", "41", "41", "1", "0", "0", "06:02", "06:09"], record: "g-spray" },
          { id: "g-user", cells: ["203.0.113.10", "Tacoma, US", "6", "1", "6", "0", "1", "07:58", "08:11"], record: "g-user" },
          { id: "g-stuff", cells: ["198.51.100.34", "Sao Paulo, BR", "33", "29", "2", "11", "2", "07:40", "07:55"], record: "g-stuff" },
        ],
      },
    },
    onprem: {
      heading: "On-premises logons | Forwarded Security log",
      filters: ["Channel: Security", "EventID: 4624, 4625, 4740, 5140", "Date: Today"],
      note: "Native Windows records from servers and workstations. A lockout refusal usually carries 0xC0000234 in Status, with 0x0 in SubStatus.",
      table: {
        columns: ["TimeCreated", "EventID", "Computer", "TargetUserName", "LogonType", "IpAddress", "Status", "SubStatus"],
        rows: [
          { id: "d-1", cells: ["07:58:41", "4625", "SP-TLR4-02", "j.avery", "2", "127.0.0.1", "0xC000006D", "0xC000006A"] },
          { id: "d-1b", cells: ["07:59:02", "4625", "SP-TLR4-02", "j.avery", "2", "127.0.0.1", "0xC000006D", "0xC000006A"] },
          { id: "d-1c", cells: ["07:59:20", "4625", "SP-TLR4-02", "j.avery", "2", "127.0.0.1", "0xC000006D", "0xC000006A"] },
          { id: "d-1d", cells: ["07:59:41", "4625", "SP-TLR4-02", "j.avery", "2", "127.0.0.1", "0xC000006D", "0xC000006A"] },
          { id: "d-2", cells: ["07:59:58", "4625", "SP-TLR4-02", "j.avery", "2", "127.0.0.1", "0xC000006D", "0xC000006A"] },
          { id: "d-3", cells: ["08:00:05", "4740", "SP-DC02", "j.avery", "-", "-", "-", "-"], record: "d-3" },
          { id: "d-4", cells: ["08:00:31", "4625", "SP-TLR4-02", "j.avery", "2", "127.0.0.1", "0xC0000234", "0x0"] },
          { id: "d-5", cells: ["08:02:17", "4624", "SP-FS03", "k.marsh", "3", "10.60.0.77", "-", "-"], record: "d-5" },
          { id: "d-6", cells: ["08:02:39", "5140", "SP-FS03", "k.marsh", "-", "10.60.0.77", "-", "-"], record: "d-6" },
          { id: "d-7", cells: ["08:11:52", "4624", "SP-TLR4-02", "j.avery", "2", "127.0.0.1", "-", "-"] },
        ],
      },
    },
  },
  records: {
    "s-a1": { id: "s-a1", title: "Activity Details: Sign-ins", actions: SIGNIN_TABS, facts: [["User", "r.sanz@silverpinecu.example"], ["Application", "Staff Portal"], ["Status", "Failure"], ["Sign-in error code", "50126"], ["Failure reason", "Invalid username or password"]], panes: { loc: [["IP address", "203.0.113.62"], ["Location", "Bucharest, RO"]], auth: [["Result", "No factor reached"]], capol: [["Result", "Not Applied: the sign-in never got that far"]] } },
    "s-j1": { id: "s-j1", title: "Activity Details: Sign-ins", actions: SIGNIN_TABS, facts: [["User", "j.avery@silverpinecu.example"], ["Application", "Windows Sign In"], ["Status", "Failure"], ["Sign-in error code", "50126"], ["Failure reason", "Invalid username or password"]], panes: { loc: [["IP address", "203.0.113.10"], ["Location", "Tacoma, US"]], auth: [["Result", "No factor reached"]], capol: [["Result", "Not Applied: the sign-in never got that far"]] } },
    "s-h1": { id: "s-h1", title: "Activity Details: Sign-ins", actions: SIGNIN_TABS, facts: [["User", "k.marsh@silverpinecu.example"], ["Application", "Office 365"], ["Status", "Success"], ["Device", "SP-LN-22, managed"]], panes: { loc: [["IP address", "203.0.113.20"], ["Location", "Tacoma, US"], ["Named location", "HQ"]], auth: [["Authentication requirement", "Multifactor authentication"], ["Method", "Authenticator app"]], capol: [["Require MFA for all staff", "Success"]] } },
    "s-b3": { id: "s-b3", title: "Activity Details: Sign-ins", actions: SIGNIN_TABS, facts: [["User", "k.marsh@silverpinecu.example"], ["Application", "Staff VPN"], ["Status", "Success"], ["Device", "Unknown, not managed"], ["VPN address assigned", "10.60.0.77"]], panes: { loc: [["IP address", "198.51.100.34"], ["Location", "Sao Paulo, BR"], ["Previous sign-in", "07:21:04 from Tacoma, US"], ["Distance between them", "About 10,800 km"]], auth: [["Authentication requirement", "Single-factor authentication"], ["Method", "Password"], ["MFA required", "No"]], capol: [["Require MFA for all staff", "Not Applied"], ["Reason", "Excluded application: Staff VPN"], ["Block legacy authentication", "Not Applied: client is not legacy"]] } },
    "s-b5": { id: "s-b5", title: "Activity Details: Sign-ins", actions: SIGNIN_TABS, facts: [["User", "e.strand@silverpinecu.example"], ["Application", "Staff VPN"], ["Status", "Success"], ["Device", "Unknown, not managed"]], panes: { loc: [["IP address", "198.51.100.34"], ["Location", "Sao Paulo, BR"]], auth: [["Authentication requirement", "Single-factor authentication"], ["Method", "Password"]], capol: [["Require MFA for all staff", "Not Applied"], ["Reason", "Excluded application: Staff VPN"]] } },
    "g-spray": { id: "g-spray", title: "203.0.113.62", facts: [["Error codes", "50126 on all 41"], ["Application", "Staff Portal"], ["Order of names", "A to Z through the staff list"], ["Lockouts caused", "None"]] },
    "g-user": { id: "g-user", title: "203.0.113.10", facts: [["Error codes", "50126 on 5, then 50053"], ["Application", "Windows Sign In"], ["Named location", "Branch 4"], ["After the failures", "Helpdesk reset, then a success"]] },
    "g-stuff": { id: "g-stuff", title: "198.51.100.34", facts: [["Error codes", "50126 on 22, 50034 on 11"], ["Application", "Staff VPN"], ["Order of names", "No order"], ["Successes", "On the first try for each account"]] },
    "d-3": { id: "d-3", title: "Event 4740", facts: [["EventID", "4740"], ["Computer", "SP-DC02"], ["TargetUserName", "j.avery"], ["Caller Computer Name", "SP-TLR4-02"]] },
    "d-5": { id: "d-5", title: "Event 4624", facts: [["EventID", "4624"], ["Computer", "SP-FS03"], ["TargetUserName", "k.marsh"], ["LogonType", "3"], ["AuthenticationPackageName", "Kerberos"], ["IpAddress", "10.60.0.77"], ["Note", "10.60.0.0/24 is the VPN pool"]] },
    "d-6": { id: "d-6", title: "Event 5140", facts: [["EventID", "5140"], ["Computer", "SP-FS03"], ["SubjectUserName", "k.marsh"], ["ShareName", "\\\\*\\Loans"], ["IpAddress", "10.60.0.77"]] },
    "u-km": { id: "u-km", title: "Kit Marsh", facts: [["User principal name", "k.marsh@silverpinecu.example"], ["Job title", "Loan Processor"], ["Password last changed", "2023-02-14"], ["Threat intel", "Address and password on a leaked forum dump"]], actions: [{ id: "block", label: "Block sign-in" }, { id: "reset", label: "Reset password" }, { id: "delete", label: "Delete" }] },
    "u-ja": { id: "u-ja", title: "Jo Avery", facts: [["User principal name", "j.avery@silverpinecu.example"], ["Job title", "Teller, Branch 4"], ["Password", "Reset by helpdesk today, 08:10"], ["Returned from leave", "Today"]] },
    "u-rs": { id: "u-rs", title: "Remy Sanz", facts: [["User principal name", "r.sanz@silverpinecu.example"], ["Job title", "Member Services"], ["Last sign-in", "Today 08:03, HQ"]] },
  },
  steps: [
    { id: "log", ask: "Start in the book the cloud keeps.", hint: "Monitoring & health, in the menu on the left.", target: "menu:signins", why: "Every attempt to sign in writes one row: who, which application, from where, and how it ended." },
    { id: "row1", ask: "Open the 06:03:12 failure for r.sanz.", hint: "The first row.", target: "row:s-a1", why: "Error 50126: the name exists and the password was wrong. Windows would write the same thing as a 4625 with SubStatus 0xC000006A. Remember this row." },
    { id: "row2", ask: "Now open j.avery's failure at 07:58:41.", hint: "Further down, Windows Sign In.", target: "row:s-j1", why: "Same code, same reason, same word Failure. Location is a hint at best: neither row says how many accounts this source touched." },
    { id: "group", ask: "Rows won't separate them. Find the view that groups failures by source.", hint: "Monitoring & health again.", target: "menu:shape", why: "Now you read shape: how many accounts, how many tries on each, how fast, and whether anything landed. Width, depth and time are what the single row couldn't show." },
    { id: "person", ask: "Which source is one person having a bad morning?", hint: "Narrow and deep: few accounts, many tries.", target: "row:g-user", why: "One account, six tries, Branch 4's own address, and a success after the helpdesk reset. A single lockout is normal. This is the teller the helpdesk just cleared, and the failures are the same event as the rest." },
    { id: "spray", ask: "Which source is guessing one password across the staff list?", hint: "Wide and shallow, every name real, nothing landed.", target: "row:g-spray", why: "41 accounts, one try each, in seven minutes, A to Z, no 50034. The lockout threshold here is 5, so it never trips: no 4740 at all. One source, many accounts, low count per account." },
    { id: "stuff", ask: "One source is left. Which is it, and what makes it worse?", hint: "A list from somewhere else has names that aren't yours.", target: "row:g-stuff", why: "Also wide and shallow, but 11 names aren't in your directory, the order means nothing, and two logged on at the first try. That's a stuffing run: pairs leaked from another site's breach, replayed here. Reused passwords simply work." },
    { id: "landed", ask: "Failures are half the book. Back in the sign-in log, open the first success from that same address.", hint: "Sign-in logs. Match the IP address and read the Status column.", target: "row:s-b3", why: "k.marsh, 07:47, from the address that was failing all around it. A success after a wide pattern moves the priority straight up. A spray that lands looks like this too, so a success always gets checked." },
    { id: "auth", ask: "What proof did that sign-in give?", hint: "The detail tabs across the top of the pane.", target: "action:auth", why: "Single-factor: a password and nothing else. For a pair that came out of a breach, a password is all the attacker has and all they needed." },
    { id: "capol", ask: "Silverpine requires MFA. Find out why it didn't apply.", hint: "There's a tab for what each policy decided.", target: "action:capol", why: "Not Applied, because the old VPN client is excluded. Nothing failed here: the door was left out of the policy, and that's a finding for Tove's report." },
    { id: "loc", ask: "Could this be the real Kit Marsh, travelling?", hint: "The Location tab.", target: "action:loc", why: "07:21 in Tacoma, 07:47 in Sao Paulo: 10,800 km in 26 minutes is about 25,000 km/h. Two successes that are each fine alone, and impossible together. The evidence is in the pairing, not in either row." },
    { id: "prem", ask: "Did it stop at the VPN? Move from the cloud log to the Windows one.", hint: "Hybrid identity, at the bottom of the menu.", target: "menu:onprem", why: "The same people, now in native Windows records. Jo's morning is here too: five 4625s, a 4740 on the domain controller whose Caller Computer Name is SP-TLR4-02, Jo's own counter PC, then a refused 4625 and a clean 4624 after the reset. One lockout, one desk, one explanation." },
    { id: "lat", ask: "Find the first thing k.marsh's account did inside the network.", hint: "Read TargetUserName, then the first EventID for that account.", target: "row:d-5", why: "4624 LogonType 3 on a file server from the VPN pool, fifteen minutes after the stolen sign-in, and the 5140 under it is the Loans share. After success, always look for other hosts and shares: this is how you scope it." },
    { id: "who", ask: "Go to the account before it goes further.", hint: "Users, near the top of the menu.", target: "row:u-km", why: "Password unchanged since 2023, and threat intel has it on a leaked dump. That's what makes this stuffing rather than a lucky guess. Check e.strand the same way." },
    { id: "block", ask: "Stop this account being used, and keep the evidence.", hint: "The buttons on the user's page.", target: "action:block", why: "Blocked now, with the account and its history intact. Next: disable it in Active Directory as well, end the VPN session, and hand Tier 2 a timeline of first failure, last failure, the successes and the Loans share." },
  ],
  traps: {
    "row:g-hq": "That's HQ: a few typos buried in 186 good sign-ins. It's the background every other source is measured against.",
    "row:g-spray": "Not this one. 41 accounts at one try each isn't a person, and nothing landed from there.",
    "row:g-stuff": "Not this one. 29 accounts isn't a person, and this source has successes and names your directory has never heard of.",
    "row:s-j4": "That's j.avery after the helpdesk reset, from Branch 4's own address. A success after failures isn't always a breach: read the source.",
    "action:delete": "Deleting the account destroys your evidence and takes a real employee's history with it.",
    "action:reset": "Worth doing later, but a password reset alone doesn't end a session that's already open. Stop the account first.",
  },
  lesson: "Three sources wrote the same failure. A person is narrow and deep. A spray is wide and shallow, on real names, and mostly fails. Stuffing is wide and shallow too, but brings names from someone else's breach and its reused pairs log on. A row tells you what happened once. Only the group tells you what's going on, and the failures always send you to look for the success.",
};

export const AUTH_IDENTITY_MONITORING: RoomExperience = {
  roomId: "auth-identity-monitoring",
  codename: "Operation Who Goes There",
  theme: "whogoes",
  handler: { name: "Tove Ramirez", role: "Identity Security Lead, Silverpine Credit Union" },
  briefing: [
    "Silverpine Credit Union. 310 staff, 12 branches, and members who trust that somebody is watching the door.",
    "Every knock at that door gets written down. Windows calls it the Security log. Tove Ramirez calls it the logon book.",
    "This morning the book filled with failed logons, all under one event ID. One of them was a teller back from leave. The others weren't.",
    "Learn to read one line, then the pattern across thousands of them, and say who goes there.",
  ],
  mission: "Read a failed logon field by field, judge logon types against their accounts, follow borrowed credentials between machines, split three stories out of one error in the sign-in logs, price a journey no plane could make, tune the failed-logon rule, walk an alert under the clock, then work the graded case.",
  estimate: "~55 min",
  look: { primary: "#5eead4", secondary: "#cbd5e1", warn: "#fb7185" },
  scene: "facilitywhogoes",
  layout: "facility",
  stations: [
    {
      id: "book",
      label: "The Logon Book",
      topic: "Events 4624, 4625, 4648, 4768, 4769 and 4740 · logon types · SubStatus codes · Kerberos against NTLM (NT LAN Manager)",
      tagline: "One line at a time",
      building: "archive",
      taskIds: ["auth-r1", "auth-q3"],
    },
    {
      id: "shape",
      label: "Read the Shape",
      topic: "Password spray · credential stuffing · impossible travel · Golden Ticket indicators",
      tagline: "Same event, three stories",
      building: "lab",
      taskIds: ["auth-r2", "auth-q1", "auth-q2"],
    },
    {
      id: "watch",
      label: "Set the Watch",
      topic: "Threshold rules · the seven-step authentication investigation · how an attack unfolds in the log",
      tagline: "How wide, how fast",
      building: "control",
      taskIds: ["auth-r3", "auth-o1"],
    },
    {
      id: "door",
      label: "Who Goes There?",
      topic: "Working a live authentication alert from the raw event to the next action",
      tagline: "Your shift, your call",
      building: "ticket",
      taskIds: ["auth-la1", "auth-flag1"],
      boss: true,
    },
  ],
  personas: {
    "auth-q3": { name: "Tove Ramirez", role: "Identity Security Lead", line: "Two records, two machines, seconds apart. What am I looking at?" },
    "auth-q1": { name: "Tove Ramirez", role: "Identity Security Lead", line: "Don't read me the lines. Tell me what they add up to." },
    "auth-q2": { name: "Tove Ramirez", role: "Identity Security Lead", line: "Two green logons, one account. What do you make of them?" },
    "auth-o1": { name: "Tove Ramirez", role: "Identity Security Lead", line: "The auditors want this in order, first step to last." },
    "auth-la1": { name: "Tove Ramirez", role: "Identity Security Lead", line: "The alert is yours. Walk me through it, field by field." },
    "auth-flag1": { name: "Tove Ramirez", role: "Identity Security Lead", line: "Same event, one more question. What goes in the search box?" },
  },
  briefings: {
    // ── Reading 1: the logon book ──
    "auth-r1": [
      {
        kind: "anatomy",
        title: "Anatomy of a Failed Logon",
        prompt: "Your first morning, and Tove Ramirez starts with their own mistake from yesterday: a typo at the jump host. Scan each field of this event 4625 and learn what it tells you. Harmless as it is, every failed logon in the building has these same fields.",
        source: "Security log · SP-JUMP01",
        fields: [
          { key: "event.code", value: "4625", label: "What", note: "4625 is a failed logon, and 4624 is a successful one. Every wrong password, expired account or disabled user lands on 4625, so the ID alone tells you very little." },
          { key: "winlog.computer_name", value: "SP-JUMP01.silverpinecu.example", label: "Where", note: "The machine that refused the logon wrote the record." },
          { key: "winlog.event_data.TargetUserName", value: "t.ramirex", label: "Claimed name", note: "The name that was typed, real or not. It's a claim, not an identity." },
          { key: "winlog.event_data.LogonType", value: "10", label: "How", note: "10 is RemoteInteractive, Remote Desktop. With Network Level Authentication on, a failed RDP logon is usually written as Type 3 instead, because it fails before a session exists. This jump host has it off." },
          { key: "winlog.event_data.Status", value: "0xC000006D", label: "Broad reason", note: "The general result: bad user name or password. It reads the same for a typo and an attack, so read the next field too." },
          { key: "winlog.event_data.SubStatus", value: "0xC0000064", label: "Exact reason", note: "0xC0000064: the name doesn't exist. 0xC000006A: the name exists and the password was wrong. 0xC0000234: the account is locked out, and that one usually sits in Status with 0x0 here. 0xC0000072: the account is disabled." },
          { key: "winlog.event_data.LogonProcessName", value: "User32", note: "The logon process behind an interactive-style logon." },
          { key: "winlog.event_data.AuthenticationPackageName", value: "Negotiate", label: "Which protocol", note: "Which authentication package handled it. On many events this names NTLM (NT LAN Manager, the older Windows protocol) or Kerberos outright, and that's worth reading." },
          { key: "winlog.event_data.IpAddress", value: "10.30.8.44", label: "From where", note: "The address the attempt came from. 4624 has the same field, so this value is what you search on to get from a failure to any success from the same origin." },
          { key: "winlog.event_data.WorkstationName", value: "SP-IT-LT03", note: "Reported by the client itself, and it's often just '-' when a tool makes the attempt. Trust IpAddress first." },
        ],
        summary: "Claimed name, how, why it failed, from where. One typo on one host: harmless. But this line alone can't say so, because a thousand attackers would write the same fields. SubStatus says whether the name is real, and IpAddress is the thread you pull next.",
      },
      {
        kind: "queue",
        title: "Does the Logon Type Fit the Account?",
        prompt: "Every 4624 carries a LogonType, and a type that doesn't fit the account is a detection by itself. Tove's review queue in the SIEM (Security Information and Event Management platform, where logs are gathered and searched) holds one of each. Read the type's meaning and the account, then say whether they fit.",
        console: "SIEM · Logon review · Status: New",
        actions: [
          { id: "fits", label: "Fits: note it", tone: "close" },
          { id: "raise", label: "Doesn't fit: raise it", tone: "escalate" },
        ],
        alerts: [
          { id: "t7", time: "08:02", severity: "Low", rule: "Review: LogonType 7", entity: "l.duarte on SP-TLR4-05",
            fields: [{ k: "EventID", v: "4624" }, { k: "LogonType", v: "7 (Unlock)" }, { k: "TargetUserName", v: "l.duarte" }, { k: "Computer", v: "SP-TLR4-05" }],
            context: "An already-logged-on workstation was unlocked. l.duarte's shift starts at 08:00 and this is their counter PC.", answer: "fits", why: "An unlock places a specific person at that console at that exact time, and that's worth remembering when you need to prove who sat where." },
          { id: "t2", time: "03:12", severity: "Medium", rule: "Review: LogonType 2", entity: "adm.ruiz on SP-DC02",
            fields: [{ k: "EventID", v: "4624" }, { k: "LogonType", v: "2 (Interactive)" }, { k: "TargetUserName", v: "adm.ruiz" }, { k: "Computer", v: "SP-DC02" }],
            context: "A logon at the physical keyboard, console or KVM. SP-DC02 sits in a locked rack at the colocation site, and nobody from Silverpine badged in tonight.", answer: "raise", why: "Normal at a desk, suspicious on a headless server nobody sits at. Interactive means someone was at a console, so find out whose." },
          { id: "t3", time: "08:05", severity: "Low", rule: "Review: LogonType 3", entity: "t.ngo on SP-FS01",
            fields: [{ k: "EventID", v: "4624" }, { k: "LogonType", v: "3 (Network)" }, { k: "TargetUserName", v: "t.ngo" }, { k: "Computer", v: "SP-FS01" }, { k: "IpAddress", v: "10.30.4.22" }],
            context: "Access from another machine over the network. t.ngo's sign-in script maps the teller share from their PC every morning.", answer: "fits", why: "Type 3 is the workhorse: file shares, mapped drives, most remote commands. It's also where lateral movement and Pass-the-Hash land, so it's the account and the source that tell you, not the type." },
          { id: "t4", time: "02:00", severity: "Low", rule: "Review: LogonType 4", entity: "adm.ruiz on SP-APP03",
            fields: [{ k: "EventID", v: "4624" }, { k: "LogonType", v: "4 (Batch)" }, { k: "TargetUserName", v: "adm.ruiz" }, { k: "Group", v: "Domain Admins" }, { k: "Computer", v: "SP-APP03" }],
            context: "A scheduled task ran as the account with no human present. adm.ruiz is a person's admin account, and no task is registered to it in the change log.", answer: "raise", why: "A human account suddenly used as Batch can be scheduled-task persistence. Microsoft's guidance says to alert when a Domain Admin shows up as Type 4 or Type 5, because that usually means a privileged credential is being reused." },
          { id: "t5", time: "00:00", severity: "Medium", rule: "Review: LogonType 5", entity: "svc-backup on SP-BKP01",
            fields: [{ k: "EventID", v: "4624" }, { k: "LogonType", v: "5 (Service)" }, { k: "TargetUserName", v: "svc-backup" }, { k: "Group", v: "Backup Operators" }, { k: "Computer", v: "SP-BKP01" }],
            context: "The Service Control Manager started a service under this account. svc-backup exists to run the nightly backup service on this host.", answer: "fits", why: "That's what service accounts are for. The type means nothing without the account: judge the pair." },
          { id: "t8", time: "09:14", severity: "Low", rule: "Review: LogonType 8", entity: "m.ferro on SP-INTRA01",
            fields: [{ k: "EventID", v: "4624" }, { k: "LogonType", v: "8 (NetworkCleartext)" }, { k: "TargetUserName", v: "m.ferro" }, { k: "Computer", v: "SP-INTRA01" }, { k: "ProcessName", v: "w3wp.exe" }],
            context: "A network logon where the password reached the server in cleartext form, for example IIS basic authentication. m.ferro was opening the HR page on the staff intranet.", answer: "raise", why: "m.ferro did nothing wrong, but cleartext credentials are crossing the network. Find which application is doing it and get it fixed." },
          { id: "t9", time: "11:40", severity: "Low", rule: "Review: LogonType 9", entity: "l.hart on SP-LN-12",
            fields: [{ k: "EventID", v: "4624" }, { k: "LogonType", v: "9 (NewCredentials)" }, { k: "TargetUserName", v: "l.hart" }, { k: "TargetOutboundUserName", v: "adm.ruiz" }, { k: "LogonProcessName", v: "seclogo" }, { k: "Computer", v: "SP-LN-12" }],
            context: "A process cloned its token and supplied different credentials for its outbound connections, the runas /netonly pattern. l.hart is a loan officer on their own PC.", answer: "raise", why: "Locally it's still l.hart, and outward it's adm.ruiz. Running as one identity and authenticating as another is classic Pass-the-Hash and lateral movement tradecraft, and a loan officer has no reason for it." },
          { id: "t10", time: "10:15", severity: "Medium", rule: "Review: LogonType 10", entity: "adm.osei on SP-APP02",
            fields: [{ k: "EventID", v: "4624" }, { k: "LogonType", v: "10 (RemoteInteractive)" }, { k: "TargetUserName", v: "adm.osei" }, { k: "Computer", v: "SP-APP02" }, { k: "IpAddress", v: "10.10.0.5 (SP-JUMP01)" }],
            context: "Remote Desktop: full graphical control of a desktop. adm.osei came through the jump host during a change window with a ticket open.", answer: "fits", why: "Expected host, expected hour, expected route. Watch Type 10 from unexpected hosts, times or countries instead." },
          { id: "t11", time: "19:30", severity: "Medium", rule: "Review: LogonType 11", entity: "k.bright on SP-LT-31",
            fields: [{ k: "EventID", v: "4624" }, { k: "LogonType", v: "11 (CachedInteractive)" }, { k: "TargetUserName", v: "k.bright" }, { k: "Computer", v: "SP-LT-31" }],
            context: "A logon with cached domain credentials because no domain controller could be reached. k.bright is a mobile loan officer, at a member's farm with no VPN up yet.", answer: "fits", why: "Normal for a laptop off the network. The same type on a wired server that should always reach a domain controller would be a different story." },
        ],
      },
      {
        kind: "sort",
        title: "Kerberos or NTLM?",
        prompt: "Active Directory has two ways of proving who you are, and the log shows which one was used. Tove pulls seven moments from a normal week. Sort each by the protocol at work, and read why.",
        buckets: [{ id: "kerb", label: "Kerberos" }, { id: "ntlm", label: "NTLM" }],
        items: [
          { id: "a", text: "A teller signs in at 08:00 and the domain controller writes a 4768", bucket: "kerb", why: "4768 is a Ticket Granting Ticket (TGT) request: 'I want to prove who I am.' Kerberos is the modern, preferred protocol in AD." },
          { id: "b", text: "A PC opens \\\\SP-FS01\\Teller by name and the domain controller writes a 4769", bucket: "kerb", why: "4769 is a service ticket (TGS) request: 'I want to access a specific service.' Tickets are issued for a service's name." },
          { id: "c", text: "The scan-to-folder copier writes to \\\\10.20.4.12\\Scans", bucket: "ntlm", why: "That's the server's raw IP, and there's no service name to request a ticket for, so the client falls back to NTLM." },
          { id: "d", text: "An old check scanner at Branch 7 whose firmware can't do anything newer", bucket: "ntlm", why: "When a device or service only supports the older fallback, that's what gets used. Keep a list of them, so a new one stands out." },
          { id: "e", text: "A wrong password at Kerberos pre-authentication: the domain controller writes 4771 with code 0x18", bucket: "kerb", why: "Failed Kerberos pre-authentication is its own event, so a spray that speaks Kerberos shows up as 4771s rather than 4625s." },
          { id: "f", text: "Sixty modern PCs suddenly authenticate to one host the old way", bucket: "ntlm", why: "A high volume from machines that could use Kerberos is suspicious. Someone may be forcing it to capture Net-NTLMv2 responses for offline cracking, or to relay them to another server, which needs no cracking at all." },
          { id: "g", text: "A 4624 with AuthenticationPackageName NTLM and LmPackageName NTLM V2", bucket: "ntlm", why: "The record names the protocol, so a filter on that field splits the two in seconds." },
        ],
      },
      {
        kind: "trace",
        title: "Follow Borrowed Credentials",
        prompt: "The rule says adm.lindqvist was used at the helpdesk at 14:02. Tove wants it followed from the machine it left to the machine it reached, then compared with one old case from the file. Click the row that answers each step.",
        lead: "4648 hit for adm.lindqvist, SP-HD-04 (10.30.2.44), 14:02",
        steps: [
          {
            id: "src", ask: "Find the record where p.lindqvist's session used another account's credentials to reach a different machine.",
            source: "Security log · SP-HD-04",
            columns: ["Time", "EventID", "SubjectUserName", "TargetUserName", "TargetServerName", "ProcessName"],
            rows: [
              ["13:58:40", "4648", "SP-HD-04$", "p.lindqvist", "localhost", "winlogon.exe"],
              ["14:01:50", "4648", "p.lindqvist", "adm.lindqvist", "localhost", "consent.exe"],
              ["14:02:07", "4648", "p.lindqvist", "adm.lindqvist", "SP-PAY01", "mmc.exe"],
              ["14:30:12", "4648", "SP-HD-04$", "svc-patch", "localhost", "svchost.exe"],
            ],
            answer: 2,
            why: "4648 is explicit credential use. The subject is whose session the process runs in, TargetUserName is whose credentials were supplied, and TargetServerName is where they went. The localhost row above it never left the box: that's a UAC prompt.",
            learned: "4648: p.lindqvist's session supplied adm.lindqvist's credentials for SP-PAY01",
          },
          {
            id: "dst", ask: "The credentials left 10.30.2.44 at 14:02:07. Find where they landed.",
            source: "Security log · SP-PAY01",
            columns: ["Time", "EventID", "TargetUserName", "LogonType", "IpAddress", "AuthenticationPackageName"],
            rows: [
              ["14:01:02", "4624", "svc-payrun", "5", "-", "Negotiate"],
              ["14:02:07", "4624", "adm.lindqvist", "3", "10.30.2.44", "Kerberos"],
              ["14:03:40", "4624", "p.lindqvist", "3", "10.30.2.44", "Kerberos"],
              ["14:05:18", "4634", "adm.lindqvist", "3", "-", "-"],
            ],
            answer: 1,
            why: "Same second, the target writes a 4624 Type 3 for the account whose credentials were supplied, from the source PC's address. The server never saw p.lindqvist on that connection. The pair is the story: 4648 on the source, 4624 on the target.",
            learned: "4624 Type 3 on SP-PAY01 for adm.lindqvist from the helpdesk PC. An admin using their own second account, with a change ticket",
          },
          {
            id: "old", ask: "From last year's case file, a teller's PC. Same event ID. Which row should have worried someone?",
            source: "Security log · SP-TLR2-09 · case file",
            columns: ["Time", "EventID", "SubjectUserName", "TargetUserName", "TargetServerName", "ProcessName"],
            rows: [
              ["07:58:03", "4648", "SP-TLR2-09$", "t.hobbs", "localhost", "winlogon.exe"],
              ["12:10:44", "4648", "t.hobbs", "t.hobbs", "SP-FS01", "explorer.exe"],
              ["16:05:31", "4648", "SP-TLR2-09$", "svc-patch", "localhost", "svchost.exe"],
              ["22:41:10", "4648", "t.hobbs", "adm.lindqvist", "SP-PAY01", "powershell.exe"],
            ],
            answer: 3,
            why: "The same event ID can be routine or a breach. This one is a teller's session, after hours, from PowerShell, supplying an admin's credentials to the payments server. A 4648 proves a process used those credentials. It doesn't say who typed them or how the process got them.",
            learned: "Same event, wrong shape: an admin's credentials in a teller's session at 22:41",
          },
        ],
      },
    ],
    // ── Reading 2: shapes ──
    "auth-r2": [
      SHAPE_LAB,
      {
        kind: "worksheet",
        title: "How Fast Would They Have to Fly?",
        prompt: "A SIEM flags two successful logons by the implied speed between them. Four pairs from this month are on Tove's desk. Do the arithmetic the SIEM does, then decide what each one means.",
        caption: "Successful logons, same account, this month",
        columns: ["User", "First 4624", "Second 4624", "Distance", "Gap", "Second source"],
        rows: [
          ["r.lund", "Tacoma 08:02", "Denver 12:02", "1,640 km", "240 min", "Hotel network"],
          ["a.benson", "Tacoma 09:10", "Frankfurt 09:50", "8,200 km", "40 min", "Hosting provider"],
          ["s.iyer", "Tacoma 13:00", "Singapore 13:10", "13,000 km", "10 min", "Silverpine VPN exit"],
          ["d.ocampo", "Portland 07:15", "Seattle 08:15", "235 km", "60 min", "Mobile carrier"],
        ],
        questions: [
          { id: "speed", q: "What speed does a.benson's pair imply, in km/h?", hint: "Distance divided by minutes, then times 60.", answer: ["12300"], why: "12,300 km/h, and a passenger jet does about 900. No human made that trip, so the likely conclusion is that the account is compromised. The raw events are just two 4624s: the intelligence comes from correlating them. They can't tell you how the account was taken, only that one of those logons isn't the person." },
          { id: "vpn", q: "Which user's pair looks impossible but has an innocent cause you must rule out first?", hint: "Read the last column.", answer: ["s.iyer"], why: "A VPN exit in another country produces the same arithmetic. Check the source against your own VPN ranges before you call it, and tune the rule to know them." },
          { id: "fly", q: "Which user's pair is the longest real journey, and shouldn't alert at all?", hint: "Work out each speed: which long trip could a plane really make?", answer: ["r.lund"], why: "410 km/h is a flight with time at both ends. A city that's merely new for the user is a much weaker signal than speed. Two sessions at once on two devices are a different question again: what makes this technique strong is the physics." },
        ],
      },
      {
        kind: "sort",
        title: "Where a Forged Ticket Shows",
        prompt: "Tove's quarterly drill. An intruder who extracts the krbtgt account's hash from a domain controller can forge a ticket for anyone, the Golden Ticket, and it's cryptographically valid. Sort each observation by where it actually helps you.",
        buckets: [{ id: "dc", label: "Domain controller log: a lead" }, { id: "host", label: "Only on the host: klist" }, { id: "no", label: "Normal: not a sign" }],
        items: [
          { id: "a", text: "4769 with TicketEncryptionType 0x17 in a domain that issues 0x12", bucket: "dc", why: "RC4 where the domain uses AES. Many forging tools default to it." },
          { id: "b", text: "4769 naming a TargetUserName that doesn't exist in Active Directory", bucket: "dc", why: "A forged ticket can name a principal the domain controller has no record of." },
          { id: "c", text: "4769 with a blank or mismatched domain field", bucket: "dc", why: "Same family as the invented name: the forger typed it, the directory didn't issue it." },
          { id: "d", text: "4769 for a logon session with no 4768 on this domain controller", bucket: "dc", why: "A lead, not proof. A forged TGT never went through the AS-REQ, but a real one is cached for about 10 hours and may have come from a different domain controller." },
          { id: "e", text: "A ticket valid for ten years", bucket: "host", why: "4769 has no lifetime, start or expiry field at all. Run klist on the endpoint holding the ticket to confirm it." },
          { id: "f", text: "4768 with TicketEncryptionType 0x12 for staff at 08:00 each morning", bucket: "no", why: "AES tickets for real people at the start of a shift are the baseline you compare against." },
          { id: "g", text: "A 4769 for cifs/SP-FS01 from a teller's PC at 08:05", bucket: "no", why: "A real person reaching a real share. On its own a service ticket is the most ordinary thing in the log." },
        ],
      },
    ],
    // ── Reading 3: the rule and the investigation ──
    "auth-r3": [
      {
        kind: "tune",
        title: "Tune the Failed-Logon Rule",
        prompt: "Monday, 16:30. Tove wants one rule on 4625s per source address: it must catch all six attack bursts below and stay quiet on all six innocent ones. Every row is the same event ID. Set how many accounts a source must fail on across the day and in its busiest hour, then deploy.",
        eventColumn: "Burst of 4625s",
        dials: [
          { id: "accts", label: "Distinct accounts failing from one source in a day, at least", short: "Day", min: 1, max: 60, step: 1, start: 1, dir: "above" },
          { id: "hour", label: "Distinct accounts in its busiest hour, at least", short: "Busiest hour", min: 1, max: 60, step: 1, start: 1, dir: "above" },
        ],
        events: [
          { id: "s1", label: "One try each, all 0xC000006A, A to Z through the staff list", bad: true, values: { accts: 64, hour: 64 } },
          { id: "s2", label: "One try every 5 minutes, all 0xC000006A, never a 4740", bad: true, values: { accts: 35, hour: 12 } },
          { id: "s3", label: "Two tries each, a pause between rounds, all 0xC000006A", bad: true, values: { accts: 22, hour: 22 } },
          { id: "s4", label: "One try each, 0xC0000064 and 0xC000006A mixed, five 4624s among them", bad: true, values: { accts: 46, hour: 46 } },
          { id: "s5", label: "One or two tries each, from a VPN abroad, two 4624s among them", bad: true, values: { accts: 14, hour: 14 } },
          { id: "s6", label: "0xC0000064 on 17 guessed names, then 0xC000006A on 20 real ones", bad: true, values: { accts: 37, hour: 37 } },
          { id: "n1", label: "One account, 5 tries, then a 4740 from the user's own PC", bad: false, values: { accts: 1, hour: 1 } },
          { id: "n2", label: "One account, a phone retrying an old password, 4740 after 4740", bad: false, values: { accts: 1, hour: 1 } },
          { id: "n3", label: "Two tellers back from leave, three tries each", bad: false, values: { accts: 2, hour: 2 } },
          { id: "n4", label: "Password expiry at a branch NAT, three tries each, then 4723", bad: false, values: { accts: 12, hour: 12 } },
          { id: "n5", label: "Monitoring probe with stale test accounts, on a fixed timer", bad: false, values: { accts: 20, hour: 10 } },
          { id: "n6", label: "New-hire class in the training room, one slip each", bad: false, values: { accts: 16, hour: 7 } },
        ],
        goal: { catch: 6, maxFalse: 0 },
        lesson: "Width separates a person from a campaign: however many tries, a forgotten password is one account. Pace separates a campaign from background: the slow spray never tops 12 accounts in an hour, so a cut at 15 misses it, and a cut at 10 pages you for a monitoring probe. A five-minute count never sees one account every five minutes, so count over the hour and the day. The rule fires alike on spray and stuffing because both are wide and shallow, so what tells them apart comes next: names that aren't yours, and 4624s mixed in. It counts per source too, so stuffing spread across many addresses needs a second count per application.",
      },
      {
        kind: "defuse",
        title: "Walk the Failed-Logon Alert",
        prompt: "The rule you just tuned fires at 01:12 on a Saturday and you're alone on the desk. Each module is one step of the investigation, in the order an analyst walks it. Read the state and cut the one wire that fits, before the clock runs out.",
        device: "Alert response · SP-AUTH-WATCH",
        seconds: 95,
        rounds: [
          {
            id: "d1", state: "Confirm the pattern. 198.51.100.140 wrote 44 4625s in six minutes: 0xC0000064 on 26 names, 0xC000006A on 18, one try each.",
            wires: [
              { id: "a", label: "Close it: 0xC0000064 means those logons went nowhere" },
              { id: "b", label: "Read it as enumeration plus spray; keep the 18 real names" },
              { id: "c", label: "Page the owners of all 44 names to change their passwords" },
            ],
            cut: "b", hint: "One of those codes says the name is real.",
            why: "0xC0000064 means the name doesn't exist, so the attacker is also testing who's real. 0xC000006A means the name exists, so those 18 are your real targets. 26 of the 44 have no owner to page.",
          },
          {
            id: "d2", state: "Failures stopped at 01:17. The queue is quiet. You have the source address and nothing else has fired.",
            wires: [
              { id: "a", label: "Search 4624s from that IpAddress since the first failure" },
              { id: "b", label: "Widen the 4625 search to see how many more failures there were" },
              { id: "c", label: "Geolocate it, note the country, and mark it attempted only" },
            ],
            cut: "a", hint: "What would make this an emergency?",
            why: "A 4624 after the failures means access gained, and priority jumps at once. More 4625s only measure the noise. Enrich the address next: your VPN range, a home ISP, a Tor exit, or a datacenter somewhere you don't operate?",
          },
          {
            id: "d3", state: "At 01:31 the shape changes. Same source, now six tries per account, and nine 4740s in three minutes. None were there before.",
            wires: [
              { id: "a", label: "A batch of staff forgot passwords: send them to the helpdesk" },
              { id: "b", label: "Drop the lockout threshold to 3 so accounts lock sooner" },
              { id: "c", label: "Same attack, gone loud: re-check for any success" },
            ],
            cut: "c", hint: "One lockout is normal. Nine at 01:31 are not.",
            why: "A quiet spray stays under the threshold and shows no 4740s. A wave of them means the attacker got impatient. Lowering the threshold would hand them an easier way to lock out your staff.",
          },
          {
            id: "d4", state: "One 4624 from that source for m.brandt at 01:44. At 01:49: 4624 Type 3 for m.brandt on SP-FS03, then a 5140 on the Treasury share.",
            wires: [
              { id: "a", label: "Cut the foothold: switch m.brandt off, brief Tier 2" },
              { id: "b", label: "Block that address, since the source of it all is now stopped" },
              { id: "c", label: "Leave a note for m.brandt to call in when the branch opens" },
            ],
            cut: "a", hint: "Which of these stops an attacker already on the file server?",
            why: "It has already moved, and blocking one address doesn't touch a session on SP-FS03. Disable the account while the investigation runs, and write it up: first failure, last failure, the success, the source, the share.",
          },
        ],
        lesson: "Confirm the shape, look for the success, enrich the source, check the targets and lockouts, follow the account to other hosts, then document and escalate. The first event is only the alarm: every step asks what the 4625s were for.",
      },
      {
        kind: "sequence",
        title: "Rebuild the Attack from the Log",
        prompt: "A sister credit union sent Tove its closed case: five log extracts, with the timestamps lost in the handover. Tap them in the order they must have happened. Each one has to be possible before the next.",
        items: [
          { id: "look", text: "net.exe group queries run as d.pryce (4688), and a 5140 shows SYSVOL opened" },
          { id: "spray", text: "4625 SubStatus 0xC000006A, one try each, on 240 names from 203.0.113.19" },
          { id: "move", text: "4648 on d.pryce's host, then a 4624 Type 3 on the mail server" },
          { id: "names", text: "4625 SubStatus 0xC0000064 on 300 names from 203.0.113.19" },
          { id: "land", text: "4624 for d.pryce from 203.0.113.19" },
        ],
        order: ["names", "spray", "land", "look", "move"],
        doneNote: "Each extract needs the one before it: only names that exist are worth spraying, a spray has to land before there's a session, and nobody moves on until they've looked around. Reading a log forward like this tells you where to look next, and what to expect there.",
      },
    ],
  },
};
