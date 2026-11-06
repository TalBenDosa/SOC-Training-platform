import type { BriefingLab, RoomExperience } from "./types";

// "Operation Tenant Zero" for the "entra-id" room.
// Script: docs/campaign/55-entra-id.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Compass Rose Tours (fictional), not the graded tasks' corp.com records.
// Signature mechanic: portal in a new Entra-style skin, working one sign-in through its
// detail tabs, the audit log and the role activation that explains it.
// Game mix: codebreak + duel + portal + tune.
// Lab data differs from the graded tasks: the codebreak uses 50053, 50057, 65001 and 70044,
// never 50126 (q2, la1) or 50076 (flag1), and the console names no error codes. No
// Shanghai or New York (la1), no hotel sign-in (q4), and no push bombing move (q3).

type Portal = Extract<BriefingLab, { kind: "portal" }>;

const SIGNIN_LAB: Portal = {
  kind: "portal",
  skin: "entra",
  title: "Work the Sign-in",
  prompt: "Monday, 07:40. Tour guide t.varga rang from Porto: the booking system says they changed a rota at 02:00, and they were asleep. Mirela Popescu opens the admin center and slides you the keyboard. Follow one sign-in until you know how it got through, and who let it.",
  product: "Identity admin center",
  resource: "Compass Rose Tours",
  tenant: "compassrose.example",
  home: "overview",
  menu: [
    { items: [{ id: "overview", label: "Overview" }, { id: "users", label: "Users" }] },
    { group: "Protection", items: [{ id: "ca", label: "Conditional Access" }, { id: "risky", label: "Risky sign-ins" }] },
    { group: "Identity governance", items: [{ id: "pim", label: "Privileged Identity Management" }] },
    { group: "Monitoring & health", items: [{ id: "signins", label: "Sign-in logs" }, { id: "audit", label: "Audit logs" }] },
  ],
  pages: {
    overview: { heading: "Overview", tiles: [{ label: "Users", value: "1,284" }, { label: "Groups", value: "96" }, { label: "Applications", value: "41" }], note: "Tenant ID 7f3e2c10-58ab-4e0d-9b1a-2c6e7d4a1f90. Primary domain compassrose.example." },
    users: {
      heading: "Users",
      table: {
        columns: ["Display name", "User principal name", "User type", "Account enabled"],
        rows: [
          { id: "u-mp", cells: ["Mirela Popescu", "m.popescu@compassrose.example", "Member", "Yes"], record: "u-mp" },
          { id: "u-tv", cells: ["Tibor Varga", "t.varga@compassrose.example", "Member", "Yes"], record: "u-tv" },
          { id: "u-kf", cells: ["Kit Ferris", "k.ferris@compassrose.example", "Member", "Yes"], record: "u-kf" },
        ],
      },
    },
    ca: {
      heading: "Conditional Access | Policies",
      table: {
        columns: ["Policy name", "State", "Creation date", "Modified date"],
        rows: [
          { id: "c1", cells: ["Require MFA outside offices", "On", "2025-03-11", "Today 01:14"] },
          { id: "c2", cells: ["Block legacy authentication", "On", "2025-03-11", "2025-09-02"] },
          { id: "c3", cells: ["Require compliant device for Finance", "On", "2025-06-20", "2025-06-20"] },
        ],
      },
    },
    risky: { heading: "Risky sign-ins", note: "Nothing rated at risk for this account. A sign-in with the right password from a quiet address often isn't." },
    pim: {
      heading: "Privileged Identity Management | Audit",
      table: {
        columns: ["Time", "Requestor", "Operation", "Role", "Justification"],
        rows: [
          { id: "p-mp", cells: ["Friday 11:02", "m.popescu", "Add member to role completed (PIM activation)", "Security Reader", "Weekly access review"], record: "p-mp" },
          { id: "p-kf", cells: ["Today 01:09", "k.ferris", "Add member to role completed (PIM activation)", "Conditional Access Administrator", "fix"], record: "p-kf" },
          { id: "p-el", cells: ["2025-11-04 09:30", "m.popescu", "Add eligible member to role in PIM", "Conditional Access Administrator", "Onboarding k.ferris"], record: "p-el" },
        ],
      },
    },
    signins: {
      heading: "Sign-in events",
      filters: ["User contains: t.varga", "Date: Last 24 hours", "Show dates as: Local"],
      table: {
        columns: ["Date", "User", "Application", "Status", "IP address", "Location", "Conditional Access"],
        rows: [
          { id: "s-1", cells: ["02:02:11", "Tibor Varga", "Rota Portal", "Failure", "203.0.113.84", "Sofia, BG", "Not Applied"], record: "s-1", tone: "low" },
          { id: "s-2", cells: ["02:03:40", "Tibor Varga", "Rota Portal", "Success", "203.0.113.84", "Sofia, BG", "Not Applied"], record: "s-2", tone: "high" },
          { id: "s-3", cells: ["07:21:05", "Tibor Varga", "Office 365", "Success", "198.51.100.23", "Porto, PT", "Success"], record: "s-3" },
        ],
      },
    },
    audit: {
      heading: "Audit logs",
      filters: ["Date: Last 24 hours", "Service: All", "Category: All"],
      table: {
        columns: ["Date", "Service", "Category", "Activity", "Status", "Initiated by (actor)"],
        rows: [
          { id: "a-pw", cells: ["06:58:12", "Core Directory", "UserManagement", "Reset user password", "Success", "Self-service"], record: "a-pw" },
          { id: "a-ca", cells: ["01:14:36", "Conditional Access", "Policy", "Update conditional access policy", "Success", "k.ferris@compassrose.example"], record: "a-ca" },
          { id: "a-add", cells: ["Friday 16:20", "Core Directory", "UserManagement", "Add user", "Success", "m.popescu@compassrose.example"], record: "a-add" },
        ],
      },
    },
  },
  records: {
    "s-1": { id: "s-1", title: "Activity Details: Sign-ins", actions: [{ id: "basic", label: "Basic info" }, { id: "loc", label: "Location" }, { id: "auth", label: "Authentication Details" }, { id: "capol", label: "Conditional Access" }], facts: [["User", "t.varga@compassrose.example"], ["Status", "Failure"], ["Failure reason", "Invalid username or password"]], panes: { auth: [["Result", "No factor reached"]], capol: [["Result", "Not Applied: sign-in never got that far"]], loc: [["IP address", "203.0.113.84"], ["Location", "Sofia, BG"]] } },
    "s-2": { id: "s-2", title: "Activity Details: Sign-ins", actions: [{ id: "basic", label: "Basic info" }, { id: "loc", label: "Location" }, { id: "auth", label: "Authentication Details" }, { id: "capol", label: "Conditional Access" }], facts: [["User", "t.varga@compassrose.example"], ["Application", "Rota Portal"], ["Status", "Success"], ["Client app", "Browser"]], panes: { loc: [["IP address", "203.0.113.84"], ["Location", "Sofia, BG"], ["Named location", "Partner-Sofia (trusted)"]], auth: [["Authentication requirement", "Single-factor authentication"], ["Method", "Password"], ["MFA required", "No"]], capol: [["Require MFA outside offices", "Not Applied"], ["Reason", "Excluded location: Partner-Sofia"], ["Block legacy authentication", "Not Applied: client is a browser"]] } },
    "s-3": { id: "s-3", title: "Activity Details: Sign-ins", actions: [{ id: "basic", label: "Basic info" }, { id: "loc", label: "Location" }, { id: "auth", label: "Authentication Details" }, { id: "capol", label: "Conditional Access" }], facts: [["User", "t.varga@compassrose.example"], ["Application", "Office 365"], ["Status", "Success"]], panes: { auth: [["Authentication requirement", "Multifactor authentication"], ["Method", "Authenticator app"]], capol: [["Require MFA outside offices", "Success"]], loc: [["Location", "Porto, PT"]] } },
    "a-ca": { id: "a-ca", title: "Audit Log Details", facts: [["Activity", "Update conditional access policy"], ["Target", "Require MFA outside offices"], ["Initiated by", "k.ferris@compassrose.example"], ["Modified property", "excludeLocations"], ["New value", "Partner-Sofia"]] },
    "a-pw": { id: "a-pw", title: "Audit Log Details", facts: [["Activity", "Reset user password"], ["Target", "t.varga@compassrose.example"], ["Note", "Tibor, this morning, after the call"]] },
    "a-add": { id: "a-add", title: "Audit Log Details", facts: [["Activity", "Add user"], ["Target", "a new seasonal guide"]] },
    "p-kf": { id: "p-kf", title: "PIM activation", facts: [["Requestor", "k.ferris"], ["Role", "Conditional Access Administrator"], ["Duration", "1 hour"], ["Justification", "fix"], ["Started", "Today 01:09"], ["Approver", "None required"]] },
    "p-mp": { id: "p-mp", title: "PIM activation", facts: [["Requestor", "m.popescu"], ["Role", "Security Reader"], ["Justification", "Weekly access review"]] },
    "p-el": { id: "p-el", title: "PIM eligibility", facts: [["Role", "Conditional Access Administrator"], ["Note", "Eligible since onboarding. Eligible isn't active"]] },
    "u-kf": { id: "u-kf", title: "Kit Ferris", facts: [["User principal name", "k.ferris@compassrose.example"], ["Job title", "IT Support"], ["Last sign-in", "Today 01:06"]], actions: [{ id: "revoke", label: "Revoke sessions" }, { id: "delete", label: "Delete" }] },
    "u-tv": { id: "u-tv", title: "Tibor Varga", facts: [["User principal name", "t.varga@compassrose.example"], ["Job title", "Tour Guide"], ["Password", "Reset today 06:58"]], actions: [{ id: "revoketv", label: "Revoke sessions" }] },
    "u-mp": { id: "u-mp", title: "Mirela Popescu", facts: [["User principal name", "m.popescu@compassrose.example"], ["Job title", "Identity Engineer"]] },
  },
  steps: [
    { id: "logs", ask: "Start where every sign-in is recorded.", hint: "Monitoring & health, in the menu on the left.", target: "menu:signins", why: "Sign-in logs hold every attempt to get a token: who, which app, from where, and what the policies decided. The filter is already on t.varga." },
    { id: "row", ask: "Open the sign-in that got through to the Rota Portal at 02:00.", hint: "A failure proves nothing happened. Find the one that worked.", target: "row:s-2", why: "Same address a minute after a failure, and this one worked. Whoever it was had the password. The Conditional Access column says Not Applied, and that's the odd part." },
    { id: "auth", ask: "How did it authenticate? Check the proof it gave.", hint: "The detail tabs across the top of the pane.", target: "action:auth", why: "Single-factor: a password and nothing else. Tibor's account requires MFA outside the offices, so why didn't it here?" },
    { id: "capol", ask: "Find out what the policies did with this sign-in.", hint: "There's a tab for each policy's result.", target: "action:capol", why: "Not Applied, and the reason is an excluded location. The policy didn't fail. It was told not to look at this address. Not Applied means the conditions didn't match, not that access was refused." },
    { id: "audit", ask: "Somebody changed that policy. Find out where changes are written down.", hint: "Monitoring & health again.", target: "menu:audit", why: "Sign-in logs say who got in. Audit logs say who changed the tenant. You need both." },
    { id: "change", ask: "Open the change behind the exclusion.", hint: "Look at the Activity column, and at the hour.", target: "row:a-ca", why: "01:14, under an hour before the sign-in. k.ferris added Partner-Sofia to excludeLocations. A policy being weakened is the event to look for, not only the policy being deleted." },
    { id: "pim", ask: "k.ferris is IT Support and has no standing admin role. Find out how that was possible.", hint: "Privileged roles are activated in one place.", target: "menu:pim", why: "With just-in-time access a role is only active on request, so every activation leaves a record." },
    { id: "act", ask: "Open the activation that fits the timing.", hint: "Just before 01:14.", target: "row:p-kf", why: "Activated at 01:09 with the justification \"fix\", no approver needed, and five minutes later the policy changes. An out-of-hours activation with a one-word reason is exactly what you'd alert on." },
    { id: "users", ask: "Someone may be using k.ferris right now. Go to the account.", hint: "Users, near the top of the menu.", target: "menu:users", why: "Two accounts are involved, and the one that made the change is the one with admin reach." },
    { id: "who", ask: "Open the account that made the change.", hint: "The one who activated the role.", target: "row:u-kf", why: "Last sign-in 01:06, three minutes before the activation." },
    { id: "revoke", ask: "End whatever that account has open.", hint: "The buttons on the user's page.", target: "action:revoke", why: "Revoking sessions invalidates its refresh tokens, so a token already issued stops being renewed. A password reset alone doesn't remove a session someone already has." },
  ],
  traps: {
    "row:s-1": "That one failed: a wrong password. It tells you someone tried, not how they got in.",
    "row:s-3": "That's Tibor in Porto this morning, with MFA. It's the real person.",
    "row:a-pw": "That's Tibor fixing it after the call. It tells you nothing about 02:00.",
    "row:a-add": "A new seasonal guide on Friday. Nothing to do with this policy.",
    "row:p-mp": "Mirela reading access reviews on Friday. Wrong person, wrong day.",
    "row:p-el": "Eligibility is old and routine. It says k.ferris could activate, not that they did.",
    "row:u-tv": "Tibor's password is already reset. The account with admin reach is the urgent one.",
    "action:delete": "Deleting the account destroys your evidence and may lock out a real employee. End the sessions first.",
    "action:revoketv": "Worth doing, but it isn't the account that changed the policy.",
  },
  lesson: "A successful sign-in is only the start. The detail tabs tell you what proof it gave and what each policy decided, the audit log tells you who changed the policy, and PIM tells you where that right came from. Not Applied is a question, not an answer.",
};

export const ENTRA_ID: RoomExperience = {
  roomId: "entra-id",
  codename: "Operation Tenant Zero",
  theme: "tenant",
  handler: { name: "Mirela Popescu", role: "Identity Engineer, Compass Rose Tours" },
  briefing: [
    "Compass Rose Tours. 900 guides in 40 countries, and not one office most of them have ever seen.",
    "For a company like this the network has no edge. The only wall left is the sign-in, and it's all held in one tenant.",
    "Mirela Popescu's warning is simple: here, every guide looks like impossible travel, so the alarm isn't enough. You have to read what the sign-in actually did.",
    "Learn what's in a tenant, how a policy decides, where rights come from, and why a failed sign-in can still be bad news.",
  ],
  mission: "Tell cloud attacks from on-prem ones, crack the sign-in codes, follow one sign-in through the console to the role behind it, tune a spray rule, beat an intruder's moves, then work the graded alert.",
  estimate: "~55 min",
  look: { primary: "#60a5fa", secondary: "#c084fc", warn: "#fb7185" },
  scene: "facilityentra",
  layout: "facility",
  stations: [
    {
      id: "tenant",
      label: "The Tenant",
      topic: "Cloud identity against on-prem AD · tenants, apps and service principals · sign-in methods",
      tagline: "What's actually in there?",
      building: "control",
      taskIds: ["entra-r1", "entra-q5"],
    },
    {
      id: "checkpoint",
      label: "The Checkpoint",
      topic: "Conditional Access · reading sign-in logs and error codes",
      tagline: "Who has to prove what?",
      building: "office",
      taskIds: ["entra-r2", "entra-q2", "entra-q4"],
    },
    {
      id: "jit",
      label: "Just in Time",
      topic: "ID Protection · PIM · identity attack patterns · audit events",
      tagline: "Where did that right come from?",
      building: "lab",
      taskIds: ["entra-r3", "entra-q1", "entra-q3"],
    },
    {
      id: "failed",
      label: "Failed, Not Safe",
      topic: "Reading a high-risk failed sign-in to the end",
      tagline: "Finish the story",
      building: "ticket",
      taskIds: ["entra-la1", "entra-flag1"],
      boss: true,
    },
  ],
  personas: {
    "entra-q5": { name: "Mirela Popescu", role: "Identity Engineer", line: "Half the sign-ins in this tenant aren't people. What's signing in?" },
    "entra-q2": { name: "Mirela Popescu", role: "Identity Engineer", line: "One code. Say what it means without looking." },
    "entra-q4": { name: "Mirela Popescu", role: "Identity Engineer", line: "Read the policy as written. What happens to this sign-in?" },
    "entra-q1": { name: "Mirela Popescu", role: "Identity Engineer", line: "Why bother with activation at all?" },
    "entra-q3": { name: "Mirela Popescu", role: "Identity Engineer", line: "It's a person's phone, at two in the morning. How does this one work?" },
    "entra-la1": { name: "Mirela Popescu", role: "Identity Engineer", line: "It failed. That's not the end of the story." },
    "entra-flag1": { name: "Mirela Popescu", role: "Identity Engineer", line: "Same record, one what-if." },
  },
  briefings: {
    // ── Reading 1: two worlds ──
    "entra-r1": [
      {
        kind: "sort",
        title: "Which World Is It In?",
        prompt: "Compass Rose kept one old domain controller for the Porto office, and everything else lives in the tenant. A new analyst has mixed up the runbooks. Put each one back where it belongs.",
        buckets: [{ id: "ad", label: "On-prem Active Directory" }, { id: "entra", label: "Entra ID" }],
        items: [
          { id: "a", text: "Kerberos tickets", bucket: "ad", why: "Domain controllers issue them. Entra ID speaks SAML, OpenID Connect and OAuth instead." },
          { id: "b", text: "OAuth 2.0 access tokens", bucket: "entra", why: "A cloud sign-in ends in a token, and that token is what an attacker wants." },
          { id: "c", text: "DCSync", bucket: "ad", why: "It abuses replication between domain controllers, and a tenant has none you can reach." },
          { id: "d", text: "Password spray at the cloud sign-in endpoint", bucket: "entra", why: "The sign-in page is on the internet, so the attacker doesn't need to be on your network." },
          { id: "e", text: "Group Policy Objects", bucket: "ad", why: "Domain-joined machines take them. Tenants have policies, but of a different kind." },
          { id: "f", text: "A managed identity on an Azure Function", bucket: "entra", why: "A credential the platform looks after, with no password to steal and no secret to rotate." },
          { id: "g", text: "An app registration's client ID", bucket: "entra", why: "How the tenant knows an application." },
          { id: "h", text: "Pass-the-Hash against a file server", bucket: "ad", why: "That's NTLM, which is on-prem protocol territory." },
        ],
      },
    ],
    // ── Reading 2: the codes ──
    "entra-r2": [
      {
        kind: "codebreak",
        title: "Crack the Sign-in Codes",
        prompt: "Mirela reads sign-in logs by number. Each clue describes a failure at Compass Rose. Crack the code, because you won't get a sentence in a filter.",
        tries: 6,
        rounds: [
          { id: "lock", clue: "A guide tried too many times and the account locked", answer: "50053", why: "Lockout. Across one user it's a fumbled password. Across many users in one hour, look closer." },
          { id: "dis", clue: "A sign-in to an account that HR already disabled", answer: "50057", why: "The password may be right, and it doesn't matter. A leaver's account being tried is worth a look." },
          { id: "cons", clue: "The user hasn't consented to the application", answer: "65001", why: "Not an attack by itself. It shows up around new apps, which is where consent phishing lives too." },
          { id: "exp", clue: "The session's token lifetime ran out", answer: "70044", why: "Routine. This one shows up all day, and it's why you don't alert on every failure." },
        ],
        lesson: "A failure code is the tenant telling you how far a sign-in got. Read the code first, and the word Failure means much less than where exactly it failed.",
      },
    ],
    // ── Reading 3: signature console, then the rule and the duel ──
    "entra-r3": [
      SIGNIN_LAB,
      {
        kind: "tune",
        title: "Tune the Spray Rule",
        prompt: "With guides on every continent, failed sign-ins are constant. Mirela wants a rule for one address trying many accounts. Set it so it catches the sprays without firing on a hotel full of guides.",
        eventColumn: "Hour",
        dials: [
          { id: "acct", label: "Different accounts failing from one IP, at least", short: "Accounts", min: 1, max: 40, step: 1, start: 1, dir: "above" },
          { id: "per", label: "Tries per account, at most", short: "Tries each", min: 1, max: 10, step: 1, start: 10, dir: "below" },
        ],
        events: [
          { id: "a1", label: "One address, 34 guides, one try each", bad: true, values: { acct: 34, per: 1 } },
          { id: "a2", label: "One address, 18 accounts, two tries each", bad: true, values: { acct: 18, per: 2 } },
          { id: "a3", label: "Slow spray, 12 accounts, one try each", bad: true, values: { acct: 12, per: 1 } },
          { id: "g1", label: "Hotel Wi-Fi, 9 guides, new passwords after a reset", bad: false, values: { acct: 9, per: 3 } },
          { id: "g2", label: "One guide, old phone retrying", bad: false, values: { acct: 1, per: 9 } },
          { id: "g3", label: "Lisbon office after a password policy change", bad: false, values: { acct: 15, per: 4 } },
          { id: "g4", label: "Two guides sharing a hotel lobby", bad: false, values: { acct: 2, per: 2 } },
        ],
        goal: { catch: 3, maxFalse: 0 },
        lesson: "A spray is wide and shallow: many accounts, very few tries each, to stay under lockout. Brute force is the opposite shape. Both dials together are what separate a spray from a hotel lobby after a reset.",
      },
      {
        kind: "duel",
        title: "The Identity Duel",
        prompt: "An intruder is working through Compass Rose's identity layer. Each move is one this tenant has really seen in reports. Play the control that really stops it. Some good controls don't help here.",
        attacker: "An intruder with a list of guide email addresses",
        moves: [
          { id: "m1", move: "Tries old mail clients that can't do MFA", detail: "IMAP, with a password from a breach.", counter: "legacy", hint: "This route skips the second factor altogether. Close the route.", why: "Legacy clients can't be asked for MFA, so blocking legacy authentication closes that door." },
          { id: "m2", move: "Uses leaked credentials on a real account", detail: "The pair turned up on a paste site.", counter: "reset", hint: "The risk belongs to the user, not to one sign-in.", why: "High user risk is what the password-reset remediation is for: leaked credentials make the password itself the problem." },
          { id: "m3", move: "Replays a stolen access token", detail: "MFA already happened, when the token was issued.", counter: "fido", hint: "Which of your cards keeps the credential from being phished in the first place?", why: "Phishing-resistant sign-in keeps the token from being stolen by a fake page, because the key won't answer for the wrong site. A new MFA prompt wouldn't appear at all." },
          { id: "m4", move: "Waits for a helpdesk admin's account", detail: "Global Administrator assigned permanently, since 2022.", counter: "pim", hint: "The danger is that the role is always on.", why: "If the role isn't active, taking the account doesn't hand over the role. That's what removing standing privilege means." },
        ],
        cards: [
          { id: "legacy", name: "Block legacy authentication", effect: "Denies clients that can't do MFA" },
          { id: "reset", name: "User-risk policy", effect: "Forces a password reset at high user risk" },
          { id: "fido", name: "Phishing-resistant MFA", effect: "FIDO2 keys for every guide" },
          { id: "pim", name: "PIM", effect: "Roles active only on request" },
          { id: "sms", name: "SMS codes", effect: "One-time code by text" },
          { id: "tou", name: "Terms of use", effect: "Users must accept a policy first" },
        ],
        lesson: "Each attack gets past something different: the factor, the password, the token or the role. No single control answers all of them, so know which layer each one touches.",
      },
    ],
  },
};
