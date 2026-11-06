import type { RoomExperience } from "./types";

// "Operation Hold Music" for the "vishing-helpdesk-social-engineering" room.
// Script: docs/campaign/93-vishing-helpdesk-social-engineering.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Brindle Mutual Insurance (fictional), not the graded tasks' solsticefg.com records.
// Signature: The Reset That Wasn't. A trace from one helpdesk ticket through the password reset
// and the MFA change to the attacker's first sign-in, and a queue of reset requests where the
// learner reads which one deserves a stop. Rooms 88 and 92 own device persistence and synthetic
// voices, so this room stays on the call and the ticket trail.
// Game mix: deduce + duel + spotdiff.
// Task order CHANGED. Room order: r0, r1, r2, r3, q1, m1, r4, r5, q2, r6, r7, q3, o1, la1, ac1, q4, f1.
// New order: r0, r1, q1, o1 | r2, r3, m1, q2, f1 | r4, r5, q3 | r6, r7, q4 | la1, ac1.
// Readings keep their relative order, so "next reading" and "earlier reading" stay true, and la1
// stays right before ac1, whose scenario says "you just worked through". No flag cites a task
// number.
// Lab data differs from the graded tasks: no r.castillo, m.alvarez, j.whitfield, d.nakamura,
// 198.51.100.44, 203.0.113.19, Chicago, Denver or HD-30217. Hanna's ticket records a staff number
// and a manager's name (la1 has an employee ID and a date of birth), the caller's pretext is a
// dead authenticator app, not a lost or replaced phone (la1, ac1), and the sign-in comes 16
// minutes after the reset (q3 has 20, ac1 has 9). Queue tickets that pass use a callback with no
// new device, a badge check with a rebuilt laptop, and a manager's confirmation, never
// a callback followed by a new device (ac1). The spotdiff compares User registered and Admin
// registered security info, with an Authentication Administrator actor, never a password reset,
// and has no initiatedBy.user.ipAddress line (la1 question 1). The stages appear once in chain order, as the duel's story, in Brindle's words,
// and are never asked as an order (o1). ATT&CK IDs sit on an anatomy filed by ID, as data (q1,
// f1). The five public cases are rows in a table whose questions ask something else (m1). The
// boss lab labels alerts from other rules, with no reset in it (ac1). Worked examples use a
// front door, a garage, a gym locker, a hotel, a block of flats, a department change, a
// replacement bank card, a bank's call, a VPN rule and a smoke alarm.
// The Case Files table names real companies from the room's own readings. That is teaching
// text, not console chrome, and m1 needs it.
// la1 and ac1 raw events pair Reset password (by admin) with loggedByService "Core Directory",
// and la1's explanation leans on it. Microsoft's audit reference lists that activity under
// Self-service Password Management. The labs show neither value. Graded data left as it is.

export const VISHING_HELPDESK_SOCIAL_ENGINEERING: RoomExperience = {
  roomId: "vishing-helpdesk-social-engineering",
  codename: "Operation Hold Music",
  theme: "holdmusic",
  handler: { name: "Marek Oduya", role: "Identity Response Lead, Brindle Mutual Insurance" },
  briefing: [
    "Brindle Mutual Insurance. 640 staff, one service desk, and a promise to answer every call inside a minute.",
    "On Thursday at 16:22 a caller spent four minutes on hold, then hung up with a new password and a new phone on Hanna Lindqvist's account.",
    "Hanna runs Claims Payments, was on leave with no signal, and never rang anyone. The ticket says Resolved.",
    "Marek Oduya needs you to read what a call leaves behind, find who really got that reset, and know which of tomorrow's resets deserves a stop.",
  ],
  mission: "See why no control hears a call, stop one at every stage, sort what a stranger can research, read five public cases, trace the reset that wasn't, decide which reset requests get a stop, test a detection rule on real days, then make the last call on a record that looks the same.",
  estimate: "~55 min",
  look: { primary: "#e5989b", secondary: "#a8dadc", warn: "#ff5d52" },
  scene: "facilityholdmusic",
  layout: "facility",
  stations: [
    {
      id: "script",
      label: "The Call Script",
      topic: "Why a call has nothing to inspect · the stages of a help-desk attack · ATT&CK for voice",
      tagline: "Nothing to scan but a person",
      building: "reception",
      taskIds: ["vish-r0", "vish-r1", "vish-q1", "vish-o1"],
    },
    {
      id: "casefiles",
      label: "The Case Files",
      topic: "Questions a stranger can answer · five public cases · two kinds of call",
      tagline: "Some calls never reach the desk",
      building: "archive",
      taskIds: ["vish-r2", "vish-r3", "vish-m1", "vish-q2", "vish-f1"],
    },
    {
      id: "trail",
      label: "The Ticket Trail",
      topic: "Reading an audit record · ticket to first sign-in · what a real check looks like",
      tagline: "The call leaves no log. What follows does",
      building: "ticket",
      taskIds: ["vish-r4", "vish-r5", "vish-q3"],
    },
    {
      id: "standing",
      label: "The Standing Order",
      topic: "Correlation rules · a ticket that holds up · hardening the desk",
      tagline: "Make the next call fail",
      building: "control",
      taskIds: ["vish-r6", "vish-r7", "vish-q4"],
    },
    {
      id: "second",
      label: "The Second Call",
      topic: "Reading a reset record · closing a case with the right label",
      tagline: "Read it before you judge it",
      building: "emergency",
      taskIds: ["vish-la1", "vish-ac1"],
      boss: true,
    },
  ],
  personas: {
    "vish-q1": { name: "Marek Oduya", role: "Identity Response Lead", line: "Two steps in this one. Name them properly for the case notes." },
    "vish-o1": { name: "Marek Oduya", role: "Identity Response Lead", line: "Lay it out for the board, first move to last." },
    "vish-m1": { name: "Marek Oduya", role: "Identity Response Lead", line: "Four public cases. Keep them straight." },
    "vish-q2": { name: "Marek Oduya", role: "Identity Response Lead", line: "Two calls, two trails. Which log do you open?" },
    "vish-f1": { name: "Marek Oduya", role: "Identity Response Lead", line: "Give me the ID for the ticket." },
    "vish-q3": { name: "Marek Oduya", role: "Identity Response Lead", line: "One more fact before I sign this off. Which one?" },
    "vish-q4": { name: "Marek Oduya", role: "Identity Response Lead", line: "The board wants one control with a name on it." },
    "vish-la1": { name: "Marek Oduya", role: "Identity Response Lead", line: "Another company's record. Read it the way you read ours." },
    "vish-ac1": { name: "Marek Oduya", role: "Identity Response Lead", line: "New ticket on your desk. Make the call and write the reason." },
  },
  briefings: {
    // ── Reading 0: what a phone call slips past ──
    "vish-r0": [
      {
        kind: "reactor",
        title: "Which Control Gets to Look?",
        prompt: "Thursday morning at Brindle Mutual, hours before the call. Everything that reaches the company goes through something that examines it, or it doesn't. Send each item to whatever examines it. If nothing can, send it to the person who has to decide alone.",
        primer: {
          title: "Why the phone is different",
          points: [
            "**Vishing** (voice phishing) is social engineering over a live call: a plausible story, a borrowed identity, and pressure to act now.",
            "Mail controls work because a message has parts to inspect: headers, links and attachments.",
            "The **IT help desk** is the richest target. Its job is to say yes to someone who is locked out, so it can reset a password, reset MFA (multi-factor authentication, a login proof of more than one kind) or register a new device.",
          ],
          example: {
            label: "The same question, at a front door",
            lines: [
              "A parcel goes through the scanner, so the scanner can say something about it.",
              "A visitor who simply talks to the receptionist goes through no scanner at all.",
              "So the honest answer to 'what checked this visitor?' is one person, alone, on the spot.",
            ],
          },
        },
        reactors: [
          { id: "auth", label: "Mail authentication", sub: "SPF, DKIM and DMARC check the sender" },
          { id: "url", label: "URL sandbox", sub: "Opens a link somewhere safe" },
          { id: "file", label: "Attachment detonation", sub: "Runs a file before delivery" },
          { id: "human", label: "A person", sub: "No control in the path" },
        ],
        items: [
          { id: "i1", text: "A mail claiming to be from brindlemutual.example, sent by a server outside its SPF record", reactor: "auth", why: "A message carries a sender domain, and the gateway can check that domain's published records." },
          { id: "i2", text: "A mail whose DKIM signature fails after it was altered in transit", reactor: "auth", why: "The signature is part of the message, so a control can test it." },
          { id: "i3", text: "An invoice mail linking to a domain registered yesterday", reactor: "url", why: "A link is something a sandbox can open and watch." },
          { id: "i4", text: "A mail linking to a look-alike of the staff sign-in page", reactor: "url", why: "Same again: the link can be followed before a person clicks it." },
          { id: "i5", text: "claim_form.docm attached to a broker's mail", reactor: "file", why: "A file can be run in isolation before anyone opens it." },
          { id: "i6", text: "An .html file attached to a mail from a new sender", reactor: "file", why: "An attachment is an object a control can pick up and examine." },
          { id: "i7", text: "A call to the service desk: 'I'm locked out and the payment run closes at five'", reactor: "human", why: "A call has no headers, no URL and no attachment, and nothing sits between the phone network and the agent. ATT&CK entry: T1566.004 Spearphishing Voice, parent T1566 Phishing, tactic Initial Access (TA0001), alongside Spearphishing Attachment, Link and via Service." },
          { id: "i8", text: "A call to a claims handler from someone saying they're from the bank", reactor: "human", why: "Anyone can be called. The help desk is simply the target that can change accounts." },
          { id: "i9", text: "A voicemail asking a manager to ring 'IT' back on a new number", reactor: "human", why: "Voice again. Excellent mail filtering stops none of it, which is why an attacker facing strong email controls picks up the phone." },
        ],
      },
    ],
    // ── Reading 1: the stages, and the techniques behind them ──
    "vish-r1": [
      {
        kind: "duel",
        title: "Stop the Call at Every Stage",
        prompt: "Marek turns the pattern behind Thursday into a duel. A caller is after a payments approver's account, and each round the caller plays the next move. Play the one Brindle control that stops that move. A control does its work at one stage, and a played card is gone.",
        primer: {
          title: "What a help-desk attack is made of",
          points: [
            "No software is exploited. Each stage hands the next one what it needs.",
            "An agent can be talked into three things: a **password reset**, a **reset or removal of MFA**, or **registering a new method or device**.",
            "A control stops one stage. So ask what this stage needs, and take that away.",
          ],
          example: {
            label: "The same shape, at a car garage",
            lines: [
              "Someone finds a customer's name on a review of the garage, then rings: 'I'm the owner, my friend will collect the car.'",
              "The keys are handed over, and the car leaves.",
              "The garage's fix isn't a better ear. Keys go only to the ID on the job sheet.",
            ],
          },
        },
        attacker: "The caller",
        moves: [
          { id: "m1", move: "Does the homework", detail: "Reads the Meet the Team page, a professional networking profile and an old breach dump. Nothing here touches a Brindle system.", counter: "script", hint: "You can't stop the reading. What can you make useless?", why: "Public research can't be blocked, so stop relying on it. If no verification step can be passed with researched facts, the homework buys nothing." },
          { id: "m2", move: "Rings the desk as the employee", detail: "A real name, a real manager, a real team, and a calm voice.", counter: "callback", hint: "The caller controls this line. Which line don't they control?", why: "End the call and ring the number in Brindle's own records. The caller can't answer a phone they were never given." },
          { id: "m3", move: "Asks for the reset, and for MFA to come off", detail: "'The app's gone, the run closes at five. Can you just take it off for today?'", counter: "second", hint: "One agent is deciding and acting. What if one agent couldn't?", why: "Removing MFA on a privileged account should need a second person. It closes the point of failure where one agent both verifies and acts." },
          { id: "m4", move: "Signs in with the working password", detail: "A real login from a device and a country this account has never used.", counter: "rule", hint: "Nothing here is broken, so no control blocks it. What can still notice?", why: "A valid login passes every authentication check. What exposes it is timing: an admin change, then a new device or country soon after, on the same account." },
          { id: "m5", move: "Adds their own authenticator", detail: "Now a later password reset won't lock them out.", counter: "methods", hint: "The password isn't what holds the door open any more.", why: "The foothold is a method, not a password. Whoever cleans up has to review the registered methods as well, or the access survives." },
        ],
        cards: [
          { id: "gateway", name: "Mail gateway", effect: "Checks headers, links and attachments on messages." },
          { id: "script", name: "New verification script", effect: "Drops every step that public facts can pass." },
          { id: "reset", name: "Force a password change", effect: "Replaces the password. Touches nothing else." },
          { id: "callback", name: "Hang up, ring the file number", effect: "The agent calls the number in Brindle's records." },
          { id: "rule", name: "Reset-then-sign-in alert", effect: "Joins admin changes to the sign-ins that follow." },
          { id: "second", name: "Second approver", effect: "One agent can't remove MFA alone." },
          { id: "methods", name: "Authentication method review", effect: "Lists and removes methods on the account." },
        ],
        lesson: "The stages depend on each other: research makes the call believable, the call gets the action, the action gives a working login, and the login lets the attacker settle in. Early cards prevent, later cards detect or clean up. Mail controls never get a turn.",
      },
      {
        kind: "anatomy",
        title: "One Call on the ATT&CK Map",
        prompt: "ATT&CK is the public catalogue of attacker techniques, and Brindle's case notes cite it. Here is every technique a help-desk call can touch, filed by ID, not by stage. Scan each one: what it names, which tactic (the attacker's goal) it sits under, and why.",
        source: "MITRE ATT&CK v19 · techniques in a voice case · sorted by ID",
        fields: [
          { key: "T1078", value: "Valid Accounts · Initial Access, Persistence, Privilege Escalation, Stealth", label: "Listed four times", note: "One working login does four jobs: it opens the door, it outlives the closing of the entry point, it brings whatever rights the account had, and it reads as the real employee." },
          { key: "T1098.005", value: "Account Manipulation: Device Registration", label: "Foothold", note: "A registered method or device stays in place after a password reset." },
          { key: "T1566.004", value: "Spearphishing Voice · Initial Access (TA0001)", label: "The call", note: "The phone call itself." },
          { key: "T1589", value: "Gather Victim Identity Information · Reconnaissance (TA0043)", label: "About a person", note: "Names, credentials, the answers to security questions." },
          { key: "T1591", value: "Gather Victim Org Information · Reconnaissance (TA0043)", label: "About the company", note: "Structure, departments and internal terms, so the caller sounds like an insider." },
          { key: "T1621", value: "Multi-Factor Authentication Request Generation · Credential Access (TA0006)", label: "The other kind of call", note: "The attacker already holds a password and triggers prompts, then talks the account owner into approving one. No help desk is involved." },
          { key: "T1684.001", value: "Social Engineering: Impersonation · Stealth (TA0005)", label: "Being someone else", note: "Formerly T1656. ATT&CK v19 moved it under a new parent, T1684. It sits under Stealth because the false identity is what slips the request past a human check, as a spoofed sender does in mail." },
        ],
        summary: "File each step by what the attacker is doing at that moment. Then ask who the call reached. A help-desk call ends in an admin changing an account. A call to the account owner ends in a prompt being approved. Those are two different kinds of record, and the next station shows why that matters.",
      },
    ],
    // ── Reading 2: why the desk's questions failed ──
    "vish-r2": [
      {
        kind: "sort",
        title: "Could a Stranger Answer This?",
        prompt: "In 2023, MGM's help desk reportedly leaned on questions a caller could prepare for. Marek has pulled Brindle's own verification script and a few alternatives. Sort each line: could someone outside Brindle pass it after an evening's research, or could they not?",
        primer: {
          title: "Knowledge-based authentication",
          points: [
            "**KBA** (knowledge-based authentication) checks a caller by asking things only the real person should know.",
            "Attackers collect those things first. `T1589` covers personal details and `T1591` covers organisation details, both under Reconnaissance (`TA0043`).",
            "Sources include professional networking sites, the company's own team page, data brokers and old breaches. Nothing has to be hacked.",
            "One test for any check: could someone who has never met this person pass it?",
          ],
          example: {
            label: "The test, on a gym locker",
            lines: [
              "Forgotten code. Staff ask which town you ran in last year. It's in the public race results, so a stranger passes.",
              "Staff compare your face with the photo on your membership. A stranger doesn't.",
            ],
          },
        },
        buckets: [
          { id: "stranger", label: "A stranger could pass it" },
          { id: "reach", label: "A stranger can't reach it" },
        ],
        items: [
          { id: "a", text: "Who is your line manager?", bucket: "stranger", why: "Org charts and profiles give this away: T1591 material." },
          { id: "b", text: "What is your job title, and what year did you join?", bucket: "stranger", why: "People publish both on their own profile." },
          { id: "c", text: "What is your home postcode?", bucket: "stranger", why: "Data brokers sell it: T1589 material." },
          { id: "d", text: "What are the last four digits of your mobile?", bucket: "stranger", why: "It turns up in old breach dumps, and it feels private, which is what makes it dangerous." },
          { id: "e", text: "What is the internal name of your team's current project?", bucket: "stranger", why: "It sounds like insider knowledge, but a few minutes of pretexting another department gets it." },
          { id: "f", text: "What is your staff number?", bucket: "stranger", why: "A number the employee can recite is a number that can leak. It's a fact, not a proof." },
          { id: "g", text: "The agent rings the number on the HR record, and you answer", bucket: "reach", why: "The agent picks the number and starts the call, so there is nothing for an outsider to prepare." },
          { id: "h", text: "You show your badge at reception and it matches the photo HR holds", bucket: "reach", why: "It needs the person, the badge and a record the caller can't edit." },
          { id: "i", text: "The agent rings your manager, who confirms the request", bucket: "reach", why: "The confirmation arrives on a line the caller doesn't control." },
        ],
      },
    ],
    // ── Reading 3: the cases, and the call that skips the desk ──
    "vish-r3": [
      {
        kind: "worksheet",
        title: "Five Calls on File",
        prompt: "Before the board asks, Marek wants the public record in one table. Five cases, in the order they became known. Read across each row, then answer from the table.",
        primer: {
          title: "Reading a case file",
          points: [
            "**Smishing** is phishing by text message.",
            "A **SIM swap** talks a mobile carrier into moving someone's number to an attacker's SIM card, which defeats SMS codes.",
            "**SSO** (single sign-on) is one login that opens many apps, so one takeover reaches them all.",
            "Read two things first in every row: who took the call, and what the attacker already had before it.",
          ],
          example: {
            label: "One row, read aloud, for a fictional hotel chain",
            lines: [
              "Who took the call: IT help desk. Before the call: an org chart found online. The call got: a new password.",
              "Read as: someone else changed the account, and research was all the attacker brought.",
            ],
          },
        },
        caption: "Public reporting · CISA advisory AA23-320A · company disclosures",
        columns: ["Case", "When", "Who took the call", "Before the call", "What the call got", "After"],
        rows: [
          ["Twilio", "Jun 2022", "An employee", "Nothing reported", "Working credentials, from a caller posing as IT", "About 12 hours of access to customer contact data"],
          ["Cisco", "Aug 2022", "An employee", "Password synced to a personal Google account, which fell first", "One approved MFA push, after push spam and calls posing as trusted organisations", "Intrusion stopped short of the most sensitive systems"],
          ["Retool", "Aug 2023", "An employee", "A texted fake portal took a password and an MFA code", "One more MFA code, in a voice cloned to resemble a real colleague who knew the office", "Attacker registered their own MFA method, reached 27 cloud customers"],
          ["MGM Resorts", "Sep 2023", "IT help desk", "An employee found on LinkedIn", "Credentials reset after a call of about ten minutes, on checks that relied on KBA", "Into the Okta identity environment, then wider IT, about ten days offline"],
          ["Caesars Entertainment", "Sep 2023", "IT help-desk vendor", "In some accounts, a SIM swap", "Passwords or MFA tokens reset on high-value SSO accounts", "Broad access across connected applications"],
        ],
        questions: [
          { id: "desk", q: "How many of the five calls never reached a help desk? (number)", hint: "Use the 'Who took the call' column.", answer: ["3", "three"], why: "Twilio, Cisco and Retool went straight to an employee. An analyst who only watches help-desk tickets never sees that kind of case." },
          { id: "had", q: "In how many of the five did the attacker already hold a password before the call? (number)", hint: "Use the 'Before the call' column. A SIM swap moves a phone number, not a password.", answer: ["2", "two"], why: "Cisco and Retool. With the password in hand, the call only had to get past MFA." },
        ],
      },
      {
        kind: "deduce",
        title: "The Call That Skipped the Desk",
        prompt: "Hanna's ticket makes Marek ask a harder question: has anyone at Brindle been rung directly? Six accounts from last month, all with an odd MFA day. One of them let a caller in, and the service desk never heard about it. Strike them out as the clues arrive.",
        primer: {
          title: "Who acted decides where the record lands",
          points: [
            "When someone else changes an account, an administration record appears: who did what to whom.",
            "When the owner answers a prompt, nothing is administered. All you get is the sign-in record.",
            "**Push spam**: the attacker holds the password, triggers prompt after prompt, and hopes a tired or persuaded owner taps approve.",
          ],
          example: {
            label: "The same split, in a block of flats",
            lines: [
              "A locksmith cuts a new key for a resident. The locksmith's book shows who asked.",
              "A resident buzzes a stranger in. There is no book, only the door log saying it opened at 21:04.",
            ],
          },
        },
        nameColumn: "Account",
        columns: ["Audit log that day", "Ticket", "Push prompts", "Approved?", "The owner's account of it"],
        suspects: [
          { id: "iqbal", name: "k.iqbal", cells: ["Reset password (by admin)", "SD-40112", "1", "Yes", "Locked out, rang the desk"] },
          { id: "achebe", name: "w.achebe", cells: ["None", "None", "1", "Yes", "Signing in at my desk"] },
          { id: "duarte", name: "s.duarte", cells: ["None", "None", "17 in 25 min", "No, all denied", "'IT' rang, so I hung up"] },
          { id: "tiernan", name: "b.tiernan", cells: ["None", "None", "6 in 20 min", "Yes, the sixth", "Was on a call with 'IT' at the time"] },
          { id: "papadakis", name: "n.papadakis", cells: ["Disable Strong Authentication", "SD-40140", "0", "Not prompted", "Asked the desk for help"] },
          { id: "ferro", name: "j.ferro", cells: ["None", "None", "3 in 20 min", "Yes", "Hotel Wi-Fi, I kept retrying"] },
        ],
        clues: [
          "No agent touched this account, so there's no ticket and no administration record.",
          "The attacker already had the password and triggered the prompts, so the owner wasn't the one signing in.",
          "It only worked because one prompt was approved.",
        ],
        culprit: "tiernan",
        why: "b.tiernan: six prompts nobody started, and one approval during a call from 'IT'. That is the account-owner kind of vishing, T1621 under Credential Access (TA0006). No ticket and no administration record exist, so the only trace is in the authentication log. s.duarte faced the same attack and denied every prompt. k.iqbal and n.papadakis are the other shape: an agent acted, so the audit log shows who changed what. j.ferro's prompts have an ordinary reason, and that account owner started them.",
      },
    ],
    // ── Reading 4: what the call leaves behind ──
    "vish-r4": [
      {
        kind: "spotdiff",
        title: "Self-Service or Someone Else?",
        prompt: "Two authentication methods added to one account, d.okafor, in the same week. Change A came from d.okafor. Find the lines in Change B that show another person did it.",
        primer: {
          title: "Who acted on whom",
          points: [
            "Every Entra ID audit record names the actor in `initiatedBy.user` and the changed account in `targetResources[0]`.",
            "Compare the two `id` values. The same value means the account acted on itself. Two values mean someone else acted on it.",
            "`initiatedBy.user.roles` lists the directory roles the actor held, such as Helpdesk Administrator or Authentication Administrator.",
          ],
          example: {
            label: "The same comparison, on a department change",
            lines: [
              "`Update user`: Department changed from Claims to Underwriting.",
              "`initiatedBy.user.id` 5d10f2c8-… and `targetResources[0].id` c93fa0b7-…: two values, so the actor isn't the account.",
              "`initiatedBy.user.roles`: User Administrator, a directory role.",
            ],
          },
        },
        goodTitle: "Change A · Monday · selected fields",
        suspectTitle: "Change B · Wednesday · selected fields",
        good: [
          "activityDateTime: 2026-11-02T08:41:09Z",
          "activityDisplayName: User registered security info",
          "category: UserManagement",
          "loggedByService: Authentication Methods",
          "result: success",
          "correlationId: 4be1a7d0-6c35-4f82-9d10-7ac2e5b3f614",
          "initiatedBy.user.id: 8e41c7a2-3d90-4b6f-a1e5-6f27d0c9b318",
          "initiatedBy.user.roles: []",
          "targetResources[0].type: User",
          "targetResources[0].userPrincipalName: d.okafor@brindlemutual.example",
          "targetResources[0].id: 8e41c7a2-3d90-4b6f-a1e5-6f27d0c9b318",
        ],
        suspect: [
          "activityDateTime: 2026-11-04T13:17:52Z",
          "activityDisplayName: Admin registered security info",
          "category: UserManagement",
          "loggedByService: Authentication Methods",
          "result: success",
          "correlationId: b07d3e19-92af-4c61-8e04-1d6fa2c7e583",
          "initiatedBy.user.id: 3a96d0f4-7e12-4c58-b4a9-e1c05d7f2b66",
          "initiatedBy.user.roles: [\"Authentication Administrator\"]",
          "targetResources[0].type: User",
          "targetResources[0].userPrincipalName: d.okafor@brindlemutual.example",
          "targetResources[0].id: 8e41c7a2-3d90-4b6f-a1e5-6f27d0c9b318",
        ],
        diffs: [
          { line: 1, why: "The activity name says it outright: User registered is the account holder, Admin registered is somebody else." },
          { line: 6, why: "This id no longer matches targetResources[0].id, so the actor and the changed account are two different identities." },
          { line: 7, why: "A role is present, so the actor was acting as an administrator of the directory." },
        ],
        decoys: [
          { line: 0, why: "Every event has its own time. That says when, not who." },
          { line: 5, why: "Each action gets its own correlationId. It groups the records from one action, and it names nobody." },
        ],
        lesson: "A different actor id and an admin role show that someone else made the change. They don't show whether that was right: a genuine request writes this record, and so does a successful vishing call.",
        hud: "Tap the lines that show someone else did Change B",
        sameLine: "That line reads the same in both records, so it can't tell them apart.",
        winTitle: "Someone else acted",
        howTo: ["Compare the two records line by line.", "Tap each line in Change B that shows another person acted on the account.", "A wrong tap costs a life, and tells you why."],
      },
      {
        kind: "trace",
        title: "The Reset That Wasn't",
        prompt: "Friday, 08:12. Hanna Lindqvist's password fails at the Leeds office, and the phone on the account belongs to nobody Hanna knows. The desk says Hanna rang yesterday. Hanna says no. Marek hands you the file: walk it from the ticket to the first sign-in.",
        primer: {
          title: "Following a change across three records",
          points: [
            "No log holds what was said on a call. You work from the **ticket** before the change and the **records** after it.",
            "Entra audit log, category `UserManagement`: `Reset password (by admin)`, `Disable Strong Authentication` (removes the MFA requirement), `Update user` (attributes such as a phone number) and `Admin registered security info` (a method added for someone).",
            "Entra sign-in log, per attempt: `ipAddress`, `location.countryOrRegion`, `deviceDetail.deviceId`, `deviceDetail.trustType`, `authenticationRequirement`. An empty `deviceId` means the directory doesn't know that device.",
            "**Timing** ties them together: the same account, minutes to a few hours apart.",
          ],
          example: {
            label: "The same trail, on a replacement bank card",
            lines: [
              "Branch note, 10:02: replacement card issued, no ID check written down.",
              "Card system, 10:04: new card linked to the account.",
              "Cash machine, 10:21: first use, in a town this customer has never used.",
            ],
          },
        },
        lead: "h.lindqvist@brindlemutual.example, Claims Payments Manager, on leave until Friday. Start at the service desk, Thursday afternoon.",
        steps: [
          {
            id: "ticket",
            ask: "Hanna never called. Find the ticket that says Hanna did.",
            source: "Service desk · tickets · Thursday 2026-11-05",
            columns: ["Ticket", "Opened", "Caller says they are", "Request", "Verification recorded", "Agent", "State"],
            rows: [
              ["SD-41862", "14:05", "g.fenn", "Password reset", "Badge checked at reception", "t.nowell", "Resolved"],
              ["SD-41871", "15:40", "h.lindgren", "New laptop setup", "Manager approval, CHG-2291", "t.nowell", "Resolved"],
              ["SD-41877", "16:22", "h.lindqvist", "Password reset. App stopped working: add temporary mobile +44 7700 900412 for MFA", "Staff number, manager's name. Held 4 min", "p.sandoval", "Resolved"],
              ["SD-41880", "16:51", "o.marsh", "Password reset", "Rang back on HR number", "p.sandoval", "Resolved"],
              ["SD-41884", "17:10", "d.okafor", "Printer offline", "Not needed", "t.nowell", "Resolved"],
            ],
            answer: 2,
            why: "SD-41877 says h.lindqvist at 16:22, while Hanna was out of signal range. The ticket is the only account of the call: who the caller claimed to be, what they asked for, and what the agent accepted. h.lindgren one row up is a different person.",
            learned: "SD-41877, 16:22, agent p.sandoval. Recorded check: staff number and manager's name. MFA number supplied by the caller.",
          },
          {
            id: "reset",
            ask: "Find the reset that ticket produced.",
            source: "Entra audit log · UserManagement · Thursday",
            columns: ["activityDateTime", "activityDisplayName", "initiatedBy.user.userPrincipalName", "initiatedBy.user.roles", "targetResources[0].userPrincipalName", "result"],
            rows: [
              ["2026-11-05T16:05:12Z", "Reset password (self-service)", "o.marsh@brindlemutual.example", "[]", "o.marsh@brindlemutual.example", "success"],
              ["2026-11-05T16:19:40Z", "Reset password (by admin)", "t.nowell@brindlemutual.example", "[\"Helpdesk Administrator\",\"Authentication Administrator\"]", "g.fenn@brindlemutual.example", "success"],
              ["2026-11-05T16:27:03Z", "Reset password (self-service)", "h.lindgren@brindlemutual.example", "[]", "h.lindgren@brindlemutual.example", "success"],
              ["2026-11-05T16:27:41Z", "Reset password (by admin)", "p.sandoval@brindlemutual.example", "[\"Helpdesk Administrator\",\"Authentication Administrator\"]", "h.lindqvist@brindlemutual.example", "success"],
              ["2026-11-05T16:52:18Z", "Reset password (by admin)", "p.sandoval@brindlemutual.example", "[\"Helpdesk Administrator\",\"Authentication Administrator\"]", "o.marsh@brindlemutual.example", "success"],
            ],
            answer: 3,
            why: "16:27:41, five minutes after the ticket opened: agent on the left, Hanna on the right. An honest reset writes this same row, so all this record proves is that the change happened. The next row down is the same agent on a different account.",
            learned: "16:27:41 Reset password (by admin): p.sandoval on h.lindqvist.",
          },
          {
            id: "mfa",
            ask: "The ticket also asked for a new phone. Find the record that put it on Hanna's account.",
            source: "Entra audit log · Authentication Methods · Thursday",
            columns: ["activityDateTime", "activityDisplayName", "initiatedBy.user.userPrincipalName", "targetResources[0].userPrincipalName", "targetResources[0].modifiedProperties[0].displayName"],
            rows: [
              ["2026-11-05T16:11:02Z", "User registered security info", "c.boyle@brindlemutual.example", "c.boyle@brindlemutual.example", "StrongAuthenticationMethod"],
              ["2026-11-05T16:29:15Z", "Admin registered security info", "p.sandoval@brindlemutual.example", "h.lindqvist@brindlemutual.example", "StrongAuthenticationMethod"],
              ["2026-11-05T16:30:44Z", "User changed default security info", "h.lindgren@brindlemutual.example", "h.lindgren@brindlemutual.example", "StrongAuthenticationMethod"],
              ["2026-11-05T16:35:27Z", "Admin deleted security info", "t.nowell@brindlemutual.example", "g.fenn@brindlemutual.example", "StrongAuthenticationMethod"],
            ],
            answer: 1,
            why: "94 seconds after the reset, on the same target, by the same agent. The number on that ticket came from the caller. The caller now holds a password and a phone that can answer MFA, and beat neither: an agent handed over both.",
            learned: "16:29:15 Admin registered security info: the caller's mobile now answers MFA for Hanna's account.",
          },
          {
            id: "signin",
            ask: "Now the payoff. Find the first sign-in that isn't Hanna.",
            source: "Entra sign-in log · h.lindqvist@brindlemutual.example",
            columns: ["createdDateTime", "ipAddress", "location.city", "location.countryOrRegion", "deviceDetail.deviceId", "deviceDetail.trustType", "authenticationRequirement", "status.errorCode"],
            rows: [
              ["2026-10-28T08:49:31Z", "203.0.113.60", "Leeds", "GB", "71c4e0ad-5b2f-4e19-a3d8-09f6b2c7d415", "Hybrid Azure AD joined", "multiFactorAuthentication", "0"],
              ["2026-10-29T08:47:02Z", "203.0.113.60", "Leeds", "GB", "71c4e0ad-5b2f-4e19-a3d8-09f6b2c7d415", "Hybrid Azure AD joined", "multiFactorAuthentication", "0"],
              ["2026-10-30T08:52:18Z", "203.0.113.60", "Leeds", "GB", "71c4e0ad-5b2f-4e19-a3d8-09f6b2c7d415", "Hybrid Azure AD joined", "multiFactorAuthentication", "0"],
              ["2026-11-05T16:43:27Z", "198.51.100.131", "Rotterdam", "NL", "(empty)", "(empty)", "multiFactorAuthentication", "0"],
              ["2026-11-06T08:12:09Z", "203.0.113.60", "Leeds", "GB", "71c4e0ad-5b2f-4e19-a3d8-09f6b2c7d415", "Hybrid Azure AD joined", "singleFactorAuthentication", "50126"],
            ],
            answer: 3,
            why: "16:43:27, sixteen minutes after the reset, from a country this account has never used and a device the directory doesn't know, with MFA satisfied by the new phone. That is T1078, Valid Accounts: a real login. The last row is Hanna, back at the usual laptop, failing with 50126 because the old password no longer works.",
            learned: "16:43:27 sign-in from 198.51.100.131, Rotterdam: first use of the reset, 16 minutes later.",
          },
        ],
      },
    ],
    // ── Reading 5: the fact that resolves a reset ──
    "vish-r5": [
      {
        kind: "queue",
        title: "Which Reset Gets a Stop?",
        prompt: "Friday, 08:40. Marek has frozen the desk's queue until someone reads it. Most of these are real people locked out of their morning, and a needless stop costs them. Read what the agent did before each request, then let it proceed or stop it.",
        primer: {
          title: "What actually separates two identical resets",
          points: [
            "A genuine reset and a vishing reset write the same audit record. What differs is what the desk did **before** acting.",
            "A check counts when the caller can't influence its result: the agent starts it, on a channel taken from Brindle's own records.",
            "Brindle accepts three: a **callback** to the number in HR, an **in-person badge check** against the photo on file, and a **manager's independent confirmation**.",
            "The check has to be written down: which method, who performed it, and a ticket reference tying it to the account change.",
            "Most resets are real people. Stopping every one buries the case that matters.",
          ],
          example: {
            label: "The same idea, at home",
            lines: [
              "Someone rings: 'This is your bank, there's fraud on your card.'",
              "You hang up, turn the card over, and ring the number printed on it.",
              "You chose the line, so it doesn't matter how convincing the first caller was.",
            ],
          },
        },
        console: "Service desk · reset requests on hold",
        actions: [
          { id: "allow", label: "Let it proceed", tone: "close" },
          { id: "stop", label: "Stop it", tone: "escalate" },
        ],
        alerts: [
          {
            id: "t1", time: "08:02", severity: "Low", rule: "Password reset after leave", entity: "SD-41903 · r.halloran",
            fields: [{ k: "Request", v: "Password expired during three weeks' leave" }, { k: "Verification", v: "Agent ended the call and rang the number on r.halloran's HR record. Answered, request confirmed." }, { k: "Verified by", v: "p.sandoval" }],
            context: "Sign-in history is unchanged: the usual laptop, the usual office.",
            answer: "allow",
            why: "The agent chose the number, from Brindle's own record, and wrote it down. That's a complete check, and a stop would only cost someone their morning.",
          },
          {
            id: "t2", time: "08:09", severity: "High", rule: "MFA reset on a payments approver", entity: "SD-41905 · a.kovac",
            fields: [{ k: "Request", v: "Re-register MFA, requested by phone" }, { k: "Verification", v: "Agent rang manager l.ostrowski on the HR directory line. Request confirmed." }, { k: "Verified by", v: "t.nowell" }],
            context: "A privileged account, so everyone in the room looks up.",
            answer: "allow",
            why: "High severity is about what the account can do, not whether the request is true. The manager confirmed on a line the caller doesn't control. Let it go.",
          },
          {
            id: "t3", time: "08:15", severity: "Medium", rule: "Password reset, device new to the account", entity: "SD-41906 · v.sorensen",
            fields: [{ k: "Request", v: "Password reset after laptop rebuild, CHG-2304" }, { k: "Verification", v: "In person at Leeds reception. t.nowell compared the badge with the HR photo." }, { k: "Device", v: "Rebuilt laptop, device ID new to this account" }],
            context: "The new device is what brought this ticket to your attention.",
            answer: "allow",
            why: "A new device is expected after a rebuild. On its own it says nothing, and a badge matched to the HR photo can't be prepared over a phone.",
          },
          {
            id: "t4", time: "08:21", severity: "Medium", rule: "Password reset", entity: "SD-41908 · m.brandt",
            fields: [{ k: "Request", v: "Locked out" }, { k: "Verification", v: "Caller gave staff number, start date and last four digits of mobile. All correct." }, { k: "Verified by", v: "p.sandoval" }],
            context: "Patient, polite, and knows the team's names.",
            answer: "stop",
            why: "Three right answers prove the homework was done. Every one can be collected before dialling, so this check verified nothing, however neatly it was recorded.",
          },
          {
            id: "t5", time: "08:26", severity: "Low", rule: "Phone number change", entity: "SD-41909 · i.moreau",
            fields: [{ k: "Request", v: "Old mobile is dead, new number given on the call" }, { k: "Verification", v: "Agent rang the new number. The caller answered." }, { k: "Verified by", v: "t.nowell" }],
            context: "Logged as a callback, and marked complete.",
            answer: "stop",
            why: "A callback only proves something when the number comes from Brindle's records. This agent rang the caller's own phone, and the caller answered it.",
          },
          {
            id: "t6", time: "08:31", severity: "Low", rule: "Password reset", entity: "SD-41910 · t.halvorsen",
            fields: [{ k: "Request", v: "Locked out" }, { k: "Verification", v: "Agent's note: 'Spoke to Tomas twice last month, sounds exactly the same.'" }, { k: "Verified by", v: "p.sandoval" }],
            context: "The agent is certain, and has eleven years on the desk.",
            answer: "stop",
            why: "Experience doesn't change what happened here: nothing passed through a channel outside the call. 'Sounds right' describes the call. It doesn't check it.",
          },
          {
            id: "t7", time: "08:36", severity: "Medium", rule: "MFA reset", entity: "SD-41911 · e.kaya",
            fields: [{ k: "Request", v: "New authenticator needed today" }, { k: "Verification", v: "Caller emailed a screenshot of a chat in which their manager approves." }, { k: "Verified by", v: "t.nowell" }],
            context: "The screenshot came from a personal address.",
            answer: "stop",
            why: "Manager confirmation counts when the agent gets it from the manager. This one came from the caller, so the caller controlled it.",
          },
        ],
      },
    ],
    // ── Reading 6: the rule, and the ticket behind it ──
    "vish-r6": [
      {
        kind: "simulate",
        title: "Would the Rule Fire?",
        prompt: "Brindle's draft detection has three conditions, and all three must hold. Replay five days from last month's log, one at a time, and watch which conditions pass.",
        primer: {
          title: "The shape of a correlation rule",
          points: [
            "A **correlation rule** joins two data sources and raises its own alert, so nobody has to think of looking.",
            "Three parts: a change, a bounded time window, and a context field that doesn't match the account's history.",
            "The window is a trade-off, and you tune it on how fast your own staff sign back in after a real reset.",
          ],
          example: {
            label: "The same shape, on a VPN rule",
            lines: [
              "Source 1: a new VPN profile is issued to a user.",
              "Source 2: within 2 hours, that user connects from a host with no history.",
              "Join on the user, bound it by the window, compare with the user's own past.",
            ],
          },
        },
        checks: [
          { name: "Admin change", question: "Reset password (by admin) or Disable Strong Authentication, by a help-desk role?" },
          { name: "Same account, in window", question: "A sign-in on that same account within 4 hours?" },
          { name: "New context", question: "Is that sign-in's device or country new to the account?" },
        ],
        scenarios: [
          { id: "mon", label: "Monday", detail: "09:05 Reset password (by admin), target j.quist, role Helpdesk Administrator | 09:40 j.quist sign-in, deviceId empty, country PT, history GB", results: ["pass", "pass", "pass"], why: ["An admin-performed reset.", "35 minutes later, same account.", "An unknown device and a country outside the history."], verdict: "FIRES. All three hold. It's an alert, not yet a verdict: the next stop is the ticket." },
          { id: "tue", label: "Tuesday", detail: "Tue 11:02 Disable Strong Authentication, target a.kovac, role Authentication Administrator | Fri 10:15 a.kovac sign-in, new deviceId", results: ["pass", "fail", "pass"], why: ["MFA removed by an admin.", "Three days later is outside the window.", "The device is new."], verdict: "NO ALERT. A window of days would catch this, and would also tie every reset to unrelated routine. A window of seconds would miss a patient attacker. A few hours is a starting point." },
          { id: "wed", label: "Wednesday", detail: "13:10 Reset password (by admin), target m.ferris, role Helpdesk Administrator | 13:14 m.ferris sign-in, usual deviceId, country GB", results: ["pass", "pass", "fail"], why: ["An admin-performed reset.", "Four minutes later, same account.", "Same device and country as always."], verdict: "NO ALERT. Someone got back to work. This is what most resets look like." },
          { id: "thu", label: "Thursday", detail: "14:40 Reset password (by admin), target c.boyle, role Helpdesk Administrator | 15:05 r.tan sign-in, new deviceId, country GB", results: ["pass", "fail", "pass"], why: ["An admin-performed reset.", "c.boyle and r.tan are two accounts, so nothing joins them.", "The device is new, for r.tan."], verdict: "NO ALERT. The join is on the account. Two events near each other on different people are a coincidence." },
          { id: "fri", label: "Friday", detail: "10:20 Reset password (by admin), target e.lowe, role Helpdesk Administrator | 10:32 e.lowe sign-in, new deviceId, country GB", results: ["pass", "pass", "pass"], why: ["An admin-performed reset.", "Twelve minutes later, same account.", "A device with no history."], verdict: "FIRES, and it's e.lowe's rebuilt laptop. The rule did its job. It can only say the pattern happened. The ticket says whether it was right." },
        ],
      },
      {
        kind: "hotspot",
        title: "Would This Ticket Survive a Review?",
        prompt: "A rule catches what already happened, and the ticket decides what it meant. Here is SD-41877 as the desk closed it. Find every line a review could not accept.",
        artifact: "Service desk · SD-41877 · closed record",
        finish: "A ticket that names the method, who verified, and the account change it covers settles a case in minutes. When any of those is missing, or the check is only knowledge, the case escalates.",
        parts: [
          { id: "p1", text: "SD-41877: password reset and MFA number change", flag: false, note: "A clear title. Nothing wrong here.", style: "subject" },
          { id: "p2", text: "Opened 16:22 · Resolved 16:31 · Agent: p.sandoval", flag: false, note: "Times and a named agent are what a reviewer needs.", style: "meta" },
          { id: "p3", text: "Verification method: caller gave staff number and manager's name", flag: true, note: "A method has to be one the caller can't influence. Both answers can be researched.", style: "body" },
          { id: "p4", text: "Verified by: (blank)", flag: true, note: "The record must name who performed the check, so someone can ask them about it.", style: "body" },
          { id: "p5", text: "New MFA number: +44 7700 900412, given by caller", flag: true, note: "A phone number taken live from the caller has no history behind it. Contact details come from Brindle's records.", style: "body" },
          { id: "p6", text: "Account change reference: (blank)", flag: true, note: "Nothing ties this ticket to the audit records it produced. The reference is what lets a reviewer line the two up.", style: "body" },
          { id: "p7", text: "Note: held caller 4 min while I found the account. Polite, knew the team, worried about the payment run.", flag: false, note: "Worth keeping: it's the only account of the call. Time pressure is a pretext to look for, not a failed field.", style: "body" },
        ],
      },
    ],
    // ── Reading 7: making the next call fail ──
    "vish-r7": [
      {
        kind: "locks",
        title: "Three Changes for Monday",
        prompt: "Marek's hardening list goes to the board on Monday. Each door is one principle. Read the idea and the example, then answer its check to open the door.",
        finish: "Detection tells you what happened. Hardening makes the next call fail before there's anything to find. A mature SOC feeds the first into the second.",
        locks: [
          {
            id: "keys", letter: "K", name: "Keys",
            idea: "CISA's joint advisory on this threat cluster, AA23-320A, leads with phishing-resistant MFA: FIDO/WebAuthn or PKI-based (Public Key Infrastructure) authentication.",
            example: "A FIDO2 security key or passkey answers only the real site it was registered with. The proof happens between the key and that site, without a person in the middle.",
            check: { q: "A look-alike of Brindle's sign-in page asks a claims manager to use their FIDO2 key. What does the page get?", options: ["A valid proof it can replay at the real site", "Nothing usable, because the key is bound to the real site's address", "A one-time code the manager reads to it"], answer: 1, why: "The key's answer is tied to the site's origin, so a look-alike has nothing it can pass on." },
          },
          {
            id: "voice", letter: "V", name: "Voice",
            idea: "No process should treat 'the caller sounded right' as a step. A voice is something an attacker can now fake, so it can't carry a decision.",
            example: "The desk script had a tick-box: 'Agent recognises caller'. Marek struck it out on Friday.",
            check: { q: "Brindle's chair rings the desk, and everyone there knows that voice. What is that worth as verification?", options: ["Enough on its own for a senior caller", "Enough, if a second agent agrees it's the chair", "Nothing, so the usual check still runs"], answer: 2, why: "Seniority raises the stakes and changes nothing else. Identity gets checked through a channel the caller can't redirect, whoever it sounds like." },
          },
          {
            id: "two", letter: "2", name: "Two People",
            idea: "Limit what one help-desk role can do alone. A second approver for any full MFA removal on a privileged account stops one agent from both verifying and acting.",
            example: "At Brindle, one agent on one call changed a payments approver's password and phone.",
            check: { q: "Which change would have stopped one agent finishing Hanna's ticket alone?", options: ["A second approver on MFA changes for payment approvers", "A faster ticket form for payment-day calls", "A longer list of questions for the agent to ask"], answer: 0, why: "The weakness was a single point of decision. Only a second person removes it." },
          },
        ],
      },
    ],
    // ── Boss warm-up: the label decides what happens to the rule ──
    "vish-ac1": [
      {
        kind: "sort",
        title: "Did the Rule Get It Right?",
        prompt: "Before Marek hands you the last case: closing an alert means choosing a label, and the label changes what happens to the rule. Here are six closed alerts from other Brindle rules. Sort each one.",
        primer: {
          title: "Two questions before you close",
          points: [
            "Did the rule catch the thing it was built to catch? If not, it misfired: a **false positive**, and the rule needs tuning.",
            "If it did, was the activity authorised, with proof? Then it's a **benign true positive**: the rule stays as it is, and you close with the justification.",
            "If it did and nobody can authorise it, it's a **true positive**, and it needs action.",
          ],
          example: {
            label: "The same questions, on a smoke alarm",
            lines: [
              "A loose wire sets it off in clean air: a misfire. Fix the alarm.",
              "A planned fire drill with smoke machines sets it off: it worked, and the drill was approved. Leave the alarm alone.",
              "A real kitchen fire sets it off: act.",
            ],
          },
        },
        buckets: [
          { id: "tp", label: "True positive" },
          { id: "btp", label: "Benign true positive" },
          { id: "fp", label: "False positive" },
        ],
        items: [
          { id: "a", text: "Mass file read on the Claims share: the nightly backup agent, listed on an approved change record", bucket: "btp", why: "A mass read really happened and the rule saw it. The change record is the justification." },
          { id: "b", text: "Mass file read on the Claims share: the parser counted each line of one log file as a separate file", bucket: "fp", why: "No mass read took place. The rule misfired on bad parsing, so fix the parser." },
          { id: "c", text: "New role assignment: a planned promotion, signed off by the CISO, ticket on file", bucket: "btp", why: "The rule was right that a role changed. The sign-off makes it authorised, and it stays on so the next one is seen too." },
          { id: "d", text: "New role assignment: no ticket, and the account's owner says they never requested it", bucket: "tp", why: "Real activity that nobody can authorise. This one needs action." },
          { id: "e", text: "Impossible travel: an out-of-date geolocation feed placed the Leeds gateway in Canada", bucket: "fp", why: "Nobody travelled. The rule read a wrong location, so the feed gets fixed." },
          { id: "f", text: "External mail forward created: the mailbox owner denies making it, and it points to a free webmail address", bucket: "tp", why: "The rule caught what it was built for, and the owner's denial removes any authorisation." },
        ],
      },
    ],
  },
};
