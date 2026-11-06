import type { RoomExperience } from "./types";

// "Operation Wire Transfer" for the "bec-investigation" room.
// Script: docs/campaign/104-bec-investigation.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Harcourt & Vane Engineering (fictional), not the graded tasks' Meridian Structural Group.
// Signature: The Money Clock. A business email compromise worked against a bank recall window:
// a backwards `sequence` of what happened, a `trace` from the first sign-in through the hidden
// rule to the changed bank details, a worksheet that runs the clock on past cases, and `defuse`
// rounds on the first hour.
// Game mix: deduce + defuse + intercept + spotdiff.
// Task order: the room's own, unchanged. No flag says "Log Analysis N".
//
// Lab data differs from the graded tasks. The lab mailbox is a project manager's, not an accounts
// payable lead's. The session came from an infostealer on a site laptop, not an AiTM page
// (o1, la1). Pittsburgh to Frankfurt, 27 minutes apart, not Denver to Lagos in nine (la1). The
// rule is called zz, keys on a sender and uses Conversation History, 20 minutes after the sign-in;
// the graded rule's name, folder, keywords and nine-minute gap appear nowhere (la2, f1). The
// timeline runs backwards and adds a dwell and a vendor master edit (o1). The foothold whodunit
// ends in thread hijacking, never a vendor (q1). The rule queue never shows a leave-coverage
// forward (ac1). The recall worksheet is past cases, with no containment in it, and the first-hour
// rounds never ask whether to start the recall (q4). The anatomy of a rule is a newsletter filter.

export const BEC_INVESTIGATION: RoomExperience = {
  roomId: "bec-investigation",
  codename: "Operation Wire Transfer",
  theme: "wiretransfer",
  handler: { name: "Oluchi Svensson", role: "Fraud Investigations Lead, Harcourt & Vane Engineering" },
  briefing: [
    "Harcourt & Vane Engineering. 310 people, bridges and highways across three states, and one Microsoft tenant.",
    "At 14:20 Pittsburgh time (18:20 UTC) on Tuesday, Noor Haddad in Finance was reconciling the month and found $387,250 paid to an account nobody recognised.",
    "The money left under two and a half hours ago. A bank can ask for it back, but only while it is still there.",
    "Oluchi Svensson runs the fraud desk, and the clock started before anyone noticed. Read the invoice, the session, the rule and the money.",
  ],
  mission: "Read the email that moved the money, name the foothold, separate a stolen session from its owner, follow it to the rule and the changed bank details, walk the case backwards, run the clock on the recall, and work the first hour.",
  estimate: "~65 min",
  look: { primary: "#e0c56e", secondary: "#6fc7a8", warn: "#ff5a5f" },
  scene: "facilitywiretransfer",
  layout: "facility",
  stations: [
    {
      id: "invoice",
      label: "The Invoice",
      topic: "What BEC is · who gets targeted · what gets asked · the four footholds",
      tagline: "Nothing in it to detonate",
      building: "office",
      taskIds: ["bec-r1", "bec-r2", "bec-q1"],
    },
    {
      id: "session",
      label: "The Second Session",
      topic: "Entra ID sign-in fields · token replay · impossible travel · session pivots",
      tagline: "Same account, twenty-seven minutes on",
      building: "control",
      taskIds: ["bec-r3", "bec-la1", "bec-q2"],
    },
    {
      id: "rule",
      label: "The Hidden Rule",
      topic: "Inbox rule levers · IP and time correlation · vectors and fields · verdicts on ordinary rules",
      tagline: "What did Erin never see?",
      building: "archive",
      taskIds: ["bec-r4", "bec-la2", "bec-m1", "bec-ac1"],
    },
    {
      id: "timeline",
      label: "The Timeline",
      topic: "Timeline reconstruction · the recall window · out-of-band checks · scoping",
      tagline: "Start at the end, walk back",
      building: "lab",
      taskIds: ["bec-r5", "bec-o1", "bec-q3"],
    },
    {
      id: "clock",
      label: "The Money Clock",
      topic: "Containment · notification and reporting · the written summary",
      tagline: "The first hour",
      building: "vault",
      taskIds: ["bec-r6", "bec-q4", "bec-f1"],
      boss: true,
    },
  ],
  personas: {
    "bec-q1": { name: "Oluchi Svensson", role: "Fraud Investigations Lead", line: "A case from a colleague's file. Which foothold fits?" },
    "bec-la1": { name: "Oluchi Svensson", role: "Fraud Investigations Lead", line: "Read the whole record before you tell me anything." },
    "bec-q2": { name: "Oluchi Svensson", role: "Fraud Investigations Lead", line: "One record is not enough. What do you search on?" },
    "bec-la2": { name: "Oluchi Svensson", role: "Fraud Investigations Lead", line: "Next record from the same mailbox. Walk me through it." },
    "bec-m1": { name: "Oluchi Svensson", role: "Fraud Investigations Lead", line: "Get the terms straight before the bank asks you about them." },
    "bec-ac1": { name: "Oluchi Svensson", role: "Fraud Investigations Lead", line: "Another alert in the queue. Your verdict." },
    "bec-o1": { name: "Oluchi Svensson", role: "Fraud Investigations Lead", line: "Put it in order. Someone will ask." },
    "bec-q3": { name: "Oluchi Svensson", role: "Fraud Investigations Lead", line: "Finance wants a status for this one. What do I tell them?" },
    "bec-q4": { name: "Oluchi Svensson", role: "Fraud Investigations Lead", line: "The controller is on the line about the bank. What's the answer?" },
    "bec-f1": { name: "Oluchi Svensson", role: "Fraud Investigations Lead", line: "One value for the report. Copy it exactly." },
  },
  briefings: {
    // ── Reading 1: what BEC is ──
    "bec-r1": [
      {
        kind: "hotspot",
        title: "The Email With Nothing to Sandbox",
        prompt: "This is the message that moved $387,250. Noor printed it and Oluchi put it on the desk. There is no lure to defuse and no payload to detonate, so the question changes: tap the parts of it that should have stopped a payment.",
        artifact: "Accounts Payable shared mailbox · message in the Ostrander thread",
        finish: "That's all of it: two sentences and no payload. The invoice was real, the amount was real and the mailbox was real. Erin Brandt never wrote those two sentences.",
        primer: {
          title: "Why There Is Nothing to Sandbox",
          points: [
            "**Business email compromise (BEC)** gets someone to move money, data or access by making a false request look like a routine, trusted one.",
            "**Usually there is no malware in it.** A convincing message and an abused identity do the work, so there is rarely a payload to detonate or a process tree to pull apart.",
            "**The evidence sits in identity and mail records:** Entra ID sign-in logs, the Office 365 Unified Audit Log (UAL) and mailbox rule history. Endpoint detection (EDR) is not the first screen to open.",
            "**It is patient.** Commodity phishing sends millions of copies. A BEC operator may sit in one mailbox for days, learn how a person writes, and send a single message at the right moment.",
            "**The tell is the ask,** not the look of the message.",
          ],
          example: {
            label: "Worked example: a rent email",
            lines: [
              "A managing agent's message says the office rent now goes to a different account. No attachment, no link, and the address is the one on file.",
              "Ask what the message wants done, not how it looks: **it changes where money goes.**",
              "Nothing on the message itself settles that. Only a check outside email can.",
            ],
          },
        },
        parts: [
          { id: "from", text: "From: Erin Brandt <e.brandt@harcourtvane.example>", flag: false, style: "meta", note: "Erin's real address, letter for letter. Reading the sender closely gets you nothing on this one." },
          { id: "to", text: "To: Accounts Payable <ap@harcourtvane.example>", flag: false, style: "meta", note: "The shared mailbox Sam Tan works from. Project managers send supplier invoices here every week." },
          { id: "auth", text: "X-MS-Exchange-Organization-AuthAs: Internal", flag: false, style: "meta", note: "Exchange stamps it as internal mail: a signed-in mailbox in Harcourt's tenant submitted it. That shows which session sent it, not whose hands were on the keyboard." },
          { id: "subject", text: "RE: RE: Kestrel Viaduct: Ostrander boring logs and invoice OG-20418", flag: false, style: "subject", note: "A real conversation, five weeks old. Everything above this reply was written by real people." },
          { id: "b1", text: "Thanks Sam. I've checked the Phase 2 logs against the PO and OG-20418 is good to pay at $387,250.", flag: false, style: "body", note: "True, as it happens. The invoice and the amount are real, which is what makes the next line easy to believe." },
          { id: "b2", text: "Ostrander moved banks last month, so this one needs to go to their new account ending 8841. Details below, please update the vendor record.", flag: true, style: "body", note: "The line that matters: it changes where the money goes. Nothing else in this message does." },
          { id: "b3", text: "I'm out at the abutment all week with no signal, so just reply here rather than calling.", flag: true, style: "body", note: "It closes the one check that would have exposed the request. Sam had a number for Erin and a number for Ostrander." },
          { id: "att", text: "Attachment: OG-20418.pdf (212 KB)", flag: false, style: "meta", note: "The real invoice from earlier in the thread, attached again. A sandbox would clear it, correctly." },
          { id: "sig", text: "Erin Brandt, PE | Project Manager, Kestrel Viaduct | Harcourt & Vane Engineering", flag: false, style: "body", note: "Erin's real signature, copied from Erin's real sent items." },
        ],
      },
      {
        kind: "intercept",
        title: "Hold or Pay?",
        prompt: "Oluchi sits you beside Sam Tan for the next payment run. Each item is a request to pay or to change a payment. Hold the ones that need a call first and let honest work through: holding everything stops the business.",
        primer: {
          title: "Who Gets Aimed At, and What Gets Asked",
          points: [
            "**The targets** are people who can move money or sit next to someone who can: accounts payable, controllers, executive assistants, payroll.",
            "**The asks** come from a short list: new bank details on an open invoice, an urgent wire before a deadline, gift cards for a confidential favour, a redirected salary.",
            "**None of those is strange on its own.** That is why they work.",
            "**Out-of-band check:** confirm through a channel the message cannot touch, by calling a number you already held: a signed contract, the internal directory, a number dialled before. Never a number found in the message.",
          ],
          example: {
            label: "Worked example: a conference deposit",
            lines: [
              "'Please pay the deposit today, same agency account as always.' Urgent, but it changes nothing about where money goes. Normal approval applies.",
              "'Our account is frozen, so pay this one to the account below.' Same agency, same tone, new destination. Hold it and ring the number on last year's booking.",
            ],
          },
        },
        protect: "the payment run",
        blockLabel: "Hold and call",
        passLabel: "Pay",
        seconds: 12,
        items: [
          { id: "i1", text: "New bank details for Keystone Aggregate, invoice 7731", sub: "Usual contact, usual address, authentication passed", bad: true, why: "An authentication pass says which server sent it, not who was typing. New bank details get a call every time." },
          { id: "i2", text: "Tri-County Rebar invoice 5120, $18,400", sub: "Same account as the last 14 payments, purchase order matches", bad: false, why: "Nothing about where the money goes has changed. Holding this would teach everyone to ignore holds." },
          { id: "i3", text: "Gift cards: 20 at $200 each, for the CEO", sub: "To the executive assistant: 'confidential, in meetings all day'", bad: true, why: "Hard-to-trace value plus a reason not to check. Ring the CEO's office on the directory number." },
          { id: "i4", text: "Kestrel stage payment, $610,000", sub: "Same account since 2023, PO and approval on file", bad: false, why: "Big is not the trigger. The destination is unchanged and the approval chain ran." },
          { id: "i5", text: "Direct deposit change for a site engineer", sub: "Email to payroll: 'please update before Friday's run'", bad: true, why: "A salary redirect is the same fraud on a smaller scale. Confirm with the employee on the directory number." },
          { id: "i6", text: "Overdue reminder from Hollis Crane Hire", sub: "Third reminder, blunt tone, same account", bad: false, why: "Pushy is not fraud, and suppliers do chase. Same payee, same account: check the PO and pay." },
          { id: "i7", text: "Urgent wire to close a land option today", sub: "From the controller's address: 'boarding now, can't talk'", bad: true, why: "A new payee, a deadline and a reason you can't call: three pressures aimed at the one check that works." },
          { id: "i8", text: "First payment to Ridgeline Surveying", sub: "Bank details confirmed last week on the contract's number, CB-2287 on file", bad: false, why: "A new account, but the call was already made and recorded. The check is done." },
          { id: "i9", text: "Remit-to change inside a live thread", sub: "From a supplier's real contact: 'our bank merged, new routing number'", bad: true, why: "It fits the thread, the tone and the timing, and it still changes where money goes. Fit is what a patient operator builds." },
          { id: "i10", text: "CEO's expense claim, $1,140", sub: "Through the expenses portal, to the salary account on file", bad: false, why: "A senior name, the normal route and an unchanged destination. A famous name alone is no reason to hold." },
        ],
        lesson: "The trigger is a change to where money goes, or a new way of paying. Size, tone and polish are not. Authentication results don't settle it either. Hold those items and call a number you already held.",
      },
    ],
    // ── Reading 2: the four footholds ──
    "bec-r2": [
      {
        kind: "deduce",
        title: "Which Foothold Was It?",
        prompt: "There are five ways that message could have reached Sam, and each leaves a different trail. The trail decides whose logs you open next. Strike them out as Oluchi reads the findings.",
        primer: {
          title: "Four Footholds, Four Trails",
          points: [
            "**Account takeover (ATO):** the attacker holds a working session or password for someone's mailbox and uses it directly. The two common routes are adversary-in-the-middle (AiTM) phishing pages, which relay the login and keep the session, and infostealer malware, which lifts saved browser cookies for use or sale.",
            "**Lookalike domain:** no mailbox is touched. A newly registered domain, nearly identical to a real one, does the talking. It is cheap, and 'almost identical' reads as identical at a glance.",
            "**Thread hijacking:** a step on from takeover. A reply inside a live conversation inherits its history, its tone and the trust already in it.",
            "**Vendor email compromise (VEC):** the stolen mailbox is a supplier's. The trail sits in the supplier's tenant, and no single ATT&CK technique covers it (T1199 Trusted Relationship is the nearest fit).",
            "**SPF, DKIM and DMARC** are the standard mail authentication checks. They test that a message came from servers and keys authorised for the domain it names, and they cannot say who was at the keyboard.",
          ],
          example: {
            label: "Worked example: a school bursar",
            lines: [
              "A request arrives from head@stmarks-school.example. The contract says st-marks-school.example.",
              "Step 1, compare the domain: a hyphen is missing, so no real mailbox was needed.",
              "Step 2, ask whose logs could hold evidence: the message headers and the domain's registration date, not the school's sign-in log.",
            ],
          },
        },
        nameColumn: "Foothold",
        columns: ["Sending address", "Authentication", "Where it lands", "Your sign-in log", "Who holds the evidence"],
        suspects: [
          { id: "look", name: "Lookalike domain", cells: ["One character off a real domain", "Pass, for the new domain", "New message", "Quiet", "Headers, domain registration"] },
          { id: "name", name: "Display name only", cells: ["Free webmail, right name shown", "Pass, for the webmail domain", "New message", "Quiet", "Headers"] },
          { id: "vec", name: "Vendor compromise", cells: ["A supplier's real address", "Pass, from their own servers", "New message or a live thread", "Quiet", "The supplier"] },
          { id: "ato", name: "Takeover, new message", cells: ["Your own real address", "Internal, from a signed-in mailbox", "New message", "A session the owner doesn't know", "Your sign-in and audit logs"] },
          { id: "hijack", name: "Thread hijacking", cells: ["Your own real address", "Internal, from a signed-in mailbox", "Reply in a live thread", "A session the owner doesn't know", "Your sign-in and audit logs"] },
        ],
        clues: [
          "No authentication check failed.",
          "The In-Reply-To header points at a real message in a five-week-old conversation.",
          "Harcourt's own sign-in log holds a session on this mailbox that Erin doesn't recognise.",
        ],
        culprit: "hijack",
        why: "Thread hijacking. No row fails authentication, so the first finding removed nobody. The header put it in a live thread, and the session put the attacker inside Erin's own mailbox. That matters now because this case has logs to read: Harcourt's sign-in log and audit log are the next stop. The rows marked Quiet leave nothing on your side, and only the out-of-band call reaches them.",
      },
    ],
    // ── Reading 3: reading a sign-in record ──
    "bec-r3": [
      {
        kind: "spotdiff",
        title: "Two Records, One Session",
        prompt: "Thursday, Erin's account. On the left, Erin signing in on a site laptop. On the right, the next record in the same session, 27 minutes later. Tap each line that changed and tells you something about who is holding the session.",
        primer: {
          title: "Reading a Sign-In Record",
          points: [
            "**isInteractive:** `true` means a person typed or approved something at that moment. `false` means a token was presented with nobody involved.",
            "**incomingTokenType:** what was presented. `none` is a fresh sign-in, `refreshToken` is a token issued earlier, and `primaryRefreshToken` (PRT) is bound to one device, so using it takes that device's secrets, not just a browser cookie.",
            "**authenticationMethod:** how the requirement was met. A named method such as `Mobile app notification` means a multi-factor authentication (MFA) prompt went out. `Previously satisfied` means an MFA claim already inside the token met it.",
            "**sessionId** stays the same across one continuous authenticated session, so it links everything done under it. **correlationId** groups the records of one underlying action.",
            "**conditionalAccessStatus** says whether the policies were met by what was presented. **riskLevelDuringSignIn** is the risk score at that moment.",
          ],
          example: {
            label: "Worked example: a contractor's tablet",
            lines: [
              "`isInteractive: true`: a person acted at that moment.",
              "`incomingTokenType: none`: fresh credentials, not a stored token.",
              "`authenticationMethod: Text message`: a code was entered just now.",
              "`deviceDetail.isManaged: false`: the company has no record of this tablet. One field states a fact, not a finding, so read the lines together.",
            ],
          },
        },
        goodTitle: "13:04:11 UTC · Erin on HV-SITE-07",
        suspectTitle: "13:31:38 UTC · next record",
        good: [
          "createdDateTime: 2026-10-08T13:04:11Z",
          "userPrincipalName: e.brandt@harcourtvane.example",
          "appDisplayName: Office 365 Exchange Online",
          "sessionId: 7be41c09-22f6-4d1a-a3c8-5e90d17f2b36",
          "correlationId: 31d0a7c4-6e18-4b52-9f03-c7a2e84d1650",
          "isInteractive: true",
          "incomingTokenType: none",
          "authenticationMethod: Mobile app notification",
          "ipAddress: 198.51.100.40 (Pittsburgh, US)",
          "deviceDetail: HV-SITE-07, isManaged true, trustType Azure AD joined",
          "conditionalAccessStatus: success",
          "riskLevelDuringSignIn: none",
        ],
        suspect: [
          "createdDateTime: 2026-10-08T13:31:38Z",
          "userPrincipalName: e.brandt@harcourtvane.example",
          "appDisplayName: Office 365 Exchange Online",
          "sessionId: 7be41c09-22f6-4d1a-a3c8-5e90d17f2b36",
          "correlationId: b26f9e13-08dd-47a1-8c55-1fe3d07ab942",
          "isInteractive: false",
          "incomingTokenType: refreshToken",
          "authenticationMethod: Previously satisfied",
          "ipAddress: 203.0.113.58 (Frankfurt, DE)",
          "deviceDetail: (no name), isManaged false, trustType (empty)",
          "conditionalAccessStatus: success",
          "riskLevelDuringSignIn: none",
        ],
        diffs: [
          { line: 5, why: "false: nobody typed or approved anything at this moment. On its own, that happens all day." },
          { line: 6, why: "refreshToken: the credential presented was issued earlier, so no password was involved here." },
          { line: 7, why: "'Previously satisfied': the MFA requirement was met by a claim already in the token, and no prompt went out." },
          { line: 8, why: "A new address on a hosting network in Frankfurt, 6,500 km from the record before it." },
          { line: 9, why: "No device name, isManaged false and an empty trustType: no enrolment relationship with Harcourt at all. The record before it came from a joined laptop." },
        ],
        decoys: [
          { line: 0, why: "A later timestamp only makes it a second record. Keep the gap, it matters in the next lab." },
          { line: 4, why: "A new correlationId is normal: it belongs to one action, and this is a new action. sessionId is the line that stayed the same." },
        ],
        hud: "Tap the lines that changed and matter",
        sameLine: "Same on both records, so this line can't tell you who is holding the session, however reassuring it looks.",
        winTitle: "Every change read",
        howTo: [
          "Read the first record on the left.",
          "Tap each line on the right that changed and says something about who holds the session.",
          "A line that matches, or that changes for a harmless reason, costs a life.",
        ],
        lesson: "Read a record for what changed and for what stayed the same. Here nobody was at a keyboard, the credential was old, the MFA came inside it, and the network and the device were new, all under one sessionId. conditionalAccessStatus and riskLevelDuringSignIn stayed green throughout, because they assess the token presented, and a stolen token is still a valid token.",
      },
      {
        kind: "worksheet",
        title: "Could Anyone Have Flown It?",
        prompt: "Impossible travel is arithmetic: distance divided by time. You can do it yourself, and you don't need a product to agree with you. An airliner cruises at about 900 km/h. Oluchi pulled this week's accounts seen in two cities, each one starting in Pittsburgh.",
        caption: "Two-city sign-in pairs · this week · first city Pittsburgh",
        columns: ["User", "Second city", "Distance (km)", "Gap (min)", "Same sessionId?"],
        rows: [
          ["a.kowalski", "Cleveland", "185", "140", "Yes"],
          ["t.hale", "London", "5,950", "430", "No"],
          ["e.brandt", "Frankfurt", "6,500", "27", "Yes"],
          ["r.duarte", "Chicago", "660", "120", "No"],
        ],
        questions: [
          { id: "speed", q: "What speed does e.brandt's pair imply, in km/h? Round to the nearest hundred.", hint: "Minutes divided by 60 gives hours. Distance divided by hours gives speed.", answer: ["14400", "14444"], why: "6,500 km in 0.45 hours is about 14,400 km/h, sixteen times an airliner." },
          { id: "close", q: "Which other user comes closest to airliner speed?", hint: "Work out each row the same way.", answer: ["t.hale", "hale"], why: "5,950 km in 430 minutes is about 830 km/h: a real flight, and a new sessionId after landing fits a fresh sign-in." },
          { id: "same", q: "One other user kept the same sessionId across two cities. Who?", hint: "Read the last column.", answer: ["a.kowalski", "kowalski"], why: "About 79 km/h, a laptop in a car. A session travels with its device, so a shared sessionId is no alarm by itself. It takes the speed as well: one session, in two places at once." },
        ],
      },
    ],
    // ── Reading 4: inbox rules ──
    "bec-r4": [
      {
        kind: "anatomy",
        title: "Anatomy of an Inbox Rule",
        prompt: "Before you open Erin's mailbox, read a rule nobody is worried about. Dana Ferro, a site engineer, filed a steel-price newsletter out of the inbox last spring. Every lever a rule can pull is in this one record.",
        source: "Unified Audit Log · Exchange · d.ferro@harcourtvane.example",
        fields: [
          { key: "Operation", value: "New-InboxRule", label: "What happened", note: "A rule created through Outlook on the web or PowerShell. Rules made in the Outlook desktop app show as UpdateInboxRules." },
          { key: "UserId", value: "d.ferro@harcourtvane.example", label: "Whose mailbox" },
          { key: "ClientIP", value: "198.51.100.40", label: "From where", note: "The address the request came from. It can be set beside sign-in records, by value and by time." },
          { key: "Parameters.Name", value: "Steel prices", label: "Rule name", note: "Free text, chosen by whoever made the rule. It can be a sentence or a lone character." },
          { key: "Parameters.FromAddressContainsWords", value: "steelnews.example", label: "Condition", note: "Which mail the rule acts on. SubjectOrBodyContainsWords does the same job with words in the message." },
          { key: "Parameters.MoveToFolder", value: "Newsletters", label: "Action", note: "Moves a match to a folder. The message stays in the mailbox." },
          { key: "Parameters.MarkAsRead", value: "True", label: "Action", note: "Marks a match as read on arrival, so no unread count appears for it." },
          { key: "Parameters.StopProcessingRules", value: "True", label: "Rule order", note: "Rules further down the list do not run on a matched message." },
        ],
        summary: "Nothing in this record is a verdict: these levers file newsletters every day. Other levers work differently: ForwardTo shows the mailbox owner as sender, RedirectTo keeps the original sender, and both leave a copy unless the rule also deletes or moves it. DeleteMessage removes the message. The three levers here send nothing anywhere, so outbound monitoring stays quiet. What a rule means depends on what it points at, which folder it uses and who made it.",
      },
      {
        kind: "trace",
        title: "From the Sign-In to the Bank Details",
        prompt: "Noor gave you the end of the story and Erin's second record gave you the start. Join them. Each log answers one question and hands you the value for the next. All times are UTC.",
        primer: {
          title: "Pivoting Between Logs",
          points: [
            "**A pivot** takes a value from one log and searches for it in the next. Sign-in logs and the UAL share the account, the IP address and the clock.",
            "**ClientIP** in the UAL is the address behind a mailbox action. Check it against the sign-ins, then count the minutes between the two records.",
            "**Default folders:** every mailbox has folders Outlook created, such as Conversation History, and many people never open them.",
            "**A Send record** in the UAL shows what left a mailbox and which address sent it.",
            "**The vendor master** is the finance system's list of who gets paid and where. Its change log shows who edited what.",
          ],
          example: {
            label: "Worked example: a contractor's document share",
            lines: [
              "Sign-in log: `198.51.100.200` at 09:02.",
              "SharePoint audit: `FileDownloaded` from `198.51.100.200` at 09:10.",
              "One address, eight minutes apart: two records that now belong to one sitting. Next, search for what else that address did.",
            ],
          },
        },
        lead: "e.brandt · second-record address 203.0.113.58 · sessionId 7be41c09",
        steps: [
          {
            id: "first",
            ask: "Where does that address first touch Erin's account?",
            source: "Entra ID sign-in logs · e.brandt · last 10 days",
            columns: ["createdDateTime", "ipAddress", "city", "isInteractive", "incomingTokenType", "sessionId"],
            rows: [
              ["10-13 14:02:47", "203.0.113.58", "Frankfurt", "false", "refreshToken", "7be41c09"],
              ["10-12 12:58:03", "198.51.100.40", "Pittsburgh", "false", "refreshToken", "7be41c09"],
              ["10-09 01:17:22", "203.0.113.58", "Frankfurt", "false", "refreshToken", "7be41c09"],
              ["10-08 13:31:38", "203.0.113.58", "Frankfurt", "false", "refreshToken", "7be41c09"],
              ["10-08 13:04:11", "198.51.100.40", "Pittsburgh", "true", "none", "7be41c09"],
              ["10-06 12:55:40", "198.51.100.40", "Pittsburgh", "true", "none", "4ac20e7d"],
            ],
            answer: 3,
            why: "Rows come newest first, so the earliest Frankfurt row is the lowest one. That was five days before any money moved.",
            learned: "First seen 10-08 13:31:38 from 203.0.113.58",
          },
          {
            id: "rule",
            ask: "Before it sent anything, that address changed the mailbox. Which record?",
            source: "Unified Audit Log · Exchange · e.brandt",
            columns: ["CreationTime", "Operation", "ClientIP", "Parameters"],
            rows: [
              ["10-09 01:19:44", "MailItemsAccessed", "203.0.113.58", "Folder: Inbox/Kestrel Viaduct"],
              ["10-08 13:52:02", "New-InboxRule", "203.0.113.58", "Name: zz; FromAddressContainsWords: ostrandergeo.example; MoveToFolder: Conversation History; MarkAsRead: True; StopProcessingRules: True"],
              ["10-08 13:38:10", "MailItemsAccessed", "203.0.113.58", "Folder: Sent Items"],
              ["10-02 14:11:27", "New-InboxRule", "198.51.100.40", "Name: Kestrel dailies; FromAddressContainsWords: site-reports@harcourtvane.example; MoveToFolder: Kestrel Daily"],
            ],
            answer: 1,
            why: "The same ClientIP as the sign-in, 20 minutes after it, so one person did both. Erin's own rule is the one from the office address. Now read what this one points at: a single supplier.",
            learned: "Rule zz, 10-08 13:52:02, sends ostrandergeo.example mail to Conversation History",
          },
          {
            id: "kept",
            ask: "Erin never saw what that rule caught. Which message was it there to keep away?",
            source: "Content search · e.brandt · Conversation History",
            columns: ["Received", "From", "Subject", "IsRead"],
            rows: [
              ["10-13 09:00:02", "noreply@ostrandergeo.example", "Client portal maintenance, Saturday", "True"],
              ["10-12 20:44:31", "logs@ostrandergeo.example", "Phase 2 boring logs, addendum", "True"],
              ["10-12 16:21:05", "ar@ostrandergeo.example", "Statement: OG-20418 due 10-13, remit to our account ending 2207", "True"],
              ["10-09 15:03:40", "logs@ostrandergeo.example", "Phase 2 boring logs, final set", "True"],
            ],
            answer: 2,
            why: "Ostrander's credit controller, stating the real account the day before the fake one arrived. Nothing here was stolen. This rule's job is silence: the honest party's words never reach the person who would spot the mismatch.",
            learned: "Real account ends 2207, and Erin never saw the statement",
          },
          {
            id: "send",
            ask: "One mailbox, one thread, two messages to Accounts Payable. Which one carried the new bank details?",
            source: "Unified Audit Log · Send · e.brandt",
            columns: ["CreationTime", "ClientIP", "To", "Subject"],
            rows: [
              ["10-13 14:06:19", "203.0.113.58", "ap@harcourtvane.example", "RE: RE: Kestrel Viaduct: Ostrander boring logs and invoice OG-20418"],
              ["10-13 13:12:55", "198.51.100.40", "ap@harcourtvane.example", "RE: Kestrel Viaduct: Ostrander boring logs and invoice OG-20418"],
              ["10-13 12:47:08", "198.51.100.40", "site-team@harcourtvane.example", "Kestrel weekly programme"],
              ["10-07 17:30:16", "198.51.100.40", "ar@ostrandergeo.example", "Phase 2 logs received, thanks"],
            ],
            answer: 0,
            why: "The subject can't separate two replies in one thread, and the ClientIP can. The 13:12 message is Erin's own. 54 minutes later the session answered in the same thread.",
            learned: "Fake reply sent 10-13 14:06:19 from 203.0.113.58",
          },
          {
            id: "vendor",
            ask: "Where did that email turn into a payment instruction?",
            source: "Finance system · vendor master change log",
            columns: ["ChangedAt", "Vendor", "Field", "Old", "New", "ChangedBy", "CallbackRef"],
            rows: [
              ["10-13 17:02:33", "Tri-County Rebar", "remit_address", "PO Box 118", "PO Box 240", "s.tan", "n/a"],
              ["10-13 15:44:12", "Keystone Aggregate", "bank_account", "****6630", "****1174", "s.tan", "CB-2291"],
              ["10-13 15:31:50", "Hollis Crane Hire", "payment_terms", "Net 30", "Net 45", "s.tan", "n/a"],
              ["10-13 15:10:06", "Ostrander Geotechnical", "bank_account", "****2207", "****8841", "s.tan", "(none)"],
              ["10-09 16:18:27", "Ostrander Geotechnical", "contact_name", "D. Pruitt", "L. Pruitt", "s.tan", "n/a"],
            ],
            answer: 3,
            why: "One bank change, one empty CallbackRef. Keystone's bank change the same afternoon shows how the field should look. From this row on, the next payment goes to 8841.",
            learned: "Vendor record changed 10-13 15:10:06 with no call-back",
          },
        ],
      },
    ],
    // ── Analyst choice: rules that fire on ordinary work ──
    "bec-ac1": [
      {
        kind: "queue",
        title: "Same Operation, Different Story",
        prompt: "The mailbox rule alert fires on more than fraud. Oluchi pulls four hits from last quarter's queue for you to work. Open each one, read what stands behind it and decide. An alert on a rule is a reason to look, not a verdict.",
        primer: {
          title: "Three Ways an Alert Can End",
          points: [
            "**True positive:** the alert fired on something real and unauthorised.",
            "**Benign true positive:** the alert was right about what happened, and the activity turns out to be authorised.",
            "**False positive:** the alert fired on something that did not happen the way it claims.",
            "**Verify with IT** asks whether a ticket or a change record stands behind the activity. A record you can check counts for more than a reason written in a rule's name.",
          ],
          example: {
            label: "Worked example: a new-country sign-in",
            lines: [
              "A buyer signs in from Germany and an alert fires. IT confirms a trade-fair ticket with matching dates, on a company laptop.",
              "The alert was right about the new country, and the trip was authorised: benign true positive.",
            ],
          },
        },
        console: "SIEM · Mailbox rule alerts",
        actions: [
          { id: "close", label: "Close: benign true positive", tone: "close" },
          { id: "esc", label: "Escalate", tone: "escalate" },
        ],
        alerts: [
          {
            id: "ext", time: "09:14", severity: "High", rule: "Inbox rule forwards mail outside the tenant", entity: "b.ortiz",
            fields: [{ k: "ForwardTo", v: "b.ortiz.home@freemail.example" }, { k: "DeleteMessage", v: "True" }, { k: "SubjectOrBodyContainsWords", v: "payroll, W-2" }, { k: "ClientIP", v: "203.0.113.91" }],
            context: "Verify with IT: no ticket. The address is not in this account's sign-in history.",
            answer: "esc", why: "An outside address, the local copy deleted, tax-form keywords and an unknown IP, with nothing on file. Payroll mail is what this rule was built to collect.",
          },
          {
            id: "rec", time: "10:02", severity: "Medium", rule: "Inbox rule forwards mail", entity: "l.nguyen",
            fields: [{ k: "Name", v: "Kestrel close-out" }, { k: "ForwardTo", v: "kestrel-records@harcourtvane.example" }, { k: "ClientIP", v: "198.51.100.40" }, { k: "StopProcessingRules", v: "False" }],
            context: "Verify with IT: ticket HD-7719. Records mailbox created for the Phase 1 close-out, requested by the project office.",
            answer: "close", why: "The alert was right that a forward exists, and Harcourt's records process explains it. The ticket is what settles it: you can read it, and it names who asked.",
          },
          {
            id: "red", time: "11:36", severity: "Medium", rule: "Inbox rule redirects mail", entity: "k.obrien",
            fields: [{ k: "Name", v: "x" }, { k: "RedirectTo", v: "g.lasker@harcourtvane.example" }, { k: "ClientIP", v: "203.0.113.140" }, { k: "StopProcessingRules", v: "True" }],
            context: "Verify with IT: no ticket. g.lasker works in another department and knows nothing about it. k.obrien's sign-ins all come from Pittsburgh.",
            answer: "esc", why: "An internal address clears nothing alone. RedirectTo keeps the original sender, so the recipient sees nothing odd, the IP is unknown, and the recipient can't explain it. Two mailboxes may be involved now.",
          },
          {
            id: "file", time: "13:20", severity: "Low", rule: "Inbox rule moves mail to a folder", entity: "s.tan",
            fields: [{ k: "Name", v: "Rebar statements" }, { k: "FromAddressContainsWords", v: "statements@tricountyrebar.example" }, { k: "MoveToFolder", v: "Supplier Statements" }, { k: "MarkAsRead", v: "False" }, { k: "ClientIP", v: "198.51.100.40" }],
            context: "Verify with IT: no ticket, and personal filing needs none. Sam confirms it on the directory number and opens that folder daily.",
            answer: "close", why: "The same lever as a concealment rule, pointed at a folder its owner reads, from the office address, with the unread count left on. Confirmed by the person, on a number you already held.",
          },
        ],
      },
    ],
    // ── Reading 5: the timeline and the clock ──
    "bec-r5": [
      {
        kind: "sequence",
        title: "Walk It Backwards",
        prompt: "Investigators meet a case like this from the wrong end. Start at Noor's reconciliation and walk back: each tap is the event that made the last one possible, until you reach where it began.",
        miss: "Not yet. Which event made the last one you placed possible?",
        items: [
          { id: "read", text: "The session reads the Kestrel folders and waits for an invoice to fall due", note: "Thursday to Tuesday. MailItemsAccessed records show days of patient reading." },
          { id: "wire", text: "Marek Dolan releases the wire on the bank portal", note: "Tuesday 15:52 UTC. The Money Clock starts here, whether or not anyone has noticed." },
          { id: "steal", text: "An infostealer on site laptop HV-SITE-07 lifts Erin's browser session", note: "Thursday, soon after 13:04 UTC. It came in with a free CAD viewer someone installed on that laptop." },
          { id: "recon", text: "Noor's reconciliation finds $387,250 paid to an account ending 8841", note: "Tuesday 18:20 UTC. Your first record, and the last thing that happened." },
          { id: "rule", text: "Rule zz starts sending Ostrander's mail to Conversation History", note: "Thursday 13:52 UTC, same ClientIP as the sign-in." },
          { id: "vendor", text: "Sam Tan edits Ostrander's bank details in the vendor master", note: "Tuesday 15:10 UTC, CallbackRef empty." },
          { id: "replay", text: "A non-interactive sign-in from Frankfurt joins Erin's session", note: "Thursday 13:31 UTC." },
          { id: "send", text: "A reply lands in the Ostrander thread from Erin's mailbox", note: "Tuesday 14:06 UTC, ClientIP 203.0.113.58." },
        ],
        order: ["recon", "wire", "vendor", "send", "read", "rule", "replay", "steal"],
        doneNote: "Read it forwards and you have the timeline for the bank and the report, with a real time on every line. Five days sat between the session and the money. A case like this is built by walking back, and written up going forwards.",
      },
      {
        kind: "worksheet",
        title: "Run the Money Clock",
        prompt: "Marek asks Oluchi what the odds are. Oluchi opens the fraud file and asks you to read it first. Every number is hours since the funds left.",
        primer: {
          title: "How a Recall Works",
          points: [
            "**A recall is a request, not an undo.** The sending bank asks the receiving bank to return the funds, and it can only return what is still there.",
            "**The window** is usually hours to a few days, and it shrinks sharply once the funds move on to a second account.",
            "**The clock starts at the transfer.** Noticing later resets nothing.",
            "**Reporting:** in the US a report goes to the FBI's Internet Crime Complaint Center (IC3), and other countries have an equivalent body. Banks and police sometimes coordinate on that report.",
          ],
          example: {
            label: "Worked example: reading one row",
            lines: [
              "Funds left at 09:00, spotted at 13:00, bank told at 13:30.",
              "The clock at the call reads 4.5 hours, not 30 minutes, because it runs from 09:00.",
            ],
          },
        },
        caption: "Oluchi's fraud file · hours since the funds left",
        columns: ["Case", "Spotted", "Bank told", "Funds moved on", "Recovered"],
        rows: [
          ["A", "2", "3", "never", "100%"],
          ["B", "3", "31", "20", "6%"],
          ["C", "4", "5", "9", "88%"],
          ["D", "240", "241", "30", "0%"],
          ["E", "26", "27", "44", "61%"],
        ],
        questions: [
          { id: "gap", q: "How many hours passed in case B between spotting the fraud and telling the bank?", hint: "Bank told minus Spotted.", answer: ["28"], why: "Spotted at hour 3, told at hour 31. The money moved on at hour 20, with nobody at the bank looking for it." },
          { id: "late", q: "Case D rang the bank within an hour of spotting it. What percentage came back?", hint: "Read the last column, then compare Bank told with Funds moved on.", answer: ["0", "0%"], why: "One hour after spotting, and 241 hours after the money left. Speed from discovery did not help, because the clock had been running for ten days." },
          { id: "before", q: "In how many of the five cases did the bank hear before the funds moved on?", hint: "Compare Bank told with Funds moved on, row by row.", answer: ["3", "three"], why: "A, C and E, which recovered 100, 88 and 61 percent. B and D told the bank after the money had gone, and got almost nothing." },
          { id: "ours", q: "Harcourt's wire left at 15:52 UTC and Noor flagged it at 18:20 UTC. How many minutes were already on the clock?", hint: "From 15:52 to 18:20.", answer: ["148"], why: "148 minutes went by before anyone knew. That time is gone, so the time from here on is the time that counts." },
        ],
      },
    ],
    // ── Scoping drill ──
    "bec-q3": [
      {
        kind: "deduce",
        title: "Who Else Did They Touch?",
        prompt: "A tenant-wide search on what this operator left behind came back with six finance-adjacent mailboxes. One of them belongs to the same operator. Strike them out as the results come in.",
        primer: {
          title: "Searching for an Operator, Not an Address",
          points: [
            "**ASN (Autonomous System Number):** the identifier for the block of IP addresses one network operator controls. Two different addresses from one hosting provider share it.",
            "**A rule's shape** is its conditions and actions taken together, whatever its name or the sender it points at.",
            "**Indicators age at different speeds.** An address can be swapped in a minute. A network takes longer, and a working rule shape tends to get reused.",
          ],
          example: {
            label: "Worked example: three searches",
            lines: [
              "Search one address: 1 hit.",
              "Search its ASN: 3 hits, two of them a commercial VPN that staff use.",
              "Add the behaviour that came with it: 1 hit is left, and it is not the one you started with.",
            ],
          },
        },
        nameColumn: "Mailbox",
        columns: ["Role", "Outside address this month", "Network", "New rule?", "Rule shape"],
        suspects: [
          { id: "tan", name: "s.tan", cells: ["Accounts payable", "None", "AS64509 (Harcourt)", "Yes", "One sender, filed, stays unread"] },
          { id: "dolan", name: "m.dolan", cells: ["Finance controller", "Atlanta hotel, once", "AS64505", "No", "None"] },
          { id: "iyer", name: "r.iyer", cells: ["Payroll officer", "203.0.113.77, twice", "AS64501", "Yes", "One sender, buried, marked read"] },
          { id: "ward", name: "c.ward", cells: ["Executive assistant", "203.0.113.212, daily", "AS64502", "Yes", "Forwards to a colleague"] },
          { id: "boyle", name: "t.boyle", cells: ["Buyer", "203.0.113.90, once", "AS64501", "No", "None"] },
          { id: "haddad", name: "n.haddad", cells: ["Finance analyst", "None", "AS64509 (Harcourt)", "Yes", "One sender, buried, marked read"] },
        ],
        clues: [
          "Searching the exact address 203.0.113.58 returns Erin and nobody else.",
          "That address sits in AS64501. Any other address in that block counts as the same network.",
          "Now look at what the session left behind, and match the shape of rule zz.",
        ],
        culprit: "iyer",
        why: "r.iyer: a different address, the same AS64501, and a rule of the same shape pointed at the payroll provider. The exact IP found nobody, because operators commonly work several accounts before acting through one, and they do not always reuse an address. t.boyle shares the network with no rule, so that one sign-in gets checked, not assumed. Noor's rule has the shape and none of the network: a newsletter, filed from the office.",
      },
    ],
    // ── Reading 6: the full response ──
    "bec-r6": [
      {
        kind: "defuse",
        title: "The First Hour",
        prompt: "Tuesday, minutes after Noor's call, and everyone on the fraud desk is on the phone. Five decisions land on you, one after another. Each has one right move, and the wrong ones feel like progress.",
        primer: {
          title: "What Each Fix Actually Removes",
          points: [
            "**Sessions and tokens:** an access token already issued runs until it expires, and a password reset does not reliably end every session. Revoke explicitly, then check the log.",
            "**Authentication methods:** a phone or authenticator app added during a compromise stays on the account until someone finds and removes it (ATT&CK T1098.005, Account Manipulation: Device Registration). Re-registration goes through a verified, out-of-band channel.",
            "**Outside parties:** reach banks and suppliers on a number from a signed agreement, the directory or a past call, because the mail thread may still be the attacker's.",
            "**Report references:** banks frequently ask for a reference from IC3 or the national equivalent before they escalate a recall internally.",
          ],
          example: {
            label: "Worked example: a stolen VPN account",
            lines: [
              "List what the intruder holds: a password, an open tunnel, a one-time-code app enrolled last night.",
              "Match each to the fix that removes it. A password change covers the first line only.",
              "Whatever is still on the list is still working.",
            ],
          },
        },
        device: "The Money Clock",
        seconds: 100,
        rounds: [
          {
            id: "number",
            state: "18:26 UTC: Marek is about to ring the bank's fraud team. Sam has a 'bank security' number from a message that arrived this morning.",
            wires: [
              { id: "a", label: "Ring the number on the signed treasury agreement" },
              { id: "b", label: "Ring the number Sam has" },
              { id: "c", label: "Reply to that message and ask them to call" },
            ],
            cut: "a",
            hint: "Which number could the attacker not have written?",
            why: "The attacker has been reading this mail for days. A number that came through mail is a number the attacker may have chosen.",
          },
          {
            id: "tokens",
            state: "18:35 UTC: Erin's password was reset. 18:39 UTC: the sign-in log shows 203.0.113.58 still reading mail.",
            wires: [
              { id: "a", label: "Reset the password a second time" },
              { id: "b", label: "Revoke Erin's sessions and refresh tokens" },
              { id: "c", label: "Delete rule zz and watch the log" },
            ],
            cut: "b",
            hint: "What can stay live after a password change?",
            why: "An access token already issued runs until it expires, and a reset does not reliably end every session, so revoke explicitly and check the log. The rule still has to go, but it isn't what's keeping them inside.",
          },
          {
            id: "method",
            state: "18:52 UTC: the directory audit log shows an authenticator app registered on Erin's account on Thursday, from 203.0.113.58.",
            wires: [
              { id: "a", label: "Require a new password at next sign-in" },
              { id: "b", label: "Add Erin to a stricter Conditional Access policy" },
              { id: "c", label: "Remove that method and re-register MFA in person" },
            ],
            cut: "c",
            hint: "Whose phone would answer the next prompt?",
            why: "A registered method is a way back in, and a reset does not touch it. Conditional Access would happily accept it as a valid second factor.",
          },
          {
            id: "report",
            state: "19:04 UTC: the bank's fraud team says a report reference will help them escalate to the receiving bank.",
            wires: [
              { id: "a", label: "Ask Ostrander to file a report for you" },
              { id: "b", label: "File with IC3 and pass on the reference" },
              { id: "c", label: "Send the bank a copy of your case notes" },
            ],
            cut: "b",
            hint: "Whose money left, and who is the bank asking?",
            why: "Harcourt is the victim here and the filer. The reference is what the bank asked for, and banks and police sometimes coordinate an intercept from that same report. Case notes are not a report.",
          },
          {
            id: "supplier",
            state: "19:20 UTC: Ostrander still doesn't know. Their statement went unanswered and their real invoice is unpaid.",
            wires: [
              { id: "a", label: "Reply in the Kestrel thread with the news" },
              { id: "b", label: "Have Erin email them from the reset account" },
              { id: "c", label: "Ring the number on the Ostrander contract" },
            ],
            cut: "c",
            hint: "Would you believe that email, if you were them?",
            why: "That thread carried the fraud, and Ostrander has no reason to trust it now. A call on a contract number reaches a real person, and they may need to check their own side too.",
          },
        ],
        lesson: "Ask what the intruder still holds and remove that, not the thing that's easiest to remove. Reach outsiders only through a channel the attacker could not have touched.",
      },
      {
        kind: "spotdiff",
        title: "What the Written Summary Needs",
        prompt: "The shift's draft is on Oluchi's desk beside the reviewed version. Tap each line of the draft that would leave the controller, the insurer or the next analyst short of something they need.",
        goodTitle: "Reviewed summary",
        suspectTitle: "Shift draft",
        good: [
          "Case: HV-2026-118, Ostrander payment diversion",
          "Accounts: e.brandt, r.iyer",
          "Timeline: 10-08 13:31:38 first replay; 13:52:02 rule zz; 10-13 14:06:19 fake reply; 15:52 wire (UTC)",
          "Indicators: 203.0.113.58, 203.0.113.77, AS64501, sessionId 7be41c09, rule zz and its parameters",
          "Exposure: $387,250.00 to account ending 8841",
          "Recall: requested 18:31 UTC, IC3 reference with the bank",
          "Actions: sessions revoked, passwords reset, rules and app removed. Pending: Ostrander's written notice",
          "Root cause: infostealer on HV-SITE-07 lifted a browser session; laptop rebuilt",
          "Prevention: call-back reference now mandatory in the vendor master",
          "Reviewed by: O. Svensson",
        ],
        suspect: [
          "Case: HV-2026-118, Ostrander payment diversion",
          "Accounts: e.brandt, r.iyer",
          "Timeline: attacker active from last Thursday until the wire on Tuesday",
          "Indicators: suspicious IP in Germany",
          "Exposure: $387,250 to account ending 8841",
          "Recall: requested 18:31 UTC, IC3 reference with the bank",
          "Actions: all done",
          "Root cause: password reset and account secured",
          "Prevention: call-back reference now mandatory in the vendor master",
          "Reviewed by: O. Svensson",
        ],
        diffs: [
          { line: 2, why: "A bank or an insurer needs exact times. Keep the real timestamps, in one stated time zone." },
          { line: 3, why: "'Suspicious IP' can't be searched. The next analyst needs the addresses, the sessionId and the rule's exact parameters." },
          { line: 6, why: "'All done' hides what is still open. A summary separates what has been done from what is pending." },
          { line: 7, why: "That is a fix, not a cause. The root cause is how the session was stolen, and only fixing that stops a repeat." },
        ],
        decoys: [
          { line: 4, why: "Same amount, same account. The cents are formatting." },
        ],
        hud: "Tap the draft lines that fall short",
        sameLine: "That line is the same in both versions, so it already does its job.",
        winTitle: "Summary ready for the controller",
        howTo: [
          "Read the reviewed summary on the left.",
          "Tap each line of the draft that leaves something out.",
          "A line that matches, or that differs only in formatting, costs a life.",
        ],
        lesson: "A summary is what other people act on. It needs exact times, exact indicators, the dollar exposure, what is done and what is pending, and the root cause. A summary that stops at the password reset leaves the real question open.",
      },
    ],
  },
};
