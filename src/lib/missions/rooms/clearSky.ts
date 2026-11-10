/**
 * Room 36 "Operation Clear Sky" (sentinel-fundamentals): Ashgrove Pharmacy moved
 * to Microsoft Sentinel last month; Malik Haddad wants analysts who open the
 * right table and write the query themselves. Five missions on one workspace
 * (dataset "clear-sky", src/lib/missions/datasets/clearSky.ts):
 *
 *   m1 three tickets, three tables     (kql x3)
 *   m2 the travel rule                 (kql, then read the result)
 *   m3 incident 4412: pivot on the IP  (kql, then the facts)
 *   m4 read the raw row                (fields on a SigninLogs record)
 *   m5 boss: call the spray            (kql, then verdict and action)
 *
 * Every KQL step is graded by its RESULT on the visible and a shadow workspace.
 */
import type { MissionTask } from "../types";

const MENTOR = "Malik Haddad, Sentinel Architect";

export const CLEAR_SKY_M1: MissionTask = {
  type: "mission",
  id: "sentinel-m1",
  heading: "Three Tickets, Three Tables",
  mentor: MENTOR,
  story: "The team moved to Sentinel a month ago and still opens the wrong table first. Malik drops three tickets on your desk. \"Each one is a single question. Each one lives in a different table. Find the table, write the query, give me the answer.\"",
  objective: "Answer three tickets with three KQL queries, one per table.",
  dataset: "clear-sky",
  steps: [
    {
      kind: "kql", id: "t1", xp: 20,
      prompt: "Ticket 1: **which account updated an existing Conditional Access policy?** Return the account (its UPN).",
      focusTables: ["AuditLogs"],
      starter: "// Which table records changes to Entra ID policies?\n",
      hint: "Changes made in Entra ID (users, groups, policies) are audit records, not sign-ins.",
      where: "Open `AuditLogs`. `OperationName` says what was done; the actor sits inside the dynamic column `InitiatedBy`, at `InitiatedBy.user.userPrincipalName`. Wrap it in `tostring()` to use it.",
      answer: {
        reference: ["AuditLogs | where OperationName == \"Update conditional access policy\" | extend Actor = tostring(InitiatedBy.user.userPrincipalName) | distinct Actor"],
        mode: "values", keys: ["Actor"],
        traps: [
          { ifQuery: "conditional access policy\"?\\s*\\)?\\s*(\\||$)|has\\s+\"conditional access\"|contains\\s+\"conditional", say: "Two different operations mention Conditional Access here. The ticket asks who UPDATED an existing policy, not who added a new one. Look at the exact `OperationName` values." },
          { ifRowsMoreThan: 1, say: "More than one account in your answer. Which of these operations is an update of an existing policy?" },
        ],
      },
      worked: "```\nAuditLogs\n| where OperationName == \"Update conditional access policy\"\n| extend Actor = tostring(InitiatedBy.user.userPrincipalName)\n| distinct Actor\n```\nThe answer is the account in `InitiatedBy.user.userPrincipalName` of that one row. `Add conditional access policy` is a different operation: a new policy, not a change to one.",
      debrief: "Directory changes live in `AuditLogs`, and the actor is nested in the dynamic `InitiatedBy` column. Filtering on the exact `OperationName` keeps \"added\" and \"updated\" apart.",
    },
    {
      kind: "kql", id: "t2", xp: 20,
      prompt: "Ticket 2: **which mailbox got a NEW inbox rule?** Return the mailbox (UserId).",
      focusTables: ["OfficeActivity"],
      hint: "Mailbox rules are Exchange operations, logged by the Microsoft 365 audit, not by Entra ID.",
      where: "Open `OfficeActivity`. Exchange cmdlets appear in `Operation` under their own names. A new rule and a changed rule are two different cmdlets.",
      answer: {
        reference: ["OfficeActivity | where Operation == \"New-InboxRule\" | distinct UserId"],
        mode: "values", keys: ["UserId"],
        traps: [
          { ifQuery: "InboxRule\"?\\s*\\)?(?!.*New-)|has\\s+\"InboxRule\"|contains\\s+\"InboxRule\"", say: "`Set-InboxRule` changes a rule that already exists, and here it was an admin tidying a shared mailbox. The ticket asks for a NEW rule: that cmdlet is `New-InboxRule`." },
          { ifRowsMoreThan: 1, say: "More than one mailbox. Only one of these operations creates a rule." },
        ],
      },
      worked: "```\nOfficeActivity\n| where Operation == \"New-InboxRule\"\n| distinct UserId\n```\nLook at that row's `Parameters` too: a rule named `.` that forwards mail about invoices and payments to an outside address, marks it as read and moves it to RSS Subscriptions is a classic attacker rule: it steals the mail and hides the replies.",
      debrief: "Mailbox and SharePoint activity is in `OfficeActivity`; the operation is the Exchange cmdlet name. Read `Parameters` before you judge a rule: the name `.`, a `ForwardTo` outside the company and MarkAsRead + MoveToFolder steal mail and hide it from the owner.",
    },
    {
      kind: "kql", id: "t3", xp: 20,
      prompt: "Ticket 3: **which shop PC ran certutil to download a file (`-urlcache`)?** Return the device name.",
      focusTables: ["DeviceProcessEvents"],
      hint: "Process launches on endpoints come from Defender for Endpoint. certutil is a normal admin tool: the switch on the command line is what makes it suspicious.",
      where: "Open `DeviceProcessEvents`. Filter `FileName` for certutil.exe (`=~` ignores case) and the command line for `urlcache` (`has` matches a whole term).",
      answer: {
        reference: [
          "DeviceProcessEvents | where FileName =~ \"certutil.exe\" and ProcessCommandLine has \"urlcache\" | distinct DeviceName",
          "DeviceProcessEvents | where ProcessCommandLine has \"urlcache\" | distinct DeviceName",
        ],
        mode: "values", keys: ["DeviceName"],
        traps: [
          { ifRowsMoreThan: 1, say: "certutil also runs for honest reasons: `-hashfile` checks an installer, `-verify` checks a certificate. Only one switch downloads a file." },
        ],
      },
      worked: "```\nDeviceProcessEvents\n| where FileName =~ \"certutil.exe\" and ProcessCommandLine has \"urlcache\"\n| distinct DeviceName\n```\n`-urlcache -split -f <url> <file>` makes certutil download a file (ATT&CK T1105, Ingress Tool Transfer). The next row on that PC loads the \"png\" with rundll32: it was never a picture.",
      debrief: "Endpoint process launches are in `DeviceProcessEvents`. A living-off-the-land binary is judged by its switches, not its name: `-urlcache` downloads, `-hashfile` does not.",
    },
  ],
};

export const CLEAR_SKY_M2: MissionTask = {
  type: "mission",
  id: "sentinel-m2",
  heading: "The Travel Rule",
  mentor: MENTOR,
  story: "One account on Incident 4412 signed in from four countries this week, and a regional manager's from three. Malik: \"People travel. Passwords travel too. Before anyone writes a rule, I want every account that does this, and which one is a person and which one is a password.\"",
  objective: "Find every account with successful sign-ins from 3 or more countries in the last 7 days, then decide which one is the real problem.",
  dataset: "clear-sky",
  steps: [
    {
      kind: "kql", id: "query", xp: 40,
      prompt: "Write the query: **accounts that signed in SUCCESSFULLY from 3 or more different countries in the last 7 days.** Build it a line at a time and watch the row counts.",
      focusTables: ["SigninLogs"],
      starter: "SigninLogs\n| where TimeGenerated > ago(7d)\n",
      hint: "Three filters and one count: last 7 days, successful sign-ins only, count DIFFERENT countries per account, keep 3 or more.",
      where: "`ResultType` is a STRING: success is `\"0\"` (with quotes). `Location` holds the country code. `dcount(Location)` counts different values; put it in `summarize ... by UserPrincipalName`, then `where` on the count.",
      answer: {
        reference: ["SigninLogs | where TimeGenerated > ago(7d) | where ResultType == \"0\" | summarize Countries = dcount(Location) by UserPrincipalName | where Countries >= 3"],
        mode: "values", keys: ["UserPrincipalName"],
        traps: [
          { ifQuery: "^(?![\\s\\S]*ResultType)", say: "Your query counts failed sign-ins too. A failed password from another country is someone trying, not someone travelling. Keep successes only." },
          { ifQuery: "^(?![\\s\\S]*(ago|between|datetime))", say: "No time window: you are counting every day in the table. The question is about the last 7 days." },
          { ifQuery: "count\\(\\)\\s*(by|$)|count\\(Location\\)", say: "`count()` counts sign-ins, not countries. Ten sign-ins from one country is still one country: use `dcount(Location)`." },
        ],
      },
      worked: "```\nSigninLogs\n| where TimeGenerated > ago(7d)\n| where ResultType == \"0\"\n| summarize Countries = dcount(Location), Where = make_set(Location) by UserPrincipalName\n| where Countries >= 3\n```\nWithout `ResultType == \"0\"` an account whose password was only GUESSED from abroad joins the list; without `ago(7d)` an old trip does.",
      debrief: "`ResultType` is a string in SigninLogs, so success is `== \"0\"`; `== 0` is a type error. `dcount()` counts distinct values, which is what \"how many countries\" means.",
    },
    {
      kind: "fields", id: "judge", xp: 20,
      prompt: "Your query returns two accounts. Add `make_set(DeviceDetail.deviceId)` and `make_set(AuthenticationRequirement)` to the summarize and compare them. **Which account is the real problem, and which column proves it?**",
      fields: [
        { id: "account", label: "The account that is the problem", format: "account", placeholder: "name@ashgrove.example", accept: ["d.okafor@ashgrove.example"], coach: "One account used the same laptop and MFA in every country: that is a person travelling. Look for the one whose last country came with a new device and no MFA.", traps: [{ value: "r.ansah@ashgrove.example", say: "r.ansah signed in from one device with MFA every time: one person on a work trip. The other account is the problem." }] },
        { id: "column", label: "The column that proves it", format: "choice", options: ["Location", "AuthenticationRequirement", "DeviceDetail", "AppDisplayName", "ResultType"], accept: ["AuthenticationRequirement", "DeviceDetail"], coach: "Both accounts have three countries in `Location`, so it cannot tell them apart. Which column differs between them?" },
      ],
      hint: "Both accounts look the same by country. Look at HOW they signed in: on which device, and with which factor.",
      where: "`DeviceDetail.deviceId` is the registered device; `AuthenticationRequirement` says whether MFA was asked for. A traveller keeps one device and passes MFA.",
      worked: "**d.okafor@ashgrove.example.** Britain, Spain and Portugal came from her own laptop with `multiFactorAuthentication`: a real trip. Nigeria, at 23:41 straight into Exchange Online, came with no device id, a Python user agent and `singleFactorAuthentication`: that sign-in is not her. r.ansah used one device with MFA in all three countries: a person travelling. Either `DeviceDetail` or `AuthenticationRequirement` proves it.",
      debrief: "A detection that only counts countries flags travellers. The context columns (device, MFA, app) decide whether the travel is a person or a password.",
    },
  ],
};

export const CLEAR_SKY_M3: MissionTask = {
  type: "mission",
  id: "sentinel-m3",
  heading: "Incident 4412: Pivot on the IP",
  mentor: MENTOR,
  story: "Incident 4412 fired last night: three analytics rules on the same account, joined into one incident. Malik: \"The incident gives you one account. The attacker never brings only one. Pivot on the address.\"",
  objective: "Pivot from the incident's IP to every account it tried, and state what it got.",
  dataset: "clear-sky",
  artifacts: [{
    id: "incident",
    title: "Incident 4412 (Microsoft Sentinel)",
    format: "mono",
    body: [
      "Incident ID      4412",
      "Title            Sign-in from a rare country, forwarding rule and bulk download",
      "Severity         High",
      "Status           New",
      "Created (UTC)    2026-11-08 23:52:30",
      "Alerts           3",
      "Analytics rules  Sign-in from a country never seen for the user (Scheduled)",
      "                 Inbox rule forwards mail outside the company (Scheduled)",
      "                 Bulk file download from SharePoint (Scheduled)",
      "Entities         Account  d.okafor@ashgrove.example",
      "                 IP       198.51.100.23",
      "Tactics          Initial Access, Persistence, Collection",
    ].join("\n"),
  }],
  steps: [
    {
      kind: "kql", id: "pivot", xp: 40,
      prompt: "Write the pivot: **every account that 198.51.100.23 tried to sign in to, with the result code of each.** One row per account and result.",
      focusTables: ["SigninLogs"],
      artifactIds: ["incident"],
      hint: "Start from the address, not from the account: filter sign-ins on the IP, then group.",
      where: "`SigninLogs | where IPAddress == \"198.51.100.23\"`, then `summarize count() by UserPrincipalName, ResultType` (or `distinct UserPrincipalName, ResultType`).",
      answer: {
        reference: ["SigninLogs | where IPAddress == \"198.51.100.23\" | summarize Attempts = count() by UserPrincipalName, ResultType"],
        mode: "rows", keys: ["UserPrincipalName", "ResultType"], distinct: true,
        traps: [
          { ifQuery: "d\\.okafor", say: "Filtering on d.okafor shows the victim only. The pivot starts from the IP so you see every account it tried." },
          { ifQuery: "^(?![\\s\\S]*ResultType)", say: "Group by the result code too: one account can have a failure AND a success from the same address, and that pair is the story." },
        ],
      },
      worked: "```\nSigninLogs\n| where IPAddress == \"198.51.100.23\"\n| summarize Attempts = count() by UserPrincipalName, ResultType\n```\nFour accounts tried in six minutes from a Python client. Three only failed (`50126`); d.okafor failed once and then succeeded (`0`) at 23:41 with a single factor.",
      debrief: "Pivoting on the entity the incident hands you (the IP) widens the scope from one victim to everyone the attacker touched. That list is your containment list.",
    },
    {
      kind: "fields", id: "facts", xp: 20,
      prompt: "From your result: state the facts for the incident notes.",
      fields: [
        { id: "tried", label: "How many different accounts did the IP try?", format: "int", accept: ["4"], coach: "Count the distinct accounts in your pivot, not the rows." },
        { id: "in", label: "Which account did it get into?", format: "account", accept: ["d.okafor@ashgrove.example"], coach: "Which account has a `ResultType` of 0 from that address?" },
        { id: "factor", label: "How did that sign-in authenticate? (AuthenticationRequirement value)", format: "text", accept: ["singleFactorAuthentication", "single factor", "single-factor", "singlefactor"], coach: "Look at the successful row's `AuthenticationRequirement`." },
      ],
      hint: "Everything is in the rows you pivoted to. Add `AuthenticationRequirement` to see how the success happened.",
      where: "Re-run the pivot with `| project TimeGenerated, UserPrincipalName, ResultType, AuthenticationRequirement, UserAgent`.",
      worked: "4 accounts tried. d.okafor@ashgrove.example signed in with `singleFactorAuthentication` and a `python-requests` user agent: a scripted login that MFA never challenged. Next: revoke d.okafor's sessions, reset the password, remove the forwarding rule, and check why MFA did not apply.",
      debrief: "Facts in incident notes are exact: a count, an account, a field value. \"Several accounts\" and \"probably MFA\" cannot be acted on.",
    },
  ],
};

export const CLEAR_SKY_M4: MissionTask = {
  type: "mission",
  id: "sentinel-m4",
  heading: "Read the Raw Row",
  mentor: MENTOR,
  story: "Behind every alert is one row. Malik pulls a failed sign-in from the night shift and hides the summary columns. \"No portal, no tooltips. Read it like evidence.\"",
  objective: "Read one SigninLogs record and state what happened, field by field.",
  artifacts: [{
    id: "row",
    title: "SigninLogs record (expanded)",
    format: "mono",
    body: JSON.stringify({
      TimeGenerated: "2026-11-07T03:14:11Z",
      UserPrincipalName: "f.lindqvist@ashgrove.example",
      AppDisplayName: "Office 365 Exchange Online",
      ClientAppUsed: "Exchange ActiveSync",
      IPAddress: "203.0.113.77",
      Location: "RU",
      ResultType: "50126",
      ResultDescription: "Error validating credentials due to invalid username or password.",
      AuthenticationRequirement: "singleFactorAuthentication",
      ConditionalAccessStatus: "notApplied",
      RiskLevelDuringSignIn: "none",
      DeviceDetail: { deviceId: "", operatingSystem: "Android", browser: "", isCompliant: false },
      UserAgent: "Android-Mail/2024.10.20.0",
      IsInteractive: false,
      CorrelationId: "5d0e2b1c-7a44-4f1d-9c3e-2b8a6f0d1e93",
    }, null, 2),
  }],
  steps: [
    {
      kind: "fields", id: "read", xp: 35,
      prompt: "Answer from the record only.",
      artifactIds: ["row"],
      fields: [
        { id: "ok", label: "Did the sign-in succeed?", format: "choice", options: ["Yes", "No"], accept: ["No"], coach: "`ResultType` 0 is success; anything else is a failure code." },
        { id: "why", label: "Why did it fail?", format: "choice", options: ["Wrong username or password", "MFA was denied", "Blocked by Conditional Access", "Account locked", "Risky sign-in blocked"], accept: ["Wrong username or password"], coach: "Read `ResultDescription` beside the code." },
        { id: "mfa", label: "Would MFA have been asked for if the password were right?", format: "choice", options: ["Yes", "No"], accept: ["No"], coach: "`AuthenticationRequirement` says what the sign-in needed." },
        { id: "protocol", label: "Which client protocol was used? (ClientAppUsed)", format: "text", accept: ["Exchange ActiveSync", "ActiveSync", "EAS"], coach: "Find `ClientAppUsed`." },
        { id: "ca", label: "Did any Conditional Access policy apply?", format: "choice", options: ["Yes, it succeeded", "Yes, it failed", "No, none applied"], accept: ["No, none applied"], coach: "`ConditionalAccessStatus` of `notApplied` means no policy covered this sign-in." },
      ],
      hint: "Every answer is one field. Find the field before you answer.",
      where: "`ResultType` + `ResultDescription` (outcome), `AuthenticationRequirement` (MFA), `ClientAppUsed` (protocol), `ConditionalAccessStatus` (policy).",
      worked: "Failed (`50126`: wrong username or password). `singleFactorAuthentication`: no MFA would have been asked. `Exchange ActiveSync`, a legacy protocol, and `ConditionalAccessStatus: notApplied`: no policy covered it. A guessed password over a legacy protocol walks straight in. That is why the pilot policy \"Block legacy authentication\" matters.",
      debrief: "Legacy protocols (ActiveSync, SMTP AUTH, IMAP) cannot do MFA, and many Conditional Access policies do not cover them. A spray over a legacy protocol tests passwords with nothing else in the way.",
    },
  ],
};

export const CLEAR_SKY_M5: MissionTask = {
  type: "mission",
  id: "sentinel-m5",
  heading: "Call the Spray",
  mentor: MENTOR,
  story: "The row you just read was not alone. Malik wants the detection he will schedule tonight, tested on this week's data first: \"Catch every spray. Do not page me for the 08:00 shift change, when half the shops mistype their passwords and then get in.\"",
  objective: "Write the spray hunt, then make the call on what it found.",
  dataset: "clear-sky",
  steps: [
    {
      kind: "kql", id: "hunt", xp: 50,
      prompt: "Write the hunt: **source IPs that failed against 10 or more different accounts within one 30-minute window, with fewer than 3 successful sign-ins in that window.** Return the IPs.",
      focusTables: ["SigninLogs"],
      hint: "Group by the source AND by a 30-minute time bin, count different failed accounts and count successes, then keep the bins that look like spraying.",
      where: "`summarize Failed = dcountif(UserPrincipalName, ResultType == \"50126\"), Succeeded = countif(ResultType == \"0\") by IPAddress, bin(TimeGenerated, 30m)`, then `where Failed >= 10 and Succeeded < 3`.",
      answer: {
        reference: [
          "SigninLogs | summarize Failed = dcountif(UserPrincipalName, ResultType == \"50126\"), Succeeded = countif(ResultType == \"0\") by IPAddress, bin(TimeGenerated, 30m) | where Failed >= 10 and Succeeded < 3 | distinct IPAddress",
          "SigninLogs | summarize Failed = dcountif(UserPrincipalName, ResultType != \"0\"), Succeeded = countif(ResultType == \"0\") by IPAddress, bin(TimeGenerated, 30m) | where Failed >= 10 and Succeeded < 3 | distinct IPAddress",
        ],
        mode: "values", keys: ["IPAddress"],
        traps: [
          { ifQuery: "^(?![\\s\\S]*(countif|Succe|== \"0\"|==\"0\"))", say: "198.51.100.10 is the shops' own NAT at the 08:00 shift change: many people mistype, then the same people get in a minute later. A spray almost never succeeds. Count the successes too." },
          { ifQuery: "^(?![\\s\\S]*bin\\()", say: "Without a time bin you count failures over the whole week. The rule must see them close together: `bin(TimeGenerated, 30m)`." },
          { ifRowsFewerThan: 2, say: "You are missing a slow spray: one source that stays under ten accounts per few minutes, but not per half hour. Check that your window is 30 minutes." },
        ],
      },
      worked: "```\nSigninLogs\n| summarize Failed = dcountif(UserPrincipalName, ResultType == \"50126\"),\n            Succeeded = countif(ResultType == \"0\")\n    by IPAddress, bin(TimeGenerated, 30m)\n| where Failed >= 10 and Succeeded < 3\n| distinct IPAddress\n```\nTwo sprays: 203.0.113.77 (13 accounts in 13 minutes over ActiveSync, then one success) and 198.51.100.140 (12 accounts in 28 minutes over SMTP). The shop NAT 198.51.100.10 drops out because its mistypes are followed by successes.",
      debrief: "A spray is one source, many accounts, few successes, in a short window. Counting distinct accounts (`dcountif`) and successes (`countif`) per source per bin separates it from a busy NAT.",
    },
    {
      kind: "fields", id: "call", xp: 30,
      prompt: "Look at what the sprays got. **Make the call** for the incident you will open.",
      fields: [
        { id: "hit", label: "Which account signed in successfully from a spraying IP?", format: "account", accept: ["m.ferreira@ashgrove.example"], coach: "Filter the spray IPs for `ResultType == \"0\"`." },
        { id: "verdict", label: "Classification", format: "choice", options: ["True positive", "Benign true positive", "False positive"], accept: ["True positive"], coach: "A real attacker, a real guessed password: is that benign?" },
        { id: "first", label: "First containment action", format: "choice", options: ["Revoke the account's sessions and reset its password", "Block 203.0.113.77 at the firewall and close the incident", "Ask the user whether they were travelling", "Disable MFA registration for the account"], accept: ["Revoke the account's sessions and reset its password"], coach: "Blocking one IP leaves the stolen password working from any other address." },
      ],
      hint: "Add `| where IPAddress in (...) and ResultType == \"0\"` to see what succeeded.",
      where: "`SigninLogs | where IPAddress in (\"203.0.113.77\", \"198.51.100.140\") and ResultType == \"0\" | project TimeGenerated, UserPrincipalName, ClientAppUsed`.",
      worked: "m.ferreira@ashgrove.example signed in from 203.0.113.77 over Exchange ActiveSync right after the spray: **true positive**, a compromised account. Revoke its sessions and reset its password first (the password works from any IP), then block legacy authentication, then check m.ferreira's mailbox for rules like d.okafor's.",
      debrief: "Containment follows the credential, not the address: an attacker with a working password just changes IP. Legacy authentication is why the spray could use it without MFA.",
    },
  ],
};

export const CLEAR_SKY_MISSIONS = [CLEAR_SKY_M1, CLEAR_SKY_M2, CLEAR_SKY_M3, CLEAR_SKY_M4, CLEAR_SKY_M5];
