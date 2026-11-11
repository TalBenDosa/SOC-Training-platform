/**
 * Room 36 "Operation Clear Sky" (sentinel-fundamentals): Ashgrove Pharmacy moved
 * to Microsoft Sentinel last month; Malik Haddad wants analysts who know the
 * console, write the query themselves and work an incident end to end. Six
 * missions on one workspace (dataset "clear-sky", src/lib/missions/datasets/clearSky.ts)
 * and its investigation console (console "clear-sky", src/lib/missions/consoles/clearSky.ts):
 *
 *   m0 find your way around the console   (console x4: queue, detections, hunts, entity)
 *   m1 three tickets, three tables        (kql x3)
 *   m2 the travel rule                    (kql, then read the result)
 *   m3 incident 4412, worked in the console (console: take it, read the evidence; kql pivot;
 *                                          facts; console: bookmark and comment)
 *   m4 read the raw row                   (fields on a SigninLogs record)
 *   m5 boss: call the spray               (kql hunt, the call, console: close 4416, work 4415)
 *
 * Every KQL step is graded by its RESULT on the visible and a shadow workspace; a
 * console step by the facts typed and by the incidents' state as the learner left it.
 * The console is our own design (XDR); each console step's debrief names the page
 * Microsoft Sentinel uses for the same job.
 */
import type { MissionTask } from "../types";

const MENTOR = "Malik Haddad, Sentinel Architect";
const CONSOLE = "clear-sky";

const CLASSIFICATIONS = [
  "True Positive - suspicious activity",
  "Benign Positive - suspicious but expected",
  "False Positive - incorrect alert logic",
  "False Positive - incorrect data",
  "Undetermined",
];
const RULE_NAMES = [
  "Sign-in from a country never seen for the user",
  "Inbox rule forwards mail outside the company",
  "Bulk file download from SharePoint",
  "Password spray: one address, many accounts",
  "Consent to an application not seen before",
];

// ─── M0. Find your way around the console ────────────────────────────────────

export const CLEAR_SKY_M0: MissionTask = {
  type: "mission",
  id: "sentinel-m0",
  heading: "Find Your Way Around the Console",
  mentor: MENTOR,
  story: "Nobody at Ashgrove writes a query on their first night. Malik walks each new analyst through the workspace the way it is used on shift: \"Sentinel is not a query box. It is a queue of incidents, the detections that fill it, hunts for what they miss, and a page for every account and address. Learn where each thing lives.\" The practice console is our own build with its own page names; each step says what Microsoft Sentinel calls the same page.",
  objective: "Read the queue, the detection behind two incidents, a hunt and an entity page, and answer from what you see.",
  dataset: "clear-sky",
  console: CONSOLE,
  steps: [
    {
      kind: "console", id: "queue", xp: 15,
      open: { screen: "incidents" },
      prompt: "**Start of shift: read the queue.** What is waiting, what goes first, and what did the last shift already close?",
      todo: [
        "Open **Incidents**. Read the tiles and the grid: severity, status, owner.",
        "The grid shows the last 24 hours and hides closed incidents. Widen the **time range** to the last 7 days and the **Status** filter to include Closed.",
        "Open incident **4409**, which the last shift closed.",
        "Read how it was closed: the classification and the closing comment.",
      ],
      fields: [
        { id: "open", label: "How many incidents are open (New or Active)?", format: "int", accept: ["4"], coach: "Count the incidents whose status is New or Active, not the closed one. The tiles above the grid count them too." },
        {
          id: "first", label: "Which open incident do you open first?", format: "choice",
          options: ["4412: Sign-in from a rare country, forwarding rule and bulk download", "4415: Password spray against many accounts from one address", "4416: Password spray against many accounts from one address", "4410: Consent to an application not seen before"],
          accept: ["4412: Sign-in from a rare country, forwarding rule and bulk download"],
          coach: "Severity sets the order of the queue. Which open incident is the only High one?",
          traps: [{ value: "4415: Password spray against many accounts from one address", say: "4415 is older, and it is Medium. The queue is worked by severity first, then age: the one High incident goes first." }],
        },
        { id: "closedAs", label: "How was 4409 classified when it was closed?", format: "choice", options: CLASSIFICATIONS, accept: ["Benign Positive - suspicious but expected"], coach: "Open 4409 itself: its status shows the closing classification, and the closing comment says why." },
      ],
      hint: "Everything here is on the Incidents page and on the incident's own page. No query needed.",
      where: "The tiles count the open incidents. Set the time range to the last 7 days and add Closed to the Status filter: 4412 is the only High, and 4409 is Closed. Open it and read its status and closing comment.",
      worked: "Open: **4** (4412, 4415, 4416, 4410). First: **4412**, the only High, with three detections on one account. 4409 was closed as **Benign Positive - suspicious but expected**: a business trip, the same compliant laptop and MFA on every sign-in.",
      debrief: "In Microsoft Sentinel this is the **Incidents** page: the same grid of severity, status and owner, and the same closing classifications. A closed incident still teaches: the last analyst's comment says why a rare-country sign-in was fine, and you will meet that detection again tonight.",
    },
    {
      kind: "console", id: "detections", xp: 15,
      open: { screen: "incidents" },
      prompt: "**Find the detection behind 4415 and 4416.** Two incidents, one rule. Read what the rule really checks.",
      todo: [
        "Open **4415** or **4416** (4415 is two days old: widen the time range) and read which detection raised its alert.",
        "Open **Detections**, select that rule and read how often it runs, how far back it looks, and its query.",
      ],
      fields: [
        { id: "rule", label: "Which detection raised both incidents?", format: "choice", options: RULE_NAMES, accept: ["Password spray: one address, many accounts"], coach: "Open one of the two incidents: each alert names the detection that raised it." },
        { id: "freq", label: "How often does that detection run?", format: "choice", options: ["Every 5 minutes", "Every 15 minutes", "Every hour", "Every day"], accept: ["Every hour"], coach: "Select the rule on the Detections page: \"Runs every\" is in its details." },
        { id: "threshold", label: "How many different accounts must fail from one address before it fires?", format: "int", accept: ["13"], coach: "Read the rule's query in its details: the last `where` line holds the threshold." },
      ],
      hint: "The alert names its rule. The Detections page lists every rule; select one to read its details and query.",
      where: "Detections > *Password spray: one address, many accounts*: runs every 1 hour, looks back over 1 hour, and its query ends with `where Accounts >= 13`.",
      worked: "Both incidents come from **Password spray: one address, many accounts**. It runs **every hour** over the last hour and fires at **13** or more failed accounts from one address.",
      debrief: "In Microsoft Sentinel these are **Analytics** rules, Scheduled ones here. Keep the threshold in mind: tonight you will see what a fixed count of 13 catches, what it pages on by mistake, and what it misses.",
    },
    {
      kind: "console", id: "hunt", xp: 15,
      open: { screen: "hunting" },
      prompt: "**Run a hunt.** A detection waits for its threshold. A hunt is a question you ask on purpose, when nothing has fired.",
      todo: [
        "Open **Hunts** and run *Sign-ins over legacy authentication*.",
        "Read the results: protocol, address, attempts, accounts and successes.",
      ],
      fields: [
        { id: "protocols", label: "Which legacy protocols appear? (comma-separated)", format: "set", item: "text", accept: ["Exchange ActiveSync", "Authenticated SMTP"], coach: "Read the `ClientAppUsed` column of the hunt's result: one row per address and protocol." },
        { id: "smtp", label: "How many sign-in attempts came over Authenticated SMTP?", format: "int", accept: ["12"], coach: "The `Attempts` column of the Authenticated SMTP row." },
        { id: "success", label: "Which address got a successful sign-in over a legacy protocol?", format: "ip", accept: ["203.0.113.77"], coach: "The `Successes` column: only one row has more than zero." },
      ],
      hint: "A hunt is a saved query. Running it shows its results like any query you write.",
      where: "Hunts > *Sign-ins over legacy authentication* > Run. One row per address and protocol: read `ClientAppUsed`, `Attempts` and `Successes`.",
      worked: "Two rows: **Exchange ActiveSync** from **203.0.113.77** (14 attempts, 14 accounts, 1 success) and **Authenticated SMTP** from 198.51.100.140 (**12** attempts, 12 accounts, no success).",
      debrief: "Microsoft Sentinel calls this page **Hunting**. Look again at the second row: 12 accounts from one address is a spray too, one account under the detection's threshold of 13, so no incident exists for it. Hunts find what thresholds miss.",
    },
    {
      kind: "console", id: "entity", xp: 15,
      open: { screen: "entity" },
      prompt: "**Look up an entity.** Incident 4410 says f.lindqvist consented to an application. Before you judge it, look at the account itself.",
      todo: [
        "Open **Entities** and find **f.lindqvist@ashgrove.example** (or open it from incident 4410).",
        "Read its insights: where it signs in from, and which alerts name it.",
      ],
      fields: [
        { id: "app", label: "Which application did the account consent to?", format: "text", accept: ["Rota Planner"], coach: "Incident 4410 names the application among its entities." },
        {
          id: "spray", label: "Which address failed to sign in to this account and never got in?", format: "ip", accept: ["203.0.113.77"],
          coach: "Read the account's sign-in activity: one address only failed, from another country.",
          traps: [{ value: "198.51.100.10", say: "198.51.100.10 is the shops' NAT. She mistyped there at 08:00 and signed in from the same address a minute later. Which address failed and never got in?" }],
        },
      ],
      hint: "An entity page runs a few saved queries about that one account: sign-ins by address, actions, alerts that name it.",
      where: "Entities > f.lindqvist@ashgrove.example > *Sign-in activity*: one row per address. The RU address has only failures. The application is on incident 4410's entities.",
      worked: "She consented to **Rota Planner**, and **203.0.113.77** (RU, Exchange ActiveSync) failed against her account in the spray. 198.51.100.10 is the shops' NAT, where she mistyped at 08:00 and got in a minute later.",
      debrief: "Microsoft Sentinel calls these **entity pages** (Entity behavior). One page put two stories side by side: a consent nobody approved, and a spray that tried her password. Neither proves the other, but before you close 4410 you now know to check where the consent came from.",
    },
  ],
};

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
  heading: "Incident 4412: Work It in the Console",
  mentor: MENTOR,
  story: "Incident 4412 fired last night: three detections on one account inside fifteen minutes, joined into one incident. Malik: \"Work it the way the job goes. Take it, read the evidence behind every alert, pivot on the address, and write what you found on the incident itself. The next shift reads the incident, not your screen.\"",
  objective: "Take incident 4412, read its alerts and the rows behind them, pivot on the IP with your own query, and record the finding on the incident.",
  dataset: "clear-sky",
  console: CONSOLE,
  steps: [
    {
      kind: "console", id: "take", xp: 15,
      open: { screen: "incidents" },
      prompt: "**Take the incident.** Before you read an alert, the incident gets an owner and a status, so nobody else starts on the same work.",
      todo: [
        "Open **4412** from the queue.",
        "Set **Owner** to yourself (Assign to me) and **Status** to Active.",
        "Read its summary: the alerts, the entities and the tactics.",
      ],
      fields: [
        { id: "alerts", label: "How many alerts does 4412 hold?", format: "int", accept: ["3"], coach: "The incident's summary lists its alerts, one per detection that fired." },
        { id: "ip", label: "Which IP address does the incident name as an entity?", format: "ip", accept: ["198.51.100.23"], coach: "Read the incident's entities: an account, a mailbox, a cloud app and one address." },
      ],
      expect: [{ incidentId: "inc-4412", ownerIsMe: true, status: "Active" }],
      hint: "Owner and Status sit at the top of the incident's page; the queue can change them too.",
      where: "Open 4412: Owner > Assign to me, Status > Active. The summary shows 3 alerts and the entities, among them 198.51.100.23.",
      worked: "Owner: you. Status: **Active**. The incident holds **3** alerts (rare country, forwarding rule, bulk download) and names **198.51.100.23**.",
      debrief: "In Microsoft Sentinel you do this at the top of the incident page or from the Incidents grid: Owner, Status, Severity. An incident that stays New and unassigned looks untouched to everyone else on shift, even while you work it.",
    },
    {
      kind: "console", id: "evidence", xp: 25,
      open: { incidentId: "inc-4412" },
      prompt: "**Read the evidence behind each alert.** An alert is a claim; the rows behind it are the evidence. Open each alert's events.",
      todo: [
        "On 4412, open each alert and use **Open in Query** to see the rows behind it.",
        "Read the successful sign-in, the inbox rule's `Parameters` and the downloads.",
      ],
      fields: [
        { id: "when", label: "When (UTC) did the sign-in from that IP succeed?", format: "utc", placeholder: "2026-11-08 23:41", accept: ["2026-11-08 23:41"], tolerance: 1, coach: "Open the rare-country alert's rows: the one with `ResultType` 0." },
        { id: "forward", label: "Where does the new inbox rule send the mail?", format: "email", accept: ["rx.archive@mailbox-relay.example"], coach: "Open the inbox-rule alert's rows and read `Parameters`: the `ForwardTo` value." },
        { id: "files", label: "How many files were downloaded from SharePoint from that IP?", format: "int", accept: ["9"], coach: "Open the bulk-download alert's rows and count them." },
      ],
      hint: "Each alert's menu opens its query in Query, scoped to that alert's rows.",
      where: "4412 > each alert > Open in Query. Sign-in: `ResultType` 0 at 23:41:07. Inbox rule: `Parameters` holds `ForwardTo`. Downloads: one row per file.",
      worked: "Signed in at **23:41** UTC on 8 November, single factor. The rule `.` forwards mail about invoices, payments and prescriptions to **rx.archive@mailbox-relay.example**, marks it read and moves it out of sight. **9** files downloaded between 23:47 and 23:55.",
      debrief: "Three detections, one story: a password works from Nigeria at 23:41, a hiding rule at 23:44, files leave at 23:47. In Microsoft Sentinel the same move is the alert's events (or the incident's Evidence) opening in Logs. Read the rows before you trust the alert's title.",
    },
    {
      kind: "kql", id: "pivot", xp: 40,
      prompt: "Write the pivot: **every account that 198.51.100.23 tried to sign in to, with the result code of each.** One row per account and result.",
      focusTables: ["SigninLogs"],
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
    {
      kind: "console", id: "record", xp: 25,
      open: { incidentId: "inc-4412" },
      prompt: "**Record it on the incident.** Save the rows that prove it, and say in one comment what it means.",
      todo: [
        "In **Query** (from the incident, or the Query page), run your pivot, select the rows from 198.51.100.23 and **Add bookmark** to incident 4412.",
        "Add a **comment** on 4412: the account that was taken, how it signed in, where its mail now goes, and how many accounts the IP tried.",
      ],
      expect: [{
        incidentId: "inc-4412", ownerIsMe: true, status: "Active",
        bookmark: { values: [{ value: "198.51.100.23", label: "the IP" }, { value: "d.okafor@ashgrove.example", label: "the account it got into" }] },
        comment: {
          checks: [
            { label: "which account was taken", anyOf: ["d.okafor"] },
            { label: "that the sign-in had no MFA (single factor)", anyOf: ["single factor", "single-factor", "singlefactor", "no mfa", "without mfa", "mfa was not", "not mfa", "no multi-factor", "without multi-factor"] },
            { label: "where the inbox rule sends the mail", anyOf: ["rx.archive", "mailbox-relay"] },
            { label: "how many accounts the IP tried", anyOf: ["re:\\b(4|four)\\b[^.\\n]{0,30}account", "re:account[^.\\n]{0,40}\\b(4|four)\\b"] },
          ],
        },
      }],
      solution: {
        values: {},
        console: {
          "inc-4412": {
            status: "Active", owner: "You", ownerIsMe: true, severity: "High", comments: ["198.51.100.23 tried 4 accounts and got into d.okafor@ashgrove.example with single factor auth. The inbox rule forwards mail to rx.archive@mailbox-relay.example."],
            bookmarks: [{ name: "Pivot on 198.51.100.23", notes: "", columns: ["UserPrincipalName", "IPAddress", "ResultType"], rows: [{ UserPrincipalName: "d.okafor@ashgrove.example", IPAddress: "198.51.100.23", ResultType: "0" }] }],
          },
        },
      },
      hint: "Select rows in a query's results to bookmark them; from the incident, the bookmark attaches to it. Comments are on the incident page.",
      where: "4412 > an alert > Open in Query (or Query): run the pivot, tick the rows from 198.51.100.23, Add bookmark. Then 4412 > Comments: write the four facts.",
      worked: "Bookmark: the pivot's rows from 198.51.100.23, among them d.okafor's success. Comment, for example: \"198.51.100.23 (NG, python-requests) tried 4 accounts; it got into d.okafor@ashgrove.example at 23:41 with single factor auth. An inbox rule forwards invoice and payment mail to rx.archive@mailbox-relay.example. 9 SharePoint files downloaded. Next: revoke sessions, reset password, remove the rule.\"",
      debrief: "A bookmark keeps the exact rows, with the query that found them, inside the incident's evidence; a comment says what they mean. In Microsoft Sentinel both live on the incident (bookmarks from Logs or Hunting, comments in its activity log), and both are what the next analyst and the incident report are built from.",
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
  console: CONSOLE,
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
    {
      kind: "console", id: "queue", xp: 40,
      open: { screen: "incidents" },
      prompt: "**Put the queue right.** Your hunt and the detection disagree: one incident is noise, one is real and half-told, and one spray never became an incident at all.",
      todo: [
        "**4416** (the shops' NAT at 08:00): close it with the right classification and a closing comment that says why.",
        "**4415** (203.0.113.77, two days old: widen the time range): take it and set it Active (containment is not done yet). Comment the account the spray got into and the second spraying address the detection missed.",
      ],
      expect: [
        {
          incidentId: "inc-4416", status: "Closed",
          classification: {
            accept: ["False Positive - incorrect alert logic", "Benign Positive - suspicious but expected"],
            coach: "Was there an attacker on 198.51.100.10? Pick the classification that says what went wrong: the activity, or the rule.",
            say: {
              "True Positive - suspicious activity": "4416 has no attacker in it: thirteen staff behind the shops' NAT mistyped at the 08:00 shift change and signed in a minute later. A True Positive needs real malicious activity.",
              "False Positive - incorrect data": "The data is right: those failures really happened. What is wrong is the rule's logic, which counts failures and ignores that the same people got in a minute later.",
              "Undetermined": "You can determine it: every failed account on 198.51.100.10 signs in successfully from the same address within a minute. Close it with what that shows.",
            },
          },
          closingComment: {
            checks: [
              { label: "that it is the shops' NAT or the shift change", anyOf: ["nat", "shift", "08:00", "8:00", "shop"] },
              { label: "that the same people signed in successfully right after", anyOf: ["success", "signed in", "logged in", "got in", "same users", "same people", "same staff", "same accounts"] },
            ],
          },
        },
        {
          incidentId: "inc-4415", ownerIsMe: true, status: "Active",
          comment: {
            checks: [
              { label: "the account the spray got into", anyOf: ["m.ferreira"] },
              { label: "the second spraying address the detection missed", anyOf: ["198.51.100.140"] },
            ],
          },
        },
      ],
      hint: "A close needs a classification and a comment; Status > Closed asks for both. 4415 stays open: the account is not contained yet.",
      where: "4416 > Status > Closed > *False Positive - incorrect alert logic*, with a comment on the NAT and the successes. 4415 > Assign to me, Active, and a comment naming m.ferreira@ashgrove.example and 198.51.100.140.",
      worked: "4416 closed as **False Positive - incorrect alert logic** (Benign Positive is accepted too): \"Shops' NAT 198.51.100.10 at the 08:00 shift change: 13 staff mistyped and signed in successfully within a minute. The rule counts failures only.\" 4415 yours and **Active**, with a comment: \"Spray got into m.ferreira@ashgrove.example over Exchange ActiveSync at 03:24. A second spray from 198.51.100.140 (Authenticated SMTP, 12 accounts) stayed under the threshold of 13: no incident. Revoke sessions and reset m.ferreira, block legacy auth, tune the rule.\"",
      debrief: "Classifications are data: they tune the detection. A False Positive for *incorrect alert logic* tells Malik the spray rule needs your hunt's logic (accounts AND successes per half hour), not a higher threshold. A true positive stays open until the account is contained, and the spray that never became an incident is now written on the one that did.",
    },
  ],
};

export const CLEAR_SKY_MISSIONS = [CLEAR_SKY_M0, CLEAR_SKY_M1, CLEAR_SKY_M2, CLEAR_SKY_M3, CLEAR_SKY_M4, CLEAR_SKY_M5];
