import type { RoomExperience } from "./types";

// "Operation Master Key" for the "privileged-access-monitoring" room.
// Script: docs/campaign/95-privileged-access-monitoring.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Ironbridge Trust Bank (fictional). The graded tasks use corp.ironbridge.example and DB-PROD-01 records; the labs use other hosts and accounts.
// Signature mechanic: Who Used the Key? Vault check-outs set against what the account then did.
// A KQL hunt joins privileged logons to their 4624 and to PAM session records, and finds an admin
// session with no check-out behind it. A tune decides which privileged events page someone.
// Game mix: defuse + hunt + tune.
//
// Task order changed. Was: r1, r1b, r2, r3, q1, q2, q3, la1, ac1, flag1, r4, la2, flag2.
// Now: r1, r2, q3 | r3, q1, q2 | r4, la2, flag2 | r1b, la1, flag1, ac1.
// q3 sits with the PAM reading, r4 sits with its log and flag, flag1 follows la1 directly (it is
// pinned by logTask anyway), and ac1 closes the room as the boss. r1b moves behind r3 because its
// text looks back at priv-r2 and priv-r3 Step 6 as already read. No flag says "Log Analysis N".
//
// The hunt engine only has an inner join. The two leftanti lines and the leftsemi line state the
// real KQL and apply as a where on SubjectLogonId, with the list worked out from PamSessions_CL,
// so the grid shows exactly what the join would return for these rows.
//
// Lab data differs from the graded tasks. The token and the check-out are adm-win03 on ITB-FS02,
// and the privilege list has no SeTcbPrivilege (r1 checkpoint, la1). The LSASS record is a 0x1010
// handle from rptcollect.exe, never PowerShell with 0x1FFFFF (q1). Group changes use other groups,
// with Domain Admins only named as a global group in a primer, and no lab pairs 4720 with a group
// event (q2). The vault appears as one record, with no question about its purpose (q3). The SQL
// record is a refused rpt_reader call with a low role, never the role in the graded event
// (la2, flag2). Parents are w3wp, spoolsv, tomcat, CcmExec, explorer and the task scheduler, never
// the database engine (la2). The offline gap is a KeePass file, never a Kerberos ticket pair (la2).
// Permitted against authorised is a firewall, gateway and file server queue from last quarter,
// never a database, a customer table or a large query (ac1, r1b checkpoint). Logon IDs and the
// hosts around them are new values (flag1).

export const PRIVILEGED_ACCESS_MONITORING: RoomExperience = {
  roomId: "privileged-access-monitoring",
  codename: "Operation Master Key",
  theme: "masterkey",
  handler: { name: "Wanjiru Castellan", role: "PAM Security Lead, Ironbridge Trust Bank" },
  briefing: [
    "Ironbridge Trust Bank. One core ledger, and a vault that signs out every administrator password in the building.",
    "Quarter-end closes on Friday, and the regulator's auditor wants one thing: for every admin session on the ledger, the check-out that allowed it.",
    "Last night a sensor on a reporting server recorded something unusual, and Wanjiru Castellan, PAM Security Lead, no longer trusts the count.",
    "Learn what each key opens and how one gets stolen, then set the vault against the logons and find out who used the key.",
  ],
  mission: "Learn what each privileged account opens, read a token, a check-out and the records a session leaves, follow an intruder's climb, follow a key that never went near the vault, then find the admin session with nothing behind it, decide what pages someone, and make the final call.",
  estimate: "~60 min",
  look: { primary: "#cfa64b", secondary: "#7fb7be", warn: "#ff5a5f" },
  scene: "facilitymasterkey",
  layout: "facility",
  stations: [
    {
      id: "vault",
      label: "The Vault",
      topic: "Domain, machine and service accounts · privilege rights · key Windows events · PAM vaults",
      tagline: "Every key signed out",
      building: "vault",
      taskIds: ["priv-r1", "priv-r2", "priv-q3"],
    },
    {
      id: "climb",
      label: "The Climb",
      topic: "The privilege escalation kill chain · LSASS access · persistence",
      tagline: "From one login to every door",
      building: "lab",
      taskIds: ["priv-r3", "priv-q1", "priv-q2"],
    },
    {
      id: "unvaulted",
      label: "The Unvaulted Key",
      topic: "Service accounts reaching SQL Server · xp_cmdshell · parent and child processes · offline gaps",
      tagline: "Not every key lives in the vault",
      building: "factory",
      taskIds: ["priv-r4", "priv-la2", "priv-flag2"],
    },
    {
      id: "whokey",
      label: "Who Used the Key?",
      topic: "Permitted and authorised · reconciling check-outs against logons · what earns a page · the verdict",
      tagline: "The vault said yes. Did anyone else?",
      building: "control",
      taskIds: ["priv-r1b", "priv-la1", "priv-flag1", "priv-ac1"],
      boss: true,
    },
  ],
  personas: {
    "priv-q3": { name: "Wanjiru Castellan", role: "PAM Security Lead", line: "The auditor always opens with this one. What is the vault actually for?" },
    "priv-q1": { name: "Wanjiru Castellan", role: "PAM Security Lead", line: "One record, one handle. Tell me what you're looking at." },
    "priv-q2": { name: "Wanjiru Castellan", role: "PAM Security Lead", line: "I want this step caught by a rule, not by luck." },
    "priv-la2": { name: "Wanjiru Castellan", role: "PAM Security Lead", line: "This file came over from a peer bank's team. Read the record before the alert title." },
    "priv-flag2": { name: "Wanjiru Castellan", role: "PAM Security Lead", line: "Give me the exact word from the evidence." },
    "priv-la1": { name: "Wanjiru Castellan", role: "PAM Security Lead", line: "Another peer bank's file. Read the event field by field." },
    "priv-flag1": { name: "Wanjiru Castellan", role: "PAM Security Lead", line: "Give me the value I search on." },
    "priv-ac1": { name: "Wanjiru Castellan", role: "PAM Security Lead", line: "Your call, and you'll be the one explaining it to the auditor." },
  },
  briefings: {
    // ── Reading 1: what the keys are ──
    "priv-r1": [
      {
        kind: "locks",
        title: "Five Doors: How Far Each Kind of Account Reaches",
        prompt: "Wednesday morning at Ironbridge. Before Wanjiru lets you near the vault, you walk its doors. Each door is one kind of privileged account: read what it opens, then answer its check.",
        finish: "Reach is what makes a key dangerous. Privilege use should be rare, predictable and from expected sources: an admin's usual weekday logon is normal, and the same account at 03:00 from a new machine is worth a question.",
        locks: [
          {
            id: "domain", letter: "1", name: "Domain Admins",
            idea: "The highest human-operated group. Members can manage every object in Active Directory, log on to every domain-joined machine and reset any password, including other admins'.",
            example: "adm-win03 is one of Ironbridge's Domain Admins accounts. It lives in the vault and nobody knows its password.",
            check: {
              q: "adm-win03 has never signed in to ITB-HR03. What can it do there?",
              options: ["Nothing, until a local administrator grants it access", "Log on and manage it, because the group reaches every domain-joined machine", "Read files only, because it does not own the server"],
              answer: 1, why: "Domain Admins reaches every domain-joined machine, whether or not the account has been there before.",
            },
          },
          {
            id: "enterprise", letter: "2", name: "Enterprise Admins",
            idea: "Exists only in the forest root domain and has full control over every domain in that forest. No built-in group controls more than one forest.",
            example: "Ironbridge runs three domains in one forest. A savings bank it bought last year still runs its own separate forest.",
            check: {
              q: "What does Ironbridge's Enterprise Admins group cover?",
              options: ["Only the root domain it sits in", "Both forests, since the two banks merged", "All three domains in Ironbridge's forest, and nothing in the other forest"],
              answer: 2, why: "A forest is the outer limit. Control of the second forest needs its own admins or a trust, and no built-in group crosses that line.",
            },
          },
          {
            id: "schema", letter: "3", name: "Schema Admins",
            idea: "Can change the Active Directory schema, the definitions of every object type. It should sit empty except during a deliberate schema extension.",
            example: "Ironbridge's change calendar shows no schema work this year.",
            check: {
              q: "On a quiet Tuesday, Schema Admins shows one member. What do you do?",
              options: ["Find out who it is and why, because this group should be empty right now", "Nothing, because it is a built-in group", "Remove the group from Active Directory"],
              answer: 0, why: "An empty group makes any member a finding. The next question is who was added, when, and by whom.",
            },
          },
          {
            id: "local", letter: "4", name: "Local Administrators",
            idea: "Admin rights on one machine, not the whole domain. They still matter for lateral movement: Pass-the-Hash logs on with a stolen password hash, so a shared password travels.",
            example: "All 300 branch PCs were built from one image with one local Administrator password.",
            check: {
              q: "One branch PC falls. Why worry about the other 299?",
              options: ["Local admin on one PC grants Domain Admins", "That password's hash works on every machine that shares it", "The PC can now change the Active Directory schema"],
              answer: 1, why: "The hash is all Pass-the-Hash needs, and the same password means the same hash on every PC.",
            },
          },
          {
            id: "service", letter: "5", name: "Service Accounts",
            idea: "Non-human accounts that run background services such as monitoring agents and database engines. They often hold elevated rights, and they are not supposed to be used interactively by people.",
            example: "svc-monitor runs the monitoring agent on every server at Ironbridge.",
            check: {
              q: "svc-monitor shows an interactive logon at a server console. What stands out?",
              options: ["Nothing: it has rights on that server", "The agent must have been upgraded", "Someone is signing in with an account meant only to run a service"],
              answer: 2, why: "The account has the right, so Windows lets it through. The way it was used is what stands out.",
            },
          },
        ],
      },
      {
        kind: "inspect",
        title: "Read the Rights in One Admin Token",
        prompt: "Groups say what an account may manage. Below that sit privilege rights, which say what a process under the token may do. Windows wrote this list into Event 4672 when adm-win03 logged on to ITB-FS02. Open each line.",
        artifact: "Event 4672 · PrivilegeList · adm-win03 on ITB-FS02",
        items: [
          { id: "sec", text: "SeSecurityPrivilege", tag: "Audit log", tone: "info", note: "Manage auditing settings and read the Security log." },
          { id: "own", text: "SeTakeOwnershipPrivilege", tag: "Ownership", tone: "info", note: "Take ownership of any file or object, whatever its permissions say." },
          { id: "drv", text: "SeLoadDriverPrivilege", tag: "Kernel", tone: "info", note: "Load a device driver, which runs in the kernel." },
          { id: "bak", text: "SeBackupPrivilege", tag: "Read anything", tone: "info", note: "Read any file regardless of its permissions. Built for backup software. On a domain controller that includes NTDS.DIT, the Active Directory database with every password hash." },
          { id: "res", text: "SeRestorePrivilege", tag: "Write anything", tone: "info", note: "Write any file regardless of its permissions." },
          { id: "dbg", text: "SeDebugPrivilege", tag: "Process memory", tone: "info", note: "Read and write the memory of any other process, LSASS included. LSASS (Local Security Authority Subsystem Service) is the Windows process holding credential hashes. Usual holders: SYSTEM and local administrators." },
          { id: "imp", text: "SeImpersonatePrivilege", tag: "Acting as", tone: "info", note: "Act under another account's identity after that account connects." },
        ],
      },
    ],
    // ── Reading 2: the records and the vault ──
    "priv-r2": [
      {
        kind: "anatomy",
        title: "Read One Vault Check-Out",
        prompt: "This is the PAM (Privileged Access Management) vault at work. adm-win03 is a shared account, and a person can only reach it through a check-out. Wanjiru hands you one ordinary record from Tuesday. Read it field by field.",
        source: "PAM vault · PamSessions_CL · REQ-48815",
        fields: [
          { key: "CheckoutTime", value: "2026-10-27T09:58:04Z", label: "When" },
          { key: "Requester", value: "i.brandt", label: "Who", note: "The person asking. adm-win03 is shared, so this is the only field in any log that names a human." },
          { key: "TargetAccount", value: "adm-win03", label: "Which key", note: "The managed account. Its password is held in the vault." },
          { key: "TargetHost", value: "ITB-FS02", label: "For where", note: "The one machine this check-out names." },
          { key: "Reason", value: "Share quota change", label: "Why", note: "Free text typed at check-out." },
          { key: "TicketId", value: "CHG-30422", note: "The change ticket cited at check-out. The ticket itself lives in the service desk." },
          { key: "GatewayHost", value: "ITB-GW01", note: "The session gateway. The session reaches the target from here, so the 4624 shows this host as its source." },
          { key: "PasswordShown", value: "false", note: "The gateway signs in for the requester. The password is never displayed or typed." },
          { key: "SessionRecorded", value: "true", note: "Keystrokes and commands from the session are kept for review." },
          { key: "CheckinTime", value: "2026-10-27T10:40:51Z" },
          { key: "RotatedOnCheckin", value: "true", note: "The vault set a new password when the account came back." },
        ],
        summary: "One person, one reason, one target, one recording, then a new password. Any attempt to use a managed account outside this path skips all of it, so monitoring watches the check-outs and watches for sessions that never came through them. A service account checking out a Domain Admin credential with no ticket is an immediate escalation.",
      },
      {
        kind: "sort",
        title: "Group Scope Picks the Event ID",
        prompt: "The auditor's pack lists this quarter's group changes. Windows writes a different event ID for each group scope, so a rule watching the wrong ID stays silent. Drop each change on the ID it would write.",
        buckets: [
          { id: "4728", label: "4728 · global group" },
          { id: "4732", label: "4732 · local group" },
          { id: "4756", label: "4756 · universal group" },
        ],
        items: [
          { id: "g1", text: "Protected Users gains a member", bucket: "4728", why: "Protected Users is a global group." },
          { id: "g2", text: "ITB-Treasury-Approvers, a global security group, gains a member", bucket: "4728", why: "The scope is in the description, and scope picks the ID." },
          { id: "g3", text: "Administrators on ITB-FS02 gains a member", bucket: "4732", why: "A group local to one server. The event lands in that server's own Security log." },
          { id: "g4", text: "Remote Desktop Users on ITB-RPT02 gains a member", bucket: "4732", why: "Another local group, and a route to an interactive session on that server." },
          { id: "g5", text: "DnsAdmins gains a member", bucket: "4732", why: "DnsAdmins is domain local, which writes the local group event." },
          { id: "g6", text: "Group Policy Creator Owners gains a member", bucket: "4728", why: "A built-in global group, and a useful one to an attacker: its members can create Group Policy objects." },
          { id: "g7", text: "ITB-Ledger-Readers, a universal security group, gains a member", bucket: "4756", why: "Universal scope writes 4756." },
          { id: "g8", text: "Schema Admins gains a member", bucket: "4756", why: "Schema Admins is universal, so a rule on 4728 alone would never see this." },
        ],
        primer: {
          title: "Three IDs, one question: what scope is the group?",
          fold: true,
          points: [
            "A membership change writes **4728** for a global group, **4732** for a local group and **4756** for a universal group.",
            "In these events `TargetUserName` is the group's name and `MemberSid` is who went in.",
            "Built-in scopes: Domain Admins and Domain Users are global. Enterprise Admins and Schema Admins are universal. Administrators is domain local.",
            "Adding to a top-tier group should have a change ticket behind it.",
          ],
          example: {
            label: "A worked read: one row from a domain controller",
            lines: [
              "`EventID: 4732`, `TargetUserName: Account Operators`, `MemberSid: S-1-5-21-...-2210`",
              "Account Operators is a built-in domain local group, so the ID fits the scope.",
              "Next, resolve the SID to a name and look for the ticket.",
            ],
          },
        },
      },
      {
        kind: "reactor",
        title: "Route Each Question to the Record That Answers It",
        prompt: "Wanjiru's audit questions keep coming. Each one has a single record that answers it. Route each question to the right record before the belt carries it away.",
        reactors: [
          { id: "r4672", label: "4672", sub: "Special logon. Written at logon, lists the token's rights." },
          { id: "r4673", label: "4673", sub: "Sensitive privilege use. Written per use, with its auditing on." },
          { id: "s10", label: "Sysmon 10", sub: "ProcessAccess. Which process opened which." },
          { id: "r7045", label: "7045", sub: "A service was installed. Written on the target." },
          { id: "r4720", label: "4720", sub: "A user account was created." },
        ],
        items: [
          { id: "i1", text: "Which rights did adm-win07 carry when its session began on ITB-PAYGW01?", reactor: "r4672", why: "The token's rights are listed once, at logon, in PrivilegeList." },
          { id: "i2", text: "A contractor's login appeared overnight. When was it made?", reactor: "r4720", why: "Account creation has its own event on the domain controller." },
          { id: "i3", text: "A remote admin tool ran on ITB-FS02 and left PSEXESVC behind.", reactor: "r7045", why: "PsExec installs a service on the target, and that writes 7045." },
          { id: "i4", text: "ITB-LEDGER01 audits privilege use. Which program called SeLoadDriverPrivilege at 14:02?", reactor: "r4673", why: "4673 names the process each time a sensitive right is called on, when that auditing is on." },
          { id: "i5", text: "A new tool on ITB-RPT02 read the ledger client's memory. Which record names the tool?", reactor: "s10", why: "SourceImage names the program that opened the handle." },
          { id: "i6", text: "Is a debug right in this token at all?", reactor: "r4672", why: "Whether a token carries a right is a logon-time fact." },
          { id: "i7", text: "Which program opened the ledger client's process at 11:02, and with what access?", reactor: "s10", why: "SourceImage, TargetImage and GrantedAccess answer all three parts." },
          { id: "i8", text: "A service with a random name appeared on a branch PC.", reactor: "r7045", why: "New services land in the System log as 7045, wherever they come from." },
          { id: "i9", text: "An onboarding script made three new accounts on Tuesday.", reactor: "r4720", why: "One 4720 per account, with who made it and who was made." },
        ],
        primer: {
          title: "Holding a right is not using it",
          fold: true,
          points: [
            "A token can carry a right for a whole session and never call on it.",
            "**4672** records what the token carries, at logon. It fires for anyone with admin-equivalent rights.",
            "**4673** fires each time a process calls on a sensitive right, so it is much noisier. Many sites leave Sensitive Privilege Use auditing off. Use of the backup and restore rights needs a further policy, off by default.",
            "**Sysmon Event 10 (ProcessAccess)** comes from Sysmon, not from the Windows audit policy. It records which process opened which, and with what access.",
          ],
          example: {
            label: "A worked read: one right, two records",
            lines: [
              "08:02, 4672: PrivilegeList includes `SeLoadDriverPrivilege`. The token holds it.",
              "08:40, 4673: `ProcessName` calls on `SeLoadDriverPrivilege`. Now it was used, and by what.",
            ],
          },
        },
      },
    ],
    // ── Reading 3: the climb ──
    "priv-r3": [
      {
        kind: "sequence",
        title: "Put One Intruder's Climb in Order",
        prompt: "Last spring's red team went from one branch login to the whole directory in 18 minutes. Their report's pages came loose on Wanjiru's desk. Put the six steps back in order, and read what each one left behind.",
        items: [
          { id: "s4", text: "Replay a stolen hash against a domain controller", note: "4624 on the DC, LogonType 3, NTLM, with the compromised workstation as source and the admin as TargetUserName." },
          { id: "s1", text: "Sign in over VPN with a phished password", note: "4624 from an external address. The token has no special rights." },
          { id: "s6", text: "Plant access that survives a password reset", note: "A new admin identity, or a golden ticket forged with the krbtgt hash." },
          { id: "s3", text: "Read credentials out of LSASS", note: "Sysmon Event 10 on LSASS, and an antivirus alert if nobody disabled it." },
          { id: "s2", text: "Become local admin on the workstation", note: "An unpatched flaw or a misconfigured SYSTEM service. 4672 on that host, and 4688 showing a child of the vulnerable service." },
          { id: "s5", text: "Ask a domain controller for every hash, as if it were another DC", note: "Event 4662 on the DC with the replication GUID, from a machine that is not a DC. Defender for Identity calls it DCSync." },
        ],
        order: ["s1", "s2", "s3", "s4", "s5", "s6"],
        doneNote: "Each step needs the one before it, and each writes something different. A skilled team can run all six in under 20 minutes, so the place to alert is the local admin or LSASS step, while the problem is still one workstation.",
        primer: {
          title: "Terms on the climb",
          fold: true,
          points: [
            "**LSASS** keeps hashes and Kerberos tickets for accounts with a session on that machine.",
            "**Pass-the-Hash** logs on with a stolen NTLM (NT LAN Manager) hash. The password is never cracked.",
            "**krbtgt** is the account whose key signs Kerberos tickets. A **golden ticket** is one forged with that key.",
          ],
          example: {
            label: "A worked read: a night at a freight depot",
            lines: [
              "Tailgate through the staff gate: a camera clip.",
              "Find the supervisor's office unlocked: a door sensor.",
              "Copy the master card from the desk: a drawer sensor.",
              "Open the strongroom: a badge record in the supervisor's name.",
              "Each step needs the last, and each leaves a different trace.",
            ],
          },
        },
      },
      {
        kind: "anatomy",
        title: "Read One LSASS Handle",
        prompt: "This is the record that started the week. Late Tuesday, a sensor on ITB-RPT02, the reporting server, wrote this. Read it field by field before anyone calls it anything.",
        source: "Sysmon · Event ID 10 · ProcessAccess · ITB-RPT02",
        fields: [
          { key: "UtcTime", value: "2026-10-27 23:31:08.412", label: "When" },
          { key: "SourceImage", value: "C:\\ProgramData\\RptTools\\rptcollect.exe", label: "Who asked", note: "The program that requested the handle." },
          { key: "SourceProcessId", value: "6044", note: "Pivot on this with the host to reach its process creation record." },
          { key: "SourceUser", value: "ITB\\svc-rpt", label: "As whom", note: "The account running that program." },
          { key: "TargetImage", value: "C:\\Windows\\System32\\lsass.exe", label: "What was opened", note: "The process that was opened." },
          { key: "GrantedAccess", value: "0x1010", label: "How much", note: "The rights on the handle. 0x1010 is limited query plus read memory. 0x1FFFFF would be every right on the process." },
          { key: "CallTrace", value: "C:\\Windows\\SYSTEM32\\ntdll.dll+9d4c4|C:\\Windows\\System32\\KERNELBASE.dll+2be1a|UNKNOWN(000001E2C4A10F3B)", note: "The code path that asked. UNKNOWN marks a frame in memory that no file on disk backs." },
        ],
        summary: "Read it left to right: who asked, what was opened, how much was granted. Opening LSASS with read rights is the step a credential thief has to take, because the hashes and tickets are in that memory, and a 4672 alone would never have shown it. The account behind this one, svc-rpt, is not in the vault. Wanjiru's next question is how it got here.",
        primer: {
          title: "What sits in LSASS, and how a record shows it being opened",
          fold: true,
          points: [
            "How much LSASS holds depends on the machine: one user on a laptop, its administrators on a server, the whole domain's accounts on a domain controller.",
            "To read a process, a program first opens a **handle** to it. **GrantedAccess** is that handle's rights as a hex mask.",
            "Reading a mask: `0x10` is the read-memory bit, `0x1000` is limited query.",
            "A short list of known programs opens LSASS in normal work, so read the source of the handle first.",
          ],
          example: {
            label: "A worked read: a handle on a browser",
            lines: [
              "`SourceImage`: `C:\\Tools\\memsnap.exe`",
              "`TargetImage`: `C:\\Program Files\\Browser\\browser.exe`",
              "`GrantedAccess`: `0x1410`",
              "memsnap asked, the browser was opened, and the mask holds the read-memory bit.",
            ],
          },
        },
      },
    ],
    // ── Reading 4: the key that was never vaulted ──
    "priv-r4": [
      {
        kind: "anatomy",
        title: "Read One Refused xp_cmdshell Call",
        prompt: "svc-rpt never went near the vault, and neither did the SQL login beside it. Six days before that LSASS handle, somebody tried to run a Windows command from inside SQL Server on ITB-RPT02, and the server said no. Read the audit record.",
        source: "SQL Server Audit · ITB-RPT02 · via SIEM",
        fields: [
          { key: "event_time", value: "2026-10-21T01:47:13Z", label: "When" },
          { key: "action_id", value: "EX", note: "EXECUTE on a stored procedure." },
          { key: "succeeded", value: "false", label: "Outcome" },
          { key: "server_principal_name", value: "rpt_reader", label: "Who", note: "The SQL login that made the call." },
          { key: "client_ip", value: "10.40.17.52", label: "From where" },
          { key: "object_name", value: "xp_cmdshell", label: "What", note: "The procedure that was called." },
          { key: "statement", value: "EXEC master..xp_cmdshell 'whoami'", note: "The exact text sent to the server." },
          { key: "sql.database_role", value: "db_datareader", label: "With what standing", note: "SIEMs enrich this as sql.database_role for a database role such as db_datareader, or sql.server_role for a server-level role. xp_cmdshell runs only for the server's top role, or through a proxy account set up for it." },
        ],
        summary: "A refused call still says who tried, from where, and what they hoped for. The role field decided this one. In any correlated SQL alert, read the role fields early: they tell you what the login could do at that moment. Had this login held the top role, the shell would have run as the SQL Server service account.",
        primer: {
          title: "What xp_cmdshell is",
          fold: true,
          points: [
            "**xp_cmdshell** is a built-in SQL Server extended stored procedure. It runs a Windows shell command from a SQL query.",
            "The command is a real Windows process, a child of the database engine, running as the SQL Server service account.",
            "It is disabled by default on modern versions and turned on with `sp_configure`. Many servers still have it on because an old script needs it.",
            "Service accounts are often over-privileged, so a command from this path can arrive with local admin rights.",
          ],
          example: {
            label: "A worked read: the same idea in a web app",
            lines: [
              "A loan portal's diagnostics page passes text to a shell.",
              "The shell runs under the portal's app pool identity, with the web server as parent.",
              "Whatever rights that identity has, the command has.",
            ],
          },
        },
      },
      {
        kind: "queue",
        title: "Does This Parent Have a Reason?",
        prompt: "The rule 'shell under a service' fired across the bank this week. None of these hits is on ITB-RPT02, and Wanjiru wants them cleared before the audit. Open each one and judge it by its parent: what is that program's job?",
        console: "Detection queue · process rules",
        actions: [
          { id: "close", label: "Close as routine", tone: "close" },
          { id: "esc", label: "Escalate", tone: "escalate" },
        ],
        alerts: [
          {
            id: "q1", time: "Mon 09:12", severity: "High", rule: "Shell under a service", entity: "ITB-WK-IT04",
            fields: [{ k: "ParentImage", v: "C:\\Windows\\explorer.exe" }, { k: "Image", v: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" }, { k: "User", v: "ITB\\i.brandt" }],
            context: "The rule counts explorer.exe as a service because it runs all day. i.brandt was at this desk.",
            answer: "close", why: "explorer.exe is the desktop. A person starting a shell from it is that person at work. The rule's High severity changes nothing about the parent's job.",
          },
          {
            id: "q2", time: "Mon 13:40", severity: "Medium", rule: "Shell under a service", entity: "ITB-WEB03",
            fields: [{ k: "ParentImage", v: "C:\\Windows\\System32\\inetsrv\\w3wp.exe" }, { k: "Image", v: "C:\\Windows\\System32\\cmd.exe" }, { k: "CommandLine", v: "cmd.exe /c whoami" }, { k: "User", v: "IIS APPPOOL\\LoanPortal" }],
            context: "ITB-WEB03 hosts the loan portal. No deployment is scheduled.",
            answer: "esc", why: "w3wp.exe answers web requests inside its own process. A shell under it asking who it is means something told the web server to run a command.",
          },
          {
            id: "q3", time: "Tue 02:03", severity: "Medium", rule: "Shell under a service", entity: "ITB-WK-FIN22",
            fields: [{ k: "ParentImage", v: "C:\\Windows\\CCM\\CcmExec.exe" }, { k: "Image", v: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" }, { k: "CommandLine", v: "powershell.exe -File compliance_check.ps1" }, { k: "User", v: "NT AUTHORITY\\SYSTEM" }],
            context: "The same script runs under the same parent on 2,400 devices every night.",
            answer: "close", why: "Running scripts is a management agent's job, and it does this on every device on a schedule. Check it once, then baseline it.",
          },
          {
            id: "q4", time: "Tue 16:21", severity: "Low", rule: "Shell under a service", entity: "ITB-PRN02",
            fields: [{ k: "ParentImage", v: "C:\\Windows\\System32\\spoolsv.exe" }, { k: "Image", v: "C:\\Windows\\System32\\cmd.exe" }, { k: "CommandLine", v: "cmd.exe /c net localgroup administrators" }, { k: "User", v: "NT AUTHORITY\\SYSTEM" }],
            context: "ITB-PRN02 is a print server. The rule scored it Low because the host is low value.",
            answer: "esc", why: "Print jobs never need a command prompt, and a low-value host does not change the parent's job.",
          },
          {
            id: "q6", time: "Tue 22:48", severity: "Medium", rule: "Shell under a service", entity: "ITB-APP05",
            fields: [{ k: "ParentImage", v: "C:\\Apache\\Tomcat9\\bin\\tomcat9.exe" }, { k: "Image", v: "C:\\Windows\\System32\\cmd.exe" }, { k: "CommandLine", v: "cmd.exe /c ipconfig /all" }, { k: "User", v: "ITB\\svc-tomcat" }],
            context: "ITB-APP05 runs the mortgage API. Its team deploys on Sundays.",
            answer: "esc", why: "An application server serves requests. A shell running network discovery under it, away from any deployment, is outside its job.",
          },
          {
            id: "q5", time: "Wed 08:02", severity: "Low", rule: "Shell under a service", entity: "ITB-FS02",
            fields: [{ k: "ParentImage", v: "C:\\Windows\\System32\\svchost.exe" }, { k: "ParentCommandLine", v: "svchost.exe -k netsvcs -p -s Schedule" }, { k: "Image", v: "C:\\Windows\\System32\\taskhostw.exe" }, { k: "User", v: "NT AUTHORITY\\SYSTEM" }],
            context: "The rule's child list was widened last month and now includes taskhostw.exe.",
            answer: "close", why: "The Task Scheduler service starts task hosts all day. That is its job, and taskhostw.exe is not a shell anyway.",
          },
        ],
        primer: {
          title: "Judge the parent, not the child",
          fold: true,
          points: [
            "Every process record names a child and its parent. The question to ask of the parent is: what is this program's job?",
            "A server process answers requests and does that work inside itself. A shell beneath it means something told it to run a command.",
            "Agents, schedulers and the desktop start programs as their normal work, so a child there can be routine.",
            "Severity comes from the rule and the host. It says nothing about the parent.",
          ],
          example: {
            label: "A worked read: a DNS server",
            lines: [
              "`ParentImage`: `dns.exe`",
              "`Image`: `cmd.exe`",
              "dns.exe answers name lookups, and no lookup needs a shell. This goes up.",
            ],
          },
        },
      },
    ],
    // ── The offline gap, before the graded log ──
    "priv-la2": [
      {
        kind: "worksheet",
        title: "Time the Quiet Gap",
        prompt: "How did anyone get those two logins? Wanjiru finds an old KeePass password file on an IT share, kept from before the vault. Work the timeline.",
        caption: "Case timeline · rpt_reader and svc-rpt",
        columns: ["Time", "Host", "Record", "What it shows", "Source address"],
        rows: [
          ["Mon 10-19 19:41", "ITB-FS02", "5145 share access", "j.vance read \\\\ITB-FS02\\IT\\old\\adm_passwords.kdbx", "10.40.17.52"],
          ["Tue 10-20 08:55", "ITB-BR-WK17", "4624 Type 2", "j.vance signed in at the branch", "-"],
          ["Wed 10-21 01:47", "ITB-RPT02", "SQL Audit EX", "rpt_reader called xp_cmdshell, refused", "10.40.17.52"],
          ["Wed 10-21 01:52", "ITB-RPT02", "4624 Type 3", "svc-rpt signed in over NTLM", "10.40.17.52"],
        ],
        questions: [
          { id: "hours", q: "How many whole hours passed between the file read and the first use of a login from it?", hint: "Count from Monday 19:41 to Wednesday 01:47.", answer: ["30", "30 hours"], why: "30 hours and 6 minutes. That is how long the master password held out on someone else's machine." },
          { id: "logged", q: "How many of these rows record the password guessing itself? (a number)", hint: "Where did the guessing run?", answer: ["0", "zero", "none"], why: "None. The guessing ran on a copy of the file, away from Ironbridge, so no sensor here had anything to record." },
          { id: "tie", q: "Which value ties the file read to the use 30 hours later?", hint: "Compare the columns of the first row and the third.", answer: ["10.40.17.52"], why: "The same source address. j.vance's branch PC, ITB-BR-WK17, sits behind it, which makes that PC the next place to look." },
        ],
        primer: {
          title: "Offline work leaves a gap",
          fold: true,
          points: [
            "**Offline** means the work happens somewhere you have no sensors, on a copy they carried off.",
            "Anything that can be carried off can be attacked this way: a password file, a copied hash, a captured service ticket.",
            "The gap between theft and first use is as long as the guessing took, from minutes for a weak password to days for a strong one.",
            "So a timeline follows the identity and the source across the silence.",
          ],
          example: {
            label: "A worked read: a stolen ZIP",
            lines: [
              "Thu 16:00: an encrypted HR_2023.zip is copied off a share.",
              "Thu 16:01 to Sat 09:30: nothing anywhere.",
              "Sat 09:30: a password from that ZIP signs in.",
              "A 41.5 hour silence, and it sits inside the case.",
            ],
          },
        },
      },
    ],
    // ── Reading 1b: the question behind every privileged alert ──
    "priv-r1b": [
      {
        kind: "defuse",
        title: "Close, Contain or Verify?",
        prompt: "Before anyone touches last night's session, Wanjiru sets the standard with four privileged alerts from last quarter. Every one of them was permitted. Read what is known, then cut the one wire that fits.",
        device: "Overnight queue · privileged alerts",
        seconds: 100,
        rounds: [
          {
            id: "d1",
            state: "Saturday 21:05. adm-win03 adds k.oyelaran to ITB-Treasury-Approvers. CHG-29861 names this exact change, the window is Saturday 21:00 to 23:00, and i.brandt, the change owner, confirms it by phone.",
            wires: [
              { id: "close", label: "Close it and cite CHG-29861" },
              { id: "kill", label: "Disable adm-win03 and pull the member out" },
              { id: "ask", label: "Escalate and ask the change owner" },
            ],
            cut: "close", hint: "Is any question still unanswered?",
            why: "The approval, its time slot and the person who answers for it all fit what happened, and that person has already said so. Nothing is left to ask.",
          },
          {
            id: "d2",
            state: "Sunday 02:40. adm-net02 signs in to ITB-FWM01, the firewall manager, over NTLM from a branch PC. The vault has no check-out for adm-net02 that night, and the network on-call says nobody is working.",
            wires: [
              { id: "close", label: "Close it: adm-net02 is a valid account" },
              { id: "note", label: "Leave a note for the morning shift" },
              { id: "kill", label: "End the session and disable adm-net02" },
            ],
            cut: "kill", hint: "Who is left to ask?",
            why: "A vaulted account with no check-out, from a source the gateway never uses, and the people who could own it say it is not theirs. Nobody can vouch for it, so contain first.",
          },
          {
            id: "d3",
            state: "Tuesday 12:10. p.novak checks out adm-win07 with the reason 'cert renewal', and the vault approves. No ticket mentions a certificate. The session creates a scheduled task on ITB-PAYGW01. The leave calendar shows p.novak away this week.",
            wires: [
              { id: "ask", label: "Escalate: reach p.novak and the service owner" },
              { id: "close", label: "Close it: the vault approved the check-out" },
              { id: "kill", label: "Disable p.novak's accounts and declare a breach" },
            ],
            cut: "ask", hint: "Could an honest person have done this? Could a thief?",
            why: "The vault's yes shows the request was allowed, and nobody has agreed to this work. It fits an engineer fixing something from home and it fits a stolen login, and no log can separate those. A person who reaches the owner can.",
          },
          {
            id: "d4",
            state: "Thursday 10:05. adm-win03 adds a contractor to Administrators on ITB-FS02. The check-out cites CHG-29877. CHG-29877 is a share quota change and says nothing about group membership.",
            wires: [
              { id: "kill", label: "Disable adm-win03 now" },
              { id: "ask", label: "Escalate and ask the ticket owner" },
              { id: "close", label: "Close it: the check-out cites a ticket" },
            ],
            cut: "ask", hint: "What does the ticket actually cover?",
            why: "A ticket covers the work it describes, not whatever happens in the session. The requester is known and reachable, so the next step is a question.",
          },
        ],
        lesson: "Group membership has already answered 'could it?'. Your question is 'was it supposed to, right now, and can someone prove it?'. Close when the approval, its time slot and the person who answers for it all fit what happened. Contain when nobody can own it. When the record fits both an honest admin and a thief, the logs will not decide it: a person has to reach the owner, and your job is to send it to someone who can.",
        primer: {
          title: "Permitted and authorised are two questions",
          fold: true,
          points: [
            "**Permitted** is a technical fact: the account's token, group or role let the action through. Every Windows event here records that.",
            "**Authorised** is a business fact: the approval, its time slot, and the person who answers for it.",
            "Windows holds none of that. Tickets sit in the service desk, and matching them is manual or done by a SOAR (Security Orchestration, Automation and Response) playbook.",
            "Ask it of the one action in front of you.",
          ],
          example: {
            label: "A worked read: a library after hours",
            lines: [
              "Door log, 19:04: staff card, rare books room, Granted. That is permitted.",
              "Booking sheet: the same conservator, 19:00 to 20:00, signed by the head librarian. That is authorised.",
              "Both records exist, and the door log alone would never have told you the second.",
            ],
          },
        },
      },
      {
        kind: "hunt",
        title: "Who Used the Key? Set Check-Outs Against Logons",
        prompt: "No alert names what the auditor asked for, so build it. Set Tuesday's privileged logons against the vault in KQL (Kusto Query Language). Every result you see is really what that line returns, and the tables are on the left.",
        language: "KQL",
        console: "Logs",
        start: "SecurityEvent",
        goal: "one row: the admin session with no check-out behind it",
        tables: [
          {
            name: "SecurityEvent",
            note: "Windows Security events from every server: the 4672 and 4673 rows. Its 4624 rows are listed below as the subquery returns them.",
            columns: ["TimeGenerated", "Computer", "EventID", "SubjectUserName", "SubjectLogonId"],
            rows: [
              ["10-27 02:00", "ITB-LEDGER01", "4672", "SYSTEM", "0x3e7"],
              ["10-27 02:05", "ITB-DC01", "4672", "ITB-DC01$", "0x1a2f04"],
              ["10-27 03:10", "ITB-PAYGW01", "4672", "svc-monitor", "0x5b31c0"],
              ["10-27 09:14", "ITB-LEDGER01", "4672", "adm-ledger01", "0x7c21a8"],
              ["10-27 10:02", "ITB-FS02", "4672", "adm-win03", "0x6d40f2"],
              ["10-27 10:41", "ITB-LEDGER01", "4673", "adm-ledger01", "0x7c21a8"],
              ["10-27 14:30", "ITB-PAYGW01", "4672", "adm-win07", "0x91e3bc"],
              ["10-27 15:05", "ITB-LEDGER02", "4672", "adm-ledger02", "0x7c21a8"],
              ["10-27 23:47", "ITB-LEDGER02", "4672", "adm-ledger01", "0x4ab9d6"],
            ],
          },
          {
            name: "SecurityEvent | where EventID == 4624",
            note: "The same SecurityEvent table, filtered to 4624 logons: what the subquery inside a join returns.",
            columns: ["TimeGenerated", "Computer", "TargetUserName", "TargetLogonId", "LogonType", "IpAddress", "AuthenticationPackageName"],
            rows: [
              ["10-27 02:05", "ITB-DC01", "ITB-DC01$", "0x1a2f04", "3", "10.40.1.11", "Kerberos"],
              ["10-27 03:10", "ITB-PAYGW01", "svc-monitor", "0x5b31c0", "3", "10.40.2.30", "Kerberos"],
              ["10-27 09:14", "ITB-LEDGER01", "adm-ledger01", "0x7c21a8", "10", "10.40.2.10", "Kerberos"],
              ["10-27 10:02", "ITB-FS02", "adm-win03", "0x6d40f2", "10", "10.40.2.10", "Kerberos"],
              ["10-27 11:20", "ITB-FS02", "j.vance", "0x2210ae", "3", "10.40.17.52", "Kerberos"],
              ["10-27 14:30", "ITB-PAYGW01", "adm-win07", "0x91e3bc", "10", "10.40.2.11", "Kerberos"],
              ["10-27 15:05", "ITB-LEDGER02", "adm-ledger02", "0x7c21a8", "10", "10.40.2.10", "Kerberos"],
              ["10-27 23:47", "ITB-LEDGER02", "adm-ledger01", "0x4ab9d6", "3", "10.40.17.52", "NTLM"],
            ],
          },
          {
            name: "PamSessions_CL",
            note: "Custom table fed by the vault: one row per check-out.",
            columns: ["CheckoutTime", "RequestId", "Requester", "TargetAccount", "TargetHost", "Reason", "TicketId", "CheckinTime"],
            rows: [
              ["10-26 18:05", "REQ-48790", "p.novak", "adm-net02", "ITB-FWM01", "Rule review", "CHG-30398", "10-26 18:50"],
              ["10-27 09:10", "REQ-48812", "l.sato", "adm-ledger01", "ITB-LEDGER01", "Month-end batch fix", "CHG-30417", "10-27 10:55"],
              ["10-27 09:58", "REQ-48815", "i.brandt", "adm-win03", "ITB-FS02", "Share quota change", "CHG-30422", "10-27 10:40"],
              ["10-27 14:26", "REQ-48829", "p.novak", "adm-win07", "ITB-PAYGW01", "Certificate renewal", "CHG-30431", "10-27 15:10"],
              ["10-27 15:01", "REQ-48833", "l.sato", "adm-ledger02", "ITB-LEDGER02", "Index rebuild", "CHG-30436", "10-27 16:20"],
            ],
          },
        ],
        rungs: [
          {
            id: "event", ask: "Line 2: keep the rows that mark a privileged logon.",
            choices: [
              { id: "a", text: "| where EventID == 4673", why: "4673 is written when a process calls on a right, not when a session starts. Most admin sessions never write one, so a hunt built on it misses them.", apply: { op: "where", col: "EventID", test: "eq", value: "4673" } },
              { id: "b", text: '| where SubjectUserName has "adm-"', why: "Right accounts, wrong rows: the 4673 came along, and one session now counts twice. Pick the event first.", apply: { op: "where", col: "SubjectUserName", test: "has", value: "adm-" } },
              { id: "c", text: "| where EventID == 4672", right: true, why: "Special logon: one row for each session that got admin-equivalent rights. Eight rows.", apply: { op: "where", col: "EventID", test: "eq", value: "4672" } },
            ],
          },
          {
            id: "scope", ask: "Line 3: a vault can only answer for the accounts it manages, and Ironbridge vaults the adm- accounts.",
            choices: [
              { id: "a", text: '| where SubjectUserName !endswith "$"', why: "The computer account is gone, but SYSTEM and svc-monitor stay. Neither is vaulted, so both would show up later as false finds.", apply: { op: "where", col: "SubjectUserName", test: "notin", value: ["ITB-DC01$"] } },
              { id: "b", text: '| where Computer has "LEDGER"', why: "Too narrow, and SYSTEM is still here. The vault covers more than the ledger: the payment gateway session dropped out.", apply: { op: "where", col: "Computer", test: "has", value: "LEDGER" } },
              { id: "c", text: '| where SubjectUserName startswith "adm-"', right: true, why: "Five sessions, all on managed accounts. Scope the hunt to what the other table can answer for.", apply: { op: "where", col: "SubjectUserName", test: "has", value: "adm-" } },
            ],
          },
          {
            id: "session", ask: "Line 4: a 4672 cannot say where a session came from. Bring in its 4624.",
            choices: [
              { id: "a", text: "| join kind=inner (SecurityEvent | where EventID == 4624) on Computer, $left.SubjectLogonId == $right.TargetLogonId", right: true, why: "The two events of one session, matched on the machine and the Logon ID. Five rows, each with its source.", apply: { op: "join", table: "SecurityEvent | where EventID == 4624", left: "SubjectLogonId", right: "TargetLogonId", also: "Computer" } },
              { id: "b", text: "| join kind=inner (SecurityEvent | where EventID == 4624) on $left.SubjectLogonId == $right.TargetLogonId", why: "Seven rows from five sessions. 0x7c21a8 exists on both ledger servers, because a Logon ID is only unique on one machine.", apply: { op: "join", table: "SecurityEvent | where EventID == 4624", left: "SubjectLogonId", right: "TargetLogonId" } },
              { id: "c", text: "| join kind=inner (SecurityEvent | where EventID == 4624) on $left.SubjectUserName == $right.TargetUserName", why: "Seven rows again. adm-ledger01 has two sessions, and each one just picked up the other's logon. An account name does not identify a session.", apply: { op: "join", table: "SecurityEvent | where EventID == 4624", left: "SubjectUserName", right: "TargetUserName" } },
            ],
          },
          {
            id: "vault", ask: "Line 5: now the vault. You want the sessions with nothing behind them.",
            choices: [
              { id: "a", text: "| join kind=leftsemi PamSessions_CL on $left.SubjectUserName == $right.TargetAccount, $left.Computer == $right.TargetHost", why: "Four rows, and each one has a check-out. leftsemi keeps left rows that do have a match, the reverse of what you want.", apply: { op: "where", col: "SubjectLogonId", test: "in", value: ["0x7c21a8", "0x6d40f2", "0x91e3bc"] } },
              { id: "b", text: "| join kind=leftanti PamSessions_CL on $left.SubjectUserName == $right.TargetAccount", why: "No results, and it looks clean. It isn't: adm-ledger01 was checked out that morning for a different server, and joining on the account alone lets that check-out cover everything the account did.", apply: { op: "where", col: "SubjectUserName", test: "notin", value: ["adm-net02", "adm-ledger01", "adm-win03", "adm-win07", "adm-ledger02"] } },
              { id: "c", text: "| join kind=leftanti PamSessions_CL on $left.SubjectUserName == $right.TargetAccount, $left.Computer == $right.TargetHost", right: true, why: "One row. A check-out names one account on one host, so both are the key. Nothing in the vault stands behind this session.", apply: { op: "where", col: "SubjectLogonId", test: "notin", value: ["0x7c21a8", "0x6d40f2", "0x91e3bc"] } },
            ],
          },
          {
            id: "show", ask: "Line 6: show only what the auditor's ticket needs.",
            choices: [
              { id: "a", text: "| project TimeGenerated, Computer, SubjectUserName, Requester", why: "Failed: leftanti returns left-hand columns only, and there was no check-out row to take a name from. That absence is the finding.", apply: { op: "project", cols: ["TimeGenerated", "Computer", "SubjectUserName", "Requester"] } },
              { id: "b", text: "| project TimeGenerated, Computer, SubjectUserName, LogonType, IpAddress, AuthenticationPackageName", right: true, why: "When, where, which key, how, from where. A Type 3 NTLM logon from a branch address, not from a gateway.", apply: { op: "project", cols: ["TimeGenerated", "Computer", "SubjectUserName", "LogonType", "IpAddress", "AuthenticationPackageName"] } },
              { id: "c", text: "| summarize count() by SubjectUserName", why: "A count tells you how often. The ticket needs when, where and from where.", apply: { op: "summarize", by: ["SubjectUserName"] } },
            ],
          },
        ],
        expect: 1,
        lesson: "Start from what Windows saw: the 4672 gives the key, its 4624 gives the source, the vault gives the person. A leftanti join finds what no single table shows, the row that should exist and doesn't. Key it on account and host, and in production also test the logon time against CheckoutTime and CheckinTime, so a morning check-out cannot cover a midnight session on the same host. The address 10.40.17.52 is j.vance's branch PC. adm-ledger01's rotation had been paused for a vendor batch job, so a hash lifted on another server kept working.",
        primer: {
          title: "Finding what is not there",
          fold: true,
          points: [
            "A 4672 and the 4624 of one session share a value: `SubjectLogonId` on the 4672 equals `TargetLogonId` on the 4624.",
            "A Logon ID is only unique on one machine, between reboots, so the machine is part of the key.",
            "An inner join keeps rows that found a partner. `kind=leftanti` keeps left-hand rows with **no** partner, and returns left-hand columns only.",
            "A check-out covers one account on one host.",
          ],
          example: {
            label: "A worked read: a car park against its permits",
            lines: [
              "`BarrierLifts` has Plate and Bay. `Permits` has Plate and Bay.",
              "`BarrierLifts | join kind=leftanti Permits on Plate, Bay`",
              "The result is a lift with no permit behind it, which neither table shows alone.",
            ],
          },
        },
      },
      {
        kind: "tune",
        title: "Which Privileged Events Page Someone?",
        prompt: "Wanjiru will not reconcile by hand again. The new rule scores each privileged event twice: approvals found (check-out, ticket, window, so 0 to 3) and reach (1 or 2 for a laptop, 10 for the directory). Set when a person gets paged, then deploy against 30 days of events.",
        eventColumn: "Privileged event, last 30 days",
        dials: [
          { id: "approvals", label: "Approvals found at or below", short: "approvals", min: 0, max: 3, step: 1, start: 3, dir: "below" },
          { id: "reach", label: "Reach score at or above", short: "reach", min: 1, max: 10, step: 1, start: 1, dir: "above" },
        ],
        events: [
          { id: "b1", label: "Ledger server session, no check-out", bad: true, values: { approvals: 0, reach: 9 } },
          { id: "b2", label: "Member added to Enterprise Admins, nothing behind it", bad: true, values: { approvals: 0, reach: 10 } },
          { id: "b3", label: "Unknown tool opens LSASS on ITB-FS02", bad: true, values: { approvals: 0, reach: 7 } },
          { id: "b4", label: "New service on ITB-PAYGW01, check-out only", bad: true, values: { approvals: 1, reach: 8 } },
          { id: "b5", label: "Service account checks out a directory credential, no ticket", bad: true, values: { approvals: 1, reach: 10 } },
          { id: "b6", label: "Replication request to ITB-DC01 from a non-DC", bad: true, values: { approvals: 0, reach: 10 } },
          { id: "b7", label: "Debug right used on a branch PC, no ticket", bad: true, values: { approvals: 0, reach: 3 } },
          { id: "n1", label: "Planned group change on ITB-DC01, all three approvals", bad: false, values: { approvals: 3, reach: 10 } },
          { id: "n2", label: "Nightly svc-monitor special logons on every server", bad: false, values: { approvals: 2, reach: 6 } },
          { id: "n3", label: "Month-end fix on ITB-LEDGER01, all three approvals", bad: false, values: { approvals: 3, reach: 9 } },
          { id: "n4", label: "Emergency certificate swap, ticket raised afterwards", bad: false, values: { approvals: 2, reach: 8 } },
          { id: "n5", label: "Engineer's local admin on their own laptop", bad: false, values: { approvals: 0, reach: 2 } },
          { id: "n6", label: "Inventory agent reads process lists on a file server", bad: false, values: { approvals: 1, reach: 5 } },
          { id: "n7", label: "Helpdesk resets a branch manager's password, ticket only", bad: false, values: { approvals: 1, reach: 4 } },
          { id: "n8", label: "Vendor support session on ITB-RPT02, check-out only", bad: false, values: { approvals: 1, reach: 6 } },
        ],
        goal: { catch: 6, maxFalse: 1 },
        deploys: 4,
        lesson: "Approvals at 1 or below with reach at 6 or 7 pages six of the seven attacks with at most one false alarm. Reach at 5 wakes someone for an inventory agent, reach at 8 loses the tool on the file server, and approvals at 2 only works at reach 7, with the emergency swap as its false alarm. All of these events were permitted, so privilege alone could not choose. The debug right on a branch PC does not page: it opens a ticket for the morning shift, because a real finding with small reach still has to land somewhere.",
        primer: {
          title: "What earns a page",
          fold: true,
          points: [
            "A **page** wakes a person. Enough false ones and the on-call stops believing them.",
            "**Approvals** count what the bank agreed to. Windows already allowed every event here, so the count is the part Windows cannot give you.",
            "**Reach** is what the target touches if this goes wrong.",
            "Tune against the whole list, including the things that should stay quiet.",
          ],
          example: {
            label: "A worked read: a card fraud rule",
            lines: [
              "Rule: no travel notice AND amount at or above 900.",
              "1,400 abroad with a notice on file: quiet.",
              "A coffee for 4 with no notice: quiet.",
              "2,100 at a jeweller abroad with no notice: page.",
            ],
          },
        },
      },
    ],
    // ── One session, end to end, before the graded log ──
    "priv-la1": [
      {
        kind: "trace",
        title: "Follow One Session From Its Rights to Its Approval",
        prompt: "This is the chain the auditor wants for every session. Take last Thursday's 4672 for adm-net02 on the firewall manager and walk it back, record by record, until you reach a person who can answer for it.",
        lead: "Event 4672 · ITB-FWM01 · Thursday 14:22 · adm-net02 · SubjectLogonId 0x3c88e10",
        steps: [
          {
            id: "logon", ask: "Which 4624 started this session?", source: "SecurityEvent · Event ID 4624",
            columns: ["TimeGenerated", "Computer", "TargetUserName", "TargetLogonId", "LogonType", "IpAddress"],
            rows: [
              ["Thu 09:34", "ITB-FWM01", "adm-net02", "0x3c61a04", "10", "10.40.2.11"],
              ["Thu 14:22", "ITB-FWM01", "adm-net02", "0x3c88e10", "10", "10.40.2.10"],
              ["Thu 14:22", "ITB-LEDGER01", "adm-ledger02", "0x3c88e10", "10", "10.40.2.10"],
              ["Thu 14:23", "ITB-FWM01", "svc-monitor", "0x3c88f2a", "3", "10.40.2.30"],
            ],
            answer: 1, why: "Same machine, same Logon ID. The ledger row shares the ID and sits on another host, so it is another session.",
            learned: "The session began at 14:22 through the gateway, 10.40.2.10.",
          },
          {
            id: "checkout", ask: "It came through the gateway, so a check-out should exist. Which one covers it?", source: "PamSessions_CL",
            columns: ["CheckoutTime", "Requester", "TargetAccount", "TargetHost", "Reason", "TicketId", "CheckinTime"],
            rows: [
              ["Wed 16:02", "p.novak", "adm-net02", "ITB-FWM01", "Rule review", "CHG-30288", "Wed 17:10"],
              ["Thu 09:30", "i.brandt", "adm-net02", "ITB-FWM01", "Log export", "CHG-30302", "Thu 10:05"],
              ["Thu 14:18", "p.novak", "adm-net02", "ITB-FWM01", "Partner subnet rule", "CHG-30311", "Thu 15:02"],
              ["Thu 14:20", "i.brandt", "adm-win03", "ITB-FS02", "Share quota change", "CHG-30312", "Thu 14:50"],
            ],
            answer: 2, why: "Right account, right host, and 14:22 falls between check-out and check-in. The earlier check-outs ended before this session began.",
            learned: "p.novak held the key, citing CHG-30311, until 15:02.",
          },
          {
            id: "ticket", ask: "Who can answer for this work if the auditor asks?", source: "Change calendar",
            columns: ["Ticket", "Summary", "Host", "Window", "Owner"],
            rows: [
              ["CHG-30311", "Add partner subnet rule", "ITB-FWM01", "Thu 14:00 to 16:00", "n.achebe"],
              ["CHG-30312", "Quota on Finance share", "ITB-FS02", "Thu 14:00 to 15:00", "i.brandt"],
              ["CHG-30288", "Quarterly rule review", "ITB-FWM01", "Wed 16:00 to 18:00", "p.novak"],
            ],
            answer: 0, why: "The ticket covers this host in this window, and its owner is someone other than the person who did the work.",
            learned: "CHG-30311 covers the work, and n.achebe can explain it.",
          },
        ],
      },
    ],
  },
};
