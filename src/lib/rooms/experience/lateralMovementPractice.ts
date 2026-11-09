import type { RoomExperience } from "./types";

// "Operation Sidestep" for the "lateral-movement-practice" room.
// Script: docs/campaign/99-lateral-movement-practice.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Corvid Cold Chain (fictional), not the graded tasks' kestrel.local records.
// Mentor: Tamsin Oyelowo, Threat Hunter.
// Signature, Rebuild the Graph: logons from several hosts become a who-reached-what map. A
// pathway walks the true route across five hosts and three clock offsets, and a KQL hunt ties
// a host's way out to its way in, on the same device and account, to find the pivot host.
// Room 76 teaches the protocols; this room is the practice of tracing a whole path.
// Game mix: hunt + intercept + pathway.
// Task order unchanged, so the "Log Analysis N" references in la2, qf1 and the flag still hold.
//
// Lab data differs from the graded tasks. Hosts, accounts and addresses are all Corvid, never
// SRV-FIL02, SRV-APP09, SRV-APP11, WKS-SALES14, JMP-ITSUPPORT01, sysmgr_svc or 10.60.x (all).
// The 4624 anatomy is a server-to-server record with no verdict attached (r1, la1, f1). The
// worksheet shows per-host grants for a named admin, not a service install (q1). The context
// trace is a known source at the wrong hour, with the owner on leave, not a source with no
// history (la1). The service record is PAExec on a test host, never PSEXESVC (la2). The
// intercept pairs WMI, WinRM, RDP, scheduled tasks and C$ logons, never a service install
// (q2). The verdict sort uses other rules altogether, no remote service and no jump host (ac1).
// The technique sheet is a purple-team record of six doors, shown and never asked (m1). The
// clock worksheet uses +02:00 and -05:00, not +03:00, on a patch job (o1). The route is four
// hops by four techniques, and the hunt joins outbound connections to logons, with no 7045, no
// allowlist and no time window (qf1).

export const LATERAL_MOVEMENT_PRACTICE: RoomExperience = {
  roomId: "lateral-movement-practice",
  codename: "Operation Sidestep",
  theme: "sidestep",
  handler: { name: "Tamsin Oyelowo", role: "Threat Hunter, Corvid Cold Chain" },
  briefing: [
    "Corvid Cold Chain. Three yards, three clocks, and a temperature record for every pallet of vaccine that moves through them.",
    "At 02:14 UTC on Saturday, CC-TEMPLOG-01 flagged a changed temperature file, one week before a regulator's audit.",
    "The alert names one file on one server. It says nothing about how anyone got there, and Tamsin Oyelowo doesn't hunt from the last stop.",
    "Read each hop from both ends, work out what each session really did, then rebuild the whole path, host by host.",
  ],
  mission: "Read a hop from both ends, separate what an account can do from what it should have done, tie a logon to what followed it, name the verdict, put every clock on UTC, then rebuild the path and find the pivot host.",
  estimate: "~45 min",
  look: { primary: "#7bdff2", secondary: "#f9c74f", warn: "#ef476f" },
  scene: "facilitysidestep",
  layout: "facility",
  stations: [
    {
      id: "firsthop",
      label: "The First Hop",
      topic: "What each host records · one logon read field by field · where local admin comes from",
      tagline: "One host, half a story",
      building: "control",
      taskIds: ["lat-r1", "lat-r2", "lat-q1"],
    },
    {
      id: "session",
      label: "What the Session Did",
      topic: "Source history, change queue, rota · logon then service · default tool names · mechanism and context",
      tagline: "It logged on. Then what?",
      building: "lab",
      taskIds: ["lat-la1", "lat-la2", "lat-q2"],
    },
    {
      id: "name",
      label: "Name the Move",
      topic: "The three verdicts · the trace each technique leaves",
      tagline: "The right word for what you saw",
      building: "office",
      taskIds: ["lat-ac1", "lat-m1"],
    },
    {
      id: "graph",
      label: "Rebuild the Graph",
      topic: "Clocks on UTC · true event order · KQL across hosts · the source address",
      tagline: "Every host, in order",
      building: "ticket",
      taskIds: ["lat-o1", "lat-qf1", "lat-f1"],
      boss: true,
    },
  ],
  personas: {
    "lat-q1": { name: "Tamsin Oyelowo", role: "Threat Hunter", line: "Someone on the call has a theory. Check the reasoning." },
    "lat-la1": { name: "Tamsin Oyelowo", role: "Threat Hunter", line: "One logon, one server. Tell me what it proves." },
    "lat-la2": { name: "Tamsin Oyelowo", role: "Threat Hunter", line: "Same host, a moment later. Put the two records side by side." },
    "lat-q2": { name: "Tamsin Oyelowo", role: "Threat Hunter", line: "Two cases, the same records, two endings. Explain it." },
    "lat-ac1": { name: "Tamsin Oyelowo", role: "Threat Hunter", line: "Another one from the queue. Read all of it, then give me your verdict." },
    "lat-m1": { name: "Tamsin Oyelowo", role: "Threat Hunter", line: "Each technique leaves its own mark. Pair them up." },
    "lat-o1": { name: "Tamsin Oyelowo", role: "Threat Hunter", line: "The SIEM handed us these in its own order. I want the real one." },
    "lat-qf1": { name: "Tamsin Oyelowo", role: "Threat Hunter", line: "Turn it into a query that runs tomorrow without us." },
    "lat-f1": { name: "Tamsin Oyelowo", role: "Threat Hunter", line: "The firewall team is on the line and wants one value." },
  },
  briefings: {
    // ── Reading 1: one host is half a story ──
    "lat-r1": [
      {
        kind: "sort",
        title: "Which Host Holds Which Half?",
        prompt: "Tamsin asks every yard for logs from one night's remote admin work on a finance server. Nine records come back. Sort each one by the machine that wrote it: the source, the target, or the domain controller in between.",
        primer: {
          title: "One hop, two ends",
          points: [
            "A hop has a **source**, where the session starts, and a **target**, where it lands. Each host writes only its own side.",
            "The source logs the outbound side: the client program, the connection, any credentials typed for that connection.",
            "The target logs the inbound side: the logon, then whatever the visitor went on to do there.",
            "The domain controller logs the credential check in between.",
          ],
          example: {
            label: "One parcel, three records",
            lines: [
              "The sender's desk: `parcel handed over, 09:00`.",
              "The sorting office: `label checked, 09:20`.",
              "The receiving dock: `parcel signed for, 11:05`, then `box opened, 11:10`.",
              "No single book holds the whole journey. You lay them side by side.",
            ],
          },
          fold: true,
        },
        buckets: [
          { id: "source", label: "Source host" },
          { id: "target", label: "Target host" },
          { id: "dc", label: "Domain controller" },
        ],
        items: [
          { id: "a", text: "mstsc.exe /v:cc-fin-02 starts under a logged-on user", bucket: "source", why: "The client program runs on the machine the session starts from." },
          { id: "b", text: "Sysmon 3: System (PID 4) connects out to 10.44.20.30:445", bucket: "source", why: "An outbound connection is recorded by the host that opened it." },
          { id: "c", text: "4648: a logon was attempted using explicit credentials, target server CC-FIN-02", bucket: "source", why: "4648 is written where the credentials were typed, and it names the server they were meant for." },
          { id: "d", text: "4624: LogonType 3 for adm-n.ferrante", bucket: "target", why: "A successful logon is written by the host that was logged on to." },
          { id: "e", text: "4672: special privileges assigned to the new logon", bucket: "target", why: "Written on the target, straight after a 4624 for a privileged account." },
          { id: "f", text: "5140: a network share object was accessed, \\\\*\\C$", bucket: "target", why: "The host that owns the share records the access." },
          { id: "g", text: "4688: new process whoami.exe", bucket: "target", why: "What the visitor does after landing is written on the host where it ran." },
          { id: "h", text: "4769: Kerberos service ticket requested for cifs/cc-fin-02", bucket: "dc", why: "Tickets are issued by the domain controller, so the request is logged there." },
          { id: "i", text: "4776: the computer attempted to validate the credentials for an account", bucket: "dc", why: "For a domain account, NTLM validation is logged on the domain controller." },
        ],
      },
      {
        kind: "anatomy",
        title: "Read One Logon on the Target",
        prompt: "Before the night's records, Tamsin pulls an ordinary 4624 from Friday afternoon so the shift can read the same fields the same way. Scan each field and see what it shows, and notice which question it leaves open.",
        source: "Security log · CC-WMS-01 · Friday 14:02 UTC",
        fields: [
          { key: "event.code", value: "4624", label: "Event", note: "An account logged on successfully. This is the target's own record of the arrival." },
          { key: "winlog.computer_name", value: "CC-WMS-01.corvidcold.example", label: "Target", note: "The host that wrote the record, which is the place the session landed." },
          { key: "TargetUserName", value: "svc_labelpush", label: "Who", note: "The account the session runs as." },
          { key: "LogonType", value: "3", label: "How", note: "3 is a network logon: a session from another machine to a resource here. Shares, remote services and WMI all start with one. 10 is a Remote Desktop session." },
          { key: "LogonProcessName", value: "NtLmSsp", note: "The component that handled the logon. NtLmSsp for NTLM, Kerberos for Kerberos." },
          { key: "AuthenticationPackageName", value: "NTLM", note: "Which protocol proved the identity. NTLM and Kerberos are both everyday values in a Windows domain." },
          { key: "WorkstationName", value: "CC-LABEL-02", label: "Source name", note: "The name the client gave for itself." },
          { key: "IpAddress", value: "10.44.20.12", label: "Source address", note: "Where the connection arrived from, as this host saw it. A name is what the client says, this is what the network delivered." },
          { key: "IpPort", value: "49822", note: "The client's temporary port, useful for matching the session in network logs." },
        ],
        summary: "The target knows who, how, when and from where. It has no field for whether the person behind the session owns the account: a correct password writes these same values whoever typed it. That answer lives outside this record, and the next stations go and get it.",
      },
    ],
    // ── Reading 2: the right is not the reason ──
    "lat-r2": [
      {
        kind: "worksheet",
        title: "Where Did This Right Come From?",
        prompt: "IT sends over the local Administrators groups for the hosts nearest the changed file, with how each member got there. The account on last night's records is adm-k.sorel. Work out what it can really do, and where.",
        primer: {
          title: "Two questions about one account",
          points: [
            "Writing to the `ADMIN$` share and creating a service through the Service Control Manager both need **local administrator rights on that target**, at that moment.",
            "Those rights come from that host's own local Administrators group. Someone can land there through a **GPO Restricted Groups** policy, a manual addition nobody undid, or the Domain Admins group.",
            "So the first question is *could this account do it?* The group answers that.",
            "The second question is *should it have, from there, at that hour?* No group answers that.",
          ],
          example: {
            label: "One line from a test host",
            lines: [
              "`net localgroup Administrators` on `LAB-VM3` lists `LABNET\\print-ops`.",
              "`print-ops` can write to `ADMIN$` and create services on `LAB-VM3`.",
              "On `LAB-VM4`, where it isn't listed, the same account gets access denied.",
            ],
          },
          fold: true,
        },
        caption: "Local Administrators · collected Saturday 07:30 UTC",
        columns: ["Host", "Member", "How it got there", "In Domain Admins?"],
        rows: [
          ["CC-LABEL-02", "CORVID\\adm-k.sorel", "GPO Restricted Groups, OU Yard Servers", "No"],
          ["CC-ROUTE-03", "CORVID\\adm-k.sorel", "GPO Restricted Groups, OU Yard Servers", "No"],
          ["CC-BACKUP-02", "CORVID\\adm-k.sorel", "GPO Restricted Groups, OU Yard Servers", "No"],
          ["CC-WMS-01", "CORVID\\adm-k.sorel", "Added by hand for a migration project that ended in 2025", "No"],
          ["CC-TEMPLOG-01", "CORVID\\adm-k.sorel", "GPO Restricted Groups, OU Cold Store Servers", "No"],
          ["CC-TEMPLOG-01", "CORVID\\Domain Admins", "Default member after the domain join", "It is that group"],
          ["CC-DC01", "CORVID\\Domain Admins", "Default on a domain controller", "It is that group"],
        ],
        questions: [
          { id: "count", q: "On how many hosts in this table is adm-k.sorel a local administrator? (a number)", hint: "Count the rows that name this account, not the group rows.", answer: ["5", "five"], why: "Five hosts, each with its own grant. The right exists host by host, and it stops at the edge of this table." },
          { id: "stale", q: "Which host's grant should have ended with a project?", hint: "Read the How it got there column.", answer: ["CC-WMS-01", "cc-wms-01", "wms-01"], why: "A manual addition has no policy to remove it. When the project ended, nothing took it back." },
          { id: "da", q: "Is adm-k.sorel in Domain Admins? (yes/no)", hint: "Read the last column of the account's own rows.", answer: ["no"], why: "Five local grants and no domain group. Administrator on several hosts and Domain Admin are different things." },
          { id: "use", q: "The table says adm-k.sorel can administer CC-ROUTE-03. Does it say whether a sign-in there last night was approved? (yes/no)", hint: "Which of the two questions does a group answer?", answer: ["no"], why: "Membership answers 'could it?' and stops. 'Should it?' needs evidence from somewhere else, and that is the next station." },
        ],
      },
    ],
    // ── Log Analysis 1 warm-up: what the record leaves out ──
    "lat-la1": [
      {
        kind: "trace",
        title: "Collect What the Record Leaves Out",
        prompt: "One logon from last night has a known account on it, and the group check from the last station says the right is real. Now fetch the context that no logon record holds. Click the row that answers each step.",
        primer: {
          title: "Where the context lives",
          points: [
            "A logon record gives you who, from where and how. Whether it fits lives in other systems.",
            "**History:** has this source used this account on this target before, and on what pattern?",
            "**Requests and people:** is a change open for this host, and is the account's owner at work?",
            "When it doesn't fit, work in both directions: who reached the source, and what did the session do on the target?",
          ],
          example: {
            label: "The method on a library scanner",
            lines: [
              "Record: `b.ito` signs in to `LIB-SCAN-2` from `LIB-DESK-1` at 11:00.",
              "History: that desk signs in to that scanner every weekday morning.",
              "Rota: `b.ito` is on the front desk today.",
              "Each answer came from a different system, and none came from the record itself.",
            ],
          },
          fold: true,
        },
        lead: "Sat 19 Sep, 01:44:02 UTC. CC-ROUTE-03 logged a network logon as adm-k.sorel from CC-LABEL-02.",
        steps: [
          {
            id: "history",
            ask: "Has this source used this account here before? Find the row that breaks the pattern.",
            source: "SIEM · 4624 on CC-ROUTE-03 from CC-LABEL-02 · last 90 days · UTC",
            columns: ["Date", "Day", "Time", "Account", "LogonType"],
            rows: [
              ["2026-08-24", "Mon", "14:06", "adm-k.sorel", "3"],
              ["2026-08-31", "Mon", "14:02", "adm-k.sorel", "3"],
              ["2026-09-07", "Mon", "14:11", "adm-k.sorel", "3"],
              ["2026-09-14", "Mon", "14:04", "adm-k.sorel", "3"],
              ["2026-09-19", "Sat", "01:44", "adm-k.sorel", "3"],
            ],
            answer: 4,
            why: "Four Mondays around 14:00, then a Saturday at 01:44. The source and the account have history here, and the hour doesn't.",
            learned: "Known source, known account, new hour",
          },
          {
            id: "change",
            ask: "Is anyone expected to be working? Open the only change whose window includes 01:44 on Saturday.",
            source: "Change queue · 17 to 22 Sep · UTC",
            columns: ["Change", "Host", "Window", "Summary"],
            rows: [
              ["CHG-5201", "CC-DISP-02", "Thu 17 Sep 20:00 to 22:00", "Driver update"],
              ["CHG-5233", "CC-PATCH-01", "Fri 18 Sep 23:30 to Sat 19 Sep 03:00", "Monthly patch push"],
              ["CHG-5240", "CC-ROUTE-03", "Tue 22 Sep 09:00 to 10:00", "Route planner upgrade"],
            ],
            answer: 1,
            why: "The one change open at 01:44 is on CC-PATCH-01. CC-ROUTE-03's own change is three days away.",
            learned: "No change covers CC-ROUTE-03 at this hour",
          },
          {
            id: "rota",
            ask: "Who owns this account, and are they working?",
            source: "IT operations rota · 18 to 21 Sep",
            columns: ["Person", "Admin account", "Status", "Back on shift"],
            rows: [
              ["n.ferrante", "adm-n.ferrante", "On call", "-"],
              ["l.tanaka", "adm-l.tanaka", "Day shift", "-"],
              ["k.sorel", "adm-k.sorel", "Annual leave from Fri 18:00", "Tue 22 Sep"],
            ],
            answer: 2,
            why: "The account was busy overnight and its owner has been on leave since Friday evening.",
            learned: "The account's owner is on leave",
          },
          {
            id: "back",
            ask: "Step back to the source. Who arrived on CC-LABEL-02 as this account just before 01:44?",
            source: "SIEM · 4624 on CC-LABEL-02 · Sat 19 Sep · UTC",
            columns: ["Time", "Account", "LogonType", "WorkstationName"],
            rows: [
              ["00:15", "LOCAL SERVICE", "5", "-"],
              ["01:02", "svc_labelpush", "3", "CC-WMS-01"],
              ["01:26", "adm-k.sorel", "3", "CC-DOCK-LT12"],
              ["02:40", "svc_labelpush", "3", "CC-WMS-01"],
            ],
            answer: 2,
            why: "A dock supervisor's laptop reached CC-LABEL-02 as this account. The label server is a stop on the path, not where the path begins.",
            learned: "CC-LABEL-02 was reached from CC-DOCK-LT12",
          },
          {
            id: "forward",
            ask: "Now forward. What did the session do first on CC-ROUTE-03?",
            source: "DeviceProcessEvents · cc-route-03 · Sat 19 Sep · UTC",
            columns: ["Timestamp", "FileName", "ProcessCommandLine", "InitiatingProcessFileName", "AccountName"],
            rows: [
              ["01:40:03", "truckfeed.exe", "truckfeed.exe --sync", "services.exe", "svc_route"],
              ["01:44:21", "cmd.exe", "cmd.exe /Q /c whoami /groups", "WmiPrvSE.exe", "adm-k.sorel"],
              ["01:45:02", "net.exe", "net group \"Domain Admins\" /domain", "cmd.exe", "adm-k.sorel"],
            ],
            answer: 1,
            why: "The account's first process here starts 19 seconds after the logon, and the next one asks who runs the domain.",
            learned: "Commands ran on the target after the logon",
          },
        ],
      },
    ],
    // ── Log Analysis 2 warm-up: what a remote service looks like ──
    "lat-la2": [
      {
        kind: "sequence",
        title: "The Shape of a Remote Service",
        prompt: "Running code on another machine over SMB isn't one event. Tap these steps in the order they happen on the target, from first packet to running code.",
        primer: {
          title: "Why tools install a service",
          points: [
            "To run code over SMB, a tool needs the target to start something for it. A Windows service is the classic way.",
            "`ADMIN$` is the hidden share for `C:\\Windows`. `IPC$` carries named pipes, and `svcctl` is the pipe to the Service Control Manager.",
            "The logon goes to the Security log and the new service to the System log. Neither record names the other, so you tie them together by host and time.",
          ],
          example: {
            label: "Tying records by host and time",
            lines: [
              "`LAB-VM7` Security, 10:00:03: a `4624` from `LAB-VM2`.",
              "`LAB-VM9` Security, 10:00:05: a `4624` from `LAB-VM2`.",
              "`LAB-VM7` Security, 10:00:09: `4698`, a scheduled task registered.",
              "Compare the two `LAB-VM7` lines. The `LAB-VM9` line is closer in time, but it sits on another host.",
            ],
          },
          fold: true,
        },
        items: [
          { id: "pipe", text: "IPC$ is opened and the svcctl named pipe is bound", note: "The tool now talks to the Service Control Manager." },
          { id: "tcp", text: "A TCP connection reaches port 445", note: "SMB, before any account is involved." },
          { id: "start", text: "The service starts and runs the operator's command", note: "Execution, usually under LocalSystem." },
          { id: "logon", text: "The target writes a network logon, LogonType 3", note: "The session exists from here on." },
          { id: "svc", text: "The Service Control Manager registers the service, and event 7045 is written", note: "This one lands in the System log." },
          { id: "copy", text: "The tool's binary is copied to the ADMIN$ share", note: "A write that needs local admin on this host." },
        ],
        order: ["tcp", "logon", "copy", "pipe", "svc", "start"],
        doneNote: "A whole hop can take seconds. The logon comes first, and the 7045 follows it on the same host, which is the pair you go looking for.",
      },
      {
        kind: "anatomy",
        title: "Read a New Service Record",
        prompt: "Last spring's purple-team exercise left this record on a test host, and Tamsin keeps it as the reference sample. Scan each field and see what it shows.",
        source: "System log · CC-LAB-07 · purple-team exercise",
        fields: [
          { key: "event.code", value: "7045", label: "Event", note: "A service was installed. Written to the System log, not the Security log." },
          { key: "winlog.computer_name", value: "CC-LAB-07.corvidcold.example", label: "Where", note: "The host the service was registered on, which is where it runs." },
          { key: "ServiceName", value: "PAExec-6172-CC-LAB-02", label: "Name", note: "PAExec's default pattern: the tool, a process ID, the host it ran from. One option changes it, and operators in a hurry often leave it." },
          { key: "ImagePath", value: "C:\\Windows\\PAExec-6172-CC-LAB-02.exe", label: "Binary", note: "Where the binary sits. C:\\Windows is the folder behind the ADMIN$ share." },
          { key: "ServiceType", value: "user mode service" },
          { key: "StartType", value: "demand start", note: "Starts on request, not at boot. The tool starts it itself." },
          { key: "AccountName", value: "LocalSystem", label: "Runs as", note: "The account the service runs under, which is a different thing from the account that installed it." },
        ],
        summary: "A 7045 says what was registered, where, and how it runs. To learn which session asked for it, go to the logons on that host around that time. Tool defaults are worth knowing by sight, because a name you recognise is one you can search a whole fleet for.",
      },
    ],
    // ── Question 2 warm-up: the mechanism and the story ──
    "lat-q2": [
      {
        kind: "intercept",
        title: "Same Mechanism, Different Story",
        prompt: "Tamsin's overnight hunt came back with ten hits across Corvid. Every mechanism on the list appears twice. Read where each one came from, then escalate it or clear it before it lands.",
        protect: "the hunt queue",
        blockLabel: "Escalate",
        passLabel: "Clear",
        seconds: 12,
        primer: {
          title: "Reading past the mechanism",
          points: [
            "The mechanism tells you what happened, and it reads the same whoever is behind it.",
            "Ask where it came from: is this host normally used for this kind of work?",
            "Ask who asked for it: does an open request name this host?",
            "Ask when: does the hour fit the person's job?",
          ],
          example: {
            label: "One badge, two nights",
            lines: [
              "A cleaner's badge opens the server room at 21:00. It's on the cleaning rota.",
              "The same badge opens it at 03:40. No rota entry, and the cleaner is abroad.",
              "The door log reads the same both times. The rota is what separates them.",
            ],
          },
          fold: true,
        },
        items: [
          { id: "i1", text: "WmiPrvSE.exe starts cmd.exe on CC-INV-02, Kerberos logon", sub: "From CC-MGMT-01, change CHG-5190 open, day shift", bad: false, why: "IT's management workstation, inside a change that names this host, in working hours." },
          { id: "i2", text: "WmiPrvSE.exe starts cmd.exe on CC-PAY-01, Kerberos logon", sub: "From a warehouse kiosk, first time in the logs, 04:10 Sunday, no change", bad: true, why: "A kiosk has no reason to run commands on a payment server, and nobody asked for this." },
          { id: "i3", text: "wsmprovhost.exe starts powershell.exe on CC-FIN-02", sub: "From CC-MGMT-01, weekly inventory, same hour for a year", bad: false, why: "A year of the same source at the same hour, doing the same job." },
          { id: "i4", text: "wsmprovhost.exe starts powershell.exe on CC-DISP-02", sub: "From the label print server, never seen before, no ticket", bad: true, why: "A print server has never administered this host, and no request explains it." },
          { id: "i5", text: "4624 LogonType 10 on CC-PATCH-01, NTLM", sub: "From the vendor's support host, agreed window, ticket SUP-771", bad: false, why: "The vendor, the window and the ticket all line up." },
          { id: "i6", text: "4624 LogonType 10 on CC-BACKUP-02, NTLM", sub: "From a dispatch PC, 02:50, account owner on leave", bad: true, why: "The wrong source, at the wrong hour, with an account whose owner isn't at work." },
          { id: "i7", text: "4698 scheduled task created on CC-CAM-01", sub: "From CC-PATCH-01, monthly change, task name in the runbook", bad: false, why: "The monthly change and the runbook both describe this exact task." },
          { id: "i8", text: "4698 scheduled task created on CC-INV-02", sub: "From a laptop in Accounts, no admin history, runs from C:\\Users\\Public", bad: true, why: "An Accounts laptop has never done admin work, and nothing asked for this task." },
          { id: "i9", text: "NTLM network logon, C$ opened on CC-DISP-02", sub: "From the help desk PC, ticket INC-3307 raised earlier by CC-DISP-02's user", bad: false, why: "A support ticket from the user of this machine, and the connection comes from the help desk." },
          { id: "i10", text: "NTLM network logon, C$ opened on CC-PAY-01", sub: "From a test VM nobody owns, 03:20, no ticket", bad: true, why: "No owner, no ticket, and an hour that fits nobody's job." },
        ],
        lesson: "Each mechanism came up twice and went both ways. What moved the call was never inside the record: it was the machine it came from, the request behind it, and the hour.",
      },
    ],
    // ── Analyst choice warm-up: the words for a verdict ──
    "lat-ac1": [
      {
        kind: "sort",
        title: "Name the Verdict",
        prompt: "Six closed alerts from other Corvid rules. Before you close another one yourself, sort these by the word each one earned.",
        primer: {
          title: "Three verdicts",
          points: [
            "Start with the rule: did the thing it describes really happen?",
            "**True Positive:** it happened, and it was an attack.",
            "**Benign True Positive:** it happened, and the activity was real but authorized.",
            "**False Positive:** the rule fired, and the thing it describes never happened.",
          ],
          example: {
            label: "One smoke alarm",
            lines: [
              "Alarm rings, the bin is on fire: True Positive.",
              "Alarm rings during a booked fire drill with a smoke machine: Benign True Positive.",
              "Alarm rings, no smoke anywhere, a loose wire in the sensor: False Positive.",
            ],
          },
          fold: true,
        },
        buckets: [
          { id: "tp", label: "True Positive" },
          { id: "btp", label: "Benign True Positive" },
          { id: "fp", label: "False Positive" },
        ],
        items: [
          { id: "v1", text: "Rule: new member in a local Administrators group. IT added a contractor to CC-DISP-02 for a booked two-week project, and the change record matches.", bucket: "btp", why: "A member really was added, so the rule did its job. The addition was approved." },
          { id: "v2", text: "Rule: bulk read of a file share. The backup account reads the share at 02:00 on schedule, from the backup server.", bucket: "btp", why: "The bulk read really happened. It's the job the account exists for." },
          { id: "v3", text: "Rule: encoded PowerShell. The match is a wiki page saved as a text file that contains the string -EncodedCommand. PowerShell never ran.", bucket: "fp", why: "The rule matched some text. The behaviour it describes never took place." },
          { id: "v4", text: "Rule: impossible travel. Both addresses are exits of Corvid's own VPN, and the user never left the depot.", bucket: "fp", why: "Nobody travelled. The rule misread two exits of one VPN as two places." },
          { id: "v5", text: "Rule: process opened lsass.exe. An unsigned binary in C:\\Users\\Public on a dock laptop, with no tool or job behind it.", bucket: "tp", why: "It happened, and nothing legitimate explains it." },
          { id: "v6", text: "Rule: password spray. 400 accounts tried from one outside address, then one success followed by a new inbox rule.", bucket: "tp", why: "It happened, and the success was put to use." },
        ],
      },
    ],
    // ── Matching warm-up: what each door leaves behind ──
    "lat-m1": [
      {
        kind: "inspect",
        title: "Six Doors, Six Footprints",
        prompt: "Tamsin's reference sheet from the purple-team exercise holds one record per technique. Tap each line and read what that technique leaves behind on the target.",
        artifact: "Purple-team log sheet · CC-LAB-07 · one record per technique",
        items: [
          { id: "smb", text: "System 7045  ServiceName: advupd  ImagePath: C:\\Windows\\advupd.exe", tag: "SMB, remote service", tone: "warn", note: "Came in on TCP 445. The lasting trace of this door is in the System log." },
          { id: "rdp", text: "Security 4624  LogonType: 10  LogonProcessName: User32", tag: "RDP", tone: "info", note: "TCP 3389. LogonType 10 is RemoteInteractive: someone is looking at the remote desktop." },
          { id: "wmi", text: "Sysmon 1  ParentImage: C:\\Windows\\System32\\wbem\\WmiPrvSE.exe  Image: cmd.exe", tag: "WMI", tone: "warn", note: "Opens on the RPC port, 135, then moves to a port picked on the fly. The command runs as a child of the WMI provider host." },
          { id: "winrm", text: "Sysmon 1  ParentImage: C:\\Windows\\System32\\wsmprovhost.exe  Image: whoami.exe", tag: "WinRM", tone: "warn", note: "Port 5985 runs over HTTP with the content encrypted at message level after authentication, 5986 wraps it in TLS. wsmprovhost.exe hosts the PowerShell Remoting session on the target." },
          { id: "task", text: "Security 4698  TaskName: \\advupd  Author: CORVID\\adm-test", tag: "Scheduled task", tone: "info", note: "Written when a task is registered. The Task Scheduler runs it later, so the logon and the execution can sit far apart." },
          { id: "dcom", text: "Sysmon 1  ParentImage: C:\\Windows\\System32\\mmc.exe  Image: cmd.exe", tag: "DCOM", tone: "info", note: "Also RPC, through a COM object such as MMC20.Application. The parent is the application that hosts the object." },
        ],
      },
    ],
    // ── Ordering warm-up: clocks, then the map ──
    "lat-o1": [
      {
        kind: "worksheet",
        title: "Put Every Clock on UTC",
        prompt: "Before the map, a clock check. The SIEM holds four records from Friday night's patch job, each from a different host, stamped the way that host's forwarder sends time and listed by when they arrived. Work out what really happened when.",
        primer: {
          title: "Clocks before order",
          points: [
            "Forwarders stamp time differently: some send UTC, some send local time with an offset.",
            "To reach UTC, **subtract the offset**. A negative offset means you add.",
            "A local stamp can sit on a different calendar day from the same moment in UTC.",
            "The SIEM's received time is arrival order. It says nothing about event order.",
            "Check the result against cause: a session has to exist before anything can use it.",
          ],
          example: {
            label: "Two stamps from another fleet",
            lines: [
              "`08:10 +05:30` minus 5 h 30 is `02:40 UTC`.",
              "`21:50 -08:00` plus 8 h is `05:50 UTC`, on the next calendar day.",
              "Two clocks, one scale: only the UTC values can be compared.",
            ],
          },
          fold: true,
        },
        caption: "SIEM · CHG-5233 · sorted by received time",
        columns: ["Received", "Host", "Stamp as forwarded", "Record"],
        rows: [
          ["00:31:02", "CC-SCALE-05", "2026-09-18 19:05 -05:00", "Patch agent installs update"],
          ["00:31:05", "CC-PATCH-01", "2026-09-18 23:40 UTC", "Patch job starts"],
          ["00:31:09", "CC-INV-02", "2026-09-19 02:20 +02:00", "Patch agent reports complete"],
          ["00:31:14", "CC-DISP-02", "2026-09-19 01:52 +02:00", "Patch agent starts download"],
        ],
        questions: [
          { id: "utc", q: "What is CC-SCALE-05's stamp in UTC? (HH:MM)", hint: "A negative offset: add it.", answer: ["00:05", "0:05"], why: "19:05 plus 5 hours is 00:05, and that is already Saturday in UTC." },
          { id: "first", q: "Which host's record really happened first?", hint: "Convert all four before you compare.", answer: ["CC-PATCH-01", "cc-patch-01", "patch-01"], why: "23:40 UTC, then 23:52, 00:05 and 00:20. The job starts before the agents act, which is the order cause expects." },
          { id: "place", q: "The SIEM received CC-SCALE-05's record first. What is its true place, 1 to 4?", hint: "Use the UTC order you just built.", answer: ["3", "third"], why: "Third. First to arrive only means its forwarder sent it soonest." },
          { id: "span", q: "How many minutes from the first event to the last?", hint: "Work in UTC across midnight.", answer: ["40"], why: "23:40 to 00:20 is 40 minutes, and the received times span only 12 seconds." },
        ],
      },
      {
        kind: "pathway",
        title: "Rebuild the Graph",
        prompt: "Each host's card shows an inbound record from the night, stamped the way its forwarder sent it. Walk the true route from the dock laptop to CC-TEMPLOG-01, one hop at a time.",
        goal: "Reach CC-TEMPLOG-01 by the true route",
        primer: {
          title: "What counts as a hop",
          points: [
            "A hop is a **successful** inbound logon whose source is the host you are standing on.",
            "It must land after you arrived there, compared in UTC.",
            "A `4625` records a failed logon: no session opens.",
            "A `4776` on a domain controller records a credential check: the session itself lands somewhere else.",
          ],
          example: {
            label: "Three hosts on a test bench",
            lines: [
              "You reach `BENCH-A` at `10:00 UTC`.",
              "`BENCH-B` shows a logon from `BENCH-A` at `09:30 UTC`: too early to be your hop.",
              "`BENCH-C` shows a logon from `BENCH-A` at `14:15 +04:00`, which is `10:15 UTC`: that one follows.",
            ],
          },
          fold: true,
        },
        nodes: [
          { id: "dock", label: "CC-DOCK-LT12", sub: "Start 03:12 +02:00", x: 12, y: 56 },
          { id: "hr", label: "CC-HR-LT03", sub: "In 01:05 +02:00 from CC-DOCK-LT12", x: 14, y: 18 },
          { id: "label", label: "CC-LABEL-02", sub: "In 03:26 +02:00 from CC-DOCK-LT12", x: 37, y: 44 },
          { id: "patch", label: "CC-PATCH-01", sub: "Failed 03:31 +02:00 from CC-LABEL-02", x: 38, y: 13 },
          { id: "dc", label: "CC-DC01", sub: "4776 checks from every host", x: 35, y: 86 },
          { id: "mgmt", label: "CC-MGMT-01", sub: "Console logons only", x: 62, y: 14 },
          { id: "route", label: "CC-ROUTE-03", sub: "In 20:44 -05:00 from CC-LABEL-02", x: 60, y: 60 },
          { id: "backup", label: "CC-BACKUP-02", sub: "In 00:20 UTC from CC-ROUTE-03", x: 62, y: 88 },
          { id: "wms", label: "CC-WMS-01", sub: "In 01:58 UTC from CC-ROUTE-03", x: 85, y: 64 },
          { id: "templog", label: "CC-TEMPLOG-01", sub: "In 02:11 UTC from CC-WMS-01", x: 86, y: 24 },
        ],
        edges: [
          ["dock", "hr"], ["dock", "label"], ["dock", "dc"],
          ["label", "patch"], ["label", "mgmt"], ["label", "route"], ["label", "dc"],
          ["route", "backup"], ["route", "wms"], ["route", "dc"],
          ["wms", "mgmt"], ["wms", "templog"], ["mgmt", "templog"],
        ],
        route: ["dock", "label", "route", "wms", "templog"],
        notes: {
          dock: "adm-k.sorel first appears here at 03:12 +02:00, which is 01:12 UTC. Every hop from here lands later than that.",
          label: "4624 on CC-LABEL-02: LogonType 3, IpAddress 10.44.12.31, stamped 03:26 +02:00, which is 01:26 UTC.",
          route: "4624 on CC-ROUTE-03: LogonType 3, IpAddress 10.44.20.12, stamped 20:44 -05:00, which is 01:44 UTC. Locally it's still Friday evening.",
          wms: "4624 on CC-WMS-01: LogonType 10, IpAddress 10.44.20.18, stamped 01:58 UTC.",
          templog: "4624 on CC-TEMPLOG-01: LogonType 3, IpAddress 10.44.20.15, stamped 02:11 UTC, then wsmprovhost.exe as a parent process. The changed file follows three minutes later.",
        },
        traps: {
          hr: "01:05 +02:00 is 23:05 UTC on Friday, two hours before adm-k.sorel appears on the dock laptop. A logon that came first can't be the next hop.",
          dc: "CC-DC01 checks credentials for every host on this map. A 4776 there is a check, and no session landed on it.",
          patch: "That record is a 4625, a failed logon. No session opened, so nothing carried on from CC-PATCH-01.",
          mgmt: "CC-MGMT-01 shows console logons only: people sitting at it. No remote session landed there.",
          backup: "00:20 UTC is 84 minutes before anyone reached CC-ROUTE-03 at 01:44 UTC. It only looks later than 20:44 until both are on one clock.",
        },
        lesson: "A map comes from one rule applied every time: a successful logon, from the host you're on, later in UTC than your arrival. Failed logons, credential checks and earlier sessions stay off the route. Four hops, three clock offsets, and no single host could have shown you this.",
      },
    ],
    // ── Query warm-up: find the pivot ──
    "lat-qf1": [
      {
        kind: "hunt",
        title: "Find the Pivot Host",
        prompt: "The map is drawn by hand, and Tamsin wants it from a query that will still work next month. Find the host that reached CC-TEMPLOG-01 on a session that itself came from somewhere else. Build it one line at a time. Every result you see is really what that line returns.",
        language: "KQL",
        start: "DeviceNetworkEvents",
        goal: "one row: the pivot host, and where its session came from",
        primer: {
          title: "In, then out",
          points: [
            "A **pivot host** is one the intruder arrived on and then left from. It takes two records to show that: the way in and the way out.",
            "`DeviceNetworkEvents` holds both directions, and `ActionType` tells them apart: `ConnectionSuccess` going out, `InboundConnectionAccepted` coming in. Every row here is outbound. `DeviceLogonEvents` is written by the host being signed in to.",
            "A process ID or a logon session only means something on one machine, and a domain account turns up on many, so a good join key **includes the device**.",
            "In this table `LogonType` is a word: `Network`, `RemoteInteractive`, `Interactive`, `Service`.",
            "After a join, a right-hand column that clashes gains a 1, so the logon's time becomes `Timestamp1`.",
          ],
          example: {
            label: "A device-safe join on two other tables",
            lines: [
              "`DeviceFileEvents`",
              "`| join kind=inner DeviceProcessEvents on DeviceName, $left.InitiatingProcessId == $right.ProcessId`",
              "For each file written, this finds the process on that same device that wrote it. On the process ID alone, a number reused on another device would match too.",
            ],
          },
          fold: true,
        },
        tables: [
          {
            name: "DeviceNetworkEvents",
            note: "Network connections on a device. Every row here is outbound.",
            columns: ["Timestamp", "DeviceName", "RemoteIP", "RemotePort", "InitiatingProcessFileName", "InitiatingProcessAccountName"],
            rows: [
              ["09-17 14:12:40", "cc-mgmt-01", "10.44.30.5", "5985", "powershell.exe", "adm-k.sorel"],
              ["09-18 23:44:10", "cc-patch-01", "10.44.30.5", "445", "patchagent.exe", "svc_patch"],
              ["09-19 00:05:00", "cc-backup-02", "10.44.30.5", "9102", "backupagent.exe", "svc_backup"],
              ["09-19 01:50:31", "cc-route-03", "10.44.30.5", "443", "truckfeed.exe", "svc_route"],
              ["09-19 01:58:44", "cc-wms-01", "10.44.20.30", "1433", "wmsengine.exe", "svc_wms"],
              ["09-19 02:11:02", "cc-wms-01", "10.44.30.5", "5985", "powershell.exe", "adm-k.sorel"],
              ["09-19 02:13:15", "cc-templog-01", "10.44.30.9", "514", "logforward.exe", "svc_temp"],
            ],
          },
          {
            name: "DeviceLogonEvents",
            note: "Sign-ins on a device, recorded by that device.",
            columns: ["Timestamp", "DeviceName", "ActionType", "LogonType", "AccountName", "RemoteDeviceName", "RemoteIP"],
            rows: [
              ["09-17 13:20:02", "cc-mgmt-01", "LogonSuccess", "Unlock", "adm-k.sorel", "-", "-"],
              ["09-17 13:58:11", "cc-mgmt-01", "LogonSuccess", "Interactive", "adm-k.sorel", "-", "-"],
              ["09-18 22:00:01", "cc-patch-01", "LogonSuccess", "Service", "svc_patch", "-", "-"],
              ["09-19 01:26:08", "cc-label-02", "LogonSuccess", "Network", "adm-k.sorel", "cc-dock-lt12", "10.44.12.31"],
              ["09-19 01:31:17", "cc-patch-01", "LogonFailed", "Network", "svc_patch", "cc-label-02", "10.44.20.12"],
              ["09-19 01:44:02", "cc-route-03", "LogonSuccess", "Network", "adm-k.sorel", "cc-label-02", "10.44.20.12"],
              ["09-19 01:58:07", "cc-wms-01", "LogonSuccess", "RemoteInteractive", "adm-k.sorel", "cc-route-03", "10.44.20.18"],
              ["09-19 01:58:40", "cc-wms-01", "LogonSuccess", "Service", "svc_wms", "-", "-"],
            ],
          },
          {
            name: "DeviceProcessEvents",
            note: "Process creation.",
            columns: ["Timestamp", "DeviceName", "FileName", "ProcessCommandLine", "InitiatingProcessFileName"],
            rows: [
              ["09-19 02:09:50", "cc-wms-01", "powershell.exe", "powershell.exe -nop", "explorer.exe"],
              ["09-19 02:12:30", "cc-templog-01", "powershell.exe", "powershell.exe -nop", "wsmprovhost.exe"],
              ["09-18 23:44:02", "cc-patch-01", "patchagent.exe", "patchagent.exe /push", "services.exe"],
            ],
          },
        ],
        rungs: [
          {
            id: "dest", ask: "Line 2: keep the connections that reached CC-TEMPLOG-01, at 10.44.30.5.",
            choices: [
              { id: "a", text: '| where DeviceName =~ "cc-templog-01"', why: "Those are connections the server opened itself. This table holds both directions, ActionType tells them apart, and every row here is outbound, so search on the address each host reached.", apply: { op: "where", col: "DeviceName", test: "ieq", value: "cc-templog-01" } },
              { id: "b", text: '| where RemoteIP has "10.44"', why: "That's the whole internal range, so every row stayed.", apply: { op: "where", col: "RemoteIP", test: "has", value: "10.44" } },
              { id: "c", text: '| where RemoteIP == "10.44.30.5"', right: true, why: "RemoteIP is the far end of the connection. Five hosts have talked to this server.", apply: { op: "where", col: "RemoteIP", test: "eq", value: "10.44.30.5" } },
            ],
          },
          {
            id: "port", ask: "Line 3: keep only the ports people use to administer a machine.",
            choices: [
              { id: "a", text: "| where RemotePort == 445", why: "SMB alone. WMI, RDP and WinRM use other ports, so the rows you need went with them.", apply: { op: "where", col: "RemotePort", test: "eq", value: "445" } },
              { id: "b", text: "| where RemotePort in (135, 445, 3389, 5985, 5986)", right: true, why: "The admin doors in one list: RPC, SMB, RDP and WinRM. The backup agent and the truck feed drop out.", apply: { op: "where", col: "RemotePort", test: "in", value: ["135", "445", "3389", "5985", "5986"] } },
              { id: "c", text: "| where RemotePort == 443", why: "That's the truck feed's HTTPS. Ordinary application traffic, on a port nobody administers a server through.", apply: { op: "where", col: "RemotePort", test: "eq", value: "443" } },
            ],
          },
          {
            id: "join", ask: "Line 4: this table shows the way out. Bring in the way in, for the same account on the same device.",
            choices: [
              { id: "a", text: "| join kind=inner DeviceLogonEvents on DeviceName", why: "Every logon on those hosts came along, whoever it belonged to. Match the account too.", apply: { op: "join", table: "DeviceLogonEvents", left: "DeviceName", right: "DeviceName" } },
              { id: "b", text: "| join kind=inner DeviceLogonEvents on $left.InitiatingProcessAccountName == $right.AccountName", why: "This account logged on at several hosts, and all of them matched. An account isn't a location: add the device.", apply: { op: "join", table: "DeviceLogonEvents", left: "InitiatingProcessAccountName", right: "AccountName" } },
              { id: "c", text: "| join kind=inner DeviceProcessEvents on DeviceName", why: "That says what ran on the host, not how the account got there. You need the table that records arrivals.", apply: { op: "join", table: "DeviceProcessEvents", left: "DeviceName", right: "DeviceName" } },
              { id: "d", text: "| join kind=inner DeviceLogonEvents on DeviceName, $left.InitiatingProcessAccountName == $right.AccountName", right: true, why: "Each connection now sits next to the logons of the same account on the same device. The two tables name that account differently, so the keys are spelled out.", apply: { op: "join", table: "DeviceLogonEvents", left: "InitiatingProcessAccountName", right: "AccountName", also: "DeviceName" } },
            ],
          },
          {
            id: "arrive", ask: "Line 5: a pivot's session came from another machine. Filter on how the account arrived.",
            choices: [
              { id: "a", text: '| where LogonType == "Interactive"', why: "That's someone at the keyboard, which is the opposite of arriving from elsewhere.", apply: { op: "where", col: "LogonType", test: "eq", value: "Interactive" } },
              { id: "b", text: '| where LogonType in ("Network", "RemoteInteractive")', right: true, why: "Both words mean the session came from another machine: Network for shares, services and WMI, RemoteInteractive for RDP.", apply: { op: "where", col: "LogonType", test: "in", value: ["Network", "RemoteInteractive"] } },
              { id: "c", text: '| where LogonType == "Network"', why: "RDP arrives as RemoteInteractive, so this leaves out a whole way of moving.", apply: { op: "where", col: "LogonType", test: "eq", value: "Network" } },
            ],
          },
          {
            id: "ok", ask: "Line 6: two rows left. A session has to exist to go anywhere.",
            choices: [
              { id: "a", text: '| where ActionType == "LogonSuccess"', right: true, why: "A failed logon opens no session, so it can't explain a connection out. One row is left.", apply: { op: "where", col: "ActionType", test: "eq", value: "LogonSuccess" } },
              { id: "b", text: '| where ActionType == "LogonFailed"', why: "That keeps the failure and drops the session. CC-PATCH-01's connection came from its own agent.", apply: { op: "where", col: "ActionType", test: "eq", value: "LogonFailed" } },
              { id: "c", text: '| where AccountName =~ "svc_patch"', why: "Choosing by a name you can see won't work tomorrow. Filter on what the row means.", apply: { op: "where", col: "AccountName", test: "ieq", value: "svc_patch" } },
            ],
          },
          {
            id: "show", ask: "Line 7: show what the map needs. The logon's own time is now Timestamp1.",
            choices: [
              { id: "a", text: "| project DeviceName, RemoteIP, RemotePort", why: "That's where the session went. The map also needs where it came from.", apply: { op: "project", cols: ["DeviceName", "RemoteIP", "RemotePort"] } },
              { id: "b", text: "| project Timestamp1, RemoteDeviceName, DeviceName, AccountName, Timestamp, RemoteIP", right: true, why: "One row, read left to right: when it arrived, from where, the pivot, the account, when it left, and where to.", apply: { op: "project", cols: ["Timestamp1", "RemoteDeviceName", "DeviceName", "AccountName", "Timestamp", "RemoteIP"] } },
              { id: "c", text: "| summarize count() by DeviceName", why: "A count tells you how many. The map needs the two ends of the session.", apply: { op: "summarize", by: ["DeviceName"] } },
            ],
          },
        ],
        expect: 1,
        lesson: "Start from the way out, join to the way in on the device and the account, keep the arrivals that came from another machine and that succeeded. On a real fleet, start with `| where ActionType == \"ConnectionSuccess\"` so that only outbound rows go in, which makes the logon's result ActionType1 after the join. This console has no time test, so add one too: `| where Timestamp1 < Timestamp`, because only a logon before the connection can explain it. Keep a Timestamp limit on both tables, and expect jump hosts in the results, since they arrive and leave all day.",
      },
    ],
  },
};
