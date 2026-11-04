import type { RoomExperience } from "./types";

// "Operation Keystone" for the "active-directory" room.
// Script: docs/campaign/34-active-directory.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Rookwood County Council (fictional), not the graded tasks' Contoso. Lab data
// differs from the graded tasks: the directory console never shows group
// categories (q4); the klist console shows healthy AES tickets and never says
// which key encrypts a service ticket (q2) or what RC4 means (q3, la1); the DC
// console is about a new account and a cleared log, never DCSync (q5) or the
// krbtgt key (q6); the pre-auth console lists flagged accounts but never reads
// a 4768 or PreAuthType (q7); and the logon sheet is a different subnet,
// user and addresses than la2 and flag2.
export const ACTIVE_DIRECTORY: RoomExperience = {
  roomId: "active-directory",
  codename: "Operation Keystone",
  theme: "ad",
  handler: { name: "Femi Adeyemi", role: "Identity Security Engineer, Rookwood County Council" },
  briefing: [
    "Rookwood County Council. Schools, social care, bin lorries and 4,200 staff, all signing in to one domain: ROOKWOOD.",
    "Two neighbouring councils were hit this year. In both, the attackers went straight for Active Directory, and once they owned it they owned everything.",
    "Femi Adeyemi secures identity at Rookwood. Every attack on AD leaves a trace on the domain controllers, if you know which event to read.",
    "Learn how the directory is built, follow a Kerberos ticket, then hunt the attacks that target it: roasting, DCSync, forged tickets and relays.",
  ],
  mission: "Map Rookwood's forest, domains and controllers, read a workstation's Kerberos tickets, catch a new admin account and a cleared log on a DC, find accounts that skip pre-authentication, and spot a logon whose name and address don't match.",
  estimate: "~60 min",
  look: { primary: "#22d3ee", secondary: "#a3e635", warn: "#fb7185" },
  scene: "domaintree",
  layout: "stage",
  stations: [
    {
      id: "directory",
      label: "The Directory",
      topic: "Domain controllers · forest, domain, OU · users, computers, groups · GPOs and trusts",
      tagline: "Map the domain before you defend it",
      building: "control",
      taskIds: ["ad-r1", "ad-q1", "ad-q4"],
    },
    {
      id: "kerberos",
      label: "Kerberos Flow",
      topic: "AS-REQ, TGT, TGS, service ticket · 4768 and 4769 · LDAP",
      tagline: "Follow the wristband",
      building: "lab",
      taskIds: ["ad-r2", "ad-q2"],
    },
    {
      id: "roast",
      label: "Kerberoast",
      topic: "PtH, PtT, Kerberoasting · what to monitor on a DC",
      tagline: "Catch the ticket nobody needed",
      building: "office",
      taskIds: ["ad-r3", "ad-q3", "ad-la1", "ad-flag1"],
    },
    {
      id: "jewels",
      label: "Crown Jewels",
      topic: "DCSync, Golden Ticket · AS-REP Roasting",
      tagline: "Guard the keys to every account",
      building: "vault",
      taskIds: ["ad-q5", "ad-q6", "ad-r4", "ad-q7"],
    },
    {
      id: "relay",
      label: "Relay and Verdict",
      topic: "LLMNR/NBT-NS poisoning · NTLM relay · a privileged logon to the DC",
      tagline: "Borrowed logons and a 3 a.m. session",
      building: "ticket",
      taskIds: ["ad-r5", "ad-la2", "ad-flag2", "ad-ac1"],
      boss: true,
    },
  ],
  personas: {
    "ad-q2": { name: "Femi Adeyemi", role: "Identity Security Engineer", line: "The KDC hands back a ticket for FS01. Who can actually read it?" },
    "ad-la1": { name: "Femi Adeyemi", role: "Identity Security Engineer", line: "A user asked for a backup account's ticket at 2 a.m. Read it with me." },
    "ad-q5": { name: "Femi Adeyemi", role: "Identity Security Engineer", line: "svc-backup asking a DC for replication rights. Normal?" },
    "ad-q7": { name: "Femi Adeyemi", role: "Identity Security Engineer", line: "PreAuthType 0 on a print account. Why does that worry me?" },
    "ad-la2": { name: "Femi Adeyemi", role: "Identity Security Engineer", line: "An LLMNR burst, then an NTLM logon. Check the name against the address." },
    "ad-ac1": { name: "Femi Adeyemi", role: "Identity Security Engineer", line: "A privileged RDP session on DC01 at 03:12. Your call." },
  },
  briefings: {
    // ── Reading 1: the directory ──
    "ad-r1": [
      {
        kind: "terminal",
        title: "Map the Domain",
        prompt: "You have a read-only seat on ADM-WS-02 with the ActiveDirectory module. Map Rookwood before anything else.",
        shell: "powershell",
        host: "PS C:\\> ",
        commands: [
          { match: "get-adforest.*", help: "Get-ADForest   the outer boundary",
            output: "Name               : rookwood.example\nRootDomain         : rookwood.example\nDomains            : {rookwood.example, schools.rookwood.example}\nForestMode         : Windows2016Forest\nGlobalCatalogs     : {RKW-DC01.rookwood.example, RKW-DC02.rookwood.example, SCH-DC01.schools.rookwood.example}" },
          { match: "get-addomaincontroller\\s+-filter\\s+\\*.*", help: "Get-ADDomainController -Filter * | Select-Object Name, Site, IsGlobalCatalog",
            output: "Name     Site        IsGlobalCatalog\n----     ----        ---------------\nRKW-DC01 CountyHall  True\nRKW-DC02 Depot-North True" },
          { match: "get-adorganizationalunit.*", help: "Get-ADOrganizationalUnit -Filter * | Select-Object Name",
            output: "Name\n----\nDomain Controllers\nCounty Hall\nSocial Care\nHighways\nServers\nService Accounts\nLeavers" },
          { match: "get-adtrust.*", help: "Get-ADTrust -Filter * | Select-Object Target, Direction, ForestTransitive",
            output: "Target                     Direction     ForestTransitive\n------                     ---------     ----------------\nschools.rookwood.example   BiDirectional False\nhalden-shared.example      Outbound      True" },
          { match: "get-gpinheritance.*social.*|get-gpo.*", help: "Get-GPInheritance -Target \"OU=Social Care,DC=rookwood,DC=example\"",
            output: "GpoLinks\n--------\nSC - Lock screen 5 min\nSC - Block USB storage\nAll Staff - Password policy" },
        ],
        objectives: [
          { id: "dcs", task: "How many domain controllers serve rookwood.example?", hint: "Get-ADDomainController -Filter *", answer: ["2", "two"], why: "Two, at two sites. Lose both and nobody signs in. Own one and you own the domain." },
          { id: "child", task: "Which other domain lives in the same forest?", hint: "Get-ADForest", answer: ["schools.rookwood.example", "schools"], why: "The schools domain shares the forest, the schema and the global catalogue. A weak school PC is a path into the council." },
          { id: "usb", task: "Which GPO linked to Social Care controls removable drives?", hint: "Get-GPInheritance on the Social Care OU", answer: ["sc - block usb storage", "block usb storage"], why: "GPOs land on OUs. Whoever can edit that GPO can change every Social Care machine at once." },
        ],
      },
    ],
    // ── Reading 2: Kerberos ──
    "ad-r2": [
      {
        kind: "terminal",
        title: "Read the Wristbands",
        prompt: "On k.boateng's laptop in Social Care, right after sign-in and opening the case-file share. List the Kerberos tickets the session holds.",
        shell: "cmd",
        host: "C:\\Users\\k.boateng> ",
        commands: [
          { match: "^klist\\s*$", help: "klist   every ticket in this logon session",
            output: "Current LogonId is 0:0x5a3f21\n\nCached Tickets: (2)\n\n#0>     Client: k.boateng @ ROOKWOOD.EXAMPLE\n        Server: krbtgt/ROOKWOOD.EXAMPLE @ ROOKWOOD.EXAMPLE\n        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96\n        Start Time: 11/4/2026 8:02:11\n        End Time:   11/4/2026 18:02:11\n        Renew Time: 11/11/2026 8:02:11\n        Kdc Called: RKW-DC01.rookwood.example\n\n#1>     Client: k.boateng @ ROOKWOOD.EXAMPLE\n        Server: cifs/RKW-FS03.rookwood.example @ ROOKWOOD.EXAMPLE\n        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96\n        Start Time: 11/4/2026 8:06:40\n        End Time:   11/4/2026 18:02:11\n        Kdc Called: RKW-DC01.rookwood.example" },
          { match: "klist\\s+tgt.*", help: "klist tgt   details of the ticket-granting ticket",
            output: "Cached TGT:\n\nServiceName        : krbtgt\nTargetName (SPN)   : krbtgt\nDomainName         : ROOKWOOD.EXAMPLE\nTargetDomainName   : ROOKWOOD.EXAMPLE\nKeyLength          : 32\nStartTime          : 11/4/2026 8:02:11\nEndTime            : 11/4/2026 18:02:11" },
          { match: "nltest\\s+/dsgetdc:.*", help: "nltest /dsgetdc:rookwood.example   which DC this laptop uses",
            output: "           DC: \\\\RKW-DC01.rookwood.example\n      Address: \\\\10.40.0.11\n     Dom Name: rookwood.example\n  Forest Name: rookwood.example\n Dc Site Name: CountyHall\nThe command completed successfully" },
        ],
        objectives: [
          { id: "tgt", task: "Which ticket is the TGT, the wristband? (its Server name)", hint: "klist: one ticket is for the KDC itself", answer: ["krbtgt", "krbtgt/rookwood.example"], why: "A ticket for krbtgt is the ticket-granting ticket. Everything else is bought with it." },
          { id: "svc", task: "Which service did the second ticket open?", hint: "Look at ticket #1's Server line", answer: ["cifs/rkw-fs03.rookwood.example", "cifs/rkw-fs03", "rkw-fs03", "cifs"], why: "cifs is file sharing: the case-file share on RKW-FS03, bought four minutes after sign-in." },
          { id: "hours", task: "How many hours is the TGT valid for?", hint: "Start Time to End Time", answer: ["10", "ten"], why: "08:02 to 18:02: the default ten hours, renewable for a week." },
        ],
      },
    ],
    // ── Reading 3: monitoring the DC ──
    "ad-r3": [
      {
        kind: "terminal",
        title: "Night on the DC",
        prompt: "RKW-DC02 at the depot. Monitoring flagged account changes overnight. Pull the events from the reading's watch list.",
        shell: "powershell",
        host: "PS C:\\> ",
        commands: [
          { match: "get-winevent\\s+-filterhashtable\\s+.*4720.*", help: "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4720} -MaxEvents 5   user created",
            output: "TimeCreated          Id   Message\n-----------          --   -------\n11/4/2026 01:47:09  4720 A user account was created.\n                          Subject:     hwy.temp04\n                          New Account: svc_mon2" },
          { match: "get-winevent\\s+-filterhashtable\\s+.*(4728|4732).*", help: "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4728,4732} -MaxEvents 5   added to a group",
            output: "TimeCreated          Id   Message\n-----------          --   -------\n11/4/2026 01:48:22  4728 A member was added to a security-enabled global group.\n                          Subject: hwy.temp04\n                          Member:  CN=svc_mon2,OU=Highways,DC=rookwood,DC=example\n                          Group:   Domain Admins" },
          { match: "get-winevent\\s+-filterhashtable\\s+.*1102.*", help: "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102}   audit log cleared",
            output: "TimeCreated          Id   Message\n-----------          --   -------\n11/4/2026 01:52:40  1102 The audit log was cleared.\n                          Subject: svc_mon2" },
          { match: "get-aduser\\s+hwy\\.temp04.*", help: "Get-ADUser hwy.temp04 -Properties MemberOf, whenCreated, Description",
            output: "Name        : hwy.temp04\nDescription : Highways seasonal contractor (gritting), ends 31/03\nwhenCreated : 10/20/2026 09:14:02\nMemberOf    : {CN=Highways Ops,OU=Highways,...; CN=Account Operators,CN=Builtin,...}" },
        ],
        objectives: [
          { id: "new", task: "Which account was created overnight?", hint: "Event 4720", answer: ["svc_mon2"], why: "A 'service' account created at 01:47 by a contractor account. Any new account is worth verifying; this one doubly so." },
          { id: "group", task: "Which group was it added to a minute later?", hint: "Events 4728 / 4732", answer: ["domain admins"], why: "Straight into Domain Admins. Then, five minutes later, the new account cleared the log: 1102." },
          { id: "why", task: "Which built-in group let a gritting contractor create accounts at all?", hint: "Get-ADUser hwy.temp04 -Properties MemberOf", answer: ["account operators"], why: "Account Operators can create and modify most accounts. Poor hygiene turned one phished contractor into a domain admin." },
        ],
      },
    ],
    // ── Reading 4: AS-REP roasting ──
    "ad-r4": [
      {
        kind: "terminal",
        title: "No Pre-Auth",
        prompt: "Femi wants a sweep: which Rookwood accounts would hand out an AS-REP to anyone who asks?",
        shell: "powershell",
        host: "PS C:\\> ",
        commands: [
          { match: "get-aduser\\s+-filter\\s+.*doesnotrequirepreauth.*", help: "Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties PasswordLastSet, Enabled | Select-Object Name, Enabled, PasswordLastSet",
            output: "Name             Enabled PasswordLastSet\n----             ------- ---------------\nsvc-cctv-legacy  True    3/2/2017 10:41:55\nj.price.old      False   6/15/2019 16:20:03\nsvc-parking-api  True    9/30/2026 11:05:12" },
          { match: "get-aduser\\s+svc-cctv-legacy.*", help: "Get-ADUser svc-cctv-legacy -Properties Description, MemberOf",
            output: "Name        : svc-cctv-legacy\nDescription : Old CCTV NVR integration (vendor gone 2019)\nMemberOf    : {CN=Highways Ops,...; CN=Server Operators,CN=Builtin,...}" },
          { match: "get-aduser\\s+svc-parking-api.*", help: "Get-ADUser svc-parking-api -Properties Description",
            output: "Name        : svc-parking-api\nDescription : Parking permit API, legacy Kerberos client (ticket CHG-3170, 32-char password)" },
        ],
        objectives: [
          { id: "count", task: "How many enabled accounts skip pre-authentication?", hint: "The DoesNotRequirePreAuth filter: count Enabled = True", answer: ["2", "two"], why: "Two live ones. j.price.old is disabled, so the KDC won't answer for it." },
          { id: "worst", task: "Which one would you fix first?", hint: "Password age and group membership", answer: ["svc-cctv-legacy"], why: "A 2017 password, a vendor that's gone, and Server Operators membership. Crack its AS-REP offline and you're on every server." },
        ],
      },
    ],
    // ── Reading 5: relay ──
    "ad-r5": [
      {
        kind: "worksheet",
        title: "Names and Addresses",
        prompt: "Three NTLM network logons to the planning file server RKW-FS05 this afternoon, enriched with DHCP and the asset inventory.",
        caption: "Security 4624 · LogonType 3 · AuthenticationPackageName NTLM · RKW-FS05",
        columns: ["user", "WorkstationName", "IpAddress", "DHCP lease for that workstation", "IP in asset inventory?"],
        rows: [
          ["p.okonkwo", "PLN-LT-14", "10.44.6.31", "10.44.6.31", "yes, PLN-LT-14"],
          ["r.duffy", "PLN-LT-22", "10.44.6.120", "10.44.6.58", "no match"],
          ["svc-scan", "PLN-MFP-01", "10.44.6.9", "reserved 10.44.6.9", "yes, PLN-MFP-01"],
        ],
        questions: [
          { id: "odd", q: "Which logon doesn't add up?", hint: "Compare the claimed name with where the connection came from.", answer: ["r.duffy", "duffy"], why: "The name says PLN-LT-22, but the connection came from an address nobody owns while PLN-LT-22 holds another lease." },
          { id: "mfp", q: "svc-scan logs on from a printer. Name, lease and inventory: do they agree? (yes/no)", hint: "Read its row across.", answer: ["yes"], why: "The multifunction printer's reserved address, its own name and its inventory entry all line up. A service account on a scanner is normal; a mismatch is what you hunt." },
        ],
      },
    ],
  },
};
