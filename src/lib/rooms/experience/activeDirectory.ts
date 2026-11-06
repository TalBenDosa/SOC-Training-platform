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
  scene: "facilitydirectory",
  layout: "facility",
  story: {
    intro: { title: "Own the Directory, Own Everything", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/active-directory/keystone-intro-cbb9ca1c.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/active-directory/keystone-intro-f14d35f7.jpg" },
    afterStation: {
      kerberos: { title: "The Wristband", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/active-directory/keystone-ch2-12db5f58.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/active-directory/keystone-ch2-616d595c.jpg" },
      roast: { title: "01:47 on the DC", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/active-directory/keystone-ch3-7bc64a95.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/active-directory/keystone-ch3-93dcd83a.jpg" },
      relay: { title: "Borrowed Logons", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/active-directory/keystone-finale-b8f84aa9.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/active-directory/keystone-finale-ed4a1ad6.jpg" },
    },
  },
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
        kind: "spotdiff",
        title: "Directory Baseline",
        prompt: "Femi keeps a signed-off export of how Rookwood's directory should look: forest, trusts, controllers, OUs and GPOs. Compare it with today's export and tap every change nobody approved. Routine drift is harmless.",
        goodTitle: "Signed-off baseline",
        suspectTitle: "Export from ADM-WS-02 today",
        good: [
          "Forest  rookwood.example  ForestMode Windows2016Forest  Domains 2",
          "Trust  schools.rookwood.example  BiDirectional  ForestTransitive False  SIDFilteringQuarantined True",
          "Trust  halden-shared.example  Outbound  ForestTransitive True  SIDFilteringQuarantined True",
          "DC  RKW-DC01  CountyHall  IsGlobalCatalog True  Replication with RKW-DC02 last OK 02:00",
          "DC  RKW-DC02  Depot-North  IsGlobalCatalog True  Replication with RKW-DC01 last OK 02:00",
          "OU  Social Care  Computers 212  Block inheritance False",
          "GPO link  Social Care  SC - Block USB storage  Enabled  Enforced False",
          "GPO link  Social Care  SC - Lock screen 5 min  Enabled  Enforced False",
          "GPO  All Staff - Password policy  Edit settings: Domain Admins, GPO Creator Owners",
          "GPO  Default Domain Controllers Policy  Edit settings: Domain Admins",
          "OU  Service Accounts  Block inheritance False  Linked GPOs 1",
        ],
        suspect: [
          "Forest  rookwood.example  ForestMode Windows2016Forest  Domains 2",
          "Trust  schools.rookwood.example  BiDirectional  ForestTransitive False  SIDFilteringQuarantined True",
          "Trust  halden-shared.example  Outbound  ForestTransitive True  SIDFilteringQuarantined False",
          "DC  RKW-DC01  CountyHall  IsGlobalCatalog True  Replication with RKW-DC02 last OK 02:30",
          "DC  RKW-DC02  Depot-North  IsGlobalCatalog True  Replication with RKW-DC01 last OK 02:00",
          "OU  Social Care  Computers 214  Block inheritance False",
          "GPO link  Social Care  SC - Block USB storage  Disabled  Enforced False",
          "GPO link  Social Care  SC - Lock screen 5 min  Enabled  Enforced False",
          "GPO  All Staff - Password policy  Edit settings: Domain Admins, GPO Creator Owners",
          "GPO  Default Domain Controllers Policy  Edit settings: Domain Admins, Authenticated Users",
          "OU  Service Accounts  Block inheritance False  Linked GPOs 1",
        ],
        diffs: [
          { line: 2, why: "SID filtering on the outbound halden-shared trust was switched off. Trusts extend one directory's reach into another, so a quarantine setting that drops is a door being widened, not a cosmetic change." },
          { line: 6, why: "The link is still there but disabled, so the USB block no longer lands on any Social Care machine. GPOs apply through OU links: whoever can edit the link changes every machine in the OU at once." },
          { line: 9, why: "Authenticated Users can now edit the policy that governs the domain controllers, which means every signed-in account can. Edit rights on a DC policy should stay with Domain Admins, because controlling it controls the controllers." },
        ],
        decoys: [
          { line: 3, why: "Replication runs every few minutes and the export was taken half an hour later. A newer last-OK time shows the controllers are healthy, not tampered with." },
          { line: 5, why: "Two laptops were joined to Social Care since the baseline: computer counts drift with onboarding. Check the join against the helpdesk queue if it jumps, but two is routine." },
        ],
        lesson: "A forest is the outer boundary, domains and trusts decide who can reach whom, and GPOs applied to OUs decide how every machine behaves. Groups come in two categories: a Security group can be placed on permissions and file-share ACLs, while a Distribution group is only an email list. The KDC, the service that issues Kerberos tickets, runs on every domain controller. Watch the controls that reach many objects at once: trusts, GPO links and who may edit them.",
      },
    ],
    // ── Reading 2: Kerberos ──
    "ad-r2": [
      {
        kind: "pathway",
        title: "Follow the Wristband",
        prompt: "k.boateng has just switched on her Social Care laptop and wants the case-file share on RKW-FS03. Walk the Kerberos route the way the tickets really travel, one hop at a time.",
        goal: "Open the case-file share with a Kerberos service ticket",
        nodes: [
          { id: "laptop", label: "Laptop sign-in", sub: "k.boateng", x: 12, y: 82 },
          { id: "ntlm", label: "NTLM challenge", sub: "straight to RKW-FS03", x: 12, y: 48 },
          { id: "as", label: "AS-REQ", sub: "KDC on RKW-DC01", x: 32, y: 60 },
          { id: "ldap", label: "LDAP bind", sub: "directory lookup", x: 36, y: 22 },
          { id: "tgt", label: "TGT cached", sub: "krbtgt ticket", x: 46, y: 86 },
          { id: "tgs", label: "TGS-REQ", sub: "ask for cifs/RKW-FS03", x: 62, y: 50 },
          { id: "fstgt", label: "Show the TGT", sub: "to RKW-FS03", x: 88, y: 52 },
          { id: "st", label: "Service ticket", sub: "cifs/RKW-FS03", x: 74, y: 82 },
          { id: "fs", label: "Case-file share", sub: "RKW-FS03", x: 88, y: 22 },
        ],
        edges: [["laptop", "as"], ["laptop", "ntlm"], ["as", "tgt"], ["as", "ldap"], ["tgt", "tgs"], ["tgt", "fstgt"], ["tgs", "st"], ["st", "fs"]],
        route: ["laptop", "as", "tgt", "tgs", "st", "fs"],
        notes: {
          laptop: "The laptop proves it knows k.boateng's password without sending it across the network. Everything after this uses tickets, not the password.",
          as: "The AS-REQ goes to the KDC on the domain controller. A successful answer is logged on the DC as event 4768.",
          tgt: "The reply is the TGT, a ticket for the krbtgt service: the wristband. It is cached for the session, valid ten hours and renewable for a week, and klist lists it.",
          tgs: "The laptop shows the TGT to the KDC and asks for a ticket for one named service. The DC logs each request as event 4769, where ServiceName is the service asked for, TargetUserName is the account asking, and TicketEncryptionType 0x12 means AES-256 while 0x17 means the weaker RC4.",
          st: "The KDC returns a service ticket for cifs/RKW-FS03. The user did not retype a password to get it. The ticket is encrypted with the key of the account the service runs under, here the file server's own, so only RKW-FS03 can read it.",
          fs: "The file server accepts the service ticket and writes its own logon event. The KDC is not asked again for this share.",
        },
        traps: {
          ntlm: "NTLM is the fallback when Kerberos cannot be used, for example when the server is reached by IP address. Going this way means no TGT and no 4768 or 4769 on the DC. The Kerberos route starts with an AS-REQ.",
          ldap: "LDAP is a directory query, such as which groups a user belongs to. It reaches the same DC but it authenticates nothing and returns no ticket.",
          fstgt: "The TGT is only good at the KDC. A file server cannot use it, so you must exchange it for a cifs service ticket first.",
        },
        lesson: "Two requests at the KDC, in order: the AS-REQ buys the TGT, the TGS-REQ turns it into a service ticket for one service. So a 4768 is followed by one 4769 per service the user touches.",
      },
    ],
    // ── Reading 3: monitoring the DC ──
    "ad-r3": [
      {
        kind: "trace",
        title: "Night on the DC",
        prompt: "RKW-DC02 at the depot raised 'Domain Admins membership changed' overnight. Follow it through the DC's own logs.",
        lead: "Alert: Domain Admins membership changed on RKW-DC02 at 01:48.",
        steps: [
          {
            id: "created", source: "Security log · 4720 user created · RKW-DC02",
            ask: "Which account was created overnight, and by whom?",
            columns: ["time", "event", "subject", "new account"],
            rows: [["11/3 09:14", "4720", "it.admin", "new.starter.kp"], ["11/4 01:47", "4720", "hwy.temp04", "svc_mon2"]],
            answer: 1,
            why: "A 'service' account created at 01:47 by a seasonal contractor account. Any new account is worth verifying; this one doubly so.",
            learned: "01:47 svc_mon2 created by hwy.temp04",
          },
          {
            id: "group", source: "Security log · 4728 / 4732 member added",
            ask: "Where did svc_mon2 go next?",
            columns: ["time", "event", "subject", "member", "group"],
            rows: [["11/3 10:02", "4732", "it.admin", "new.starter.kp", "Remote Desktop Users"], ["11/4 01:48", "4728", "hwy.temp04", "svc_mon2", "Domain Admins"]],
            answer: 1,
            why: "Straight into Domain Admins, one minute after it was created.",
            learned: "01:48 svc_mon2 added to Domain Admins",
          },
          {
            id: "cleared", source: "Security log · RKW-DC02 · 01:50-02:00",
            ask: "What did the new admin do first?",
            columns: ["time", "event", "account", "detail"],
            rows: [["01:52", "1102", "svc_mon2", "The audit log was cleared"], ["01:55", "4624", "svc_mon2", "Logon type 3 from 10.40.9.17"]],
            answer: 0,
            why: "Clearing the log is the first move: hide what came before. It logged 1102 doing it.",
            learned: "01:52 svc_mon2 cleared the Security log",
          },
          {
            id: "why", source: "Active Directory · hwy.temp04 · MemberOf",
            ask: "Which group let a gritting contractor create accounts and change who is in Domain Admins?",
            columns: ["group", "type", "added"],
            rows: [["Highways Ops", "Global", "2026-10-20"], ["Directory Delegation", "Global", "2026-10-20"]],
            answer: 1,
            why: "Directory Delegation carried delegated rights to create accounts and to write the member list of Domain Admins. Account Operators would not have been enough: it cannot change protected groups such as Domain Admins. Poor hygiene turned one phished contractor into a domain admin.",
            learned: "Root cause: contractor in an over-delegated group",
          },
          {
            id: "sync", source: "Network sensor · RPC calls to RKW-DC02 · DRSGetNCChanges",
            ask: "svc_mon2's 01:55 logon came from 10.40.9.17. DRSGetNCChanges is the call DCs use to replicate the directory. Which of these calls should never have happened?",
            columns: ["time", "caller", "caller IP", "asset role"],
            rows: [["01:30", "RKW-DC01", "10.40.1.10", "Domain Controller"], ["01:58", "RKW-ENG-17", "10.40.9.17", "Engineering workstation"]],
            answer: 1,
            why: "Only DCs replicate. A workstation making that call is posing as a DC so the real one hands over the password hash of every account. The technique is called DCSync, and it needs replication rights, which a Domain Admin has.",
            learned: "01:58 DCSync from RKW-ENG-17: treat every hash as stolen",
          },
          {
            id: "reset", source: "Containment plan · passwords to reset after DCSync",
            ask: "Every hash left the domain. Which account does Femi reset first, and twice?",
            columns: ["account", "what its key does", "what an attacker can forge with the hash"],
            rows: [["krbtgt", "Signs every TGT in the domain", "Golden Ticket: a TGT for any account"], ["svc-sql", "Encrypts service tickets for SQL", "Silver Ticket: access to that one service"], ["hwy.temp04", "Ordinary user logon", "Nothing: only signs in as that user"]],
            answer: 0,
            why: "Ordinary resets leave the key that signs tickets untouched, so forged tickets keep working. krbtgt is reset twice because the domain keeps its previous key as well.",
            learned: "krbtgt reset twice, then every other account",
          },
        ],
      },
    ],
    // ── Reading 4: AS-REP roasting ──
    "ad-r4": [
      {
        kind: "deduce",
        title: "Which Account Was Roasted?",
        prompt: "Overnight the DC handed an AS-REP to a host that had never signed in. Femi pulls six candidate accounts from the directory. Strike out the ones the evidence rules out, then name the account whose reply was cracked.",
        nameColumn: "Account",
        columns: ["Status", "Pre-auth required", "Password set", "Notable group"],
        suspects: [
          { id: "roster", name: "svc-roster-api", cells: ["Enabled", "Yes", "2026-08", "None"] },
          { id: "hrexport", name: "svc-hr-export", cells: ["Enabled", "No", "2026-09, 32 characters", "None"] },
          { id: "okoro", name: "j.okoro.old", cells: ["Disabled", "No", "2019-06", "None"] },
          { id: "gis", name: "svc-gis-sync", cells: ["Enabled", "No", "2016-03", "Server Operators"] },
          { id: "alder", name: "t.alder", cells: ["Enabled", "Yes", "2026-10", "Highways Ops"] },
          { id: "fleet", name: "svc-fleet-tel", cells: ["Enabled", "No", "2020-11", "None"] },
        ],
        clues: [
          "The DC returned an AS-REP, sealed with a key derived from the account's password, to a host that had never authenticated.",
          "The DC answered cleanly at 03:41, with no error returned to the requester.",
          "The password fell to an offline guess run in under an hour. Rookwood's 14-character minimum took effect in 2019, and every account set after it has been checked against a breach list.",
        ],
        culprit: "gis",
        why: "svc-gis-sync is the only account that fits all three. The KDC only hands out an AS-REP without a proof of identity when pre-authentication is switched off, which rules out the two accounts that require it. A disabled account such as j.okoro.old gets an error, not a reply. And only a pre-2019 password falls that fast: svc-hr-export is the benign near miss, flagged but protected by a 32-character secret. Fix svc-gis-sync first: a 2016 password, a vendor that left, and Server Operators membership put every server one cracked reply away.",
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
