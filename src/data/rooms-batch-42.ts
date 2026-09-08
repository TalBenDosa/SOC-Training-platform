/**
 * Learning Rooms — Batch 42
 *
 * Closes a P0 coverage gap: MITRE ATT&CK's Discovery tactic (TA0007) is
 * practised in nearly every scenario on this platform -- host recon, domain
 * enumeration, cloud API sweeps, share discovery -- yet it was never taught
 * as its own subject in any room. Companion to the theory lesson "Discovery &
 * Enumeration in the Logs" in newTopicLessons.ts -- every task here is built
 * on that lesson's reading, not on outside knowledge.
 *
 * Rooms in this batch:
 *  1. discovery-and-enumeration
 */

import type { TelemetryEvent } from "@/lib/sim/types";

// ===========================================================================
// ROOM — Discovery & Enumeration in the Logs
// ===========================================================================

// Log-analysis 1: local Administrators group enumeration (Event 4799) on a
// freshly phished workstation. The genuine baseline (no prior admin-console
// use on this host) is narrated in the task's `context`, not as a second
// event -- the student reads this one event's raw fields against that
// narrated baseline, exactly as an analyst would.
const localAdminEnumEvent: TelemetryEvent = {
  id: "evt-disc-la1-001",
  ts: "2026-05-12T14:07:33.000Z",
  source: "windows_security",
  vendor: "Windows Security",
  event_type: "privileged_operation",
  severity: "medium",
  mitre_technique: "T1033",
  mitre_tactic: "Discovery",
  hostname: "WKS-FIN22.meridiancap.local",
  user_title: "Accounts Payable Clerk",
  description:
    "A security-enabled local group membership enumeration (Administrators) was recorded on WKS-FIN22, two minutes after j.ramos's account clicked a link in an email the mail gateway later flagged as phishing.",
  raw: {
    "event.code": "4799",
    "winlog.channel": "Security",
    "winlog.computer_name": "WKS-FIN22",
    "winlog.event_data.SubjectUserName": "j.ramos",
    "winlog.event_data.SubjectDomainName": "MERIDIANCAP",
    "winlog.event_data.SubjectLogonId": "0x8a3f21",
    "winlog.event_data.GroupName": "Administrators",
    "winlog.event_data.GroupDomain": "Builtin",
    "winlog.event_data.CallerProcessId": "0x1a04",
    "winlog.event_data.CallerProcessName": "C:\\Windows\\System32\\net.exe",
    "winlog.event_id": 4799,
  },
};

// Log-analysis 2: the first of a 47-call Describe/List burst against one
// AWS assumed role, spanning four services in eight minutes overnight. The
// burst itself is narrated in `context` (never as a raw aggregate field --
// a single CloudTrail record cannot legitimately carry a windowed count).
const cloudDescribeEvent: TelemetryEvent = {
  id: "evt-disc-la2-001",
  ts: "2026-06-03T02:14:08.000Z",
  source: "cloudtrail",
  vendor: "AWS CloudTrail",
  event_type: "cloud_api_call",
  severity: "medium",
  mitre_technique: "T1580",
  mitre_tactic: "Discovery",
  src_ip: "45.148.10.62",
  description:
    "The first EC2 DescribeInstances call in a sequence of Describe/List API calls made by the lambda-reporting-role IAM role overnight.",
  raw: {
    "aws.cloudtrail.eventName": "DescribeInstances",
    "aws.cloudtrail.eventSource": "ec2.amazonaws.com",
    "aws.cloudtrail.awsRegion": "us-east-1",
    "aws.cloudtrail.userIdentity.type": "AssumedRole",
    "aws.cloudtrail.userIdentity.arn":
      "arn:aws:sts::719400852261:assumed-role/lambda-reporting-role/i-0f3a8b21c9d4e5678",
    "aws.cloudtrail.userIdentity.accountId": "719400852261",
    "aws.cloudtrail.sourceIPAddress": "45.148.10.62",
    "aws.cloudtrail.userAgent": "aws-cli/2.15.2 Python/3.11.6 Linux/6.1.0",
    "aws.cloudtrail.requestParameters": {},
    "aws.cloudtrail.responseElements": null,
    "aws.cloudtrail.errorCode": "",
    "aws.cloudtrail.errorMessage": "",
    "aws.cloudtrail.requestID": "9B7C2D4E1A6F3081",
    "aws.cloudtrail.eventType": "AwsApiCall",
    "aws.cloudtrail.managementEvent": true,
    "aws.cloudtrail.readOnly": true,
  },
};

// Analyst-choice control case: the FP a broad "any domain enumeration
// command" rule guarantees -- a two-year-old, IT-confirmed nightly audit
// script, unrelated to any incident.
const nightlyAuditEvent: TelemetryEvent = {
  id: "evt-disc-ac1-001",
  ts: "2026-04-02T03:00:11.000Z",
  source: "sysmon",
  vendor: "Sysmon",
  event_type: "process_create",
  severity: "low",
  mitre_technique: "T1087.002",
  mitre_tactic: "Discovery",
  hostname: "SRV-ITAUDIT01.meridiancap.local",
  user_title: "Scheduled IT Audit Service Account",
  process: {
    name: "net.exe",
    pid: 4412,
    path: "C:\\Windows\\System32\\net.exe",
    parent_name: "powershell.exe",
    parent_pid: 3390,
    cmdline: "C:\\Windows\\System32\\net.exe user /domain",
    user: "MERIDIANCAP\\svc-itaudit",
    integrity: "medium",
  },
  description:
    "svc-itaudit executed 'net user /domain' on SRV-ITAUDIT01, part of a scheduled task that has run at 03:00 every night for the past two years.",
  it_verify_result: "confirmed",
  it_verify_message:
    "IT confirms Scheduled Task 'Nightly-AD-Account-Audit' on SRV-ITAUDIT01 runs this exact command every night at 03:00 as part of the quarterly access-review process; svc-itaudit has no interactive logon capability and only ever runs from this one server.",
  raw: {
    "event.code": "1",
    "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
    "winlog.computer_name": "SRV-ITAUDIT01",
    "winlog.event_data.Image": "C:\\Windows\\System32\\net.exe",
    "winlog.event_data.CommandLine": "C:\\Windows\\System32\\net.exe user /domain",
    "winlog.event_data.ParentImage":
      "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "winlog.event_data.User": "MERIDIANCAP\\svc-itaudit",
    "winlog.event_data.IntegrityLevel": "Medium",
    "winlog.event_id": 1,
  },
};

const discoveryEnumerationRoom = {
  id: "discovery-and-enumeration",
  title: "Discovery & Enumeration in the Logs: The Recon Before the Breach",
  description:
    "MITRE ATT&CK's Discovery tactic (TA0007) is practised in nearly every real intrusion -- host-level recon (T1033), domain account and privileged-group enumeration (T1087.002, T1069.002), cloud infrastructure and storage discovery (T1580, T1526, T1619), and network share discovery feeding data collection (T1135 -> T1039) -- yet almost every command that performs it is a completely legitimate, built-in feature. Learn to read the pattern, not the single event.",
  difficulty: "intermediate" as const,
  category: "Threat Detection",
  estimatedMinutes: 75,
  xp: 250,
  icon: "\ud83d\udd75\ufe0f",
  prerequisites: ["active-directory", "windows-event-logs", "mitre-attack", "cloud-security-monitoring"],
  tasks: [
    // ── Reading 0: ATT&CK primer ─────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "disc-r0",
      heading: "What a MITRE ATT&CK Tactic Actually Is, and Why Discovery Gets Its Own ID",
      content:
        "Before this room can name specific enumeration techniques, one piece of vocabulary needs to be solid: what MITRE ATT&CK actually means by a **tactic** versus a **technique**. ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) is a public, continuously updated knowledge base, maintained by the MITRE Corporation, cataloguing how real attackers actually operate -- built from observed intrusions, not theory.\n\n" +
        "A **tactic** answers \"why is the attacker doing this right now\" -- the goal, such as gaining initial access, executing code, or discovering more about the environment. A **technique** answers \"how\" -- the specific method used to reach that goal. Every technique is tagged with one or more tactics it serves, and every tactic groups many techniques that all serve the same purpose.\n\n" +
        "**Discovery** is tactic **TA0007** in the ATT&CK Enterprise matrix. MITRE's own one-line description: \"the adversary is trying to figure out your environment.\" Every technique this room covers -- T1033, T1087.002, T1069.002, T1018, T1046, T1580, T1526, T1619, T1135 -- carries this exact tactic ID, because each one, in its own way, is the attacker asking a version of the same question: what does this environment actually look like, and what can I reach from here. Holding onto this shared tactic ID is what lets an analyst recognize a brand-new tool or command they've never seen before as 'probably Discovery' just from what it's asking, even before looking up its specific technique number.",
      xp: 5,
    },

    // ── Reading 1: framing ──────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "disc-r1",
      heading: "Discovery: The Recon Every Intrusion Practices",
      content:
        "Every named attack this platform teaches -- a Kerberoasting run, a DCSync, a ransomware deployment, an AWS account takeover -- assumes the attacker already knows something about the environment: which accounts have SPNs, which account holds replication rights, which S3 bucket is worth stealing. That knowledge doesn't appear by magic. MITRE ATT&CK calls the phase that produces it **Discovery** (tactic **TA0007**), and describes its purpose in one sentence: \"the adversary is trying to figure out your environment.\" It sits right after Initial Access and Execution in almost every real intrusion, because an attacker who has just landed genuinely does not know what they are looking at -- is this a developer laptop or a domain controller, does this stolen account have any real privilege, which of a thousand cloud resources actually matters.\n\n" +
        "Discovery is one of the most universally practised tactics in the whole framework, and one of the least explicitly taught, for a specific reason: almost every command that performs it -- whoami, net user, an AWS DescribeInstances call -- is a completely ordinary, built-in feature that legitimate IT staff and automation run constantly. There is no single malicious-looking \"discovery virus.\" There is only a PATTERN that separates an attacker's reconnaissance sweep from a Tuesday-afternoon helpdesk script.\n\n" +
        "This room builds that pattern-recognition skill layer by layer: what an attacker checks the moment they land on one host, how enumeration scales up to a whole Windows domain, the cloud-native version of the same questions asked through API calls, the point where \"looking\" becomes \"taking\" via network shares, and the detection discipline -- baselining, volume, false-positive judgment -- that applies identically across every layer.",
      checkpoint: {
        question: "Why is Discovery one of the hardest ATT&CK tactics to build a reliable detection rule for?",
        options: [
          "It almost never actually happens in real intrusions, so there is little log data to build a rule from in the first place",
          "Nearly every command that performs it is a completely ordinary, legitimate operating-system or cloud-API feature -- there is no single malicious event, only a suspicious pattern",
          "MITRE ATT&CK does not currently classify Discovery as an official tactic with its own ID",
          "Discovery only ever occurs on Linux systems, which most commercial SIEM products do not support at all",
        ],
        answer: 1,
        explanation: "This is the central framing of the room: whoami, net user, and DescribeInstances are all legitimate, everyday commands. There is no single 'bad' discovery event -- detection depends on recognizing volume, breadth, and source patterns instead. Discovery is TA0007, a real, extremely commonly practised tactic, and it occurs on Windows, Linux, and cloud platforms alike.",
      },
      xp: 5,
    },

    // ── Reading 2: host-level ────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "disc-r2",
      heading: "Host-Level Discovery: Who Am I, and Who Runs This Box? (T1033)",
      content:
        "The very first questions an attacker asks after landing on a machine are about the machine itself, not the domain. MITRE tracks this as **T1033, System Owner/User Discovery** (Discovery tactic): identifying primary users, currently logged-in users, or whether a user is actively using the system.\n\n" +
        "On Windows the toolkit is entirely built-in: whoami and whoami /groups (who is this account, what groups does it belong to), query user / quser (who else is logged on right now), net user with no target (every LOCAL account on the machine), and net config workstation (basic host identity). Two related commands go one step further and actually generate a Windows Security event: net user <accountname> (list one account's local group memberships) and net localgroup administrators (who is a local admin on THIS box).\n\n" +
        "**Event ID 4798 -- \"A user's local group membership was enumerated.\"** Fires when a process reads which local groups a specific target account belongs to. Key fields: SubjectUserName/SubjectDomainName (who ran the query), TargetUserName/TargetSid (whose memberships were read), and CallerProcessName (the full path of the executable that made the call).\n\n" +
        "**Event ID 4799 -- \"A security-enabled local group membership was enumerated.\"** Fires when a process reads who is a member of a specific local group. Same shape, with GroupName/GroupDomain identifying which group was read.\n\n" +
        "Neither event is inherently suspicious -- both are logged constantly by ordinary admin tools such as mmc.exe (Microsoft Management Console) and dsa.msc (Active Directory Users and Computers). The tell is the **CallerProcessName**: a 4799 whose caller is net.exe, cmd.exe, or powershell.exe -- command-line tools, not an admin console -- especially minutes after a suspicious phishing click, is a materially different story than the same event fired by mmc.exe from an IT administrator's known workstation.",
      codeExample:
        "EventID: 4799\nSubjectUserName: j.ramos\nSubjectDomainName: CONTOSO\nGroupName: Administrators\nGroupDomain: Builtin\nCallerProcessId: 0x1a04\nCallerProcessName: C:\\Windows\\System32\\net.exe",
      checkpoint: {
        question: "What is the single strongest tell that a 4798/4799 event is worth a closer look, rather than routine admin activity?",
        options: [
          "The event ID itself -- 4798 and 4799 only ever fire when the request is malicious, with no legitimate use case",
          "The CallerProcessName -- a command-line tool such as net.exe, cmd.exe, or powershell.exe, rather than an expected admin console such as mmc.exe",
          "The GroupName field -- any event naming the Administrators group is definitionally an attack",
          "The hostname field -- 4798/4799 only fire on servers, never on ordinary workstations",
        ],
        answer: 1,
        explanation: "Both events fire constantly for entirely benign reasons through admin consoles like mmc.exe. The CallerProcessName is what actually distinguishes a routine admin check from a command-line enumeration -- especially when combined with unusual timing or a suspicious preceding event. 4798/4799 fire on any Windows host, and naming Administrators as the target group is completely normal for legitimate access reviews.",
      },
      xp: 5,
    },

    // ── Question 1 ────────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "disc-q1",
      question:
        "An attacker has just landed on a workstation via a phished credential. Which MITRE ATT&CK technique describes them immediately running whoami and net user to establish who they are and what local privileges they hold?",
      options: [
        "T1087.002, Domain Account Discovery -- since any account-related command always maps to the domain-wide sub-technique regardless of scope",
        "T1033, System Owner/User Discovery -- identifying the current user and their local standing on the specific machine just compromised",
        "T1580, Cloud Infrastructure Discovery -- since whoami is a generic identity command usable in any environment, including the cloud",
        "T1135, Network Share Discovery -- since establishing identity is a prerequisite step before any share can be enumerated",
      ],
      answer: 1,
      explanation:
        "T1033 is specifically about identifying the current user and local system context -- exactly what whoami and net user (with no /domain flag) provide. T1087.002 is the domain-WIDE sub-technique covered later in this room, not a catch-all for any account-related command. T1580 is cloud-specific and unrelated to a local whoami. T1135 is about finding network shares, a separate later step.",
      xp: 15,
    },

    // ── Reading 3: domain-wide ───────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "disc-r3",
      heading: "Domain-Wide Discovery: Accounts and Privileged Groups (T1087.002, T1069.002)",
      content:
        "Once an attacker knows what ONE host looks like, the next question scales up: what does the whole domain look like, and who actually holds power? This is genuinely different reconnaissance -- instead of reading the local SAM database on one machine, these commands ask a Domain Controller.\n\n" +
        "**T1087.002 -- Domain Account Discovery** (a sub-technique of T1087) is enumerating every account in the domain. MITRE's real-world tooling list: net user /domain and net group /domain, PowerShell's Get-ADUser and Get-ADGroupMember, dsquery, and offensive tools including AdFind, BloodHound, and CrackMapExec.\n\n" +
        "**T1069.002 -- Permission Groups Discovery: Domain Groups** (a sub-technique of T1069) is the companion technique aimed at privileged groups specifically -- finding out who is a Domain Admin. Representative commands: net group /domain and net group \"domain admins\" /domain, dsquery, Get-ADGroup, or a direct LDAP query.\n\n" +
        "Note the boundary from the previous reading: net localgroup administrators (no /domain flag) reads THIS machine's local SAM database and produces Event 4799 on that machine. net group /domain instead queries the Domain Controller over LDAP, and produces entirely different telemetry -- ground the LDAP and BloodHound content in this platform's Active Directory track covers in full depth (Event 4662, ACL abuse, SharpHound/PowerView at scale). This room does not re-teach that ground; the point here is recognizing where the boundary sits.\n\n" +
        "MITRE's own detection guidance for T1087.002 is precise: watch for domain-account enumeration commands (net.exe, PowerShell, WMI, or LDAP queries) run **from non-domain-controller or non-admin endpoints**. The trigger isn't the command -- it's the combination of the command with an unexpected source. A single query from an unusual workstation is a lead, not a verdict; what raises confidence sharply is BREADTH -- the same source querying dozens or hundreds of accounts, or every privileged group in sequence, within a tight window.",
      checkpoint: {
        question: "Per MITRE's own detection guidance for T1087.002, what is the primary tell that separates an attacker's domain enumeration from routine IT activity?",
        options: [
          "The exact wording of the command used, since only certain untranslatable command syntaxes are ever considered malicious",
          "The command running from a non-domain-controller or non-admin endpoint -- the same command is legitimate from an admin's own workstation",
          "Whether the command was typed manually versus pasted from a script, which Windows always records in a dedicated field",
          "The time zone offset recorded in the event, since domain enumeration is only ever malicious outside business hours",
        ],
        answer: 1,
        explanation: "MITRE's detection guidance explicitly names the source -- non-domain-controller or non-admin endpoint -- as the key signal, not the command syntax itself, since the same net.exe/PowerShell/LDAP commands are completely legitimate when run by IT admins from expected systems.",
      },
      xp: 5,
    },

    // ── Question 2 ────────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "disc-q2",
      question:
        "A single instance of net group \"domain admins\" /domain runs once from a new IT hire's laptop while they are learning the environment. Per this room's detection discipline, how should this be weighted compared to the same command run 200 times against every privileged group from the same source in six minutes?",
      options: [
        "Identically -- MITRE ATT&CK treats every instance of a technique as equally severe regardless of volume or breadth",
        "The single instance should be weighted as the more severe finding, since a first-time occurrence is always more suspicious than repeated activity",
        "The single instance is a lead, not a verdict; the 200-query burst in six minutes is the far stronger signal, since breadth and volume are what distinguish a sweep from an isolated legitimate query",
        "Neither should be investigated at all, since both are examples of a fully built-in, unblockable Windows feature",
      ],
      answer: 2,
      explanation:
        "This is the breadth principle from the reading: a single query is ambiguous and could have an innocent explanation (a new hire exploring), while touching every privileged group in a tight window from one source is the enumeration signature. ATT&CK technique classification does not itself encode severity by volume -- that judgment is the analyst's job. Both remain worth investigating; being built-in does not mean unblockable or unworthy of monitoring.",
      xp: 15,
    },

    // ── Reading 4: adjacent techniques ───────────────────────────────────────
    {
      type: "reading" as const,
      id: "disc-r4",
      heading: "Two Close Cousins You'll Meet in the Same Investigations: T1018 and T1046",
      content:
        "Two more Discovery techniques sit right alongside the ones above in almost every real investigation.\n\n" +
        "**T1018, Remote System Discovery** asks \"what other machines exist that I could reach.\" Example commands: ping sweeps, net view and net view /domain (available remote systems, and every machine in the domain), arp -a (the local ARP cache of recently-contacted IP-to-MAC mappings), and nltest /dclist (specifically which machines are Domain Controllers). This turns 'I have one compromised host' into a map of what to pivot to next.\n\n" +
        "**T1046, Network Service Discovery** goes one layer deeper: not just that a host exists, but WHAT is running on it. MITRE names port scanning generally, and tools such as nmap, alongside SMB enumeration and CrackMapExec.\n\n" +
        "Both share a detection headache that becomes this room's closing subject: legitimate vulnerability scanners (Nessus, Qualys, Rapid7) perform port scans and host sweeps as their literal, sanctioned job, every day, often against the entire IP range. An nmap-shaped pattern from an unauthorized workstation at 2 AM is a strong signal; the identical pattern from the security team's own scanner appliance, on schedule, is exactly what it is supposed to look like. Telling the two apart is not a technical problem -- the packets look the same -- it is an asset and identity management problem.",
      xp: 5,
    },

    // ── Log analysis 1 ───────────────────────────────────────────────────────
    {
      type: "log_analysis" as const,
      id: "disc-la1",
      heading: "Investigate: Local Admin Group Check on WKS-FIN22",
      context:
        "j.ramos, an Accounts Payable Clerk at Meridian Capital, clicked a link in an email at 14:05 that the mail gateway later flagged as phishing. Two minutes later, the event below was recorded on her workstation. Her account has never run an administrative console (mmc.exe, dsa.msc) on this machine, and IT has no ticket or scheduled task associated with any activity on this host today.",
      event: localAdminEnumEvent,
      questions: [
        {
          question:
            "What single field in this event is the strongest indicator that this enumeration was NOT performed through a normal administrative tool?",
          options: [
            "GroupName, since Windows only ever logs the value Administrators when the underlying request is malicious",
            "CallerProcessName, showing net.exe rather than an administrative console such as mmc.exe or dsa.msc",
            "SubjectDomainName, since MERIDIANCAP as a domain name is inherently suspicious regardless of context",
            "winlog.event_id, since the value 4799 by itself, with no other field considered, is inherently a malicious-only event code",
          ],
          answer: 1,
          explanation:
            "CallerProcessName recording net.exe -- a command-line tool -- rather than the expected admin console mmc.exe or dsa.msc is exactly the tell this room's reading teaches. GroupName reading 'Administrators' is completely routine for legitimate access checks. SubjectDomainName is just the organization's own domain name, and 4799 fires constantly for benign reasons -- neither is inherently suspicious alone.",
          xp: 15,
        },
        {
          question:
            "Given everything in the context above, what is the most defensible next analytic step, consistent with this room's detection discipline?",
          options: [
            "Close the alert immediately, since a single 4799 event alone is never sufficient grounds for any further investigation",
            "Treat this as confirmed, unambiguous compromise and immediately trigger full incident response without checking any other telemetry",
            "Correlate this event with j.ramos's broader timeline -- the preceding phishing click, and whether further discovery, privilege, or process activity follows from this host or account",
            "Escalate this specifically as a T1087.002 Domain Account Discovery finding, since any local group enumeration always indicates domain-wide account discovery is also underway",
          ],
          answer: 2,
          explanation:
            "Discovery is a leading indicator, not a verdict by itself -- the correct move is correlating this event against the rest of the timeline (the phishing click, and whatever follows). Closing immediately ignores a genuinely suspicious combination of signals. Jumping to full incident response on one event skips the correlation step this room repeatedly emphasizes. And this event is local-group enumeration (T1033), not evidence of domain-wide enumeration (T1087.002) -- the two are distinct techniques with distinct telemetry, as the previous reading established.",
          xp: 15,
        },
      ],
    },

    // ── Reading 5: cloud discovery ───────────────────────────────────────────
    {
      type: "reading" as const,
      id: "disc-r5",
      heading: "Discovery in the Cloud: Infrastructure, Services, and Storage (T1580, T1526, T1619)",
      content:
        "A huge share of real intrusions start with a stolen cloud API key or a compromised IAM identity instead of a Windows foothold. Cloud discovery is the exact same idea -- ask the environment what exists -- executed through API calls instead of net.exe.\n\n" +
        "**T1580 -- Cloud Infrastructure Discovery** covers enumerating compute, storage, and database resources inside an IaaS environment. Real API calls: AWS's DescribeInstances (every EC2 instance), ListBuckets and HeadBucket (every S3 bucket, and access to a specific one), GetPublicAccessBlock (a bucket's public-exposure configuration), DescribeDBInstances (databases); GCP's gcloud compute instances list; Azure's az vm list. MITRE names Pacu (an AWS-specific post-exploitation framework) and TruffleHog as offensive tooling here.\n\n" +
        "**T1526 -- Cloud Service Discovery** maps higher-level services and identity configuration: applications registered in the tenant, management groups, policy definitions, OAuth app registrations, through Microsoft Graph and Azure Resource Manager APIs. MITRE names Stormspotter (Azure resource-graph enumeration), ROADTools (discovers Azure AD applications and service principals), and AADInternals (Office 365/OpenID enumeration).\n\n" +
        "**T1619 -- Cloud Storage Object Discovery** is narrower still: not 'does this bucket exist' but 'what objects are actually inside it.' Defining calls: AWS S3's ListObjectsV2 and Azure's List Blobs. This is the step that turns a discovered bucket into a worthwhile exfiltration target.\n\n" +
        "A single CloudTrail record for one of these calls is completely unremarkable on its own -- Terraform, cost dashboards, and CI/CD pipelines call DescribeInstances constantly, and readOnly: true confirms nothing was changed. What turns it into a Discovery-tactic finding is the SAME identity making dozens of Describe*/List* calls across multiple services within minutes, especially from a role that has never previously called half of them.\n\n" +
        "AWS GuardDuty ships purpose-built findings for exactly this: **Discovery:S3/MaliciousIPCaller** (an S3 ListObjectsV2-family call from a known-malicious IP), **Discovery:IAMUser/AnomalousBehavior** (behavioral anomaly on enumeration-style API usage), and **Recon:IAMUser/MaliciousIPCaller** (account-level reconnaissance from a threat-listed IP).",
      checkpoint: {
        question: "What is the actual difference between T1580 and T1619, per this reading?",
        options: [
          "There is no real difference -- both technique IDs describe the exact same set of AWS API calls",
          "T1580 discovers that resources like buckets, instances, and databases EXIST; T1619 goes further and enumerates what OBJECTS are actually inside an already-discovered storage location",
          "T1580 applies only to Azure, while T1619 applies only to AWS, with no overlap between the two cloud providers",
          "T1580 is a Collection-tactic technique, while T1619 is the only true Discovery-tactic technique among the three covered in this reading",
        ],
        answer: 1,
        explanation: "T1580 (Cloud Infrastructure Discovery) is the broader existence check across compute/storage/database resources; T1619 (Cloud Storage Object Discovery) is the narrower follow-up step of listing what objects sit inside a bucket already found. Both are genuinely different technique IDs with different defining API calls. Both apply across cloud providers, not one each. All three techniques in this reading -- T1580, T1526, and T1619 -- sit on the Discovery tactic, not Collection.",
      },
      xp: 5,
    },

    // ── Question 3 ────────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "disc-q3",
      question:
        "Which AWS GuardDuty finding type is purpose-built to flag an S3 ListObjectsV2-family call originating from an IP address already known to be malicious?",
      options: [
        "Recon:IAMUser/MaliciousIPCaller -- since this finding type covers every possible AWS API call regardless of which service it targets",
        "Discovery:S3/MaliciousIPCaller -- the S3-specific finding built for exactly this call pattern from a threat-listed source",
        "UnauthorizedAccess:EC2/RDPBruteForce -- since any malicious-IP-sourced finding in AWS falls under this single finding type",
        "Impact:S3/AnomalousBehavior.Delete -- since object listing and object deletion are treated as the identical underlying action",
      ],
      answer: 1,
      explanation:
        "Discovery:S3/MaliciousIPCaller is the S3-specific GuardDuty finding for this exact pattern. Recon:IAMUser/MaliciousIPCaller is the IAM-level equivalent, not S3-specific, and does not cover every AWS API call. UnauthorizedAccess:EC2/RDPBruteForce is an unrelated EC2/RDP finding. Impact:S3/AnomalousBehavior.Delete concerns anomalous deletion activity, not listing -- listing and deleting are different actions with different findings.",
      xp: 20,
    },

    // ── Log analysis 2 ───────────────────────────────────────────────────────
    {
      type: "log_analysis" as const,
      id: "disc-la2",
      heading: "Investigate: An Overnight API Burst from lambda-reporting-role",
      context:
        "SecureLedger Financial's cloud team receives an automated summary: the IAM role lambda-reporting-role -- normally invoked twice daily by a scheduled Lambda function to generate a cost report -- made 47 distinct Describe/List API calls spanning EC2, S3, IAM, and RDS between 02:06 and 02:14 this morning, all from the same source IP address. The event below is the first of those 47 calls.",
      event: cloudDescribeEvent,
      questions: [
        {
          question:
            "The raw event alone shows aws.cloudtrail.readOnly: true and a syntactically valid, successfully-authenticated API call. Why is that NOT sufficient to clear this activity as benign, given the context above?",
          options: [
            "readOnly: true always means the call was rejected by IAM, so no data was actually returned to whoever made it",
            "A single read-only call is genuinely unremarkable on its own; what matters is the SAME role making dozens of Describe/List calls across four services, in eight minutes, at 2 AM -- a pattern this role has never previously shown",
            "DescribeInstances is classified by AWS as a write operation, so readOnly: true is a self-contradictory, malformed record",
            "The event lacks a populated errorCode field, and AWS CloudTrail always requires one for any legitimate API call to be considered valid",
          ],
          answer: 1,
          explanation:
            "A single readOnly call is exactly what routine automation looks like -- the actual signal is the burst: dozens of Describe/List calls across four services in eight minutes, from a role whose normal pattern is two invocations a day. readOnly: true means the call did not change any state, not that it was rejected. DescribeInstances is a read (Describe) operation, not a write. An empty errorCode simply means the call succeeded -- that is normal, not a defect.",
          xp: 15,
        },
        {
          question:
            "What about this event's userIdentity and sourceIPAddress fields is most worth flagging for follow-up, independent of the volume pattern?",
          options: [
            "The role's normal pattern is a scheduled Lambda invocation twice daily, yet this call comes from a directly-connected aws-cli client at an unusual hour and source IP",
            "The arn value contains the word role, which by itself is treated as definitive, standalone proof of a compromised identity in any AWS account, regardless of anything else",
            "us-east-1 is a region that AWS does not actually operate any real infrastructure in, so the awsRegion field here must necessarily have been fabricated by the caller",
            "accountId is formatted as a 12-digit number, and any AWS account ID of that specific length is automatically flagged as inherently suspicious by CloudTrail itself",
          ],
          answer: 0,
          explanation:
            "The mismatch between the role's known, scheduled, Lambda-driven usage pattern and this call's aws-cli user agent, timing, and source IP is a genuine independent tell. Every assumed role's arn legitimately contains the word 'role' -- that is not suspicious. us-east-1 is one of AWS's oldest and most heavily used real regions. A 12-digit accountId is simply the standard AWS account ID format, not a suspicious property.",
          xp: 15,
        },
      ],
    },

    // ── Reading 6: share discovery to collection ─────────────────────────────
    {
      type: "reading" as const,
      id: "disc-r6",
      heading: "From Discovery to Collection: Network Share Discovery Feeds Data Theft (T1135 to T1039)",
      content:
        "Every technique so far has been about LOOKING. This reading is about the moment looking turns into TAKING.\n\n" +
        "**T1135 -- Network Share Discovery** (still Discovery, TA0007) is finding shared folders and drives reachable from wherever the attacker currently stands, over SMB. Commands: net view \\\\remotesystem (what does this ONE remote system share), net share (what does THIS machine share), and on macOS, sharing -l. CrackMapExec and PowerView automate scanning many hosts for shares at once.\n\n" +
        "**T1039 -- Data from Network Shared Drive** is a DIFFERENT tactic -- Collection, TA0009, not Discovery -- covering actually reading and harvesting files FROM shares that T1135 already found. MITRE's real-world examples: APT28 collected files directly from network shared drives; menuPass used net use to mount a discovered share and Robocopy to pull data off it in bulk; Gamaredon Group specifically collected Microsoft Office documents from mapped network drives.\n\n" +
        "This tactic boundary matters operationally, not just academically: Discovery and Collection represent genuinely different points of attacker commitment, and different points where a defender can intervene at very different cost. Stopping an attacker still running net view against every host on the subnet means stopping them before they've taken anything. Stopping them after Robocopy has already pulled ten thousand files off a finance share means the exposure has already happened. Detection strategies for this pairing correlate the two stages: net view/net share activity against multiple hosts, from one source, in a short window is the early, cheap signal; a subsequent burst of large file reads or copies off a UNC path by the SAME source in the following minutes confirms Discovery became Collection. Watch also for unusual read/copy activity against admin shares (C$, ADMIN$) rather than ordinary user shares, and atypical processes (PowerShell, certutil) accessing mounted drives instead of a user double-clicking a file in Explorer.",
      xp: 5,
    },

    // ── Ordering task ──────────────────────────────────────────────────────
    {
      type: "ordering" as const,
      id: "disc-o1",
      heading: "Order the Recon-to-Collection Chain on a Freshly Compromised Host",
      instructions:
        "Place these six steps of a discovery-to-collection chain in the order they actually occur, from the moment an attacker lands on one host to the point data leaves the network.",
      items: [
        { id: "step-host", text: "The attacker runs whoami and net user on the freshly compromised host to identify the current account and its local privileges (T1033)" },
        { id: "step-localgroup", text: "The attacker runs net localgroup administrators to see who else has local admin rights on this specific machine" },
        { id: "step-domain", text: "The attacker runs net user /domain and net group \"domain admins\" /domain against the Domain Controller to map domain-wide accounts and privileged groups (T1087.002, T1069.002)" },
        { id: "step-share", text: "The attacker runs net view \\\\fileserver01 and net share to find which network shares are reachable and what they expose (T1135)" },
        { id: "step-collect", text: "The attacker mounts a discovered share with net use and copies files off it in bulk using Robocopy (T1039 -- now Collection, not Discovery)" },
        { id: "step-exfil", text: "The attacker compresses and exfiltrates the collected files to attacker-controlled infrastructure" },
      ],
      correct_order: ["step-host", "step-localgroup", "step-domain", "step-share", "step-collect", "step-exfil"],
      explanation:
        "This is the full arc this room teaches: recon scales from the single host outward (T1033, then local group checks) to the whole domain (T1087.002/T1069.002), before shifting to shares (T1135) and finally crossing the tactic boundary into Collection (T1039) and Exfiltration. Each step depends on knowledge the previous step provided -- an attacker cannot usefully target a share before knowing it exists, and cannot usefully enumerate the domain before knowing their own starting privilege.",
      xp: 20,
    },

    // ── Reading 7: detection methodology ─────────────────────────────────────
    {
      type: "reading" as const,
      id: "disc-r7",
      heading: "Detecting Discovery Like an Analyst: Baselining, Velocity, and the False-Positive Problem",
      content:
        "Every reading above has pointed at the same underlying principle from a different angle. This reading makes it explicit: a single discovery-shaped event is baseline noise; a pattern is the signature.\n\n" +
        "Three questions turn noise into signal. (1) **Is this identity or host EXPECTED to do this?** A helpdesk service account running net user /domain at 3 AM as part of a nightly audit script is baseline -- IT can confirm the scheduled task that owns it. The identical command from a marketing laptop, once, is not expected. (2) **Is the VOLUME and BREADTH consistent with a human, an automated tool, or an attacker's sweep?** A person manually checking a handful of accounts touches a handful of objects over minutes. A legitimate inventory tool touches everything, on a fixed schedule, from a documented service identity. An attacker's enumeration tool touches dozens-to-thousands of objects in a tight burst, from an identity with no scheduled reason to do so. (3) **Does this activity correlate with something else in the timeline?** Discovery almost never IS the incident by itself -- it's the leading indicator. Did it follow a phishing click or an anomalous sign-in? Is it followed by Lateral Movement, Privilege Escalation, or Collection?\n\n" +
        "Discovery generates more false positives than almost any other tactic, because so much of the SOC's own tooling performs it as its actual job: vulnerability scanners (Nessus, Qualys, Rapid7) run port/service scans across the entire IP range -- literally T1046's signature, on purpose, on schedule. RMM/asset-management tools (SCCM, Intune) enumerate installed software, local groups, and logged-on users across every managed endpoint. Infrastructure-as-code tools (Terraform, CloudFormation) run Describe*/List* sweeps on every apply to detect drift -- exactly T1580's signature. Backup software enumerates network shares to know what to back up -- exactly T1135's signature. IT helpdesk scripts run nightly domain account audits.\n\n" +
        "None of these are edge cases -- they are the majority of the volume a real discovery-focused rule will fire on. The professional discipline is maintaining an allowlist of the specific accounts, hosts, and schedules authorized to generate this traffic, and alerting on everything OUTSIDE that allowlist rather than on the raw pattern alone.",
      diagram:
        "flowchart TD\n" +
        "  A[Discovery-shaped event fires] --> B{Is this identity/host\\nexpected to do this?}\n" +
        "  B -->|Yes, matches allowlist| C[Baseline -- close, no escalation]\n" +
        "  B -->|No, or unclear| D{Volume and breadth\\nconsistent with a sweep?}\n" +
        "  D -->|Single query, narrow| E[Lead -- log, watch for repeats]\n" +
        "  D -->|Burst across many objects/services| F{Correlates with a\\nsuspicious precursor or follow-on?}\n" +
        "  F -->|Yes| G[Escalate -- likely reconnaissance]\n" +
        "  F -->|No known correlation yet| H[Investigate further before verdict]\n",
      diagramCaption: "The three-question decision framework this reading teaches",
      checkpoint: {
        question: "Why does this reading insist that vulnerability scanners, RMM tools, and IT audit scripts are 'the majority of the volume,' not edge cases to ignore?",
        options: [
          "Because these tools are actually more dangerous than real attacker enumeration, so they deserve the highest-priority alerts",
          "Because a real discovery-focused detection rule will fire on this legitimate traffic far more often than on genuine attacker activity, making an accurate allowlist essential rather than optional",
          "Because vulnerability scanners are technically incapable of ever triggering a Discovery-tactic detection rule under any configuration",
          "Because MITRE ATT&CK explicitly excludes any activity performed by an authorized security tool from being classified under the Discovery tactic",
        ],
        answer: 1,
        explanation: "This is the practical weight of the false-positive problem: legitimate scanning/audit/IaC tools generate the bulk of discovery-shaped telemetry, so an accurate allowlist of authorized accounts/hosts/schedules is what makes the detection usable rather than a flood of tickets. These tools are not more dangerous than real attackers, they absolutely can and do trigger the same detection logic, and ATT&CK classifies techniques by behavior, not by the identity of who performed them.",
      },
      xp: 5,
    },

    // ── Question 4 ─────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "disc-q4",
      question:
        "A burst of 200 net group /domain queries fires from two different sources in the same hour: Source A is a documented Qualys vulnerability-scanner service account running its Tuesday 2 AM job; Source B is a marketing department laptop with no prior domain-query history. Per this room's detection discipline, how should these be triaged?",
      options: [
        "Identically -- since both sources produced the exact same command and volume, they must be treated as equally severe findings",
        "Source A should be escalated as the higher-priority finding, since a security-team-owned account is inherently more suspicious than an ordinary employee laptop",
        "Source A should be confirmed against the documented allowlist and closed as expected; Source B falls outside any authorized pattern and warrants investigation",
        "Neither should be investigated, since net group /domain is a fully legitimate Windows command that no analyst can ever act on",
      ],
      answer: 2,
      explanation:
        "This is the allowlist discipline applied directly: Source A matches a documented, authorized account/host/schedule and should be confirmed and closed; Source B has no such match and no prior history, which is exactly the profile worth investigating. Identical command and volume do not mean identical risk once source and expectation are considered -- that is the whole point of baselining. A security-team-owned account being 'inherently more suspicious' inverts the actual reasoning taught here.",
      xp: 20,
    },

    // ── Analyst choice: FP control case ──────────────────────────────────────
    {
      type: "analyst_choice" as const,
      id: "disc-ac1",
      heading: "Triage: Nightly Domain Account Audit on SRV-ITAUDIT01",
      scenario:
        "An alert fires for 'domain account enumeration command executed' on SRV-ITAUDIT01. The rule watches for any net user /domain or Get-ADUser execution anywhere in the environment, with no allowlist. Checking history shows this exact command has run from this exact server, under this exact service account, at this exact time, every night, for two years.",
      event: nightlyAuditEvent,
      correct_verdict: "false_positive",
      explanation:
        "This is the allowlist principle from the detection-discipline reading applied directly: a scheduled, IT-confirmed nightly audit script, from a service account with no interactive logon capability, running from the one server it always runs from, at the time it always runs. There is no volume anomaly, no unexpected source, and IT verification confirms the scheduled task by name. This is the control case -- a real domain-enumeration command that is not an attack.",
      fp_trap:
        "The alert rule fires on ANY execution of this command anywhere in the environment, with no allowlist for the very source this room's detection-discipline reading names explicitly -- a scheduled, IT-confirmed nightly audit script. Escalating this without checking source, schedule, and IT verification is the textbook mistake this room is built to correct.",
      xp: 20,
    },

    // ── Matching task ──────────────────────────────────────────────────────
    {
      type: "matching" as const,
      id: "disc-m1",
      heading: "Match Each Discovery Technique to Its Real Example Command or API",
      instructions:
        "Match each MITRE ATT&CK technique ID from this room to a real, documented example command or API call for that technique.",
      pairs: [
        { id: "p1", left: "T1033 -- System Owner/User Discovery", right: "whoami, query user, net config workstation" },
        { id: "p2", left: "T1087.002 -- Domain Account Discovery", right: "net user /domain, Get-ADUser" },
        { id: "p3", left: "T1069.002 -- Permission Groups Discovery: Domain Groups", right: "net group \"domain admins\" /domain, Get-ADGroup" },
        { id: "p4", left: "T1018 -- Remote System Discovery", right: "net view /domain, nltest /dclist, arp -a" },
        { id: "p5", left: "T1580 -- Cloud Infrastructure Discovery", right: "DescribeInstances, az vm list, gcloud compute instances list" },
        { id: "p6", left: "T1526 -- Cloud Service Discovery", right: "Microsoft Graph / Azure Resource Manager enumeration via Stormspotter" },
        { id: "p7", left: "T1619 -- Cloud Storage Object Discovery", right: "ListObjectsV2, Azure List Blobs" },
        { id: "p8", left: "T1135 -- Network Share Discovery", right: "net view \\\\remotesystem, net share" },
      ],
      explanation:
        "This is the full technique map this room covers, host to cloud: T1033 establishes local identity, T1087.002/T1069.002 scale that to the whole domain, T1018 maps reachable machines, and T1580/T1526/T1619 are the cloud-native equivalents of the same questions asked through APIs instead of net.exe. T1135 sits apart as the final Discovery step before T1039 crosses into the Collection tactic, covered separately in this room's reading on that boundary.",
      xp: 25,
    },

    // ── Flag ──────────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "disc-f1",
      prompt:
        "This room's cloud reading names three real AWS GuardDuty finding types built specifically to detect Discovery-tactic activity. Which exact finding type flags an S3 ListObjectsV2-family call made from an IP address already known to be malicious? Answer in the exact Category:Resource/Name format.",
      answer: "Discovery:S3/MaliciousIPCaller",
      hint: "Covered in the reading 'Discovery in the Cloud' -- it's the S3-specific one, distinct from Recon:IAMUser/MaliciousIPCaller, which covers IAM-level reconnaissance instead.",
      xp: 15,
    },
  ],
};

export const roomsBatch42 = [discoveryEnumerationRoom];
