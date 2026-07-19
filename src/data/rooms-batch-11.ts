import type { TelemetryEvent } from "@/lib/sim/types";

const rooms = [
  // ─────────────────────────────────────────────────────────────
  // Room 1 — Authentication & Identity Monitoring
  // ─────────────────────────────────────────────────────────────
  {
    id: "auth-identity-monitoring",
    title: "Authentication & Identity Monitoring",
    description:
      "Learn to detect password sprays, credential stuffing, impossible travel, and Kerberos-based attacks by reading Windows authentication logs.",
    difficulty: "intermediate",
    category: "Threat Detection",
    estimatedMinutes: 45,
    xp: 450,
    icon: "🔑",
    prerequisites: ["windows-event-logs"],
    tasks: [
      // ── Reading 1 ──────────────────────────────────────────────
      {
        type: "reading",
        id: "auth-r1",
        heading: "How Authentication Works — and How Attackers Abuse It",
        content:
          "**Analogy:** Imagine a nightclub with a list at the door. When you arrive, the bouncer checks your name (username) and your ID (password). If they match the list, you're in. An attacker who wants inside has two choices: guess your name and ID combination, or steal your ID entirely.\n\nEvery time a user logs on to a Windows computer or server, the operating system writes an event to the **Security Event Log**. These events are the bouncer's notebook — a permanent record of everyone who tried to enter and whether they succeeded.\n\nThe most important events you'll encounter as a SOC analyst are:\n\n- **Event ID 4624** — Successful logon. The 'Logon Type' field tells you *how* the user authenticated:\n  - Type 2 = Interactive (sitting at the keyboard)\n  - Type 3 = Network (from another machine — file shares, mapped drives)\n  - Type 10 = RemoteInteractive (Remote Desktop / RDP)\n- **Event ID 4625** — Failed logon. Every wrong password, expired account, or disabled user lands here. The `SubStatus` field is a hex code that tells you *why* it failed: `0xC000006A` = wrong password, `0xC0000064` = username doesn't exist, `0xC0000234` = account locked out.\n- **Event ID 4648** — Explicit credential use. This fires when a process starts using *different* credentials — for example, `runas.exe` or a service running as another account. Attackers who have stolen credentials but aren't logged in as that user will generate this event.\n- **Event ID 4768 / 4769** — Kerberos ticket requests. Kerberos is the authentication protocol for Active Directory environments. 4768 is a Ticket Granting Ticket (TGT) request — 'I want to prove who I am.' 4769 is a Service Ticket (TGS) request — 'I want to access a specific service.'\n\n**Why does any of this matter?** Because attackers must authenticate to do almost anything on a Windows network. Moving laterally to a new server, accessing a file share, running a remote command — all of these leave authentication footprints. If you can read the authentication log, you can often catch the attacker in the act.\n\n**The NTLM vs Kerberos split** is worth understanding. Kerberos is the modern, preferred protocol in Active Directory. NTLM is the older fallback — used when a client connects by IP address instead of hostname, or when Kerberos is unavailable. Seeing a high volume of NTLM auth from modern machines is suspicious; it may mean an attacker is forcing NTLM to capture hashes for offline cracking (NTLM relay attacks).\n\n**Account lockout (Event 4740)** fires when a user hits the maximum number of failed attempts and their account gets locked. A single lockout is normal — a user typed their password wrong. A wave of lockouts across 20 different accounts at 2 AM is an attacker running a spray.\n\nAs a SOC analyst, you don't read these logs one by one. You look at *patterns*: many 4625s from the same IP in a short window, 4740s appearing on accounts that don't usually get locked, or a 4624 Type 10 (RDP) from a country where no employee lives.",
      },
      // ── Reading 2 ──────────────────────────────────────────────
      {
        type: "reading",
        id: "auth-r2",
        heading: "Password Spray vs Credential Stuffing — Spot the Difference",
        content:
          "**Analogy:** A password spray is like a burglar who walks down a street and tries the same master key on every front door, hoping one house has a bad lock. Credential stuffing is like that same burglar using a stolen list of house keys — they know the real keys, they just don't know *which house* each key belongs to.\n\nBoth attacks are designed to stay under the radar of account lockout policies. Here's how each one works:\n\n**Password Spray:**\n- The attacker picks one or a few common passwords: `Spring2024!`, `Company123`, `Welcome1`.\n- They try that password against *every account in the organisation* — hundreds or thousands.\n- Because they only try each account once or twice, the account lockout threshold (e.g. 5 failed attempts) is never triggered.\n- In the Windows Security log, you'll see Event 4625 with SubStatus `0xC000006A` (wrong password) distributed across *many different* `TargetUserName` values, all from the **same source IP** in a short time window.\n- Detection signature: **single source IP, many target accounts, low attempt count per account, SubStatus 0xC000006A**.\n\n**Credential Stuffing:**\n- The attacker has a database of username + password pairs leaked from another breach (e.g. from the 2021 RockYou2021 leak).\n- They try those exact pairs against your login page or VPN.\n- Attempt counts per account are also low — usually one or two per account.\n- The difference is that some attempts *succeed*, because users reused their password from the breached site.\n- Detection: mixed SubStatus codes (some 0xC000006A, some 4624 successes), and the successful logon IPs may be in unusual geographic locations.\n\n**Impossible Travel** is one of the most reliable signals in identity monitoring. If a user successfully authenticates from New York at 09:00 and then again from Tokyo at 09:45, something is wrong — no human can travel that distance in 45 minutes. This pattern means either the account is compromised (attacker in Tokyo) or the user is using a VPN that exits in a different country.\n\nSIEM tools like Microsoft Sentinel and Splunk can calculate the time and distance between consecutive logons and fire an alert when the implied travel speed is physically impossible. The raw events are still just two 4624s — the intelligence comes from correlating them.\n\n**Golden Ticket** attacks are the most dangerous Kerberos attack. After an attacker compromises the Domain Controller and extracts the `krbtgt` account's NTLM hash, they can forge any Kerberos ticket for any user at any time — with no expiry and no account password required. Indicators in logs:\n- Kerberos tickets with lifetimes much longer than your policy (standard is 10 hours, golden tickets are often set to 10 years)\n- 4769 events for service tickets where no corresponding 4768 TGT was issued (forged tickets skip the TGT step)\n- Events from accounts that don't exist in Active Directory\n\nAs an analyst, catching a golden ticket requires comparing the ticket lifetime in 4769 events against your organisation's Kerberos policy. Most SIEM systems have a dedicated detection rule for this.",
      },
      // ── Reading 3 ──────────────────────────────────────────────
      {
        type: "reading",
        id: "auth-r3",
        heading: "Building an Authentication Investigation — Step by Step",
        content:
          "**Analogy:** When a fire alarm goes off in a building, a good fire marshal doesn't just check one room and declare 'all clear.' They check the source room, check adjacent rooms, look at the alarm panel history, and figure out *how* the fire started. An authentication alert works the same way — the first event is just the alarm; your job is to find the fire.\n\nHere is the step-by-step approach a SOC analyst uses when an authentication alert fires:\n\n**Step 1 — Confirm the pattern.** Pull all 4625 events from the alerted source IP in the last 60 minutes. How many target accounts? What's the SubStatus? Is this one user mistyping their password (1 account, 5 attempts) or a spray (50 accounts, 1-2 attempts each)?\n\n**Step 2 — Check for success.** Did any 4624 follow the failures from that same IP? A 4624 after a spray pattern is an 'access gained' indicator — priority escalates immediately.\n\n**Step 3 — Geolocate the source IP.** Every 4625 and 4624 event contains `IpAddress`. Plug it into your SIEM's IP enrichment or a threat intel feed. Is it from a known corporate VPN range? An employee's home ISP? A Tor exit node? A datacenter in a country you don't operate in?\n\n**Step 4 — Examine the target accounts.** In a spray, the attacker usually tries all accounts alphabetically or from a harvested directory. Look at whether the targets are real accounts vs guesses. If `SubStatus = 0xC0000064` (account doesn't exist) appears alongside `0xC000006A`, the attacker is also doing user enumeration.\n\n**Step 5 — Check lockout state.** Query Active Directory or SIEM for Event 4740 (lockout) on any of the targeted accounts. Multiple lockouts from a spray means the attacker got impatient and increased attempt frequency.\n\n**Step 6 — Check for lateral movement after success.** If an account was successfully authenticated, did it immediately access file shares (Event 5140), log on to other hosts (4624 Type 3 from that account on a different machine), or run privileged commands?\n\n**Step 7 — Document and escalate.** Write a timeline: first failure timestamp, last failure, any successes, source IP geolocation, affected accounts. If a success was recorded from a suspicious IP, escalate to Tier 2 immediately — that account should be disabled while investigation continues.\n\n**Threshold-based detection rules** in your SIEM automate Step 1. A typical rule looks like: 'Fire an alert if a single source IP generates more than 20 failed logon events (4625) targeting more than 10 distinct accounts within 5 minutes.' Tuning these thresholds is an ongoing process — set them too low and you alert on every user who mistyped their password; set them too high and a slow spray goes undetected.\n\n**Key takeaway:** authentication logs are the most densely populated logs in any Windows environment. The skill is not reading individual events — it is recognising patterns across thousands of events and knowing which patterns indicate human error versus an active attack.",
      },
      // ── Question 1 ──────────────────────────────────────────────
      {
        type: "question",
        id: "auth-q1",
        question:
          "A SOC analyst sees 80 Event ID 4625 entries within 3 minutes, all from IP 185.220.101.45, targeting 75 different user accounts, each account attempted exactly once. SubStatus is 0xC000006A on all events. What attack technique does this BEST describe?",
        options: [
          "Credential stuffing using a breached password database",
          "Password spray — one common password tried across many accounts",
          "Brute force attack against a single administrator account",
          "Pass-the-Hash lateral movement between domain-joined hosts",
        ],
        answer: 1,
        explanation:
          "This is a textbook password spray: one source IP, many target accounts, very low attempt count per account (1 attempt each, staying under lockout threshold), and SubStatus 0xC000006A meaning 'wrong password' — the attacker is trying the same guessed password against every account. Credential stuffing would show mixed SubStatus results including some 4624 successes. Brute force concentrates many attempts on one account. Pass-the-Hash does not generate 4625 events with 0xC000006A.",
        xp: 20,
      },
      // ── Question 2 ──────────────────────────────────────────────
      {
        type: "question",
        id: "auth-q2",
        question:
          "A user's account shows a successful logon (Event 4624) from London at 08:00 UTC, and another successful logon from Sydney at 08:50 UTC, 50 minutes later. The distance is approximately 17,000 km. What is this detection technique called, and what is the MOST likely conclusion?",
        options: [
          "Kerberoasting — the attacker cracked a service account password offline",
          "Impossible travel — the account is likely compromised since no human can cover 17,000 km in 50 minutes",
          "Pass-the-Ticket — a golden ticket was used to forge the Sydney logon",
          "Account sharing — the user legitimately gave their password to an overseas colleague",
        ],
        answer: 1,
        explanation:
          "Impossible travel detection identifies when the implied speed between two consecutive successful logons is physically impossible. London to Sydney (17,000 km) in 50 minutes requires ~20,000 km/h — far beyond any aircraft. The most likely conclusion is account compromise: an attacker in Sydney obtained the user's credentials. Account sharing is a policy violation and would not explain the geographic distance without prior coordination. Kerberoasting and Pass-the-Ticket are different attack types not directly evidenced here.",
        xp: 20,
      },
      // ── Question 3 ──────────────────────────────────────────────
      {
        type: "question",
        id: "auth-q3",
        question:
          "Which Windows Security Event ID fires when a Domain Controller detects that a user account has exceeded the maximum failed logon attempt threshold and locks the account?",
        options: ["4625", "4648", "4740", "4769"],
        answer: 2,
        explanation:
          "Event ID 4740 is 'A user account was locked out.' It is generated on the Domain Controller that enforced the lockout policy. Event 4625 is a failed logon attempt (one of the events that *leads to* the lockout). Event 4648 is explicit credential use. Event 4769 is a Kerberos service ticket request. In a password spray investigation, 4740 appearing on multiple accounts in a short window is a high-confidence indicator that spray volume exceeded the lockout threshold.",
        xp: 15,
      },
      // ── Log Analysis ───────────────────────────────────────────
      {
        type: "log_analysis",
        id: "auth-la1",
        heading: "Investigate a Password Spray in Progress",
        context:
          "Your SIEM fired alert CORP-AUTH-0101: 'Password spray detected — 62 failed logon events from single IP targeting 58 accounts in 4 minutes.' The event below is a representative sample from the alert. All 62 events share the same source IP and SubStatus code. Three of the targeted accounts successfully authenticated 7 minutes after the failures stopped.",
        event: {
          id: "evt-auth-spray-001",
          ts: "2026-06-24T02:17:34.812Z",
          source: "windows_security",
          event_type: "auth_failure",
          hostname: "DC01.corp.internal",
          severity: "high",
          raw: {
            "event.code": "4625",
            "winlog.channel": "Security",
            "winlog.computer_name": "DC01.corp.internal",
            "winlog.event_data.TargetUserName": "j.morrison",
            "winlog.event_data.TargetDomainName": "CORP",
            "winlog.event_data.IpAddress": "185.220.101.45",
            "winlog.event_data.IpPort": "52841",
            "winlog.event_data.LogonType": "3",
            "winlog.event_data.LogonProcessName": "NtLmSsp",
            "winlog.event_data.AuthenticationPackageName": "NTLM",
            "winlog.event_data.SubStatus": "0xC000006A",
            "winlog.event_data.Status": "0xC000006D",
            "winlog.event_data.WorkstationName": "-",
            "winlog.event_data.ProcessName": "-",
            "winlog.event_data.TransmittedServices": "-",
            "winlog.event_data.KeyLength": "0",
            "event.created": "2026-06-24T02:17:34.812Z",
            "log.level": "warning",
            "tags": ["authentication", "spray-alert", "CORP-AUTH-0101"],
          },
        },
        questions: [
          {
            question:
              "The SubStatus field shows '0xC000006A'. Based on the reading material, what does this hex code mean?",
            options: [
              "The user account does not exist in the directory",
              "The user account is currently locked out",
              "The password provided was incorrect",
              "The account's logon hours restriction blocked the attempt",
            ],
            answer: 2,
            explanation:
              "0xC000006A = STATUS_WRONG_PASSWORD — the username exists and was found in the directory, but the password supplied did not match. This is the key SubStatus code for a password spray where the attacker is guessing the same common password against real accounts. If the username didn't exist it would be 0xC0000064. If the account were locked it would be 0xC0000234.",
            xp: 20,
          },
          {
            question:
              "The LogonType is '3' and AuthenticationPackageName is 'NTLM'. What does this combination tell you about HOW the attacker is authenticating?",
            options: [
              "The attacker is sitting at a physical keyboard on the DC (interactive logon)",
              "The attacker is connecting over the network using NTLM — possibly because they are connecting by IP address rather than hostname, or Kerberos is unavailable",
              "The attacker is using a Remote Desktop session and has domain credentials",
              "The attacker has already obtained a Kerberos TGT and is using it to request service tickets",
            ],
            answer: 1,
            explanation:
              "Logon Type 3 is a network logon — the authentication request arrived over the network, not from a local interactive session. NTLM being used instead of Kerberos (the preferred AD protocol) often means the attacker connected by IP address (e.g., \\\\185.220.101.45\\share) rather than hostname, or that they are targeting a service that only supports NTLM. This is a common pattern in sprays where automated tools connect directly by IP.",
            xp: 20,
          },
          {
            question:
              "The alert notes that 3 accounts successfully authenticated 7 minutes AFTER the spray ended. What is the CORRECT next action for the analyst?",
            options: [
              "Close the alert as resolved — the spray stopped and the 3 successes are probably coincidental",
              "Increase the SIEM threshold to reduce future alert noise from similar patterns",
              "Immediately disable the 3 accounts that had successful logons, preserve evidence, and escalate to Tier 2 for full investigation of what those accounts accessed post-logon",
              "Block the source IP at the perimeter firewall and take no further action since the attack is over",
            ],
            answer: 2,
            explanation:
              "Three successful logons immediately after a spray from the same source IP is a 'spray followed by success' pattern — the attacker found valid credentials. Blocking the IP is a useful containment step but is insufficient alone (attackers switch IPs). Closing the alert ignores a likely compromise. The most important actions are: disable the compromised accounts to stop further access, pull post-logon activity (what did those accounts do in the 7 minutes?), and escalate so a Tier 2 analyst can determine the blast radius.",
            xp: 25,
          },
        ],
      },
      // ── Ordering Task — Password Spray Attack Sequence ──────────
      {
        type: "ordering" as const,
        id: "auth-o1",
        heading: "Order the Password Spray Attack Stages",
        instructions: "A password spray attack follows a specific sequence. Arrange these stages from the very first attacker action to the final post-compromise activity. Select an item on the right, then click a numbered slot on the left.",
        items: [
          { id: "recon",    text: "Username enumeration — attacker gathers a list of valid domain usernames (LinkedIn, email format guessing, LDAP query)" },
          { id: "single",   text: "Single-password spray — one common password tried against ALL accounts to stay below lockout threshold" },
          { id: "rotate",   text: "Password rotation — attacker waits the lockout observation window, then tries the next common password" },
          { id: "success",  text: "Credential validation — one or more accounts authenticate successfully with the sprayed password" },
          { id: "logon",    text: "Logon and reconnaissance — attacker logs in as the compromised account and maps the environment" },
          { id: "lateral",  text: "Lateral movement — attacker uses compromised credentials to access additional systems or elevate privileges" },
        ],
        correct_order: ["recon", "single", "rotate", "success", "logon", "lateral"],
        explanation: "Password spray must follow this sequence because each stage depends on the previous. Reconnaissance comes first because the attacker needs valid usernames before they can spray. Single-password spray is the distinguishing feature of spray vs. brute force — one guess per account stays under lockout thresholds. The waiting period (rotate) mimics the lockout observation window used by many organizations. Successful authentication is the pivot point where the attack shifts from credential theft to active intrusion. Understanding this sequence helps analysts recognize spray at earlier stages — catching it at 'single-password spray' or even 'username enumeration' prevents the lateral movement stage entirely.",
        xp: 30,
      },

      // ── Flag ───────────────────────────────────────────────────
      {
        type: "flag",
        id: "auth-flag1",
        prompt:
          "Examine the log event in the analysis section above. The `winlog.event_data.SubStatus` field contains a Windows NTSTATUS hex code that identifies exactly WHY the authentication failed. Enter that hex code exactly as it appears in the raw log (include the '0x' prefix).",
        answer: "0xC000006A",
        hint: "Look at the SubStatus field in the raw log. It is an eight-character hex value beginning with 0xC — and it means 'wrong password.'",
        xp: 35,
      },
    ],
  },

  // ─────────────────────────────────────────────────────────────
  // Room 2 — Privileged Access Monitoring
  // ─────────────────────────────────────────────────────────────
  {
    id: "privileged-access-monitoring",
    title: "Privileged Access Monitoring",
    description:
      "Master the detection of privilege abuse — from Domain Admin misuse and SeDebugPrivilege to LSASS dumping and PAM vault anomalies.",
    difficulty: "advanced",
    category: "Threat Detection",
    estimatedMinutes: 50,
    xp: 500,
    icon: "👑",
    prerequisites: ["auth-identity-monitoring"],
    tasks: [
      // ── Reading 1 ──────────────────────────────────────────────
      {
        type: "reading",
        id: "priv-r1",
        heading: "What Privileged Accounts Are and Why Attackers Love Them",
        content:
          "**Analogy:** In a hospital, most staff can access their own patient ward and the common areas. But a small group — the hospital administrator, the chief of surgery, the IT director — have a master key that opens every door. If an attacker steals an ordinary nurse's badge, they can access one ward. If they steal the administrator's master key, they can access everything, including the pharmacy, the server room, and the billing department. Privileged accounts are that master key.\n\nIn an Active Directory environment, 'privileged' means different things at different levels:\n\n**Domain-level privileges:**\n- **Domain Admins** — the highest human-operated group. Members can manage every object in Active Directory, log on to every domain-joined machine, and reset any password including other admins.\n- **Enterprise Admins** — even higher; control multiple Active Directory forests. Usually only a handful of people should ever be in this group.\n- **Schema Admins** — can modify the AD schema itself. Should be empty except during deliberate schema extensions.\n\n**Machine-level privileges:**\n- **Local Administrators** — admin rights on a single machine, not the whole domain. Still dangerous for lateral movement.\n- **Service Accounts** — non-human accounts that run background services (backup software, monitoring agents, database engines). They often have elevated rights but are not supposed to be used interactively by humans.\n\n**Windows Privilege Rights (User Rights):**\nBeyond group membership, Windows assigns specific 'privilege rights' to accounts. These are lower-level than group membership and control what a process can do:\n- **SeDebugPrivilege** — allows a process to read and write memory of *any other process*, including the LSASS process (which stores credential hashes). This is the privilege used by tools like Mimikatz to dump credentials. Legitimate holders: SYSTEM, local administrators. Seeing this on a service account is a red flag.\n- **SeBackupPrivilege** — allows reading any file regardless of file permissions, ostensibly for backup software. An attacker with this privilege can read the NTDS.DIT file (the Active Directory database containing all password hashes) off a Domain Controller.\n- **SeRestorePrivilege** — allows writing any file regardless of file permissions. Combined with SeBackupPrivilege, an attacker can replace system files.\n- **SeTcbPrivilege** — 'Act as part of the operating system.' Extremely powerful; almost never legitimately granted to non-SYSTEM accounts.\n\n**Why attackers target privileged accounts:**\n1. **Persistence** — Domain Admin can create new accounts, modify group policies, and maintain access even if their initial foothold is evicted.\n2. **Lateral movement** — Local admin credentials work on every machine in the environment if password reuse is present (Pass-the-Hash).\n3. **Credential harvesting** — SeDebugPrivilege + LSASS access = every logged-on user's password hash in memory.\n4. **Data access** — With SeBackupPrivilege, the entire AD database can be read and exfiltrated.\n\nThe key insight for monitoring: **privilege use should be rare, predictable, and from expected sources.** A Domain Admin account that logs on every weekday morning from the same workstation is normal. That same account logging on at 3 AM from a new machine via RDP is an alert.",
      },
      // ── Reading 2 ──────────────────────────────────────────────
      {
        type: "reading",
        id: "priv-r2",
        heading: "Key Windows Events for Privileged Activity Detection",
        content:
          "**Analogy:** A high-security vault doesn't just have a lock — it has a camera, a visitor log, a guard who signs people in and out, and an alarm on the door. Windows privileged access events are that multi-layer record: every privilege grant, every group change, every special logon is written down.\n\nHere are the critical event IDs every SOC analyst must know for privileged access monitoring:\n\n**Event 4672 — Special Logon (Admin Rights Granted):**\nThis event fires every time a user logs on with administrator-equivalent privileges. The `PrivilegeList` field lists every elevated privilege right their token carries. Key fields: `SubjectUserName` (who logged on), `SubjectLogonId` (their session ID, links to 4624), `PrivilegeList` (list of special privileges). Normal: your Domain Admin logging on from their admin workstation generates this. Abnormal: a service account (`svc-` prefix) generating 4672 with dangerous privileges like `SeDebugPrivilege`, or any 4672 at an unusual time.\n\n**Event 4728 — A member was added to a security-enabled global group:**\n**Event 4732 — A member was added to a security-enabled local group:**\n**Event 4756 — A member was added to a security-enabled universal group:**\nAll three record group membership changes. The critical version: `Domain Admins`, `Enterprise Admins`, `Administrators` as the target group. Any addition to these groups should be a change-ticket in your organisation — if no ticket exists, treat it as malicious. Field to watch: `MemberSid` (who was added) and `TargetUserName` (name of the group).\n\n**Event 4673 — Sensitive Privilege Use:**\nFires when a process actually *uses* a sensitive privilege (SeDebugPrivilege, SeBackupPrivilege, etc.) — not just holds it. This is noisier than 4672 (fires per-use, not per-logon) but catches active abuse. Look for process names that shouldn't be using these privileges: `cmd.exe`, `powershell.exe`, or unknown executables using `SeDebugPrivilege` is very suspicious.\n\n**Event 4688 / Sysmon Event 1 — Process Creation:**\nAttackers use tools like `PsExec` (legitimate remote admin tool, heavily abused) and `wmic.exe` to move laterally and execute commands as SYSTEM. PsExec generates an Event 7045 (service installed) on the target machine when it creates its remote service. Watch for `psexec` in process command lines and for new services with random names (e.g., `PSEXESVC`).\n\n**LSASS access patterns (Sysmon Event 10 — Process Access):**\nLSASS.EXE is the Windows process that holds credential material (password hashes, Kerberos tickets) in memory. Legitimate access to LSASS is done only by specific Windows system processes. Mimikatz and similar tools access LSASS with `GrantedAccess = 0x1FFFFF` (full access) or `0x1010` (read virtual memory). Sysmon's Event 10 records which process opened which handle to LSASS, and with what access rights. This is one of the most reliable detections for credential dumping.\n\n**PAM (Privileged Access Management) Solutions:**\nIn mature organisations, privileged accounts are managed by PAM vaults — systems like **CyberArk** or **BeyondTrust** that:\n- Store admin passwords in an encrypted vault (analysts never know the actual password)\n- Require checkout with a reason before granting access\n- Rotate passwords automatically after each use\n- Record every keystroke and command during privileged sessions\n\nPAM logs to monitor: vault checkout events (who checked out which account, when, and with what justification), session recordings reviewed post-incident, and any attempt to access a privileged account *outside* the PAM vault (bypassing controls). **Just-in-time (JIT) access** is a modern pattern where an account only receives admin privileges for the duration it's needed — a 2-hour window rather than permanent membership.\n\nA service account checking out a Domain Admin credential from the PAM vault with no associated change ticket is an immediate escalation trigger.",
      },
      // ── Reading 3 ──────────────────────────────────────────────
      {
        type: "reading",
        id: "priv-r3",
        heading: "Privilege Escalation Kill Chain — What the Attacker Does Step by Step",
        content:
          "**Analogy:** A burglar who breaks into a mailroom doesn't stop there — they look for the master keycard, find the door to the server room, copy the management computer's drive, and walk out with everything. In cyber, this progression is called the 'kill chain' or 'attack path.' Privilege escalation is the step where a burglar finds that master keycard.\n\nHere is a realistic attacker progression from regular user to Domain Admin, and the events each step generates:\n\n**Step 1 — Initial access as a regular user.**\nThe attacker phishes an employee and gets their domain credentials. They authenticate via VPN (Event 4624, Type 3). Their token has no special privileges. Events: 4624 from an external IP, potentially via unusual VPN endpoint.\n\n**Step 2 — Local privilege escalation on the compromised workstation.**\nThe attacker uses an unpatched local vulnerability (e.g., PrintNightmare, AlwaysInstallElevated) or a misconfigured service running as SYSTEM to get local admin. Events: 4672 with elevated privileges on the compromised host, 4688 showing a child process spawned from a vulnerable service.\n\n**Step 3 — Credential harvesting from LSASS.**\nWith local admin rights, the attacker runs Mimikatz: `sekurlsa::logonpasswords`. This reads LSASS memory and extracts NTLM hashes and Kerberos tickets for every user who has a session on that machine. If a Domain Admin happened to have logged on, their hash is now in the attacker's hands. Events: Sysmon Event 10 (LSASS access with GrantedAccess 0x1FFFFF), AV detection if not disabled, Windows Defender alert.\n\n**Step 4 — Pass-the-Hash / Pass-the-Ticket to Domain Admin.**\nThe attacker uses the stolen Domain Admin NTLM hash directly without cracking it (Pass-the-Hash). They connect to the Domain Controller using that hash. Events: 4624 on the DC with LogonType 3, NTLM authentication package (not Kerberos), source IP of the compromised workstation, SubjectUserName = Domain Admin.\n\n**Step 5 — DCSync / NTDS extraction.**\nOnce on the Domain Controller, the attacker runs `mimikatz lsadump::dcsync /domain:corp.local /all`. This mimics a legitimate Domain Controller replication request and pulls all password hashes from Active Directory without touching the NTDS.DIT file on disk. Events: Event 4662 (Directory Service access) with access mask 0x100 and GUID for DS-Replication-Get-Changes. Microsoft Defender for Identity (MDI) generates a 'DCSync attack suspected' alert.\n\n**Step 6 — Persistence via new admin account or golden ticket.**\nWith all hashes, the attacker creates a new Domain Admin account (Events 4720 account create, 4728 added to Domain Admins) or forges a golden ticket using the extracted `krbtgt` hash, giving them perpetual access regardless of password resets.\n\n**Analyst takeaway:** Each step in this chain is detectable if you have the right logging and rules in place. But each step also happens quickly — a skilled attacker can go from Step 1 to Step 6 in under 20 minutes. The goal of privileged access monitoring is to generate an alert at Step 2 or Step 3 — *before* Domain Admin is reached — so the response team can contain the compromise while it's still limited to one workstation.",
      },
      // ── Question 1 ──────────────────────────────────────────────
      {
        type: "question",
        id: "priv-q1",
        question:
          "A Sysmon Event 10 (ProcessAccess) fires showing that `powershell.exe` accessed `lsass.exe` with GrantedAccess value `0x1FFFFF`. What does this MOST likely indicate?",
        options: [
          "Windows Defender performing a routine memory scan of LSASS for malware",
          "A credential dumping tool (such as Mimikatz) attempting to extract password hashes and Kerberos tickets from LSASS memory",
          "Normal PowerShell management activity — PowerShell routinely reads LSASS to manage user sessions",
          "A backup agent performing a VSS snapshot that requires reading all process memory",
        ],
        answer: 1,
        explanation:
          "GrantedAccess 0x1FFFFF is PROCESS_ALL_ACCESS — the broadest possible access level to another process. Legitimate system processes that access LSASS (like Windows Defender's antimalware service) use much more restricted access masks. PowerShell has no legitimate reason to open full access to LSASS. This pattern — powershell.exe + LSASS + 0x1FFFFF — is the most common signature of Mimikatz's `sekurlsa::logonpasswords` command being executed in a PowerShell session.",
        xp: 20,
      },
      // ── Question 2 ──────────────────────────────────────────────
      {
        type: "question",
        id: "priv-q2",
        question:
          "Which combination of Windows Event IDs would BEST help a SOC analyst detect an attacker adding a newly created account to the Domain Admins group?",
        options: [
          "4625 (failed logon) + 4672 (special logon)",
          "4720 (account created) + 4728 (added to security-enabled global group)",
          "4769 (Kerberos service ticket) + 4662 (directory service access)",
          "4673 (sensitive privilege use) + 4688 (process creation)",
        ],
        answer: 1,
        explanation:
          "Creating a backdoor admin account generates Event 4720 (a user account was created) followed almost immediately by Event 4728 (a member was added to a security-enabled global group) where the target group is 'Domain Admins'. This two-event sequence with a new SID being added to a highly privileged group in quick succession is a strong indicator of persistence via account creation. Correlating 4720 → 4728 → (checking if target group is a privileged group) is a core SIEM detection rule.",
        xp: 20,
      },
      // ── Question 3 ──────────────────────────────────────────────
      {
        type: "question",
        id: "priv-q3",
        question:
          "What is the PRIMARY security purpose of a PAM (Privileged Access Management) vault solution like CyberArk?",
        options: [
          "To encrypt all network traffic between privileged users and the systems they manage",
          "To store privileged account passwords so that human administrators never know the actual password — requiring vault checkout, logging all use, and automatically rotating credentials after each session",
          "To enforce multi-factor authentication on VPN connections for all employees",
          "To scan Active Directory for accounts with excessive privileges and remove them automatically",
        ],
        answer: 1,
        explanation:
          "A PAM vault's core function is credential vaulting and session management: admin passwords are stored encrypted in the vault, users must check out credentials (with a justification) to use them, the actual password is injected into the session automatically (so the human never sees it and cannot share or reuse it), all session activity is recorded, and credentials are rotated after each checkout. This means a compromised human account cannot directly access privileged systems — the attacker would also need to compromise the vault itself.",
        xp: 20,
      },
      // ── Log Analysis ───────────────────────────────────────────
      {
        type: "log_analysis",
        id: "priv-la1",
        heading: "Service Account with Unexpected Privileges on a Domain Controller",
        context:
          "SIEM alert: 'Service account special logon with dangerous privilege list detected on DC01.' Your organisation's backup service account `svc-backup` is supposed to have SeBackupPrivilege and SeRestorePrivilege to allow it to read and write backup files. The event below was generated on the Domain Controller at 03:22 AM — outside of the scheduled backup window (weeknights 22:00-23:30). Review the event carefully.",
        event: {
          id: "evt-priv-4672-001",
          ts: "2026-06-24T03:22:11.004Z",
          source: "windows_security",
          event_type: "privilege_escalation",
          hostname: "DC01.corp.internal",
          severity: "critical",
          raw: {
            "event.code": "4672",
            "winlog.channel": "Security",
            "winlog.computer_name": "DC01.corp.internal",
            "winlog.event_data.SubjectUserName": "svc-backup",
            "winlog.event_data.SubjectUserSid": "S-1-5-21-3948293847-2938471729-1029384756-1104",
            "winlog.event_data.SubjectDomainName": "CORP",
            "winlog.event_data.SubjectLogonId": "0x7F4A21C",
            "winlog.event_data.PrivilegeList":
              "SeBackupPrivilege\nSeRestorePrivilege\nSeDebugPrivilege\nSeTcbPrivilege",
            "winlog.event_data.LogonType": "3",
            "event.created": "2026-06-24T03:22:11.004Z",
            "log.level": "critical",
            "tags": ["privileged-access", "service-account", "DC"],
          },
        },
        questions: [
          {
            question:
              "The backup service account `svc-backup` is expected to hold SeBackupPrivilege and SeRestorePrivilege. What is anomalous about the PrivilegeList in this event?",
            options: [
              "SeBackupPrivilege is missing from the list — the account cannot perform backups",
              "The account also holds SeDebugPrivilege and SeTcbPrivilege, which are not needed for backup operations and are extremely dangerous privileges",
              "LogonType 3 is unexpected — backup accounts should only use interactive logons (Type 2)",
              "The SubjectDomainName shows CORP which means this is a local account that should not have domain privileges",
            ],
            answer: 1,
            explanation:
              "A backup account legitimately needs SeBackupPrivilege (read any file for backup) and SeRestorePrivilege (write any file for restore). SeDebugPrivilege allows reading memory of any process — including LSASS for credential dumping — which backup software has no reason to hold. SeTcbPrivilege ('Act as part of the OS') is one of the highest privileges in Windows. These two extra privileges on a service account on a Domain Controller at 3 AM is a critical indicator that the account has been compromised or its token has been manipulated.",
            xp: 25,
          },
          {
            question:
              "This event was generated at 03:22 AM on a Domain Controller, outside the scheduled backup window. What is the MOST dangerous potential attack scenario indicated by the combination of DC01 hostname + svc-backup account + SeDebugPrivilege + off-hours timing?",
            options: [
              "The backup scheduler ran slightly late due to a server load issue and the privileges are a legacy misconfiguration that poses no immediate threat",
              "An attacker who compromised the svc-backup account (or its credentials) is operating on the Domain Controller, and with SeDebugPrivilege they can dump LSASS memory to extract all domain user password hashes and Kerberos ticket material",
              "A legitimate administrator enabled SeDebugPrivilege temporarily for troubleshooting and forgot to remove it — this is a policy violation but not an active attack",
              "The Domain Controller is experiencing a replication failure and Windows automatically elevates service account privileges during replication recovery",
            ],
            answer: 1,
            explanation:
              "A service account with SeDebugPrivilege on a Domain Controller is one of the most dangerous combinations in Windows environments. SeDebugPrivilege allows reading LSASS.EXE memory — which on a Domain Controller contains cached credentials for every recently authenticated domain user. An attacker in this position can run Mimikatz to extract the krbtgt hash (enabling golden ticket creation) and all other domain account hashes. The off-hours timing confirms this is not a scheduled operation. This is a Tier 1 escalation — the DC should be treated as fully compromised until proven otherwise.",
            xp: 25,
          },
        ],
      },
      // ── Analyst Choice — Privileged Access ──────────────────────
      {
        type: "analyst_choice" as const,
        id: "priv-ac1",
        heading: "Verdict: Authorized Privileged Operation or Abuse?",
        scenario: "3:22 AM Saturday. PAM vault shows: account 'db-admin-prod' was checked out from CyberArk by user s.chen@contoso.com, used for 4 minutes, then checked back in. Access log shows a successful PostgreSQL login and SELECT query on the 'customers' table returning 250,000 rows. S.Chen is a senior DBA. No change-management ticket was filed for Saturday night. What is your verdict?",
        event: {
          id: "evt-priv-ac-001",
          ts: "2026-06-21T03:22:17.000Z",
          source: "iam" as const,
          vendor: "CyberArk PAM",
          event_type: "privileged_operation" as const,
          severity: "high" as const,
          hostname: "DB-PROD-01",
          user_email: "s.chen@contoso.com",
          description: "PAM vault checkout off-hours — no change ticket — 250k row SELECT on customer table",
          mitre_technique: "T1078.002",
          mitre_tactic: "Privilege Escalation",
          raw: {
            "pam.vault": "CyberArk-Production",
            "pam.account_checked_out": "db-admin-prod",
            "pam.requester": "s.chen@contoso.com",
            "pam.checkout_time": "2026-06-21T03:22:17Z",
            "pam.checkin_time": "2026-06-21T03:26:04Z",
            "pam.session_duration_seconds": 227,
            "pam.reason_provided": "Emergency maintenance",
            "db.host": "DB-PROD-01",
            "db.type": "postgresql",
            "db.statement": "SELECT * FROM customers WHERE region = ALL",
            "db.rows_returned": 250000,
            "db.query_duration_ms": 8420,
            "user.department": "Database Administration",
            "user.title": "Senior DBA",
            "user.mfa_verified": true,
            "cm.ticket_required": true,
            "cm.ticket_found": false,
            "rule.name": "PAM_Checkout_OffHours_NoTicket_LargeQuery",
            "rule.level": 14,
          },
        },
        correct_verdict: "escalate",
        explanation: "Escalation is correct — this cannot be definitively classified without additional context. For benign: S.Chen is a legitimate Senior DBA with MFA-verified access and a valid CyberArk session. An emergency maintenance reason was provided and the session was short (4 minutes). Against benign: a 250,000-row SELECT on a customer table at 3 AM with no change ticket is consistent with insider data exfiltration. A Tier-2 analyst needs to: call S.Chen directly to verify the emergency, check if a ticket was filed verbally (some companies allow emergency verbal authorization), and review whether the query results were exported to a file or sent anywhere.",
        fp_trap: "The user is a legitimate Senior DBA with MFA and a short session. It's tempting to say 'trusted user with valid access during an emergency — false positive'. But the missing change ticket is a process violation regardless of legitimacy, and a 250k-row SELECT at 3 AM is worth verifying. Insider threats often look exactly like legitimate users operating outside normal hours.",
        xp: 30,
      },

      // ── Flag ───────────────────────────────────────────────────
      {
        type: "flag",
        id: "priv-flag1",
        prompt:
          "In the log analysis event above, the `svc-backup` service account was granted several privileges. Two of them are expected for a backup account. Identify the single most dangerous UNEXPECTED privilege that was assigned — the one that allows reading memory of any process on the system. Enter the exact privilege name as it appears in the PrivilegeList field.",
        answer: "SeDebugPrivilege",
        hint: "Look at the PrivilegeList field. A backup account needs SeBackupPrivilege and SeRestorePrivilege. One of the remaining two privileges specifically allows debugging (reading/writing) the memory of any process — including LSASS.",
        xp: 40,
      },

      // ── Reading 4 — Privilege abuse beyond Windows: xp_cmdshell ──
      {
        type: "reading",
        id: "priv-r4",
        heading: "When a Compromised Service Account Reaches a Database: xp_cmdshell Abuse",
        content:
          "**Analogy:** Imagine a company gives its cleaning contractor a master key that opens every office door, purely so they can empty the bins after hours. One night, someone steals that master key. They don't just have access to the offices — because the key also happens to open the server room, they now have a path to something far more valuable than the cleaning contractor ever needed. This is exactly what happens when a compromised low-privilege AD service account turns out to also have access to a Microsoft SQL Server database — and that database has a legacy feature enabled that lets you run operating-system commands directly from SQL.\n\n**Where this fits in the attack chain you already know.** You have already learned that Kerberoasting lets an attacker crack a service account's password offline (Reading 2/3 of the Active Directory room) and that privileged accounts are the highest-value target once an attacker is inside (Reading 1 of this room). What happens *after* a service account like `svc-mssql` is cracked is often the part analysts underestimate: many SQL Server service accounts are themselves database logins with `sysadmin` server role membership — meaning the attacker doesn't just get a Windows logon, they get full control of a SQL Server instance.\n\n**xp_cmdshell — a legitimate feature turned into a backdoor.** `xp_cmdshell` is a built-in Microsoft SQL Server extended stored procedure that lets a database user run arbitrary Windows shell commands **as the SQL Server service account**, directly from a SQL query. It was designed decades ago for legitimate DBA automation tasks (kicking off OS-level backup scripts, for example) and is disabled by default on modern SQL Server installations — but 'disabled by default' does not mean 'never enabled.' Many production databases still have it turned on because a script written years ago depends on it, and nobody has revisited the decision since.\n\nOnce an attacker has `sysadmin`-equivalent access to a SQL Server instance (via the cracked `svc-mssql` account, for example), running a command is as simple as:\n```sql\nEXEC xp_cmdshell 'powershell -enc <base64 payload>';\n```\nThis single SQL statement spawns a full Windows process (commonly `cmd.exe` or `powershell.exe`) as a child of `sqlservr.exe`, running with the SQL Server service account's Windows privileges — which, because service accounts are frequently over-privileged, can mean local administrator or higher on that host.\n\n**Why this is so effective as an escalation path:** a SOC that only watches Windows Security logs may never see the actual attacker command — because from a Windows Event Log perspective, the process was launched by `sqlservr.exe`, which looks like normal, if unusual, database server activity. The attacker never touched RDP, never opened a new interactive session, and never triggered a Windows-native lateral-movement detection like PsExec (Event 7045) — the entire escalation happened inside a single SQL query.\n\n**The detection signature:** the tell-tale indicator is the **process parent-child relationship**, exactly like the Office-macro pattern you learned in the Windows Event Logs room, but with a database twist: `sqlservr.exe` (SQL Server's own service process) spawning `cmd.exe` or `powershell.exe` is never legitimate DBA behaviour — real database administration happens through SQL Server Management Studio or scheduled SQL Agent jobs, not through the SQL Server *process itself* launching a shell. Any EDR or Sysmon Event ID 1 (Process Creation) showing `ParentProcessName = sqlservr.exe` and `NewProcessName` in `{cmd.exe, powershell.exe}` should be treated as a near-certain `xp_cmdshell` abuse indicator — especially if it follows suspicious Kerberos activity (RC4 ticket requests, PreAuthType 0) against a service account with database privileges hours earlier.\n\n**Prevention:** `xp_cmdshell` should be disabled (`sp_configure 'xp_cmdshell', 0`) on any SQL Server instance that does not have a specific, documented business need for it. Service accounts used to run SQL Server should never be granted local administrator rights on the host, and should never be members of Domain Admins — the principle of least privilege applies just as much to database service accounts as it does to human users.",
      },

      // ── Log Analysis — xp_cmdshell post-Kerberoasting escalation ──
      {
        type: "log_analysis",
        id: "priv-la2",
        heading: "sqlservr.exe Spawns PowerShell — Post-Kerberoasting Escalation",
        context:
          "Six hours after a Kerberoasting alert fired for the service account `svc-mssql` (RC4 ticket request, EncryptionType 0x17), your EDR generates a new critical alert on the SQL Server host itself. Review the process creation event below and answer the questions.",
        event: {
          id: "priv-xpcmd-evt-001",
          ts: "2024-11-14T08:31:52.000Z",
          source: "edr",
          vendor: "Microsoft Defender for Endpoint",
          event_type: "process_create",
          severity: "critical",
          hostname: "SRV-DB01.corp.contoso.com",
          mitre_technique: "T1059.001",
          mitre_tactic: "Execution",
          process: {
            name: "powershell.exe",
            pid: 8842,
            path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            parent_name: "sqlservr.exe",
            parent_pid: 2104,
            cmdline: "powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4A",
            user: "CORP\\svc-mssql",
            integrity: "high",
          },
          raw: {
            "mde.event_type": "ProcessCreated",
            "process.name": "powershell.exe",
            "process.command_line": "powershell.exe -nop -w hidden -enc SQBFAFgA...",
            "process.parent.name": "sqlservr.exe",
            "process.parent.path": "C:\\Program Files\\Microsoft SQL Server\\MSSQL15.MSSQLSERVER\\MSSQL\\Binn\\sqlservr.exe",
            "process.integrity_level": "High",
            "user.name": "CORP\\svc-mssql",
            "host.name": "SRV-DB01.corp.contoso.com",
            "sql.originating_login": "svc-mssql",
            "sql.stored_procedure": "xp_cmdshell",
            "sql.query_text": "EXEC xp_cmdshell 'powershell -nop -w hidden -enc SQBFAFgA...'",
            "sql.database_role": "sysadmin",
          },
        },
        questions: [
          {
            question:
              "The ParentProcessName is 'sqlservr.exe' and the NewProcessName is 'powershell.exe'. Why is this parent-child relationship, on its own, enough to escalate this alert to critical — even before reading the sql.stored_procedure field?",
            options: [
              "It isn't unusual — DBAs commonly launch PowerShell scripts directly from the SQL Server process during routine maintenance",
              "sqlservr.exe (the SQL Server database engine process) has no legitimate reason to spawn a shell interpreter like PowerShell — real database administration happens through management tools or scheduled SQL Agent jobs, not through the database engine process itself launching cmd.exe or powershell.exe. This parent-child pattern is functionally identical to the 'Office app spawns shell' red flag you learned earlier, just with a database process instead of Word or Excel",
              "PowerShell should never run on a database server under any circumstances, regardless of what launched it",
              "The alert is only critical because the integrity level is 'High' — the parent process name is not itself meaningful",
            ],
            answer: 1,
            explanation:
              "Just like winword.exe spawning cmd.exe is a hallmark of a malicious Office macro, sqlservr.exe spawning powershell.exe is a hallmark of xp_cmdshell abuse. The SQL Server database engine process's job is to serve queries — it has no legitimate operational reason to launch a scripting shell as a child process. This parent-child relationship alone, independent of the command line content, is a near-certain sign that a SQL query executed xp_cmdshell to break out of the database and run OS-level commands.",
            xp: 30,
          },
          {
            question:
              "The event occurred 6 hours after a Kerberoasting alert against the same account, svc-mssql. What does this timing gap tell you about what happened in between, and what should the analyst's investigation timeline include?",
            options: [
              "The 6-hour gap is irrelevant — the two events should be treated as completely unrelated incidents",
              "The gap is consistent with offline password cracking: the attacker captured svc-mssql's Kerberos service ticket (RC4-encrypted) via Kerberoasting, spent time cracking it offline on their own hardware (generating zero logs during that period), and once cracked, authenticated as svc-mssql to the SQL Server instance and abused its sysadmin privileges via xp_cmdshell. The investigation timeline should span from the original 4769 Kerberoasting event through to this process creation, treating both as one continuous incident",
              "The gap indicates the SQL Server was rebooted during that window, which reset the account's permissions",
              "A 6-hour gap is too long for the two events to be part of the same attack — Kerberoasting attacks must be followed by exploitation within minutes",
            ],
            answer: 1,
            explanation:
              "This is the exact 'silent gap' pattern taught in the Active Directory room's AS-REP Roasting reading, applied to Kerberoasting: cracking an RC4-encrypted Kerberos ticket offline can take anywhere from minutes to many hours depending on password strength and attacker hardware, and it generates no logs at all because it happens entirely outside the domain's visibility. A mature SOC investigation treats the original Kerberoasting alert and this xp_cmdshell escalation as a single incident timeline, not two unrelated events — the multi-hour gap is itself diagnostic evidence of offline cracking having occurred in between.",
            xp: 30,
          },
        ],
      },

      // ── Flag — xp_cmdshell ────────────────────────────────────────
      {
        type: "flag",
        id: "priv-flag2",
        prompt:
          "Look at the xp_cmdshell log analysis event above. What is the exact name of the SQL Server extended stored procedure the attacker used to break out of the database and execute operating-system commands? Enter it exactly as it appears in the sql.stored_procedure field.",
        answer: "xp_cmdshell",
        hint: "Look at the 'sql.stored_procedure' field in the raw log. It is a built-in SQL Server feature, disabled by default, that lets a database user run OS shell commands.",
        xp: 30,
      },
    ],
  },

  // ─────────────────────────────────────────────────────────────
  // Room 3 — Cloud Security Monitoring
  // ─────────────────────────────────────────────────────────────
  {
    id: "cloud-security-monitoring",
    title: "Cloud Security Monitoring",
    description:
      "Learn to detect IAM backdoors, S3 exfiltration, EC2 metadata abuse, and suspicious API calls across AWS CloudTrail, Azure Activity Logs, and GCP Audit Logs.",
    difficulty: "advanced",
    category: "Cloud Security",
    estimatedMinutes: 55,
    xp: 550,
    icon: "☁️",
    prerequisites: ["auth-identity-monitoring"],
    tasks: [
      // ── Reading 1 ──────────────────────────────────────────────
      {
        type: "reading",
        id: "cloud-r1",
        heading: "Cloud Audit Logs — The CCTV of the Cloud",
        content:
          "**Analogy:** When you rent office space in a building, the building management installs cameras in the lobby, elevators, and corridors. They don't install cameras inside your office — that's your responsibility. Cloud providers work the same way: they record every API call made to their infrastructure (their 'lobby'), but you are responsible for enabling detailed logging inside your own workloads.\n\n**AWS CloudTrail** is Amazon's audit log for every API call made to your AWS account. When you create an EC2 server, delete an S3 bucket, or change an IAM policy — CloudTrail writes a record. Key fields in every CloudTrail event:\n- `eventName` — what action was performed (e.g., `CreateUser`, `PutBucketPolicy`, `GetObject`)\n- `sourceIPAddress` — where the call came from. Could be an AWS service (`lambda.amazonaws.com`), a corporate IP, or an attacker's IP.\n- `userIdentity.type` — the type of caller: `IAMUser` (a human with permanent keys), `AssumedRole` (someone who used STS to assume a role — common for applications and cross-account access), `Root` (the all-powerful account root user — should almost never appear in CloudTrail)\n- `userIdentity.arn` — the full ARN of the caller, e.g., `arn:aws:iam::123456789012:assumed-role/DevRole/session-name`\n- `requestParameters` — the arguments passed to the API (e.g., `{\"userName\": \"backdoor-admin\"}` for a CreateUser call)\n- `responseElements` — the result returned by AWS (e.g., the ARN of the newly created user)\n- `awsRegion` — which region the action occurred in. Activity in unexpected regions (especially `us-east-1` for a European company) is suspicious.\n- `errorCode` — if the API call failed, why (e.g., `AccessDenied`, `NoSuchBucket`). Many `AccessDenied` errors from the same identity indicate reconnaissance.\n\n**Azure Activity Log** records all control-plane operations in Azure (creating VMs, changing NSGs, modifying role assignments). **Microsoft Entra ID (formerly Azure AD) Sign-in Logs** record every authentication event. **Microsoft Defender for Cloud** (formerly Azure Security Center) provides security posture and threat detection. **Microsoft Sentinel** is Azure's cloud-native SIEM that ingests all of these.\n\n**GCP Cloud Audit Logs** work similarly — Admin Activity logs (always on, free), Data Access logs (must be enabled, can be expensive), and System Event logs. GCP's **Security Command Center** is the equivalent of AWS GuardDuty for threat detection.\n\n**What makes cloud monitoring different from on-premises:**\n1. **No perimeter** — anyone on the internet can attempt API calls against your cloud account. There's no corporate firewall limiting who can *try*.\n2. **Credentials live in code** — developers accidentally commit AWS access keys to GitHub regularly. A leaked key gives an attacker the same access as the developer, from anywhere.\n3. **Scale and speed** — an attacker with valid cloud credentials can provision 1,000 crypto-mining servers, exfiltrate a 10 TB database, or create 50 backdoor accounts in seconds. The blast radius is enormous.\n4. **Misconfiguration is the leading cause** — open S3 buckets, overly permissive IAM roles, publicly accessible databases. Attackers scan for these continuously.",
      },
      // ── Reading 2 ──────────────────────────────────────────────
      {
        type: "reading",
        id: "cloud-r2",
        heading: "IAM Attacks, S3 Exfiltration, and EC2 Metadata Abuse",
        content:
          "**Analogy:** An IAM (Identity and Access Management) backdoor is like a thief who breaks into a hotel, finds the master key, makes a copy, and then leaves — they can come back any time, even after you change the front door lock. AWS IAM attacks are about creating permanent access that survives initial detection.\n\n**IAM Backdoor Pattern — CreateUser + AttachUserPolicy:**\nThe most common IAM attack sequence:\n1. Attacker compromises existing credentials (leaked key, SSRF, phishing)\n2. `CreateUser` — creates a new IAM user with an inconspicuous name (`svc-monitor`, `backup-agent`, `deploy-bot`)\n3. `CreateAccessKey` — creates API keys for the new user\n4. `AttachUserPolicy` — attaches the `AdministratorAccess` managed policy (full control of the entire AWS account) to the new user\n5. Attacker now has a permanent backdoor that survives even if the original compromised credential is revoked\n\nDetection: `CreateUser` followed within minutes by `AttachUserPolicy` with PolicyArn containing `AdministratorAccess` from the same or correlated session. Especially suspicious if `sourceIPAddress` is a Tor exit node, a cloud proxy, or an IP that has never been seen in your CloudTrail before.\n\n**S3 Data Exfiltration:**\nS3 holds enormous amounts of sensitive data — database backups, application configs, user uploads, financial records. Exfiltration patterns:\n- `ListBuckets` — attacker enumerates all S3 buckets in the account (reconnaissance)\n- `GetBucketAcl` / `GetBucketPolicy` — checking permissions on specific buckets\n- Repeated `GetObject` on many objects in a sensitive bucket from an unusual IP\n- `GetObject` on files with sensitive names (`credentials`, `backup`, `.env`, `secrets`)\n- `PutBucketPublicAccessBlock` set to `false` followed by `PutBucketAcl` making a bucket world-readable — a common data exfiltration technique where the attacker opens your private bucket to the internet\n\n**EC2 Instance Metadata Service (IMDS) Abuse:**\nEvery EC2 instance has access to a metadata endpoint at `http://169.254.169.254/` that returns information about the instance — including **temporary AWS credentials** for whatever IAM role is attached to the instance. If an attacker achieves code execution on an EC2 instance (e.g., via a web app vulnerability), they can run:\n```\ncurl http://169.254.169.254/latest/meta-data/iam/security-credentials/\n```\nThis returns live AWS credentials that allow the attacker to make API calls with the EC2 instance's IAM role permissions — potentially with `S3FullAccess`, `EC2FullAccess`, etc. The resulting API calls will appear in CloudTrail with `sourceIPAddress` being the EC2 instance's IP and `userIdentity.type = AssumedRole` for the instance's role. IMDSv2 (requiring a session token) mitigates this, but many organisations still run IMDSv1.\n\n**AWS GuardDuty** is Amazon's managed threat detection service that analyses CloudTrail, VPC Flow Logs, and DNS logs automatically. Key finding types:\n- `UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B` — console login from unusual geography\n- `Recon:IAMUser/MaliciousIPCaller` — API calls from a known malicious IP\n- `CryptoCurrency:EC2/BitcoinTool.B` — EC2 instance communicating with crypto mining pools\n- `Exfiltration:S3/ObjectRead.Unusual` — unusual S3 data access pattern\n- `PrivilegeEscalation:IAMUser/AdministrativePermissions` — policy changes granting excessive permissions",
      },
      // ── Reading 3 ──────────────────────────────────────────────
      {
        type: "reading",
        id: "cloud-r3",
        heading: "Building a Cloud Security Investigation — AWS Focus",
        content:
          "**Analogy:** Investigating a cloud security incident is like investigating a bank robbery where the thief never set foot in the bank — everything happened over the phone and the internet. You have logs of every call, but no physical evidence. The investigation is entirely about correlating API calls, timestamps, and IP addresses.\n\nHere is how to investigate a suspected AWS IAM compromise:\n\n**Step 1 — Identify the compromised identity.**\nYour alert fires on a `CreateUser` + `AttachUserPolicy` sequence. Pull the `userIdentity.arn` from both events. Is it a human IAM user, a role, or — most dangerous — the root account? Check `sourceIPAddress` against your known IP ranges and threat intel.\n\n**Step 2 — Establish the attacker's access window.**\nWhen did the first API call from the suspicious IP appear in CloudTrail? Run a query for all events from that ARN or IP in the last 30 days. Did anything appear before the attack event that explains how they got in? (A `GetSecretValue` on a secret containing access keys? An EC2 console login from the same IP days earlier?)\n\n**Step 3 — Enumerate what was created, changed, or accessed.**\nScan CloudTrail for all API calls from the attacker's session:\n- New IAM users, roles, or access keys created\n- Policies attached or inline policies modified\n- S3 `GetObject` or `PutBucketAcl` calls\n- EC2 instances launched (possible crypto mining)\n- Secrets Manager or SSM Parameter Store reads (credential harvesting)\n- `CloudTrail StopLogging` (attacker trying to hide their tracks — this fires one final CloudTrail event)\n\n**Step 4 — Check for lateral movement to other accounts.**\nIn AWS organisations with multiple accounts, an attacker in one account may assume roles in other accounts (`AssumeRole` across accounts). Check the `userIdentity.accountId` in events to see if actions occurred in accounts other than the initially compromised one.\n\n**Step 5 — Contain.**\n- Revoke all sessions for the compromised identity: `aws iam delete-login-profile`, rotate or delete access keys\n- Disable or delete any backdoor accounts/access keys the attacker created\n- Remove any overly permissive policies the attacker attached\n- Rotate any secrets the attacker may have read\n- If EC2 instances were launched, terminate them and isolate the instance profile role\n\n**Step 6 — Determine the root cause.**\nHow did the attacker get credentials in the first place? Common sources: GitHub commit containing access keys, SSRF vulnerability pulling IMDS credentials, phishing for console password + MFA bypass, supply chain compromise in a CI/CD pipeline.\n\n**Tor and VPN exit nodes** in `sourceIPAddress` are a major indicator. Legitimate developers connect from corporate IPs, home ISPs, or known VPN ranges. Calls from Tor exit nodes or anonymous datacenter IPs have almost no legitimate explanation in a production AWS environment. Your SIEM should enrich CloudTrail `sourceIPAddress` with threat intel automatically.",
      },
      // ── Question 1 ──────────────────────────────────────────────
      {
        type: "question",
        id: "cloud-q1",
        question:
          "An AWS CloudTrail query returns a `CreateUser` event for user `svc-cloudmonitor` followed 90 seconds later by an `AttachUserPolicy` event attaching policy `arn:aws:iam::aws:policy/AdministratorAccess` to that user. Both events originate from IP `185.220.101.45`. What is this MOST likely?",
        options: [
          "A legitimate DevOps engineer creating a service account for cloud monitoring infrastructure",
          "An IAM backdoor attack — an attacker with compromised credentials is creating a new admin user with permanent full access to the AWS account",
          "AWS's own automation creating a monitoring account as part of a new service activation",
          "A failed credential stuffing attempt that was blocked by AWS IAM policy restrictions",
        ],
        answer: 1,
        explanation:
          "`CreateUser` immediately followed by `AttachUserPolicy` with `AdministratorAccess` is the textbook IAM backdoor sequence. Legitimate service accounts are created through version-controlled Infrastructure-as-Code (Terraform, CloudFormation) from known CI/CD IPs, not via direct API calls from an anonymous IP. The IP 185.220.101.45 is a known Tor exit node — no legitimate automated system or engineer uses Tor to manage production AWS. The `AdministratorAccess` policy grant to a newly created account is the most dangerous possible outcome of an AWS compromise.",
        xp: 20,
      },
      // ── Question 2 ──────────────────────────────────────────────
      {
        type: "question",
        id: "cloud-q2",
        question:
          "A developer's EC2 instance running a web application is compromised via a Server-Side Request Forgery (SSRF) vulnerability. The attacker makes HTTP requests to `http://169.254.169.254/latest/meta-data/iam/security-credentials/`. What does this endpoint expose?",
        options: [
          "The EC2 instance's operating system root password in plaintext",
          "The AWS account's root access keys stored in the instance's local filesystem",
          "Temporary AWS credentials (access key, secret key, and session token) for the IAM role attached to the EC2 instance",
          "A list of all IAM users in the AWS account and their permission policies",
        ],
        answer: 2,
        explanation:
          "The EC2 Instance Metadata Service (IMDS) at 169.254.169.254 is a link-local address accessible only from within the EC2 instance. The IAM credentials endpoint returns temporary AWS credentials (AccessKeyId, SecretAccessKey, Token) issued by STS for the role attached to the instance profile. An SSRF vulnerability that can reach this endpoint gives the attacker full use of the instance's IAM role — often with significant permissions like S3FullAccess. These credentials appear valid in CloudTrail but come from the EC2 instance's IP, which may seem legitimate unless analysts correlate it with the web app's SSRF vulnerability.",
        xp: 20,
      },
      // ── Question 3 ──────────────────────────────────────────────
      {
        type: "question",
        id: "cloud-q3",
        question:
          "In AWS CloudTrail, what does `userIdentity.type = \"Root\"` in a CloudTrail event indicate, and why should SOC analysts treat this as high-priority?",
        options: [
          "The action was performed by an IAM user with 'root' in their username — common for database administrators",
          "The action was performed by the AWS account root user — the all-powerful account that bypasses all IAM policies. Root should almost never be used, and any root activity should be investigated immediately.",
          "The action was performed by a Lambda function running with root-level OS privileges within the container",
          "The event was generated by AWS's internal automation systems maintaining account infrastructure",
        ],
        answer: 1,
        explanation:
          "The AWS root account is the email/password account used to originally create the AWS account. It bypasses all IAM policies, cannot be restricted by SCPs (Service Control Policies), and has access to billing and account closure. AWS's own best practices say root should be used only for a handful of specific tasks (e.g., closing the account, restoring a locked-out admin) and should have MFA enabled with the access keys deleted. Any `Root` event in CloudTrail — especially API calls rather than console logins — is a Tier 1 alert. Attackers who obtain root access own the entire AWS organization.",
        xp: 20,
      },
      // ── Log Analysis ───────────────────────────────────────────
      {
        type: "log_analysis",
        id: "cloud-la1",
        heading: "AWS CloudTrail — IAM Backdoor User Creation",
        context:
          "AWS GuardDuty generated finding: `PrivilegeEscalation:IAMUser/AdministrativePermissions`. CloudTrail has the underlying events. The event below is the `CreateUser` call. A second event (not shown) captured `AttachUserPolicy` with PolicyArn `arn:aws:iam::aws:policy/AdministratorAccess` targeting the same username, 47 seconds later from the same source IP. Your organisation operates only from EU-WEST-1 and AP-SOUTHEAST-1 regions. No change ticket exists for this activity.",
        event: {
          id: "evt-cloud-iam-001",
          ts: "2026-06-24T04:51:22.391Z",
          source: "cloudtrail",
          event_type: "cloud_api_call",
          hostname: undefined,
          severity: "critical",
          raw: {
            "aws.cloudtrail.eventName": "CreateUser",
            "aws.cloudtrail.eventSource": "iam.amazonaws.com",
            "aws.cloudtrail.awsRegion": "us-east-1",
            "aws.cloudtrail.sourceIPAddress": "185.220.101.45",
            "aws.cloudtrail.userAgent":
              "aws-cli/2.13.1 Python/3.11.4 Linux/5.15.0 botocore/2.0.1",
            "aws.cloudtrail.userIdentity.type": "AssumedRole",
            "aws.cloudtrail.userIdentity.arn":
              "arn:aws:sts::847291038472:assumed-role/DevOps-Deploy-Role/ci-session-prod",
            "aws.cloudtrail.userIdentity.accountId": "847291038472",
            "aws.cloudtrail.userIdentity.sessionContext.sessionIssuer.userName":
              "DevOps-Deploy-Role",
            "aws.cloudtrail.requestParameters.userName": "svc-cloudmonitor-prod",
            "aws.cloudtrail.responseElements.user.arn":
              "arn:aws:iam::847291038472:user/svc-cloudmonitor-prod",
            "aws.cloudtrail.responseElements.user.userId": "AIDA4XYZABC123DEF456G",
            "aws.cloudtrail.responseElements.user.createDate": "2026-06-24T04:51:22.000Z",
            "aws.cloudtrail.errorCode": null,
            "aws.cloudtrail.errorMessage": null,
            "aws.cloudtrail.readOnly": false,
            "aws.cloudtrail.eventType": "AwsApiCall",
            "aws.cloudtrail.managementEvent": true,
            "event.created": "2026-06-24T04:51:22.391Z",
          },
        },
        questions: [
          {
            question:
              "The `userIdentity.type` is `AssumedRole` and the ARN shows `DevOps-Deploy-Role/ci-session-prod`. The call comes from IP `185.220.101.45`. What is anomalous about this, and why does it indicate compromise rather than legitimate DevOps automation?",
            options: [
              "AssumedRole is not allowed to call IAM CreateUser — only IAMUser type can create users, so this event must be a CloudTrail error",
              "Legitimate CI/CD pipelines run from fixed corporate or cloud-provider IP ranges (GitHub Actions, Jenkins servers, etc.) — not from Tor exit nodes like 185.220.101.45. The DevOps-Deploy-Role's session has been hijacked and used from an attacker-controlled IP.",
              "The session name 'ci-session-prod' is too short to be a legitimate CI pipeline — production sessions always include the full pipeline ID and build number",
              "AssumedRole credentials expire after 15 minutes, so this event is impossible — the session would have timed out before CreateUser could be called",
            ],
            answer: 1,
            explanation:
              "AssumedRole via a CI/CD role is entirely legitimate — it's the correct way for pipelines to authenticate to AWS. The red flag is the sourceIPAddress. CI/CD systems (GitHub Actions, GitLab, Jenkins, CircleCI) call AWS APIs from known, documented IP ranges. They do not originate from 185.220.101.45, a well-known Tor exit node. This pattern — legitimate role, illegitimate source IP — indicates the role's credentials were stolen (e.g., from a leaked GitHub Actions secret, a compromised developer machine, or an SSRF on the CI server) and are now being used by an attacker.",
            xp: 25,
          },
          {
            question:
              "The `awsRegion` field shows `us-east-1`, but your organisation only operates in `eu-west-1` and `ap-southeast-1`. What is the significance of this detail?",
            options: [
              "IAM is a global service and always logs to us-east-1 regardless of where the call originated — this is expected behavior and not suspicious",
              "Activity in an unexpected region indicates the attacker chose a region your monitoring may not cover, or where your organisation has no legitimate resources and therefore no CloudTrail alerts configured for that region",
              "AWS automatically routes all API calls through us-east-1 for latency optimisation — the actual region would be shown in a different field",
              "IAM CreateUser can only be called from us-east-1 because IAM is a global service hosted in North Virginia — this is not anomalous",
            ],
            answer: 1,
            explanation:
              "While IAM is a global service (not region-specific), CloudTrail records the region from which the API call was routed. Attackers sometimes target regions their victims don't actively monitor — if your SIEM CloudTrail pipeline only ingests eu-west-1 and ap-southeast-1 logs, us-east-1 activity may be invisible. This is a real gap many organisations have. However, IAM actions in CloudTrail appear in the global trail regardless of region. The key point: region anomaly + unknown IP + no change ticket = investigate. Many GuardDuty findings also include region as a factor.",
            xp: 20,
          },
          {
            question:
              "Looking at the `requestParameters.userName` field: what was the name of the IAM user that the attacker created?",
            options: [
              "DevOps-Deploy-Role",
              "ci-session-prod",
              "svc-cloudmonitor-prod",
              "AIDA4XYZABC123DEF456G",
            ],
            answer: 2,
            explanation:
              "`requestParameters.userName` is the argument the caller passed to the `CreateUser` API — it is the name of the new IAM user being created. In this case: `svc-cloudmonitor-prod`. Attackers typically choose names that blend in with legitimate service accounts (prefixed with `svc-`, ending in `-prod` or `-monitor`). The `userId` value `AIDA4XYZABC123DEF456G` is the AWS-generated unique identifier for the user — not the human-readable name. `DevOps-Deploy-Role` and `ci-session-prod` are the identity of the *caller* who made the API call, not the newly created account.",
            xp: 15,
          },
        ],
      },
      // ── Analyst Choice — Cloud IAM ───────────────────────────────
      {
        type: "analyst_choice" as const,
        id: "cloud-ac1",
        heading: "Verdict: Routine Cloud Admin or IAM Privilege Escalation?",
        scenario: "AWS GuardDuty fired: IAM user 'ci-session-dev' called GetCallerIdentity, then ListRoles, then passed a role to an EC2 instance that previously had no IAM role. All API calls originated from IP 34.215.110.32 (AWS us-west-2 NAT gateway — internal). The user was created 2 weeks ago. No CloudTrail alerts fired previously on this account. What is your verdict?",
        event: {
          id: "evt-cloud-ac-001",
          ts: "2026-06-23T11:47:33.000Z",
          source: "cloudtrail" as const,
          vendor: "AWS CloudTrail + GuardDuty",
          event_type: "cloud_api_call" as const,
          severity: "high" as const,
          hostname: "i-0c3d4e5f6a7b8c9d0",
          user_email: "ci-session-dev",
          description: "IAM user performed identity verification then role enumeration then PassRole to existing EC2 — possible privilege escalation",
          mitre_technique: "T1548.005",
          mitre_tactic: "Privilege Escalation",
          raw: {
            "aws.cloudtrail.eventName": "PassRole",
            "aws.cloudtrail.eventSource": "iam.amazonaws.com",
            "aws.cloudtrail.userIdentity.type": "IAMUser",
            "aws.cloudtrail.userIdentity.userName": "ci-session-dev",
            "aws.cloudtrail.userIdentity.arn": "arn:aws:iam::123456789012:user/ci-session-dev",
            "aws.cloudtrail.sourceIPAddress": "34.215.110.32",
            "aws.cloudtrail.requestParameters.roleName": "ec2-prod-s3-full-access",
            "aws.cloudtrail.requestParameters.instanceId": "i-0c3d4e5f6a7b8c9d0",
            "aws.cloudtrail.errorCode": "",
            "aws.cloudtrail.errorMessage": "",
            "sequence.prior_api_calls": "GetCallerIdentity -> ListRoles -> PassRole",
            "iam.user.created_date": "2026-06-09",
            "iam.user.prior_passrole": false,
            "iam.role.permissions": "s3:*, ec2:Describe*",
            "guardduty.finding_type": "PrivilegeEscalation:IAMUser/AnomalousBehavior",
            "guardduty.severity": 7.8,
            "rule.name": "CloudTrail_IAM_PassRole_New_User",
            "rule.level": 13,
          },
        },
        correct_verdict: "true_positive",
        explanation: "This is a true positive privilege escalation. The three-step sequence is the textbook IAM privilege escalation pattern: (1) GetCallerIdentity — confirming own identity, standard first step for attacker to understand their position; (2) ListRoles — enumerating what roles exist and their permissions, which is reconnaissance; (3) PassRole — attaching a higher-privileged role to an EC2 instance the attacker controls. The fact that ci-session-dev had never called PassRole before and the role 'ec2-prod-s3-full-access' grants S3 full access confirms this: an attacker with read-only IAM access escalated to full S3 access by passing a more powerful role to their EC2 instance. The internal AWS IP address is not a false-positive indicator — attackers operating within AWS frequently use NAT gateways.",
        fp_trap: "The source IP is a legitimate AWS NAT gateway IP (34.215.x.x) — not an attacker IP. Many analysts see an internal AWS IP and assume the activity is from a legitimate internal process. But CI/CD users routinely operate from within AWS, and this IP just means the call came from within the same AWS account — it says nothing about whether the action was authorized.",
        xp: 30,
      },

      // ── Flag ───────────────────────────────────────────────────
      {
        type: "flag",
        id: "cloud-flag1",
        prompt:
          "In the CloudTrail log event above, look at the `requestParameters.userName` field. This is the name of the backdoor IAM user the attacker created. Enter the exact username as it appears in the log.",
        answer: "svc-cloudmonitor-prod",
        hint: "The username is in the `aws.cloudtrail.requestParameters.userName` field of the raw log — it looks like a legitimate service account name, which is exactly why attackers choose names like this.",
        xp: 45,
      },
    ],
  },

  // ─────────────────────────────────────────────────────────────
  // Room 4 — Detection Engineering Fundamentals
  // ─────────────────────────────────────────────────────────────
  {
    id: "detection-engineering",
    title: "Detection Engineering Fundamentals",
    description:
      "Learn how to write, tune, and manage SIEM detection rules — from Sigma format to MITRE ATT&CK coverage mapping, alert fatigue, and the full rule lifecycle.",
    difficulty: "advanced",
    category: "SIEM",
    estimatedMinutes: 50,
    xp: 530,
    icon: "⚙️",
    prerequisites: ["siem-fundamentals", "auth-identity-monitoring"],
    tasks: [
      // ── Reading 1 ──────────────────────────────────────────────
      {
        type: "reading",
        id: "deteng-r1",
        heading: "What Detection Engineering Is — Rules That Catch Bad Actors",
        content:
          "**Analogy:** Imagine you run a large warehouse and you're worried about theft. You install cameras everywhere — but cameras alone don't catch thieves. You need someone watching the monitors 24/7, or better: you set up a motion sensor that automatically sounds an alarm if someone enters the restricted area after hours. Detection engineering is the process of building those motion sensors — *automated rules that fire when bad things happen* so that human analysts don't need to stare at logs all day waiting for something suspicious.\n\nA **SIEM (Security Information and Event Management)** system like Splunk, Microsoft Sentinel, or IBM QRadar ingests logs from across your environment and lets you run queries against them. Detection engineering is the discipline of writing those queries as *persistent rules* that run continuously and generate alerts when their conditions are met.\n\n**Why you need detection engineering — and can't just use vendor defaults:**\nEvery SIEM vendor ships with default detection rules — hundreds of them. But default rules are built for the average environment, not your environment. Your organisation may have:\n- Legitimate tools that trigger default rules (e.g., your IT team uses PsExec for remote admin — but default rules fire on all PsExec usage)\n- Specific assets that need custom monitoring (e.g., a critical SAP server that should never have external connections)\n- Unique user behaviour (e.g., your finance team works at unusual hours that trigger 'after-hours login' rules)\n- Local naming conventions (e.g., service accounts that start with `SVC-` that shouldn't trigger 'suspicious service account' rules)\n\nA detection engineer's job is to take general threat knowledge and turn it into precise, tuned rules that:\n1. Fire reliably when an actual attack technique is used (high true positive rate)\n2. Rarely fire for legitimate activity (low false positive rate)\n3. Cover the attack techniques relevant to your threat model\n\n**The anatomy of a SIEM detection rule:**\n- **Data source** — which logs does this rule query? (Windows Security Events, CrowdStrike EDR, CloudTrail?)\n- **Filter conditions** — what specific field values trigger the rule? (EventID = 4625 AND SubStatus = 0xC000006A)\n- **Threshold** — how many times must the condition be met? (More than 10 accounts targeted within 5 minutes)\n- **Grouping** — what field do we group by? (Count distinct TargetUserName per SourceIP)\n- **Severity** — how urgent is this alert? (Critical / High / Medium / Low)\n- **MITRE ATT&CK mapping** — which technique does this detect? (T1110.003 — Password Spraying)\n- **Action** — what happens when the rule fires? (Create SIEM alert, open SOAR ticket, send email, block IP automatically?)\n\n**Alert fatigue** is the detection engineer's biggest enemy. If a rule fires 500 times a day and 490 of those are false positives, analysts stop trusting the rule and start ignoring it. This is how real attacks slip through — not because the attack was sophisticated, but because the analyst had been conditioned by too many false alarms to treat the real alert as just another noise event.\n\nResearch shows that at 95% accuracy with 10,000 daily events, you have 500 false positives per day — far too many for a team to investigate. The goal for production rules is typically >99% precision (fewer than 1 false positive per 100 alerts) for high-severity alerts.",
      },
      // ── Reading 2 ──────────────────────────────────────────────
      {
        type: "reading",
        id: "deteng-r2",
        heading: "Sigma Rules, Detection Logic Types, and the MITRE ATT&CK Framework",
        content:
          "**Analogy:** Imagine you're a chef who wants to share a recipe. You could write it for your specific kitchen — your oven, your brand of butter, your measuring cups. Or you could write it in a standardised recipe format that any chef in any kitchen can follow. **Sigma** is that standardised recipe format for detection rules — a vendor-neutral specification that can be compiled for Splunk, Elastic, Microsoft Sentinel, QRadar, and many other SIEMs.\n\n**Sigma Rules** are written in YAML and describe detection logic without using any vendor-specific query language. A simple Sigma rule looks like:\n\n```yaml\ntitle: Password Spray via NTLM\nstatus: experimental\ndescription: Detects multiple failed logons across many accounts from single source\nlogsource:\n  product: windows\n  service: security\ndetection:\n  selection:\n    EventID: 4625\n    SubStatus: '0xC000006A'\n  condition: selection | count(TargetUserName) by IpAddress > 10\nfields:\n  - TargetUserName\n  - IpAddress\nfalsepositives:\n  - Misconfigured applications retrying authentication\nlevel: high\ntags:\n  - attack.credential_access\n  - attack.t1110.003\n```\n\nThis single Sigma rule can be converted to a Splunk SPL query, an Elastic KQL rule, a Sentinel KQL query, or a QRadar AQL rule using the `sigmac` compiler tool or `sigma-cli`. This portability is enormously valuable — security researchers publish Sigma rules that the community can share and adapt.\n\n**Detection Logic Types:**\n\n**1. Signature-based** — exact match on a known bad pattern (a specific hash, a specific command line string). Very precise but only catches *known* variants. Example: process name `mimikatz.exe` or command line containing `sekurlsa::logonpasswords`.\n\n**2. Threshold-based** — count-based logic that fires when a quantity exceeds a limit. Example: more than 20 failed logons from one IP in 5 minutes. Works for volume-based attacks (sprays, brute force, DDoS). Requires careful threshold tuning per environment.\n\n**3. Anomaly/Behavioral** — fires when current behaviour deviates from a learned baseline. Example: this user account normally authenticates from UK IPs, but today authenticated from Brazil. Requires a training period to establish baselines (UEBA systems do this). High detection power for subtle attacks but more complex to tune.\n\n**4. Correlation** — combines multiple events from different sources into a composite detection. Example: failed logons (Windows) + successful VPN logon from same IP (VPN logs) + file access on file server (Windows) within 30 minutes = lateral movement post-spray. The most powerful type but also the most complex to build.\n\n**MITRE ATT&CK Framework** is a publicly available knowledge base of adversary tactics, techniques, and sub-techniques observed in real attacks. It is organised as a matrix:\n- **Tactics** (columns) — the *goal* of the adversary at a given stage: Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Exfiltration, Impact\n- **Techniques** (rows within each tactic) — the *specific method* used: T1110 (Brute Force), T1059 (Command and Scripting Interpreter), T1078 (Valid Accounts)\n- **Sub-techniques** — more specific variants: T1110.003 is Password Spraying specifically under the Brute Force technique\n\nEvery detection rule should map to one or more ATT&CK techniques. Why? Because you can then create an **ATT&CK Coverage Heatmap** — a visual representation of which techniques you can detect and which techniques have no detection rule. A technique with no coverage is a gap an attacker can exploit without triggering any alert. Detection engineers use this heatmap to prioritise writing new rules for uncovered techniques, especially those used by threat actors relevant to their industry.",
      },
      // ── Reading 3 ──────────────────────────────────────────────
      {
        type: "reading",
        id: "deteng-r3",
        heading: "The Rule Lifecycle — From Writing to Retirement",
        content:
          "**Analogy:** A speed camera on a road doesn't just get installed and left alone forever. The speed limit might change, the camera might drift out of calibration, new road layouts might mean it catches innocent drivers turning into a petrol station. Someone has to maintain it — verify it's still catching the right cars, adjust the settings, and eventually replace it when the road is redesigned. Detection rules are exactly the same — they need an ongoing maintenance lifecycle, not a one-time 'set and forget.'\n\n**The Detection Rule Lifecycle:**\n\n**Stage 1 — Identify the Threat.**\nWhat attack technique do you want to detect? Sources:\n- Threat intelligence reports about attackers targeting your industry\n- MITRE ATT&CK techniques used by relevant threat groups (e.g., if you're a financial institution, look at what FIN7 or Lazarus Group use)\n- Incidents your organisation has already experienced\n- ATT&CK coverage gaps identified from your heatmap\n- Sigma community rules released for newly published CVEs\n\n**Stage 2 — Write the Rule.**\nTranslate the threat technique into detection logic. This requires understanding:\n- What log source captures this activity (which product, which log type)\n- What fields are populated when this technique is used\n- What values distinguish malicious from benign (a filter condition)\n- What volume or sequence indicates an attack (threshold or correlation)\n\nWrite it first in Sigma (vendor-neutral) then compile for your SIEM.\n\n**Stage 3 — Test Against Historical Data.**\nBefore deploying, test the rule against historical logs:\n- Does it detect the attack simulations or known historical incidents?\n- How many events does it fire in a typical week? (Estimate false positive rate)\n- Are there obvious false positive sources you can immediately exclude?\n\nMany teams have a **Detection Lab** — a test environment where they run red-team attack simulations to validate that new rules fire correctly.\n\n**Stage 4 — Deploy in 'Alert-Only' Mode.**\nDeploy the rule to production but with low severity and no automated action. Monitor for 2-4 weeks. Collect every alert and classify each one: true positive (TP) or false positive (FP). Calculate your precision: TP/(TP+FP).\n\n**Stage 5 — Tune.**\nBased on observed false positives, add exclusions:\n- Exclude known admin IPs (`NOT src.ip IN [10.1.2.3, 10.1.2.4]`)\n- Exclude known tools (`NOT process.name = \"backup-agent.exe\"`)\n- Add context filters (`AND user.department != \"IT Operations\"`)\n- Adjust thresholds based on observed volumes\n\nBe careful not to over-tune. Every exclusion is a potential blind spot — an attacker who knows your exclusions can operate within them. Document every exclusion with a business justification.\n\n**Stage 6 — Promote to Production Severity.**\nOnce precision meets your threshold (typically >98% for high/critical severity), elevate the rule's severity and potentially enable automated response (SOAR playbook trigger, automatic IP block, account disable).\n\n**Stage 7 — Ongoing Review and Retirement.**\nReview rules at least quarterly:\n- Has the attack technique changed? (Attackers evolve to evade known detections — LOLBins replace custom malware, living-off-the-land techniques replace noisy tools)\n- Has the environment changed? (A new tool deployed that triggers the rule? A network segment change that breaks the rule's assumptions?)\n- Is the rule still firing? A rule that hasn't fired in 6 months either means no attacks (good) or the rule is broken (bad — test it).\n- Retire rules that detect threats no longer relevant to your environment.\n\n**Alert Fatigue Management:** Set explicit SLAs for different severity levels:\n- Critical: analyst response within 15 minutes\n- High: within 2 hours\n- Medium: within 8 hours\n- Low: reviewed in daily triage\n\nIf your team cannot meet these SLAs, you have either a staffing problem or a false-positive problem. Tune the rules — not the SLAs.",
      },
      // ── Question 1 ──────────────────────────────────────────────
      {
        type: "question",
        id: "deteng-q1",
        question:
          "Your SIEM has a rule with 95% accuracy (95% of alerts are true positives, 5% are false positives). The rule fires an average of 200 times per day. How many false positive alerts would your analyst team need to investigate daily, and what does this illustrate about detection accuracy requirements?",
        options: [
          "5 false positives per day — this is a well-tuned rule that is perfectly acceptable for production use at any severity level",
          "10 false positives per day — acceptable for medium severity but not for critical severity alerts",
          "10 false positives per day — this illustrates that even 95% accuracy generates significant noise at scale, and high-severity rules need much higher precision (>99%) to remain actionable",
          "190 false positives per day — the formula should invert the accuracy, giving 1 true positive per 5% false positive rate",
        ],
        answer: 2,
        explanation:
          "200 alerts/day × 5% false positive rate = 10 false positives per day. This seems manageable, but consider: if your team has 50 such rules, that's 500 false positive investigations per day before handling any real incidents. High-severity rules that require rapid response must have very high precision — at 99% precision with 200 daily alerts, you have only 2 false positives per day. The 95% number illustrates that accuracy requirements scale with alert volume: a rule that fires 10 times/day at 95% accuracy (0.5 FP/day) is fine; the same accuracy at 10,000 events/day (500 FP/day) is catastrophic for analyst workload.",
        xp: 20,
      },
      // ── Question 2 ──────────────────────────────────────────────
      {
        type: "question",
        id: "deteng-q2",
        question:
          "What is the PRIMARY advantage of writing detection rules in Sigma format instead of directly in your SIEM vendor's query language (e.g., Splunk SPL or Sentinel KQL)?",
        options: [
          "Sigma rules execute faster than native SIEM queries because they are compiled to machine code before being stored in the SIEM",
          "Sigma rules are vendor-neutral and portable — they can be compiled into the query language of any supported SIEM, allowing the organisation to share rules with the community and migrate between vendors without rewriting all detections",
          "Sigma rules support artificial intelligence-based anomaly detection that native SIEM query languages do not provide",
          "Sigma format automatically tests rules against historical data before deploying them, eliminating the need for a separate testing phase",
        ],
        answer: 1,
        explanation:
          "Sigma's core value proposition is portability and community sharing. A rule written in Sigma YAML can be compiled via `sigma-cli` into Splunk SPL, Elastic ESQL, Microsoft Sentinel KQL, IBM QRadar AQL, and many others. This means: (1) a detection engineer can share rules publicly (GitHub, SigmaHQ community repo) that any organisation with any SIEM can use; (2) if your organisation migrates from Splunk to Sentinel, your Sigma rules don't need to be rewritten from scratch; (3) threat intel vendors can publish Sigma rules for newly discovered attack techniques that your team can immediately compile and deploy. Sigma does not execute faster, does not include AI anomaly detection, and does not automatically test rules.",
        xp: 20,
      },
      // ── Question 3 ──────────────────────────────────────────────
      {
        type: "question",
        id: "deteng-q3",
        question:
          "A detection engineer creates an ATT&CK coverage heatmap for their environment and discovers that techniques T1566 (Phishing), T1078 (Valid Accounts), and T1190 (Exploit Public-Facing Application) have zero detection rules assigned to them. What does this mean practically?",
        options: [
          "These three techniques are so rare that no rule is needed — the probability of encountering them is statistically negligible",
          "These three techniques represent blind spots — if an attacker uses any of them against the organisation, no SIEM alert will fire, and the intrusion may go undetected until another, later technique is caught",
          "The SIEM vendor has already built-in default rules for these techniques, so a custom rule would be redundant and cause duplicate alerts",
          "ATT&CK techniques can only be detected by endpoint detection tools (EDR), not by SIEM rules — these gaps do not apply to SIEM coverage",
        ],
        answer: 1,
        explanation:
          "A coverage gap on an ATT&CK heatmap means: if an attacker uses that technique, your detection infrastructure will be silent. T1566 (Phishing), T1078 (Valid Accounts used by attackers), and T1190 (exploiting a web-facing application) are three of the most common initial access techniques. Having no detection for them means an attacker's initial compromise could go entirely unnoticed. The ATT&CK heatmap's purpose is exactly to surface these gaps so detection engineers can prioritise writing rules for uncovered techniques — especially those used by threat actors relevant to the organisation's industry and geography.",
        xp: 20,
      },
      // ── Log Analysis ───────────────────────────────────────────
      {
        type: "log_analysis",
        id: "deteng-la1",
        heading: "SIEM Correlation Rule Alert — Spray-then-Success Pattern",
        context:
          "Your SIEM fired alert CORP-AUTH-0042 with severity HIGH. The rule name is 'Spray-then-Success' and it is designed to catch password spray attacks that ultimately succeed — the most dangerous variant where the attacker actually gained access. Review the SIEM alert event below, which represents the correlation rule's output after aggregating underlying authentication events.",
        event: {
          id: "evt-deteng-siem-001",
          ts: "2026-06-24T06:43:19.007Z",
          source: "siem",
          event_type: "edr_alert",
          hostname: "SIEM-CORP-PROD",
          severity: "high",
          raw: {
            "rule.name": "Spray-then-Success",
            "rule.id": "CORP-AUTH-0042",
            "rule.description":
              "Multiple failed Windows logons targeting distinct accounts followed by a successful logon from the same source IP within a 10-minute window — indicates successful password spray attack",
            "rule.level": 8,
            "rule.category": "Credential Access",
            "mitre.tactic": "Credential Access",
            "mitre.technique": "T1110.003",
            "mitre.technique_name": "Brute Force: Password Spraying",
            "source.ip": "91.108.56.177",
            "source.geo.country_name": "Russia",
            "source.geo.city_name": "Moscow",
            "target.user.distinct_count": 47,
            "target.user.success_list": ["r.huang", "m.patel", "d.oconnor"],
            "auth.failure_count": 94,
            "auth.success_count": 3,
            "auth.timespan_minutes": 8,
            "auth.failure_substatus": "0xC000006A",
            "auth.logon_type": 3,
            "auth.auth_package": "NTLM",
            "related_events.count": 97,
            "related_events.first_seen": "2026-06-24T06:35:11.001Z",
            "related_events.last_seen": "2026-06-24T06:43:07.882Z",
            "event.created": "2026-06-24T06:43:19.007Z",
          },
        },
        questions: [
          {
            question:
              "The rule's `mitre.technique` field shows `T1110.003`. Based on the reading material, what does the breakdown of T1110 → .003 represent in the MITRE ATT&CK framework?",
            options: [
              "T1110 is the tactic (Credential Access) and .003 is the specific technique (Password Spraying)",
              "T1110 is the parent technique (Brute Force) and .003 is the sub-technique (Password Spraying) — a more specific variant of the broader brute force category",
              "T1110 is the rule version number and .003 is the detection confidence level on a scale of 0.000 to 1.000",
              "T1110 is the SIEM vendor's internal technique code and .003 is the MITRE-assigned identifier for that vendor's mapping",
            ],
            answer: 1,
            explanation:
              "In MITRE ATT&CK, techniques are organised hierarchically: T1110 is 'Brute Force' — the parent technique covering all forms of trying many passwords to gain access. Sub-techniques add specificity: T1110.001 is Password Guessing (random passwords against one account), T1110.002 is Password Cracking (offline hash cracking), T1110.003 is Password Spraying (one password against many accounts), T1110.004 is Credential Stuffing (breached credential pairs). The sub-technique tells you exactly *what* the attacker did, which helps with both investigation (what to look for) and response (what to contain).",
            xp: 20,
          },
          {
            question:
              "The alert shows `auth.failure_count: 94` failures against `target.user.distinct_count: 47` accounts, followed by `auth.success_count: 3` successes, all within `auth.timespan_minutes: 8`. What does the ratio of ~2 failures per distinct account tell you about this attack?",
            options: [
              "The attacker tried 2 passwords per account, which is a brute force approach that would trigger lockout policies on most systems",
              "Each account was attempted approximately twice, staying at or below the typical lockout threshold (often 3-5 attempts), which is deliberately designed to avoid triggering account lockout while still testing multiple accounts",
              "The 2:1 ratio is statistically normal for legitimate authentication errors and does not indicate a spray pattern",
              "The 94 failures are too many for a spray — real sprays attempt each account exactly once. This is actually a brute force attack on 2 accounts with 47 attempts each",
            ],
            answer: 1,
            explanation:
              "94 failures / 47 accounts = approximately 2 attempts per account. Many organisations set lockout thresholds at 3-10 failed attempts. By keeping attempts per account below the lockout threshold, the attacker avoids triggering Event 4740 (account lockout) while still testing many accounts. This low-attempt-per-account pattern is the defining characteristic of a password spray versus brute force. The 3 successes out of 47 tested accounts (6.4% success rate) is also realistic for a spray using a common password against a large user base.",
            xp: 20,
          },
          {
            question:
              "Given the alert details above — 3 accounts with confirmed successful logons after the spray, all within an 8-minute window — what is the MOST time-critical action and why?",
            options: [
              "Block the source IP — preventing the attacker from making further API calls is the fastest way to stop the attack and should always be the first step",
              "Escalate to Tier 2 — only senior analysts can make decisions about compromised accounts, so no action should be taken until escalation is complete",
              "Disable the 3 accounts in `target.user.success_list` (r.huang, m.patel, d.oconnor) — these are accounts where the attacker already succeeded and may currently be active in the environment, making every minute of continued access dangerous",
              "Run a forensic image of all servers before touching anything — evidence preservation takes priority over containment when attackers are already inside",
            ],
            answer: 2,
            explanation:
              "When a spray has already succeeded, the compromised accounts are the active threat vector — the attacker may already be logged in, moving laterally, or exfiltrating data right now. Disabling those 3 accounts immediately stops their current and future use by the attacker. Blocking the source IP is valuable but secondary — the attacker can switch IPs, but they cannot use the disabled accounts regardless of IP. Evidence preservation is important but not more important than stopping an active intrusion. Tier 2 escalation should happen in parallel with, not instead of, immediate containment.",
            xp: 25,
          },
        ],
      },
      // ── Matching Task — Sigma Rule Components ───────────────────
      {
        type: "matching" as const,
        id: "deteng-m1",
        heading: "Match Sigma Rule Components to Their Purpose",
        instructions: "A Sigma detection rule is built from named sections. Match each section name on the left to what it actually does in the rule.",
        pairs: [
          {
            id: "logsource",
            left: "logsource",
            right: "Defines which log type this rule applies to — product, service, and category",
          },
          {
            id: "detection",
            left: "detection",
            right: "Contains the field-value conditions that must match for the rule to fire",
          },
          {
            id: "condition",
            left: "condition",
            right: "Boolean expression combining the named detection groups (e.g. 'selection and not filter')",
          },
          {
            id: "falsepositives",
            left: "falsepositives",
            right: "Documents known benign behaviors that trigger this rule — guides analyst triage",
          },
          {
            id: "level",
            left: "level",
            right: "Severity rating of the finding — informational, low, medium, high, or critical",
          },
        ],
        explanation: "A Sigma rule is a vendor-neutral detection specification. Understanding each section's purpose is essential for tuning. The 'logsource' section tells the SIEM which log collection to search. The 'detection' section defines named groups of field-value conditions. The 'condition' combines those groups with boolean logic — this is where you add exclusions (e.g., 'not filter') to reduce false positives. The 'falsepositives' section is a human-readable guide for the analyst — it does not affect rule behavior but tells the responder what to verify before escalating. The 'level' maps to SIEM alert priority. When tuning, you modify 'detection' to add exceptions and update 'falsepositives' to document why.",
        xp: 30,
      },

      // ── Flag ───────────────────────────────────────────────────
      {
        type: "flag",
        id: "deteng-flag1",
        prompt:
          "The SIEM correlation rule that fired in the log analysis above contains a MITRE ATT&CK technique identifier in the `mitre.technique` field. This technique ID specifically identifies 'Password Spraying' as a sub-technique of Brute Force. Enter the exact technique ID as it appears in the raw log (format: T followed by 7 digits with a decimal point, e.g., T1234.567).",
        answer: "T1110.003",
        hint: "Look at the `mitre.technique` field in the raw log event. It follows the standard ATT&CK format: T followed by 4 digits, a dot, and 3 more digits.",
        xp: 40,
      },
      // ── Query Fill: compile the Sigma rule to SPL ────────────────
      {
        type: "query_fill",
        id: "deteng-queryfill1",
        heading: "Write It Yourself: Compile the Password Spray Sigma Rule to SPL",
        language: "spl",
        context:
          "Reading 2 showed the password-spray Sigma rule as EventID: 4625, SubStatus: 0xC000006A, condition: count(TargetUserName) by IpAddress > 10. Compile that same detection logic into Splunk SPL yourself, the way a detection engineer would before deploying it.",
        template:
          "index=security sourcetype=WinEventLog:Security\n| where EventCode={{eventcode}}\n| where Sub_Status=\"{{substatus}}\"\n| stats dc(TargetUserName) as accounts_targeted by src_ip\n| where accounts_targeted > {{threshold}}",
        blanks: [
          { id: "eventcode", answers: ["4625"], placeholder: "Event ID" },
          { id: "substatus", answers: ["0xC000006A", "0xc000006a"], placeholder: "wrong-password SubStatus" },
          { id: "threshold", answers: ["10"], placeholder: "account count threshold" },
        ],
        explanation:
          "EventCode 4625 is a failed logon; Sub_Status 0xC000006A specifically means \"wrong password\" (as opposed to 0xC0000064, unknown username). dc(TargetUserName) — distinct count — by src_ip mirrors the Sigma rule's \"count(TargetUserName) by IpAddress\", and the > 10 threshold is the same one specified in the Sigma condition. This is exactly what a sigmac/sigma-cli compile step produces for a Splunk backend.",
        xp: 30,
      },
    ],
  },
];

export default rooms;
