
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
    xp: 185,
    icon: "🔑",
    // identity-basics teaches authn-vs-authz, MFA, sessions/tokens — the ground
    // this room assumes. It was authored later (batch 21) and never wired in as a
    // prerequisite, so a learner could hit password-spray/Kerberos monitoring
    // without the identity foundations. (identity-basics itself only needs
    // intro-cybersecurity, so this adds no deep lock.)
    // active-directory (batch-03) teaches domain controllers, Kerberos, NTDS.dit
    // and the LSASS/DCSync ground this room's Kerberoasting/DCSync monitoring
    // assumes — added as a prerequisite so the learner meets the AD mechanics
    // before being asked to DETECT attacks against them (expert-review P1).
    prerequisites: ["windows-event-logs", "identity-basics", "active-directory"],
    tasks: [
      // ── Reading 1 ──────────────────────────────────────────────
      {
        type: "reading",
        id: "auth-r1",
        heading: "How Authentication Works — and How Attackers Abuse It",
        content:
          "**Analogy:** Imagine a nightclub with a list at the door. When you arrive, the bouncer checks your name (username) and your ID (password). If they match the list, you're in. An attacker who wants inside has two choices: guess your name and ID combination, or steal your ID entirely.\n\nEvery time a user logs on to a Windows computer or server, the operating system writes an event to the **Security Event Log**. These events are the bouncer's notebook — a permanent record of everyone who tried to enter and whether they succeeded.\n\nThe most important events you'll encounter as a SOC analyst are:\n\n- **Event ID 4624** — Successful logon. The 'Logon Type' field tells you *how* the user authenticated. This is a small, fixed, documented list of values — worth memorising, because a logon type that does not fit the account is itself a detection. Microsoft's own guidance for this event explicitly recommends alerting when, for example, a Domain Admin shows up as a Type 4 (Batch) or Type 5 (Service) logon, because that mismatch usually means an attacker is reusing a privileged credential in an unexpected way. The full set:\n\n| Type | Name | What it means | Why a SOC analyst cares |\n| --- | --- | --- | --- |\n| 2 | Interactive | A user logged on at the physical keyboard, console, or KVM | Normal at a desk; suspicious on a headless server nobody sits at |\n| 3 | Network | Access from another machine over the network — SMB file shares, mapped drives, most remote command execution | The workhorse of lateral movement; Pass-the-Hash lands here |\n| 4 | Batch | A scheduled task or batch job ran as the account, with no human present | A normally human account suddenly used as Batch can indicate scheduled-task persistence |\n| 5 | Service | The Service Control Manager started a service under this account | Expected for service accounts; a Domain Admin appearing as Type 5 is a red flag |\n| 7 | Unlock | An already-logged-on workstation was unlocked | Places a specific person at that console at that exact time |\n| 8 | NetworkCleartext | A network logon where the password reached the server in cleartext (unhashed) form, e.g. IIS basic authentication | Cleartext credentials crossing the network — find out which application is doing this |\n| 9 | NewCredentials | A process cloned its own token and supplied *different* credentials for its outbound network connections (the runas /netonly pattern) | Classic Pass-the-Hash / lateral-movement tradecraft — the attacker runs as one identity locally but authenticates outward as another |\n| 10 | RemoteInteractive | Remote Desktop / Terminal Services (RDP) | Full graphical control of a desktop; watch for RDP from unexpected hosts, times, or countries |\n| 11 | CachedInteractive | Logon using cached domain credentials because the domain controller could not be reached | Normal for a laptop off the corporate network; unusual on a wired server that should always reach a DC |\n\n(Type 0 is System-only, and types 12 and 13 are internal cached-variant/auditing values you will rarely triage directly.)\n- **Event ID 4625** — Failed logon. Every wrong password, expired account, or disabled user lands here. The `SubStatus` field is a hex code that tells you *why* it failed: `0xC000006A` = wrong password, `0xC0000064` = username doesn't exist, `0xC0000234` = account locked out.\n- **Event ID 4648** — Explicit credential use. This fires when a process starts using *different* credentials — for example, `runas.exe` or a service running as another account. Attackers who have stolen credentials but aren't logged in as that user will generate this event.\n- **Event ID 4768 / 4769** — Kerberos ticket requests. Kerberos is the authentication protocol for Active Directory environments. 4768 is a Ticket Granting Ticket (TGT) request — 'I want to prove who I am.' 4769 is a Service Ticket (TGS) request — 'I want to access a specific service.'\n\n**Why does any of this matter?** Because attackers must authenticate to do almost anything on a Windows network. Moving laterally to a new server, accessing a file share, running a remote command — all of these leave authentication footprints. If you can read the authentication log, you can often catch the attacker in the act.\n\n**The NTLM vs Kerberos split** is worth understanding. Kerberos is the modern, preferred protocol in Active Directory. NTLM is the older fallback — used when a client connects by IP address instead of hostname, or when Kerberos is unavailable. Seeing a high volume of NTLM auth from modern machines is suspicious; it may mean an attacker is forcing NTLM — either to capture Net-NTLMv2 challenge-responses for offline cracking, or to relay the authentication to another server in real time (NTLM relay, which needs no cracking at all).\n\n**Account lockout (Event 4740)** fires when a user hits the maximum number of failed attempts and their account gets locked. A single lockout is normal — a user typed their password wrong. A wave of lockouts across 20 different accounts at 2 AM is an attacker running a spray.\n\nAs a SOC analyst, you don't read these logs one by one. You look at *patterns*: many 4625s from the same IP in a short window, 4740s appearing on accounts that don't usually get locked, or a 4624 Type 10 (RDP) from a country where no employee lives.",
        checkpoint: {
          question: "According to the reading, which Event ID fires when a user hits the maximum number of failed logon attempts and their account gets locked?",
          options: ["Event ID 4624", "Event ID 4648", "Event ID 4740", "Event ID 4768"],
          answer: 2,
          explanation:
            "Event ID 4740 is the account lockout event. A single lockout is normal user error, but a wave of lockouts across many accounts at an unusual hour is a strong indicator of a password spray.",
        },
      },
      // ── Reading 2 ──────────────────────────────────────────────
      {
        type: "reading",
        id: "auth-r2",
        heading: "Password Spray vs Credential Stuffing — Spot the Difference",
        content:
          "**Analogy:** A password spray is like a burglar who walks down a street and tries the same master key on every front door, hoping one house has a bad lock. Credential stuffing is like that same burglar using a stolen list of house keys — they know the real keys, they just don't know *which house* each key belongs to.\n\nBoth attacks are designed to stay under the radar of account lockout policies. Here's how each one works:\n\n**Password Spray:**\n- The attacker picks one or a few common passwords: `Spring2024!`, `Company123`, `Welcome1`.\n- They try that password against *every account in the organisation* — hundreds or thousands.\n- Because they only try each account once or twice, the account lockout threshold (e.g. 5 failed attempts) is never triggered.\n- In the Windows Security log, you'll see Event 4625 with SubStatus `0xC000006A` (wrong password) distributed across *many different* `TargetUserName` values, all from the **same source IP** in a short time window.\n- Detection signature: **single source IP, many target accounts, low attempt count per account, SubStatus 0xC000006A**.\n\n**Credential Stuffing:**\n- The attacker has a database of username + password pairs leaked from another breach (e.g. a \"combo list\" such as Collection #1, 2019).\n- They try those exact pairs against your login page or VPN.\n- Attempt counts per account are also low — usually one or two per account.\n- The difference is that some attempts *succeed*, because users reused their password from the breached site.\n- Detection: mixed SubStatus codes (some 0xC000006A, some 4624 successes), and the successful logon IPs may be in unusual geographic locations.\n\n**Impossible Travel** is one of the most reliable signals in identity monitoring. If a user successfully authenticates from New York at 09:00 and then again from Tokyo at 09:45, something is wrong — no human can travel that distance in 45 minutes. This pattern means either the account is compromised (attacker in Tokyo) or the user is using a VPN that exits in a different country.\n\nSIEM tools like Microsoft Sentinel and Splunk can calculate the time and distance between consecutive logons and fire an alert when the implied travel speed is physically impossible. The raw events are still just two 4624s — the intelligence comes from correlating them.\n\n**Golden Ticket** attacks are the most dangerous Kerberos attack. After an attacker compromises the Domain Controller and extracts the `krbtgt` account's NTLM hash, they can forge a TGT for any user at any time — with an arbitrary lifetime and no account password required. A forged ticket is cryptographically valid, so the tells in the DC logs are subtle. The reliable indicators:\n- A `TargetUserName` in 4768/4769 that **doesn't exist in Active Directory**, or a mismatched/blank domain field — a forged ticket can name a principal the DC has no record of.\n- **Encryption downgrade**: RC4 (`Ticket Encryption Type 0x17`) in a domain that otherwise issues AES (`0x12`). Many forging tools default to RC4.\n- A 4769 (service-ticket request) for a logon session with **no preceding 4768** (TGT request) from that same DC — a forged TGT never went through the AS-REQ. Treat this as a *lead, not proof*: a legitimate TGT is cached on the client for ~10 hours (so the 4768 may sit outside your search window), and the 4768 may have been served by a **different DC** than the one logging the 4769. A missing 4768 on one DC is therefore not conclusive on its own.\n\nNote what 4769 does **not** give you: it has no ticket-lifetime, start-time or expiry field at all (its fields are Account Name, Service Name, Client Address, Ticket Options, Ticket Encryption Type, Failure Code and Transited Services). The tell-tale 10-year lifetime is real, but you see it by running `klist` on the endpoint holding the ticket — **not** in the DC's event log. So catch a golden ticket by correlating the DC-log anomalies above, then confirm the abnormal lifetime with `klist` on the host.",
        checkpoint: {
          question: "According to the reading, what is the key difference in Windows Security logs between password spray and credential stuffing?",
          options: [
            "Password spray only ever targets non-interactive service accounts, while credential stuffing exclusively targets accounts belonging to human users",
            "Credential stuffing shows some successful logons because attackers use real leaked username/password pairs, while a pure password spray is all failures with SubStatus 0xC000006A",
            "Password spray attacks always originate from known Tor exit node IP ranges, whereas credential stuffing attacks never use Tor infrastructure at all",
            "There is no observable difference between the two attacks anywhere in the logs — both produce an identical field pattern in Windows Security events",
          ],
          answer: 1,
          explanation:
            "In credential stuffing, some login attempts succeed because the attacker is using real username/password pairs leaked from another breach and reused by the victim. In pure password spray, the attacker is guessing a common password, so it's almost entirely failures (0xC000006A) across many accounts with no successes. Neither attack is defined by account type (service vs. human) or by whether Tor is used — both are defined by the shape of the attempts, and that shape is clearly visible in the logs, not identical between the two.",
        },
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
          "Atypical location — a first-seen country for this user, which is low severity and closes once the user confirms recent travel",
          "Impossible travel — the implied speed between the two logons is physically unachievable, so the account is likely compromised",
          "Pass-the-Ticket — a stolen Kerberos ticket was replayed from Sydney, and the two 4624 events alone prove ticket theft",
          "Concurrent session — the user is legitimately signed in on two devices, so the Sydney logon is benign without further evidence",
        ],
        answer: 1,
        explanation:
          "Impossible travel detection identifies when the implied speed between two consecutive successful logons is physically impossible. London to Sydney (17,000 km) in 50 minutes requires ~20,000 km/h — far beyond any aircraft. The most likely conclusion is account compromise: an attacker in Sydney obtained the user's credentials. An atypical-location alert only flags a first-seen country and ignores the time between logons, so it does not capture the physical impossibility here. A concurrent session on a second device cannot explain two continents within 50 minutes, and two 4624 events alone do not prove Kerberos ticket theft (Pass-the-Ticket would need ticket-level evidence such as 4768/4769 anomalies).",
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
          vendor: "Windows Security",
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
              "The attacker is physically sitting at the Domain Controller's own keyboard, which is what LogonType 3 combined with the NTLM package specifically represents",
              "The attacker is connecting over the network using NTLM — possibly because they are connecting by IP address rather than hostname, or Kerberos is unavailable",
              "The attacker is using an interactive Remote Desktop Protocol session and already holds valid domain credentials for the account being targeted",
              "The attacker has already obtained a full Kerberos Ticket Granting Ticket and is now using it to request additional Kerberos service tickets",
            ],
            answer: 1,
            explanation:
              "Logon Type 3 is a network logon — the authentication request arrived over the network, not from a local interactive session. NTLM being used instead of Kerberos (the preferred AD protocol) often means the client addressed the target server by IP address rather than hostname (e.g., \\\\<DC01's IP>\\share — Kerberos tickets are issued for service names, so pointing at a raw IP falls back to NTLM; the IP in that path is the SERVER's, while 185.220.101.45 in IpAddress is the attacker's source), or that they are targeting a service that only supports NTLM. This is a common pattern in sprays where automated tools connect directly by IP.",
            xp: 20,
          },
          {
            question:
              "The alert notes that 3 accounts successfully authenticated 7 minutes AFTER the spray ended. What is the CORRECT next action for the analyst?",
            options: [
              "Close the alert as fully resolved — the spray traffic has stopped and the 3 successful logons that followed it are most likely just coincidental timing",
              "Simply increase the SIEM's alerting threshold going forward, so that similar future patterns generate less noise for the on-call analyst to review",
              "Immediately disable the 3 accounts that had successful logons, preserve evidence, and escalate to Tier 2 for full investigation of what those accounts accessed post-logon",
              "Block the source IP address at the perimeter firewall and consider the matter fully handled, since the attacker can no longer reach the network at all",
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
    xp: 270,
    icon: "👑",
    prerequisites: ["auth-identity-monitoring"],
    tasks: [
      // ── Reading 1 ──────────────────────────────────────────────
      {
        type: "reading",
        id: "priv-r1",
        heading: "What Privileged Accounts Are and Why Attackers Love Them",
        content:
          "**Analogy:** In a hospital, most staff can access their own patient ward and the common areas. But a small group — the hospital administrator, the chief of surgery, the IT director — have a master key that opens every door. If an attacker steals an ordinary nurse's badge, they can access one ward. If they steal the administrator's master key, they can access everything, including the pharmacy, the server room, and the billing department. Privileged accounts are that master key.\n\nIn an Active Directory environment, 'privileged' means different things at different levels:\n\n**Domain-level privileges:**\n- **Domain Admins** — the highest human-operated group. Members can manage every object in Active Directory, log on to every domain-joined machine, and reset any password including other admins.\n- **Enterprise Admins** — even higher; a group that exists only in the forest root domain and has full control over every domain in the forest (there is no built-in group that controls more than one forest). Usually only a handful of people should ever be in this group.\n- **Schema Admins** — can modify the AD schema itself. Should be empty except during deliberate schema extensions.\n\n**Machine-level privileges:**\n- **Local Administrators** — admin rights on a single machine, not the whole domain. Still dangerous for lateral movement.\n- **Service Accounts** — non-human accounts that run background services (backup software, monitoring agents, database engines). They often have elevated rights but are not supposed to be used interactively by humans.\n\n**Windows Privilege Rights (User Rights):**\nBeyond group membership, Windows assigns specific 'privilege rights' to accounts. These are lower-level than group membership and control what a process can do:\n- **SeDebugPrivilege** — allows a process to read and write memory of *any other process*, including the LSASS process (which stores credential hashes). This is the privilege used by tools like Mimikatz to dump credentials. Legitimate holders: SYSTEM, local administrators. Seeing this on a service account is a red flag.\n- **SeBackupPrivilege** — allows reading any file regardless of file permissions, ostensibly for backup software. An attacker with this privilege can read the NTDS.DIT file (the Active Directory database containing all password hashes) off a Domain Controller.\n- **SeRestorePrivilege** — allows writing any file regardless of file permissions. Combined with SeBackupPrivilege, an attacker can replace system files.\n- **SeTcbPrivilege** — 'Act as part of the operating system.' Extremely powerful; almost never legitimately granted to non-SYSTEM accounts.\n\n**Why attackers target privileged accounts:**\n1. **Persistence** — Domain Admin can create new accounts, modify group policies, and maintain access even if their initial foothold is evicted.\n2. **Lateral movement** — Local admin credentials work on every machine in the environment if password reuse is present (Pass-the-Hash).\n3. **Credential harvesting** — SeDebugPrivilege + LSASS access = every logged-on user's password hash in memory.\n4. **Data access** — With SeBackupPrivilege, the entire AD database can be read and exfiltrated.\n\nThe key insight for monitoring: **privilege use should be rare, predictable, and from expected sources.** A Domain Admin account that logs on every weekday morning from the same workstation is normal. That same account logging on at 3 AM from a new machine via RDP is an alert.",
        checkpoint: {
          question: "According to the reading, which Windows privilege right allows a process to read and write the memory of any other process — including LSASS — and is the privilege used by tools like Mimikatz?",
          options: ["SeBackupPrivilege", "SeDebugPrivilege", "SeRestorePrivilege", "SeTcbPrivilege"],
          answer: 1,
          explanation:
            "SeDebugPrivilege allows a process to access the memory of any other process, including LSASS where credential hashes live — exactly what Mimikatz and similar credential-dumping tools rely on. Seeing this privilege on a service account is a red flag.",
        },
      },
      // ── Reading 1b ─────────────────────────────────────────────
      {
        type: "reading",
        id: "priv-r1b",
        heading: "\"Permitted\" Is Not \"Authorised\" — The Question Behind Every Privileged Alert",
        content:
          "**Analogy:** A hotel maid's keycard technically opens every room on her floor — the hotel's access system grants her that. If she uses it to enter Room 214 to clean it during her shift, that's normal work. If she uses that exact same keycard to enter Room 214 at 3 AM while the guest is out, using the same door, the same badge swipe, the same 'access granted' log entry — something is very wrong, even though the system permitted it both times. The keycard reader has no concept of *why* she's there. Only a human looking at context — the time, the guest's schedule, whether housekeeping was even assigned that room that night — can tell the difference.\n\nThis is the single most important mental model in privileged access monitoring, and it is worth stating as its own rule, because almost every false negative in this space comes from skipping it: **'permitted' and 'authorised' are two completely different questions, and Windows (or any system) can only ever answer the first one.**\n\n**Permitted** is a technical fact. It means the account's token, group membership or role grants it the ability to perform the action. A Domain Admin account is *permitted* to create a new user, reset any password, add someone to any group, or log on to any machine in the domain, at any hour, from anywhere its network access allows. The operating system checked the account's privileges, found them sufficient, and let the action through. Every event you read in priv-r2 — 4672, 4728, 4673 — is a record that something was permitted. None of them, by themselves, say whether it was *supposed* to happen.\n\n**Authorised** is a business fact, and it lives outside the operating system entirely. It means a specific human or process with the standing to approve that specific action actually approved it, through the organisation's own process — typically a **change ticket** (a documented, pre-approved record of planned work, referenced by an ID like `CHG-91004`), inside an agreed **maintenance window** (a scheduled time block, often overnight, when planned changes are allowed to happen), and traceable to a **requester or owner** who can be asked 'why did you do this?' and give an answer that checks out. Nothing about a Windows Security Event records any of this — a change ticket lives in a separate system (a service-desk or ITSM platform), and correlating the two is manual, or handled by SOAR playbooks that query the ticketing system automatically.\n\nHere is why this distinction has to become reflexive. Take the exact scenario priv-r1 ended on: 'a Domain Admin account that logs on every weekday morning from the same workstation is normal — that same account logging on at 3 AM from a new machine is an alert.' Both logons are equally *permitted* — the account's group membership does not change between 9 AM and 3 AM. What changed is the second, invisible layer: was there a change ticket scheduling maintenance for 3 AM? Was that new machine the admin's usual jump box, or unrecognised? A junior analyst who only checks 'is this account allowed to do this?' will wave through both logons, because the answer is yes both times. A trained analyst asks the second question — was this *specific* action, at *this* specific time, by *this* specific actor, something the organisation actually agreed to — and that is where the 3 AM logon fails.\n\nThe same test applies to every reading in this room. priv-r2 already hinted at it: 'any addition to \\[Domain Admins\\] should be a change-ticket in your organisation — if no ticket exists, treat it as malicious.' That sentence is the permitted-vs-authorised test applied to Event 4728. priv-r3's Step 6 (an attacker creating a new Domain Admin account for persistence) generates events that are technically identical, field-for-field, to a system administrator legitimately onboarding a new admin during a planned access review — the only thing that tells them apart is whether a change ticket, an owner and a business reason exist to back it up. **The question you must learn to ask before closing any privileged-access alert is not 'could this account do this?' — group membership already answered that. It is 'was this account *supposed* to do this, right now, and can someone prove it?'**",
        checkpoint: {
          question:
            "A Domain Admin account creates a new user account and adds it to the Domain Admins group at 2 AM. The account's group membership fully permits this action. What is the correct next analyst step?",
          options: [
            "Confirm the acting account is a current member of Domain Admins, since valid membership means the change was approved",
            "Look for a change ticket, maintenance window and named owner covering this specific addition before deciding",
            "Declare a confirmed compromise, since a privileged-group addition at 2 AM is enough evidence of malice on its own",
            "Close it as benign, since Windows only writes Event 4728 after verifying the actor had rights to make the change",
          ],
          answer: 1,
          explanation:
            "Group membership only proves the action was permitted; authorisation lives outside Windows — a change ticket, an agreed maintenance window and an owner who can explain it. “Confirm the acting account is a current member of Domain Admins” re-checks permission, which the stem already established. “Declare a confirmed compromise” over-reads the hour: a planned 2 AM change is normal if a ticket backs it. “Close it as benign, since Windows only writes Event 4728 after verifying the actor had rights” is true about the log but again only proves permission, not approval.",
        },
      },
      // ── Reading 2 ──────────────────────────────────────────────
      {
        type: "reading",
        id: "priv-r2",
        heading: "Key Windows Events for Privileged Activity Detection",
        content:
          "**Analogy:** A high-security vault doesn't just have a lock — it has a camera, a visitor log, a guard who signs people in and out, and an alarm on the door. Windows privileged access events are that multi-layer record: every privilege grant, every group change, every special logon is written down.\n\nHere are the critical event IDs every SOC analyst must know for privileged access monitoring:\n\n**Event 4672 — Special Logon (Admin Rights Granted):**\nThis event fires every time a user logs on with administrator-equivalent privileges. The `PrivilegeList` field lists every elevated privilege right their token carries. Key fields: `SubjectUserName` (who logged on), `SubjectLogonId` (their session ID, links to 4624), `PrivilegeList` (list of special privileges). Normal: your Domain Admin logging on from their admin workstation generates this. Abnormal: a service account (`svc-` prefix) generating 4672 with dangerous privileges like `SeDebugPrivilege`, or any 4672 at an unusual time.\n\n**Event 4728 — A member was added to a security-enabled global group:**\n**Event 4732 — A member was added to a security-enabled local group:**\n**Event 4756 — A member was added to a security-enabled universal group:**\nAll three record group membership changes. The critical version: `Domain Admins`, `Enterprise Admins`, `Administrators` as the target group. Any addition to these groups should be a change-ticket in your organisation — if no ticket exists, treat it as malicious. Field to watch: `MemberSid` (who was added) and `TargetUserName` (name of the group).\n\n**Event 4673 — Sensitive Privilege Use:**\nFires when a process actually *uses* a sensitive privilege (SeDebugPrivilege, SeBackupPrivilege, etc.) — not just holds it. This is noisier than 4672 (fires per-use, not per-logon) but can catch active abuse. Look for process names that shouldn't be using these privileges: `cmd.exe`, `powershell.exe`, or unknown executables using `SeDebugPrivilege` is very suspicious. Two caveats: use of SeBackupPrivilege and SeRestorePrivilege is only audited when the \"Audit: Audit the use of Backup and Restore privilege\" policy is enabled (off by default, because it is extremely noisy), and many environments don't enable Sensitive Privilege Use auditing at all. For the classic debug-privilege abuse — a tool opening LSASS memory — the practical detection is process-access telemetry: Sysmon Event 10 (ProcessAccess) with `TargetImage` = `lsass.exe`, or your EDR's LSASS-access alerts.\n\n**Event 4688 / Sysmon Event 1 — Process Creation:**\nAttackers use tools like `PsExec` (legitimate remote admin tool, heavily abused) and `wmic.exe` to move laterally and execute commands as SYSTEM. PsExec generates an Event 7045 (service installed) on the target machine when it creates its remote service. Watch for `psexec` in process command lines and for new services with random names (e.g., `PSEXESVC`).\n\n**LSASS access patterns (Sysmon Event 10 — Process Access):**\nLSASS.EXE is the Windows process that holds credential material (password hashes, Kerberos tickets) in memory. Legitimate access to LSASS is done only by specific Windows system processes. Mimikatz and similar tools access LSASS with `GrantedAccess = 0x1FFFFF` (full access) or `0x1010` (read virtual memory). Sysmon's Event 10 records which process opened which handle to LSASS, and with what access rights. This is one of the most reliable detections for credential dumping.\n\n**PAM (Privileged Access Management) Solutions:**\nIn mature organisations, privileged accounts are managed by PAM vaults — systems like **CyberArk** or **BeyondTrust** that:\n- Store admin passwords in an encrypted vault (analysts never know the actual password)\n- Require checkout with a reason before granting access\n- Rotate passwords automatically after each use\n- Record every keystroke and command during privileged sessions\n\nPAM logs to monitor: vault checkout events (who checked out which account, when, and with what justification), session recordings reviewed post-incident, and any attempt to access a privileged account *outside* the PAM vault (bypassing controls). **Just-in-time (JIT) access** is a modern pattern where an account only receives admin privileges for the duration it's needed — a 2-hour window rather than permanent membership.\n\nA service account checking out a Domain Admin credential from the PAM vault with no associated change ticket is an immediate escalation trigger.",
      },
      // ── Reading 3 ──────────────────────────────────────────────
      {
        type: "reading",
        id: "priv-r3",
        heading: "Privilege Escalation Kill Chain — What the Attacker Does Step by Step",
        content:
          "**Analogy:** A burglar who breaks into a mailroom doesn't stop there — they look for the master keycard, find the door to the server room, copy the management computer's drive, and walk out with everything. In cyber, this progression is called the 'kill chain' or 'attack path.' Privilege escalation is the step where a burglar finds that master keycard.\n\nHere is a realistic attacker progression from regular user to Domain Admin, and the events each step generates:\n\n**Step 1 — Initial access as a regular user.**\nThe attacker phishes an employee and gets their domain credentials. They authenticate via VPN (Event 4624, Type 3). Their token has no special privileges. Events: 4624 from an external IP, potentially via unusual VPN endpoint.\n\n**Step 2 — Local privilege escalation on the compromised workstation.**\nThe attacker uses an unpatched local vulnerability (e.g., PrintNightmare, AlwaysInstallElevated) or a misconfigured service running as SYSTEM to get local admin. Events: 4672 with elevated privileges on the compromised host, 4688 showing a child process spawned from a vulnerable service.\n\n**Step 3 — Credential harvesting from LSASS.**\nWith local admin rights, the attacker runs Mimikatz: `sekurlsa::logonpasswords`. This reads LSASS memory and extracts NTLM hashes and Kerberos tickets for every user who has a session on that machine. If a Domain Admin happened to have logged on, their hash is now in the attacker's hands. Events: Sysmon Event 10 (LSASS access with GrantedAccess 0x1FFFFF), AV detection if not disabled, Windows Defender alert.\n\n**Step 4 — Pass-the-Hash / Pass-the-Ticket to Domain Admin.**\nThe attacker uses the stolen Domain Admin NTLM hash directly without cracking it (Pass-the-Hash). They connect to the Domain Controller using that hash. Events: 4624 on the DC with LogonType 3, NTLM authentication package (not Kerberos), source IP of the compromised workstation, TargetUserName = the Domain Admin account (in a 4624 the account that logged on is the Target; the Subject fields are the requesting context, usually NULL SID for network logons).\n\n**Step 5 — DCSync / NTDS extraction.**\nFrom any host — no logon to the Domain Controller needed — the attacker uses the Domain Admin's replication rights to run `mimikatz lsadump::dcsync /domain:corp.local /all`. This mimics a legitimate Domain Controller replication request and pulls all password hashes from Active Directory without touching the NTDS.DIT file on disk. Events: Event 4662 (Directory Service access) on the DC with access mask 0x100 and GUID for DS-Replication-Get-Changes — and the key tell is that the replication request comes from a machine that is not a Domain Controller. Microsoft Defender for Identity (MDI) generates a 'DCSync attack suspected' alert.\n\n**Step 6 — Persistence via new admin account or golden ticket.**\nWith all hashes, the attacker creates a new Domain Admin account (Events 4720 account create, 4728 added to Domain Admins) or forges a golden ticket using the extracted `krbtgt` hash, giving them perpetual access regardless of password resets.\n\n**Analyst takeaway:** Each step in this chain is detectable if you have the right logging and rules in place. But each step also happens quickly — a skilled attacker can go from Step 1 to Step 6 in under 20 minutes. The goal of privileged access monitoring is to generate an alert at Step 2 or Step 3 — *before* Domain Admin is reached — so the response team can contain the compromise while it's still limited to one workstation.",
        checkpoint: {
          question: "According to the reading's attack chain, what does the attacker use in Step 5 (DCSync / NTDS extraction) to pull all password hashes from Active Directory?",
          options: [
            "A Pass-the-Hash logon to the DC with the Domain Admin's NTLM hash, followed by copying NTDS.DIT off its disk",
            "A request that mimics DC-to-DC replication, pulling every hash without touching NTDS.DIT on disk",
            "A Mimikatz sekurlsa::logonpasswords run on the DC, reading every domain hash out of its LSASS memory",
            "A golden ticket forged from the krbtgt hash, used to authenticate to the DC as any user it chooses",
          ],
          answer: 1,
          explanation:
            "DCSync (mimikatz lsadump::dcsync) impersonates a DC replication request and can run from any host holding replication rights. “A Pass-the-Hash logon to the DC ... copying NTDS.DIT” merges Step 4 with a file-copy approach the reading explicitly says DCSync avoids. “sekurlsa::logonpasswords” is the Step 3 LSASS harvest of logged-on sessions, not directory replication. “A golden ticket forged from the krbtgt hash” is Step 6 persistence, which depends on the krbtgt hash that DCSync obtains.",
        },
      },
      // ── Question 1 ──────────────────────────────────────────────
      {
        type: "question",
        id: "priv-q1",
        question:
          "A Sysmon Event 10 (ProcessAccess) fires showing that `powershell.exe` accessed `lsass.exe` with GrantedAccess value `0x1FFFFF`. What does this MOST likely indicate?",
        options: [
          "A Windows Defender scan of LSASS memory, which routinely opens the process with a full-access handle",
          "Credential dumping, e.g. Mimikatz loaded in PowerShell, reading hashes and tickets from LSASS memory",
          "Session administration in PowerShell, since listing logged-on users needs a full-access LSASS handle",
          "A VSS backup snapshot, since capturing a consistent state requires opening each process with full access",
        ],
        answer: 1,
        explanation:
          "GrantedAccess 0x1FFFFF is PROCESS_ALL_ACCESS, and the reading names it as the classic Mimikatz access mask against LSASS. “A Windows Defender scan” is wrong because legitimate system processes that touch LSASS use far narrower masks, and the source here is powershell.exe, not a Defender binary. “Session administration in PowerShell” is wrong: listing logged-on users uses query APIs, not a handle into LSASS memory. “A VSS backup snapshot” works at the volume level and does not open process memory at all.",
        xp: 20,
      },
      // ── Question 2 ──────────────────────────────────────────────
      {
        type: "question",
        id: "priv-q2",
        question:
          "In the reading's Step 6, the attacker sets up persistence with a brand-new backdoor identity placed in Domain Admins. Which pair of DC events should your correlation rule join to catch that step?",
        options: [
          "4720 (user account created) + 4732 (member added to a security-enabled local group)",
          "4720 (user account created) + 4728 (member added to a security-enabled global group)",
          "4672 (special logon) + 4728 (member added to a security-enabled global group)",
          "4662 (directory service access) + 4756 (member added to a security-enabled universal group)",
        ],
        answer: 1,
        explanation:
          "Step 6 generates 4720 for the new account and 4728, because Domain Admins is a global group. “4720 + 4732” picks the local-group event, which covers groups like a server's local Administrators, not Domain Admins. “4672 + 4728” swaps creation for a special logon: 4672 only appears once the new account logs on, so it misses the creation itself. “4662 + 4756” pairs the DCSync-style directory-access event with the universal-group event — neither records creating a user or adding it to Domain Admins.",
        xp: 20,
      },
      // ── Question 3 ──────────────────────────────────────────────
      {
        type: "question",
        id: "priv-q3",
        question:
          "What is the PRIMARY security purpose of a PAM (Privileged Access Management) vault solution like CyberArk?",
        options: [
          "To keep a shared, encrypted store of admin passwords that administrators look up and type in when needed",
          "To hold privileged credentials so admins never learn them, with justified checkout, session recording and rotation",
          "To make admin rights temporary by adding accounts to Domain Admins for a fixed window, then removing them",
          "To detect credential dumping by alerting whenever a non-system process opens a handle to LSASS",
        ],
        answer: 1,
        explanation:
          "The reading lists the PAM vault's functions: encrypted storage where analysts never know the password, checkout with a reason, rotation after each use and recording of every privileged session. “A shared, encrypted store ... administrators look up and type in” is a plain password manager: the human learns the password and can reuse it, which PAM is designed to prevent. “Make admin rights temporary” describes just-in-time (JIT) access, a related pattern the reading treats separately. “Detect credential dumping” is LSASS-access telemetry (Sysmon Event 10 / EDR), not a vault.",
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
          vendor: "Windows Security",
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
            "event.created": "2026-06-24T03:22:11.004Z",
            "log.level": "critical",
            "tags": ["privileged-access", "service-account", "DC"],
          },
        },
        questions: [
          {
            question:
              "This 4672 shows svc-backup's token HOLDS SeDebugPrivilege. Sensitive Privilege Use auditing is not enabled on DC01. Which evidence would best show whether that privilege was actually used to read credentials?",
            options: [
              "Event 4673 entries for svc-backup on DC01 around 03:22, which record each use of a sensitive privilege",
              "Sysmon Event 10 on DC01 around 03:22 with TargetImage lsass.exe, showing which process opened it and how",
              "Events 4728/4732 naming svc-backup, showing which group change gave the account its extra privileges",
              "A second 4672 for svc-backup later that night, since a repeated special logon shows the privilege in use",
            ],
            answer: 1,
            explanation:
              "Debug-privilege abuse means a tool opening LSASS memory, and the reading names Sysmon Event 10 (TargetImage lsass.exe, GrantedAccess) as the practical detection. “Event 4673 entries” would record use, but the stem says Sensitive Privilege Use auditing is off, so none will exist. “Events 4728/4732” could explain how the account gained rights, but not whether they were used. “A second 4672” confuses holding with using: 4672 is written at logon and lists what the token carries, whether or not it is ever exercised.",
            xp: 25,
          },
          {
            question:
              "This event was generated at 03:22 AM on a Domain Controller, outside the scheduled backup window. What is the MOST dangerous potential attack scenario indicated by the combination of DC01 hostname + svc-backup account + SeDebugPrivilege + off-hours timing?",
            options: [
              "A backup job that started late, with the extra privileges a stale misconfiguration to fix in a hygiene ticket",
              "Someone acting as svc-backup on the DC who can open LSASS and harvest domain credential material",
              "An admin who granted SeDebugPrivilege for troubleshooting and forgot to remove it — a policy gap",
              "A Kerberoasting attempt on svc-backup, with this 4672 being the DC logging the service-ticket request",
            ],
            answer: 1,
            explanation:
              "On a DC, a token with SeDebugPrivilege can read LSASS memory, which holds credential material for domain accounts — including what an attacker needs for golden tickets. That is the most dangerous reading. “A backup job that started late” ignores that 03:22 is hours outside the 22:00–23:30 window and does not explain the two extra privileges. “An admin who ... forgot to remove it” could explain how the rights appeared, but not who is using the account at 03:22, and it is not an attack scenario. “A Kerberoasting attempt” confuses events: a service-ticket request is Event 4769, not a 4672 special logon.",
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
            "db.statement": "SELECT * FROM customers",
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
          "In the svc-backup special-logon event on DC01, you now want the matching 4624 logon event to see which machine this session came from. Enter the exact value you would search for in DC01's logon events to tie them to this 4672.",
        answer: "0x7F4A21C",
        hint: "A 4672 and the 4624 that started the same session share one identifier. The “Key Windows Events” reading names the 4672 field that carries it.",
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
          "Six hours after a Kerberoasting alert fired for the service account `svc-mssql` (RC4 ticket request, EncryptionType 0x17), your SIEM fires a new critical correlation alert on the SQL Server host itself, combining EDR process telemetry with SQL Server audit logs from the same time window. Review the process creation event below and answer the questions.",
        event: {
          id: "priv-xpcmd-evt-001",
          ts: "2024-11-14T08:31:52.000Z",
          source: "siem",
          vendor: "Microsoft Sentinel",
          event_type: "edr_alert",
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
            // ── Sentinel correlation rule: EDR process telemetry ──
            "AlertName": "EDR-SQL Correlation: xp_cmdshell Process Spawn",
            "alert.rule.id": "SQL-XPCMDSHELL-EDR-CORR-001",
            "process.name": "powershell.exe",
            "process.command_line": "powershell.exe -nop -w hidden -enc SQBFAFgA...",
            "process.parent.name": "sqlservr.exe",
            "process.parent.path": "C:\\Program Files\\Microsoft SQL Server\\MSSQL15.MSSQLSERVER\\MSSQL\\Binn\\sqlservr.exe",
            "process.integrity_level": "High",
            "user.name": "CORP\\svc-mssql",
            "host.name": "SRV-DB01.corp.contoso.com",
            // ── Correlated evidence: SQL Server Audit (same 60s window) ──
            "sql.originating_login": "svc-mssql",
            "sql.stored_procedure": "xp_cmdshell",
            "sql.query_text": "EXEC xp_cmdshell 'powershell -nop -w hidden -enc SQBFAFgA...'",
            "sql.database_role": "sysadmin",
          },
        },
        questions: [
          {
            question:
              "The process.parent.name is 'sqlservr.exe' and the process.name is 'powershell.exe'. Why is this parent-child relationship, on its own, enough to escalate this alert to critical — even before reading the sql.stored_procedure field?",
            options: [
              "Because PowerShell running on a database server is the indicator in itself, whichever process launched it",
              "Because the database engine has no routine reason to launch a shell; real DBA work runs through tools or SQL Agent jobs",
              "Because the High integrity level shows the shell escalated beyond the rights of the svc-mssql service account",
              "Because sqlservr.exe runs as SYSTEM, so any shell it spawns starts with full control of the host",
            ],
            answer: 1,
            explanation:
              "The reading's signature is the parent-child pair: the SQL Server engine serves queries and has no routine reason to start a shell, so sqlservr.exe → powershell.exe points to xp_cmdshell, much like winword.exe → cmd.exe points to a macro. “PowerShell running on a database server is the indicator in itself” ignores that admins legitimately run PowerShell there; the parent is what makes it abnormal. “The High integrity level shows the shell escalated” misreads the log: the child simply inherits the service account's token, and the user field still shows CORP\\svc-mssql. “sqlservr.exe runs as SYSTEM” is contradicted by the same field — the shell runs as svc-mssql.",
            xp: 30,
          },
          {
            question:
              "The event occurred 6 hours after a Kerberoasting alert against the same account, svc-mssql. What does this timing gap tell you about what happened in between, and what should the analyst's investigation timeline include?",
            options: [
              "Two unrelated incidents: correlation should only join alerts a few minutes apart, so triage them as separate tickets",
              "Offline cracking of the captured RC4 ticket, which logs nothing; build one timeline from the 4769 to this spawn",
              "AS-REP roasting rather than Kerberoasting, so scope the timeline to svc-mssql's 4768 events only",
              "A second, separate credential theft, since a captured ticket expires minutes after capture and can't be cracked later",
            ],
            answer: 1,
            explanation:
              "Cracking a captured RC4 service ticket happens on the attacker's own hardware and leaves no logs; once the password falls, the attacker logs in as svc-mssql and uses its sysadmin role for xp_cmdshell. The gap itself is evidence, so the timeline runs from the 4769 through this event. “Two unrelated incidents” assumes correlation windows of minutes; same-account correlation should span hours. “AS-REP roasting” is wrong because the alert was a service-ticket (4769, EncryptionType 0x17) request — AS-REP roasting targets accounts without pre-authentication through 4768. “A captured ticket expires minutes after capture” is false: offline cracking works on the captured ticket however long it takes.",
            xp: 30,
          },
        ],
      },

      // ── Flag — xp_cmdshell ────────────────────────────────────────
      {
        type: "flag",
        id: "priv-flag2",
        prompt:
          "In the sqlservr.exe → powershell.exe event, the cracked login could only run its shell breakout because of one server-level permission it held. Find that permission in the correlated SQL audit evidence and enter its name exactly.",
        answer: "sysadmin",
        hint: "The xp_cmdshell reading explains which SQL Server role a cracked SQL service account often belongs to, and why that is what turns a Windows logon into full control of the instance.",
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
    xp: 195,
    icon: "☁️",
    prerequisites: ["auth-identity-monitoring"],
    tasks: [
      // ── Reading 1 ──────────────────────────────────────────────
      {
        type: "reading",
        id: "cloud-r1",
        heading: "Cloud Audit Logs — The CCTV of the Cloud",
        content:
          "**Analogy:** When you rent office space in a building, the building management installs cameras in the lobby, elevators, and corridors. They don't install cameras inside your office — that's your responsibility. Cloud providers work the same way: they record every API call made to their infrastructure (their 'lobby'), but you are responsible for enabling detailed logging inside your own workloads.\n\n**AWS CloudTrail** is Amazon's audit log for every API call made to your AWS account. When you create an EC2 server, delete an S3 bucket, or change an IAM policy — CloudTrail writes a record. Key fields in every CloudTrail event:\n- `eventName` — what action was performed (e.g., `CreateUser`, `PutBucketPolicy`, `GetObject`)\n- `sourceIPAddress` — where the call came from. Could be an AWS service (`lambda.amazonaws.com`), a corporate IP, or an attacker's IP.\n- `userIdentity.type` — the type of caller: `IAMUser` (a human with permanent keys), `AssumedRole` (someone who used STS to assume a role — common for applications and cross-account access), `Root` (the all-powerful account root user — should almost never appear in CloudTrail)\n- `userIdentity.arn` — the full ARN of the caller, e.g., `arn:aws:iam::123456789012:assumed-role/DevRole/session-name`\n- `requestParameters` — the arguments passed to the API (e.g., `{\"userName\": \"backdoor-admin\"}` for a CreateUser call)\n- `responseElements` — the result returned by AWS (e.g., the ARN of the newly created user)\n- `awsRegion` — which region the action occurred in. Activity in regions you never use (e.g. EC2 instances launched in `sa-east-1` by a company that only runs in Europe) is suspicious. Exception: global services — IAM, the STS global endpoint, Organizations, CloudFront — always log as `us-east-1`, wherever the caller is, so `us-east-1` on an IAM event is expected and proves nothing.\n- `errorCode` — if the API call failed, why (e.g., `AccessDenied`, `NoSuchBucket`). Many `AccessDenied` errors from the same identity indicate reconnaissance.\n\n**Azure Activity Log** records all control-plane operations in Azure (creating VMs, changing NSGs, modifying role assignments). **Microsoft Entra ID (formerly Azure AD) Sign-in Logs** record every authentication event. **Microsoft Defender for Cloud** (formerly Azure Security Center) provides security posture and threat detection. **Microsoft Sentinel** is Azure's cloud-native SIEM that ingests all of these.\n\n**GCP Cloud Audit Logs** work similarly — Admin Activity logs (always on, free), Data Access logs (must be enabled, can be expensive), and System Event logs. GCP's **Security Command Center** is the equivalent of AWS GuardDuty for threat detection.\n\n**What makes cloud monitoring different from on-premises:**\n1. **No perimeter** — anyone on the internet can attempt API calls against your cloud account. There's no corporate firewall limiting who can *try*.\n2. **Credentials live in code** — developers accidentally commit AWS access keys to GitHub regularly. A leaked key gives an attacker the same access as the developer, from anywhere.\n3. **Scale and speed** — an attacker with valid cloud credentials can provision 1,000 crypto-mining servers, exfiltrate a 10 TB database, or create 50 backdoor accounts in seconds. The blast radius is enormous.\n4. **Misconfiguration is the leading cause** — open S3 buckets, overly permissive IAM roles, publicly accessible databases. Attackers scan for these continuously.",
        checkpoint: {
          question: "In five minutes, one identity produces 60 CloudTrail events spread across IAM, S3, EC2 and Secrets Manager, and nearly all carry errorCode `AccessDenied`. Based on the reading, what does this pattern most likely indicate?",
          options: [
            "A misconfigured application retrying one API call it was never granted permission to make",
            "CloudTrail failing to deliver these events to its S3 bucket, recorded as AccessDenied on each",
            "Reconnaissance — someone probing what a credential can do by trying many different calls",
            "A password-guessing attack on the identity's console login, logging each wrong guess as AccessDenied",
          ],
          answer: 2,
          explanation:
            "The reading says many `AccessDenied` errors from the same identity indicate reconnaissance — an attacker testing what a stolen credential is allowed to do. The spread across four services is the tell. “A misconfigured application retrying one API call” would repeat a single eventName, not dozens of calls across IAM, S3, EC2 and Secrets Manager. “CloudTrail failing to deliver these events” misreads the field: `errorCode` records why the API call itself failed, not a logging problem. “A password-guessing attack on the console login” would appear as failed ConsoleLogin events, not as AccessDenied on API calls to other services.",
        },
      },
      // ── Reading 2 ──────────────────────────────────────────────
      {
        type: "reading",
        id: "cloud-r2",
        heading: "IAM Attacks, S3 Exfiltration, and EC2 Metadata Abuse",
        content:
          "**Analogy:** An IAM (Identity and Access Management) backdoor is like a thief who breaks into a hotel, finds the master key, makes a copy, and then leaves — they can come back any time, even after you change the front door lock. AWS IAM attacks are about creating permanent access that survives initial detection.\n\n**IAM Backdoor Pattern — CreateUser + AttachUserPolicy:**\nThe most common IAM attack sequence:\n1. Attacker compromises existing credentials (leaked key, SSRF, phishing)\n2. `CreateUser` — creates a new IAM user with an inconspicuous name (`svc-monitor`, `backup-agent`, `deploy-bot`)\n3. `CreateAccessKey` — creates API keys for the new user\n4. `AttachUserPolicy` — attaches the `AdministratorAccess` managed policy (full control of the entire AWS account) to the new user\n5. Attacker now has a permanent backdoor that survives even if the original compromised credential is revoked\n\nDetection: `CreateUser` followed within minutes by `AttachUserPolicy` with PolicyArn containing `AdministratorAccess` from the same or correlated session. Especially suspicious if `sourceIPAddress` is a Tor exit node, a cloud proxy, or an IP that has never been seen in your CloudTrail before.\n\n**S3 Data Exfiltration:**\nS3 holds enormous amounts of sensitive data — database backups, application configs, user uploads, financial records. Exfiltration patterns:\n- `ListBuckets` — attacker enumerates all S3 buckets in the account (reconnaissance)\n- `GetBucketAcl` / `GetBucketPolicy` — checking permissions on specific buckets\n- Repeated `GetObject` on many objects in a sensitive bucket from an unusual IP\n- `GetObject` on files with sensitive names (`credentials`, `backup`, `.env`, `secrets`)\n- `PutBucketPublicAccessBlock` set to `false` followed by `PutBucketAcl` making a bucket world-readable — a common data exfiltration technique where the attacker opens your private bucket to the internet\n\n**EC2 Instance Metadata Service (IMDS) Abuse:**\nEvery EC2 instance has access to a metadata endpoint at `http://169.254.169.254/` that returns information about the instance — including **temporary AWS credentials** for whatever IAM role is attached to the instance. If an attacker achieves code execution on an EC2 instance (e.g., via a web app vulnerability), they can run:\n```\ncurl http://169.254.169.254/latest/meta-data/iam/security-credentials/\n```\nThis returns live AWS credentials that allow the attacker to make API calls with the EC2 instance's IAM role permissions — potentially with `S3FullAccess`, `EC2FullAccess`, etc. The resulting API calls will appear in CloudTrail with `sourceIPAddress` being the EC2 instance's IP and `userIdentity.type = AssumedRole` for the instance's role. IMDSv2 (requiring a session token) mitigates this, but many organisations still run IMDSv1.\n\n**AWS GuardDuty** is Amazon's managed threat detection service that analyses CloudTrail, VPC Flow Logs, and DNS logs automatically. Key finding types:\n- `UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B` — console login from unusual geography\n- `Recon:IAMUser/MaliciousIPCaller` — API calls from a known malicious IP\n- `CryptoCurrency:EC2/BitcoinTool.B` — EC2 instance communicating with crypto mining pools\n- `Exfiltration:S3/ObjectRead.Unusual` — unusual S3 data access pattern\n- `PrivilegeEscalation:IAMUser/AdministrativePermissions` — policy changes granting excessive permissions",
        checkpoint: {
          question: "According to the reading, what endpoint does an attacker query on a compromised EC2 instance to retrieve live, temporary AWS credentials for the instance's IAM role?",
          options: [
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/dynamic/instance-identity/document",
            "https://sts.amazonaws.com/?Action=GetSessionToken&Version=2011-06-15",
            "https://iam.amazonaws.com/?Action=ListAccessKeys&Version=2010-05-08",
          ],
          answer: 0,
          explanation:
            "The metadata service's `iam/security-credentials/` path returns temporary credentials for the instance's attached IAM role, and under IMDSv1 any code on the instance can query it. “/dynamic/instance-identity/document” is on the same metadata service but returns the instance's identity (account, region, instance ID), not role credentials. “sts.amazonaws.com ... GetSessionToken” is an API that needs valid credentials before it will answer. “iam.amazonaws.com ... ListAccessKeys” only lists key IDs, never secrets, and also needs credentials first.",
        },
      },
      // ── Reading 3 ──────────────────────────────────────────────
      {
        type: "reading",
        id: "cloud-r3",
        heading: "Building a Cloud Security Investigation — AWS Focus",
        content:
          "**Analogy:** Investigating a cloud security incident is like investigating a bank robbery where the thief never set foot in the bank — everything happened over the phone and the internet. You have logs of every call, but no physical evidence. The investigation is entirely about correlating API calls, timestamps, and IP addresses.\n\nHere is how to investigate a suspected AWS IAM compromise:\n\n**Step 1 — Identify the compromised identity.**\nYour alert fires on a `CreateUser` + `AttachUserPolicy` sequence. Pull the `userIdentity.arn` from both events. Is it a human IAM user, a role, or — most dangerous — the root account? Check `sourceIPAddress` against your known IP ranges and threat intel.\n\n**Step 2 — Establish the attacker's access window.**\nWhen did the first API call from the suspicious IP appear in CloudTrail? Run a query for all events from that ARN or IP in the last 30 days. Did anything appear before the attack event that explains how they got in? (A `GetSecretValue` on a secret containing access keys? An EC2 console login from the same IP days earlier?)\n\n**Step 3 — Enumerate what was created, changed, or accessed.**\nScan CloudTrail for all API calls from the attacker's session:\n- New IAM users, roles, or access keys created\n- Policies attached or inline policies modified\n- S3 `GetObject` or `PutBucketAcl` calls\n- EC2 instances launched (possible crypto mining)\n- Secrets Manager or SSM Parameter Store reads (credential harvesting)\n- `CloudTrail StopLogging` (attacker trying to hide their tracks — this fires one final CloudTrail event)\n\n**Step 4 — Check for lateral movement to other accounts.**\nIn AWS organisations with multiple accounts, an attacker in one account may assume roles in other accounts (`AssumeRole` across accounts). Check the `userIdentity.accountId` in events to see if actions occurred in accounts other than the initially compromised one.\n\n**Step 5 — Contain.**\n- Cut off the compromised identity: for an IAM user, deactivate its access keys (`aws iam update-access-key --status Inactive`) and remove or reset its console password (`aws iam delete-login-profile` — note this only removes the console password and does not end sessions already issued); for a role such as `DevOps-Deploy-Role`, use \"Revoke active sessions\" in the IAM console, which attaches an inline deny policy on `aws:TokenIssueTime` so every session token issued before now stops working\n- Disable or delete any backdoor accounts/access keys the attacker created\n- Remove any overly permissive policies the attacker attached\n- Rotate any secrets the attacker may have read\n- If EC2 instances were launched, terminate them and isolate the instance profile role\n\n**Step 6 — Determine the root cause.**\nHow did the attacker get credentials in the first place? Common sources: GitHub commit containing access keys, SSRF vulnerability pulling IMDS credentials, phishing for console password + MFA bypass, supply chain compromise in a CI/CD pipeline.\n\n**Tor and VPN exit nodes** in `sourceIPAddress` are a major indicator. Legitimate developers connect from corporate IPs, home ISPs, or known VPN ranges. Calls from Tor exit nodes or anonymous datacenter IPs have almost no legitimate explanation in a production AWS environment. Your SIEM should enrich CloudTrail `sourceIPAddress` with threat intel automatically.",
      },
      // ── Question 1 ──────────────────────────────────────────────
      {
        type: "question",
        id: "cloud-q1",
        question:
          "An AWS CloudTrail query returns a `CreateUser` event for user `svc-cloudmonitor` followed 90 seconds later by an `AttachUserPolicy` event attaching policy `arn:aws:iam::aws:policy/AdministratorAccess` to that user. Both events originate from IP `185.220.101.45`, which your threat-intel enrichment tags as a Tor exit node. What is this MOST likely?",
        options: [
          "A DevOps engineer provisioning a monitoring service account, where attaching AdministratorAccess is a common CI shortcut",
          "An IAM backdoor — compromised credentials used to create a new user and give it persistent administrator access",
          "An AWS service-linked role being created automatically when a new monitoring feature is activated in the account",
          "A scheduled IAM access-review automation recreating service users and reattaching policies to correct permission drift",
        ],
        answer: 1,
        explanation:
          "`CreateUser` followed within minutes by `AttachUserPolicy` with `AdministratorAccess` is the reading's IAM backdoor sequence, and a Tor source IP is one of the aggravating signs it names. “A DevOps engineer provisioning a monitoring service account” does not fit a Tor source — engineers and CI work from corporate, home or known pipeline ranges. “An AWS service-linked role” is created by AWS as a role, not through `CreateUser`, and never from an external Tor IP. “A scheduled IAM access-review automation” would run from your own known infrastructure and would not hand a brand-new user full administrator rights.",
        xp: 20,
      },
      // ── Question 2 ──────────────────────────────────────────────
      {
        type: "question",
        id: "cloud-q2",
        question:
          "A web application on EC2 has a Server-Side Request Forgery (SSRF) flaw, and the instance still runs IMDSv1. Your team cannot patch the application this week. Which change most directly stops an attacker from using the SSRF to pull the instance role's temporary credentials?",
        options: [
          "Remove the instance's public IP so the metadata endpoint can no longer be reached from the internet",
          "Enable GuardDuty in the region so credential theft from the metadata service is caught as it happens",
          "Require IMDSv2 on the instance, so the metadata service only answers requests carrying a session token",
          "Tighten the security group to allow only inbound 443, closing the path the attacker uses to reach IMDS",
        ],
        answer: 2,
        explanation:
          "The reading names IMDSv2 (session token required) as the mitigation for metadata credential theft: a token must first be obtained with a separate request, which a simple SSRF that only makes the app fetch a URL usually cannot do. “Remove the instance's public IP” misses how SSRF works: the vulnerable app makes the request from inside the instance, and 169.254.169.254 is link-local, never reached from the internet. “Enable GuardDuty” detects abuse but blocks nothing. “Tighten the security group” is also wrong — security groups filter traffic to the instance, not the instance's own calls to its link-local metadata endpoint.",
        xp: 20,
      },
      // ── Question 3 ──────────────────────────────────────────────
      {
        type: "question",
        id: "cloud-q3",
        question:
          "In AWS CloudTrail, what does `userIdentity.type = \"Root\"` in a CloudTrail event indicate, and why should SOC analysts treat this as high-priority?",
        options: [
          "The action was made by an IAM user holding AdministratorAccess, which CloudTrail labels Root because that policy grants every permission",
          "The action was performed by the account root user, which sits outside IAM policy limits and should almost never be used day to day",
          "The call came from a Lambda function whose execution role has full-account permissions, which CloudTrail records as a Root identity",
          "The action was made by a federated SSO user mapped to the top administrator permission set, recorded as the root of that session",
        ],
        answer: 1,
        explanation:
          "The AWS root account is the email/password account used to originally create the AWS account. It cannot be restricted by IAM policies (Service Control Policies restrict it only in member accounts of an AWS Organization — never in the management account), and it has access to billing and account closure. AWS's own best practices say root should be used only for a handful of specific tasks (e.g., closing the account, restoring a locked-out admin) and should have MFA enabled with the access keys deleted. Any `Root` event in CloudTrail — especially API calls rather than console logins — is a Tier 1 alert. Attackers who obtain root access own that account — and if it is the Organization's management account, effectively the whole organization. The distractors describe other identities that CloudTrail labels differently: an IAM user holding AdministratorAccess is still type `IAMUser`; a Lambda execution role and a federated SSO session are both `AssumedRole`. Broad permissions never turn an identity into `Root`.",
        xp: 20,
      },
      // ── Log Analysis ───────────────────────────────────────────
      {
        type: "log_analysis",
        id: "cloud-la1",
        heading: "AWS CloudTrail — IAM Backdoor User Creation",
        context:
          "AWS GuardDuty generated finding: `PrivilegeEscalation:IAMUser/AdministrativePermissions`. CloudTrail has the underlying events. The event below is the `CreateUser` call. A second event (not shown) captured `AttachUserPolicy` with PolicyArn `arn:aws:iam::aws:policy/AdministratorAccess` targeting the same username, 47 seconds later from the same source IP. Your organisation operates only from EU-WEST-1 and AP-SOUTHEAST-1 regions. Your CI pipeline calls AWS from a documented set of runner IP ranges. SIEM threat-intel enrichment tags the source IP 185.220.101.45 as a known Tor exit node. No change ticket exists for this activity.",
        event: {
          id: "evt-cloud-iam-001",
          ts: "2026-06-24T04:51:22.391Z",
          source: "cloudtrail",
          event_type: "cloud_api_call",
          hostname: undefined,
          severity: "critical",
          vendor: "AWS CloudTrail",
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
              "The caller is an `AssumedRole` session of `DevOps-Deploy-Role` named `ci-session-prod`, and the call came from `185.220.101.45`. Which interpretation of the caller and source fields is correct?",
            options: [
              "An AssumedRole session can't call CreateUser — only an IAMUser can create users, so this must be a logging error",
              "The CI role's session credentials are being used from a Tor exit node, not the pipeline's runners — they were stolen",
              "The session name ci-session-prod marks a production pipeline run, so the CreateUser is expected automation",
              "The aws-cli userAgent proves a human typed the command, so this is an insider using their own access",
            ],
            answer: 1,
            explanation:
              "Pipelines legitimately use `AssumedRole`; the anomaly is where the session is used from. The context says the CI calls AWS from documented runner ranges, and this call came from a Tor exit node, so the role's temporary credentials were stolen and replayed. “An AssumedRole session can't call CreateUser” is false — any identity whose policy allows `iam:CreateUser` can call it. “The session name ci-session-prod marks a production pipeline run” trusts a label the caller chooses when assuming the role. “The aws-cli userAgent proves a human typed the command” over-reads the field: the user agent is set by the client, and an attacker or a script can use the CLI just as easily.",
            xp: 25,
          },
          {
            question:
              "The `awsRegion` field shows `us-east-1`, but your organisation only operates in `eu-west-1` and `ap-southeast-1`. What is the significance of this detail?",
            options: [
              "IAM is a global service whose events always log as us-east-1, so this field is expected and proves nothing",
              "The attacker picked a region outside your footprint, hoping region-scoped monitoring would not see it",
              "The call was made in us-east-1, so the backdoor user exists only there and can't be used in your regions",
              "awsRegion records where the caller is, so us-east-1 places the attacker's exit node in North Virginia",
            ],
            answer: 0,
            explanation:
              "IAM is a global service, and CloudTrail records every IAM API call — like calls to the STS global endpoint and to Organizations — with `awsRegion: us-east-1`, no matter where the caller is or which regions your organisation uses. So `us-east-1` on this CreateUser is expected and is not evidence of anything. “The attacker picked a region outside your footprint” would only make sense for a regional service; nobody chooses a region for an IAM call. “The backdoor user exists only there” is wrong for the same reason: IAM users are global and work in every region. “awsRegion records where the caller is” confuses fields — the caller's address is `sourceIPAddress`. The practical lesson is a coverage one: if your SIEM only ingests trails for eu-west-1 and ap-southeast-1, you would miss every IAM event, so make sure your trail is multi-region (or at least includes global service events). The genuine red flags in this event are elsewhere: the Tor source IP, a new user that receives AdministratorAccess 47 seconds later, and no change ticket. Region only becomes a signal for regional services — for example EC2 RunInstances in a region you never use.",
            xp: 20,
          },
          {
            question:
              "Following Step 2 of the investigation reading, you want every other API call made by this same hijacked session, without pulling in the pipeline's legitimate runs of the role. Which value should you search CloudTrail for?",
            options: [
              "responseElements.user.arn — the ARN AWS returned for the newly created user",
              "responseElements.user.userId — the unique AIDA… ID assigned to that user",
              "userIdentity.arn — the assumed-role ARN that ends in the session name",
              "sessionIssuer.userName — the name of the role that issued the session",
            ],
            answer: 2,
            explanation:
              "Step 2 says to query all events from the attacker's ARN or IP. The caller's `userIdentity.arn` is the assumed-role session ARN, which includes the session name, so it isolates this session. The `responseElements` values — the user ARN and the `AIDA…` userId — identify the NEW backdoor user: they find what that user does later, not what this session did. `sessionIssuer.userName` (DevOps-Deploy-Role) matches every session of the role, so it would mix the attacker's calls with the pipeline's legitimate ones.",
            xp: 15,
          },
        ],
      },
      // ── Analyst Choice — Cloud IAM ───────────────────────────────
      {
        type: "analyst_choice" as const,
        id: "cloud-ac1",
        heading: "Verdict: Routine Cloud Admin or IAM Privilege Escalation?",
        scenario: "AWS GuardDuty fired: IAM user 'ci-session-dev' called GetCallerIdentity, then ListRoles, then passed a role to an EC2 instance that previously had no IAM role. All API calls originated from IP 34.215.110.32 (an AWS-owned public EC2 address in us-west-2). The user was created 2 weeks ago. No CloudTrail alerts fired previously on this account. What is your verdict?",
        event: {
          id: "evt-cloud-ac-001",
          ts: "2026-06-23T11:47:33.000Z",
          source: "cloudtrail" as const,
          vendor: "AWS CloudTrail",
          event_type: "cloud_api_call" as const,
          severity: "high" as const,
          hostname: "i-0c3d4e5f6a7b8c9d0",
          user_email: "ci-session-dev",
          description: "IAM user performed identity verification then role enumeration then attached an instance profile (role) to an existing EC2 instance — possible privilege escalation",
          mitre_technique: "T1548.005",
          mitre_tactic: "Privilege Escalation",
          raw: {
            "aws.cloudtrail.eventName": "AssociateIamInstanceProfile",
            "aws.cloudtrail.eventSource": "ec2.amazonaws.com",
            "aws.cloudtrail.awsRegion": "us-west-2",
            "aws.cloudtrail.userIdentity.type": "IAMUser",
            "aws.cloudtrail.userIdentity.userName": "ci-session-dev",
            "aws.cloudtrail.userIdentity.arn": "arn:aws:iam::123456789012:user/ci-session-dev",
            "aws.cloudtrail.sourceIPAddress": "34.215.110.32",
            "aws.cloudtrail.requestParameters.AssociateIamInstanceProfileRequest.IamInstanceProfile.Name": "ec2-prod-s3-full-access",
            "aws.cloudtrail.requestParameters.AssociateIamInstanceProfileRequest.InstanceId": "i-0c3d4e5f6a7b8c9d0",
            "aws.cloudtrail.errorCode": "",
            "aws.cloudtrail.errorMessage": "",
            "sequence.prior_api_calls": "GetCallerIdentity -> ListRoles -> AssociateIamInstanceProfile",
            "iam.user.created_date": "2026-06-09",
            "iam.role.permissions": "s3:*, ec2:Describe*",
            "guardduty.finding_type": "PrivilegeEscalation:IAMUser/AnomalousBehavior",
            "guardduty.severity": 7.8,
            "rule.name": "CloudTrail_EC2_AssociateInstanceProfile_New_User",
            "rule.level": 13,
          },
        },
        correct_verdict: "true_positive",
        explanation: "This is a true positive privilege escalation. The three-step sequence is the textbook IAM privilege escalation pattern: (1) GetCallerIdentity — confirming own identity, standard first step for attacker to understand their position; (2) ListRoles — enumerating what roles exist and their permissions, which is reconnaissance; (3) AssociateIamInstanceProfile — attaching a higher-privileged role (through its instance profile) to an EC2 instance the attacker controls. Note that CloudTrail never logs 'PassRole' as an event of its own: iam:PassRole is a permission AWS checks silently inside calls such as AssociateIamInstanceProfile and RunInstances, so this record IS the evidence of the role being passed. The fact that ci-session-dev had never attached an instance profile before and the role 'ec2-prod-s3-full-access' grants S3 full access confirms this: a low-privilege identity that held just iam:PassRole and ec2:AssociateIamInstanceProfile (plus the read permissions it used for recon) escalated to full S3 access by handing a more powerful role to an instance it can run code on. The AWS-owned source IP is not a false-positive indicator — attackers operating from inside AWS frequently egress through NAT gateways.",
        fp_trap: "The source IP is AWS-owned (34.215.x.x), so it looks like infrastructure rather than an attacker IP. Many analysts see an AWS address and assume the activity is from a legitimate internal process. But 34.215.x.x is public EC2 address space that any AWS customer can use, and even when it is your own NAT gateway it only tells you the call left from a workload inside your VPC — it says nothing about whether the action was authorized.",
        xp: 30,
      },

      // ── Flag ───────────────────────────────────────────────────
      {
        type: "flag",
        id: "cloud-flag1",
        prompt:
          "Containment Step 5 says to disable or delete any backdoor identity the attacker created. In the CloudTrail CreateUser event, find the name of the IAM user that will need to be removed — the one that received AdministratorAccess 47 seconds later — and enter it exactly.",
        answer: "svc-cloudmonitor-prod",
        hint: "The event holds two identities: the one making the call and the one being created. Only one of them is a brand-new IAM user, and the arguments sent to the API sit in a different field group from the caller.",
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
    xp: 225,
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
        checkpoint: {
          question: "According to the reading, why can't a SOC just rely on a SIEM vendor's default detection rules?",
          options: [
            "They are tuned too sensitively, so raising every threshold fixes the noise without writing new rules",
            "They are built for an average environment, not your own tools, assets, naming and user behaviour",
            "They match only known malware signatures, so behaviour-based techniques are never covered by them",
            "They are locked by the vendor, so exclusions such as the IT team's own PsExec use can't be added",
          ],
          answer: 1,
          explanation:
            "The reading's reason is fit: defaults target the average environment, so they fire on your legitimate tools (IT's PsExec), miss your critical assets, and misread your users' habits. “Raising every threshold” would cut noise but also blind the rules, and does nothing for assets that need custom monitoring. “Match only known malware signatures” is not what the reading says — signature logic is one of four detection types, and vendor packs are not limited to it. “Locked by the vendor” is wrong: the tuning stage in Reading 3 adds exactly these exclusions.",
        },
      },
      // ── Reading 2 ──────────────────────────────────────────────
      {
        type: "reading",
        id: "deteng-r2",
        heading: "Sigma Rules, Detection Logic Types, and the MITRE ATT&CK Framework",
        content:
          "**Analogy:** Imagine you're a chef who wants to share a recipe. You could write it for your specific kitchen — your oven, your brand of butter, your measuring cups. Or you could write it in a standardised recipe format that any chef in any kitchen can follow. **Sigma** is that standardised recipe format for detection rules — a vendor-neutral specification that can be compiled for Splunk, Elastic, Microsoft Sentinel, QRadar, and many other SIEMs.\n\n**Sigma Rules** are written in YAML and describe detection logic without using any vendor-specific query language. A simple Sigma rule looks like:\n\n```yaml\ntitle: Password Spray via NTLM\nstatus: experimental\ndescription: Detects multiple failed logons across many accounts from single source\nlogsource:\n  product: windows\n  service: security\ndetection:\n  selection:\n    EventID: 4625\n    SubStatus: '0xC000006A'\n  condition: selection | count(TargetUserName) by IpAddress > 10\nfields:\n  - TargetUserName\n  - IpAddress\nfalsepositives:\n  - Misconfigured applications retrying authentication\nlevel: high\ntags:\n  - attack.credential_access\n  - attack.t1110.003\n```\n\nThis single Sigma rule can be converted to a Splunk SPL query, an Elastic KQL rule, a Sentinel KQL query, or a QRadar AQL rule using the `sigmac` compiler tool or `sigma-cli`. This portability is enormously valuable — security researchers publish Sigma rules that the community can share and adapt.\n\n**Detection Logic Types:**\n\n**1. Signature-based** — exact match on a known bad pattern (a specific hash, a specific command line string). Very precise but only catches *known* variants. Example: process name `mimikatz.exe` or command line containing `sekurlsa::logonpasswords`.\n\n**2. Threshold-based** — count-based logic that fires when a quantity exceeds a limit. Example: more than 20 failed logons from one IP in 5 minutes. Works for volume-based attacks (sprays, brute force, DDoS). Requires careful threshold tuning per environment.\n\n**3. Anomaly/Behavioral** — fires when current behaviour deviates from a learned baseline. Example: this user account normally authenticates from UK IPs, but today authenticated from Brazil. Requires a training period to establish baselines (UEBA systems do this). High detection power for subtle attacks but more complex to tune.\n\n**4. Correlation** — combines multiple events from different sources into a composite detection. Example: failed logons (Windows) + successful VPN logon from same IP (VPN logs) + file access on file server (Windows) within 30 minutes = lateral movement post-spray. The most powerful type but also the most complex to build.\n\n**MITRE ATT&CK Framework** is a publicly available knowledge base of adversary tactics, techniques, and sub-techniques observed in real attacks. It is organised as a matrix:\n- **Tactics** (columns) — the *goal* of the adversary at a given stage: Reconnaissance, Resource Development, Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact (14 tactics in the Enterprise matrix)\n- **Techniques** (rows within each tactic) — the *specific method* used: T1110 (Brute Force), T1059 (Command and Scripting Interpreter), T1078 (Valid Accounts)\n- **Sub-techniques** — more specific variants: T1110.003 is Password Spraying specifically under the Brute Force technique\n\nEvery detection rule should map to one or more ATT&CK techniques. Why? Because you can then create an **ATT&CK Coverage Heatmap** — a visual representation of which techniques you can detect and which techniques have no detection rule. A technique with no coverage is a gap an attacker can exploit without triggering any alert. Detection engineers use this heatmap to prioritise writing new rules for uncovered techniques, especially those used by threat actors relevant to their industry.",
        checkpoint: {
          question: "According to the reading, what is the main advantage of writing a detection rule in Sigma format instead of directly in a specific SIEM's query language?",
          options: [
            "Sigma rules run faster than native queries, because the SIEM executes the YAML instead of parsing its own language",
            "Sigma is vendor-neutral: one rule compiles to Splunk, Elastic, Sentinel, QRadar and more, so it can be shared",
            "SigmaHQ pre-validates its rules, so a downloaded rule can skip historical testing and go straight to production",
            "Sigma infers each rule's ATT&CK technique from its detection logic, so the tags section is filled in for you",
          ],
          answer: 1,
          explanation:
            "Sigma is a vendor-neutral YAML specification; one rule converts to SPL, KQL, AQL and other languages, which is what makes community sharing work. “Run faster” is wrong — the SIEM never runs YAML; it runs the converted native query. “SigmaHQ pre-validates its rules” skips the reading's lifecycle: every rule, wherever it came from, still needs testing and tuning against your own data. “Infers each rule's ATT&CK technique” is wrong too: the `tags` in the example are written by the author.",
        },
      },
      // ── Reading 3 ──────────────────────────────────────────────
      {
        type: "reading",
        id: "deteng-r3",
        heading: "The Rule Lifecycle — From Writing to Retirement",
        content:
          "**Analogy:** A speed camera on a road doesn't just get installed and left alone forever. The speed limit might change, the camera might drift out of calibration, new road layouts might mean it catches innocent drivers turning into a petrol station. Someone has to maintain it — verify it's still catching the right cars, adjust the settings, and eventually replace it when the road is redesigned. Detection rules are exactly the same — they need an ongoing maintenance lifecycle, not a one-time 'set and forget.'\n\n**The Detection Rule Lifecycle:**\n\n**Stage 1 — Identify the Threat.**\nWhat attack technique do you want to detect? Sources:\n- Threat intelligence reports about attackers targeting your industry\n- MITRE ATT&CK techniques used by relevant threat groups (e.g., if you're a financial institution, look at what FIN7 or Lazarus Group use)\n- Incidents your organisation has already experienced\n- ATT&CK coverage gaps identified from your heatmap\n- Sigma community rules released for newly published CVEs\n\n**Stage 2 — Write the Rule.**\nTranslate the threat technique into detection logic. This requires understanding:\n- What log source captures this activity (which product, which log type)\n- What fields are populated when this technique is used\n- What values distinguish malicious from benign (a filter condition)\n- What volume or sequence indicates an attack (threshold or correlation)\n\nWrite it first in Sigma (vendor-neutral) then compile for your SIEM.\n\n**Stage 3 — Test Against Historical Data.**\nBefore deploying, test the rule against historical logs:\n- Does it detect the attack simulations or known historical incidents?\n- How many events does it fire in a typical week? (Estimate false positive rate)\n- Are there obvious false positive sources you can immediately exclude?\n\nMany teams have a **Detection Lab** — a test environment where they run red-team attack simulations to validate that new rules fire correctly.\n\n**Stage 4 — Deploy in 'Alert-Only' Mode.**\nDeploy the rule to production but with low severity and no automated action. Monitor for 2-4 weeks. Collect every alert and classify each one: true positive (TP) or false positive (FP). Calculate your precision: TP/(TP+FP).\n\n**Stage 5 — Tune.**\nBased on observed false positives, add exclusions:\n- Exclude known admin IPs (`NOT src.ip IN [10.1.2.3, 10.1.2.4]`)\n- Exclude known tools (`NOT process.name = \"backup-agent.exe\"`)\n- Add context filters (`AND user.department != \"IT Operations\"`)\n- Adjust thresholds based on observed volumes\n\nBe careful not to over-tune. Every exclusion is a potential blind spot — an attacker who knows your exclusions can operate within them. Document every exclusion with a business justification.\n\n**Stage 6 — Promote to Production Severity.**\nOnce precision meets your threshold (typically >98% for high/critical severity), elevate the rule's severity and potentially enable automated response (SOAR playbook trigger, automatic IP block, account disable).\n\n**Stage 7 — Ongoing Review and Retirement.**\nReview rules at least quarterly:\n- Has the attack technique changed? (Attackers evolve to evade known detections — LOLBins replace custom malware, living-off-the-land techniques replace noisy tools)\n- Has the environment changed? (A new tool deployed that triggers the rule? A network segment change that breaks the rule's assumptions?)\n- Is the rule still firing? A rule that hasn't fired in 6 months either means no attacks (good) or the rule is broken (bad — test it).\n- Retire rules that detect threats no longer relevant to your environment.\n\n**Alert Fatigue Management:** Set explicit SLAs for different severity levels:\n- Critical: analyst response within 15 minutes\n- High: within 2 hours\n- Medium: within 8 hours\n- Low: reviewed in daily triage\n\nIf your team cannot meet these SLAs, you have either a staffing problem or a false-positive problem. Tune the rules — not the SLAs.",
      },
      // ── Reading 4 ──────────────────────────────────────────────
      {
        type: "reading",
        id: "deteng-r4",
        heading: "Writing a Complete Sigma Rule, Field by Field",
        content:
          "**Analogy:** Reading 2 introduced Sigma as a standardised recipe format. But knowing that recipes exist isn't the same as being able to write one from a blank page. This reading walks through writing a real, complete Sigma rule field by field — the way a detection engineer actually builds one, not just reads one.\n\n**Why Sigma exists in the first place:** without it, a detection engineer who wants to catch the same technique in Splunk, Microsoft Sentinel, and Elastic has to write and maintain three separate queries in three separate syntaxes — and keep all three in sync every time the detection logic changes. Sigma solves this by separating the *detection logic* (written once, in plain YAML) from the *query language* it eventually becomes. A converter tool — historically `sigmac`, now the Python library `pySigma` and its `sigma-cli` front-end — takes a Sigma YAML file and a target backend, and emits the equivalent KQL, SPL, or Elasticsearch/ES-QL query. Write once, deploy everywhere.\n\n**The scenario:** attackers and red teamers frequently launch PowerShell with an encoded (Base64) command, or with its window hidden, so a user glancing at their screen doesn't notice a console flash. This is common in malicious macros, LOLBin-based execution, and post-exploitation frameworks. Sysmon Event ID 1 (Process Creation) captures the full command line of every process launch, which makes it the right log source. Here is a complete, working Sigma rule for it:\n\n```yaml\ntitle: Suspicious Encoded PowerShell Execution\nid: 3fa76c9e-9b45-4e2d-8f1a-6c2b7e4d1a90\nstatus: experimental\ndescription: Detects PowerShell launched with an encoded command or a hidden window, a common LOLBin/macro-delivery pattern.\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    Image|endswith: '\\\\powershell.exe'\n    CommandLine|contains:\n      - '-enc'\n      - '-EncodedCommand'\n      - '-w hidden'\n      - '-windowstyle hidden'\n  condition: selection\nfalsepositives:\n  - Legitimate administrative scripts that pass encoded commands\nlevel: high\ntags:\n  - attack.execution\n  - attack.t1059.001\n```\n\n**Field by field:**\n\n`title` is a short human-readable name — the first thing an analyst sees on an alert, so it should describe the behaviour, not just the tool ('Suspicious Encoded PowerShell Execution', not 'PowerShell Rule #4').\n\n`id` is a globally unique identifier (UUID) for the rule itself. This matters once a rule is shared: SigmaHQ and downstream SIEMs use this ID to track a rule across updates, forks, and version history, independent of whether someone later renames the title.\n\n`status` tracks the rule's maturity in its own lifecycle — `experimental` means newly written and not yet fully tuned, `test` means under active validation, `stable` means production-ready with a known false-positive profile. This is the Sigma-native version of the 'alert-only then promote' lifecycle covered in Reading 3.\n\n`description` documents in plain English exactly what behaviour the rule is looking for and why it matters — essential for any analyst triaging an alert months after the rule's author has moved to another team.\n\n`logsource` tells the converter and the analyst which log collection this rule targets. `category: process_creation` plus `product: windows` maps, on most SIEM backends, to Sysmon Event ID 1 or the equivalent Windows process-creation telemetry — not firewall logs, not authentication logs. Getting `logsource` wrong means the compiled query searches the wrong index entirely, and the rule silently never fires.\n\n`detection` is where the actual matching logic lives. `selection` is a named group of field-value conditions — here, `Image|endswith` matches any process image path ending in `powershell.exe` (catching it regardless of install directory), and `CommandLine|contains` is a **list**, which Sigma evaluates as OR: the condition is satisfied if the command line contains `-enc` **or** `-EncodedCommand` **or** `-w hidden` **or** `-windowstyle hidden`. A rule can define multiple named groups (`selection`, `filter`, `exclusion`) to build more complex logic.\n\n`condition` is the boolean expression that combines those named groups. Here it's simply `selection` — fire whenever selection matches. A tuned version, after Stage 5 of the rule lifecycle, might read `selection and not filter`, where `filter` defines a known-benign exclusion (for example, a specific signed backup agent that legitimately passes `-EncodedCommand`).\n\n`falsepositives` is the same documented-exclusions concept from Reading 3's tuning stage, built into the rule format itself — a plain-English list of legitimate activity known to trigger this rule, so an analyst investigating an alert knows what to rule out first before treating it as malicious.\n\n`level` sets the severity — here `high`, reflecting that hidden-window and encoded execution are rarely legitimate and warrant fast analyst attention.\n\n`tags` maps the rule to MITRE ATT&CK, exactly as covered in Reading 2 — `attack.t1059.001` is the sub-technique for PowerShell specifically, under the parent technique T1059 (Command and Scripting Interpreter). This is what feeds the ATT&CK coverage heatmap: without this tag, a rule that perfectly detects T1059.001 in practice would still show up as a coverage gap on the heatmap, because the heatmap only knows what the tags tell it.\n\nMost detection engineers don't write every rule from scratch. **SigmaHQ** (github.com/SigmaHQ/sigma) is the community repository of several thousand public Sigma rules, contributed and maintained by researchers and detection engineers worldwide, covering everything from commodity malware to nation-state techniques. The common workflow is to pull a relevant rule from SigmaHQ, compile it for your SIEM with `sigma-cli`, and then tune the `detection` and `falsepositives` sections for your own environment — the same Stage 5 tuning process from Reading 3 — rather than writing every rule from a blank page.",
        checkpoint: {
          question:
            "In the Sigma rule above, `CommandLine|contains` is followed by a list of four strings: '-enc', '-EncodedCommand', '-w hidden', '-windowstyle hidden'. How does Sigma evaluate a list of values under one field?",
          options: [
            "As AND logic — the command line must contain all four strings simultaneously for the selection to match",
            "As OR logic — the selection matches if the command line contains any one of the listed strings",
            "As a regular expression, where the four strings must appear in that exact left-to-right order in the command line",
            "As a weighted score, where each matching string adds points until a threshold defined elsewhere in the rule is reached",
          ],
          answer: 1,
          explanation:
            "A list of values under a single field in a Sigma selection is evaluated as OR logic — the condition is satisfied if any one of the listed values matches. That's exactly why this rule catches both the short form (-enc) and the long form (-EncodedCommand) of the same PowerShell flag, plus both hidden-window variants, with a single selection block rather than four separate rules.",
        },
      },
      // ── Question 1 ──────────────────────────────────────────────
      {
        type: "question",
        id: "deteng-q1",
        question:
          "Your SIEM has a rule with 95% precision (95% of its alerts are true positives, 5% are false positives). It fires about 200 times per day. How many false positives does the team investigate daily, and what does that imply?",
        options: [
          "5 per day — the 5% rate is the daily count, so the rule is already precise enough for high severity",
          "10 per day — a small number, so 95% precision is good enough to run the rule at critical severity",
          "10 per day — small for one rule, but it adds up across many rules; high-severity rules need higher precision",
          "190 per day — 95% is the false share, so only 10 of the 200 daily alerts are true positives",
        ],
        answer: 2,
        explanation:
          "Precision is TP/(TP+FP) over alerts: 200 × 5% = 10 false positives a day. One rule's 10 looks harmless, but 50 such rules mean 500 dead-end investigations a day, which is why the reading sets a much higher bar before a rule is promoted to high/critical severity. “5 per day” applies the percentage as a count. “10 per day ... good enough to run at critical severity” gets the arithmetic right but ignores the cumulative alert-fatigue effect. “190 per day” inverts the definition given in the stem.",
        xp: 20,
      },
      // ── Question 2 ──────────────────────────────────────────────
      {
        type: "question",
        id: "deteng-q2",
        question:
          "A colleague copies the encoded-PowerShell Sigma rule from Reading 4 but changes its logsource to `category: firewall`. It converts and deploys without errors. A red-team test then runs `powershell.exe -enc ...` on a workstation that sends Sysmon process-creation logs to the SIEM. What happens?",
        options: [
          "The SIEM refuses the rule at deploy time, because firewall logs have no CommandLine field to match",
          "No alert: the converted query searches firewall data, which never holds process command lines",
          "An alert fires as usual, since the CommandLine condition matches whichever log carries that string",
          "An alert fires on the firewall's record of the connection, which carries the PowerShell command line",
        ],
        answer: 1,
        explanation:
          "Reading 4: getting `logsource` wrong means the compiled query searches the wrong index entirely, and the rule silently never fires. That is why the test is what catches it. “The SIEM refuses the rule” is the dangerous assumption — the stem says it deployed cleanly, and a query over missing fields simply returns nothing. “An alert fires as usual” ignores that logsource decides where the query looks, so the Sysmon events are never searched. “The firewall's record of the connection” is wrong because network logs hold addresses, ports and actions, not process command lines.",
        xp: 20,
      },
      // ── Question 3 ──────────────────────────────────────────────
      {
        type: "question",
        id: "deteng-q3",
        question:
          "A detection engineer creates an ATT&CK coverage heatmap for their environment and discovers that techniques T1566 (Phishing), T1078 (Valid Accounts), and T1190 (Exploit Public-Facing Application) have zero detection rules assigned to them. What does this mean practically?",
        options: [
          "They are mostly stopped upstream (mail gateway, MFA, WAF), so the zero count reflects prevention, not a gap",
          "They are blind spots: an attacker using one of them triggers no rule, so the intrusion may surface only at a later step",
          "The SIEM vendor ships default rules for them, so empty cells are expected and custom rules would only duplicate alerts",
          "They can only be seen in EDR telemetry, so the zero count reflects the SIEM's scope rather than a coverage gap",
        ],
        answer: 1,
        explanation:
          "A technique with no coverage is, in the reading's words, a gap an attacker can exploit without triggering any alert — and these three are among the most common initial-access routes. “Mostly stopped upstream” confuses prevention with detection: gateways, MFA and WAFs get bypassed, and the heatmap measures whether you would SEE it. “The SIEM vendor ships default rules” — if they existed and were mapped, the cells would not be empty. “They can only be seen in EDR telemetry” is false: phishing is visible in mail logs, valid-account abuse in authentication logs and web exploitation in WAF/web logs, all of which a SIEM ingests.",
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
              "T1110 is the tactic (Credential Access); .003 is the technique under it (Password Spraying)",
              "T1110 is the parent technique (Brute Force); .003 is a sub-technique of it (Password Spraying)",
              "T1110 is the technique (Brute Force); .003 is the severity tier ATT&CK gives this variant",
              "T1110 is the technique (Brute Force); .003 is the data source that detects it (logon events)",
            ],
            answer: 1,
            explanation:
              "Reading 2: techniques carry T-numbers, and sub-techniques add a suffix — T1110.003 is Password Spraying under the Brute Force technique. “T1110 is the tactic” confuses levels: tactics are the matrix columns (the goal, here Credential Access) and are not T-numbered. “The severity tier” and “the data source” both invent a meaning for the suffix; ATT&CK assigns no severity to techniques, and data sources are documented separately from the ID. Siblings such as T1110.001 (Password Guessing) and T1110.004 (Credential Stuffing) show the suffix just enumerates variants.",
            xp: 20,
          },
          {
            question:
              "Work out how the failures are spread across the targeted accounts using the auth.* and target.user.* fields. What does that spread tell you about the attacker's method?",
            options: [
              "About two guesses per account — a brute-force run that most lockout policies would have stopped",
              "About two guesses per account — kept under typical lockout thresholds so many accounts can be tried",
              "About two failures per account — ordinary background noise from users mistyping their passwords",
              "Two accounts hit about 47 times each — a focused brute force against a couple of chosen users",
            ],
            answer: 1,
            explanation:
              "94 failures across 47 distinct accounts is about 2 per account, under common lockout thresholds (often 3–10), so no lockouts fire while many accounts are tested — the defining shape of a password spray. “A brute-force run that most lockout policies would have stopped” has the arithmetic but the wrong conclusion: two tries stays below those policies. “Ordinary background noise” can't explain 47 different accounts failing from one source IP inside 8 minutes. “Two accounts hit about 47 times each” misreads `target.user.distinct_count` (47 accounts) as an attempt count.",
            xp: 20,
          },
          {
            question:
              "Given the alert details above — 3 accounts with confirmed successful logons after the spray, all within an 8-minute window — what is the MOST time-critical action and why?",
            options: [
              "Block 91.108.56.177 at the perimeter, since cutting that source ends the attacker's access in one step",
              "Escalate to Tier 2 and hold off on changing the three accounts until a senior analyst signs off",
              "Disable or reset the three accounts in the success list and end their sessions, wherever they log in from",
              "Image the domain controllers first, so evidence of the three successful logons is preserved intact",
            ],
            answer: 2,
            explanation:
              "Once a spray has succeeded, the three compromised accounts are the live threat: the attacker can use them from any IP, right now. Disabling or resetting them and ending their sessions removes that access. “Block 91.108.56.177” is worth doing, but the attacker holds valid credentials and can simply switch IPs. “Escalate to Tier 2 and hold off” — escalation should run in parallel with containment, not delay it. “Image the domain controllers first” puts evidence ahead of stopping an active intrusion; logon records already sit in the SIEM, and imaging takes hours.",
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
          "Before writing the containment note, you confirm that the attacker was trying real usernames with wrong passwords, rather than guessing at accounts that don't exist. Find the status code in the Spray-then-Success alert that proves this, and enter it exactly.",
        answer: "0xC000006A",
        hint: "The reading's password-spray filter condition pairs Event 4625 with one specific sub-status value. The correlated alert carries the same value for its failures.",
        xp: 40,
      },
      // ── Query Fill: compile the Sigma rule to SPL ────────────────
      {
        type: "query_fill",
        id: "deteng-queryfill1",
        heading: "Write It Yourself: Compile the Password Spray Sigma Rule to SPL",
        language: "spl",
        context:
          "Reading 2's password-spray Sigma rule fires when one source address fails logons against more than 10 DIFFERENT accounts. Hand-compile that aggregation into Splunk SPL. In this index the failed-logon events (4625) carry these extracted fields: TargetUserName (the account tried), src_ip (the machine the logon came from) and ComputerName (the domain controller that logged it). Fill in the stats function and the grouping field.",
        template:
          "index=security sourcetype=WinEventLog:Security EventCode=4625 Sub_Status=\"0xC000006A\"\n| stats {{func}}(TargetUserName) as accounts_targeted by {{groupby}}\n| where accounts_targeted > 10",
        blanks: [
          { id: "func", answers: ["dc", "distinct_count"], placeholder: "stats function" },
          { id: "groupby", answers: ["src_ip"], placeholder: "group-by field" },
        ],
        explanation:
          "`dc()` (long form `distinct_count()`) counts DIFFERENT TargetUserName values, which is what a spray threshold needs; `count()` would count every failure, so one user mistyping a password 11 times would trip it. Grouping `by src_ip` keeps one counter per attacking source, mirroring the Sigma rule's `by IpAddress`. Grouping by ComputerName would instead count accounts per domain controller, merging every source together. Sub_Status 0xC000006A means wrong password for a real account (as opposed to 0xC0000064, unknown username). This is a hand-compiled equivalent; current pySigma tooling handles aggregations through separate Sigma correlation rules.",
        xp: 30,
      },
    ],
  },
];

export default rooms;
