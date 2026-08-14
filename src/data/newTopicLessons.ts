// AUTO-GENERATED companion file of NEW standalone theory lessons.
// New focused lessons on specific high-value curriculum topics that previously
// existed only as sub-sections of broader lessons. Registered in builtinLessons.ts.


const NEW_TOPIC_LESSONS = [
{
  "id": "topic-lesson-kerberoasting",
  "slug": "kerberoasting-explained",
  "title": "Kerberoasting: Cracking Service Accounts Without Admin Rights",
  "topic": "Active Directory Attacks",
  "difficulty": "advanced",
  "kind": "lesson",
  "intro": "Kerberoasting is one of the most common — and most quietly dangerous — attacks in any Active Directory environment, because it lets an ordinary, non-privileged domain user walk away with the password of a powerful service account, and it does the hard part entirely offline where no lockout or alert can stop it. This lesson explains exactly how it works, why the design of Kerberos makes it possible, how you detect it in the logs, and how it is defended.",
  "sections": [
    {
      "heading": "What Kerberoasting Is and Why It Works",
      "content": "Kerberoasting (MITRE ATT&CK **T1558.003**) abuses a completely normal, by-design feature of **Kerberos**, the authentication protocol at the heart of Active Directory. To understand it you need one concept: the **SPN (Service Principal Name)**. When a service — a SQL database, a web app, a file share — runs under a domain **service account**, that account is registered with an SPN so that clients can request access to it through Kerberos.\n\nHere is the design that the attack exploits. When any user wants to use a service, they ask the Domain Controller (the **KDC**) for a **service ticket (TGS)** for that service's SPN. The KDC hands one over — and, crucially, **that ticket is encrypted with the service account's own password hash.** This is not a bug; it is how Kerberos proves to the service that the ticket is genuine. But it creates an opening: the requester now holds a blob of data that is encrypted with the service account's password, and they can take it away and try to crack it.\n\nThe two facts that make this dangerous together:\n\n- **Any authenticated domain user can request a TGS for any SPN.** You do not need to be an admin, and you do not need any special permission on the service — requesting the ticket is a normal operation the KDC will not refuse. So a single low-privilege account (or one the attacker has already phished) is enough to start.\n- **The ticket is crackable offline.** Because the ticket is encrypted with the service account's password hash, an attacker who captures it can try to guess that password on their **own hardware**, with no further contact with the Domain Controller.\n\nSo Kerberoasting turns a routine Kerberos request into a password-cracking opportunity, and the target — a service account — is often exactly the kind of account worth stealing: over-privileged, with a password that was set once years ago and never changed."
    },
    {
      "heading": "The Attack, Step by Step",
      "content": "The mechanics are short, which is part of why the attack is so popular. From a single ordinary domain account, the attacker:\n\n1. **Enumerates SPNs.** They query Active Directory (via LDAP) for all accounts that have an SPN registered — this lists every service account that can be Kerberoasted. This is a normal read that any user can perform.\n2. **Requests a service ticket (TGS) for the chosen SPN.** A single Kerberos request to the KDC returns the ticket, encrypted with the target service account's password hash. Tools automate this in seconds (Rubeus, Impacket's GetUserSPNs, PowerShell).\n3. **Extracts the encrypted ticket** from memory and saves it to a file.\n4. **Cracks it offline.** They feed the ticket to a password-cracking tool such as **hashcat** or John the Ripper on their own machine, trying enormous wordlists and rule-based guesses. If the service account's password is weak, it falls — and now the attacker knows the **real password** of that service account.\n\nThe result is not a hash to replay but the **actual cleartext password**, which the attacker can use to log in directly as the service account, wherever it has access. And because step 4 happens entirely offline, everything after step 3 is invisible to your defences.\n\nThe single most important thing to internalise is that steps 1 and 2 — the only parts that touch your network — look almost exactly like legitimate Kerberos activity, because they *are* legitimate Kerberos requests. The attack hides inside the normal operation of the protocol, which is why detecting it depends on subtle signals rather than an obviously malicious action."
    },
    {
      "heading": "Why It Is So Effective — and So Stealthy",
      "content": "Kerberoasting sits near the top of every attacker's Active Directory playbook because it combines low cost, high reward, and stealth:\n\n- **It needs no privilege to start.** Unlike attacks that require admin rights, Kerberoasting works from *any* domain account. A single phished user, an intern's laptop, a low-privilege foothold — all are enough. This is what makes it a favourite early move after initial access.\n- **The reward is often huge.** Service accounts are frequently **over-privileged** — granted far more access than the service truly needs, sometimes even Domain Admin — because that was the easy way to make the service work years ago. So cracking one weak service-account password can hand the attacker sweeping access, turning a foothold into near-total control.\n- **The cracking is offline and untouchable.** Once the ticket is captured, guessing the password happens on the attacker's hardware. Your account-lockout policy, your rate limits, your failed-logon alerts — none of them apply, because there are no logon attempts against your systems at all. The attacker can grind for days.\n- **The service password rarely changes.** Human passwords expire and rotate; service-account passwords are often set once and left for years because changing them risks breaking the service. That gives the attacker a large, stable target and all the time in the world.\n\nThere is one more technical wrinkle that helps the attacker: **the encryption type**. Kerberos can protect tickets with strong AES or with the older, weaker **RC4**. RC4-encrypted tickets are dramatically faster to crack, so attackers specifically request RC4 where they can — which, helpfully for defenders, is also one of the clearest signals that a Kerberoasting attack is under way."
    },
    {
      "heading": "Detecting Kerberoasting in the Logs",
      "content": "Because the network-facing part of Kerberoasting is a normal Kerberos request, detection is about spotting *anomalous patterns* in ticket requests rather than an obviously bad event. The workhorse is **Windows Event ID 4769 — 'A Kerberos service ticket was requested'** — logged on the Domain Controllers. Every service-ticket request generates one, so the raw volume is huge; the skill is filtering for the tells:\n\n- **Encryption type 0x17 (RC4).** The 4769 event records the ticket-encryption type. A request for a service ticket using **RC4 (type 0x17)** in an environment that should be using AES is a strong Kerberoasting indicator, because attackers deliberately downgrade to RC4 to crack faster. Alerting on 4769 with encryption type 0x17 is one of the highest-value AD detections you can build.\n- **Volume and fan-out from one account.** A single user account requesting service tickets for **many different SPNs in a short window** is highly abnormal — a real user touches a handful of services, not dozens in a burst. That fan-out is the signature of an attacker enumerating and roasting every service account at once.\n- **Requests for SPNs the account never normally uses**, or a spike of 4769s against sensitive service accounts, are worth surfacing.\n- **Honeypot (decoy) service accounts.** A powerful, deliberate detection: create a service account with an SPN, a tempting name, and a *strong* password, and grant it nothing. No legitimate process ever requests its ticket — so **any** 4769 for that honeypot's SPN is almost certainly an attacker enumerating SPNs, giving you a near-zero-false-positive alarm.\n\nThe analyst mindset here mirrors the rest of the curriculum: no single 4769 is malicious, so you hunt the *pattern* — RC4 downgrade, one account fanning out to many SPNs, or a hit on a honeypot — rather than any one event."
    },
    {
      "heading": "Defending Against Kerberoasting",
      "content": "Because the attack cracks a password offline, every defence comes down to one of two ideas: make the password **impossible to crack**, or **remove the reward** if it is. Both matter, and a mature environment does both.\n\n**Make the password uncrackable:**\n\n- **Use very long, random service-account passwords.** Offline cracking only wins against guessable passwords; a 25+ character random password is effectively uncrackable with today's hardware, which neutralises the attack even though the attacker still gets the ticket. This is the single most important control.\n- **Use Group Managed Service Accounts (gMSA).** A gMSA has a **long, complex password that Active Directory manages and rotates automatically** (every 30 days by default), with no human ever knowing or setting it. This is the modern best-practice answer to Kerberoasting: the password is both uncrackable and constantly changing.\n- **Enforce AES over RC4.** Configuring accounts and the domain to use AES encryption for Kerberos removes the fast-cracking RC4 path, making any captured ticket far harder to break.\n\n**Remove the reward:**\n\n- **Apply least privilege to service accounts.** A service account should have only the access its service genuinely needs — never Domain Admin 'to be safe.' Then, even if its password is cracked, the blast radius is small. Over-privileged service accounts are what turn a Kerberoast into a domain compromise.\n- **Audit and reduce SPNs.** Every account with an SPN is roastable; removing SPNs from accounts that no longer need them shrinks the attack surface.\n\nThe takeaway ties the lesson together: you cannot stop a domain user from requesting a service ticket — that is Kerberos working as designed — so you defeat Kerberoasting by making the ticket worthless to crack (long/managed passwords, AES) and worthless if cracked (least privilege), while watching Event 4769 for the RC4-and-fan-out pattern that reveals the attempt.",
      "image": {
        "src": "/lesson-images/ad/kerberoasting-flow.svg",
        "alt": "A diagram of a Kerberoasting attack. Any domain user — a normal, low-privilege or stolen account with no admin rights — sends step 1, a request to the KDC (Domain Controller) for a service ticket (TGS) for a service principal name such as svc-sql. In step 2 the KDC returns the TGS by design, encrypted with the service account's password hash using RC4. The service account, for example svc-sql, has an SPN registered and often a weak, never-changed password. Step 3: the attacker takes the encrypted ticket offline and cracks it with hashcat on their own hardware — no more traffic to the DC, nothing to lock out or alert — and if the password is weak it falls, giving the attacker that account's real password. Why it is dangerous: service accounts are often over-privileged and any user can request the ticket, so one normal account becomes a path to a powerful service account, and the cracking is offline so lockout and rate-limits do not apply (MITRE ATT&CK T1558.003). How to catch it: Event 4769 (service ticket requested) with encryption type 0x17 (RC4) plus one account requesting many SPN tickets in a burst; defend with long or random service-account passwords or gMSA, and AES.",
        "caption": "Kerberoasting: any domain user requests a service ticket encrypted with the service account's password, then cracks it offline. Catch it via Event 4769 with RC4 (0x17) + one account fanning out to many SPNs.",
        "credit": "Figure authored for this course. Technique per MITRE ATT&CK T1558.003."
      }
    }
  ],
  "keyTakeaways": [
    "Kerberoasting (T1558.003) abuses a Kerberos design feature: any authenticated domain user can request a service ticket (TGS) for any SPN, and that ticket is encrypted with the service account's password hash — so a low-privilege account (no admin needed) can capture it and crack the password OFFLINE, where lockouts and alerts never apply.",
    "It is effective because service accounts are often over-privileged with weak, never-changed passwords, and attackers downgrade to RC4 to crack faster; detect it via Event 4769 with encryption type 0x17 (RC4) + one account fanning out to many SPNs (or a honeypot SPN account), and defend by making the password uncrackable (long/random passwords, gMSA auto-rotation, AES) and worthless if cracked (least privilege on service accounts)."
  ],
  "quiz": [
    {
      "question": "An attacker has compromised a single ordinary domain user account with no special privileges. Using only that account, they are able to obtain and later crack the password of a powerful SQL service account. How is this possible without any elevated rights, and what is the attack called?",
      "options": [
        {
          "label": "It is impossible without admin rights, because obtaining another account's password always requires domain-administrator privileges, so the scenario as described could not actually occur in a real environment",
          "value": "a"
        },
        {
          "label": "Kerberoasting (T1558.003): any domain user can request a Kerberos service ticket for the service's SPN, and the ticket is encrypted with the service account's password hash — the attacker captures it and cracks it offline, needing no elevated rights at all",
          "value": "b"
        },
        {
          "label": "Pass-the-Hash, because requesting a service ticket automatically hands the requester the plaintext password of every account in the domain in a single step regardless of permissions",
          "value": "c"
        },
        {
          "label": "A brute-force attack against the SQL service's login, which succeeds only because the attacker's ordinary account was secretly granted administrator rights on the domain controller beforehand",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "This is Kerberoasting: because any authenticated domain user can request a service ticket (TGS) for any SPN, and the KDC encrypts that ticket with the target service account's password hash, an ordinary account can capture the ticket and crack the password entirely offline — no elevated rights required. Option a is wrong; the whole danger is that no privilege is needed. Option c misdescribes Pass-the-Hash (which replays a hash, and does not hand over plaintext for every account). Option d invents secret admin rights the scenario does not have; Kerberoasting works precisely without them."
    },
    {
      "question": "You want to build a high-fidelity detection for Kerberoasting on your domain controllers. Which signal is most characteristic of the attack, and why?",
      "options": [
        {
          "label": "A spike in Event 4625 (failed logons), because Kerberoasting works by repeatedly attempting to log in to each service account until the correct password is guessed against the live domain controller",
          "value": "a"
        },
        {
          "label": "Event 4769 (service ticket requested) with encryption type 0x17 (RC4), especially with one account requesting tickets for many different SPNs in a burst — attackers downgrade to RC4 to crack faster, and the fan-out reveals SPN enumeration",
          "value": "b"
        },
        {
          "label": "A sudden increase in outbound network traffic on port 443, because Kerberoasting exfiltrates the cracked passwords to an external command-and-control server over HTTPS as its final and most detectable step",
          "value": "c"
        },
        {
          "label": "Event 1102 (the security log was cleared), since Kerberoasting always begins by wiping the domain controller's logs to hide the ticket requests before it starts enumerating service accounts",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "The most characteristic signal is Event 4769 with RC4 encryption (type 0x17), particularly when one account requests service tickets for many SPNs in a short window: attackers deliberately request the weaker RC4 to speed up offline cracking, and roasting every service account at once produces an abnormal fan-out. Option a is wrong because the cracking is offline — Kerberoasting generates no failed logons against your systems. Option c invents an HTTPS-exfiltration step that is not part of the attack's signature. Option d describes log clearing, which is a different technique and not intrinsic to Kerberoasting."
    }
  ],
  "references": [
    "https://attack.mitre.org/techniques/T1558/003/",
    "https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769",
    "https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview"
  ],
  "xp": 240,
  "estimatedMinutes": 40,
  "researchUsed": false,
  "createdAt": "2026-08-14T00:00:00.000Z"
},
{
  "id": "topic-lesson-pth-ptt",
  "slug": "pass-the-hash-and-pass-the-ticket",
  "title": "Pass-the-Hash and Pass-the-Ticket: Authenticating Without the Password",
  "topic": "Active Directory Attacks",
  "difficulty": "intermediate",
  "kind": "lesson",
  "intro": "Two of the most important credential-reuse techniques in Windows attacks share one unsettling idea: the attacker never needs to know the actual password. Instead they steal the cryptographic proof of identity — an NTLM hash or a Kerberos ticket — and replay it directly. This lesson explains how Pass-the-Hash and Pass-the-Ticket work, why they make lateral movement so easy, and how you detect and defend against them.",
  "sections": [
    {
      "heading": "The Core Idea: The Hash or Ticket IS the Credential",
      "content": "The single concept that unlocks both attacks is this: **Windows authentication does not always require your password — it requires proof that you know it, and that proof can be stolen and reused.** Understanding this dissolves the intuition that stealing a password means cracking it.\n\nWhen you log into Windows, the system does not keep your plaintext password lying around; it keeps a **hash** of it (for NTLM authentication) and issues you **Kerberos tickets** (for Kerberos authentication) that prove you already authenticated. These secrets live in the memory of the **LSASS** process. The crucial fact is that both the hash and the ticket function as **password-equivalents**: the authentication protocols accept them as proof of identity *directly*.\n\nSo an attacker who dumps these secrets from LSASS (the credential-theft you met in the Windows-internals lesson) does not need to crack anything. They simply **replay** the stolen hash or ticket, and the target system authenticates them as the victim. This is why the two attacks are grouped under MITRE ATT&CK **T1550 — Use Alternate Authentication Material**: the attacker uses the *material* that stands in for the password, not the password itself.\n\nTwo consequences follow, and they are what make these techniques so dangerous:\n\n- **Cracking is skipped entirely.** Unlike Kerberoasting or offline password cracking, there is no guessing — the secret is used as-is, instantly. A strong, uncrackable password does not help if its hash or ticket is stolen and replayed.\n- **Stealing the secret needs admin on only ONE machine.** Dumping LSASS requires local admin on a single host. From that one foothold, the attacker harvests every credential that has been used on that machine — and replays them to reach everywhere those accounts can go. This is the engine of lateral movement across a domain."
    },
    {
      "heading": "Pass-the-Hash (T1550.002)",
      "content": "**Pass-the-Hash (PtH)** targets **NTLM authentication.** When Windows authenticates a user over NTLM, it proves knowledge of the password using the **NTLM hash** of that password — not the plaintext. That design choice is the whole vulnerability: if the protocol only ever uses the hash, then possessing the hash is as good as possessing the password.\n\nThe attack is direct. Having dumped a user's NTLM hash from LSASS on a compromised host, the attacker feeds that hash to a tool (Mimikatz, Impacket's tools, or a built-in via `sekurlsa::pth`) that authenticates to a *remote* system — a file share, a management interface, another workstation — presenting the hash as proof. The remote system runs NTLM authentication, the hash validates, and the attacker is **logged in as the victim** without ever knowing or cracking the password.\n\nWhy this is a lateral-movement powerhouse:\n\n- **Local admin passwords are the classic target.** If every machine shares the *same* local administrator password (and therefore the same hash), a single dumped hash unlocks the entire fleet via PtH — which is exactly the problem Microsoft's **LAPS** (unique per-machine local-admin passwords) was built to solve.\n- **Privileged domain accounts are worse.** A domain admin's hash, harvested from any machine they logged into, lets the attacker Pass-the-Hash straight to domain-wide control — which is why tiering (keeping domain-admin logons off ordinary workstations) matters so much.\n\nThe defining detection idea is that PtH produces **NTLM authentication** where you might otherwise expect Kerberos. In a modern, Kerberos-first domain, a burst of NTLM logons — especially between workstations, or to sensitive systems, using privileged accounts — is anomalous, and the domain controller records NTLM credential validation as **Event 4776**. PtH also surfaces as **4624 type 3 (network) logons** followed by **4672 (special privileges)** on the target when a privileged hash is replayed."
    },
    {
      "heading": "Pass-the-Ticket (T1550.003)",
      "content": "**Pass-the-Ticket (PtT)** is the Kerberos equivalent: instead of a hash, the attacker steals and replays a **Kerberos ticket.** Recall from the authentication lessons that Kerberos issues two kinds of ticket — a **TGT (Ticket-Granting Ticket)**, which proves you authenticated and lets you request service tickets, and **service tickets (TGS)**, which grant access to a specific service. Both live in memory, and both can be stolen.\n\nThe attack: from a compromised host, the attacker extracts a valid ticket from LSASS memory (again with tools like Mimikatz or Rubeus) and **injects it into their own logon session.** From then on, the attacker's session *is* that identity as far as Kerberos is concerned — they present the ticket to services, which honour it because a valid ticket is proof that its holder already authenticated. Steal a **TGT** and the attacker can request service tickets to anything the victim can reach; steal a **service ticket** and they get that specific service directly.\n\nWhy PtT matters alongside PtH:\n\n- **It works where Kerberos is used** — which, in a modern domain, is most of the time. As organisations reduce NTLM to blunt Pass-the-Hash, Pass-the-Ticket becomes the natural successor, because it abuses the protocol that replaced NTLM.\n- **It is the foundation for the elite AD attacks.** The Golden Ticket and Silver Ticket attacks are, at bottom, Pass-the-Ticket with a *forged* ticket rather than a stolen one — so understanding PtT is the prerequisite for those.\n\nA key defensive lever specific to PtT is **ticket lifetime**: tickets expire (a TGT typically after ~10 hours), so a stolen *legitimate* ticket is only useful within its validity window — which is one reason short, well-configured ticket lifetimes limit the damage, and why a forged ticket with an absurdly long lifetime is itself a detection signal."
    },
    {
      "heading": "Detection and Defence",
      "content": "Because both attacks replay legitimate credentials, they blend into normal authentication — so detection leans on *anomalies* and defence leans on *removing the stealable secret* and *shrinking what it unlocks*.\n\n**Detection signals:**\n\n- **NTLM where Kerberos is expected.** A rise in NTLM authentication (**Event 4776** on the DC), especially by IP, between workstations, or with privileged accounts in a Kerberos-first environment, is a Pass-the-Hash smell.\n- **Anomalous network logons.** **4624 type 3** logons from unusual sources followed by **4672 (special privileges)**, or a privileged account suddenly authenticating to many hosts, point at replayed credentials driving lateral movement.\n- **Ticket anomalies.** For Pass-the-Ticket, tickets with abnormal lifetimes or encryption, or tickets used from a host different from the one that obtained them, are red flags.\n- **The precursor is the loudest signal.** Both attacks require stealing the secret first — so a **process opening LSASS (Sysmon Event ID 10)**, the credential-dumping detection from the Windows lesson, is often your earliest and clearest warning, before any replay happens.\n\n**Defences — remove the secret and limit its reach:**\n\n- **Protect LSASS.** **Credential Guard** isolates secrets in a virtualised container so they cannot be dumped by ordinary means; this attacks the problem at its root by making the hash/ticket unstealable in the first place.\n- **LAPS** gives every machine a unique local-admin password, so one stolen hash unlocks exactly one host instead of the whole fleet.\n- **Administrative tiering** keeps privileged credentials off the machines most likely to be compromised, so a workstation compromise cannot yield a domain-admin hash to pass.\n- **Reduce NTLM and shorten ticket lifetimes**, removing the easy Pass-the-Hash path and limiting how long a stolen ticket is useful.\n\nThe takeaway ties back to the whole credential story: you cannot stop Windows from using hashes and tickets — that is how authentication works — so you defeat Pass-the-Hash and Pass-the-Ticket by making the secret unstealable (Credential Guard), unique (LAPS), and low-value (tiering), while watching for the LSASS access that precedes every replay and the NTLM/logon anomalies that reveal it in progress.",
      "image": {
        "src": "/lesson-images/ad/pass-the-hash-ticket.svg",
        "alt": "A diagram of Pass-the-Hash and Pass-the-Ticket, showing that the hash or ticket is the credential and no plaintext password is needed. Pass-the-Hash (T1550.002): the attacker dumped an NTLM password hash from LSASS and never cracked it; they authenticate to a remote host or share WITH the hash, and NTLM authentication accepts the hash as proof of identity without asking for the plaintext, so they are logged in as the victim. Pass-the-Ticket (T1550.003): the attacker stole a Kerberos ticket (TGT or TGS) from memory and injects it into their own logon session, then presents the ticket to a Kerberos service, which grants access to the ticket's identity because the ticket already proves the holder authenticated, again with no password. Why it matters: stealing the hash or ticket needs only admin on one host (LSASS), cracking is skipped because the secret is replayed as-is, and this is how attackers move laterally across the domain. Detect and defend: NTLM logons where Kerberos is expected (Event 4776, 4624 type 3 plus 4672), protect LSASS with Credential Guard, and use LAPS, tiering, disabling NTLM, and short ticket lifetimes.",
        "caption": "In Pass-the-Hash and Pass-the-Ticket the stolen hash/ticket IS the credential — replayed directly, no cracking. Defeat it by making the secret unstealable (Credential Guard), unique (LAPS), and low-value (tiering).",
        "credit": "Figure authored for this course. Techniques per MITRE ATT&CK T1550.002 / T1550.003."
      }
    }
  ],
  "keyTakeaways": [
    "Windows authentication accepts the NTLM hash (Pass-the-Hash) or a Kerberos ticket (Pass-the-Ticket) as proof of identity DIRECTLY — both are password-equivalents living in LSASS memory — so an attacker replays the stolen secret without ever cracking a password (MITRE T1550): a strong password doesn't help if its hash/ticket is stolen, and dumping LSASS needs admin on just ONE host to then reach everywhere those accounts go (the engine of lateral movement).",
    "Pass-the-Hash abuses NTLM (watch for NTLM/4776 where Kerberos is expected, 4624 type-3 + 4672); Pass-the-Ticket abuses Kerberos (watch for ticket-lifetime/host anomalies, and it's the basis of Golden/Silver Ticket); the earliest signal for both is LSASS access (Sysmon Event ID 10) BEFORE the replay — defend by making the secret unstealable (Credential Guard), unique per host (LAPS), and low-value (admin tiering), plus reducing NTLM and shortening ticket lifetimes."
  ],
  "quiz": [
    {
      "question": "An organisation enforces very strong, uncrackable passwords, yet an attacker who compromised one workstation is authenticating to other machines as a domain administrator without ever knowing or cracking that admin's password. How is this possible, and what technique is in use?",
      "options": [
        {
          "label": "It is impossible, because strong uncrackable passwords make it fundamentally impossible for an attacker to authenticate as another user under any circumstances, so the scenario cannot really be happening",
          "value": "a"
        },
        {
          "label": "Pass-the-Hash / Pass-the-Ticket (T1550): the attacker dumped the admin's NTLM hash or Kerberos ticket from LSASS on the compromised host and replays it directly — Windows accepts the hash/ticket as proof, so password strength is irrelevant once the secret is stolen",
          "value": "b"
        },
        {
          "label": "A dictionary attack that succeeded because the admin's password, despite policy, was actually the word 'password', which is the only way to authenticate as another user without their real credentials",
          "value": "c"
        },
        {
          "label": "The attacker guessed the password through the domain controller's login prompt, which is why account-lockout policy is the single control that would have completely prevented this activity",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "Windows accepts the NTLM hash and the Kerberos ticket as direct proof of identity, so an attacker who dumped the admin's hash or ticket from LSASS on the compromised host can replay it (Pass-the-Hash / Pass-the-Ticket, T1550) and authenticate as the admin — no cracking involved, which is why even an uncrackable password does not help. Option a misunderstands that the attack bypasses the password entirely. Option c invents a weak password contradicting the premise. Option d describes online guessing, which is not what is happening — there are no password attempts, just replayed secrets."
    },
    {
      "question": "In a Kerberos-first Windows domain, you observe a spike of NTLM authentications (Event 4776) between workstations using a privileged account, shortly after a process was seen opening lsass.exe on one of those hosts. What does this sequence most likely indicate?",
      "options": [
        {
          "label": "Routine Kerberos operation, because NTLM and Kerberos are the same protocol and a spike in one is simply normal domain authentication that never warrants any investigation at all",
          "value": "a"
        },
        {
          "label": "Credential theft followed by Pass-the-Hash: the LSASS access dumped a hash, and the subsequent NTLM-where-Kerberos-is-expected logons with a privileged account are the replay driving lateral movement — the LSASS access is the earliest warning",
          "value": "b"
        },
        {
          "label": "A failed backup job, since LSASS access and NTLM authentication together are the normal signature of backup software and carry no security meaning whatsoever for an analyst",
          "value": "c"
        },
        {
          "label": "Proof that the domain has switched to NTLM permanently, which is a beneficial security upgrade and explains the spike as an intended and desirable configuration change",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "The sequence is textbook: a process opening lsass.exe indicates credential dumping, and the following NTLM authentications (4776) in a Kerberos-first domain — privileged account, workstation-to-workstation — are the Pass-the-Hash replay driving lateral movement. The LSASS access is the earliest and clearest warning, before the replay. Option a falsely equates NTLM and Kerberos and dismisses a real signal. Option c invents a benign backup explanation the pattern does not fit. Option d misframes a Pass-the-Hash indicator as a beneficial upgrade; NTLM is the weaker, older protocol."
    }
  ],
  "references": [
    "https://attack.mitre.org/techniques/T1550/002/",
    "https://attack.mitre.org/techniques/T1550/003/",
    "https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/"
  ],
  "xp": 210,
  "estimatedMinutes": 38,
  "researchUsed": false,
  "createdAt": "2026-08-14T00:00:00.000Z"
},
{
  "id": "topic-lesson-malware-types",
  "slug": "malware-types-field-guide",
  "title": "Malware Types: A Field Guide for the SOC Analyst",
  "topic": "Malware",
  "difficulty": "beginner",
  "kind": "lesson",
  "intro": "Virus, worm, trojan, RAT, rootkit, ransomware, infostealer, dropper, loader — the vocabulary of malware can feel like a pile of interchangeable scary words. It is not. Each term describes a malware's PURPOSE, and knowing which is which tells you immediately what a sample is trying to do and what you must check next. This lesson is a field guide organised the way analysts actually think: not by name, but by what the malware is FOR.",
  "sections": [
    {
      "heading": "Why We Categorise Malware by Purpose, Not by Name",
      "content": "The first thing to unlearn is the idea that these terms are a neat, exclusive taxonomy where every sample is exactly one thing. Real-world malware is almost always **several of these categories at once** — a trojan that drops a loader that installs an infostealer, or a worm that carries ransomware. The words describe *functions*, and one program can perform many.\n\nSo the useful way to think is by **purpose**: what is this malware *for*? Every category answers a different question about a sample:\n\n- **How does it spread?** (virus, worm, trojan)\n- **How does it hide?** (rootkit, fileless, packer)\n- **How does it get onto and stage the system?** (dropper, loader, downloader)\n- **What does it steal or watch?** (spyware, infostealer, keylogger)\n- **How does the attacker control it?** (RAT, bot, backdoor)\n- **What is the attacker's end goal / payoff?** (ransomware, wiper, cryptominer)\n\nThis matters enormously for an analyst, because **the category drives your investigation.** Knowing a sample is an *infostealer* immediately tells you to ask 'what credentials and data left the environment?'. Knowing it is a *worm* tells you to ask 'which other hosts did it spread to?'. Knowing it is a *RAT* tells you to find the command-and-control channel. Knowing it is *ransomware* tells you to scope the encryption and check your backups. The type is not trivia — it is the fastest route to the right next question.\n\nThe rest of this lesson walks the categories. Do not memorise them as isolated definitions; learn them as a set of *lenses* you apply to any sample: 'what does this thing do — how does it spread, hide, deliver, steal, control, and what is its payoff?'"
    },
    {
      "heading": "How It Spreads: Virus, Worm, and Trojan",
      "content": "The oldest distinctions are about **propagation** — how the malware gets from one place to the next.\n\n- **Virus.** A virus attaches itself to a **host file or program** and requires a **user to run that file** to activate and spread. Like a biological virus, it needs a host and it needs help propagating (a person opening the infected file). Pure classic viruses are rarer today, but the term persists — and the key property to remember is *needs a host + needs user action*.\n- **Worm.** A worm is **self-propagating**: it spreads across a network **on its own**, with no host file and no user needed, typically by exploiting a vulnerability or abusing credentials to copy itself to other machines. This autonomy is what makes worms so dangerous and fast — WannaCry (2017) spread worldwide in hours precisely because its ransomware payload had a worm's self-spreading engine. When you identify worm behaviour, the urgent question is always *how many other hosts already have it?*.\n- **Trojan.** A trojan (from the Trojan Horse) **disguises itself as something the user wants** — a cracked game, a fake invoice, a legitimate-looking installer — to trick the victim into running it. It does not self-spread and does not infect other files; its whole trick is *social*, relying on the user to invite it in. 'Trojan' describes the *delivery disguise*, which is why it so often combines with other categories: a **trojan dropper**, a **banking trojan**, a **RAT delivered as a trojan**.\n\nThe practical distinction to carry: **a virus needs a host file and a user; a worm needs neither and spreads itself; a trojan is a disguise that relies on the user.** These answer the 'how did it get here and how far could it go?' question that opens most malware investigations."
    },
    {
      "heading": "Delivery and Stealth: Droppers, Loaders, Rootkits, and Fileless",
      "content": "Two more sets of categories describe the *first stage* (getting the real payload onto the system) and *staying hidden* once there.\n\n**Delivery — the malware whose job is to bring more malware:**\n\n- **Dropper.** A dropper **carries the malicious payload inside itself** and writes ('drops') it onto disk, then runs it. It is a self-contained delivery vehicle.\n- **Loader / Downloader.** A loader **fetches the next stage from the internet** and runs it (often in memory). A downloader pulls additional malware. These first-stage tools are what you frequently catch *first* — a maldoc's macro launching a loader — and catching them early can stop the real payload from ever arriving.\n\n**Stealth — the malware whose job is to not be seen:**\n\n- **Rootkit.** A rootkit **hides deep in the system** — often at the kernel level — to conceal the attacker's presence: hiding processes, files, and network connections from the operating system and from security tools. Rootkits are among the hardest malware to detect precisely because they subvert the very tools you would use to find them, which is why detection often relies on external/behavioural signals rather than asking the compromised OS.\n- **Fileless malware.** As the malware-triage lesson covered, fileless malware **runs in memory using trusted built-in tools** and writes no malicious file, evading signature scanning and hash reputation entirely — caught by behaviour, not by a file.\n- **Packers / crypters** obfuscate a malware's code so it looks different on disk and its strings are hidden, defeating simple signature matching (the high-entropy tell from the crypto lesson).\n\nThe analyst takeaway: droppers and loaders are the *first stage* — catching them is your early-intervention opportunity — while rootkits, fileless techniques, and packing are all about **evading detection**, which is why 'the AV is clean' never closes a case on its own."
    },
    {
      "heading": "Theft, Control, and the Payoff",
      "content": "The final categories describe what the malware ultimately *does for the attacker* — steal, control, or cause impact.\n\n**What it steals or watches:**\n\n- **Spyware** covertly monitors the user — activity, screenshots, browsing.\n- **Infostealer** is the modern powerhouse: it rapidly harvests **credentials, browser cookies and saved passwords, session tokens, and cryptocurrency wallets**, then exfiltrates them. Infostealers feed the criminal economy (stolen credentials are sold), so identifying one means asking *what was taken and which accounts are now exposed?*.\n- **Keylogger** records every keystroke, capturing passwords and messages as they are typed.\n\n**How the attacker controls it:**\n\n- **RAT (Remote Access Trojan)** gives the attacker **full interactive remote control** of the machine — like remote-desktop for the adversary. Finding a RAT means finding its **command-and-control** channel.\n- **Bot** enrols the machine into a **botnet** that takes commands from a central controller (for DDoS, spam, or mining).\n- **Backdoor** provides the attacker **quiet re-entry** — a way back in that survives even if the original infection is cleaned, which is why eradication must hunt for backdoors, not just the obvious payload.\n\n**The payoff — the attacker's end goal:**\n\n- **Ransomware** encrypts data and extorts payment (the ransomware lesson covers its full lifecycle).\n- **Wiper** destroys data outright with no ransom — pure sabotage, often disguised as ransomware.\n- **Cryptominer** hijacks the victim's compute to mine cryptocurrency, stealing electricity and performance rather than data.\n\nThe unifying lesson, and the reason this field guide matters: **real malware combines these categories, so you describe what a sample DOES rather than forcing it into one label** — a trojan dropper that loads an infostealer and installs a backdoor is four categories in one. And each category you identify hands you the next investigation question: infostealer → what data/creds left; worm → which hosts; RAT/backdoor → what C2 and re-entry; ransomware/wiper → scope and recoverability. Naming the type is the fastest way to know what to check and how to respond.",
      "image": {
        "src": "/lesson-images/malware/malware-types-by-purpose.svg",
        "alt": "A field guide to malware types organised by purpose rather than by name. How it spreads: a virus needs a host file plus a user to run it, a worm self-propagates across the network with no host, a trojan is disguised as something the user wants. How it hides: a rootkit hides deep in the kernel to evade detection, fileless malware lives in memory with no file to scan, packers and crypters obfuscate the code. How it delivers: a dropper carries and drops the payload, a loader fetches and runs the next stage, a downloader pulls more malware. What it steals: spyware watches the user, an infostealer grabs passwords, cookies, and wallets, a keylogger records keystrokes. How it controls: a RAT gives full remote control, a bot joins a botnet and takes commands, a backdoor provides quiet re-entry. The payoff or impact: ransomware encrypts and extorts, a wiper destroys data with no ransom, a cryptominer steals compute. Two ideas to carry: the labels overlap and combine, since real malware is usually several of these at once such as a trojan dropper that loads an infostealer, so describe what the sample does rather than hunting one label; and the category tells you what to check next — infostealer means what credentials and data left, worm means which other hosts, RAT means what command and control, ransomware means scope and backups.",
        "caption": "Malware is categorised by PURPOSE — spread, hide, deliver, steal, control, payoff. Real samples combine several, so describe what it DOES; each category drives the next investigation question.",
        "credit": "Figure authored for this course."
      }
    }
  ],
  "keyTakeaways": [
    "Malware terms describe PURPOSE, not exclusive labels, and real samples combine many at once (a trojan dropper that loads an infostealer and installs a backdoor). Learn them as lenses: how it spreads (virus needs host+user; worm self-propagates; trojan is a user-tricking disguise), how it hides (rootkit=kernel stealth; fileless=in-memory; packer=obfuscation), and how it's delivered (dropper carries the payload; loader/downloader fetches the next stage).",
    "The rest is theft, control, and payoff: spyware/infostealer/keylogger STEAL (creds, cookies, wallets, keystrokes); RAT/bot/backdoor give the attacker CONTROL and re-entry; ransomware/wiper/cryptominer are the PAYOFF (extort/destroy/steal compute). Naming the category drives your next question — infostealer→what data left, worm→which hosts, RAT/backdoor→what C2 and re-entry, ransomware→scope + backups — so the type is the fastest route to the right investigation and response."
  ],
  "quiz": [
    {
      "question": "During triage you determine a sample was disguised as a software update the user ran (no self-spreading), which then wrote a second program to disk and executed it; that second program harvested saved browser passwords and cookies and sent them out. Using the purpose-based categories, how would you describe this sample, and why does the description matter more than a single label?",
      "options": [
        {
          "label": "It is simply 'a virus', because all malware is a virus, and forcing every sample into that one category is the standard and correct way analysts classify malicious software",
          "value": "a"
        },
        {
          "label": "A trojan (disguise, no self-spread) that acts as a dropper (writes + runs a second stage) delivering an infostealer (harvests credentials/cookies) — describing what it DOES across categories tells you the next questions: what creds/data left and which accounts are now exposed",
          "value": "b"
        },
        {
          "label": "It must be a worm, because any malware that writes a file to disk is by definition self-propagating across the network, which is the single defining property of every type of malware",
          "value": "c"
        },
        {
          "label": "The categories are irrelevant labels, so the only correct action is to record the file hash and close the case, since what a sample actually does has no bearing on the investigation",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "The sample combines categories by purpose: a trojan (disguised as an update, relying on the user, not self-spreading), acting as a dropper (writing and running a second stage), which is an infostealer (harvesting saved passwords and cookies and exfiltrating them). Describing what it does across categories is what drives the investigation — an infostealer means you must determine what credentials and data left and which accounts are now exposed. Option a wrongly collapses everything to 'virus.' Option c misdefines a worm (writing a file is not self-propagation). Option d dismisses the categories that actually direct the response."
    },
    {
      "question": "An analyst confirms a host is infected with a worm. Beyond cleaning the infected host, what is the single most urgent question the 'worm' category should immediately prompt, and why?",
      "options": [
        {
          "label": "What ransom amount is being demanded, because every worm's defining purpose is to encrypt files and extort payment, so the ransom note is always the first thing to locate and analyse",
          "value": "a"
        },
        {
          "label": "Which other hosts has it already spread to — because a worm self-propagates across the network on its own, so by the time one host is found the infection has very likely reached others that must be found and contained",
          "value": "b"
        },
        {
          "label": "Nothing further is needed, because a worm cannot spread beyond the single machine it first infects, so cleaning that one host fully resolves the entire incident with no wider scope",
          "value": "c"
        },
        {
          "label": "What the user clicked to run it, because a worm requires a user to open a host file to propagate, making the user's action the only relevant factor in a worm investigation",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "A worm's defining property is that it self-propagates across the network with no host file and no user action, so identifying a worm should immediately raise the scope question: which other hosts has it already reached? By the time you find one infected machine, a worm has likely spread further, and containment depends on finding and isolating the rest. Option a confuses worms with ransomware. Option c is exactly wrong — self-spreading is the whole danger. Option d describes a virus (needs a host file and user), not a worm, which needs neither."
    }
  ],
  "references": [
    "https://attack.mitre.org/tactics/TA0002/",
    "https://www.cisa.gov/news-events/news/understanding-hidden-threats-rootkits-and-botnets",
    "https://attack.mitre.org/software/"
  ],
  "xp": 170,
  "estimatedMinutes": 34,
  "researchUsed": false,
  "createdAt": "2026-08-14T00:00:00.000Z"
}
];

export default NEW_TOPIC_LESSONS;
export { NEW_TOPIC_LESSONS };
