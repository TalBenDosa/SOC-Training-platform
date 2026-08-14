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
}
];

export default NEW_TOPIC_LESSONS;
export { NEW_TOPIC_LESSONS };
