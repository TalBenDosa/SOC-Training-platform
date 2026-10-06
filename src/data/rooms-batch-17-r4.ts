/**
 * Learning Rooms — Batch 17 (Room 4)
 *
 * "Windows Protocols & Lateral Movement" (windows-protocols-lateral)
 *
 * Advanced deep dive into the Windows protocols attackers ride during lateral
 * movement: SMB signing/relay/admin shares, the Kerberos ticket exchange at
 * the field level, Kerberoasting/AS-REP roasting/Pass-the-Ticket at the
 * protocol level, NTLM challenge-response, LDAP reconnaissance queries, and
 * DCERPC/named pipes behind PsExec/WMI-style lateral movement.
 */

import type { TelemetryEvent } from "@/lib/sim/types";
import { KQL_PRIMER } from "@/data/kqlPrimer";

// ── Log analysis event 1: admin-share / named-pipe access consistent with
//    remote service-based lateral movement ──────────────────────────────────
const adminShareEvent: TelemetryEvent = {
  id: "evt-winproto-la1-001",
  ts: "2026-05-11T23:48:02.000Z",
  source: "windows_security",
  vendor: "Windows Security",
  event_type: "privileged_operation",
  severity: "high",
  hostname: "WKS-OPS31.solvix.local",
  src_ip: "10.40.6.90",
  description:
    "A remote session from 10.40.6.90 accessed the IPC$ administrative share on WKS-OPS31 and opened the svcctl named pipe; a new service was subsequently registered on the same host moments later",
  authentication: { method: "NTLM", result: "Success", logon_type: 3 },
  raw: {
    "event.code": "5145",
    "winlog.channel": "Security",
    "winlog.computer_name": "WKS-OPS31.solvix.local",
    "winlog.event_data.SubjectUserName": "m.reyes",
    "winlog.event_data.SubjectDomainName": "SOLVIX",
    "winlog.event_data.IpAddress": "10.40.6.90",
    "winlog.event_data.IpPort": "51422",
    "winlog.event_data.ShareName": "\\\\*\\IPC$",
    "winlog.event_data.RelativeTargetName": "svcctl",
    "winlog.event_data.AccessMask": "0x120089",
    "winlog.event_data.AccessList": "%%4416\n\t\t\t%%4423\n\t\t\t%%4432",
    "winlog.event_data.AccessReason": "-",
    "winlog.event_id": 5145,
  },
};

// ── Log analysis event 2: Kerberoasting sweep — many SPNs, RC4, rapid succession
const kerberoastSweepEvent: TelemetryEvent = {
  id: "evt-winproto-la2-001",
  ts: "2026-05-14T02:03:11.000Z",
  source: "ad",
  vendor: "Windows Security",
  event_type: "kerberos_tgs",
  severity: "high",
  hostname: "DC02.solvix.local",
  description:
    "Kerberos TGS-REQ recorded on DC02 for service principal MSSQLSvc/sqlrpt02.solvix.local:1433 (owned by service account sqlrpt_svc), requested by account m.reyes; this is one of several similar requests from the same account within a two-minute window",
  raw: {
    "event.code": "4769",
    "winlog.channel": "Security",
    "winlog.computer_name": "DC02.solvix.local",
    "winlog.event_data.TargetUserName": "m.reyes",
    "winlog.event_data.TargetDomainName": "SOLVIX.LOCAL",
    "winlog.event_data.ServiceName": "sqlrpt_svc",
    "winlog.event_data.TicketEncryptionType": "0x17",
    "winlog.event_data.TicketOptions": "0x40810000",
    "winlog.event_data.Status": "0x0",
    "winlog.event_data.IpAddress": "10.40.6.90",
    "winlog.event_data.IpPort": "0",
    "winlog.event_id": 4769,
  },
};

const winProtoRoom = {
  id: "windows-protocols-lateral",
  title: "Windows Protocols & Lateral Movement",
  description:
    "Go beneath the alert names into the wire-level mechanics of the Windows protocols attackers abuse to move laterally: SMB signing, relay, and administrative shares; the Kerberos AS/TGS ticket exchange field by field, and how Kerberoasting, AS-REP roasting, and Pass-the-Ticket each manipulate a specific step of that exchange; the NTLM challenge-response handshake and why it enables relay; the LDAP reconnaissance queries tools like BloodHound actually send; and the DCERPC named pipes behind PsExec- and WMI-style remote service execution.",
  difficulty: "advanced" as const,
  category: "Network Security" as const,
  estimatedMinutes: 70,
  xp: 400,
  icon: "🗝️",
  prerequisites: ["active-directory", "windows-event-logs"],
  tasks: [
    // ── Reading 1: SMB signing, sessions, admin shares ───────────────────────
    {
      type: "reading" as const,
      id: "winproto-r1",
      heading: "SMB Protocol Internals: Signing, Sessions, and Administrative Shares",
      content:
        `SMB (Server Message Block) is the protocol behind Windows file sharing, print sharing, and — critically for lateral movement — remote administration. Understanding its session model and default administrative shares is what lets you read a share-access log and know exactly what an attacker was reaching for.\n\n` +
        `**The SMB connection sequence**\n\n` +
        `An SMB session goes through a defined sequence: **Negotiate** (client and server agree on the SMB dialect — SMB1, SMB2, or SMB3 — and capabilities), **Session Setup** (the client authenticates, typically via NTLM or Kerberos, establishing a session with a specific user identity), and **Tree Connect** (the client requests access to a specific **share** — a named resource exposed over SMB, like a folder, a printer, or one of the special administrative shares covered below). Only after a successful Tree Connect can the client actually open files, read directory listings, or — as you'll see — reach the special named pipes that let it remotely control services.\n\n` +
        `**Default administrative shares**\n\n` +
        `Every Windows machine automatically exposes a set of hidden administrative shares (the trailing $ marks them hidden from normal browsing, not access-restricted): **C$** (and one for every other fixed drive letter) gives full access to the entire drive root for anyone authenticating with local administrator rights; **ADMIN$** maps directly to the Windows installation directory (%SystemRoot%, typically C:\\Windows); and **IPC$** (Inter-Process Communication) is the special share that doesn't map to a filesystem location at all — it exists purely to carry **named pipes**, which is how remote procedure calls (RPC) travel over SMB. Legitimate IT tooling (Group Policy software deployment, backup agents, remote administration consoles) uses these shares constantly. So do lateral-movement tools — which is exactly why the presence of admin-share access alone is not suspicious; the pattern of who, from where, and to which named pipe is what matters, and that's covered in Reading 6.\n\n` +
        `**SMB signing: why it exists**\n\n` +
        `**SMB signing** adds a cryptographic signature to every SMB message, verified by both sides, specifically to prevent two classes of attack: tampering (an on-path attacker modifying SMB traffic in transit) and, most importantly for this room, **relay attacks** (covered in Reading 4's NTLM discussion) — without signing, a captured NTLM authentication attempt can be forwarded, unmodified, to a different server and accepted as valid, because nothing in the unsigned SMB session cryptographically ties the authentication to the specific server it was originally intended for. Signing is configured via Group Policy ("Microsoft network client/server: Digitally sign communications") and, since Windows Server 2022/Windows 11, is enabled by default for many scenarios — but plenty of production environments still run with signing disabled or only partially enforced, specifically because it was historically optional and carries a (now largely negligible on modern hardware) performance cost, leaving relay attacks viable against them.\n\n` +
        `**SMB versions and why SMBv1 still matters**\n\n` +
        `SMBv1, the original 1980s-era dialect, lacks signing enforcement options as robust as later versions and was the protocol version carrying the **EternalBlue** vulnerability (MS17-010) that WannaCry and NotPetya both exploited for unauthenticated remote code execution. SMBv1 is disabled by default on all current Windows versions, but any environment where you see SMBv1 negotiated at all (visible in the Negotiate exchange) should be treated as a legacy-system finding worth tracking, independent of whether any specific incident is underway.`,
      codeExample:
        "SMB CONNECTION SEQUENCE\n" +
        "=======================================================\n" +
        "1. Negotiate      -- agree on SMB dialect (SMB1/2/3) +\n" +
        "                     capabilities (incl. signing support)\n" +
        "2. Session Setup  -- client authenticates (NTLM or\n" +
        "                     Kerberos), session tied to a user\n" +
        "3. Tree Connect   -- client requests access to a specific\n" +
        "                     share (a folder, a printer, or IPC$)\n" +
        "4. [File/Pipe operations happen within that Tree Connect]\n" +
        "=======================================================\n\n" +
        "DEFAULT ADMINISTRATIVE SHARES\n" +
        "=======================================================\n" +
        "C$ (and D$, E$, ...)  Full access to a drive's root --\n" +
        "                       requires local admin rights\n" +
        "ADMIN$                 Maps to %SystemRoot% (C:\\Windows)\n" +
        "IPC$                   No filesystem mapping -- exists\n" +
        "                       purely to carry named pipes / RPC\n" +
        "=======================================================\n\n" +
        "SMB SIGNING -- WHAT IT PREVENTS\n" +
        "=======================================================\n" +
        "Unsigned SMB: a captured NTLM auth attempt can be relayed,\n" +
        "              unmodified, to a DIFFERENT server and be\n" +
        "              accepted -- nothing ties it to the intended\n" +
        "              target\n" +
        "Signed SMB:   every message cryptographically signed --\n" +
        "              relay attempts fail because the signature\n" +
        "              doesn't match the actual destination session\n" +
        "=======================================================",
      checkpoint: {
        question:
          "According to the reading, what does the IPC$ administrative share actually map to on disk?",
        options: [
          "The root of the C: drive — the same mapping C$ uses, reachable by any local administrator",
          "The Windows installation folder at %SystemRoot%, which is why deployment tools write files to IPC$",
          "Nothing — IPC$ has no filesystem location at all; it exists purely to carry named pipes",
          "The logged-on user's home directory under C:\\Users, exposed over SMB to that user alone",
        ],
        answer: 2,
        explanation:
          "IPC$ (Inter-Process Communication) doesn't map to a filesystem location at all — it exists purely to carry named pipes, which is how remote procedure calls (RPC) travel over SMB. C$ maps to a drive root, and ADMIN$ maps to %SystemRoot%.",
      },
    },

    // ── Reading 2: Kerberos ticket flow at the field level ───────────────────
    {
      type: "reading" as const,
      id: "winproto-r2",
      heading: "The Kerberos Ticket Flow at the Field Level: AS-REQ, AS-REP, TGS-REQ, TGS-REP",
      content:
        `You already know Kerberos authentication happens in two request/reply pairs. What matters for lateral-movement investigation is exactly what's INSIDE each of those tickets — because every major Kerberos-based attack manipulates one specific field or one specific step of this exchange.\n\n` +
        `**AS-REQ / AS-REP: obtaining the TGT**\n\n` +
        `The client sends an **AS-REQ** to the Domain Controller's Key Distribution Center (KDC), containing the client's principal name (cname), the realm (the Kerberos name for the domain), and — normally — **pre-authentication data (PA-DATA)**: a timestamp encrypted with a key derived from the user's password, proving the client actually knows that password before the KDC will issue anything. If pre-authentication succeeds, the KDC replies with an **AS-REP** containing a **Ticket Granting Ticket (TGT)**: an opaque blob, encrypted with the KDC's own krbtgt account key (which the client can never read), containing the client's identity, an authorization data structure (the PAC, Privilege Attribute Certificate, listing group memberships), a **session key**, and validity fields — authtime (when it was issued), starttime, **endtime** (when it expires, typically 10 hours by default), and **renew-till** (how long it can be renewed before requiring a fresh AS-REQ). The AS-REP also includes an outer, unencrypted portion the client CAN read, containing that same session key (encrypted instead with a key derived from the client's own password) so the client can use it for the next step.\n\n` +
        `**TGS-REQ / TGS-REP: exchanging the TGT for a service ticket**\n\n` +
        `To actually access a specific service, the client sends a **TGS-REQ** to the KDC, presenting its TGT alongside the **sname** (service principal name, e.g. MSSQLSvc/sqlsrv01.solvix.local:1433) it wants access to. The KDC validates the TGT, then replies with a **TGS-REP** containing a **service ticket**: similar structure to the TGT, but encrypted with a key derived from the TARGET SERVICE ACCOUNT's own password hash (not the krbtgt key) — this is the critical detail that makes Kerberoasting possible, since it means the encrypted portion of a service ticket is, cryptographically, tied directly to the service account's own credential material.\n\n` +
        `**AP-REQ: presenting the ticket to the actual service**\n\n` +
        `Finally, the client presents the service ticket directly to the target service (not back to the KDC) in an **AP-REQ**, along with a fresh **authenticator** (a timestamp encrypted with the service ticket's session key, proving the client currently holds that session key and this isn't a replayed old ticket). The service decrypts the ticket using its own long-term key, extracts the session key, verifies the authenticator, and grants access.\n\n` +
        `**Why the field-level detail matters**\n\n` +
        `Every attack in the next reading is best understood as "which of these fields, or which of these steps, does the attacker skip, forge, or exploit" — Kerberoasting exploits the fact that the TGS-REP's encrypted portion is tied to the service account's password; AS-REP roasting exploits skipping the PA-DATA pre-authentication step entirely; Pass-the-Ticket exploits the fact that a validly-issued ticket, once obtained, has no binding to a specific source machine and can be replayed from anywhere until its endtime/renew-till expires.`,
      codeExample:
        "KERBEROS TICKET FIELDS -- WHAT'S INSIDE A TGT / SERVICE TICKET\n" +
        "=======================================================\n" +
        "cname          Client principal name (the user)\n" +
        "realm          Kerberos realm (the domain)\n" +
        "sname          Service principal name (TGS/service tkts only)\n" +
        "flags          Ticket options/flags (forwardable, renewable...)\n" +
        "session_key    Shared key for this ticket's lifetime\n" +
        "authtime       When the ticket was originally issued\n" +
        "starttime      When the ticket becomes valid\n" +
        "endtime        When the ticket expires (~10h default for TGTs)\n" +
        "renew-till     How long it can be renewed without a fresh AS-REQ\n" +
        "PAC            Privilege Attribute Certificate -- group\n" +
        "               memberships and authorization data\n" +
        "=======================================================\n\n" +
        "WHAT ENCRYPTS EACH TICKET -- THE CRITICAL DETAIL\n" +
        "=======================================================\n" +
        "TGT (from AS-REP)         Encrypted with the krbtgt\n" +
        "                          account's own key (client can\n" +
        "                          never read it)\n" +
        "Service ticket (TGS-REP)  Encrypted with the TARGET\n" +
        "                          SERVICE ACCOUNT's own password-\n" +
        "                          derived key -- this single fact\n" +
        "                          is what makes Kerberoasting work\n" +
        "=======================================================\n\n" +
        "FIELD -> EVENT ID MAPPING\n" +
        "=======================================================\n" +
        "AS-REQ / AS-REP  -> Event ID 4768 (TGT request)\n" +
        "TGS-REQ / TGS-REP -> Event ID 4769 (service ticket request)\n" +
        "AP-REQ (to the service, not the KDC) -> typically not\n" +
        "  separately logged by the KDC at all; visible instead as\n" +
        "  a 4624 logon on the TARGET service's own host\n" +
        "=======================================================",
      checkpoint: {
        question:
          "An attacker requests a service ticket for MSSQLSvc/sqlrpt02.solvix.local:1433, takes the TGS-REP offline and cracks it. Whose password do they recover?",
        options: [
          "The krbtgt account's, since krbtgt's key encrypts every ticket the KDC issues",
          "The SQL service account's, since the ticket is encrypted with that account's key",
          "The requester's own, since the KDC seals each reply with the client's password key",
          "No one's: service tickets use a random key that changes with every request made",
        ],
        answer: 1,
        explanation:
          "The service ticket inside a TGS-REP is encrypted with a key derived from the password of the account that owns the SPN, which is exactly why Kerberoasting works and why service accounts need long, rotated passwords. “The krbtgt account's…” is true for TGTs, not service tickets. “The requester's own…” confuses the ticket with the outer part of the AS-REP, which carries the session key for the client. “No one's…” mixes up the per-ticket session key with the long-term key that encrypts the ticket itself.",
      },
    },

    // ── Reading 3: Kerberoasting/AS-REP roasting/PtT at the protocol level ───
    {
      type: "reading" as const,
      id: "winproto-r3",
      heading: "Kerberoasting, AS-REP Roasting, and Pass-the-Ticket: What Changes at the Wire Level",
      content:
        `With the ticket structure from Reading 2 in hand, here is exactly what each of these three attacks does differently from a normal Kerberos exchange — at the protocol level, not just "what the tool does."\n\n` +
        `**Kerberoasting: exploiting the TGS-REP encryption target**\n\n` +
        `The attacker performs a completely normal AS-REQ/AS-REP first (they authenticate as themselves, with valid credentials — no anomaly here at all), then sends one or more entirely normal-looking TGS-REQ messages, requesting service tickets for SPNs (Service Principal Names) associated with accounts they want to target — commonly service accounts, which are frequently over-privileged and rarely have their passwords rotated. The KDC has no way to know the requester's INTENT is to crack the reply offline — issuing a service ticket to any authenticated user who asks for a valid SPN is completely normal, expected KDC behavior. What makes it "Kerberoasting" is what the attacker does AFTER receiving the TGS-REP: because that ticket's encrypted portion is tied to the service account's password-derived key (as established in Reading 2), the attacker takes it offline and brute-forces/dictionary-attacks it completely disconnected from the network — no further Kerberos traffic, no lockout, no rate limiting applies to that offline phase at all. The wire-level tell is not any single request, but the PATTERN: an account (often not itself a service account) requesting TGS tickets for MULTIPLE different SPNs in rapid succession, especially with older RC4 (0x17) encryption specifically requested even in an AES-capable domain (RC4 is dramatically faster to crack offline, and many Kerberoasting tools specifically request or downgrade to it), which is precisely the pattern in this room's log analysis exercise below. One caution: the ticket's encryption type is chosen from what the TARGET service account supports (its msDS-SupportedEncryptionTypes setting and whether it has AES keys), not from the requester's settings, so legacy service accounts can legitimately produce RC4 tickets. RC4 is therefore a supporting signal; the burst across many different SPNs is the decisive one.\n\n` +
        `**AS-REP Roasting: skipping the pre-authentication step entirely**\n\n` +
        `This attack targets the FIRST exchange, not the second. Normally, AS-REQ includes PA-DATA (that password-derived encrypted timestamp) proving the client knows the account's password before the KDC issues anything. Some accounts, however, have the "Do not require Kerberos preauthentication" flag set (the DONT_REQ_PREAUTH userAccountControl bit) — for these accounts specifically, the KDC will issue an AS-REP to ANYONE who requests a TGT for that username, with no proof of password knowledge required at all. The returned AS-REP's encrypted portion is, like a service ticket, tied to that account's own password-derived key — so it can be cracked offline exactly like a Kerberoasted service ticket, but the attacker never needed valid credentials of their own to begin with. At the wire level, this shows up as a single 4768 (AS-REQ/AS-REP exchange) with PreAuthType 0 instead of the normal PreAuthType 2 — a request that skipped the proof-of-password step and got a ticket anyway.\n\n` +
        `**Pass-the-Ticket: replaying a valid ticket with no source-machine binding**\n\n` +
        `Unlike the previous two attacks (which are about obtaining a crackable, encrypted blob), Pass-the-Ticket (PtT) doesn't crack anything — it steals an ALREADY-VALID ticket (TGT or service ticket) directly from a compromised machine's memory (classically via Mimikatz's sekurlsa::tickets, extracting tickets cached by the LSASS process) and injects it into a logon session on a DIFFERENT machine (mimikatz's kerberos::ptt). This works because a Kerberos ticket, once issued, carries NO cryptographic binding to the specific machine that originally requested it — Kerberos was designed around the identity making the request, not the device, so any process holding a valid ticket and its associated session key can present it anywhere, to any service that ticket is valid for, until its endtime or renew-till is reached. The wire-level tell is subtle and requires correlation on the domain controller. Remember that a normal network logon ALWAYS spans two machines: the user's workstation requests the TGT (4768 on the DC, Client Address = the workstation) and the server records the logon (4624). That alone is not suspicious. The PtT tell is about WHERE the ticket is used from: 4769 service-ticket requests (on the DC) and 4624 Kerberos network logons (on the target, logon type 3) whose source IP never issued a 4768 for that account. The TGT was requested from IP A, but the account's tickets are being presented from IP C — a machine that never actually requested one. (If IP C had requested its own fresh TGT with stolen credentials or a hash, you would see a 4768 from C instead: that is overpass-the-hash or plain credential theft, not ticket replay.)`,
      codeExample:
        "THREE ATTACKS, THREE DIFFERENT WIRE-LEVEL SIGNATURES\n" +
        "=======================================================\n" +
        "KERBEROASTING\n" +
        "  Normal AS-REQ/AS-REP (attacker's own valid creds), then\n" +
        "  MULTIPLE TGS-REQ for DIFFERENT SPNs in rapid succession,\n" +
        "  often requesting/getting RC4 (0x17) even in an AES domain\n" +
        "  Cracking happens OFFLINE -- zero further Kerberos traffic\n" +
        "\n" +
        "AS-REP ROASTING\n" +
        "  Single 4768 (AS-REQ/AS-REP) with PreAuthType = 0\n" +
        "  (normal is PreAuthType = 2) -- pre-authentication skipped\n" +
        "  entirely; attacker never needed valid credentials at all\n" +
        "  Cracking happens OFFLINE -- zero further Kerberos traffic\n" +
        "\n" +
        "PASS-THE-TICKET\n" +
        "  No cracking at all -- a VALID ticket stolen from one\n" +
        "  host's LSASS memory, replayed on a different host\n" +
        "  Tell: 4769 / 4624 (Kerberos, type 3) for the account\n" +
        "  from source IP C, but the account's 4768 came only from\n" +
        "  IP A -- ticket used from a machine that never requested it\n" +
        "  (normal: 4768 from A, then 4624 on server B from A)\n" +
        "=======================================================",
    },

    // ── Reading 4: NTLM challenge-response + relay ────────────────────────────
    {
      type: "reading" as const,
      id: "winproto-r4",
      heading: "NTLM Challenge-Response: Type 1/2/3 Messages, and Why Relay Works",
      content:
        `NTLM is Kerberos's older sibling — still used whenever Kerberos isn't available (no line of sight to a DC, authentication by IP address instead of hostname, or legacy application requirements) — and its challenge-response design is exactly what makes NTLM relay possible.\n\n` +
        `**The three-message NTLM handshake**\n\n` +
        `1. **Type 1 — Negotiate.** The client tells the server which NTLM capabilities/flags it supports.\n` +
        `2. **Type 2 — Challenge.** The server generates a random 8-byte value (the "challenge") and sends it back to the client. This challenge exists specifically so the same password never produces the same response twice, defeating simple replay of a captured response against the SAME server.\n` +
        `3. **Type 3 — Authenticate.** The client combines the server's challenge with a key derived from the user's password hash (in modern NTLMv2, this also incorporates a client-generated nonce and a timestamp) to produce a **response value**, which it sends back along with the username and target information. The server (or, in a domain environment, the Domain Controller it delegates the actual verification to) independently computes what the correct response SHOULD be, using its own copy of the user's password hash, and compares.\n\n` +
        `**Why this enables relay: the challenge isn't bound to a specific downstream server**\n\n` +
        `The critical gap: the Type 2 challenge is generated by whichever server the client is currently talking to, but nothing in the base protocol cryptographically ties that challenge — or the resulting Type 3 response — to that SPECIFIC server's identity in a way a relaying attacker can't reuse. If an attacker (often positioned via LLMNR/NBT-NS poisoning, as covered in the active-directory room's lateral-movement content) receives a victim's Type 1 Negotiate, the attacker can immediately turn around and open their OWN connection to a real, different target server, receive THAT server's Type 2 Challenge, forward that exact challenge back to the original victim as if it were the attacker's own challenge, receive the victim's Type 3 Authenticate response computed against it, and forward that response on to the real target server — which, having generated that exact challenge itself, sees what looks like a perfectly valid authentication and grants access, as the victim, to the attacker's chosen target. The attacker never learns the victim's password or password hash at any point — they only ever relay live authentication material between two connections they control the timing of. This is precisely what SMB signing (Reading 1) and, for other protocols, mechanisms like channel binding and Extended Protection for Authentication are designed to close, by cryptographically tying the authentication to the specific session/channel it was negotiated on.\n\n` +
        `**Event ID 4776 — where NTLM authentication itself is logged**\n\n` +
        `A Domain Controller validating an NTLM authentication attempt (rather than the client and target negotiating Kerberos) logs Event ID 4776, recording the target account name and the calling workstation name (Workstation field) — but notably NOT a reliable source IP field the way Kerberos events do, which is one reason NTLM authentication is inherently harder to trace back to its true originating machine than Kerberos activity is, and another reason security teams are broadly encouraged to disable NTLM wherever Kerberos can be used instead.`,
      codeExample:
        "NTLM CHALLENGE-RESPONSE -- THE THREE MESSAGES\n" +
        "=======================================================\n" +
        "Client -> Server   Type 1: NEGOTIATE (supported flags)\n" +
        "Server -> Client   Type 2: CHALLENGE (random 8-byte value)\n" +
        "Client -> Server   Type 3: AUTHENTICATE (username +\n" +
        "                   response = f(challenge, password hash,\n" +
        "                   client nonce, timestamp) for NTLMv2)\n" +
        "=======================================================\n\n" +
        "WHY RELAY WORKS -- THE ATTACKER SITS IN THE MIDDLE\n" +
        "=======================================================\n" +
        "1. Victim's Type 1 arrives at the attacker (e.g. via\n" +
        "   LLMNR/NBT-NS poisoning tricking the victim into\n" +
        "   connecting to the attacker in the first place)\n" +
        "2. Attacker opens their OWN connection to the REAL target\n" +
        "3. Real target sends ITS Type 2 Challenge to the attacker\n" +
        "4. Attacker forwards that exact challenge to the victim\n" +
        "5. Victim computes and sends its Type 3 Authenticate\n" +
        "   response against that challenge\n" +
        "6. Attacker forwards the victim's Type 3 response to the\n" +
        "   real target -- which sees a valid, matching response\n" +
        "   to the challenge IT generated, and grants access AS\n" +
        "   THE VICTIM\n" +
        "   -- attacker never learns the password or its hash --\n" +
        "=======================================================",
      checkpoint: {
        question:
          "An attacker poisons LLMNR, receives a victim’s NTLM negotiation and ends up authenticated as the victim on a file server, without ever learning the password or its hash. What protocol gap made this possible?",
        options: [
          "The Type 2 challenge is reused across sessions, so a response captured once replays later",
          "Nothing binds the challenge or the Type 3 response to one server, so both can be forwarded",
          "The Type 3 message carries the password hash itself, so the attacker reuses it on any host",
          "The DC does not check the Workstation field, so any host can claim to be the victim's PC",
        ],
        answer: 1,
        explanation:
          "In a relay the attacker gets a fresh Type 2 challenge from the real target, passes it to the victim and forwards the victim’s live Type 3 response back; nothing in base NTLM ties that response to the server it was meant for, which is what SMB signing and channel binding fix. “The Type 2 challenge is reused across sessions…” is wrong: each server issues a fresh random challenge, which is why simple replay fails and live relay is needed. “The Type 3 message carries the password hash itself…” describes pass-the-hash, and the stem says the attacker never learned the hash. “The DC does not check the Workstation field…” is a real logging weakness of 4776, but it is not what lets the response be accepted.",
      },
    },

    // ── Reading 5: LDAP recon queries ─────────────────────────────────────────
    {
      type: "reading" as const,
      id: "winproto-r5",
      heading: "LDAP Reconnaissance: The Queries BloodHound and Attackers Actually Send",
      content:
        `Before any of the credential attacks in Reading 3 can be targeted effectively, an attacker (or a legitimate red-team/BloodHound run) typically maps the environment first — and that mapping happens almost entirely over **LDAP**, the protocol Active Directory itself is built on.\n\n` +
        `**LDAP basics: bind, then search**\n\n` +
        `An LDAP session starts with a **bind** (authenticating to the directory, which any domain user can do with their own credentials by default), followed by one or more **search** operations — each specifying a base DN (where in the directory tree to start), a scope (this object only, one level down, or the entire subtree), and, critically, a **filter**: a query expression describing which objects to return and which attributes to read. Because any authenticated domain user can, by default, read a very large portion of the directory's attributes (this is intentional — AD needs to be broadly readable for normal operation, like looking up a colleague's phone number or department), LDAP reconnaissance requires no special privileges at all — just a normal domain account.\n\n` +
        `**The specific recon filters worth recognizing**\n\n` +
        `- **Kerberoastable accounts**: (&(objectClass=user)(servicePrincipalName=*)) — every account that has at least one SPN set. Computer objects inherit objectClass=user and always carry SPNs, so this filter returns them too; attackers and hunters usually narrow it to user accounts with (!(objectClass=computer)) or (samAccountType=805306368), because computer-account passwords are long and random while user service accounts often have crackable, human-chosen ones. This is the exact target list Kerberoasting draws from, and it's precisely why every account this query returns should be treated as a candidate target requiring a strong, rotated password.\n` +
        `- **AS-REP-roastable accounts**: (userAccountControl:1.2.840.113556.1.4.803:=4194304) — a bitwise-AND LDAP matching rule filter that returns every account with the DONT_REQ_PREAUTH flag set (4194304, i.e. 0x400000, is the decimal value of that specific userAccountControl bit).\n` +
        `- **High-value/privileged accounts**: (adminCount=1) — returns accounts that are, or historically were, members of a protected administrative group (Domain Admins, Enterprise Admins, and similar); AD's AdminSDHolder process stamps this attribute and, notably, does NOT automatically un-stamp it if the account is later removed from the privileged group, which is itself a useful (if imperfect) hunting signal.\n` +
        `- **Nested group membership walks**: repeated queries against the memberOf and member attributes, recursively, to map out the full effective group membership chain for an account or the full effective membership of a group — this is exactly how tools like BloodHound build their graph of "who can reach what, through which chain of group memberships and permissions," which is often far less obvious than looking at direct group membership alone.\n\n` +
        `**Why LDAP recon is hard to distinguish from legitimate activity in isolation**\n\n` +
        `Every one of these queries is something a normal IT admin script, a help-desk tool, or a legitimate security assessment might also run. The recon signal is rarely any single query — it's the VOLUME and BREADTH from one account in a short period: a workstation account or a regular user account suddenly issuing hundreds or thousands of LDAP search operations against the directory, touching a broad cross-section of objects and attributes it has never queried before, especially via a recognizable tool signature (BloodHound's collector, SharpHound, generates a very specific, high-volume LDAP query pattern that's well-documented and detectable). A single admin querying (adminCount=1) once is nothing. The same query pattern, repeated across dozens of different filters, from an account with no prior history of directory-wide queries, in the space of a few minutes, is reconnaissance.`,
      codeExample:
        "COMMON LDAP RECONNAISSANCE FILTERS\n" +
        "=======================================================\n" +
        "Kerberoastable accounts:\n" +
        "  (&(objectClass=user)(servicePrincipalName=*))\n" +
        "\n" +
        "AS-REP-roastable accounts (DONT_REQ_PREAUTH set):\n" +
        "  (userAccountControl:1.2.840.113556.1.4.803:=4194304)\n" +
        "\n" +
        "Privileged / high-value accounts:\n" +
        "  (adminCount=1)\n" +
        "\n" +
        "Accounts with passwords that never expire:\n" +
        "  (userAccountControl:1.2.840.113556.1.4.803:=65536)\n" +
        "=======================================================\n\n" +
        "WHAT MAKES A SEARCH \"RECON\" RATHER THAN NORMAL AD USE\n" +
        "=======================================================\n" +
        "Normal:  one admin, one filter, occasional use, matches\n" +
        "         their known job function\n" +
        "\n" +
        "Recon:   one account (often NOT an admin), MANY distinct\n" +
        "         filters, high query VOLUME, broad OBJECT/ATTRIBUTE\n" +
        "         coverage the account has no history of touching,\n" +
        "         all within a short time window -- e.g. a\n" +
        "         recognizable SharpHound/BloodHound collection run\n" +
        "=======================================================",
    },

    // ── Reading 6: DCERPC and named pipes ────────────────────────────────────
    {
      type: "reading" as const,
      id: "winproto-r6",
      heading: "DCERPC and Named Pipes: The Machinery Behind PsExec, WMI, and Service-Based Lateral Movement",
      content:
        `Once an attacker has valid credentials (via any of the techniques in this room, or simply a phished password), the actual mechanics of remotely executing code on another Windows host almost always ride on **DCERPC** (Distributed Computing Environment Remote Procedure Call), either tunneled through SMB named pipes or, for some tools, directly over TCP port 135 plus a dynamically negotiated high port.\n\n` +
        `**Named pipes: RPC over the IPC$ share**\n\n` +
        `Recall from Reading 1 that IPC$ exists purely to carry named pipes. A **named pipe** is an inter-process communication mechanism that, over SMB, lets a remote client talk directly to a specific Windows service's RPC interface as if it were a local file handle. The specific pipe name tells you exactly which RPC interface — and therefore exactly what capability — is being invoked: **\\PIPE\\svcctl** talks to the Service Control Manager (create, start, stop, delete services remotely — this is the exact mechanism Sysinternals PsExec uses under the hood: connect to IPC$, open \\PIPE\\svcctl, remotely create and start a new service pointing at the payload executable it has already copied over via the ADMIN$ share); **\\PIPE\\atsvc** talks to the Task Scheduler RPC interface (remote scheduled task creation — another classic lateral-movement primitive); **\\PIPE\\wkssvc** exposes workstation service functions (including remote enumeration of logged-on sessions); **\\PIPE\\epmapper** is the RPC endpoint mapper itself, used to look up which dynamic port a given RPC interface is actually listening on.\n\n` +
        `**PsExec's actual mechanism, step by step**\n\n` +
        `1. Authenticate to the target and connect to its ADMIN$ share.\n` +
        `2. Copy the payload executable (or, classically, PSEXESVC.exe, PsExec's own small service-hosting binary) into %SystemRoot% via that share.\n` +
        `3. Connect to IPC$ and open \\PIPE\\svcctl.\n` +
        `4. Issue an RPC call over that pipe to the Service Control Manager to CREATE a new service pointing at the just-copied executable, then a second call to START it.\n` +
        `5. The new service runs, as SYSTEM by default, executing the payload — this is why the target machine's own event log shows Event ID 7045 (a new service was installed) with a service name (PSEXESVC is the actual, real default name PsExec itself uses if not overridden) and an ImagePath pointing at the just-copied file.\n\n` +
        `**WMI-based lateral movement — a different transport, same RPC foundation**\n\n` +
        `Tools using WMI (Windows Management Instrumentation) for remote execution — including Impacket's wmiexec — instead connect via DCOM/RPC directly, typically hitting TCP port 135 first (the endpoint mapper) to be told which dynamically-assigned high port the actual WMI service is listening on for this session, then issuing a Win32_Process Create call over that connection to launch a process remotely. This produces a different network fingerprint (a connection to 135, then a second connection to a dynamic high port, rather than SMB/445 the whole way through) but accomplishes a very similar remote-execution outcome, and is popular specifically because it avoids leaving a new SERVICE artifact (Event ID 7045) behind at all — the process it starts is not registered as a service, which is exactly why detection strategies for WMI-based lateral movement lean more heavily on Sysmon process-creation telemetry (a new process on the target with WmiPrvSE.exe as its parent) than on service-installation events.\n\n` +
        `**The detection throughline**\n\n` +
        `Whichever transport is used, the common thread across all of these techniques is: authentication from one internal host to another (rarely a legitimate pattern for workstation-to-workstation, as opposed to workstation-to-server, traffic), followed by activity on a specific named pipe or RPC interface that corresponds to a real administrative capability, followed by observable evidence on the TARGET (a new service, a new process with an unusual parent, or a new scheduled task) — the pipe name or RPC interface itself tells you which specific capability was invoked, and that's the detail that turns "SMB traffic between two workstations" into "someone remotely created and started a service on this machine."`,
      codeExample:
        "NAMED PIPE -> RPC INTERFACE -> WHAT IT DOES\n" +
        "=======================================================\n" +
        "\\PIPE\\svcctl    Service Control Manager -- create/start/\n" +
        "                 stop/delete services remotely (PsExec's\n" +
        "                 core mechanism)\n" +
        "\\PIPE\\atsvc      Task Scheduler RPC -- remote scheduled\n" +
        "                 task creation\n" +
        "\\PIPE\\wkssvc     Workstation service functions, incl.\n" +
        "                 remote session enumeration\n" +
        "\\PIPE\\epmapper   RPC endpoint mapper -- looks up which\n" +
        "                 dynamic port an RPC interface is on\n" +
        "=======================================================\n\n" +
        "PsExec, STEP BY STEP\n" +
        "=======================================================\n" +
        "1. Auth + connect to target's ADMIN$ share\n" +
        "2. Copy payload/PSEXESVC.exe into %SystemRoot% via ADMIN$\n" +
        "3. Connect to IPC$, open \\PIPE\\svcctl\n" +
        "4. RPC call: CreateService, then StartService\n" +
        "5. Target logs Event ID 7045 -- New Service Installed\n" +
        "   (ServiceName: PSEXESVC, ImagePath: %SystemRoot%\\\n" +
        "   PSEXESVC.exe -- these are the tool's REAL default\n" +
        "   values, not a fabricated \"hacker\" name)\n" +
        "=======================================================\n\n" +
        "WMI-BASED (Impacket wmiexec-style) LATERAL MOVEMENT\n" +
        "=======================================================\n" +
        "1. Connect to target TCP/135 (RPC endpoint mapper)\n" +
        "2. Get redirected to a dynamically-assigned high port\n" +
        "3. Win32_Process Create call launches the process remotely\n" +
        "4. NO new service artifact -- detection leans on Sysmon\n" +
        "   process creation: new process, parent = WmiPrvSE.exe\n" +
        "=======================================================",
      checkpoint: {
        question:
          "A hunt for remote execution relies only on Event ID 7045 (new service installed) across all workstations. Which of these techniques would the hunt miss?",
        options: [
          "PsExec run with its default settings, installing the PSEXESVC service",
          "WMI execution such as wmiexec, which calls Win32_Process Create",
          "PsExec with its service renamed to look like a software updater",
          "A custom tool creating and starting a service through \\PIPE\\svcctl",
        ],
        answer: 1,
        explanation:
          "WMI-based execution launches the process with a Win32_Process Create call over DCOM/RPC and never registers a service, so no 7045 is written; you catch it with process creation where WmiPrvSE.exe is the parent. “PsExec run with its default settings…” and “PsExec with its service renamed…” both create a service, so 7045 still fires, only with a different ServiceName. “A custom tool creating and starting a service…” uses the same Service Control Manager calls PsExec uses, so it also leaves a 7045.",
      },
    },

    // ── Question 1 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "winproto-q1",
      question:
        "You observe a Windows workstation (not a server, not a designated file/print server) accessing another workstation's IPC$ share and opening \\PIPE\\svcctl. What is the single most important contextual fact needed to judge how suspicious this is?",
      options: [
        "Whether SMB signing was enforced, since an unsigned session means the access was relayed",
        "Whether this account and source host match an approved admin workflow for that workstation",
        "Whether a 7045 followed, since svcctl access that creates no new service carries no risk",
        "Whether the target has SMBv1 enabled, since svcctl abuse depends on the EternalBlue flaw",
      ],
      answer: 1,
      explanation:
        "IPC$ and \\PIPE\\svcctl are used every day by remote administration, deployment tools and helpdesk workflows, so the deciding fact is context: is this a known admin account, from a known management host, doing expected work, or an unexplained account and peer pair. “Whether SMB signing was enforced…” confuses a precondition for relay with proof that relay happened. “Whether a 7045 followed…” is useful corroboration, but svcctl can also start, stop or reconfigure existing services without creating a new one. “Whether the target has SMBv1 enabled…” mixes in EternalBlue, an unauthenticated exploit; svcctl abuse needs only valid credentials.",
      xp: 25,
    },

    // ── Question 2 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "winproto-q2",
      question:
        "Domain controller logs show j.alvarez's only TGT request today (4768) came from 10.20.4.15, j.alvarez's usual workstation, at 08:02. At 10:41, 4769 service-ticket requests for j.alvarez arrive from 10.20.9.88 — a workstation j.alvarez has never used, which shows signs of separate compromise and has issued no 4768 for j.alvarez — and SRV-DATA07 records a matching 4624 (Kerberos, logon type 3) from 10.20.9.88. What does this pattern most strongly suggest?",
      options: [
        "Overpass-the-hash: j.alvarez's NTLM hash was used on 10.20.9.88 to get new Kerberos tickets",
        "Pass-the-Ticket: a ticket stolen from LSASS is replayed from a host that never requested it",
        "Kerberoasting: the 4769s from the new host are requests for crackable service tickets",
        "Normal roaming: j.alvarez logged on at another desk, and the DC reused the morning TGT",
      ],
      answer: 1,
      explanation:
        "A Kerberos ticket is not bound to the machine that requested it. The TGT came from 10.20.4.15, yet j.alvarez’s tickets are being used from 10.20.9.88, which issued no 4768 for the account: a ticket taken from LSASS and replayed elsewhere. “Overpass-the-hash…” would show a fresh 4768 from 10.20.9.88, because the hash is used to request a new TGT. “Kerberoasting…” is a burst of service-ticket requests across many SPNs for offline cracking, not a 4624 logon on a server with the user’s identity. “Normal roaming…” is wrong because a new interactive logon on another workstation requests its own TGT from that workstation.",
      xp: 25,
    },

    // ── Question 3 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "winproto-q3",
      question:
        "An LDAP query with the filter (&(objectClass=user)(servicePrincipalName=*)) is observed being run from a standard user's workstation account. Why does this specific filter matter for an investigator's next steps, even though the query itself requires no special privileges?",
      options: [
        "It lists AS-REP-roastable accounts, so next watch for 4768 requests with PreAuthType 0",
        "It lists accounts that have SPNs, the Kerberoasting target list, so watch for a 4769 burst",
        "It lists privileged accounts stamped by AdminSDHolder, so watch their logons closely next",
        "It is routine AD use, since any domain user is allowed to run it, so it needs no follow-up",
      ],
      answer: 1,
      explanation:
        "servicePrincipalName=* returns every account with an SPN, which is the list Kerberoasting works from, so the next thing to watch for is a burst of 4769 service-ticket requests from the same account. “It lists AS-REP-roastable accounts…” describes the userAccountControl filter for DONT_REQ_PREAUTH (4194304). “It lists privileged accounts stamped by AdminSDHolder…” describes (adminCount=1). “It is routine AD use…” confuses “allowed” with “harmless”: reconnaissance needs no special rights, which is exactly why a standard workstation account running it deserves follow-up.",
      xp: 25,
    },

    // ── Log Analysis 1: admin share / named pipe access ──────────────────────
    {
      type: "log_analysis" as const,
      id: "winproto-la1",
      heading: "Investigating Workstation-to-Workstation Named Pipe Access",
      context:
        "WKS-OPS31 is a standard operations-team workstation. It is not a designated jump host, and m.reyes's account is a regular domain user account, not a member of any IT administration group according to the last group-membership export. Review the event below, recorded on WKS-OPS31's own Security event log. Two seconds after it, WKS-OPS31's System log recorded Event ID 7045 (provider Service Control Manager) with ServiceName PSEXESVC, ImagePath %SystemRoot%\\PSEXESVC.exe, ServiceType user mode service, StartType demand start and AccountName LocalSystem.",
      event: adminShareEvent,
      questions: [
        {
          question:
            "The event shows ShareName '\\\\*\\IPC$' and RelativeTargetName 'svcctl', with SubjectUserName 'm.reyes' and IpAddress '10.40.6.90' (a different host than WKS-OPS31 itself). What does this combination of fields tell you was actually being accessed, and why does that matter?",
          options: [
            "m.reyes browsed a file share named IPC$ on WKS-OPS31 to read a document stored there",
            "10.40.6.90, as m.reyes, reached WKS-OPS31's Service Control Manager via svcctl on IPC$",
            "WKS-OPS31 connected out to 10.40.6.90's IPC$ share to manage services on that host",
            "10.40.6.90, as m.reyes, reached WKS-OPS31's Task Scheduler to create a remote task",
          ],
          answer: 1,
          explanation:
            "IPC$ has no files behind it; it carries named pipes, and RelativeTargetName svcctl is the Service Control Manager’s RPC interface, the pipe used to create and start services remotely. The record is on WKS-OPS31, so IpAddress 10.40.6.90 is the remote client. “m.reyes browsed a file share named IPC$…” treats IPC$ like a folder. “WKS-OPS31 connected out…” reverses the direction: 5145 is logged by the machine whose share was accessed. “…reached WKS-OPS31's Task Scheduler…” would be \\PIPE\\atsvc, not svcctl.",
          xp: 25,
        },
        {
          question:
            "Two seconds after the svcctl access, WKS-OPS31 logged the Event ID 7045 described in the context (ServiceName PSEXESVC, ImagePath %SystemRoot%\\PSEXESVC.exe). What does this record confirm?",
          options: [
            "Only that some installer added a service around then; it is unrelated to the svcctl access",
            "The svcctl session created a real new service, with the name and path PsExec uses by default",
            "That m.reyes ran PsExec locally on WKS-OPS31, since 7045 records the logged-on user's account",
            "A WMI-based execution, since a service created through svcctl is how wmiexec starts a process",
          ],
          answer: 1,
          explanation:
            "A 7045 two seconds after svcctl access is the next step of the PsExec mechanism from Reading 6: connect to IPC$, open svcctl, create and start a service. PSEXESVC and %SystemRoot%\\PSEXESVC.exe are PsExec’s real defaults. “Only that some installer added a service…” ignores the timing and the tool-specific name. “That m.reyes ran PsExec locally…” misreads the record: AccountName LocalSystem is the account the service runs as, not who logged on, and the 5145 shows the session came from 10.40.6.90. “A WMI-based execution…” is the other technique: wmiexec uses Win32_Process Create and leaves no 7045.",
          xp: 25,
        },
        {
          question:
            "Given that m.reyes is a regular domain user with no IT administration group membership, and WKS-OPS31 is a standard workstation (not a designated administrative jump host), what is the appropriate next step?",
          options: [
            "Close it: svcctl access plus a new service is normal Windows administration on any machine",
            "Check for an approved change; if none, treat it as lateral movement, scope 10.40.6.90, reset m.reyes",
            "Reimage WKS-OPS31 now: the service install alone confirms compromise, so evidence adds nothing",
            "Reset m.reyes's password and close, since the stolen account is all the attacker controls",
          ],
          answer: 1,
          explanation:
            "The same mechanism serves legitimate IT tooling and attackers, so you first look for an approved change or support session; with no IT role for m.reyes and no jump host involved, absent a ticket it is lateral movement, the source 10.40.6.90 needs its own investigation and m.reyes’s credentials are reset. “Close it…” ignores that the account and host have no administrative reason to do this. “Reimage WKS-OPS31 now…” destroys the evidence needed to scope what the service ran. “Reset m.reyes's password and close…” leaves the source host, where the credentials were most likely stolen, uninvestigated.",
          xp: 30,
        },
      ],
    },

    // ── Log Analysis 2: Kerberoasting sweep ──────────────────────────────────
    {
      type: "log_analysis" as const,
      id: "winproto-la2",
      heading: "A Rapid Sequence of Service Ticket Requests for Different SPNs",
      context:
        "m.reyes's account (the same account from the previous investigation) has been active on DC02 as well. In a two-minute window, DC02 logged 47 separate Kerberos service ticket requests from this account, for SPNs owned by 44 distinct service accounts (a 4769's ServiceName field records the account that owns the requested SPN) — 45 of the 47 came back RC4-HMAC (0x17) and 2 came back AES-256 (0x12). Review the representative event below, one of those 47 requests.",
      event: kerberoastSweepEvent,
      questions: [
        {
          question:
            "TicketEncryptionType on this sample is 0x17 (RC4-HMAC); across the sweep, 45 of 47 tickets were RC4 and 2 were AES-256 (0x12). What is the most defensible reading of the encryption types?",
          options: [
            "m.reyes's own account allows only RC4, so every ticket issued to m.reyes comes back as RC4",
            "RC4 may partly reflect legacy service accounts, but RC4 across a 44-account sweep fits roasting",
            "0x17 marks a failed request that the KDC retried with a weaker cipher after repeated attempts",
            "The 0x12 tickets are the suspicious ones, since attackers request AES to blend in with users",
          ],
          answer: 1,
          explanation:
            "The ticket’s encryption type depends on what the target service account supports, so some RC4 could come from legacy accounts without AES keys; but RC4 on almost every ticket in a two-minute sweep across 44 service accounts, in a domain where AES is clearly available, fits tooling that requests the faster-to-crack cipher. “m.reyes's own account allows only RC4…” looks at the wrong account: the requester’s settings do not choose the service ticket’s cipher. “0x17 marks a failed request…” misreads the log: Status 0x0 is success, and 0x17 is simply RC4-HMAC. “The 0x12 tickets are the suspicious ones…” inverts it: roasting tools prefer RC4 because it cracks far faster.",
          xp: 25,
        },
        {
          question:
            "47 requests covering 44 distinct service accounts is nearly one request per service. Why is this aggregate a stronger signal than the single request shown in the raw event?",
          options: [
            "It isn't: one RC4 ticket for a SQL service is already proof of roasting on its own",
            "One ticket for a service you use is normal; 44 different services in two minutes is harvesting",
            "It shows m.reyes is a service account, since only service accounts request many tickets at once",
            "It fits a user opening an intranet portal, which fetches tickets for every backend at once",
          ],
          answer: 1,
          explanation:
            "A single service-ticket request is everyday Kerberos; tickets for 44 different service accounts in two minutes has no normal user explanation and matches a tool working through a list of roastable SPNs, likely from the LDAP servicePrincipalName=* query. “It isn't…” over-reads one event: a single RC4 ticket can come from a legacy service account. “It shows m.reyes is a service account…” is contradicted by the context: m.reyes is a regular user. “It fits a user opening an intranet portal…” is the benign hypothesis that fails: the portal’s server fetches tickets for its backends, not the user’s workstation, and not dozens within two minutes.",
          xp: 25,
        },
        {
          question:
            "Given this is the SAME account (m.reyes) and likely the same compromised source (10.40.6.90) from the previous investigation, what should the analyst conclude and do?",
          options: [
            "Treat it as separate from the PsExec case, since Kerberos and SMB activity log on different hosts",
            "One incident: reset m.reyes, revoke its tickets, rotate the 44 targeted accounts, scope 10.40.6.90",
            "Rotate only sqlrpt_svc, the account in the sample event, since the others are not in the log",
            "Disable RC4 domain-wide and close, since without RC4 the captured tickets become useless",
          ],
          answer: 1,
          explanation:
            "Same account, same source, one escalating intrusion: lateral movement with PsExec and now a Kerberoasting sweep. Contain the identity (reset the password, revoke tickets and sessions), assume the 44 targeted service accounts’ tickets are being cracked offline and rotate them, and keep scoping 10.40.6.90. “Treat it as separate…” lets where events are logged split one attacker into two cases. “Rotate only sqlrpt_svc…” forgets that the sample is one of 47 requests. “Disable RC4 domain-wide and close…” is a sound hardening step later, but tickets already captured stay crackable and the compromised account is still in use.",
          xp: 30,
        },
      ],
    },

    // ── Analyst Choice: authorized helpdesk remote service install ──────────
    {
      type: "analyst_choice" as const,
      id: "winproto-ac1",
      heading: "Verdict: A Remote Service Installation During Business Hours",
      scenario:
        "A detection rule fired on IPC$/svcctl access followed by a new service installation, this time on WKS-ENG44, originating from 10.40.1.12. IT change records show 10.40.1.12 is the Helpdesk team's designated remote-support jump host, and the access occurred at 10:14 AM on a weekday, matching an open support ticket for a software installation on WKS-ENG44 submitted by that workstation's user earlier that morning. The follow-up record is a System log Event ID 7045 on WKS-ENG44: ServiceName SolvixDeployAgent, ImagePath C:\\ProgramData\\SolvixIT\\deploy_agent.exe, StartType demand start, AccountName LocalSystem.",
      event: {
        id: "evt-winproto-ac1-001",
        ts: "2026-05-13T10:14:22.000Z",
        source: "windows_security",
        vendor: "Windows Security",
        event_type: "privileged_operation",
        severity: "low",
        hostname: "WKS-ENG44.solvix.local",
        src_ip: "10.40.1.12",
        it_verify_result: "confirmed",
        it_verify_message: "10.40.1.12 is the Helpdesk remote-support jump host. Ticket #48221 requests a software install on WKS-ENG44, opened 09:02 the same morning by the workstation's assigned user.",
        description:
          "A remote session from 10.40.1.12 accessed WKS-ENG44's IPC$ share and svcctl pipe at 10:14 AM, followed by a service installation matching a deployment tool's expected footprint",
        authentication: { method: "Kerberos", result: "Success", logon_type: 3 },
        raw: {
          "event.code": "5145",
          "winlog.computer_name": "WKS-ENG44.solvix.local",
          "winlog.event_data.SubjectUserName": "helpdesk-svc",
          "winlog.event_data.SubjectDomainName": "SOLVIX",
          "winlog.event_data.IpAddress": "10.40.1.12",
          "winlog.event_data.ShareName": "\\\\*\\IPC$",
          "winlog.event_data.RelativeTargetName": "svcctl",
          "winlog.event_data.AccessMask": "0x120089",
          "winlog.event_id": 5145,
        },
      },
      correct_verdict: "false_positive",
      explanation:
        "Every raw technical detail here — IPC$/svcctl access, a new service installed via 7045 — matches the same mechanism seen in the malicious lateral-movement example earlier in this room, which is exactly why context, not the mechanism alone, determines the verdict. IT verification confirmed the context: the source (10.40.1.12) is the documented Helpdesk jump host, the account (helpdesk-svc) is a known IT service account with a legitimate administrative function, the timing (10:14 AM weekday) matches an open, user-submitted support ticket, and the installed service (SolvixDeployAgent, running from a known internal software-deployment path, not a generic tool like PSEXESVC) is consistent with the organization's own documented software deployment mechanism.",
      fp_trap:
        "IPC$/svcctl access followed by a new service installation is precisely the mechanism this room just taught you to treat as a strong lateral-movement indicator — and it's tempting to escalate any instance of it reflexively. But the room was equally explicit that this mechanism is also exactly how legitimate remote administration and software deployment work. The differentiators that actually separate this case from the earlier malicious one are the verified source host (a documented jump host vs. an unexplained peer workstation), the account (a known IT service account vs. a regular user with no admin role), the corroborating change ticket, and the installed service's identity (a named, known internal deployment tool vs. a generic remote-execution tool's default artifacts). Escalating purely on 'IPC$ + svcctl + 7045' without checking any of that context is exactly the kind of pattern-matching-without-verification that burns analyst time on legitimate IT operations.",
      xp: 30,
    },

    // ── Matching: lateral movement tool -> transport ─────────────────────────
    {
      type: "matching" as const,
      id: "winproto-m1",
      heading: "Match Each Remote-Access Technique to Its Underlying Transport",
      instructions: "Match each Windows remote-access/lateral-movement technique to the protocol/transport it actually rides on.",
      pairs: [
        { id: "psexec", left: "PsExec-style service execution", right: "SMB (ADMIN$ file copy, then IPC$ + \\PIPE\\svcctl RPC calls to the Service Control Manager)" },
        { id: "wmi", left: "WMI-based remote execution (e.g. Impacket wmiexec)", right: "DCOM/RPC — connects to TCP/135 (endpoint mapper) then a dynamically assigned high port; leaves no new-service artifact" },
        { id: "winrm", left: "WinRM / PowerShell Remoting", right: "HTTP or HTTPS on TCP 5985/5986" },
        { id: "rdp", left: "RDP (Remote Desktop Protocol)", right: "TCP 3389, full graphical session, not RPC/named-pipe based" },
        { id: "atsvc", left: "Remote scheduled task creation", right: "SMB named pipe \\PIPE\\atsvc, talking to the Task Scheduler RPC interface" },
        { id: "kerbrelay", left: "Kerberos service ticket presentation to a target service", right: "AP-REQ sent directly to the target service (not the KDC), verified using the service's own long-term key" },
      ],
      explanation:
        "Recognizing which transport a technique uses lets you predict exactly which log source will show evidence of it: SMB/named-pipe techniques (PsExec, scheduled tasks) leave IPC$ access and Event ID 7045/4698 artifacts; DCOM/RPC-based WMI execution leaves TCP/135 connections and Sysmon process-creation events with WmiPrvSE.exe as parent, but no service artifact; WinRM and RDP are entirely different transports altogether (HTTP-based and full graphical-session-based respectively) with their own distinct log signatures.",
      xp: 40,
    },

    // ── Ordering: Kerberos AS/TGS exchange for a normal service logon ────────
    {
      type: "ordering" as const,
      id: "winproto-o1",
      heading: "Order a Normal Kerberos Authentication and Service-Access Sequence",
      instructions: "Arrange these steps in the order they occur when a user authenticates to the domain and then accesses a specific service.",
      items: [
        { id: "asreq", text: "Client sends AS-REQ to the KDC, including PA-DATA (encrypted timestamp proving password knowledge)" },
        { id: "asrep", text: "KDC validates pre-authentication and replies with AS-REP, containing the TGT" },
        { id: "tgsreq", text: "Client sends TGS-REQ to the KDC, presenting the TGT and the target service's SPN" },
        { id: "tgsrep", text: "KDC validates the TGT and replies with TGS-REP, containing a service ticket encrypted with the target service account's key" },
        { id: "apreq", text: "Client sends AP-REQ directly to the target SERVICE (not the KDC), presenting the service ticket and a fresh authenticator" },
        { id: "granted", text: "The service decrypts the ticket with its own key, verifies the authenticator, and grants access" },
      ],
      correct_order: ["asreq", "asrep", "tgsreq", "tgsrep", "apreq", "granted"],
      explanation:
        "This is the complete normal Kerberos flow: prove password knowledge to get a TGT (AS-REQ/AS-REP), exchange that TGT for a specific service ticket (TGS-REQ/TGS-REP), then present that service ticket directly to the target service itself, not back to the KDC (AP-REQ). Every attack covered in this room targets a specific point in this sequence: Kerberoasting targets the TGS-REP's encryption, AS-REP roasting targets a version of the AS-REQ/AS-REP step with pre-authentication skipped, and Pass-the-Ticket skips the legitimate request process entirely by replaying an already-issued ticket.",
      xp: 35,
    },

    // ── Query Fill: KQL for detecting a Kerberoasting sweep ──────────────────
    {
      type: "query_fill" as const,
      id: "winproto-qf1",
      heading: "Write It Yourself: Detect a Kerberoasting Sweep in KQL",
      language: "kql",
      context: KQL_PRIMER +
        "Using the pattern confirmed in Log Analysis 2 (one account requesting RC4-encrypted service tickets for many distinct SPNs in a short window), write the KQL a detection engineer would deploy to catch this pattern across the whole domain. Team guidance for this rule: aggregate over a window of 2–15 minutes, and alert above a threshold somewhere between 5 and 30 distinct service accounts.",
      template:
        "SecurityEvent\n| where EventID == {{eventid}}\n| where TicketEncryptionType == \"{{enctype}}\"\n| summarize DistinctSPNs = dcount(ServiceName) by TargetAccount = Account, bin(TimeGenerated, {{window}})\n| where DistinctSPNs > {{threshold}}",
      blanks: [
        { id: "eventid", answers: ["4769"], placeholder: "Kerberos service ticket request Event ID" },
        { id: "enctype", answers: ["0x17"], placeholder: "RC4-HMAC encryption type value" },
        { id: "window", answers: ["2m", "3m", "4m", "5m", "6m", "7m", "8m", "9m", "10m", "11m", "12m", "13m", "14m", "15m", "2min", "3min", "5min", "10min", "15min", "120s", "180s", "300s", "600s", "900s"], placeholder: "aggregation window" },
        { id: "threshold", answers: ["5", "6", "7", "8", "9", "10", "12", "15", "20", "25", "30"], placeholder: "distinct-SPN count threshold" },
      ],
      explanation:
        "This mirrors the exact aggregate pattern you evaluated in Log Analysis 2: filter to 4769 (TGS-REQ/service ticket requests) that specifically obtained RC4-HMAC (0x17) — the encryption type Kerberoasting tooling favors — group by the requesting account within a short window, count distinct SPNs targeted, and alert when that count is far higher than any single legitimate application access pattern would ever produce. A production version of this rule would typically also exclude known, approved vulnerability-scanning or security-assessment service accounts to reduce noise from authorized testing.",
      xp: 35,
    },

    // ── Flag ──────────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "winproto-f1",
      prompt:
        "Look at Log Analysis 1, the admin-share investigation on WKS-OPS31. The 7045 record gives the service binary's path with an environment variable. On a default Windows installation, what full path did PsExec copy its service binary to? Enter the expanded path, e.g. C:\\Folder\\file.exe.",
      answer: "C:\\Windows\\PSEXESVC.exe",
      hint: "Reading 1 says which folder ADMIN$ and %SystemRoot% map to on a default installation.",
      xp: 25,
    },
  ],
};

export default [winProtoRoom];
