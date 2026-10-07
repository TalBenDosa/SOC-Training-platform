/**
 * Learning Rooms — Batch 18
 *
 * Closes a coverage gap found in an ATT&CK audit: Kerberoasting, AS-REP
 * roasting, Golden Ticket/DCSync, and NTLM relay were all practised in
 * scenarios with no room ever teaching Kerberos itself. These four rooms
 * teach the techniques the platform already asks students to investigate:
 *
 * - kerberos-authentication      — the AS/TGS exchange, encryption types,
 *   SPNs, Kerberoasting vs AS-REP roasting, overpass-the-hash, Golden/Silver
 *   tickets.
 * - windows-privilege-escalation — integrity levels, SeDebugPrivilege and
 *   LSASS access, UAC bypass (fodhelper), token manipulation, SeImpersonate
 *   and the Potato family, unquoted service paths.
 * - persistence-mechanisms       — Run keys, scheduled tasks/cron, services,
 *   BITS jobs, WMI event subscriptions, cloud/OAuth persistence, and why
 *   persistence changes containment order.
 * - web-application-attacks      — reading IIS/nginx access logs, SQL
 *   injection variants, path traversal/SSRF, web shells, WAF log limits.
 */

import type { Room } from "@/data/rooms";
import { KQL_PRIMER } from "@/data/kqlPrimer";
import type { TelemetryEvent } from "@/lib/sim/types";

// =============================================================================
// ROOM 1: kerberos-authentication
// =============================================================================

const kerberoastEvent: TelemetryEvent = {
  id: "evt-krb-la1-001",
  ts: "2026-04-02T03:11:07.000Z",
  source: "ad",
  vendor: "Windows Security",
  event_type: "kerberos_tgs",
  severity: "high",
  hostname: "DC02.meridian.local",
  description:
    "DC02 recorded a Kerberos TGS-REQ for service principal HTTPRpt/rpt04.meridian.local, requested under account k.alvarez; this is one of a run of similar requests from the same requesting account within a three-minute window.",
  // TargetUserName on a real 4769 is the account that REQUESTED the ticket —
  // there is no separate field for that; the sibling events below (the 4768
  // and the legitimate 4769) already use it that way. A `RequestorName` field
  // and 180-second aggregate counters do not exist on this event type at all —
  // 4769 is one ticket, not a window. The volume is stated in `context`
  // instead, which is where a SIEM's correlation summary belongs.
  raw: {
    "event.code": "4769",
    "winlog.channel": "Security",
    "winlog.computer_name": "DC02.meridian.local",
    "winlog.event_data.TargetUserName": "k.alvarez",
    "winlog.event_data.TargetDomainName": "MERIDIAN.LOCAL",
    "winlog.event_data.ServiceName": "HTTPRpt/rpt04.meridian.local",
    "winlog.event_data.TicketEncryptionType": "0x17",
    "winlog.event_data.TicketOptions": "0x40810000",
    "winlog.event_data.Status": "0x0",
    "winlog.event_data.IpAddress": "10.55.14.203",
    "winlog.event_data.IpPort": "0",
    "winlog.event_id": 4769,
  },
};

const asrepRoastEvent: TelemetryEvent = {
  id: "evt-krb-la2-001",
  ts: "2026-04-05T22:47:51.000Z",
  source: "ad",
  vendor: "Windows Security",
  event_type: "kerberos_tgt",
  severity: "high",
  hostname: "DC01.meridian.local",
  description:
    "DC01 recorded a Kerberos AS-REQ/AS-REP exchange for account svc_reports; no failed pre-authentication attempt precedes it, and the request originated from a workstation IP not previously associated with this account.",
  raw: {
    "event.code": "4768",
    "winlog.channel": "Security",
    "winlog.computer_name": "DC01.meridian.local",
    "winlog.event_data.TargetUserName": "svc_reports",
    "winlog.event_data.TargetDomainName": "MERIDIAN.LOCAL",
    "winlog.event_data.TicketEncryptionType": "0x17",
    "winlog.event_data.PreAuthType": "0",
    "winlog.event_data.Status": "0x0",
    "winlog.event_data.IpAddress": "10.55.2.211",
    "winlog.event_data.IpPort": "0",
    "winlog.event_id": 4768,
  },
};

const rc4LegacyBackupEvent: TelemetryEvent = {
  id: "evt-krb-ac1-001",
  ts: "2026-04-03T03:00:12.000Z",
  source: "ad",
  vendor: "Windows Security",
  event_type: "kerberos_tgs",
  severity: "low",
  hostname: "DC01.meridian.local",
  description:
    "DC01 recorded a Kerberos TGS-REQ for the cifs/nas02.meridian.local service, requested under account svc_nasbackup; this account requests this same service once daily at 03:00 as part of the scheduled backup job.",
  it_verify_result: "confirmed",
  it_verify_message:
    "Change ticket CHG-88213 confirms nas02's backup appliance firmware only implements RC4-HMAC Kerberos and cannot be upgraded until the vendor's next major release.",
  raw: {
    "event.code": "4769",
    "winlog.channel": "Security",
    "winlog.computer_name": "DC01.meridian.local",
    "winlog.event_data.TargetUserName": "svc_nasbackup",
    "winlog.event_data.TargetDomainName": "MERIDIAN.LOCAL",
    "winlog.event_data.ServiceName": "cifs/nas02.meridian.local",
    "winlog.event_data.TicketEncryptionType": "0x17",
    "winlog.event_data.TicketOptions": "0x40810000",
    "winlog.event_data.Status": "0x0",
    "winlog.event_data.IpAddress": "10.55.2.44",
    "winlog.event_data.IpPort": "0",
    "winlog.event_id": 4769,
  },
};

const kerberosRoom: Room = {
  id: "kerberos-authentication",
  title: "Kerberos & Windows Authentication Deep Dive",
  description:
    "Move past 'Kerberos issues tickets' into the mechanics an analyst actually needs: the full AS-REQ/AS-REP/TGS-REQ/TGS-REP exchange, the difference between a TGT and a TGS and exactly which Event IDs and which host logs each, why encryption type is a downgrade signal, why any authenticated user can request a ticket for any Service Principal Name, and how that single fact separates Kerberoasting from AS-REP roasting, overpass-the-hash, and Golden and Silver tickets.",
  difficulty: "advanced",
  category: "Identity",
  estimatedMinutes: 70,
  xp: 390,
  icon: "🎫",
  prerequisites: ["active-directory"],
  tasks: [
    {
      type: "reading",
      id: "krb-r1",
      heading: "The Kerberos Exchange: AS-REQ, AS-REP, TGS-REQ, TGS-REP",
      content:
        `**Why a second Kerberos room, if you already covered this in active-directory?** The active-directory room introduced Kerberos at foundation level. Enough to recognize a TGT and a TGS, and to know that Event IDs 4768 and 4769 mean "ticket issued." That was necessary, but it stops well short of what an analyst needs to actually investigate an attack. This room assumes that foundation and goes to the depth the platform's own scenarios require: exactly which field in a 4769 tells you the ticket's encryption downgraded, why any authenticated domain user can request a service ticket for any Service Principal Name (the fact Kerberoasting depends on), how AS-REP roasting differs from Kerberoasting even though both "roast" a ticket offline, and how Golden and Silver tickets are forged without a real request ever reaching a Domain Controller. If the terms TGT, TGS, and 4768/4769 already feel completely comfortable, skim Readings 1 and 2 rather than skipping them outright: the rest of this room builds directly on the exact wording used here, not just the general idea.\n\n` +
        `Kerberos is the default authentication protocol in Windows domains, and almost every credential-theft technique you will investigate is an attack on one specific step of a four-message exchange. Getting that exchange exactly right is worth more than any amount of memorized Event IDs, because the Event IDs only make sense once you know which message they represent.\n\n` +
        `**The two-phase design**\n\n` +
        `A client never sends its password over the network. Instead it proves identity to a Key Distribution Center (KDC) (a role every Domain Controller (DC) performs) and receives tickets it can present later. The exchange happens in two phases. Phase one, the Authentication Service (AS) exchange, gets the client a Ticket Granting Ticket (TGT): proof to the KDC itself that the client already authenticated once. Phase two, the Ticket Granting Service (TGS) exchange, uses that TGT to get a service ticket (a TGS) for one specific service, without the client ever re-entering a password.\n\n` +
        `**Message by message**\n\n` +
        `AS-REQ: the client sends its username and, in a normal modern configuration, a timestamp encrypted with a key derived from its own password (this is what "pre-authentication" means, proving you know the password before the KDC will hand out anything). AS-REP: the KDC decrypts that timestamp with its own copy of the user's key to confirm it, then returns a TGT (encrypted with a key derived from the krbtgt account's password, a key only the KDC holds) plus a session key, itself encrypted with the client's key so only the real client can read it. TGS-REQ: later, when the client needs to reach a specific service, it presents the TGT back to the KDC along with the name of the service it wants (a Service Principal Name, covered in Reading 4). TGS-REP: the KDC returns a TGS, a ticket encrypted with a key derived from the target service account's own password, not the client's. AP-REQ: the client finally presents that TGS directly to the service, which decrypts it with its own key to validate the client and grant access.\n\n` +
        `**The detail that explains almost every attack in this room**\n\n` +
        `Notice that the target service in the last step never talks to the KDC to confirm the ticket. It trusts the ticket purely because the ticket decrypts correctly with the key the service already holds. If an attacker ever obtains that key directly (the service account's password hash, or worse, the krbtgt account's hash) they can construct a valid-looking ticket entirely offline, without a real AS-REQ or TGS-REQ ever touching a Domain Controller. That single design fact is exactly what makes Golden and Silver tickets possible, and it's why this reading is worth re-reading before Reading 6.`,
      diagram:
        "sequenceDiagram\n" +
        "  participant C as Client\n" +
        "  participant KDC as KDC (Domain Controller)\n" +
        "  participant S as Service (SPN owner)\n" +
        "  C->>KDC: AS-REQ (username + timestamp encrypted with user's key)\n" +
        "  KDC-->>C: AS-REP (TGT encrypted with krbtgt hash + session key encrypted with user's key)\n" +
        "  Note over C: Client now holds a TGT, proof it already authenticated once\n" +
        "  C->>KDC: TGS-REQ (present TGT, ask for a ticket to a specific SPN)\n" +
        "  KDC-->>C: TGS-REP (TGS encrypted with the SPN's service account hash)\n" +
        "  C->>S: AP-REQ (present the TGS)\n" +
        "  S-->>C: AP-REP (service decrypts TGS with its own key, grants access)\n" +
        "  Note over S: The service never asks the KDC to confirm the ticket. It trusts its own decryption",
      diagramCaption: "The Kerberos AS/TGS exchange",
      checkpoint: {
        question:
          "A client has just completed the AS exchange and has not yet contacted any service. What does it now hold?",
        options: [
          "A service ticket for the first SPN the user will need that day",
          "A TGT encrypted with the krbtgt key, plus a session key it can read",
          "A TGT encrypted with the user's own key, so the client can read it",
          "Only a session key: the TGT itself is issued in the TGS exchange",
        ],
        answer: 1,
        explanation:
          "The AS-REP returns a TGT encrypted with the krbtgt-derived key (only the KDC can read it) and a session key encrypted with the client's key. “Encrypted with the user's own key” mixes up the two parts: only the session key is wrapped with the user's key, the TGT is opaque to the client. “A service ticket” comes later, from the TGS exchange, one per SPN. “Only a session key” reverses the phases: the TGT is the product of the AS exchange and is what the client presents in the TGS-REQ.",
      },
    },
    {
      type: "reading",
      id: "krb-r2",
      heading: "TGT vs TGS, and Exactly Which Host Logs What",
      content:
        `Confusing a TGT with a TGS is the single most common terminology error in Kerberos investigations, and it changes which Event ID and which host you should be pulling logs from.\n\n` +
        `**Where each ticket lives in the exchange**\n\n` +
        `A TGT (Ticket Granting Ticket) is issued once per logon session by the AS-REQ/AS-REP pair and is reusable: the client presents it repeatedly to request tickets for as many different services as it needs, without re-entering credentials, until the TGT expires (10 hours by default). A TGS (Ticket Granting Service ticket, often just called a "service ticket") is issued per service, one TGS-REQ/TGS-REP pair for each distinct SPN the client wants to reach.\n\n` +
        `**The Event IDs, and who logs them**\n\n` +
        `Every one of these authentication events is logged on the Domain Controller performing the KDC role, because the KDC is the only party that ever sees the AS-REQ/AS-REP and TGS-REQ/TGS-REP messages. Event 4768 is logged for every AS-REQ/AS-REP pair: a TGT being issued. Event 4769 is logged for every TGS-REQ/TGS-REP pair: a service ticket being issued, and this is the event Kerberoasting produces. Event 4771 is logged when Kerberos pre-authentication fails (wrong password on an AS-REQ), the Kerberos equivalent of a failed logon. Event 4776 is a different protocol entirely. It is logged when a Domain Controller validates NTLM credentials, not Kerberos ones, and its appearance where Kerberos was expected is itself a signal covered later in this room.\n\n` +
        `**What the target service host logs, and does not**\n\n` +
        `The service the client is actually trying to reach (a file server, a SQL server, a web application) does not independently verify a TGS against the KDC at all. It trusts its own successful decryption of the ticket using its own account's key. What it does log, once the AP-REQ is validated, is a normal Windows logon event, most commonly Event 4624 with AuthenticationPackageName: Kerberos and a LogonType matching how the client connected (3 for a network logon, 10 for RDP, and so on). That 4624 on the target server tells you a session was established; it tells you nothing at all about how the ticket that authorized it was obtained, for that, you always have to go back to the Domain Controller's 4768/4769 pair.`,
      codeExample:
        "WHICH HOST LOGS WHICH KERBEROS EVENT\n" +
        "=======================================================\n" +
        "Domain Controller (the KDC) logs:\n" +
        "  4768   AS-REQ/AS-REP      -- TGT issued\n" +
        "  4769   TGS-REQ/TGS-REP    -- TGS (service ticket) issued\n" +
        "  4771   Pre-authentication failed\n" +
        "  4776   NTLM validation (NOT Kerberos -- different protocol)\n" +
        "\n" +
        "Target service host logs:\n" +
        "  4624   Logon succeeded, AuthenticationPackageName: Kerberos\n" +
        "         (confirms a session was established -- says nothing\n" +
        "          about how the presented ticket was originally obtained)\n" +
        "=======================================================",
    },
    {
      type: "question",
      id: "krb-q1",
      question:
        "To investigate a suspicious file-server session, an analyst searches the Security logs of EVERY Domain Controller in the domain (Kerberos auditing confirmed on each) across the full ticket lifetime, and finds no 4768 or 4769 for the account. Where should the investigation go next?",
      options: [
        "No KDC issued a ticket: check the file server's 4624 for NTLM, or suspect a ticket forged offline",
        "Another DC probably issued the ticket, so the next step is to widen the search to the other DCs",
        "Search the DCs for 4771 instead, because a successful smart-card logon is recorded under that ID",
        "Search the file server for 4769, because the service host records the TGS it was presented with",
      ],
      answer: 0,
      explanation:
        "4768/4769 are written only by the DC acting as KDC, so with every DC searched and auditing confirmed, no KDC issued this ticket: either the session did not use Kerberos (check the file server's own 4624 AuthenticationPackageName for NTLM) or it used a forged ticket that never touched a KDC (Reading 6). “Another DC probably issued it” is normally the right first check in a multi-DC domain, but the stem says every DC was already searched. “Search for 4771” misreads that event: it records a FAILED pre-authentication, not a successful logon. “Search the file server for 4769” is wrong because the service host logs a 4624 when it accepts a ticket; 4769 exists only on the KDC.",
      xp: 20,
    },
    {
      type: "reading",
      id: "krb-r3",
      heading: "Encryption Types: 0x12 vs 0x17, and Why a Downgrade Is the Signal",
      content:
        `Every Kerberos ticket specifies an encryption type, and the value recorded in TicketEncryptionType is one of the highest-value single fields in any Kerberos log, because it tells you not just how the ticket was protected, but how expensive it would be for an attacker to break that protection offline.\n\n` +
        `**The values you'll actually see**\n\n` +
        `0x12 is AES256-CTS-HMAC-SHA1-96: the modern default in any domain running Windows Server 2008 or later with default settings, and the strongest commonly-seen type. 0x11 is its AES128 sibling, less common but not itself alarming. 0x17 is RC4-HMAC: an older, much weaker cipher that Windows still supports for backward compatibility with legacy applications and operating systems. 0x1 and 0x3 (DES variants) are effectively extinct in a modern domain and their presence at all is worth investigating regardless of context.\n\n` +
        `**Why RC4 specifically matters for offline cracking**\n\n` +
        `A TGS is encrypted with a key derived from the target service account's password. If an attacker captures that ticket, they can attempt to crack it offline, guessing passwords until one produces a key that correctly decrypts the ticket. AES256's key derivation involves substantially more computational work per guess than RC4-HMAC's, whose key is derived far more directly from the account's NTLM hash. In practice this means an RC4-encrypted ticket can be cracked orders of magnitude faster than the same password protected by AES256, which is precisely why every mainstream Kerberoasting tool explicitly requests RC4 tickets when it can, rather than accepting whatever a domain controller would offer by default.\n\n` +
        `**Reading the field as a downgrade, not a default**\n\n` +
        `Each account has an msDS-SupportedEncryptionTypes attribute controlling which encryption types the KDC will issue for it. In an environment where every account is correctly configured to support and prefer AES, RC4 should almost never appear in a 4769 at all: a client requesting it anyway is deliberately asking for the weaker option because a request can specify supported encryption types in its own message. Seeing 0x17 where the environment's baseline is AES-only is not a coincidence of legacy configuration; it's the request explicitly asking to be given the crackable version, and that is the signal, not the encryption type by itself. The next reading gives you the mechanism that makes requesting a ticket for any service at all so easy in the first place.`,
      codeExample:
        "KERBEROS TICKET ENCRYPTION TYPES\n" +
        "=======================================================\n" +
        "0x12   AES256-CTS-HMAC-SHA1-96   Modern default, strong\n" +
        "0x11   AES128-CTS-HMAC-SHA1-96   Modern, less common\n" +
        "0x17   RC4-HMAC                  Legacy, weak -- fast offline cracking\n" +
        "0x1/0x3 DES-CBC-CRC / DES-CBC-MD5 Effectively extinct, always worth a look\n" +
        "=======================================================\n\n" +
        "WHY RC4 IS THE KERBEROASTING TOOL'S PREFERRED TARGET\n" +
        "=======================================================\n" +
        "RC4-HMAC key   <- derived almost directly from the account's\n" +
        "                  NTLM hash -- cheap to test each password guess\n" +
        "AES256 key     <- derived with far more per-guess computation\n" +
        "                  -- the same password takes vastly longer to crack\n" +
        "=======================================================",
      checkpoint: {
        question:
          "Kerberoasting tools ask the KDC for 0x17 tickets even in domains that default to 0x12. What do they gain from that request?",
        options: [
          "RC4 tickets skip the service-account key, so no cracking step is needed",
          "The KDC logs RC4 requests under 4768, so the sweep avoids 4769 alerts",
          "Each password guess against an RC4 ticket is far cheaper than against AES",
          "RC4 tickets use the requester's key, which the attacker already knows",
        ],
        answer: 2,
        explanation:
          "0x17 is RC4-HMAC, whose key derives almost directly from the account's NTLM hash, so testing each guess costs far less than against AES256 (0x12): the same password cracks orders of magnitude faster. “Skip the service-account key” and “use the requester's key” are both wrong: every TGS, whatever its cipher, is encrypted with the target service account's key, which is the whole reason it is worth cracking. “Logs RC4 requests under 4768” is wrong because the event ID reflects the message type (4769 for any TGS), not the cipher: the RC4 value appears in that 4769's TicketEncryptionType field.",
      },
    },
    {
      type: "reading",
      id: "krb-r4",
      heading: "Service Principal Names, and Why Any User Can Request a Ticket for One",
      content:
        `A Service Principal Name (SPN) is the identifier a Kerberos client uses to name the specific service it wants a ticket for: a string like HTTPRpt/rpt04.meridian.local or MSSQLSvc/sqlsrv01.meridian.local:1433, registered against whichever account (a computer account or, very often, a service account) actually runs that service. Understanding what SPNs are for is what makes Kerberoasting make sense as "not really a hack at all" in the technical sense. It abuses a feature working exactly as designed.\n\n` +
        `**Why the protocol has to allow this**\n\n` +
        `For the TGS-REQ/TGS-REP step to work at all, the KDC has to be willing to issue a service ticket to any authenticated client that names a valid, registered SPN. That's the entire point of the step. There is no additional authorization check the KDC performs before issuing the ticket beyond "does this SPN exist, and does the requesting client hold a valid TGT." No group membership, no access-control list, no relationship between the requesting user and the target service is checked at this stage. That authorization happens later, when the service itself decides what the presented identity is allowed to do. This means literally any authenticated domain user, with zero special privileges, can request, and receive, a TGS for any SPN registered anywhere in the domain, including SPNs registered to service accounts they have no legitimate reason to ever talk to.\n\n` +
        `**What that ticket is actually worth to an attacker**\n\n` +
        `The TGS the KDC hands back is encrypted with a key derived from the target service account's own password, not the requesting user's. The requesting user can't read the ticket's contents, but they can take it home and try to crack the encryption offline, attempting password guesses against it with no further interaction with the domain (and, critically, no further audit trail: the DC already logged one legitimate-looking 4769 and has nothing further to say once the ticket leaves). If the service account's password is weak, the attacker recovers it entirely offline. This is Kerberoasting in full: request tickets for every SPN you can enumerate (a simple, unprivileged LDAP query), then crack them at your leisure. The only thing standing between "any user can request this" and "the domain is compromised" is whether the accounts behind those SPNs (very often legacy service accounts with long-unrotated, weak passwords) can survive an offline cracking attempt.`,
      codeExample:
        "AN SPN, DECOMPOSED\n" +
        "=======================================================\n" +
        "HTTPRpt/rpt04.meridian.local\n" +
        "  ^^^^^^^  ^^^^^^^^^^^^^^^^^^\n" +
        "  service  hostname the service runs on\n" +
        "  class\n" +
        "\n" +
        "Registered against an account (often a service account, e.g.\n" +
        "svc_reporting) via setspn -- that account's password is what\n" +
        "encrypts every TGS issued for this SPN.\n" +
        "=======================================================\n\n" +
        "THE KDC's ONLY CHECK BEFORE ISSUING A TGS\n" +
        "=======================================================\n" +
        "1. Does the requesting client hold a valid TGT?      -- yes/no\n" +
        "2. Does the requested SPN exist in the domain?        -- yes/no\n" +
        "   (NO check on whether this user has any business\n" +
        "    reason to talk to this specific service)\n" +
        "=======================================================",
    },
    {
      type: "question",
      id: "krb-q2",
      question:
        "A junior analyst says 'this can't be Kerberoasting: the requesting user, k.alvarez, has no group membership or ACL entry granting them access to the SQL service they requested a ticket for.' Why does this reasoning not rule out Kerberoasting?",
      options: [
        "Kerberoasting needs no TGT or domain account at all, so k.alvarez's rights on the SQL service never come into play",
        "The KDC issues a TGS for any existing SPN to any TGT holder; access is checked at the service, which a cracker never contacts",
        "The KDC compares the requester's groups with the service ACL, so a successful 4769 proves k.alvarez had access",
        "A user who is a local admin on the SQL host can request its tickets, so k.alvarez must hold rights on that server",
      ],
      answer: 1,
      explanation:
        "Reading 4: before issuing a TGS the KDC checks only that the SPN exists and the requester holds a valid TGT; authorization is the service's job, and a Kerberoaster never presents the ticket to the service, they crack it offline. “Needs no TGT or domain account” describes AS-REP roasting, not Kerberoasting, which does need a valid TGT. “Compares the requester's groups with the service ACL” and “must hold rights on that server” both invent an authorization step the KDC does not perform at TGS-REQ time, so a successful 4769 proves nothing about access.",
      xp: 20,
    },
    {
      type: "reading",
      id: "krb-r5",
      heading: "Kerberoasting vs AS-REP Roasting: Two Attacks That Look Similar and Aren't",
      content:
        `Kerberoasting and AS-REP roasting are frequently confused because both end the same way (an attacker walking away with an offline-crackable, Kerberos-encrypted blob) but they target completely different steps of the exchange, need different preconditions, and produce different Event IDs. Telling them apart correctly is worth practicing deliberately, because the wrong diagnosis sends you looking at the wrong accounts.\n\n` +
        `**Kerberoasting (T1558.003), attacking the TGS-REP**\n\n` +
        `As Reading 4 covered, any authenticated user can request a TGS for any registered SPN, and that TGS is encrypted with the target service account's password-derived key. Kerberoasting is requesting TGS tickets (often many, across every SPN the attacker can enumerate) and cracking them offline. It requires the attacker to already have valid domain credentials (any account will do, since the check is "do you hold a TGT," not "are you privileged"), and it produces 4769 events, one per SPN requested, very often in a tight burst against many distinct service names, frequently with the RC4 downgrade from Reading 3.\n\n` +
        `**AS-REP Roasting (T1558.004), attacking the AS-REP, before pre-auth even happens**\n\n` +
        `Recall from Reading 1 that pre-authentication means proving you know the account's password before the KDC will issue an AS-REP at all: the client encrypts a timestamp with a key derived from the password, and the KDC only replies if it decrypts correctly. Some accounts have the "Do not require Kerberos preauthentication" flag set (DONT_REQ_PREAUTH), sometimes deliberately, for compatibility with older Kerberos implementations that don't support pre-auth, but often as an overlooked misconfiguration. For those accounts, the KDC will hand back an AS-REP (including the encrypted portion an attacker can crack offline to recover the password) to anyone who simply asks for a TGT by username, with no proof of any password at all. This requires zero valid domain credentials: an unauthenticated attacker who only knows (or guesses, by enumerating usernames) that an account exists and has this flag set can pull a crackable AS-REP. It produces a single 4768, with PreAuthType: 0 (normal successful pre-authenticated logons show PreAuthType: 2), no 4771 failure ever appears, because pre-authentication was never attempted, not attempted and failed.\n\n` +
        `**The precondition is the fastest way to tell them apart**\n\n` +
        `If you're looking at a 4769 for a service account's SPN, you're looking at Kerberoasting, and the attacker already had valid domain credentials of some kind. If you're looking at a 4768 with PreAuthType: 0 and no prior successful authentication from that source, you're looking at AS-REP roasting, and the attacker may not have needed any valid credentials at all, which makes it, if anything, the more dangerous of the two to leave unaddressed.`,
      codeExample:
        "KERBEROASTING vs AS-REP ROASTING -- SIDE BY SIDE\n" +
        "=======================================================\n" +
        "                    Kerberoasting        AS-REP Roasting\n" +
        "-------------------------------------------------------\n" +
        "ATT&CK ID           T1558.003            T1558.004\n" +
        "Event ID             4769 (TGS-REQ)        4768 (AS-REQ)\n" +
        "Attacks              TGS-REP               AS-REP\n" +
        "Encrypted with        Service account's      Target account's\n" +
        "                      password-derived key    password-derived key\n" +
        "Key tell               ServiceName + RC4       PreAuthType: 0\n" +
        "                        (0x17), high volume     (normal is 2)\n" +
        "Requires attacker      YES -- any valid TGT     NO -- account must\n" +
        "to already hold                                  merely have preauth\n" +
        "valid credentials?                               disabled\n" +
        "=======================================================",
      checkpoint: {
        question:
          "An attacker AS-REP roasts svc_legacyftp and later cracks the blob offline. Whose password have they recovered?",
        options: [
          "krbtgt's: the TGT inside every AS-REP is encrypted with the krbtgt key",
          "svc_legacyftp's: the crackable AS-REP part uses that account's own key",
          "The requesting user's: an AS-REP is always encrypted for whoever asked",
          "The service account's behind whichever SPN the attacker named in the request",
        ],
        answer: 1,
        explanation:
          "The crackable portion of an AS-REP is encrypted with the TARGET account's password-derived key (Reading 1's session key; Reading 5's side-by-side table), so cracking it yields svc_legacyftp's password. “krbtgt's” is a real part of the AS-REP, the TGT is krbtgt-encrypted, but that key is far too strong to crack and is not what roasting targets. “The requesting user's” fails because in AS-REP roasting the attacker asks for a TGT in the target's name, needing no account of their own. “The SPN's service account” describes Kerberoasting, which attacks the TGS-REP, not the AS-REP.",
      },
    },
    {
      type: "log_analysis",
      id: "krb-la1",
      heading: "Investigating a Burst of TGS Requests",
      context:
        "DC02 flagged an unusual volume of Kerberos service-ticket activity from account k.alvarez, a marketing analyst with no known reason to touch reporting or database infrastructure. In the three minutes before this sample event, the account made 63 TGS requests covering 59 distinct services. Review the representative 4769 record below.",
      event: kerberoastEvent,
      questions: [
        {
          question:
            "TargetUserName (the requesting account on a 4769) is 'k.alvarez', TicketEncryptionType is 0x17 (RC4), Status is 0x0 (success), and per the SIEM correlation noted above this account requested 59 distinct SPNs in the preceding three minutes. What does this combination indicate?",
          options: [
            "Overpass-the-hash: an RC4 ticket in an AES domain shows k.alvarez's NTLM hash was used to log on",
            "Kerberoasting: one account pulled RC4 service tickets for 59 SPNs it has no business need for",
            "Routine logon behaviour: a client fetching tickets for mapped drives and apps as the session starts",
            "Nothing captured yet: the tickets are encrypted, so no secret has left the KDC until cracking is seen",
          ],
          answer: 1,
          explanation:
            "A successful (Status 0x0) RC4 TGS for 59 distinct SPNs in three minutes from one account with no business need is the Kerberoasting fingerprint from Reading 5. “Overpass-the-hash” is the confusable one: its RC4 tell appears on a 4768 (a TGT), whereas this is a 4769 for a service ticket, and overpass does not explain the breadth across 59 SPNs. “Routine logon behaviour” does not fit 59 unrelated services at 03:11 for a marketing analyst, nor RC4 in an AES baseline. “Nothing captured yet” misunderstands the attack: the issued ticket IS the captured material, crackable offline with no further contact with the domain.",
          xp: 25,
        },
        {
          question:
            "Using only the fields in this 4769, which value tells you whose password the attacker can now attempt to crack offline?",
          options: [
            "TargetUserName (k.alvarez): the TGS is encrypted with the requesting account's key",
            "ServiceName (HTTPRpt/rpt04): the TGS uses the key of the account that owns that SPN",
            "TicketEncryptionType (0x17): RC4 tickets are encrypted with the domain's NTLM key",
            "None of its fields: every TGS is encrypted with krbtgt, so only krbtgt is exposed",
          ],
          answer: 1,
          explanation:
            "A TGS is encrypted with a key derived from the password of the account the SPN is registered to, so ServiceName points you to the exposed account. Here the service account behind HTTPRpt/rpt04 (svc_reporting in Reading 4's example); you resolve it with an SPN lookup. “TargetUserName” is the requester on a 4769; k.alvarez's own key never protects the service ticket. “TicketEncryptionType” tells you how cheap cracking will be, not whose key it is. There is no domain-wide NTLM key. “Every TGS is encrypted with krbtgt” confuses the TGS with the TGT, which is the krbtgt-encrypted one.",
          xp: 25,
        },
        {
          question:
            "What is the correct response given this pattern?",
          options: [
            "Reset k.alvarez's password and close: the requesting account is the one whose secret was exposed",
            "Rotate the roasted service accounts' passwords, find the tool on k.alvarez's host, and curb RC4 use",
            "Rotate krbtgt twice: a burst of service tickets like this means the domain-wide key is exposed",
            "Disable k.alvarez and wait: rotate nothing until a cracked password is actually seen in use",
          ],
          answer: 1,
          explanation:
            "The tickets are encrypted with the service accounts' keys, so their passwords (svc_reporting first, then the other weak ones among the 59 SPNs) must be rotated before cracking finishes; the host needs investigating for the tooling, and msDS-SupportedEncryptionTypes should be tightened to stop RC4 downgrades. “Reset k.alvarez's password” protects the wrong secret (the requester's key never encrypted these tickets) though the account does need investigating as compromised. “Rotate krbtgt twice” is the Golden Ticket response; nothing here exposes krbtgt. “Wait until a cracked password is seen” is the wrong timing: offline cracking leaves no trail, so by the time you see the password used, the attacker already has it.",
          xp: 30,
        },
      ],
    },
    {
      type: "reading",
      id: "krb-r6",
      heading: "Overpass-the-Hash, and Why Golden and Silver Tickets Skip the KDC Entirely",
      content:
        `The three techniques in this reading share one property: none of them require the attacker to ever know a plaintext password. Each takes a different piece of stolen key material and uses it to shortcut a different part of the exchange from Reading 1.\n\n` +
        `**Overpass-the-hash (T1550.002), turning a stolen NTLM hash into a real TGT**\n\n` +
        `An attacker who has dumped an account's NTLM hash (from LSASS memory, as covered in the privilege-escalation room) can use that hash directly as the key material for a normal AS-REQ, rather than needing the actual password. The KDC has no way to distinguish "a client that encrypted its timestamp using a key derived from the real password" from "a client that encrypted its timestamp using a key derived from the hash of that password": the math produces the same key either way. This still produces a completely ordinary-looking 4768 on the DC. The one consistent tell: because an NTLM hash alone doesn't contain the additional salting information AES key derivation requires (which comes from the actual password plus account-specific data, not the hash), a TGT obtained this way is very often requested and issued with RC4 encryption even in an otherwise AES-only environment, the same downgrade signal from Reading 3, but this time on a TGT rather than a TGS.\n\n` +
        `**Golden Ticket, forging a TGT entirely offline**\n\n` +
        `Recall from Reading 1 that a TGT is encrypted with a key derived from the krbtgt account's password: a single account shared by the whole domain to protect every TGT it issues. An attacker who has ever obtained the krbtgt hash (typically via a DCSync-style replication abuse, covered in your Active Directory room) can forge a completely valid-looking TGT for any user, including one that doesn't exist, entirely on their own machine, with no AS-REQ ever sent to a Domain Controller. When that forged TGT is later presented in a TGS-REQ to actually request service tickets, the DC logs a normal-looking 4769, but if you go looking for the 4768 that should have preceded it for that same logon session, you won't find one, because no real AS-REQ ever happened. A 4769 with no corresponding 4768 for the same principal is one of the most reliable Golden Ticket indicators available from DC logs alone.\n\n` +
        `**Silver Ticket, forging a TGS, and skipping the DC completely**\n\n` +
        `A Silver Ticket goes one step further: instead of forging a TGT and then requesting a real TGS with it, the attacker forges the TGS itself directly, using a stolen service account's own password hash (not krbtgt's). Because the target service validates the TGS purely by decrypting it with its own key (remember from Reading 1 that the service never asks the DC to confirm anything) a correctly forged Silver Ticket is accepted with no interaction with a Domain Controller at all. Neither a 4768 nor a 4769 appears anywhere on any DC for this access, which is exactly what makes Silver Tickets harder to detect centrally than Golden Tickets: the only trace at all is the target service's own local logon event, and even that looks like an ordinary Kerberos authentication succeeding.`,
      codeExample:
        "WHAT EACH TECHNIQUE STEALS, AND WHAT IT SKIPS\n" +
        "=======================================================\n" +
        "Overpass-the-hash   Steals: user's own NTLM hash\n" +
        "(T1550.002)         Skips:  needing the plaintext password\n" +
        "                    DC sees: a normal 4768 (often RC4-downgraded)\n" +
        "\n" +
        "Golden Ticket       Steals: krbtgt account's hash (domain-wide key)\n" +
        "                    Skips:  the entire AS-REQ/AS-REP step\n" +
        "                    DC sees: a 4769 with NO preceding 4768\n" +
        "\n" +
        "Silver Ticket       Steals: one service account's own hash\n" +
        "                    Skips:  the DC entirely -- no AS-REQ, no TGS-REQ\n" +
        "                    DC sees: NOTHING -- only the target service's\n" +
        "                             own local logon event exists at all\n" +
        "=======================================================",
    },
    {
      type: "log_analysis",
      id: "krb-la2",
      heading: "A Ticket Issued With No Password Check at All",
      context:
        "DC01's Kerberos logs were reviewed after an unrelated phishing report against Meridian's finance team. While scanning recent AS-REQ activity, an analyst noticed the entry below for the account svc_reports, a service account belonging to a discontinued internal reporting tool that Meridian's asset inventory says was decommissioned eight months ago.",
      event: asrepRoastEvent,
      questions: [
        {
          question:
            "PreAuthType is recorded as 0, TicketEncryptionType is 0x17, and Status is 0x0 (success), with no 4771 (pre-authentication failure) preceding it for this account. What does this combination indicate?",
          options: [
            "Overpass-the-hash: an RC4 TGT in an AES domain means a stolen NTLM hash built this AS-REQ",
            "Pre-auth is disabled for svc_reports, so the KDC returned a crackable AS-REP with no password proof",
            "A normal password logon: PreAuthType 0 is the standard value for a successful AS-REQ",
            "Likely benign: an attacker's attempt would have produced a 4771 before this success",
          ],
          answer: 1,
          explanation:
            "PreAuthType 0 (normal is 2) means the KDC issued the AS-REP without any proof of the password: the DONT_REQ_PREAUTH condition AS-REP roasting needs, and 0x17 makes the result cheap to crack. “Overpass-the-hash” is the tempting confusion because it also shows RC4 on a 4768, but overpass still performs pre-authentication (the stolen hash encrypts the timestamp), so it would show PreAuthType 2, not 0. “A normal password logon” has the values reversed. “An attacker would have produced a 4771” is wrong: 4771 records pre-authentication that was attempted and failed, and here it was never attempted at all.",
          xp: 25,
        },
        {
          question:
            "The requesting IP, 10.55.2.211, has no prior association with svc_reports in any log, and the account belongs to a tool the asset inventory says was decommissioned eight months ago. Why does that context matter here specifically, more than it would for a normal service account?",
          options: [
            "It points to an insider, only someone who knew svc_reports' password could have obtained this TGT",
            "A forgotten account with pre-auth off can be roasted with no credentials, so this may be a first foothold",
            "It proves the inventory is wrong: AD disables an account automatically once its tool is retired",
            "It shows lateral movement: the request needed a valid TGT already held on 10.55.2.211",
          ],
          answer: 1,
          explanation:
            "A retired account nobody watches, with pre-authentication disabled, can be roasted by anyone who knows its name, no credentials needed, so this event could be the intrusion's very first foothold rather than movement from an already-compromised account. “Only someone who knew the password” ignores what PreAuthType 0 means: the KDC asked for no password. “AD disables it automatically” is false, retiring a tool does not touch its AD account, which is exactly why such accounts linger enabled. “Needed a valid TGT already held” describes Kerberoasting's precondition; AS-REP roasting requests the TGT itself and needs none.",
          xp: 25,
        },
        {
          question:
            "What is the correct next step?",
          options: [
            "Disable svc_reports if confirmed unused, rotate its password anyway, and sweep for other DONT_REQ_PREAUTH accounts",
            "Wait for signs of cracking: an issued AS-REP is harmless until the password is used somewhere",
            "Rotate krbtgt twice: a TGT issued without pre-authentication suggests the ticket was forged",
            "Re-enable pre-authentication on svc_reports and close: the flag was the whole problem",
          ],
          answer: 0,
          explanation:
            "Disable the account if it is truly retired, rotate its password regardless (the crackable material has already left, and logs cannot tell you whether it was cracked), and sweep for other accounts with the same flag, which attackers enumerate for. “Re-enable pre-authentication and close” is a correct fix applied too late: it stops future roasting but does nothing about the AS-REP already taken. “Wait for signs of cracking” fails because offline cracking leaves no trace. “Rotate krbtgt” is the Golden Ticket response; this TGT was really issued by the KDC (a 4768 exists), and the Golden Ticket tell is a 4769 with no preceding 4768.",
          xp: 30,
        },
      ],
    },
    {
      type: "question",
      id: "krb-q3",
      question:
        "You are triaging two separate DC log entries. Entry A: a 4769 for SPN MSSQLSvc/sqlrpt02.meridian.local:1433, TicketEncryptionType 0x17, requested by an account that also has 47 similar requests to other SPNs in the same two minutes. Entry B: a 4768 for account svc_legacyftp, PreAuthType 0, TicketEncryptionType 0x17, no prior activity from this account at all. Which is Kerberoasting and which is AS-REP roasting?",
      options: [
        "Both are Kerberoasting: RC4 (0x17) is the defining signal, whichever Event ID or precondition each entry shows",
        "A is Kerberoasting (4769, many distinct SPNs, valid TGT); B is AS-REP roasting (4768 with PreAuthType 0, no pre-authentication required)",
        "A is AS-REP roasting and B is Kerberoasting, AS-REP roasting is a high-volume sweep, while Kerberoasting is one targeted request",
        "Neither can be classified without the source IP and requesting process, since Event ID and PreAuthType alone cannot separate the two attacks",
      ],
      answer: 1,
      explanation:
        "RC4 encryption alone never determines which attack you're looking at. It's a downgrade signal common to both. The determining factor is the Event ID and precondition: 4769 with high-volume distinct-SPN requests from an account that already holds a TGT is Kerberoasting (Reading 5); 4768 with PreAuthType 0 and no prior authentication is AS-REP roasting, which requires no valid credentials at all. Event ID alone is sufficient to tell them apart. You don't need the source IP for that specific determination.",
      xp: 25,
    },
    {
      type: "analyst_choice",
      id: "krb-ac1",
      heading: "Verdict: A Daily RC4 Ticket Request From a Backup Service Account",
      scenario:
        "A detection rule tuned to flag any TicketEncryptionType: 0x17 in the environment (which enforces AES-only Kerberos policy for all standard accounts) fired on account svc_nasbackup. Before deciding, you pulled the last 30 days of 4769 events for this account: exactly one TGS request per day, always at about 03:00 (the scheduled backup window), always for the same single SPN cifs/nas02.meridian.local, always from 10.55.2.44, and no requests for any other SPN. Review the event below alongside the change-ticket note attached to it.",
      event: rc4LegacyBackupEvent,
      correct_verdict: "false_positive",
      explanation:
        "RC4 encryption alone triggered this alert because the environment's baseline policy is AES-only, but RC4 usage is not equivalent to Kerberoasting: the Kerberoasting fingerprint from Reading 5 is volume and breadth across distinct SPNs in a short window, and this account requested exactly one SPN, once. This account requests the exact same single SPN once per day at the same time, from the same internal IP, matching a confirmed change ticket explaining a hardware constraint the vendor has not yet resolved. The encryption type is a genuine finding worth tracking (this account should be prioritized for remediation once the vendor supports AES), but it is not, on its own, an active attack.",
      fp_trap:
        "It's tempting to treat any RC4-encrypted ticket in an AES-only environment as automatically suspicious, since Reading 3 taught RC4 as a downgrade signal. But a downgrade signal only becomes a strong indicator in combination with the volume and breadth pattern that separates Kerberoasting from ordinary (if outdated) legacy usage: a single account requesting a single, consistent service once a day is the shape of a documented technical debt item, not an attacker sweeping SPNs. Escalating every RC4 ticket as an incident, without checking request volume and SPN diversity first, is exactly the over-alerting trap that burns analyst time on findings that should instead go to a remediation backlog.",
      xp: 30,
    },
    {
      type: "matching",
      id: "krb-m1",
      heading: "Match Each Kerberos Signal to What It Reveals",
      instructions: "Match each Kerberos log signal to the finding or attack it points to.",
      pairs: [
        { id: "4768-preauth0", left: "4768 with PreAuthType: 0", right: "AS-REP Roasting (T1558.004): the account never required proof of a password before the AS-REP was issued" },
        { id: "4769-burst", left: "4769 for many distinct SPNs from one account in a short window", right: "Kerberoasting (T1558.003): the attacker is harvesting crackable TGS tickets" },
        { id: "4769-no4768", left: "A 4769 with no corresponding 4768 for the same logon session", right: "Golden Ticket: the TGT was forged offline using the krbtgt hash, so no real AS-REQ/AS-REP ever occurred" },
        { id: "no-dc-logs-at-all", left: "A service session with no 4768 or 4769 anywhere on any Domain Controller", right: "Possible Silver Ticket: the TGS was forged directly from a stolen service account hash, skipping the DC entirely" },
        { id: "0x17-tgt", left: "A 4768 issued with RC4 encryption (0x17) in an otherwise AES-only environment", right: "Consistent with overpass-the-hash (T1550.002): an NTLM hash alone cannot derive an AES key, only RC4" },
        { id: "4776-not-4768", left: "A 4776 (NTLM validation) appearing where Kerberos was expected", right: "The session used NTLM, not Kerberos, at all: a different authentication protocol with its own separate audit trail" },
      ],
      explanation:
        "Each of these pairings comes directly from the precondition and Event ID differences covered in this room: PreAuthType and Event ID (4768 vs 4769) separate AS-REP roasting from Kerberoasting; the presence or absence of a preceding 4768/4769 on the DC at all separates a legitimately issued ticket from a Golden or Silver Ticket forged offline; and RC4 on a TGT specifically (not just a TGS) is a strong overpass-the-hash tell, because AES key derivation needs the actual password, not just its hash.",
      xp: 40,
    },
    {
      type: "ordering",
      id: "krb-o1",
      heading: "Order the Full Kerberos Exchange for a Client Reaching a New Service",
      instructions: "Arrange the steps in the order they occur for a client with no cached TGT reaching a service for the first time.",
      items: [
        { id: "as-req", text: "Client sends AS-REQ: username plus a timestamp encrypted with a key derived from its password" },
        { id: "as-rep", text: "KDC validates the timestamp, then returns AS-REP: a TGT encrypted with the krbtgt hash, plus a session key encrypted with the client's key" },
        { id: "tgs-req", text: "Client sends TGS-REQ: presents the TGT and names the SPN of the service it wants to reach" },
        { id: "tgs-rep", text: "KDC returns TGS-REP: a TGS encrypted with the target service account's own key" },
        { id: "ap-req", text: "Client sends AP-REQ directly to the service: presents the TGS" },
        { id: "ap-rep", text: "Service decrypts the TGS with its own key and grants access, without ever contacting the KDC to confirm it" },
      ],
      correct_order: ["as-req", "as-rep", "tgs-req", "tgs-rep", "ap-req", "ap-rep"],
      explanation:
        "This is the full two-phase exchange from Reading 1: AS-REQ/AS-REP gets the client a reusable TGT, then TGS-REQ/TGS-REP exchanges that TGT for a ticket to one specific service, and finally AP-REQ/AP-REP is where the client actually presents that ticket to the service itself, the one step where the KDC is not involved at all, which is the design fact behind every forged-ticket technique in this room.",
      xp: 35,
    },
    {
      type: "query_fill",
      id: "krb-qf1",
      heading: "Write It Yourself: Surface Kerberoasting Candidates in KQL",
      language: "kql",
      context: KQL_PRIMER +
        "Using the pattern confirmed in Log Analysis 1 (RC4 encryption, high volume, broad distinct-SPN spread, from one requesting account, in a short window), write the KQL a detection engineer would ship to flag this behavior across the whole domain.",
      template:
        "SecurityEvent\n| where EventID == {{eventid}}\n| where TicketEncryptionType == \"{{enc}}\"\n| summarize RequestCount = count(), DistinctSPNs = dcount(ServiceName) by Account, bin(TimeGenerated, {{window}})\n| where DistinctSPNs > {{threshold}}",
      blanks: [
        { id: "eventid", answers: ["4769"], placeholder: "TGS-REQ event ID" },
        { id: "enc", answers: ["0x17"], placeholder: "encryption type Kerberoasting tools request" },
        { id: "window", answers: ["5m", "10m", "3m", "1m", "2m", "15m", "30m", "60m", "1h", "1hr", "5min", "10min", "3min", "1min", "2min", "15min", "30min", "60min"], placeholder: "aggregation window (a KQL timespan, up to 1h)" },
        { id: "threshold", answers: ["10", "15", "20", "5", "8", "25", "30", "40", "50"], placeholder: "minimum distinct-SPN count to consider suspicious (5–50)" },
      ],
      explanation:
        "This mirrors the exact case from Log Analysis 1: filter to 4769 (TGS-REQ, not 4768) events with RC4 encryption, group by the requesting account over a short window, and alert when the count of distinct SPNs requested is itself abnormally high, because one legitimate service request looks nothing like a sweep across dozens of unrelated SPNs from the same account in minutes.",
      xp: 35,
    },
    {
      type: "flag",
      id: "krb-f1",
      prompt:
        "In Log Analysis 1, the roasting tool ran on whichever client sent the TGS-REQs, not on DC02. Enter the IP address of the host you would pivot to next to find that tool.",
      answer: "10.55.14.203",
      hint: "One field in the 4769 records where the request came from. The DC's own name is not it.",
      xp: 25,
    },
  ],
};

// =============================================================================
// ROOM 2: windows-privilege-escalation
// =============================================================================

const fodhelperEvent: TelemetryEvent = {
  id: "evt-privesc-la1-001",
  ts: "2026-04-08T14:22:37.000Z",
  source: "sysmon",
  vendor: "Microsoft Sysmon",
  event_type: "process_create",
  severity: "high",
  hostname: "WKS-OPS14.meridian.local",
  process: {
    name: "cmd.exe",
    pid: 7710,
    path: "C:\\Windows\\System32\\cmd.exe",
    parent_name: "fodhelper.exe",
    parent_pid: 6604,
    cmdline: "C:\\Windows\\System32\\cmd.exe /c whoami /priv",
    user: "MERIDIAN\\d.oyelaran",
    integrity: "high",
  },
  description:
    "cmd.exe (PID 7710) was created with fodhelper.exe as its parent process, roughly ten seconds after a registry value was set under this user's HKCU hive at a path associated with ms-settings protocol handling. No consent.exe process appears anywhere in this session's process tree.",
  raw: {
    "winlog.event_id": 1,
    "winlog.provider_name": "Microsoft-Windows-Sysmon",
    "winlog.event_data.Image": "C:\\Windows\\System32\\cmd.exe",
    "winlog.event_data.CommandLine": "C:\\Windows\\System32\\cmd.exe /c whoami /priv",
    "winlog.event_data.ParentImage": "C:\\Windows\\System32\\fodhelper.exe",
    "winlog.event_data.ParentCommandLine": "\"C:\\Windows\\System32\\fodhelper.exe\"",
    "winlog.event_data.IntegrityLevel": "High",
    "winlog.event_data.User": "MERIDIAN\\d.oyelaran",
    "winlog.event_data.ParentUser": "MERIDIAN\\d.oyelaran",
    "winlog.event_data.CurrentDirectory": "C:\\Windows\\System32\\",
  },
};

const uacConsentEvent: TelemetryEvent = {
  id: "evt-privesc-ac1-001",
  ts: "2026-04-09T10:05:02.000Z",
  source: "sysmon",
  vendor: "Microsoft Sysmon",
  event_type: "process_create",
  severity: "low",
  hostname: "WKS-FIN08.meridian.local",
  process: {
    name: "MeridianExpenseInstaller.exe",
    pid: 5120,
    path: "C:\\Users\\r.chukwu\\Downloads\\MeridianExpenseInstaller.exe",
    parent_name: "explorer.exe",
    parent_pid: 3312,
    cmdline: "\"C:\\Users\\r.chukwu\\Downloads\\MeridianExpenseInstaller.exe\" /S",
    user: "MERIDIAN\\r.chukwu",
    integrity: "high",
  },
  description:
    "MeridianExpenseInstaller.exe was created at High integrity with the user's explorer.exe as its parent; Sysmon on the same host recorded consent.exe (parent svchost.exe, the AppInfo service) starting in this user's session four seconds earlier.",
  it_verify_result: "confirmed",
  it_verify_message:
    "SCCM deployment record DPL-4471 confirms MeridianExpenseInstaller.exe was pushed to this host today as part of the approved finance-tool rollout.",
  raw: {
    "winlog.event_id": 1,
    "winlog.provider_name": "Microsoft-Windows-Sysmon",
    "winlog.event_data.Image": "C:\\Users\\r.chukwu\\Downloads\\MeridianExpenseInstaller.exe",
    "winlog.event_data.CommandLine": "\"C:\\Users\\r.chukwu\\Downloads\\MeridianExpenseInstaller.exe\" /S",
    "winlog.event_data.ParentImage": "C:\\Windows\\explorer.exe",
    "winlog.event_data.IntegrityLevel": "High",
    "winlog.event_data.User": "MERIDIAN\\r.chukwu",
    "winlog.event_data.Hashes": "SHA256=91AE7C40B6F1D82A5E3C9F0847B2D6A1E4C8F35907A2B6D1E4F8C0A3B5D7E2C1",
    "winlog.event_data.Signed": "true",
    "winlog.event_data.Signature": "Meridian Trust IT Deployment CA",
  },
};

const privescRoom: Room = {
  id: "windows-privilege-escalation",
  title: "Windows Privilege Escalation & UAC Bypass",
  description:
    "Learn to read a Windows process tree the way privilege escalation actually happens: integrity levels and what each one is and isn't allowed to do, why reading LSASS memory requires SeDebugPrivilege and an elevated token, how fodhelper-style UAC bypasses reach High integrity without ever showing a consent prompt, token manipulation and the SeImpersonatePrivilege abused by the Potato exploit family, and the service misconfigurations, unquoted paths and weak permissions, that hand SYSTEM to anyone who can restart a service.",
  difficulty: "advanced",
  category: "Endpoint Security",
  estimatedMinutes: 65,
  xp: 310,
  icon: "🔓",
  prerequisites: ["windows-fundamentals"],
  tasks: [
    {
      type: "reading",
      id: "privesc-r1",
      heading: "Integrity Levels: Low, Medium, High, System",
      content:
        `Windows enforces a second access-control system alongside the familiar user/group permissions model: every running process carries an integrity level, and a process at a lower level generally cannot write to, or interfere with, an object owned by a process at a higher level. Regardless of what the user account's own permissions would otherwise allow. Reading integrity levels correctly in a process tree is often the fastest way to spot that something escalated.\n\n` +
        `**The four levels you'll see**\n\n` +
        `Low integrity is reserved for the most sandboxed, least-trusted processes: a browser's content-rendering process is the classic example, deliberately restricted so that even a fully compromised renderer can write to almost nothing outside its own narrow sandbox folder. Medium integrity is the default for a standard user's ordinary applications (Explorer, a word processor, a normal command prompt opened without elevation) and it's also, importantly, the default for an administrator's own processes when User Account Control (UAC) is active, since being a member of the Administrators group does not, by itself, run everything you do at full privilege. High integrity is what a process gets after explicit elevation. Right-click "Run as administrator," accepting a UAC consent prompt, or a small set of Microsoft binaries Windows silently auto-elevates (covered in Reading 3). System integrity is the highest level, reserved for core OS components, drivers, and services running as the SYSTEM account. Above even a High-integrity administrator process in what it's permitted to touch.\n\n` +
        `**Why this matters more than the user account alone**\n\n` +
        `An administrator logged on and doing ordinary work runs almost everything at Medium integrity by default. This is the entire point of UAC's "Admin Approval Mode": being an administrator gives you the *ability* to elevate, but your everyday processes don't run elevated unless something specifically triggers that elevation. This is why "the user is a local admin" and "this specific process is running elevated" are two different facts you have to check separately, and why a compromised Medium-integrity process belonging to an admin user still cannot do everything that user's account is theoretically capable of. It first has to become High (or System) somehow. Every technique in this room is, at its core, a different way of engineering that "somehow."`,
      codeExample:
        "WINDOWS INTEGRITY LEVELS\n" +
        "=======================================================\n" +
        "System   Core OS, drivers, services running as SYSTEM\n" +
        "         -- can touch almost anything on the machine\n" +
        "High     Elevated / Administrator-approved processes\n" +
        "         -- reached via UAC consent, or auto-elevate\n" +
        "Medium   Standard user apps, AND an admin's own apps\n" +
        "         by default (UAC Admin Approval Mode)\n" +
        "Low      Sandboxed, least-trusted (e.g. browser renderer)\n" +
        "=======================================================\n\n" +
        "KEY FACT: BEING AN ADMIN ACCOUNT != RUNNING ELEVATED\n" +
        "=======================================================\n" +
        "An admin's normal desktop session runs at Medium.\n" +
        "It has to be explicitly elevated (UAC prompt, or\n" +
        "auto-elevate) to reach High -- 'admin user' and\n" +
        "'elevated process' are two separate facts to verify.\n" +
        "=======================================================",
      checkpoint: {
        question:
          "r.levi is a member of the local Administrators group on a workstation with UAC active. She opens cmd.exe from the Start menu the ordinary way (no “Run as administrator”, no prompt). What IntegrityLevel will Sysmon record for that cmd.exe?",
        options: ["System", "High", "Medium", "Low"],
        answer: 2,
        explanation:
          "Medium: under UAC Admin Approval Mode an administrator's ordinary processes run at Medium; group membership only gives the ability to elevate. “High” would need an explicit elevation (consent prompt or an auto-elevate binary), which did not happen here. “System” is reserved for OS components and services running as SYSTEM, and “Low” is for sandboxed processes such as a browser renderer, not a normal command prompt.",
      },
    },
    {
      type: "reading",
      id: "privesc-r2",
      heading: "SeDebugPrivilege and Reaching LSASS Memory",
      content:
        `LSASS (Local Security Authority Subsystem Service) is the process that validates logons and holds credential material in memory: NTLM hashes, Kerberos tickets, and in some configurations cached plaintext credentials. It is the single highest-value target on any Windows endpoint for an attacker who wants credentials, and integrity levels are the exact reason reaching it isn't trivial even for a process already running under an administrator's account.\n\n` +
        `**Why you can't just open it**\n\n` +
        `Reading another process's memory requires opening a handle to it with sufficient access rights. Dumping LSASS needs surprisingly little: PROCESS_VM_READ (0x0010) plus a query right. MiniDumpWriteDump documents PROCESS_QUERY_INFORMATION | PROCESS_VM_READ (0x0410), Mimikatz's sekurlsa module typically requests 0x1010 (PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ), and cruder tools simply ask for everything, PROCESS_ALL_ACCESS (0x1FFFFF). By default, even an administrator's Medium-integrity process is denied any of these: opening a memory-read handle to a SYSTEM-owned process like LSASS requires the calling process to both hold SeDebugPrivilege (a privilege that lets a process debug and adjust the memory of other processes, normally disabled even for administrator tokens until explicitly enabled) and be running at High integrity or above. A Medium-integrity process, even one owned by an admin, will be denied this access outright: the privilege has to be enabled first, and the process has to have already elevated.\n\n` +
        `Two defences raise the bar further. **LSA Protection (RunAsPPL)** runs LSASS as a Protected Process Light, so even a SYSTEM process holding SeDebugPrivilege is refused a memory-read handle unless it is itself a signed protected process. Attackers then need a vulnerable signed driver or similar kernel trick. **Credential Guard** moves NTLM hashes and Kerberos secrets into an isolated, virtualization-protected process (LsaIso.exe), so even a successful LSASS dump no longer contains them for protected accounts.\n\n` +
        `**What this looks like in EDR telemetry**\n\n` +
        `This is exactly why credential-dumping detections center on the access mask, not just the target process name: Sysmon Event ID 10 (ProcessAccess) records each successfully opened handle with its TargetImage and GrantedAccess, and the masks dumpers most often leave against lsass.exe are 0x1010, 0x1410, 0x143A and 0x1FFFFF, a rule that only watches for 0x1FFFFF misses the most common tools. Legitimate software does open LSASS too (AV/EDR agents, MsMpEng.exe, some Windows components and backup tools), so tune on the requesting process (SourceImage) and its signer, not on the mask alone. Seeing a memory-read mask granted at all confirms the requesting process was already running with SeDebugPrivilege enabled at High or System integrity, if it had still been at Medium, the access request would have failed and no dump would occur. This is why attackers chase privilege escalation before credential dumping, not the other way around: the escalation is the precondition, not an afterthought.`,
      codeExample:
        "A CREDENTIAL-DUMPING ACCESS REQUEST, DECODED\n" +
        "=======================================================\n" +
        "TargetProcessName:  lsass.exe\n" +
        "GrantedAccess:      0x1010   (QUERY_LIMITED_INFORMATION\n" +
        "                              | VM_READ -- Mimikatz-style)\n" +
        "Other common dumper masks: 0x1410, 0x143A, 0x1FFFFF\n" +
        "(0x1FFFFF = PROCESS_ALL_ACCESS)\n" +
        "\n" +
        "For this to succeed, the REQUESTING process needed:\n" +
        "  1. SeDebugPrivilege enabled in its token\n" +
        "  2. High or System integrity (Medium is denied outright)\n" +
        "\n" +
        "If either condition is missing, Windows denies the handle\n" +
        "request and no memory read occurs -- which is why this\n" +
        "access mask, if GRANTED, already proves prior elevation.\n" +
        "=======================================================",
    },
    {
      type: "question",
      id: "privesc-q1",
      question:
        "With kernel-object auditing enabled, Windows Security Event 4656 (Audit Failure) shows a process at IntegrityLevel: Medium requesting a handle to lsass.exe with access mask 0x1FFFFF, and the request failed. What is the correct interpretation?",
      options: [
        "The read succeeded: the 0x1FFFFF mask in the event is what the process obtained, so LSASS memory was accessible",
        "Windows denied it: a Medium process lacks elevation and an enabled SeDebugPrivilege, so the tool must reach High or SYSTEM first",
        "Windows denied it because Credential Guard is active; without it the same Medium-integrity request would have been granted",
        "The oversized mask caused the denial: the same Medium process asking for a smaller read mask such as 0x1010 would be granted",
      ],
      answer: 1,
      explanation:
        "A denied access request means exactly what it says: no memory was read, because Windows enforced the SeDebugPrivilege/integrity-level requirement from Reading 2. “The oversized mask caused the denial” is wrong because that requirement applies to ANY memory-read mask, so 0x1010 would have been refused just the same. “Credential Guard is active” is wrong too: Credential Guard isolates secrets inside LsaIso.exe, it is not the handle check that denied this request. “The read succeeded” misreads the event: 4656 here is an Audit Failure for a request, not a granted handle. Note the log source: Event 4656 records handle requests including failures, whereas Sysmon Event 10's GrantedAccess only appears for handles that were actually opened. A denial here is still valuable: it tells you an attempt occurred and that the attacker had not yet escalated. Being a local admin account does not bypass this check on its own: the process itself has to be running elevated.",
      xp: 20,
    },
    {
      type: "reading",
      id: "privesc-r3",
      heading: "UAC Bypass: The fodhelper / computerdefaults Registry Hijack",
      content:
        `A small number of Microsoft binaries: fodhelper.exe, computerdefaults.exe, eventvwr.exe, and sdclt.exe among them. Are flagged in their application manifest as "auto-elevate," meaning that when an administrator running in Admin Approval Mode launches one, Windows silently elevates it straight to High integrity without ever showing the familiar UAC consent prompt. Microsoft trusts these binaries enough to skip the prompt; that trust is exactly what T1548.002 (Abuse Elevation Control Mechanism: Bypass User Account Control) abuses.\n\n` +
        `**One precondition worth stating clearly**\n\n` +
        `This technique escalates a process from "administrator running at Medium integrity" to "administrator running at High integrity, silently": it does not turn a standard, non-administrator user into an administrator. The account still has to already be a member of the local Administrators group in Admin Approval Mode for auto-elevation to apply at all; a genuinely standard user attempting the same registry hijack gains nothing, because there's no elevated token available to silently hand to them in the first place.\n\n` +
        `**The mechanism**\n\n` +
        `fodhelper.exe, when it runs, internally checks a registry key under the current user's own hive, HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command, to determine how to open the ms-settings handler, and it does so without validating that this particular path is a protected, trusted location. Because HKCU is the user's own per-user hive, a completely unprivileged, Medium-integrity process can write to it freely: no admin rights, no special privilege, just an ordinary registry write. An attacker sets that key's default value to an arbitrary command, then simply launches fodhelper.exe. fodhelper silently auto-elevates to High integrity as designed, internally invokes the ms-settings handler, reads the hijacked key the attacker planted, and executes the attacker's command: now running at High integrity, with no consent prompt ever shown.\n\n` +
        `**What this looks like in Sysmon**\n\n` +
        `The registry write is captured by Sysmon Event ID 13 (RegistryEvent: value set), showing the TargetObject as the hijacked ms-settings command path. The payoff is captured by Sysmon Event ID 1 (process creation): fodhelper.exe appears as the parent of whatever command the attacker planted, and critically, that child process shows IntegrityLevel: High even though fodhelper's own launcher (almost always explorer.exe, at Medium integrity for this admin's ordinary desktop session) never went through an elevation prompt. The strongest corroborating evidence is the Sysmon Event 13 write itself, to ...\\ms-settings\\Shell\\Open\\command, usually together with an empty DelegateExecute value under the same key, which fodhelper needs before it will honour the planted command. Followed seconds later by fodhelper.exe parenting a High-integrity child. A supporting negative: no consent.exe process started at that moment. To read that correctly, know how a NORMAL elevation looks: the AppInfo service (hosted in svchost.exe) launches consent.exe only to draw the prompt; once the user approves, AppInfo itself creates the elevated process and re-parents it to the requester, so in Sysmon the elevated process shows its requester (usually explorer.exe) as ParentImage, never consent.exe. You therefore look for consent.exe as a separate process (child of svchost.exe) starting in the same session at the same moment, not in the elevated process's parent chain.`,
      codeExample:
        "THE FODHELPER UAC BYPASS, STEP BY STEP\n" +
        "=======================================================\n" +
        "1. Attacker (already Medium-integrity, admin account)\n" +
        "   writes to their OWN writable HKCU hive:\n" +
        "     HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command\n" +
        "     (Default) = <attacker's command>\n" +
        "   -- captured as Sysmon Event 13 (RegistryEvent)\n" +
        "\n" +
        "2. Attacker launches fodhelper.exe\n" +
        "   -- Windows silently auto-elevates it to High integrity\n" +
        "      (it's on Microsoft's auto-elevate whitelist)\n" +
        "\n" +
        "3. fodhelper.exe internally opens the ms-settings handler,\n" +
        "   reads the HIJACKED key instead of the real handler,\n" +
        "   and executes the attacker's command\n" +
        "   -- captured as Sysmon Event 1: fodhelper.exe (parent)\n" +
        "      spawns attacker's command (child) at IntegrityLevel: High\n" +
        "\n" +
        "TELL: Sysmon 13 on ms-settings\\Shell\\Open\\command\n" +
        "      (+ DelegateExecute), then fodhelper -> High child,\n" +
        "      and no consent.exe launched in that session\n" +
        "=======================================================",
      checkpoint: {
        question:
          "An attacker has code execution as a Medium-integrity process and plans the fodhelper registry hijack. Which condition must already be true for it to yield a High-integrity process?",
        options: [
          "The account is already a local administrator running in Admin Approval Mode",
          "The account holds SeImpersonatePrivilege, which fodhelper uses to borrow an elevated token",
          "The process is already at High integrity, which it needs to write the ms-settings key",
          "Any standard user qualifies, provided they can write to their own HKCU hive",
        ],
        answer: 0,
        explanation:
          "The bypass lifts an existing administrator's session from Medium to High; it needs the elevated token that Admin Approval Mode keeps in reserve. “Any standard user qualifies” is the classic mistake: a standard user can write the HKCU key, but there is no elevated token for fodhelper to hand over, so nothing is gained. “Already at High integrity” reverses the logic: the HKCU write is an ordinary Medium-integrity operation, and an attacker already at High would not need a bypass. “SeImpersonatePrivilege” belongs to the Potato technique in Reading 4, not to auto-elevation.",
      },
    },
    {
      type: "log_analysis",
      id: "privesc-la1",
      heading: "A Medium-Integrity Session That Produced a High-Integrity Shell",
      context:
        "WKS-OPS14 belongs to d.oyelaran, a member of the local Administrators group on this endpoint. Ten seconds before the event below, Sysmon recorded a registry value being set under this user's HKCU hive at a path associated with ms-settings protocol handling. Review the process-creation event that followed.",
      event: fodhelperEvent,
      questions: [
        {
          question:
            "ParentImage is fodhelper.exe with IntegrityLevel: High, but this session's own explorer.exe (the process that would have launched fodhelper.exe) is running at Medium integrity, and no consent.exe process appears anywhere in the session. What does this combination indicate?",
          options: [
            "d.oyelaran accepted a UAC prompt for fodhelper.exe, and the cmd.exe child simply inherited that approved High token",
            "An auto-elevating binary ran a command planted in the user's HKCU ms-settings key: a UAC bypass (T1548.002)",
            "A Potato-style tool impersonated a SYSTEM token inside fodhelper.exe, which is why its child reached High integrity",
            "fodhelper.exe auto-elevates by design, so a High-integrity child of it is expected and needs no further correlation",
          ],
          answer: 1,
          explanation:
            "fodhelper.exe is on the auto-elevate list, so its own High integrity is expected. What is abnormal is the HKCU ms-settings write seconds earlier followed by fodhelper parenting a shell, the exact T1548.002 sequence. “Accepted a UAC prompt” is ruled out by the evidence: a real prompt starts consent.exe in the session, and none appears. “A Potato-style tool” does not fit: Potato abuses SeImpersonatePrivilege from a service account and lands at SYSTEM, not an admin user's High-integrity shell, and nothing here shows coercion. “Expected by design” stops one step short: auto-elevation explains fodhelper's level, but fodhelper does not normally launch cmd.exe, the planted registry command is what made it do so.",
          xp: 25,
        },
        {
          question:
            "Why was d.oyelaran able to write to HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command in the first place, without needing any elevated privilege at all?",
          options: [
            "HKCU is the user's own per-user hive, so a Medium-integrity process can write it with no elevation",
            "As a local administrator, d.oyelaran's Medium processes may write protected keys anywhere in the registry",
            "SeDebugPrivilege was enabled in the session, and that privilege grants write access to protected keys",
            "fodhelper.exe wrote the key itself after it auto-elevated, so the write ran at High integrity",
          ],
          answer: 0,
          explanation:
            "HKCU is the logged-on user's own hive, so writing to it is an ordinary Medium-integrity operation. That is what makes this bypass possible for an attacker who has not yet elevated. “Medium processes may write protected keys anywhere” confuses admin membership with elevation: Reading 1 showed an admin's Medium processes cannot do everything the account could. “SeDebugPrivilege” governs opening other processes' memory (Reading 2), not registry writes. “fodhelper wrote the key itself” reverses the order: the Sysmon 13 write came before fodhelper launched, which is why the hijack was already in place when fodhelper read it.",
          xp: 25,
        },
        {
          question:
            "What is the correct response, given this pattern is confirmed?",
          options: [
            "Kill the tree, remove the HKCU value, trace what the High child did, and review why this user is a local admin",
            "Close as benign: fodhelper.exe is a signed Microsoft binary, so the processes it launches share its trust",
            "Delete the hijacked HKCU value and close, removing the planted key fully undoes the escalation",
            "Re-image WKS-OPS14 at once, before pulling the Sysmon ancestry of the High-integrity process",
          ],
          answer: 0,
          explanation:
            "The response must contain the escalation (kill the tree, clean the hijacked value), scope it (trace what the High-integrity process did via its Sysmon ancestry) and address the precondition (local admin rights the technique depends on). “Close as benign” mistakes the tool's signature for trust in what it ran: a signed auto-elevate binary is exactly what this technique abuses. “Delete the value and close” cleans up the method but ignores what already ran at High integrity, which may have planted persistence or dumped credentials. “Re-image at once” is a reasonable later step at the wrong time: wiping first destroys the evidence you need to learn what the elevated shell did.",
          xp: 30,
        },
      ],
    },
    {
      type: "reading",
      id: "privesc-r4",
      heading: "Token Manipulation, SeImpersonatePrivilege, and the Potato Family",
      content:
        `Not every escalation path runs through a registry hijack. Token manipulation (T1134) is a broader category: rather than tricking a process into running at a higher integrity level, an attacker steals or duplicates an access token that already belongs to a more privileged process, then uses it to act as that identity (via API calls like DuplicateToken or ImpersonateLoggedOnUser) without ever needing that account's password.\n\n` +
        `**Why SeImpersonatePrivilege matters specifically**\n\n` +
        `SeImpersonatePrivilege lets a process impersonate the security context of another user after that user connects to it: a completely legitimate and necessary capability for services that act on behalf of callers, like IIS application pool identities and Windows service accounts including NETWORK SERVICE and LOCAL SERVICE, all of which are commonly granted this privilege by default so they can, for example, serve a web request "as" the connecting principal. The problem is that this same privilege, combined with a coercion trick, is exactly what the Potato family of exploits (JuicyPotato, RoguePotato, PrintSpoofer, and their successors) abuses.\n\n` +
        `**How the Potato technique works, at a level worth knowing**\n\n` +
        `These tools trick a SYSTEM-level Windows service into authenticating to a listener the attacker controls, typically by abusing a COM or RPC interface (older variants relied on a COM marshaling quirk in DCOM's NTLM authentication; newer ones abuse different local services, including the print spooler for PrintSpoofer) so that SYSTEM itself initiates an authenticated connection. Because the attacker's low-privileged process already holds SeImpersonatePrivilege, it can capture that inbound SYSTEM authentication and impersonate it, effectively borrowing a SYSTEM token without ever cracking a password, dumping LSASS, or touching a registry key at all.\n\n` +
        `**Why this matters most for web application compromises**\n\n` +
        `A web shell landing in a compromised application often lands as whatever account the web server's worker process runs under (an IIS APPPOOL identity, for example) which is a deliberately low-privileged virtual account, not SYSTEM. But because that identity is commonly granted SeImpersonatePrivilege by default (it needs to be, to do its normal job), an attacker who gets code execution through a web shell is frequently just one Potato-family exploit away from SYSTEM on that host. This is the exact chain covered in the Web Application Attacks room: landing a shell is not the same as owning the machine, but the gap between the two is often smaller than it looks.`,
      codeExample:
        "SeImpersonatePrivilege AND THE POTATO CHAIN\n" +
        "=======================================================\n" +
        "1. Attacker gets code execution as a LOW-privileged\n" +
        "   service identity that legitimately holds\n" +
        "   SeImpersonatePrivilege (e.g. an IIS APPPOOL account)\n" +
        "\n" +
        "2. Potato-family tool coerces a SYSTEM-level Windows\n" +
        "   component to authenticate to an attacker-controlled\n" +
        "   listener (via a COM/RPC/spooler coercion trick)\n" +
        "\n" +
        "3. Attacker's process, already holding\n" +
        "   SeImpersonatePrivilege, IMPERSONATES that inbound\n" +
        "   SYSTEM authentication\n" +
        "\n" +
        "4. Attacker now runs commands AS SYSTEM\n" +
        "   -- no password ever needed, no LSASS memory read\n" +
        "=======================================================",
    },
    {
      type: "question",
      id: "privesc-q2",
      question:
        "A web shell is confirmed running under the IIS APPPOOL\\ContosoSite identity, which shows IntegrityLevel: Medium and holds SeImpersonatePrivilege by default. What is the accurate way to describe the attacker's current position?",
      options: [
        "The attacker already has SYSTEM-level control. Code execution on a Windows server is equivalent to SYSTEM whichever account runs the process",
        "The attacker has low-privileged service-account execution, and SeImpersonatePrivilege puts a Potato-family escalation to SYSTEM within a short, known step",
        "The attacker is contained: an app-pool virtual account has no privilege an impersonation exploit could abuse",
        "The attacker must dump LSASS before escalating, because impersonating SYSTEM needs a captured hash first",
      ],
      answer: 1,
      explanation:
        "IIS APPPOOL identities are deliberately low-privileged, Medium-integrity virtual accounts, but they commonly hold SeImpersonatePrivilege by default: exactly the precondition the Potato family abuses to reach SYSTEM. “Already has SYSTEM-level control” confuses code execution with privilege; the stem itself shows Medium integrity. “Contained” ignores the SeImpersonatePrivilege the stem lists. “Must dump LSASS first” gets the order backwards: Potato captures a coerced SYSTEM authentication and impersonates it with no password or hash, and a Medium process could not open LSASS anyway (Reading 2).",
      xp: 20,
    },
    {
      type: "reading",
      id: "privesc-r5",
      heading: "Unquoted Service Paths, Weak Service Permissions, and Reading an Integrity Jump",
      content:
        `Two older but still common misconfigurations hand SYSTEM to anyone who can predict or influence a service's execution, plus the closing synthesis for reading integrity levels in a process tree correctly.\n\n` +
        `**Unquoted service paths**\n\n` +
        `Windows services run as SYSTEM by default unless configured otherwise, and a service's ImagePath tells Windows exactly which binary to launch. If that path contains a space and isn't wrapped in quotes, for example C:\\Program Files\\Meridian App\\service.exe, stored unquoted. Windows resolves it by trying each space-delimited segment as a potential executable path in order: first C:\\Program.exe, then C:\\Program Files\\Meridian.exe, and only if neither exists does it fall through to the real, intended path. An attacker with write access to any of those earlier candidate locations (often C:\\ itself, or a parent folder with looser permissions than the final destination) can drop a malicious binary at one of those intermediate paths, and the next time the service starts (at boot, or on a scheduled or manual restart) Windows launches the attacker's file instead, running it as SYSTEM.\n\n` +
        `**Weak service permissions**\n\n` +
        `Separately, a service's own configuration (its registry entry under HKLM\\SYSTEM\\CurrentControlSet\\Services) or the binary it points to can simply have overly permissive access control lists, allowing a low-privileged user to reconfigure the service's ImagePath directly, or overwrite the target binary on disk, without needing to exploit any path-parsing quirk at all. Either misconfiguration produces the same outcome: the next time a SYSTEM-run service starts, it executes attacker-controlled code.\n\n` +
        `**What "the parent is Medium, the child is High" actually proves**\n\n` +
        `Across every technique in this room, the single fastest triage signal in a process tree is a jump in integrity level between a parent and its child that doesn't have an obvious, expected explanation. A completely ordinary elevation (a user deliberately running an installer as administrator) is accompanied by a consent.exe process (launched by the AppInfo service, svchost.exe) in the same session at the same moment, while the elevated process itself shows its requester, usually explorer.exe, as its parent; IT or deployment records typically corroborate it (as in the analyst_choice task ahead). An elevation with no consent.exe, no deployment record, and no auto-elevate binary that would explain it on its own is the pattern worth escalating every time: something made that jump happen without going through the path Windows normally requires, and your job is to work out which of the techniques in this room did it.`,
      codeExample:
        "UNQUOTED SERVICE PATH -- HOW WINDOWS RESOLVES IT\n" +
        "=======================================================\n" +
        "ImagePath (unquoted): C:\\Program Files\\Meridian App\\service.exe\n" +
        "\n" +
        "Windows tries, IN ORDER, until one exists:\n" +
        "  1. C:\\Program.exe                    <- attacker's target\n" +
        "  2. C:\\Program Files\\Meridian.exe     <- attacker's target\n" +
        "  3. C:\\Program Files\\Meridian App\\service.exe  (intended)\n" +
        "\n" +
        "Fix: wrap the path in quotes so Windows treats it as one\n" +
        "     unambiguous string: \"C:\\Program Files\\Meridian App\\service.exe\"\n" +
        "=======================================================\n\n" +
        "THE FASTEST TRIAGE QUESTION FOR ANY PROCESS TREE\n" +
        "=======================================================\n" +
        "Does a Medium -> High (or higher) integrity jump have an\n" +
        "explanation? Check for, in order:\n" +
        "  [ ] consent.exe (child of svchost) started in the same\n" +
        "      session at that moment (normal UAC prompt)\n" +
        "  [ ] a known auto-elevate binary (fodhelper, etc.) AND\n" +
        "      a preceding registry hijack under HKCU (T1548.002)\n" +
        "  [ ] a SYSTEM-run service restarting with a modified or\n" +
        "      hijacked ImagePath (unquoted path / weak ACL)\n" +
        "  [ ] SeImpersonatePrivilege + a Potato-style coercion tool\n" +
        "None of the above present? Escalate -- the jump is unexplained.\n" +
        "=======================================================",
      checkpoint: {
        question:
          "A SYSTEM service has the unquoted ImagePath C:\\Apps\\Data Sync\\Bin Tools\\sync.exe. Applying the resolution order from this reading, which path does Windows attempt to execute FIRST?",
        options: [
          "C:\\Apps\\Data Sync\\Bin.exe",
          "C:\\Apps\\Data.exe",
          "C:\\Program.exe",
          "C:\\Apps\\Data Sync\\Bin Tools\\sync.exe",
        ],
        answer: 1,
        explanation:
          "Windows cuts the unquoted path at the first space and appends .exe, so C:\\Apps\\Data.exe is tried first; next comes C:\\Apps\\Data Sync\\Bin.exe (the second space), and only then the real sync.exe. “C:\\Program.exe” is the first candidate only when the path starts with C:\\Program Files: it is the reading's example, not a fixed rule. The intended path is tried last, which is exactly why a planted binary at an earlier candidate wins.",
      },
    },
    {
      type: "question",
      id: "privesc-q3",
      question:
        "A service named MeridianSyncSvc is configured with ImagePath: C:\\Program Files\\Meridian Sync\\agent.exe (unquoted, containing spaces) and runs as LocalSystem. An analyst finds a newly created file at C:\\Program Files\\Meridian.exe that was not present last week. What is the most likely explanation and risk?",
      options: [
        "Unrelated to the service: Windows executes ImagePath exactly as written, so a new file in the Program Files root is coincidence",
        "A binary planted at an intermediate path Windows tries for the unquoted ImagePath; at next start Meridian.exe will likely run as SYSTEM",
        "Low risk, writing to the Program Files root already needs admin rights, so the file gains an attacker nothing",
        "A risk once the attacker also holds SeImpersonatePrivilege, which the hijack needs to adopt the service token",
      ],
      answer: 1,
      explanation:
        "Windows tries each space-delimited candidate in order, and C:\\Program Files\\Meridian.exe is one it attempts before the real agent.exe; because the service runs as LocalSystem, the planted file runs as SYSTEM at the next service start. “Executes ImagePath exactly as written” is true only for quoted paths. “Low risk because writing there needs admin” starts from a true fact, on modern Windows a standard user cannot normally write to the Program Files root, so whoever placed it had admin rights or found a weak folder ACL, but the hijack still turns that into SYSTEM execution plus persistence on every start. “Needs SeImpersonatePrivilege” mixes in the Potato technique; the service itself launches the binary, so no token impersonation is involved.",
      xp: 25,
    },
    {
      type: "analyst_choice",
      id: "privesc-ac1",
      heading: "Verdict: A Medium-to-High Jump on WKS-FIN08",
      scenario:
        "A detection rule flagged a Medium-to-High integrity jump on WKS-FIN08: MeridianExpenseInstaller.exe launched at IntegrityLevel: High under r.chukwu's session (r.chukwu is a local administrator in Admin Approval Mode). Pivoting on the host, you find a Sysmon Event 1 for C:\\Windows\\System32\\consent.exe (ParentImage: svchost.exe) in r.chukwu's session at 10:04:58. Four seconds before the event below. Review the event and the deployment record attached to it.",
      event: uacConsentEvent,
      correct_verdict: "false_positive",
      explanation:
        "The parent is the user's own explorer.exe: exactly what a normal UAC elevation looks like, because the AppInfo service creates the elevated process and re-parents it to whoever requested elevation. The corroborating UAC evidence is the consent.exe process (launched by svchost.exe/AppInfo) that started in the same session four seconds earlier: that is the prompt being drawn and accepted, which is exactly what a fodhelper-style bypass specifically lacks, there, the parent would be an auto-elevate binary and no consent.exe would appear. The binary is signed by Meridian Trust's own deployment CA, and an SCCM deployment record independently confirms this exact installer was scheduled to this host today as part of an approved rollout. A Medium-to-High integrity jump alone is not suspicious. It's the expected shape of any legitimate elevation; what makes it benign here is the consent.exe prompt at the same moment, an ordinary explorer.exe parent, and independent deployment corroboration.",
      fp_trap:
        "Reading 5 taught 'an unexplained integrity jump is the fastest triage signal,' which makes it tempting to treat every Medium-to-High jump as worth escalating on sight. But this jump is explained: a consent.exe prompt was launched in the same session seconds before (the UAC bypass techniques in this room specifically avoid triggering consent.exe) and the parent is the user's ordinary explorer.exe, not an auto-elevate binary, the binary is signed by an internal CA, and a deployment ticket independently corroborates it. Escalating this as an incident because 'integrity went up' without checking for a matching consent.exe first is exactly the shortcut this room is trying to train out of you.",
      xp: 30,
    },
    {
      type: "matching",
      id: "privesc-m1",
      heading: "Match Each Escalation Technique to Its Signature",
      instructions: "Match each privilege escalation technique to the artifact or precondition that best identifies it.",
      pairs: [
        { id: "fodhelper", left: "fodhelper.exe as parent, IntegrityLevel: High, no consent.exe launched in the session", right: "UAC bypass via registry hijack (T1548.002). Auto-elevate binary reading an attacker-planted HKCU command key" },
        { id: "lsass-access", left: "GrantedAccess: 0x1FFFFF requested against lsass.exe", right: "PROCESS_ALL_ACCESS: requires SeDebugPrivilege and High/System integrity already held by the requesting process" },
        { id: "potato", left: "A Medium-integrity service account holding SeImpersonatePrivilege suddenly executing commands as SYSTEM", right: "Potato-family exploit: coerces a SYSTEM component to authenticate to an attacker-controlled listener, then impersonates that connection" },
        { id: "unquoted", left: "A SYSTEM-run service's unquoted ImagePath, with a new binary appearing at one of the intermediate space-delimited paths", right: "Unquoted service path abuse: Windows executes the attacker's binary as SYSTEM on the service's next start" },
        { id: "consent", left: "consent.exe (child of svchost.exe) starting in the same session seconds before a High-integrity process whose parent is explorer.exe", right: "Normal, expected UAC elevation: the exact evidence a bypass technique specifically avoids leaving behind" },
        { id: "duptoken", left: "DuplicateToken/ImpersonateLoggedOnUser used to act as another logged-on user's identity", right: "Token manipulation (T1134), reusing an already-privileged token instead of escalating integrity directly" },
      ],
      explanation:
        "Each pairing is the specific artifact this room taught you to look for: the presence or absence of consent.exe separates legitimate elevation from a bypass; a granted PROCESS_ALL_ACCESS against LSASS already proves prior elevation occurred; SeImpersonatePrivilege plus a sudden SYSTEM-level action is the Potato fingerprint; and an unquoted path plus a new file at an intermediate location is the classic service-hijack setup.",
      xp: 40,
    },
    {
      type: "ordering",
      id: "privesc-o1",
      heading: "Order the fodhelper UAC Bypass From First Action to Final Execution",
      instructions: "Arrange the steps of the fodhelper registry-hijack UAC bypass in the order they occur.",
      items: [
        { id: "medium-start", text: "Attacker's process starts at Medium integrity, under an account already in the local Administrators group" },
        { id: "hkcu-write", text: "Attacker writes an arbitrary command to HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command: an ordinary, unprivileged registry write to their own hive" },
        { id: "launch-fodhelper", text: "Attacker launches fodhelper.exe" },
        { id: "auto-elevate", text: "Windows silently auto-elevates fodhelper.exe to High integrity because it is on the auto-elevate whitelist: no consent.exe prompt is shown" },
        { id: "handler-read", text: "fodhelper.exe internally invokes the ms-settings handler and reads the hijacked HKCU key instead of the legitimate handler" },
        { id: "high-exec", text: "The attacker's planted command executes, inheriting fodhelper's High integrity" },
      ],
      correct_order: ["medium-start", "hkcu-write", "launch-fodhelper", "auto-elevate", "handler-read", "high-exec"],
      explanation:
        "The order matters because the registry write has to happen before fodhelper.exe is launched: the hijack has to already be in place for fodhelper's internal handler lookup to find it. The precondition (already-Medium, already-admin) has to be true from the start, since this technique elevates an existing admin session, not a standard user account.",
      xp: 35,
    },
    {
      type: "flag",
      id: "privesc-f1",
      prompt:
        "In the fodhelper bypass on WKS-OPS14, one artefact is written BEFORE fodhelper.exe is ever launched. Which Sysmon Event ID records that artefact? Enter the number only.",
      answer: "13",
      hint: "Work out which step of the bypass has to be in place before the auto-elevate binary starts, then recall which Sysmon event type records that kind of change.",
      xp: 25,
    },
    {
      type: "query_fill",
      id: "privesc-qf1",
      heading: "Write It Yourself: Hunt for fodhelper-Style UAC Bypasses",
      language: "kql",
      context: KQL_PRIMER +
        "Using the pattern from Log Analysis 1 (an auto-elevate binary as parent, a High-integrity child, no consent.exe prompt at that moment), write the KQL that would surface candidate UAC bypasses across the fleet. The join pairs each candidate with any UAC-prompt process on the same device; the summarize then keeps only candidates with NO such prompt within 60 seconds, excluding a whole device just because it once showed a UAC prompt would hide real bypasses.",
      template:
        "DeviceProcessEvents\n| where InitiatingProcessFileName in~ (\"{{binary1}}\", \"computerdefaults.exe\", \"eventvwr.exe\", \"sdclt.exe\")\n| where ProcessIntegrityLevel =~ \"{{level}}\"\n| where InitiatingProcessAccountName !contains \"SYSTEM\"\n| join kind=leftouter (DeviceProcessEvents | where FileName =~ \"{{consentproc}}\" | project DeviceId, PromptTime = Timestamp) on DeviceId\n| summarize PromptsNearby = countif(isnotempty(PromptTime) and abs(datetime_diff('second', Timestamp, PromptTime)) <= 60) by DeviceId, ReportId, Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName\n| where PromptsNearby == 0",
      blanks: [
        { id: "binary1", answers: ["fodhelper.exe", "FodHelper.exe"], placeholder: "auto-elevate binary from this room's example" },
        { id: "level", answers: ["High", "high", "HIGH"], placeholder: "integrity level the child process shows" },
        { id: "consentproc", answers: ["consent.exe"], placeholder: "process that appears during a normal UAC prompt" },
      ],
      explanation:
        "This mirrors the exact detection logic from Log Analysis 1: filter to the known auto-elevate binaries acting as a parent process, require the resulting child to be High integrity, and drop any candidate that had a consent.exe process start on the same device within 60 seconds. Since a UAC prompt at that moment is the signature of a normal, expected elevation rather than a bypass. Correlating by device AND time matters: consent.exe is never the elevated process's parent (AppInfo re-parents the elevated process to the requester), and a device-wide exclusion would suppress every bypass on any machine that had ever shown a UAC prompt.",
      xp: 35,
    },
  ],
};

// =============================================================================
// ROOM 3: persistence-mechanisms
// =============================================================================

const scheduledTaskPersistEvent: TelemetryEvent = {
  id: "evt-persist-la1-001",
  ts: "2026-04-11T02:14:09.000Z",
  source: "sysmon",
  vendor: "Microsoft Sysmon",
  event_type: "scheduled_task",
  severity: "high",
  hostname: "WKS-FIN22.meridian.local",
  process: {
    name: "schtasks.exe",
    pid: 5566,
    path: "C:\\Windows\\System32\\schtasks.exe",
    parent_name: "cmd.exe",
    parent_pid: 4410,
    cmdline: "schtasks.exe /create /sc onstart /tn \"WindowsUpdateHelper\" /tr \"C:\\Users\\Public\\svchelper.exe\" /ru SYSTEM /rl HIGHEST /f",
    user: "MERIDIAN\\c.iversen",
    integrity: "high",
  },
  description:
    "schtasks.exe was launched by cmd.exe under c.iversen's session and exited with status 0; the task binary path referenced does not appear in this host's approved-application inventory.",
  raw: {
    "winlog.event_id": 1,
    "winlog.provider_name": "Microsoft-Windows-Sysmon",
    "winlog.event_data.Image": "C:\\Windows\\System32\\schtasks.exe",
    "winlog.event_data.CommandLine":
      "schtasks.exe /create /sc onstart /tn \"WindowsUpdateHelper\" /tr \"C:\\Users\\Public\\svchelper.exe\" /ru SYSTEM /rl HIGHEST /f",
    "winlog.event_data.ParentImage": "C:\\Windows\\System32\\cmd.exe",
    "winlog.event_data.User": "MERIDIAN\\c.iversen",
    "winlog.event_data.IntegrityLevel": "High",
    "winlog.event_data.CurrentDirectory": "C:\\Users\\c.iversen\\",
  },
};

const legitUpdaterAutorunEvent: TelemetryEvent = {
  id: "evt-persist-ac1-001",
  ts: "2026-04-12T09:00:44.000Z",
  source: "sysmon",
  vendor: "Microsoft Sysmon",
  event_type: "registry_set",
  severity: "low",
  hostname: "WKS-OPS09.meridian.local",
  process: {
    name: "MeridianVPNClient.exe",
    pid: 3312,
    path: "C:\\Program Files\\Meridian VPN Client\\MeridianVPNClient.exe",
    user: "NT AUTHORITY\\SYSTEM",
    integrity: "system",
  },
  description:
    "MeridianVPNClient.exe set a value under HKLM Run during its post-install configuration step; the binary is signed and matches the version deployed via this week's approved rollout.",
  it_verify_result: "confirmed",
  it_verify_message:
    "SCCM deployment record DPL-4502 confirms MeridianVPNClient v11.2 was pushed to this host today, and its documented install behavior registers an HKLM Run entry to launch the connection-status tray icon at login.",
  raw: {
    "winlog.event_id": 13,
    "winlog.provider_name": "Microsoft-Windows-Sysmon",
    "winlog.event_data.EventType": "SetValue",
    "winlog.event_data.TargetObject":
      "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\MeridianVPNTray",
    "winlog.event_data.Details": "C:\\Program Files\\Meridian VPN Client\\vpntray.exe",
    "winlog.event_data.Image": "C:\\Program Files\\Meridian VPN Client\\MeridianVPNClient.exe",
    "winlog.event_data.User": "NT AUTHORITY\\SYSTEM",
  },
};

const persistenceRoom: Room = {
  id: "persistence-mechanisms",
  title: "Persistence: How Attackers Survive a Reboot",
  description:
    "Learn the mechanisms attackers plant to survive a reboot, a logoff, or even a password reset: Run and RunOnce registry keys, scheduled tasks and cron jobs, Windows services, BITS jobs, WMI event subscriptions, and cloud-account and OAuth persistence, plus the operational lesson that separates a contained incident from one that reopens itself: persistence is what turns an intrusion into an incident, and its presence changes the order in which you're allowed to remediate.",
  difficulty: "intermediate",
  category: "Endpoint Security",
  estimatedMinutes: 55,
  xp: 275,
  icon: "🔁",
  prerequisites: ["windows-fundamentals"],
  tasks: [
    {
      type: "reading",
      id: "persist-r1",
      heading: "Registry Run Keys and the Startup Folder (T1547.001)",
      content:
        `The simplest, oldest, and still one of the most common ways malware survives a reboot is telling Windows to launch it automatically at logon, and Windows offers several nearly-identical ways to ask for that.\n\n` +
        `**Run and RunOnce keys**\n\n` +
        `Both HKEY_CURRENT_USER (HKCU) and HKEY_LOCAL_MACHINE (HKLM) have a Software\\Microsoft\\Windows\\CurrentVersion\\Run key (and a RunOnce variant, which executes its entry once and then removes it). Anything with a value under HKCU\\...\\Run launches for that one user at their next logon; anything under HKLM\\...\\Run launches for every user who logs onto the machine, at their logon, but writing to HKLM requires administrator rights, since it's a machine-wide, protected location. Unlike the always-user-writable HKCU covered in the privilege-escalation room. This asymmetry is itself informative: an HKLM Run key entry implies the attacker already had, or gained, administrative access to plant it; an HKCU entry only required whatever access the compromised user already had.\n\n` +
        `**The Startup folder**\n\n` +
        `A GUI-visible equivalent exists as a literal folder: shell:startup opens each user's personal Startup folder, and anything placed there (a shortcut, a script, an executable) runs at that user's next logon, with the same per-user versus all-users distinction as the registry keys (there's a per-user Startup folder and an all-users one, the latter again requiring admin rights to write to).\n\n` +
        `**What this looks like in Sysmon, and why it's still worth watching closely**\n\n` +
        `Sysmon Event ID 13 (RegistryEvent: value set) captures a write to any of these Run/RunOnce paths, with TargetObject showing the exact key and Details showing the value written, typically the path to whatever gets launched. This is also one of the most heavily false-positive-prone persistence mechanisms to alert on, precisely because it's the standard, fully legitimate way huge amounts of ordinary software (VPN clients, chat apps, update checkers, printer utilities) register themselves to start at login. The signal worth chasing isn't "a Run key was set" on its own; it's whether the binary it points to is signed, matches a known deployment, and lives in an expected location: the same triage discipline the analyst_choice task in this room will walk through directly.`,
      codeExample:
        "REGISTRY RUN KEY LOCATIONS\n" +
        "=======================================================\n" +
        "HKCU\\...\\CurrentVersion\\Run      Per-user, no admin needed\n" +
        "HKCU\\...\\CurrentVersion\\RunOnce  Per-user, runs once then deletes itself\n" +
        "HKLM\\...\\CurrentVersion\\Run      All users, admin rights required to write\n" +
        "HKLM\\...\\CurrentVersion\\RunOnce  All users, admin rights required, one-shot\n" +
        "\n" +
        "shell:startup (per-user) / All Users Startup folder\n" +
        "  -- GUI-visible equivalent, same per-user/admin distinction\n" +
        "=======================================================",
      checkpoint: {
        question:
          "Triage finds two new Run-key values on one host: one under HKCU, one under HKLM. What does the HKLM value tell you that the HKCU one does not?",
        options: [
          "That it runs once and then deletes itself, unlike the HKCU value",
          "That whoever wrote it had admin rights, since HKLM is protected",
          "That it will launch just for administrators who log on to the host",
          "That the attacker already held SYSTEM, the account that writes HKLM",
        ],
        answer: 1,
        explanation:
          "HKLM is a machine-wide, protected hive, so planting a Run value there required administrator rights; HKCU is writable by the logged-on user. Running once and deleting itself is RunOnce behaviour, which exists under both hives. An HKLM Run value launches for every user who logs on, not only administrators. And administrator rights are enough to write HKLM. It does not prove SYSTEM.",
      },
    },
    {
      type: "reading",
      id: "persist-r2",
      heading: "Scheduled Tasks (T1053.005) and Cron (T1053.003)",
      content:
        `Where a Run key only fires at logon, the Windows Task Scheduler and Linux's cron can trigger persistence on almost any condition (a specific time, a recurring interval, system startup, even a particular event) which makes them both more flexible for an attacker and, in principle, more distinctive to hunt for.\n\n` +
        `**Windows Scheduled Tasks and the /ru SYSTEM flag**\n\n` +
        `schtasks.exe /create lets an attacker register a task with a trigger (/sc. Onstart, daily, onlogon, and others), a target binary (/tr), and critically, a "run as" principal (/ru) specifying which account's privileges the task executes with. Registering a task to run /ru SYSTEM is a privileged operation: Task Scheduler checks the calling process's own token before allowing it to register a task under a different, more privileged principal, which means the process running schtasks.exe must already hold an elevated token to succeed. This is not a privilege escalation technique on its own, it's a persistence technique that requires escalation to have already happened. Task creation is logged as Event ID 4698 on the host (Task Scheduler's own operational log also records related events, including 106 for task registration and 140/141 for updates and deletions), and Sysmon's process-creation telemetry for schtasks.exe itself shows the full command line, including the /ru value, directly.\n\n` +
        `**Linux cron**\n\n` +
        `The equivalent on Linux is a crontab entry. Either a user's personal crontab (crontab -e, running with that user's own privileges) or an entry dropped into /etc/cron.d/ or /etc/crontab, which commonly run as root and are writable only by a privileged account, mirroring the same "the level of access required to plant it tells you what the attacker already had" logic as HKCU versus HKLM. This activity surfaces as a linux_cron event type in host-based Linux auditing, alongside the shell history or auditd record of whichever command actually edited the crontab.\n\n` +
        `**The setgid crontab bit: a subtler user-level persistence path**\n\n` +
        `System-level cron (/etc/cron.d and /etc/crontab) is easy to reason about: only root can write those files, so a job appearing there means the attacker already had root. But the crontab -e path an ordinary user takes to edit their own personal crontab is worth understanding mechanically, because it depends on a Linux permission feature that trips people up: the setgid bit. The /usr/bin/crontab binary on many Linux distributions is installed with its setgid (set-group-ID) bit set, meaning that whoever runs it temporarily executes with the file's owning group, not the caller's own group, for the duration of that one command. That's normal and by design: it's how an unprivileged user is allowed to write into the protected cron spool directory (commonly owned by a dedicated group such as crontab, GID 102 in some distributions) at all, without needing to be root. The moment crontab runs, the process's effective group ID (egid) temporarily switches (for example, from the calling user's ordinary group 1004 to the crontab-owning group 102) write the new job into the spool, then exits and drops that borrowed group membership.\n\n` +
        `This is a completely legitimate mechanism, which is exactly why it matters to an analyst: it means a low-privileged, unprivileged local account (one with no sudo rights, no root shell, nothing "special" about it at all) can still install its own persistent, recurring cron job using nothing but a binary and a permission bit already present on every default install. No exploit is required and no privilege escalation event fires, because none actually occurred; the user is only using the access setgid was designed to grant. This is precisely why it's a favored technique after gaining any local foothold at all, however low-privileged: the attacker doesn't need to escalate first, they only need to reach crontab -e as whatever user they already are. Detection has to shift accordingly, not "did this account escalate privileges," which it did not, but "did this account, which has never run crontab before, suddenly create or modify a personal cron job," visible in auditd as an execve of /usr/bin/crontab followed by a write to that user's spool file under /var/spool/cron/crontabs/ (paths vary slightly by distribution), together with the transient egid switch itself if process-level group auditing is enabled.\n\n` +
        `**Why this trigger flexibility matters operationally**\n\n` +
        `A logon-triggered Run key only fires when a user logs on: useful, but conditional. An onstart-triggered scheduled task fires at every single boot, regardless of whether any particular user ever logs in at all, which is exactly why it's a favored mechanism for persistence on servers and infrastructure hosts that may reboot (for patching, for example) far more often than any human logs onto them interactively.`,
      codeExample:
        "SCHEDULED TASK CREATION -- KEY FIELDS TO PULL\n" +
        "=======================================================\n" +
        "schtasks.exe /create\n" +
        "  /sc <trigger>     onstart, daily, onlogon, onevent, ...\n" +
        "  /tn <name>        task name (often disguised as legit-looking)\n" +
        "  /tr <path>        the binary/script that actually runs\n" +
        "  /ru <principal>   who it runs AS -- /ru SYSTEM requires the\n" +
        "                    CALLING process to already be elevated\n" +
        "\n" +
        "Windows Event ID 4698   Scheduled task created\n" +
        "Sysmon Event ID 1       schtasks.exe process creation,\n" +
        "                        full CommandLine incl. /ru value\n" +
        "\n" +
        "Linux equivalent: crontab -e (user-level) or\n" +
        "/etc/cron.d/* , /etc/crontab (root-level, root-writable only)\n" +
        "=======================================================\n\n" +
        "SETGID CRONTAB MECHANISM (crontab -e path)\n" +
        "=======================================================\n" +
        "/usr/bin/crontab has the setgid bit set on many distros\n" +
        "  -> caller's egid temporarily becomes the crontab group\n" +
        "     (e.g. egid 1004 -> 102) for the duration of the command\n" +
        "  -> allows an UNPRIVILEGED user to write into the\n" +
        "     protected cron spool directory -- no root/sudo needed\n" +
        "  -> no privilege-escalation event fires -- none occurred,\n" +
        "     this is the setgid mechanism working as designed\n" +
        "\n" +
        "Watch for: execve of /usr/bin/crontab (in auditd) by an\n" +
        "account that has never used it before, followed by a write\n" +
        "to /var/spool/cron/crontabs/<user>\n" +
        "=======================================================",
      checkpoint: {
        question:
          "A local account with no sudo rights runs crontab -e and successfully installs a recurring job. No privilege-escalation event appears anywhere in the logs. Why not?",
        options: [
          "A logging gap: installing a cron job needs root, so an escalation was missed",
          "crontab's setgid bit lends the spool group's write access; nothing was escalated",
          "crontab -e jobs run as root by default, so the job itself needed no escalation",
          "auditd does not record crontab use, so no event of any kind would be produced",
        ],
        answer: 1,
        explanation:
          "This is the setgid mechanism from the reading: crontab is installed with setgid set, so running it temporarily grants the caller the file's group (able to write the spool) without ever elevating the user's own account privileges. Because no escalation actually happens (the user is only using access the setgid bit was designed to grant everyone) no escalation event fires. This is exactly why detection has to focus on unusual crontab usage by an account, not on a nonexistent escalation signal. A personal crontab needs no root, and its jobs run as that user, not as root. And auditd can record the execve of /usr/bin/crontab and the write to the spool file. That is the signal to watch.",
      },
    },
    {
      type: "question",
      id: "persist-q1",
      question:
        "A Sysmon process-creation event shows schtasks.exe /create /sc onstart /tn \"SyncHelper\" /tr \"C:\\ProgramData\\sync.exe\" /ru SYSTEM, launched by a process at IntegrityLevel: Medium. What does the integrity level tell you about whether this task registration would succeed?",
      options: [
        "It would succeed: /ru is a label, and Task Scheduler does not check the caller",
        "It would most likely fail: a SYSTEM task needs an elevated caller, which this is not",
        "It would fail because C:\\ProgramData is read-only at Medium; integrity plays no part",
        "It would succeed, but the task would quietly run as the Medium-integrity user",
      ],
      answer: 1,
      explanation:
        "Task Scheduler enforces the privilege requirement described in this reading: registering a task under the SYSTEM principal requires the calling process to already hold an elevated token. A Medium-integrity process attempting this should be denied, which makes an observed Medium-integrity attempt worth noting as a failed escalation attempt rather than assuming it silently succeeded at a lower privilege: Task Scheduler does not silently downgrade the principal on failure, it rejects the registration. Nor is C:\\ProgramData the obstacle: standard users can normally create files there, and the question is about registering the task, not writing the binary.",
      xp: 20,
    },
    {
      type: "reading",
      id: "persist-r3",
      heading: "Windows Services (T1543.003)",
      content:
        `A Windows service is, by design, meant to run persistently and often with high privilege, which is exactly why registering a new one is one of the more powerful persistence mechanisms available, and why sc create (or the equivalent programmatic API calls) is worth watching closely.\n\n` +
        `**What makes a service attractive for persistence**\n\n` +
        `A service configured for automatic start type launches at every boot, with no user logon required at all, and services very commonly run as LocalSystem, meaning a newly registered malicious service isn't just persistent, it's persistent at SYSTEM privilege from the moment it first starts, with no separate escalation step needed. This makes service creation a favored technique specifically after an attacker has already achieved SYSTEM or administrative access once and wants to guarantee they keep it across reboots without having to re-run any escalation chain.\n\n` +
        `**What it looks like in logs**\n\n` +
"Windows logs new service installation as Event ID 7045 (a new service was installed on the system). Key fields include the service name, the image path (ImagePath, pointing to the actual binary that will run), the start type, and the account it's configured to run as. A service whose ImagePath points into a temporary directory, a user profile folder, or anywhere outside the expected Program Files/System32 locations, especially one configured to run as LocalSystem, is a strong persistence indicator on its own: legitimate, vendor-installed services essentially never live in locations like C:\\Users\\Public or %TEMP%.\n\n" +
        `**Distinguishing this from ordinary software installation**\n\n` +
        `Plenty of entirely legitimate software installs a new service: backup agents, endpoint security tools, database engines. The differentiators are the same ones that apply throughout this room: is the binary signed, does its path match an expected vendor location, and is there a change record or deployment tool (SCCM, Intune, a documented installer) that accounts for it. A 7045 event with no corroborating deployment record, pointing to an unsigned binary in an unusual path, deserves the same scrutiny as an unexplained scheduled task.`,
      codeExample:
        "WINDOWS SERVICE PERSISTENCE -- WHAT TO PULL FROM EVENT 7045\n" +
        "=======================================================\n" +
        "Event ID 7045 (Service Control Manager)\n" +
        "  Service Name       -- often disguised to look benign\n" +
        "  Service File Name  -- the ImagePath; check location\n" +
        "                        (Program Files/System32 = expected;\n" +
        "                         Temp/Public/user profile = suspect)\n" +
        "  Service Type       -- own process vs shared\n" +
        "  Service Start Type -- 'auto start' = runs every boot,\n" +
        "                        no logon required\n" +
        "  Service Account    -- LocalSystem = SYSTEM privilege\n" +
        "                        from first start, no further\n" +
        "                        escalation needed\n" +
        "=======================================================",
    },
    {
      type: "reading",
      id: "persist-r4",
      heading: "BITS Jobs (T1197) and WMI Event Subscriptions",
      content:
        `Two mechanisms in this reading share a common advantage for an attacker: both use trusted, built-in Windows components, and neither shows up in the "obvious" persistence locations (Run keys, Task Scheduler, Services) a defender might check first.\n\n` +
        `**BITS jobs**\n\n` +
        `The Background Intelligent Transfer Service (BITS) is a Windows component designed to manage file transfers in the background (most visibly used by Windows Update itself) throttling bandwidth and resuming automatically after interruptions. bitsadmin.exe (or the modern BITS PowerShell cmdlets) can create a BITS job with a NotifyCmdLine parameter: a command that BITS will execute automatically once the associated transfer completes. An attacker can create a BITS job whose "transfer" is trivial or even already complete, purely to get NotifyCmdLine to execute a payload, and because BITS is a normal, trusted OS service that plenty of legitimate software also uses, this activity often blends into background noise far better than a scheduled task would. BITS activity is logged in the Microsoft-Windows-Bits-Client/Operational event log, with Event ID 3 marking job creation (job title, owner and the creating process). That record does NOT show the job's NotifyCmdLine, to see the command a job will run, enumerate the queue with bitsadmin /list /allusers /verbose (or Get-BitsTransfer -AllUsers) or parse the BITS queue database during forensics.\n\n` +
        `**WMI event subscriptions**\n\n` +
        `Windows Management Instrumentation (WMI) supports permanent event subscriptions: a __EventFilter object defines a trigger condition (a specific time, a process starting, a user logging on. Nearly anything WMI can observe), a __EventConsumer object defines the action to take (frequently, running a command), and a __FilterToConsumerBinding object connects the two. Once registered, this subscription lives in the WMI repository itself, not the file system, not the registry in any of the locations Reading 1 covered, not Task Scheduler, and fires automatically forever, surviving reboots indefinitely, with no process needing to remain running in the meantime. This makes it one of the stealthiest persistence mechanisms available, because standard "autoruns" tooling that checks the well-known locations won't find it at all; it has to be specifically inspected for in the WMI repository. Sysmon Event IDs 19, 20, and 21 (WmiEvent: Filter, Consumer, and Filter-to-Consumer-Binding activity, respectively) are the direct way to catch this being created.\n\n` +
        `**Why both matter to a defender the same way**\n\n` +
        `The lesson from both mechanisms is the same: "I checked the usual persistence locations and found nothing" is not the same as "there is no persistence." A thorough sweep has to include BITS job enumeration and WMI subscription inspection specifically, not just Run keys, Startup folders, Scheduled Tasks, and Services.`,
      codeExample:
        "BITS JOB PERSISTENCE\n" +
        "=======================================================\n" +
        "bitsadmin /create ... /addfile ...\n" +
        "bitsadmin /SetNotifyCmdLine <job> <payload.exe> NULL\n" +
        "  -- NotifyCmdLine runs automatically on transfer completion\n" +
        "Log: Microsoft-Windows-Bits-Client/Operational, Event ID 3\n" +
        "     (job created -- NOT the NotifyCmdLine; for that run\n" +
        "      bitsadmin /list /allusers /verbose)\n" +
        "=======================================================\n\n" +
        "WMI EVENT SUBSCRIPTION PERSISTENCE\n" +
        "=======================================================\n" +
        "__EventFilter              defines the TRIGGER condition\n" +
        "__EventConsumer            defines the ACTION (e.g. run a command)\n" +
        "__FilterToConsumerBinding  connects trigger -> action\n" +
        "\n" +
        "Lives in the WMI repository -- NOT registry, NOT Task\n" +
        "Scheduler, NOT the file system. Standard 'autoruns' checks\n" +
        "MISS this entirely unless the WMI repository is inspected.\n" +
        "\n" +
        "Sysmon Event IDs 19 / 20 / 21 -- Filter / Consumer / Binding\n" +
        "=======================================================",
      checkpoint: {
        question:
          "Why can a WMI permanent event subscription survive a sweep that checks Run keys, Startup folders, Task Scheduler and Services?",
        options: [
          "It is stored as a hidden Run key value that registry sweeps skip",
          "It lives in the WMI repository, which none of those four checks read",
          "It deletes itself after firing and is re-created at the next boot",
          "It runs inside the Task Scheduler service, hidden from the task list",
        ],
        answer: 1,
        explanation:
          "The filter, consumer and binding live in the WMI repository, not in the registry Run keys, the Startup folders, Task Scheduler or the services list, so a sweep of those four never looks where it is. It is not a Run value of any kind. A permanent subscription stays registered and fires on every trigger; it does not delete and re-create itself. And it is executed by WMI, not by Task Scheduler. Inspect the repository directly, or catch creation with Sysmon Events 19/20/21.",
      },
    },
    {
      type: "question",
      id: "persist-q2",
      question:
        "An incident responder checks Run keys, the Startup folder, Task Scheduler, and Services on a compromised host and finds nothing unusual. They conclude the host has no persistence. What is wrong with this conclusion?",
      options: [
        "Nothing: those four places cover the Windows persistence that survives a reboot",
        "It is incomplete: BITS jobs and WMI subscriptions persist outside all four places",
        "It is incomplete: a scheduled task stays hidden from Task Scheduler until it first runs",
        "It is incomplete for user-level persistence, but SYSTEM-level is ruled out by the four",
      ],
      answer: 1,
      explanation:
        "This is the exact gap Reading 4 warns about: BITS jobs and WMI event subscriptions deliberately don't live in any of the four commonly-checked locations, which is precisely why they're effective. A complete sweep has to include bitsadmin/BITS job enumeration and inspection of the WMI repository's __EventFilter/__EventConsumer/__FilterToConsumerBinding objects, not stop at Run keys, Startup, Task Scheduler, and Services. A registered task is visible in Task Scheduler from the moment it is created, whether or not it has run. And SYSTEM-level persistence is not ruled out either: a BITS job or WMI subscription can run with high privilege while sitting outside all four places.",
      xp: 20,
    },
    {
      type: "log_analysis",
      id: "persist-la1",
      heading: "A Scheduled Task Registered to Run as SYSTEM",
      context:
        "WKS-FIN22 belongs to c.iversen, an accounts-payable analyst. Endpoint telemetry shows schtasks.exe was launched under this user's session shortly after an earlier alert flagged unusual elevated activity on this host. Review the event below.",
      event: scheduledTaskPersistEvent,
      questions: [
        {
          question:
            "c.iversen is an accounts-payable analyst, yet schtasks.exe ran at IntegrityLevel High. Given what Reading 2 says about this kind of task, where does this event sit in the attack, and what should you look for?",
          options: [
            "It is the escalation itself: registering the task is how her session reached High",
            "Escalation already happened; find how her session became elevated before this",
            "Nothing notable: processes launched from cmd.exe normally run at High integrity",
            "Little impact: the task runs as c.iversen, so a SYSTEM-level foothold is ruled out",
          ],
          answer: 1,
          explanation:
            "Reading 2 is explicit that registering a task under a more privileged principal is a persistence technique that requires an elevated caller. It is not the escalation. So by the time schtasks.exe ran, her session was already elevated, and the next question is how (the earlier alert on this host is where to start). For a standard user, cmd.exe runs at Medium integrity, so High is not the default. And the /ru value in the command line, not the user who typed it, decides which account the task runs as.",
          xp: 25,
        },
        {
          question:
            "The task binary path is C:\\Users\\Public\\svchelper.exe, and the trigger is /sc onstart. What does this combination tell you operationally, beyond confirming a task was created?",
          options: [
            "Little: onstart triggers and Public folders are common for ordinary software tasks",
            "It runs with full privileges at every boot, from a folder any local user can write to",
            "The file was staged by an administrator, since C:\\Users\\Public is an admin-only folder",
            "It fires once, after the first restart, so it behaves like a RunOnce registry value",
          ],
          answer: 1,
          explanation:
            "onstart fires at every startup with no logon needed (the boot-persistence pattern from Reading 2) and the task runs with the principal named by /ru. C:\\Users\\Public is writable by every local user, which is both an odd home for a privileged binary and a second risk: anyone with local access could swap the file later. Legitimate vendor tasks point into Program Files or System32, as the room teaches for services too. The Public folder is not admin-only. And an onstart trigger fires on every boot, not once.",
          xp: 25,
        },
        {
          question:
            "What is the correct containment order once this task is confirmed malicious?",
          options: [
            "Delete the scheduled task, confirm it is gone, and close the ticket",
            "Isolate, hunt every other mechanism and the elevation path, then reset and rebuild",
            "Reset c.iversen's password first, so the task can no longer authenticate",
            "Rebuild the host first, then hunt for other persistence on the fresh image",
          ],
          answer: 1,
          explanation:
            "Once persistence is confirmed, the order is contain, hunt for every mechanism this session may have planted (Run keys, other tasks, services, BITS, WMI) plus how the session got elevated, remove them, and only then reset credentials and rebuild. Deleting the one task you found ignores whatever else was planted. A scheduled task does not authenticate with her password each time it fires (it runs under the principal it was registered with) so a reset does not touch it. Rebuilding first destroys the evidence you need, and a fresh image has nothing left to hunt.",
          xp: 30,
        },
      ],
    },
    {
      type: "reading",
      id: "persist-r5",
      heading: "Cloud Account (T1136.003) and OAuth App Persistence (T1671)",
      content:
        `Every mechanism so far has been endpoint-based, something planted on a single host. Cloud and identity-based persistence is fundamentally different in one important way: it can survive actions that would kill every technique covered so far, including resetting the compromised user's own password.\n\n` +
        `**Why a password reset doesn't automatically evict a cloud attacker**\n\n` +
        `If an attacker compromises a cloud identity (an Azure AD / Microsoft Entra ID account, for example) and creates a brand new cloud account, adds themselves to a privileged role, or, very commonly, grants an OAuth application consent to their compromised user's mailbox or data, none of those actions depend on continuing to know that user's password. An OAuth app grant works through a refresh token issued once at consent time, independent of the account's password entirely; resetting the password does not revoke previously issued OAuth tokens or app permissions unless the defender specifically also revokes app consents and active sessions as a separate remediation step. A newly created cloud account, similarly, has its own separate credentials from the very start.\n\n` +
        `**The specific techniques**\n\n` +
        `T1136.003 covers an attacker creating an entirely new cloud account, often with an innocuous-looking name, as a durable foothold independent of any single compromised user. Malicious OAuth app consent is a closely related and, in practice, extremely common technique, tracked separately in ATT&CK as T1671 (Cloud Application Integration): a phishing page tricks a user into approving what looks like a normal third-party app permission request, and the attacker's app is granted delegated access (commonly to read mail, or in broader grants, to access files and other data) that persists as long as the consent remains active, again, entirely independent of the user's password. A related mailbox-level technique worth knowing: attacker-created inbox forwarding rules or mailbox delegation, which likewise survive a password reset because they're configured mailbox-side, not credential-side.\n\n` +
        `**The operational takeaway**\n\n` +
        `Any cloud account compromise investigation has to include a specific check for newly created accounts, newly granted OAuth app consents, and mailbox rule/delegation changes: a password reset alone, no matter how quickly it's done, does not remediate any of these, and treating it as sufficient is one of the most common incomplete-containment mistakes in cloud incident response.`,
      codeExample:
        "WHY PASSWORD RESET ALONE DOESN'T EVICT CLOUD PERSISTENCE\n" +
        "=======================================================\n" +
        "Mechanism                    Survives a password reset?\n" +
        "-------------------------------------------------------\n" +
        "New cloud account created     YES -- has its own separate\n" +
        "(T1136.003)                   credentials from creation\n" +
        "OAuth app consent granted     YES -- refresh token issued at\n" +
        "(T1671)                       consent time, independent of\n" +
        "                              the account's password\n" +
        "Mailbox forwarding rule /     YES -- configured mailbox-side,\n" +
        "delegation                    not credential-side\n" +
        "-------------------------------------------------------\n" +
        "Required remediation: revoke OAuth app consents AND active\n" +
        "sessions/tokens, review new accounts, review mailbox rules --\n" +
        "in addition to, not instead of, the password reset\n" +
        "=======================================================",
    },
    {
      type: "reading",
      id: "persist-r6",
      heading: "Why Persistence Changes the Incident",
      content:
        `Every mechanism in this room shares one operational consequence, and it's the single most important thing to take from this entire topic: confirmed persistence changes the order in which you're allowed to remediate.\n\n` +
        `**Persistence is what makes an incident an incident**\n\n` +
        `A single compromised process, with no persistence mechanism behind it, is largely self-limiting. Kill the process, and the attacker's access ends when the host next reboots or the session ends, even without further action. The moment any persistence mechanism is confirmed, that stops being true: the attacker has engineered a way back in that doesn't depend on the initial foothold surviving. This is the practical dividing line between "an alert we closed" and "an incident we have to fully work". Persistence is what obligates the fuller response.\n\n` +
        `**Why the naive order fails**\n\n` +
        `The instinctive order (kill the malicious process, reset the compromised account's password, move on) works perfectly against a purely in-memory, no-persistence compromise. Against a confirmed persistence mechanism, it fails in a specific, predictable way: a Run key, scheduled task, service, BITS job, or WMI subscription doesn't care that the password changed, because none of them re-authenticate using that password to keep running. They were already planted, and they'll fire again at the next trigger regardless of what the account's credentials are now. Similarly, as Reading 5 covered, cloud/OAuth persistence specifically survives a password reset by design. Resetting credentials first, without first finding and removing every persistence mechanism, gives a false sense of closure while leaving the attacker's way back in fully intact.\n\n` +
        `**The correct order**\n\n` +
        `Contain first: isolate the affected host or account to stop further damage while you investigate. Then hunt comprehensively across every mechanism in this room. Run keys and Startup folders, Scheduled Tasks and cron, Services, BITS jobs, WMI subscriptions, and, for identity/cloud compromises, new accounts and OAuth consents. Before assuming you've found everything. Only once every confirmed mechanism is removed does resetting credentials and rebuilding actually close the door rather than just changing the lock while leaving a spare key already handed out.`,
      codeExample:
        "CONTAINMENT ORDER: NO PERSISTENCE vs CONFIRMED PERSISTENCE\n" +
        "=======================================================\n" +
        "No persistence confirmed:\n" +
        "  Kill process -> reset credentials if warranted -> done\n" +
        "\n" +
        "Persistence confirmed (the case this room prepares you for):\n" +
        "  1. Isolate/contain (host and/or account)\n" +
        "  2. Enumerate EVERY persistence mechanism, not just the\n" +
        "     one you already found (Run keys, tasks, services,\n" +
        "     BITS, WMI subscriptions, new cloud accounts, OAuth\n" +
        "     consents, mailbox rules)\n" +
        "  3. Remove/disable each confirmed mechanism\n" +
        "  4. THEN reset credentials and revoke sessions/tokens\n" +
        "  5. Rebuild or verify a clean state before returning to\n" +
        "     production\n" +
        "\n" +
        "Doing step 4 before step 2/3 leaves the attacker's way\n" +
        "back in fully intact.\n" +
        "=======================================================",
      checkpoint: {
        question:
          "A malicious Run key is confirmed on a user's laptop and the user asks you to just reset her password now. Why does the reading put the reset after the hunt instead?",
        options: [
          "A reset made before the rebuild is lost when the host is re-imaged",
          "Planted mechanisms don't use her password, so they survive a reset",
          "The Run key re-reads her password at logon, so a reset breaks evidence",
          "Once the Run key is deleted, a password reset is no longer needed",
        ],
        answer: 1,
        explanation:
          "Run keys, tasks, services, BITS jobs and WMI subscriptions fire on their own triggers without using her password, so resetting first changes the lock while the attacker's spare key stays planted. Contain, hunt every mechanism, remove them, then reset. A password reset lives in the directory, not on the laptop, so re-imaging does not undo it. A Run key stores a command to launch, not a credential. And deleting one Run key does not make the reset unnecessary: the reset still closes off any credentials the attacker obtained.",
      },
    },
    {
      type: "question",
      id: "persist-q3",
      question:
        "During a cloud account compromise investigation, the SOC resets the affected user's password within minutes of detection and closes the incident. Three days later, the same user's mailbox is still leaking messages to an external address via a forwarding rule the attacker configured before the reset. What was missed, and why?",
      options: [
        "Nothing: a reset wipes the account's mailbox rules, so this rule must be a new one",
        "The rule is mailbox-side, so it survives a reset; rules and tokens also need removal",
        "MFA methods were not re-registered after the reset, which kept the old rule active",
        "The attacker had admin rights, since ordinary users cannot create forwarding rules",
      ],
      answer: 1,
      explanation:
        "This is precisely the gap Reading 5 and Reading 6 both warn about: a mailbox forwarding rule doesn't depend on continuing to know the account's password to keep functioning, so resetting the password has no effect on it. The correct remediation has to specifically include reviewing and removing mailbox rules (and revoking OAuth consents/active sessions) as separate steps, not assume the password reset alone was sufficient. A reset does not touch existing rules, so the rule can be the old one. MFA registration controls sign-in, not whether a rule already in the mailbox keeps running. And ordinary users can create inbox and forwarding rules on their own mailbox, which is exactly why attackers with a user's session use them.",
      xp: 25,
    },
    {
      type: "analyst_choice",
      id: "persist-ac1",
      heading: "Verdict: A VPN Client Registering an Autorun Entry",
      scenario:
        "A detection rule flagged an HKLM Run key write on WKS-OPS09 shortly after a software deployment window. Review the event and the deployment record attached to it.",
      event: legitUpdaterAutorunEvent,
      correct_verdict: "false_positive",
      explanation:
        "The registry write was made by MeridianVPNClient.exe itself, running as SYSTEM the way an SCCM-pushed installer does, and the endpoint record notes the binary is signed and matches the deployed version, during its own documented post-install configuration step, and an SCCM deployment record independently confirms this exact software and version was pushed to this host today. The Details value points to vpntray.exe inside the same Program Files installation directory as the parent binary, not an unusual or unexpected location. Any of these facts alone would be worth checking; together, they describe exactly the kind of legitimate, ordinary software autorun Reading 1 described as the majority case for Run key writes.",
      fp_trap:
        "A Run key write matches the shape of T1547.001 persistence closely enough that it's tempting to treat every instance as suspicious, especially right after other alerts on the same host. But the differentiators taught throughout this room: a signed binary, a path inside the expected Program Files installation folder rather than a temp or public directory, and independent corroboration from a deployment record. Are exactly what should separate this from a genuine finding. Escalating every Run key write without checking those three things first would generate far more noise than any SOC can sustainably triage, which is the over-alerting failure mode this room is explicitly trying to train against.",
      xp: 30,
    },
    {
      type: "matching",
      id: "persist-m1",
      heading: "Match Each Persistence Mechanism to Its Detection Source",
      instructions: "Match each persistence mechanism to the log source or artifact that reveals it.",
      pairs: [
        { id: "runkey", left: "HKCU/HKLM Run or RunOnce key value set", right: "T1547.001, Sysmon Event 13 (RegistryEvent: value set), TargetObject under CurrentVersion\\Run" },
        { id: "task", left: "Scheduled task registered with /ru SYSTEM", right: "T1053.005: Windows Event ID 4698 (Scheduled Task Created)" },
        { id: "service", left: "New service installed, auto-start, running as LocalSystem", right: "T1543.003: Windows Event ID 7045 (Service Installed)" },
        { id: "bits", left: "BITS job configured with a NotifyCmdLine", right: "T1197: Bits-Client/Operational Event 3 (job created), plus bitsadmin /list /allusers /verbose to see the NotifyCmdLine" },
        { id: "wmi", left: "__EventFilter/__EventConsumer/__FilterToConsumerBinding created in the WMI repository", right: "WMI event subscription persistence: Sysmon Events 19/20/21, missed by sweeps of Run keys, tasks and services" },
        { id: "oauth", left: "New OAuth app granted delegated mailbox permissions on a compromised account", right: "T1671 (Cloud Application Integration): survives a password reset because it doesn't depend on the account's password" },
      ],
      explanation:
        "Each pairing reflects a distinct mechanism and its specific detection source from this room: registry-based persistence shows up in Sysmon 13, task/service persistence show up in their own dedicated Windows Event IDs (4698/7045), BITS and WMI persistence deliberately avoid all of the 'usual' locations, and cloud/OAuth persistence is identity-side rather than endpoint-side entirely, which is exactly why it survives a password reset.",
      xp: 40,
    },
    {
      type: "ordering",
      id: "persist-o1",
      heading: "Order the Correct Containment Steps Once Persistence Is Confirmed",
      instructions: "Arrange the response steps in the correct order for an incident where a persistence mechanism has been confirmed.",
      items: [
        { id: "isolate", text: "Isolate the affected host and/or account to stop further damage" },
        { id: "enumerate", text: "Enumerate every persistence mechanism the attacker may have planted (Run keys, tasks, services, BITS, WMI, cloud accounts, OAuth consents, mailbox rules)" },
        { id: "remove", text: "Remove or disable each confirmed persistence mechanism" },
        { id: "reset", text: "Reset compromised credentials and revoke active sessions/tokens" },
        { id: "rebuild", text: "Rebuild or verify a clean state before returning the host/account to production" },
      ],
      correct_order: ["isolate", "enumerate", "remove", "reset", "rebuild"],
      explanation:
        "This is the exact order from Reading 6: resetting credentials before finding and removing every persistence mechanism leaves the attacker's non-credential-based ways back in fully intact, a Run key, service, or OAuth consent doesn't care that the password changed. Containment and a full enumeration have to come first, remediation of each specific mechanism next, and only then credential resets and rebuild/verification.",
      xp: 35,
    },
    {
      type: "flag",
      id: "persist-f1",
      event: scheduledTaskPersistEvent, // show the scheduled-task log this flag reads
      prompt:
        "In the scheduled-task event, which account will svchelper.exe run as every time the task fires? Enter the account exactly as the registration command names it.",
      answer: "SYSTEM",
      hint: "The user who typed the command is not necessarily the account the task runs as. One switch in the command line decides that.",
      xp: 25,
    },
  ],
};

export const roomsBatch18 = [kerberosRoom, privescRoom, persistenceRoom];
