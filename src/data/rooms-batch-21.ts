/**
 * Learning Rooms — Batch 21
 *
 * Closes two beginner-tier coverage gaps:
 *
 * - log-entry-anatomy — a generic, format-agnostic grounding in how to read
 *   ANY log entry (syslog, key=value, JSON, CSV/W3C, CEF/LEEF), before a
 *   student is ever asked to read a vendor-specific log elsewhere on the
 *   platform. Teaches the five-question frame (when/who/where/what/how
 *   confident), field-name normalisation, why severity is a vendor opinion
 *   rather than a fact, and how to read absence of evidence correctly.
 *
 * - identity-basics — the first step before active-directory, entra-id, and
 *   kerberos-authentication, all of which currently assume a student already
 *   understands authentication vs authorization, MFA factors, what a
 *   credential is (including that a password hash is one), and how session
 *   tokens work. This room is what makes pass-the-hash, AitM token theft, and
 *   MFA fatigue make sense later, instead of being introduced cold.
 */

import type { Room } from "@/data/rooms";
import type { TelemetryEvent } from "@/lib/sim/types";

// =============================================================================
// ROOM 1: log-entry-anatomy
// =============================================================================

const zeekConnEvent: TelemetryEvent = {
  id: "evt-loganat-la1-001",
  ts: "2026-02-11T09:14:22.481Z",
  source: "ids",
  vendor: "Corelight (Zeek)",
  event_type: "net_connection",
  hostname: "zeek-sensor-corevlan",
  description:
    "The core-VLAN Zeek sensor recorded this TCP connection record between two internal hosts. Zeek's conn.log format summarises connections rather than rating them — apply the five-question method from Reading 1 to work out what this record can, and cannot, tell you.",
  // Zeek's conn.log genuinely has no identity field and no severity field —
  // that is a real property of this data source, not an omission for the
  // exercise. uid below is a per-connection flow identifier, not a username.
  raw: {
    ts: 1770800062.481,
    uid: "CHhAvVGS1DHFjwGM9",
    "id.orig_h": "10.40.6.118",
    "id.orig_p": 51422,
    "id.resp_h": "10.40.2.15",
    "id.resp_p": 3389,
    proto: "tcp",
    service: "-",
    duration: 812.334,
    orig_bytes: 48210,
    resp_bytes: 991823,
    conn_state: "SF",
    history: "ShADadfF",
    orig_pkts: 640,
    resp_pkts: 712,
  },
};

const fortigateIpsEvent: TelemetryEvent = {
  id: "evt-loganat-ac1-001",
  ts: "2026-03-02T02:10:04.000Z",
  source: "ids",
  vendor: "FortiGate",
  event_type: "ids_signature",
  severity: "critical",
  hostname: "SRV-DB07.meridian.local",
  description:
    "FortiGate's IPS engine on the DMZ segment logged this signature match. The vendor's built-in severity rating for this signature family is 'critical' by default, regardless of the source or destination.",
  it_verify_result: "confirmed",
  it_verify_message:
    "Change ticket CHG-91004 confirms this falls inside the monthly authorised vulnerability-scan window (02:00-04:00), run by the internal Qualys scanner at 10.20.1.50 against the DMZ subnet.",
  raw: {
    type: "utm",
    subtype: "ips",
    level: "critical",
    srcip: "10.20.1.50",
    dstip: "10.20.4.17",
    srcport: 51190,
    dstport: 443,
    action: "detected",
    attack: "SQL.Injection.Generic",
    proto: "tcp",
    policyid: 14,
  },
};

const logEntryAnatomyRoom: Room = {
  id: "log-entry-anatomy",
  title: "Anatomy of a Log Entry",
  description:
    "Learn to read any log you have never seen before: the five questions every entry answers (when, who, where, what, how confident), the formats you will actually meet — plain syslog, key=value, JSON, CSV/W3C, and CEF/LEEF — why the same fact gets a different field name in every product and how a SIEM normalises them, why severity is a vendor's opinion and not a fact, and how to tell 'it didn't happen' apart from 'it wasn't logged.'",
  difficulty: "beginner",
  category: "Log Analysis",
  estimatedMinutes: 45,
  xp: 205,
  icon: "🔎",
  prerequisites: ["intro-cybersecurity"],
  tasks: [
    // ----- Reading 1: The five-question frame -------------------------------
    {
      type: "reading",
      id: "loganat-r1",
      heading: "The Five Questions Every Log Answers",
      content:
        `Picture a security guard's logbook at a building's front desk. Every entry follows the same shape no matter who wrote it: the time someone came in, whose badge they used, which door they went through, what they did, and how sure the guard is that anything is wrong. A new guard reading last week's entries, written by someone else, in a different building, can still make sense of them because that shape never changes.\n\n` +
        `Every log entry a computer system produces follows the same shape. Once you can find these five things in any log, you can start reading logs you have never seen before — which is most of the job, because no analyst has memorised every product's format.\n\n` +
        `**WHEN — the timestamp.** Every entry records when the recorded thing happened. This sounds trivial until you notice that "when it happened" and "when you are reading about it" can be hours apart, and that different systems record time in different formats and sometimes different time zones — a real, recurring source of investigative mistakes.\n\n` +
        `**WHO — the identity.** Who or what caused this? A username, a service account, a process, sometimes a device with no human behind it at all — one server calling another. Not every log has a human identity in it at all, and that absence is itself information, covered later in this room.\n\n` +
        `**WHERE — source and destination.** Which host, IP address, or system was involved — often two of them: where the action came from, and what it touched. A login has a source (the workstation the person typed on) and a destination (the server they logged into).\n\n` +
        `**WHAT — the action and its outcome.** What actually happened, and did it succeed or fail? "User logged in" and "user failed to log in" are opposite outcomes of the same action, and mixing them up is one of the most common beginner mistakes in this field.\n\n` +
        `**HOW CONFIDENT — severity or level.** Most logs carry some rating of how urgent the vendor thinks this entry is: critical, high, informational, and so on. Reading 6 in this room explains why that field deserves more suspicion than the other four put together.\n\n` +
        `Hold onto this five-question frame — it is also the method. When you meet an unfamiliar log format for the first time: find the timestamp, find the identity field, find the action field, find the outcome field, and only then go looking for any additional fields the specific question in front of you actually requires. Every reading after this one hands you a different format — plain text, key-value pairs, JSON, spreadsheets — but the same five questions apply to all of them.`,
      diagram:
        "flowchart TD\n" +
        "  L[\"Raw syslog line: Jun 24 14:32:11 fw-edge-01 sshd -- Failed password for invalid user admin from 203.0.113.55 port 51422 ssh2\"]\n" +
        "  L --> Q1[\"WHEN -- Jun 24 14:32:11 (the timestamp)\"]\n" +
        "  L --> Q2[\"WHERE -- fw-edge-01 is the host; 203.0.113.55 is the source IP\"]\n" +
        "  L --> Q3[\"WHO -- invalid user admin (the identity that was attempted)\"]\n" +
        "  L --> Q4[\"WHAT + OUTCOME -- sshd reported Failed password (a failed authentication)\"]\n" +
        "  L --> Q5[\"HOW CONFIDENT -- priority code 134 decodes to a low, informational-level severity\"]\n",
      diagramCaption: "Mapping the five-question frame onto a real log line",
    },
    // ----- Reading 2: Plain syslog ------------------------------------------
    {
      type: "reading",
      id: "loganat-r2",
      heading: "Plain Syslog: The Oldest Format You Will Still See Every Day",
      content:
        `Syslog is the original standard for log messages on Unix and Linux systems, standardised decades ago and still the default output format for network devices, routers, older Linux daemons, and a large share of the security appliances you will meet on the job.\n\n` +
        `**The shape of a syslog line.** A classic syslog entry (the RFC 3164 style) opens with a priority code in angle brackets, followed by a month, day, and time with no year, a hostname, a process name with its process ID in brackets, a colon, and then a free-text message the process wrote itself. Look at the sample below with that shape in mind.\n\n` +
        `**The priority code.** The number in brackets at the start (134, in this sample) is not random — it is calculated as facility times 8 plus severity, where facility says which kind of system component logged it (mail, auth, kernel, and so on) and severity is a 0-7 scale built into the protocol itself, completely separate from whatever severity field a SIEM later assigns to the same event. Most analysts never decode it by hand; the collecting tool does that automatically.\n\n` +
        `**No year in the timestamp.** Notice the timestamp has no year — just month, day, and time. This is a real limitation of the original standard, and it means the *collector* has to stamp the ingestion year onto the message itself. Around New Year's Eve, a message that arrives a little late can be misdated by a year if a collector is not handling this carefully — a small but genuinely reported source of timeline errors in investigations.\n\n` +
        `**Why it is still everywhere.** Syslog's message body is free text — whatever the process author decided to write, in whatever shape they chose. That makes it flexible and cheap to implement, which is why so many devices still emit it, and it also makes it the hardest format on this list to parse reliably at scale, because there is no guaranteed structure inside the message itself beyond whatever convention the author happened to follow.\n\n` +
        `Apply the five-question frame to the sample: the timestamp is easy to find; the destination is the hostname sshd is running on; the identity is buried inside the free text itself ("invalid user admin"); the outcome is also inside the free text ("Failed password"). Notice how much of the useful information here is not in a clean, labelled field — it is inside a sentence a human wrote for another human to read. That is plain syslog's central weakness, and the reason the next two readings exist.`,
      codeExample:
        "<134>Jun 24 14:32:11 fw-edge-01 sshd[19442]: Failed password for invalid user admin from 203.0.113.55 port 51422 ssh2",
    },
    // ----- Question 1 --------------------------------------------------------
    {
      type: "question",
      id: "loganat-q1",
      question:
        "Using the five-question frame, what is the WHO in this syslog line: <134>Jun 24 14:32:11 fw-edge-01 sshd[19442]: Failed password for invalid user admin from 203.0.113.55 port 51422 ssh2 ?",
      options: [
        "fw-edge-01 — this is WHERE, the host that logged the event, not the WHO",
        "\"admin\" — the username the failed login attempt used, buried inside the free-text message",
        "sshd — this is the process/service name, not an identity",
        "203.0.113.55 — this is WHERE (the source), not WHO",
      ],
      answer: 1,
      explanation:
        "The identity being claimed in this failed attempt is the username 'admin', sitting inside the free-text portion of the message, exactly as Reading 2 described. fw-edge-01 and 203.0.113.55 both answer WHERE (the logging host and the source IP), and sshd names the process that wrote the log, not a person or account attempting to log in.",
      xp: 15,
    },
    // ----- Reading 3: key=value ----------------------------------------------
    {
      type: "reading",
      id: "loganat-r3",
      heading: "Key=Value: Why FortiGate and Palo Alto Logs Are Built to Be Grepped",
      content:
        `Key=value format writes each piece of information as a short field name, an equals sign, and its value, separated by spaces — no free-text sentence to parse, no need to guess where one fact ends and the next begins.\n\n` +
        `**Reading the sample.** Look at the line below: date and time are their own labelled fields, srcip and dstip name the two ends of the connection explicitly, and action states the outcome directly as a word, not a sentence.\n\n` +
        `**Why vendors like Fortinet, Palo Alto Networks, and Check Point favour it.** Every fact is already labelled. A human, or a simple grep or regex, can pull "srcip" out of a million lines without needing to understand sentence structure, quoting rules, or where a free-text description happens to end. This is the format's whole appeal: self-describing, and still readable as plain text — a middle ground between syslog's free text and JSON's nested structure, covered next.\n\n` +
        `**Applying the five-question frame.** date/time answer WHEN. srcip and dstip both answer WHERE — srcip is where the traffic came from, dstip is where it was headed, and telling those apart correctly matters enormously once you start reading firewall logs at volume. action answers WHAT happened, including its outcome (deny means blocked). level answers HOW CONFIDENT the vendor is that this entry matters.\n\n` +
        `**One habit worth building now.** In key=value logs, always check whether a field name means "source" or "destination" before you trust your instinct — vendors are not consistent about which side of a connection gets which prefix, and misreading srcip as the target of an attack instead of its origin is an easy, embarrassing mistake to make under time pressure.`,
      codeExample:
        "date=2026-06-24 time=14:32:19 devname=FGT-EDGE01 devid=FG100F logid=0000000013 type=traffic subtype=forward level=notice srcip=10.10.4.55 srcport=51422 dstip=203.0.113.55 dstport=443 proto=6 action=deny policyid=12 service=HTTPS",
    },
    // ----- Question 2 --------------------------------------------------------
    {
      type: "question",
      id: "loganat-q2",
      question:
        "In the key=value line above (FortiGate traffic log), which field tells you the outcome of the connection attempt, and what does it show?",
      options: [
        "devid=FG100F — identifies the logging device, not the outcome",
        "action=deny — the connection was blocked by the firewall",
        "proto=6 — just the protocol number for TCP, not an outcome",
        "policyid=12 — identifies which policy matched, not what happened as a result",
      ],
      answer: 1,
      explanation:
        "action is the outcome field here — action=deny states directly that the connection was blocked. devid identifies the device that logged the event, proto states the protocol number, and policyid names which rule matched, but none of those three say whether the traffic was allowed or stopped.",
      xp: 15,
    },
    // ----- Reading 4: JSON -----------------------------------------------------
    {
      type: "reading",
      id: "loganat-r4",
      heading: "JSON: Nested Fields and Why a Field Name Has Dots In It",
      content:
        `JSON (JavaScript Object Notation) organises data into objects that can contain other objects, and this nesting is exactly what makes Windows and many SIEM-ingested logs look intimidating the first time you see one.\n\n` +
        `**Reading the sample.** Look at the structure below: braces mark the start and end of an object, and a field name followed by a colon can point either to a plain value or to an entire nested object of its own.\n\n` +
        `**What the nesting means.** The event has a top-level field called winlog. Inside winlog is a field called event_data. Inside event_data is a field called TargetUserName. When a SIEM search bar shows you a field named winlog.event_data.TargetUserName, the dots are not decoration — they are a path, exactly like folders inside folders on a hard drive. winlog.event_data.TargetUserName means "go into winlog, then into event_data, then read TargetUserName."\n\n` +
        `**Why logs get structured this way.** Nesting lets a single event carry several related pieces of information — who did it, what tool logged it, what specific data the tool recorded — without cramming everything into one flat list of same-level fields, and without ambiguity about which value belongs to which concept. It also means the same underlying event can be represented as pretty, human-readable JSON or as a flat list of dotted field names in a search index — both are the same data, shown two different ways.\n\n` +
        `**Applying the five-question frame.** The timestamp field answers WHEN. winlog.event_id (4625) tells you WHAT happened generically — a Windows Security event, specifically a failed logon — and winlog.event_data.TargetUserName answers WHO. winlog.event_data.IpAddress answers WHERE the attempt came from. Notice that unlike the syslog example, every one of these facts sits in its own clearly labelled field — nothing here needs to be extracted from a sentence.`,
      codeExample:
        "{\n" +
        "  \"@timestamp\": \"2026-06-24T14:32:19.000Z\",\n" +
        "  \"winlog\": {\n" +
        "    \"event_id\": 4625,\n" +
        "    \"provider_name\": \"Microsoft-Windows-Security-Auditing\",\n" +
        "    \"event_data\": {\n" +
        "      \"TargetUserName\": \"j.romero\",\n" +
        "      \"IpAddress\": \"203.0.113.55\",\n" +
        "      \"LogonType\": \"3\"\n" +
        "    }\n" +
        "  }\n" +
        "}",
    },
    // ----- Matching ------------------------------------------------------------
    {
      type: "matching",
      id: "loganat-m1",
      heading: "Match Each Sample to Its Log Format",
      instructions: "Match each short log sample to the format it is written in.",
      pairs: [
        { id: "syslog", left: "Priority code, no-year date, hostname, process[pid]: free-text message", right: "Plain syslog (RFC 3164-style)" },
        { id: "kv", left: "srcip=10.10.4.55 dstport=443 action=deny policyid=12", right: "Key=value — self-describing pairs, common on Fortinet/Palo Alto/Check Point" },
        { id: "json", left: "A field named winlog.event_data.TargetUserName inside nested braces", right: "JSON — nested objects; dots in a field name represent nesting" },
        { id: "csv", left: "A #Fields header line naming columns, followed by rows of space-separated values", right: "CSV/W3C — a column's meaning depends entirely on the header line" },
        { id: "cef", left: "CEF:0|Fortinet|FortiGate|7.0|0000000013|Traffic Deny|5|src=10.10.4.55 dst=203.0.113.55", right: "CEF — a SIEM-normalised format vendors emit so one parser works across products" },
      ],
      explanation:
        "Each sample carries a distinct, recognisable shape: syslog's priority-code-plus-free-text, key=value's field=value pairs, JSON's nested braces and dotted paths, CSV/W3C's header-defines-the-columns rule, and CEF's fixed pipe-delimited header in front of key=value extensions. Recognising the shape is the first step to knowing where to look for the five-question fields inside it.",
      xp: 30,
    },
    // ----- Reading 5: CSV/W3C and CEF/LEEF --------------------------------------
    {
      type: "reading",
      id: "loganat-r5",
      heading: "CSV/W3C and CEF/LEEF: Spreadsheets and SIEM-Normalised Formats",
      content:
        `Two more formats round out what you will meet as a working analyst — one far older than JSON, one designed specifically to make a SIEM's job easier.\n\n` +
        `**CSV and the W3C Extended Log Format.** Internet Information Services (IIS), Microsoft's web server, writes its access logs as plain columns of values separated by spaces, preceded by a #Fields header line that names each column in order. This is the same idea as a spreadsheet: the third value in every row means whatever the third column header says it means — nothing more. Look at the sample below: the header says date time c-ip cs-username s-sitename cs-method cs-uri-stem sc-status, so the third value on the data row is the client IP only because that specific file's header put c-ip in that position. Two IIS logs configured differently can have completely different column orders, and if you skip the header line, you will misread every single row with total confidence and no idea you are wrong.\n\n` +
        `**CEF and LEEF — normalised for the SIEM, not for the device.** Common Event Format (CEF, from ArcSight) and Log Event Extended Format (LEEF, from IBM QRadar) are not native formats devices invented on their own — they are formats a SIEM vendor defined so that other products could emit logs in one predictable shape instead of the SIEM needing a custom parser for every vendor. A CEF line starts with a fixed header (CEF, a version number, vendor, product, version, a signature ID, a name, and a severity) followed by key=value extension fields, similar in spirit to Reading 3's key=value logs but with a standardised header in front. You will not often read raw CEF by hand — its whole purpose is to be machine-parsed reliably — but recognising it tells you the source is emitting logs in a format built specifically for interoperability, not its own native voice.\n\n` +
        `**The lesson underneath both.** A format's meaning is never self-evident from position alone. CSV needs its header; CEF needs its spec. The five-question frame still applies to both, but which raw text answers which question depends entirely on reading the surrounding definition first — exactly the discipline the next tasks ask you to apply, including to a format this room never shows you a sample of.`,
      codeExample:
        "#Fields: date time c-ip cs-username s-sitename cs-method cs-uri-stem sc-status\n" +
        "2026-06-24 14:32:11 203.0.113.55 - W3SVC1 GET /login.aspx 200\n\n" +
        "CEF:0|Fortinet|FortiGate|7.0|0000000013|Traffic Deny|5|src=10.10.4.55 dst=203.0.113.55 dpt=443 act=deny",
    },
    // ----- Ordering ------------------------------------------------------------
    {
      type: "ordering",
      id: "loganat-o1",
      heading: "Order the Repeatable Method for Reading an Unfamiliar Log",
      instructions: "You are handed a log format you have never seen before, from a product you don't know. Put these steps in the order Reading 1 recommends.",
      items: [
        { id: "step-ts", text: "Find the timestamp — establish when this happened" },
        { id: "step-who", text: "Find the identity field — who or what triggered it" },
        { id: "step-what", text: "Find the action/event-type field — what happened" },
        { id: "step-outcome", text: "Find the outcome field — did it succeed, fail, or get blocked" },
        { id: "step-extra", text: "Only then look up any additional fields the specific question actually requires" },
      ],
      correct_order: ["step-ts", "step-who", "step-what", "step-outcome", "step-extra"],
      explanation:
        "This is the five-question method from Reading 1, applied in the order that gets you oriented fastest: timestamp and identity ground you in when and who, action and outcome tell you what happened and how it ended, and only after those four are answered do you go hunting for whatever extra fields your specific investigative question needs — chasing details before you have the basic shape wastes time and invites misreads.",
      xp: 25,
    },
    // ----- Reading 6: normalisation ----------------------------------------------
    {
      type: "reading",
      id: "loganat-r6",
      heading: "Field Naming Chaos, and Why a SIEM Normalises Everything",
      content:
        `Here is the same fact — a source IP address of 10.10.4.55 — as it might appear, completely unedited, in five different real products: srcip in a Fortinet log, source.ip in an Elastic Common Schema-normalised event, id.orig_h in Zeek network monitoring records, cIP in an older-style IIS log, and ClientIP in an Azure AD sign-in log.\n\n` +
        `**Why this happens.** Every vendor designed their own logging schema independently, often years apart, often before any industry-wide convention existed. Nobody sat down and agreed on one name for "the IP address a connection came from" across the entire security industry — each product just picked something that made sense to its own engineers at the time.\n\n` +
        `**Why this matters to you.** If you had to write five completely different search queries — one per vendor's field name — every time you wanted to check whether a single suspicious IP address touched anything anywhere in your environment, correlation across log sources would be nearly impossible at any real scale. This is exactly the problem a SIEM's normalisation layer solves: it maps every vendor's own field name onto one common schema field, so a single query for source.ip: 10.10.4.55 can search across your firewall, your web server, your identity provider, and your network sensor all at once, regardless of what each one originally called that field.\n\n` +
        `**What this means practically.** When you open raw logs, as this room has done throughout, you will see the vendor's own native field names — because that is literally what the product emits. When you search inside a SIEM, you are almost always querying the normalised names instead. Knowing both matters: you need the normalised name to write a cross-source query, and you need the native name to correctly read a raw log sample, a vendor's documentation, or a support ticket that quotes the product's own field directly.`,
      diagram:
        "flowchart LR\n" +
        "  A[\"Fortinet FortiGate: srcip = 10.10.4.55\"] --> N[\"Normalised SIEM field: source.ip = 10.10.4.55\"]\n" +
        "  B[\"Zeek/Bro: id.orig_h = 10.10.4.55\"] --> N\n" +
        "  C[\"Legacy IIS: cIP = 10.10.4.55\"] --> N\n" +
        "  D[\"Azure AD sign-in: ClientIP = 10.10.4.55\"] --> N\n" +
        "  E[\"Older Suricata: src_ip = 10.10.4.55\"] --> N\n" +
        "  N --> Q[\"One query now works across every source: source.ip: 10.10.4.55\"]\n",
      diagramCaption: "Five vendors, one fact, one normalised field",
    },
    // ----- Question 3 ------------------------------------------------------------
    {
      type: "question",
      id: "loganat-q3",
      question:
        "A SIEM correlation rule needs to check whether the same IP address appears in both your firewall logs (which use srcip) and your identity provider's sign-in logs (which use ClientIP). What makes this possible without writing two separate field names into the rule?",
      options: [
        "It isn't possible — each log source must always be queried separately with its own native field name",
        "The SIEM's normalisation layer maps both srcip and ClientIP onto one common schema field (for example, source.ip), so a single query condition matches both",
        "Firewalls and identity providers never record IP-related fields, so this correlation can't be built at all",
        "You must manually rename the field inside the identity provider's own product settings before the two logs can ever be compared",
      ],
      answer: 1,
      explanation:
        "This is exactly the normalisation concept from Reading 6: the SIEM maps each vendor's native field name onto one shared schema field behind the scenes, so an analyst can write one condition that matches the fact regardless of which product logged it. Nothing needs to be renamed at the source product, and both log types genuinely do carry IP fields — they're just spelled differently.",
      xp: 15,
    },
    // ----- Reading 7: severity is a vendor opinion --------------------------------
    {
      type: "reading",
      id: "loganat-r7",
      heading: "Severity Is a Vendor Opinion, Not a Fact",
      content:
        `It is tempting to treat a log's severity field as an objective measurement of danger, the way a thermometer measures temperature. It is not that. Severity is a rating one specific vendor's engineers assigned to one specific category of event, according to that vendor's own internal scale — and different vendors do not use the same scale, the same criteria, or even always agree with themselves over time.\n\n` +
        `**Two "criticals" that mean different things.** An antivirus product might mark every detection of a known ransomware family as critical, regardless of whether the file was quarantined instantly with zero impact or whether it actually executed. A firewall's intrusion-prevention engine might mark an entire signature family — say, generic SQL injection patterns — as critical by default, regardless of whether the destination is a public web form or an internal test server nobody uses. Both say "critical." Neither number tells you what actually happened at your organisation; both only tell you how the vendor classifies that category of finding in general.\n\n` +
        `**Severity is not the same thing as impact.** Impact depends on what was actually touched, whether it succeeded, whether compensating controls stopped it, and whether the target mattered. A "critical" alert against an internal test server that was already scheduled for a vulnerability scan may have essentially zero real impact. A "medium" alert on a domain controller that nobody expected any activity on at 3 a.m. might deserve far more of your attention than the label alone suggests.\n\n` +
        `**What this means for triage.** Never let severity alone decide how urgently you investigate something, and never assume two "high" alerts from two different products carry equal weight. Use severity as one input — a vendor's rough first guess — and always read the actual fields underneath it: the source, the destination, the outcome, and whatever context (a change ticket, an asset's role, a pattern across multiple events) tells you what this specific occurrence actually means.`,
    },
    // ----- Analyst choice (false positive) -----------------------------------------
    {
      type: "analyst_choice",
      id: "loganat-ac1",
      heading: "Verdict: A 'Critical' IPS Signature Against the DMZ",
      scenario:
        "A detection dashboard escalates any FortiGate IPS event with level=critical for immediate review. Review the event below alongside the change-ticket note attached to it.",
      event: fortigateIpsEvent,
      correct_verdict: "false_positive",
      explanation:
        "The signature genuinely matched — attack=SQL.Injection.Generic and action=detected are real, factual fields, not fabricated. But level=critical is the vendor's static rating for this signature family, not an assessment of this specific occurrence's actual risk. The source, 10.20.1.50, is the organisation's own authorised vulnerability scanner, running inside its documented weekly window, confirmed by a change ticket. Severity tells you how the vendor classified the pattern in general; it does not tell you whether this particular event is a real attack — that only comes from checking the context underneath it, exactly as Reading 7 taught.",
      fp_trap:
        "level=critical paired with attack=SQL.Injection.Generic against a host named SRV-DB07 naturally reads as an active attack against a database server, and a student trained to escalate every 'critical' would fire this straight to incident response. But severity in a vendor log describes the signature's default classification, not the specific event's real-world risk — that only comes from context: is the source authorised, is this a known scan window, does IT verification confirm it. Skipping the source and context check and escalating on severity alone is exactly the over-alerting trap Reading 7 warns about.",
      xp: 25,
    },
    // ----- Reading 8: absence of evidence -------------------------------------------
    {
      type: "reading",
      id: "loganat-r8",
      heading: "What Is Not in the Log: Reading Absence of Evidence Correctly",
      content:
        `A log only ever records what a sensor was configured to record, at the moment it was configured to record it, successfully delivered through every step of a pipeline. A missing field, or a missing event entirely, is not proof that nothing happened — it is proof only that nothing was recorded, and those are two very different claims.\n\n` +
        `**Where a log can be lost before you ever see it.** The diagram below shows the path: a device generates an event, an agent or forwarder ships it off the device, a parser or normaliser maps its raw fields into your SIEM's schema, the event lands in an index, and only then can you query it. Something can go wrong at every one of those steps — an agent that crashed hours ago and silently stopped forwarding, a parser with no rule for a brand-new log format that drops or mis-files the event, a retention policy that aged old data out of the index before you went looking for it.\n\n` +
        `**Three different reasons a field or event can be missing — and why telling them apart matters.** It might mean the thing genuinely did not happen — the honest, simple case. It might mean it happened but was never logged at all, because the sensor was never configured to capture that category of activity in the first place, a common gap with default-off audit policies. Or it might mean it was logged, but the logging pipeline itself failed somewhere between the device and your query — the far more dangerous case, because it can hide an entire active intrusion behind what looks like a quiet, uneventful log.\n\n` +
        `**How to actually tell these apart.** Check whether the sensor is known to cover this activity at all — read its documentation or configuration, do not assume. Check whether the agent or forwarder for that specific host is healthy and has recent heartbeat activity. Check a nearby, related log source for corroborating evidence — if a workstation shows a login attempt but the domain controller has no matching authentication event at all, that gap itself is worth escalating, not dismissing as "nothing happened." Never write "no evidence of X" in a finding without first confirming X would have been logged at all if it had occurred.`,
      diagram:
        "flowchart LR\n" +
        "  D1[\"Device generates the event (endpoint, firewall, server)\"] --> A1[\"Agent / forwarder ships it -- can crash, fall behind, or skip event types if misconfigured\"]\n" +
        "  A1 --> P1[\"Parser / normaliser maps raw fields to schema -- an unrecognised format can be dropped or mis-filed\"]\n" +
        "  P1 --> I1[\"Index / storage -- retention limits mean old events silently age out\"]\n" +
        "  I1 --> Q1[\"Your query -- you only ever see what survived every step before this one\"]\n",
      diagramCaption: "Where a log entry can be lost before it ever reaches your query",
    },
    // ----- Log analysis --------------------------------------------------------------
    {
      type: "log_analysis",
      id: "loganat-la1",
      heading: "A Format You've Never Seen: Reading a Zeek Connection Record",
      context:
        "A network sensor on the core VLAN, running Zeek — a network security monitoring tool that summarises connections rather than inspecting full packet contents — logged the record below. Apply the five-question method from Reading 1 before answering.",
      event: zeekConnEvent,
      questions: [
        {
          question:
            "Using the five-question frame, which of WHEN, WHERE, and WHAT can you answer directly from this record, and which of the five questions has no field at all in this log format?",
          options: [
            "You can answer WHEN (ts), WHERE (id.orig_h / id.resp_h), and WHAT (proto and id.resp_p show a TCP connection to port 3389); there is no WHO field at all — Zeek's connection log records network activity, not identity, and there's no HOW CONFIDENT/severity field either, since conn.log summarises connections rather than rating them",
            "You can answer all five questions directly from this one record, including WHO, because uid identifies the user who made the connection",
            "This record only answers WHEN — none of the other fields map to the five-question frame",
            "WHERE cannot be determined because Zeek does not record IP addresses, only hostnames",
          ],
          answer: 0,
          explanation:
            "uid in Zeek is a unique connection (flow) identifier — like a case number for this specific network session — not a username; that's exactly the look-alike field name trap Reading 6 warned about. Zeek's conn.log genuinely has no identity field and no severity field; that absence isn't a mistake, it's a property of this data source, which the next question builds on. WHERE is very much answerable — id.orig_h and id.resp_h are IP addresses, not hostnames.",
          xp: 20,
        },
        {
          question:
            "duration is 812.334 seconds, orig_bytes is 48210, resp_bytes is 991823, and conn_state is SF. Zeek's documentation defines SF as a connection that completed a normal TCP handshake and closed normally, as opposed to S0 (a connection attempt with no reply at all). What does this combination tell you about the WHAT of this record?",
          options: [
            "The connection was rejected by the destination host before any data was exchanged",
            "A sustained (over 13-minute), fully-established TCP session to port 3389 (the standard port for Remote Desktop Protocol) exchanged data in both directions and ended normally — a real, completed session, not a blocked or failed attempt",
            "conn_state SF means the connection was flagged as malicious by the sensor",
            "The byte counts indicate this must be a file download, unrelated to port 3389's normal use",
          ],
          answer: 1,
          explanation:
            "SF specifically means a normal, complete handshake-and-close — the opposite of a failed or blocked attempt, which would show as S0 or REJ. This is real session activity to TCP/3389, registered for RDP, with meaningful data flowing both directions over a long duration. conn_state is a protocol-state field describing how the TCP session behaved, not a verdict field — Zeek does not label sessions malicious in conn.log, exactly the point of the previous question.",
          xp: 20,
        },
        {
          question:
            "This record shows a real, completed 13-minute connection to TCP/3389 with substantial two-way data transfer between two internal hosts. Before concluding anything about whether this was legitimate remote administration or something else, what is essential that this record cannot tell you, and where would you look for it?",
          options: [
            "Nothing further is needed — the connection details alone are sufficient to close this as informational",
            "This record has no identity field at all, so you cannot tell WHO used this connection; you would need to correlate the timestamp and the two IP addresses against an authentication log (for example, a Windows Security 4624 logon on the destination host) to find out which account, if any, actually logged on during this window",
            "You would need to run this same query again with a longer time range, since the missing information is simply a matter of expanding the search window",
            "Zeek logs always include the associated username in a separate field called owner, which should be queried instead",
          ],
          answer: 1,
          explanation:
            "This is the absence-of-evidence lesson from Reading 8 applied directly: the gap here is not a logging failure, it's a structural property of what a network sensor can see at all — it observes traffic, not identities. The correct move is to correlate against a log source that does carry identity, such as an authentication log on the destination host, for the matching time window — not to guess. There is no owner field in Zeek's conn.log, and expanding the time range does not manufacture a field that was never captured.",
          xp: 25,
        },
      ],
    },
    // ----- Flag ------------------------------------------------------------------------
    {
      type: "flag",
      id: "loganat-f1",
      prompt:
        "In the log_analysis task, what TCP destination port did the Zeek connection record use? Enter the number only.",
      answer: "3389",
      hint: "It's the id.resp_p field — and it's the standard port for Remote Desktop Protocol.",
      xp: 15,
    },
  ],
};

// =============================================================================
// ROOM 2: identity-basics
// =============================================================================

const authBurstEvent: TelemetryEvent = {
  id: "evt-idbasics-la1-001",
  ts: "2026-05-14T03:47:12.000Z",
  source: "windows_security",
  vendor: "Windows Security",
  event_type: "auth_success",
  severity: "high",
  hostname: "SRV-FILE03.meridian.local",
  description:
    "SRV-FILE03 recorded this successful logon for account b.osei. SIEM correlation shows 14 failed logon attempts against this same account, from the same source IP, in the six minutes immediately before this one — all rejected for bad password, and none of them triggered an account lockout.",
  raw: {
    "event.code": "4624",
    "winlog.channel": "Security",
    "winlog.computer_name": "SRV-FILE03.meridian.local",
    "winlog.event_data.TargetUserName": "b.osei",
    "winlog.event_data.TargetDomainName": "MERIDIAN",
    "winlog.event_data.LogonType": "3",
    "winlog.event_data.AuthenticationPackageName": "NTLM",
    "winlog.event_data.IpAddress": "185.220.101.47",
    "winlog.event_data.WorkstationName": "-",
    "winlog.event_id": 4624,
  },
};

const oktaPushEvent: TelemetryEvent = {
  id: "evt-idbasics-ac1-001",
  ts: "2026-05-06T08:58:40.000Z",
  source: "mfa",
  vendor: "Okta",
  event_type: "auth_success",
  severity: "medium",
  hostname: undefined,
  description:
    "Okta's system log recorded this MFA push approval for l.marsh. Five push challenges were sent to this user's device in the three minutes before this one was approved.",
  it_verify_result: "confirmed",
  it_verify_message:
    "Helpdesk ticket HD-33291 confirms l.marsh reinstalled Okta Verify this morning after a phone replacement; the re-enrollment process re-sent several queued push prompts from the new device pairing before the user approved the final one.",
  raw: {
    eventType: "user.authentication.auth_via_mfa",
    displayMessage: "Authentication of user via MFA",
    "outcome.result": "SUCCESS",
    "actor.alternateId": "l.marsh@meridian.local",
    "client.ipAddress": "10.44.8.12",
    "client.device": "Computer",
    "authenticationContext.credentialType": "OKTA_VERIFY_PUSH",
    "debugContext.debugData.factor": "PUSH",
  },
};

const identityBasicsRoom: Room = {
  id: "identity-basics",
  title: "Identity Basics: Credentials, Sessions & MFA",
  description:
    "Learn the identity fundamentals every later room assumes you already have: authentication vs authorization, the three MFA factors and why two of the same kind isn't MFA, what a credential actually is (including why a password hash is a credential too), how session tokens work and why stealing one bypasses MFA entirely, the correct order for shutting an attacker out (revoke sessions before resetting the password), and how to read a Windows authentication log.",
  difficulty: "beginner",
  category: "Identity",
  estimatedMinutes: 45,
  xp: 205,
  icon: "🔐",
  prerequisites: ["intro-cybersecurity"],
  tasks: [
    // ----- Reading 1: authn vs authz ------------------------------------------
    {
      type: "reading",
      id: "idbasics-r1",
      heading: "Authentication vs Authorization: Proving Who You Are vs What You're Allowed to Do",
      content:
        `These two words look almost identical and get confused constantly, but they describe two completely different moments, and mixing them up leads to real misdiagnosis in an investigation.\n\n` +
        `**Authentication is proving who you are.** Think of showing your ID card to a receptionist at a building's front desk. The receptionist checks that the ID is real and that the photo matches your face. That is the entire job of authentication: confirm the identity being claimed is genuine. In computer systems, this usually means checking a password, a certificate, or some other credential against what the system has on record.\n\n` +
        `**Authorization is deciding what you're allowed to do once you're in.** Having a valid ID card that gets you through the front door does not mean every door inside the building opens for you. Authorization is the separate check — often happening every single time you try to open a specific door — of whether your already-confirmed identity has permission for this specific action.\n\n` +
        `**Why the distinction matters to an analyst.** If someone logs in with a completely valid username and password, and that account then does something it should never be allowed to do — reads a file it has no business reading, calls an administrative function it was never granted access to — that is an authorization failure, not an authentication one. The login itself was completely legitimate; the credential was real. The identity behind it, whether the rightful owner or an attacker who stole the credential, simply had no business doing what they did next. Treating that as "check whether the password was guessed" investigates the wrong question entirely — the real question is why the permissions allowed it, or whether this identity's access was ever appropriate in the first place.\n\n` +
        `**A short example.** A help-desk technician's account authenticates successfully every single day — nothing wrong there at all. If that same account is later used to reset a company executive's password, and that technician's role was never supposed to include executive accounts, the login was fine; the authorization boundary is what failed, and that boundary is exactly what you would review, tighten, or investigate — not the login event itself.`,
    },
    // ----- Reading 2: three factors -------------------------------------------
    {
      type: "reading",
      id: "idbasics-r2",
      heading: "The Three Factors — and Why Two of the Same Kind Isn't MFA",
      content:
        `Multi-factor authentication (MFA) means proving your identity using more than one *category* of proof — not simply proving it twice. There are three recognised categories, and understanding what actually falls into each one is the difference between MFA that meaningfully raises an attacker's cost and MFA that only looks like it does.\n\n` +
        `**Something you know.** A password, a PIN, the answer to a security question. This category has one structural weakness above all others: anything you know can, in principle, be learned by someone else — phished, guessed, leaked in a breach, written on a sticky note.\n\n` +
        `**Something you have.** A physical security key, a phone receiving a push notification or generating a one-time code, a smart card. This category is stronger in one specific way: an attacker on the other side of the world typically cannot produce the physical object, even if they know everything else about you.\n\n` +
        `**Something you are.** A fingerprint, a face scan, any biometric measurement. This category cannot be "reset" the way a password can if it is ever compromised, which is exactly why biometric systems are built to avoid ever transmitting or storing the raw biometric data itself.\n\n` +
        `**The trap: two of the same category is not MFA, no matter how it feels.** A password plus a secret PIN is still just two things you know — an attacker who phishes one can very often phish or guess the other through the same channel, at the same time, using the same trick. Genuine MFA requires crossing into a second category: something you know plus something you have is real MFA; something you know plus something else you also merely know is not, regardless of how many boxes a login screen makes you fill in.\n\n` +
        `**Why this matters for the rest of the room.** Every attack covered from here on targets one specific factor, or targets the gap between two of them. Knowing which category a given credential belongs to is what lets you reason about what stealing it actually gets an attacker — which is exactly Reading 3's subject.`,
    },
    // ----- Question 1 ------------------------------------------------------------
    {
      type: "question",
      id: "idbasics-q1",
      question:
        "An application requires a password to log in, and then a second screen asking the user to answer their mother's maiden name before granting access. Does this qualify as multi-factor authentication?",
      options: [
        "Yes — two separate prompts were required before access was granted",
        "No — both the password and a security-question answer are 'something you know', so this is still single-factor authentication with two steps, not two categories",
        "Yes, because the second prompt appears on a separate screen, which counts as a second factor by definition",
        "No, because MFA always requires a smartphone app specifically",
      ],
      answer: 1,
      explanation:
        "Both a password and a security-question answer fall into the 'something you know' category, so this is two steps of the same single factor, not multi-factor authentication — exactly the trap Reading 2 described. Requiring two prompts, or putting them on separate screens, doesn't change which category each one belongs to, and MFA doesn't require any specific technology like a smartphone app — it requires crossing into a second category of proof.",
      xp: 15,
    },
    // ----- Reading 3: credentials ---------------------------------------------------
    {
      type: "reading",
      id: "idbasics-r3",
      heading: "What a Credential Actually Is — and Why a Password Hash Counts Too",
      content:
        `A credential is anything a system accepts as proof of identity. Most people picture a password when they hear the word, but that is only one of several forms a credential can take, and the differences matter enormously once you're investigating a breach.\n\n` +
        `**Passwords** are the most familiar: a secret string the account holder chose or was assigned, checked directly against the system.\n\n` +
        `**Password hashes** are what many systems actually store, and, critically, what many protocols actually check — not the password itself. A hash is a one-way mathematical transformation of the password; in theory it cannot be reversed back into the original password. Here is the fact that matters most in this whole reading: in some authentication protocols, especially older ones like NTLM, the protocol can be satisfied by presenting the hash directly, without ever knowing or supplying the plaintext password behind it. If an attacker steals a password hash — from a compromised machine's memory, for instance — they may not need to crack it into a plaintext password at all to use it. This is the exact mechanism behind an attack technique called pass-the-hash, and it is precisely why "we don't store plaintext passwords" is reassuring but not, by itself, a complete defence.\n\n` +
        `**Certificates** are cryptographic credentials tied to a private key the holder keeps secret; a system that trusts the certificate's issuer will accept anything correctly signed with that private key as proof of the certificate holder's identity.\n\n` +
        `**API keys** are long, typically static strings issued to an application or script rather than a human — they usually have no built-in expiration and, unlike a human's password, are rarely typed by a person who would notice if it stopped working, which means a stolen one can go unnoticed for a long time.\n\n` +
        `**Tokens** are short-lived proof of an already-completed authentication, generated by a system after you've successfully logged in, so you don't have to keep re-entering a password. Reading 4 is dedicated entirely to why tokens are, for an attacker, often the single most valuable credential of all.\n\n` +
        `**The common thread.** Every one of these is a credential in the exact same sense a password is: something the system will accept as sufficient proof of identity. An attacker's actual goal is rarely "learn the plaintext password" — it's "obtain something, in whatever form, the system will accept in its place." Keeping that broader definition in mind is what stops an analyst from dismissing a stolen hash, key, certificate, or token as somehow less serious than a stolen password.`,
    },
    // ----- Matching --------------------------------------------------------------------
    {
      type: "matching",
      id: "idbasics-m1",
      heading: "Match Each Stolen Credential to What the Attacker Gains",
      instructions: "Match each stolen credential type to what it actually gives an attacker.",
      pairs: [
        { id: "password", left: "Attacker steals the plaintext password", right: "Full account takeover on any system trusting that password; the password should be rotated everywhere it was reused" },
        { id: "hash", left: "Attacker steals the password HASH (not the password itself)", right: "In some protocols (e.g. NTLM), the attacker can authenticate directly using the hash (pass-the-hash), without ever learning the plaintext password" },
        { id: "token", left: "Attacker steals a session token/cookie after MFA already succeeded", right: "Attacker gets an already-authenticated session, bypassing MFA entirely; resetting the password alone will not remove this access" },
        { id: "apikey", left: "Attacker steals a long-lived API key issued to a service account", right: "Attacker gets programmatic access with whatever privileges the key holds, often with no MFA and no expiry to force re-authentication" },
        { id: "cert", left: "Attacker steals a client certificate used for authentication", right: "Attacker can authenticate as the certificate's subject anywhere that certificate is trusted, until it is explicitly revoked" },
      ],
      explanation:
        "Each of these follows directly from Reading 3's core point: a credential is anything the system accepts as proof of identity, and what an attacker gains depends entirely on which form they stole and how that specific protocol validates it — a hash, a token, a key, and a certificate each behave differently once stolen, even though all four are 'just' credentials in the broad sense.",
      xp: 30,
    },
    // ----- Reading 4: sessions and tokens ------------------------------------------------
    {
      type: "reading",
      id: "idbasics-r4",
      heading: "Sessions and Tokens — the Idea That Unlocks the Modern Attacks",
      content:
        `Re-entering your password on every single click of every website you use all day would be unworkable, so systems don't ask you to. After you authenticate once, the system issues you a session token (often stored as a browser cookie, or as a bearer token for an API) that your device then presents automatically on every subsequent request, proving "I already logged in" without repeating the original credential check.\n\n` +
        `**Why this matters more than almost anything else in identity security.** The token itself, once issued, is what the system actually checks from that point forward — not the password that originally earned it. This single design fact is the reason token theft has become one of the most dangerous classes of attack in modern identity security: if an attacker steals a valid session token — through malware on the device, a malicious proxy sitting between the user and the real login page (an adversary-in-the-middle, or AitM, attack), or a leaked browser session — they can present that token themselves and be treated as the already-authenticated user, with no password required at all.\n\n` +
        `**This bypasses MFA entirely — not by defeating it, but by arriving after it.** MFA's whole job is to make the moment of authentication harder to fake. A stolen token represents a login that has already happened, MFA and all — the token is proof the second factor was already satisfied. An attacker presenting a stolen token isn't asked to prove anything again; the system's whole reason for asking in the first place already occurred, for someone else, earlier.\n\n` +
        `**The critical containment fact this room keeps coming back to.** Resetting a compromised account's password does absolutely nothing to a session token that was already issued before the reset. The token was never derived from a fresh password check on every use — it was issued once and is honoured on its own until it expires or is explicitly revoked. An attacker holding a stolen token before a password reset can, in many systems, continue using that exact token after the reset with zero interruption, because nothing about resetting a password inherently invalidates tokens that already exist. Reading 5 covers exactly what to do about that.`,
      diagram:
        "sequenceDiagram\n" +
        "  participant U as User\n" +
        "  participant Id as Identity Provider\n" +
        "  participant App as Application\n" +
        "  U->>Id: Present credential + MFA\n" +
        "  Id-->>U: Session token issued\n" +
        "  U->>App: Request + token (no password sent again)\n" +
        "  App-->>U: Access granted -- token trusted\n" +
        "  Note over App: Every later request reuses this same token, not the original password or MFA proof\n",
      diagramCaption: "How a login becomes a reusable token",
    },
    // ----- Question 2 --------------------------------------------------------------------
    {
      type: "question",
      id: "idbasics-q2",
      question:
        "An attacker uses a malicious proxy to intercept a user's login and steals the session token issued right after the user completes MFA. What is true about this attacker's access?",
      options: [
        "The attacker still needs the user's password to do anything, since only the password is checked on each request",
        "The attacker's access is limited to read-only actions, since tokens never carry the same permissions as a live login",
        "The attacker can present the stolen token as if they were the already-authenticated user, bypassing MFA entirely, because MFA already succeeded before the theft — no password or second factor is required from this point",
        "MFA will automatically detect and block the stolen token the next time it's used, since MFA is checked on every request",
      ],
      answer: 2,
      explanation:
        "Once a token is issued, it — not the original password or MFA proof — is what later requests are checked against, exactly as Reading 4 described. The attacker doesn't need the password at all, the token typically carries the same access the real session had, and MFA is not re-checked on every request; it was already satisfied once, before the theft, which is exactly why token theft bypasses it.",
      xp: 15,
    },
    // ----- Reading 5: correct containment order -----------------------------------------
    {
      type: "reading",
      id: "idbasics-r5",
      heading: "Why Resetting the Password Isn't Enough — the Correct Containment Order",
      content:
        `This reading is one idea, stated as plainly as possible, because getting the order wrong during a real incident leaves an attacker with continued access while everyone believes the account is secured.\n\n` +
        `**The mistake.** A common, understandable first instinct when an account is confirmed compromised is to reset the password immediately. It feels decisive, and it genuinely does stop an attacker who only has the password from logging in again. But Reading 4 already established the problem: if the attacker already holds a valid session token from before the reset, that token is not tied to the password at all — it was issued once, and it keeps working until it is explicitly revoked or naturally expires, regardless of what the password becomes afterward.\n\n` +
        `**What "revoke sessions and tokens" actually means.** Most identity platforms provide an explicit action for this, separate from a password reset, that immediately invalidates every currently active session and token for an account, forcing every device and application using that account to re-authenticate from scratch. This is the action that actually removes an attacker who is already inside an open session.\n\n` +
        `**The correct order, and why the order itself is the point.** Revoke sessions and tokens first. Only then reset the password. Done in that order, the attacker's existing token is killed immediately, and the new password prevents them from simply logging in again afterward with credentials they may also hold. Done in the reverse order — password first — there is a window, however brief, where the attacker's still-valid token keeps working exactly as before, undisturbed by a password change that was never the thing actually authorising their access in the first place.\n\n` +
        `**One more step worth remembering.** After both actions, review what the attacker's session actually touched while it was active, and check whether they created anything new during that window — a new registered device, a new app permission grant, a new mail forwarding rule — because a revoked session does not undo actions the attacker already took while it was valid.`,
      diagram:
        "flowchart TD\n" +
        "  subgraph Wrong_Order\n" +
        "    W1[\"Step 1: Reset the password\"] --> W2[\"Step 2: Revoke sessions and tokens\"]\n" +
        "    W2 --> W3[\"Result: the attacker's stolen token kept working the entire time between Step 1 and Step 2\"]\n" +
        "  end\n" +
        "  subgraph Correct_Order\n" +
        "    C1[\"Step 1: Revoke sessions and tokens\"] --> C2[\"Step 2: Reset the password\"]\n" +
        "    C2 --> C3[\"Result: the stolen token dies immediately, and the old password can no longer be used either\"]\n" +
        "  end\n",
      diagramCaption: "Containment order: why password-first leaves the attacker logged in",
    },
    // ----- Ordering ----------------------------------------------------------------------
    {
      type: "ordering",
      id: "idbasics-o1",
      heading: "Order the Correct Containment Steps for a Compromised Account",
      instructions: "An account is confirmed compromised, and the attacker may hold an active session. Put the response steps in the correct order.",
      items: [
        { id: "revoke", text: "Revoke the account's active sessions and tokens" },
        { id: "reset", text: "Reset the compromised account's password" },
        { id: "review", text: "Review what the session accessed, and whether the attacker created anything new (a forwarding rule, a new device, a new app permission)" },
        { id: "confirm", text: "Confirm with the user that the account is fully back under their sole control" },
      ],
      correct_order: ["revoke", "reset", "review", "confirm"],
      explanation:
        "This is the order from Reading 5: revoking sessions and tokens first kills any access the attacker already holds immediately; resetting the password afterward stops them from simply logging back in with credentials they may also have; reviewing what happened during the compromise catches anything the attacker planted or accessed while inside; and confirming with the user closes the loop. Resetting the password before revoking sessions leaves an already-open session untouched for as long as the gap lasts.",
      xp: 25,
    },
    // ----- Reading 6: MFA proves/doesn't -------------------------------------------------
    {
      type: "reading",
      id: "idbasics-r6",
      heading: "MFA — What It Proves, and What It Doesn't",
      content:
        `Multi-factor authentication is one of the single highest-value controls in identity security, and it is also frequently misunderstood as a guarantee it was never designed to be.\n\n` +
        `**What MFA actually proves.** That whoever approved the second-factor prompt had access to that specific factor at that specific moment — the phone that received the push, the app that generated the code, the security key that was tapped. That's the whole claim. It says nothing about whether the person who approved it understood what they were approving, and it says nothing at all about anything that happens after that moment of approval.\n\n` +
        `**MFA fatigue attacks exploit the first gap.** An attacker who already has a valid password can trigger repeated push notification prompts, often late at night or in a burst, hoping the legitimate user eventually taps "approve" just to make the notifications stop — not because they intended to authorise anything, but because a wall of interruptions wears a person down. The user did hold the factor and did approve the prompt; they simply didn't understand what they were approving. MFA "worked" exactly as designed and still let an attacker in.\n\n` +
        `**Token replay exploits the second gap.** As Reading 4 covered, a stolen session token represents a login where MFA already succeeded, for someone else, at an earlier point in time. Presenting that token doesn't ask MFA anything at all — MFA is simply never consulted again for that same session, because the system's whole reason for asking has already been satisfied once.\n\n` +
        `**Not all factors resist this equally.** Push notifications and SMS-based one-time codes are convenient but comparatively weak: SMS specifically can be intercepted through SIM-swapping (convincing a carrier to transfer a phone number to an attacker's device) and has no protection at all against a user who simply approves a fraudulent prompt. TOTP (time-based one-time codes from an authenticator app) is somewhat stronger since it isn't tied to the phone network, but a user can still be phished into typing a valid code into a fake login page in real time.\n\n` +
        `**FIDO2/WebAuthn — the one that actually breaks the AitM chain.** Phishing-resistant authentication standards like FIDO2 and WebAuthn cryptographically bind the authentication to the specific website's real domain — a security key or platform authenticator will simply refuse to complete authentication against a fraudulent look-alike site, because the cryptographic challenge itself is tied to the legitimate domain and cannot be replayed elsewhere. This is the one MFA method here that a proxy-based AitM attack, of the kind described in Reading 4, structurally cannot defeat — not because it's harder to fool a human, but because the protocol itself refuses to complete against the wrong domain at all.`,
      diagram:
        "flowchart LR\n" +
        "  A[\"User submits username + password\"] --> B[\"MFA gate: second factor requested\"]\n" +
        "  B -->|Factor approved| C[\"Session token issued\"]\n" +
        "  C --> D[\"Token presented on every later request\"]\n" +
        "  E[\"Attacker steals the token after step C\"] --> D\n" +
        "  D --> F[\"Application grants access -- token alone is checked, MFA is never asked again\"]\n",
      diagramCaption: "Where MFA sits in the flow -- and where a replayed token skips it",
    },
    // ----- Analyst choice (false positive) --------------------------------------------------
    {
      type: "analyst_choice",
      id: "idbasics-ac1",
      heading: "Verdict: Five Push Prompts Before One Approval",
      scenario:
        "An MFA-fatigue detection rule fires on any account receiving three or more push challenges within five minutes. Review the event below alongside the helpdesk ticket attached to it.",
      event: oktaPushEvent,
      correct_verdict: "false_positive",
      explanation:
        "Multiple push prompts followed by one approval is the textbook shape of an MFA-fatigue attack described in Reading 6, and this alert is right to flag it for review. But the source IP (10.44.8.12) is internal, not an unfamiliar external address, and a confirmed helpdesk ticket explains the repeated prompts as a routine side effect of re-enrolling Okta Verify on a replacement phone, which resends queued challenges from the pairing process. The pattern matched the detection rule correctly; the context confirms this specific occurrence is routine device re-enrollment, not an attacker wearing the user down.",
      fp_trap:
        "A burst of pushes followed by one approval is exactly the shape Reading 6 taught as MFA fatigue, which makes this tempting to escalate as a confirmed attack on sight. But the repeated-push pattern alone doesn't distinguish a real fatigue attack from a legitimate device re-pairing that queues several prompts in a row — the deciding factor is context: an internal source IP and a verified helpdesk ticket, not the push count by itself. Escalating every multi-push event without checking source and verification first is the same over-alerting trap severity misreads created in the other room.",
      xp: 25,
    },
    // ----- Reading 7: account types --------------------------------------------------------
    {
      type: "reading",
      id: "idbasics-r7",
      heading: "Account Types — Why a Service Account Is a Different Kind of Risk",
      content:
        `Not every account on a network represents a human sitting at a keyboard, and treating every account the same way — same monitoring, same assumptions, same MFA expectations — misses where a huge share of real risk actually concentrates.\n\n` +
        `**User accounts** belong to individual people and are, in a well-run environment, the most closely watched: MFA enforced, regular password expectations, activity that roughly follows a human's working hours and patterns.\n\n` +
        `**Admin accounts** carry elevated privilege over the accounts an individual uses day to day, and are supposed to be used sparingly, for specific administrative tasks, ideally separate from a person's everyday login — a practice often called least-privilege separation. An admin account behaving like someone's daily-driver account is itself a finding worth a second look.\n\n` +
        `**Service accounts** are created for an application, script, or automated process to authenticate with — not for a human to log into interactively at all. They exist so that, for example, a backup job can access a file share every night without a person typing credentials in each time.\n\n` +
        `**Machine accounts** represent a computer or device itself within a domain, rather than any person or application running on it, authenticating so the device can participate in domain services.\n\n` +
        `**Why service accounts specifically draw attacker attention.** They are frequently over-privileged relative to what the specific task actually requires, because it's easier to grant broad access once than to scope it precisely and revisit it later. Their passwords are rotated far less often than a human's, sometimes because rotating them risks breaking whatever automated process depends on them, and nobody wants to be the one who breaks production. And they are very often explicitly exempted from MFA enforcement, because MFA assumes an interactive human is present to approve a prompt — an unattended nightly job has nobody to tap "approve." Put those three properties together — broad access, a password that rarely changes, and no second factor standing in the way — and a compromised service account is frequently a more valuable and less-defended target than the human admin account sitting right next to it.`,
    },
    // ----- Question 3 ---------------------------------------------------------------------
    {
      type: "question",
      id: "idbasics-q3",
      question:
        "Why do attackers who gain an initial foothold frequently pivot toward compromising a service account rather than continuing to target user accounts?",
      options: [
        "Service accounts are always disabled by default and represent no real risk if compromised",
        "Service accounts are often over-privileged for their actual task, rarely have their passwords rotated, and are frequently exempted from MFA since no human is present to approve a prompt — making them a high-value, comparatively undefended target",
        "Service accounts cannot authenticate over a network at all, so compromising one has no practical value",
        "Service accounts are subject to stricter monitoring than user accounts in every organisation, making them a poor target",
      ],
      answer: 1,
      explanation:
        "This is the combination from Reading 7: broad, rarely-scoped-down access, infrequent password rotation, and frequent MFA exemption together make service accounts an efficient target once an attacker has a foothold. They are not disabled by default, they authenticate over the network constantly (that's their whole purpose), and in most environments they receive less scrutiny than user accounts, not more.",
      xp: 15,
    },
    // ----- Reading 8: reading an auth log --------------------------------------------------
    {
      type: "reading",
      id: "idbasics-r8",
      heading: "Reading an Authentication Log — Success, Failure, and the Pattern Between Them",
      content:
        `Two Windows Security events carry most of the weight in authentication investigations, and reading them correctly, including reading the pattern across several of them together, is a core daily skill.\n\n` +
        `**Event 4624 — successful logon.** Recorded every time a logon genuinely succeeds. Key fields include TargetUserName (who logged on), IpAddress (where the attempt came from), and LogonType, a number describing how the logon happened: 2 is an interactive console logon (someone physically at the keyboard), 3 is a network logon (connecting to a file share or similar, no interactive session), and 10 is RemoteInteractive, meaning Remote Desktop Protocol (RDP). The same username logging on with LogonType 3 to a file server and LogonType 10 to a workstation are very different situations worth reading differently.\n\n` +
        `**Event 4625 — failed logon.** Recorded every time a logon attempt is rejected — wrong password, disabled account, expired account, and so on. On its own, a single 4625 usually means nothing more than someone mistyped their password, which happens constantly and is rarely worth investigating in isolation.\n\n` +
        `**The pattern that matters far more than either event alone: a burst of failures immediately followed by one success.** Several 4625 events against the same account, from the same source, in a short window, followed immediately by a 4624 for that same account, is one of the most reliable shapes in authentication monitoring — it looks exactly like an attacker guessing passwords (brute-forcing one account, or trying a short list of likely passwords) who eventually guessed correctly. The single success sitting right after a run of failures is far more significant than either fact would be alone; a 4624 by itself just means someone logged in, and a handful of 4625s by themselves often mean nothing at all.\n\n` +
        `**What to check once you see this pattern.** Whether the account has any MFA on the authentication path it used — an NTLM network logon to a file server, for instance, very often has none at all, as Reading 6 covered — because a burst-then-success pattern against an MFA-protected account is a very different risk than the same pattern against one with no second factor standing between a guessed password and full access.`,
    },
    // ----- Log analysis ----------------------------------------------------------------------
    {
      type: "log_analysis",
      id: "idbasics-la1",
      heading: "A Successful Logon After a Run of Failures",
      context:
        "SRV-FILE03's Security log was pulled after a routine review of file-server access. Review the successful logon below, together with the SIEM correlation noted in its description.",
      event: authBurstEvent,
      questions: [
        {
          question:
            "Fourteen failed logon attempts (rejected for bad password) preceded this single successful logon, all from the same source IP against the same account, with no account lockout in between. What pattern does this match, and what does the absence of a lockout suggest?",
          options: [
            "This is routine behaviour — users mistype their passwords fourteen times fairly often and there is nothing unusual about it",
            "This matches password-guessing (brute-force) activity against one account that eventually succeeded, and the lack of any lockout in between suggests the account's lockout threshold is either not configured or was never reached — worth reviewing separately",
            "Fourteen failures followed by a success proves this is a legitimate user who simply forgot their password several times before remembering it",
            "The event is meaningless without also knowing the exact keyboard layout the user typed on",
          ],
          answer: 1,
          explanation:
            "Fourteen failed attempts from one source against one account, immediately followed by a success, is the burst-then-success shape from Reading 8 — a strong password-guessing signature, not routine mistyping. The absence of a lockout in between is worth flagging on its own: either the lockout policy's threshold is too high, isn't enabled for this account, or wasn't triggered for some other reason, and any of those is worth a separate look regardless of this specific incident.",
          xp: 20,
        },
        {
          question:
            "IpAddress is 185.220.101.47 — an external address — yet AuthenticationPackageName is NTLM rather than Kerberos, and there is no MFA-related field anywhere in this record. Why does the missing MFA field matter here?",
          options: [
            "It doesn't matter — MFA fields are never logged on 4624 events regardless of whether MFA was used",
            "This account authenticated via an NTLM network logon (LogonType 3) directly to a file server; NTLM network logons commonly do not enforce MFA at all, since MFA is typically bound to a different authentication path, so an attacker who successfully guesses this password walks straight in with no second factor to stop them",
            "The missing field proves this is a forged event and did not actually happen",
            "NTLM logons always include MFA by design, so this record must be incomplete or corrupted",
          ],
          answer: 1,
          explanation:
            "This ties Reading 4 and Reading 8 together: NTLM network logons directly to a resource like a file share frequently sit outside where MFA gets enforced, because MFA is usually bound to a specific entry point (a VPN, an identity provider's login page) rather than every possible authentication path in the environment. That means a successfully guessed password on this path can grant access with no second factor at all — exactly why accounts reachable this way are high-value targets. The field's absence here reflects that gap, not a corrupted or forged event.",
          xp: 20,
        },
        {
          question:
            "What is the correct immediate response to this event?",
          options: [
            "Revoke b.osei's active sessions and tokens first, then reset the account's password, review what the session accessed, and evaluate whether this account's NTLM network-logon path should be restricted or brought under MFA",
            "Reset the password only — since the login already succeeded normally, no further action is needed",
            "Take no action, since a successful logon is by definition not a security event",
            "Block the source IP only, and leave the account's credentials unchanged",
          ],
          answer: 0,
          explanation:
            "This is the correct containment order from Reading 5, applied to a real case: revoke sessions and tokens first so any access already granted is cut immediately, then reset the password so the same guessed credential can't be reused, then review what happened during the session and consider whether this account's exposure over NTLM without MFA needs to change. Resetting the password alone leaves an already-established session untouched, and blocking only the IP does nothing about the account itself, which is now confirmed compromised.",
          xp: 25,
        },
      ],
    },
    // ----- Flag ------------------------------------------------------------------------------
    {
      type: "flag",
      id: "idbasics-f1",
      prompt:
        "In the log_analysis task, what source IP address did both the 14 failed logons and the final successful logon come from? Enter it exactly.",
      answer: "185.220.101.47",
      hint: "It's the winlog.event_data.IpAddress field on the 4624 event.",
      xp: 15,
    },
  ],
};

export const roomsBatch21 = [logEntryAnatomyRoom, identityBasicsRoom];
