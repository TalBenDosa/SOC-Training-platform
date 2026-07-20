/**
 * Learning Rooms — Batch 14 (Room 6)
 *
 * "SOAR and Security Automation"
 *
 * This room teaches what SOAR (Security Orchestration, Automation and
 * Response) is, how it differs from a SIEM, how playbooks and enrichment
 * automation work, how automated containment works and why a human
 * approval gate matters, how SOAR value is measured, and the real risks
 * of over-automation.
 */

import type { TelemetryEvent } from "@/lib/sim/types";

// ── Log analysis event 1: raw brute-force alert BEFORE enrichment ──────────
const bruteForceRawEvent: TelemetryEvent = {
  id: "evt-soar-la1-001",
  ts: "2024-10-03T02:14:07.000Z",
  source: "ad",
  vendor: "Windows Security",
  event_type: "auth_failure",
  severity: "high",
  hostname: "DC01.nexacorp.com",
  user_email: "svc-backup@nexacorp.com",
  src_ip: "185.220.101.47",
  description: "23 failed logon attempts against the svc-backup service account in six minutes, all from a single external IP",
  mitre_technique: "T1110.003",
  mitre_tactic: "Credential Access",
  raw: {
    "event.code": "4625",
    "winlog.event_data.TargetUserName": "svc-backup",
    "winlog.event_data.TargetDomainName": "CORP",
    "winlog.event_data.Status": "0xC000006D",
    "winlog.event_data.SubStatus": "0xC000006A",
    "winlog.event_data.LogonType": "3",
    "winlog.event_data.IpAddress": "185.220.101.47",
    "winlog.event_data.WorkstationName": "-",
    "winlog.event_data.FailureReason": "%%2313",
    "soar.correlation.failed_attempt_count": "23",
    "soar.correlation.window_seconds": "360",
  },
};

// ── Log analysis event 2: the SAME alert AFTER SOAR enrichment ─────────────
const bruteForceEnrichedEvent: TelemetryEvent = {
  id: "evt-soar-la2-001",
  ts: "2024-10-03T02:14:22.000Z",
  source: "soar",
  vendor: "Palo Alto Cortex XSOAR",
  event_type: "auth_failure",
  severity: "critical",
  hostname: "DC01.nexacorp.com",
  user_email: "svc-backup@nexacorp.com",
  src_ip: "185.220.101.47",
  description: "Playbook 'Brute Force - Auto Containment' auto-enriched the alert: source IP has no legitimate business reason to authenticate, is TOR-associated, and the target is a privileged service account",
  mitre_technique: "T1110.003",
  mitre_tactic: "Credential Access",
  raw: {
    "xsoar.playbook.name": "Brute Force - Auto Containment v3",
    "xsoar.playbook.id": "pb-4471",
    "xsoar.incident.id": "INC-88213",
    "xsoar.enrichment.ip_reputation.source": "VirusTotal",
    "xsoar.enrichment.ip_reputation.score": "9/89 malicious",
    "xsoar.enrichment.ip_reputation.tags": ["tor-exit-node", "known-scanner"],
    "xsoar.enrichment.geoip.country": "Netherlands",
    "xsoar.enrichment.geoip.city": "Amsterdam",
    "xsoar.enrichment.asset_owner.team": "Infrastructure - Backup Team",
    "xsoar.enrichment.asset_owner.criticality": "high",
    "xsoar.enrichment.user_context.account_type": "service_account",
    "xsoar.enrichment.user_context.privileged": "true",
    "xsoar.enrichment.user_context.normal_source_ips": ["10.10.5.0/24"],
    "xsoar.playbook.action_recommended": "block_ip_and_disable_account",
    "xsoar.playbook.approval_required": "true",
    "xsoar.playbook.approval_status": "pending",
    "xsoar.playbook.assigned_analyst": "tier1-queue",
  },
};

// ── Analyst choice event: the over-automation trap ──────────────────────────
const overAutomationEvent: TelemetryEvent = {
  id: "evt-soar-ac1-001",
  ts: "2024-11-19T09:03:41.000Z",
  source: "firewall",
  vendor: "Palo Alto Networks PAN-OS",
  event_type: "auth_failure",
  severity: "medium",
  hostname: "VPN-GW-01",
  user_email: "helpdesk-integration@nexacorp.com",
  src_ip: "52.14.88.201",
  description: "A SOAR playbook flagged repeated failed authentication attempts from 52.14.88.201 against a shared helpdesk integration account and recommends auto-blocking the source IP",
  mitre_technique: "T1110",
  mitre_tactic: "Credential Access",
  raw: {
    "event.action": "network-connection-denied",
    "source.ip": "52.14.88.201",
    "destination.ip": "10.10.1.5",
    "destination.port": "443",
    "pan.app": "ssl",
    "pan.action": "deny",
    "xsoar.playbook.name": "Brute Force - Auto Containment v3",
    "xsoar.playbook.action_recommended": "block_ip",
    "xsoar.enrichment.ip_reputation.source": "VirusTotal",
    "xsoar.enrichment.ip_reputation.score": "0/89 malicious",
    "xsoar.enrichment.ip_reputation.tags": [],
    "xsoar.enrichment.asset_owner.notes":
      "52.14.88.201 resolves to an AWS Elastic IP used by Zendesk's outbound integration servers (documented in vendor integration ticket VEND-2291). The helpdesk-integration service account had its password rotated by IT yesterday; the connector was not yet updated with the new credential, causing repeated auth failures from a legitimate, expected source.",
    "xsoar.playbook.failure_pattern": "23 failures over 40 minutes, consistent timing, single stable IP, no credential guessing pattern (same wrong password each time)",
    "action_result": "deny",
  },
};

// ── Room definition ──────────────────────────────────────────────────────
const soarRoom = {
  id: "soar-automation",
  title: "SOAR and Security Automation",
  description:
    "Learn how modern SOCs use SOAR (Security Orchestration, Automation and Response) to cut through alert volume — automating the repetitive parts of investigation and response so analysts can focus on judgment calls. You will learn what a playbook actually is, how enrichment automation works, how automated containment works and why a human approval gate is non-negotiable for high-impact actions, how to measure whether SOAR is actually helping, and — critically — the real-world risk of over-automation, where a well-intentioned playbook auto-blocks a legitimate business partner.",
  difficulty: "intermediate" as const,
  category: "SOC Operations",
  estimatedMinutes: 60,
  xp: 380,
  icon: "⚙️",
  prerequisites: ["siem-fundamentals", "alert-triage"],
  tasks: [
    // ── Reading 1: What is SOAR + the smoke detector / sprinkler analogy ──
    {
      type: "reading" as const,
      id: "soar-r1",
      heading: "What Is SOAR, and How Is It Different From a SIEM?",
      content:
        "SOAR stands for **Security Orchestration, Automation and Response**. It is a category of tooling that sits on top of your other security systems and does three related things: it **orchestrates** (pulls data from many different tools into one place and coordinates actions across them), it **automates** (executes repeatable steps without a human doing them by hand every time), and it **responds** (takes action — enriching an alert, opening a ticket, or even containing a threat — based on a predefined workflow called a playbook).\n\n" +
        "**The Smoke Detector and the Sprinkler**\n\n" +
        "The clearest way to understand the difference between a SIEM and a SOAR is a simple analogy: a **SIEM is the smoke detector**. It is constantly watching, collecting signals from every room in the building (every log source in your environment), correlating them, and the moment it detects smoke, it makes noise — it generates an alert. That is genuinely valuable and often life-saving, but a smoke detector does not put out the fire. It does not call anyone. It just screams and waits for a human to react.\n\n" +
        "A **SOAR is the automatic sprinkler system plus the phone call to the fire department**, wired directly into that smoke detector. The instant the detector goes off, the sprinkler system does not wait for a human to walk over and turn a valve — it activates immediately, based on rules that were configured in advance. At the same time, an automated system dials the fire department and gives them the address, so professional help is already on the way before a human resident has even grabbed their phone. The building still needs a human to eventually inspect the damage, decide if it's safe to re-enter, and file the incident report — but the automatic, immediate part of the response already happened without waiting on that human.\n\n" +
        "**Translating the Analogy Back to the SOC**\n\n" +
        "In SOC terms: the SIEM detects a brute-force attack against a privileged account (the smoke) and raises an alert (the noise). Without SOAR, a human analyst has to notice that alert in a queue, manually look up the source IP's reputation, manually check who owns the affected account, manually decide whether to block the IP, and manually open a ticket to document all of it — often ten to fifteen minutes of repetitive, mostly mechanical work, for every single alert. With SOAR, a **playbook** fires automatically the instant the SIEM alert lands: it looks up the IP reputation, checks the account owner, checks whether this source IP has ever been seen before, drafts a ticket, and — for actions with real consequences, like blocking traffic or disabling an account — pauses and asks a human to approve before pulling the trigger. The mechanical, repeatable 90% of the work happens in seconds. The judgment-requiring 10% still goes to a human.\n\n" +
        "**SOAR Does Not Replace the SIEM — It Extends It**\n\n" +
        "A common misconception is that SOAR is a fancier SIEM, or that buying a SOAR platform means you no longer need a SIEM. That is backwards. The SIEM is still the detection engine — it is still the thing that ingests logs, correlates events, and decides 'something worth looking at just happened.' SOAR is the layer that takes what the SIEM found and does something USEFUL and FAST with it, so analysts are not spending their entire shift on repetitive manual lookups and ticket-typing instead of actual investigation and decision-making.",
      codeExample:
        "SIEM vs SOAR — WHO DOES WHAT\n" +
        "===============================\n\n" +
        "SIEM (the smoke detector)\n" +
        "  - Collects logs from everywhere\n" +
        "  - Correlates events, applies detection rules\n" +
        "  - Raises an ALERT when something looks wrong\n" +
        "  - Does NOT take action on its own\n\n" +
        "SOAR (the sprinkler + the call to the fire dept.)\n" +
        "  - Watches for alerts coming out of the SIEM (and other tools)\n" +
        "  - Runs a PLAYBOOK: a predefined sequence of automated steps\n" +
        "  - ENRICHES the alert automatically (IP reputation, asset owner,\n" +
        "    user context, geo-location...)\n" +
        "  - Can take LOW-RISK actions immediately (open a ticket, tag an\n" +
        "    alert, notify a channel)\n" +
        "  - PAUSES for human approval before HIGH-RISK actions (block an\n" +
        "    IP, disable an account, isolate a host)\n\n" +
        "  Neither tool replaces the other. The SIEM decides WHAT is worth\n" +
        "  looking at. SOAR decides HOW FAST and HOW CONSISTENTLY you react\n" +
        "  to it.",
    },

    // ── Reading 2: Playbooks, workflows, and enrichment automation ─────────
    {
      type: "reading" as const,
      id: "soar-r2",
      heading: "Playbooks, Workflows, and Enrichment Automation",
      content:
        "A **playbook** is a predefined, repeatable sequence of steps that a SOAR platform executes automatically when a specific type of alert arrives — the digital equivalent of a checklist a Tier 1 analyst would otherwise follow by hand. Playbooks are usually built visually, as a flowchart of steps and decision points, and they can call out to dozens of different tools through **integrations** (API connections to your firewall, EDR, ticketing system, threat intel feeds, identity provider, and more).\n\n" +
        "**What 'Enrichment' Actually Means**\n\n" +
        "Enrichment is the process of automatically gathering extra context about an alert so a human analyst does not have to go look it up manually, one tool at a time. When a raw alert arrives, it usually contains bare facts: an IP address, a username, a file hash, a hostname. Those facts are nearly meaningless on their own — an analyst's job is to figure out what they MEAN, and that requires context from other systems. A SOAR playbook automates exactly that lookup work:\n\n" +
        "**IP reputation lookup** — is this source IP known-malicious, a TOR exit node, a cloud provider IP, or an IP with no history at all? (Queried against threat intel feeds like VirusTotal, AbuseIPDB, or a commercial feed.)\n\n" +
        "**File hash reputation lookup** — has this exact file hash been seen before, and is it flagged as malware by other engines? (Queried against VirusTotal, internal EDR history, or a malware sandbox.)\n\n" +
        "**User/account lookup** — who is this user, what is their department and role, are they a privileged or service account, and where do they normally log in from? (Queried against Active Directory / Entra ID / the HR system.)\n\n" +
        "**Geo-IP lookup** — what country and city does this IP resolve to, and does that match where this user is expected to be?\n\n" +
        "**Asset owner lookup** — which team owns the affected server or workstation, and how critical is it? (Queried against a CMDB — configuration management database — or asset inventory.)\n\n" +
        "Each of these lookups might take a human analyst two to five minutes of clicking through separate consoles. A playbook does all of them in parallel, in seconds, and drops the results directly into the alert — so by the time a human even opens the ticket, the boring lookup work is already done and the analyst can go straight to the judgment call: is this actually bad?\n\n" +
        "**A Worked Example — Phishing Report Playbook**\n\n" +
        "A very common, high-value playbook is triggered every time an employee uses the 'Report Phishing' button in their email client. The playbook automatically: extracts the sender address, URLs, and attachment hashes from the reported email; checks the sender domain's reputation and age; detonates any attachment in an automated sandbox to see what it actually does when opened; checks whether the same email was sent to any OTHER employees (so one report can trigger a search-and-quarantine across the whole mailbox environment); and finally opens a ticket summarizing all of that — ready for a human analyst to make the final call on whether to quarantine, block the sender domain, and notify affected users. What used to be twenty minutes of manual work across four different tools becomes a two-minute human review of an already-assembled case file.",
      codeExample:
        "ENRICHMENT PLAYBOOK — WHAT GETS AUTO-LOOKED-UP\n" +
        "==================================================\n" +
        "  Raw alert arrives:  src_ip=185.220.101.47, user=svc-backup\n\n" +
        "  Playbook runs IN PARALLEL:\n" +
        "    -> IP reputation lookup      (VirusTotal / AbuseIPDB)\n" +
        "    -> Geo-IP lookup             (country / city / ASN)\n" +
        "    -> User/account lookup       (AD: role, privilege, normal IPs)\n" +
        "    -> Asset owner lookup        (CMDB: which team owns this host)\n" +
        "    -> Historical lookup         (has this IP been seen here before?)\n\n" +
        "  Result: an alert that arrived with 2 bare fields now arrives with\n" +
        "  a full context package attached — in seconds, not minutes of\n" +
        "  manual clicking across five different consoles.",
    },

    // ── Reading 3: Automated containment + the human approval gate ─────────
    {
      type: "reading" as const,
      id: "soar-r3",
      heading: "Automated Containment — and Why the Human Approval Gate Matters",
      content:
        "Enrichment is low-risk: looking up information does not change anything in your environment, so it is safe to fully automate. **Containment** is a different category entirely, because containment actions actively change something — and if the playbook's judgment is wrong, the automation itself becomes the incident.\n\n" +
        "**Common Automated Containment Actions**\n\n" +
        "**Isolate a host** — the EDR agent puts the endpoint into network quarantine, cutting it off from the rest of the network (except a channel back to the security tooling) while still leaving it running for forensic collection.\n\n" +
        "**Disable a user account** — the identity provider (AD, Entra ID, Okta) flips the account to disabled, immediately killing any active sessions and blocking new logins.\n\n" +
        "**Block an IP address** — the firewall or WAF adds a deny rule for a specific source IP, stopping further traffic from that address.\n\n" +
        "**Revoke active sessions / tokens** — force a re-authentication, invalidating any session an attacker may have already stolen.\n\n" +
        "**Why a Human Approval Gate Matters**\n\n" +
        "All four of those actions can be triggered by a playbook in under a second. The question a mature SOC has to answer is: should they be? The honest answer is: **it depends entirely on the confidence level and the blast radius of being wrong.**\n\n" +
        "For a clearly malicious, high-confidence indicator — say, a file hash that a threat intel feed rates as 100% malicious with zero legitimate use anywhere — fully automatic containment with no human in the loop is often the right call, because the cost of a false positive is near zero (you can't accidentally quarantine legitimate traffic to a hash that has never once been seen in benign software) and the cost of NOT acting fast is high (malware spreading).\n\n" +
        "For anything involving a judgment call — is this IP actually malicious or is it a business partner having a bad day; is this account actually compromised or did the user just forget their password fifteen times — a mature playbook is built with an **approval gate**: the playbook does all the enrichment, drafts the recommended action, and then STOPS and waits for a human analyst (or, for higher-impact actions, a Tier 2/manager) to click 'approve' before the action actually fires. This is sometimes called a **human-in-the-loop** step, as opposed to a **fully autonomous** step.\n\n" +
        "**Where You Draw the Line Is a Real Decision, Not a Default**\n\n" +
        "A common, sensible pattern many SOCs use: fully automate actions that are reversible and low blast-radius (open a ticket, tag an alert, notify a Slack channel, add an indicator to a watchlist) — automate WITH an approval gate for actions that are disruptive but recoverable (isolate a workstation, disable a low-privilege account) — and require MANDATORY human approval, every time, no exceptions, for actions that are hard to reverse quickly or affect shared/critical infrastructure (disable a domain controller service account, block an IP that might be a shared corporate gateway, isolate a production server). The approval gate is not a sign that automation failed — it is the deliberate design choice that keeps automation safe enough to trust with real authority.",
      codeExample:
        "CONTAINMENT AUTOMATION — RISK TIER = HOW MUCH HUMAN IN THE LOOP\n" +
        "===================================================================\n" +
        "  TIER 1 -- Fully automatic, no approval needed\n" +
        "    e.g. open a ticket, tag the alert, add IOC to a watchlist\n" +
        "    (reversible, zero blast radius if wrong)\n\n" +
        "  TIER 2 -- Automatic ACTION + human APPROVAL GATE\n" +
        "    e.g. isolate a workstation, disable a low-privilege account\n" +
        "    (disruptive but recoverable -- a human clicks 'approve' first)\n\n" +
        "  TIER 3 -- MANDATORY human approval, every single time\n" +
        "    e.g. block traffic on a shared gateway IP, disable a service\n" +
        "    account used by production infrastructure, isolate a\n" +
        "    domain controller\n" +
        "    (hard to reverse quickly / high blast radius if the call is\n" +
        "    wrong -- automation drafts the recommendation, a human decides)",
    },

    // ── Reading 4: Case management, tier-1 auto-triage, measuring value, over-automation risk ──
    {
      type: "reading" as const,
      id: "soar-r4",
      heading: "Case Management, Auto-Triage, Measuring Value, and the Danger of Over-Automation",
      content:
        "**Case Management and Ticketing Integration**\n\n" +
        "A SOAR platform is also, functionally, a case management system. Every playbook run typically creates or updates a **case** (sometimes called an incident record) inside the SOAR platform itself, and — through an integration — a matching ticket in whatever ticketing tool the organization already uses (ServiceNow, Jira, PagerDuty, etc.). This matters because it gives every alert a single, auditable timeline: what fired, what the enrichment found, what action was recommended, who approved or rejected it, and when it was closed. Without this, investigation notes live scattered across analysts' heads, email threads, and sticky notes — which becomes a real liability during an audit or a post-incident review.\n\n" +
        "**Auto-Triage of Tier-1 Alerts**\n\n" +
        "One of the highest-value uses of SOAR is auto-triage: automatically sorting the flood of incoming Tier-1 alerts into buckets BEFORE a human ever looks at them, based on enrichment results. A playbook might automatically close an alert as a confirmed false positive if the enrichment finds strong, well-documented benign indicators (e.g., the source IP is a known, allow-listed vulnerability scanner that runs on this exact schedule every week) — while still logging that closure for later audit. It might automatically escalate straight to Tier 2 if enrichment finds strong malicious indicators on a high-criticality asset. And for everything in between — the genuinely ambiguous cases — it routes to a human Tier-1 queue with the enrichment already attached. The goal is not to remove humans from triage; it is to make sure human attention is spent on the alerts that actually need human judgment, instead of being spread evenly across alerts that mostly don't.\n\n" +
        "**Measuring SOAR Value**\n\n" +
        "A SOC that adopts SOAR should be able to point to concrete numbers, not just a vague sense that things feel faster. The two most common and meaningful metrics are:\n\n" +
        "**MTTR (Mean Time To Respond/Resolve)** — the average time from when an alert fires to when the appropriate response action is complete. If enrichment and initial containment that used to take an analyst fifteen minutes of manual work now happens in under sixty seconds automatically, MTTR for that alert category drops dramatically — often the single most visible, most reportable SOAR win.\n\n" +
        "**Analyst time saved / alerts auto-handled** — how many alerts per week are now closed, escalated, or enriched without requiring a human to manually perform each lookup step? This is usually expressed as hours of analyst time reclaimed per week, and it is the number that justifies the tool's cost to leadership — freeing analysts to spend that reclaimed time on genuine investigation, threat hunting, and the ambiguous cases that actually need a human brain.\n\n" +
        "**The Real Risk: Over-Automation**\n\n" +
        "Every one of these benefits comes with a matching risk, and it is the single most important caution in this entire room: **a playbook is only as good as the confidence of the enrichment feeding it, and confidence is never 100%.** A playbook that auto-blocks any IP with more than 20 failed logins in ten minutes sounds reasonable — until that exact pattern shows up from a legitimate SaaS integration partner whose credentials just got rotated and whose connector hasn't been updated yet. If that IP gets auto-blocked with no human approval gate, you have just broken a real business integration, potentially causing an outage, based entirely on a rule that could not tell the difference between an attacker guessing passwords and a broken but legitimate service losing its credential. This is exactly why the approval-gate design from the previous reading is not optional caution — it is the difference between a SOAR platform that makes your SOC faster and one that occasionally becomes its own incident.",
      codeExample:
        "SOAR VALUE METRICS — WHAT LEADERSHIP ACTUALLY WANTS TO SEE\n" +
        "==============================================================\n" +
        "  MTTR (Mean Time To Respond)\n" +
        "    BEFORE SOAR:  ~15 min/alert (manual lookups + manual action)\n" +
        "    AFTER SOAR:   <60 sec for enrichment; approval-gated action\n" +
        "                   typically resolved within minutes of analyst review\n\n" +
        "  Analyst time saved\n" +
        "    e.g. \"420 alerts/week auto-enriched, 180 auto-closed as\n" +
        "         confirmed benign, ~35 analyst-hours/week reclaimed\n" +
        "         for actual investigation and threat hunting\"\n\n" +
        "  OVER-AUTOMATION RISK -- the other side of the coin\n" +
        "    A rule that is 95% accurate still auto-fires on the 5% wrong\n" +
        "    case if there is no approval gate. When that 5% is a real\n" +
        "    business partner's IP, YOUR automation just caused an outage.\n" +
        "    Fast + wrong, at scale, is worse than slow + right.",
    },

    // ── Question 1 ──────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "soar-q1",
      question:
        "Using the smoke detector / sprinkler analogy from this room, which statement correctly describes the relationship between a SIEM and a SOAR platform?",
      options: [
        "SOAR replaces the SIEM entirely — once you have SOAR, log correlation and alerting are no longer needed",
        "The SIEM detects and raises the alert (the smoke detector going off); the SOAR platform takes the automated response actions and coordinates the workflow (the sprinkler activating and the call to the fire department) — they work together, not as substitutes for each other",
        "SOAR is simply a nicer user interface for viewing the same SIEM alerts, with no automation capability of its own",
        "The SIEM only matters for compliance reporting, while SOAR does all real detection work"
      ],
      answer: 1,
      explanation:
        "SIEM and SOAR play complementary, not competing, roles. The SIEM ingests and correlates logs to decide something is worth looking at (detection). SOAR takes what the SIEM found and automatically enriches it, coordinates a workflow across multiple tools, and can take response actions — with approval gates for anything high-risk. Neither tool replaces the other.",
      xp: 30,
    },

    // ── Question 2 ──────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "soar-q2",
      question:
        "A SOAR playbook automatically looks up an IP address's reputation, resolves its geo-location, and identifies which team owns the affected server — all within seconds of an alert arriving. What is this category of automation called?",
      options: [
        "Automated containment",
        "Case management",
        "Enrichment",
        "Auto-triage"
      ],
      answer: 2,
      explanation:
        "This is enrichment: automatically gathering additional context (IP reputation, geo-IP, asset ownership, user role, etc.) about an alert so a human analyst does not have to manually look each piece up across separate tools. Enrichment is low-risk because it only gathers information — it does not change anything in the environment, which is why it is safe to fully automate without an approval gate.",
      xp: 30,
    },

    // ── Question 3 ──────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "soar-q3",
      question:
        "Why do mature SOC teams typically insist on a human approval gate before a playbook auto-blocks an IP address or disables a user account, even though the technology is capable of doing it instantly with no human involved?",
      options: [
        "Because SOAR platforms are technically incapable of taking action without a human clicking a button first",
        "Because containment actions change something in the live environment, and if the enrichment/confidence behind the recommendation is wrong, the automation itself can cause an outage or business disruption — the approval gate limits the blast radius of an incorrect automated decision",
        "Because compliance regulations universally forbid any security automation from taking action without a ticket number",
        "Because human analysts are always faster than automated playbooks at making containment decisions"
      ],
      answer: 1,
      explanation:
        "The approval gate exists because containment actions are not reversible-and-harmless the way enrichment lookups are — they actively change something (blocking traffic, disabling a login). No detection or reputation signal is ever 100% certain, so a playbook that fires disruptive actions with no human check will eventually act on a false positive, and at that point the automation itself becomes an incident (e.g., blocking a legitimate business partner's IP). The gate keeps the speed of automation while bounding the cost of being wrong.",
      xp: 30,
    },

    // ── Log analysis 1: raw vs enriched brute-force ─────────────────────
    {
      type: "log_analysis" as const,
      id: "soar-la1",
      heading: "Before Enrichment — Reading a Raw Brute-Force Alert",
      context:
        "It is 02:14 AM. A Windows Security alert has fired: 23 failed logon attempts against a service account, all from a single external IP, in six minutes. This is the RAW alert, exactly as the SIEM generated it, before any SOAR playbook has touched it. Read it and answer the questions using only what is actually present in this raw event.",
      event: bruteForceRawEvent,
      questions: [
        {
          question:
            "Looking only at this raw alert, which piece of context that a human analyst would normally need is NOT yet present, and would require manual lookup (or automated enrichment) to answer?",
          options: [
            "The number of failed attempts — that information is missing from this alert",
            "Whether the source IP (185.220.101.47) has any known malicious reputation, and whether this IP has ever legitimately contacted this environment before",
            "The target username — that information is missing from this alert",
            "The SubStatus code — that information is missing from this alert"
          ],
          answer: 1,
          explanation:
            "The raw alert gives you the mechanical facts (username, IP, failed attempt count, SubStatus 0xC000006A = wrong password) but nothing about WHO or WHAT this source IP actually is. Is it a known-malicious TOR node, a cloud scanner, or a legitimate partner's gateway? That requires an external reputation lookup — exactly the kind of step a SOAR enrichment playbook automates, and exactly the gap the next event (the enriched version of this same alert) fills in.",
          xp: 35,
        },
        {
          question:
            "The target account is svc-backup — a service account, not a named human. Why does that fact alone raise the priority of this alert, using the WHO framework from earlier training?",
          options: [
            "It doesn't — service accounts are always lower priority than human accounts",
            "Service accounts typically have broad, standing privileges and do not have a 'the user just mistyped their password' explanation the way a human does, since nothing should be manually typing a service account's password at all — repeated failures against one are inherently more suspicious",
            "Service accounts cannot be locked out, so failed logons against them are never meaningful",
            "The LogonType value proves this is definitely an attacker and needs no further check"
          ],
          answer: 1,
          explanation:
            "Service accounts are a common high-value target because they often carry elevated, standing privileges and are not supposed to have anyone manually typing a password against them at all (they normally authenticate via stored credentials or certificates in an automated process). Repeated interactive/network failed logon attempts against a service account do not have the easy 'the user just fat-fingered their password' innocent explanation that a human account might have, which is exactly the kind of WHO-based context that should raise this alert's priority.",
          xp: 35,
        },
      ],
    },

    // ── Log analysis 2: the enriched version ─────────────────────────────
    {
      type: "log_analysis" as const,
      id: "soar-la2",
      heading: "After Enrichment — The Same Alert, 15 Seconds Later",
      context:
        "This is the exact same brute-force attempt from the previous event — but now a SOAR playbook ('Brute Force - Auto Containment v3') has automatically enriched it. Compare what is now present versus the raw version, and notice that the playbook has recommended an action but has NOT yet executed it.",
      event: bruteForceEnrichedEvent,
      questions: [
        {
          question:
            "Based on the enrichment fields now present, does this alert look MORE or LESS likely to be a genuine attack compared to the raw version — and which specific enriched field is most responsible for that shift?",
          options: [
            "Less likely — the enrichment did not add any useful information",
            "More likely — the IP reputation lookup tags this source as a TOR exit node with a malicious score, and the user-context enrichment confirms the normal source IPs for this service account are internal (10.10.5.0/24), meaning this external TOR-associated IP has no legitimate reason to be authenticating as svc-backup at all",
            "About the same — enrichment only adds cosmetic detail, not decision-relevant information",
            "Less likely — the asset owner enrichment shows this is a low-criticality system"
          ],
          answer: 1,
          explanation:
            "The enrichment turns two bare facts (an IP and a username) into an actual case for suspicion: the IP is independently flagged as a TOR exit node with a poor reputation score, AND the user-context lookup shows this service account should only ever be authenticating from an internal subnet (10.10.5.0/24) — never from an external TOR node. This is exactly the value of enrichment: it replaces guesswork with verifiable, checkable facts, gathered automatically in seconds.",
          xp: 35,
        },
        {
          question:
            "The playbook set 'xsoar.playbook.approval_required' to true and 'approval_status' to 'pending', rather than immediately executing 'block_ip_and_disable_account'. Why is this the correct design, even though the enrichment strongly supports a malicious verdict?",
          options: [
            "It is a mistake — a TOR-associated IP with a bad reputation score should always be blocked instantly with no human involved",
            "Disabling a privileged service account is a disruptive, moderately-hard-to-reverse action (it could break a legitimate backup process if the verdict were somehow wrong) — even strong enrichment evidence should pass through a human approval gate before an action with real operational consequences fires automatically",
            "SOAR platforms are never allowed to recommend account actions, only IP blocks",
            "Approval is only required during business hours, and this alert happens to have fired at night"
          ],
          answer: 1,
          explanation:
            "This demonstrates the approval-gate principle from the reading: disabling a service account used by backup infrastructure is a Tier 2/3-style action — disruptive if wrong and not instantly reversible without operational impact. Even with strong supporting enrichment (TOR IP, wrong normal source range), the playbook is correctly designed to draft the recommended action and route it to a human for a final decision, rather than auto-executing a high-impact account action with zero human check.",
          xp: 35,
        },
      ],
    },

    // ── Analyst choice: the over-automation trap ─────────────────────────
    {
      type: "analyst_choice" as const,
      id: "soar-ac1",
      heading: "Verdict: Should the Playbook Auto-Block This IP?",
      scenario:
        "A brute-force detection playbook flags 52.14.88.201 for 23 failed logins against a shared 'helpdesk-integration' service account over 40 minutes and recommends an automatic IP block. Before approving or rejecting the recommended containment action, review the full enrichment the playbook already gathered — including the IP reputation score, the asset owner notes, and the failure pattern — and decide whether this should be auto-contained or held for human review.",
      event: overAutomationEvent,
      correct_verdict: "false_positive" as const,
      explanation:
        "This is a false positive, and it is the exact over-automation trap this room warns about. The enrichment itself, if actually read rather than rubber-stamped, tells the real story: the IP reputation score is 0/89 malicious with no threat tags at all — nothing here looks like attacker infrastructure. The asset owner notes independently confirm 52.14.88.201 is a known, documented AWS Elastic IP belonging to Zendesk's outbound integration (referenced in vendor ticket VEND-2291), and explain that IT rotated the helpdesk-integration account's password yesterday without yet updating the connector — producing exactly the kind of steady, mechanical, same-wrong-password-every-time failure pattern a broken integration produces, not the varied password-guessing pattern of a real brute-force attack. Auto-blocking this IP would sever a legitimate, documented business integration and likely trigger a helpdesk outage — a self-inflicted incident caused by trusting the playbook's raw pattern match instead of reading the enrichment it already provided.",
      fp_trap:
        "The scary-looking surface pattern — '23 failed logins, playbook recommends auto-block' — is designed to tempt you into rubber-stamping the recommended containment action without reading the enrichment fields the playbook already gathered. This is precisely the over-automation risk from the reading: a detection rule that is accurate most of the time will still occasionally flag a legitimate, documented, business-critical source, and if a human (or a fully automated rule with no approval gate) approves the block reflexively instead of checking the IP reputation score (0/89, no tags) and the asset owner notes (a known Zendesk integration IP, with a documented, mundane explanation involving a recent password rotation), you cause exactly the kind of self-inflicted outage this room warns about.",
      xp: 40,
    },

    // ── Matching: SOAR action ↔ what it does ─────────────────────────────
    {
      type: "matching" as const,
      id: "soar-m1",
      heading: "Match Each SOAR Action to What It Actually Does",
      instructions:
        "SOAR playbooks combine many different kinds of actions. Match each action on the left to the correct description of what it does on the right.",
      pairs: [
        {
          id: "enrich",
          left: "IP/hash/user reputation enrichment",
          right: "Automatically queries threat intel feeds, AD, and asset inventories to attach context to a bare alert — a read-only lookup with no risk of changing anything",
        },
        {
          id: "isolate",
          left: "Host isolation",
          right: "The EDR agent cuts the endpoint off from the network (except a channel back to security tooling) while leaving it running for forensic collection",
        },
        {
          id: "disable",
          left: "Disable user account",
          right: "The identity provider flips the account to disabled, immediately killing active sessions and blocking new logins",
        },
        {
          id: "block",
          left: "Block IP address",
          right: "The firewall or WAF adds a deny rule for a specific source IP, stopping further traffic from that address",
        },
        {
          id: "approval_gate",
          left: "Human approval gate",
          right: "The playbook drafts a recommended high-impact action and pauses, waiting for a human analyst to click approve before the action actually executes",
        },
        {
          id: "case_mgmt",
          left: "Case management / ticketing integration",
          right: "Every playbook run creates or updates an auditable case record and a matching ticket, capturing what fired, what was found, and who approved what",
        },
      ],
      explanation:
        "SOAR combines information-gathering actions (enrichment, which is safe to fully automate) with state-changing actions (isolate, disable, block, which carry real operational risk if wrong) — and ties an approval gate to the risky ones. Case management ensures every one of these actions leaves an auditable trail, which matters both for post-incident review and for compliance.",
      xp: 40,
    },

    // ── Ordering: phishing-report playbook ────────────────────────────────
    {
      type: "ordering" as const,
      id: "soar-o1",
      heading: "Order the Steps of a Phishing-Report Playbook",
      instructions:
        "An employee clicks the 'Report Phishing' button in their email client, which triggers a SOAR playbook. Arrange the playbook's steps in the order they actually execute, from the trigger to the final human decision point.",
      items: [
        {
          id: "trigger",
          text: "Employee clicks 'Report Phishing' in their email client, which sends the reported email to the SOAR platform as a new case",
        },
        {
          id: "extract",
          text: "The playbook automatically extracts the sender address, embedded URLs, and any attachment file hashes from the reported email",
        },
        {
          id: "reputation",
          text: "The playbook checks the sender domain's reputation and registration age against threat intel feeds",
        },
        {
          id: "detonate",
          text: "Any attachment is automatically detonated in a sandbox to observe what it actually does when opened",
        },
        {
          id: "search",
          text: "The playbook searches the mail environment for the same email sent to other employees, to determine the true scope",
        },
        {
          id: "ticket",
          text: "The playbook opens a ticket summarizing all findings, with a recommended action (quarantine sender-wide, notify affected users) awaiting human review",
        },
        {
          id: "human_decision",
          text: "A human analyst reviews the assembled case and approves or adjusts the final response action",
        },
      ],
      correct_order: ["trigger", "extract", "reputation", "detonate", "search", "ticket", "human_decision"],
      explanation:
        "The playbook starts from the employee's report, mechanically extracts the raw indicators (sender, URLs, hashes), enriches those indicators with reputation and sandbox detonation results, determines the true blast radius by searching for the same email elsewhere in the environment, and only THEN assembles everything into a ticket for a human to make the final, judgment-requiring call on quarantine and notification. This mirrors the general SOAR principle: automate the mechanical gathering, gate the disruptive decision behind a human.",
      xp: 40,
    },

    // ── Flag ──────────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "soar-flag1",
      prompt:
        "Look back at the over-automation analyst_choice event above (the helpdesk-integration IP 52.14.88.201). The asset owner notes reference a specific vendor integration ticket number that documents this IP as a legitimate Zendesk integration source. Enter that exact ticket number.",
      answer: "VEND-2291",
      hint: "Look at the 'xsoar.enrichment.asset_owner.notes' field in the raw block — the ticket number is written in the format LETTERS-NUMBERS.",
      xp: 30,
    },
  ],
};

export default [soarRoom];
