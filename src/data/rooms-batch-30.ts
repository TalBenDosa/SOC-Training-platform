/**
 * Learning Rooms — Batch 30
 *
 * Closes a coverage gap found by audit: no room on the platform explicitly
 * teaches the classic Threat x Vulnerability x Risk equation as a formal
 * prioritisation framework, and Attack Surface — despite being referenced
 * in passing across many rooms (cyber-kill-chain, vulnerability-management,
 * and others) — is never taught as a subject in its own right.
 *
 * One room in this batch:
 *  1. risk-fundamentals — Threat, Vulnerability, Impact and Risk as distinct,
 *     precisely defined concepts; the qualitative "Risk = Threat x
 *     Vulnerability x Impact" model referenced by NIST SP 800-30 and
 *     ISO/IEC 27005; why a high CVSS score does not automatically mean high
 *     real-world risk; Attack Surface vs Attack Vector; and Attack Surface
 *     Reduction as a proactive defensive strategy.
 */

import type {
  Room,
  ReadingTask,
  QuestionTask,
  AnalystChoiceTask,
  MatchingTask,
  FlagTask,
} from "@/data/rooms";
import type { TelemetryEvent } from "@/lib/sim/types";

// ---------------------------------------------------------------------------
// Shared event — analyst_choice
// ---------------------------------------------------------------------------

const vpnThreatIntelEvent: TelemetryEvent = {
  id: "evt-riskfund-ac1-001",
  ts: "2026-07-14T09:12:00.000Z",
  source: "threat_intel",
  vendor: "Recorded Future",
  event_type: "threat_intel_match",
  severity: "medium",
  hostname: "SRV-EDGE-VPN02",
  description:
    "A vulnerability intelligence feed enriched an existing finding on this host with fresh threat-actor activity reporting. Review the underlying fields before deciding how urgently this needs to move.",
  mitre_technique: "T1190",
  raw: {
    "vendor.product": "Recorded Future Vulnerability Intelligence",
    "cve.id": "CVE-2026-24819",
    "cve.description": "Improper authentication in SSL-VPN web management interface",
    "cve.cvss_v3_score": 6.5,
    "cve.cvss_v3_severity": "Medium",
    "asset.hostname": "SRV-EDGE-VPN02",
    "asset.role": "SSL-VPN gateway",
    "asset.internet_facing": true,
    "asset.business_unit": "Remote Access Infrastructure",
    "threat_intel.active_exploitation_confirmed": true,
    "threat_intel.associated_actor":
      "financially motivated intrusion cluster linked to ransomware deployment",
    "threat_intel.first_observed_itw": "2026-06-29",
    "threat_intel.cisa_kev_listed": true,
    "patch.available": true,
    "patch.scheduled_maintenance_window": null,
  },
};

// ---------------------------------------------------------------------------
// Room — Risk Fundamentals
// ---------------------------------------------------------------------------

const riskFundamentalsRoom: Room = {
  id: "risk-fundamentals",
  title: "Risk Fundamentals: Threat, Vulnerability, and What Actually Gets Prioritised",
  description:
    "Learn the classic Threat x Vulnerability x Impact model that determines real-world risk, why a critical CVSS score does not automatically mean urgent action, how active threat intelligence changes prioritisation, and what Attack Surface and Attack Vector actually mean and how to reduce exposure before any specific vulnerability is even known.",
  difficulty: "beginner",
  category: "Foundations",
  estimatedMinutes: 40,
  xp: 180,
  icon: "⚖️",
  prerequisites: ["intro-cybersecurity"],
  tasks: [
    // ----- Reading 1 ---------------------------------------------------------
    {
      type: "reading",
      id: "riskfund-r1",
      heading: "Threat, Vulnerability, and Risk: Three Different Things That Get Confused Constantly",
      content: `Picture a house with a broken lock on a back window. A burglar exists somewhere in the world whether or not that lock is ever fixed. The broken lock exists whether or not any burglar currently knows about it or has any interest in this particular house. Only when both of those things are true at once (a burglar who wants in, and a window that lets them in) and there is something inside worth stealing, does the situation become a genuine, urgent problem rather than an abstract possibility.

Security uses three precisely different words for the pieces of that story, and mixing them up is one of the most common, and most consequential, mistakes a new analyst makes.

**Threat** is any actor, event, or circumstance with the potential to cause harm to an asset. Threats can be human (an external ransomware gang, a nation-state group, a disgruntled insider) or non-human, such as a hardware failure, a natural disaster, or a misconfigured automated process. A threat only matters in practice when it combines two things: capability (can this actor actually pull it off) and intent (do they want to target you specifically, your industry generally, or is their activity purely opportunistic and indiscriminate).

**Vulnerability** is a weakness that a threat could exploit to cause harm. Most people picture a technical vulnerability, an unpatched CVE (Common Vulnerabilities and Exposures, the public catalogue that gives every known software flaw a unique tracking ID like CVE-2024-3400), a misconfigured cloud storage bucket, a weak password policy, but vulnerabilities are just as often non-technical: an untrained employee who reliably clicks phishing links, an undocumented process, a missing approval step before a wire transfer goes out. A vulnerability with no known threat currently targeting it carries a lower likelihood, so it can usually wait behind weaknesses under confirmed attack, but its risk is not zero, because opportunistic, indiscriminate scanning can still find it, especially on an internet-facing system.

**Impact** is the consequence to the organisation if a threat successfully exploits a vulnerability. Financial loss, operational downtime, regulatory fines, reputational damage, exposure of sensitive data. Impact depends heavily on which specific asset is involved: a compromised disposable test server carries a very different impact than a compromised domain controller or a payment-processing system holding customer card data.

**Risk** is what you get when all three are considered together. The industry's common shorthand is "Risk = Threat x Vulnerability x Impact", but treat that as a way of thinking, not a literal arithmetic formula. Formal frameworks handle the combination slightly differently: NIST SP 800-30 frames risk as a function of likelihood and impact, where likelihood is itself derived from combining threat and vulnerability; ISO/IEC 27005 frames it as the combination of the likelihood of a scenario and its consequence. Both land on the same underlying logic, and both usually rate each component qualitatively (low, medium, high) rather than with precise numbers, because precisely quantifying "how likely is this specific threat actor" is rarely possible. The real lesson behind the multiplication sign is this: if any one of the three components is genuinely at zero, overall risk collapses toward zero too, no matter how severe the other two look on paper.

**A worked example.** SRV-APP12 has a high-severity, unpatched vulnerability, on paper, it looks like the scarier finding. No current threat intelligence indicates any threat actor is targeting it. SRV-VPN04 has a more moderate misconfiguration, but threat intelligence confirms that a known ransomware-affiliated group is actively exploiting exactly this weakness against organisations in the same sector, right now. Even though SRV-APP12's vulnerability rating looks worse in isolation, SRV-VPN04 currently represents the higher real-world risk, because its Threat component is active, specific, and confirmed, not theoretical.

**Why this matters for prioritisation.** A SOC or vulnerability management team can never patch every "critical"-rated finding immediately. There is always more work than there is time or maintenance windows. The Threat x Vulnerability x Impact lens is exactly what turns a pile of severity ratings into an actual prioritisation decision. As an analyst, the questions worth asking are: Is there current threat intelligence showing this exact vulnerability is being actively exploited, and by whom? What does exploitation actually require: remote and unauthenticated, or local and already-authenticated? What is the impact if this specific asset, given its role and the data it holds, were compromised? A CVSS (Common Vulnerability Scoring System) score rates only a flaw's technical severity on a 0–10 scale and says nothing about whether anyone is exploiting it. That is what threat intelligence adds, for example CISA's Known Exploited Vulnerabilities (KEV) catalog of flaws confirmed exploited in the wild. A severity rating only becomes a real prioritisation decision once all three questions have been answered, not before.`,
      checkpoint: {
        question:
          "A server has an unpatched vulnerability, but threat intelligence shows no actor currently exploiting it. Using the reading's model, how should this finding be treated right now?",
        options: [
          "As zero risk for now: with no known actor targeting it, there is nothing to fix yet",
          "As a real but lower-priority risk: no known threat lowers likelihood, but not to zero",
          "As top priority: an unpatched flaw outranks any finding that has a lower severity score",
          "At the same priority as every finding with the same severity score, whatever the threat",
        ],
        answer: 1,
        explanation:
          "Risk combines threat, vulnerability, and impact. With no known actor exploiting the flaw, the likelihood side is lower, so it can usually wait behind weaknesses under confirmed attack, but opportunistic, indiscriminate scanning can still find it, so it is a real, lower-priority risk. “Zero risk for now” confuses lower likelihood with no threat at all. “Top priority” and “same priority as every finding with the same severity score” both rank by the severity score alone, which is exactly the shortcut the Threat x Vulnerability x Impact view replaces.",
      },
    } satisfies ReadingTask,

    // ----- Reading 2 ---------------------------------------------------------
    {
      type: "reading",
      id: "riskfund-r2",
      heading: "Attack Surface: Everything an Attacker Could Actually Reach",
      content: `A house has a surface of possible entry points: the front door, the back door, every window, the garage door, the mail slot, and, in a modern smart home, the wifi-connected doorbell and thermostat too. An organisation's **attack surface** is the exact same idea at a much larger scale: the sum of every point where an attacker could conceivably attempt unauthorised entry, considered all together, not any single one of them in isolation.

**The categories that make up an attack surface.** The external attack surface covers every internet-facing system: web applications, VPN gateways, email servers, exposed APIs, cloud storage buckets, and public DNS records. The internal attack surface covers everything reachable once someone is already inside the network perimeter: internal servers, file shares, unpatched workstations, internal APIs, and service accounts. The human attack surface is every employee, contractor, and third party who could be phished, socially engineered, or otherwise tricked into acting on an attacker's behalf. The physical attack surface covers server rooms, unlocked network closets, exposed USB ports, and discarded hardware that was never properly wiped. And the cloud/SaaS attack surface covers every third-party cloud service, SaaS application, and API integration the organisation actually uses, including the ones the security team never approved or even knows about.

**Why attack surface keeps growing.** Every new employee hired, every new SaaS subscription approved (or quietly adopted without approval), every new cloud service connected, every new integration between two systems. Each one adds at least one new potential entry point. Digital transformation, cloud adoption, remote work, and mergers all accelerate this growth. Left unmanaged, attack surface almost never shrinks on its own; it only grows, unless someone actively works to reduce it, which is exactly why maintaining an accurate, current asset inventory matters as much as any single security control.

**Attack Surface vs. Attack Vector.** These two terms get used almost interchangeably in casual conversation, but they mean structurally different things. Attack surface is the total set of all potential entry points that exist at a given moment, whether or not anyone is currently trying to use any of them. Attack vector is the one specific path or method an actual attacker used, or is actively attempting to use, in one particular attack. Back to the house: the attack surface is every door, window, and vent that exists on the building; the attack vector is the specific window a particular burglar actually climbed through on a particular night. An organisation can, and should, reduce its attack surface long before it knows anything about which specific vector any future attacker will eventually choose.

**Attack Surface Reduction as a proactive strategy.** Because attack surface is about the total count of exposure, not about any one known weakness, reducing it does not require first discovering a specific vulnerability. The core techniques are: least privilege (limiting what each account and service can reach in the first place), disabling or fully decommissioning unused services, ports, and dormant accounts, network segmentation (so that reaching one segment does not automatically grant reach into every other segment), removing orphaned or forgotten assets nobody remembers still exist, and restricting what is exposed to the public internet to only what genuinely needs to be there. None of these actions depend on knowing about a specific CVE in advance. They simply reduce the number of places a future, still-unknown vulnerability could ever be exploited from.

**A Shadow IT example.** An employee needs to send a large file to a client and, without asking IT or security, signs up on their own for a third-party file-sharing service nobody has reviewed. No vulnerability has been found in that specific tool, nothing has "happened" yet in the sense of an exploit. But the organisation's attack surface has already grown the moment company data started flowing through an unmanaged, unreviewed external account: an account with unknown password hygiene, unknown data-retention practices, and a security posture entirely outside the visibility of the security team. This is exactly why attack surface and known-vulnerability count are not the same measurement at all. Surface can expand well before any vulnerability is ever identified in whatever was just added.`,
      checkpoint: {
        question:
          "No new CVE has been announced, but the security team takes a forgotten test web server off the internet and disables 15 dormant accounts. What have these changes achieved?",
        options: [
          "Nothing measurable yet: exposure only drops once a known vulnerability is patched",
          "A smaller attack surface: fewer places a future, unknown flaw could be exploited from",
          "A smaller attack vector: the path a future attacker will choose is now known and closed",
          "A lower threat level: attackers lose interest in organisations that run fewer systems",
        ],
        answer: 1,
        explanation:
          "Removing unused exposure and dormant accounts is attack surface reduction: it cuts the total number of entry points, and it does not require knowing any specific CVE in advance. “Nothing measurable yet” ties exposure to known vulnerabilities, but the reading shows surface and known-vulnerability count are different measurements. “A smaller attack vector” misuses the term: a vector is the one path a real attacker uses in a particular attack, and no attack has happened here. “A lower threat level” changes the wrong component: the actors and their intent are unchanged; what shrank is what they could reach.",
      },
    } satisfies ReadingTask,

    // ----- Question 1 ---------------------------------------------------------
    {
      type: "question",
      id: "riskfund-q1",
      question:
        "The same CVE (CVSS 7.5) is found unpatched on two internal servers. Threat intelligence shows no active exploitation of it. LAB-TEST07 is a disposable test VM holding no real data; PAY-DB01 stores customer card data for the payment system. Applying the Threat x Vulnerability x Impact view, which statement is most accurate?",
      options: [
        "Equal risk: the same CVE with the same score means the same risk on every asset",
        "LAB-TEST07 first: test machines are patched less often, so it is the weaker host",
        "PAY-DB01 ranks higher: threat and weakness match, but its compromise costs far more",
        "Neither is a risk yet: both wait until threat intelligence reports exploitation",
      ],
      answer: 2,
      explanation:
        "Threat (no known exploitation) and vulnerability (the same CVE, same score) are identical on both hosts, so the deciding component is impact: a compromised payment database holding card data costs far more than a disposable test VM. “Equal risk” treats the CVSS score as the whole of risk and ignores which asset is involved. “LAB-TEST07 first” brings in a patching habit the stem rules out: both hosts carry the same unpatched CVE, so neither is weaker. “Neither is a risk yet” confuses lower likelihood with zero risk: an unexploited flaw is still a real, lower-priority risk.",
      xp: 25,
    } satisfies QuestionTask,

    // ----- Question 2 ---------------------------------------------------------
    {
      type: "question",
      id: "riskfund-q2",
      question:
        "A company's public website, VPN gateway, and email service are internet-facing, while its internal file shares and unpatched workstations are only reachable once inside the network. An attacker eventually breaks in through a phishing email that tricks an employee into entering their password on a fake login page. Which statement correctly distinguishes attack surface from attack vector in this scenario?",
      options: [
        "The full set of internet-facing systems, internal systems and employees who could be targeted is the attack surface; the phishing email actually used is the vector",
        "The phishing email is the attack surface, being the one artifact investigators collected, and the VPN gateway is the vector because it is the most exposed system",
        "The attack surface is the internal file shares and workstations reached after entry, and the vector is the set of internet-facing systems the attacker came through",
        "Incident response names the attack vector after it confirms the breach; until then the scenario has an attack surface but no vector at all",
      ],
      answer: 0,
      explanation:
        "Attack surface is the total inventory of everything that could theoretically be targeted: every internet-facing system, internal system, and employee. Attack vector is the one specific path actually used in this attack: the phishing email. Calling the phishing email the surface because it was the artifact collected, with the VPN gateway as the vector, swaps the two terms, and the VPN was not the path used. Calling the internal systems the surface and the internet-facing systems the vector splits one inventory into two parts instead of separating “everything reachable” from “the path used”. And a vector does not wait for incident response to confirm a breach: an attacker choosing and attempting a specific path is already using that vector, whether or not it succeeds.",
      xp: 25,
    } satisfies QuestionTask,

    // ----- Question 3 ---------------------------------------------------------
    {
      type: "question",
      id: "riskfund-q3",
      question:
        "Without telling IT or security, the marketing team connects a new third-party analytics app to the company CRM through an API integration that can read customer records. No vulnerability is known in the app, and no attack has been seen. What has changed?",
      options: [
        "Nothing yet: exposure grows when a flaw is found in the app, not before",
        "The attack vector: the API integration is now the path an attacker is using",
        "The impact rose as data sits with a vendor, but the entry points are unchanged",
        "The attack surface grew: an unreviewed integration is a new entry point",
      ],
      answer: 3,
      explanation:
        "Every new integration adds a potential entry point, and this one is unreviewed and outside security's visibility, so the attack surface grew the moment it was connected, with no known vulnerability required. “Nothing yet” ties exposure to known flaws, but surface and known-vulnerability count are different measurements. “The attack vector” misuses the term: a vector is the path a real attacker uses in a particular attack, and no attack has been seen. “The impact rose … entry points are unchanged” is wrong about the entry points: the integration itself is a new way in to customer records.",
      xp: 25,
    } satisfies QuestionTask,

    // ----- Analyst Choice ---------------------------------------------------------
    {
      type: "analyst_choice",
      id: "riskfund-ac1",
      heading: "Verdict: A 'Medium' Finding in a Queue Full of 'Critical' Ones",
      scenario:
        "Your vulnerability management queue is full of dozens of findings rated Critical by CVSS score alone. This particular finding on SRV-EDGE-VPN02 is only rated Medium (CVSS 6.5), and would normally sit near the bottom of this week's patching list. A threat-intelligence enrichment job has just attached fresh context to it, shown in the fields below. Decide whether this finding should be escalated for expedited remediation, or left in its regularly scheduled patch cycle.",
      event: vpnThreatIntelEvent,
      correct_verdict: "escalate",
      explanation:
        "cve.cvss_v3_score of 6.5 (Medium) alone would place this well behind the Critical-rated findings crowding the queue. But the Threat component here is not theoretical: threat_intel.active_exploitation_confirmed is true, a financially motivated intrusion cluster associated with ransomware deployment has been actively using this exact weakness since late June, and it is listed in CISA's Known Exploited Vulnerabilities catalog, a specific, confirmed threat targeting this specific vulnerability, on an internet-facing SSL-VPN gateway sitting squarely in Remote Access Infrastructure. Applying the Threat x Vulnerability x Impact view from Reading 1: the vulnerability severity alone is moderate, but a confirmed active threat combined with a high-impact, internet-facing asset raises the real risk well above what the CVSS number suggests on its own. This finding should jump the queue ahead of Critical-rated findings that currently have no known active threat behind them.",
      fp_trap:
        "A CVSS score of 6.5 reads as 'Medium' next to a queue full of 'Critical' findings, and it is tempting to file this under 'handle it in the next scheduled maintenance cycle' purely on that number. That instinct skips the Threat component entirely. Confirmed active exploitation by a known threat actor, a CISA KEV listing, and an internet-facing gateway role are exactly the factors that can make a moderate-severity vulnerability the most urgent item in the entire queue. Reading severity in isolation, without checking whether an active threat currently exists, is precisely the mistake this task is built to catch.",
      xp: 40,
    } satisfies AnalystChoiceTask,

    // ----- Matching ---------------------------------------------------------
    {
      type: "matching",
      id: "riskfund-m1",
      heading: "Match Each Scenario to the Term It Represents",
      instructions:
        "Match each short scenario to the risk term it demonstrates.",
      pairs: [
        {
          id: "threat",
          left: "A known ransomware-affiliated group is actively scanning the internet for a specific unpatched VPN flaw",
          right: "Threat: an actor or circumstance with the potential and intent to cause harm",
        },
        {
          id: "vulnerability",
          left: "An SSL-VPN gateway is running firmware with a known authentication bypass flaw that has not yet been patched",
          right: "Vulnerability: a weakness that could be exploited to cause harm",
        },
        {
          id: "impact",
          left: "If successfully exploited, the attacker gains a foothold on the network hosting financial and HR systems",
          right: "Impact: the consequence to the organisation if a threat successfully exploits a vulnerability",
        },
        {
          id: "risk",
          left: "The combined likelihood and consequence of this specific threat exploiting this specific vulnerability against this specific asset",
          right: "Risk: the outcome of Threat, Vulnerability, and Impact considered together",
        },
        {
          id: "attack-surface",
          left: "Every internet-facing service, internal system, employee, and cloud integration that could theoretically be targeted",
          right: "Attack Surface: the total set of potential entry points, whether or not anyone is currently trying to use them",
        },
        {
          id: "attack-vector",
          left: "The specific phishing email an actual attacker sent, or the specific exposed port they actually used, to get in",
          right: "Attack Vector: the specific path or method used in one particular attack",
        },
      ],
      explanation:
        "Each scenario maps onto exactly one term from Reading 1 and Reading 2: Threat is the actor with capability and intent, Vulnerability is the weakness itself, Impact is the consequence of a successful exploit, Risk is all three considered together, Attack Surface is the full inventory of potential entry points, and Attack Vector is the one specific path actually used in a given attack.",
      xp: 35,
    } satisfies MatchingTask,

    // ----- Flag ---------------------------------------------------------
    {
      type: "flag",
      id: "riskfund-f1",
      prompt:
        "Three findings arrive in this week's queue. WEB-DEV03: CVSS 9.8, internal lab server holding no real data, no known exploitation. HR-FS02: CVSS 8.1, internal HR file share, no known exploitation. PAY-API01: CVSS 7.2, internet-facing payment API, threat intelligence confirms active exploitation of this CVE against retailers like yours. Applying Threat x Vulnerability x Impact, enter the hostname you would remediate first.",
      answer: "PAY-API01",
      hint: "Rate each finding on all three components (who is exploiting it, how exposed it is, and what its compromise would cost) instead of sorting by the score.",
      xp: 30,
    } satisfies FlagTask,
  ],
};

export const roomsBatch30 = [riskFundamentalsRoom];
