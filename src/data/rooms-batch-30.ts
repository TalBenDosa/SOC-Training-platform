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
  title: "Risk Fundamentals — Threat, Vulnerability, and What Actually Gets Prioritised",
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
      content: `Picture a house with a broken lock on a back window. A burglar exists somewhere in the world whether or not that lock is ever fixed. The broken lock exists whether or not any burglar currently knows about it or has any interest in this particular house. Only when both of those things are true at once — a burglar who wants in, and a window that lets them in — and there is something inside worth stealing, does the situation become a genuine, urgent problem rather than an abstract possibility.

Security uses three precisely different words for the pieces of that story, and mixing them up is one of the most common — and most consequential — mistakes a new analyst makes.

**Threat** is any actor, event, or circumstance with the potential to cause harm to an asset. Threats can be human — an external ransomware gang, a nation-state group, a disgruntled insider — or non-human, such as a hardware failure, a natural disaster, or a misconfigured automated process. A threat only matters in practice when it combines two things: capability (can this actor actually pull it off) and intent (do they want to target you specifically, your industry generally, or is their activity purely opportunistic and indiscriminate).

**Vulnerability** is a weakness that a threat could exploit to cause harm. Most people picture a technical vulnerability — an unpatched CVE, a misconfigured cloud storage bucket, a weak password policy — but vulnerabilities are just as often non-technical: an untrained employee who reliably clicks phishing links, an undocumented process, a missing approval step before a wire transfer goes out. A vulnerability sitting on its own, with no threat currently targeting it, is a liability worth fixing eventually — but it is not yet an active risk.

**Impact** is the consequence to the organisation if a threat successfully exploits a vulnerability. Financial loss, operational downtime, regulatory fines, reputational damage, exposure of sensitive data. Impact depends heavily on which specific asset is involved — a compromised disposable test server carries a very different impact than a compromised domain controller or a payment-processing system holding customer card data.

**Risk** is what you get when all three are considered together. The industry's common shorthand is "Risk = Threat x Vulnerability x Impact" — but treat that as a way of thinking, not a literal arithmetic formula. Formal frameworks handle the combination slightly differently: NIST SP 800-30 frames risk as a function of likelihood and impact, where likelihood is itself derived from combining threat and vulnerability; ISO/IEC 27005 frames it as the combination of the likelihood of a scenario and its consequence. Both land on the same underlying logic, and both usually rate each component qualitatively — low, medium, high — rather than with precise numbers, because precisely quantifying "how likely is this specific threat actor" is rarely possible. The real lesson behind the multiplication sign is this: if any one of the three components is genuinely at zero, overall risk collapses toward zero too, no matter how severe the other two look on paper.

**A worked example.** SRV-APP12 has a high-severity, unpatched vulnerability — on paper, it looks like the scarier finding. No current threat intelligence indicates any threat actor is targeting it. SRV-VPN04 has a more moderate misconfiguration, but threat intelligence confirms that a known ransomware-affiliated group is actively exploiting exactly this weakness against organisations in the same sector, right now. Even though SRV-APP12's vulnerability rating looks worse in isolation, SRV-VPN04 currently represents the higher real-world risk — because its Threat component is active, specific, and confirmed, not theoretical.

**Why this matters for prioritisation.** A SOC or vulnerability management team can never patch every "critical"-rated finding immediately — there is always more work than there is time or maintenance windows. The Threat x Vulnerability x Impact lens is exactly what turns a pile of severity ratings into an actual prioritisation decision. As an analyst, the questions worth asking are: Is there current threat intelligence showing this exact vulnerability is being actively exploited, and by whom? What does exploitation actually require — remote and unauthenticated, or local and already-authenticated? What is the impact if this specific asset, given its role and the data it holds, were compromised? A severity rating only becomes a real prioritisation decision once all three questions have been answered — not before.`,
      checkpoint: {
        question:
          "A vulnerability exists on a server, but no threat intelligence indicates any actor is currently aware of it or targeting it. According to the reading, what does this vulnerability represent right now?",
        options: [
          "Zero risk of any kind, since risk cannot exist without an active exploit already in progress",
          "A liability worth fixing, but not yet an active risk — risk requires a threat component as well, not vulnerability alone",
          "The highest possible risk, because unpatched vulnerabilities are always the most urgent item regardless of any other factor",
          "Exactly the same risk level as every other vulnerability of the same technical severity rating",
        ],
        answer: 1,
        explanation:
          "A vulnerability with no threat currently targeting it is a liability worth fixing eventually, but risk is the combination of threat, vulnerability, and impact together — without an active or credible threat component, it has not yet become an active risk.",
      },
    } satisfies ReadingTask,

    // ----- Reading 2 ---------------------------------------------------------
    {
      type: "reading",
      id: "riskfund-r2",
      heading: "Attack Surface: Everything an Attacker Could Actually Reach",
      content: `A house has a surface of possible entry points: the front door, the back door, every window, the garage door, the mail slot, and — in a modern smart home — the wifi-connected doorbell and thermostat too. An organisation's **attack surface** is the exact same idea at a much larger scale: the sum of every point where an attacker could conceivably attempt unauthorised entry, considered all together, not any single one of them in isolation.

**The categories that make up an attack surface.** The external attack surface covers every internet-facing system: web applications, VPN gateways, email servers, exposed APIs, cloud storage buckets, and public DNS records. The internal attack surface covers everything reachable once someone is already inside the network perimeter: internal servers, file shares, unpatched workstations, internal APIs, and service accounts. The human attack surface is every employee, contractor, and third party who could be phished, socially engineered, or otherwise tricked into acting on an attacker's behalf. The physical attack surface covers server rooms, unlocked network closets, exposed USB ports, and discarded hardware that was never properly wiped. And the cloud/SaaS attack surface covers every third-party cloud service, SaaS application, and API integration the organisation actually uses — including the ones the security team never approved or even knows about.

**Why attack surface keeps growing.** Every new employee hired, every new SaaS subscription approved (or quietly adopted without approval), every new cloud service connected, every new integration between two systems — each one adds at least one new potential entry point. Digital transformation, cloud adoption, remote work, and mergers all accelerate this growth. Left unmanaged, attack surface almost never shrinks on its own; it only grows, unless someone actively works to reduce it — which is exactly why maintaining an accurate, current asset inventory matters as much as any single security control.

**Attack Surface vs. Attack Vector.** These two terms get used almost interchangeably in casual conversation, but they mean structurally different things. Attack surface is the total set of all potential entry points that exist at a given moment — whether or not anyone is currently trying to use any of them. Attack vector is the one specific path or method an actual attacker used, or is actively attempting to use, in one particular attack. Back to the house: the attack surface is every door, window, and vent that exists on the building; the attack vector is the specific window a particular burglar actually climbed through on a particular night. An organisation can — and should — reduce its attack surface long before it knows anything about which specific vector any future attacker will eventually choose.

**Attack Surface Reduction as a proactive strategy.** Because attack surface is about the total count of exposure, not about any one known weakness, reducing it does not require first discovering a specific vulnerability. The core techniques are: least privilege (limiting what each account and service can reach in the first place), disabling or fully decommissioning unused services, ports, and dormant accounts, network segmentation (so that reaching one segment does not automatically grant reach into every other segment), removing orphaned or forgotten assets nobody remembers still exist, and restricting what is exposed to the public internet to only what genuinely needs to be there. None of these actions depend on knowing about a specific CVE in advance — they simply reduce the number of places a future, still-unknown vulnerability could ever be exploited from.

**A Shadow IT example.** An employee needs to send a large file to a client and, without asking IT or security, signs up on their own for a third-party file-sharing service nobody has reviewed. No vulnerability has been found in that specific tool — nothing has "happened" yet in the sense of an exploit. But the organisation's attack surface has already grown the moment company data started flowing through an unmanaged, unreviewed external account: an account with unknown password hygiene, unknown data-retention practices, and a security posture entirely outside the visibility of the security team. This is exactly why attack surface and known-vulnerability count are not the same measurement at all — surface can expand well before any vulnerability is ever identified in whatever was just added.`,
      checkpoint: {
        question:
          "According to the reading, what is the key structural difference between Attack Surface and Attack Vector?",
        options: [
          "They are two names for the exact same concept and can always be used interchangeably",
          "Attack surface is the total set of all potential entry points that exist, regardless of whether anyone is using them; attack vector is the one specific path an actual attacker used or is attempting to use",
          "Attack surface only applies to physical break-ins, while attack vector only applies to purely digital attacks",
          "Attack vector always refers to a larger, organisation-wide measurement, while attack surface refers to one single specific incident",
        ],
        answer: 1,
        explanation:
          "Attack surface is the full inventory of potential entry points that exist at a given moment, whether or not anyone is currently trying to use any of them. Attack vector is the specific path a particular attacker actually used, or is attempting to use, in one particular attack — the specific window a burglar climbed through, not every window that exists.",
      },
    } satisfies ReadingTask,

    // ----- Question 1 ---------------------------------------------------------
    {
      type: "question",
      id: "riskfund-q1",
      question:
        "Two findings land in the same prioritisation queue on the same day. SRV-APP12 has a high-severity, unpatched vulnerability, but no current threat intelligence indicates any threat actor is targeting it. SRV-VPN04 has a moderate-severity misconfiguration, but threat intelligence confirms a known ransomware-affiliated group is actively exploiting that exact weakness against organisations in your sector right now. Applying the Threat x Vulnerability x Impact view of risk, which statement is most accurate?",
      options: [
        "Both findings carry identical risk, since risk is determined only by the assigned severity rating and nothing else",
        "SRV-APP12 must always be prioritised first, because vulnerability severity alone determines risk regardless of any other factor",
        "SRV-VPN04 likely represents the higher real-world risk right now, because an active, specific threat targeting the exact weakness drives risk upward even though the vulnerability itself is rated lower severity",
        "Neither finding represents a real risk until the vulnerability has already been exploited somewhere inside the organisation",
      ],
      answer: 2,
      explanation:
        "Risk is the combination of Threat, Vulnerability, and Impact together — not vulnerability severity in isolation. SRV-VPN04's active, confirmed, sector-specific threat activity raises its real-world risk above SRV-APP12's, whose higher-severity vulnerability currently has no known threat actor behind it. Waiting for an actual exploitation event inside the organisation before treating something as a risk defeats the entire purpose of proactive prioritisation.",
      xp: 25,
    } satisfies QuestionTask,

    // ----- Question 2 ---------------------------------------------------------
    {
      type: "question",
      id: "riskfund-q2",
      question:
        "A company's public website, VPN gateway, and email service are internet-facing, while its internal file shares and unpatched workstations are only reachable once inside the network. An attacker eventually breaks in through a phishing email that tricks an employee into entering their password on a fake login page. Which statement correctly distinguishes attack surface from attack vector in this scenario?",
      options: [
        "The full set of internet-facing systems, internal systems, and employees who could theoretically be targeted is the attack surface; the specific phishing email that was actually used is the attack vector",
        "The phishing email itself is the attack surface, since it is the single artifact investigators actually collected, while the VPN gateway counts as the attack vector because it is the most exposed internet-facing system",
        "Attack surface and attack vector mean exactly the same thing and are used completely interchangeably in every professional security context, regardless of the framework or vendor documentation being referenced",
        "An attack vector only comes into existence once a breach has been formally confirmed by the incident response team; before that confirmation point, only an attack surface can be said to exist at all",
      ],
      answer: 0,
      explanation:
        "Attack surface is the total inventory of everything that could theoretically be targeted — every internet-facing system, internal system, and employee. Attack vector is the one specific path actually used in this attack: the phishing email. An attempted vector does not require a confirmed breach to exist as a vector — an attacker choosing and attempting a specific path is already using that vector, whether or not it ultimately succeeds.",
      xp: 25,
    } satisfies QuestionTask,

    // ----- Question 3 ---------------------------------------------------------
    {
      type: "question",
      id: "riskfund-q3",
      question:
        "An employee begins using a personal, unapproved cloud storage account to share large client files, without informing the security team (Shadow IT). No vulnerability has yet been identified in that specific cloud service. Has the organisation's risk exposure changed, and why?",
      options: [
        "No — risk exposure never changes at all until a specific, named vulnerability has actually been discovered and formally confirmed as present somewhere inside the new, unapproved cloud service",
        "No — Shadow IT only becomes a genuine security concern once the unapproved service itself suffers a publicly disclosed data breach that names affected customer organisations",
        "Yes, but only because personal cloud storage accounts of this kind are, essentially by definition, always operated by malicious actors seeking to harvest corporate data",
        "Yes — the organisation's attack surface has already grown, because company data now flows through an unmanaged external service outside the security team's visibility, even though no specific vulnerability has been identified there yet",
      ],
      answer: 3,
      explanation:
        "Attack surface expands the moment a new, unreviewed entry point is added — a new account with unknown password hygiene, unknown data-retention practices, and no security oversight — regardless of whether any specific vulnerability has been found in it yet. This is exactly why attack surface and known-vulnerability count are different measurements: surface can grow well before any vulnerability is ever identified in whatever was just added.",
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
        "cve.cvss_v3_score of 6.5 (Medium) alone would place this well behind the Critical-rated findings crowding the queue. But the Threat component here is not theoretical: threat_intel.active_exploitation_confirmed is true, a financially motivated intrusion cluster associated with ransomware deployment has been actively using this exact weakness since late June, and it is listed in CISA's Known Exploited Vulnerabilities catalog — a specific, confirmed threat targeting this specific vulnerability, on an internet-facing SSL-VPN gateway sitting squarely in Remote Access Infrastructure. Applying the Threat x Vulnerability x Impact view from Reading 1: the vulnerability severity alone is moderate, but a confirmed active threat combined with a high-impact, internet-facing asset raises the real risk well above what the CVSS number suggests on its own. This finding should jump the queue ahead of Critical-rated findings that currently have no known active threat behind them.",
      fp_trap:
        "A CVSS score of 6.5 reads as 'Medium' next to a queue full of 'Critical' findings, and it is tempting to file this under 'handle it in the next scheduled maintenance cycle' purely on that number. That instinct skips the Threat component entirely — confirmed active exploitation by a known threat actor, a CISA KEV listing, and an internet-facing gateway role are exactly the factors that can make a moderate-severity vulnerability the most urgent item in the entire queue. Reading severity in isolation, without checking whether an active threat currently exists, is precisely the mistake this task is built to catch.",
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
          right: "Threat — an actor or circumstance with the potential and intent to cause harm",
        },
        {
          id: "vulnerability",
          left: "An SSL-VPN gateway is running firmware with a known authentication bypass flaw that has not yet been patched",
          right: "Vulnerability — a weakness that could be exploited to cause harm",
        },
        {
          id: "impact",
          left: "If successfully exploited, the attacker gains a foothold on the network hosting financial and HR systems",
          right: "Impact — the consequence to the organisation if a threat successfully exploits a vulnerability",
        },
        {
          id: "risk",
          left: "The combined likelihood and consequence of this specific threat exploiting this specific vulnerability against this specific asset",
          right: "Risk — the outcome of Threat, Vulnerability, and Impact considered together",
        },
        {
          id: "attack-surface",
          left: "Every internet-facing service, internal system, employee, and cloud integration that could theoretically be targeted",
          right: "Attack Surface — the total set of potential entry points, whether or not anyone is currently trying to use them",
        },
        {
          id: "attack-vector",
          left: "The specific phishing email an actual attacker sent, or the specific exposed port they actually used, to get in",
          right: "Attack Vector — the specific path or method used in one particular attack",
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
        "According to Reading 2, what two-word term describes the specific path or method an attacker actually uses in a given attack — as distinct from the full set of all potential entry points (the attack surface)? Enter the term only.",
      answer: "Attack Vector",
      hint: "It's the counterpart to 'Attack Surface' from the second reading — the specific window a burglar actually climbed through, not every window that exists on the house.",
      xp: 30,
    } satisfies FlagTask,
  ],
};

export const roomsBatch30 = [riskFundamentalsRoom];
