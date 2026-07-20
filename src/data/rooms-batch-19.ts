/**
 * Learning Rooms — Batch 19
 *
 * Four rooms closing a coverage gap found by audit: Vulnerability Management
 * had zero rooms, Forensics had one, Incident Response had two, and several
 * techniques the scenarios make students practise were taught nowhere —
 * notably T1114.002 (remote email collection), T1496 (resource hijacking is
 * referenced but not this batch's focus), T1621 (MFA request generation) and
 * T1550.004 (web session cookie theft).
 *
 * Rooms in this batch:
 *  1. vulnerability-management        — CVE/CWE/CVSS, EPSS, CISA KEV, scanning
 *  2. memory-disk-forensics           — advanced acquisition & anti-forensics
 *  3. email-collection-exfiltration   — T1114.002, T1564.008, delegation, DLP
 *  4. mfa-attacks-session-hijacking   — T1621, AitM, T1550.004, T1098.005
 */

import type { TelemetryEvent } from "@/lib/sim/types";

// ===========================================================================
// ROOM 1 — Vulnerability Management for SOC Analysts
// ===========================================================================

const vulnScanEvent: TelemetryEvent = {
  id: "evt-vulnmgmt-la1-001",
  ts: "2026-06-02T03:14:00.000Z",
  source: "edr",
  vendor: "Tenable.io",
  event_type: "edr_alert",
  severity: "critical",
  hostname: "portal-web03.solvix.com",
  description:
    "The nightly authenticated scan of portal-web03 (the public customer login portal) reported a reflected XSS finding. The platform's displayed severity is Critical, driven by the Vulnerability Priority Rating rather than the CVSS base score alone — compare the two fields in the raw record below.",
  raw: {
    "tenable.plugin_id": "212344",
    "tenable.plugin_name": "Reflected XSS in Login Parameter Handling",
    "tenable.plugin_family": "Web Applications",
    "tenable.cve": "CVE-2025-31337",
    "tenable.cwe": "CWE-79",
    "tenable.cvss3_base_score": 6.1,
    "tenable.cvss3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "tenable.vpr_score": 9.3,
    "tenable.epss_score": 0.94,
    "tenable.epss_percentile": 0.99,
    "tenable.cisa_known_exploited": true,
    "tenable.cisa_kev_due_date": "2026-06-16",
    "tenable.exploit_available": true,
    "tenable.exploit_code_maturity": "Functional",
    "tenable.patch_publication_date": "2025-11-03",
    "tenable.asset_hostname": "portal-web03.solvix.com",
    "tenable.asset_ipv4": "203.0.113.44",
    "tenable.asset_exposure": "internet-facing",
    "tenable.asset_criticality": "production",
    "tenable.scan_type": "authenticated",
    "tenable.first_found": "2026-05-20T09:00:00.000Z",
    "tenable.last_found": "2026-06-02T03:14:00.000Z",
    "tenable.port": 443,
    "tenable.protocol": "tcp",
  },
};

const vulnFpEvent: TelemetryEvent = {
  id: "evt-vulnmgmt-ac1-001",
  ts: "2026-06-02T03:41:00.000Z",
  source: "edr",
  vendor: "Tenable.io",
  event_type: "edr_alert",
  severity: "high",
  hostname: "api-gw02.solvix.com",
  it_verify_result: "confirmed",
  it_verify_message:
    "Platform team ran 'rpm -q --changelog httpd' on api-gw02 and confirmed the CVE-2017-15715 fix is present in the installed package (httpd-2.4.6-97.el7_9.4). Red Hat backports security fixes into its own point releases without changing the upstream version string the banner reports.",
  description:
    "An unauthenticated web scan of api-gw02 flagged an eight-year-old Apache HTTP Server vulnerability based on the version string returned in the server banner.",
  raw: {
    "tenable.plugin_id": "103259",
    "tenable.plugin_name": "Apache HTTP Server mod_expires Out-of-Bounds Read",
    "tenable.plugin_family": "Web Servers",
    "tenable.cve": "CVE-2017-15715",
    "tenable.cwe": "CWE-125",
    "tenable.cvss3_base_score": 8.6,
    "tenable.cvss3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    "tenable.vpr_score": 3.1,
    "tenable.epss_score": 0.02,
    "tenable.cisa_known_exploited": false,
    "tenable.exploit_available": false,
    "tenable.plugin_output": "Server: Apache/2.4.6 (Red Hat Enterprise Linux)",
    "tenable.asset_hostname": "api-gw02.solvix.com",
    "tenable.asset_ipv4": "10.20.4.17",
    "tenable.asset_exposure": "internal",
    "tenable.asset_os": "Red Hat Enterprise Linux 7.9",
    "tenable.scan_type": "unauthenticated",
    "tenable.first_found": "2026-06-02T03:41:00.000Z",
    "tenable.last_found": "2026-06-02T03:41:00.000Z",
    "tenable.port": 443,
    "tenable.protocol": "tcp",
  },
};

const vulnerabilityManagementRoom = {
  id: "vulnerability-management",
  title: "Vulnerability Management for SOC Analysts",
  description:
    "Learn to read a vulnerability scan the way an analyst actually has to: what CVE, CWE, and CVSS each identify (and why they get confused), how CVSS scores are built from base, temporal, and environmental metrics, why EPSS and the CISA KEV catalog often matter more than the base score, how authenticated and unauthenticated scanning differ, how to confirm a false positive before it burns a ticket, and where the SOC's job ends and IT's patching job begins.",
  difficulty: "intermediate" as const,
  category: "Vulnerability Management",
  estimatedMinutes: 55,
  xp: 295,
  icon: "🩹",
  prerequisites: ["intro-cybersecurity"],
  tasks: [
    // ── Reading 1: CVE vs CWE vs CVSS ────────────────────────────────────
    {
      type: "reading" as const,
      id: "vm-r1",
      heading: "CVE, CWE, and CVSS Are Three Different Questions",
      content:
        "Three acronyms get mixed up constantly by junior analysts, and the confusion causes real mistakes — like treating a weakness category as if it carried a severity score, or assuming a CVE number tells you how dangerous something is. Each one answers a completely different question.\n\n" +
        "**CVE (Common Vulnerabilities and Exposures) answers: which specific vulnerability is this?** A CVE is a unique identifier — CVE-2021-44228, the Log4Shell vulnerability, is a good example — assigned to one specific, publicly disclosed flaw in one specific piece of software. It is a name, nothing more. CVE numbers are issued by CVE Numbering Authorities (CNAs, often the vendor itself or a coordinating body like MITRE) whenever a new vulnerability is disclosed. Knowing a CVE number tells you which bug you are talking about; it tells you nothing about how bad it is.\n\n" +
        "**CWE (Common Weakness Enumeration) answers: what TYPE of mistake caused this?** A CWE is a category, not an instance. CWE-79 is Cross-Site Scripting as a general class of coding mistake — the failure to properly neutralize user input before it is rendered in a web page. Thousands of different CVEs, across thousands of different products, are all classified as CWE-79, because they all share the same underlying pattern of weakness. CWE is useful for spotting trends (does our codebase have a recurring SQL injection problem — CWE-89 — across multiple applications?) and for secure-coding training, but a CWE category itself carries no severity: CWE-79 does not mean 'this is always a medium-severity finding.' A CWE-79 finding can score anywhere from low to critical depending on exactly what the specific CVE lets an attacker do.\n\n" +
        "**CVSS (Common Vulnerability Scoring System) answers: how severe is THIS specific CVE?** CVSS is a numeric score, 0.0 to 10.0, calculated from a defined set of metrics describing exploitability and impact for one specific vulnerability instance. It is the only one of the three that produces a number you can rank findings by — which is exactly why it gets treated as the whole story, and exactly why the next two readings exist: CVSS alone is a poor prioritization tool on its own.\n\n" +
        "**Putting them together with a real example.** CVE-2021-44228 (the identifier) is an instance of CWE-502 (Deserialization of Untrusted Data — the weakness category) that was assigned a CVSS base score of 10.0 (the severity number, reflecting that it was unauthenticated, network-reachable, required no user interaction, and gave complete remote code execution). A different CVE, in a completely different product, can also be CWE-502 and score a 4.0, because the specific conditions required to trigger it are far more restrictive. The category tells you the shape of the mistake; the CVE tells you which mistake; the score tells you how much this particular mistake matters right now.\n\n" +
        "**The confusion that actually happens on the job.** New analysts often read 'CWE-79' in a scan report and assume it directly implies a severity level, or say things like 'the CVSS is 79' when they mean the CWE number. Get in the habit of reading a finding as three separate facts stacked together: identifier, category, severity — never collapse them into one.",
      codeExample:
        "THREE ACRONYMS, THREE QUESTIONS\n" +
        "=======================================================\n" +
        "CVE   \"Which specific vulnerability is this?\"\n" +
        "      -> CVE-2021-44228 (Log4Shell)\n" +
        "      -> a unique ID for one disclosed flaw in one product\n" +
        "\n" +
        "CWE   \"What TYPE of coding mistake caused it?\"\n" +
        "      -> CWE-502 (Deserialization of Untrusted Data)\n" +
        "      -> a category shared by thousands of unrelated CVEs\n" +
        "      -> carries NO severity of its own\n" +
        "\n" +
        "CVSS  \"How severe is THIS specific CVE, right now?\"\n" +
        "      -> 10.0 for CVE-2021-44228\n" +
        "      -> the only one of the three that is a ranked number\n" +
        "=======================================================\n" +
        "Same CWE category, different CVSS scores:\n" +
        "  CVE-2021-44228  CWE-502  CVSS 10.0 (unauth RCE, network)\n" +
        "  CVE-2019-XXXXX  CWE-502  CVSS  4.3 (needs local auth first)\n" +
        "=======================================================",
    },

    // ── Reading 2: CVSS structure and bands ──────────────────────────────
    {
      type: "reading" as const,
      id: "vm-r2",
      heading: "Inside a CVSS Score: Base, Temporal, and Environmental Metrics",
      content:
        "A CVSS score is not one opaque number — it is built from a vector string you can read metric by metric, and understanding that vector is what lets you explain to a stakeholder exactly why a finding scored what it did, instead of just repeating the number.\n\n" +
        "**The Base score — intrinsic to the vulnerability itself.** This is the part everyone sees, built from eight metrics that never change once assigned (they describe the flaw, not the environment it happens to be running in). Attack Vector (AV) is how reachable it is: N for Network (reachable over the internet or a routed network), A for Adjacent (same broadcast domain/segment), L for Local, P for Physical (requires hands on the device). Attack Complexity (AC) is L (Low, reliably exploitable) or H (High, requires specific conditions the attacker doesn't fully control). Privileges Required (PR) is N, L, or H. User Interaction (UI) is N (none needed) or R (a victim has to click or open something). Scope (S) is U (Unchanged — the impact stays inside the vulnerable component) or C (Changed — exploiting it lets the attacker affect resources beyond its own security boundary, which is a significant severity multiplier). Finally Confidentiality, Integrity, and Availability Impact (C/I/A) are each N, L, or H, describing what the attacker actually gains. A vector like CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H — network-reachable, low complexity, no privileges or interaction needed, full impact on all three properties — is what a 9.8 looks like.\n\n" +
        "**Score bands you should know cold:** None is 0.0, Low is 0.1–3.9, Medium is 4.0–6.9, High is 7.0–8.9, and Critical is 9.0–10.0.\n\n" +
        "**The Temporal score — how the picture changes over time.** Temporal metrics adjust the base score as real-world circumstances evolve: Exploit Code Maturity (E) ranges from Unproven through Proof-of-Concept, Functional, and High (weaponized/automated); Remediation Level (RL) is Official Fix, Temporary Fix, Workaround, or Unavailable; Report Confidence (RC) reflects how solid the technical details are. A vulnerability with a widely available, automated exploit and no official patch scores meaningfully differently, in practice, than the same base flaw the week it was disclosed with only a theoretical write-up.\n\n" +
        "**The Environmental score — specific to your organization.** This lets you re-score a vulnerability against your own actual deployment: Confidentiality/Integrity/Availability Requirements (CR/IR/AR) reflect how much each property actually matters for this asset in your business, and Modified Base Metrics let you reflect compensating controls already in place (a vulnerable service sitting behind strict network segmentation might get a Modified Attack Vector of Local instead of Network, lowering the effective score for your environment specifically, even though the vendor's published base score never changes).\n\n" +
        "**Why this matters for prioritization:** the base score is what the vendor publishes once and never touches again. Temporal and environmental scoring are what tell you whether that number still describes your actual risk today — which is exactly the gap the next reading closes with EPSS and the CISA KEV catalog.",
      codeExample:
        "CVSS v3.1 BASE METRICS — READING A VECTOR STRING\n" +
        "=======================================================\n" +
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H  = 9.8 (Critical)\n" +
        "\n" +
        "AV  Attack Vector        N=Network A=Adjacent L=Local P=Physical\n" +
        "AC  Attack Complexity    L=Low  H=High\n" +
        "PR  Privileges Required  N=None L=Low H=High\n" +
        "UI  User Interaction     N=None R=Required\n" +
        "S   Scope                U=Unchanged C=Changed\n" +
        "C/I/A  Impact            N=None L=Low H=High\n" +
        "=======================================================\n" +
        "SCORE BANDS\n" +
        "=======================================================\n" +
        "None 0.0 | Low 0.1-3.9 | Medium 4.0-6.9 | High 7.0-8.9\n" +
        "Critical 9.0-10.0\n" +
        "=======================================================\n" +
        "TEMPORAL METRICS -- change as the world changes\n" +
        "  E  Exploit Code Maturity   U / POC / F / H\n" +
        "  RL Remediation Level       OF / TF / W / U\n" +
        "  RC Report Confidence       U / R / C\n" +
        "ENVIRONMENTAL METRICS -- specific to YOUR org\n" +
        "  CR/IR/AR  Security requirement for this asset\n" +
        "  Modified base metrics reflecting compensating controls\n" +
        "=======================================================",
    },

    // ── Question 1 (applied — CVE/CWE/CVSS confusion) ────────────────────
    {
      type: "question" as const,
      id: "vm-q1",
      question:
        "A scan report line reads: 'CVE-2024-21762, CWE-787 (Out-of-bounds Write), CVSS 9.8.' A junior analyst writes in the ticket: 'CWE-787 findings are always critical, so I'm closing every other CWE-787 result in the backlog as high priority too.' What is wrong with that reasoning?",
      options: [
        "Nothing — CWE categories do carry a fixed, universal severity rating",
        "CWE-787 is only a category describing the type of coding mistake (writing past a buffer's bounds); it carries no severity of its own — two different CVEs both classified as CWE-787 can have completely different CVSS scores depending on reachability, privileges required, and impact",
        "CVE-2024-21762 is not a real identifier format, so the whole line should be disregarded",
        "CVSS 9.8 means the vulnerability has already been patched, so no action is needed either way",
      ],
      answer: 1,
      explanation:
        "CWE is a weakness category, not a severity rating — CWE-787 describes a pattern of coding mistake shared by many unrelated CVEs in many unrelated products, each of which gets its own independent CVSS score based on its own specific exploitability and impact. Assuming every CWE-787 finding is automatically critical would misprioritize a low-severity local-only out-of-bounds write the same as an unauthenticated remote one. The CVE-2024-21762 identifier format is a real, valid CVE number format (CVE-YYYY-NNNNN), and a high CVSS score says nothing about whether a patch exists yet — those are two unrelated facts.",
      xp: 25,
    },

    // ── Reading 3: EPSS + CISA KEV, worked prioritization example ─────────
    {
      type: "reading" as const,
      id: "vm-r3",
      heading: "Why CVSS Alone Prioritizes Badly — EPSS and the CISA KEV Catalog",
      content:
        "CVSS answers one question well: if this vulnerability IS exploited, how bad is the technical impact? It says almost nothing about whether it is actually being exploited, or how likely that is to happen soon — and prioritizing a patch backlog by CVSS score alone routinely gets the order wrong.\n\n" +
        "**EPSS (Exploit Prediction Scoring System)** answers a different question: how likely is this specific CVE to be exploited in the wild in the next 30 days? Published by FIRST (the same organization that maintains the CVSS standard) and updated daily, EPSS is a machine-learning model trained on real-world attacker activity — scanning traffic, exploit-kit inclusion, dark-web chatter, and more — and it outputs a probability from 0 to 100%, plus a percentile ranking against every other scored CVE. A CVE with a high CVSS score but an EPSS of 0.4% has a real technical impact but very little evidence anyone is actually going after it. A CVE with a middling CVSS score and an EPSS of 94% is, statistically, something attackers are already actively working against right now.\n\n" +
        "**The CISA KEV (Known Exploited Vulnerabilities) catalog** answers a third, even sharper question: has this CVE actually, confirmedly, already been used by attackers? It is a curated list maintained by the U.S. Cybersecurity and Infrastructure Security Agency, and getting added requires real evidence of in-the-wild exploitation — not a theoretical risk, a confirmed one. Under Binding Operational Directive 22-01, U.S. federal agencies must remediate KEV entries by a published due date; most private-sector security teams have adopted the same catalog as a prioritization signal regardless of whether they're a federal agency, because 'this is proven to be exploited' is about as strong a prioritization signal as exists.\n\n" +
        "**Three different questions, three different signals:** CVSS says how bad IF it happens. EPSS says how likely it is to happen soon. KEV says whether it has already happened, confirmed. A mature vulnerability management program combines all three with asset context — you'll see exactly that combination in this room's log analysis exercise.\n\n" +
        "**A real worked example — the lower CVSS score is the more urgent one.** Imagine your scan run turns up two findings the same week. Finding A: CVSS 8.8 (High) — a local privilege-escalation flaw in an internal accounting application, reachable only by an already-authenticated user on an isolated finance VLAN accessible from a single jump host, no public exploit code exists, and it is not in the KEV catalog; EPSS sits at 0.4%. Finding B: CVSS 6.1 (Medium) — a reflected XSS on your internet-facing customer login portal, but this exact CVE IS in the CISA KEV catalog with a two-week remediation due date, EPSS is 94% (99th percentile), and a public, functional exploit is confirmed to exist. On CVSS alone, Finding A looks more urgent — 8.8 beats 6.1. In reality, Finding B is the fire: it is reachable by anyone on the internet, it is being actively exploited against organizations like yours right now, and the exploitation probability is about as high as EPSS ever reports. Finding A matters and should still be scheduled, but it is not this week's emergency. This is exactly the gap between 'severe if it happens' and 'actually happening' that CVSS alone cannot tell you.",
      codeExample:
        "THREE PRIORITIZATION SIGNALS -- THREE DIFFERENT QUESTIONS\n" +
        "=======================================================\n" +
        "CVSS   \"How bad IS this, technically, IF exploited?\"\n" +
        "       Static. Published once by the vendor/NVD.\n" +
        "\n" +
        "EPSS   \"How LIKELY is exploitation in the next 30 days?\"\n" +
        "       Dynamic. Updated daily. 0-100% + percentile.\n" +
        "\n" +
        "CISA KEV  \"Is this CONFIRMED already being exploited?\"\n" +
        "          Binary flag. Evidence-based, not predictive.\n" +
        "=======================================================\n" +
        "WORKED EXAMPLE -- lower CVSS, higher real urgency\n" +
        "=======================================================\n" +
        "Finding A: CVSS 8.8 (High)\n" +
        "  - internal-only, isolated finance VLAN\n" +
        "  - authenticated access required\n" +
        "  - no public exploit, not in KEV, EPSS 0.4%\n" +
        "  -> patch on the normal cycle\n" +
        "\n" +
        "Finding B: CVSS 6.1 (Medium)\n" +
        "  - internet-facing customer login portal\n" +
        "  - IN the CISA KEV catalog, 2-week due date\n" +
        "  - EPSS 94% (99th percentile), functional exploit exists\n" +
        "  -> patch THIS WEEK, despite the lower base score\n" +
        "=======================================================",
    },

    // ── Question 2 (applied — worked prioritization) ─────────────────────
    {
      type: "question" as const,
      id: "vm-q2",
      question:
        "Your team has patch capacity for one emergency fix this week. Option 1: CVSS 8.1, internal build server reachable only from the CI/CD VLAN, no known exploit, not in KEV. Option 2: CVSS 5.4, internet-facing VPN gateway login page, listed in the CISA KEV catalog with a 14-day remediation deadline, EPSS 91%. Which do you patch first, and why?",
      options: [
        "Option 1, because 8.1 is a higher CVSS score and CVSS is the industry-standard severity measure",
        "Option 2, because a confirmed active-exploitation listing (KEV) plus a very high exploitation probability (EPSS) on an internet-facing asset outweighs a higher base score on an internal, hard-to-reach system with no evidence of real-world exploitation",
        "Neither — wait until next week's scan to see if either score changes",
        "Option 1, because internal systems should always be patched before internet-facing ones",
      ],
      answer: 1,
      explanation:
        "This mirrors the worked example: CVSS alone favors Option 1, but CVSS only measures potential impact if exploited — it says nothing about likelihood or confirmed activity. Option 2's KEV listing means attackers are confirmed to already be using this exact vulnerability, its EPSS of 91% says exploitation is highly probable in the near term, and it sits on an internet-facing VPN gateway that anyone can reach — a far larger and more immediate exposure than an internal build server reachable only from a restricted CI/CD network with zero evidence of exploitation. Waiting for another scan cycle wastes the KEV due-date window, and 'internal systems first' has the exposure logic backwards.",
      xp: 25,
    },

    // ── Reading 4: authenticated vs unauthenticated scanning, exposure ────
    {
      type: "reading" as const,
      id: "vm-r4",
      heading: "Authenticated vs Unauthenticated Scanning, and Asset Context",
      content:
        "The same target scanned two different ways can produce wildly different results — and knowing which method produced a given finding changes how much you trust it.\n\n" +
        "**Unauthenticated scanning** probes a target the way an outside attacker would: no credentials, just open ports, service banners, and responses to crafted network requests. It is fast, requires no credential management, and is the only option for assets you don't control (a third party's internet-facing service, for instance). But it has real limits: it can only see what's externally visible, and a lot of its findings are inferred from version banners rather than direct inspection — which means it is prone to exactly the false-positive pattern in this room's analyst-choice exercise, where a vendor backports a security fix without changing the version string the banner reports.\n\n" +
        "**Authenticated scanning** logs into the target with valid credentials (via SSH, WinRM, or an agent) and inspects the system directly — the actual installed package list, patch level, and configuration, not an inference from the outside. It finds far more real vulnerabilities (missing patches that don't change any externally visible banner at all, local misconfigurations, weak file permissions) and produces dramatically fewer false positives, because it isn't guessing. The tradeoff is operational: it requires managing scan credentials securely (ideally through a PAM vault with rotation, not a static service account password sitting in the scanner config), and it can occasionally miss something only visible from an external vantage point, like a firewall rule that shouldn't be open. Mature programs run both: unauthenticated externally to see what an attacker actually sees, authenticated internally for ground truth on patch levels.\n\n" +
        "**Asset criticality and internet exposure as multipliers.** No score in the previous readings knows anything about YOUR environment until you add that context yourself. The same CVE on an internet-facing production system holding customer data deserves urgent treatment; the identical CVE on an isolated lab machine scheduled for decommission next month does not, even though the CVSS, EPSS, and KEV status are byte-for-byte identical. Build the habit of asking, for every finding: is this reachable from the internet or only from inside a segmented network? Is this asset business-critical, or a throwaway? Does compromising it lead anywhere else (a jump box into a sensitive segment is worth more to an attacker than its own contents suggest)? None of this appears in the CVE record — it lives in your asset inventory, and a vulnerability management program without accurate asset context is scoring blind.",
      codeExample:
        "AUTHENTICATED vs UNAUTHENTICATED SCANNING\n" +
        "=======================================================\n" +
        "UNAUTHENTICATED             AUTHENTICATED\n" +
        "-----------------------     -----------------------\n" +
        "No credentials needed       Logs in via SSH/WinRM/agent\n" +
        "Sees only what's externally  Inspects installed packages,\n" +
        "  visible (banners, ports)     patch level directly\n" +
        "Fast, low operational cost   Slower, needs credential mgmt\n" +
        "Prone to banner-based FPs    Far fewer false positives\n" +
        "Only option for 3rd-party    Best for assets you control\n" +
        "  or unmanaged assets\n" +
        "=======================================================\n" +
        "CONTEXT MULTIPLIERS -- not in the CVE record at all\n" +
        "=======================================================\n" +
        "Internet-facing?      -> raises real-world urgency\n" +
        "Business-critical?    -> raises real-world urgency\n" +
        "Pivot point to other  -> raises real-world urgency\n" +
        "  sensitive segments?\n" +
        "Isolated / decommission scheduled? -> lowers urgency\n" +
        "=======================================================",
    },

    // ── Log Analysis: the Critical VPR finding ────────────────────────────
    {
      type: "log_analysis" as const,
      id: "vm-la1",
      heading: "One Finding, Two Severity Numbers",
      context:
        "Solvix's Tenable.io tenant is configured to display severity based on VPR (Tenable's own Vulnerability Priority Rating, a proprietary 0–10 score that folds in threat intelligence, not just CVSS) rather than raw CVSS. For comparison, the same scan run also flagged CVE-2025-40021 on ACCT-INTERNAL-07: CVSS 8.8 (High), a local privilege-escalation flaw reachable only from a single finance-team jump host on an isolated VLAN, no public exploit code, and not listed in CISA KEV. Review the finding below and decide how the two should actually be prioritized against each other.",
      event: vulnScanEvent,
      questions: [
        {
          question:
            "The event's top-level severity is 'critical', but tenable.cvss3_base_score is only 6.1 (Medium). Which combination of fields explains that gap?",
          options: [
            "It's a display bug — CVSS and severity should always match exactly",
            "tenable.vpr_score is 9.3, and tenable.cisa_known_exploited is true with tenable.epss_score at 0.94 — VPR folds in real exploitation evidence and likelihood that the static CVSS base score does not, which is why Tenable's VPR-driven severity reads far higher than CVSS alone would suggest",
            "The severity field always defaults to critical for any internet-facing asset regardless of the actual finding",
            "tenable.exploit_code_maturity being 'Functional' automatically overrides CVSS to critical for every vendor",
          ],
          answer: 1,
          explanation:
            "As covered in Reading 3, CVSS is static and only measures potential impact. VPR, EPSS, and KEV status all fold in real-world exploitation evidence and likelihood — this finding has a confirmed CISA KEV listing and a 94% EPSS score, which is exactly why a platform combining those signals (VPR) rates it far more urgently than the CVSS base score alone would. This isn't a bug or a blanket rule about exposure or exploit maturity; it's the specific combination of KEV + EPSS driving VPR upward for this specific CVE.",
          xp: 30,
        },
        {
          question:
            "Comparing this finding (CVSS 6.1, VPR 9.3, internet-facing) against CVE-2025-40021 described in the context (CVSS 8.8, internal-only, isolated VLAN, not in KEV, no public exploit), which should be remediated first?",
          options: [
            "CVE-2025-40021, because 8.8 is a higher CVSS score than 6.1",
            "This finding (CVE-2025-31337), because it combines a confirmed CISA KEV listing, a near-certain EPSS score, and internet exposure — exactly the pattern from the worked example in Reading 3 where the lower CVSS finding is the real emergency",
            "Neither — both should wait for the next standard patch cycle since neither is critical by CVSS alone",
            "CVE-2025-40021, because internal systems are always a bigger insider-threat risk than internet-facing ones",
          ],
          answer: 1,
          explanation:
            "This is the exact pattern taught in Reading 3: the lower CVSS finding, when it is KEV-confirmed, has a near-certain EPSS score, and sits on an internet-facing asset, outranks a higher-CVSS finding that is internal-only, unauthenticated by design (isolated VLAN, single jump host), has no public exploit, and isn't in KEV. CVE-2025-40021 still needs scheduling — it isn't dismissed — but it is not this week's fire the way CVE-2025-31337 is.",
          xp: 35,
        },
        {
          question:
            "tenable.scan_type on this finding is 'authenticated'. If this same host had only ever been scanned unauthenticated, what is the most accurate statement about what you might have missed?",
          options: [
            "Nothing — authenticated and unauthenticated scans always return identical results for web application findings",
            "An unauthenticated scan could still surface an externally-visible reflected XSS finding like this one since it's detectable from outside, but you would have far less confidence in banner-based findings on the same host and would miss any vulnerability only visible by inspecting installed packages and patch levels directly",
            "Unauthenticated scans are always more accurate because they see the system the way a real attacker does",
            "Authenticated and unauthenticated scans differ only in scan speed, never in what they can detect",
          ],
          answer: 1,
          explanation:
            "As covered in Reading 4, a reflected XSS like this one is externally reachable and detectable without credentials, so an unauthenticated scan could plausibly still find it. But unauthenticated scanning generally produces less reliable findings for anything based on version-banner inference (exactly the false-positive pattern in this room's analyst-choice task), and it structurally cannot see internal package/patch state the way an authenticated scan can — so relying on unauthenticated-only scanning would leave real gaps in coverage beyond just this one finding.",
          xp: 25,
        },
      ],
    },

    // ── Matching: terms ────────────────────────────────────────────────
    {
      type: "matching" as const,
      id: "vm-m1",
      heading: "Match the Vulnerability Management Term to Its Definition",
      instructions: "Match each term to what it actually measures or does.",
      pairs: [
        { id: "cve", left: "CVE", right: "Unique identifier for one specific, publicly disclosed vulnerability instance" },
        { id: "cwe", left: "CWE", right: "Category describing the general TYPE of software weakness, shared across many unrelated CVEs" },
        { id: "cvss", left: "CVSS", right: "Numeric 0.0-10.0 score describing how severe a specific CVE is, based on exploitability and impact" },
        { id: "epss", left: "EPSS", right: "Daily-updated probability (0-100%) that a specific CVE will be exploited in the wild within 30 days" },
        { id: "kev", left: "CISA KEV Catalog", right: "List of vulnerabilities with CONFIRMED evidence of active in-the-wild exploitation" },
        { id: "authscan", left: "Authenticated scan", right: "Scanner logs into the host with valid credentials and inspects installed packages/patches directly" },
        { id: "compcontrol", left: "Compensating control", right: "A mitigation (WAF rule, network segmentation) applied when a vulnerability can't be patched immediately" },
        { id: "acceptrisk", left: "Accepted risk", right: "A formally documented, time-bound decision by a risk owner not to remediate a known vulnerability" },
      ],
      explanation:
        "Notice how few of these terms actually measure severity: only CVSS does. CVE and CWE are identifiers/categories, EPSS and KEV measure likelihood and confirmation of exploitation rather than technical impact, and the scanning/remediation terms describe process, not score. Confusing what each term measures is exactly how a backlog gets prioritized in the wrong order.",
      xp: 40,
    },

    // ── Reading 5: false positive confirmation, remediation options, boundary ──
    {
      type: "reading" as const,
      id: "vm-r5",
      heading: "Confirming a False Positive, Choosing a Remediation Path, and Where the SOC's Job Ends",
      content:
        "Not every scan finding is real, and treating all of them as equally trustworthy either burns analyst time chasing ghosts or — worse — trains the team to dismiss findings reflexively, which is how a real one eventually gets missed.\n\n" +
        "**Confirming a scanner false positive.** The most common pattern, especially from unauthenticated scans, is version-banner inference gone wrong: a vulnerability plugin sees 'Apache/2.4.6' in a server header and flags every CVE ever associated with that version number, without knowing that the operating system vendor (commonly Red Hat/CentOS, which is notorious for this) backports individual security fixes into its own point releases without ever changing the upstream version string the banner reports. The way to actually confirm this, rather than guess, is to check the system directly: for a Linux package, the package manager's changelog (rpm -q --changelog, or the equivalent apt changelog) will show exactly which CVE fixes have been backported into the installed build, regardless of what the banner says. For anything you can't verify this way, run — or request — an authenticated scan of the same host; if the authenticated result doesn't reproduce the finding, that's strong evidence the unauthenticated result was a banner-based false positive, not proof by itself, so document what you checked.\n\n" +
        "**Three remediation paths, not one.** A **patch** is the only path that permanently closes the vulnerability — it should be the default goal. A **compensating control** mitigates the risk without touching the vulnerable component itself: a WAF rule blocking the specific exploit pattern, network segmentation isolating the asset, or disabling the specific vulnerable feature — used when a patch isn't available yet, or would break something business-critical that needs more testing time. This is a genuine, legitimate remediation path, not a way to avoid the real fix indefinitely — it should come with a plan and a date to apply the actual patch. **Accepted risk** is the third path: a formal, documented decision by a risk owner (not the analyst who found it) that the organization will not remediate this specific finding, because the cost or disruption of fixing it outweighs the actual risk (a legacy system with no sensitive data, scheduled for decommission in six weeks, for example). A real risk acceptance has an owner's name on it, an expiration/review date, and a written justification — 'we'll get to it eventually' is not risk acceptance, it's an unmanaged finding sitting in the backlog.\n\n" +
        "**Where the SOC's job ends and IT's begins.** The SOC identifies, prioritizes, verifies, and communicates urgency — confirming whether a finding is real, combining CVSS/EPSS/KEV/asset context into an actual priority order, and escalating loudly when a KEV-listed or actively-exploited finding is stalling past its deadline. Deploying the actual patch — testing it in staging, scheduling the maintenance window, pushing it to production, and confirming the fix with a rescan — is IT/infrastructure's job, not the SOC's. A SOC analyst who tries to personally patch a production server is operating outside their lane and skipping change management that exists for good reasons; a SOC analyst who lets a KEV-listed finding sit unescalated for weeks because 'patching isn't my job' has also failed. The SOC's job is tracking the SLA and making noise when it slips, not doing the deployment.",
      codeExample:
        "THREE REMEDIATION PATHS\n" +
        "=======================================================\n" +
        "PATCH                Permanently closes the vulnerability.\n" +
        "                     Default goal for every real finding.\n" +
        "\n" +
        "COMPENSATING CONTROL  Mitigates without touching the flaw\n" +
        "                      itself (WAF rule, segmentation,\n" +
        "                      disable the feature). Needs a plan\n" +
        "                      + date for the real patch to follow.\n" +
        "\n" +
        "ACCEPTED RISK         Formal, owner-signed, time-bound\n" +
        "                      decision NOT to remediate. Needs a\n" +
        "                      name, a justification, a review date.\n" +
        "=======================================================\n" +
        "SOC's JOB              vs        IT/INFRA's JOB\n" +
        "=======================================================\n" +
        "Identify + verify                Test the patch in staging\n" +
        "Prioritize (CVSS+EPSS+KEV+asset)  Schedule the maintenance\n" +
        "Confirm false positives             window\n" +
        "Escalate when SLA slips           Deploy to production\n" +
        "Track KEV due dates               Confirm fix via rescan\n" +
        "=======================================================",
    },

    // ── Analyst Choice: confirmed false positive ──────────────────────────
    {
      type: "analyst_choice" as const,
      id: "vm-ac1",
      heading: "Verdict: An Eight-Year-Old CVE on a Patched System",
      scenario:
        "An unauthenticated scan of api-gw02 (an internal API gateway, not internet-facing) flagged CVE-2017-15715 with a CVSS of 8.6 (High), based on the Apache version string in the server's response banner. The platform team was asked to check.",
      event: vulnFpEvent,
      correct_verdict: "false_positive",
      explanation:
        "tenable.plugin_output shows the banner reads 'Apache/2.4.6 (Red Hat Enterprise Linux)' — exactly the version pattern this plugin is designed to flag. But it_verify_result is confirmed: the platform team checked the installed package's changelog directly (rpm -q --changelog) and found the CVE-2017-15715 fix already present in the installed build, because Red Hat backports security fixes into its own point releases without bumping the version string the banner reports. tenable.scan_type is 'unauthenticated', which is exactly the scan method most prone to this specific false-positive pattern, as covered in Reading 4 and Reading 5. tenable.epss_score (0.02) and tenable.cisa_known_exploited (false) also don't support urgency even before the false-positive check.",
      fp_trap:
        "CVSS 8.6 (High) on a well-known, named CVE is exactly the kind of finding that gets escalated on sight — and it's tempting to open a critical ticket immediately. But the plugin_output field is a version-banner guess, not direct inspection, and this exact pattern (RHEL/CentOS backporting fixes without changing the version string) is one of the single most common sources of false positives from unauthenticated web scans. The lesson from Reading 5 is to verify before escalating: check the package changelog directly, or request an authenticated rescan, rather than opening a ticket purely off a CVSS number and a banner string.",
      xp: 30,
    },

    // ── Ordering: vulnerability management lifecycle ──────────────────────
    {
      type: "ordering" as const,
      id: "vm-o1",
      heading: "Order the Vulnerability Management Lifecycle",
      instructions: "Arrange these stages in the order a mature vulnerability management program actually runs them.",
      items: [
        { id: "discover", text: "Discover — scan assets, preferring authenticated scanning wherever credentials can be safely managed" },
        { id: "prioritize", text: "Prioritize — combine CVSS, EPSS, CISA KEV status, and asset criticality/exposure into an actual priority order" },
        { id: "remediate", text: "Remediate — patch, apply a compensating control, or formally accept the risk with an owner and a review date" },
        { id: "verify", text: "Verify — rescan to confirm the vulnerability is actually gone, not just assumed fixed" },
        { id: "report", text: "Report — track SLA compliance against KEV due dates and internal targets, escalate anything stalled" },
      ],
      correct_order: ["discover", "prioritize", "remediate", "verify", "report"],
      explanation:
        "Skipping straight from discovery to remediation without prioritization is how teams burn their patch capacity on low-urgency findings while a KEV-listed internet-facing issue waits its turn. Skipping verification is how a 'fixed' vulnerability turns out to still be exploitable weeks later because the patch failed to apply or a config rolled back. Reporting isn't an afterthought — it's what surfaces the finding that's been stuck in remediation past its deadline before an attacker finds it first.",
      xp: 35,
    },

    // ── Question 3: SOC vs IT boundary ────────────────────────────────────
    {
      type: "question" as const,
      id: "vm-q3",
      question:
        "A CISA KEV-listed vulnerability on an internet-facing server has been sitting unpatched for three weeks, past its due date, and the SOC analyst who found it has no way to deploy the patch themselves. What is the correct action?",
      options: [
        "Log into the server directly and apply the patch personally, since the SOC already understands the vulnerability best",
        "Escalate clearly and repeatedly to the team that owns patch deployment, citing the KEV due date and the ongoing exposure, and keep tracking it until it's actually remediated and verified — this is squarely the SOC's job even though applying the patch is not",
        "Close the finding as accepted risk on the SOC's own authority, since three weeks is long enough to wait",
        "Do nothing further — once a finding is reported once, responsibility passes entirely to IT and the SOC's job is done",
      ],
      answer: 1,
      explanation:
        "As covered in Reading 5, the SOC's job includes identifying, prioritizing, verifying, and escalating — not personally deploying patches into production outside of change management, which risks breaking something the SOC doesn't have full context on. Accepting risk requires a risk owner's sign-off, not a unilateral SOC decision, especially for something already confirmed to be actively exploited via KEV. And 'reported once, done' abandons exactly the tracking and escalation responsibility that's the SOC's actual job here — a stalled KEV-listed internet-facing exposure is precisely the kind of finding that needs to keep getting louder until it's fixed.",
      xp: 25,
    },

    // ── Flag ──────────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "vm-f1",
      prompt:
        "Look at the Log Analysis finding on portal-web03. What is the exact value of the tenable.epss_score field in the raw log? Enter it exactly as shown (a decimal, not a percentage).",
      answer: "0.94",
      hint: "Look inside the raw block of the vulnScanEvent for the field named tenable.epss_score.",
      xp: 25,
    },
  ],
};

// ===========================================================================
// ROOM 2 — Memory & Disk Forensics for Analysts
// ===========================================================================

const mftTimestompEvent: TelemetryEvent = {
  id: "evt-mdf-la1-001",
  ts: "2026-04-19T02:11:07.000Z",
  source: "edr",
  vendor: "Velociraptor",
  event_type: "file_modify",
  severity: "high",
  hostname: "HOST-ACCT-19",
  description:
    "The Windows.NTFS.MFT artifact was collected from HOST-ACCT-19 as part of a live forensic sweep, focused on a suspicious executable found in the user's Downloads folder. Two different sets of NTFS timestamps are recorded for the same MFT entry — compare them carefully.",
  raw: {
    "velociraptor.artifact": "Windows.NTFS.MFT",
    "mft.entry_number": 88214,
    "mft.filename": "quarterly_report.exe",
    "mft.full_path": "C:\\Users\\r.okafor\\Downloads\\quarterly_report.exe",
    "mft.file_size": 412672,
    "mft.si_created": "2019-03-11T08:00:00.000Z",
    "mft.si_modified": "2019-03-11T08:00:00.000Z",
    "mft.si_accessed": "2019-03-11T08:00:00.000Z",
    "mft.si_mft_modified": "2019-03-11T08:00:00.000Z",
    "mft.fn_created": "2026-04-19T02:04:51.000Z",
    "mft.fn_modified": "2026-04-19T02:04:51.000Z",
    "mft.fn_accessed": "2026-04-19T02:04:51.000Z",
    "mft.fn_mft_modified": "2026-04-19T02:04:51.000Z",
    "mft.usnjrnl_last_reason": "FILE_CREATE|DATA_EXTEND",
    "mft.usnjrnl_last_timestamp": "2026-04-19T02:04:51.000Z",
  },
};

const shadowCopyEvent: TelemetryEvent = {
  id: "evt-mdf-ac1-001",
  ts: "2026-04-20T04:00:12.000Z",
  source: "edr",
  vendor: "CrowdStrike Falcon",
  event_type: "process_create",
  severity: "medium",
  hostname: "FS-BACKUP-02",
  it_verify_result: "confirmed",
  it_verify_message:
    "Change ticket CHG-40217 authorizes the nightly Veeam retention job on FS-BACKUP-02, which prunes shadow copies older than the configured 14-day window every night at 04:00. VeeamAgentSvc.exe is the documented parent process for this scheduled task.",
  process: {
    name: "vssadmin.exe",
    pid: 6120,
    path: "C:\\Windows\\System32\\vssadmin.exe",
    parent_name: "VeeamAgentSvc.exe",
    parent_pid: 2244,
    cmdline: "vssadmin.exe delete shadows /for=D: /oldest",
    user: "SOLVIX\\svc-veeam-backup",
    integrity: "system",
  },
  description:
    "vssadmin.exe deleted the oldest shadow copy on volume D: of FS-BACKUP-02 as part of the nightly retention job, launched from the Veeam agent service.",
  raw: {
    "event.code": "1",
    "winlog.provider_name": "Microsoft-Windows-Sysmon",
    "winlog.event_data.Image": "C:\\Windows\\System32\\vssadmin.exe",
    "winlog.event_data.ParentImage": "C:\\Program Files\\Veeam\\Endpoint Backup\\VeeamAgentSvc.exe",
    "winlog.event_data.CommandLine": "vssadmin.exe delete shadows /for=D: /oldest",
    "winlog.event_data.User": "SOLVIX\\svc-veeam-backup",
    "winlog.event_data.IntegrityLevel": "System",
    "winlog.event_id": 1,
  },
};

const memoryDiskForensicsRoom = {
  id: "memory-disk-forensics",
  title: "Memory & Disk Forensics for Analysts",
  description:
    "Go beyond the basics into live acquisition that doesn't contaminate the scene, what a memory image yields that a disk image structurally cannot, MACB timeline building past the $MFT, the anti-forensics techniques attackers actually use — log clearing, timestomping, shadow-copy deletion — and what each one still leaves behind, and the real tension between preserving evidence and shutting down an active intrusion.",
  difficulty: "advanced" as const,
  category: "Forensics",
  estimatedMinutes: 65,
  xp: 315,
  icon: "🔬",
  prerequisites: ["digital-forensics-basics"],
  tasks: [
    // ── Reading 1: Live acquisition without contaminating the scene ────────
    {
      type: "reading" as const,
      id: "mdf-r1",
      heading: "Live Acquisition Without Contaminating the Scene",
      content:
        "You already know the order of volatility from the basics room: memory before disk, disk before backups. This reading is about the part that order alone doesn't cover — HOW you touch a live, running, possibly-compromised machine without your own investigation becoming part of the evidence you're trying to read.\n\n" +
        "**Every tool you run changes the system.** Launching any executable on a live host creates a process, allocates memory, may write a Prefetch entry, and touches the filesystem's access timestamps — on the very machine you're trying to examine cleanly. The goal isn't zero footprint (that's impossible on a live system), it's minimum, known, documented footprint: use trusted, statically-linked binaries run from read-only or write-protected external media (a USB drive you control, not something copied onto the target's own disk), so you aren't relying on any DLL or library already present on a machine that might itself be compromised, and so you leave the smallest possible trace of your own presence in the artifact you'll later be reading for attacker activity.\n\n" +
        "**Order of operations on a live host, in practice:** capture the most volatile, least-footprint information first — active network connections and the process list, both of which can be queried quickly with minimal impact — before you kick off a full memory dump, which takes several minutes and is the highest-impact step you'll take (allocating disk space for the dump file, generating significant read activity across RAM). Only after memory is safely captured and hashed do you move to disk imaging, which is comparatively low-risk to the live system's state because you're imaging, not booting into, the disk.\n\n" +
        "**Never install anything.** Never run a setup wizard, never write your tool to the target's own C: drive, and never use a GUI tool that requires installation — every one of those actions writes registry keys, creates Prefetch entries, and potentially overwrites evidence you haven't collected yet. The forensic tools built for this (DumpIt, winpmem, Velociraptor's agent-based collection) are specifically designed to run standalone from removable media with no installation step.\n\n" +
        "**Document as you go, not after.** Write down the exact command you ran, the exact timestamp, and the exact tool version before you run it — not from memory afterward. If your actions ever need to be defended (in a legal proceeding, or just to a skeptical colleague reviewing your findings), a contemporaneous log of exactly what you touched and when is what makes your findings credible instead of disputable. This is the practical extension of chain of custody: it isn't just about the evidence you collected, it's about being able to account for every action you personally took on the live system before you collected it.",
      codeExample:
        "LIVE ACQUISITION -- ORDER OF OPERATIONS\n" +
        "=======================================================\n" +
        "1. Network connections    -- fastest, lowest footprint\n" +
        "2. Process list           -- fast, low footprint\n" +
        "3. Full memory dump       -- highest footprint, do once\n" +
        "                             volatile snapshots are safe\n" +
        "4. Disk imaging           -- lower risk to LIVE state,\n" +
        "                             comparatively slow\n" +
        "=======================================================\n" +
        "RULES FOR TOUCHING A LIVE, POSSIBLY-COMPROMISED HOST\n" +
        "=======================================================\n" +
        "- Run trusted, statically-linked binaries only\n" +
        "- Run FROM external/write-protected media, never copy\n" +
        "  your tool onto the target's own disk\n" +
        "- Never install anything -- no setup wizard, no registry\n" +
        "  writes, no Prefetch entry for your own tooling\n" +
        "- Document command + timestamp + tool version BEFORE\n" +
        "  you run it, not reconstructed afterward\n" +
        "=======================================================",
    },

    // ── Reading 2: What memory yields that disk cannot ─────────────────────
    {
      type: "reading" as const,
      id: "mdf-r2",
      heading: "What a Memory Image Yields That Disk Structurally Cannot",
      content:
        "The basics room told you memory is the most valuable evidence source and gave you the headline reasons. Here is exactly why disk can never substitute for it, artifact by artifact.\n\n" +
        "**Injected code with no file behind it.** Legitimate code is always loaded from a file — a .exe or .dll you can point to on disk, hash, and check against a reputation source. Process injection (writing executable shellcode directly into another process's memory space, or reflectively loading a DLL that never touches disk) produces a memory region that is marked executable but has no backing file at all. Disk imaging cannot find this, because there is nothing on disk to find — the code exists purely as bytes the CPU is willing to execute, sitting inside a legitimate process like explorer.exe or svchost.exe. Volatility's malfind plugin (from the basics room) exists specifically because this class of evidence has no disk equivalent whatsoever.\n\n" +
        "**Decrypted strings from an otherwise-encrypted payload.** Modern malware routinely ships encrypted or obfuscated on disk specifically to defeat static analysis and signature-based detection — but it has to decrypt itself in memory to actually run. The C2 (command-and-control) domain, the RC4 or AES key, the operator's hardcoded credentials, the exact configuration the malware is using right now: all of it exists in plaintext in RAM for as long as the process runs, and none of it is recoverable from the encrypted file sitting on disk without already having the key.\n\n" +
        "**Live network connections that closed before any log rotated.** A short-lived C2 beacon connection, open for thirty seconds before closing, may never appear in a firewall or proxy log with a retention window measured in hours rather than seconds, or may appear only as an aggregate flow record stripped of the process context that matters. windows.netscan against a memory image shows you the connection AND which process owned it, captured at the instant of acquisition — a live snapshot no disk-based log source can retroactively produce once the connection has closed and rotated out of a log.\n\n" +
        "**Unlinked, hidden processes.** Windows tracks running processes through a doubly-linked list the OS walks to enumerate them for Task Manager or tasklist. A rootkit using DKOM (Direct Kernel Object Manipulation) can unlink a malicious process's entry from that list — the process keeps running, keeps consuming CPU and holding its handles, but tools that rely on walking the list (including the live host's own Task Manager) simply never see it. Memory forensics tools like Volatility don't rely on the OS's own bookkeeping to find processes; a plugin like windows.psscan searches memory directly for the data structure signature every process object has (the EPROCESS pool tag on Windows), regardless of whether that structure is currently linked into the visible list — which is exactly how DKOM-hidden processes get caught. None of this exists on disk in any form; a hidden process leaves no file artifact by design.\n\n" +
        "**The tradeoff to remember:** memory is a single snapshot — the instant you captured it — while disk persists across reboots and captures history. Neither replaces the other; this is why the order of volatility from the basics room says collect both, in that order, rather than picking one.",
      codeExample:
        "FOUR THINGS ONLY A MEMORY IMAGE CAN GIVE YOU\n" +
        "=======================================================\n" +
        "1. INJECTED CODE\n" +
        "   Executable memory region, NO backing file on disk.\n" +
        "   Disk imaging finds nothing -- there's nothing there.\n" +
        "\n" +
        "2. DECRYPTED STRINGS\n" +
        "   Malware ships encrypted on disk, decrypts to run.\n" +
        "   C2 domains/keys/config exist in plaintext ONLY in RAM.\n" +
        "\n" +
        "3. LIVE NETWORK CONNECTIONS\n" +
        "   Short C2 beacons can close before any log rotation\n" +
        "   window captures them. Memory = a live snapshot.\n" +
        "\n" +
        "4. UNLINKED / HIDDEN PROCESSES (DKOM rootkits)\n" +
        "   Unlinked from the OS's own process list -- invisible\n" +
        "   to Task Manager AND to the live host itself.\n" +
        "   Memory tools scan for the raw structure signature,\n" +
        "   not the (tampered) list -- and leave no disk artifact.\n" +
        "=======================================================",
    },

    // ── Question 1 ─────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "mdf-q1",
      question:
        "An incident responder images the disk of a suspected-compromised server but skips memory acquisition entirely, reasoning that 'the malware writes its files to disk, so disk imaging should find everything.' Six months later, the case stalls because the C2 domain and decryption key the malware used were never recovered. What went wrong?",
      options: [
        "Nothing went wrong — disk imaging is always sufficient for any well-resourced investigation",
        "The malware very likely shipped its C2 configuration encrypted on disk specifically to defeat static analysis, and only decrypted it in memory at runtime — evidence that exists only in RAM for as long as the process runs and cannot be recovered from the encrypted file after the fact",
        "The disk image must have been corrupted; a proper disk image always contains decrypted copies of any malware configuration",
        "C2 domains are always stored in the Windows registry, not in memory, so imaging the registry hive would have solved this",
      ],
      answer: 1,
      explanation:
        "This is exactly the decrypted-strings gap from Reading 2: malware commonly ships encrypted specifically to defeat the kind of static, disk-based analysis this responder relied on exclusively, and decrypts itself only in memory at runtime. Without a memory capture taken while the process was still running, that plaintext configuration is gone — the encrypted file on disk doesn't help without the key, which also only ever existed in memory. This isn't a disk-image-corruption problem or something the registry would incidentally contain; it's a fundamental gap that only live memory acquisition closes.",
      xp: 30,
    },

    // ── Reading 3: Hashing, chain of custody for live acquisition ──────────
    {
      type: "reading" as const,
      id: "mdf-r3",
      heading: "Hashing and Chain of Custody, Applied to Live Acquisition",
      content:
        "The basics room covered why you hash evidence and what a chain of custody document records. Here is how that applies specifically to the messier reality of live, on-the-fly collection — where you don't have the luxury of a powered-off drive sitting still while you work.\n\n" +
        "**Hash immediately, and hash the right thing.** The moment a memory dump or disk image finishes writing, compute its SHA256 hash before doing anything else with the file — before copying it, before opening it in an analysis tool, before even renaming it. That hash is your baseline: any future comparison against it proves whether the file has been altered since that exact moment. For a memory dump specifically, understand that the hash covers the dump FILE, not 'the state of the running system' — the live system kept changing the instant after your dump finished, which is exactly why the dump's timestamp matters as much as its hash: it's a snapshot of one moment, and the hash proves that snapshot hasn't been tampered with since.\n\n" +
        "**Write blockers on live triage — the compromise you're actually making.** A hardware write blocker guarantees zero writes reach a drive during imaging, which is straightforward when a machine is already powered off. On a LIVE system you're actively triaging, you cannot use a hardware write blocker at all — the OS is running and writing to its own disk constantly regardless of what you do (temp files, log rotation, page file activity). What you're doing instead is minimizing and documenting your own additional writes (Reading 1) while accepting that the OS's own background writes are outside your control. This is a real, acknowledged limitation of live triage compared to dead-box (powered-off) disk imaging, and it's worth stating plainly in your notes rather than implying a live triage image has the same integrity guarantee as an offline one.\n\n" +
        "**What the chain of custody form needs for live acquisition specifically:** the exact tool and version used, the exact command line, the analyst's name, the start and end timestamp of the collection, the SHA256 of the resulting file, and — this is the part live acquisition adds beyond the basics room's version — an explicit note of what else was running or being touched on the system during collection (was antivirus actively scanning? was a backup job mid-run? did you have to kill a process that was locking a file you needed?). None of that is optional detail; it's exactly the kind of thing a defense attorney or a skeptical peer reviewer asks about, and having it documented at the time is the difference between a credible answer and a shrug.\n\n" +
        "**Storage after collection.** Evidence files get copied to write-once or access-controlled storage immediately, with access logged — not left sitting on a shared drive with default permissions. Every subsequent person who opens the file for analysis gets logged as an access event in the chain of custody, same as the original collection.",
      codeExample:
        "CHAIN OF CUSTODY -- LIVE ACQUISITION FIELDS\n" +
        "=======================================================\n" +
        "Standard fields (from the basics room):\n" +
        "  - Evidence item, analyst name, collection method\n" +
        "  - SHA256 hash, subsequent access log\n" +
        "\n" +
        "ADDED for LIVE (on a running system) acquisition:\n" +
        "  - Exact tool + version + exact command line used\n" +
        "  - Start / end timestamp of the collection itself\n" +
        "  - What else was active on the system during collection\n" +
        "    (AV scan running? backup job mid-write? a process you\n" +
        "    had to kill to unlock a needed file?)\n" +
        "  - Explicit note: NO hardware write blocker was possible\n" +
        "    -- the OS was writing to its own disk throughout\n" +
        "=======================================================",
    },

    // ── Question 2 (applied) ──────────────────────────────────────────────
    {
      type: "question" as const,
      id: "mdf-q2",
      question:
        "An analyst images the disk of a live, running production server during an active incident (it cannot be powered off) and records the SHA256 of the resulting image file. A colleague later challenges the finding, arguing 'you can't trust this image, the system was writing to its own disk the whole time you imaged it.' Which response is accurate?",
      options: [
        "The colleague is wrong — a live system never writes to its own disk during active use",
        "The colleague is raising a real, acknowledged limitation of live imaging: a hardware write blocker isn't possible on a running system, so the OS's own background writes happened throughout collection — this should already be documented in the chain of custody, and the hash proves the resulting IMAGE FILE hasn't been altered since it finished, not that the source disk was static during collection",
        "The hash is meaningless in this scenario and should be discarded",
        "This proves the analyst made a critical error and the entire investigation should be restarted with a fresh disk",
      ],
      answer: 1,
      explanation:
        "As covered in Reading 3, this is a genuine and well-understood limitation of live triage, not an error — a hardware write blocker simply cannot be applied to a disk the operating system is actively using. The correct response is to acknowledge it, point to where it was documented at collection time, and be precise about what the hash actually proves: integrity of the resulting file from the moment imaging finished, not that the source disk held perfectly still during the process. Discarding the hash or restarting the entire investigation overreacts to a limitation that live-acquisition methodology already accounts for and documents.",
      xp: 30,
    },

    // ── Reading 4: Timeline building beyond $MFT ────────────────────────────
    {
      type: "reading" as const,
      id: "mdf-r4",
      heading: "Timeline Building Beyond the $MFT: $UsnJrnl, $LogFile, and Cross-Source Correlation",
      content:
        "The basics room introduced MACB timestamps ($STANDARD_INFORMATION's Modified, Accessed, Changed, and Birth/created times) from the $MFT and Plaso's supertimeline concept. There are two more NTFS artifacts worth knowing by name, because they answer a question the $MFT alone cannot: not just 'what does this file's current timestamp say,' but 'what actually happened to it, in what order, and can I trust the timestamp I'm looking at.'\n\n" +
        "**$UsnJrnl (the USN Change Journal)** is NTFS's own append-only log of every change made to every file and directory on the volume — file created, data extended, file renamed, security descriptor changed, and more, each entry tagged with a reason code and a timestamp. Critically, it's a running LOG of events, not a snapshot of current state the way the $MFT's timestamps are — which means it can show you a SEQUENCE of things that happened to a file (created, then written to, then renamed) even when the $MFT itself only shows you the file's current, final state. This is often the artifact that catches a renamed or briefly-existing file that's already been deleted, because the $UsnJrnl entry can persist for a period after the file itself and its $MFT entry are gone.\n\n" +
        "**$LogFile** is NTFS's transaction journal, used for filesystem crash recovery — it records low-level metadata operations (not file contents) as they happen, in transactional detail even more granular than $UsnJrnl. It's less commonly needed than $UsnJrnl for day-to-day investigation but becomes valuable specifically when you need to verify or challenge a $UsnJrnl or $MFT timestamp you don't fully trust, because $LogFile operations are harder for an attacker to selectively edit than a single MACB timestamp field.\n\n" +
        "**Why cross-referencing matters: two clocks that should agree.** Every file on NTFS actually has two separate sets of timestamps stored in two separate MFT attributes: $STANDARD_INFORMATION (the one every normal tool — Explorer, PowerShell's Get-Item, dir /T — shows you, and the one that's trivial to modify with a timestomping tool) and $FILE_NAME (stored inside the same MFT record but updated far less often, normally only when the file is created, renamed, or moved — and critically, NOT touched by the common consumer-grade timestomping tools that only target $STANDARD_INFORMATION). In an untouched file, both attributes' Created/Modified timestamps line up closely, because both get set together at file creation and neither one is being deliberately manipulated. When they disagree significantly — $STANDARD_INFORMATION claiming a file has existed since 2019, while $FILE_NAME shows it was actually created minutes ago — that gap is one of the most reliable single indicators of timestomping available, and it's exactly what you'll examine in this room's log analysis exercise.\n\n" +
        "**Building a defensible timeline means correlating, not trusting one source.** A supertimeline built purely from $STANDARD_INFORMATION timestamps inherits every timestomp an attacker applied without any way to flag it. Pulling $FILE_NAME, $UsnJrnl, and — where the finding matters enough to justify the extra work — $LogFile into the same timeline, and looking for exactly this kind of disagreement between sources, is what turns a plausible narrative into a defensible one.",
      codeExample:
        "TWO TIMESTAMP SETS INSIDE ONE MFT RECORD\n" +
        "=======================================================\n" +
        "$STANDARD_INFORMATION  ($SI)\n" +
        "  - What every normal tool shows you (Explorer, dir /T)\n" +
        "  - Trivially modified by common timestomping tools\n" +
        "\n" +
        "$FILE_NAME              ($FN)\n" +
        "  - Stored in the same MFT record, updated far less often\n" +
        "  - NOT touched by common $SI-only timestomping tools\n" +
        "  - Requires direct, sophisticated MFT editing to forge\n" +
        "=======================================================\n" +
        "THE TELL: $SI and $FN should roughly agree on an\n" +
        "untouched file. A large, unexplained gap between them\n" +
        "is one of the strongest single indicators of timestomping.\n" +
        "=======================================================\n" +
        "OTHER TIMELINE SOURCES BEYOND $MFT\n" +
        "=======================================================\n" +
        "$UsnJrnl   Append-only LOG of changes (create/write/\n" +
        "           rename/etc, each with a reason code) --\n" +
        "           shows SEQUENCE, can outlive the file itself\n" +
        "$LogFile   NTFS's own crash-recovery transaction journal;\n" +
        "           harder to selectively edit than one timestamp\n" +
        "=======================================================",
    },

    // ── Log Analysis: SI vs FN timestomping mismatch ────────────────────────
    {
      type: "log_analysis" as const,
      id: "mdf-la1",
      heading: "One File, Two Timestamp Stories",
      context:
        "During a live forensic sweep of HOST-ACCT-19, an executable was found in a user's Downloads folder that the user says they've 'never seen before.' Velociraptor pulled the raw $STANDARD_INFORMATION and $FILE_NAME timestamps for its MFT record, along with the most recent $UsnJrnl entry for the same file. Review the finding and decide what actually happened.",
      event: mftTimestompEvent,
      questions: [
        {
          question:
            "mft.si_created reads 2019-03-11, while mft.fn_created reads 2026-04-19 — a difference of over seven years. Given what you learned about which attribute common timestomping tools actually modify, what does this gap most likely indicate?",
          options: [
            "A normal file copy operation, which always ages the $STANDARD_INFORMATION timestamp by exactly this much",
            "The file's $STANDARD_INFORMATION timestamps were deliberately set to an old date using a timestomping tool, while the harder-to-forge $FILE_NAME attribute — which the tool didn't touch — still reflects the file's real creation time in 2026",
            "The system clock on HOST-ACCT-19 must have been wrong in 2019, unrelated to this specific file",
            "This is expected behavior any time a file is downloaded from the internet",
          ],
          answer: 1,
          explanation:
            "As covered in Reading 4, this is exactly the classic timestomping signature: common tools modify $STANDARD_INFORMATION (what every normal tool displays) to make a file appear old and unremarkable, but leave $FILE_NAME untouched because forging it requires direct MFT editing most tools don't attempt. A seven-year gap between the two, on a file the user says they've never seen, in the Downloads folder, is not something a normal copy operation, a clock error, or ordinary download behavior would produce.",
          xp: 35,
        },
        {
          question:
            "mft.usnjrnl_last_reason shows 'FILE_CREATE|DATA_EXTEND' with mft.usnjrnl_last_timestamp matching the $FILE_NAME time (2026-04-19), not the $STANDARD_INFORMATION time (2019). Why does this specific piece of corroborating evidence matter to the investigation?",
          options: [
            "It doesn't add anything beyond what the $FILE_NAME timestamp already showed",
            "The $UsnJrnl is an independent, append-only log of what actually happened to the file, not just a static timestamp field — its FILE_CREATE entry landing on the same 2026 date as $FILE_NAME, rather than the fabricated 2019 date, is a second, structurally different source confirming the real creation time, which strengthens the finding beyond a single attribute comparison",
            "It proves the file was created by a scheduled task rather than a user",
            "FILE_CREATE|DATA_EXTEND is a reason code reserved exclusively for malware installers",
          ],
          answer: 1,
          explanation:
            "As covered in Reading 4, a defensible timeline correlates multiple independent sources rather than trusting one attribute. The $UsnJrnl is a fundamentally different kind of artifact — an append-only change log, not a mutable timestamp field — and its entry agreeing with $FILE_NAME rather than the fabricated $STANDARD_INFORMATION date is exactly the kind of cross-source corroboration that turns 'these two fields disagree' into a well-supported conclusion. The reason code doesn't imply anything about who created the file or that it's malware-specific, and this evidence is meaningfully additive, not redundant.",
          xp: 35,
        },
      ],
    },

    // ── Reading 5: Anti-forensics ────────────────────────────────────────
    {
      type: "reading" as const,
      id: "mdf-r5",
      heading: "Anti-Forensics: What Event 1102, Timestomping, and Shadow-Copy Deletion Still Leave Behind",
      content:
        "Attackers who know they're being investigated — or who simply follow standard post-exploitation playbooks — actively try to destroy or falsify the evidence you're looking for. None of the three most common techniques actually achieves a clean erasure, and knowing exactly what each one still leaves behind is what separates 'the logs are gone, dead end' from a continued investigation.\n\n" +
        "**Event ID 1102 — the Security log was cleared.** Running wevtutil cl Security (or the GUI equivalent, Clear Log) wipes the contents of the Windows Security event log — which sounds like a clean erasure of exactly the evidence an analyst most wants. But the act of clearing the log is itself logged: Windows writes a fresh Event ID 1102 ('The audit log was cleared') as the very first — often only — entry in the newly emptied log, recording the account that did it and the timestamp. An attacker who clears the log to hide their tracks leaves behind unambiguous proof that SOMETHING was hidden, at a precise, known time — which immediately tells an analyst to go looking in every OTHER log source (Sysmon, if configured to a separate channel; EDR telemetry, which is usually not stored on the host at all; network logs; the $UsnJrnl, which is unaffected by clearing a Windows event log) for whatever happened right around that timestamp.\n\n" +
        "**Timestomping — covered at the field level in Reading 4.** The practical anti-forensics summary: it convincingly fools any tool or analyst who only checks $STANDARD_INFORMATION, but leaves $FILE_NAME, $UsnJrnl, and $LogFile largely untouched, because forging all of them consistently requires far more sophisticated, direct MFT manipulation than the common consumer tools attempt. A file's true creation time doesn't disappear — it moves to a place most casual review doesn't look.\n\n" +
        "**Shadow-copy deletion — vssadmin delete shadows, or the PowerShell/WMI equivalent.** Windows' Volume Shadow Copy Service periodically creates point-in-time snapshots of a volume, which ransomware operators specifically target and delete (this is MITRE ATT&CK T1490, Inhibit System Recovery) because those shadow copies are exactly what lets a victim recover files without paying — and they can also contain forensically useful older versions of files an attacker has since modified or deleted. Deleting shadow copies genuinely does destroy that specific recovery/forensic source; unlike the previous two techniques, there usually isn't a hidden backup copy of the shadow copies themselves. But the DELETION ACTION is itself a highly visible artifact: the vssadmin.exe (or PowerShell Get-WmiObject Win32_ShadowCopy | Remove-WmiObject, or wmic shadowcopy delete) process execution is exactly the kind of event Sysmon Event ID 1 or EDR process-creation telemetry captures cleanly, complete with the parent process, the command line, and the executing account — which is precisely why this technique, meant to erase evidence, instead functions as one of the highest-confidence indicators of an active ransomware precursor once you know to look for the process itself rather than what it deleted.\n\n" +
        "**The pattern across all three:** anti-forensics techniques target one specific evidence source and, in the process of attacking it, almost always create a new artifact in a DIFFERENT source. The investigative discipline is to never treat 'the obvious place is empty' as 'there's no evidence' — it's a prompt to go find where the erasure attempt itself got logged.",
      codeExample:
        "ANTI-FORENSICS: WHAT'S DESTROYED vs WHAT'S LEFT BEHIND\n" +
        "=======================================================\n" +
        "EVENT 1102 -- Security log cleared\n" +
        "  Destroys: prior Security log contents\n" +
        "  Leaves:   Event 1102 itself (who, when) as the new\n" +
        "            first entry -- proof something was hidden,\n" +
        "            at a known time. Go check every OTHER log.\n" +
        "\n" +
        "TIMESTOMPING -- $SI timestamps forged\n" +
        "  Destroys: the story a casual $SI-only check tells\n" +
        "  Leaves:   $FILE_NAME (rarely touched), $UsnJrnl,\n" +
        "            $LogFile -- all largely intact\n" +
        "\n" +
        "SHADOW COPY DELETION -- vssadmin/WMI/PowerShell\n" +
        "  Destroys: the shadow copies themselves (usually for\n" +
        "            real -- no hidden backup of a backup)\n" +
        "  Leaves:   the DELETION PROCESS ITSELF as a Sysmon/EDR\n" +
        "            process-creation event -- command line,\n" +
        "            parent process, account, all captured\n" +
        "=======================================================",
    },

    // ── Matching: anti-forensics technique -> residual evidence ────────────
    {
      type: "matching" as const,
      id: "mdf-m1",
      heading: "Match the Anti-Forensics Technique to What It Still Leaves Behind",
      instructions: "Match each anti-forensics technique to the residual evidence it creates or leaves untouched.",
      pairs: [
        { id: "clearlog", left: "Security log cleared (wevtutil cl Security)", right: "A fresh Event ID 1102 recording who cleared it and when — proof the erasure happened, at a known timestamp" },
        { id: "timestomp", left: "Timestomping $STANDARD_INFORMATION", right: "The $FILE_NAME attribute and $UsnJrnl entries, rarely touched by common tools, still reflect the real timeline" },
        { id: "shadowdel", left: "Shadow copy deletion (vssadmin/WMI)", right: "The deletion process itself — command line, parent process, executing account — captured by Sysmon/EDR process telemetry" },
        { id: "diskwipe", left: "Secure-deleting a specific file", right: "The file's now-orphaned MFT entry and $UsnJrnl history may persist even after the file's data is unrecoverable" },
      ],
      explanation:
        "The pattern across every anti-forensics technique: attacking one evidence source almost always creates a new artifact in a different source. Investigative discipline means treating an empty obvious location as a prompt to look elsewhere, not as a dead end.",
      xp: 40,
    },

    // ── Question 3 (applied) ─────────────────────────────────────────────
    {
      type: "question" as const,
      id: "mdf-q3",
      question:
        "An analyst opens the Security event log on a suspected-compromised host and finds it nearly empty, with a single Event ID 1102 as the newest entry. A colleague says 'the logs are gone, there's nothing more we can do here.' What is the correct next step?",
      options: [
        "Agree — an Event 1102 with a cleared log means the investigation has hit a dead end",
        "Note the exact timestamp on the 1102 event and pivot to every OTHER available log source around that same window — Sysmon (if logged to a separate channel), EDR telemetry, network/firewall logs, and NTFS artifacts like $UsnJrnl — since the log-clearing action itself pinpoints exactly when to focus the search elsewhere",
        "Restore the Security log from the most recent Volume Shadow Copy, which always contains an unmodified backup",
        "Conclude the finding must be a false positive, since a real attacker would never leave a 1102 event behind",
      ],
      answer: 1,
      explanation:
        "As covered in Reading 5, Event 1102 is not a dead end — it's a precise timestamp telling you exactly when to focus your search in every OTHER log source that the attacker didn't (or couldn't) also clear. EDR telemetry in particular is usually stored off-host entirely, unaffected by clearing the local Windows event log. Assuming a shadow copy always contains an untouched backup ignores that shadow-copy deletion is a real, separate anti-forensics technique attackers frequently pair with log clearing. And 1102 appearing is not evidence of a false positive — it's the expected, well-documented artifact of a genuine log-clearing action.",
      xp: 30,
    },

    // ── Analyst Choice: shadow copy deletion FP ────────────────────────────
    {
      type: "analyst_choice" as const,
      id: "mdf-ac1",
      heading: "Verdict: A Shadow Copy Deletion on a Backup Server",
      scenario:
        "A detection rule fired on vssadmin.exe deleting a shadow copy on FS-BACKUP-02 — the exact process execution pattern this room just taught you to treat as a strong ransomware precursor (T1490). Review the event below before deciding.",
      event: shadowCopyEvent,
      correct_verdict: "false_positive",
      explanation:
        "Every technical detail here matches the T1490 pattern from Reading 5 — vssadmin.exe deleting a shadow copy is exactly the process-creation signature that indicator is built on, which is why context, not the process name alone, determines the verdict. it_verify_result is confirmed: change ticket CHG-40217 documents this as the nightly Veeam retention job, the parent process is VeeamAgentSvc.exe (the documented backup agent, not explorer.exe or a script host), the executing account is the dedicated svc-veeam-backup service account rather than an interactive user, the command line targets a specific volume with /oldest (a retention operation, not /all which is what ransomware operators typically use to wipe every restore point at once), and the timing (04:00, a routine maintenance window) matches the scheduled job.",
      fp_trap:
        "Reading 5 taught you that shadow-copy deletion is one of the highest-confidence indicators of active ransomware — and it's tempting to escalate the process name and command on sight. But the same mechanism (vssadmin delete shadows) is also exactly how legitimate backup retention policies prune old restore points on a schedule. The differentiators that separate this case from a genuine T1490 finding are the verified change ticket, the known backup-agent parent process, the dedicated service account (not an interactive or unusual account), and the scoped command (/for=D: /oldest, a single volume's oldest copy — not /all, which wipes everything at once and is what ransomware precursors typically use). Escalating purely on 'vssadmin deleted a shadow copy' without checking any of that context burns analyst time on routine backup hygiene.",
      xp: 35,
    },

    // ── Reading 6: The tension — preserving evidence vs containing intrusion ──
    {
      type: "reading" as const,
      id: "mdf-r6",
      heading: "The Real Tension: Preserving Evidence vs Containing an Active Intrusion",
      content:
        "Every forensic best practice in this room assumes you have the luxury of careful, methodical, order-of-volatility-respecting collection. Real incidents frequently don't offer that luxury, and the honest answer to 'should I preserve evidence or contain the threat right now' is: it depends, and pretending it's always one or the other is how good analysts freeze up at exactly the wrong moment.\n\n" +
        "**Why the tension is real, not manufactured.** Containment actions — isolating a host from the network, killing a malicious process, disabling a compromised account — are frequently exactly the actions that destroy volatile evidence. Powering off a machine (the fastest, most complete way to stop an active ransomware encryption process) instantly and irreversibly destroys everything in RAM: the injected code, the decrypted strings, the live connections, all of it, gone the moment power cuts. Network-isolating a host (pulling the network cable, or the modern equivalent of an EDR network-containment action) is far gentler — it stops the bleeding without touching memory — but it can still change what a live investigation would otherwise observe, like an active C2 beacon that simply stops trying to connect once isolated, denying you the chance to watch where it was trying to go next.\n\n" +
        "**The deciding factors, roughly in priority order:** \n\n" +
        "First, is data actively being destroyed or exfiltrated right now? Active ransomware encryption in progress, or a large ongoing exfiltration transfer, generally justifies immediate containment even at real evidentiary cost — the damage from waiting is concrete, immediate, and often irreversible, while the evidentiary cost, though real, is a cost to the investigation rather than to the business's actual survival. Second, is this a single, understood, contained incident, or does the scope remain genuinely unclear? If you don't yet know whether other hosts are affected, an overly hasty single-host containment can tip off an attacker who's watching, causing them to accelerate or pivot elsewhere before you've captured what you need across the wider environment. Third, what does your organization's incident response plan and legal/regulatory obligation actually require? Some industries and some specific incident types (particularly anything likely to become a legal matter, a regulatory breach notification, or law-enforcement involvement) carry real requirements around evidence preservation that should be decided in advance, not improvised mid-incident by whichever analyst is on shift.\n\n" +
        "**The practical middle path, most of the time:** network isolation (not power-off) plus a rapid, minimum-footprint memory capture BEFORE isolation completes, wherever that sequence is achievable in the time available. This captures the highest-value volatile evidence while still stopping active damage within minutes rather than hours. It is not always achievable — a host actively and rapidly encrypting files across a shared drive may simply not afford you those few extra minutes — and knowing that going in, rather than discovering it mid-incident, is what this reading is actually about.\n\n" +
        "**The decision does not have to be made alone, and shouldn't be.** This is exactly the kind of call that benefits from a pre-agreed escalation path — a decision an analyst can make instantly for a single low-impact host based on a documented playbook, versus one that gets escalated to an incident commander in real time when the stakes or the scope are larger. Organizations that never think through this tension in advance are the ones where an analyst either freezes for ten minutes trying to decide, or acts recklessly in either direction — and both outcomes are avoidable with a plan made before the incident, not during it.",
      codeExample:
        "PRESERVE EVIDENCE vs CONTAIN THE INTRUSION\n" +
        "=======================================================\n" +
        "DECIDING FACTORS, ROUGHLY IN PRIORITY ORDER\n" +
        "1. Is data being destroyed/exfiltrated RIGHT NOW?\n" +
        "   -> concrete, irreversible damage usually wins\n" +
        "2. Is the scope of the incident actually understood yet?\n" +
        "   -> premature single-host action can tip off a wider\n" +
        "      attacker before you've captured what you need\n" +
        "3. What does your IR plan / legal-regulatory duty require?\n" +
        "   -> decide this BEFORE an incident, not during one\n" +
        "=======================================================\n" +
        "CONTAINMENT ACTIONS, BY EVIDENTIARY COST\n" +
        "=======================================================\n" +
        "Power off             Fastest, most complete stop.\n" +
        "                      DESTROYS ALL of RAM instantly.\n" +
        "\n" +
        "Network isolation      Stops the bleeding, memory\n" +
        "(EDR contain/cable)    survives -- BUT changes what a\n" +
        "                       live C2 connection would show you\n" +
        "\n" +
        "PRACTICAL MIDDLE PATH (most of the time, if time allows):\n" +
        "  Network isolation + rapid minimum-footprint memory\n" +
        "  capture BEFORE isolation fully completes\n" +
        "=======================================================",
    },

    // ── Ordering: decision sequence during an active intrusion ─────────────
    {
      type: "ordering" as const,
      id: "mdf-o1",
      heading: "Order the Response When Active Damage Is Detected Mid-Investigation",
      instructions: "You are mid-forensic-triage on a host when you observe active file encryption beginning. Arrange the correct sequence of actions.",
      items: [
        { id: "assess", text: "Confirm what's actively happening (active encryption in progress, not a stale alert) and check whether scope beyond this host is already known" },
        { id: "quickcapture", text: "If time allows within minutes, trigger the fastest available volatile-evidence capture (network connections, process list, and a memory dump if it can start immediately)" },
        { id: "isolate", text: "Network-isolate the host (EDR containment or physical disconnection) rather than powering it off, to stop the damage while preserving what memory capture already started" },
        { id: "escalate", text: "Escalate to the incident commander / follow the pre-agreed playbook for wider scope, since a single host's containment may not address the full incident" },
        { id: "continueforensics", text: "Once contained, continue full forensic collection (disk imaging, full timeline) on the now-isolated, powered-on host" },
      ],
      correct_order: ["assess", "quickcapture", "isolate", "escalate", "continueforensics"],
      explanation:
        "The order matters: assessing first prevents an overreaction to a stale or misunderstood alert; a rapid volatile-capture attempt, if time genuinely allows, captures the highest-value evidence before it's gone; isolating (not powering off) stops active damage while preserving what was captured and keeps the host available for full imaging afterward; escalating ensures a single-host decision doesn't quietly become the entire organization's incident response; and full forensic collection continues afterward on a host that is now both contained and still forensically available, rather than a smoking, powered-off box that took the evidence down with it.",
      xp: 35,
    },

    // ── Flag ──────────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "mdf-f1",
      prompt:
        "Look at the Log Analysis finding on HOST-ACCT-19. What is the exact value of the mft.fn_created field (the real creation timestamp, not the timestomped one)? Enter it exactly as shown.",
      answer: "2026-04-19T02:04:51.000Z",
      hint: "Look in the raw block for mft.fn_created — the $FILE_NAME attribute's creation time, which the timestomping tool did not touch.",
      xp: 45,
    },
  ],
};


// The agent writing this batch was cut off mid-file by an API error after two
// rooms. Both are complete and valid; the export it never reached is added here
// so the finished work is usable. The two it did not get to —
// email-collection-exfiltration and mfa-attacks-session-hijacking — are still
// outstanding and are tracked as the remaining coverage gap.
export const roomsBatch19 = [vulnerabilityManagementRoom, memoryDiskForensicsRoom];
