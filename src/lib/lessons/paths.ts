/**
 * Canonical lesson catalog — shared between the learning path UI and the
 * /api/lessons/[slug] generation endpoint and Admin Panel.
 */

export interface LessonMeta {
  slug: string;          // kebab-cased unique ID within the path
  title: string;
  kind: "lesson" | "lab" | "quiz" | "simulation";
  min: number;
  xp: number;
  difficulty: "beginner" | "intermediate" | "advanced" | "expert";
  topic: string;         // used as context for Claude generation
}

export interface ModuleMeta {
  slug: string;
  title: string;
  lessons: LessonMeta[];
}

export interface PathMeta {
  slug: string;
  title: string;
  blurb: string;
  difficulty: "beginner" | "intermediate" | "advanced" | "expert";
  modules: ModuleMeta[];
}

export function titleToSlug(title: string): string {
  return title
    .toLowerCase()
    .replace(/[^a-z0-9 ]/g, "")
    .trim()
    .replace(/\s+/g, "-");
}

export const LESSON_PATHS: PathMeta[] = [
  // ─── Add learning paths here ──────────────────────────────────────────────
  /*
  {
    slug: "soc-analyst",
    title: "SOC Analyst",
    blurb: "Triage, contain, escalate. The Tier-1 → Tier-2 backbone.",
    difficulty: "beginner",
    modules: [
      {
        slug: "soc-foundations",
        title: "SOC Foundations",
        lessons: [
          { slug: "what-is-a-soc",           title: "What is a SOC?",            kind: "lesson", min: 8,  xp: 50,  difficulty: "beginner",     topic: "SOC structure, purpose, people, processes, and technology" },
          { slug: "tier-model-and-slas",      title: "Tier model & SLAs",         kind: "lesson", min: 10, xp: 50,  difficulty: "beginner",     topic: "L1/L2/L3 analyst tiers, escalation, SLA definitions, MTTD MTTR" },
          { slug: "mental-models-for-triage", title: "Mental models for triage",  kind: "lesson", min: 12, xp: 50,  difficulty: "beginner",     topic: "Decision frameworks for alert triage: false positive vs true positive, risk-based thinking" },
          { slug: "quiz-foundations",         title: "Quiz: SOC Foundations",     kind: "quiz",   min: 5,  xp: 100, difficulty: "beginner",     topic: "Knowledge check on SOC structure, tiers, SLAs, and triage thinking" },
        ],
      },
      {
        slug: "alert-triage",
        title: "Alert Triage",
        lessons: [
          { slug: "reading-edr-alerts",       title: "Reading EDR alerts",        kind: "lesson", min: 12, xp: 75,  difficulty: "beginner",     topic: "CrowdStrike Falcon and Microsoft Defender alert formats, fields, severity levels" },
          { slug: "process-trees-in-depth",   title: "Process trees in depth",    kind: "lab",    min: 18, xp: 150, difficulty: "intermediate", topic: "How to read parent-child process relationships in Windows EDR telemetry, PPID spoofing" },
          { slug: "severity-vs-risk-score",   title: "Severity vs. risk score",   kind: "lesson", min: 8,  xp: 50,  difficulty: "beginner",     topic: "Difference between alert severity, confidence, and risk score in SIEM context" },
          { slug: "containment-basics",       title: "Containment basics",        kind: "lesson", min: 10, xp: 75,  difficulty: "beginner",     topic: "Isolating hosts, disabling accounts, blocking IOCs — analyst-level containment actions" },
        ],
      },
      {
        slug: "mitre-attack",
        title: "MITRE ATT&CK",
        lessons: [
          { slug: "tactics-and-techniques",   title: "Tactics & techniques",      kind: "lesson", min: 10, xp: 75,  difficulty: "beginner",     topic: "MITRE ATT&CK framework: 14 tactics, technique IDs, sub-techniques, and enterprise matrix" },
          { slug: "mapping-alerts-to-attack", title: "Mapping alerts to ATT&CK",  kind: "lab",    min: 20, xp: 150, difficulty: "intermediate", topic: "Practical exercise: mapping EDR/SIEM alerts to MITRE technique IDs with examples" },
          { slug: "coverage-thinking",        title: "Coverage thinking",         kind: "lesson", min: 10, xp: 75,  difficulty: "intermediate", topic: "Detection coverage gaps, ATT&CK heatmaps, prioritizing detection engineering efforts" },
        ],
      },
      {
        slug: "investigation-workflow",
        title: "Investigation",
        lessons: [
          { slug: "building-timelines",       title: "Building timelines",        kind: "lesson", min: 12, xp: 75,  difficulty: "beginner",     topic: "Creating investigation timelines from disparate log sources, time normalization, pivot chains" },
          { slug: "pivoting-on-entities",     title: "Pivoting on entities",      kind: "lab",    min: 22, xp: 200, difficulty: "intermediate", topic: "Entity-based investigation: pivoting from host to user to IP to domain to hash in SIEM" },
          { slug: "verdict-workflows",        title: "Verdict workflows",         kind: "lesson", min: 10, xp: 75,  difficulty: "beginner",     topic: "True positive, false positive, benign, undetermined — how to classify and document verdicts" },
        ],
      },
    ],
  },

  // ─── Threat Hunter (Intermediate) ─────────────────────────────────────────
  {
    slug: "threat-hunter",
    title: "Threat Hunter",
    blurb: "Hypothesize, query, find what your SIEM missed.",
    difficulty: "intermediate",
    modules: [
      {
        slug: "hunt-methodology",
        title: "Hunt Methodology",
        lessons: [
          { slug: "ttp-based-hunting",        title: "TTP-based hunting",         kind: "lesson", min: 12, xp: 75,  difficulty: "intermediate", topic: "Threat hunting using MITRE ATT&CK TTPs as hypothesis drivers, intel-driven hunting" },
          { slug: "hypothesis-framework",     title: "Hypothesis framework",      kind: "lesson", min: 10, xp: 75,  difficulty: "intermediate", topic: "Structured hypothesis creation for threat hunts: data source, TTP, detection logic" },
          { slug: "coverage-gaps",            title: "Coverage gaps",             kind: "lesson", min: 10, xp: 75,  difficulty: "intermediate", topic: "Identifying blind spots in your detection stack, log source coverage, MITRE gap analysis" },
        ],
      },
      {
        slug: "query-languages",
        title: "KQL & SPL",
        lessons: [
          { slug: "kql-joins",                title: "KQL: Joins and lookups",    kind: "lesson", min: 15, xp: 100, difficulty: "intermediate", topic: "KQL join, lookup, and externaldata operators for correlating event tables in Microsoft Sentinel" },
          { slug: "kql-aggregations",         title: "KQL: Aggregations",         kind: "lesson", min: 15, xp: 100, difficulty: "intermediate", topic: "summarize, bin(), arg_max, count, dcountby in KQL for anomaly detection and baselining" },
          { slug: "entity-baselining",        title: "Entity baselining",         kind: "lab",    min: 20, xp: 150, difficulty: "advanced",     topic: "Building user and host behavioral baselines with KQL percentile functions for anomaly detection" },
          { slug: "time-series-analysis",     title: "Time series analysis",      kind: "lesson", min: 15, xp: 100, difficulty: "intermediate", topic: "Time series analysis with KQL: make-series, series_decompose, anomaly detection over sliding windows" },
        ],
      },
      {
        slug: "sigma-and-detection",
        title: "Sigma & Detection",
        lessons: [
          { slug: "sigma-syntax-basics",      title: "Sigma syntax basics",       kind: "lesson", min: 12, xp: 75,  difficulty: "intermediate", topic: "Sigma rule syntax, YAML structure, logsource definitions, detection conditions for hunt queries" },
          { slug: "backend-conversion",       title: "Backend conversion",        kind: "lesson", min: 10, xp: 75,  difficulty: "intermediate", topic: "Converting Sigma rules to SIEM queries: Splunk SPL, KQL, Elastic ESQL using pySigma backends" },
          { slug: "sigma-test-data",          title: "Test data generation",      kind: "lab",    min: 18, xp: 150, difficulty: "intermediate", topic: "Generating synthetic log data to validate Sigma rules, rule testing frameworks, detection coverage gaps" },
        ],
      },
    ],
  },

  // ─── Incident Responder (Advanced) ────────────────────────────────────────
  {
    slug: "incident-responder",
    title: "Incident Responder",
    blurb: "Contain, eradicate, recover. Lead the war room.",
    difficulty: "advanced",
    modules: [
      {
        slug: "ir-lifecycle",
        title: "IR Lifecycle (NIST)",
        lessons: [
          { slug: "ir-phases-overview",       title: "IR phases overview",        kind: "lesson", min: 10, xp: 75,  difficulty: "advanced", topic: "NIST SP 800-61 incident response lifecycle, PICERL model, IR team roles and responsibilities" },
          { slug: "detection-and-analysis",   title: "Detection & Analysis",      kind: "lesson", min: 12, xp: 75,  difficulty: "advanced", topic: "Initial detection from SIEM/EDR alerts, triage, scope assessment, incident classification matrix" },
          { slug: "containment-strategies",   title: "Containment strategies",    kind: "lesson", min: 12, xp: 75,  difficulty: "advanced", topic: "Short-term vs long-term containment, host isolation, network segmentation, account disabling" },
          { slug: "eradication-and-recovery", title: "Eradication & recovery",    kind: "lesson", min: 12, xp: 75,  difficulty: "advanced", topic: "Malware removal, reimaging, credential reset, hardening, monitoring during recovery phase" },
          { slug: "post-incident-review",     title: "Post-incident review",      kind: "lesson", min: 10, xp: 75,  difficulty: "advanced", topic: "Lessons learned process, root cause analysis, blameless postmortems, IR report writing" },
          { slug: "ir-playbooks",             title: "IR playbooks",              kind: "lab",    min: 20, xp: 150, difficulty: "advanced", topic: "Building incident response playbooks, decision trees, SOAR integration hooks, playbook testing" },
        ],
      },
      {
        slug: "forensics-101",
        title: "Forensics 101",
        lessons: [
          { slug: "triage-acquisition",       title: "Triage acquisition",        kind: "lesson", min: 12, xp: 75,  difficulty: "advanced", topic: "Volatile data collection (memory, processes, network), disk imaging, chain of custody documentation" },
          { slug: "timeline-analysis",        title: "Timeline analysis",         kind: "lab",    min: 20, xp: 150, difficulty: "advanced", topic: "Creating super-timelines from multiple log sources, filesystem artifacts, log2timeline/plaso" },
          { slug: "memory-forensics-basics",  title: "Memory forensics basics",   kind: "lesson", min: 12, xp: 75,  difficulty: "advanced", topic: "Volatility framework, process injection detection, code caves, malware artifacts in memory" },
        ],
      },
      {
        slug: "comms-and-reporting",
        title: "Comms & Reporting",
        lessons: [
          { slug: "exec-briefings",           title: "Exec briefings",            kind: "lesson", min: 8,  xp: 50,  difficulty: "advanced", topic: "Communicating incidents to executives and non-technical stakeholders, impact framing, business language" },
          { slug: "customer-notifications",   title: "Customer notifications",    kind: "lesson", min: 8,  xp: 50,  difficulty: "advanced", topic: "Breach notification requirements, GDPR/CCPA timelines, customer communication templates" },
          { slug: "postmortems",              title: "Postmortems",               kind: "lesson", min: 10, xp: 75,  difficulty: "advanced", topic: "Incident postmortem structure, blameless culture, action items, metric improvement tracking" },
        ],
      },
    ],
  },

  // ─── Detection Engineer (Advanced) ────────────────────────────────────────
  {
    slug: "detection-engineer",
    title: "Detection Engineer",
    blurb: "Author, validate, tune, and ship detections.",
    difficulty: "advanced",
    modules: [
      {
        slug: "sigma-mastery",
        title: "Sigma Mastery",
        lessons: [
          { slug: "sigma-selection-patterns", title: "Sigma selection patterns",  kind: "lesson", min: 12, xp: 75,  difficulty: "advanced", topic: "Sigma rule structure, condition logic, selection/filter patterns, field mappings across backends" },
          { slug: "sigma-modifiers",          title: "Sigma modifiers",           kind: "lesson", min: 10, xp: 75,  difficulty: "advanced", topic: "Sigma modifiers: contains, endswith, startswith, re (regex), base64offset, windash, all" },
          { slug: "sigma-coverage-testing",   title: "Coverage testing",          kind: "lab",    min: 20, xp: 150, difficulty: "advanced", topic: "Testing Sigma rules against log samples, sigma2stix, detection coverage mapping to MITRE ATT&CK heatmaps" },
        ],
      },
      {
        slug: "telemetry-sources",
        title: "Telemetry Sources",
        lessons: [
          { slug: "edr-vs-sysmon",            title: "EDR vs Sysmon",             kind: "lesson", min: 12, xp: 75,  difficulty: "advanced", topic: "EDR telemetry vs Sysmon event coverage comparison, gaps, event ID mapping, detection implications" },
          { slug: "o365-ual",                 title: "O365 Unified Audit Log",    kind: "lesson", min: 12, xp: 75,  difficulty: "advanced", topic: "Office 365 UAL fields, key operations for detection: FileDownloaded, MailboxLogin, New-InboxRule, retention" },
          { slug: "cloudtrail-for-detection", title: "CloudTrail for detection",  kind: "lesson", min: 12, xp: 75,  difficulty: "advanced", topic: "AWS CloudTrail event types (management/data/insight), key events: AssumeRole, GetSecretValue, CreateUser" },
        ],
      },
      {
        slug: "detection-tuning",
        title: "Tuning",
        lessons: [
          { slug: "fp-analysis",              title: "FP analysis",               kind: "lesson", min: 10, xp: 75,  difficulty: "advanced", topic: "False positive root cause analysis, baselining legitimate activity, alert fatigue measurement" },
          { slug: "allowlists-and-exceptions",title: "Allowlists & exceptions",   kind: "lab",    min: 18, xp: 150, difficulty: "advanced", topic: "Building Sigma exception lists, SIEM suppression rules, allowlist management lifecycle" },
          { slug: "tiered-severities",        title: "Tiered severities",         kind: "lesson", min: 10, xp: 75,  difficulty: "advanced", topic: "Alert severity classification, risk scoring matrices, priority tiering based on asset criticality and confidence" },
        ],
      },
    ],
  },

  // ─── Purple Team (Expert) ──────────────────────────────────────────────────
  {
    slug: "purple-team",
    title: "Purple Team",
    blurb: "Emulate adversaries. Detect. Improve. Repeat.",
    difficulty: "expert",
    modules: [
      {
        slug: "adversary-emulation",
        title: "Adversary Emulation",
        lessons: [
          { slug: "atomic-red-team",          title: "Atomic Red Team",           kind: "lab",    min: 20, xp: 150, difficulty: "expert", topic: "Atomic Red Team framework, test atomics, execution on Windows/Linux, ATT&CK coverage tracking" },
          { slug: "caldera-platform",         title: "CALDERA platform",          kind: "lab",    min: 22, xp: 200, difficulty: "expert", topic: "MITRE CALDERA adversary emulation, abilities, adversaries, operations, agent deployment" },
          { slug: "custom-ttps",              title: "Custom TTPs",               kind: "lesson", min: 12, xp: 75,  difficulty: "expert", topic: "Writing custom adversary TTPs, ATT&CK navigator layer creation, emulation plan development" },
        ],
      },
      {
        slug: "detection-validation",
        title: "Detection Validation",
        lessons: [
          { slug: "replay-frameworks",        title: "Replay frameworks",         kind: "lab",    min: 20, xp: 200, difficulty: "expert", topic: "Log replay for detection testing, sigma replay, detection-as-code CI/CD pipelines, automated validation" },
          { slug: "kpi-tracking",             title: "KPI tracking",              kind: "lesson", min: 10, xp: 75,  difficulty: "expert", topic: "Detection engineering KPIs: MTTD, coverage %, FP rate, rule count, ATT&CK coverage score" },
        ],
      },
      {
        slug: "reporting-and-roi",
        title: "Reporting & ROI",
        lessons: [
          { slug: "heatmap-delta",            title: "Heatmap delta",             kind: "lesson", min: 10, xp: 75,  difficulty: "expert", topic: "ATT&CK heatmap before/after purple team exercise, coverage delta reporting, DeTT&CT scoring" },
          { slug: "investment-justification", title: "Investment justification",  kind: "lesson", min: 10, xp: 75,  difficulty: "expert", topic: "Business case for detection investment, ROSI calculation, board-level reporting, cost per detection" },
          { slug: "detection-maturity",       title: "Detection maturity",        kind: "lesson", min: 10, xp: 75,  difficulty: "expert", topic: "Detection maturity models (DeTT&CT, SOC CMM), maturity scoring, improvement roadmap development" },
        ],
      },
    ],
  },
  */
];

/** Look up a specific lesson and its context (path, module, lesson). */
export function findLesson(
  pathSlug: string,
  lessonSlug: string,
): { path: PathMeta; module: ModuleMeta; lesson: LessonMeta } | null {
  const path = LESSON_PATHS.find(p => p.slug === pathSlug);
  if (!path) return null;
  for (const mod of path.modules) {
    const lesson = mod.lessons.find(l => l.slug === lessonSlug);
    if (lesson) return { path, module: mod, lesson };
  }
  return null;
}

/** Return the next/prev lesson slugs for navigation. */
export function adjacentLessons(
  pathSlug: string,
  lessonSlug: string,
): { prev: LessonMeta | null; next: LessonMeta | null } {
  const path = LESSON_PATHS.find(p => p.slug === pathSlug);
  if (!path) return { prev: null, next: null };
  const all: LessonMeta[] = path.modules.flatMap(m => m.lessons);
  const idx = all.findIndex(l => l.slug === lessonSlug);
  return {
    prev: idx > 0 ? all[idx - 1] : null,
    next: idx < all.length - 1 ? all[idx + 1] : null,
  };
}
