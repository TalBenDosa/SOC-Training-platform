/**
 * One skill taxonomy for the whole platform: every room, quiz, lesson and scenario maps to
 * one of these areas, so a student's mastery can be read per area instead of through three
 * category systems that never matched (room "Network Security" vs quiz "Network" vs a lesson
 * module title). Isomorphic and answer-free.
 *
 * Mapping order: two cross-cutting areas that the broad categories hide (phishing / email,
 * Windows / Active Directory) are recognised from the title; everything else comes from the
 * content's own category, then from the title, then a per-kind default. skills.test.ts fails
 * when built-in content lands nowhere or an area is left empty.
 */

export const SKILL_AREAS = [
  { id: "soc_fundamentals", label: "SOC fundamentals" },
  { id: "logs_siem",        label: "Logs and SIEM" },
  { id: "windows_ad",       label: "Windows and AD" },
  { id: "network",          label: "Network" },
  { id: "endpoint",         label: "Endpoint and malware" },
  { id: "email_phishing",   label: "Email and phishing" },
  { id: "identity",         label: "Identity and access" },
  { id: "cloud",            label: "Cloud" },
  { id: "threat_intel",     label: "Threat intel and MITRE" },
  { id: "detection",        label: "Detection and hunting" },
  { id: "ir_forensics",     label: "IR and forensics" },
  { id: "app_data_ot",      label: "Apps, data and OT" },
] as const;

export type SkillArea = (typeof SKILL_AREAS)[number]["id"];
export const SKILL_LABEL: Record<SkillArea, string> = Object.fromEntries(SKILL_AREAS.map(a => [a.id, a.label])) as Record<SkillArea, string>;

/** Category strings used by rooms and quizzes (built-in), mapped explicitly. */
const CATEGORY_AREA: Record<string, SkillArea> = {
  "foundations": "soc_fundamentals", "soc operations": "soc_fundamentals", "soc fundamentals": "soc_fundamentals",
  "log analysis": "logs_siem", "siem": "logs_siem",
  "windows security": "windows_ad", "microsoft security": "identity",
  "network security": "network", "network": "network",
  "endpoint security": "endpoint", "malware analysis": "endpoint", "linux": "endpoint",
  "identity": "identity",
  "cloud security": "cloud",
  "threat intelligence": "threat_intel", "threat framework": "threat_intel",
  "threat detection": "detection",
  "incident response": "ir_forensics", "forensics": "ir_forensics",
  "application security": "app_data_ot", "data security": "app_data_ot", "vulnerability management": "app_data_ot", "ot/ics security": "app_data_ot",
};

/** The two areas recognised from a title, whatever the category says. */
const CROSS_CUTTING: [RegExp, SkillArea][] = [
  [/\b(phish\w*|e-?mail|bec\b|business email|spoof\w*|spf\b|dkim|dmarc|attachment)/i, "email_phishing"],
  [/\b(active directory|kerbero\w*|ntlm|dcsync|golden ticket|lsass|mimikatz|domain controller|group policy|\bgpo\b|pass[- ]the[- ]hash|windows event|event id|sysmon)/i, "windows_ad"],
];

/** Title keywords, used when a category is unknown (e.g. org-authored content). */
const TITLE_AREA: [RegExp, SkillArea][] = [
  ...CROSS_CUTTING,
  [/\b(aws|azure|gcp|google cloud|cloud|s3\b|kubernetes|k8s|container|iam role|cloudtrail)/i, "cloud"],
  [/\b(okta|entra|mfa|oauth|sso\b|identity|account takeover|password spray|credential stuffing|impossible travel)/i, "identity"],
  [/\b(siem|splunk|kql|spl\b|sentinel|log|query)/i, "logs_siem"],
  [/\b(network|dns|firewall|tcp|http|tls|vpn|packet|pcap|port|proxy)/i, "network"],
  [/\b(malware|ransomware|edr|endpoint|process|powershell|persistence|lolbin|macro)/i, "endpoint"],
  [/\b(mitre|att&ck|threat intel|ioc|apt\b|ttp)/i, "threat_intel"],
  [/\b(incident|forensic|triage|containment|report|playbook)/i, "ir_forensics"],
  [/\b(detection|hunt\w*|sigma|yara|rule)/i, "detection"],
  [/\b(sql|web|waf|application|database|dlp|data loss|ot\b|ics\b|scada|vulnerab\w*|cve)/i, "app_data_ot"],
];

const fromTitle = (t: string, rules: [RegExp, SkillArea][]) => rules.find(([re]) => re.test(t))?.[1];

export function areaFor(input: { title?: string | null; category?: string | null }, fallback: SkillArea = "soc_fundamentals"): SkillArea {
  const title = input.title ?? "";
  return fromTitle(title, CROSS_CUTTING)
    ?? (input.category ? CATEGORY_AREA[input.category.trim().toLowerCase()] : undefined)
    ?? fromTitle(title, TITLE_AREA)
    ?? (input.category ? fromTitle(input.category, TITLE_AREA) : undefined)
    ?? fallback;
}

/** A learning-path lesson: by module + lesson title, else the path's own focus. */
const PATH_DEFAULT: Record<string, SkillArea> = {
  "soc-analyst": "soc_fundamentals", "threat-hunter": "detection", "incident-responder": "ir_forensics",
  "detection-engineer": "detection", "purple-team": "threat_intel",
};
export function areaForLesson(pathSlug: string, moduleTitle: string, lessonTitle: string): SkillArea {
  return areaFor({ title: `${lessonTitle} ${moduleTitle}` }, PATH_DEFAULT[pathSlug] ?? "soc_fundamentals");
}
