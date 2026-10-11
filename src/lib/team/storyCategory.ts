/**
 * Attack categories for the Session Builder's storyline picker, so staff choose from
 * grouped lists ("Phishing & malicious email", "Active Directory attacks", ...) instead of
 * one long alphabetical list. Every story id is mapped explicitly; storyCategory.test.ts
 * fails when a new story is added without a category.
 */
export const STORY_CATEGORIES = [
  { id: "phishing", label: "Phishing & malicious email" },
  { id: "endpoint", label: "Malware & endpoint" },
  { id: "identity", label: "Identity & account takeover" },
  { id: "bec", label: "BEC & OAuth abuse" },
  { id: "ad", label: "Active Directory attacks" },
  { id: "ransomware", label: "Ransomware & extortion" },
  { id: "insider", label: "Insider threat" },
  { id: "cloud", label: "Cloud, DevOps & supply chain" },
  { id: "exploit", label: "Server & edge exploitation" },
  { id: "fraud", label: "Financial fraud" },
  { id: "ai", label: "AI & LLM attacks" },
  { id: "other", label: "Other" },
] as const;

export type StoryCategory = (typeof STORY_CATEGORIES)[number]["id"];

const BY_ID: Record<string, StoryCategory> = {
  "phishing-malware": "phishing", "malicious-macro": "phishing", "phishing": "phishing",
  "gws-phish-attachment": "phishing", "iso-container-smuggling": "phishing",
  "nexacorp-chain-a": "phishing", "globallogis-chain-a": "phishing",

  "usb-malware": "endpoint", "browser-extension": "endpoint", "tech-support-scam": "endpoint",
  "cracked-software": "endpoint", "fake-browser-update": "endpoint", "trojanized-keylogger": "endpoint",
  "seo-poisoned-installer": "endpoint", "clickfix-fake-captcha": "endpoint",
  "scheduled-task-persistence": "endpoint", "lolbins": "endpoint", "dns-tunneling": "endpoint",
  "globallogis-chain-b": "endpoint",

  "impossible-travel": "identity", "impossible-travel-basic": "identity", "mfa-fatigue": "identity",
  "okta-password-burst": "identity", "bruteforce-single": "identity", "helpdesk-mfa-reset": "identity",
  "infostealer-session-theft": "identity", "aitm-token-theft": "identity", "rogue-admin": "identity",
  "rocketstack-chain-a": "identity", "rocketstack-chain-d": "identity", "rocketstack-cred-stuffing": "identity",
  "quantumbank-chain-a": "identity", "quantumbank-chain-b": "identity", "quantumbank-chain-d": "identity",
  "medcore-chain-c": "identity", "medcore-chain-d": "identity",

  "bec": "bec", "oauth": "bec", "oauth-consent": "bec", "rs-oauth-consent-chaining": "bec",
  "nexacorp-chain-b": "bec",

  "dcsync": "ad", "kerberoasting": "ad", "asrep-roasting": "ad", "ntlm-relay": "ad", "nexacorp-chain-d": "ad",

  "ransomware": "ransomware", "esxi-ransomware": "ransomware", "exfil-first-extortion": "ransomware",
  "medcore-chain-a": "ransomware",

  "insider": "insider", "nexacorp-chain-c": "insider", "medcore-chain-b": "insider",
  "globallogis-chain-c": "insider", "quantumbank-chain-c": "insider",

  "aws-key-leak-s3-exfil": "cloud", "k8s-pod-escape": "cloud", "supply-chain": "cloud",
  "rs-cicd-pipeline-poisoning": "cloud", "rs-terraform-iac-backdoor": "cloud", "rocketstack-chain-b": "cloud",

  "webshell-rce": "exploit", "edge-vpn-cve-exploit": "exploit", "linux-ssh-persistence": "exploit",
  "globallogis-chain-d": "exploit",

  "qb-swift-wire-fraud": "fraud", "qb-fraud-monitoring-tampering": "fraud", "qb-cyberark-mule-payout": "fraud",
};

export function storyCategory(storyId: string): StoryCategory {
  if (storyId.startsWith("ai-")) return "ai";
  return BY_ID[storyId] ?? "other";
}

/** Groups a picker list by category, in STORY_CATEGORIES order, dropping empty groups. */
export function groupByCategory<T extends { category: StoryCategory }>(items: T[]): { id: StoryCategory; label: string; items: T[] }[] {
  return STORY_CATEGORIES
    .map(c => ({ id: c.id as StoryCategory, label: c.label as string, items: items.filter(i => i.category === c.id) }))
    .filter(g => g.items.length > 0);
}
