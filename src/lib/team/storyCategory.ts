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
  { id: "web", label: "Web application attacks" },
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
  "seo-poisoned-installer": "endpoint", "clickfix-fake-captcha": "endpoint", "windows-privesc-token": "endpoint",
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
  "lateral-movement-pth": "ad", "golden-saml": "ad",

  "ransomware": "ransomware", "esxi-ransomware": "ransomware", "exfil-first-extortion": "ransomware",
  "medcore-chain-a": "ransomware",

  "insider": "insider", "nexacorp-chain-c": "insider", "medcore-chain-b": "insider",
  "globallogis-chain-c": "insider", "quantumbank-chain-c": "insider",

  "aws-key-leak-s3-exfil": "cloud", "k8s-pod-escape": "cloud", "supply-chain": "cloud",
  "rs-cicd-pipeline-poisoning": "cloud", "rs-terraform-iac-backdoor": "cloud", "rocketstack-chain-b": "cloud",
  "azure-managed-identity-abuse": "cloud", "gcp-sa-key-theft": "cloud",

  "webshell-rce": "exploit", "edge-vpn-cve-exploit": "exploit", "linux-ssh-persistence": "exploit",
  "globallogis-chain-d": "exploit", "linux-privesc-suid": "exploit",

  "qb-swift-wire-fraud": "fraud", "qb-fraud-monitoring-tampering": "fraud", "qb-cyberark-mule-payout": "fraud",
};

/** The core catalog (src/app/(app)/dashboard/core-stories), by area. */
const CORE: Record<string, StoryCategory> = {
  "core-device-code-phish": "identity", "core-teams-helpdesk-vishing": "identity", "core-qr-code-phish": "identity",
  "core-adcs-esc1": "ad", "core-shadow-credentials": "ad", "core-gpo-scheduled-task": "ad", "core-adidns-wildcard": "ad",
  "core-byovd-edr-killer": "endpoint", "core-dll-sideload": "endpoint", "core-rmm-first-stage": "endpoint", "core-wmi-remote-exec": "ad",
  "core-s3-ssec-extortion": "ransomware", "core-azure-cloud-extortion": "ransomware", "core-ebs-snapshot-share": "cloud",
  "core-ide-extension-theft": "cloud", "core-thread-hijack-smuggling": "phishing",
};

export function storyCategory(storyId: string): StoryCategory {
  if (CORE[storyId]) return CORE[storyId];
  if (storyId.startsWith("ai-")) return "ai";
  if (storyId.startsWith("web-")) return "web";
  return BY_ID[storyId] ?? "other";
}

/**
 * The attack an AI or web story is a variant of, when that is another category: an AI voice-clone
 * help-desk reset is still a help-desk account takeover. The bonus attack never repeats a theme of
 * a planned one (Sdema review K10: a help-desk reset twice in one exercise).
 */
const ALSO: Record<string, StoryCategory> = {
  "ai-helpdesk-voice-reset": "identity", "ai-claude-compliance-key-harvest": "identity", "ai-gemini-drive-sweep": "identity",
  "ai-deepfake-exec-call-payment-fraud": "bec", "ai-browser-agent-prompt-hijack": "bec", "ai-stored-injection-copilot-kb": "bec",
  "ai-svg-invoice-lure": "phishing",
  "ai-chat-harvest-extension": "endpoint", "ai-hub-model-load-workstation": "endpoint",
  "ai-claude-enterprise-departure": "insider", "ai-shadow-chat-upload": "insider",
  "ai-llmjacking-bedrock": "cloud", "ai-aoai-key-capacity-abuse": "cloud", "ai-mcp-tool-poisoning": "cloud", "ai-agentic-intrusion-tempo": "cloud",
  "ai-assistant-commit-key-leak-aws": "cloud", "ai-assistant-commit-key-leak-azure": "cloud", "ai-agent-skill-host-cloud-aws": "cloud",
  "ai-agent-skill-host-cloud-azure": "cloud", "ai-claude-shared-secret": "cloud", "ai-agent-prod-delete-aws": "cloud", "ai-agent-prod-delete-azure": "cloud",
  "ai-training-data-poisoning-aws": "cloud", "ai-agent-rules-file-tamper": "cloud",
  "ai-exposed-inference-endpoint": "exploit", "ai-exposed-vector-store": "exploit", "ai-malicious-model-pickle": "exploit",
  "web-cred-stuffing-portal": "identity", "web-mft-sqli-shell": "exploit", "web-template-injection-wiki": "exploit", "web-viewstate-machinekey": "exploit",
  "web-ssrf-cloud-metadata": "cloud", "web-upload-webshell": "exploit",
};

/** Every category a story belongs to: its own, and the attack it is a variant of. */
export function storyThemes(storyId: string): StoryCategory[] {
  const c = storyCategory(storyId);
  const also = ALSO[storyId];
  return also && also !== c ? [c, also] : [c];
}

/** Groups a picker list by category, in STORY_CATEGORIES order, dropping empty groups. */
export function groupByCategory<T extends { category: StoryCategory }>(items: T[]): { id: StoryCategory; label: string; items: T[] }[] {
  return STORY_CATEGORIES
    .map(c => ({ id: c.id as StoryCategory, label: c.label as string, items: items.filter(i => i.category === c.id) }))
    .filter(g => g.items.length > 0);
}
