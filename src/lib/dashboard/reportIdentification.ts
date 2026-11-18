/**
 * Did the report name the attack that really happened? (Stage B1, dashboard review 2026-11.)
 *
 * The grader used to compare the report only with the story's title words, so a correct report of
 * a narratively titled story ("Catalog Searches That Took Five Seconds", a blind SQL injection) read
 * as the wrong attack, and the check could only cap the score, never stop a pass. A report now
 * matches its story through any of: the title's words, the words of the techniques the attack used
 * (ATT&CK names), or the vocabulary of the story's kind of attack (its category and the attack it is
 * a variant of). The vocabulary is deliberately generous: a correct analyst must never fail on wording.
 */
import { techniqueById } from "@/lib/mitre/attack";

/** How an analyst names each kind of attack (story categories, lib/team/storyCategory.ts). */
export const THEME_WORDS: Record<string, RegExp> = {
  phishing:   /phish|spear.?phish|malicious (attachment|link|e-?mail|document|macro)|macro|lure|attachment|smishing|qr.?code|html smuggl|iso|lnk/i,
  endpoint:   /malware|trojan|keylogger|infostealer|stealer|loader|dropper|rat\b|remote access tool|backdoor|persist|scheduled task|run key|lolbin|living.?off.?the.?land|certutil|regsvr32|rundll32|c2|command.?and.?control|beacon|miner|cryptojack|usb|browser extension|clickfix|fake (browser )?update|drive.?by|dns tunnel/i,
  identity:   /credential|password|spray|brute.?force|stuffing|mfa|multi.?factor|push (bomb|fatigue)|account (takeover|compromise)|impossible travel|token|session (hijack|theft|replay)|cookie|sign.?in|help.?desk|social engineer|aitm|adversary.?in.?the.?middle|vpn|privileged access|vault/i,
  bec:        /business.?email|\bbec\b|inbox rule|mailbox rule|forwarding rule|oauth|consent|app registration|ceo fraud|invoice|payment (redirect|change)|mail (access|read)/i,
  ad:         /kerberos|kerberoast|as.?rep|ntlm|relay|pass.?the.?hash|\bpth\b|dcsync|golden (ticket|saml)|saml|ad fs|lateral|domain controller|active directory|lsass|mimikatz|service account|spn/i,
  ransomware: /ransom|encrypt|extortion|exfil|lockbit|esxi|hypervisor|shadow cop|vssadmin|double extortion|leak site/i,
  insider:    /insider|exfil|usb|removable|personal (e-?mail|account|drive|gmail)|data (theft|leak|loss)|disgruntled|departing|leaver|copied|downloaded|bulk (download|export)|rogue|trading/i,
  cloud:      /cloud|aws|azure|entra|gcp|google cloud|s3|bucket|iam|access key|secret|lambda|function app|kubernetes|k8s|container|pod|ci\/?cd|pipeline|github actions|runner|supply.?chain|terraform|iac|service (principal|account)|federation|role|metadata|cloudtrail|key vault|npm|package|dependency/i,
  exploit:    /exploit|cve|vulnerab|injection|sqli|sql|web.?shell|rce|remote code|ssh|brute|privilege escalation|privesc|suid|root|edge (device|appliance)|vpn|fortios|fortigate|appliance|unpatched/i,
  web:        /inject|sqli|sql|xss|cross.?site|ssrf|log4|jndi|ldap|nosql|crlf|prototype pollution|jwt|command injection|web (app|application|attack)|session (hijack|theft)|cookie|redirect|waf|api key/i,
  ai:         /prompt|jailbreak|llm|language model|model|copilot|chatbot|chat ?gpt|claude|gemini|openai|bedrock|\bai\b|agent|mcp|deepfake|voice clone|shadow ai|rag|knowledge base|data leak|exfil/i,
  fraud:      /fraud|wire|swift|payment|money|mule|structuring|threshold|tamper|transfer|beneficiary/i,
};

/** Words too generic to identify an attack on their own (they appear in many technique names). */
const STOP = new Set(["technique", "service", "services", "valid", "accounts", "account", "remote", "system", "systems",
  "execution", "access", "using", "other", "network", "local", "domain", "cloud", "default", "information", "discovery",
  "protocol", "protocols", "application", "layer", "standard", "command", "scripting", "interpreter", "user", "users"]);

/** The distinctive words of the ATT&CK techniques an attack used ("Phishing: Spearphishing Link" → phishing, spearphishing). */
export function techniqueWords(mitre: string[]): string[] {
  const out = new Set<string>();
  for (const id of mitre) {
    const name = techniqueById(id)?.name ?? techniqueById(id.split(".")[0])?.name;
    if (!name) continue;
    for (const w of name.toLowerCase().split(/[^a-z0-9]+/)) if (w.length > 4 && !STOP.has(w)) out.add(w);
  }
  return [...out];
}

/** True when the report names the attack in any way the story supports. */
export function namesTheStory(summary: string, o: { title?: string; mitre?: string[]; themes?: string[] }): boolean {
  const t = summary.toLowerCase();
  const titleWords = (o.title ?? "").toLowerCase().replace(/[→\-–:]/g, " ").split(/\s+/).filter(w => w.length > 4);
  if (titleWords.some(w => t.includes(w))) return true;
  if (techniqueWords(o.mitre ?? []).some(w => t.includes(w))) return true;
  return (o.themes ?? []).some(th => THEME_WORDS[th]?.test(summary));
}
