/**
 * "Did the analyst name the attack?" for the incident-report graders: generic words earn
 * a little, a category more, a specific technique the most, plus credit for matching the
 * attack's own name or one of the techniques it really used. Shared by the free-text
 * grader and the timeline report so both read a report the same way.
 */
const GENERIC_WORDS  = /incident|attack|threat|breach|suspicious|intrusion|compromise|unauthorized|anomal/i;
const CATEGORY_WORDS = /phishing|malware|ransomware|spray|credential|lateral|exfil|c2|beacon|brute.?force|mfa|injection|privilege|escalat|dump|harvest|backdoor|persist|trojan|rootkit|botnet/i;
const SPECIFIC_WORDS = /password.?spray|mfa.?fatigue|credential.?dump|lsass|kerberos|as.?rep.?roast|mimikatz|impacket|responder|ntlm.?relay|golden.?ticket|dcsync|pass.?the.?hash|process.?inject|dll.?inject|drive.?by|business.?email.?compromise|supply.?chain|pod.?escape|oauth.?consent|\bapt\s?\d{1,3}\b/i;   // "APT29", never the "apt" inside "laptop" / "capture" (QA-DASH-1)

export interface AttackIdentification {
  /** 0-40 */
  attackScore: number;
  /** Named a specific attack that does not match the real one. */
  wrongType: boolean;
  matchesTitle: boolean;
  hasMitre: boolean;
}

export function scoreAttackIdentification(text: string, attackTitle: string | undefined, attackMitreTechniques: string[]): AttackIdentification {
  const t = text.trim().toLowerCase();
  const titleKeywords = attackTitle
    ? attackTitle.toLowerCase().replace(/[→\-–]/g, " ").split(/\s+/).filter(w => w.length > 4)
    : [];
  const matchesTitle = titleKeywords.length > 0 && titleKeywords.some(kw => t.includes(kw));

  // QA-DASH-1: MITRE credit only for a technique ID the attack really used (or its
  // parent / sub-technique). The bare word "MITRE" used to add points AND cancel the
  // wrong-attack penalty below.
  const realTech = attackMitreTechniques.map(x => x.toUpperCase());
  const citedTech = [...text.toUpperCase().matchAll(/\bT1\d{3}(?:\.\d{3})?\b/g)].map(m => m[0]);
  const hasMitre = citedTech.some(c => realTech.some(r => r === c || r.split(".")[0] === c.split(".")[0]));

  let attackScore = 0;
  if (SPECIFIC_WORDS.test(text))       attackScore = 30;
  else if (CATEGORY_WORDS.test(text))  attackScore = 20;
  else if (GENERIC_WORDS.test(text))   attackScore = 10;
  if (matchesTitle) attackScore = Math.min(40, attackScore + 5);
  if (hasMitre)     attackScore = Math.min(40, attackScore + 5);
  // Named a specific attack but it does NOT match the real story → likely wrong type
  const wrongType = attackScore >= 20 && titleKeywords.length > 0 && !matchesTitle && !hasMitre;
  if (wrongType) attackScore = Math.min(attackScore, 20);
  return { attackScore, wrongType, matchesTitle, hasMitre };
}
