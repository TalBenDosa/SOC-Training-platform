/**
 * Tier-3 hunt record checks and starter hypotheses (2026-10-18 review: across four Team Training
 * exercises Tier-3 logged one hunt, and its "hypothesis" was a message to a user; Tier-3 had no
 * work of its own until Tier-2 elevated something, so it worked as an extra Tier-1).
 */

export const HUNT_MIN_CHARS = 15;
const TECHNIQUE = /^T\d{4}(\.\d{3})?$/i;
/** Reads like a message to a person, not a record of what was looked for and found. */
const MESSAGE_TO_PERSON = /^(hi|hello|hey|dear|please|can you|could you|are you|is this|did you)\b|\?\s*$/i;

export interface HuntDraft { hypothesis: string; finding: string; technique: string }

/** Problems that block logging, in the order to fix them (empty = ready). */
export function huntProblems(f: HuntDraft): string[] {
  const out: string[] = [];
  const h = f.hypothesis.trim(), fd = f.finding.trim(), t = f.technique.trim();
  if (h.length < HUNT_MIN_CHARS) out.push("Write the hypothesis: what you suspect, on which hosts / users.");
  else if (MESSAGE_TO_PERSON.test(h)) out.push("The hypothesis reads like a message to a person. State what you suspect; ask people in the chat.");
  if (fd.length < HUNT_MIN_CHARS) out.push("Write the finding: what you checked and what the evidence shows.");
  else if (MESSAGE_TO_PERSON.test(fd)) out.push("The finding reads like a message to a person. Record what the evidence shows.");
  if (t && !TECHNIQUE.test(t)) out.push("Technique must look like T1059 or T1059.001 (or leave it empty).");
  return out;
}

/** Hunts a Tier-3 can start before anything is elevated, by what the organization runs. */
export function starterHypotheses(platforms: string[] = []): { hypothesis: string; technique: string }[] {
  const base = [
    { hypothesis: "Encoded or download-cradle PowerShell on workstations (powershell -enc, IEX, DownloadString)", technique: "T1059.001" },
    { hypothesis: "New services or scheduled tasks created outside a change window (persistence)", technique: "T1053.005" },
    { hypothesis: "Kerberos service-ticket requests with RC4 encryption for service accounts (Kerberoasting)", technique: "T1558.003" },
    { hypothesis: "Outbound connections from servers to rare external addresses or newly seen domains (C2)", technique: "T1071" },
    { hypothesis: "Long or random-looking DNS subdomains to one domain from a single host (DNS tunnelling)", technique: "T1071.004" },
    { hypothesis: "Mailbox forwarding or inbox rules created to external addresses (BEC)", technique: "T1114.003" },
  ];
  const extra: { hypothesis: string; technique: string }[] = [];
  if (platforms.includes("aws")) extra.push({ hypothesis: "IAM keys used from new countries or GetCallerIdentity from unfamiliar hosts", technique: "T1078.004" });
  if (platforms.includes("azure")) extra.push({ hypothesis: "Key Vault secret listing or role assignments by users who never did it before", technique: "T1555.006" });
  if (platforms.includes("linux")) extra.push({ hypothesis: "New cron entries or SSH authorized_keys changes on Linux servers", technique: "T1053.003" });
  if (platforms.includes("k8s")) extra.push({ hypothesis: "Privileged pods or exec into running containers in production namespaces", technique: "T1609" });
  return [...base, ...extra];
}
