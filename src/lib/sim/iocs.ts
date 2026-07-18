/**
 * Realistic IOC primitives — domains, IPs, hashes, URLs, User-Agents.
 * All values are synthetic but structurally identical to what an analyst sees in production.
 */
import { rng, pick, hashString, intBetween } from "./rng";

// ── Malicious TLDs ─────────────────────────────────────────────────────────────
export const MALICIOUS_TLDS = [
  ".xyz",".top",".click",".support",".cyou",".live",".cf",".ru",".tk",
  ".pw",".monster",".bond",".cfd",".beauty",".lol",".rest",".ws",
];

// ── Suspicious keywords for domain generation ──────────────────────────────────
export const SUSPICIOUS_KEYWORDS = [
  "secure","login","update","verify","drive","msoffice","support","billing","auth",
  "office365","okta-auth","saml-verify","sso-portal","idp-connect","mfa-reset",
  "docusign","sharepoint","webmail","account","helpdesk","it-service","hr-portal",
  "payroll","expense-mgmt","vendor-pay","ach-confirm","wire-transfer",
];

// ── C2 host prefixes ───────────────────────────────────────────────────────────
export const C2_HOSTS = [
  "cdn-static-edge","telemetry-api","metrics-collector","node-relay","sync-worker",
  "update-svc","analytics-track","heartbeat-svc","config-pull","beacon-api",
  "edge-cache","proxy-relay","data-push","status-check","health-monitor",
];

// ── Known good domains (for FP events) ────────────────────────────────────────
export const KNOWN_GOOD_DOMAINS = [
  "microsoft.com","login.microsoftonline.com","office.com","outlook.office.com",
  "graph.microsoft.com","login.windows.net",
  "google.com","accounts.google.com","googleapis.com","gstatic.com",
  "github.com","raw.githubusercontent.com","api.github.com",
  "slack.com","api.slack.com","files.slack.com",
  "okta.com","*.okta.com",
  "aws.amazon.com","s3.amazonaws.com","ec2.amazonaws.com",
  "zoom.us","api.zoom.us",
  "akamaized.net","cloudfront.net","fastly.net",
  "cryotech.io","*.cryotech.io",
  "salesforce.com","*.salesforce.com",
  "jira.atlassian.net","confluence.atlassian.net",
];

// ── Attack source geography (varied, not just APT countries) ──────────────────
export const ATTACK_COUNTRIES = [
  "RU","CN","KP","IR","BY",        // APT state-sponsored
  "UA","RO","BG","RS","MK",        // Eastern Europe cybercriminal
  "NG","GH","CI","SN","KE",        // West/East Africa BEC
  "BR","CO","MX","AR","PE",        // Latin America fraud
  "IN","PK","BD","VN","ID",        // South/Southeast Asia
  "NL","DE","FR","GB","SE",        // Bulletproof hosting (legitimate countries)
  "US","CA","AU","SG","HK",        // Compromised infrastructure
];

// ── Tor / VPN exit IPs ─────────────────────────────────────────────────────────
export const TOR_EXIT_SAMPLE_IPS = [
  "185.220.101.4","199.249.230.66","51.75.64.23","23.129.64.130","192.42.116.176",
  "185.220.100.240","171.25.193.25","62.102.148.68","204.8.156.142","109.70.100.2",
];

// ── Realistic User-Agent strings ──────────────────────────────────────────────
export const BENIGN_USER_AGENTS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Safari/537.36",
];

export const SUSPICIOUS_USER_AGENTS = [
  "python-requests/2.31.0",
  "curl/8.1.2",
  "Go-http-client/1.1",
  "Invoke-WebRequest",
  "powershell/7.4.0",
  "python-urllib3/2.0.7",
  "libwww-perl/6.72",
  "Wget/1.21.4 (linux-gnu)",
  "Java/17.0.8",
  "HTTPie/3.2.2",
  "axios/1.6.0 node/20.11",
  "Scrapy/2.11.0 (+https://scrapy.org)",
];

export const MALWARE_USER_AGENTS = [
  "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)",
  "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)",
  "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.2.3) Gecko/20100401",
];

// ── Malware family names ───────────────────────────────────────────────────────
export const MALWARE_FAMILIES = [
  // Ransomware
  "LockBit 3.0","BlackCat/ALPHV","Cl0p","Royal","Play","Akira","BlackSuit",
  "Medusa","NoEscape","RansomHub","Hunters International","8Base","BianLian",
  // Infostealer
  "Redline Stealer","Vidar","Raccoon v2","StealC","MetaStealer","Lumma Stealer",
  "Aurora Stealer","Titan Stealer","WhiteSnake","RisePro",
  // RAT / Backdoor
  "Cobalt Strike","Brute Ratel","Sliver","Havoc","Metasploit","NimPlant",
  "AsyncRAT","QuasarRAT","NetWire","XWorm","DCRat","SystemBC",
  // Loaders
  "IcedID","QakBot","Emotet","Bumblebee","GootLoader","SocGholish","Pikabot",
  // APT implants
  "Mimikatz","WinPEAS","SharpHound","Rubeus","Kerbrute","CrackMapExec","Impacket",
];

// ── IOC generation helpers ─────────────────────────────────────────────────────
export function makeSha256(seed: string): string {
  const r = rng(hashString(seed));
  let s = "";
  for (let i = 0; i < 64; i++) s += Math.floor(r() * 16).toString(16);
  return s;
}

export function makeMd5(seed: string): string {
  const r = rng(hashString(seed) ^ 0xdeadbeef);
  let s = "";
  for (let i = 0; i < 32; i++) s += Math.floor(r() * 16).toString(16);
  return s;
}

export function makePublicIp(r: () => number): string {
  let a = Math.floor(r() * 223) + 1;
  while ([10, 127, 172, 192, 169].includes(a)) a = Math.floor(r() * 223) + 1;
  return `${a}.${Math.floor(r() * 256)}.${Math.floor(r() * 256)}.${Math.floor(r() * 254) + 1}`;
}

export function makePrivateIp(subnet: "corp" | "servers" | "vpn" | "dmz", r: () => number): string {
  switch (subnet) {
    case "corp":    return `10.20.${intBetween(r,1,50)}.${intBetween(r,1,254)}`;
    case "servers": return `10.30.${intBetween(r,0,9)}.${intBetween(r,1,254)}`;
    case "vpn":     return `10.40.${intBetween(r,0,50)}.${intBetween(r,1,254)}`;
    case "dmz":     return `172.21.${intBetween(r,1,5)}.${intBetween(r,1,254)}`;
  }
}

export function makeMaliciousDomain(seed: number): string {
  const r = rng(seed);
  const kw   = pick(r, SUSPICIOUS_KEYWORDS);
  const noise = Math.floor(r() * 100000).toString(36);
  const tld   = pick(r, MALICIOUS_TLDS);
  return `${kw}-${noise}${tld}`;
}

export function makeC2Domain(seed: number): string {
  const r    = rng(seed);
  const host = pick(r, C2_HOSTS);
  const noise = Math.floor(r() * 1e6).toString(16);
  const tlds = [".com",".net",".io",".app",".cloud",".tech",".dev"];
  return `${host}-${noise}${pick(r, tlds)}`;
}

export function makeDgaDomain(seed: number): string {
  const r = rng(seed);
  const v = "aeiou", c = "bcdfghjklmnpqrstvwxyz";
  const len = 10 + Math.floor(r() * 8);
  let s = "";
  for (let i = 0; i < len; i++) s += (i % 2 ? v : c)[Math.floor(r() * (i % 2 ? v.length : c.length))];
  const tld = pick(r, [".com",".net",".org",".biz"]);
  return `${s}${tld}`;
}

export function makePhishingUrl(seed: number): string {
  const r    = rng(seed);
  const dom  = makeMaliciousDomain(seed);
  const path = pick(r, [
    "/login/o365/auth","/verify/account","/secure/document","/drive/share/preview",
    "/auth/session/refresh","/billing/invoice/view","/mfa/setup","/sso/redirect",
    "/consent/authorize","/reset-password","/profile/update","/onedrive/access",
  ]);
  const id = Math.floor(r() * 1e8).toString(16);
  return `https://${dom}${path}?id=${id}&token=${Math.floor(r() * 1e12).toString(36)}`;
}

export function makePhishingSender(seed: number): string {
  const r = rng(seed);
  return pick(r, [
    `noreply@${makeMaliciousDomain(seed + 1)}`,
    `security-alert@${makeMaliciousDomain(seed + 2)}`,
    `it-helpdesk@${makeMaliciousDomain(seed + 3)}`,
    `accounts@${makeMaliciousDomain(seed + 4)}`,
    `docusign-noreply@${makeMaliciousDomain(seed + 5)}`,
    `microsoft-security@${makeMaliciousDomain(seed + 6)}`,
    `payroll@${makeMaliciousDomain(seed + 7)}`,
    `hr-portal@${makeMaliciousDomain(seed + 8)}`,
  ]);
}

export function makeRegistryPersistenceKey(): string {
  const keys = [
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
    "HKLM\\System\\CurrentControlSet\\Services",
    "HKCU\\Environment\\UserInitMprLogonScript",
    "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
  ];
  return pick(rng(Date.now()), keys);
}

// ── Attack scenario names ──────────────────────────────────────────────────────
export const PHISHING_SUBJECTS = [
  "Re: Wire transfer confirmation - URGENT",
  "Quarterly invoice attached - action required",
  "Your DocuSign envelope: Q3 budget review",
  "[ACTION] Vendor banking details update",
  "Password reset required - Account security alert",
  "Your IT helpdesk ticket #48291 has been updated",
  "Shared document: Q4 Planning - please review",
  "Urgent: HR policy update - acknowledgment required",
  "Benefits enrollment closes Friday - action needed",
  "Security notice: Unusual login to your account",
  "Re: Contract #2026-0481 - signature pending",
  "Your expense report has been approved",
  "Important: Payroll processing delay notification",
  "Meeting invitation: Q4 budget alignment",
  "Legal notice: Compliance document for review",
];
