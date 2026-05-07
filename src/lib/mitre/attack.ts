/**
 * Curated MITRE ATT&CK Enterprise data — the techniques most commonly seen
 * by SOC analysts. This is intentionally a working subset (not the full ~600
 * techniques) but is faithful to MITRE naming and IDs as of v15.
 */

export type MitreTactic = {
  id: string;        // TA0001
  name: string;
  short: string;     // for compact UI badges
  description: string;
};

export type MitreTechnique = {
  id: string;        // T1059, T1059.001
  name: string;
  tactic: string;    // tactic id (TA000x)
  tactics?: string[]; // many techniques span multiple tactics
  description: string;
  platforms: ("Windows" | "macOS" | "Linux" | "Cloud" | "SaaS" | "Identity" | "Network")[];
  data_sources: string[];
  detection_hint?: string;
};

export const TACTICS: MitreTactic[] = [
  { id: "TA0043", name: "Reconnaissance",        short: "Recon",       description: "Gathering information about the target." },
  { id: "TA0042", name: "Resource Development",  short: "ResDev",      description: "Establishing resources for operations." },
  { id: "TA0001", name: "Initial Access",        short: "Initial",     description: "Adversary entering the environment." },
  { id: "TA0002", name: "Execution",             short: "Exec",        description: "Running malicious code." },
  { id: "TA0003", name: "Persistence",           short: "Persist",     description: "Maintaining foothold across reboots." },
  { id: "TA0004", name: "Privilege Escalation",  short: "PrivEsc",     description: "Gaining higher-level permissions." },
  { id: "TA0005", name: "Defense Evasion",       short: "Evasion",     description: "Avoiding detection." },
  { id: "TA0006", name: "Credential Access",     short: "CredAcc",     description: "Stealing account names and passwords." },
  { id: "TA0007", name: "Discovery",             short: "Discover",    description: "Mapping the environment." },
  { id: "TA0008", name: "Lateral Movement",      short: "LatMove",     description: "Moving through the environment." },
  { id: "TA0009", name: "Collection",            short: "Collect",     description: "Gathering data of interest." },
  { id: "TA0011", name: "Command and Control",   short: "C2",          description: "Communicating with compromised systems." },
  { id: "TA0010", name: "Exfiltration",          short: "Exfil",       description: "Stealing data." },
  { id: "TA0040", name: "Impact",                short: "Impact",      description: "Manipulating, interrupting or destroying data." },
];

export const TECHNIQUES: MitreTechnique[] = [
  // Initial Access
  { id: "T1566.001", name: "Spearphishing Attachment", tactic: "TA0001",
    description: "Adversaries send an email with a malicious attachment to gain access.",
    platforms: ["Windows","macOS","Linux"],
    data_sources: ["Email Gateway","EDR","Network"],
    detection_hint: "Look for child processes of OUTLOOK.EXE writing executables to %TEMP% or AppData." },
  { id: "T1566.002", name: "Spearphishing Link", tactic: "TA0001",
    description: "Adversaries send phishing emails with a malicious link.",
    platforms: ["Windows","macOS","Linux","SaaS"],
    data_sources: ["Email Gateway","DNS","Web Proxy"] },
  { id: "T1190", name: "Exploit Public-Facing Application", tactic: "TA0001",
    description: "Use of a software weakness in an internet-facing system.",
    platforms: ["Windows","Linux","Cloud","Network"],
    data_sources: ["WAF","Network","App Logs"] },
  { id: "T1078", name: "Valid Accounts", tactic: "TA0001",
    tactics: ["TA0001","TA0003","TA0004","TA0005"],
    description: "Adversaries use valid credentials to access systems.",
    platforms: ["Windows","macOS","Linux","Cloud","SaaS","Identity"],
    data_sources: ["Identity Provider","AD","Cloud Audit"] },

  // Execution
  { id: "T1059.001", name: "PowerShell", tactic: "TA0002",
    description: "Adversaries use PowerShell to execute commands and scripts.",
    platforms: ["Windows"],
    data_sources: ["EDR","Sysmon","Script Block Logging"],
    detection_hint: "EncodedCommand, -ExecutionPolicy Bypass, IEX(New-Object Net.WebClient)." },
  { id: "T1059.003", name: "Windows Command Shell", tactic: "TA0002",
    description: "cmd.exe used for execution.", platforms: ["Windows"],
    data_sources: ["EDR","Sysmon"] },
  { id: "T1059.005", name: "Visual Basic", tactic: "TA0002",
    description: "VBA macros in Office documents.", platforms: ["Windows"],
    data_sources: ["EDR","Email","Office Telemetry"] },
  { id: "T1204.002", name: "User Execution: Malicious File", tactic: "TA0002",
    description: "User opens a malicious file.", platforms: ["Windows","macOS","Linux"],
    data_sources: ["EDR","Email"] },
  { id: "T1053.005", name: "Scheduled Task", tactic: "TA0002",
    tactics: ["TA0002","TA0003","TA0004"],
    description: "Use of schtasks for execution and persistence.", platforms: ["Windows"],
    data_sources: ["EDR","Sysmon","Event Log 4698"] },

  // Persistence
  { id: "T1547.001", name: "Registry Run Keys / Startup Folder", tactic: "TA0003",
    description: "Run keys in HKCU/HKLM Software\\Microsoft\\Windows\\CurrentVersion\\Run.",
    platforms: ["Windows"],
    data_sources: ["Registry","EDR"] },
  { id: "T1543.003", name: "Windows Service", tactic: "TA0003",
    tactics: ["TA0003","TA0004"],
    description: "Creates or modifies a Windows service to run code.", platforms: ["Windows"],
    data_sources: ["EDR","Service Control Manager"] },

  // Privilege Escalation / Credential Access
  { id: "T1003.001", name: "LSASS Memory", tactic: "TA0006",
    description: "Dump credentials from LSASS process memory (mimikatz, procdump).",
    platforms: ["Windows"],
    data_sources: ["EDR","Sysmon Event 10"],
    detection_hint: "ProcessAccess to lsass.exe with GrantedAccess 0x1410 / 0x1010." },
  { id: "T1110.003", name: "Password Spraying", tactic: "TA0006",
    description: "Trying a few passwords against many accounts to evade lockouts.",
    platforms: ["Cloud","SaaS","Identity","Windows"],
    data_sources: ["Identity Provider","AD","Cloud Audit"] },
  { id: "T1555", name: "Credentials from Password Stores", tactic: "TA0006",
    description: "Browsers, vaults, keychain.", platforms: ["Windows","macOS","Linux"],
    data_sources: ["EDR"] },

  // Defense Evasion
  { id: "T1218.011", name: "Signed Binary Proxy: Rundll32", tactic: "TA0005",
    description: "Use rundll32.exe to execute attacker DLLs.", platforms: ["Windows"],
    data_sources: ["EDR","Sysmon"] },
  { id: "T1027", name: "Obfuscated Files or Information", tactic: "TA0005",
    description: "Encoded/encrypted payloads.", platforms: ["Windows","macOS","Linux"],
    data_sources: ["EDR"] },
  { id: "T1562.001", name: "Disable or Modify Tools", tactic: "TA0005",
    description: "Tampering with EDR/AV.", platforms: ["Windows","macOS","Linux"],
    data_sources: ["EDR","Service Logs"] },

  // Discovery
  { id: "T1087.002", name: "Account Discovery: Domain", tactic: "TA0007",
    description: "net group /domain, AdFind.", platforms: ["Windows"],
    data_sources: ["EDR","AD"] },
  { id: "T1018", name: "Remote System Discovery", tactic: "TA0007",
    description: "ping/nslookup/netscan to map hosts.", platforms: ["Windows","macOS","Linux"],
    data_sources: ["EDR","Network"] },

  // Lateral Movement
  { id: "T1021.001", name: "Remote Services: RDP", tactic: "TA0008",
    description: "Use RDP to move laterally.", platforms: ["Windows"],
    data_sources: ["Auth Logs","Network","EDR"] },
  { id: "T1021.002", name: "SMB / Admin Shares", tactic: "TA0008",
    description: "Access via ADMIN$, C$, IPC$.", platforms: ["Windows"],
    data_sources: ["EDR","SMB Logs"] },
  { id: "T1021.006", name: "Windows Remote Management", tactic: "TA0008",
    description: "WinRM / PSRemoting.", platforms: ["Windows"],
    data_sources: ["EDR","WinRM Logs"] },

  // Collection / C2 / Exfil
  { id: "T1005", name: "Data from Local System", tactic: "TA0009",
    description: "Searching and copying files of interest.", platforms: ["Windows","macOS","Linux"],
    data_sources: ["EDR","File"] },
  { id: "T1071.001", name: "Application Layer Protocol: Web", tactic: "TA0011",
    description: "HTTPS C2 over web.", platforms: ["Windows","macOS","Linux","Cloud"],
    data_sources: ["Web Proxy","DNS","Network"] },
  { id: "T1071.004", name: "DNS Tunneling", tactic: "TA0011",
    description: "Encoded data in DNS queries/responses.", platforms: ["Windows","macOS","Linux"],
    data_sources: ["DNS"],
    detection_hint: "Long subdomains, high entropy, unusual TLD, NXDOMAIN spikes." },
  { id: "T1572", name: "Protocol Tunneling", tactic: "TA0011",
    description: "ssh/icmp/dns tunnels.", platforms: ["Windows","Linux","macOS"],
    data_sources: ["Network"] },
  { id: "T1041", name: "Exfiltration Over C2 Channel", tactic: "TA0010",
    description: "Steal data over the same C2 channel.", platforms: ["Windows","Linux","macOS","Cloud"],
    data_sources: ["Network","EDR"] },
  { id: "T1567.002", name: "Exfil to Cloud Storage", tactic: "TA0010",
    description: "Upload to S3/GDrive/Mega/Dropbox.", platforms: ["Windows","Linux","macOS","Cloud"],
    data_sources: ["Web Proxy","DLP"] },

  // Impact
  { id: "T1486", name: "Data Encrypted for Impact", tactic: "TA0040",
    description: "Ransomware encryption of files.", platforms: ["Windows","Linux","macOS","Cloud"],
    data_sources: ["EDR","File"] },
  { id: "T1490", name: "Inhibit System Recovery", tactic: "TA0040",
    description: "vssadmin delete shadows, wbadmin delete catalog.", platforms: ["Windows"],
    data_sources: ["EDR","Sysmon"] },
];

export function techniqueById(id: string): MitreTechnique | undefined {
  return TECHNIQUES.find(t => t.id === id);
}

export function tacticById(id: string): MitreTactic | undefined {
  return TACTICS.find(t => t.id === id);
}

export function techniquesForTactic(tacticId: string): MitreTechnique[] {
  return TECHNIQUES.filter(t => t.tactic === tacticId || t.tactics?.includes(tacticId));
}
