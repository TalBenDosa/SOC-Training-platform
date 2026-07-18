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
  whatAttackerDoes?: string;
  logIndicators?: string[];
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
    detection_hint: "Look for child processes of OUTLOOK.EXE writing executables to %TEMP% or AppData.",
    whatAttackerDoes: "Sends a targeted email with a malicious Office document (.docx/.xlsx) that contains a macro. When the victim opens it and enables macros, the macro runs PowerShell to download and execute malware.",
    logIndicators: ["OUTLOOK.EXE spawns WINWORD.EXE or EXCEL.EXE", "Office process spawns PowerShell or cmd.exe", "Macro-enabled file (.xlsm, .docm) opened", "Child process created in %TEMP% or AppData\\Roaming"],
  },
  { id: "T1566.002", name: "Spearphishing Link", tactic: "TA0001",
    description: "Adversaries send phishing emails with a malicious link.",
    platforms: ["Windows","macOS","Linux","SaaS"],
    data_sources: ["Email Gateway","DNS","Web Proxy"],
    whatAttackerDoes: "Sends a phishing email with a link to a fake login page or a file hosted on a malicious domain. When the victim clicks and enters credentials, the attacker captures them.",
    logIndicators: ["Email with external link to new/unknown domain", "User visits newly-registered domain shortly after email receipt", "Credential submission to external domain (proxy logs)", "Browser spawns unexpected download"],
  },
  { id: "T1190", name: "Exploit Public-Facing Application", tactic: "TA0001",
    description: "Use of a software weakness in an internet-facing system.",
    platforms: ["Windows","Linux","Cloud","Network"],
    data_sources: ["WAF","Network","App Logs"],
    whatAttackerDoes: "Exploits a vulnerability in an internet-facing application (web server, VPN, firewall) to gain initial access without needing credentials.",
    logIndicators: ["WAF rules triggered for SQL injection or RCE patterns", "Unusual HTTP response codes (500, 404 spikes)", "Web server spawning system processes (cmd.exe, bash)", "Unexpected outbound connection from web server"],
  },
  { id: "T1078", name: "Valid Accounts", tactic: "TA0001",
    tactics: ["TA0001","TA0003","TA0004","TA0005"],
    description: "Adversaries use valid credentials to access systems.",
    platforms: ["Windows","macOS","Linux","Cloud","SaaS","Identity"],
    data_sources: ["Identity Provider","AD","Cloud Audit"],
    whatAttackerDoes: "Uses legitimate stolen or purchased credentials to log in, bypassing security tools that look for malware. The attacker blends in with normal user activity.",
    logIndicators: ["Login from new country or impossible travel (two logins from different countries within hours)", "Login at unusual hour for that user", "First-time use of legacy authentication protocol", "No MFA challenge despite policy (MFA bypassed)"],
  },

  // Execution
  { id: "T1059.001", name: "PowerShell", tactic: "TA0002",
    description: "Adversaries use PowerShell to execute commands and scripts.",
    platforms: ["Windows"],
    data_sources: ["EDR","Sysmon","Script Block Logging"],
    detection_hint: "EncodedCommand, -ExecutionPolicy Bypass, IEX(New-Object Net.WebClient).",
    whatAttackerDoes: "Uses PowerShell to download and execute malware, move laterally, or dump credentials. Often obfuscates commands with Base64 encoding to hide the payload from basic detection.",
    logIndicators: ["powershell.exe with -EncodedCommand or -enc flag", "powershell.exe with -WindowStyle Hidden or -w hidden", "-ExecutionPolicy Bypass flag", "PowerShell spawned by Office app (Word, Excel, Outlook)", "IEX(New-Object Net.WebClient).DownloadString in cmdline"],
  },
  { id: "T1059.003", name: "Windows Command Shell", tactic: "TA0002",
    description: "cmd.exe used for execution.", platforms: ["Windows"],
    data_sources: ["EDR","Sysmon"],
    whatAttackerDoes: "Uses cmd.exe to run commands, create files, delete logs, or chain multiple tools together. Often used to launch other attack tools or as a stepping stone after gaining initial access.",
    logIndicators: ["cmd.exe spawned by a non-standard parent (Word, Excel, browser)", "del /f /q to delete logs or evidence files", "net user /add or net localgroup administrators", "Piping commands to hide output (> nul 2>&1)"],
  },
  { id: "T1059.005", name: "Visual Basic", tactic: "TA0002",
    description: "VBA macros in Office documents.", platforms: ["Windows"],
    data_sources: ["EDR","Email","Office Telemetry"],
    whatAttackerDoes: "Embeds VBA macros inside Office files (.doc, .xls, .ppt). When the victim opens the file and clicks 'Enable Content', the macro runs automatically and can download/execute malware.",
    logIndicators: ["Macro-enabled Office file (.docm, .xlsm, .pptm) opened", "Office application creating or modifying executable files", "Office process making outbound network connections", "Windows Script Host (wscript.exe/cscript.exe) spawned by Office"],
  },
  { id: "T1204.002", name: "User Execution: Malicious File", tactic: "TA0002",
    description: "User opens a malicious file.", platforms: ["Windows","macOS","Linux"],
    data_sources: ["EDR","Email"],
    whatAttackerDoes: "Tricks the user into opening a malicious file — disguised as an invoice, resume, or notification. The file exploits the application or executes embedded code when opened.",
    logIndicators: ["User opens file from Downloads folder or email attachment", "Unexpected process spawned from document viewer", "New executable created in user's temp folder", "Browser or email client spawns unexpected child process"],
  },
  { id: "T1053.005", name: "Scheduled Task", tactic: "TA0002",
    tactics: ["TA0002","TA0003","TA0004"],
    description: "Use of schtasks for execution and persistence.", platforms: ["Windows"],
    data_sources: ["EDR","Sysmon","Event Log 4698"],
    whatAttackerDoes: "Creates a Windows scheduled task to run malware repeatedly — at login, on a timer, or at a specific time. This ensures the malware survives a reboot.",
    logIndicators: ["schtasks.exe /create with suspicious command", "New task created in Task Scheduler (Event ID 4698)", "Task pointing to executable in %TEMP% or AppData", "Task running PowerShell with encoded command"],
  },

  // Persistence
  { id: "T1547.001", name: "Registry Run Keys / Startup Folder", tactic: "TA0003",
    description: "Run keys in HKCU/HKLM Software\\Microsoft\\Windows\\CurrentVersion\\Run.",
    platforms: ["Windows"],
    data_sources: ["Registry","EDR"],
    whatAttackerDoes: "Writes a registry key under HKCU or HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run so that the malware launches automatically every time the user logs in.",
    logIndicators: ["Registry write to CurrentVersion\\Run or CurrentVersion\\RunOnce", "New run key pointing to executable in AppData or Temp", "Process creating run key at unusual hour", "Run key value contains encoded PowerShell or obfuscated path"],
  },
  { id: "T1543.003", name: "Windows Service", tactic: "TA0003",
    tactics: ["TA0003","TA0004"],
    description: "Creates or modifies a Windows service to run code.", platforms: ["Windows"],
    data_sources: ["EDR","Service Control Manager"],
    whatAttackerDoes: "Installs a malicious Windows service so that the malware runs with SYSTEM privileges and restarts automatically if stopped.",
    logIndicators: ["sc.exe create with suspicious binary path", "New service created (Event ID 7045)", "Service binary located in temp folder instead of System32", "Service running as SYSTEM with non-standard name"],
  },

  // Privilege Escalation / Credential Access
  { id: "T1003.001", name: "LSASS Memory", tactic: "TA0006",
    description: "Dump credentials from LSASS process memory (mimikatz, procdump).",
    platforms: ["Windows"],
    data_sources: ["EDR","Sysmon Event 10"],
    detection_hint: "ProcessAccess to lsass.exe with GrantedAccess 0x1410 / 0x1010.",
    whatAttackerDoes: "Reads the memory of lsass.exe — the Windows process that holds all active user credentials. The extracted dump file contains password hashes and Kerberos tickets that can be used to authenticate as any logged-in user.",
    logIndicators: ["Process opening lsass.exe with PROCESS_VM_READ access (Sysmon Event 10)", "procdump.exe, taskmgr.exe, or comsvcs.dll accessing lsass", "File named debug.bin, lsass.dmp, or similar created in temp", "rundll32.exe executing comsvcs.dll MiniDump"],
  },
  { id: "T1110.003", name: "Password Spraying", tactic: "TA0006",
    description: "Trying a few passwords against many accounts to evade lockouts.",
    platforms: ["Cloud","SaaS","Identity","Windows"],
    data_sources: ["Identity Provider","AD","Cloud Audit"],
    whatAttackerDoes: "Tries one or two common passwords (Password1!, Welcome123) against hundreds of accounts. By staying below the lockout threshold per account, the attacker avoids triggering lockouts while still finding accounts with weak passwords.",
    logIndicators: ["Many accounts with exactly 1-2 failed logins from same source IP", "Event ID 4625 (logon failure) for many different usernames", "Short time window between attempts (automated)", "Attempts target accounts across the whole domain, not one user"],
  },
  { id: "T1555", name: "Credentials from Password Stores", tactic: "TA0006",
    description: "Browsers, vaults, keychain.", platforms: ["Windows","macOS","Linux"],
    data_sources: ["EDR"],
    whatAttackerDoes: "Steals saved passwords from browsers (Chrome, Firefox), credential managers, or the Windows Credential Manager to collect working credentials without needing to crack hashes.",
    logIndicators: ["Process accessing Chrome's Login Data SQLite database", "Process reading Windows Credential Manager (vaultcli.dll)", "Suspicious process opening browser profile directories", "Sensitive file path in process file access events"],
  },

  // Defense Evasion
  { id: "T1218.011", name: "Signed Binary Proxy: Rundll32", tactic: "TA0005",
    description: "Use rundll32.exe to execute attacker DLLs.", platforms: ["Windows"],
    data_sources: ["EDR","Sysmon"],
    whatAttackerDoes: "Uses rundll32.exe (a legitimate Windows tool) to execute a malicious DLL file. Because rundll32 is a trusted Windows binary, it often bypasses application allowlists and some AV products.",
    logIndicators: ["rundll32.exe executing DLL from %TEMP% or AppData", "rundll32.exe making network connections", "Unusual DLL path (not in System32 or Program Files)", "rundll32.exe spawned by Office or browser"],
  },
  { id: "T1027", name: "Obfuscated Files or Information", tactic: "TA0005",
    description: "Encoded/encrypted payloads.", platforms: ["Windows","macOS","Linux"],
    data_sources: ["EDR"],
    whatAttackerDoes: "Encodes or encrypts the malicious payload to hide it from security tools that scan for known bad strings. Base64 encoding is most common — the encoded payload is decoded and run in memory.",
    logIndicators: ["Long Base64-encoded string in command line", "PowerShell with -EncodedCommand or [System.Convert]::FromBase64String", "File written with .txt or .jpg extension that is actually an executable", "Obfuscated script with variable substitution or string splitting"],
  },
  { id: "T1562.001", name: "Disable or Modify Tools", tactic: "TA0005",
    description: "Tampering with EDR/AV.", platforms: ["Windows","macOS","Linux"],
    data_sources: ["EDR","Service Logs"],
    whatAttackerDoes: "Disables or tampers with endpoint security tools (antivirus, EDR) so that subsequent malicious actions are not detected or blocked.",
    logIndicators: ["EDR/AV service stopped or disabled (Event ID 7036)", "Registry key for security software set to disabled", "Process killing antivirus process (MsMpEng.exe, CSFalconService)", "Windows Defender real-time protection turned off via PowerShell"],
  },

  // Discovery
  { id: "T1087.002", name: "Account Discovery: Domain", tactic: "TA0007",
    description: "net group /domain, AdFind.", platforms: ["Windows"],
    data_sources: ["EDR","AD"],
    whatAttackerDoes: "Enumerates all users, groups, and computers in Active Directory to understand the environment and identify high-value targets like domain admins.",
    logIndicators: ["net user /domain or net group /domain commands", "LDAP queries for all user objects (Event ID 4662)", "AdFind.exe or BloodHound collector running", "Large number of LDAP queries from single workstation in short time"],
  },
  { id: "T1018", name: "Remote System Discovery", tactic: "TA0007",
    description: "ping/nslookup/netscan to map hosts.", platforms: ["Windows","macOS","Linux"],
    data_sources: ["EDR","Network"],
    whatAttackerDoes: "Scans the network to find other machines — which servers are running, what ports are open, and what OS they run. This helps the attacker plan lateral movement.",
    logIndicators: ["ping.exe or nslookup.exe run in rapid succession", "Network scan tool (nmap, Advanced IP Scanner) executed", "Many ICMP packets from single host in short time", "Multiple RDP (3389) or SMB (445) connection attempts to different hosts"],
  },

  // Lateral Movement
  { id: "T1021.001", name: "Remote Services: RDP", tactic: "TA0008",
    description: "Use RDP to move laterally.", platforms: ["Windows"],
    data_sources: ["Auth Logs","Network","EDR"],
    whatAttackerDoes: "Uses Remote Desktop Protocol to log into another machine interactively. After stealing credentials, the attacker can move to servers or admin workstations using legitimate RDP.",
    logIndicators: ["mstsc.exe launched with command-line target", "Event ID 4624 logon type 10 (RemoteInteractive) from workstation", "RDP connection to server outside of normal working hours", "New user performing first-ever RDP login to a server"],
  },
  { id: "T1021.002", name: "SMB / Admin Shares", tactic: "TA0008",
    description: "Access via ADMIN$, C$, IPC$.", platforms: ["Windows"],
    data_sources: ["EDR","SMB Logs"],
    whatAttackerDoes: "Connects to ADMIN$, C$, or IPC$ shares on remote computers using stolen credentials to copy files, execute tools, or access data without needing RDP.",
    logIndicators: ["Net use command connecting to \\\\hostname\\ADMIN$", "Event ID 5140 (network share accessed) for admin shares", "File copy to/from ADMIN$ or C$", "PsExec or similar tool creating remote service via SMB"],
  },
  { id: "T1021.006", name: "Windows Remote Management", tactic: "TA0008",
    description: "WinRM / PSRemoting.", platforms: ["Windows"],
    data_sources: ["EDR","WinRM Logs"],
    whatAttackerDoes: "Uses Windows Remote Management (WinRM) or PowerShell Remoting to execute commands on remote computers. Harder to detect because it uses legitimate Windows management protocols.",
    logIndicators: ["powershell.exe -Command Invoke-Command -ComputerName", "WinRM service connections (port 5985/5986)", "Event ID 4624 logon type 3 from management tool", "wsmprovhost.exe spawning on target system"],
  },

  // Collection / C2 / Exfil
  { id: "T1005", name: "Data from Local System", tactic: "TA0009",
    description: "Searching and copying files of interest.", platforms: ["Windows","macOS","Linux"],
    data_sources: ["EDR","File"],
    whatAttackerDoes: "Searches the compromised machine for valuable files — documents, databases, password files, source code — before exfiltrating them.",
    logIndicators: ["Bulk file access in short time window", "Search commands targeting sensitive extensions (.pdf, .docx, .kdbx, .sql)", "Directory traversal across multiple paths", "Files copied to staging folder before exfiltration"],
  },
  { id: "T1071.001", name: "Application Layer Protocol: Web", tactic: "TA0011",
    description: "HTTPS C2 over web.", platforms: ["Windows","macOS","Linux","Cloud"],
    data_sources: ["Web Proxy","DNS","Network"],
    whatAttackerDoes: "Communicates with the attacker's command-and-control (C2) server over HTTPS so the traffic looks like normal web browsing. The malware sends status updates and receives new commands.",
    logIndicators: ["HTTPS connection to domain registered less than 30 days ago", "Periodic beaconing — connections at exact regular intervals", "Unusual process (powershell.exe, svchost.exe) making HTTPS connections", "Large outbound HTTPS POST to uncategorized domain"],
  },
  { id: "T1071.004", name: "DNS Tunneling", tactic: "TA0011",
    description: "Encoded data in DNS queries/responses.", platforms: ["Windows","macOS","Linux"],
    data_sources: ["DNS"],
    detection_hint: "Long subdomains, high entropy, unusual TLD, NXDOMAIN spikes.",
    whatAttackerDoes: "Encodes data inside DNS queries to pass information to the attacker's server without triggering web proxy or firewall rules. The encoded data is hidden in subdomain names (e.g. abc123def456.attacker.com).",
    logIndicators: ["Unusually long subdomain names (>30 characters)", "High volume of DNS queries to single domain", "DNS query types TXT or NULL (rare in normal traffic)", "Many NXDOMAIN responses for subdomains of same domain"],
  },
  { id: "T1572", name: "Protocol Tunneling", tactic: "TA0011",
    description: "ssh/icmp/dns tunnels.", platforms: ["Windows","Linux","macOS"],
    data_sources: ["Network"],
    whatAttackerDoes: "Wraps malicious traffic inside a legitimate protocol (SSH, ICMP, DNS) to bypass firewalls. The attacker creates an encrypted tunnel that looks like normal network management traffic.",
    logIndicators: ["SSH connection to unexpected external host from server", "Unusually large ICMP packets (normal ping is 64 bytes)", "iodine, dnscat2, or similar tunnel tool processes", "High volume of traffic on non-standard port disguised as known protocol"],
  },
  { id: "T1041", name: "Exfiltration Over C2 Channel", tactic: "TA0010",
    description: "Steal data over the same C2 channel.", platforms: ["Windows","Linux","macOS","Cloud"],
    data_sources: ["Network","EDR"],
    whatAttackerDoes: "Sends stolen data back to the attacker using the same C2 channel already established. The data is often compressed and encrypted to hide its contents and reduce size.",
    logIndicators: ["Sudden increase in outbound data to C2 domain", "Large encrypted archive (.zip, .7z) sent over HTTPS", "Outbound data transfer much larger than normal for that host", "Data sent in chunks at regular intervals to avoid detection"],
  },
  { id: "T1567.002", name: "Exfil to Cloud Storage", tactic: "TA0010",
    description: "Upload to S3/GDrive/Mega/Dropbox.", platforms: ["Windows","Linux","macOS","Cloud"],
    data_sources: ["Web Proxy","DLP"],
    whatAttackerDoes: "Uploads stolen files to legitimate cloud storage services (Dropbox, Google Drive, OneDrive, Mega) that are often not blocked by corporate firewalls. The data blends in with legitimate cloud sync traffic.",
    logIndicators: ["Large file upload to cloud storage service", "Upload to personal account (non-corporate email)", "Unusual process (cmd.exe, PowerShell) accessing cloud storage API", "File upload volume far exceeds historical average for that user"],
  },

  // Impact
  { id: "T1486", name: "Data Encrypted for Impact", tactic: "TA0040",
    description: "Ransomware encryption of files.", platforms: ["Windows","Linux","macOS","Cloud"],
    data_sources: ["EDR","File"],
    whatAttackerDoes: "Encrypts files across the organization to make them inaccessible, then demands a ransom for the decryption key. Modern ransomware encrypts mapped drives and network shares too.",
    logIndicators: ["Thousands of file modification events in minutes", "Files renamed with new extension (.locked, .encrypted, .CRYPT)", "New file created: README_DECRYPT.txt or similar ransom note", "vssadmin or wbadmin commands deleting backups before or after encryption"],
  },
  { id: "T1490", name: "Inhibit System Recovery", tactic: "TA0040",
    description: "vssadmin delete shadows, wbadmin delete catalog.", platforms: ["Windows"],
    data_sources: ["EDR","Sysmon"],
    whatAttackerDoes: "Deletes Windows backup snapshots (Volume Shadow Copies) and disables recovery tools so victims cannot restore files without paying the ransom.",
    logIndicators: ["vssadmin.exe delete shadows /all /quiet", "wbadmin.exe delete catalog", "bcdedit.exe /set {default} recoveryenabled No", "Event ID 524 (system restore point deleted) or VSS service events"],
  },
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
