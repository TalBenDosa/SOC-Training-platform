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
}

export interface EdrDetection {
  pid: number;
  technique: string;      // MITRE ID
  name: string;
  severity: "low" | "medium" | "high" | "critical";
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
      { pid: 6240, ppid: 6104, name: "powershell.exe", cmdline: "powershell.exe -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQ...", user: "CORP\\r.bakker", path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", signed: true, startedAt: "09:41:56", verdict: "suspicious", note: "Encoded, hidden-window PowerShell — the downloader. Signed LOLBin abused; it fetched and ran the payload below." },
      { pid: 6388, ppid: 6240, name: "rundll32.exe", cmdline: "rundll32.exe C:\\Users\\r.bakker\\AppData\\Roaming\\svc\\update.dll,Start", user: "CORP\\r.bakker", path: "C:\\Users\\r.bakker\\AppData\\Roaming\\svc\\update.dll", signed: false, sha256: "415dde31bb66f5a6fa3b7ec84d5c1c33c4c6c7038e897dee5b562d8ce70246a9", startedAt: "09:42:01", verdict: "malicious", note: "THE PAYLOAD. rundll32 running an UNSIGNED DLL from AppData\\Roaming — real rundll32 loads system DLLs, never user-writable ones. The hash is a known Agent Tesla sample; it beaconed to the C2 below." },
      { pid: 2140, ppid: 1064, name: "svchost.exe", cmdline: "C:\\Windows\\System32\\svchost.exe -k netsvcs -p", user: "NT AUTHORITY\\SYSTEM", path: "C:\\Windows\\System32\\svchost.exe", signed: true, startedAt: "08:01:40", verdict: "benign", note: "Benign noise — a real service host under SYSTEM, correct path and signer." },
      { pid: 7702, ppid: 1200, name: "chrome.exe", cmdline: "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\"", user: "CORP\\r.bakker", path: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", signed: true, startedAt: "09:05:22", verdict: "benign", note: "Benign — normal browser under the user, signed, correct path." },
    ],
    detections: [
      { pid: 6240, technique: "T1059.001", name: "Encoded PowerShell command line", severity: "high" },
      { pid: 6388, technique: "T1218.011", name: "rundll32 executing unsigned DLL from AppData", severity: "critical" },
      { pid: 6104, technique: "T1059.003", name: "Office application spawned a command shell", severity: "medium" },
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
